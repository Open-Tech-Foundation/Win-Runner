#!/usr/bin/env python3
"""Local registry + throttled nodejs archive for scripts/demo.tape.

Serves on 127.0.0.1:8734:
  /registry.zip  the repo registry/ tree, with the nodejs x64 manifest's
                 url pointed at this server (sha256 unchanged, so wpkg
                 still verifies the archive it downloads)
  /nodejs.zip    the exact upstream nodejs archive, streamed at a fixed
                 rate so the recorded download bar has a bounded duration

The blob is looked up by the manifest's sha256 in /tmp/winrun-demo-serve
first, then in the host wpkg cache ($XDG_CACHE_HOME/winrun/wpkg).
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import sys
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_DIR = ROOT / "registry"
HOST = "127.0.0.1"
PORT = 8734
RATE = 5.5 * 1024 * 1024
CHUNK = 64 * 1024
NODEJS_URL = f"http://{HOST}:{PORT}/nodejs.zip"
SERVE_DIR = Path("/tmp/winrun-demo-serve")


def nodejs_x64_manifest() -> str:
    text = ""
    for path in sorted((REGISTRY_DIR / "packages" / "nodejs").glob("*.wpkg")):
        manifest = path.read_text(encoding="utf-8")
        if 'arch = "x64"' in manifest:
            text = manifest
            break
    if not text:
        raise SystemExit("nodejs x64 manifest not found")
    return text


def manifest_sha256(text: str) -> str:
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "sha256":
            return value.strip().strip('"')
    raise SystemExit("manifest has no sha256")


def build_registry() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(p for p in REGISTRY_DIR.rglob("*") if p.is_file() and p.name != "source"):
            if path.is_symlink():
                raise SystemExit(f"registry must not contain symlinks: {path}")
            data = path.read_bytes()
            if (
                path.parent.name == "nodejs"
                and path.suffix == ".wpkg"
                and b'arch = "x64"' in data
            ):
                data = re.sub(
                    rb'url = "[^"]*"',
                    b'url = "' + NODEJS_URL.encode("ascii") + b'"',
                    data,
                    count=1,
                )
            info = zipfile.ZipInfo(path.relative_to(REGISTRY_DIR).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return buffer.getvalue()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def find_blob(sha256: str) -> Path:
    candidates = [SERVE_DIR / "nodejs.zip"]
    cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "winrun" / "wpkg"
    if cache.is_dir():
        candidates.extend(
            path for path in sorted(cache.iterdir()) if path.is_file() and 10 * 1024 * 1024 <= path.stat().st_size <= 200 * 1024 * 1024
        )
    for path in candidates:
        if path.is_file() and sha256_file(path) == sha256:
            return path
    raise SystemExit(
        f"nodejs archive not found (sha256 {sha256}); "
        f"place it at {SERVE_DIR}/nodejs.zip"
    )


class Handler(BaseHTTPRequestHandler):
    registry: bytes = b""
    blob: bytes = b""

    def log_message(self, *_args) -> None:
        pass

    def _send(self, data: bytes, throttle: bool) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if throttle:
            for offset in range(0, len(data), CHUNK):
                block = data[offset : offset + CHUNK]
                self.wfile.write(block)
                self.wfile.flush()
                time.sleep(len(block) / RATE)
        else:
            self.wfile.write(data)

    def do_GET(self) -> None:
        try:
            if self.path == "/registry.zip":
                self._send(self.registry, throttle=False)
            elif self.path == "/nodejs.zip":
                self._send(self.blob, throttle=True)
            else:
                self.send_error(404)
        except OSError:
            pass


def main() -> None:
    manifest = nodejs_x64_manifest()
    sha256 = manifest_sha256(manifest)
    blob = find_blob(sha256).read_bytes()
    if hashlib.sha256(blob).hexdigest() != sha256:
        raise SystemExit("nodejs archive checksum mismatch")
    Handler.registry = build_registry()
    Handler.blob = blob
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"registry + throttled nodejs on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
