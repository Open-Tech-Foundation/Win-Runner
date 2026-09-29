#!/usr/bin/env python3
"""Build the deterministic registry ZIP embedded by src/wpkg.rs."""

from pathlib import Path
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "registry"
OUTPUT = ROOT / "registry.zip"
ALLOWED = {".md", ".wpkg", ".txt", ""}


def manifest_version(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "version":
            return value.strip().strip('"')
    raise SystemExit(f"manifest has no version: {path.relative_to(REGISTRY)}")


def check_versions() -> None:
    """Each package lists every manifest version once, including `latest`."""
    for package in sorted((REGISTRY / "packages").iterdir()):
        if not package.is_dir():
            continue
        name = package.name
        manifests = {manifest_version(path) for path in package.glob("*.wpkg")}
        versions_file = package / "versions"
        if not versions_file.is_file():
            raise SystemExit(f"{name}: missing packages/{name}/versions")
        listed = [line.strip() for line in versions_file.read_text(encoding="utf-8").splitlines()]
        listed = [line for line in listed if line]
        if len(listed) != len(set(listed)) or set(listed) != manifests:
            raise SystemExit(
                f"{name}: versions file {sorted(listed)} does not match manifests {sorted(manifests)}"
            )
        latest = (package / "latest").read_text(encoding="utf-8").strip()
        if latest not in manifests:
            raise SystemExit(f"{name}: latest version {latest} has no manifest")


def main() -> None:
    files = sorted(path for path in REGISTRY.rglob("*") if path.is_file())
    if not files:
        raise SystemExit("registry is empty")
    check_versions()
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            if path.is_symlink():
                raise SystemExit(f"registry must not contain symlinks: {path}")
            relative = path.relative_to(REGISTRY).as_posix()
            if relative.startswith("../") or "\\" in relative:
                raise SystemExit(f"unsafe registry path: {relative}")
            if path.suffix.lower() not in ALLOWED:
                raise SystemExit(f"registry files must be text metadata: {relative}")
            data = path.read_bytes()
            try:
                data.decode("utf-8")
            except UnicodeDecodeError as error:
                raise SystemExit(f"registry file is not UTF-8: {relative}: {error}")
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
