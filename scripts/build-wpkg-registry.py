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


def manifest_field(path: Path, field: str):
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == field:
            return value.strip()
    return None


def dependency_names(path: Path) -> list[str]:
    value = manifest_field(path, "dependencies")
    if not value:
        return []
    return [item.strip().strip('"').split("@")[0] for item in value.strip("[]").split(",") if item.strip()]


def check_versions() -> None:
    """A package is upstream (one `upstream.wpkg`, nothing else) or pinned:
    every manifest version listed once in `versions`, including `latest`.
    Pinned packages may depend only on pinned packages."""
    packages = sorted(p for p in (REGISTRY / "packages").iterdir() if p.is_dir())
    upstream = {p.name for p in packages if (p / "upstream.wpkg").is_file()}
    for package in packages:
        name = package.name
        if name in upstream:
            extra = [p.name for p in package.iterdir() if p.name not in ("upstream.wpkg",)]
            if extra:
                raise SystemExit(f"{name}: an upstream package has only upstream.wpkg, not {extra}")
            continue
        for manifest in package.glob("*.wpkg"):
            for dependency in dependency_names(manifest):
                if dependency in upstream:
                    raise SystemExit(f"{name}: pinned packages may not depend on upstream {dependency}")
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
    # `source` files are maintainer recipes for scripts/wpkg-registry.py.
    files = sorted(path for path in REGISTRY.rglob("*") if path.is_file() and path.name != "source")
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
