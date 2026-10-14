#!/usr/bin/env python3
"""Pin package versions in the wpkg registry.

Pinned packages (the ones whose versions we choose and test, like git,
nodejs, python, dotnet) keep a maintainer recipe in
`registry/packages/<name>/source`: where releases are published and how
their files are named. Upstream packages need nothing here; their
`upstream.wpkg` is resolved by wpkg itself at install time.

  scripts/wpkg-registry.py latest NAME [LINE]   newest release (in LINE, e.g. 24)
  scripts/wpkg-registry.py add NAME VERSION     pin VERSION: write its manifests

`add` writes `<version>.wpkg` (x64) and `<version>-arm64.wpkg` with each
archive's SHA-256 (taken from upstream when published, else computed from
a download), lists the version in `versions`, moves `latest` when it is
the highest, and rebuilds `registry.zip`.

Recipe kinds and keys (`x64`/`arm64` name the file per architecture):

  github  repo, tag ("v{version}"), x64, arm64: asset names; `version` is a
          regex with one group per version part when the tag needs it
  nuget   x64, arm64: NuGet package ids
  dotnet  channel ("10.0"), product ("runtime")
  node    (none)

Every recipe has `bin`, and may have `dependencies`, `run`, `env`, and
`description`. Templates may use {version}, {version_nodot}, {arch}, and in
`bin` also {stem}: the archive's file name without its extension.

Set GITHUB_TOKEN to raise GitHub's API rate limit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT / "registry" / "packages"
ARCHES = ("x64", "arm64")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "wpkg-registry"})
    if "api.github.com" in url and os.environ.get("GITHUB_TOKEN"):
        request.add_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def fetch_json(url: str):
    return json.loads(fetch(url))


def version_key(version: str):
    return [int(part) if part.isdigit() else part for part in re.split(r"[.\-+]", version)]


def stable(version: str) -> bool:
    return not re.search(r"[-+]", version)


def in_line(version: str, line: str | None) -> bool:
    return line is None or version == line or version.startswith(line + ".")


def fill(template: str, version: str, arch: str, stem: str = "") -> str:
    return (
        template.replace("{version}", version)
        .replace("{version_nodot}", version.replace(".", ""))
        .replace("{arch}", arch)
        .replace("{stem}", stem)
    )


def tag_version(source: dict, tag: str) -> str | None:
    if "version" in source:
        match = re.fullmatch(source["version"], tag)
        return ".".join(match.groups()) if match else None
    prefix, _, suffix = source.get("tag", "v{version}").partition("{version}")
    if tag.startswith(prefix) and tag.endswith(suffix):
        version = tag[len(prefix) : len(tag) - len(suffix) or None]
        return version if version[:1].isdigit() else None
    return None


# Each kind: (versions on offer, files of one version as {arch: (url, sha256 or None)}).


def github_releases(source: dict) -> dict[str, dict]:
    releases = {}
    for page in range(1, 4):
        batch = fetch_json(f"https://api.github.com/repos/{source['repo']}/releases?per_page=100&page={page}")
        for release in batch:
            version = tag_version(source, release["tag_name"])
            if version and not release.get("draft"):
                releases[version] = release
        if len(batch) < 100:
            break
    return releases


def github_versions(source: dict, line: str | None) -> list[str]:
    return list(github_releases(source))


def github_files(source: dict, version: str) -> dict:
    release = github_releases(source).get(version)
    if release is None:
        raise SystemExit(f"{source['repo']}: no release {version}")
    assets = {asset["name"]: asset for asset in release["assets"]}
    found = {}
    for arch in ARCHES:
        asset = assets.get(fill(source[arch], version, arch)) if arch in source else None
        if asset:
            found[arch] = (asset["browser_download_url"], (asset.get("digest") or "").removeprefix("sha256:") or None)
    return found


def nuget_versions(source: dict, line: str | None) -> list[str]:
    package = (source.get("x64") or source["arm64"]).lower()
    return fetch_json(f"https://api.nuget.org/v3-flatcontainer/{package}/index.json")["versions"]


def nuget_files(source: dict, version: str) -> dict:
    return {
        arch: (f"https://globalcdn.nuget.org/packages/{source[arch].lower()}.{version}.nupkg", None)
        for arch in ARCHES
        if arch in source
    }


def dotnet_meta(source: dict, channel: str | None):
    return fetch_json(
        f"https://builds.dotnet.microsoft.com/dotnet/release-metadata/{channel or source.get('channel', '10.0')}/releases.json"
    )


def dotnet_versions(source: dict, line: str | None) -> list[str]:
    product = source.get("product", "runtime")
    return [r[product]["version"] for r in dotnet_meta(source, line)["releases"] if r.get(product, {}).get("version")]


def dotnet_files(source: dict, version: str) -> dict:
    product = source.get("product", "runtime")
    prefix = {"runtime": "dotnet-runtime", "aspnetcore-runtime": "aspnetcore-runtime", "sdk": "dotnet-sdk"}[product]
    channel = ".".join(version.split(".")[:2])
    release = next(r for r in dotnet_meta(source, channel)["releases"] if r.get(product, {}).get("version") == version)
    return {
        arch: (file["url"], None)
        for arch in ARCHES
        for file in release[product]["files"]
        if file["rid"] == f"win-{arch}" and file["name"] == f"{prefix}-win-{arch}.zip"
    }


def node_versions(source: dict, line: str | None) -> list[str]:
    return [r["version"].lstrip("v") for r in fetch_json("https://nodejs.org/dist/index.json")]


def node_files(source: dict, version: str) -> dict:
    sums = fetch(f"https://nodejs.org/dist/v{version}/SHASUMS256.txt").decode()
    found = {}
    for arch in ARCHES:
        name = f"node-v{version}-win-{arch}.zip"
        digest = next((line.split()[0] for line in sums.splitlines() if line.endswith(name)), None)
        if digest:
            found[arch] = (f"https://nodejs.org/download/release/v{version}/{name}", digest)
    return found


KINDS = {
    "github": (github_versions, github_files),
    "nuget": (nuget_versions, nuget_files),
    "dotnet": (dotnet_versions, dotnet_files),
    "node": (node_versions, node_files),
}


def recipe(name: str) -> dict:
    path = PACKAGES / name / "source"
    if not path.is_file():
        raise SystemExit(f"{name}: no maintainer recipe (registry/packages/{name}/source)")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def latest(name: str, line: str | None) -> str:
    source = recipe(name)
    versions = [v for v in KINDS[source["kind"]][0](source, line) if stable(v) and in_line(v, line)]
    if not versions:
        raise SystemExit(f"{name}: no release{' in ' + line if line else ''}")
    return max(versions, key=version_key)


def quoted(items) -> str:
    return "[" + ", ".join(json.dumps(item) for item in items) + "]"


def add(name: str, version: str) -> None:
    source = recipe(name)
    found = KINDS[source["kind"]][1](source, version)
    if not found:
        raise SystemExit(f"{name}: release {version} has no Windows archives")
    directory = PACKAGES / name
    for arch, (url, sha) in found.items():
        if not sha:
            print(f"  downloading {url}", file=sys.stderr)
            sha = hashlib.sha256(fetch(url)).hexdigest()
        stem = re.sub(r"(\.tar\.gz|\.tgz|\.zip|\.7z|\.nupkg)$", "", url.rsplit("/", 1)[-1])
        lines = [
            f'name = "{name}"',
            f'version = "{version}"',
            f'arch = "{arch}"',
            f'url = "{url}"',
            f'sha256 = "{sha}"',
            f"bin = {quoted(fill(entry, version, arch, stem) for entry in source['bin'])}",
        ]
        for key in ("run", "description"):
            if source.get(key):
                lines.append(f"{key} = {json.dumps(source[key])}")
        for key in ("env", "dependencies"):
            if source.get(key):
                lines.append(f"{key} = {quoted(source[key])}")
        file = directory / (f"{version}.wpkg" if arch == "x64" else f"{version}-{arch}.wpkg")
        file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"{name}: wrote {file.name}")
    versions_file = directory / "versions"
    versions = [v for v in versions_file.read_text().split() if v] if versions_file.exists() else []
    if version not in versions:
        versions.append(version)
    versions_file.write_text("\n".join(sorted(versions, key=version_key)) + "\n")
    (directory / "latest").write_text(max(versions, key=version_key) + "\n")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build-wpkg-registry.py")], check=True)


def main(argv: list[str]) -> None:
    if len(argv) >= 3 and argv[1] == "latest":
        print(latest(argv[2], argv[3] if len(argv) > 3 else None))
    elif len(argv) == 4 and argv[1] == "add":
        add(argv[2], argv[3])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
