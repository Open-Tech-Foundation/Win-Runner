#!/usr/bin/env python3
"""Add and update wpkg registry packages from where projects publish them.

Each package records its origin in `registry/packages/<name>/source`
(TOML). `update` reads it, finds the newest release, writes the `.wpkg`
manifests (x64 and arm64) with their SHA-256, updates `latest`,
`versions` and `index`, and rebuilds `registry.zip`.

  scripts/wpkg-registry.py update [NAME ...]        refresh (all by default)
  scripts/wpkg-registry.py update --check           report, change nothing
  scripts/wpkg-registry.py add NAME KIND KEY=VALUE ...  record a source, then update

Kinds and their keys (`x64`/`arm64` name what to fetch per architecture;
leave one out when upstream has no such build):

  github  repo, tag ("v{version}"), x64, arm64: asset names
  npm     x64, arm64: npm package names (the platform packages)
  nuget   x64, arm64: NuGet package ids
  dotnet  channel ("10.0"), product ("runtime")
  node    major ("24")

Every kind takes `bin` (paths inside the archive; a list), optional
`dependencies`, `prerelease = true` to allow prereleases, and `version`
(a regex with one group per version part) when the tag needs more than
the `tag` pattern. Templates may use {version}, {version_nodot},
{major}, {arch} (x64|arm64), and in `bin` also {stem}: the archive's file
name without its extension.

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


def fetch(url: str, accept: str | None = None) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "wpkg-registry"})
    if accept:
        request.add_header("Accept", accept)
    if "api.github.com" in url and os.environ.get("GITHUB_TOKEN"):
        request.add_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def fetch_json(url: str):
    return json.loads(fetch(url, "application/json"))


def sha256_of(url: str) -> str:
    print(f"  downloading {url}", file=sys.stderr)
    return hashlib.sha256(fetch(url)).hexdigest()


def version_key(version: str):
    return [int(part) if part.isdigit() else part for part in re.split(r"[.\-+]", version)]


def fill(template: str, version: str, arch: str, stem: str = "") -> str:
    return template.format(
        version=version,
        version_nodot=version.replace(".", ""),
        major=version.split(".")[0],
        arch=arch,
        stem=stem,
    )


def tag_regex(source: dict) -> re.Pattern:
    if "version" in source:
        return re.compile(f"^{source['version']}$")
    pattern = re.escape(source.get("tag", "v{version}")).replace(r"\{version\}", r"(\d[\w.\-+]*)")
    return re.compile(f"^{pattern}$")


# Each resolver returns (version, {arch: (url, sha256 or None)}).


def resolve_github(source: dict):
    repo = source["repo"]
    releases = fetch_json(f"https://api.github.com/repos/{repo}/releases?per_page=30")
    pattern = tag_regex(source)
    for release in releases:
        if release.get("draft") or (release.get("prerelease") and not source.get("prerelease")):
            continue
        match = pattern.match(release["tag_name"])
        if not match:
            continue
        version = ".".join(match.groups())
        assets = {asset["name"]: asset for asset in release["assets"]}
        found = {}
        for arch in ARCHES:
            if arch not in source:
                continue
            name = fill(source[arch], version, arch)
            asset = assets.get(name)
            if asset is None:
                break
            digest = asset.get("digest") or ""
            found[arch] = (asset["browser_download_url"], digest.removeprefix("sha256:") or None)
        else:
            return version, found
    raise SystemExit(f"{repo}: no release matches tag pattern and assets")


def resolve_npm(source: dict):
    first = source.get("x64") or source["arm64"]
    meta = fetch_json(f"https://registry.npmjs.org/{first.replace('/', '%2F')}/latest")
    version = meta["version"]
    found = {}
    for arch in ARCHES:
        if arch in source:
            package = source[arch].replace("/", "%2F")
            info = fetch_json(f"https://registry.npmjs.org/{package}/{version}")
            found[arch] = (info["dist"]["tarball"], None)
    return version, found


def resolve_nuget(source: dict):
    first = (source.get("x64") or source["arm64"]).lower()
    versions = fetch_json(f"https://api.nuget.org/v3-flatcontainer/{first}/index.json")["versions"]
    stable = [v for v in versions if source.get("prerelease") or "-" not in v]
    version = max(stable, key=version_key)
    found = {}
    for arch in ARCHES:
        if arch in source:
            package = source[arch].lower()
            found[arch] = (f"https://globalcdn.nuget.org/packages/{package}.{version}.nupkg", None)
    return version, found


def resolve_dotnet(source: dict):
    channel = source.get("channel", "10.0")
    product = source.get("product", "runtime")
    meta = fetch_json(f"https://builds.dotnet.microsoft.com/dotnet/release-metadata/{channel}/releases.json")
    version = meta[f"latest-{product}"]
    release = next(r for r in meta["releases"] if r.get(product, {}).get("version") == version)
    prefix = {"runtime": "dotnet-runtime", "aspnetcore-runtime": "aspnetcore-runtime", "sdk": "dotnet-sdk"}[product]
    found = {}
    for arch in ARCHES:
        for file in release[product]["files"]:
            if file["rid"] == f"win-{arch}" and file["name"] == f"{prefix}-win-{arch}.zip":
                found[arch] = (file["url"], None)
    return version, found


def resolve_node(source: dict):
    major = str(source["major"])
    releases = fetch_json("https://nodejs.org/dist/index.json")
    version = next(r["version"] for r in releases if r["version"].startswith(f"v{major}.")).lstrip("v")
    sums = fetch(f"https://nodejs.org/dist/v{version}/SHASUMS256.txt").decode()
    found = {}
    for arch in ARCHES:
        name = f"node-v{version}-win-{arch}.zip"
        digest = next((line.split()[0] for line in sums.splitlines() if line.endswith(name)), None)
        found[arch] = (f"https://nodejs.org/download/release/v{version}/{name}", digest)
    return version, found


RESOLVERS = {
    "github": resolve_github,
    "npm": resolve_npm,
    "nuget": resolve_nuget,
    "dotnet": resolve_dotnet,
    "node": resolve_node,
}


def quoted(items) -> str:
    return "[" + ", ".join(json.dumps(item) for item in items) + "]"


def manifest(name: str, version: str, arch: str, url: str, sha: str, source: dict) -> str:
    stem = re.sub(r"(\.tar\.gz|\.tgz|\.zip|\.7z|\.nupkg)$", "", url.rsplit("/", 1)[-1])
    bins = [fill(entry, version, arch, stem) for entry in source["bin"]]
    text = (
        f'name = "{name}"\nversion = "{version}"\narch = "{arch}"\n'
        f'url = "{url}"\nsha256 = "{sha}"\nbin = {quoted(bins)}\n'
    )
    if source.get("dependencies"):
        text += f"dependencies = {quoted(source['dependencies'])}\n"
    return text


def update(name: str, check: bool) -> bool:
    directory = PACKAGES / name
    source = tomllib.loads((directory / "source").read_text(encoding="utf-8"))
    version, found = RESOLVERS[source["kind"]](source)
    if not found:
        raise SystemExit(f"{name}: no Windows archives found for {version}")
    versions_file = directory / "versions"
    versions = [v for v in versions_file.read_text().split() if v] if versions_file.exists() else []
    current = (directory / "latest").read_text().strip() if (directory / "latest").exists() else None
    if version in versions and current == version:
        print(f"{name}: {version} is current")
        return False
    print(f"{name}: {current or '(new)'} -> {version}")
    if check:
        return True
    for arch, (url, sha) in found.items():
        sha = sha or sha256_of(url)
        file = directory / (f"{version}.wpkg" if arch == "x64" else f"{version}-{arch}.wpkg")
        file.write_text(manifest(name, version, arch, url, sha, source), encoding="utf-8")
    if version not in versions:
        versions.append(version)
    versions_file.write_text("\n".join(sorted(versions, key=version_key)) + "\n")
    newest = max(versions, key=version_key)
    (directory / "latest").write_text(newest + "\n")
    add_to_index(name)
    return True


def add_to_index(name: str) -> None:
    index = PACKAGES / "index"
    lines = index.read_text().splitlines()
    header = [line for line in lines if line.startswith("#")]
    names = sorted({line for line in lines if line and not line.startswith("#")} | {name})
    index.write_text("\n".join(header + names) + "\n")


def parse_value(text: str):
    """`a,b` lists for bin/dependencies, true/false, else a string."""
    if text in ("true", "false"):
        return text == "true"
    return text


def add(name: str, kind: str, pairs: list[str]) -> None:
    if kind not in RESOLVERS:
        raise SystemExit(f"unknown kind {kind}; one of {', '.join(RESOLVERS)}")
    fields: dict = {"kind": kind}
    for pair in pairs:
        key, _, value = pair.partition("=")
        if key in ("bin", "dependencies"):
            fields[key] = [item for item in value.split(",") if item]
        else:
            fields[key] = parse_value(value)
    if "bin" not in fields:
        raise SystemExit("bin=... is required")
    directory = PACKAGES / name
    directory.mkdir(parents=True, exist_ok=True)
    lines = []
    for key, value in fields.items():
        lines.append(f"{key} = {json.dumps(value)}")
    (directory / "source").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str]) -> None:
    if len(argv) < 2 or argv[1] not in ("add", "update"):
        raise SystemExit(__doc__)
    if argv[1] == "add":
        if len(argv) < 4:
            raise SystemExit("usage: add NAME KIND KEY=VALUE ...")
        add(argv[2], argv[3], argv[4:])
        names, check = [argv[2]], False
    else:
        check = "--check" in argv
        names = [a for a in argv[2:] if not a.startswith("--")] or sorted(
            p.parent.name for p in PACKAGES.glob("*/source")
        )
    changed = False
    for name in names:
        changed |= update(name, check)
    if changed and not check:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "build-wpkg-registry.py")], check=True)


if __name__ == "__main__":
    main(sys.argv)
