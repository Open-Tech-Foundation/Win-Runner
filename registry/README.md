# Win-Runner package registry

This directory is the source of `registry.zip`, the package list wpkg uses.
Only package metadata belongs here; application archives stay at their HTTPS
URLs.

## How instances get it

`tsr registry` builds `registry.zip`, which is committed to the repository. An
instance fetches it once, on first use, from

```text
https://raw.githubusercontent.com/Open-Tech-Foundation/Win-CLI/main/registry.zip
```

into `C:\ProgramData\wpkg\registry.zip`, and replaces it only when someone runs
`wpkg refresh`, which prints what changed. When it cannot be fetched, wpkg
uses the copy built into winrun. `WINRUN_WPKG_REGISTRY` names another URL, or
`embedded` to use only the built-in copy (offline tests do).

## Two kinds of packages

Every package has `.wpkg` files under `packages/<name>/`; what is in them
decides how it installs. `packages/index` lists the names for `wpkg search`.

**Pinned** packages are the ones whose versions we choose and test on winrun
(git, nodejs, python, dotnet, 7zip, curl, micro). Each version has its
manifest, and only listed versions install:

```text
packages/<name>/latest              the default version
packages/<name>/versions            every listed version, one per line
packages/<name>/<version>.wpkg      x64 (and <version>-arm64.wpkg)
```

A manifest has `name`, `version`, `arch` (`x64` or `arm64`), `url` (ZIP, 7z or
tarball), `sha256` (or `sha512`), and `bin`. `wpkg install <name>@24` picks the
newest listed version equal to `24` or starting with `24.`.

**Upstream** packages are tools that publish their own releases (opencode,
esbuild, biome, bun, deno, uv, fd, bat, fzf, gh, ripgrep, csharpier). They have
only `packages/<name>/upstream.wpkg`, and each install resolves the newest
release (or the one `@version` names) where it is published:

```toml
name = "opencode"
upstream = "npm"                    # npm, nuget, or github
x64 = "opencode-windows-x64"        # npm package, NuGet id, or GitHub asset
arm64 = "opencode-windows-arm64"
bin = ["package/bin/opencode.exe"]
description = "The AI coding agent built for the terminal"
```

GitHub packages add `repo = "OWNER/REPO"` and `tag = "v{version}"` (or a
`version` pattern with `(\d+)` groups), and their asset names and `bin` may use
`{version}` and `{stem}` (the archive name without its extension). Archives are
checked against the hash upstream publishes: npm's and NuGet's SHA-512, or
GitHub's SHA-256 asset digest. A release without one is refused.

## Keys both kinds share

- `bin`: commands to expose, as `path` or `command=path` inside the archive.
- `run`: a program that opens each `bin` file (`run = "dotnet"` for a .NET
  tool's DLL); its commands become `.cmd` shims running `<run> <file> %*`.
- `env`: `NAME=VALUE` settings for the package's commands (`{dir}` is the
  package's directory).
- `dependencies`: `name` or `name@version`; a version line like `dotnet@10`
  takes the newest pinned 10.x, installed beside other versions when needed.
  Pinned packages may depend only on pinned packages.
- `description`: one line for `wpkg search` and `wpkg info`.

## Pinning versions

Pinned packages keep a maintainer recipe in `packages/<name>/source` (left out
of `registry.zip`) that says where their releases come from:

```text
tsr registry-latest -- nodejs 24     # newest release in a line: 24.22.0
tsr registry-add -- nodejs 24.22.0   # pin it: manifests with SHA-256, zip rebuilt
tsr registry                         # rebuild registry.zip after hand edits
```

Packages without a `source` (curl) are maintained by hand. Commit the updated
`registry.zip` with the change.
