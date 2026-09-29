# Win-Runner package registry

This directory is the source for the small registry ZIP embedded in `winrun`.
Only package metadata belongs here; application archives stay at their HTTPS URLs.

Each package uses this layout:

```text
packages/<name>/latest
packages/<name>/versions
packages/<name>/<version>.wpkg
```

`latest` contains one version string. `versions` lists every version that has a
manifest, one per line; `wpkg install <name>@26` picks the newest listed
version equal to `26` or starting with `26.`, `26-`, or `26+`. The build script
rejects a `versions` file that disagrees with the manifests. Versions may not be
named `current` or start with `.`, because those names are reserved inside
`C:\softwares\<name>`. A `.wpkg` file is a UTF-8 TOML
manifest with `name`, `version`, `arch` (`x64` or `arm64`), `url` (ZIP or 7z), `sha256`,
`bin`, and optional `dependencies`. `packages/index` contains one package name
per line for `wpkg search`.

After editing registry data, run `python3 scripts/build-wpkg-registry.py` and
include the updated `registry.zip` with the source change. The ZIP is embedded
in the winrun binary; registry refreshes from GitHub Releases are planned later.

The initial catalog contains Node.js (`nodejs`), Python's embeddable distribution,
ripgrep, curl, MinGit, and the x64 standalone 7za CLI from the official 7-Zip
Extra archive. ARM64 manifests are included where upstream provides them.
