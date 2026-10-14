# Package registry (`wpkg`)

Every package below installs with `wpkg install <name>` inside `winrun shell`.
Versions are SHA-256-pinned in the bundled registry; archives download on demand.

```powershell
wpkg install nodejs          # latest; becomes the default
wpkg install nodejs@24       # newest 24.x, side by side
wpkg list                    # show installed packages (* = default)
wpkg search <query>          # search the catalog
```

| Package | Latest | Notes |
|---|---|---|
| nodejs | 24.21.0 | node, npm, npx, corepack |
| python | 3.14.7 | Full dist; `venv`, `pip` work |
| micro | 2.0.15 | Run with `micro -clipboard internal` |
| curl | 8.22.0 | Official Windows build, HTTPS works |
| git | 2.55.0.2 | MinGit distribution |
| 7zip | 26.03 | 7za CLI |
| ripgrep | 15.2.0 | — |
| fd | 10.5.0 | — |
| bat | 0.26.1 | — |
| fzf | 0.74.5 | — |
| gh | 2.102.0 | GitHub CLI |
| bun | 1.4.3 | Official installer also works (needs `curl`) |
| deno | 2.9.7 | — |
| uv | 0.13.0 | — |
| esbuild | 0.28.2 | From npm tarballs |
| biome | 2.5.15 | From npm platform packages |
| opencode | 1.19.0 | From npm tarballs |

Most packages ship x64 + arm64 manifests (arm64 for future hosts).
Side-by-side versions: `wpkg install <name>@<major>`, switch with
`wpkg default <name> <major>`, drop one with `wpkg remove <name>@<version>`.

> Pins mirror `registry/packages/*/latest`. If this page lags the source,
> the `latest` files — and `wpkg list` output — win.
