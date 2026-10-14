# Compatibility: what works today

APIs are added per real program. Unlisted binaries: check with `winrun inspect` first.

| Status | Meaning |
|---|---|
| **E2E** | Real Windows binary tested under Win-Runner |
| **Packaged** | SHA-256-pinned `wpkg` manifest; no dedicated E2E yet |
| **In-box** | Built into Win-Runner (shell, System32) |

## Tested tools and versions

Pins from `registry/packages/*/latest`. Full list: [registry.md](registry.md).

| Tool | Version | Status | Proves |
|---|---|---|---|
| Node.js (+npm, npx) | 24.21.0 / npm 11.19.0 | E2E | `npm install`/`run`, create-vite dev/build, napi addons, child pipes |
| Python | 3.14.7 | E2E | `venv`, `pip`, asyncio, pyrepl, `mmap`, `subprocess` |
| Micro | 2.0.15 | E2E | Editing, resize, save, snapshots (`-clipboard internal`) |
| curl | 8.22.0 | E2E | HTTPS via guest ROOT store |
| opencode | 1.19.0 | E2E | `opencode_native` |
| ripgrep | 15.2.0 | E2E | `rg_native` (needs `WINRUN_RG_EXE`) |
| .NET / CoreCLR | fixture | E2E | `fetch-dotnet-fixture.sh` + `WINRUN_DOTNET_FIXTURE` |
| Bun | 1.4.3 | Packaged | `irm bun.sh/install.ps1\|iex` works (needs `curl`) |
| Deno / uv / fd / bat / fzf / gh / git / 7zip | [registry](registry.md) | Packaged | x64 + arm64 manifests |
| esbuild / biome | [registry](registry.md) | Packaged | Installed from npm tarballs |

## In-box tools (System32)

On every guest C:, checked against real-Windows oracles:

| Tool | Coverage |
|---|---|
| `cmd.exe` | `cmd /c`, batch files, pipes, redirection, `for`/`if`/`set`, delayed expansion |
| `tar.exe` | `-c/-x/-t`, `-f`, `-C`, `-z/-j/-a`, `--strip-components`, `--exclude` |
| `curl.exe` | Common flags, redirects, gzip/deflate, timeouts, curl exit codes |
| `where.exe` | `PATH`/`PATHEXT` lookup, `/Q /F /R` |
| `find` / `sort` / `more` | Standard flags incl. piped input |
| `taskkill.exe` | `/PID /IM /F /T`, guest process table |
| `powershell.exe` | `execFileSync('powershell.exe', …)` capture path Node uses |

## Shell coverage (PowerShell subset)

| Group | Covered |
|---|---|
| Files | Item + ChildItem (`-Recurse`, `-Filter`) + Content (`-Raw`, `-Head`, `-Tail`) |
| Text pipeline | Select-String, Sort, Unique, Measure, Out-File, Tee, Where/ForEach/Select |
| Utilities | Date, Random, Format/Table/List, Group, Json convert, Read-Host, Process |
| System | Registry (`HKLM:`/`HKCU:`), `Add-Type [DllImport]`, web requests, archives |

`Get-Command` / `Get-Help` in the shell are authoritative for your build;
`tests/oracle/*.ps1` checks behavior against real PowerShell.

## API areas implemented

| Area | Covered |
|---|---|
| Processes/threads | Job table (`taskkill`), descriptions, APCs, alertable waits |
| Files/pipes | Overlapped I/O, completion ports, locks, reparse points |
| Memory/sync | Virtual memory, mutexes, SRW/InitOnce, condition variables |
| Runtimes | UCRT surface, C++ EH/RTTI (`__CxxFrameHandler3`, `dynamic_cast`) |
| Network/crypto | Winsock (sync/async/events), cert chains vs guest ROOT store |
| Console/locale | Code pages, raw mode, NLS, manifest-aware versioning |
| Misc | Registry, resources, known folders, session clipboard/messages |

## Out of scope (by design)

GUI, games, drivers, services, remote desktop, desktop clipboard,
Update/Defender, domains, Hyper-V/WSL-in-guest, and **.NET Framework** exes.

## How to check a new binary

```bash
winrun inspect app.exe        # exit 0 = runnable, 1 = missing imports
WINRUN_NATIVE_STRICT_IMPORTS=1 winrun app.exe   # refuse before executing
```

Missing imports print as `DLL!API`, even through nested children and
redirected output. File an issue with those names — that list is the roadmap.
