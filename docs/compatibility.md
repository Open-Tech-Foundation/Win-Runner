# Compatibility: what works today

Win-Runner implements Windows APIs incrementally, driven by real programs.
This page records what is verified working, with pinned versions and the
evidence behind each claim. Anything not listed here should be checked with
`winrun inspect` before you depend on it.

Status levels:

| Status | Meaning |
|---|---|
| **E2E covered** | Automated end-to-end tests run the real Windows binary under Win-Runner |
| **Packaged** | A SHA-256-pinned `wpkg` manifest exists; no dedicated E2E test yet |
| **In-box** | Implemented inside Win-Runner itself (shell built-ins, System32 tools) |

## Tested tools and versions

These are the `latest` pins in `registry/packages/*/latest` at the time of
writing. Install with `wpkg install <name>` (or `wpkg install <name>@<major>`);
see [registry.md](registry.md) for the full package list.

| Tool | Pinned version | Status | Notes / evidence |
|---|---|---|---|
| Node.js | 24.21.0 (npm 11.19.0, plus npx, corepack) | E2E covered | `tests/node_native.rs`, `tests/choco_node.rs`; `npm install`, `npm run`, create-vite dev/build, native addons (napi-rs / rolldown), child-process pipes |
| Python (CPython, python.org NuGet dist) | 3.14.7 | E2E covered | `venv`, `pip` (via truststore + cert chain), asyncio/proactor, pyrepl REPL, `os.chmod`, `mmap`, `subprocess` |
| Micro editor | 2.0.15 (Windows x64) | E2E covered | `tests/micro_native.rs`; Unicode editing, resize, save/quit, snapshot persistence; use `micro -clipboard internal` |
| curl (official Windows build) | 8.22.0 | E2E covered | `tests/curl_native.rs`, `tests/system_curl.rs`; HTTPS verified against the guest ROOT store |
| opencode (Bun executable) | 1.19.0 | E2E covered | `tests/opencode_native.rs` |
| ripgrep | 15.2.0 | E2E covered | `tests/rg_native.rs` (needs `WINRUN_RG_EXE` fixture) |
| .NET / CoreCLR | fixture (see below) | E2E covered | `tests/dotnet_native.rs`; fetch with `bash scripts/fetch-dotnet-fixture.sh`, run with `WINRUN_DOTNET_FIXTURE=target/dotnet-fixture` |
| Bun | 1.4.3 | Packaged (+ installer path exercised) | `powershell -c "irm bun.sh/install.ps1 \| iex"` works; needs `wpkg install curl` for its download step |
| Deno | 2.9.7 | Packaged | x64 and arm64 manifests |
| esbuild | 0.28.2 | Packaged | Installed from npm tarballs (`wpkg install esbuild`) |
| biome | 2.5.15 | Packaged | Installed from npm platform packages |
| uv | 0.13.0 | Packaged | x64 and arm64 manifests |
| fd | 10.5.0 | Packaged | x64 and arm64 manifests |
| bat | 0.26.1 | Packaged | x64 and arm64 manifests |
| fzf | 0.74.5 | Packaged | x64 and arm64 manifests |
| GitHub CLI (`gh`) | 2.102.0 | Packaged | x64 and arm64 manifests |
| git (MinGit) | 2.55.0.2 | Packaged | x64 and arm64 manifests |
| 7-Zip CLI (7za) | 26.03 | Packaged | x64 standalone CLI from the official Extra archive |

ARM64 manifests are included where upstream publishes them, for future hosts;
today's releases execute on Linux x86-64.

## In-box tools (System32)

Shipped on every guest C: drive, tested against real-Windows oracles:

| Tool | Coverage |
|---|---|
| `cmd.exe` | `cmd /c`, batch files, pipes, redirection, `for`/`if`/`set`, delayed expansion; `tests/cmd_file_builtins.rs` |
| `tar.exe` (bsdtar CLI) | `-c/-x/-t`, `-f`, `-C`, `-z/-j/-a`, `--strip-components`, `--exclude`; `tests/system_tar.rs` |
| `curl.exe` (built-in) | Common flags, redirects, gzip/deflate, timeouts, curl exit codes; `tests/system_curl.rs` |
| `where.exe` | `PATH`/`PATHEXT` lookup, `/Q /F /R`; `tests/system_where.rs` |
| `find.exe`, `sort.exe`, `more.com` | Standard flags incl. piped input |
| `taskkill.exe` | `/PID /IM /F /T`, guest process table |
| `powershell.exe` launcher | `execFileSync('powershell.exe', …)` capture path used by Node |

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
