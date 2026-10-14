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
writing. Install with `wpkg install <name>` (or `wpkg install <name>@<major>`).

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

File cmdlets (`New/Get/Copy/Move/Rename/Remove/Test-Item`, `Get-ChildItem`
with `-Recurse/-Filter`, `Get/Set/Add/Clear-Content` with `-Raw/-Head/-Tail`),
text pipeline (`Select-String`, `Sort-Object`, `Get-Unique`, `Measure-Object`,
`Out-File`, `Tee-Object`, `Where/ForEach/Select-Object`), utilities
(`Get-Date`, `Get-Random`, `Out-String`, `Format-Table/List`, `Group-Object`,
`ConvertTo/From-Json`, `Read-Host`, `Get-Process`, `Start-Process`,
`Get-ItemPropertyValue`), registry provider (`HKLM:`/`HKCU:`), `Add-Type`
`[DllImport]`, `Invoke-RestMethod`/`Invoke-WebRequest`, `Expand-Archive`.
`Get-Command` / `Get-Help` inside the shell are authoritative for the build
you run. Oracle scripts in `tests/oracle/*.ps1` compare behavior against real
Windows PowerShell.

## API areas implemented

Kernel/process/threads (incl. `taskkill` process table, thread descriptions,
APCs, alertable waits), file I/O (incl. overlapped I/O, completion ports,
locks, reparse points, pipes), memory/virtual memory, synchronization (mutexes,
SRW, InitOnce, condition variables), CRT/UCRT surface CPython and MSVC programs
need, C++ EH/RTTI (`__CxxFrameHandler3`, `dynamic_cast`), Winsock (blocking,
non-blocking, overlapped, events, multicast/TTL options), CryptoAPI/Cert chain
building against the guest ROOT store, NLS/locale, console (code pages, raw
mode, scroll regions), clipboard (session-local formats), messages/queues,
`GetVersionEx` manifest-aware versioning, PE resources, known folders.

## Out of scope (by design)

GUI apps and windows, games, drivers, Windows services, remote desktop,
interactive `cmd` prompt, desktop clipboard, Windows Update / Defender,
domain-join / Group Policy, Hyper-V / WSL-in-guest, and **.NET Framework**
executables (reported as a loader limitation by `winrun inspect`).

## How to check a new binary

```bash
winrun inspect app.exe        # exit 0 = runnable, 1 = missing imports
WINRUN_NATIVE_STRICT_IMPORTS=1 winrun app.exe   # refuse before executing
```

Missing imports print as `DLL!API` (executable, DLL, and API name), including
through nested child processes and redirected output. File an issue with the
missing names — that list is the compatibility roadmap. Tracked work lives in
`COMPATIBILITY_BACKLOG.md`.
