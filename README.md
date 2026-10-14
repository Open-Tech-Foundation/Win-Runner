<div align="center">

# Win-Runner

***Run Windows command-line programs outside Windows.***

</div>

<div align="right">

*An [Open Tech Foundation](https://opentechf.org/) project*

</div>

> Win-Runner (`winrun`) runs Windows x86-64 command-line programs outside
> Windows through platform backends and Windows API shims, with a disposable
> C: drive, snapshots, a scriptable shell, package installs, host folder
> mounts, and a WebSocket control API. No Wine or VM is required.

| | |
|---|---|
| **Supported today** | `native-linux-x64`: Linux x86-64, guest code runs directly on the host CPU |
| **Planned** | Additional platform backends (see [Architecture](docs/architecture.md)) |
| **In progress** | Built-in security sandbox — not done, see [Threat model](docs/threat-model.md) |

> [!WARNING]
> Win-Runner is a compatibility runtime, not a security sandbox. Guest
> programs run natively with Win-Runner's OS privileges and can issue host
> system calls. Do not run untrusted binaries without OS-level isolation;
> see [Threat model](docs/threat-model.md) for container/`bwrap` recipes.

## Why Win-Runner?

Testing a Windows command-line program usually means a Windows machine, a VM, or a
paid CI runner. Wine can run it elsewhere, but it is built for desktop apps: a large
prefix to set up and reset, noisy logs, and quiet workarounds that can hide bugs.

Win-Runner is built for one job: **fast, repeatable, scriptable runs of Windows CLI
programs**, driven by people, CI pipelines, and coding agents.

- **Instant, clean state:** every run starts from a fresh in-memory C: drive or a
  saved snapshot. There is no prefix to create, copy, or clean up.
- **Native speed:** on the Linux x86-64 backend, x86-64 code runs directly on the
  host CPU; only Windows API calls go through compatibility shims.
- **Honest failures:** unsupported APIs are reported by name, and `winrun inspect`
  shows what a program needs before it runs. A missing feature fails loudly
  instead of silently changing behavior.
- **Built for automation:** `runner` (stdin jobs), the headless WebSocket control
  API (streams output, accepts input/key/resize, reports exit codes), and
  long-lived `instance`s let an agent build, run, and check Windows programs
  without a Windows machine.
- **One small binary:** a single executable with a shell, PowerShell-style
  scripts, and a manifest-based portable package manager.

Win-Runner does not aim to replace Wine. It targets command-line programs, not GUI
apps, games, drivers, or services. For those, use Wine or a real Windows machine.

## Requirements

| | |
|---|---|
| **Host (today)** | Linux x86-64 (the only backend shipped in releases so far) |
| **Guest** | Windows x86-64 (PE32+) console programs |
| **Privileges** | None beyond normal user access to the paths you mount |
| **Not required** | Wine, Windows, a VM, or a separate package manager |

Network access is only needed when you download packages with `wpkg` or call out
to HTTP from the guest.

## Installation

### Install (copy and paste)

Linux x86-64 only. Needs `curl` and `sha256sum`.

```bash
curl -fsSL https://raw.githubusercontent.com/Open-Tech-Foundation/Win-Runner/main/scripts/install.sh | bash
```

Installs `winrun` onto your `PATH` (no service; no admin step unless the prefix needs it).

### Install options

```bash
# From a clone of this repository
./scripts/install.sh
```

```bash
# Pin a version and choose where it goes
./scripts/install.sh --version v0.2.0 --prefix "$HOME/.local/bin"
```

```bash
# See what it would do without downloading
./scripts/install.sh --dry-run
```

| Flag / env | Meaning |
|---|---|
| `--version TAG` / `WINRUN_VERSION` | Release tag (default `v0.2.0`) |
| `--prefix DIR` / `WINRUN_PREFIX` | Install directory (default `/usr/local/bin` if writable, else `~/.local/bin`) |
| `--dry-run` | Print the plan only |

### Download a release manually

Prebuilt binaries are on the [GitHub Releases](https://github.com/Open-Tech-Foundation/Win-Runner/releases)
page. Each release ships a Linux x86-64 `winrun` binary in a tarball plus a
`checksums.txt` file.

```bash
VERSION=v0.2.0
curl -fsSLO "https://github.com/Open-Tech-Foundation/Win-Runner/releases/download/${VERSION}/winrun-win-runner.tar.gz"
curl -fsSLO "https://github.com/Open-Tech-Foundation/Win-Runner/releases/download/${VERSION}/checksums.txt"
sha256sum -c checksums.txt
tar -xzf winrun-win-runner.tar.gz
sudo install -m 755 winrun /usr/local/bin/winrun
```

```bash
# or install into your home directory without sudo
install -m 755 winrun "$HOME/.local/bin/winrun"
```

The archive contains only the `winrun` binary (stripped). License text lives
in the repository (`LICENSE`, `NOTICE`); release assets are checksummed, and
the release workflow attaches build provenance when published from CI.

### Build from source

Requires a stable Rust toolchain with Cargo (edition 2021).

```bash
git clone https://github.com/Open-Tech-Foundation/Win-Runner.git
cd Win-Runner
cargo build --release
sudo install -m 755 target/release/winrun /usr/local/bin/winrun
```

```bash
# without installing system-wide
export PATH="$PWD/target/release:$PATH"
```

Offline builds work with a warm Cargo cache: `cargo build --release --offline`.

### Verify the install

```bash
which winrun
winrun --version
winrun inspect path/to/app.exe
winrun shell
```

`winrun` with no arguments prints usage and exits 2. If `winrun` is not found,
add the install directory to `PATH`, for example:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Quickstart

```bash
# 1. Open a clean, disposable Windows-like shell
winrun shell
```

```powershell
# Inside the shell: install Node.js and run it — no Windows machine needed
wpkg install nodejs
node -v
node -e "console.log('hello from Windows node')"
exit
```

```bash
# 2. Keep your tools between runs with a snapshot
winrun --snapshot=tools.winfs --save shell
```

```bash
# 3. Run one guest command headlessly (CI / agent style)
winrun --snapshot=tools.winfs "C:\Program Files\nodejs\current\node.exe" -e "console.log(1+1)"
```

```bash
# 4. Check compatibility before running
winrun inspect app.exe
```

## How to use

| Goal | Command |
|---|---|
| Interactive shell | `winrun shell` |
| Show help / version | `winrun --help`, `winrun --version` |
| Run a Windows EXE from a host path | `winrun path/to/app.exe [args…]` |
| Run a PowerShell-style script | `winrun path/to/script.ps1 [args…]` (binds to `param(...)` or `$args`) |
| Inspect PE imports before running | `winrun inspect path/to/app.exe` |
| Persistent C: between runs | `winrun --snapshot=tools.winfs --save shell` |
| Save to a new snapshot file | `winrun --save-snapshot=new.winfs shell` |
| Mount a host folder as guest `Z:` | `winrun --mount=Z:/path/to/folder shell` |
| Read-only mount | `winrun --mount-ro=Z:/path/to/folder shell` |
| Guest memory (default 512M) | `winrun --memory=8G shell` (or `WINRUN_MEMORY=8G`) |
| Headless / agent control | `winrun --headless --control=127.0.0.1:0 shell` |
| Scripted batch jobs | `winrun runner` (commands on stdin) |
| Long-lived named instance | `winrun instance boot <name>` then `instance exec` / `status` / `destroy` |

Runtime flags (`--snapshot`, `--mount`, `--headless`, …) must appear **before**
the program target. Everything after the target is passed to the guest program,
even if it looks like a Win-Runner option. Use `--` to separate unambiguously:

```bash
winrun --snapshot=tools.winfs -- "C:\Program Files\nodejs\current\node.exe" --mount=not-a-flag
```

Exit codes: `0` success; `2` usage error; `1` runtime error (including
`inspect` reporting missing imports and "nothing to run"); otherwise the guest
program's own exit code. A crashing guest exits with its Windows exception code
(e.g. `0xC0000005` for an access violation) and a note on stderr.

### Automation for agents and CI

Three surfaces, pick by lifetime:

```bash
# Short jobs: pipe commands, read output, check exit code.
# Prefer single-quoted literals and ConvertTo-Json for machine-readable output.
printf '%s\n' "Write-Output '{\"ok\":true}'" 'exit' | winrun runner
printf '%s\n' '$o = @{a=1}; $o | ConvertTo-Json -Compress' 'exit' | winrun runner
```

Per-command status inside `runner` is explicit — emit it yourself:

```powershell
npm test
Write-Output "__EXIT:$LASTEXITCODE"
exit
```

```bash
# Interactive agents: headless shell with a WebSocket control endpoint.
winrun --headless --control=127.0.0.1:0 shell
# Prints one JSON line: {"event":"ready","protocol":1,"url":"ws://127.0.0.1:PORT/control/<token>"}
# See docs/control-protocol.md for input ops (write, key, resize) and output events.
```

```bash
# Long-lived state across many commands:
winrun instance boot ci
winrun instance exec ci -- Write-Output 'hello-from-instance'
winrun instance status ci
winrun instance destroy ci
```

Agent tips:

- Prefer `runner` / headless / `instance` over bare interactive `shell`, which
  can block on prompts (e.g. installers asking questions).
- Use `winrun inspect` first for unknown binaries; missing `DLL!API` names tell
  you exactly what is unsupported.
- Mounts are silent on boot — confirm with `dir Z:`.
- `--save` writes back only on clean exit; run `snapshot save` inside the shell
  to checkpoint sooner. A killed session can lose trailing changes.

## Guest state

Each new run gets a disposable C: drive laid out like a stock Windows installation, signed in as the user `runner` on the computer `WINRUNNER`. The shell starts in the profile directory `C:\Users\runner`.

| Folder | Path |
|---|---|
| `%USERPROFILE%`, `$HOME` | `C:\Users\runner` |
| `%APPDATA%` / `%LOCALAPPDATA%` | `C:\Users\runner\AppData\Roaming` / `...\Local` |
| `%TEMP%`, `%TMP%` | `C:\Users\runner\AppData\Local\Temp` |
| `%ProgramFiles%` / `%ProgramData%` | `C:\Program Files` / `C:\ProgramData` |
| `%SystemRoot%` | `C:\Windows` |

The standard Windows environment variables (`PATH`, `PATHEXT`, `ComSpec`, `COMPUTERNAME`, `ProgramFiles(x86)`, and so on) are set, and the Windows folder APIs (`SHGetFolderPath`, `GetUserProfileDirectory`, `GetTempPath`, `GetComputerName`) report the same locations, so tools such as npm find their usual folders. `$env:` and `[Environment]` in PowerShell read and change this guest environment, never the host's.

Each disk also has a Windows registry, stored in WinFS so snapshots keep it (`HKLM` in `C:\Windows\System32\config\machine.json`, `HKCU` in `C:\Users\runner\NTUSER.json`). As on Windows, a new session builds its environment from the registry's machine and user `Environment` keys, and programs can use the `Reg*` APIs.

```text
setx EDITOR vim                    # user variable for sessions started later
setx JAVA_HOME C:\jdk /M           # machine variable
[Environment]::SetEnvironmentVariable('EDITOR', 'vim', 'User')
reg query HKCU\Environment
reg add HKCU\Software\Vendor /v Mode /t REG_DWORD /d 3
reg delete HKCU\Software\Vendor /f
```

`set` and `$env:NAME = value` change only the current session; `setx`, `reg`, and the `User`/`Machine` targets persist and apply from the next session, as on Windows. Where Windows `reg` would prompt before overwriting or deleting, add `/f`.

Run `reload` to apply saved environment changes, including PATH, immediately:

```text
reload
node --version
```

`reload` rebuilds the environment from the guest registry and restores the active
Node/npm command paths. It replaces temporary environment overrides while keeping
shell variables, functions, the current directory, and files.

Use a WinFS snapshot to keep files and installed programs between runs.

```bash
winrun --snapshot=tools.winfs --save shell
```

`--save` writes changes back to the loaded snapshot when the shell exits; run `snapshot save` inside the shell to save sooner.
Snapshots are indexed, seekable WinFS disks and contain C: only.
While a session runs, each file a program writes lives in its own file in a session directory under the temp directory (`$TMPDIR`, default `/tmp`), shared by all of the session's guest processes. A write costs only what it writes, and deleting a file frees its space. The session directory is removed when `winrun` exits; one left by a killed instance is removed the next time `winrun` starts.
Explicitly mounted host directories appear as separate guest drives (for example, Z:).

## Shell and packages

The interactive shell implements a PowerShell subset. `Get-Command` lists
implemented commands and guest programs on PATH; `Get-Alias` lists aliases,
and `Get-Help Rename-Item` shows the supported syntax. These commands also
appear in tab completion.

Everyday file commands include `New-Item`, `Get-Item`, `Get-ChildItem`,
`Copy-Item`, `Move-Item`, `Rename-Item`, `Remove-Item`, `Test-Path`,
`Get-Content`, `Set-Content`, `Add-Content`, and `Clear-Content`.
`Rename-Item test.js test.mjs` renames a file in its existing directory;
`-Force` never replaces a destination during rename. Use `Resolve-Path`,
`Split-Path`, `Join-Path`, and the location commands for navigation.

Utility cmdlets include `Get-Date` (with .NET `-Format` strings), `Get-Random`,
`Out-String`, `Format-Table`/`Format-List`, `Group-Object`, `ConvertTo-Json`
(`-Depth`, `-Compress`), `ConvertFrom-Json`, `Read-Host`, `Get-Process` (this
session's guest processes), `Start-Process` (runs to completion),
`Get-ItemPropertyValue`, `Select-String`, `Sort-Object`, `Get-Unique`,
`Measure-Object`, `Out-File`, and `Tee-Object`.

Scripts support `param(...)` blocks (bound by name or position, with defaults;
remaining args land in `$args`), functions, `return`, `try`/`catch` (with `$_`
as an error record), here-strings, backtick escapes, casts, and the
`HKLM:`/`HKCU:` registry provider. They run programs with
`& "C:\path\app.exe" args` or by name on the `PATH`, read `$LASTEXITCODE`,
and capture program output with `$(...)`. `Add-Type` accepts
`[DllImport]` declarations for the Win32 calls installers make.
Pipelines carry text rather than full PowerShell objects; advanced
providers, administration cmdlets, and unimplemented parameters remain
unsupported. This shell is not a complete PowerShell distribution.

The shell includes `wpkg`, which installs SHA-256-verified ZIP and 7z packages into the guest C: drive without running installers or package scripts. Its text registry is bundled in the binary; package archives download only when installed.

For a terminal text editor, install the Windows build of Micro:

```powershell
wpkg install micro
micro -clipboard internal notes.txt
```

Use Ctrl-S to save and Ctrl-Q to quit. Micro edits files in the guest drive,
including files restored from snapshots. The `internal` clipboard setting
keeps copy and paste inside the editor; the guest has no desktop clipboard.

```text
wpkg search <query> | info <package[@version]>
wpkg install <package[@version]> | list [package] | default <package> [version]
wpkg upgrade [package] | remove <package[@version]>
wpkg cache | cache clean [package]
```

Versions install side by side under `C:\Program Files\<package>\<version>`. The first version installed becomes the default; `C:\Program Files\<package>\current` links to the default, and each command in `C:\ProgramData\wpkg\bin` (on the `PATH`) links through it. Verified archives stay in `C:\ProgramData\wpkg\cache`, so reinstalling a version (for example after `remove`) needs no download; the cache is part of the disk and its snapshots, and `wpkg cache clean` empties it. Verified archives are also kept on the host, named by their SHA-256, in `$XDG_CACHE_HOME/winrun/wpkg` (`~/.cache/winrun/wpkg` by default, or `$WINRUN_CACHE_DIR/wpkg`), so a new session installs a package it has downloaded before without downloading it again; each copy is checked against the manifest's SHA-256 before use. On a terminal, downloads show a progress bar with the size and speed. Package state lives in `C:\ProgramData\wpkg`, and each installed version is listed under the registry's installed-programs key (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\wpkg-<package>-<version>`). `@26` selects the newest `26.x` release, and `wpkg default nodejs 26` switches every Node.js command to it. `upgrade` installs the latest release beside the existing ones and moves the default only when it was already on the newest version.

```text
wpkg install nodejs          # latest; becomes the default
wpkg install nodejs@26       # side by side; the default is unchanged
wpkg list nodejs             # * marks the default
wpkg default nodejs 26
wpkg remove nodejs@24        # one version; `remove nodejs` removes all
```

### cmd.exe for programs that shell out

The shell you type into is PowerShell-style, but many programs start `%ComSpec%` themselves: Node's `child_process` with `shell: true`, `npm run`, Python's `subprocess(shell=True)`, and the `.cmd` launchers that npm and pip install. For those, the disk has `C:\Windows\System32\cmd.exe`, a narrow command processor that runs as a real child process. It supports `cmd /c` and `/d /s /c`, `&`, `&&`, `||`, `( )` blocks, `>`, `>>`, `2>&1`, `<` and `nul` redirection, `%VAR%` expansion (including `:a=b` and `:~n,m`), and batch files with `%1`, `%*`, `%~dp0`, labels, `goto`, `call`, `exit /b`, `setlocal`, `if`, `for`, and `for /f` over command output. It also handles `set /a` arithmetic, `set /p` from redirected or piped input, pipes (the left side runs to completion first, then feeds the right side), and delayed `!var!` expansion with `setlocal enabledelayedexpansion` or `cmd /v:on`. There is no interactive cmd prompt. As on Windows, starting a `.bat` or `.cmd` file with `CreateProcess` runs it through cmd.exe, and typing a command in the shell looks it up through `PATH` and `PATHEXT`, so `tsc` runs npm's `tsc.cmd` launcher.

## Compatibility

Win-Runner implements the Windows APIs its supported programs need, incrementally.
`winrun inspect app.exe` reports static imports with supported/missing verdicts
(exit `0` = runnable, `1` = missing), and `WINRUN_NATIVE_STRICT_IMPORTS=1`
rejects missing imports before execution. At runtime, an unsupported API call
fails loudly naming the executable, DLL, and API — including through nested
child processes and redirected output.

What runs today, with pinned versions and evidence, lives in
[docs/compatibility.md](docs/compatibility.md):

| Tool | Pinned version | Status |
|---|---|---|
| Node.js (+ npm, npx, corepack) | 24.21.0 / npm 11.19.0 | E2E covered (`node_native`, incl. `npm install`, create-vite dev/build) |
| Python | 3.14.7 | E2E covered (`venv`, `pip`, asyncio, pyrepl REPL) |
| Micro editor | 2.0.15 | E2E covered (Unicode editing, resize, save, snapshots) |
| curl (official Windows build) | 8.22.0 | E2E covered (HTTPS via guest ROOT store) |
| opencode (Bun executable) | 1.19.0 | E2E covered (`opencode_native`) |
| ripgrep | 15.2.0 | E2E covered (`rg_native`, fixture) |
| .NET / CoreCLR | fixture via `scripts/fetch-dotnet-fixture.sh` | E2E covered (`dotnet_native`, fixture) |
| Bun / Deno / esbuild / biome / uv / fd / bat / fzf / gh / 7zip / git | see table | Packaged in `wpkg` (SHA-256 pinned); Bun+Deno+esbuild+biome exercised via installer paths |

Out of scope by design: GUI apps, games, drivers, services, and .NET Framework
executables. See [docs/compatibility.md](docs/compatibility.md) for the full
table, and [docs/differences-from-windows.md](docs/differences-from-windows.md)
for intentional behavior differences.

## Security

Win-Runner is **not** a sandbox. See [docs/threat-model.md](docs/threat-model.md) for:

- the threat model (what the runtime does and does not protect),
- supply-chain notes (`wpkg` SHA-256 verification, pinned Mozilla roots),
- copy-paste `bwrap` and container recipes for running untrusted binaries,
- control-listener notes (loopback-only, per-session token).

## Differences from real Windows

Short version: CLI surface only; PowerShell and `cmd.exe` subsets (text
pipelines, no GUI/admin/service cmdlets); guest C: is case-insensitive;
network goes through the host stack verified against the guest ROOT store;
memory size, CPU identity, and clock come from the host (memory size is
configurable). Details: [docs/differences-from-windows.md](docs/differences-from-windows.md).

## Architecture

How a PE gets from disk to exit code: PE parsing and mapping at the preferred
base, import resolution to native trampolines, TEB/PEB and exception handling,
exec-worker child processes, and the WinFS snapshot filesystem. Start at
[docs/architecture.md](docs/architecture.md) — it names the modules so
contributors and reviewers can judge soundness.

## Further docs

| Doc | Contents |
|---|---|
| [docs/compatibility.md](docs/compatibility.md) | Tested tools and versions, API coverage, out-of-scope list |
| [docs/threat-model.md](docs/threat-model.md) | Threat model + `bwrap`/container recipes until the sandbox lands |
| [docs/differences-from-windows.md](docs/differences-from-windows.md) | Intentional behavior differences vs real Windows |
| [docs/architecture.md](docs/architecture.md) | PE loading, API shims, child processes, WinFS |
| [docs/control-protocol.md](docs/control-protocol.md) | Headless WebSocket protocol for agents |

## Development

Run the test suite with `cargo test --offline`; native changes should also be exercised with real Windows binaries or E2E fixtures.

See [CHANGELOG.md](CHANGELOG.md) for release notes and [COMPATIBILITY_BACKLOG.md](COMPATIBILITY_BACKLOG.md) for tracked compatibility work.

Fixture-dependent tests are reported as **ignored** in the default suite. Run
these explicitly with their fixture environment variables and `-- --ignored`;
missing fixtures then fail instead of reporting a pass. For example:

```bash
WINRUN_NODE_EXE=/path/to/node.exe WINRUN_NPM_ROOT=/path/to/node_modules/npm \
  WINRUN_TEST_LIVE_NPM=1 cargo test --test node_native -- --ignored
bash scripts/fetch-dotnet-fixture.sh
WINRUN_DOTNET_FIXTURE=target/dotnet-fixture cargo test --test dotnet_native -- --ignored
WINRUN_RG_EXE=/path/to/rg.exe cargo test --test rg_native -- --ignored
```

CI runs the default suite plus dedicated Node/npm and CoreCLR fixture jobs.

## License

Licensed under the [Apache License, Version 2.0](LICENSE); see [NOTICE](NOTICE).
