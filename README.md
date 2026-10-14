<div align="center">

# Win-Runner

***Run Windows command-line programs outside Windows.***

</div>

<div align="right">

*An [Open Tech Foundation](https://opentechf.org/) project*

</div>

> Win-Runner (`winrun`) runs Windows x86-64 CLI programs outside Windows via platform
> backends and API shims — disposable C:, snapshots, scriptable shell, packages,
> mounts, WebSocket control. No Wine or VM.

| | |
|---|---|
| **Supported today** | `native-linux-x64`: Linux x86-64, guest code runs directly on the host CPU |
| **Planned** | Additional platform backends (see [Architecture](docs/architecture.md)) |
| **In progress** | Built-in security sandbox — not done, see [Threat model](docs/threat-model.md) |

> [!WARNING]
> Win-Runner is a compatibility runtime, not a security sandbox. Guest
> programs run natively with Win-Runner's OS privileges and can issue host
> system calls. Isolate untrusted binaries — see [Threat model](docs/threat-model.md).

## Why Win-Runner?

Testing a Windows CLI program usually means a Windows box, a VM, or paid CI. Wine
works but targets desktop apps: heavy prefixes, noisy logs, silent workarounds.

Win-Runner does one job: **fast, repeatable, scriptable runs of Windows CLI programs** —
for people, CI, and coding agents. Not GUI, games, drivers, or services.

- **Instant, clean state:** fresh in-memory C: or saved snapshot per run. No prefix to manage.
- **Native speed:** guest code runs on the host CPU; only API calls hit shims.
- **Honest failures:** missing APIs fail loudly by name; `winrun inspect` lists them upfront.
- **Built for automation:** `runner` jobs, headless WebSocket control, and `instance`s for agents.
- **One small binary:** shell, PowerShell-style scripts, and package manager included.

## Requirements

| | |
|---|---|
| **Host (today)** | Linux x86-64 (the only backend shipped in releases so far) |
| **Guest** | Windows x86-64 (PE32+) console programs |
| **Privileges** | None beyond normal user access to the paths you mount |
| **Not required** | Wine, Windows, a VM, or a separate package manager |

Network is needed only to download `wpkg` packages or call out to HTTP from the guest.

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

Prebuilt Linux x86-64 binaries are on [GitHub Releases](https://github.com/Open-Tech-Foundation/Win-Runner/releases).
Each ships the `winrun` tarball plus `checksums.txt`.

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

The archive holds only the stripped `winrun` binary (license in `LICENSE`/`NOTICE`).
Assets are checksummed, with CI build provenance on release builds.

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

`winrun` with no arguments prints usage and exits 2. If not found, add the install dir to `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Upgrading

```bash
winrun upgrade                    # latest release over this binary
winrun upgrade --check            # show latest vs current; change nothing
winrun upgrade --dry-run          # show what would happen; change nothing
winrun upgrade --version v0.2.0   # pin a tag (or set WINRUN_VERSION)
```

Verifies SHA-256, smoke-checks the new binary, replaces atomically. No-op when current.
Needs write access to the binary's dir (else `sudo`, or `install.sh --prefix`).

## Quickstart

```bash
# 1. Open a clean, disposable Windows-like shell
winrun shell
```

```powershell
# Inside: install Node.js and run it — no Windows machine needed
wpkg install nodejs
node -v
node -e "console.log('hello from Windows node')"
exit
```

```bash
# 2. Keep tools between runs with a snapshot
winrun --snapshot=tools.winfs --save shell
```

```bash
# 3. One guest command, headless (CI / agent style)
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
| Self-update to latest release | `winrun upgrade [--version TAG] [--check] [--dry-run]` |
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

Runtime flags (`--snapshot`, `--mount`, `--headless`, …) go **before** the target.
Everything after belongs to the guest, even if flag-like. Use `--` to separate:

```bash
winrun --snapshot=tools.winfs -- "C:\Program Files\nodejs\current\node.exe" --mount=not-a-flag
```

| Code | Meaning |
|---|---|
| `0` | Success (or already current, for `upgrade`) |
| `1` | Runtime error, `inspect` missing imports, or "nothing to run" |
| `2` | Usage error |
| other | Guest's own exit code (crash → Windows exception code + stderr note) |

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

- Prefer `runner` / headless / `instance` — bare `shell` can block on prompts.
- `inspect` unknown binaries first; missing `DLL!API` names are the full answer.
- Mounts are silent on boot — confirm with `dir Z:`.
- `--save` writes back only on clean exit; `snapshot save` checkpoints sooner.

## Guest state

Each run gets a disposable C: like a stock Windows install, as user `runner` on `WINRUNNER`.
The shell starts in `C:\Users\runner`.

| Folder | Path |
|---|---|
| `%USERPROFILE%`, `$HOME` | `C:\Users\runner` |
| `%APPDATA%` / `%LOCALAPPDATA%` | `C:\Users\runner\AppData\Roaming` / `...\Local` |
| `%TEMP%`, `%TMP%` | `C:\Users\runner\AppData\Local\Temp` |
| `%ProgramFiles%` / `%ProgramData%` | `C:\Program Files` / `C:\ProgramData` |
| `%SystemRoot%` | `C:\Windows` |

Standard variables (`PATH`, `PATHEXT`, `ComSpec`, …) and folder APIs report guest locations,
so tools like npm find their folders. `$env:` / `[Environment]` touch the guest env only.

Each disk has a registry (`HKLM` → `C:\Windows\System32\config\machine.json`,
`HKCU` → `C:\Users\runner\NTUSER.json`); sessions build their env from it, like Windows.

```text
setx EDITOR vim                    # user variable for sessions started later
setx JAVA_HOME C:\jdk /M           # machine variable
[Environment]::SetEnvironmentVariable('EDITOR', 'vim', 'User')
reg query HKCU\Environment
reg add HKCU\Software\Vendor /v Mode /t REG_DWORD /d 3
reg delete HKCU\Software\Vendor /f
```

`set` / `$env:` affect this session only; `setx`, `reg`, and `User`/`Machine` targets persist
for later sessions. Add `/f` where Windows `reg` would prompt.

`reload` applies saved env changes (incl. PATH) now, keeping shell state and files:

```text
reload
node --version
```

Keep files and programs between runs with a snapshot:

```bash
winrun --snapshot=tools.winfs --save shell
```

`--save` writes back on exit (`snapshot save` checkpoints sooner). Snapshots hold C: only.
Session writes live as one host file each under `$TMPDIR` (default `/tmp`), shared by all guest
processes; the dir is removed on exit (leftovers from kills are swept at next start).
Host mounts appear as extra drives (e.g. Z:).

## Shell and packages

PowerShell subset. `Get-Command` / `Get-Alias` / `Get-Help` list what's implemented
(also in tab completion) — authoritative for your build.

| Group | Covered |
|---|---|
| Files | Item + ChildItem (`-Recurse`, `-Filter`) + Content (`-Raw`, `-Head`, `-Tail`); path + location helpers |
| Text pipeline | Select-String, Sort, Unique, Measure, Out-File, Tee, Where/ForEach/Select |
| Utilities | Date (`-Format`), Random, Format/Table/List, Group, Json convert, Read-Host, Process |
| System | Registry (`HKLM:`/`HKCU:`), `Add-Type [DllImport]`, web requests, archives |

Scripts take `param(...)` (by name/position, rest in `$args`): functions, `return`,
`try`/`catch` (`$_` is the error), `& exe` runs, `$LASTEXITCODE`, `$(...)` capture.
Pipelines carry text, not .NET objects; admin cmdlets and unimplemented flags stay out.

`wpkg` installs SHA-256-verified ZIP/7z packages into C: without running installers.
Its registry ships in the binary; archives download on demand. Full list: [registry](docs/registry.md).

```powershell
wpkg install micro
micro -clipboard internal notes.txt   # Ctrl-S saves, Ctrl-Q quits; no desktop clipboard
```

```text
wpkg search <query> | info <package[@version]>
wpkg install <package[@version]> | list [package] | default <package> [version]
wpkg upgrade [package] | remove <package[@version]>
wpkg cache | cache clean [package]
```

| | |
|---|---|
| Layout | `C:\Program Files\<pkg>\<ver>` side by side; `current` → default; bin dir on PATH |
| Cache | Guest `…\wpkg\cache` + host `~/.cache/winrun/wpkg`; SHA-256 verified, reused |
| Versions | `@26` = newest `26.x`; `default` switches; `upgrade` moves default only if it tracked newest |
| State | `C:\ProgramData\wpkg` + one uninstall key per version |

```text
wpkg install nodejs          # latest; becomes the default
wpkg install nodejs@26       # side by side; the default is unchanged
wpkg list nodejs             # * marks the default
wpkg default nodejs 26
wpkg remove nodejs@24        # one version; `remove nodejs` removes all
```

### cmd.exe for programs that shell out

The shell is PowerShell-style, but shelling-out programs (`child_process shell:true`,
`npm run`, `subprocess(shell=True)`, `.cmd` launchers) get `C:\Windows\System32\cmd.exe`
as a real child process: `cmd /c`, batch files, pipes, redirection, `%VAR%`,
`for`/`if`/`set`, delayed expansion. No interactive prompt. `.bat`/`.cmd` run through
it via `CreateProcess`; lookup uses `PATH`+`PATHEXT` (so `tsc` runs `tsc.cmd`).

## Compatibility

APIs are added per program. `inspect` gives supported/missing verdicts (exit 0/1);
`WINRUN_NATIVE_STRICT_IMPORTS=1` refuses upfront. Runtime misses fail loudly as
`executable: DLL!API`, even through nested children and redirected output.

Pinned versions with evidence ([full table](docs/compatibility.md)):

| Tool | Pinned version | Status |
|---|---|---|
| Node.js (+ npm, npx, corepack) | 24.21.0 / npm 11.19.0 | E2E (`npm install`, create-vite dev/build) |
| Python | 3.14.7 | E2E (`venv`, `pip`, asyncio, pyrepl) |
| Micro editor | 2.0.15 | E2E (edit, resize, save, snapshots) |
| curl (Windows build) | 8.22.0 | E2E (HTTPS via guest ROOT store) |
| opencode | 1.19.0 | E2E (`opencode_native`) |
| ripgrep | 15.2.0 | E2E (`rg_native`, fixture) |
| .NET / CoreCLR | fixture (`scripts/fetch-dotnet-fixture.sh`) | E2E (`dotnet_native`) |
| Bun / Deno / esbuild / biome / uv / fd / bat / fzf / gh / 7zip / git | [registry](docs/registry.md) | Packaged, SHA-256 pinned |

Out of scope: GUI, games, drivers, services, .NET Framework exes.
Behavior deltas: [differences](docs/differences-from-windows.md).

## Security

Win-Runner is **not** a sandbox. See [threat model](docs/threat-model.md):

- What the runtime does and does not protect.
- Supply chain (`wpkg` SHA-256, pinned Mozilla roots).
- `bwrap` / container recipes for untrusted binaries.
- Control listener (loopback-only, per-session token).

## Differences from real Windows

CLI surface only; PowerShell/`cmd` subsets with text pipelines; case-insensitive C:;
host-stack networking against the guest ROOT store; host CPU/clock, configurable
memory size. Details: [differences](docs/differences-from-windows.md).

## Architecture

PE parse → map at preferred base → imports to native trampolines → run on CPU;
exec-worker children; WinFS snapshot filesystem. Module map for reviewers:
[architecture](docs/architecture.md).

## Further docs

| Doc | Contents |
|---|---|
| [docs/compatibility.md](docs/compatibility.md) | Tested tools and versions, API coverage, out-of-scope list |
| [docs/registry.md](docs/registry.md) | `wpkg` package list with versions and install commands |
| [docs/threat-model.md](docs/threat-model.md) | Threat model + `bwrap`/container recipes until the sandbox lands |
| [docs/differences-from-windows.md](docs/differences-from-windows.md) | Intentional behavior differences vs real Windows |
| [docs/architecture.md](docs/architecture.md) | PE loading, API shims, child processes, WinFS |
| [docs/control-protocol.md](docs/control-protocol.md) | Headless WebSocket protocol for agents |

## Development

Run `cargo test --offline`; exercise native changes with real binaries/E2E fixtures.
See [CHANGELOG](CHANGELOG.md) and [backlog](COMPATIBILITY_BACKLOG.md).

Fixture tests report **ignored** unless their env vars are set; `-- --ignored` runs
them (missing fixtures then fail):

```bash
WINRUN_NODE_EXE=/path/to/node.exe WINRUN_NPM_ROOT=/path/to/node_modules/npm \
  WINRUN_TEST_LIVE_NPM=1 cargo test --test node_native -- --ignored
bash scripts/fetch-dotnet-fixture.sh
WINRUN_DOTNET_FIXTURE=target/dotnet-fixture cargo test --test dotnet_native -- --ignored
WINRUN_RG_EXE=/path/to/rg.exe cargo test --test rg_native -- --ignored
```

CI runs the default suite plus Node/npm and CoreCLR fixture jobs.

## License

Licensed under the [Apache License, Version 2.0](LICENSE); see [NOTICE](NOTICE).
