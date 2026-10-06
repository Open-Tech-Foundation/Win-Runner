<div align="center">

# Win-Runner

***Run Windows command-line programs outside Windows.***

</div>

<div align="right">

*An [Open Tech Foundation](https://opentechf.org/) project*

</div>

> Win-Runner (`winrun`) runs Windows x86-64 programs on Linux through native Windows API shims, with a disposable C: drive, snapshots, a scriptable shell, package installs, host folder mounts, and a WebSocket control API. No Wine or VM is required.

- ✅ **Supported today:** Linux x86-64 native execution.
- ⏳ **Planned:** Additional platform backends.
- ⏳ **In progress:** Built-in security sandbox.

> [!WARNING]
> Win-Runner is a compatibility runtime, not a security sandbox. Native guest programs can make Linux system calls with Win-Runner's privileges. The built-in sandbox is a work in progress; use an OS sandbox for untrusted programs.

## Why Win-Runner?

Testing a Windows command-line program usually means a Windows machine, a VM, or a
paid CI runner. Wine can run it elsewhere, but it is built for desktop apps: a large
prefix to set up and reset, noisy logs, and quiet workarounds that can hide bugs.

Win-Runner is built for one job: **fast, repeatable, scriptable runs of Windows CLI
programs**, driven by people, CI pipelines, and coding agents.

- **Instant, clean state:** every run starts from a fresh in-memory C: drive or a
  saved snapshot. There is no prefix to create, copy, or clean up.
- **Native speed:** x86-64 code runs directly on the host CPU; only Windows API calls
  go through compatibility shims.
- **Honest failures:** unsupported APIs are reported by name, and `winrun inspect`
  shows what a program needs before it runs. A missing feature fails loudly
  instead of silently changing behavior.
- **Built for automation:** the headless WebSocket control API streams output,
  accepts input, key, and resize events, and reports exit codes, so an agent can
  build, run, and check Windows programs without a Windows machine.
- **One small binary:** a single Rust executable with a shell, PowerShell-style
  scripts, and a manifest-based portable package manager.

Win-Runner does not aim to replace Wine. It targets command-line programs, not GUI
apps, games, or drivers. For those, use Wine or a real Windows machine.

## Quick start

```bash
cargo build --release
./target/release/winrun shell
```

Run a Windows program or script directly, or inspect a PE file's imported APIs:

```bash
winrun app.exe [args...]
winrun script.ps1
winrun inspect app.exe
```

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
tsr --version
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

Text pipelines support `Select-String`, `Sort-Object`, `Get-Unique`,
`Measure-Object`, `Out-File`, `Tee-Object`, and the existing
`Where-Object`, `ForEach-Object`, and `Select-Object -First` operations.
`Get-Content` supports `-Raw`, `-TotalCount`/`-Head`, and `-Tail`;
`Get-ChildItem` supports `-Recurse`, `-File`, `-Directory`, `-Filter`,
and filename `*`/`?` patterns. File output uses UTF-8 without a BOM.
Scripts can declare `param(...)` blocks and functions, `return`, use
`try`/`catch`, here-strings, backtick escapes, casts, and the
`HKLM:`/`HKCU:` registry provider (`Get-ItemProperty`, `New-ItemProperty`,
`RegistryKey` methods) over the guest hives. They run programs with
`& "C:\path\app.exe" args` or by name on the `PATH`, read `$LASTEXITCODE`,
and capture program output with `$(...)`. `Add-Type` accepts
`[DllImport]` declarations for the Win32 calls installers make
(`IsProcessorFeaturePresent`, `SendMessageTimeout`). Official one-liners
such as `powershell -c "irm bun.sh/install.ps1|iex"` run unchanged.
`C:\Windows\System32\curl.exe` downloads over HTTP(S) through the host's
curl, with the options of plain downloads (`-fsSL`, `-#`, `-o`, `-O`, `-H`,
`-A`, timeouts and retries); options that would reach host files are
refused.
Pipelines carry text rather than full PowerShell objects. Advanced
providers, administration cmdlets, and unimplemented parameters remain
unsupported; this shell is not a complete PowerShell distribution.

The shell includes `wpkg`, which installs SHA-256-verified ZIP and 7z packages into the guest C: drive without running installers or package scripts. Its text registry is bundled in the binary; package archives download only when installed.

For a terminal text editor on Linux x86-64, install the Windows build of Micro:

```powershell
wpkg install micro
micro -clipboard internal notes.txt
```

Use Ctrl-S to save and Ctrl-Q to quit. Micro edits files in the guest drive,
including files restored from snapshots. The `internal` clipboard setting
keeps copy and paste inside the editor; the guest has no desktop clipboard.
Micro 2.0.15 is pinned in the registry and runs through the native PE backend.

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

## Headless control

Start a persistent shell with a loopback WebSocket endpoint; any WebSocket client can send input and read streamed output events.

```bash
winrun --headless --control=127.0.0.1:0 shell
```

The process prints a JSON `ready` event containing the connection URL and session token. The control protocol supports text, key, and resize input.

## Mount host folders

Mounting explicitly exposes a host directory as a guest drive; writable mounts write through to the host.

```bash
winrun --mount=Z:/path/to/folder shell
winrun --mount-ro=Z:/path/to/folder shell
```

## Compatibility

Win-Runner implements Windows APIs needed by supported programs incrementally; unsupported imports are reported with the executable, DLL, and API name when called. Missing-import, worker-startup, and child-crash errors reach the launcher even when child processes redirect stderr or discard it with `stdio: "ignore"`.
`winrun inspect app.exe` reports static imports, and `WINRUN_NATIVE_STRICT_IMPORTS=1` rejects missing imports before execution.

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
