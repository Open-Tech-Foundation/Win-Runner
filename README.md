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

Each new run gets a disposable C: drive. Use a WinFS snapshot to keep its files and installed programs between runs.

```bash
winrun --snapshot=tools.winfs --save shell
```

`--save` writes changes back to the loaded snapshot when the shell exits; run `snapshot save` inside the shell to save sooner.
Snapshots are indexed, seekable WinFS disks and contain C: only.
Explicitly mounted host directories appear as separate guest drives (for example, Z:).

## Shell and packages

The interactive shell supports common file and directory commands, PowerShell-style scripts, environment updates, history, and tab completion.
Its built-in `choco` and `winget` commands install a limited set of portable packages into the guest C: drive.

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

Win-Runner implements Windows APIs needed by supported programs incrementally; unsupported imports are reported by name when called.
`winrun inspect app.exe` reports static imports, and `WINRUN_NATIVE_STRICT_IMPORTS=1` rejects missing imports before execution.

## Development

Run the test suite with `cargo test --offline`; native changes should also be exercised with real Windows binaries or E2E fixtures.

See [CHANGELOG.md](CHANGELOG.md) for release notes and [COMPATIBILITY_BACKLOG.md](COMPATIBILITY_BACKLOG.md) for tracked compatibility work.
