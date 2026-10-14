# Differences from real Windows

Win-Runner targets **command-line program compatibility**, not Windows
fidelity. This page lists intentional differences so test results are read
correctly. Anything here is by design; anything else that differs is a bug —
check it against real Windows with the oracle scripts in `tests/oracle/` and
report it.

## Scope differences

- **CLI only.** No GUI windows, games, drivers, services, tray, notifications,
  remote desktop, or interactive `cmd` prompt.
- **No .NET Framework.** Framework executables are rejected with a loader
  limitation. Modern CoreCLR / self-contained binaries are covered via E2E
  fixtures instead.
- **Single user, single machine.** Every session is user `runner` on computer
  `WINRUNNER`. No UAC/elevation, logon sessions, Terminal Services, or domain.
- **PowerShell subset, not full PowerShell.** Missing cmdlets/parameters fail
  loudly. `Get-Command` / `Get-Help` in the shell list what exists.
- **`cmd.exe` subset.** Covers what programs that shell out need (`cmd /c`,
  batch files, pipes, redirection, `for`/`if`/`set`, delayed expansion). No
  interactive prompt, no `cmd /k` persistence.

## Object model

- **Pipelines carry text, not .NET objects.** `... | Select-Object -First 1`,
  `Where-Object`, `ForEach-Object` work on lines. Property access on
  structured output (e.g. `(Get-Process)[0].Id`) mostly does not apply.
- **No desktop clipboard.** Micro and console tools use an internal clipboard;
  session-local clipboard formats exist for API compatibility only.
- **No real windows/messages desktop.** Window/message-queue APIs that GUI
  scaffolding calls are stubbed sufficiently for CLI tools; visible behavior
  is limited to console title updates (OSC 0).

## Filesystem and registry

- **Guest C: is case-insensitive** (original casing preserved in listings),
  like NTFS. `TEST.JS` and `test.js` are the same file.
- **No short (8.3) names**, no per-file security descriptors visible to
  guests (SDDL parsing exists where APIs require it, e.g. private dirs).
- **Timestamps** follow Windows semantics (create/access/write moved on
  create/write); host-mounted files report host times.
- **Registry** is a JSON-backed `HKLM`/`HKCU` sufficient for environment,
  uninstall entries, certificates, and installer probes — not the full
  Windows hive set.

## Process, console, and hardware

- **CPU is the host CPU.** `IsProcessorFeaturePresent` answers from host
  CPUID; cycle/perf counters follow the host clock.
- **Memory size is configurable, default 512 MiB** (`--memory=8G` /
  `WINRUN_MEMORY`). It changes what the guest *reports*, not a real cap.
- **Clock is the host clock.** No virtualized time; sleeps/timers use host
  waits.
- **Console is the host terminal** (or pipes). Window size defaults to 80×25
  and follows resizes in controlled sessions. `GetConsoleMode`/`SetConsoleMode`
  fail with `ERROR_INVALID_HANDLE` on redirected handles, as on Windows.
- **Crash exit codes** surface the Windows exception code (e.g. `0xC0000005`)
  with a stderr note, so nested crashes (node under cmd under npm) are visible.

## Networking and crypto

- **Traffic goes through the host stack.** There is no virtual NIC; Winsock
  maps onto host sockets with Winsock error semantics.
- **Trust comes from the guest ROOT store** (seeded from the pinned Mozilla
  bundle), not the host CA files. Revocation is not checked.
- Hostname, interface list, and proxy env visible to the guest reflect the host.

## Error behavior (deliberately strict)

- Unknown programs: `winrun` exits `1` ("nothing to run …"); unsupported file
  types: exit `2`.
- Unsupported guest APIs fail loudly with `executable: DLL!API` naming —
  Windows would run them, Win-Runner stops at them. That list is the roadmap
  (see `docs/compatibility.md`).
- `WINRUN_NATIVE_STRICT_IMPORTS=1` turns missing imports into a pre-execution
  error instead of failing at first call.

## Reading test results

A passing Win-Runner run means "behaves like Windows *for the APIs this
program uses*". For fidelity disputes, the oracle suite (`tests/oracle/`,
`tests/oracle_native.rs`) records real-Windows behavior probe by probe and
compares field by field — start there before assuming either side is right.
