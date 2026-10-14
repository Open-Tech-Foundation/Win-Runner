# Differences from real Windows

CLI compatibility, not Windows fidelity. Listed = by design; anything else
that differs is a bug — check `tests/oracle/` against real Windows and report it.

## Scope

- **CLI only.** No GUI, games, drivers, services, tray, RDP, or interactive `cmd`.
- **No .NET Framework.** Rejected at load; modern CoreCLR via E2E fixtures instead.
- **One user, one machine.** `runner` on `WINRUNNER`. No UAC, logons, TS, or domain.
- **PowerShell subset.** Missing cmdlets fail loudly; `Get-Command` lists what exists.
- **`cmd.exe` subset.** `cmd /c`, batch, pipes, redirection, `for`/`if`/`set`. No `/k`.

## Object model

- **Pipelines carry text, not .NET objects.** Line-based filtering; no property paths.
- **No desktop clipboard.** Internal clipboard only (API formats stubbed per-session).
- **No window desktop.** GUI scaffolding APIs stubbed for CLI tools; only title updates show.

## Filesystem and registry

- **C: is case-insensitive** (casing preserved), like NTFS.
- **No 8.3 names**, no visible file ACLs (SDDL parsed where APIs need it).
- **Windows timestamps** on C:; host times on mounted drives.
- **Registry** is JSON-backed `HKLM`/`HKCU` for env, uninstall, certs, installers.

## Process, console, hardware

- **Host CPU, host clock.** CPUID/timers answer from the host; no virtual time.
- **Memory size is reported, not enforced.** Default 512 MiB (`--memory=8G`).
- **Host terminal** (or pipes), 80×25 default. Console-mode calls fail on
  redirected handles, as on Windows.
- **Crashes exit with the Windows exception code** (`0xC0000005`) + stderr note.

## Networking and crypto

- **Host stack, no virtual NIC.** Winsock maps to host sockets with Winsock errors.
- **Guest ROOT store** (pinned Mozilla bundle), not host CAs. No revocation checks.
- Hostname, interfaces, and proxy env leak through from the host.

## Errors (deliberately strict)

- Unknown target → exit `1`; unsupported file type → exit `2`.
- Unsupported APIs fail as `executable: DLL!API` — that list is the roadmap.
- `WINRUN_NATIVE_STRICT_IMPORTS=1` refuses upfront instead of at first call.

## Reading test results

Passing = "like Windows *for the APIs this program uses*". For disputes, the oracle
suite records real-Windows behavior probe by probe — start there.
