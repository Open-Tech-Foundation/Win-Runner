# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Removed

- Removed the PE instruction emulator and the `wincli probe` command. Windows
  executables now use the Linux x86-64 native platform backend.

### Added

- Added native PE loader, TLS/TEB initialization, direct CPU execution, Windows
  API import trampolines, child process contexts, and WinFS snapshot transfer.
- Added native process, thread, synchronization, memory, console, file, crypto,
  Winsock, I/O completion, and selected NTDLL compatibility shims.
- Added Windows stack bounds for guest threads and a 16 MiB primary guest stack
  so V8 can run JavaScript without reporting an immediate stack overflow.
- Added anonymous file mapping views, `VirtualAlloc` reserve/commit/reset,
  standard pipe handles, file access queries, and worker thread exit handling
  used by the official Windows Node.js binary.
- Added a real binary E2E check for Node.js 24.21.0 `--version` and simple
  JavaScript evaluation with `WINCLI_BACKEND=native`.
- Added optional strict import validation with `WINCLI_NATIVE_STRICT_IMPORTS=1`.

### Changed

- Missing static imports now use named fail-on-call trampolines by default, so
  programs can run when their optional Windows APIs are unused. Calling an
  unsupported import still stops execution with its exact DLL and API name.
- `wincli inspect` reports static native shim coverage; missing optional imports
  may appear even when a tested program path runs successfully.
