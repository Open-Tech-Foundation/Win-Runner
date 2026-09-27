# Compatibility, security, and architecture backlog

This checklist records the review feedback and tracks work in priority order.
Items remain open until implementation and relevant verification are complete.

## High priority

- [x] **1. Confine package extraction to its destination.** Use a shared safe
  archive path helper for Chocolatey `tools/` extraction, nested archive
  extraction, npm distribution extraction, and guest WinFS extraction. Reject
  traversal, absolute paths, drive prefixes, alternate data stream syntax, and
  unsafe existing symlink components. Validate external 7-Zip archive paths
  before extraction.
- [x] **2. Clarify the guest security boundary.** Guest PE code runs natively
  and can issue Linux syscalls, so WinFS and read-only mounts are not a
  security sandbox. Document this clearly; assess seccomp, namespaces, and
  Landlock as a separate implementation project.
- [ ] **3. Remove unsafe fork-after-threads behavior.** `CreateProcessW` forks
  from a multithreaded guest. `CreateProcessW` now builds the child filesystem,
  process context, environment, TLS template, and inherited pipe table before
  forking, then installs the process context through thread-local storage.
  This removes the identified post-fork context/pipe/global-dispatcher locks
  from `CreateProcessW`; it does not remove general fork-after-threads hazards.
  The initial `wincli app.exe` launcher still forks and then creates a Rust
  thread. Move guest execution to a fresh WinCLI worker process to close this
  item.
- [ ] **4. Keep the control listener alive after invalid connections.** Continue
  accepting until an authenticated WebSocket session is established, and use
  constant-time token comparison.
- [ ] **5. Define child filesystem visibility and crash semantics.** Current
  child changes are applied on normal exit, can be lost on kill/crash, and
  concurrent writers are last-finisher-wins. Document this behavior and plan
  shared/incremental filesystem updates for cooperating processes.
- [ ] **6. Preserve guest arguments after the executable.** Parse WinCLI
  options only before the target program; pass later `--snapshot`, `--mount`,
  `--control`, and `--headless` arguments through unchanged.
- [ ] **7. Verify stderr on the control channel.** Trace native guest stderr and
  ensure it is emitted as `OutputChannel::Stderr` rather than host fd 2.

## Housekeeping

- [ ] Ignore generated `*.snap` and `*.winfs` files so local disks are not
  accidentally staged.
- [ ] Split `src/native.rs` by subsystem: loader, handles, file I/O, sync,
  processes, sockets, and related Windows API groups.
- [ ] Cache `WINCLI_NATIVE_DIAGNOSTIC` once rather than reading the environment
  from hot shims.
- [ ] Fix Clippy's unevenly grouped hexadecimal literal warnings.

## Compatibility coverage priorities

### P0: startup and basic runtime support

- [ ] Load real guest DLLs; resolve recursive imports and forwarded exports;
  run `DllMain` and DLL TLS callbacks.
- [ ] Map common API-set DLL names to supported host implementations, starting
  with the UCRT API-set families.
- [ ] Implement UCRT startup (`_configure_narrow_argv`,
  `_initialize_narrow_environment`, `__p___argc`, `__p___argv`, `_crt_atexit`,
  `_register_onexit_function`, `_seh_filter_exe`, `_set_new_mode`,
  `_configthreadlocale`), standard I/O (`__stdio_common_vfprintf`,
  `__stdio_common_vsprintf`, `__acrt_iob_func`), and basic file, conversion,
  sorting, time, and string functions (`fopen`, `fread`, `fclose`, `strtol`,
  `strtod`, `qsort`, `_time64`, `strstr`).
- [ ] Add basic `msvcrt.dll` output and file I/O, including `printf` and `fopen`.
- [ ] Add VCRUNTIME140 exception handlers, `_CxxThrowException`, and memory
  functions needed by C++ and default Rust MSVC binaries.
- [ ] Implement structured exception lookup/unwind/raise APIs and translate
  Linux fault signals into guest Windows exceptions.

### P1: common command-line tools

- [ ] Add process/sync APIs: `CreatePipe`, `PeekNamedPipe`,
  `WaitForMultipleObjects(Ex)`, mutex and semaphore APIs, `OpenProcess`,
  `CreateProcessA`, `SleepEx`, and `GetProcessTimes`.
- [ ] Add console APIs: `ReadConsoleW`, `ReadConsoleInputW`,
  `FillConsoleOutput*`, and `GetConsoleCP`.
- [ ] Add path/locale APIs: `CommandLineToArgvW`, `SHGetKnownFolderPath`,
  `GetWindowsDirectoryW`, `SearchPathW`, `LCMapStringEx`, and `CompareStringEx`.
- [ ] Cover Winsock imports by name: `WSAStartup`, `socket`, `connect`,
  `send`, `recv`, `closesocket`, `select`, `getaddrinfo`, `setsockopt`, and
  `ioctlsocket`.

### P2: broader APIs

- [ ] Add `LockFileEx`, `GetDiskFreeSpaceExW`, `GetVolumeInformationW`,
  `DeviceIoControl` symlink/reparse support, `BCryptGenRandom`, and
  `GetProcessMemoryInfo`.
- [ ] Add COM initialization stubs where `CoInitializeEx` succeeds and
  `CoCreateInstance` reports that a component is not registered.

## Measurement and architecture

- [ ] Build a corpus of 30–50 real executables (Git, embeddable Python, curl,
  7-Zip, jq, CMake, Go/Deno/Rust builds, and others); run
  `wincli inspect --json`, aggregate missing imports by executable, and rank
  shim work by measured demand.
- [ ] Replace split `supports_import` and `baseline_trampoline` registration
  with one shim registry that drives import binding, inspect output, and
  coverage reporting.
- [ ] Introduce one typed object manager for process, thread, event, semaphore,
  mutex, file, and pipe handles so wait, duplicate, and inheritance behavior
  share one model.
- [ ] Move to a server/worker process model: the main WinCLI server owns WinFS
  and process/handle tables; fresh WinCLI workers execute guest processes over
  a Unix socket. Use this boundary for per-process sandboxing and incremental
  filesystem updates.
- [ ] Extend the WebSocket/instance protocol with structured jobs: timeout,
  separate stdout/stderr, exit code, and filesystem change list.
- [ ] Add a compatibility CI suite that starts the real-executable corpus and
  reports shim coverage changes.

## Work order

1. Close package extraction traversal (High #1).
2. Resolve the security boundary and fork safety (High #2–3).
3. Fix control, argument, stderr, and child filesystem semantics (High #4–7).
4. Measure real executable import demand; establish the shim registry and
   source split.
5. Implement DLL loading, API sets, UCRT, and exception support (P0), then P1
   and P2 APIs.
6. Evolve process/handle/filesystem ownership, structured agent jobs, and CI.
