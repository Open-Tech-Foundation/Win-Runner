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
- [x] **3. Remove the `CreateProcessW` fork fallback.** Every Windows child now
  starts in a fresh exec worker. Workers receive process identity, cwd,
  environment, WinFS state, standard handles, and open-file metadata. Inheritable
  pipe endpoints (including standard pipes, pending clients, and completion
  associations) cross through descriptor passing; inheritable Winsock handles
  and completion associations are restored in the worker. Generic native parent
  and child E2E tests cover output, cwd, and filesystem changes. The direct Rust
  library runner retains its separate fork path when invoked without a worker
  executable; normal CLI runs use exec workers.
- [x] **4. Keep the control listener alive after invalid connections.** Continue
  accepting until an authenticated WebSocket session is established, and use
  constant-time token comparison.
- [x] **5. Define child filesystem visibility and crash semantics.** Current
  child changes are applied on normal exit, can be lost on kill/crash, and
  concurrent writers are last-finisher-wins. Document this behavior and plan
  shared/incremental filesystem updates for cooperating processes.
- [x] **6. Preserve guest arguments after the executable.** Parse Win-Runner
  options only before the target program; pass later `--snapshot`, `--mount`,
  `--control`, and `--headless` arguments through unchanged.
- [x] **7. Route guest stderr through the control channel.** The native
  launcher captures stdout and stderr independently, drains both without
  blocking, and reports the channel to the output sink. Legacy callers continue
  receiving guest stderr on host stderr.
- [x] **8. Fix Node child-process pipe capture.** Named-pipe EOF after child
  output, overlapped `GetOverlappedResult`, cancellation/readiness races,
  `FilePipeLocalInformation`, and null-buffer zero-byte writes to standard
  handles are handled. The official Node 24.21.0 default
  `execFileSync('powershell.exe', ...)` probe captures `Hello` without an
  error.

## Housekeeping

- [x] Ignore generated `*.snap` and `*.winfs` files so local disks are not
  accidentally staged.
- [x] Split native execution by subsystem. The public `native.rs` is a
  platform-neutral façade; Linux x86-64 execution and unsupported-host behavior
  use separate backends. The Linux backend root is now a compact module index.
  Host ABI declarations, import registration, PE mapping, runner orchestration,
  x86-64 assembly, and runtime state each have dedicated modules. Win32 API
  shims are organized by loader, process, handles, file I/O, synchronization,
  CRT, console, sockets, memory, locale, environment, clock, NTDLL, exceptions,
  registry, and related API groups. File I/O is further divided into open/read
  and named-pipe setup, namespace operations, temporary/metadata operations,
  path/search operations, and write/pipe APIs. Guest state and handle ownership
  remain in dedicated context/state modules; host syscall bindings remain
  backend-specific to support future macOS native backends. Wait and
  process-scoped object maps remain follow-up architecture work, not outstanding
  source separation.
- [x] Cache `WINRUN_NATIVE_DIAGNOSTIC` once rather than reading the environment
  from hot shims; initialize the cache before guest forks.
- [x] Fix Clippy's unevenly grouped hexadecimal literal warnings. A current
  all-targets Clippy run still reports unrelated warnings across the codebase.
- [ ] Triage remaining Clippy warnings. Current toolchain reports 81 library
  warnings and 14 binary warnings, plus repeated warnings in test targets.
- [ ] Remove or explicitly constrain the direct library runner's fork path,
  which remains available when callers invoke it without a worker executable.

## Compatibility coverage priorities

### P0: startup and basic runtime support

- [ ] Load real guest DLLs; resolve recursive imports and forwarded exports;
  run `DllMain` and DLL TLS callbacks.
- [ ] Map common API-set DLL names to supported host implementations, starting
  with the UCRT API-set families.
  - [x] Route common `api-ms-win-core-*`, `api-ms-win-crt-*`,
    `api-ms-win-security-*`, and related `ext-ms-win-*` names through existing
    Kernel32/UCRT/Advapi32 shim registrations.
  - [ ] Expand family mappings and exports as CoreCLR import inspection
    identifies additional modules and functions.
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
- [ ] **Modern .NET via Microsoft's real CoreCLR.** Do not implement an IL
  interpreter or a replacement CLR. Run modern .NET apphosts and bundled
  Windows runtime DLLs through the native x86-64 backend, using redistributable
  Microsoft CoreCLR files. This is also the route toward real PowerShell 7.
  - [x] Identify .NET Framework PE entry imports and report
    `.NET Framework executables are not supported yet`; CoreCLR hosting does
    not yet imply Framework compatibility.
  - [ ] Load guest DLLs from WinFS: map PE sections, resolve imports
    recursively, handle forwarded exports, invoke `DllMain` and TLS callbacks,
    and implement `LoadLibrary`/`GetProcAddress` against real modules.
    - [x] Parse bounded PE export tables, including names, ordinals, and
      forwarder strings, as input to runtime export resolution.
    - [x] Track the main image and loaded guest modules; load WinFS DLLs,
      recursively resolve guest-DLL dependencies and shim-backed imports,
      invoke process-attach `DllMain`, and resolve named/ordinal exports plus
      forwarders to shim-backed system modules.
    - [x] Invoke main-image and DLL TLS process-attach callbacks. DLL TLS
      directories with non-empty templates or zero-fill remain unsupported.
    - [x] Send TLS and `DllMain` thread-attach/detach notifications around
      guest `CreateThread` routines, ordered by module load sequence.
    - [x] Resolve cyclic guest-DLL import references using provisional module
      records so each side can resolve the other's exports.
    - [ ] Match Windows initialization order for cyclic dependency graphs,
      support per-thread static TLS and notifications for already-running
      threads when a DLL is loaded, and implement FreeLibrary reference-count
      and unload semantics.
  - [ ] Host `hostfxr.dll`, `hostpolicy.dll`, and `coreclr.dll` using the
    supported native hosting interfaces; cover shared, app-local, and
    self-contained runtime layouts, then add single-file apps.
  - [ ] Complete SEH dispatch and stack unwinding, including native fault
    translation required by CoreCLR.
  - [ ] Complete virtual memory semantics used by the GC/JIT: reserve versus
    commit, guard pages, and writable/executable protection transitions.
  - [ ] Implement GC thread suspension/context APIs (`SuspendThread`,
    `GetThreadContext`, `SetThreadContext`, `FlushProcessWriteBuffers`) with a
    Linux signal-based stop/resume protocol.
  - [ ] Complete thread/TLS/FLS, events/waits, timers, and thread-pool support
    required by CoreCLR.
  - [ ] Install an official redistributable CoreCLR package into guest WinFS
    and validate first with a minimal modern .NET app, then `pwsh.exe`.
  - [ ] Leave old .NET Framework unsupported with the clear diagnostic above;
    consider routing `_CorExeMain` to CoreCLR only as a later compatibility
    experiment. NativeAOT remains ordinary native PE execution.

### P2: broader APIs

- [ ] Add `LockFileEx`, `GetDiskFreeSpaceExW`, `GetVolumeInformationW`,
  `DeviceIoControl` symlink/reparse support, `BCryptGenRandom`, and
  `GetProcessMemoryInfo`.
- [ ] Add COM initialization stubs where `CoInitializeEx` succeeds and
  `CoCreateInstance` reports that a component is not registered.

## WinFs paths and storage review

The following behaviors were confirmed by comparison with Windows. Preserve
the input, cwd, expected result, and expected Win32 error in a Windows-oracle
table, then run the same cases against WinFs unit tests and guest executables.
Record oracle values from `GetFullPathNameW`, `CreateFileW`, and
`GetLastError` on real Windows before changing behavior.

### Path compatibility cases

- [ ] **Path oracle table.** Build shared cases with input path, cwd, expected
  normalized path or device result, and expected error code. Include both
  WinFs unit tests and guest `.exe` tests.
- [x] **Per-drive current directories.** Relative `file.txt` under cwd
  `Z:\sub` must resolve to `Z:\sub\file.txt`; drive-relative `C:foo` must use
  the remembered C: cwd even when the active cwd is on another drive. Model
  Windows `=C:`-style per-drive cwd behavior. WinFs now retains a cwd per
  mounted drive and tests relative resolution on Z: plus C: drive-relative
  lookup while Z: is active.
- [x] **Null device.** `NUL`, `nul.txt`, `C:\work\nul`, and `\\.\NUL` open
  as a character device through `CreateFileW`; writes are discarded, reads
  return EOF, and no WinFs file entry is created. Unit and generated native PE
  guest tests cover these semantics.
- [x] **Console and reserved DOS device names.** `CON`, `CONIN$`, and
  `CONOUT$` open as character handles routed to the process standard handles;
  invalid read/write directions fail. Reserved names including `COM1` and
  `LPT1` are rejected even with extensions. Unit tests and a generated native
  PE guest test cover these cases.
- [x] **Device and pipe namespace.** The typed parser classifies DOS device
  aliases and `\\.\pipe\foo` as device paths instead of ordinary C: paths;
  native `CreateFileW` dispatches pipe names to the named-pipe implementation.
- [x] **UNC paths.** WinFs rejects `\\server\share\x`,
  `\\?\UNC\server\share\x`, and `\??\UNC\server\share\x` instead of
  remapping them onto C:. Native `CreateFileW` reports
  `ERROR_BAD_NETPATH` (53) for the unsupported UNC share paths.
- [x] **Trailing dots and spaces.** The typed parser drops trailing dots and
  spaces from each component (`foo.` aliases `foo`, and `foo \bar` trims the
  component's trailing space) while preserving leading spaces (` lead` remains
  distinct). WinFs tests cover all three cases.
- [x] **Invalid characters and streams.** The parser rejects invalid path
  characters such as `|`, `<`, and `>` and rejects colon stream syntax such as
  `C:\file.txt:stream` instead of creating an ordinary file. Native
  `CreateFileW` reports `ERROR_INVALID_NAME` (123); parser and native tests
  cover these results. Alternate data streams remain unsupported.
- [x] **Windows name comparison.** WinFs keys now uppercase one Unicode
  character at a time instead of applying whole-string lowercase expansion.
  `İ.txt` and `i\u{307}.txt` stay distinct while ASCII case variants continue
  to resolve to the same file; unit tests cover identity and contents.
- [x] **Optional MAX_PATH mode.** WinFs exposes an opt-in strict 260 UTF-16
  unit check (including the terminator); extended-length paths bypass it.
  Unit tests cover 259/260-character boundaries and extended paths.
- [x] **One typed path parser.** Added `win_path::parse()` returning
  `Dos { drive, absolute, components }`, `Unc { server, share, components }`,
  `Device(Nul | Con | ConIn | ConOut | Reserved | Pipe(name))`, or
  `Invalid(reason)`. WinFs normalization, UNC detection, and DOS-device
  classification use this parser; native filesystem APIs therefore share the
  same path classification before lookup.

### Filesystem representation and mounted drives

- [ ] **ID-based WinFs nodes.** Give every file and directory an ID with its
  metadata attached; directory entries map names to IDs. Make rename update
  directory entries rather than rewriting path-keyed metadata, and support
  hard links through shared IDs.
- [x] **Relative symlink targets.** WinFs stores the target exactly as
  supplied and resolves relative targets from the link's parent directory, so
  moving a containing directory preserves the link. Unit tests cover moves
  and filesystem change replay.
- [x] **Indexed mounted directories.** Host mounts cache each directory's
  one-character-uppercase name index, refresh it when the directory
  modification time changes, and report case collisions such as simultaneous
  `Foo` and `foo` explicitly. Cache misses trigger a rescan too, for mounted
  filesystems with coarse or synthetic timestamps. Unit tests cover refresh
  and collision errors.
- [ ] **Shared filesystem service.** Keep this aligned with the server/worker
  architecture item below: a shared filesystem owner should make child writes
  visible immediately. Current child-exit merge and crash-loss behavior is
  already tracked under High priority #5.

### Suggested implementation order

1. Fix relative paths on non-C: drives and per-drive cwd handling.
2. [x] Implement NUL and CON-family devices, and reject reserved COM/LPT names.
3. [x] Add the typed parser for UNC and device paths.
4. Normalize trailing dots/spaces and reject invalid/reserved names.
5. Move WinFs nodes to IDs and retain relative symlink targets.
6. Add mounted-directory indexes and collision reporting.

## Measurement and architecture

- [ ] Build a corpus of 30–50 real executables (Git, embeddable Python, curl,
  7-Zip, jq, CMake, Go/Deno/Rust builds, and others); run
  `winrun inspect --json`, aggregate missing imports by executable, and rank
  shim work by measured demand.
- [ ] Replace split `supports_import` and `baseline_trampoline` registration
  with one shim registry that drives import binding, inspect output, and
  coverage reporting.
- [ ] Introduce one typed object manager for process, thread, event, semaphore,
  mutex, file, and pipe handles so wait, duplicate, and inheritance behavior
  share one model.
- [ ] Move to a server/worker process model: the main Win-Runner server owns WinFS
  and process/handle tables; fresh Win-Runner workers execute guest processes over
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
