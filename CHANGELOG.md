# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- Detect .NET Framework `_CorExeMain`/`_CorDllMain` images and report the clear
  unsupported-runtime limitation in `winrun inspect` and native execution.
- Replaced the PS1 interpreter's proposed install-script .NET API expansion
  with a CoreCLR hosting roadmap for modern .NET executables; no custom IL
  runtime is planned.
- Parse PE export tables into named, ordinal-only, and forwarded export records
  as the first implementation step toward loading guest DLLs.
- Add per-process module records, LoadLibrary support for WinFS DLLs,
  process-attach `DllMain` calls, and dynamic `GetProcAddress` for named,
  ordinal, and shim-forwarded exports.
- Resolve acyclic guest-DLL dependency graphs recursively and map common
  Kernel32, UCRT, and Advapi32 API-set names onto existing shim registrations.
- Invoke process-attach TLS callbacks for the main image and DLLs, with static
  TLS storage initialized from mapped template bytes and zero-fill.
- Send DLL/TLS thread-attach and thread-detach notifications around guest
  `CreateThread` start routines using modules captured in load order.
- Resolve cyclic guest-DLL import references by publishing mapped exports while
  their dependency imports are patched.
- Allocate DLL static TLS templates and zero-fill for live guest threads and
  later-created threads cloned from the process TLS template.
- Count repeated `LoadLibrary` calls and import-dependency references; release
  dependencies when their importing module reaches zero references.

- Added a "Why Win-Runner?" section to the README explaining the project's focus
  and how it differs from Wine, VMs, and Windows CI runners.
- Added an Apache 2.0 `NOTICE` file and linked it from the README.
- Added `--save` to write changes back to the loaded snapshot on exit, without
  repeating the snapshot path.
- Simplified the README, aligned its opening with the organization project format,
  and removed program-specific package examples.
- Renamed the Cargo package to `win-runner` and both the Rust library crate
  and command-line executable to `winrun` (project name: Win-Runner).
- Kept interactive shell history exclusively in guest
  `C:\.system\shell-history`; it follows the WinFS instance or snapshot and
  no longer writes to host state directories.
- Changed the synthetic guest user and profile name to Win-Runner, and made
  `GetUserNameW` read the guest process environment instead of the host.
- Allowed exec workers to inherit named-pipe endpoints while the parent has
  active overlapped I/O; pending requests remain owned by the parent context.

- Released the pending client endpoint after named-pipe connection so closing
  a writer delivers EOF after buffered output. Scoped `CancelIo` to the thread
  that issued the I/O request. Added overlapped named-pipe support to
  `GetOverlappedResult`, preserved buffered reads when cancellation races with
  readiness, implemented `FilePipeLocalInformation` for libuv shutdown, and
  accepted zero-byte writes with null buffers on standard handles. The official
  Node 24.21.0 `execFileSync` default path now captures PowerShell shell-link
  output without a pipe error.
- Launched CLI PE guests in a fresh exec-based WinCLI worker instead of
  forking the multithreaded launcher. Workers reopen mounted drives and
  seekable WinFS extents, and return portable filesystem journals while
  preserving guest stdout, stderr, and exit codes.
- Routed every `CreateProcessW` child through a fresh exec worker and removed
  its in-process fork fallback. Workers preserve child identity, cwd,
  environment, WinFS state, standard handles, open-file metadata, inheritable
  sockets, named-pipe endpoints, and completion-port associations. Nested-child
  E2E tests cover output and child working-directory filesystem changes.
- Completed the Linux native backend split: launch/output orchestration, shared
  runtime state, x86-64 assembly, and shared string helpers are in dedicated
  modules; file I/O is divided into open/read, namespace, temporary/metadata,
  path/search, and write/pipe modules. The native backend root now serves as a
  compact module index and compatibility façade.

- Hardened Chocolatey and npm archive extraction against traversal, absolute
  paths, drive prefixes, and existing symlink components.
- Documented that native guest execution and mounted host folders are not a
  security sandbox.
- Prepared `CreateProcessW` child state before `fork` and installed the child
  process context in thread-local storage, avoiding inherited dispatcher and
  pipe-table locks in that child startup path.
- Kept the headless control listener available after invalid handshakes and
  compared session tokens in constant time.
- Documented child WinFS snapshot visibility, crash persistence, and the
  current last-applied-write behavior for concurrent children.
- Stopped consuming WinCLI options after the target program, preserving
  guest arguments that happen to match WinCLI flags.
- Added a guest `C:\bin\powershell.exe` shell link so native child-process
  launches run scripts through WinCLI's PowerShell-compatible interpreter.
- Added the `KERNEL32!NeedCurrentDirectoryForExePathW` shim used by child
  process executable lookup.
- Captured guest stdout and stderr separately and forwarded both channels to
  control clients while preserving stderr for existing host-facing callers.
- Ignored generated snapshot disk files (`*.snap` and `*.winfs`).
- Cached the native diagnostic setting before guest forks to avoid repeated
  environment lookups from API shims.
- Grouped PE image-base hex literals consistently and simplified a redundant
  `Remove-Item` recursion condition reported by Clippy.
- Reproduced the Node `execFileSync`/PowerShell shell-link hang and recorded it
  for pipe inheritance and EOF investigation.
- Added the confirmed WinFs path, device, UNC, Unicode comparison, node-model,
  symlink, and mounted-directory findings to the compatibility backlog, with
  Windows-oracle testing and an ordered implementation plan.
- Fixed WinFs relative paths on mounted drives and retained a separate current
  directory for each drive, including drive-relative paths such as `C:foo`.
- Added native `NUL` device opens with discarded writes, EOF reads, and no
  corresponding ordinary WinFs file creation.
- Added native `CON`, `CONIN$`, and `CONOUT$` character handles routed through
  process standard handles, and rejected reserved `COM1`–`COM9` and `LPT1`–
  `LPT9` names instead of creating ordinary files.
- Rejected unsupported UNC paths explicitly in WinFs and returned
  `ERROR_BAD_NETPATH` from native `CreateFileW` instead of mapping shares onto
  the C: drive.
- Added a shared typed WinFs path parser for DOS, UNC, device, and named-pipe
  paths, and routed WinFs normalization and device/UNC classification through
  it.
- Normalized trailing dots and spaces out of WinFs path components while
  preserving leading spaces.
- Rejected invalid Windows path characters and unsupported alternate-data
  stream syntax with `ERROR_INVALID_NAME` from native `CreateFileW`.
- Changed WinFs case-insensitive keys to use one-character uppercase mapping,
  keeping the distinct Windows names `İ.txt` and `i` plus a combining dot apart.
- Preserved relative symlink targets as written and resolve them from the
  link's parent directory, including after directory moves and change replay.
- Cached mounted host directory name indexes and refresh them when directory
  modification times change; case-colliding host names now return an explicit
  error.
- Added optional strict `MAX_PATH` checking for WinFs, with extended-length
  paths exempt from the 260 UTF-16 unit limit.
- Updated the integration assertion to match the current guest output EOF
  timing label.
- Moved native execution behind a platform-neutral façade, with Linux x86-64
  and unsupported-host implementations in separate modules as the first step
  toward platform-specific native backends.
- Separated Linux host ABI declarations and PE import/trampoline selection
  into backend-local modules.
- Split Linux x86-64 PE mapping and process-launch support into backend-local
  modules, keeping their host-specific implementation beside the Linux backend.
- Moved Winsock API shims into a Linux backend socket module, with Linux socket
  ABI calls remaining in the backend-local host bindings.
- Moved WinFs-backed file, directory, and named-pipe API shims into a dedicated
  Linux backend module.
- Moved standard stream, descriptor conversion, duplication, type, and close
  APIs into a dedicated Linux backend handle module.
- Moved critical section, SRW lock, condition variable, and InitOnce shims into
  a Linux backend synchronization module.
- Grouped single-object waits, event, and semaphore shims with the
  synchronization APIs.
- Moved thread creation, job-object, process identity, child exit, and
  termination shims into the Linux process module.
- Grouped registered wait callbacks with the synchronization APIs.
- Moved the C runtime shims and their environment, errno, stream, and startup
  state into a Linux backend CRT module.
- Moved console screen, mode, output, and input-event shims into a Linux backend
  console module.
- Moved completion-port APIs, directory notifications, and overlapped file I/O
  queue/cancellation support into a Linux backend module.
- Moved Linux backend file, pipe, TLS, filesystem, and per-process context data
  types into a dedicated state module; backend initialization and state access
  remain in the backend root.
- Moved Linux backend thread-local guest state and active process/filesystem
  context accessors into a dedicated context module.
- Grouped Linux critical section, SLIST, address-wait, and waitable-timer shims
  with the synchronization APIs.
- Moved Windows code-page conversion and character classification shims into a
  dedicated Linux backend locale module.
- Grouped Linux `CreateProcessW`, child exit/state transfer, and process-table
  management with the existing process APIs.
- Moved guest environment-block, environment-variable, and current-directory
  APIs into a dedicated Linux backend environment module.
- Isolated Linux TEB/TLS setup and per-thread last-error access in a thread
  runtime module.
- Grouped Linux performance counters, monotonic tick counts, time-zone data,
  and UTC-to-FILETIME conversions in a clock module; moved sleep/yield shims
  into synchronization.
- Moved Linux NTDLL file, process, and system-information shims into a dedicated
  backend module.
- Grouped Linux guest heap, virtual-memory, and file-mapping APIs in a memory
  module, with page sizing and protection helpers shared by the PE loader.
- Moved Linux Windows-version, processor, token, user, and computer/system
  information shims into a dedicated system module.
- Grouped Linux file path expansion, directory enumeration, timestamps, named
  pipe writes, and `WriteFile` with the existing file I/O APIs.
- Moved the in-memory Windows registry and `LocalFree` APIs into the registry
  module beside import registration and trampoline dispatch.
- Grouped dynamic library and module lookup APIs with the Linux PE loader, and
  command-line, startup, and per-thread exit APIs with process support.
- Moved ordinal locale comparison and locale-information APIs into the locale
  module, network byte-order helpers into Winsock, and named-pipe state APIs
  into file I/O.
- Grouped guest TLS/FLS and stack settings with thread runtime; separated
  exception registration, crypto, event-provider, message-formatting, and
  remaining profile/version APIs into subsystem modules.
- Added the C-locale `msvcrt!mbstowcs` shim used by Nano.
- Added an optional native Node check proving a relative file that Node leaves
  in WinFS appears in the following shell directory listing.
- Added a headless localhost WebSocket control session for a persistent shell,
  with streamed output events, text/key input, terminal resizing, and optional
  snapshot save on exit.
- Added common WinFS-backed shell commands for navigation, directory listing,
  file display/copy/move/deletion, directory creation/removal, and screen clear.
- Added interactive Tab completion for shell commands, PATH executables, and
  files and directories in the current guest working directory.
- Added headless execution of a program from a C: snapshot with controller-fed
  standard input and streamed output.
- Added `GetTickCount` and `GetTickCount64` shims using the monotonic host clock,
  plus CRT C-locale setup, guest environment lookup, thread-local errno and
  standard stream storage, and string comparison, case-folding, search, and
  decimal parsing, C-locale case conversion, bounded string copying, and
  zero-initialized allocation, and standard output writes used by Nano.
- Added basic guest console screen-buffer sizing, switching, and
  window-rectangle handling.
- Added CRT signal registration and bounded `sprintf` support for the formats
  used by Nano, plus allocated `_strdup` copies and C-locale `wcstombs`.
- Added CRT `realloc` support that preserves existing allocation contents.
- Added `_stat64` metadata lookup for files and directories in WinFS.
- Added CRT `_access` checks for WinFS paths and read/write mode flags.
- Added a headless `MessageBeep` success shim for console applications.
- Added validation for console cursor visibility and shape updates.
- Added rectangular `WriteConsoleOutputA` cell rendering through host ANSI
  cursor positioning and console colors.
- Added host ANSI cursor positioning for console applications.
- Persisted interactive shell history in the host user-state directory, so it
  survives fresh ephemeral shells, and mirrored it to `C:\.system\shell-history`
  so history also travels with C: snapshots.
- Added Windows-style `set` and `path` commands, `%NAME%` expansion in values,
  guest PATH executable lookup, and environment inheritance by native programs.
- Added a `winget install` shell builtin alongside `choco`, with package ID
  forms, common silent/exact flags, hash-verified portable installs, and
  manifest command aliases. Architecture-neutral portable packages are
  accepted only when their payload validates as x64 PE.
- Corrected WinFS file identity preservation across renames, directory
  creation through POSIX-style `CreateFileW` flags, backup-semantics checks,
  completion modes for overlapped file handles, and `MoveFileW` error codes.
- Added native shims for `CreateFile2`, `FlushFileBuffers`, `SetEndOfFile`,
  `ReOpenFile`, and `GetOverlappedResultEx`.
- Added file-ID opens, privilege-checked valid-data handling, and aligned
  vectored `WriteFileGather` support.
- Added byte-range lock tracking and default data-stream enumeration for WinFS
  handles.
- Added ANSI file-operation wrappers, copy variants, and temporary path/file
  name APIs.
- Added wildcard-filtered wide enumeration and ANSI find-data conversion for
  `FindFirstFileA` and `FindFirstFileExA`.
- Added hard-link identity tracking, symbolic-link entries, and replacement
  operations in both ANSI and wide forms.
- Added the missing ANSI directory-removal and final-path-name exports.
- Removed the obsolete backend selection environment variable; WinCLI
  automatically uses the available platform backend.
- Added interactive shell line editing with cursor movement, insertion,
  deletion, and history navigation. Added a `GetConsoleCursorInfo` shim for
  console applications such as npm.
- Removed the persistent host package cache and one-shot `wincli install`
  command. Package staging and shell guest disks are disposable; snapshots are
  the only way to carry installed programs or other guest files between runs.
- Streamed native guest output to the terminal as it arrives. Added opt-in
  per-stage PE load, native launch, time-to-first-output, guest-run, and
  filesystem-state timings with `WINCLI_TIMINGS=1`.
- `snapshot save` now defaults to the snapshot loaded by the shell or runner,
  and remembers a path given to an earlier save command.
- Replaced ZIP snapshots with an append-only indexed WinFS disk file. Boot
  loads the C: path index and reads file extents on demand; native process
  state now transfers filesystem changes instead of a full disk image.
- Added seeked range reads for synchronous, NT, and overlapped Win32 file reads.
- Added Rust WinFS compatibility tests for `SetFilePointer`/`ReadFile`, copy,
  move, delete, enumeration, metadata, and directory cleanup.
- Expanded modern WinFS compatibility coverage for path resolution, case-
  insensitive enumeration, wrong-type operations, failed mutations, and
  filesystem change replay; added copy-overwrite and rename-identity checks,
  all `FindFirstFileEx` option combinations and failure paths, expanded file
  handle metadata classes, and explicit tests for pending native API bindings.
- Expanded the native WinFS compatibility tests to cover read-only access,
  sharing conflicts, wildcard enumeration, read-only deletion, and guest file
  times.
- Added behavior fixtures for handle reopening, hard links, file replacement,
  byte-range locking, ANSI path operations, and file copying so missing native
  API support has explicit WinFS expectations.
- Added modern WinFS behavior fixtures for temporary files, `CreateFile2`,
  `CopyFile2`/`CopyFileExW`, stream enumeration, and handle-based deletion.
- Added behavior fixtures for symbolic and hard links, ANSI attributes and
  enumeration, `SetEndOfFile`, buffer flushing, and extended overlapped results.
- Extended `SetEndOfFile` coverage to verify truncation, zero-filled extension,
  and invalid-handle errors; corrected handle setup in several pending API
  behavior fixtures.
- Added direct wide-path `MoveFileW` and `DeleteFileW` behavior cases.
- Added wide-path move and delete failure cases for existing destinations and
  missing files.
- Added API-level wide-path attribute toggling and extended metadata success
  and missing-file cases.
- Added ANSI temporary-file and symbolic-link cases, all reference
  `FindFirstFileExA` option combinations, and invalid-input checks for
  `OpenFileById` and `SetFileValidData`.
- Added ANSI replacement and empty-directory removal behavior cases, plus an
  aligned-buffer invalid-handle case for `WriteFileGather`.
- Added wide-path copy and handle-based rename behavior fixtures.
- Added wide-path move-with-replacement and directory create/remove cases.
- Persisted Win32 file attributes and timestamps in WinFS snapshots and change
  replay, including metadata updates through file handles and copied files.
- Implemented guest hard links with shared file identity/content and symbolic
  links that resolve to their targets and survive snapshot reload.
- Routed ANSI file paths through the Windows active code page conversion,
  including Windows-1252 names in create and enumeration operations.
- Added deeper file-ID open, privileged valid-data, aligned gather-write, and
  file-handle completion-port behavior fixtures.
- Implemented native EOF resize and handle-based rename information classes;
  enforced WinFS handle access, sharing, and read-only deletion rules, and
  completed valid guest-handle timestamp updates.
- Corrected wildcard test cleanup paths and asynchronous EOF completion
  expectations in the IOCP fixture.
- Added failed-mutation coverage for overlapping locks, hard-link destination
  conflicts, and invalid handle-information classes.
- Added destination-conflict checks for wide copy and move operations.
- Added ANSI file-mapping persistence and duplicate file completion-port
  association cases.
- Added file-type and file-size metadata checks for directory handles, null
  outputs, and invalid handles.
- Added API-level `SetFilePointer`/`SetFilePointerEx` and
  `GetOverlappedResult` position, completion, and error checks.
- Added completed-operation `GetOverlappedResultEx` and full
  `GetFileInformationByHandle` record checks.
- Added ANSI file-enumeration error cases for empty searches, missing paths,
  and invalid output arguments.
- Added WinFS edge-case tests for truncating writes, recursive tree copy/move,
  and invalid directory create/remove operations.
- Added NT file compatibility tests for EOF resizing, rename-by-handle, and
  resizing files with active mapped views.
- Failed native launches keep the current C: filesystem in memory and discard
  only changes from the failed child process.
- Added live host-folder mounts as guest drives (`mount Z: <host-directory>` or
  `--mount=Z:<host-directory>`). Mounts read and write through to the host and
  are kept outside C: snapshots.

### Removed

- Removed the PE instruction emulator and the `wincli probe` command. Windows
  executables now use the Linux x86-64 native platform backend.

### Added

- Added guest-disk installation for Chocolatey's `7zip.install`: the verified
  package is extracted into WinFS, its silent installer runs through the
  native backend, and `7z` remains available after snapshot reload.
- Added `snapshot save <file>` and `--save-snapshot=<file>` to persist a shell
  or runner disk for later boot with `--snapshot=<file>`.
- Node.js, npm, and portable Chocolatey package contents are kept on the guest
  disk so snapshots preserve installed commands and npm files.
- Added a Chocolatey-compatible `choco install nodejs` shell builtin: it
  downloads the official `node-v<version>-win-x64.zip` from nodejs.org,
  verifies its SHA-256 against the release `SHASUMS256.txt`, caches
  `node.exe` as `C:\bin\node.exe`, and extracts the bundled npm tree so
  bare `node -v` and `npm -v` work in `wincli shell`. `choco` needs no
  bootstrap. Remote scripts fetched with `irm|iex` always execute
  genuinely (no URL is stubbed); scripts needing full PowerShell/.NET
  fail with a clear error.
- Added a `powershell -c <script>` shell passthrough so Windows install
  one-liners run as in-session PS1.
- Added PS1 location cmdlets (`Get/Set/Push/Pop-Location` with
  `pwd`/`cd`/`pushd`/`popd`), `Get-Item`, and `Start-Sleep`.
- Added PS1 `<# ... #>` block-comment support (multi-line, quote-aware).
- Added a live `choco install nodejs` E2E test (`WINCLI_TEST_CHOCO=1`)
  asserting `node -v` prints `v24.21.0` and `npm -v` prints `11.19.0`.

- Added a native byte-mode named-pipe handle model for libuv, with `CreateNamedPipe`,
  `CreateFile`, `ConnectNamedPipe`, synchronous and overlapped transfers, IOCP
  completion, cancellation, pipe state/type queries, and inheritable child
  standard handles. Message-mode pipes remain unsupported.
- Added native job-object and process-wait shims used during Windows child
  process startup.
- Added native Winsock IOCP association, completion-mode handling, `ConnectEx`,
  and zero-byte overlapped receive readiness used by Node.js TLS and npm registry
  installs. Native E2E coverage can verify live registry installs.
- Added native Winsock `listen`, `AcceptEx`, `shutdown`, and accepted-socket
  context support for Node.js TCP servers.
- Added WinFS-backed asynchronous `ReadDirectoryChangesW` notifications and
  long-path normalization used by Node.js `fs.watch` and Vite file watching.
- Added case-insensitive ordinal UTF-16 comparison queried by npm's Windows
  Node.js process.
- Added WinFS `GetShortPathNameW` compatibility for Vite dependency loading;
  WinFS returns the normalized path because it does not create 8.3 aliases.
- Added native Node.js E2E coverage that watches a guest directory and receives
  a file creation event after a WinFS write.
- Added an optional native Node.js E2E test that verifies a host HTTP request
  can reach and receive a response from a guest TCP server.
- Added WinFS-backed `GetFileAttributesExW` metadata and `SetFileAttributesW`
  attributes for files and directories used by npm package discovery.
- Added Windows-sized default stacks for native guest threads, recursive
  thread-aware critical sections, per-thread Windows IDs, address wait/wake
  synchronization, native DNS resolution, and initial Winsock socket setup for
  Node.js.
- Added optional real-binary E2E coverage that seeds the MIT-licensed
  `is-number@7.0.0` npm package into guest `node_modules` and executes it with
  the official Windows Node binary.
- Added native code-page aliases, file seeking, environment updates, and process,
  console, timezone, CPU, and network information queried by Node.js and npm.
- Added optional real-binary E2E coverage for the staged npm CLI `--version`
  path on the native backend.
- Added native WinFS file attributes, disk handle types, and NT file metadata
  queries used by Node.js. The real Windows Node binary now reads and stats
  files supplied through the guest filesystem.
- Added `GetFileInformationByHandleEx`, `GetFileSizeEx`, ANSI file mappings, and
  synchronous `NtWriteFile` support for native Windows processes.
- Added WinFS-backed `NtQueryDirectoryFile` enumeration, including multi-entry
  directory results and restart/end-of-directory behavior used by Node's
  `fs.readdir` implementation.
- Added file-backed `CreateFileMappingW` views with flush/unmap persistence, the
  common `CreateFileW` creation dispositions, and `MoveFileExW` replacement
  support used by package managers and other Windows applications.
- Added WinFS handling for Windows extended-length DOS/NT paths and native
  file-disposition information, including the Windows APIs npm uses for cache
  paths and temporary-file cleanup. The native Node.js E2E now installs the
  real `is-number@7.0.0` tarball with npm before executing it.
- Added `CancelIoEx` and same-thread `CancelIo` for pending native WinFS
  operations, including canceled `OVERLAPPED` status, event signaling, and
  failed IOCP completion packets. Native unit and PE tests cover cancellation
  and its completion race.
- Added a per-process bounded queue with four native workers for pending WinFS
  I/O, replacing one host thread per transfer. A real PE fixture now checks
  multiple concurrent completion packets and the queue-capacity boundary is
  covered by a unit test.
- Added native manual and auto reset event handles, named event reopening,
  `CreateEventA/W`/`CreateEventExA/W`, `SetEvent`, and `ResetEvent`. Overlapped
  WinFS operations now reset and signal `hEvent`, including deferred failures.
- Added background completion for larger overlapped WinFS reads and writes,
  including `ERROR_IO_PENDING`, waitable `GetOverlappedResult`, and failed
  completion packets for deferred EOF. Native PE tests cover both paths.
- Added overlapped WinFS reads and writes with explicit offsets, immediate
  completion packets, per-file IOCP keys, and `GetQueuedCompletionStatus` on
  the native backend. A real Windows PE fixture covers success and error paths.
- Added synchronous `NtReadFile` for WinFS handles with current or explicit
  offsets, EOF status, and NT I/O status blocks. The official Windows ripgrep
  15.2.0 binary now searches guest files and directories, lists files, and
  produces glob-filtered JSON matches on the native backend.
- Added optional real ripgrep E2E coverage for single-file and two-thread
  directory searches, file listing, JSON/glob filtering, and missing paths.
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
  JavaScript evaluation through the default native platform backend.
- Added optional strict import validation with `WINCLI_NATIVE_STRICT_IMPORTS=1`.

### Changed

- Windows last-error state now belongs to each native guest thread and is
  mirrored into the guest TEB, preventing cross-thread error-code races.
- Missing static imports now use named fail-on-call trampolines by default, so
  programs can run when their optional Windows APIs are unused. Calling an
  unsupported import still stops execution with its exact DLL and API name.
- `wincli inspect` reports static native shim coverage; missing optional imports
  may appear even when a tested program path runs successfully.
