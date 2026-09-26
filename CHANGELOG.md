# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

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
  Coverage follows the `SetFilePointer`/`ReadFile` cases in Wine's
  `dlls/kernel32/tests/file.c`.
- Added Rust tests modeled on modern file-operation cases from Wine's
  `file.c`, covering copy, move, delete, enumeration, metadata, and directory
  cleanup through WinFS and the native Win32 shims.
- Expanded the Wine-inspired native tests to cover read-only access, sharing
  conflicts, wildcard enumeration, read-only deletion, and guest file times.
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
