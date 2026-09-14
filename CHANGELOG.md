# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `TerminateProcess` now sends a contained host termination signal to launched
  native children; the child monitor subsequently reaps it and publishes the
  resulting completion state to process waits and exit-code queries.
- Native `CreateProcessW` now has the isolated child-launch path: it maps a
  relocatable PE at a distinct address, patches native imports, creates an
  independent process context, and returns process/thread handles while a
  monitor publishes child completion and its snapshot-backed WinFs changes.
  Non-relocatable child images continue to fail with `ERROR_BAD_EXE_FORMAT`.
- Checked-in Rust guest artifacts now opt into ASLR and retain base relocation
  records, matching the native child-launch requirement. Added native coverage
  for creating, waiting for, and reaping a relocatable WinFs child image.
- Native child registry allocation now reserves distinct process and primary
  thread handles, with a 64-bit `PROCESS_INFORMATION` layout writer for the
  forthcoming successful `CreateProcessW` launch path.
- Added a native distinct-address mapping primitive that reserves a kernel
  selected range, rebases the child PE to that actual address, and copies the
  relocated image for the upcoming child launcher.
- Added checked PE rebasing: validated DIR64 relocation targets can now be
  adjusted for a distinct mapping base, with positive/negative delta and
  overflow coverage.
- PE32+ loading now validates and retains `IMAGE_REL_BASED_DIR64` relocation
  entries, rejecting malformed relocation blocks and unsupported relocation
  types. This supplies the relocation data needed for distinct child-image
  mappings.
- `CreateProcessW` now loads child executable bytes only from WinFs and
  validates them as supported PE images. Missing guest files report
  `ERROR_FILE_NOT_FOUND`; malformed or unsupported PE files report
  `ERROR_BAD_EXE_FORMAT` before the separate-image launch boundary.
- Native processes now own a child-process registry with unique process IDs
  and closable handles. `GetExitCodeProcess`, `TerminateProcess`, and
  `WaitForSingleObject` use those records, including active, timeout, exit,
  and invalid-handle behavior; child PE launch will attach to this registry.
- `CreateProcessW` now parses Windows-quoted command lines and validates its
  application target and guest working directory before launch. Invalid
  process-information records, malformed command lines, and invalid working
  directories return their corresponding Windows errors; actual child PE
  execution remains the next process-registry step.
- Added repository contribution instructions covering commit conventions,
  changelog updates, test expectations, and AI-attribution restrictions.
- Native guest process state is now owned by `NativeProcessContext` rather
  than shared runtime globals: command lines, image/TLS state, filesystem
  handles, thread/timer allocation, last-error/FLS/exception state, and
  snapshot-pipe ownership are isolated behind the process dispatcher. The
  native import bridge now implements current-process IDs and handles,
  `GetExitCodeProcess`, `TerminateProcess`, and correct pseudo-handle
  rejection in `CloseHandle`, establishing the process-core foundation for
  `CreateProcessW` children.
- Added the transport-neutral v1 instance frame contract: a versioned,
  bounded multiplexed envelope for request/response, stdin, stdout, stderr,
  completion, cancellation, and failure events. Unix sockets and future
  Windows named pipes will carry the same frames. `instance exec` now uses
  that frame stream and returns chunked stdout plus an explicit exit frame.
  Interpreter console output is forwarded directly through stdout frames while
  the command runs; buffered script output remains compatible.
- `wincli instance boot <name>`, `status`, and `destroy` now provide the
  first persistent named-instance lifecycle on Unix hosts. A background daemon
  owns a snapshot-backed WinFs image and protects its private control socket
  with mode `0600`; this generic transport is intentionally separate from
  future Windows named-pipe support and from GitHub-specific adapters.
  `wincli instance exec <name> -- <command> [args...]` now sends a bounded
  local request to that daemon and returns command output and exit status from
  its retained guest session.
- PE execution now goes through a platform-neutral `ExecutionBackend`
  interface. The portable interpreter and the Linux x86-64 direct-PE backend
  are registered implementations with stable identifiers and capabilities;
  macOS translation, Windows-native, and VM worker backends can be added
  without changing runner, snapshot, or instance semantics.
  Backends now also expose an output-sink execution hook; the interpreter
  forwards console chunks as they occur, establishing the live-output bridge
  used by future instance stream writers. The Linux native child bridge now
  forwards stdout while draining its pipe, so native instance commands use
  the same live stdout-frame path.
- Native runner commands now retain their WinFs changes across the forked
  direct-PE execution boundary. On guest exit, the child returns a validated
  in-memory snapshot through a private pipe; the host restores it into the
  same ephemeral session without exposing a Linux filesystem mount. This
  enables a native guest to create files consumed by following runner steps.
  `CreateProcessW` is now an explicit native process-model boundary that
  returns `ERROR_CALL_NOT_IMPLEMENTED` until per-process guest contexts and
  inherited-handle semantics are available.
  Native launch state now begins in an explicit `NativeProcessContext`,
  consolidating process-owned command-line, image, and WinFs ownership for
  the ongoing multi-process refactor.
- `wincli --snapshot=os.snap shell` and `runner` now boot a compressed ZIP
  snapshot over the fresh instance image. The documented v1 archive layout
  maps `files/C/...` entries to WinFs paths and verifies a version marker;
  directories are implicit and archive paths cannot escape the guest disk.
  `wincli snapshot build <dir> <os.snap>` deterministically packages the
  regular files beneath `<dir>/C`, with a standard ZIP directory, while
  rejecting symlinks and special files.
- `wincli shell` now boots the same ephemeral runner image as native
  launches, starts in `C:\\actions-runner\\_work`, and discards it when the
  session exits. `wincli runner` is its non-interactive, stdin-driven
  host-control counterpart, providing the initial lifecycle seam for a
  GitHub Actions protocol adapter. Both accept an explicit `@seed <host-file>
  <guest-path>` directive, which copies one host file into the instance and
  permits execution from that guest path without creating a filesystem mount.
- Native launches now boot a fresh, child-local runner WinFs image rather
  than a bare filesystem root. The ephemeral image supplies Windows system,
  runner, work, diagnostics, user-profile, and temp directories and starts
  at `C:\\actions-runner\\_work`. Its state is never mounted from or written
  back to Linux and is discarded after the guest exits. Native current- and
  full-path queries now resolve through that instance filesystem.
- Initial opt-in native Linux/x86-64 PE backend: maps an import-free,
  TLS-free PE32+ fixture at its preferred image base and invokes a returning
  Windows-x64 entry point directly on the host CPU. `WINCLI_BACKEND=native`
  additionally runs `rust_hello.exe`-class guests in a child process through
  IAT trampolines for `GetCommandLineW`, `GetStdHandle`, `WriteFile`, and
  `ExitProcess`, including MSVC command-line quoting. Native Rust guests now
  also use a child-local in-memory WinFS through `CreateFileW`, `ReadFile`,
  `CloseHandle`, directory creation/removal, delete, copy, and move shims.
  `GetProcessHeap`, `HeapAlloc`, and `HeapFree` let the native backend run the
  Rust allocator guest (`Vec`, `String`, `Box`, and `BTreeMap`).
  `rust_alloc_fs.exe` confirms allocation-backed formatting and WinFS I/O work
  together on the native path.
  `rust_hashmap.exe` additionally covers native allocation growth, rehashing,
  lookup, and removal.
  Native regression coverage now includes the 16-phase `rust_lang.exe` guest
  and `rust_fp.exe` floating-point workload.
  Native PE bring-up now creates a child-local TEB/PEB/TLS block, initializes
  the image TLS index, installs the guest `GS` base, and maps unresolved
  imports to contained fail trampolines for real-program startup diagnostics.
  Native ripgrep bring-up adds `GetSystemTimeAsFileTime` and
  `GetCurrentThreadId` for CRT security-cookie initialization, plus
  `GetCurrentProcessId`, `QueryPerformanceCounter`, and a single-threaded
  critical-section shim (`InitializeCriticalSectionEx`, enter, leave, and
  delete). A single-threaded `FlsAlloc`/get/set/free slot supports ripgrep CRT
  fiber-local initialization, and
  `GetCurrentProcess` supplies the Windows pseudo-handle. `GetLastError` and
  `SetLastError` preserve child-local error values. `GetStartupInfoW` exposes
  a zeroed console-process startup record, and `GetFileType` identifies the
  native child standard descriptors as console character handles.
  Both `GetCommandLineW` and `GetCommandLineA` expose the native guest command
  line. ANSI and OEM code-page queries report Windows-1252, while code-page
  validation supports Windows-1252 and UTF-8; `GetCPInfo` supplies their CRT
  metadata. `MultiByteToWideChar` converts those pages for CRT locale setup.
  `GetStringTypeW` provides ASCII `CT_CTYPE1` character classifications.
  `LCMapStringW` supports CRT string sizing, copying, and ASCII case mapping.
  `WideCharToMultiByte` converts native CRT strings to Windows-1252 or UTF-8.
  `GetModuleFileNameW` supplies a synthetic Windows module path for CRT path
  discovery. `InitializeSListHead` creates empty 64-bit CRT list headers.
  `GetEnvironmentStringsW` exposes an empty child-local environment block.
  `SetUnhandledExceptionFilter` retains the child-local handler pointer for
  CRT setup. `AddVectoredExceptionHandler` records the native child callback
  for startup compatibility. `SetThreadStackGuarantee` accepts CRT guard-stack
  requests, `GetCurrentThread` supplies its pseudo-handle, and
  `GetModuleHandleA` resolves the CRT's `kernel32` probe, and `HeapReAlloc`
  grows CRT process-heap allocations. `ProcessPrng` draws native Rust runtime
  entropy from Linux `getrandom`, and `GetConsoleMode` exposes a basic mode on
  the child standard descriptors. `GetConsoleOutputCP` returns the matching
  Windows-1252 console encoding. `SetFileTime` accepts metadata updates on
  standard descriptors without persisting timestamps. `WriteConsoleW` writes
  native UTF-16 console text as UTF-8. `GetEnvironmentVariableW` correctly
  reports missing values from the native child’s empty environment, including
  ripgrep's dynamic kernel32 lookup. `GetCurrentDirectoryW` supplies the
  synthetic `C:\\` working directory. `GetComputerNameExW` exposes the
  synthetic `wincli` host name. `GetSystemInfo` exposes the x64 page and
  allocation layout. `GetFullPathNameW` expands relative paths in the native
  `C:\\` WinFs namespace. `GetUserProfileDirectoryW` provides the synthetic
  `C:\\Users\\wincli` profile path. `GetConsoleScreenBufferInfo` exposes an
  80×25 native console buffer, and `SetConsoleMode` accepts standard-handle
  mode changes. `FormatMessageW` supplies bounded native error text, and
  `GetModuleHandleW(NULL)` and `GetModuleHandleExW` return the mapped main
  module. `CreateFileW` accepts existing WinFs directories for enumeration,
  `GetFileInformationByHandle` reports directory-aware WinFs metadata, and
  `GetFinalPathNameByHandleW` returns extended WinFs paths. WinFs directory
  enumeration now supports `FindFirstFileExW`, `FindNextFileW`, and
  `FindClose`. Native `CreateThread` now launches guest workers with cloned
  TLS state, and `WaitForSingleObject` joins their Windows-style handles.
  `QueryPerformanceFrequency` matches the native nanosecond counter.
  `WaitOnAddress` and wake calls provide cooperative worker parking. Native
  waitable timers are immediately signaled for worker scheduling.
  Native WinFs and its file/enumeration handle tables are now synchronized for
  concurrent guest-worker access.
  `VirtualProtect`
  translates the standard page-access modes to page-aligned Linux mappings.
  A narrow API-set pseudo-module resolves the CRT's dynamic `CompareStringEx`
  lookup without loading a host DLL.
  Imported programs outside that baseline remain on the interpreter.
- Minimal `wincli` tool: `wincli app.exe` runs PE32+ x86_64 console apps,
  `wincli script.ps1` runs filesystem scripts, both on the same in-memory
  `WinFS` (case-insensitive, `.`/`..` aware, no host filesystem access).
- `winfs`: in-memory Windows-style filesystem shared by EXE shims and PS1.
- `pe`: PE32+ loader (unknown imports fail clearly) plus a minimal x86_64
  interpreter for straight-line Win32 code.
- `winapi`: shims for `ExitProcess`, `GetStdHandle`, `WriteFile`,
  `CreateFileW`, `ReadFile`, `CloseHandle`, `CreateDirectoryW`,
  `RemoveDirectoryW`, `DeleteFileW`, `MoveFileW`, `CopyFileW`.
- `ps1`: minimal interpreter for `New-Item`, `Set-Content`, `Add-Content`,
  `Get-Content`, `Get-ChildItem`, `Remove-Item`, `Copy-Item`, `Move-Item`,
  `Test-Path`.
- Unit tests (WinFS) and end-to-end tests (all nine required behaviors).
- Committed test artifacts: `tests/artifacts/ps1/*.ps1` scripts covering
  every cmdlet (plus case-insensitivity, `./..`, error path),
  `tests/artifacts/exe/*.exe` self-verifying PE32+ guest programs, and the
  `examples/gen_artifacts.rs` Rust generator that builds them. Black-box CLI
  tests run `wincli` against every artifact.
- Rust guest lane (`guests/`): real `no_std` programs for
  `x86_64-pc-windows-msvc` built offline with `rustc` + `rust-lld`
  (`guests/build.sh`, `guests/kernel32.def` pinned to the supported API set),
  starting with `rust_hello.exe` plus a CLI test that also asserts the guest
  imports stay within the supported set.
- `guests/fs_selftest.rs` + `rust_fs.exe`: real Rust guest exercising every
  FS shim (write/read/byte-compare/copy/move/delete, mkdir/rmdir plus
  negative cases, mixed-case paths), self-reporting `PASS`/exit 0.
- Emulator: XMM state with `xorps`/`movaps`/`movups`, group-1 `Eb,Ib`
  (`CMP r/m8,imm8` etc.), `SETcc`, 8-bit `TEST` — each demanded by rustc
  output (trace-driven, with unit tests).
- Fixed a real Win-x64 ABI bug the Rust guest exposed: `CreateFileW`
  `creation` is the 5th arg (first stack slot); shim and test-EXE builder
  were both off by one slot in the same direction, masking each other.
- `wincli inspect <app.exe`: static compatibility report (arch, entry,
  supported vs missing imports; exit 0 = runnable, 1 = missing/invalid).
  Backed by lenient PE loading that collects unknown imports instead of
  failing; the exec path stays strict and `Runner` refuses lenient images.
- P1 offline packages: `wincli install <pkg>` from local `$WINCLI_SOURCE`
  dirs into a content-addressed host cache (`$WINCLI_CACHE`: `archives/`,
  `pkgs/`, `index/`), with vendored SHA-256 + stored-zip support, guest
  address `C:\bin\<exe>`, and `inspect <cached-name>` lookup. Offline
  fixtures in `tests/artifacts/packages/`; remote WinGet sources + deflate
  are P2.
- P2 remote packages: default install source is the WinGet catalog
  (short aliases `rg`/`fd`/`jq`/`bat`/`fzf` or full IDs; version discovery
  via GitHub API, manifests via raw, portable/zip-x64 only, SHA-256
  verified, never re-downloads). Vendored raw-DEFLATE decoder with zip-bomb
  guard; fixed a header-offset bug it exposed in the zip reader. Live
  acceptance installs real ripgrep; `inspect rg` reports 5/127 supported as
  the expansion backlog.
- Documented console contract: transparent byte pipe to the host terminal,
  no console emulation; `WriteConsoleW`/`GetConsoleMode`/streaming/input
  planned with run-with-args.
- P3 run-with-args: `wincli <exe|pkg> [args...]` with guest argv via
  `GetCommandLineW/A` (64K guest block, MSVC quoting, unit-tested),
  bare-name and `C:\bin\` resolution through the package cache, and a
  `rust_argv.exe` echo guest proving it with real rustc output.
- Console shims demanded by real tools: `GetConsoleMode` (TTY-aware),
  `SetConsoleMode`, `WriteConsoleW` (UTF-16→UTF-8), `GetConsoleOutputCP`
  (UTF-8), `SetConsoleTextAttribute`, line-buffered `ReadConsoleW`, plus
  live-streaming console sink (buffered behavior preserved for tests).
- Emulator, trace-driven by the argv guest: 16-bit `TEST`/`MOV`/`MOV imm`,
  `CMOVcc`, multi-byte `NOP`, segment-override-tolerant prefixes with a
  clear FS/GS (TLS) error. Guest rule documented: no unproven bounds
  checks (`panic_bounds_check` is undefined under `/NODEFAULTLIB`).
- `guests/lang.rs` (`rust_lang.exe`): 16 self-verifying phases covering
  conditionals, loops, match, calls/recursion, refs, structs/enums, casts,
  bitwise ops, slices, u128, signed division, fn pointers, bit intrinsics.
- Scalar-double FP: `MOVSD`/`ADDSD`/`SUBSD`/`MULSD`/`DIVSD`/`CMPLTSD`
  (bit-identical via host f64 ops), `UCOMISD` with ZF/PF/CF (new `pf`
  flag, `JP`/`JNP` now work), `ANDPD`/`ANDNPD`/`ORPD`, `MOVAPD`, plus a
  `rust_fp.exe` guest proving `FP-OK` (guests define `_fltused` themselves).
- `guests/alloc.rs` (`rust_alloc.exe`): `extern crate alloc` on a
  `HeapAlloc`-backed `#[global_allocator]` — `Vec`/`String`/`format!`,
  closures, `Box`/`BTreeMap`/`sort` all pass. Link recipe: sysroot
  `alloc`/`core` rlibs + guest-provided `memcpy`/`memset`/`strlen`/
  `__chkstk`/`__CxxFrameHandler3` and the two toolchain-specific
  `__rustc::` alloc gates (loud link failure documents the coupling).
- `guests/alloc_fs.rs` (`rust_alloc_fs.exe`): `format!` (width/precision/
  float) + WinFS file write/read exact roundtrip + cleanup. Shared guest
  scaffold extracted to `guests/support.rs`. Emulator additions demanded
  along the way: `RCL`/`RCR` carry chains, 8-bit Grp2, 3-operand `IMUL`,
  `PAND`/`PANDN`/`POR`.
- Emulator 8-bit high-byte registers: without a REX prefix, indices 4-7
  address `AH`/`CH`/`DH`/`BH` (the hashmap guest's FNV loop reads `BH` via
  `movzx edx,bh`; the old code read `DIL` instead, silently corrupting
  hashes). Central `read_r8`/`write_r8` helpers cover `movzx`/`movsx`,
  `mov r/m8,r8`, `SETcc`, `XADD`/`CMPXCHG`/`XCHG`, `TEST`, `mov r8,imm8`
  and the generic ALU group, with unit tests for each direction.
- `guests/hashmap.rs` (`rust_hashmap.exe`): hand-rolled open-addressing map
  (FNV-1a, linear probing, growth/rehash, removal) passing `H1`-`H5`/`PASS`,
  with a CLI end-to-end test.
- Fixed a stack-layout bug the real `rg.exe` exposed: `RSP` started at
  top-of-memory so deep CRT startup marched down through the TEB page and
  heap tail (clobbering the TLS slot array and faulting on a `-1` slot).
  `RSP` now starts at the top of the dedicated 2MB stack region, with a unit
  test pinning the entry invariant.
- Emulator, trace-driven by real `rg.exe --help`: `BT`/`BTS`/`BTR`/`BTC`
  `r/m,r` (`0F A3`/`AB`/`B3`/`BB`) with register masking and memory
  bit-string addressing (only `CF` changes), plus unit tests for each form.
- Emulator, trace-driven by real `rg.exe --help`: `MOVQ xmm/m64,xmm`
  (`66 0F D6`, low qword, zero-extending reg-reg form) with a unit test;
  MMX and `MOVQ2DQ` spellings fail clearly.
- Emulator, trace-driven by real `rg.exe --help`: `UNPCKLPS xmm,xmm/m128`
  (`0F 14`, low-lane interleave) with a unit test; prefixed spellings fail
  clearly.
- Emulator, trace-driven by real `rg.exe --help`: packed double
  `ADDPD`/`MULPD`/`SUBPD`/`DIVPD` (`66 0F 58`/`59`/`5C`/`5E`, per-lane host
  `f64`, bit-identical) with unit tests for reg and mem forms plus NaN
  propagation.
- Real `rg.exe --version` now prints and exits 0: `NtWriteFile` is a real
  shim (Rust std writes console/file output through it, not `WriteFile`;
  synchronous, console + WinFS file handles, `IoStatusBlock` status/count),
  promoted from fail-stub to supported with a builder-probe test. Minimal
  zeroed `PEB_LDR_DATA` so loader-bit checks see genuine values.
  `CVTSI2SD` (`F2 0F 2A`) joined the scalar-double arm along the way.
- `wincli shell`: interactive session with one WinFS. Each line is a PS1
  statement, `install`/`inspect`, a host `.exe`/`.ps1` file, or a cached
  package run; guest output streams, errors print and continue, `exit`/`quit`
  (Ctrl-D) ends with the last code. Unit-tested dispatch plus a piped-stdin
  end-to-end test (offline install + run + shared files).
- PS1 text pipelines and download-and-run: `a | b` feeds captured text to
  the next command, `irm`/`Invoke-RestMethod` GETs a URL via host curl, and
  `iex`/`Invoke-Expression` runs text as code in the same session (nesting
  capped). Unit-tested offline; `irm <url> | iex` is the entry pattern real
  installer scripts use.
- PS1 variables: `$name = value` with session persistence (`Session` +
  `run_ps1_session`; the shell shares one), `$env:`/`$HOME` reads from the
  host, `$null`/unknown names expand empty, comparison operators fail
  clearly. Unit-tested including shape errors.
- PS1 string interpolation: double-quoted `$x`, `${x}`, and `$(...)`
  subexpressions (captured, trimmed); single-quoted spans stay verbatim.
  Unit-tested including unbalanced delimiters.
- PS1 `if`/`elseif`/`else` blocks (same-line or next-line tails) with
  truthiness, `-not`, and case-insensitive `-eq`/`-ne`; `throw` surfaces
  its message. Methods, properties, arrays, and other operators fail
  clearly. Unit-tested including chains, nesting, and shape errors.
- PS1 arrays and membership: `@(...)` literals, `+=` appends, `.Count` /
  `.Length`, and `-in` / `-notin` / `-contains` / `-notcontains`
  (case-insensitive); `-match` and friends fail clearly. Unit-tested.
- PS1 `switch` on literal patterns plus `default` (case-insensitive),
  as a statement or an assignment value; bare quoted/`$` strings output
  their value. Scriptblock patterns and flags fail clearly. Unit-tested.
- PS1 `foreach` over arrays/literals/scalars with `break`/`continue`
  (dynamic scope, nested-safe), and `function` definitions with positional
  params, child-scope calls, and capturable output. Unit-tested.
- PS1 hashtables: `@{}` literals, `.ContainsKey()`, `[key]` reads/writes
  (arrays/strings index too, negatives count back). Other methods and
  entry-ful literals fail clearly. Unit-tested.
- PS1 `try`/`catch`/`finally` (typed catches accepted, first wins;
  `finally` always runs and overrides in-flight signals/breaks) and
  `Join-Path` (multi-child join, `-Resolve` checks existence).
  Error paths flush partial output first in both CLI and shell. Unit-tested.
- PS1 builtin capture (`$x = Join-Path ...` runs any builtin capturing
  output) and `Out-Null`. Unit-tested.
- PS1 string methods: `ToUpper`/`ToLower`, `Trim`/`TrimStart`/`TrimEnd`,
  `Replace`, `Split` (arrays, chainable with `[n]`), `StartsWith` /
  `EndsWith` / `Contains`; tokenizer keeps quotes inside `(...)` so quoted
  literals re-parse. Unit-tested.
- PS1 static .NET calls: `[Environment]` get/set (User/Machine read the
  host process env; sets are session-local), `[Guid]::NewGuid` (v4 from
  host randomness), `[regex]::Escape`; plus `ToString` (`'N'` strips
  dashes). Unit-tested.
- PS1 pipeline cmdlets over text/JSON: `ForEach-Object`/`%` (binds `$_`,
  JSON arrays enumerate), `Where-Object`/`where`/`?` (conditions with
  `-match`), `Select-Object`/`select -First N`; a regex subset (literals,
  classes, anchors, alternation, groups, `*`/`+`/`?`, case-insensitive)
  with loud errors outside it; JSON auto-parse in `irm` (arrays flow one
  element per line); `(...)` grouping in statements and values; bare
  collections enumerate; `-ErrorAction`/`-ErrorVariable` are universal
  no-ops. Unit-tested.
- PS1 pipeline cmdlets over text/JSON: `ForEach-Object`/`%` (binds `$_`,
  JSON arrays enumerate), `Where-Object`/`where`/`?` (conditions with
  `-match`), `Select-Object`/`select -First N`; a regex subset (literals,
  classes, anchors, alternation, groups, `*`/`+`/`?`, case-insensitive)
  with loud errors outside it; JSON auto-parse in `irm` (arrays flow one
  element per line); `(...)` grouping in statements and values. Unit-tested.
- PS1 download/verify/extract: `Invoke-WebRequest`/`iwr`/`wget` (`-Uri`,
  `-OutFile`, `-UseBasicParsing` no-op), `Expand-Archive` (`-Path`,
  `-DestinationPath`, `-Force`), `Get-FileHash` (SHA-256 only; object form
  with `.Hash`/`.Algorithm`/`.Path` so `(Get-FileHash $f).Hash` works);
  `install::zip_entries`/`extract_bytes` factored out of `extract_entry`.
  Unit-tested offline (FIPS vector, stored-zip tree extraction).
- PS1 expressions: whole-token `(...)` groups in arguments, member/method/
  index tails on parenthesized values (`(Get-FileHash $f).Hash.ToLower()`,
  `(($line -split '\s+')[0])`), the `-split` regex operator (leftmost,
  greedy), `A + B` string concatenation, `X -join S` expression statements,
  and full pipelines in assignments (`$line = Get-Content $f | Where ... |
  Select -First 1` captures the last stage, not the first). Unit-tested.
- PS1 conditions: `-and`/`-or` with short-circuiting, and whole-group
  `(...)` conditions (comparison-shaped inners evaluate as conditions,
  command-shaped ones run with output tested for truthiness, e.g.
  `((Test-Path $p) -and ($a -ne $b))`). Unit-tested.
- Milestone (live-network validation, not in the suite): the real ES-Runtime
  `install.ps1` via `irm ... | iex` runs end to end, installing and
  checksum-verifying both the `esrun` and `esdev` releases.
- Emulator, trace-driven by real `rg.exe --help` output corruption (8-byte
  forward smears with content from ~15 bytes earlier): `F3 0F 7E` without
  REX.W is MOVQ (8-byte load), not MOVD — it executed as a store, never
  loading. Fixed with unit tests; `--help` output is now word-identical to
  upstream. Caught via guest watchpoints, disassembly, and a reference
  Linux binary (kept out of tree).
- Emulator, trace-driven by real `rg.exe` search: `PINSRW`, `PUNPCKHBW`,
  `PUNPCKLWD`/`HWD`, `PACKUSWB`, scalar `MOVSS` load/store, `ADC`/`SBB`
  `AL,imm8` plus Grp4 `INC`/`DEC r/m8` — each with unit tests.
- `winapi` for real search: fixed `GetCurrentDirectoryW` arg order
  (`nBufferLength` first); new `GetFileSizeEx`,
  `GetFileInformationByHandle`/`Ex` (correct struct layouts), `NtReadFile`
  (UCRT read path, EOF semantics); completed `GetSystemInfo` to 48 bytes
  (missing allocation granularity divided-by-zeroed `memmap2`).
  Unit-tested via builder probes (size, info structs, read round-trip).
- W^X enforcement: guest writes to executable-but-not-writable sections
  fail loudly (loader IAT patching exempt, like the real loader); test
  builder emits RWX sections and fixtures were regenerated
  (`gen_artifacts`, plus manual `demoz.zip` — see its note).
- `guests/memcpy.rs` (`rust_memcpy.exe`): copy torture (sizes incl.
  212/213, misaligned, overlapping, explicit `movdqu` loops, ~100KB
  `format!` growth) with e2e test.
- Milestone (live-network validation): real `rg.exe` searches WinFS files
  end to end (`rg error C:\log.txt` prints matches); the live acceptance
  test now covers install → inspect (0 missing) → search.
- `winapi` for real directory walks: `FindFirstFileExW`/`FindNextFileW`/
  `FindClose` over WinFS (`*`/`?` wildcards, case-insensitive, dirs-only op,
  `WIN32_FIND_DATAW`, `NO_MORE_FILES` exhaustion), `GetFinalPathNameByHandleW`
  (canonical path + NUL, size query), and `CreateFileW` directory handles only
  with `FILE_FLAG_BACKUP_SEMANTICS`. Promoted from fail-stubs to supported.
  Unit-tested via builder probes (wildcard matcher, enumerate/count/close).
- Emulator, trace-driven by real `rg.exe` directory walking: `MOVLPS`/`MOVHPS`
  loads merge one qword (other half preserved) and stores write memory
  (reg-reg stores fail clearly), with a unit test; test builder gains a
  `jmp rel32` label helper used by the enumeration probe.
- `GetFinalPathNameByHandleW` now covered by a builder probe (length, content
  spot-checks, NUL terminator, `n=0` size query); removed stale
  `GetFileInformationByHandle`/`Ex` duplicates from the fail-stub list (they
  are supported shims).
