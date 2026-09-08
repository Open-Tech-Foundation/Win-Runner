# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

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
