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
