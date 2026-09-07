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
- Documented console contract: transparent byte pipe to the host terminal,
  no console emulation; `WriteConsoleW`/`GetConsoleMode`/streaming/input
  planned with run-with-args.
