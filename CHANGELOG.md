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
