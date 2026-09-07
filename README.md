# Win-CLI

Minimal Linux tool for running Windows console programs and filesystem scripts
against a fully in-memory Windows-style filesystem. No Wine, VM, Windows DLLs,
or host filesystem backing.

```bash
wincli app.exe     # minimal x86_64 PE execution (PE32+, native console apps)
wincli script.ps1  # minimal PowerShell-like script execution
```

Both share the exact same in-memory `WinFS`: case-insensitive lookup with
original casing preserved, `C:\` + relative paths, `.`/`..` normalization.

## Layout

```text
src/winfs/   in-memory Windows filesystem (shared by EXE shims and PS1)
src/pe/      PE32+ loader, minimal x86_64 interpreter, test-EXE builder
src/winapi/  Win32 shims: ExitProcess, GetStdHandle, WriteFile,
             CreateFileW, ReadFile, CloseHandle, CreateDirectoryW,
             RemoveDirectoryW, DeleteFileW, MoveFileW, CopyFileW
src/ps1/     minimal interpreter: New-Item, Set-Content, Add-Content,
             Get-Content, Get-ChildItem, Remove-Item, Copy-Item,
             Move-Item, Test-Path
tests/artifacts/  committed test artifacts (see below)
```

Unsupported PE imports and unemulated opcodes fail with a clear error instead
of silently succeeding.

## Test artifacts

- `tests/artifacts/ps1/*.ps1` — scripts covering every cmdlet, plus
  case-insensitivity, `./..` normalization, and an error-path script.
- `tests/artifacts/exe/*.exe` — real PE32+ x86_64 guest programs. The
  `fs_*.exe` guests self-verify inside the guest (print `PASS`, exit 0), so
  each `wincli` run is a fully observable black box despite the per-process
  WinFS.
- `examples/gen_artifacts.rs` — the Rust generator that builds the `.exe`
  artifacts from the `pe::builder` API. Regenerate with:

```bash
cargo run --example gen_artifacts
```

## Rust guests (`guests/`)

Real Rust programs targeting `x86_64-pc-windows-msvc`, written `no_std` +
`no_main` with a custom entry so they need no CRT startup and only the Win32
APIs WinCLI implements. Built with rustup parts only (`rustc` + `rust-lld`,
no mingw/xwin):

```bash
./guests/build.sh   # needs: rustup target add x86_64-pc-windows-msvc
```

This compiles `guests/*.rs`, links with `guests/kernel32.def` (exactly the
supported API set — keep in sync with `pe::SUPPORTED_APIS`), and copies the
result to `tests/artifacts/exe/rust_*.exe`.

## Tests

```bash
cargo test   # unit tests + CLI end-to-end tests against tests/artifacts/
```
