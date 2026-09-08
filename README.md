# Win-CLI

Minimal Linux tool for running Windows console programs and filesystem scripts
against a fully in-memory Windows-style filesystem. No Wine, VM, Windows DLLs,
or host filesystem backing.

```bash
wincli app.exe [args...]  # minimal x86_64 PE execution (PE32+, native console apps)
wincli rg --version       # cached package by bare name (or C:\bin\rg.exe)
wincli script.ps1         # minimal PowerShell-like script execution
wincli shell              # interactive shell: one in-memory WinFS per session
wincli inspect app.exe    # PE compatibility report: supported vs missing imports
```

Both share the exact same in-memory `WinFS`: case-insensitive lookup with
original casing preserved, `C:\` + relative paths, `.`/`..` normalization.

## Layout

```text
src/winfs/   in-memory Windows filesystem (shared by EXE shims and PS1)
src/pe/      PE32+ loader, minimal x86_64 interpreter, test-EXE builder
src/winapi/  Win32 shims: ExitProcess, GetStdHandle, WriteFile,
             CreateFileW, ReadFile, CloseHandle, CreateDirectoryW,
             RemoveDirectoryW, DeleteFileW, MoveFileW, CopyFileW,
             GetCommandLineW/A, GetConsoleMode, SetConsoleMode,
             WriteConsoleW, GetConsoleOutputCP, SetConsoleTextAttribute,
             ReadConsoleW
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

This compiles `guests/*.rs` (`hello.rs`, `fs_selftest.rs`, `argv_echo.rs`,
`lang.rs`, `fp.rs`, `alloc.rs`, `alloc_fs.rs`; shared scaffold in
`guests/support.rs`), links with `guests/kernel32.def` (exactly the supported
API set — keep in sync with `pe::SUPPORTED_APIS`) plus the sysroot
`alloc`/`core` rlibs (so `extern crate alloc`, bounds-check panics,
and slice helpers resolve without CRT), and copies the results to
`tests/artifacts/exe/rust_*.exe`. Guests are `no_std` self-tests: new rustc
output not yet emulated fails with a clear `unsupported opcode` error, which
drives emulator growth (so far: `xorps`/`movaps`/`movups`, `CMP r/m8,imm8`,
`SETcc`, `TEST r/m8`, 16-bit ops, `CMOVcc`, shifts/rotates, `XCHG`, `CPUID`,
string ops, Grp3 mul/div, 8-bit ALU, scalar-double + `UCOMISD`).
Guest rules: no CRT (`_fltused`, `memcpy`/`memset`, `__chkstk`,
`strlen`, `__CxxFrameHandler3` stubs live in the guest); toolchain-specific
`__rustc::` alloc link gates are defined in-guest and fail loudly at link
if the toolchain changes.

## Tests

```bash
cargo test   # unit tests + CLI end-to-end tests against tests/artifacts/
```

## Interactive shell

```bash
wincli shell
```

One in-memory WinFS for the whole session (files created by one command
are visible to the next). Each line is a PS1 statement, `install`/`inspect`,
a host `.exe`/`.ps1` file, or a cached package with args — so `install rg`
followed by `rg --version` works in one session. Errors print as
`wincli: ...` without ending the session; `exit`/`quit` (or Ctrl-D) ends it
with the last guest exit code. The prompt goes to stderr, keeping stdout
clean for pipes.

## Packages

```bash
wincli install rg        # remote WinGet catalog (default source)
wincli install demo      # WINCLI_SOURCE=tests/artifacts/packages (local dir)
wincli inspect rg        # inspect the cached package
```

`install` resolves `<source>/<name>.json` + `<name>.zip`, stores the blob
content-addressed under `$WINCLI_CACHE/archives/`, extracts the exe to
`pkgs/<name>.exe`, and reports the guest-logical address (`C:\bin\demo.exe`;
bytes live in the host cache, the guest FS stays in-memory per run).
Run targets resolve as: host path first, then cached package
(`name`, `name.exe`, or `C:\bin\name.exe`); guest argv after the target
reaches the program via `GetCommandLineW/A` (MSVC quoting).
Remote WinGet-catalog sources, hash verification, and deflate land in P2;
until then only local directories (`WINCLI_SOURCE=./dir`, stored zips).
`tests/artifacts/packages/` holds offline fixtures built by
`cargo run --example gen_artifacts`.

Remote sources: short aliases (`rg`, `fd`, `jq`, `bat`, `fzf`) or full
WinGet IDs (`BurntSushi.ripgrep.MSVC`). Manifests come from winget-pkgs
(version discovery via GitHub API, YAML via raw); only portable/zip x64
installers are accepted, downloads are SHA-256-verified against the
manifest, and re-installs never re-download (content-addressed cache).

## Compatibility harness

`wincli inspect` statically reports which imports a real Windows binary needs
versus what WinCLI implements (exit 0 = runnable, 1 = missing APIs). Point it
at portable Windows CLI tools to drive expansion one program at a time:

```bash
wincli inspect rg.exe
```

Planned next step is `wincli install <name>`: resolve portable Windows x64
releases (preferred source: the WinGet catalog, portable EXE / ZIP only —
no MSI/MSIX/setup emulation), cache the PE on the host, and run it through
the runtime with its filesystem activity landing in WinFS.

## Console contract

Guest output is a transparent byte pipe to the host terminal — same content,
no console emulation (no conpty): programs emitting ANSI escapes render via
the host terminal, and pipes (`wincli rg … | head`) behave identically.

- Console writes are forwarded to host stdout (buffered per run;
  streamed live in CLI runs via a sink).
- `WriteFile` bytes pass through bit-identical; `WriteConsoleW` transcodes
  UTF-16→UTF-8 (invalid sequences → U+FFFD); `GetConsoleMode` succeeds iff
  host stdout is a TTY (so `--color=auto` works); `GetConsoleOutputCP`
  reports UTF-8; input is line-buffered (`ReadConsoleW`).
- Cursor/screen-buffer APIs and Ctrl-C handling are non-goals; unsupported
  console APIs fail clearly so guests fall back.
