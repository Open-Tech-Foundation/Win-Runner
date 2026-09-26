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

### Native platform backend

On Linux/x86-64, `wincli app.exe` executes PE instructions directly on the
host CPU in a forked child. Windows
imports require native shims; an unsupported import fails with its name if the
guest calls it. Set `WINCLI_NATIVE_STRICT_IMPORTS=1` to reject unsupported
imports before entry. `wincli inspect` lists static shim coverage. Other host platforms currently have no PE
execution backend.

The native loader has experimental TLS/TEB/PEB initialization. It is not yet
sufficient for general Windows CRT startup or exception handling.

PE programs and PS1 scripts share the exact same in-memory `WinFS`: case-insensitive lookup with
original casing preserved, `C:\` + relative paths, `.`/`..` normalization.

## Layout

```text
src/winfs/   in-memory Windows filesystem (shared by EXE shims and PS1)
src/pe/      PE32+ loader and test-EXE builder
src/native.rs Linux x86-64 PE execution and Windows API shims
src/choco.rs Chocolatey-compatible `choco install nodejs` (shell builtin)
src/ps1/     minimal interpreter: New-Item, Set-Content, Add-Content,
              Get-Content, Get-ChildItem, Remove-Item, Copy-Item,
              Move-Item, Test-Path, Get-Item, Get/Set/Push/Pop-Location,
              Start-Sleep, Join-Path, text pipelines (|), irm, iex
tests/artifacts/  committed test artifacts (see below)
```

Unsupported PE imports fail with a named error when called. Strict import
binding is available through `WINCLI_NATIVE_STRICT_IMPORTS=1`.

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
`guests/support.rs`), links with `guests/kernel32.def` (the guest import set
must have native trampolines) plus the sysroot
`alloc`/`core` rlibs (so `extern crate alloc`, bounds-check panics,
and slice helpers resolve without CRT), and copies the results to
`tests/artifacts/exe/rust_*.exe`. Guests are `no_std` self-tests running on the
native backend.
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
`choco`, `powershell -c`, a host `.exe`/`.ps1` file, or a cached package
with args — so `install rg` followed by `rg --version` works in one session. Errors print as
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

## Node.js via `choco`

`choco` is built into the shell (no bootstrap needed). Installing
Node.js fetches the official
distribution zip from nodejs.org, verifies it against the release
`SHASUMS256.txt`, caches `node.exe` as `C:\bin\node.exe`, and extracts
the bundled npm tree so bare `npm` runs through the cached node:

```bash
wincli shell
choco install nodejs --version="24.21.0"
node -v   # v24.21.0
npm -v    # 11.19.0
```

Omitting `--version` installs the pinned default (currently 24.21.0). Community
packages with portable `tools/` payloads can also be installed, for example
`choco install 7zip.portable -y`. `choco install 7zip.install -y` runs the
package's silent 64-bit installer against the guest disk and exposes `7z` in
`C:\bin`:

```bash
choco install 7zip.install -y
7z -h
```

Save the in-session disk, including Chocolatey-installed commands, and load it
on a later run:

```bash
wincli shell
choco install nodejs
choco install 7zip.install -y
snapshot save wincli.snap
exit
wincli --snapshot=wincli.snap shell
node -v
7z -h
```

`wincli --save-snapshot=wincli.snap shell` also writes the disk when the shell
exits. Both forms save guest files and installed tools as a snapshot archive.

Set `WINCLI_TEST_CHOCO=1` to run the live download-and-verify E2E test
(`cargo test --test choco_node`).

## Compatibility harness

`wincli inspect` statically reports which imports a real Windows binary needs
versus what WinCLI implements (exit 0 = runnable, 1 = missing APIs). Point it
at portable Windows CLI tools to drive expansion one program at a time:

```bash
wincli inspect rg.exe
```

The official Node.js 24.21.0 Windows x64 `node.exe` runs on the Linux native
backend for version reporting and simple JavaScript evaluation:

```bash
wincli node.exe --version
wincli node.exe -e 'console.log(1 + 2)'
```

The downloaded binary is kept locally under `target/nodejs/` for development
and is not committed to this repository. Node still imports Windows APIs that
WinCLI does not implement; untested Node features may stop at a named missing
API. Set `WINCLI_NATIVE_DIAGNOSTIC=1` to log dynamic import misses and native
startup calls.
Node can load JavaScript modules and read and stat files in WinFS. With the
staged npm files under `target/nodejs/npm-stage/C/npm`, its CLI `--version`
command also runs on the native backend. The offline tarball and live registry
install paths have both been exercised.
Set `WINCLI_NODE_EXE=target/nodejs/node-v24.21.0-win-x64.exe` when running
`cargo test --test node_native` to include the real binary checks. Set
`WINCLI_TEST_LIVE_NPM=1` as well to install a package from the live npm registry.
The npm E2E uses `WINCLI_NPM_ROOT` if set; otherwise it looks for
`npm-stage/C/npm` beside the Node executable. The executable
comes from `https://nodejs.org/download/release/v24.21.0/win-x64/node.exe`;
its official SHA-256 is
`ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32`.

The official ripgrep 15.2.0 Windows x64 `rg.exe` is a smaller native
filesystem target. With a guest file created in `wincli shell`, it searches
files and directories, lists paths, filters globs, and writes JSON results.
Its Windows x64 zip is available from the [ripgrep release page](https://github.com/BurntSushi/ripgrep/releases/tag/15.2.0).
The archive SHA-256 is
`71b2fef860abe467217a538ff31de02f5258807c0129f771846f87bd029aafc5`.
Keep the extracted executable under `target/compat/rg.exe` and run the real
binary checks with:

```bash
WINCLI_RG_EXE=target/compat/rg.exe cargo test --test rg_native
```

Like Node, ripgrep has optional static imports that `wincli inspect` lists as
missing even when these tested paths run successfully.

## Console contract

Guest output is a transparent byte pipe to the host terminal — same content,
no console emulation (no conpty): programs emitting ANSI escapes render via
the host terminal, and pipes (`wincli rg … | head`) behave identically.

- Console writes are forwarded to host stdout (buffered per run;
  streamed live in CLI runs via a sink).
- `WriteFile` bytes pass through bit-identical; `WriteConsoleW` transcodes
  UTF-16→UTF-8 (invalid sequences → U+FFFD); `GetConsoleOutputCP`
  reports UTF-8. `GetConsoleMode` currently reports a basic console mode for
  standard handles, so some programs emit ANSI color into redirected output.
- Cursor/screen-buffer APIs and Ctrl-C handling are non-goals; unsupported
  console APIs fail clearly so guests fall back.
