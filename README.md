# Win-CLI

Minimal Linux tool for running Windows console programs and filesystem scripts
against an indexed WinFS disk. Its default C: disk is temporary and discarded
when the session ends. No Wine, VM, or host Windows installation is required.

```bash
wincli app.exe [args...]  # minimal x86_64 PE execution (PE32+, native console apps)
wincli --snapshot=tools.winfs shell # boot a saved C: guest disk
wincli --mount=Z:/host/folder shell # expose a host folder as a live drive
wincli script.ps1         # minimal PowerShell-like script execution
wincli shell              # interactive shell: one ephemeral WinFS per session
wincli inspect app.exe    # PE compatibility report: supported vs missing imports
```

### Native platform backend

On Linux/x86-64, `wincli app.exe` executes PE instructions directly on the
host CPU in a forked child. Windows
imports require native shims; an unsupported import fails with its name if the
guest calls it. Set `WINCLI_NATIVE_STRICT_IMPORTS=1` to reject unsupported
imports before entry. `wincli inspect` lists static shim coverage. Other host platforms currently have no PE
execution backend.

The shim code is part of the Rust executable, and an interactive shell selects
its native backend once when the shell starts. Each PE still gets its own
image mapping and import resolution, as it would when the OS loads a new
process.

The native loader has experimental TLS/TEB/PEB initialization. It is not yet
sufficient for general Windows CRT startup or exception handling.

PE programs and PS1 scripts share the same indexed `WinFS`: case-insensitive
lookup with original casing preserved, `C:\` and mounted drive paths, relative
paths, and `.`/`..` normalization. File contents live in a seekable backing
store; file reads fetch only the requested ranges.

## Layout

```text
src/winfs/   indexed, seekable Windows filesystem (shared by EXE shims and PS1)
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

One ephemeral WinFS for the whole session (files created by one command
are visible to the next). Common shell commands include `cd`/`chdir`, `pwd`,
`dir`/`ls`, `type`/`cat`, `copy`/`cp`, `move`/`mv`, `del`/`rm`, `mkdir`,
`rmdir`, and `cls`. Each line can also be a PS1 statement, `install`/`inspect`,
`winget`, `choco`, `powershell -c`, a host `.exe`/`.ps1` file, or a package
installed in the session with args — so `install rg` followed by `rg --version`
works. Use `help` to list the built-in commands.
Errors print as
`wincli: ...` without ending the session; `exit`/`quit` (or Ctrl-D) ends it
with the last guest exit code. Interactive input supports cursor movement,
insertion, deletion, history navigation, and Tab completion for built-in
commands, PATH executables, and entries in the current guest directory. The
prompt goes to stderr, keeping stdout clean for pipes. Interactive command history lives at
`$XDG_STATE_HOME/wincli/shell-history` (or `~/.local/state/wincli/shell-history`)
on the host, so it survives fresh ephemeral shells. A copy also lives at
`C:\.system\shell-history` in WinFS and is carried by saved C: snapshots.
Set `WINCLI_HISTORY_FILE` to choose a different host history file.
Use Windows-style `set NAME=value` or `path C:\tools;%PATH%` to update the
session environment and guest executable search path.

Mount a host folder on a separate guest drive with the `mount` command or at
startup. Mounted files read and write through to the host folder. Use
`mount Z: /path/to/folder ro` or `--mount-ro=Z:/path/to/folder` for a
read-only mount. Snapshots save only C: and do not preserve mount settings.

New snapshots use an append-only indexed WinFS disk file, not ZIP. Boot reads
the C: path index and seeks file data on demand; saving to the active snapshot
appends changed file extents and a new index. Older ZIP snapshots can still be
loaded and are converted the next time they are saved.

## Packages

```bash
wincli shell
winget install BurntSushi.ripgrep.MSVC
rg --version
choco install nodejs
node --version
install demo             # WINCLI_SOURCE=tests/artifacts/packages (local dir)
demo
snapshot save tools.snap
```

`winget` and `choco` are WinCLI shell builtins, not the upstream package
manager executables. WinCLI implements a limited install subset for portable
packages; it verifies catalog hashes and stages installed commands on C:.
`winget install <id>` supports portable or ZIP x64 packages, including
architecture-neutral manifests whose payload validates as x64 PE. Common
WinGet forms such as `-e`, `--exact`, and `--silent` are accepted. MSI, MSIX,
and interactive installer packages are not supported.

`install` is a shorthand for installing from the configured package source.
It resolves `<source>/<name>.json` + `<name>.zip` for local fixtures, stages
the download in temporary process storage, and copies the executable into the
current guest disk at `C:\bin\<name>.exe`. Both the staging area and guest disk are
discarded when WinCLI exits unless you save a snapshot. Load that snapshot on
the next run with `wincli --snapshot=tools.snap shell`; it is the only way to
carry installed programs or other guest files between runs. `WINCLI_CACHE` is
not supported. Guest argv reaches the program via `GetCommandLineW/A` (MSVC
quoting).
`tests/artifacts/packages/` holds offline fixtures built by
`cargo run --example gen_artifacts`.

Remote sources: short aliases (`rg`, `fd`, `jq`, `bat`, `fzf`) or full
WinGet IDs (`BurntSushi.ripgrep.MSVC`). Manifests come from winget-pkgs
(version discovery via GitHub API, YAML via raw); only portable/zip x64
portable/zip x64 packages are accepted (plus neutral portable executables
validated as x64 PE), downloads are SHA-256-verified against the
manifest. Download staging is reused only during the current process and is
removed when WinCLI exits.

## Node.js via `choco`

`choco` is built into the shell (no bootstrap needed). Installing
Node.js fetches the official
distribution zip from nodejs.org, verifies it against the release
`SHASUMS256.txt`, and places `node.exe` plus the bundled npm tree in the
current guest disk. A new shell starts blank, so Node.js is available only
after installing it in that session or loading a snapshot that contains it:

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
snapshot save                # overwrite the snapshot this shell loaded
```

`wincli --save-snapshot=wincli.snap shell` also writes the disk when the shell
exits. A named `snapshot save <file>` establishes the default for later
`snapshot save` commands; without a loaded or previously saved path, the first
save needs a filename.

Set `WINCLI_TEST_CHOCO=1` to run the live download-and-verify E2E test
(`cargo test --test choco_node`).

## Compatibility harness

`wincli inspect` statically reports which imports a real Windows binary needs
versus what WinCLI implements (exit 0 = runnable, 1 = missing APIs). Point it
at portable Windows CLI tools to drive expansion one program at a time:

```bash
wincli inspect rg.exe
```

Native program output streams to the terminal while the program runs. To see
where time is spent, start the shell with `WINCLI_TIMINGS=1 wincli shell`;
WinCLI prints PE loading, native setup, time to first output, guest execution,
and filesystem-state timing details to stderr for each PE program, including
the guest-disk read when a program is launched from the shell.

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
- The interactive shell supports command-line cursor movement, insertion,
  deletion, and history navigation. `GetConsoleCursorInfo` reports a visible
  cursor; screen-buffer APIs beyond the basic dimensions and Ctrl-C handling
  remain unsupported.
