# Windows oracle

Differential tests of Win-Runner against real Windows. They check Windows
compatibility itself, not any application: each probe calls Win32 APIs
directly with fixed inputs and prints what happened. The same `.exe` runs on
real Windows, whose transcript is the expected result, and under Win-Runner.
Every line that differs is a place where Win-Runner does not behave like
Windows.

## Probes

`guests/oracle/<name>.rs` builds to `tests/artifacts/exe/oracle_<name>.exe`
with `guests/build-oracle.sh` (rustc and rust-lld only). A probe:

- is `no_std` with no C runtime, so nothing but the Win32 API is exercised;
- imports only `GetStdHandle`, `WriteFile`, `ExitProcess`, `GetModuleHandleW`,
  and `GetProcAddress`, and looks up every API it tests at run time, so a
  missing API prints `<case>: unavailable` instead of stopping the probe;
- prints one line per observation, `<case>: <result>`, with the error code
  (`err=<n>`) of a failed call; `SetLastError(0)` runs before each call;
- normalizes what depends on the machine: its work directory prints as
  `<W>`, the directory it started in as `<B>`, their drive letter as `<D>`.
  Timestamps, handles, and ids are not printed;
- ends with `END`.

| Probe | Covers |
| --- | --- |
| `fs_paths` | path normalization, `CreateFileW` outcomes, final paths, directory listings, file-operation error codes |
| `path_names` | path spellings from `GetLongPathNameW`, `GetFullPathNameW`, and final paths |
| `links` | `CreateSymbolicLinkW`, what a handle names with and without `FILE_FLAG_OPEN_REPARSE_POINT`, `FSCTL_GET_REPARSE_POINT` data |
| `pool_console` | `QueueUserWorkItem`, `MapVirtualKeyW`, console input functions on a non-console handle |
| `apc_io` | per-thread APC queues, FIFO and duplicated thread handles, alertable single/multiple waits, wait-all state preservation, extended file completion callbacks, EOF, pipe cancellation, result timeouts and alertable completion-port waits |
| `dll_search` | directory cookies and removal, Set/Get DLL directory buffers, search flags and defaults, loaded-name reuse, distinct absolute paths, recursive dependencies, loaded module filenames and truncation |
| `file_locks` | shared/exclusive byte ranges, contention, read/write exclusion, exact unlock, close cleanup, 64-bit offsets, async grants and cancellation |
| `process_runtime` | anonymous pipe access, duplication and EOF, startup handle-list filtering and child output/timestamps, volume metadata, error mode and WER flags, system-directory buffer sizing, priority boost, continuation dispatch, timer deadlines/reset/cancel/errors, shared clocks and PEB, read/write console devices and VT modes |

`dll_search` embeds four small real DLLs, built from the `dll_*_support.rs`
fixtures. The runners place its executable in an application subdirectory,
separate from the current directory and added user directory. It checks search
order with two different implementations of the same DLL and a parent/middle
import chain. Resource-only loading and signed-image policy flags are not
implemented and return an explicit unsupported error locally.

`crt_runtime` checks global/thread-local invalid-parameter handlers, callback
metadata and recovery through public `mbstowcs_s` validation (without relying
on internal dispatch exports), CRT strings and secure conversions, descriptor/stream file I/O,
ANSI module-name truncation, and
SSPI table initialization with an unknown package. Installed SSPI authentication
providers are not implemented by Win-Runner and are outside this comparison.
`socket_events` checks loopback TCP, Windows fd-set layout, event reset and
read rearming, peer closure, and cancellation. Neither probe needs the internet.

`process_runtime` covers the native APIs added for Micro and its background linter
jobs. The existing `links` and `pool_console` probes cover the recent reparse
buffer and non-console error fixes. Application behavior such as `reload`,
PowerShell installers, and npm launchers remains covered by their shell and
real-binary E2E tests; `reload` is a Win-Runner command with no Windows API
equivalent. Unsupported desktop clipboard/provider catalog services and
asynchronous thread suspension are tested locally for explicit failure.
No Windows golden is recorded for a new probe until Windows CI produces it.

`powershell_essentials.ps1` additionally runs unchanged in real PowerShell
on Windows and the guest interpreter. Its transcript compares rename and
collision handling, directory rename, content clearing/reads, path tests,
filename listing/splitting, text search, and UTF-8 output/append. Local E2E
tests check native results while Windows CI supplies the authoritative
comparison; cmdlet objects and help-table formatting are outside this probe.

Add a probe for an area of the API, not for a program: when an application
misbehaves, find the Win32 behavior behind it and add cases that pin that
behavior down.

## Running

```sh
bash guests/build-oracle.sh
bash tests/oracle/run-winrun.sh target/debug/winrun out/winrun
pwsh tests/oracle/run-windows.ps1 -OutputDir out/windows   # on Windows
bash tests/oracle/compare.sh out/windows out/winrun
```

Both run scripts start each probe in a fresh empty directory.

The `windows-oracle` workflow does all of this on every push: it builds the
probes once, runs them on `windows-latest` and under Win-Runner, and fails
when a transcript differs, with the diff in the job summary and the
transcripts as the `oracle-comparison` artifact.

## Goldens

`tests/oracle/golden/<name>.txt` holds a Windows transcript. When one is
present, `cargo test --test oracle_native` requires Win-Runner's transcript to
match it exactly, so the comparison also runs locally without Windows. To
record or refresh one, copy it from the workflow's `oracle-windows` artifact
and commit it. Record the Windows version it came from in the commit message.
