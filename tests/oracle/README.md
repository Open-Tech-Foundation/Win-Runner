# Windows oracle

Differential tests of Win-Runner against real Windows. They check Windows
compatibility itself, not any application: each probe calls Win32 APIs
directly with fixed inputs and prints what happened. The same `.exe` runs on
real Windows, whose transcript is the expected result, and under Win-Runner.
Every line that differs is a place where Win-Runner does not behave like
Windows.

## Probes

`guests/oracle/<name>.rs` builds to `tests/artifacts/exe/oracle_<name>.exe`
with `guests/build-oracle.sh` (rustc and rust-lld only). The MSVC-ABI probes in `guests/oracle-msvc` (a C++ program and a std Rust
program, which need the MSVC CRT) build with `guests/build-msvc-oracle.sh`
through cargo-xwin; their `.exe` files are committed. A probe:

- is `no_std` with no C runtime, so nothing but the Win32 API is exercised;
- normally imports only `GetStdHandle`, `WriteFile`, `ExitProcess`, `GetModuleHandleW`,
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
| `desktop_clipboard` | global-memory handles and locks, hidden STATIC windows, message queues, clipboard payload ownership and cross-process sharing |
| `native_startup` | main-module ANSI/Unicode identity, Winsock dynamic ordinal lookup, static NT directory/attribute queries and handle closing, native address waits and NTSTATUS timeouts |
| `console_runtime` | independent input/output code pages, invalid-page errors, shared child-process changes without handle inheritance, restoration, current thread stack bounds on main and created threads |
| `thread_queries` | pseudo/opened/duplicated thread identity, query/set/synchronize rights, UTF-16 description copies, suspended and terminated threads, retained handles, exit codes and CPU timestamps |
| `apc_io` | per-thread APC queues, FIFO and duplicated thread handles, alertable single/multiple waits, wait-all state preservation, extended file completion callbacks, EOF, pipe cancellation, result timeouts and alertable completion-port waits |
| `dll_search` | directory cookies and removal, Set/Get DLL directory buffers, search flags and defaults, loaded-name reuse, distinct absolute paths, recursive dependencies, loaded module filenames and truncation |
| `file_locks` | shared/exclusive byte ranges, contention, read/write exclusion, exact unlock, close cleanup, 64-bit offsets, async grants and cancellation |
| `process_runtime` | anonymous pipe access, duplication and EOF, startup handle-list filtering and child output/timestamps, volume metadata, error mode and WER flags, system-directory buffer sizing, priority boost, continuation dispatch, timer deadlines/reset/cancel/errors, shared clocks and PEB, read/write console devices and VT modes |
| `file_info` | the last error `CreateFileW` leaves per creation disposition on new and existing files, and file sizes after `SetFileInformationByHandle` with `FileAllocationInfo` and `FileEndOfFileInfo` |
| `nt_pipes` | `NtWriteFile`/`NtReadFile` on `CreatePipe` ends, and unnamed pipes through `\Device\NamedPipe\` with `NtCreateNamedPipeFile` and a peer opened relative to the pipe, as current runtimes make a child's standard streams |
| `sync_crypto` | mutex ownership, recursion, names and non-owner release; `CompareFileTime`/`GetFileTime`; `BCryptGenRandom`; `CertGetIntendedKeyUsage` and `CertOpenSystemStoreA`; CRT `strtoll`, `_byteswap_*`, `isxdigit`, `_difftime64` |
| `cxx_eh` | MSVC C++ exceptions through VCRUNTIME140: catch by type, value, reference and `...`, rethrow, throws from catch blocks, destructor unwinding; SEH `__except`/`__finally` around divide-by-zero, access violations and `RaiseException` (C++ source in `guests/oracle-msvc`) |
| `rust_unwind` | Rust panics on `x86_64-pc-windows-msvc`: drops while unwinding, `catch_unwind`, `resume_unwind`, nested catches, thread panics seen by `join` (Rust source in `guests/oracle-msvc`) |
| `powershell_essentials.ps1` | everyday item, content and text-pipeline cmdlets (a script, run by real PowerShell and the guest shell) |
| `powershell_scripting.ps1` | `param` blocks, named/switch/positional binding, `return`, the `HKLM:`/`HKCU:` registry provider and `RegistryKey` methods |

`thread_queries` exercises threads in the active guest process. Opening
threads in other guest processes or arbitrary Linux host processes is outside
this batch. Thread descriptions preserve UTF-16 and returned copies are freed
with `LocalFree`; CPU times use Linux per-thread accounting.
Access-denial checks use a `THREAD_TERMINATE`-only handle, which grants
neither query nor synchronization rights. They do not rely on Windows
accepting an empty `OpenThread` access mask.

`native_startup` additionally imports the tested NT APIs statically through
`ntdll.def`, so it exercises PE import binding as well as API behavior. Its
directory checks cover `FileDirectoryInformation`; unsupported NT directory
information classes remain outside this probe. It also checks duplicated file
handle classification and process I/O/basic/extended memory queries, including
invalid handles and undersized buffers. A self-spawned child verifies
`CREATE_SUSPENDED`, primary-thread resume counts, wrong-handle rejection,
exit status and retained final I/O counters. Winsock cases cover ordinal
exports for both `WSOCK32.dll` and `WS2_32.dll`, IPv4 formatting, exclusive binds against a competing socket, and
loopback receive flags (`MSG_PEEK`, `MSG_WAITALL`, `MSG_PUSH_IMMEDIATE`).
Linux I/O counters use syscall counts
and cached read/write bytes; Windows "other" counters and kernel pool quotas
have no Linux equivalent and are zero. Resident memory and faults use `/proc`
and final `wait4` accounting. Commit charge sums accountable VMAs in `smaps`;
peak commit is the maximum sampled by queries, not a lifetime kernel counter.
Extended memory counters beyond `PROCESS_MEMORY_COUNTERS_EX` fail explicitly.

The startup probe checks direct PEB process-heap identity and interoperable NT/Win32
heap allocations, including zero initialization, reallocation and LastError.
An executable without an activation context checks the absent-context query;
side-by-side manifest activation is outside this implementation. NT thread creation
checks suspended execution, client-ID/TEB outputs, resume and completion. It
supports current-process creation and these two output attributes; additional
creation flags, nonzero ZeroBits and custom security descriptors fail explicitly.
Host stacks reserve the larger requested stack size with the native 4 MiB minimum.
It also checks child namespace visibility before exit and
ensures final journals do not undo parent deletions. Child-to-parent namespace
publication currently polls every 20 ms; changes from a parent into an already
running child are not broadcast. Shared existing file contents use the same
blob backing. Certificate checks normalize ROOT-store contents, validate
certificate/context and EKU buffer layouts, enumerate to the documented end
error, and retain duplicated contexts across store close. Linux ROOT stores
use the host CA bundle; writable system stores, personal certificates, registry
properties and chain verification are outside this implementation. NT memory
operations cover the current process, with page rounding, protection and release;
nonzero ZeroBits and operations on other processes remain unsupported. Thread
alert checks cover pending alerts, coalescing, timeouts and delivery to a newly
created thread. Console input flushing checks queued input removal and rejection
of an output handle.


`desktop_clipboard` uses a clipboard shared by workers in one WinFS session,
backed by host files and process-safe locks. It does not access the Linux desktop
clipboard or persist clipboard contents into snapshots. Only immediate HGLOBAL
formats and nonvisual built-in STATIC windows are supported; GUI rendering,
custom window procedures, clipboard format synthesis and delayed rendering
remain unsupported. The probe clears the clipboard in its test environment and
checks a child reads the same registered format and payload. `native_startup`
also checks TEB client IDs, shared PEB standard handles and updates, NT object
waits and error translations, and that byte-pipe peeks leave data available for
reads. Optional real Windows Bun PTY tests verify console identity across output
forwarding and pipe classification for captured child output.
The pipe backend still rejects message-type pipes; peeks apply to byte pipes.

`console_runtime` tests code pages 1252 and 65001, the encodings currently
supported by Win-Runner. Other encodings return an explicit invalid-parameter
error. Initial Windows console code pages are saved and restored rather than
assuming a machine-specific default. The child shares its parent's console;
detached and separately allocated consoles are outside this probe.

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

Optional OpenCode integration checks use an unchanged official Windows binary:

```sh
WINRUN_OPENCODE_EXE=/path/to/opencode.exe cargo test --test opencode_native -- --ignored
```

These checks require Python 3 and network access. Each creates a fresh shell,
seeds the executable, verifies a rendered frame and typed prompt text, and exits
with Ctrl+C without an unsupported-import diagnostic. Both managed and standalone
server startup are covered. They do not submit a model request.
