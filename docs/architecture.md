# Architecture

How a Windows EXE gets from disk to exit code under Win-Runner, and where
each piece lives. Written for contributors and reviewers judging soundness.

## Big picture

```text
 host .exe ──▶ PE parse (src/pe) ──▶ backend pick (src/backend.rs)
                                              │
                        ┌─────────────────────┴──────────────────────┐
                        │ native-linux-x64 (only backend shipped)     │
                        │  map image → resolve imports → run natively │
                        │  Windows APIs = Rust shims (src/native/…)   │
                        └─────────────────────┬──────────────────────┘
                                              │
 Files ◀── WinFS (src/winfs) ──▶ guest C: + mounts + snapshots
 Output ──▶ host stdio / control channel / instance frames
 Children ──▶ fresh exec workers (__native-worker) + journals
```

Key point: **guest machine code is never interpreted**. On Linux x86-64 the
CPU executes guest instructions directly; Win-Runner supplies the Windows
personality around them (loader, shims, TEB/PEB, exceptions, threads). On
hosts without a backend, `src/native/unsupported.rs` reports that clearly.

## 1. PE loading (`src/pe/`, `src/native/linux_x86_64/loader.rs`)

1. **Parse + validate** (`src/pe/mod.rs`): headers, sections, imports, exports
   (incl. ordinals and forwarders), resources, manifest. `load_lenient` keeps
   going past unknown features so `winrun inspect` can still list every import.
2. **Map at the preferred base** (`loader.rs::map`): `mmap` with
   `MAP_FIXED_NOREPLACE` at `image_base`, sections copied to their virtual
   addresses, then per-section protections applied (`.text` execute-read,
   `.data` read-write, headers read-only). A colliding base is an error, not
   a silent relocate.
3. **Resolve imports to trampolines**: each `DLL!API` (or ordinal) binds to a
   native Rust shim; anything without a shim is recorded. Strict mode
   (`WINRUN_NATIVE_STRICT_IMPORTS=1`) refuses to start when the list is
   non-empty; default mode fails loudly at first call with
   `executable: DLL!API`.
4. **Loader duties**: load-time DLL dependencies (e.g. `python.exe` +
   `python314.dll` beside it) are loaded, bound, and initialized before the
   entry point, Windows-loader order; DLL search honors `SetDefaultDllDirectories`
   / `LoadLibraryEx` flags against configured directories only; TLS callbacks
   run; the main module's exports stay visible so `GetProcAddress` finds N-API
   in `node.exe`.
5. **Entry**: version reported per the program's manifest (`GetVersionEx`
   semantics), PEB/process parameters populated (image path, command line,
   standard handles), TEB fully sized (0x2000, TLS slots in place), then the
   entry point runs on the host CPU.

Exceptions: MSVC/C++ EH (`__CxxFrameHandler3`, `__C_specific_handler`),
`__RTDynamicCast`/RTTI, vectored handlers, and hardware faults (dispatched on
the faulting thread's stack below the fault frame) are implemented so
`catch_unwind`, `#[should_panic]`, and `__try/__except` behave as on Windows.

## 2. Windows API shims, not syscall translation

There is **no guest-syscall interception layer**. Guest code that calls a
Windows API lands in a Rust shim; guest code that issues a raw Linux syscall
goes straight to the kernel with Win-Runner's privileges (hence: not a
sandbox — see `docs/threat-model.md`).

Shims live in `src/native/linux_x86_64/` (~70 modules), grouped by area:

| Area | Modules | Strategy |
|---|---|---|
| Processes, threads, APCs | `process.rs`, `runner.rs`, `thread_runtime.rs`, `nt_threads.rs`, `apc.rs`, `overlapped.rs` | Host threads + guest thread objects, per-thread APC queues, alertable waits, completion ports |
| Files, pipes, FS metadata | `file_io/`, `unnamed_pipes.rs`, `process_journal.rs` | WinFS/host-fs backed handles, overlapped I/O, locks, reparse points |
| Memory | `memory.rs`, `nt_memory.rs` | Host `mmap` with Windows reserve/commit/protect semantics, `VirtualQuery` per-section truth |
| Sync | `sync.rs`, `mutexes.rs` | Futex-backed, inline state (no per-object host allocation) |
| Sockets | `sockets.rs`, `afd.rs`, `socket_events.rs`, `socket_pending.rs` | Host sockets + Winsock errors as thread last-error; non-blocking/overlapped parity |
| Registry, env | `registry.rs`, `advapi_registry.rs`, `environment.rs` | JSON-backed hives; logon env rebuilt per session |
| Console | `console.rs`, `console_code_pages.rs` | termios raw/canonical modes, input records, scroll regions, OSC title |
| Crypto/certs | `certificates.rs`, `cert_chain.rs`, `crypto.rs` | rustls-webpki chains vs guest ROOT store; revocation unchecked |
| CRT/UCRT, C++ | `crt*.rs`, `cxx_eh.rs`, `rtti.rs`, `exceptions.rs` | Descriptor/semantic parity (errno/`_doserrno`, math, time, invalid-parameter handlers) |
| Loader-adjacent | `dll_search.rs`, `resources.rs`, `shared_data.rs`, `system.rs`, `topology.rs`, `clock.rs`, `nls_locale.rs`, `locale.rs`, `path_cch.rs` | Search order, version/locale/clock answers oracles verify |

Each shim is checked against real Windows by an **oracle**: small probes run on
actual Windows, their observations recorded, and the same probes asserted under
Win-Runner (`tests/oracle/`, `tests/oracle_native.rs`). Disputed behavior is
settled by the oracle, not by opinion.

## 3. Child processes: exec workers + journals

`CreateProcess` never forks guest state in-process. Every Windows child starts
in a **fresh exec'd worker** (`winrun __native-worker <request-file>`):

- The parent serializes process identity, cwd, environment, WinFS state,
  standard handles, and inheritable handle metadata into a request file.
- Inheritable pipe endpoints travel via descriptor passing; Winsock handles
  and completion associations are restored in the worker.
- The child publishes filesystem changes through a **journal**; the parent
  applies it on clean exit. A killed/crashed child can lose trailing changes
  (documented; cooperative processes should checkpoint).
- Fatal diagnostics (missing import, worker startup, crash with exception
  code) travel a **launcher-owned channel** independent of guest stdio, so
  `stdio: "ignore"` and nested `npm → cmd → node` chains still report the
  failing `executable: DLL!API`.

Guest PIDs are unique across the tree (workers use host pids; in-process
children take ids above every host pid) so npm-style `parent_pid`-derived temp
names never collide.

## 4. WinFS (`src/winfs/`, `src/snapshot.rs`)

The guest C: drive:

- **Snapshot disks** (`.winfs`, magic `WFSDSK01`): a path index plus file
  extents in one seekable file. Boot reads the index only; contents are paged
  from extents on open. Legacy ZIP snapshots still load.
- **Session writes**: each written file lives in its **own host file (blob)**
  in a per-session directory under `$TMPDIR`, written in place (`pwrite`) and
  freed on delete — disk use stays proportional to live files. The session dir
  is removed on clean exit; leftovers from killed runs are swept at startup.
- **Sharing**: workers share the session, so files are visible across guest
  processes as on Windows; journals name blobs instead of copying contents.
- **Semantics**: case-insensitive lookup with original casing preserved,
  `.`/`..` normalization, Windows timestamp rules, hard-link-aware times;
  one shared API serves both native shims and the PS1 shell.
- **Mounts** (`--mount=Z:/host`, `--mount-ro`) expose host dirs as separate
  guest drives; writable mounts write through to the host.

Snapshots contain **C: only** (files + registry hives + `wpkg` state).

## 5. Shell, control, instances

- **Shell** (`src/shell.rs`, `src/ps1/`): PowerShell-subset interpreter over
  WinFS; `runner` mode is the same shell with stdin jobs and no prompt.
- **Control** (`src/control.rs`, `docs/control-protocol.md`): loopback
  WebSocket, token URL, stdin wired via `dup2` so guest console input flows
  from the socket; stdout/stderr forwarded as `output` events.
- **Instances** (`src/instance.rs`, `src/protocol.rs`): daemon + versioned
  `WCLI` frames over a Unix socket for `boot/exec/status/destroy`.
- **Backends** (`src/backend.rs`): `ExecutionBackend` trait (`id`,
  `available`, `capabilities`, `execute[…]`). `native-linux-x64` is the only
  registered backend; macOS translation / Windows-native / VM workers plug in
  here without changing shell, runner, or snapshot semantics.

## 6. Verification strategy

- `cargo test --offline`: unit + native tests (default suite; fixture tests
  report **ignored** unless their env vars are set).
- Oracle suite (`tests/oracle*`): parity with real Windows, probe by probe.
- Real-binary E2E (`tests/node_native.rs`, `dotnet_native.rs`,
  `micro_native.rs`, `curl_native.rs`, `opencode_native.rs`, `rg_native.rs`,
  …): the programs in `docs/compatibility.md`, run for real.
- `COMPATIBILITY_BACKLOG.md`: the prioritized remainder.
