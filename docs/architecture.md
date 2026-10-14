# Architecture

Windows EXE → exit code: where each piece lives. For contributors and reviewers.

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

1. **Parse + validate** (`src/pe/mod.rs`): headers, sections, imports, exports, resources,
   manifest. `load_lenient` survives unknowns so `inspect` still lists every import.
2. **Map at preferred base** (`loader.rs::map`): `mmap(MAP_FIXED_NOREPLACE)`, per-section
   protections (`.text` X+R, `.data` RW). Collision = error, never silent relocate.
3. **Imports → trampolines**: each `DLL!API` binds a Rust shim; the rest are recorded.
   Strict mode refuses upfront; default fails loudly at first call (`exe: DLL!API`).
4. **Loader duties**: dependency DLLs bound/init'd first (Windows order), `LoadLibraryEx`
   search flags honored, TLS callbacks run, main-module exports kept (N-API in `node.exe`).
5. **Entry**: manifest-aware version, PEB params, full-size TEB — then run on the host CPU.

Exceptions: MSVC/C++ EH, RTTI/`dynamic_cast`, vectored handlers, hardware faults on the
faulting thread's stack — `catch_unwind`, `#[should_panic]`, `__try/__except` all work.

## 2. Windows API shims, not syscall translation

There is **no guest-syscall interception layer**. Guest code that calls a
Windows API lands in a Rust shim; guest code that issues a raw Linux syscall
goes straight to the kernel with Win-Runner's privileges (hence: not a
sandbox — see `docs/threat-model.md`).

Shims live in `src/native/linux_x86_64/` (~70 modules), grouped by area:

| Area | Modules | Strategy |
|---|---|---|
| Processes/threads/APCs | `process.rs`, `runner.rs`, `thread_runtime.rs`, `nt_threads.rs`, `apc.rs`, `overlapped.rs` | Host threads + guest objects, APC queues, alertable waits, completion ports |
| Files/pipes | `file_io/`, `unnamed_pipes.rs`, `process_journal.rs` | WinFS-backed handles, overlapped I/O, locks, reparse points |
| Memory | `memory.rs`, `nt_memory.rs` | Host `mmap` with reserve/commit/protect; truthful `VirtualQuery` |
| Sync | `sync.rs`, `mutexes.rs` | Futex-backed, inline state |
| Sockets | `sockets.rs`, `afd.rs`, `socket_events.rs`, `socket_pending.rs` | Host sockets + Winsock errors; sync/async parity |
| Registry/env | `registry.rs`, `advapi_registry.rs`, `environment.rs` | JSON hives; logon env per session |
| Console | `console.rs`, `console_code_pages.rs` | termios modes, input records, scroll, OSC title |
| Crypto/certs | `certificates.rs`, `cert_chain.rs`, `crypto.rs` | rustls-webpki vs guest ROOT; no revocation |
| CRT/C++ | `crt*.rs`, `cxx_eh.rs`, `rtti.rs`, `exceptions.rs` | errno/`_doserrno`, math/time parity, EH/RTTI |
| Loader-adjacent | `dll_search.rs`, `resources.rs`, `system.rs`, `clock.rs`, `locale.rs`, … | Search order, version/locale/clock answers |

Oracles settle disputes: probes run on real Windows, same probes asserted here
(`tests/oracle/`, `tests/oracle_native.rs`).

## 3. Child processes: exec workers + journals

`CreateProcess` never forks in-process. Each child is a **fresh exec'd worker**
(`winrun __native-worker <request-file>`):

- Parent serializes identity, cwd, env, WinFS state, stdio, inheritable handles.
- Pipes travel via fd passing; Winsock/completion state restored in the worker.
- FS changes publish through a **journal**, applied on clean exit. Killed children
  can lose the tail — checkpoint if it matters.
- Fatal diagnostics use a **launcher-owned channel** (not guest stdio), so even
  `stdio: "ignore"` and `npm → cmd → node` chains report `exe: DLL!API`.

PIDs are tree-unique (workers = host pids; nested = above all host pids), so
`parent_pid`-derived temp names never collide.

## 4. WinFS (`src/winfs/`, `src/snapshot.rs`)

The guest C: drive:

- **Snapshots** (`.winfs`): path index + extents in one seekable file. Boot reads
  the index; contents page in on open. Legacy ZIP snapshots still load.
- **Session writes**: one host blob per written file under `$TMPDIR`, freed on
  delete — disk use tracks live files. Removed on exit; kill leftovers swept at start.
- **Sharing**: workers share the session (Windows-visible); journals name blobs, no copies.
- **Semantics**: case-insensitive, casing preserved, `.`/`..`, Windows times, hard links.
- **Mounts** (`--mount=Z:/host`, `--mount-ro`): extra drives; writable ones write through.

Snapshots hold **C: only** (files + hives + `wpkg` state).

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

- `cargo test --offline`: unit + native tests (fixture tests **ignored** without env vars).
- Oracles (`tests/oracle*`): parity with real Windows, probe by probe.
- Real-binary E2E (`node_`, `dotnet_`, `micro_`, `curl_`, `opencode_`, `rg_native`): compat programs, run for real.
- `COMPATIBILITY_BACKLOG.md`: the prioritized remainder.
