//! Windows-oracle probes (tests/oracle/README.md) under Win-Runner: every
//! probe must run to `END`, and when a Windows transcript is recorded in
//! tests/oracle/golden, Win-Runner's must match it line for line.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn probes() -> Vec<PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/artifacts/exe");
    let mut probes: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("oracle_") && name.ends_with(".exe"))
        })
        .collect();
    probes.sort();
    probes
}

/// The probe's transcript, started in a fresh `C:\oracle-run` as
/// tests/oracle/run-winrun.sh starts it.
fn transcript(probe: &Path) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the winrun shell");
    let stem = probe.file_stem().and_then(|name| name.to_str()).unwrap();
    let executable = if matches!(stem, "oracle_process_runtime" | "oracle_console_runtime" | "oracle_native_startup" | "oracle_desktop_clipboard") {
        let name = stem.trim_start_matches("oracle_");
        format!(
            "@seed \"{}\" C:\\oracle-run\\{name}.exe\nC:\\oracle-run\\{name}.exe",
            probe.display()
        )
    } else if probe.file_stem().and_then(|name| name.to_str()) == Some("oracle_dll_search") {
        format!("New-Item C:\\oracle-run\\app -ItemType Directory\n@seed \"{}\" C:\\oracle-run\\app\\oracle_dll_search.exe\nC:\\oracle-run\\app\\oracle_dll_search.exe", probe.display())
    } else {
        format!("\"{}\"", probe.display())
    };
    let commands = format!(
        "New-Item C:\\oracle-run -ItemType Directory\ncd C:\\oracle-run\n{}\nexit\n",
        executable
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(commands.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

#[test]
fn every_oracle_probe_runs_and_matches_its_windows_golden() {
    let probes = probes();
    assert!(
        !probes.is_empty(),
        "no oracle probes in tests/artifacts/exe"
    );
    let mut mismatches = Vec::new();
    for probe in probes {
        let name = probe
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .trim_start_matches("oracle_")
            .to_string();
        let actual = transcript(&probe);
        assert!(
            actual.ends_with("END\n"),
            "{name} did not finish:\n{actual}"
        );
        assert!(!actual.contains("PANIC"), "{name} panicked:\n{actual}");
        if matches!(
            name.as_str(),
            "process_runtime"
                | "crt_runtime"
                | "socket_events"
                | "file_locks"
                | "dll_search"
                | "apc_io"
                | "thread_queries"
                | "console_runtime"
                | "native_startup"
        ) {
            assert!(
                !actual.contains("wrong") && !actual.contains("unavailable"),
                "{name}: native behavior checks failed:\n{actual}"
            );
        }
        if name == "process_runtime" {
            for line in [
                "pipe.eof: fail err=109",
                "pipe.write_reader: fail err=5",
                "pipe.read_writer: fail err=5",
                "continue.dispatched: 1",
                "timer.expires: 0",
                "timer.auto_reset: 258",
                "timer.periodic_second: 0",
                "console.vt_preserved: ok",
                "volume.serial_consistent: ok",
                "startup.child_wait: 0",
                "startup.child_times: ok",
                "startup.time_order: ok",
                "startup.output: ok",
            ] {
                assert!(
                    actual.lines().any(|actual| actual == line),
                    "{name}: missing native behavior result {line:?}\n{actual}"
                );
            }
        }
        // Require important behavior cases even before complete transcripts
        // are checked in. Windows CI compares every new probe with Windows.
        let required: &[&str] = match name.as_str() {
            "desktop_clipboard" => &["format.register: ok", "global.movable: ok", "global.zeroed: ok", "global.nested_lock: ok", "global.final_unlock: ok", "global.not_locked: ok", "global.free: ok", "global.fixed: ok", "window.create: ok", "window.post: ok", "window.peek: ok", "window.remove: ok", "clipboard.not_open: ok", "clipboard.open: ok", "clipboard.set: ok", "clipboard.roundtrip: ok", "clipboard.close: ok", "clipboard.child: ok", "clipboard.clear: ok", "window.destroy: ok", "window.invalid: ok"],
            "sync_crypto" => &[
                "mutex.create_owned: ok", "mutex.recursive_wait: 0", "mutex.other_wait: 258",
                "mutex.other_release: 0 err=288", "mutex.release_free: 0 err=288", "mutex.handoff_wait: 0",
                "mutex.named_second_error: 183", "mutex.named_not_owner: 0 err=288", "mutex.open_missing: 0 err=2",
                "filetime.compare: -1 0 1 ", "filetime.roundtrip: ok", "filetime.invalid_handle: 0 err=6",
                "bcrypt.system_preferred: ok", "bcrypt.no_algorithm: 0xc0000008",
                "cert.intended: 1 0x84 0x80", "cert.intended_none: 0 zeroed err=0", "cert.system_store: ok",
                "crt.strtoll_overflow: -9223372036854775808 used=20", "crt.byteswap: 0x78563412 0x3412",
                "crt.isxdigit: ok", "crt.difftime: ok",
            ],
            "native_startup" => &[
                "socket.ordinal_text: ok", "socket.ordinal_select: ok", "socket.ipv4_text: ok",
                "socket.modern_ioctl: ok", "socket.modern_addr: ok", "socket.modern_text: ok",
                "socket.ordinal_addr: ok", "socket.ordinal_ioctl: ok", "socket.ordinal_fdset: ok",
                "socket.accept: ok", "socket.recv_push_peek: ok", "socket.recv_push_waitall: failed err=10045", "socket.recv_waitall: ok",
                "socket.exclusive: ok", "socket.exclusive_reuse: ok", "socket.exclusive_bind: ok", "socket.exclusive_competitor: ok",
                "alert.timeout: ok", "alert.pending: ok", "alert.other_thread: ok",
                "console.flush_input: ok", "console.flush_output: ok",
                "pipe.peek: ok", "pipe.peek_query: ok", "pipe.peek_eof: ok",
                "sync_pipe.created: ok", "sync_pipe.read_access: ok", "sync_pipe.write_access: ok",
                "sync_pipe.write: ok", "sync_pipe.read: ok", "sync_pipe.eof: ok",
                "nt_thread.create: ok", "nt_thread.outputs: ok", "nt_thread.teb_identity: ok", "nt_thread.suspended: ok", "nt_thread.resume: ok", "nt_thread.completed: ok", "nt_thread.invalid: ok",
                "nt_wait.nonalertable: ok", "nt_wait.apc: ok", "nt_wait.thread: ok", "nt_wait.poll: ok", "nt_wait.relative: ok", "nt_wait.absolute: ok", "nt_wait.invalid: ok", "nt_wait.last_error: ok", "nt_error.missing_parent: ok", "nt_error.invalid_name: ok", "peb.standard_handles: ok", "peb.image_path: ok", "peb.command_line: ok", "peb.set_standard_handle: ok", "nt_thread.parameters_shared: ok", "activation.absent: ok", "heap.peb: ok", "heap.allocate: ok", "heap.reallocate: ok", "heap.free: ok", "heap.last_error: ok",
                "nt_memory.allocate: ok", "nt_memory.protect: ok", "nt_memory.release: ok", "nt_time.precise: ok", "nt_time.performance: ok",
                "device.attributes_roundtrip: ok",
                "cert.memory_empty: ok", "cert.memory_close: ok", "cert.root_open: ok",
                "cert.usage_size: ok", "cert.usage_small: ok", "cert.usage_read: 1", "cert.usage_read_size: =query",
                "cert.root_context: ok", "cert.duplicate: ok", "cert.enum_end: ok",
                "cert.pending_close: ok", "cert.copy_survives_close: ok", "cert.free: ok",
                "live.before_exit: ok", "live.parent_remove: ok", "live.no_final_replay: ok",
                "suspend.created: ok", "suspend.before_resume: ok", "suspend.invalid_handle: ok",
                "suspend.resume: ok", "suspend.second_resume: ok", "suspend.exit: ok", "suspend.final_io: ok",
                "file.duplicate_type: ok", "file.duplicate_closed: ok",
                "process.io: ok", "process.io_invalid: ok", "process.memory: ok",
                "process.memory_invalid: ok", "process.memory_small: ok", "process.memory_basic: ok",
                "module.main: ok", "socket.ordinal: ok", "socket.hostname: ok", "close.success: ok",
                "close.invalid: ok", "attributes.file: ok", "directory.entries: ok",
                "wait.different: ok", "wait.timeout: ok", "wait.invalid: ok",
            ],
            "console_runtime" => &[
                "pages.independent: ok",
                "pages.invalid_input: fail err=87",
                "pages.invalid_output: fail err=87",
                "pages.invalid_preserves: ok",
                "pages.child: ok",
                "pages.child_updates: ok",
                "pages.restored: ok",
                "stack.main: ok",
                "stack.thread: ok",
            ],
            "crt_runtime" => &[
                "invalid.global_dispatch: ok",
                "invalid.local_dispatch: ok",
                "invalid.metadata: ok",
                "invalid.recovery: ok",
                "convert.truncate: ok",
                "module.truncated: ok",
                "security.unknown_package: ok",
                "fd.stat: ok",
                "fd.missing: ok",
            ],
            "socket_events" => &[
                "select.empty: ok",
                "event.rearmed: ok",
                "event.close_record: ok",
                "event.cancel: ok",
            ],
            "file_locks" => &[
                "lock.shared_read: ok",
                "lock.close_releases: ok",
                "lock.large_range: ok",
                "async.granted: ok",
                "async.cancel_result: ok",
            ],
            "thread_queries" => &[
                "rights.restricted_open: ok",
                "identity.pseudo: ok",
                "identity.open: ok",
                "rights.id: ok",
                "rights.code: ok",
                "rights.times: ok",
                "rights.wait: ok",
                "name.roundtrip: ok",
                "thread.close_original: ok",
                "thread.resume_opened: ok",
                "thread.completed: ok",
                "thread.final_times: ok",
                "thread.times_stable: ok",
                "thread.reopen_terminated: ok",
                "thread.exit_259: ok",
            ],
            "apc_io" => &[
                "apc.fifo: ok",
                "apc.prestart_delivery: ok",
                "wait.signal_apc: ok",
                "apc.thread_owner: ok",
                "apc.duplicated_owner: ok",
                "apc.access_denied: ok",
                "wait.all_preserves_event: ok",
                "io.write_callback: ok",
                "io.read_callback: ok",
                "io.eof_callback: ok",
                "io.zero_preserves_size: ok",
                "io.append: ok",
                "pipe.cancel_result: ok",
                "port.alertable: ok",
                "result.timeout: ok",
                "result.alertable: ok",
                "io.cancel_callback: ok",
            ],
            "dll_search" => &[
                "module.loaded_paths: ok",
                "module.truncated: ok",
                "directory.missing: ok",
                "search.loaded_extensionless: ok",
                "search.absolute_distinct: ok",
                "search.removed_missing: ok",
                "dependency.dll_load_dir_recursive: ok",
                "dependency.application_before_user: ok",
                "defaults.removed_missing: ok",
            ],
            "links" => &[
                "reparse.dirlink_small: fail err=122",
                "reparse.dirlink_tiny: fail err=122",
            ],
            "pool_console" => &[
                "console.read_file: fail err=87",
                "console.read_input_file: fail err=87",
                "console.write_input_file: fail err=6",
                "console.events_file: fail err=6",
            ],
            _ => &[],
        };
        for line in required {
            assert!(
                actual.lines().any(|actual| actual == *line),
                "{name}: missing Windows result {line:?}\n{actual}"
            );
        }
        let golden =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/oracle/golden/{name}.txt"));
        let Ok(expected) = std::fs::read_to_string(&golden) else {
            continue; // no Windows transcript recorded yet
        };
        let expected = expected.replace("\r\n", "\n");
        let differing: Vec<String> = expected
            .lines()
            .zip(actual.lines())
            .filter(|(windows, winrun)| windows != winrun)
            .map(|(windows, winrun)| format!("  windows: {windows}\n  winrun:  {winrun}"))
            .collect();
        if !differing.is_empty() || expected.lines().count() != actual.lines().count() {
            mismatches.push(format!("{name}:\n{}", differing.join("\n")));
        }
    }
    assert!(
        mismatches.is_empty(),
        "Win-Runner differs from Windows:\n{}",
        mismatches.join("\n")
    );
}
