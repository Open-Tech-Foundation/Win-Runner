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
    let executable = if probe.file_stem().and_then(|name| name.to_str())
        == Some("oracle_process_runtime")
    {
        format!(
            "@seed \"{}\" C:\\oracle-run\\process_runtime.exe\nC:\\oracle-run\\process_runtime.exe",
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
