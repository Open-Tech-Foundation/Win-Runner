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
    let commands = format!(
        "New-Item C:\\oracle-run -ItemType Directory\ncd C:\\oracle-run\n\"{}\"\nexit\n",
        probe.display()
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
        // Error codes captured by the Windows CI oracle. Keep these covered
        // even before complete transcripts for these probes are checked in.
        let required: &[&str] = match name.as_str() {
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
