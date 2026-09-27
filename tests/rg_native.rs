//! Real Windows ripgrep checks. Set WINRUN_RG_EXE to an x64 rg.exe to enable.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn rg_path() -> Option<PathBuf> {
    std::env::var_os("WINRUN_RG_EXE").map(PathBuf::from)
}

fn run_shell(rg: &Path, commands: &str) -> Output {
    let executable = rg.canonicalize().expect("WINRUN_RG_EXE exists");
    let script = commands.replace("{rg}", &format!("\"{}\"", executable.display()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native Win-Runner shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn windows_ripgrep_runs_version_and_searches_guest_files() {
    let Some(rg) = rg_path() else {
        return;
    };
    let version = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(&rg)
        .arg("--version")
        .output()
        .expect("run Windows ripgrep");
    assert_eq!(
        version.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("ripgrep "));

    let file = run_shell(&rg, "Set-Content C:\\one.txt 'error: disk full'\n{rg} --color never --no-heading --no-line-number error C:\\one.txt\nexit\n");
    assert_eq!(
        file.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&file.stderr)
    );
    assert_eq!(file.stdout, b"error: disk full\n");

    let tree = run_shell(&rg, "New-Item C:\\data -ItemType Directory\nSet-Content C:\\data\\one.txt 'error: one'\nSet-Content C:\\data\\two.txt 'error: two'\n{rg} --color never --no-heading --no-line-number --threads 2 error C:\\data\nexit\n");
    assert_eq!(
        tree.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&tree.stderr)
    );
    let output = String::from_utf8_lossy(&tree.stdout);
    assert!(
        output.contains("C:\\data\\one.txt:error: one\n"),
        "{output}"
    );
    assert!(
        output.contains("C:\\data\\two.txt:error: two\n"),
        "{output}"
    );
}

#[test]
fn windows_ripgrep_lists_files_filters_globs_and_reports_missing_paths() {
    let Some(rg) = rg_path() else {
        return;
    };
    let listing = run_shell(&rg, "New-Item C:\\data -ItemType Directory\nSet-Content C:\\data\\one.txt 'error: one'\nSet-Content C:\\data\\two.log 'error: two'\n{rg} --color never --files C:\\data\nexit\n");
    assert_eq!(
        listing.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let paths = String::from_utf8_lossy(&listing.stdout);
    assert!(paths.contains("C:\\data\\one.txt\n"), "{paths}");
    assert!(paths.contains("C:\\data\\two.log\n"), "{paths}");

    let json = run_shell(&rg, "New-Item C:\\data -ItemType Directory\nSet-Content C:\\data\\one.txt 'error: one'\nSet-Content C:\\data\\two.log 'error: two'\n{rg} --json --threads 2 -g '*.txt' error C:\\data\nexit\n");
    assert_eq!(
        json.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let output = String::from_utf8_lossy(&json.stdout);
    assert_eq!(output.matches("\"type\":\"match\"").count(), 1, "{output}");
    assert!(output.contains("one.txt"), "{output}");
    assert!(!output.contains("two.log"), "{output}");

    let missing = run_shell(&rg, "{rg} --color never error C:\\missing.txt\nexit\n");
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("C:\\missing.txt"));
}
