//! Modern .NET on the native backend: Microsoft's apphost, hostfxr,
//! hostpolicy, CoreCLR, and JIT run a framework-dependent app.
//!
//! Set WINRUN_DOTNET_FIXTURE to a directory made by
//! `scripts/fetch-dotnet-fixture.sh` to enable.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> Option<PathBuf> {
    std::env::var_os("WINRUN_DOTNET_FIXTURE").map(PathBuf::from)
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// A disk with the runtime in `C:\Program Files\dotnet` and the app in
/// `C:\Users\runner\hello`, as an installed runtime and app would be.
fn build_snapshot(fixture: &Path) -> PathBuf {
    let root = std::env::temp_dir().join(format!("winrun-dotnet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let stage = root.join("stage");
    copy_tree(&fixture.join("dotnet"), &stage.join("C/Program Files/dotnet"));
    copy_tree(&fixture.join("hello"), &stage.join("C/Users/runner/hello"));
    let snapshot = root.join("dotnet.winfs");
    let status = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .args(["snapshot", "build"])
        .arg(&stage)
        .arg(&snapshot)
        .status()
        .expect("build .NET snapshot");
    assert!(status.success());
    snapshot
}

#[test]
fn framework_dependent_app_runs_on_the_windows_coreclr() {
    let Some(fixture) = fixture() else {
        return;
    };
    let snapshot = build_snapshot(&fixture);
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_winrun"))
            .arg(format!("--snapshot={}", snapshot.display()))
            .arg(r"C:\Users\runner\hello\hello.exe")
            .args(args)
            .output()
            .expect("run the .NET app")
    };

    let output = run(&["one", "two"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("Hello from .NET "),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Console.WriteLine ends lines with Windows' Environment.NewLine.
    assert!(stdout.ends_with("\r\nargs: one,two\r\n"), "{stdout:?}");
    // Main's return value (the argument count) is the exit code.
    assert_eq!(output.status.code(), Some(2));

    let output = run(&[]);
    assert!(String::from_utf8_lossy(&output.stdout).ends_with("args: \r\n"));
    assert_eq!(output.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(snapshot.parent().unwrap());
}
