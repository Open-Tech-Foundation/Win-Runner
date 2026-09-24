//! Optional real Node.js Windows binary compatibility check.
//! Set WINCLI_NODE_EXE to an official Windows x64 node.exe to run it.

use std::path::Path;
use std::process::Command;

#[test]
fn official_windows_node_runs_version_and_javascript_natively() {
    let Ok(path) = std::env::var("WINCLI_NODE_EXE") else {
        return;
    };
    let path = Path::new(&path);
    let bytes = std::fs::read(path).expect("read WINCLI_NODE_EXE");
    let report = wincli::inspect::inspect_pe(&bytes).expect("parse Windows node.exe");
    assert_eq!(report.arch, "x86_64");
    assert!(report.total() > 400, "unexpected Node.js import table");
    assert!(
        !report.runnable(),
        "inspection still lists optional static imports"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg(path)
        .arg("--version")
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("start native WinCLI");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "v24.21.0");

    let output = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg(path)
        .args(["-e", "console.log(1 + 2)"])
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("evaluate JavaScript through native WinCLI");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "3");
}
