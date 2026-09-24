//! Optional real Node.js Windows binary compatibility check.
//! Set WINCLI_NODE_EXE to an official Windows x64 node.exe to run it.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

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

#[test]
fn official_windows_node_reads_guest_file_metadata_and_contents() {
    let Ok(node) = std::env::var("WINCLI_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let host_file = std::env::temp_dir().join(format!("wincli-node-fs-{}.txt", std::process::id()));
    std::fs::write(&host_file, b"npm-probe\n").expect("create host seed file");
    let script = format!(
        "@seed {} C:\\probe.txt\n\"{}\" -e \"const fs=require('node:fs');const p='C:\\\\probe.txt';console.log(fs.statSync(p).size+':'+fs.readFileSync(p,'utf8').trim())\"\nexit\n",
        host_file.display(),
        node.display(),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg("shell")
        .env("WINCLI_BACKEND", "native")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native WinCLI shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("send guest commands");
    let output = child.wait_with_output().expect("read guest output");
    std::fs::remove_file(&host_file).expect("remove host seed file");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"10:npm-probe\n");
}
