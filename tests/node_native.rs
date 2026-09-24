//! Optional real Node.js Windows binary compatibility check.
//! Set WINCLI_NODE_EXE to an official Windows x64 node.exe to run it.

use std::path::Path;
use std::process::Command;

#[test]
fn official_node_exposes_current_native_import_gap() {
    let Ok(path) = std::env::var("WINCLI_NODE_EXE") else {
        return;
    };
    let path = Path::new(&path);
    let bytes = std::fs::read(path).expect("read WINCLI_NODE_EXE");
    let report = wincli::inspect::inspect_pe(&bytes).expect("parse Windows node.exe");
    assert_eq!(report.arch, "x86_64");
    assert!(report.total() > 400, "unexpected Node.js import table");
    assert!(!report.runnable(), "Node.js requires more native API shims");

    let output = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg(path)
        .arg("--version")
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("start native WinCLI");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported native import: CRYPT32.dll!CertCloseStore"), "{stderr}");
}
