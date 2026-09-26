//! Optional live Chocolatey-style Node.js flow.
//! Set WINCLI_TEST_CHOCO=1 to download the official `node-v24.21.0-win-x64`
//! distribution from nodejs.org, install it through the shell's `choco`
//! builtin, and check `node -v` / `npm -v` on the native backend.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn choco_install_nodejs_then_node_and_npm_report_pinned_versions() {
    if std::env::var("WINCLI_TEST_CHOCO").as_deref() != Ok("1") {
        return;
    }
    let cache = std::env::temp_dir().join(format!("wincli-choco-e2e-{}", std::process::id()));
    let script = "powershell -c \"irm https://community.chocolatey.org/install.ps1|iex\"\nchoco install nodejs --version=\"24.21.0\"\nnode -v\nnpm -v\nexit\n";
    let mut child = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg("shell")
        .env("WINCLI_BACKEND", "native")
        .env("WINCLI_CACHE", &cache)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start WinCLI shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("send choco flow");
    let output = child.wait_with_output().expect("read shell output");
    std::fs::remove_dir_all(&cache).ok();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("wincli: Chocolatey is built in"),
        "bootstrap stub missing: {stdout}"
    );
    assert!(
        stdout.contains("Installed nodejs 24.21.0"),
        "install report missing: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| line.trim() == "v24.21.0"),
        "node -v wrong: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| line.trim() == "11.19.0"),
        "npm -v wrong: {stdout}"
    );
}
