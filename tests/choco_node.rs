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
    // The upstream bootstrap script needs full PowerShell/.NET, so it
    // fails clearly on stderr; the session must survive it and the
    // built-in choco flow below still runs.
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

#[test]
fn choco_7zip_install_runs_and_survives_snapshot_reload() {
    if std::env::var("WINCLI_TEST_CHOCO").as_deref() != Ok("1") {
        return;
    }
    let snapshot = std::env::temp_dir().join(format!("wincli-7zip-{}.snap", std::process::id()));
    let script = "choco install 7zip.install -y\n7z -h\nexit\n";
    let mut install = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg(format!("--save-snapshot={}", snapshot.display()))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start WinCLI shell");
    install
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("send install and run flow");
    let installed = install.wait_with_output().expect("read install output");
    assert_eq!(
        installed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let output = String::from_utf8_lossy(&installed.stdout);
    assert!(
        output.contains("Installed 7zip.install"),
        "install missing: {output}"
    );
    assert!(output.contains("7-Zip"), "7z did not run: {output}");

    let mut reload = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg(format!("--snapshot={}", snapshot.display()))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("reload WinCLI snapshot");
    reload
        .stdin
        .take()
        .unwrap()
        .write_all(b"7z -h\nexit\n")
        .expect("run 7z after reload");
    let reloaded = reload.wait_with_output().expect("read reloaded output");
    std::fs::remove_file(&snapshot).ok();
    assert_eq!(
        reloaded.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&reloaded.stderr)
    );
    let output = String::from_utf8_lossy(&reloaded.stdout);
    assert!(
        output.contains("7-Zip"),
        "7z unavailable after reload: {output}"
    );
}
