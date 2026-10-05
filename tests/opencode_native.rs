//! Optional E2E checks against the official, unchanged Windows OpenCode binary.
#[cfg(unix)]
fn check_interactive(mode: &str) {
    let binary = std::env::var("WINRUN_OPENCODE_EXE").expect("set WINRUN_OPENCODE_EXE");
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/opencode/interactive_driver.py"
        ))
        .arg(env!("CARGO_BIN_EXE_winrun"))
        .arg(binary)
        .arg(mode)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[cfg(unix)]
#[test]
#[ignore = "requires WINRUN_OPENCODE_EXE, python3 and network access"]
fn windows_opencode_renders_accepts_input_and_exits_with_standalone_server() {
    check_interactive("standalone");
}
#[cfg(unix)]
#[test]
#[ignore = "requires WINRUN_OPENCODE_EXE, python3 and network access"]
fn windows_opencode_renders_accepts_input_and_exits_with_managed_server() {
    check_interactive("managed");
}
