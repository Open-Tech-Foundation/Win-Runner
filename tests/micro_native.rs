//! Official Windows Micro fixture; fetch with scripts/fetch-micro-fixture.sh.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const HASH: &str = "90635c53c11aa2a0d997f5e3ed43528877740725500207640b29551cef18479b";

#[test]
#[ignore = "requires WINRUN_MICRO_FIXTURE; run explicitly with --ignored"]
fn wpkg_micro_edits_unicode_resizes_and_persists_a_snapshot() {
    let fixture =
        PathBuf::from(std::env::var_os("WINRUN_MICRO_FIXTURE").expect("set WINRUN_MICRO_FIXTURE"));
    let archive = std::fs::read(fixture.join("micro-2.0.15-win64.zip"))
        .expect("fetch official Micro archive");
    let directory = std::env::temp_dir().join(format!("winrun-micro-{}", std::process::id()));
    std::fs::create_dir_all(directory.join("wpkg")).unwrap();
    std::fs::write(directory.join("wpkg").join(HASH), archive).unwrap();
    let initial = directory.join("installed.snap");
    let edited = directory.join("edited.snap");
    let mut setup = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .env("WINRUN_CACHE_DIR", &directory)
        .arg(format!("--save-snapshot={}", initial.display()))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    setup
        .stdin
        .take()
        .unwrap()
        .write_all(b"wpkg install micro\nmicro -version\nexit\n")
        .unwrap();
    let installed = setup.wait_with_output().unwrap();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&installed.stdout).contains("Version: 2.0.15"),
        "{}",
        String::from_utf8_lossy(&installed.stdout)
    );
    let terminal = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/micro/pty_driver.py"
        ))
        .arg(env!("CARGO_BIN_EXE_winrun"))
        .arg(&initial)
        .arg(&edited)
        .output()
        .unwrap();
    assert!(
        terminal.status.success(),
        "{}",
        String::from_utf8_lossy(&terminal.stderr)
    );
    let fs = winrun::snapshot::load_file(edited.to_str().unwrap()).unwrap();
    assert_eq!(
        fs.read_file(r"C:\notes.txt").unwrap(),
        "Hello café 界?\r\n".as_bytes()
    );
    for mode in ["reopen", "save-error"] {
        let next = directory.join(format!("{mode}.snap"));
        let terminal = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/artifacts/micro/pty_driver.py"
            ))
            .arg(env!("CARGO_BIN_EXE_winrun"))
            .arg(&edited)
            .arg(&next)
            .arg(mode)
            .output()
            .unwrap();
        assert!(
            terminal.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&terminal.stderr)
        );
        let fs = winrun::snapshot::load_file(next.to_str().unwrap()).unwrap();
        if mode == "reopen" {
            assert_eq!(
                fs.read_file(r"C:\notes.txt").unwrap(),
                "Reopened: Hello café 界?\r\n".as_bytes()
            );
        } else {
            assert!(fs.read_file(r"C:\missing\notes.txt").is_err());
            assert_eq!(
                fs.read_file(r"C:\notes.txt").unwrap(),
                "Hello café 界?\r\n".as_bytes()
            );
        }
    }
    let plugin_snapshot = directory.join("plugin.snap");
    let job_snapshot = directory.join("job.snap");
    let mut fs = winrun::snapshot::load_file(initial.to_str().unwrap()).unwrap();
    fs.mkdir(r"C:\Users\runner\.config\micro\plug\jobfixture")
        .unwrap();
    fs.write_file(
        r"C:\Users\runner\.config\micro\plug\jobfixture\jobfixture.lua",
        include_bytes!("artifacts/micro/jobfixture.lua").to_vec(),
    )
    .unwrap();
    winrun::snapshot::save_file(&mut fs, plugin_snapshot.to_str().unwrap()).unwrap();
    let terminal = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/micro/pty_driver.py"
        ))
        .arg(env!("CARGO_BIN_EXE_winrun"))
        .arg(&plugin_snapshot)
        .arg(&job_snapshot)
        .arg("job")
        .output()
        .unwrap();
    assert!(
        terminal.status.success(),
        "plugin job: {}",
        String::from_utf8_lossy(&terminal.stderr)
    );
    let fs = winrun::snapshot::load_file(job_snapshot.to_str().unwrap()).unwrap();
    assert_eq!(
        fs.read_file(r"C:\job-output.txt").unwrap(),
        b"lint-probe\r\n"
    );
    std::fs::remove_dir_all(directory).unwrap();
}
