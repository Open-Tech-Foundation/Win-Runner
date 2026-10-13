//! The `tar.exe` every Windows 10+ installation has in System32, run by
//! guest shells on guest files.

use std::io::Write;
use std::process::{Command, Stdio};

fn shell(script: &str) -> (String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn system32_tar_creates_lists_and_extracts_archives() {
    let (out, err) = shell(
        "Test-Path C:\\Windows\\System32\\tar.exe\n\
         New-Item C:\\work -ItemType Directory\n\
         cd C:\\work\n\
         New-Item src -ItemType Directory\n\
         New-Item src\\sub -ItemType Directory\n\
         Set-Content src\\a.txt alpha\n\
         Set-Content src\\sub\\b.txt beta\n\
         tar -czf pkg.tgz src\n\
         tar -tf pkg.tgz\n\
         New-Item out -ItemType Directory\n\
         tar -xf pkg.tgz -C out --strip-components 1\n\
         Get-Content out\\sub\\b.txt\n\
         tar -caf pkg.zip src\n\
         cmd /c \"tar -xf pkg.zip -C out2 || echo cmd saw the failure\"\n\
         New-Item zipped -ItemType Directory\n\
         tar -xf pkg.zip -C zipped\n\
         Get-Content zipped\\src\\a.txt\n\
         tar -xf missing.tar\n\
         \"code=$LASTEXITCODE\"\n\
         exit\n",
    );
    assert_eq!(
        out,
        "True\nsrc/\nsrc/a.txt\nsrc/sub/\nsrc/sub/b.txt\nbeta\ncmd saw the failure\r\nalpha\ncode=1\n",
        "{err}"
    );
    assert!(err.contains("tar: could not chdir to 'out2'"), "{err}");
    assert!(err.contains("tar: Error opening archive: Failed to open 'missing.tar'"), "{err}");
}
