//! The `where.exe` every Windows installation has in System32, run by guest
//! shells over the guest disk and PATH.

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
fn system32_where_finds_programs_on_path_and_in_the_current_directory() {
    let (out, err) = shell(
        "where.exe cmd\n\
         \"code=$LASTEXITCODE\"\n\
         New-Item C:\\work -ItemType Directory | Out-Null\n\
         cd C:\\work\n\
         Set-Content tool.bat 'echo hi'\n\
         where.exe tool\n\
         where.exe /Q winrun-no-such-program\n\
         \"code=$LASTEXITCODE\"\n\
         where.exe winrun-no-such-program\n\
         \"code=$LASTEXITCODE\"\n\
         where.exe /R C:\\work *.bat\n\
         exit\n",
    );
    assert_eq!(
        out,
        "C:\\Windows\\System32\\cmd.exe\ncode=0\nC:\\work\\tool.bat\ncode=1\ncode=1\nC:\\work\\tool.bat\n",
        "{err}"
    );
    assert_eq!(err.matches("INFO: Could not find files for the given pattern(s).").count(), 1, "{err}");
}
