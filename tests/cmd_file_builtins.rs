//! cmd.exe's file built-ins and the System32 text tools (find, sort,
//! more), run by guest shells on guest files.

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
        String::from_utf8_lossy(&output.stdout).replace('\r', ""),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn dir_ren_move_and_path_run_inside_cmd() {
    let (out, err) = shell(
        "New-Item C:\\work -ItemType Directory | Out-Null\n\
         cd C:\\work\n\
         cmd /c 'mkdir sub & echo one> a.txt & echo two> sub\\b.log'\n\
         cmd /c 'dir /b'\n\
         cmd /c 'dir | find \"File(s)\"'\n\
         cmd /c 'dir /b /s *.log'\n\
         cmd /c 'ren a.txt c.txt & move c.txt sub & dir /b sub'\n\
         cmd /c 'set PATH=C:\\x& path'\n\
         cmd /c 'dir /b missing.txt'\n\
         \"code=$LASTEXITCODE\"\n\
         exit\n",
    );
    assert_eq!(
        out,
        "a.txt\nsub\n               1 File(s)              6 bytes\nC:\\work\\sub\\b.log\n        1 file(s) moved.\nb.log\nc.txt\nPATH=C:\\x\ncode=1\n",
        "{err}"
    );
    assert!(err.contains("File Not Found"), "{err}");
}

#[test]
fn find_sort_and_more_filter_text_from_files_and_pipes() {
    let (out, err) = shell(
        "New-Item C:\\work -ItemType Directory | Out-Null\n\
         cd C:\\work\n\
         cmd /c 'echo pear> f.txt& echo Apple>> f.txt& echo banana>> f.txt'\n\
         cmd /c 'find \"an\" f.txt'\n\
         cmd /c 'type f.txt | find /c /i \"a\"'\n\
         cmd /c 'type f.txt | sort'\n\
         cmd /c 'more f.txt'\n\
         cmd /c 'find \"zz\" f.txt'\n\
         \"code=$LASTEXITCODE\"\n\
         exit\n",
    );
    assert_eq!(
        out,
        "\n---------- F.TXT\nbanana\n3\nApple\nbanana\npear\npear\nApple\nbanana\n\n---------- F.TXT\ncode=1\n",
        "{err}"
    );
}
