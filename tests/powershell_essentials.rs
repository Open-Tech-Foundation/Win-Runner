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
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn everyday_powershell_commands_work_in_interactive_shell() {
    let (out, err) = shell("New-Item C:\\work -ItemType Directory\ncd C:\\work\nSet-Content test.js hello\nRename-Item test.js test.mjs\nTest-Path test.js\nTest-Path test.mjs -PathType Leaf\nGet-ChildItem\nGet-Content test.mjs | Select-String HELLO -Quiet\ncat test.mjs | Tee-Object copy.txt | Out-File log.txt\nren copy.txt renamed.txt\nGet-Content renamed.txt -Tail 1\nSplit-Path C:\\work\\test.mjs -Leaf\nResolve-Path test.mjs\nGet-Command Rename-Item\nGet-Alias rni\nGet-Help Rename-Item\nClear-Content test.mjs\nGet-Content test.mjs | Measure-Object\ndir -File -Filter *.mjs\nexit\n");
    assert!(err.is_empty(), "{err}");
    assert!(out.starts_with("False\nTrue\ntest.mjs\nTrue\nhello\ntest.mjs\nC:\\work\\test.mjs\nrename-item\nrni -> rename-item\n"), "{out}");
    assert!(out.contains("-NewName"), "{out}");
    assert!(out.ends_with("Count: 0\ntest.mjs\n"), "{out}");
}

#[test]
fn rename_collision_and_invalid_commands_report_script_errors() {
    let (out, err) = shell("Set-Content test.js source\nSet-Content taken.mjs keep\nRename-Item test.js taken.mjs -Force\nGet-Content taken.mjs\nRename-Item test.js folder\\new.mjs\nGet-Content test.js\nGet-Content test.js -UnknownFlag\nexit 0\n");
    assert_eq!(out, "keep\nsource\n");
    assert!(err.contains("Rename-Item: destination exists"), "{err}");
    assert!(err.contains("-NewName must be a single filename"), "{err}");
    assert!(err.contains("unknown parameter -unknownflag"), "{err}");
    assert!(!err.contains("wpkg install"), "{err}");
}

#[test]
fn powershell_oracle_script_finishes_with_expected_native_results() {
    let probe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/oracle/powershell_essentials.ps1"
    );
    let (out, err) = shell(&format!(
        "@seed \"{probe}\" C:\\probe.ps1\nC:\\probe.ps1\nexit\n"
    ));
    assert!(err.is_empty(), "{err}");
    assert_eq!(out, "rename.old\nFalse\nrename.new\nTrue\nhello\nhello\ncollision: rejected\nkeep\nTrue\nFalse\nnested\nlisting\ntaken.mjs\nwith space.mjs\nnested.txt\n.txt\nTrue\npipeline\nappend\nTrue\nEND\n");
}

#[test]
fn powershell_scripting_oracle_script_matches_windows_results() {
    let probe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/oracle/powershell_scripting.ps1"
    );
    let (out, err) = shell(&format!(
        "@seed \"{probe}\" C:\\probe.ps1\npowershell -File C:\\probe.ps1\nexit\n"
    ));
    assert!(err.is_empty(), "{err}");
    assert_eq!(
        out,
        "param.defaults: latest False\n\
         param.bound: def-False-False\n\
         param.bound: x-True-False\n\
         param.bound: y-False-True\n\
         param.bound: z-False-False\n\
         return.early: one\n\
         return.value: loop-5\n\
         reg.arch: AMD64\n\
         reg.created: HKEY_CURRENT_USER\\Software\\WinRunOracle\n\
         reg.plain: C:\\plain\n\
         reg.expanded: C:\\Windows\\x\n\
         reg.number: 7\n\
         reg.changed: C:\\changed\n\
         reg.root: HKEY_CURRENT_USER\n\
         reg.open: HKEY_CURRENT_USER\\Software\\WinRunOracle\n\
         reg.raw: %SystemRoot%\\x\n\
         reg.kind: ExpandString DWord\n\
         reg.set: ExpandString a;b\n\
         reg.deleted: gone\n\
         reg.missing: null\n\
         reg.removed: []\n\
         reg.cleaned: False\n\
         os: True Win32NT\n\
         expr.bool: False False True\n\
         expr.numeric: True True True\n\
         nested: yes\n\
         continued: ok\n\
         mkdir: deep True\n\
         erroraction: continued\n\
         scope: g g\n\
         addtype.sse2: False True\n\
         addtype.as: True True\n\
         here: quote \"one\" and $literal\n\
         second False\n\
         verbatim: keep $this `n\n\
         escapes: \"q\" [$x] it's\n\
         char: A\n\
         cast: 255 42\n\
         END\n"
    );
}
