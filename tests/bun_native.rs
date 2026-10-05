//! Optional integration coverage using a real Windows x64 Bun executable.
//! A compiled Bun application also works with BUN_BE_BUN enabled by this test.
#[cfg(unix)]
#[test]
#[ignore = "requires WINRUN_BUN_EXE; run explicitly with --ignored"]
fn windows_bun_redirects_child_output_resumes_detached_children_and_serves_http() {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let binary =
        std::fs::canonicalize(std::env::var("WINRUN_BUN_EXE").expect("set WINRUN_BUN_EXE"))
            .unwrap();
    let source = r#"const fs = require('fs');
const cp = require('child_process');
const file = 'C:\\probe\\child.log';
const fd = fs.openSync(file, 'w');
console.log('file-child.start');
const wait = child => new Promise((resolve,reject) => { child.on('error',reject); child.on('exit',code => code === 0 ? resolve() : reject(Error('child exit '+code))); });
let child = cp.spawn(process.execPath, ['-e', 'process.stdout.write("file-child")'], {stdio:['ignore',fd,fd]});
await wait(child);
fs.closeSync(fd);
if (fs.readFileSync(file, 'utf8') !== 'file-child') throw Error('file redirection failed');
console.log('file-child.complete');
child = cp.spawn(process.execPath, ['-e', 'process.stderr.write("pipe-child")'], {detached:true, windowsHide:true, stdio:['ignore','ignore','pipe']});
let stderr = ''; child.stderr.on('data', data => stderr += data.toString());
await wait(child);
if (stderr !== 'pipe-child') throw Error('detached pipe failed: '+stderr);
console.log('detached-child.complete');
child = cp.spawn(process.execPath, ['-e', 'process.stdout.write(await Bun.stdin.text())'], {stdio:['pipe','pipe','pipe']});
let inputErrors = ''; child.stderr.on('data', data => inputErrors += data.toString());
let echoed = ''; child.stdout.on('data', data => echoed += data.toString());
child.stdin.end('native-stdin');
await wait(child).catch(error => { throw Error(error.message+': '+inputErrors); });
if (echoed !== 'native-stdin') throw Error('child stdin failed: '+echoed);
console.log('stdin-child.complete');
const server = Bun.serve({hostname:'127.0.0.1', port:0, fetch(){return new Response('native-http')}});
console.log('server.listen');
try {
  const response = await fetch('http://127.0.0.1:' + server.port);
  if (await response.text() !== 'native-http') throw Error('HTTP roundtrip failed');
} finally { server.stop(true); }
console.log('native Bun startup verified');
"#;
    let directory = std::env::temp_dir().join(format!("winrun-bun-test-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source_path = directory.join("startup.js");
    std::fs::write(&source_path, source).unwrap();
    let script = format!(
        "New-Item C:\\probe -ItemType Directory\n@seed \"{}\" C:\\probe\\bun.exe\n@seed \"{}\" C:\\probe\\startup.js\n$env:BUN_BE_BUN = \"1\"\nC:\\probe\\bun.exe C:\\probe\\startup.js\nexit\n",
        binary.display(), source_path.display()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .process_group(0)
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
    let start = Instant::now();
    let mut timed_out = false;
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(45) {
            timed_out = true;
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!timed_out, "native Bun timed out:\n{stdout}\n{stderr}");
    assert!(
        output.status.success(),
        "native Bun failed:\n{stdout}\n{stderr}"
    );
    assert!(stderr.is_empty(), "unexpected native diagnostics: {stderr}");
    assert!(stdout.contains("native Bun startup verified"), "{stdout}");
}

#[cfg(unix)]
#[test]
#[ignore = "requires WINRUN_BUN_EXE and python3; run explicitly with --ignored"]
fn windows_bun_preserves_console_identity_and_classifies_redirected_children_as_pipes() {
    let binary = std::env::var("WINRUN_BUN_EXE").expect("set WINRUN_BUN_EXE");
    let output = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/artifacts/bun/console_driver.py"))
        .arg(env!("CARGO_BIN_EXE_winrun"))
        .arg(binary)
        .output().unwrap();
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}
