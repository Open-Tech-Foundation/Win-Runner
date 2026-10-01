//! Optional real Node.js Windows binary compatibility check.
//! Set WINRUN_NODE_EXE to an official Windows x64 node.exe to run it.

#[cfg(unix)]
use std::io::Read;
use std::io::Write;
#[cfg(unix)]
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

#[test]
fn official_windows_node_runs_version_and_javascript_natively() {
    let Ok(path) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let path = Path::new(&path);
    let bytes = std::fs::read(path).expect("read WINRUN_NODE_EXE");
    let report = winrun::inspect::inspect_pe(&bytes).expect("parse Windows node.exe");
    assert_eq!(report.arch, "x86_64");
    assert!(report.total() > 400, "unexpected Node.js import table");
    assert!(
        !report.runnable(),
        "inspection still lists optional static imports"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(path)
        .arg("--version")
        .output()
        .expect("start native Win-Runner");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "v24.21.0");

    let output = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(path)
        .args(["-e", "console.log(1 + 2)"])
        .output()
        .expect("evaluate JavaScript through native Win-Runner");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "3");
}

#[test]
#[cfg(unix)]
fn official_windows_node_serves_an_http_request_natively() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let reservation = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a local test port");
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let source = format!(
        "require('node:http').createServer((req,res)=>res.end('native-node-http-ok')).listen({port},'127.0.0.1')"
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_winrun"));
    command
        .arg(node)
        .args(["-e", &source])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.process_group(0);
    let mut child = command.spawn().expect("start native Node HTTP server");

    let response = (|| -> Result<Vec<u8>, String> {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                return Err(format!("Node exited before listening: {status}"));
            }
            if Instant::now() >= deadline {
                return Err("Node HTTP server did not accept a connection within 10s".into());
            }
            match TcpStream::connect_timeout(&address, Duration::from_millis(250)) {
                Ok(mut stream) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .map_err(|error| error.to_string())?;
                    stream
                        .write_all(
                            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                        )
                        .map_err(|error| error.to_string())?;
                    let mut response = Vec::new();
                    stream
                        .read_to_end(&mut response)
                        .map_err(|error| error.to_string())?;
                    return Ok(response);
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    })();
    unsafe {
        kill(-(child.id() as i32), 15);
    }
    let output = child.wait_with_output().expect("collect Node output");
    let response = response.unwrap_or_else(|error| {
        format!(
            "{error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into_bytes()
    });
    assert!(
        response
            .windows(b"HTTP/1.1 200".len())
            .any(|window| window == b"HTTP/1.1 200"),
        "unexpected native Node HTTP response: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        response
            .windows(b"native-node-http-ok".len())
            .any(|window| window == b"native-node-http-ok"),
        "native Node HTTP body is missing: {}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn official_windows_node_receives_winfs_directory_changes_natively() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let source = "const fs=require('node:fs');fs.mkdirSync('C:/watch');const timeout=setTimeout(()=>process.exit(2),5000);const watcher=fs.watch('C:/watch',{recursive:true},(event,name)=>{if(name==='probe.txt'){clearTimeout(timeout);watcher.close();console.log('winfs-watch-ok:'+event+':'+name)}});setTimeout(()=>fs.writeFileSync('C:/watch/probe.txt','changed'),200)";
    let output = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(node)
        .args(["-e", source])
        .output()
        .expect("run native Node fs.watch check");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "winfs-watch-ok:rename:probe.txt"
    );
}

#[test]
fn official_windows_node_relative_file_remains_visible_to_shell_dir() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let script = format!(
        "\"{}\" -e 'const fs=require(\"fs\");fs.writeFileSync(\"node-test.txt\",\"Hello from Node\");console.log(fs.readdirSync(\".\").includes(\"node-test.txt\"))'\nls\nexit\n",
        node.display()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native Win-Runner shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("send Node file creation and listing commands");
    let output = child.wait_with_output().expect("read shell output");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("true"),
        "Node did not see its file: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| line.trim() == "node-test.txt"),
        "Win-Runner dir did not list Node's retained file: {stdout}"
    );
}

#[test]
fn official_windows_node_reads_guest_file_metadata_and_contents() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let host_file = std::env::temp_dir().join(format!("winrun-node-fs-{}.txt", std::process::id()));
    std::fs::write(&host_file, b"npm-probe\n").expect("create host seed file");
    let script = format!(
        "@seed {} C:\\probe.txt\n\"{}\" -e \"const fs=require('node:fs');const p='C:\\\\probe.txt';console.log(fs.statSync(p).size+':'+fs.readFileSync(p,'utf8').trim()+':'+fs.readdirSync('C:/').includes('probe.txt'))\"\nexit\n",
        host_file.display(),
        node.display(),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native Win-Runner shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("send guest commands");
    let output = child.wait_with_output().expect("read guest output");
    std::fs::remove_file(&host_file).expect("remove host seed file");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"10:npm-probe:true\n");
}

#[test]
fn official_windows_node_exec_file_sync_captures_powershell_output() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let source = "const {execFileSync}=require('child_process'); const output=execFileSync('powershell.exe',['-NoProfile','-Command','Write-Output Hello']); process.stdout.write(output.toString().trim()+'\\n')";
    let script = format!(
        "@seed {} C:\\bin\\node.exe\nC:\\bin\\node.exe -e \"{source}\"\nexit\n",
        node.display()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native Win-Runner shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("send Node child-process probe");
    let output = child
        .wait_with_output()
        .expect("read Node child-process output");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Hello"),
        "Node did not capture PowerShell output: {stdout}"
    );
}

#[test]
fn official_windows_node_starts_nested_node_in_an_exec_worker() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let source = "const {execFileSync}=require('node:child_process');const out=execFileSync('C:\\\\bin\\\\node.exe',['-p','process.pid']);process.stdout.write(out.toString())";
    let script = format!(
        "@seed {} C:\\bin\\node.exe\nC:\\bin\\node.exe -e \"{source}\"\nexit\n",
        node.display()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native Win-Runner shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("send nested Node process probe");
    let output = child
        .wait_with_output()
        .expect("read nested Node process output");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let child_pid = stdout
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .find(|pid| *pid > 1);
    assert!(
        child_pid.is_some(),
        "nested child PID was not reported: {stdout}"
    );
}

#[test]
fn official_windows_node_runs_the_staged_npm_cli_natively() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let npm = std::env::var_os("WINRUN_NPM_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| node.parent().unwrap().join("npm-stage/C/npm"));
    if !npm.join("bin/npm-cli.js").is_file() {
        return;
    }
    let npm = npm.canonicalize().expect("npm root exists");
    let expected_version = std::fs::read_to_string(npm.join("package.json"))
        .expect("read npm package metadata")
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "\"version\"").then(|| {
                value
                    .trim()
                    .trim_end_matches(',')
                    .trim_matches('"')
                    .to_string()
            })
        })
        .expect("npm package version exists");

    let mut files = Vec::new();
    collect_files(&npm, &mut files);
    files.sort();
    let mut script = String::new();
    for file in files {
        let relative = file.strip_prefix(&npm).unwrap();
        let guest = format!("C:\\npm\\{}", relative.to_string_lossy().replace('/', "\\"));
        script.push_str(&format!("@seed \"{}\" {guest}\n", file.display()));
    }
    script.push_str(&format!(
        "\"{}\" C:\\npm\\bin\\npm-cli.js --version\nexit\n",
        node.display()
    ));

    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native Win-Runner shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("seed npm and run its CLI");
    let output = child.wait_with_output().expect("read npm output");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        expected_version
    );
}

#[test]
fn official_windows_node_installs_and_runs_a_real_npm_package_natively() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let npm = std::env::var_os("WINRUN_NPM_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| node.parent().unwrap().join("npm-stage/C/npm"));
    if !npm.join("bin/npm-cli.js").is_file() {
        return;
    }
    let npm = npm.canonicalize().expect("npm root exists");
    let artifacts = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/artifacts/node");
    let mut files = Vec::new();
    collect_files(&npm, &mut files);
    files.sort();
    let mut script = String::from(
        "New-Item -ItemType Directory -Force C:\\Users\\winrun\\npm-cache\\_cacache\\tmp | Out-Null\nNew-Item -ItemType Directory -Force C:\\Users\\winrun\\npm-cache\\_logs | Out-Null\nNew-Item -ItemType Directory -Force C:\\project | Out-Null\n",
    );
    for file in files {
        let relative = file.strip_prefix(&npm).unwrap();
        let guest = format!("C:\\npm\\{}", relative.to_string_lossy().replace('/', "\\"));
        script.push_str(&format!("@seed \"{}\" {guest}\n", file.display()));
    }
    let tarball = artifacts.join("is-number-7.0.0.tgz");
    let probe = artifacts.join("is-number-probe.js");
    script.push_str(&format!(
        "@seed \"{}\" C:\\project\\is-number-7.0.0.tgz\n@seed \"{}\" C:\\project\\probe.js\n\"{}\" C:\\npm\\bin\\npm-cli.js --prefix C:\\project install C:\\project\\is-number-7.0.0.tgz --offline --no-update-notifier --no-audit --no-fund --no-package-lock --ignore-scripts\n\"{}\" C:\\project\\probe.js\nexit\n",
        tarball.display(),
        probe.display(),
        node.display(),
        node.display()
    ));

    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native Win-Runner shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("install and run the npm package");
    let output = child.wait_with_output().expect("read package output");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("added 1 package")),
        "npm did not report installing the package: {stdout}"
    );
    assert_eq!(stdout.lines().last(), Some("true false false"));
}

#[test]
fn official_windows_node_installs_from_the_live_npm_registry_natively() {
    if std::env::var("WINRUN_TEST_LIVE_NPM").as_deref() != Ok("1") {
        return;
    }
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let npm = std::env::var_os("WINRUN_NPM_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| node.parent().unwrap().join("npm-stage/C/npm"));
    if !npm.join("bin/npm-cli.js").is_file() {
        return;
    }
    let npm = npm.canonicalize().expect("npm root exists");
    let probe =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/artifacts/node/is-number-probe.js");
    let mut files = Vec::new();
    collect_files(&npm, &mut files);
    files.sort();
    let mut script = String::from(
        "New-Item -ItemType Directory -Force C:\\Users\\winrun\\npm-cache\\_cacache\\tmp | Out-Null\nNew-Item -ItemType Directory -Force C:\\Users\\winrun\\npm-cache\\_logs | Out-Null\nNew-Item -ItemType Directory -Force C:\\project | Out-Null\n",
    );
    for file in files {
        let relative = file.strip_prefix(&npm).unwrap();
        let guest = format!("C:\\npm\\{}", relative.to_string_lossy().replace('/', "\\"));
        script.push_str(&format!("@seed \"{}\" {guest}\n", file.display()));
    }
    script.push_str(&format!(
        "@seed \"{}\" C:\\project\\probe.js\n\"{}\" C:\\npm\\bin\\npm-cli.js --prefix C:\\project install is-number@7.0.0 --no-update-notifier --no-audit --no-fund --no-package-lock --ignore-scripts\n\"{}\" C:\\project\\probe.js\nexit\n",
        probe.display(), node.display(), node.display()
    ));

    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native Win-Runner shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("read npm output");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("added 1 package")),
        "npm did not install from the registry: {stdout}"
    );
    assert_eq!(stdout.lines().last(), Some("true false false"));
}

fn collect_files(root: &Path, output: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).expect("read npm directory") {
        let path = entry.expect("read npm entry").path();
        if path.is_dir() {
            collect_files(&path, output);
        } else if path.is_file() {
            output.push(path);
        }
    }
}

/// npm's "Ok to proceed? (y)" prompt reads a line from a console stdin
/// through libuv's `ReadConsoleW` line reader on a `QueueUserWorkItem`
/// thread. `script` gives the guest a real pseudo-terminal.
#[test]
#[cfg(unix)]
fn official_windows_node_reads_a_prompt_answer_from_a_terminal() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    if Command::new("script").arg("--version").output().is_err() {
        return;
    }
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let source = "const rl=require('readline').createInterface({input:process.stdin,output:process.stdout});\
        rl.question('Ok to proceed? (y) ',a=>{console.log('ANSWER='+JSON.stringify(a)+' tty='+process.stdin.isTTY);rl.close()})";
    let command = format!(
        "'{}' '{}' -e \"{}\"",
        env!("CARGO_BIN_EXE_winrun"),
        node.display(),
        source
    );
    let mut child = Command::new("script")
        .args(["-qec", &command, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start Windows node on a pseudo-terminal");
    let mut stdin = child.stdin.take().unwrap();
    let writer = thread::spawn(move || {
        // Let node reach the prompt before the terminal sees the answer.
        thread::sleep(Duration::from_secs(3));
        let _ = stdin.write_all(b"y\n");
        thread::sleep(Duration::from_secs(30));
    });
    let output = child.wait_with_output().expect("read node output");
    drop(writer);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ANSWER=\"y\" tty=true"),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// create-vite's prompts switch stdin between line and raw mode. Raw mode
/// reads keys through `RegisterWaitForSingleObject` on the console handle
/// and `ReadConsoleInputW`; leaving raw mode starts a line read that the
/// next switch cancels with an injected Enter (`WriteConsoleInputW`).
#[test]
#[cfg(unix)]
fn official_windows_node_reads_raw_keys_across_terminal_mode_switches() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    if Command::new("script").arg("--version").output().is_err() {
        return;
    }
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    // Read a line, then start a line read and switch to raw mode while it
    // waits. The Enter that cancels it must not reach the raw keys.
    let source = "const rl=require('readline');\
        const i=rl.createInterface({input:process.stdin,output:process.stdout});\
        i.question('name? ',n=>{i.close();let got='';\
        process.stdin.setRawMode(false);process.stdin.resume();\
        setTimeout(()=>process.stdin.setRawMode(true),500);\
        process.stdin.on('data',d=>{got+=d.toString();\
        if(got.includes('\\r')){process.stdin.setRawMode(false);\
        console.log('LINE='+JSON.stringify(n)+' RAW='+JSON.stringify(got));process.exit(0)}})})";
    let command = format!(
        "'{}' '{}' -e \"{}\"",
        env!("CARGO_BIN_EXE_winrun"),
        node.display(),
        source
    );
    let mut child = Command::new("script")
        .args(["-qec", &command, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start Windows node on a pseudo-terminal");
    let mut stdin = child.stdin.take().unwrap();
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_secs(3));
        let _ = stdin.write_all(b"app\n");
        thread::sleep(Duration::from_secs(2));
        let _ = stdin.write_all(b"y\x1b[B\r");
        thread::sleep(Duration::from_secs(30));
    });
    let output = child.wait_with_output().expect("read node output");
    drop(writer);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#"LINE="app" RAW="y\u001b[B\r""#),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Guest process ids must be unique across a process tree: npm and its
/// cache name temp files after `process.pid`. Each process used to number
/// its children from 2, so nested processes shared ids (and debug builds
/// panicked on a child id below its parent's).
#[test]
fn official_windows_node_processes_nested_three_deep_have_distinct_ids() {
    let Ok(node) = std::env::var("WINRUN_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    // Each level prints its pid, then runs the next level and prints its
    // output. Two siblings at the deepest level run one after the other.
    let scripts = std::env::temp_dir().join(format!("winrun-nested-ids-{}", std::process::id()));
    std::fs::create_dir_all(&scripts).unwrap();
    // Inherited stdio, as npm runs its children.
    let run = "const run=f=>require('node:child_process')\
        .spawnSync('C:\\\\bin\\\\node.exe',['C:\\\\bin\\\\'+f],{stdio:'inherit'});";
    std::fs::write(scripts.join("leaf.js"), "console.log(process.pid)").unwrap();
    std::fs::write(
        scripts.join("middle.js"),
        format!("{run}console.log(process.pid);run('leaf.js');run('leaf.js')"),
    )
    .unwrap();
    std::fs::write(
        scripts.join("top.js"),
        format!("{run}console.log(process.pid);run('middle.js')"),
    )
    .unwrap();
    let mut script = format!("@seed {} C:\\bin\\node.exe\n", node.display());
    for name in ["top.js", "middle.js", "leaf.js"] {
        script.push_str(&format!(
            "@seed {} C:\\bin\\{name}\n",
            scripts.join(name).display()
        ));
    }
    script.push_str("C:\\bin\\node.exe C:\\bin\\top.js\nexit\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native Win-Runner shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .expect("send the nested process probe");
    let output = child.wait_with_output().expect("read nested output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pids: Vec<u32> = stdout
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .collect();
    assert_eq!(
        pids.len(),
        4,
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut unique = pids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 4, "process ids repeat: {pids:?}");
    assert!(!stdout.contains("panicked"), "{stdout}");
    std::fs::remove_dir_all(scripts).ok();
}
