//! Optional real Node.js Windows binary compatibility check.
//! Set WINCLI_NODE_EXE to an official Windows x64 node.exe to run it.

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
    let Ok(path) = std::env::var("WINCLI_NODE_EXE") else {
        return;
    };
    let path = Path::new(&path);
    let bytes = std::fs::read(path).expect("read WINCLI_NODE_EXE");
    let report = wincli::inspect::inspect_pe(&bytes).expect("parse Windows node.exe");
    assert_eq!(report.arch, "x86_64");
    assert!(report.total() > 400, "unexpected Node.js import table");
    assert!(
        !report.runnable(),
        "inspection still lists optional static imports"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg(path)
        .arg("--version")
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("start native WinCLI");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "v24.21.0");

    let output = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg(path)
        .args(["-e", "console.log(1 + 2)"])
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("evaluate JavaScript through native WinCLI");
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
    let Ok(node) = std::env::var("WINCLI_NODE_EXE") else {
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_wincli"));
    command
        .arg(node)
        .args(["-e", &source])
        .env("WINCLI_BACKEND", "native")
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
    let Ok(node) = std::env::var("WINCLI_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let source = "const fs=require('node:fs');fs.mkdirSync('C:/watch');const timeout=setTimeout(()=>process.exit(2),5000);const watcher=fs.watch('C:/watch',{recursive:true},(event,name)=>{if(name==='probe.txt'){clearTimeout(timeout);watcher.close();console.log('winfs-watch-ok:'+event+':'+name)}});setTimeout(()=>fs.writeFileSync('C:/watch/probe.txt','changed'),200)";
    let output = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg(node)
        .args(["-e", source])
        .env("WINCLI_BACKEND", "native")
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
fn official_windows_node_reads_guest_file_metadata_and_contents() {
    let Ok(node) = std::env::var("WINCLI_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let host_file = std::env::temp_dir().join(format!("wincli-node-fs-{}.txt", std::process::id()));
    std::fs::write(&host_file, b"npm-probe\n").expect("create host seed file");
    let script = format!(
        "@seed {} C:\\probe.txt\n\"{}\" -e \"const fs=require('node:fs');const p='C:\\\\probe.txt';console.log(fs.statSync(p).size+':'+fs.readFileSync(p,'utf8').trim()+':'+fs.readdirSync('C:/').includes('probe.txt'))\"\nexit\n",
        host_file.display(),
        node.display(),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg("shell")
        .env("WINCLI_BACKEND", "native")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native WinCLI shell");
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
fn official_windows_node_runs_the_staged_npm_cli_natively() {
    let Ok(node) = std::env::var("WINCLI_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let npm = std::env::var_os("WINCLI_NPM_ROOT")
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg("shell")
        .env("WINCLI_BACKEND", "native")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native WinCLI shell");
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
    let Ok(node) = std::env::var("WINCLI_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let npm = std::env::var_os("WINCLI_NPM_ROOT")
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
        "New-Item -ItemType Directory -Force C:\\Users\\wincli\\npm-cache\\_cacache\\tmp | Out-Null\nNew-Item -ItemType Directory -Force C:\\Users\\wincli\\npm-cache\\_logs | Out-Null\nNew-Item -ItemType Directory -Force C:\\project | Out-Null\n",
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg("shell")
        .env("WINCLI_BACKEND", "native")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native WinCLI shell");
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
    if std::env::var("WINCLI_TEST_LIVE_NPM").as_deref() != Ok("1") {
        return;
    }
    let Ok(node) = std::env::var("WINCLI_NODE_EXE") else {
        return;
    };
    let node = Path::new(&node)
        .canonicalize()
        .expect("Windows node.exe exists");
    let npm = std::env::var_os("WINCLI_NPM_ROOT")
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
        "New-Item -ItemType Directory -Force C:\\Users\\wincli\\npm-cache\\_cacache\\tmp | Out-Null\nNew-Item -ItemType Directory -Force C:\\Users\\wincli\\npm-cache\\_logs | Out-Null\nNew-Item -ItemType Directory -Force C:\\project | Out-Null\n",
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_wincli"))
        .arg("shell")
        .env("WINCLI_BACKEND", "native")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native WinCLI shell");
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
