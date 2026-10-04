//! Pinned official Windows curl through native PE execution.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn curl() -> PathBuf {
    std::env::var_os("WINRUN_CURL_EXE")
        .map(PathBuf::from)
        .expect("configure WINRUN_CURL_EXE")
        .canonicalize()
        .unwrap()
}
fn shell(script: &str) -> Output {
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
    child.wait_with_output().unwrap()
}
fn server(status: u16, body: &'static str) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/probe", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                        .unwrap();
                    let mut request = [0; 4096];
                    let count = stream.read(&mut request).unwrap();
                    assert!(request[..count].starts_with(b"GET /probe HTTP/1.1"));
                    let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    stream.write_all(response.as_bytes()).unwrap();
                    break;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(5))
                }
                Err(error) => panic!("curl did not connect: {error}"),
            }
        }
    });
    (url, worker)
}

#[test]
#[ignore = "requires WINRUN_CURL_EXE; run explicitly with --ignored"]
fn windows_curl_starts_and_prints_version_and_usage() {
    let version = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(curl())
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "{}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("curl 8.22.0 "));
    let usage = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(curl())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&usage.stdout),
        String::from_utf8_lossy(&usage.stderr)
    );
    assert!(!text.contains("unsupported native import"), "{text}");
    assert!(text.contains("curl --help"), "{text}");
}

#[test]
#[ignore = "requires WINRUN_CURL_EXE; run explicitly with --ignored"]
fn windows_curl_on_guest_path_downloads_http_to_guest_file() {
    let (url, worker) = server(200, "native curl body\n");
    let output = shell(&format!("New-Item C:\\bin -ItemType Directory\n@seed \"{}\" C:\\bin\\curl.exe\n$env:PATH = 'C:\\bin'\ncurl --noproxy '*' --max-time 4 --silent --show-error --output C:\\download.txt {url}\nGet-Content C:\\download.txt\nexit\n", curl().display()));
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    worker.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"native curl body\n");
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires WINRUN_CURL_EXE; run explicitly with --ignored"]
fn windows_curl_reports_http_failures_and_missing_guest_files() {
    let (url, worker) = server(404, "not found\n");
    let failed = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(curl())
        .args([
            "--noproxy",
            "*",
            "--max-time",
            "4",
            "--silent",
            "--show-error",
            "--fail",
            &url,
        ])
        .output()
        .unwrap();
    worker.join().unwrap();
    assert_eq!(
        failed.status.code(),
        Some(22),
        "{}",
        String::from_utf8_lossy(&failed.stderr)
    );
    assert!(String::from_utf8_lossy(&failed.stderr).contains("404"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let refused_url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let refused = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(curl())
        .args([
            "--noproxy",
            "*",
            "--max-time",
            "4",
            "--silent",
            "--show-error",
            &refused_url,
        ])
        .output()
        .unwrap();
    assert_eq!(
        refused.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let file = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(curl())
        .args([
            "--noproxy",
            "*",
            "--silent",
            "--show-error",
            "file:///C:/missing-curl-fixture.txt",
        ])
        .output()
        .unwrap();
    assert_eq!(
        file.status.code(),
        Some(37),
        "{}",
        String::from_utf8_lossy(&file.stderr)
    );
}
