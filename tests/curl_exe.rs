//! `C:\Windows\System32\curl.exe` downloads through the host's curl into
//! the guest disk, from the prompt and from PowerShell scripts.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

/// Serve `body` once per connection for `connections` requests.
fn serve(body: &'static [u8], connections: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(connections) {
            let mut stream = stream.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let status = if request.starts_with(b"GET /missing") {
                "404 Not Found"
            } else {
                "200 OK"
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(body);
        }
    });
    port
}

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
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn curl_exe_downloads_into_the_guest_and_reports_exit_codes() {
    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("skipping: host curl is not installed");
        return;
    }
    let port = serve(b"payload", 3);
    let (out, err) = shell(&format!(
        "curl.exe -sSfLo C:\\got.txt http://127.0.0.1:{port}/file\n\
         type C:\\got.txt\n\
         powershell -c \"curl.exe -sf http://127.0.0.1:{port}/missing; echo code=$LASTEXITCODE\"\n\
         powershell -c \"$t = curl.exe -s http://127.0.0.1:{port}/x; echo body=$t\"\n\
         powershell -c \"curl.exe -K cfg http://127.0.0.1:{port}/x; echo refused=$LASTEXITCODE\"\n\
         exit\n"
    ));
    assert_eq!(out, "payload\ncode=22\nbody=payload\nrefused=2\n", "{err}");
    assert!(err.contains("option -K: is unknown"), "{err}");
}
