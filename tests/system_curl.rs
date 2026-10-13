//! The `curl.exe` every Windows 10+ installation has in System32, run by
//! guest programs and shells against a local HTTP server.

use std::io::{Read, Write};
use std::net::TcpListener;
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

/// Serve `/hello` and `/echo` (which returns the request body); anything
/// else is a 404.
fn server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            let _ = stream.read_exact(&mut body);
            let (status, body) = match head.split(' ').nth(1).unwrap_or("") {
                "/hello" => ("200 OK", b"hello from the server\nsecond line\n".to_vec()),
                "/echo" => ("200 OK", body),
                "/moved" => ("302 Found", Vec::new()),
                _ => ("404 Not Found", b"missing".to_vec()),
            };
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nLocation: /hello\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    port
}

#[test]
fn system32_has_curl_and_it_downloads_into_the_guest() {
    let base = format!("http://127.0.0.1:{}", server());
    let (out, err) = shell(&format!(
        "Test-Path C:\\Windows\\System32\\curl.exe\n\
         curl.exe -s -o C:\\got.txt {base}/hello\n\
         Get-Content C:\\got.txt -TotalCount 1\n\
         curl.exe -sL -w \"`n%{{http_code}} %{{num_redirects}}`n\" {base}/moved\n\
         $target = \"{base}/echo\"\n\
         curl.exe -s -d \"name=value\" $target\n\
         exit\n"
    ));
    assert!(err.is_empty(), "{err}");
    assert_eq!(
        out,
        "True\nhello from the server\nhello from the server\nsecond line\n\n200 1\nname=value"
    );
}

#[test]
fn curl_exit_codes_reach_shells_and_pipelines() {
    let base = format!("http://127.0.0.1:{}", server());
    let (out, err) = shell(&format!(
        "curl.exe -sf {base}/missing\n\
         \"code=$LASTEXITCODE\"\n\
         curl.exe -s {base}/hello | Select-Object -First 1\n\
         cmd /c \"curl.exe -sSf {base}/missing || echo cmd saw the failure\"\n\
         curl.exe --definitely-unknown\n\
         \"code=$LASTEXITCODE\"\n\
         exit\n"
    ));
    assert_eq!(out, "code=22\nhello from the server\ncmd saw the failure\r\ncode=2\n", "{err}");
    assert!(err.contains("curl: (22) The requested URL returned error: 404"), "{err}");
    assert!(err.contains("curl: option --definitely-unknown: is unknown"), "{err}");
}

#[test]
fn invoke_rest_method_saves_bodies_with_outfile() {
    let base = format!("http://127.0.0.1:{}", server());
    let (out, err) = shell(&format!(
        "Invoke-RestMethod {base}/hello -OutFile C:\\saved.txt\n\
         Get-Content C:\\saved.txt\n\
         exit\n"
    ));
    assert!(err.is_empty(), "{err}");
    assert_eq!(out, "hello from the server\nsecond line\n");
}
