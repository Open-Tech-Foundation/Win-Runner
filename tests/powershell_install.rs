//! Remote PowerShell installers exercised through the interactive CLI.
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;

struct Server {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    fn new(routes: HashMap<String, (u16, Vec<u8>, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                            .unwrap();
                        let mut request = String::new();
                        if BufReader::new(&stream).read_line(&mut request).is_err() {
                            continue;
                        }
                        let path = request.split_whitespace().nth(1).unwrap_or("");
                        let missing = (404, b"missing".to_vec(), String::new());
                        let (status, body, headers) = routes.get(path).unwrap_or(&missing);
                        let header = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n", body.len());
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(body);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5))
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn shell(input: &str) -> (String, String) {
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
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

// A stored ZIP entry: the reader uses the local header, as streamed ZIPs do.
fn archive(exe: &[u8]) -> Vec<u8> {
    let mut data = b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec();
    data.extend_from_slice(&(exe.len() as u32).to_le_bytes());
    data.extend_from_slice(&(exe.len() as u32).to_le_bytes());
    data.extend_from_slice(&[7, 0, 0, 0]);
    data.extend_from_slice(b"tsr.exe");
    data.extend_from_slice(exe);
    data
}

fn installer(url: &str) -> String {
    // Representative release installer, retaining the expressions used by TSR.
    r#"
$ErrorActionPreference = 'Stop'
$InstallDir = if ($env:TSR_INSTALL) { $env:TSR_INSTALL } else { Join-Path $HOME '.tsr' }
$BinDir = Join-Path $InstallDir 'bin'
$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'x86-64' } default { throw 'unsupported architecture' } }
$name = "tsr-windows-$arch"
$resp = Invoke-WebRequest -Uri '@URL@/latest' -UseBasicParsing
$final = if ($resp.BaseResponse.ResponseUri) { $resp.BaseResponse.ResponseUri.AbsoluteUri } else { $resp.BaseResponse.RequestMessage.RequestUri.AbsoluteUri }
$version = $final -replace '.*/tag/', ''
Write-Host "Installing $version"
$tmp = Join-Path $env:TEMP ("tsr-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $zip = Join-Path $tmp "$name.zip"
  Invoke-WebRequest -Uri "@URL@/download/$version/$name.zip" -OutFile $zip
  $sumFile = Join-Path $tmp 'checksums.txt'
  $line = $null
  try {
    Invoke-WebRequest -Uri '@URL@/checksums.txt' -OutFile $sumFile
    $line = Get-Content $sumFile | Where-Object { $_ -match "  $([regex]::Escape($name)).zip$" } | Select-Object -First 1
  } catch {}
  if ($line) {
    $expected = (($line -split '\s+')[0]).ToLower()
    $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) { throw 'checksum verification failed' }
    Write-Host 'checksum verified'
  } else { Write-Host 'no checksums available' }
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
  Copy-Item (Join-Path $tmp 'tsr.exe') (Join-Path $BinDir 'tsr.exe') -Force
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $BinDir) {
    [Environment]::SetEnvironmentVariable('Path', "$BinDir;$userPath", 'User')
  }
} finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
"#.replace("@URL@", url)
}

fn install_fixture(checksum: Option<&str>) -> (String, String) {
    let exe = winrun::pe::builder::hello("installed native executable\n");
    let zip = archive(&exe);
    let sum = match checksum {
        Some("valid") => Some(winrun::install::sha256_hex(&zip)),
        Some(s) => Some(s.to_string()),
        None => None,
    };
    let mut routes = HashMap::from([
        (
            "/latest".into(),
            (302, Vec::new(), "Location: /tag/v1.2.3\r\n".into()),
        ),
        (
            "/tag/v1.2.3".into(),
            (200, b"release".to_vec(), String::new()),
        ),
        (
            "/download/v1.2.3/tsr-windows-x86-64.zip".into(),
            (200, zip, String::new()),
        ),
    ]);
    if let Some(sum) = sum {
        routes.insert(
            "/checksums.txt".into(),
            (
                200,
                format!("{sum}  tsr-windows-x86-64.zip\n").into_bytes(),
                String::new(),
            ),
        );
    }
    // A second server serves the script using the release server's origin.
    let release = Server::new(routes);
    let script = installer(&release.url);
    let source = Server::new(HashMap::from([(
        "/install.ps1".into(),
        (200, script.into_bytes(), String::new()),
    )]));
    shell(&format!("irm {}/install.ps1 | iex\nTest-Path $tmp\nTest-Path (Join-Path $BinDir 'tsr.exe')\npowershell -c \"[Environment]::GetEnvironmentVariable('Path', 'User')\"\nC:\\Users\\runner\\.tsr\\bin\\tsr.exe\nexit\n", source.url))
}

#[test]
fn remote_installer_downloads_verifies_and_runs_native_executable() {
    let (out, err) = install_fixture(Some("valid"));
    assert!(err.is_empty(), "{err}");
    assert!(
        out.contains("Installing v1.2.3\nchecksum verified\nFalse\nTrue\n"),
        "{out}"
    );
    assert!(out.contains(r"C:\Users\runner\.tsr\bin;"), "{out}");
    assert!(out.ends_with("installed native executable\n"), "{out}");
}

#[test]
fn remote_installer_allows_missing_optional_checksums() {
    let (out, err) = install_fixture(None);
    assert!(err.is_empty(), "{err}");
    assert!(
        out.contains("no checksums available\nFalse\nTrue\n"),
        "{out}"
    );
    assert!(out.ends_with("installed native executable\n"), "{out}");
}

#[test]
fn remote_installer_reports_checksum_failure_and_cleans_temp_files() {
    let (out, err) = install_fixture(Some("bad"));
    assert!(
        err.contains("script error: checksum verification failed"),
        "{err}"
    );
    assert!(!err.contains("nothing to run: irm"), "{err}");
    assert!(out.contains("Installing v1.2.3\nFalse\nFalse\n"), "{out}");
    assert!(!out.contains("installed native executable"));
}

#[test]
fn webrequest_follows_redirects_preserves_bytes_and_reports_http_errors() {
    let bytes = b"binary\0body\n200\ntrailing\n".to_vec();
    let server = Server::new(HashMap::from([
        (
            "/redirect".into(),
            (302, Vec::new(), "Location: /final\r\n".into()),
        ),
        ("/final".into(), (200, bytes.clone(), String::new())),
    ]));
    let response = winrun::install::fetch_response(&format!("{}/redirect", server.url), 5).unwrap();
    assert_eq!(response.body, bytes);
    assert_eq!(response.status, 200);
    assert_eq!(response.url, format!("{}/final", server.url));
    assert!(
        winrun::install::fetch_url(&format!("{}/missing", server.url), 5)
            .unwrap_err()
            .contains("404")
    );
    let (out, err) = shell(&format!("$r = iwr {}/redirect -UseBasicParsing\n$r.StatusCode\n$r.BaseResponse.RequestMessage.RequestUri.AbsoluteUri\n$status = (IWR {}/final).StatusCode\n$status\n$r.baseresponse.responseuri.absoluteuri\nirm {}/missing | iex\nunknown-test-command\nexit\n", server.url, server.url, server.url));
    assert_eq!(
        out,
        format!("200\n{}/final\n200\n{}/final\n", server.url, server.url)
    );
    assert!(err.contains("script error:"), "{err}");
    assert!(err.contains("404"), "{err}");
    assert!(
        err.contains("nothing to run: unknown-test-command"),
        "{err}"
    );
    assert!(!err.contains("nothing to run: irm"), "{err}");
}

/// A stored archive holding `name` and its directory, with a central
/// directory like release archives have.
fn named_archive(name: &str, data: &[u8]) -> Vec<u8> {
    let mut zip = Vec::new();
    let mut central = Vec::new();
    let directory = format!("{}/", name.rsplit_once('/').unwrap().0);
    for (entry, body) in [(directory.as_str(), &[][..]), (name, data)] {
        let offset = zip.len() as u32;
        let header = |zip: &mut Vec<u8>, signature: &[u8], central: bool| {
            zip.extend_from_slice(signature);
            if central {
                zip.extend_from_slice(&20u16.to_le_bytes());
            }
            zip.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            zip.extend_from_slice(&(body.len() as u32).to_le_bytes());
            zip.extend_from_slice(&(body.len() as u32).to_le_bytes());
            zip.extend_from_slice(&(entry.len() as u16).to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
        };
        header(&mut zip, b"PK\x03\x04", false);
        zip.extend_from_slice(entry.as_bytes());
        zip.extend_from_slice(body);
        header(&mut central, b"PK\x01\x02", true);
        // Comment length, disk, internal and external attributes.
        central.extend_from_slice(&[0; 10]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(entry.as_bytes());
    }
    let start = zip.len() as u32;
    zip.extend_from_slice(&central);
    zip.extend_from_slice(b"PK\x05\x06\0\0\0\0\x02\0\x02\0");
    zip.extend_from_slice(&(central.len() as u32).to_le_bytes());
    zip.extend_from_slice(&start.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

#[test]
#[ignore = "requires WINRUN_CURL_EXE (official Windows curl); run explicitly with --ignored"]
fn bun_official_installer_installs_registers_and_updates_the_user_path() {
    // The installer downloads with `curl.exe`, which Windows ships in
    // System32; the official Windows build runs natively here.
    let curl = std::fs::canonicalize(
        std::env::var_os("WINRUN_CURL_EXE").expect("configure WINRUN_CURL_EXE"),
    )
    .unwrap();
    // A stand-in bun.exe: it prints its command line and exits 0.
    let stub = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_argv.exe"
    ))
    .unwrap();
    let mut routes = HashMap::new();
    for target in ["bun-windows-x64", "bun-windows-x64-baseline"] {
        routes.insert(
            format!("/latest/download/{target}.zip"),
            (200, named_archive(&format!("{target}/bun.exe"), &stub), String::new()),
        );
    }
    let release = Server::new(routes);
    let script = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/bun-install.ps1"
    ))
    .unwrap()
    .replace("https://github.com/oven-sh/bun/releases", &release.url);
    let source = Server::new(HashMap::from([(
        "/install.ps1".into(),
        (200, script.into_bytes(), String::new()),
    )]));
    let (out, err) = shell(&format!(
        "@seed \"{}\" C:\\Windows\\System32\\curl.exe\n\
         powershell -c \"irm {}/install.ps1|iex\"\n\
         reg query HKCU\\Environment /v Path\n\
         reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Bun /v InstallLocation\n\
         bun --version\n\
         exit\n",
        curl.display(),
        source.url
    ));
    assert!(out.contains("was installed successfully!"), "{out}\n{err}");
    assert!(
        out.contains(r"The binary is located at C:\Users\runner\.bun\bin\bun.exe"),
        "{out}"
    );
    assert!(
        out.contains("To get started, restart your terminal/editor, then type \"bun\""),
        "{out}"
    );
    assert!(out.contains(r";C:\Users\runner\.bun\bin"), "{out}");
    assert!(out.contains(r"InstallLocation    REG_SZ    C:\Users\runner\.bun"), "{out}");
    assert!(out.trim_end().ends_with("--version"), "{out}");
    assert!(!err.contains("script error"), "{err}");
}
