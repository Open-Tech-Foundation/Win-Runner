//! `C:\Windows\System32\curl.exe`, which Windows ships and installer
//! scripts call (`curl.exe -#SfLo file url`). The guest file is a link the
//! shell recognizes; the transfer runs through the host's curl.
//!
//! Only the options of a plain HTTP(S) download are accepted, and only
//! `http`/`https` URLs (redirects included), so a guest cannot reach host
//! files through `file://`, `-K` config files, or `@file` arguments.
//! Output files are written into the guest disk.
use crate::winfs::WinFs;
use std::process::{Command, Stdio};

pub const CURL_SHELL_LINK: &[u8] = b"WINRUN_CURL_SHELL_LINK/v1\n";

/// curl's exit code for options it does not know or cannot use here.
const BAD_OPTION: i32 = 2;
/// curl's exit code for an unwritable output file.
const WRITE_ERROR: i32 = 23;

pub fn curl_exe_path() -> String {
    format!(r"{}\curl.exe", crate::system_profile::SYSTEM32)
}

pub fn is_curl_shell_link(fs: &WinFs, path: &str) -> bool {
    fs.read_file(path)
        .is_ok_and(|contents| contents == CURL_SHELL_LINK)
}

/// Seed `System32\curl.exe` unless the disk already has a file there.
pub fn seed_curl_exe(fs: &mut WinFs) {
    let path = curl_exe_path();
    if fs.is_file(&path) || fs.mkdir(crate::system_profile::SYSTEM32).is_err() {
        return;
    }
    let _ = fs.write_file(&path, CURL_SHELL_LINK.to_vec());
}

/// A finished curl run: exit code and standard output. Progress and
/// errors go to the console's standard error, as curl writes them.
pub struct CurlRun {
    pub code: i32,
    pub stdout: Vec<u8>,
}

#[derive(Debug, Default, PartialEq)]
struct Request {
    url: Option<String>,
    /// Guest output file (`-o`), or the URL's last segment (`-O`).
    output: Option<String>,
    remote_name: bool,
    create_dirs: bool,
    /// Host curl options carried over unchanged.
    passthrough: Vec<String>,
    version: bool,
}

/// Options without a value that pass straight to host curl.
const SWITCHES: &[(&str, char)] = &[
    ("--silent", 's'),
    ("--show-error", 'S'),
    ("--fail", 'f'),
    ("--location", 'L'),
    ("--progress-bar", '#'),
    ("--head", 'I'),
    ("--include", 'i'),
    ("--insecure", 'k'),
    ("--verbose", 'v'),
];
const LONG_SWITCHES: &[&str] = &[
    "--fail-with-body",
    "--compressed",
    "--http1.1",
    "--http2",
    "--tlsv1.2",
    "--no-progress-meter",
];
/// Options taking a value that pass to host curl (the value must not be
/// an `@file` reference).
const VALUED: &[(&str, Option<char>)] = &[
    ("--user-agent", Some('A')),
    ("--header", Some('H')),
    ("--max-time", Some('m')),
    ("--referer", Some('e')),
    ("--connect-timeout", None),
    ("--retry", None),
    ("--retry-delay", None),
    ("--retry-max-time", None),
];

fn unknown(option: &str) -> String {
    format!("curl: option {option}: is unknown or not supported by this curl.exe")
}

fn parse(args: &[String]) -> Result<Request, String> {
    let mut request = Request::default();
    let mut i = 0;
    let take_value = |i: &mut usize, inline: Option<String>, option: &str| {
        if let Some(v) = inline.filter(|v| !v.is_empty()) {
            return Ok(v);
        }
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("curl: option {option}: requires parameter"))
    };
    while i < args.len() {
        let arg = &args[i];
        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (format!("--{n}"), Some(v.to_string())),
                None => (arg.clone(), None),
            };
            match name.as_str() {
                "--output" => request.output = Some(take_value(&mut i, inline, &name)?),
                "--url" => request.url = Some(take_value(&mut i, inline, &name)?),
                "--remote-name" => request.remote_name = true,
                "--create-dirs" => request.create_dirs = true,
                "--version" => request.version = true,
                // Windows' build checks revocation through Schannel; there
                // is nothing to turn off here.
                "--ssl-no-revoke" => {}
                n if SWITCHES.iter().any(|(l, _)| *l == n) || LONG_SWITCHES.contains(&n) => {
                    request.passthrough.push(name.clone())
                }
                n if VALUED.iter().any(|(l, _)| *l == n) => {
                    let value = take_value(&mut i, inline, &name)?;
                    if value.starts_with('@') {
                        return Err(unknown(&format!("{name} @file")));
                    }
                    request.passthrough.push(name.clone());
                    request.passthrough.push(value);
                }
                _ => return Err(unknown(&name)),
            }
        } else if arg.len() > 1 && arg.starts_with('-') {
            let flags: Vec<char> = arg[1..].chars().collect();
            let mut k = 0;
            while k < flags.len() {
                let flag = flags[k];
                k += 1;
                let rest: String = flags[k..].iter().collect();
                let inline = (!rest.is_empty()).then_some(rest);
                match flag {
                    'o' => {
                        request.output = Some(take_value(&mut i, inline, "-o")?);
                        break;
                    }
                    'O' => request.remote_name = true,
                    'V' => request.version = true,
                    f if SWITCHES.iter().any(|(_, s)| *s == f) => {
                        request.passthrough.push(format!("-{f}"))
                    }
                    f if VALUED.iter().any(|(_, s)| *s == Some(f)) => {
                        let option = format!("-{f}");
                        let value = take_value(&mut i, inline, &option)?;
                        if value.starts_with('@') {
                            return Err(unknown(&format!("{option} @file")));
                        }
                        request.passthrough.push(option);
                        request.passthrough.push(value);
                        break;
                    }
                    f => return Err(unknown(&format!("-{f}"))),
                }
            }
        } else if request.url.is_none() {
            request.url = Some(arg.clone());
        } else {
            return Err("curl: only one URL per call is supported by this curl.exe".into());
        }
        i += 1;
    }
    Ok(request)
}

/// The file name `-O` saves to: the URL path's last segment.
fn remote_name(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next()?;
    let after_scheme = path.split_once("://").map_or(path, |(_, rest)| rest);
    let (_, segments) = after_scheme.split_once('/')?;
    segments
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn fail(code: i32, message: &str) -> CurlRun {
    eprintln!("{message}");
    CurlRun {
        code,
        stdout: Vec::new(),
    }
}

/// Run `curl.exe` with guest arguments.
pub fn run(fs: &mut WinFs, args: &[String]) -> CurlRun {
    let request = match parse(args) {
        Ok(request) => request,
        Err(message) => return fail(BAD_OPTION, &message),
    };
    if request.version {
        return CurlRun {
            code: 0,
            stdout: b"curl (Windows) via winrun\nProtocols: http https\n".to_vec(),
        };
    }
    let Some(url) = request.url.clone() else {
        return fail(BAD_OPTION, "curl: no URL specified");
    };
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return fail(1, &format!("curl: (1) Protocol not supported: {url}"));
    }
    let output = match (&request.output, request.remote_name) {
        (Some(path), _) => Some(path.clone()),
        (None, true) => match remote_name(&url) {
            Some(name) => Some(name),
            None => return fail(WRITE_ERROR, "curl: (23) Remote file name has no length"),
        },
        (None, false) => None,
    };
    if let Some(path) = &output {
        let parent = path.rsplit_once(['\\', '/']).map(|(p, _)| p);
        if let Some(parent) = parent.filter(|p| !p.is_empty() && !p.ends_with(':')) {
            if request.create_dirs {
                if let Err(e) = fs.mkdir(parent) {
                    return fail(WRITE_ERROR, &format!("curl: (23) cannot create {parent}: {e}"));
                }
            } else if !fs.is_dir(parent) {
                return fail(
                    WRITE_ERROR,
                    &format!("curl: (23) Failure writing output to destination: {path}"),
                );
            }
        }
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let temp = std::env::temp_dir().join(format!(
        "winrun-curl-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut command = Command::new("curl");
    command
        .args(["--proto", "=http,https", "--proto-redir", "=http,https"])
        .args(&request.passthrough)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped());
    if output.is_some() {
        command.arg("--output").arg(&temp);
    }
    command.arg("--url").arg(&url);
    let result = match command.output() {
        Ok(result) => result,
        Err(e) => return fail(127, &format!("curl.exe: cannot start the host curl: {e}")),
    };
    let code = result.status.code().unwrap_or(1);
    if let Some(path) = &output {
        let data = std::fs::read(&temp);
        let _ = std::fs::remove_file(&temp);
        if let Ok(data) = data {
            if let Err(e) = fs.write_file(path, data) {
                return fail(WRITE_ERROR, &format!("curl: (23) Failure writing output to {path}: {e}"));
            }
        }
    }
    CurlRun {
        code,
        stdout: result.stdout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn combined_short_flags_and_outputs_parse() {
        let request = parse(&strings(&["-#SfLo", r"C:\x.zip", "https://e.test/a.zip"])).unwrap();
        assert_eq!(request.output.as_deref(), Some(r"C:\x.zip"));
        assert_eq!(request.url.as_deref(), Some("https://e.test/a.zip"));
        assert_eq!(request.passthrough, strings(&["-#", "-S", "-f", "-L"]));
        let request = parse(&strings(&["-fsSL", "-H", "Accept: x", "--output=o", "--url", "http://e"])).unwrap();
        assert_eq!(request.passthrough, strings(&["-f", "-s", "-S", "-L", "-H", "Accept: x"]));
        assert_eq!(request.output.as_deref(), Some("o"));
        let request = parse(&strings(&["-Ao/1", "-O", "http://e/f"])).unwrap();
        assert_eq!(request.passthrough, strings(&["-A", "o/1"]));
        assert!(request.remote_name);
    }

    #[test]
    fn host_reaching_options_are_refused() {
        for args in [
            vec!["-K", "cfg", "https://e"],
            vec!["-d", "@/etc/passwd", "https://e"],
            vec!["--config", "x"],
            vec!["-H", "@/etc/hosts", "https://e"],
            vec!["--upload-file", "x", "https://e"],
            vec!["-o"],
        ] {
            assert!(parse(&strings(&args)).is_err(), "{args:?}");
        }
        let mut fs = WinFs::ephemeral_runner();
        let run = run(&mut fs, &strings(&["-s", "file:///etc/passwd"]));
        assert_eq!(run.code, 1);
        assert!(run.stdout.is_empty());
    }

    #[test]
    fn missing_output_directories_fail_before_downloading() {
        let mut fs = WinFs::ephemeral_runner();
        let run = run(&mut fs, &strings(&["-o", r"C:\no\such\f", "https://e.invalid/"]));
        assert_eq!(run.code, WRITE_ERROR);
        assert_eq!(remote_name("https://h/a/b.zip?x=1"), Some("b.zip".to_string()));
        assert_eq!(remote_name("https://h/"), None);
        assert_eq!(remote_name("https://h"), None);
    }

    #[test]
    fn seeded_link_is_recognized() {
        let mut fs = WinFs::ephemeral_runner();
        seed_curl_exe(&mut fs);
        assert!(is_curl_shell_link(&fs, &curl_exe_path()));
        assert!(!is_curl_shell_link(&fs, r"C:\Windows\System32\cmd.exe"));
    }
}
