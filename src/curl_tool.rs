//! `curl.exe`, which Windows ships in System32: curl's command line over
//! [`crate::http_client`]. The process it runs in supplies standard
//! streams, files, and the trusted roots through [`CurlHost`]; on a guest
//! those are the process's own handles, the guest filesystem, and the
//! guest's ROOT certificate store.

use crate::http_client::{self, HttpError, Request, ResponseHead, Url};
use std::time::{Duration, Instant};

/// The curl release whose command line this follows.
pub const VERSION: &str = "8.13.0";

/// Where Windows keeps curl.exe.
pub fn curl_exe_path() -> String {
    format!(r"{}\curl.exe", crate::system_profile::SYSTEM32)
}

/// Put `curl.exe` in System32 unless the disk already has one.
pub fn seed_curl_exe(fs: &mut crate::winfs::WinFs) {
    let path = curl_exe_path();
    if fs.is_file(&path) || fs.mkdir(crate::system_profile::SYSTEM32).is_err() {
        return;
    }
    let _ = fs.write_file(&path, crate::cmd::stub_image("WinrunCurlMain"));
}

/// What a curl process needs from its surroundings.
pub trait CurlHost {
    fn stdout(&mut self, bytes: &[u8]) -> Result<(), String>;
    fn stderr(&mut self, bytes: &[u8]);
    /// Create or truncate a file (creating its folders when asked) and
    /// return an id for [`CurlHost::write`].
    fn create(&mut self, path: &str, create_dirs: bool) -> Result<u64, String>;
    fn write(&mut self, file: u64, bytes: &[u8]) -> Result<(), String>;
    fn close(&mut self, file: u64);
    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, String>;
    fn read_stdin(&mut self) -> Result<Vec<u8>, String>;
    /// DER encodings of the certificates servers are verified against.
    fn roots(&mut self) -> Vec<Vec<u8>>;
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Where `-o`/`-O` sends a URL's body.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Output {
    File(String),
    /// `-O`: named after the URL's last path segment.
    RemoteName,
}

#[derive(Debug, Default)]
struct Options {
    urls: Vec<String>,
    outputs: Vec<Output>,
    remote_name_all: bool,
    method: Option<String>,
    headers: Vec<(String, String)>,
    /// `-d` and friends, joined with `&`.
    data: Vec<Vec<u8>>,
    /// `--data-binary`/`--json` bodies keep their bytes; `-d` defaults the
    /// content type to a form.
    form_data: bool,
    json: bool,
    get: bool,
    upload: Option<String>,
    head: bool,
    include: bool,
    location: bool,
    max_redirs: Option<u32>,
    silent: bool,
    show_error: bool,
    fail: bool,
    fail_with_body: bool,
    insecure: bool,
    compressed: bool,
    verbose: bool,
    write_out: Option<String>,
    max_time: Option<Duration>,
    connect_timeout: Option<Duration>,
    user: Option<String>,
    user_agent: Option<String>,
    referer: Option<String>,
    dump_header: Option<String>,
    retry: u32,
    retry_delay: Option<Duration>,
    create_dirs: bool,
    output_dir: Option<String>,
}

/// A command line curl refuses before transferring anything.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// Print to stdout and exit 0 (`--help`, `--version`).
    Print(String),
    /// A usage error: message lines and exit 2.
    Usage(String),
    /// Another error with its curl code.
    Failed(i32, String),
}

const TRY_HELP: &str = "curl: try 'curl --help' for more information\n";

/// Options taking a value, by long name and short letter.
const WITH_VALUE: &[(&str, Option<char>)] = &[
    ("output", Some('o')),
    ("request", Some('X')),
    ("header", Some('H')),
    ("data", Some('d')),
    ("data-ascii", None),
    ("data-raw", None),
    ("data-binary", None),
    ("data-urlencode", None),
    ("json", None),
    ("user-agent", Some('A')),
    ("referer", Some('e')),
    ("max-time", Some('m')),
    ("connect-timeout", None),
    ("user", Some('u')),
    ("write-out", Some('w')),
    ("dump-header", Some('D')),
    ("upload-file", Some('T')),
    ("max-redirs", None),
    ("retry", None),
    ("retry-delay", None),
    ("retry-max-time", None),
    ("output-dir", None),
    ("url", None),
    ("proto", None),
    ("proto-redir", None),
    ("proto-default", None),
    ("limit-rate", None),
    ("keepalive-time", None),
    ("expect100-timeout", None),
    ("cookie", Some('b')),
    ("cookie-jar", Some('c')),
    ("form", Some('F')),
    ("proxy", Some('x')),
    ("config", Some('K')),
    ("continue-at", Some('C')),
    ("range", Some('r')),
];

/// Value options this curl.exe does not implement.
const UNSUPPORTED: &[&str] = &["cookie", "cookie-jar", "form", "proxy", "config", "continue-at", "range"];

/// Switches, by long name and short letter.
const SWITCHES: &[(&str, Option<char>)] = &[
    ("silent", Some('s')),
    ("show-error", Some('S')),
    ("location", Some('L')),
    ("location-trusted", None),
    ("fail", Some('f')),
    ("fail-with-body", None),
    ("fail-early", None),
    ("head", Some('I')),
    ("include", Some('i')),
    ("show-headers", None),
    ("insecure", Some('k')),
    ("verbose", Some('v')),
    ("remote-name", Some('O')),
    ("remote-name-all", None),
    ("get", Some('G')),
    ("progress-bar", Some('#')),
    ("no-progress-meter", None),
    ("version", Some('V')),
    ("help", Some('h')),
    ("no-buffer", Some('N')),
    ("compressed", None),
    ("create-dirs", None),
    ("ssl-no-revoke", None),
    ("ssl-revoke-best-effort", None),
    ("http1.1", None),
    ("tlsv1", None),
    ("tlsv1.2", None),
    ("tlsv1.3", None),
    ("globoff", Some('g')),
    ("retry-all-errors", None),
    ("retry-connrefused", None),
    ("no-keepalive", None),
    ("disable", Some('q')),
    ("path-as-is", None),
    ("styled-output", None),
    ("no-styled-output", None),
];

fn seconds(option: &str, value: &str) -> Result<Duration, Refusal> {
    value
        .parse::<f64>()
        .ok()
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .map(Duration::from_secs_f64)
        .ok_or_else(|| Refusal::Usage(format!("curl: option {option}: expected a proper numerical parameter\n{TRY_HELP}")))
}

fn count(option: &str, value: &str) -> Result<u32, Refusal> {
    value
        .parse::<i64>()
        .ok()
        // curl's -1 means "no limit" for --max-redirs.
        .map(|count| if count < 0 { u32::MAX } else { count.min(u32::MAX as i64) as u32 })
        .ok_or_else(|| Refusal::Usage(format!("curl: option {option}: expected a proper numerical parameter\n{TRY_HELP}")))
}

fn url_encode(bytes: &[u8]) -> String {
    let mut text = String::new();
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            text.push(byte as char);
        } else {
            text.push_str(&format!("%{byte:02X}"));
        }
    }
    text
}

/// A `-d`-style value: `@file` reads the file (`@-` standard input).
fn data_value(host: &mut dyn CurlHost, value: &str, strip_newlines: bool) -> Result<Vec<u8>, Refusal> {
    let Some(source) = value.strip_prefix('@') else {
        return Ok(value.as_bytes().to_vec());
    };
    let read = if source == "-" { host.read_stdin() } else { host.read_file(source) };
    match read {
        Ok(mut bytes) => {
            if strip_newlines {
                bytes.retain(|byte| *byte != b'\r' && *byte != b'\n');
            }
            Ok(bytes)
        }
        Err(_) => {
            // curl warns and sends nothing for an unreadable file.
            host.stderr(format!("Warning: Couldn't read data from file \"{source}\", this makes an empty POST.\n").as_bytes());
            Ok(Vec::new())
        }
    }
}

fn apply(host: &mut dyn CurlHost, options: &mut Options, name: &str, value: Option<&str>) -> Result<(), Refusal> {
    let shown = |name: &str| {
        WITH_VALUE
            .iter()
            .chain(SWITCHES)
            .find(|(long, _)| *long == name)
            .and_then(|(_, short)| *short)
            .map_or_else(|| format!("--{name}"), |short| format!("-{short}"))
    };
    let value = value.unwrap_or_default();
    match name {
        "output" => options.outputs.push(Output::File(value.to_string())),
        "remote-name" => options.outputs.push(Output::RemoteName),
        "remote-name-all" => options.remote_name_all = true,
        "request" => options.method = Some(value.to_string()),
        "header" => {
            if let Some((header, content)) = value.split_once(':') {
                options.headers.push((header.trim().to_string(), content.trim().to_string()));
            } else if let Some(header) = value.strip_suffix(';') {
                options.headers.push((header.trim().to_string(), String::new()));
            }
        }
        "data" | "data-ascii" => {
            let bytes = data_value(host, value, true)?;
            options.data.push(bytes);
            options.form_data = true;
        }
        "data-raw" => {
            options.data.push(value.as_bytes().to_vec());
            options.form_data = true;
        }
        "data-binary" => {
            let bytes = data_value(host, value, false)?;
            options.data.push(bytes);
            options.form_data = true;
        }
        "data-urlencode" => {
            // name=content, =content, name@file, @file, or content.
            let encoded = if let Some((key, content)) = value.split_once('=') {
                let content = url_encode(content.as_bytes());
                if key.is_empty() { content } else { format!("{key}={content}") }
            } else if let Some((key, file)) = value.split_once('@') {
                let content = url_encode(&data_value(host, &format!("@{file}"), false)?);
                if key.is_empty() { content } else { format!("{key}={content}") }
            } else {
                url_encode(value.as_bytes())
            };
            options.data.push(encoded.into_bytes());
            options.form_data = true;
        }
        "json" => {
            let bytes = data_value(host, value, false)?;
            options.data.push(bytes);
            options.json = true;
        }
        "user-agent" => options.user_agent = Some(value.to_string()),
        "referer" => options.referer = Some(value.to_string()),
        "max-time" => options.max_time = Some(seconds(&shown(name), value)?),
        "connect-timeout" => options.connect_timeout = Some(seconds(&shown(name), value)?),
        "user" => options.user = Some(value.to_string()),
        "write-out" => {
            let format = match value.strip_prefix('@') {
                Some("-") => host.read_stdin().map_err(|e| Refusal::Failed(26, e))?,
                Some(file) => host.read_file(file).map_err(|e| Refusal::Failed(26, e))?,
                None => value.as_bytes().to_vec(),
            };
            options.write_out = Some(String::from_utf8_lossy(&format).into_owned());
        }
        "dump-header" => options.dump_header = Some(value.to_string()),
        "upload-file" => options.upload = Some(value.to_string()),
        "max-redirs" => options.max_redirs = Some(count(&shown(name), value)?),
        "retry" => options.retry = count(&shown(name), value)?,
        "retry-delay" => options.retry_delay = Some(seconds(&shown(name), value)?),
        "output-dir" => options.output_dir = Some(value.to_string()),
        "url" => options.urls.push(value.to_string()),
        "silent" => options.silent = true,
        "show-error" => options.show_error = true,
        "location" | "location-trusted" => options.location = true,
        "fail" => options.fail = true,
        "fail-with-body" => options.fail_with_body = true,
        "head" => options.head = true,
        "include" | "show-headers" => options.include = true,
        "insecure" => options.insecure = true,
        "verbose" => options.verbose = true,
        "get" => options.get = true,
        "compressed" => options.compressed = true,
        "create-dirs" => options.create_dirs = true,
        "version" => {
            return Err(Refusal::Print(format!(
                "curl {VERSION} (x86_64-pc-win32) winrun\nRelease-Date: [unreleased]\nProtocols: http https\nFeatures: AsynchDNS HTTPS-proxy IPv6 Largefile libz SSL threadsafe\n"
            )))
        }
        "help" => {
            return Err(Refusal::Print(
                "Usage: curl [options...] <url>\n \
                 -d, --data <data>           HTTP POST data\n \
                 -f, --fail                  Fail fast with no output on HTTP errors\n \
                 -h, --help <category>       Get help for commands\n \
                 -i, --include               Include response headers in output\n \
                 -o, --output <file>         Write to file instead of stdout\n \
                 -O, --remote-name           Write output to file named as remote file\n \
                 -s, --silent                Silent mode\n \
                 -T, --upload-file <file>    Transfer local FILE to destination\n \
                 -u, --user <user:password>  Server user and password\n \
                 -A, --user-agent <name>     Send User-Agent <name> to server\n \
                 -v, --verbose               Make the operation more talkative\n \
                 -V, --version               Show version number and quit\n"
                    .to_string(),
            ))
        }
        // Accepted; they change nothing here.
        _ => {}
    }
    Ok(())
}

fn parse(host: &mut dyn CurlHost, arguments: &[String]) -> Result<Options, Refusal> {
    let mut options = Options::default();
    let mut index = 0;
    let missing = |option: &str| Refusal::Usage(format!("curl: option {option}: requires parameter\n{TRY_HELP}"));
    let unsupported =
        |option: &str| Refusal::Failed(2, format!("curl: option {option}: is not supported by this curl.exe\n{TRY_HELP}"));
    while index < arguments.len() {
        let argument = &arguments[index];
        index += 1;
        if let Some(long) = argument.strip_prefix("--").filter(|long| !long.is_empty()) {
            let (name, negated) = match long.strip_prefix("no-") {
                Some(name) if SWITCHES.iter().any(|(switch, _)| *switch == name) => (name, true),
                _ => (long, false),
            };
            if WITH_VALUE.iter().any(|(option, _)| *option == name) {
                if UNSUPPORTED.contains(&name) {
                    return Err(unsupported(argument));
                }
                let value = arguments.get(index).ok_or_else(|| missing(argument))?.clone();
                index += 1;
                apply(host, &mut options, name, Some(&value))?;
            } else if SWITCHES.iter().any(|(switch, _)| *switch == name) {
                if !negated {
                    apply(host, &mut options, name, None)?;
                }
            } else {
                return Err(Refusal::Usage(format!("curl: option {argument}: is unknown\n{TRY_HELP}")));
            }
        } else if argument.len() > 1 && argument.starts_with('-') {
            let letters: Vec<char> = argument[1..].chars().collect();
            let mut at = 0;
            while at < letters.len() {
                let letter = letters[at];
                at += 1;
                if let Some((name, _)) = WITH_VALUE.iter().find(|(_, short)| *short == Some(letter)) {
                    if UNSUPPORTED.contains(name) {
                        return Err(unsupported(&format!("-{letter}")));
                    }
                    let value = if at < letters.len() {
                        letters[at..].iter().collect::<String>()
                    } else {
                        index += 1;
                        arguments.get(index - 1).ok_or_else(|| missing(&format!("-{letter}")))?.clone()
                    };
                    apply(host, &mut options, name, Some(&value))?;
                    break;
                } else if let Some((name, _)) = SWITCHES.iter().find(|(_, short)| *short == Some(letter)) {
                    apply(host, &mut options, name, None)?;
                } else {
                    return Err(Refusal::Usage(format!("curl: option -{letter}: is unknown\n{TRY_HELP}")));
                }
            }
        } else {
            options.urls.push(argument.clone());
        }
    }
    if options.urls.is_empty() {
        return Err(Refusal::Usage(format!(
            "curl: no URL specified\ncurl: try 'curl --help' or 'curl --manual' for more information\n"
        )));
    }
    Ok(options)
}

/// Where a body or header dump is being written.
enum Destination {
    Stdout,
    File(u64),
}

/// Reports one transfer to the host.
struct CurlSink<'a> {
    host: &'a mut dyn CurlHost,
    options: &'a Options,
    output_path: Option<String>,
    output: Option<Destination>,
    dump: Option<Destination>,
    /// A `--fail` status that ended (or will end) the transfer.
    failed_status: Option<u16>,
    status: u16,
    redirects: u32,
    downloaded: u64,
    header_bytes: u64,
    content_type: String,
    redirect_url: String,
}

impl CurlSink<'_> {
    fn emit(&mut self, to_dump: bool, bytes: &[u8]) -> Result<(), HttpError> {
        let destination = if to_dump { &self.dump } else { &self.output };
        let result = match destination {
            Some(Destination::Stdout) | None => self.host.stdout(bytes),
            Some(Destination::File(file)) => self.host.write(*file, bytes),
        };
        result.map_err(HttpError::Write)
    }

    fn open_output(&mut self) -> Result<(), HttpError> {
        if self.output.is_some() {
            return Ok(());
        }
        self.output = Some(match &self.output_path {
            None => Destination::Stdout,
            Some(path) => Destination::File(
                self.host
                    .create(path, self.options.create_dirs)
                    .map_err(|e| HttpError::Write(format!("{path}: {e}")))?,
            ),
        });
        Ok(())
    }

    fn close(&mut self) {
        for destination in [self.output.take(), self.dump.take()].into_iter().flatten() {
            if let Destination::File(file) = destination {
                self.host.close(file);
            }
        }
    }
}

impl http_client::Sink for CurlSink<'_> {
    fn head(&mut self, head: &ResponseHead, last: bool) -> Result<(), HttpError> {
        let raw = head.raw();
        self.header_bytes += raw.len() as u64;
        self.status = head.status;
        if !last {
            self.redirects += 1;
        }
        if self.options.verbose {
            let mut text = String::new();
            for line in raw.split("\r\n").filter(|line| !line.is_empty()) {
                text.push_str(&format!("< {line}\n"));
            }
            text.push_str("<\n");
            self.host.stderr(text.as_bytes());
        }
        if last {
            self.content_type = head.header("Content-Type").unwrap_or_default().to_string();
            self.redirect_url = head
                .header("Location")
                .and_then(|location| head.url.join(location).ok())
                .map(|url| url.as_string())
                .unwrap_or_default();
            if head.status >= 400 && (self.options.fail || self.options.fail_with_body) {
                self.failed_status = Some(head.status);
                if !self.options.fail_with_body {
                    return Err(HttpError::Write("--fail".into()));
                }
            }
        }
        if self.options.dump_header.is_some() {
            if self.dump.is_none() {
                let path = self.options.dump_header.clone().unwrap_or_default();
                self.dump = Some(if path == "-" {
                    Destination::Stdout
                } else {
                    Destination::File(
                        self.host
                            .create(&path, self.options.create_dirs)
                            .map_err(|e| HttpError::Write(format!("{path}: {e}")))?,
                    )
                });
            }
            self.emit(true, raw.as_bytes())?;
        }
        if self.options.include || self.options.head {
            self.open_output()?;
            self.emit(false, raw.as_bytes())?;
        }
        if last {
            self.open_output()?;
        }
        Ok(())
    }

    fn data(&mut self, data: &[u8]) -> Result<(), HttpError> {
        self.open_output()?;
        self.downloaded += data.len() as u64;
        self.emit(false, data)
    }

    fn request_sent(&mut self, head: &str) {
        if self.options.verbose {
            let mut text = String::new();
            for line in head.split("\r\n").filter(|line| !line.is_empty()) {
                text.push_str(&format!("> {line}\n"));
            }
            text.push_str(">\n");
            self.host.stderr(text.as_bytes());
        }
    }
}

/// The base64 of `user:password` for `-u`.
fn basic_credentials(user: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(user.as_bytes())
}

/// The request for one transfer.
fn request(options: &Options, url: &str) -> Result<Request, HttpError> {
    let mut url_text = url.to_string();
    let body = (!options.data.is_empty()).then(|| options.data.join(&b'&'));
    if options.get {
        if let Some(body) = &body {
            url_text.push(if url_text.contains('?') { '&' } else { '?' });
            url_text.push_str(&String::from_utf8_lossy(body));
        }
    }
    let mut request = Request::get(Url::parse(&url_text)?);
    request.user_agent = format!("curl/{VERSION}");
    request.follow_redirects = options.location;
    request.max_redirects = options.max_redirs.unwrap_or(50);
    request.timeout = options.max_time;
    request.connect_timeout = options.connect_timeout;
    request.insecure = options.insecure;
    request.compressed = options.compressed;
    if let Some(user) = &options.user {
        request.headers.push(("Authorization".into(), format!("Basic {}", basic_credentials(user))));
    }
    if let Some(referer) = &options.referer {
        request.headers.push(("Referer".into(), referer.clone()));
    }
    if let Some(agent) = &options.user_agent {
        request.headers.push(("User-Agent".into(), agent.clone()));
    }
    let mut method = "GET";
    if options.head {
        method = "HEAD";
    } else if let Some(upload) = &options.upload {
        method = "PUT";
        // A URL ending in a slash gets the file's name appended.
        if request.url.target.ends_with('/') {
            let name = upload.rsplit(['\\', '/']).next().unwrap_or(upload);
            request.url.target.push_str(name);
        }
    } else if let Some(body) = body.filter(|_| !options.get) {
        method = "POST";
        if options.json {
            request.headers.push(("Content-Type".into(), "application/json".into()));
            request.headers.push(("Accept".into(), "application/json".into()));
        } else if options.form_data {
            request.headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
        }
        request.body = Some(body);
    }
    request.method = options.method.clone().unwrap_or_else(|| method.to_string());
    request.headers.extend(options.headers.iter().cloned());
    Ok(request)
}

/// Where `-O` saves `url`.
fn remote_name(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let path = parsed.target.split('?').next().unwrap_or_default();
    let name = path.rsplit('/').next().unwrap_or_default();
    (!name.is_empty()).then(|| name.to_string())
}

/// The outcome of one transfer, for messages and `-w`.
struct Outcome {
    code: i32,
    message: String,
    status: u16,
    url_effective: String,
    redirects: u32,
    downloaded: u64,
    header_bytes: u64,
    content_type: String,
    redirect_url: String,
    method: String,
    elapsed: Duration,
}

fn write_out(host: &mut dyn CurlHost, format: &str, outcome: &Outcome) {
    let mut to_stderr = false;
    let mut text = String::new();
    let flush = |host: &mut dyn CurlHost, text: &mut String, to_stderr: bool| {
        if to_stderr {
            host.stderr(text.as_bytes());
        } else {
            let _ = host.stdout(text.as_bytes());
        }
        text.clear();
    };
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '%' if chars.peek() == Some(&'%') => {
                chars.next();
                text.push('%');
            }
            '%' if chars.peek() == Some(&'{') => {
                chars.next();
                let name: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let value = match name.as_str() {
                    "http_code" | "response_code" => format!("{:03}", outcome.status),
                    "url_effective" => outcome.url_effective.clone(),
                    "size_download" => outcome.downloaded.to_string(),
                    "size_header" => outcome.header_bytes.to_string(),
                    "content_type" => outcome.content_type.clone(),
                    "num_redirects" => outcome.redirects.to_string(),
                    "redirect_url" => outcome.redirect_url.clone(),
                    "exitcode" => outcome.code.to_string(),
                    "errormsg" => outcome.message.clone(),
                    "method" => outcome.method.clone(),
                    "time_total" => format!("{:.6}", outcome.elapsed.as_secs_f64()),
                    "stdout" | "stderr" => {
                        flush(host, &mut text, to_stderr);
                        to_stderr = name == "stderr";
                        String::new()
                    }
                    other => {
                        host.stderr(format!("curl: unknown --write-out variable: '{other}'\n").as_bytes());
                        String::new()
                    }
                };
                text.push_str(&value);
            }
            '\\' => match chars.next() {
                Some('n') => text.push('\n'),
                Some('r') => text.push('\r'),
                Some('t') => text.push('\t'),
                Some(other) => {
                    text.push('\\');
                    text.push(other);
                }
                None => text.push('\\'),
            },
            other => text.push(other),
        }
    }
    flush(host, &mut text, to_stderr);
}

fn transfer(host: &mut dyn CurlHost, options: &Options, url: &str, output_path: Option<String>) -> Outcome {
    let started = Instant::now();
    let mut outcome = Outcome {
        code: 0,
        message: String::new(),
        status: 0,
        url_effective: url.to_string(),
        redirects: 0,
        downloaded: 0,
        header_bytes: 0,
        content_type: String::new(),
        redirect_url: String::new(),
        method: String::new(),
        elapsed: Duration::ZERO,
    };
    let mut request = match request(options, url) {
        Ok(request) => request,
        Err(error) => {
            outcome.code = error.curl_code();
            outcome.message = error.message();
            return outcome;
        }
    };
    if let Some(upload) = &options.upload {
        match host.read_file(upload) {
            Ok(bytes) => request.body = Some(bytes),
            Err(_) => {
                outcome.code = 26;
                outcome.message = format!("Failed to open/read local data from file/application");
                return outcome;
            }
        }
    }
    outcome.method = request.method.clone();
    outcome.url_effective = request.url.as_string();
    let roots = if request.url.https && !options.insecure { host.roots() } else { Vec::new() };
    let mut sink = CurlSink {
        host: &mut *host,
        options,
        output_path,
        output: None,
        dump: None,
        failed_status: None,
        status: 0,
        redirects: 0,
        downloaded: 0,
        header_bytes: 0,
        content_type: String::new(),
        redirect_url: String::new(),
    };
    let result = http_client::fetch(&request, &roots, &mut sink);
    sink.close();
    outcome.status = sink.status;
    outcome.redirects = sink.redirects;
    outcome.downloaded = sink.downloaded;
    outcome.header_bytes = sink.header_bytes;
    outcome.content_type = std::mem::take(&mut sink.content_type);
    outcome.redirect_url = std::mem::take(&mut sink.redirect_url);
    let failed_status = sink.failed_status;
    match (result, failed_status) {
        (_, Some(status)) => {
            outcome.code = 22;
            outcome.message = format!("The requested URL returned error: {status}");
        }
        (Ok(head), None) => outcome.url_effective = head.url.as_string(),
        (Err(error), None) => {
            outcome.code = error.curl_code();
            outcome.message = error.message();
        }
    }
    outcome.elapsed = started.elapsed();
    outcome
}

/// Whether `--retry` tries again: timeouts and transient HTTP statuses.
fn transient(outcome: &Outcome) -> bool {
    outcome.code == 28 || matches!(outcome.status, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Run curl with `arguments` (without the program name); returns the exit
/// code.
pub fn run(host: &mut dyn CurlHost, arguments: &[String]) -> i32 {
    let options = match parse(host, arguments) {
        Ok(options) => options,
        Err(Refusal::Print(text)) => {
            let _ = host.stdout(text.as_bytes());
            return 0;
        }
        Err(Refusal::Usage(text)) => {
            host.stderr(text.as_bytes());
            return 2;
        }
        Err(Refusal::Failed(code, text)) => {
            host.stderr(text.as_bytes());
            return code;
        }
    };
    let mut exit = 0;
    for (index, url) in options.urls.iter().enumerate() {
        let output = options
            .outputs
            .get(index)
            .cloned()
            .or_else(|| options.remote_name_all.then_some(Output::RemoteName));
        let output_path = match output {
            None => None,
            Some(Output::File(path)) => Some(path),
            Some(Output::RemoteName) => match remote_name(url) {
                Some(name) => Some(name),
                None => {
                    if !options.silent || options.show_error {
                        host.stderr(b"curl: (23) Remote file name has no length\n");
                    }
                    exit = 23;
                    continue;
                }
            },
        };
        let output_path = output_path.map(|path| match &options.output_dir {
            Some(directory) if !path.contains(':') && !path.starts_with(['\\', '/']) => {
                format!("{}\\{path}", directory.trim_end_matches(['\\', '/']))
            }
            _ => path,
        });
        let mut attempts_left = options.retry;
        let mut delay = options.retry_delay.unwrap_or(Duration::from_secs(1));
        let outcome = loop {
            let outcome = transfer(host, &options, url, output_path.clone());
            if attempts_left == 0 || !transient(&outcome) {
                break outcome;
            }
            if !options.silent {
                let problem = if outcome.code == 28 { "timeout".to_string() } else { format!("HTTP error") };
                host.stderr(
                    format!(
                        "Warning: Problem : {problem}. Will retry in {} second{}. {attempts_left} retr{} left.\n",
                        delay.as_secs(),
                        if delay.as_secs() == 1 { "" } else { "s" },
                        if attempts_left == 1 { "y" } else { "ies" }
                    )
                    .as_bytes(),
                );
            }
            host.sleep(delay);
            attempts_left -= 1;
            if options.retry_delay.is_none() {
                delay = (delay * 2).min(Duration::from_secs(600));
            }
        };
        if outcome.code != 0 {
            exit = outcome.code;
            if !options.silent || options.show_error {
                host.stderr(format!("curl: ({}) {}\n", outcome.code, outcome.message).as_bytes());
            }
        }
        if let Some(format) = &options.write_out {
            write_out(host, format, &outcome);
        }
    }
    exit
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[derive(Default)]
    struct FakeHost {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        files: HashMap<String, Vec<u8>>,
        open: HashMap<u64, String>,
        next: u64,
        stdin: Vec<u8>,
        slept: Vec<Duration>,
    }

    impl CurlHost for FakeHost {
        fn stdout(&mut self, bytes: &[u8]) -> Result<(), String> {
            self.stdout.extend_from_slice(bytes);
            Ok(())
        }
        fn stderr(&mut self, bytes: &[u8]) {
            self.stderr.extend_from_slice(bytes);
        }
        fn create(&mut self, path: &str, _create_dirs: bool) -> Result<u64, String> {
            if path.starts_with("Z:") {
                return Err("The system cannot find the path specified.".into());
            }
            self.next += 1;
            self.files.insert(path.to_string(), Vec::new());
            self.open.insert(self.next, path.to_string());
            Ok(self.next)
        }
        fn write(&mut self, file: u64, bytes: &[u8]) -> Result<(), String> {
            let path = &self.open[&file];
            self.files.get_mut(path).unwrap().extend_from_slice(bytes);
            Ok(())
        }
        fn close(&mut self, file: u64) {
            self.open.remove(&file);
        }
        fn read_file(&mut self, path: &str) -> Result<Vec<u8>, String> {
            self.files.get(path).cloned().ok_or_else(|| "missing".into())
        }
        fn read_stdin(&mut self) -> Result<Vec<u8>, String> {
            Ok(std::mem::take(&mut self.stdin))
        }
        fn roots(&mut self) -> Vec<Vec<u8>> {
            Vec::new()
        }
        fn sleep(&mut self, duration: Duration) {
            self.slept.push(duration);
        }
    }

    impl FakeHost {
        fn run(&mut self, arguments: &[&str]) -> i32 {
            let arguments: Vec<String> = arguments.iter().map(|a| a.to_string()).collect();
            run(self, &arguments)
        }
        fn err(&self) -> String {
            String::from_utf8_lossy(&self.stderr).into_owned()
        }
        fn out(&self) -> String {
            String::from_utf8_lossy(&self.stdout).into_owned()
        }
    }

    /// Answer each connection with the reply for its path; the request
    /// heads and bodies are sent back over the channel.
    fn serve(routes: Vec<(&'static str, &'static str)>, connections: usize) -> (u16, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(connections) {
                let mut stream = stream.unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    request.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&request).into_owned();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; length];
                let _ = stream.read_exact(&mut body);
                let path = head.split(' ').nth(1).unwrap_or("").to_string();
                let reply = routes
                    .iter()
                    .find(|(route, _)| path == *route)
                    .map_or("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found", |(_, reply)| reply);
                let _ = stream.write_all(reply.as_bytes());
                let _ = sender.send(format!("{head}{}", String::from_utf8_lossy(&body)));
            }
        });
        (port, receiver)
    }

    const HELLO: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";

    #[test]
    fn bodies_go_to_stdout_or_files() {
        let (port, _) = serve(vec![("/file.txt", HELLO)], 3);
        let url = format!("http://127.0.0.1:{port}/file.txt");
        let mut host = FakeHost::default();
        assert_eq!(host.run(&[&url]), 0);
        assert_eq!(host.out(), "hello");
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-so", r"C:\out.txt", &url]), 0, "{}", host.err());
        assert_eq!(host.files[r"C:\out.txt"], b"hello");
        assert!(host.stdout.is_empty());
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["--output-dir", r"C:\dl\", "-O", &url]), 0, "{}", host.err());
        assert_eq!(host.files[r"C:\dl\file.txt"], b"hello");
    }

    #[test]
    fn redirects_follow_with_l_and_report_through_write_out() {
        let (port, _) = serve(
            vec![
                ("/old", "HTTP/1.1 301 Moved\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n"),
                ("/new", HELLO),
            ],
            3,
        );
        let url = format!("http://127.0.0.1:{port}/old");
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-s", "-w", "%{http_code} %{redirect_url}", &url]), 0);
        assert_eq!(host.out(), format!("301 http://127.0.0.1:{port}/new"));
        let mut host = FakeHost::default();
        assert_eq!(
            host.run(&["-sL", "-w", r"\n%{http_code} %{num_redirects} %{url_effective} %{size_download} %{content_type}", &url]),
            0
        );
        assert_eq!(host.out(), format!("hello\n200 1 http://127.0.0.1:{port}/new 5 text/plain"));
    }

    #[test]
    fn fail_suppresses_the_body_and_exits_22() {
        let (port, _) = serve(vec![], 4);
        let url = format!("http://127.0.0.1:{port}/missing");
        let mut host = FakeHost::default();
        assert_eq!(host.run(&[&url]), 0, "without -f an error status is a success");
        assert_eq!(host.out(), "not found");
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-f", &url]), 22);
        assert!(host.stdout.is_empty());
        assert_eq!(host.err(), "curl: (22) The requested URL returned error: 404\n");
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-fs", &url]), 22);
        assert!(host.stderr.is_empty(), "-s hides the message");
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["--fail-with-body", "-sS", &url]), 22);
        assert_eq!(host.out(), "not found");
        assert_eq!(host.err(), "curl: (22) The requested URL returned error: 404\n");
    }

    #[test]
    fn requests_carry_methods_headers_and_bodies() {
        let (port, requests) = serve(vec![("/api", HELLO), ("/api?a=1&b=2", HELLO), ("/up/data.bin", HELLO)], 4);
        let base = format!("http://127.0.0.1:{port}");
        let mut host = FakeHost::default();
        host.run(&["-s", "-d", "a=1", "-d", "b=2", "-H", "X-Test: yes", "-u", "user:pass", &format!("{base}/api")]);
        let sent = requests.recv().unwrap();
        assert!(sent.starts_with("POST /api HTTP/1.1\r\n"), "{sent}");
        assert!(sent.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
        assert!(sent.contains("X-Test: yes\r\n"));
        assert!(sent.contains("Authorization: Basic dXNlcjpwYXNz\r\n"));
        assert!(sent.contains(&format!("User-Agent: curl/{VERSION}\r\n")));
        assert!(sent.ends_with("\r\n\r\na=1&b=2"), "{sent}");
        host.run(&["-s", "-G", "-d", "a=1", "-d", "b=2", &format!("{base}/api")]);
        assert!(requests.recv().unwrap().starts_with("GET /api?a=1&b=2 HTTP/1.1"));
        host.files.insert(r"C:\data.bin".into(), b"\x00\x01".to_vec());
        host.run(&["-s", "-T", r"C:\data.bin", &format!("{base}/up/")]);
        let sent = requests.recv().unwrap();
        assert!(sent.starts_with("PUT /up/data.bin HTTP/1.1"), "{sent}");
        assert!(!sent.contains("Content-Type"), "{sent}");
        host.run(&["-s", "-X", "DELETE", "--json", r#"{"k":1}"#, "-A", "agent/1", &format!("{base}/api")]);
        let sent = requests.recv().unwrap();
        assert!(sent.starts_with("DELETE /api HTTP/1.1"), "{sent}");
        assert!(sent.contains("Content-Type: application/json\r\nAccept: application/json\r\n"), "{sent}");
        assert!(sent.contains("User-Agent: agent/1\r\n") && sent.ends_with(r#"{"k":1}"#));
    }

    #[test]
    fn data_from_files_and_url_encoding() {
        let (port, requests) = serve(vec![("/", HELLO)], 2);
        let url = format!("http://127.0.0.1:{port}/");
        let mut host = FakeHost::default();
        host.files.insert("form.txt".into(), b"x=1\r\ny=2\n".to_vec());
        host.run(&["-s", "-d", "@form.txt", "--data-urlencode", "q=a b&c", &url]);
        assert!(requests.recv().unwrap().ends_with("\r\n\r\nx=1y=2&q=a%20b%26c"));
        host.stdin = b"raw\n".to_vec();
        host.run(&["-s", "--data-binary", "@-", &url]);
        assert!(requests.recv().unwrap().ends_with("\r\n\r\nraw\n"));
    }

    #[test]
    fn heads_include_and_dump_headers() {
        let (port, requests) = serve(vec![("/", HELLO)], 3);
        let url = format!("http://127.0.0.1:{port}/");
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-sI", &url]), 0);
        assert!(requests.recv().unwrap().starts_with("HEAD / HTTP/1.1"));
        assert_eq!(host.out(), "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n");
        let mut host = FakeHost::default();
        host.run(&["-si", &url]);
        assert!(host.out().starts_with("HTTP/1.1 200 OK\r\n") && host.out().ends_with("\r\n\r\nhello"));
        let mut host = FakeHost::default();
        host.run(&["-s", "-D", "h.txt", "-o", "b.txt", &url]);
        assert!(String::from_utf8_lossy(&host.files["h.txt"]).starts_with("HTTP/1.1 200 OK"));
        assert_eq!(host.files["b.txt"], b"hello");
    }

    #[test]
    fn retries_transient_statuses() {
        let (port, _) = serve(vec![("/", "HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n")], 3);
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-sf", "--retry", "2", &format!("http://127.0.0.1:{port}/")]), 22);
        assert_eq!(host.slept, vec![Duration::from_secs(1), Duration::from_secs(2)]);
    }

    #[test]
    fn usage_errors_and_transport_failures() {
        let mut host = FakeHost::default();
        assert_eq!(host.run(&[]), 2);
        assert!(host.err().starts_with("curl: no URL specified"));
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["--bogus", "x"]), 2);
        assert_eq!(host.err(), format!("curl: option --bogus: is unknown\n{TRY_HELP}"));
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-o"]), 2);
        assert!(host.err().starts_with("curl: option -o: requires parameter"));
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-V"]), 0);
        assert!(host.out().starts_with(&format!("curl {VERSION} ")));
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["ftp://example.com/"]), 1);
        assert_eq!(host.err(), "curl: (1) Protocol \"ftp\" not supported\n");
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-s", "-w", "%{http_code}", &format!("http://127.0.0.1:{closed}/")]), 7);
        assert_eq!(host.out(), "000");
        assert!(host.stderr.is_empty());
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-O", "http://127.0.0.1:1/"]), 23);
        let (port, _) = serve(vec![("/", HELLO)], 1);
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-o", r"Z:\nowhere\x", &format!("http://127.0.0.1:{port}/")]), 23);
    }
}
