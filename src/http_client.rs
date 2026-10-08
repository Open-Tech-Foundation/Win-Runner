//! A small HTTP/1.1 client for the guest's built-in network tools
//! (`curl.exe`): plain and TLS connections, redirects, chunked and
//! length-delimited bodies, gzip/deflate decoding, and timeouts. TLS
//! verifies servers against the roots the caller passes — the guest's own
//! ROOT store — never the host's.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Why a transfer failed, in curl's terms (see [`HttpError::curl_code`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// A URL that cannot be parsed (curl 3).
    Url(String),
    /// A scheme other than http/https (curl 1).
    Protocol(String),
    /// The host name does not resolve (curl 6).
    Resolve(String),
    /// No connection could be made (curl 7).
    Connect(String),
    /// The overall or connect time limit passed (curl 28).
    Timeout,
    /// The TLS handshake failed (curl 35).
    Tls(String),
    /// The server's certificate was not trusted (curl 60).
    Certificate(String),
    /// More redirects than allowed (curl 47).
    TooManyRedirects(u32),
    /// The server's reply is not HTTP (curl 8).
    BadReply(String),
    /// Receiving failed mid-transfer (curl 56).
    Receive(String),
    /// Sending failed (curl 55).
    Send(String),
    /// The caller's sink refused the data (curl 23).
    Write(String),
}

impl HttpError {
    pub fn curl_code(&self) -> i32 {
        match self {
            HttpError::Url(_) => 3,
            HttpError::Protocol(_) => 1,
            HttpError::Resolve(_) => 6,
            HttpError::Connect(_) => 7,
            HttpError::Timeout => 28,
            HttpError::Tls(_) => 35,
            HttpError::Certificate(_) => 60,
            HttpError::TooManyRedirects(_) => 47,
            HttpError::BadReply(_) => 8,
            HttpError::Receive(_) => 56,
            HttpError::Send(_) => 55,
            HttpError::Write(_) => 23,
        }
    }

    /// curl's message for the error.
    pub fn message(&self) -> String {
        match self {
            HttpError::Url(url) => format!("URL rejected: Malformed input to a URL function ({url})"),
            HttpError::Protocol(scheme) => {
                format!("Protocol \"{scheme}\" not supported")
            }
            HttpError::Resolve(host) => format!("Could not resolve host: {host}"),
            HttpError::Connect(detail) => format!("Failed to connect to {detail}"),
            HttpError::Timeout => "Operation timed out".to_string(),
            HttpError::Tls(detail) => format!("TLS connect error: {detail}"),
            HttpError::Certificate(detail) => {
                format!("SSL certificate problem: {detail}")
            }
            HttpError::TooManyRedirects(count) => {
                format!("Maximum ({count}) redirects followed")
            }
            HttpError::BadReply(detail) => format!("Weird server reply: {detail}"),
            HttpError::Receive(detail) => format!("Failure when receiving data from the peer: {detail}"),
            HttpError::Send(detail) => format!("Failed sending data to the peer: {detail}"),
            HttpError::Write(detail) => format!("Failure writing output to destination: {detail}"),
        }
    }
}

/// A parsed http(s) URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub target: String,
}

impl Url {
    pub fn parse(text: &str) -> Result<Url, HttpError> {
        let text = text.trim();
        let (scheme, rest) = match text.split_once("://") {
            Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
            // curl assumes http:// without a scheme.
            None => ("http".to_string(), text),
        };
        let https = match scheme.as_str() {
            "http" => false,
            "https" => true,
            other => return Err(HttpError::Protocol(other.to_string())),
        };
        let rest = rest.split('#').next().unwrap_or("");
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, target) = rest.split_at(split);
        let target = if target.is_empty() {
            "/".to_string()
        } else if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_string()
        };
        if authority.contains('@') {
            return Err(HttpError::Url(text.to_string()));
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, after) = bracketed
                .split_once(']')
                .ok_or_else(|| HttpError::Url(text.to_string()))?;
            (host.to_string(), after.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host.to_string(), Some(port)),
                None => (authority.to_string(), None),
            }
        };
        let port = match port {
            Some(port) => port.parse().map_err(|_| HttpError::Url(text.to_string()))?,
            None if https => 443,
            None => 80,
        };
        if host.is_empty() || target.contains(char::is_whitespace) {
            return Err(HttpError::Url(text.to_string()));
        }
        Ok(Url { https, host, port, target })
    }

    /// The `Host` header value.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if (self.https && self.port == 443) || (!self.https && self.port == 80) {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn as_string(&self) -> String {
        format!(
            "{}://{}{}",
            if self.https { "https" } else { "http" },
            self.authority(),
            self.target
        )
    }

    /// A `Location` header resolved against this URL.
    pub fn join(&self, location: &str) -> Result<Url, HttpError> {
        let location = location.trim();
        if location.contains("://") {
            return Url::parse(location);
        }
        let scheme = if self.https { "https" } else { "http" };
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{scheme}://{rest}"));
        }
        let target = if location.starts_with('/') {
            location.to_string()
        } else {
            let path = self.target.split('?').next().unwrap_or("/");
            let directory = &path[..path.rfind('/').map_or(1, |slash| slash + 1)];
            format!("{directory}{location}")
        };
        Ok(Url {
            target,
            ..self.clone()
        })
    }
}

/// One request.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub url: Url,
    /// Extra or replacing headers; an empty value removes a default one.
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    /// The whole transfer's limit.
    pub timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    /// Accept any server certificate (`curl -k`).
    pub insecure: bool,
    /// Ask for and decode gzip/deflate bodies (`curl --compressed`).
    pub compressed: bool,
    pub user_agent: String,
}

impl Request {
    pub fn get(url: Url) -> Request {
        Request {
            method: "GET".to_string(),
            url,
            headers: Vec::new(),
            body: None,
            follow_redirects: false,
            max_redirects: 50,
            timeout: None,
            connect_timeout: None,
            insecure: false,
            compressed: false,
            user_agent: "curl/8.0.0".to_string(),
        }
    }
}

/// A response's status line and headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    /// The URL this response came from.
    pub url: Url,
}

impl ResponseHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The raw header block as received (status line through the blank
    /// line), for `curl -i`.
    pub fn raw(&self) -> String {
        let mut text = format!("{} {} {}\r\n", self.version, self.status, self.reason);
        for (name, value) in &self.headers {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
        text.push_str("\r\n");
        text
    }
}

/// What a transfer reports as it goes.
pub trait Sink {
    /// Each response's head, redirects included (`last` for the final one).
    fn head(&mut self, head: &ResponseHead, last: bool) -> Result<(), HttpError>;
    /// The final response's body, in order.
    fn data(&mut self, data: &[u8]) -> Result<(), HttpError>;
    /// Bytes of the final body received so far, and the expected total.
    fn progress(&mut self, _received: u64, _total: Option<u64>) {}
    /// The request about to be sent (for `curl -v`).
    fn request_sent(&mut self, _head: &str) {}
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let result = match self {
            Stream::Plain(stream) => stream.read(buffer),
            Stream::Tls(stream) => stream.read(buffer),
        };
        // A peer that closes without close_notify still ends the body.
        match result {
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
            other => other,
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(stream) => stream.write(buffer),
            Stream::Tls(stream) => stream.write(buffer),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(stream) => stream.flush(),
            Stream::Tls(stream) => stream.flush(),
        }
    }
}

/// Accepts every certificate (`-k`); signatures still verify.
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config(roots: &[Vec<u8>], insecure: bool) -> Result<Arc<rustls::ClientConfig>, HttpError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| HttpError::Tls(e.to_string()))?;
    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth()
    } else {
        let mut store = rustls::RootCertStore::empty();
        for der in roots {
            // Roots the verifier cannot use are skipped, as Windows would
            // never pick them for a chain.
            let _ = store.add(rustls::pki_types::CertificateDer::from(der.clone()));
        }
        builder.with_root_certificates(store).with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn remaining(deadline: Option<Instant>) -> Result<Option<Duration>, HttpError> {
    match deadline {
        None => Ok(None),
        Some(deadline) => {
            let now = Instant::now();
            if now >= deadline {
                Err(HttpError::Timeout)
            } else {
                Ok(Some(deadline - now))
            }
        }
    }
}

fn io_error(error: std::io::Error, deadline: Option<Instant>, make: fn(String) -> HttpError) -> HttpError {
    if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
        || deadline.is_some_and(|deadline| Instant::now() >= deadline)
    {
        HttpError::Timeout
    } else {
        make(error.to_string())
    }
}

fn connect(request: &Request, url: &Url, roots: &[Vec<u8>], deadline: Option<Instant>) -> Result<Stream, HttpError> {
    let addresses: Vec<_> = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|_| HttpError::Resolve(url.host.clone()))?
        .collect();
    if addresses.is_empty() {
        return Err(HttpError::Resolve(url.host.clone()));
    }
    let mut last = None;
    let mut tcp = None;
    for address in addresses {
        let limit = match (request.connect_timeout, remaining(deadline)?) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => Duration::from_secs(300),
        };
        match TcpStream::connect_timeout(&address, limit) {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(error) => last = Some(error),
        }
    }
    let Some(tcp) = tcp else {
        let error = last.expect("an address was tried");
        if error.kind() == std::io::ErrorKind::TimedOut {
            return Err(HttpError::Timeout);
        }
        return Err(HttpError::Connect(format!("{} port {}: {error}", url.host, url.port)));
    };
    let _ = tcp.set_nodelay(true);
    let limit = remaining(deadline)?;
    let _ = tcp.set_read_timeout(limit);
    let _ = tcp.set_write_timeout(limit);
    if !url.https {
        return Ok(Stream::Plain(tcp));
    }
    let name = rustls::pki_types::ServerName::try_from(url.host.clone())
        .map_err(|_| HttpError::Url(url.as_string()))?;
    let connection = rustls::ClientConnection::new(tls_config(roots, request.insecure)?, name)
        .map_err(|e| HttpError::Tls(e.to_string()))?;
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    // Drive the handshake now, so certificate failures report as such.
    while stream.conn.is_handshaking() {
        if let Err(error) = stream.conn.complete_io(&mut stream.sock) {
            return Err(match error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
                Some(rustls::Error::InvalidCertificate(reason)) => HttpError::Certificate(certificate_problem(reason)),
                Some(other) => HttpError::Tls(other.to_string()),
                None => io_error(error, deadline, HttpError::Tls),
            });
        }
    }
    Ok(Stream::Tls(Box::new(stream)))
}

/// curl's (OpenSSL's) wording for why a certificate was rejected.
fn certificate_problem(reason: &rustls::CertificateError) -> String {
    use rustls::CertificateError as E;
    match reason {
        E::Expired | E::ExpiredContext { .. } => "certificate has expired".into(),
        E::NotValidYet | E::NotValidYetContext { .. } => "certificate is not yet valid".into(),
        E::UnknownIssuer => "unable to get local issuer certificate".into(),
        E::Revoked => "certificate revoked".into(),
        E::NotValidForName | E::NotValidForNameContext { .. } => {
            "no alternative certificate subject name matches target host name".into()
        }
        E::BadSignature => "certificate signature failure".into(),
        other => format!("{other:?}"),
    }
}

/// The request head as sent.
fn request_head(request: &Request, method: &str, url: &Url, body: Option<&[u8]>) -> String {
    let mut headers: Vec<(String, String)> = vec![
        ("Host".into(), url.authority()),
        ("User-Agent".into(), request.user_agent.clone()),
        ("Accept".into(), "*/*".into()),
    ];
    if request.compressed {
        headers.push(("Accept-Encoding".into(), "deflate, gzip".into()));
    }
    for (name, value) in &request.headers {
        headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        if !value.is_empty() {
            headers.push((name.clone(), value.clone()));
        }
    }
    if let Some(body) = body {
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("Content-Type")) {
            headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
        }
        headers.push(("Content-Length".into(), body.len().to_string()));
    }
    headers.push(("Connection".into(), "close".into()));
    let mut head = format!("{method} {} HTTP/1.1\r\n", url.target);
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    head
}

/// Reads a stream with a lookahead buffer.
struct Reader<'a> {
    stream: &'a mut Stream,
    buffer: Vec<u8>,
    deadline: Option<Instant>,
}

impl Reader<'_> {
    fn fill(&mut self) -> Result<bool, HttpError> {
        remaining(self.deadline)?;
        let mut chunk = [0u8; 16 * 1024];
        let count = self
            .stream
            .read(&mut chunk)
            .map_err(|e| io_error(e, self.deadline, HttpError::Receive))?;
        self.buffer.extend_from_slice(&chunk[..count]);
        Ok(count > 0)
    }

    fn line(&mut self) -> Result<String, HttpError> {
        loop {
            if let Some(end) = self.buffer.windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&self.buffer[..end]).into_owned();
                self.buffer.drain(..end + 2);
                return Ok(line);
            }
            if self.buffer.len() > 64 * 1024 {
                return Err(HttpError::BadReply("header line too long".into()));
            }
            if !self.fill()? {
                return Err(HttpError::Receive("connection closed in the response head".into()));
            }
        }
    }

    fn take(&mut self, mut count: u64, mut out: impl FnMut(&[u8]) -> Result<(), HttpError>) -> Result<(), HttpError> {
        while count > 0 {
            if self.buffer.is_empty() && !self.fill()? {
                return Err(HttpError::Receive("connection closed before the body ended".into()));
            }
            let n = (self.buffer.len() as u64).min(count) as usize;
            out(&self.buffer[..n])?;
            self.buffer.drain(..n);
            count -= n as u64;
        }
        Ok(())
    }

    fn rest(&mut self, mut out: impl FnMut(&[u8]) -> Result<(), HttpError>) -> Result<(), HttpError> {
        loop {
            if !self.buffer.is_empty() {
                out(&self.buffer)?;
                self.buffer.clear();
            }
            if !self.fill()? {
                return Ok(());
            }
        }
    }
}

fn read_head(reader: &mut Reader<'_>, url: &Url) -> Result<ResponseHead, HttpError> {
    loop {
        let status_line = reader.line()?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default().to_string();
        if !version.starts_with("HTTP/") {
            return Err(HttpError::BadReply(status_line));
        }
        let status: u16 = parts
            .next()
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| HttpError::BadReply(status_line.clone()))?;
        let reason = parts.next().unwrap_or_default().to_string();
        let mut headers = Vec::new();
        loop {
            let line = reader.line()?;
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
        // Interim responses (100 Continue and friends) precede the real one.
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        return Ok(ResponseHead { version, status, reason, headers, url: url.clone() });
    }
}

/// Read a body to `out` by its framing.
fn read_body(reader: &mut Reader<'_>, head: &ResponseHead, method: &str, mut out: impl FnMut(&[u8]) -> Result<(), HttpError>) -> Result<(), HttpError> {
    if method == "HEAD" || head.status == 204 || head.status == 304 {
        return Ok(());
    }
    let chunked = head
        .header("Transfer-Encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    if chunked {
        loop {
            let size_line = reader.line()?;
            let size = u64::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| HttpError::BadReply(format!("bad chunk size {size_line:?}")))?;
            if size == 0 {
                // Trailers, then the blank line.
                while !reader.line()?.is_empty() {}
                return Ok(());
            }
            reader.take(size, &mut out)?;
            if !reader.line()?.is_empty() {
                return Err(HttpError::BadReply("chunk without CRLF".into()));
            }
        }
    }
    match head.header("Content-Length").and_then(|value| value.trim().parse::<u64>().ok()) {
        Some(length) => reader.take(length, out),
        None => reader.rest(out),
    }
}

/// Decode a whole gzip or deflate body.
fn decode(encoding: &str, body: &[u8]) -> Result<Vec<u8>, HttpError> {
    let bad = |what: &str| HttpError::BadReply(format!("bad {what} body"));
    match encoding {
        "gzip" | "x-gzip" => {
            if body.len() < 18 || body[0] != 0x1f || body[1] != 0x8b || body[2] != 8 {
                return Err(bad("gzip"));
            }
            let flags = body[3];
            let mut at = 10;
            if flags & 4 != 0 {
                let extra = u16::from_le_bytes([body[at], body[at + 1]]) as usize;
                at += 2 + extra;
            }
            for flag in [8, 16] {
                if flags & flag != 0 {
                    at += body.get(at..).and_then(|rest| rest.iter().position(|b| *b == 0)).ok_or_else(|| bad("gzip"))? + 1;
                }
            }
            if flags & 2 != 0 {
                at += 2;
            }
            crate::deflate::inflate(body.get(at..body.len() - 8).ok_or_else(|| bad("gzip"))?).map_err(|_| bad("gzip"))
        }
        // HTTP "deflate" is zlib-wrapped; some servers send raw deflate.
        "deflate" => {
            let zlib = body.len() > 2 && body[0] & 0x0f == 8 && (u16::from(body[0]) << 8 | u16::from(body[1])) % 31 == 0;
            let raw = if zlib { &body[2..body.len().saturating_sub(4)] } else { body };
            crate::deflate::inflate(raw).map_err(|_| bad("deflate"))
        }
        _ => Ok(body.to_vec()),
    }
}

/// Run a request, following redirects when asked; reports through `sink`
/// and returns the final response's head.
pub fn fetch(request: &Request, roots: &[Vec<u8>], sink: &mut dyn Sink) -> Result<ResponseHead, HttpError> {
    let deadline = request.timeout.map(|limit| Instant::now() + limit);
    let mut url = request.url.clone();
    let mut method = request.method.clone();
    let mut body = request.body.clone();
    let mut redirects = 0;
    loop {
        let mut stream = connect(request, &url, roots, deadline)?;
        let head = request_head(request, &method, &url, body.as_deref());
        sink.request_sent(&head);
        stream
            .write_all(head.as_bytes())
            .and_then(|()| body.as_deref().map_or(Ok(()), |body| stream.write_all(body)))
            .and_then(|()| stream.flush())
            .map_err(|e| io_error(e, deadline, HttpError::Send))?;
        let mut reader = Reader { stream: &mut stream, buffer: Vec::new(), deadline };
        let response = read_head(&mut reader, &url)?;
        let location = response.header("Location").map(str::to_string);
        let redirect = request.follow_redirects
            && matches!(response.status, 301 | 302 | 303 | 307 | 308)
            && location.is_some();
        sink.head(&response, !redirect)?;
        if redirect {
            redirects += 1;
            if redirects > request.max_redirects {
                return Err(HttpError::TooManyRedirects(request.max_redirects));
            }
            url = url.join(location.as_deref().unwrap_or(""))?;
            // curl turns a POST into a GET for 301/302/303, as browsers do.
            if matches!(response.status, 301..=303) && method != "HEAD" {
                if method == "POST" || response.status == 303 {
                    method = "GET".to_string();
                    body = None;
                }
            }
            continue;
        }
        let total = response.header("Content-Length").and_then(|v| v.trim().parse::<u64>().ok());
        let encoding = response
            .header("Content-Encoding")
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| request.compressed && matches!(value.as_str(), "gzip" | "x-gzip" | "deflate"));
        let mut received = 0u64;
        if let Some(encoding) = encoding {
            let mut whole = Vec::new();
            read_body(&mut reader, &response, &method, |data| {
                whole.extend_from_slice(data);
                received += data.len() as u64;
                sink.progress(received, total);
                Ok(())
            })?;
            sink.data(&decode(&encoding, &whole)?)?;
        } else {
            read_body(&mut reader, &response, &method, |data| {
                received += data.len() as u64;
                sink.data(data)?;
                sink.progress(received, total);
                Ok(())
            })?;
        }
        return Ok(response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn urls_parse_and_resolve_redirects() {
        let url = Url::parse("https://example.com:8443/a/b?x=1#frag").unwrap();
        assert_eq!((url.https, url.host.as_str(), url.port, url.target.as_str()), (true, "example.com", 8443, "/a/b?x=1"));
        assert_eq!(Url::parse("example.com").unwrap().as_string(), "http://example.com/");
        assert_eq!(Url::parse("http://[::1]:81/").unwrap().authority(), "[::1]:81");
        assert_eq!(url.join("c").unwrap().target, "/a/c");
        assert_eq!(url.join("/z").unwrap().target, "/z");
        assert_eq!(url.join("//other.test/p").unwrap().as_string(), "https://other.test/p");
        assert_eq!(url.join("http://x.test/").unwrap().as_string(), "http://x.test/");
        assert_eq!(Url::parse("ftp://x/").unwrap_err().curl_code(), 1);
        assert_eq!(Url::parse("http://u:p@x/").unwrap_err().curl_code(), 3);
        assert_eq!(Url::parse("http://x:port/").unwrap_err().curl_code(), 3);
    }

    #[derive(Default)]
    struct Collect {
        heads: Vec<(u16, bool)>,
        body: Vec<u8>,
        sent: Vec<String>,
    }

    impl Sink for Collect {
        fn head(&mut self, head: &ResponseHead, last: bool) -> Result<(), HttpError> {
            self.heads.push((head.status, last));
            Ok(())
        }
        fn data(&mut self, data: &[u8]) -> Result<(), HttpError> {
            self.body.extend_from_slice(data);
            Ok(())
        }
        fn request_sent(&mut self, head: &str) {
            self.sent.push(head.to_string());
        }
    }

    /// Serve canned responses, one per connection, by request path.
    fn serve(responses: Vec<(&'static str, Vec<u8>)>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(responses.len()) {
                let mut stream = stream.unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    request.push(byte[0]);
                }
                let path = String::from_utf8_lossy(&request).split(' ').nth(1).unwrap_or("").to_string();
                let reply = responses
                    .iter()
                    .find(|(prefix, _)| path == *prefix)
                    .map(|(_, reply)| reply.clone())
                    .unwrap_or_else(|| b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec());
                let _ = stream.write_all(&reply);
            }
        });
        port
    }

    #[test]
    fn redirects_chunked_and_length_bodies() {
        let port = serve(vec![
            ("/start", b"HTTP/1.1 302 Found\r\nLocation: /chunked\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("/chunked", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n5;x=y\r\npedia\r\n0\r\nT: v\r\n\r\n".to_vec()),
            ("/length", b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA".to_vec()),
        ]);
        let base = format!("http://127.0.0.1:{port}");
        let mut request = Request::get(Url::parse(&format!("{base}/start")).unwrap());
        request.follow_redirects = true;
        let mut sink = Collect::default();
        let head = fetch(&request, &[], &mut sink).unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.url.target, "/chunked");
        assert_eq!(sink.heads, vec![(302, false), (200, true)]);
        assert_eq!(sink.body, b"wikipedia");
        assert!(sink.sent[0].starts_with("GET /start HTTP/1.1\r\nHost: 127.0.0.1:"), "{}", sink.sent[0]);
        let mut sink = Collect::default();
        fetch(&Request::get(Url::parse(&format!("{base}/length")).unwrap()), &[], &mut sink).unwrap();
        assert_eq!(sink.body, b"abc", "Content-Length bounds the body; 100 Continue is skipped");
    }

    #[test]
    fn failures_map_to_curl_codes() {
        let port = serve(vec![("/loop", b"HTTP/1.1 301 Moved\r\nLocation: /loop\r\n\r\n".to_vec()); 3]);
        let mut request = Request::get(Url::parse(&format!("http://127.0.0.1:{port}/loop")).unwrap());
        request.follow_redirects = true;
        request.max_redirects = 2;
        assert_eq!(fetch(&request, &[], &mut Collect::default()).unwrap_err().curl_code(), 47);
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let request = Request::get(Url::parse(&format!("http://127.0.0.1:{closed}/")).unwrap());
        assert_eq!(fetch(&request, &[], &mut Collect::default()).unwrap_err().curl_code(), 7);
        let request = Request::get(Url::parse("http://winrun-no-such-host.invalid/").unwrap());
        assert_eq!(fetch(&request, &[], &mut Collect::default()).unwrap_err().curl_code(), 6);
        let port = serve(vec![("/", b"SSH-2.0-OpenSSH\r\n".to_vec())]);
        let request = Request::get(Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap());
        assert_eq!(fetch(&request, &[], &mut Collect::default()).unwrap_err().curl_code(), 8);
    }

    #[test]
    fn a_server_that_does_not_speak_tls_fails_the_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut hello = [0u8; 5];
                let _ = stream.read_exact(&mut hello);
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            }
        });
        let request = Request::get(Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap());
        assert_eq!(fetch(&request, &[], &mut Collect::default()).unwrap_err().curl_code(), 35);
    }

    #[test]
    fn gzip_bodies_decode() {
        // "hello" gzip-compressed (stored block).
        let gzip = [
            0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1, 5, 0, 0xfa, 0xff, b'h', b'e', b'l', b'l', b'o',
            0x86, 0xa6, 0x10, 0x36, 5, 0, 0, 0,
        ];
        assert_eq!(decode("gzip", &gzip).unwrap(), b"hello");
        assert!(decode("gzip", b"not gzip at all, really").is_err());
        assert_eq!(decode("identity", b"x").unwrap(), b"x");
    }
}
