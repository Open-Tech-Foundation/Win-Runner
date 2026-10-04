//! Headless, cross-language control for a persistent Win-Runner shell.
//!
//! The public transport is a localhost WebSocket carrying JSON messages. A
//! private Unix stream connects controller input to the shell and native
//! guest standard input; guest output is sent back as asynchronous events.

use crate::backend::{OutputChannel, OutputSink};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tungstenite::{accept_hdr, handshake::HandshakeError, Error as WsError, Message, WebSocket};

#[repr(C)]
struct SharedTerminalSize {
    columns: AtomicUsize,
    rows: AtomicUsize,
}

static TERMINAL_SIZE: std::sync::atomic::AtomicPtr<SharedTerminalSize> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
static CONTROL_SESSION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn terminal_size() -> (usize, usize) {
    let shared = TERMINAL_SIZE.load(Ordering::Acquire);
    if shared.is_null() {
        return (80, 25);
    }
    // SAFETY: this mapping is created before guest processes fork and remains
    // mapped until the Win-Runner process exits.
    let shared = unsafe { &*shared };
    (
        shared.columns.load(Ordering::Relaxed).max(1),
        shared.rows.load(Ordering::Relaxed).max(1),
    )
}

pub fn is_control_session() -> bool {
    CONTROL_SESSION.load(Ordering::Relaxed)
}

pub struct ControlHandle {
    endpoint: String,
    output: Sender<Value>,
    server: Option<JoinHandle<()>>,
    _stdin_reader: UnixStream,
}

impl ControlHandle {
    /// Bind only to loopback. The random port is reported to the launching
    /// agent before the shell starts consuming controller input.
    pub fn start(bind: &str) -> Result<Self, String> {
        let address: SocketAddr = bind
            .parse()
            .map_err(|error| format!("invalid control address {bind}: {error}"))?;
        if !address.ip().is_loopback() {
            return Err("Win-Runner control listener must bind to a loopback address".to_string());
        }
        let listener = TcpListener::bind(address)
            .map_err(|error| format!("cannot bind control listener {address}: {error}"))?;
        let local = listener
            .local_addr()
            .map_err(|error| format!("cannot inspect control listener: {error}"))?;
        let mut token = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut token))
            .map_err(|error| format!("cannot create control token: {error}"))?;
        let token = token
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = format!("/control/{token}");
        let endpoint = format!("ws://{local}{path}");

        let size_map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<SharedTerminalSize>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if size_map == libc::MAP_FAILED {
            return Err(format!(
                "cannot allocate shared console size: {}",
                std::io::Error::last_os_error()
            ));
        }
        let size_map = size_map.cast::<SharedTerminalSize>();
        unsafe {
            size_map.write(SharedTerminalSize {
                columns: AtomicUsize::new(80),
                rows: AtomicUsize::new(25),
            });
        }
        TERMINAL_SIZE.store(size_map, Ordering::Release);

        let (stdin_reader, stdin_writer) = UnixStream::pair()
            .map_err(|error| format!("cannot create controlled stdin stream: {error}"))?;
        // Win32 ReadFile(GetStdHandle(STD_INPUT_HANDLE)) reads descriptor 0.
        // Replacing it with this private stream lets WebSocket input reach the
        // shell or whichever guest PE is currently running.
        let result = unsafe { libc::dup2(stdin_reader.as_raw_fd(), libc::STDIN_FILENO) };
        if result < 0 {
            return Err(format!(
                "cannot connect controlled input to stdin: {}",
                std::io::Error::last_os_error()
            ));
        }
        CONTROL_SESSION.store(true, Ordering::Release);

        let (output, receiver) = mpsc::channel();
        let server = thread::Builder::new()
            .name("winrun-control-ws".to_string())
            .spawn(move || serve(listener, stdin_writer, receiver, path))
            .map_err(|error| format!("cannot start control listener: {error}"))?;
        Ok(Self {
            endpoint,
            output,
            server: Some(server),
            _stdin_reader: stdin_reader,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn output_sink(&self) -> OutputSink {
        let output = self.output.clone();
        Arc::new(move |channel, bytes| {
            let channel = match channel {
                OutputChannel::Stdout => "stdout",
                OutputChannel::Stderr => "stderr",
            };
            let _ = output.send(json!({
                "event": "output",
                "channel": channel,
                "text": String::from_utf8_lossy(bytes),
                "data_base64": BASE64.encode(bytes),
            }));
        })
    }

    pub fn emit_prompt(&self, cwd: &str) {
        let _ = self.output.send(json!({"event": "prompt", "cwd": cwd}));
    }

    pub fn finish(mut self, code: i32) {
        let _ = self.output.send(json!({"event": "exit", "code": code}));
        drop(self.output);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

fn serve(
    listener: TcpListener,
    mut input: UnixStream,
    receiver: mpsc::Receiver<Value>,
    expected_path: String,
) {
    if let Err(error) = listener.set_nonblocking(true) {
        eprintln!("winrun: cannot configure control listener: {error}");
        return;
    }
    let mut pending = Vec::new();
    let mut handshakes = Vec::new();
    let mut socket = 'accept: loop {
        loop {
            match receiver.try_recv() {
                Ok(event) => {
                    if event.get("event").and_then(Value::as_str) == Some("exit") {
                        return;
                    }
                    pending.push(event);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        // Drive each handshake without blocking the accept loop. A slow or idle
        // unauthenticated peer cannot monopolize the control endpoint.
        if let Ok((stream, _)) = listener.accept() {
            if handshakes.len() < 64 && stream.set_nonblocking(true).is_ok() {
                let path = expected_path.clone();
                match accept_hdr(
                    stream,
                    move |request: &tungstenite::handshake::server::Request, response| {
                        if constant_time_eq(request.uri().path().as_bytes(), path.as_bytes()) {
                            Ok(response)
                        } else {
                            Err(tungstenite::http::Response::builder()
                                .status(401)
                                .body(Some("invalid control token".to_string()))
                                .expect("valid response"))
                        }
                    },
                ) {
                    Ok(socket) => break socket,
                    Err(HandshakeError::Interrupted(handshake)) => {
                        handshakes.push((Instant::now(), handshake))
                    }
                    Err(HandshakeError::Failure(_)) => {}
                }
            }
        }
        let mut remaining = Vec::new();
        for (started, handshake) in handshakes.drain(..) {
            if started.elapsed() >= Duration::from_secs(2) {
                continue;
            }
            match handshake.handshake() {
                Ok(socket) => break 'accept socket,
                Err(HandshakeError::Interrupted(handshake)) => remaining.push((started, handshake)),
                Err(HandshakeError::Failure(_)) => {}
            }
        }
        handshakes = remaining;
        thread::sleep(Duration::from_millis(10));
    };
    drop(handshakes);
    let _ = socket.get_ref().set_nonblocking(false);
    let _ = socket
        .get_ref()
        .set_write_timeout(Some(Duration::from_secs(2)));
    let _ = socket
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(20)));
    if send_json(&mut socket, &json!({"event": "connected", "protocol": 1})).is_err() {
        return;
    }
    for event in pending {
        let is_exit = event.get("event").and_then(Value::as_str) == Some("exit");
        if send_json(&mut socket, &event).is_err() {
            return;
        }
        if is_exit {
            let _ = socket.close(None);
            return;
        }
    }
    loop {
        loop {
            match receiver.try_recv() {
                Ok(event) => {
                    if send_json(&mut socket, &event).is_err() {
                        return;
                    }
                    if event.get("event").and_then(Value::as_str) == Some("exit") {
                        let _ = socket.close(None);
                        return;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    let _ = socket.close(None);
                    return;
                }
            }
        }
        match socket.read() {
            Ok(Message::Text(text)) => match serde_json::from_str::<Value>(&text) {
                Ok(request) => {
                    if let Err(error) = handle_request(&request, &mut input) {
                        let response = json!({
                            "event": "error",
                            "id": request.get("id"),
                            "message": error,
                        });
                        if send_json(&mut socket, &response).is_err() {
                            return;
                        }
                    } else {
                        let response = json!({"event": "accepted", "id": request.get("id")});
                        if send_json(&mut socket, &response).is_err() {
                            return;
                        }
                    }
                    if request.get("op").and_then(Value::as_str) == Some("close") {
                        let _ = input.shutdown(Shutdown::Write);
                    }
                }
                Err(error) => {
                    if send_json(
                        &mut socket,
                        &json!({"event": "error", "message": format!("invalid JSON: {error}")}),
                    )
                    .is_err()
                    {
                        return;
                    }
                }
            },
            Ok(Message::Close(_)) => return,
            Ok(Message::Ping(payload)) => {
                if socket.send(Message::Pong(payload)).is_err() {
                    return;
                }
            }
            Ok(_) => {}
            Err(WsError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => return,
            Err(error) => {
                eprintln!("winrun: control connection failed: {error}");
                return;
            }
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn send_json(socket: &mut WebSocket<TcpStream>, value: &Value) -> Result<(), WsError> {
    socket.send(Message::Text(value.to_string().into()))
}

fn handle_request(request: &Value, input: &mut UnixStream) -> Result<(), String> {
    match request.get("op").and_then(Value::as_str) {
        Some("write") => {
            let text = request
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| "write requires a string `text`".to_string())?;
            input
                .write_all(text.as_bytes())
                .map_err(|error| format!("cannot deliver input: {error}"))
        }
        Some("write_bytes") => {
            let encoded = request
                .get("data_base64")
                .and_then(Value::as_str)
                .ok_or_else(|| "write_bytes requires `data_base64`".to_string())?;
            let bytes = BASE64
                .decode(encoded)
                .map_err(|error| format!("invalid base64 input: {error}"))?;
            input
                .write_all(&bytes)
                .map_err(|error| format!("cannot deliver input: {error}"))
        }
        Some("key") => {
            let key = request
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| "key requires a string `key`".to_string())?;
            let bytes: &[u8] = match key.to_ascii_uppercase().as_str() {
                "ENTER" => b"\r",
                "TAB" => b"\t",
                "ESC" | "ESCAPE" => b"\x1b",
                "BACKSPACE" => b"\x7f",
                "CTRL_C" => b"\x03",
                "CTRL_D" => b"\x04",
                "CTRL_X" => b"\x18",
                "CTRL_S" => b"\x13",
                "UP" => b"\x1b[A",
                "DOWN" => b"\x1b[B",
                "RIGHT" => b"\x1b[C",
                "LEFT" => b"\x1b[D",
                _ => return Err(format!("unsupported key name: {key}")),
            };
            input
                .write_all(bytes)
                .map_err(|error| format!("cannot deliver key input: {error}"))
        }
        Some("resize") => {
            let columns = request
                .get("columns")
                .and_then(Value::as_u64)
                .filter(|size| (1..=500).contains(size))
                .ok_or_else(|| "resize requires columns in 1..=500".to_string())?;
            let rows = request
                .get("rows")
                .and_then(Value::as_u64)
                .filter(|size| (1..=300).contains(size))
                .ok_or_else(|| "resize requires rows in 1..=300".to_string())?;
            let shared = TERMINAL_SIZE.load(Ordering::Acquire);
            if !shared.is_null() {
                // SAFETY: the shared mapping remains valid for this session
                // and is inherited by native guest processes.
                let shared = unsafe { &*shared };
                shared.columns.store(columns as usize, Ordering::Relaxed);
                shared.rows.store(rows as usize, Ordering::Relaxed);
            }
            Ok(())
        }
        Some("close") => Ok(()),
        Some(operation) => Err(format!("unknown operation: {operation}")),
        None => Err("request requires string `op`".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn control_token_comparison_checks_all_equal_length_bytes() {
        assert!(constant_time_eq(b"/control/secret", b"/control/secret"));
        assert!(!constant_time_eq(b"/control/secret", b"/control/secrex"));
        assert!(!constant_time_eq(b"/control/secret", b"/control/short"));
    }
}
