//! Persistent, named Win-Runner instance lifecycle.
//!
//! Each daemon owns one loaded snapshot and its writable WinFs overlay. The
//! initial Linux transport is a mode-0600 Unix-domain socket; higher layers
//! use the same commands over named pipes on Windows or Unix sockets on
//! macOS. This module intentionally contains no GitHub-specific behavior.

use crate::{
    protocol::{read_frame, write_frame, Frame, Kind},
    shell::{Shell, ShellFlow},
    snapshot,
    winfs::WinFs,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SOCKET_SUFFIX: &str = ".sock";

pub fn state_dir() -> PathBuf {
    std::env::var_os("WINRUN_INSTANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("winrun-instances"))
}

pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("instance name must be 1-64 ASCII letters, digits, '-' or '_'".to_string());
    }
    Ok(())
}

fn socket_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}{SOCKET_SUFFIX}"))
}

pub fn boot(name: &str, snapshot_path: Option<&str>) -> Result<(), String> {
    validate_name(name)?;
    let dir = state_dir();
    std::fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "cannot create instance state directory {}: {e}",
            dir.display()
        )
    })?;
    let socket = socket_path(&dir, name);
    if socket.exists() {
        if ping(name).is_ok() {
            return Err(format!("instance already running: {name}"));
        }
        std::fs::remove_file(&socket).map_err(|e| {
            format!(
                "cannot remove stale instance socket {}: {e}",
                socket.display()
            )
        })?;
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot find winrun executable: {e}"))?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("__instance-daemon")
        .arg(name)
        .arg(&dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(path) = snapshot_path {
        command.arg(path);
    }
    command
        .spawn()
        .map_err(|e| format!("cannot start instance daemon: {e}"))?;
    for _ in 0..100 {
        if ping(name).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(format!("instance daemon did not become ready: {name}"))
}

pub fn status(name: &str) -> Result<(), String> {
    let response = String::from_utf8(request(name, b"PING\n")?)
        .map_err(|_| "invalid status response".to_string())?;
    if response.starts_with("OK ") {
        Ok(())
    } else {
        Err(format!("invalid status response for {name}"))
    }
}

pub fn destroy(name: &str) -> Result<(), String> {
    let response = String::from_utf8(request(name, b"DESTROY\n")?)
        .map_err(|_| "invalid destroy response".to_string())?;
    if response != "OK\n" {
        return Err(format!("invalid destroy response for {name}"));
    }
    let socket = socket_path(&state_dir(), name);
    for _ in 0..100 {
        if !socket.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(format!("instance daemon did not stop: {name}"))
}

fn ping(name: &str) -> Result<(), String> {
    let response = String::from_utf8(request(name, b"PING\n")?)
        .map_err(|_| "invalid instance response".to_string())?;
    response
        .starts_with("OK ")
        .then_some(())
        .ok_or_else(|| "unexpected instance response".to_string())
}

pub struct ExecResult {
    pub code: i32,
    pub stdout: Vec<u8>,
}

/// Execute one command in the daemon's retained guest session.
pub fn exec(name: &str, command: &str) -> Result<ExecResult, String> {
    if command.is_empty() {
        return Err("instance command may not be empty".to_string());
    }
    framed_exec(name, command)
}

#[cfg(unix)]
fn framed_exec(name: &str, command: &str) -> Result<ExecResult, String> {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    validate_name(name)?;
    let socket = socket_path(&state_dir(), name);
    let mut stream = UnixStream::connect(&socket)
        .map_err(|e| format!("instance is not running ({name}): {e}"))?;
    write_frame(
        &mut stream,
        &Frame {
            stream: 1,
            kind: Kind::Request,
            flags: 1,
            payload: command.as_bytes().to_vec(),
        },
    )?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("cannot finish execution request: {e}"))?;
    let mut stdout = Vec::new();
    loop {
        let frame = read_frame(&mut stream)?;
        if frame.stream != 1 {
            return Err("unexpected execution stream".to_string());
        }
        match frame.kind {
            Kind::Response => {}
            Kind::Stdout | Kind::Stderr => stdout.extend_from_slice(&frame.payload),
            Kind::Failure => return Err(String::from_utf8_lossy(&frame.payload).to_string()),
            Kind::Exit if frame.payload.len() == 4 => {
                return Ok(ExecResult {
                    code: i32::from_be_bytes(frame.payload.try_into().unwrap()),
                    stdout,
                });
            }
            _ => return Err("invalid execution frame".to_string()),
        }
    }
}

#[cfg(not(unix))]
fn framed_exec(_: &str, _: &str) -> Result<ExecResult, String> {
    Err("named-pipe instance transport is not implemented on this host".to_string())
}

#[cfg(unix)]
fn request(name: &str, message: &[u8]) -> Result<Vec<u8>, String> {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    validate_name(name)?;
    let socket = socket_path(&state_dir(), name);
    let mut stream = UnixStream::connect(&socket)
        .map_err(|e| format!("instance is not running ({name}): {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("cannot configure instance socket: {e}"))?;
    stream
        .write_all(message)
        .map_err(|e| format!("cannot send instance request: {e}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("cannot finish instance request: {e}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("cannot read instance response: {e}"))?;
    Ok(response)
}

#[cfg(not(unix))]
fn request(_: &str, _: &[u8]) -> Result<Vec<u8>, String> {
    Err("named-pipe instance transport is not implemented on this host".to_string())
}

/// Internal daemon entry point. Called only by `winrun __instance-daemon`.
pub fn run_daemon(name: &str, dir: &str, snapshot_path: Option<&str>) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (name, dir, snapshot_path);
        return Err("named-pipe instance transport is not implemented on this host".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        validate_name(name)?;
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).map_err(|e| {
            format!(
                "cannot create daemon state directory {}: {e}",
                dir.display()
            )
        })?;
        let socket = socket_path(&dir, name);
        if socket.exists() {
            std::fs::remove_file(&socket)
                .map_err(|e| format!("cannot clear daemon socket {}: {e}", socket.display()))?;
        }
        let instance_fs: WinFs = match snapshot_path {
            Some(path) => snapshot::load_file(path)?,
            None => WinFs::ephemeral_runner(),
        };
        let mut shell = Shell::with_fs(instance_fs);
        let listener = UnixListener::bind(&socket)
            .map_err(|e| format!("cannot bind instance socket {}: {e}", socket.display()))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot protect instance socket {}: {e}", socket.display()))?;
        for connection in listener.incoming() {
            let mut stream = match connection {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let mut request = Vec::new();
            let count = match stream.read_to_end(&mut request) {
                Ok(count) => count,
                Err(_) => continue,
            };
            if count > 64 * 1024 {
                let _ = stream.write_all(b"ERR request too large\n");
                continue;
            }
            if request.starts_with(b"WCLI") {
                let frame = match read_frame(request.as_slice()) {
                    Ok(frame) if frame.stream == 1 && frame.kind == Kind::Request => frame,
                    Ok(_) => {
                        let _ = write_frame(
                            &mut stream,
                            &Frame {
                                stream: 1,
                                kind: Kind::Failure,
                                flags: 1,
                                payload: b"invalid execution request".to_vec(),
                            },
                        );
                        continue;
                    }
                    Err(error) => {
                        let _ = write_frame(
                            &mut stream,
                            &Frame {
                                stream: 1,
                                kind: Kind::Failure,
                                flags: 1,
                                payload: error.into_bytes(),
                            },
                        );
                        continue;
                    }
                };
                let command = match std::str::from_utf8(&frame.payload) {
                    Ok(command) if !command.is_empty() => command,
                    _ => {
                        let _ = write_frame(
                            &mut stream,
                            &Frame {
                                stream: 1,
                                kind: Kind::Failure,
                                flags: 1,
                                payload: b"invalid command".to_vec(),
                            },
                        );
                        continue;
                    }
                };
                let mut output = Vec::new();
                let output_stream = match stream.try_clone() {
                    Ok(value) => std::sync::Arc::new(std::sync::Mutex::new(value)),
                    Err(error) => {
                        let _ = write_frame(
                            &mut stream,
                            &Frame {
                                stream: 1,
                                kind: Kind::Failure,
                                flags: 1,
                                payload: error.to_string().into_bytes(),
                            },
                        );
                        continue;
                    }
                };
                let sink: crate::backend::OutputSink =
                    std::sync::Arc::new(move |channel, chunk| {
                        let kind = match channel {
                            crate::backend::OutputChannel::Stdout => Kind::Stdout,
                            crate::backend::OutputChannel::Stderr => Kind::Stderr,
                        };
                        if let Ok(mut writer) = output_stream.lock() {
                            let _ = write_frame(
                                &mut *writer,
                                &Frame {
                                    stream: 1,
                                    kind,
                                    flags: 0,
                                    payload: chunk.to_vec(),
                                },
                            );
                        }
                    });
                let code = match shell.exec_line_streaming(command, &mut output, sink) {
                    Ok(ShellFlow::Continue) => shell.last_code(),
                    Ok(ShellFlow::Exit(code)) => code,
                    Err(error) => {
                        let _ = write_frame(
                            &mut stream,
                            &Frame {
                                stream: 1,
                                kind: Kind::Failure,
                                flags: 1,
                                payload: error.into_bytes(),
                            },
                        );
                        continue;
                    }
                };
                let _ = write_frame(
                    &mut stream,
                    &Frame {
                        stream: 1,
                        kind: Kind::Response,
                        flags: 0,
                        payload: Vec::new(),
                    },
                );
                for chunk in output.chunks(crate::protocol::MAX_PAYLOAD) {
                    let _ = write_frame(
                        &mut stream,
                        &Frame {
                            stream: 1,
                            kind: Kind::Stdout,
                            flags: 0,
                            payload: chunk.to_vec(),
                        },
                    );
                }
                let _ = write_frame(
                    &mut stream,
                    &Frame {
                        stream: 1,
                        kind: Kind::Exit,
                        flags: 1,
                        payload: code.to_be_bytes().to_vec(),
                    },
                );
                continue;
            }
            match request.as_slice() {
                b"PING\n" => {
                    let _ = stream.write_all(format!("OK {name}\n").as_bytes());
                }
                b"DESTROY\n" => {
                    let _ = stream.write_all(b"OK\n");
                    let _ = std::fs::remove_file(&socket);
                    return Ok(());
                }
                request if request.starts_with(b"EXEC ") => {
                    let command = match std::str::from_utf8(&request[5..]) {
                        Ok(command) if !command.is_empty() => command,
                        _ => {
                            let _ = stream.write_all(b"ERR invalid command\n");
                            continue;
                        }
                    };
                    let mut output = Vec::new();
                    let code = match shell.exec_line(command, &mut output) {
                        Ok(ShellFlow::Continue) => shell.last_code(),
                        Ok(ShellFlow::Exit(code)) => code,
                        Err(error) => {
                            let _ = stream.write_all(format!("ERR {error}\n").as_bytes());
                            continue;
                        }
                    };
                    let _ = stream.write_all(format!("OK {code}\n").as_bytes());
                    let _ = stream.write_all(&output);
                }
                _ => {
                    let _ = stream.write_all(b"ERR unsupported request\n");
                }
            }
        }
        let _ = std::fs::remove_file(&socket);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_safe_instance_names() {
        assert!(validate_name("task-42_a").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("../bad").is_err());
        assert!(validate_name("space bad").is_err());
    }
}
