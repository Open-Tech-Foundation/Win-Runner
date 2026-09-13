//! Persistent, named WinCLI instance lifecycle.
//!
//! Each daemon owns one loaded snapshot and its writable WinFs overlay. The
//! initial Linux transport is a mode-0600 Unix-domain socket; higher layers
//! use the same commands over named pipes on Windows or Unix sockets on
//! macOS. This module intentionally contains no GitHub-specific behavior.

use crate::{snapshot, winfs::WinFs};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SOCKET_SUFFIX: &str = ".sock";

pub fn state_dir() -> PathBuf {
    std::env::var_os("WINCLI_INSTANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("wincli-instances"))
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
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("cannot create instance state directory {}: {e}", dir.display()))?;
    let socket = socket_path(&dir, name);
    if socket.exists() {
        if ping(name).is_ok() {
            return Err(format!("instance already running: {name}"));
        }
        std::fs::remove_file(&socket)
            .map_err(|e| format!("cannot remove stale instance socket {}: {e}", socket.display()))?;
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot find wincli executable: {e}"))?;
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
    let response = request(name, b"PING\n")?;
    if response.starts_with("OK ") {
        Ok(())
    } else {
        Err(format!("invalid status response for {name}"))
    }
}

pub fn destroy(name: &str) -> Result<(), String> {
    let response = request(name, b"DESTROY\n")?;
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
    let response = request(name, b"PING\n")?;
    response
        .starts_with("OK ")
        .then_some(())
        .ok_or_else(|| "unexpected instance response".to_string())
}

#[cfg(unix)]
fn request(name: &str, message: &[u8]) -> Result<String, String> {
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
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("cannot read instance response: {e}"))?;
    Ok(response)
}

#[cfg(not(unix))]
fn request(_: &str, _: &[u8]) -> Result<String, String> {
    Err("named-pipe instance transport is not implemented on this host".to_string())
}

/// Internal daemon entry point. Called only by `wincli __instance-daemon`.
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
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create daemon state directory {}: {e}", dir.display()))?;
        let socket = socket_path(&dir, name);
        if socket.exists() {
            std::fs::remove_file(&socket)
                .map_err(|e| format!("cannot clear daemon socket {}: {e}", socket.display()))?;
        }
        let _instance_fs: WinFs = match snapshot_path {
            Some(path) => snapshot::load_file(path)?,
            None => WinFs::ephemeral_runner(),
        };
        let listener = UnixListener::bind(&socket)
            .map_err(|e| format!("cannot bind instance socket {}: {e}", socket.display()))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot protect instance socket {}: {e}", socket.display()))?;
        for connection in listener.incoming() {
            let mut stream = match connection {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let mut request = [0; 32];
            let count = match stream.read(&mut request) {
                Ok(count) => count,
                Err(_) => continue,
            };
            match &request[..count] {
                b"PING\n" => {
                    let _ = stream.write_all(format!("OK {name}\n").as_bytes());
                }
                b"DESTROY\n" => {
                    let _ = stream.write_all(b"OK\n");
                    let _ = std::fs::remove_file(&socket);
                    return Ok(());
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
