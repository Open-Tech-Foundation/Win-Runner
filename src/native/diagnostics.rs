//! Host-owned diagnostics channel, independent of guest stdout and stderr.
//! Workers inherit its writer, so redirection in any descendant cannot hide
//! a fatal compatibility error from the launcher.
#[cfg(test)]
use std::os::fd::AsRawFd;
use std::os::fd::{FromRawFd, OwnedFd};

pub(super) const CHANNEL_ENV: &str = "WINRUN_NATIVE_ERROR_FD";

pub(super) struct DiagnosticChannel {
    pub(super) reader: std::fs::File,
    pub(super) writer: OwnedFd,
}
impl DiagnosticChannel {
    pub(super) fn new() -> std::io::Result<Self> {
        let mut descriptors = [-1; 2];
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let reader = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        // Both ends stay close-on-exec in the launcher. A pre-exec hook
        // makes just this worker's writer inheritable, avoiding leaks into
        // unrelated processes spawned concurrently by other host threads.
        Ok(Self { reader, writer })
    }
}
pub(super) fn inherit_writer(fd: i32) -> std::io::Result<()> {
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
fn write_message(fd: i32, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if count < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if count <= 0 {
            return false;
        }
        bytes = &bytes[count as usize..];
    }
    true
}
pub(super) fn report(message: &[u8]) {
    let channel = std::env::var(CHANNEL_ENV)
        .ok()
        .and_then(|value| value.parse::<i32>().ok());
    if let Some(fd) = channel.filter(|fd| *fd > 2) {
        if write_message(fd, message) {
            return;
        }
    }
    // Library/fork execution and workers without a launcher retain stderr.
    write_message(libc::STDERR_FILENO, message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    #[test]
    fn only_the_writer_is_inherited_and_eof_follows_its_close() {
        let mut channel = DiagnosticChannel::new().unwrap();
        assert_eq!(
            unsafe { libc::fcntl(channel.reader.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC
        );
        assert_eq!(
            unsafe { libc::fcntl(channel.writer.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC
        );
        inherit_writer(channel.writer.as_raw_fd()).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(channel.writer.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert!(write_message(channel.writer.as_raw_fd(), b"missing shim\n"));
        drop(channel.writer);
        let mut text = String::new();
        channel.reader.read_to_string(&mut text).unwrap();
        assert_eq!(text, "missing shim\n");
    }
    #[test]
    fn a_closed_channel_reports_failure_for_stderr_fallback() {
        assert!(!write_message(-1, b"missing shim\n"));
    }
}
