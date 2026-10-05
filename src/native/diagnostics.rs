//! Host-owned diagnostics channel, independent of guest stdout and stderr.
//! Workers inherit its writer, so redirection in any descendant cannot hide
//! a fatal compatibility error from the launcher.
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
/// Foreground diagnostics participate in the launcher's output stream. Once the
/// foreground worker exits, keep reading errors from surviving child workers
/// through a host sink without retaining the launcher's completion channel.
pub(super) fn forward(
    mut reader: std::fs::File,
    sender: std::sync::mpsc::Sender<(bool, Vec<u8>)>,
    background: impl Fn(&[u8]) + Send + 'static,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    use std::io::Read;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let foreground = Arc::new(AtomicBool::new(true));
    let active = Arc::clone(&foreground);
    let worker = std::thread::spawn(move || {
        let mut sender = Some(sender);
        let mut buffer = [0u8; 4096];
        loop {
            // Drain diagnostics already queued before switching sinks; fatal
            // errors written just before process exit still reach its caller.
            let is_foreground = active.load(Ordering::Acquire);
            let mut descriptor = libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe {
                libc::poll(
                    &mut descriptor,
                    1,
                    if sender.is_none() {
                        -1 // Background diagnostics sleep until bytes or EOF arrive.
                    } else if is_foreground {
                        25
                    } else {
                        0
                    },
                )
            };
            if ready < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if ready == 0 {
                if !is_foreground {
                    sender.take();
                }
                continue;
            }
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    let bytes = &buffer[..length];
                    if let Some(ref output) = sender {
                        if output.send((true, bytes.to_vec())).is_err() {
                            sender.take();
                            background(bytes);
                        }
                    } else {
                        background(bytes);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });
    (foreground, worker)
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
    fn surviving_child_writer_does_not_block_foreground_and_still_reports_errors() {
        use std::sync::{atomic::Ordering, mpsc, Arc, Mutex};
        use std::time::Duration;
        let channel = DiagnosticChannel::new().unwrap();
        let (sender, receiver) = mpsc::channel();
        let (background_sender, background_receiver) = mpsc::channel();
        let sink = Arc::new(Mutex::new(background_sender));
        let (foreground, worker) = forward(channel.reader, sender, move |bytes| {
            sink.lock().unwrap().send(bytes.to_vec()).unwrap();
        });
        assert!(write_message(
            channel.writer.as_raw_fd(),
            b"foreground error\n"
        ));
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            (true, b"foreground error\n".to_vec())
        );
        foreground.store(false, Ordering::Release);
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
        // The surviving child retains its writer after foreground completion.
        assert!(write_message(
            channel.writer.as_raw_fd(),
            b"background error\n"
        ));
        assert_eq!(
            background_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            b"background error\n"
        );
        drop(channel.writer);
        worker.join().unwrap();
    }
    #[test]
    fn a_closed_channel_reports_failure_for_stderr_fallback() {
        assert!(!write_message(-1, b"missing shim\n"));
    }
}
