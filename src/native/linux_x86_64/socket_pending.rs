//! Overlapped socket receives and sends that cannot finish at once. As on
//! Windows they return WSA_IO_PENDING (whatever the socket's blocking
//! mode) and complete through the socket's completion port when the data
//! moves, or with STATUS_CANCELLED after `CancelIoEx` or `closesocket`.

use super::*;

const STATUS_CONNECTION_RESET: u64 = 0xC000_020D;
const STATUS_CONNECTION_ABORTED: u64 = 0xC000_0241;
const STATUS_UNSUCCESSFUL: u64 = 0xC000_0001;

struct PendingSocketIo {
    socket: u64,
    overlapped: u64,
    /// Set by whichever finishes it first: the transfer or a cancellation.
    finished: Arc<AtomicBool>,
}

static PENDING_SOCKET_IO: Mutex<Vec<PendingSocketIo>> = Mutex::new(Vec::new());

/// Run `transfer` (a non-blocking receive or send returning bytes or an
/// errno) once `socket` is ready for `events` (POLLIN 1 / POLLOUT 4), then
/// post its completion. The caller returns WSA_IO_PENDING.
pub(super) fn pend_socket_io(
    socket: u64,
    overlapped: u64,
    events: i16,
    transfer: impl Fn() -> Result<u32, i32> + Send + 'static,
) {
    let finished = Arc::new(AtomicBool::new(false));
    native_set_overlapped_status(overlapped, STATUS_PENDING, 0);
    PENDING_SOCKET_IO.lock().unwrap_or_else(|e| e.into_inner()).push(PendingSocketIo {
        socket,
        overlapped,
        finished: Arc::clone(&finished),
    });
    std::thread::spawn(move || {
        let fd = socket as u32 as i32;
        let status = loop {
            if finished.load(Ordering::Acquire) {
                return; // cancelled; the canceller posted the completion
            }
            let mut poll_fd = NativePollFd { fd, events, revents: 0 };
            if unsafe { poll(&mut poll_fd, 1, 50) } <= 0 {
                continue;
            }
            match transfer() {
                Ok(bytes) => break Ok(bytes),
                Err(libc::EAGAIN) | Err(libc::EINTR) => continue,
                Err(errno) => break Err(errno),
            }
        };
        if finished.swap(true, Ordering::AcqRel) {
            return;
        }
        forget(socket, overlapped);
        match status {
            Ok(bytes) => native_post_pending_socket_completion(socket, overlapped, bytes),
            Err(errno) => native_post_socket_failure(
                socket,
                overlapped,
                match errno {
                    libc::ECONNRESET | libc::EPIPE => STATUS_CONNECTION_RESET,
                    libc::ECONNABORTED => STATUS_CONNECTION_ABORTED,
                    _ => STATUS_UNSUCCESSFUL,
                },
            ),
        }
    });
}

fn forget(socket: u64, overlapped: u64) {
    PENDING_SOCKET_IO
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|pending| !(pending.socket == socket && pending.overlapped == overlapped));
}

/// Cancel `socket`'s pending receives and sends (one `overlapped`, or all
/// for 0) with STATUS_CANCELLED; whether any were pending.
pub(super) fn cancel_pending_socket_io(socket: u64, overlapped: u64) -> bool {
    let cancelled: Vec<u64> = {
        let mut pending = PENDING_SOCKET_IO.lock().unwrap_or_else(|e| e.into_inner());
        let mut cancelled = Vec::new();
        pending.retain(|io| {
            let matches = io.socket == socket && (overlapped == 0 || io.overlapped == overlapped);
            if matches && !io.finished.swap(true, Ordering::AcqRel) {
                cancelled.push(io.overlapped);
            }
            !matches
        });
        cancelled
    };
    for overlapped in &cancelled {
        native_post_socket_failure(socket, *overlapped, STATUS_CANCELLED);
    }
    !cancelled.is_empty()
}
