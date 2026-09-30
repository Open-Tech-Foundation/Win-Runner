//! The Ancillary Function Driver's socket polling (`\Device\Afd`), which
//! event loops such as mio (under tokio) and libuv's `uv_poll` use for
//! socket readiness on Windows: a handle opened on the device, associated
//! with a completion port, accepts `IOCTL_AFD_POLL` requests that complete
//! through the port when a watched socket is ready, and that
//! `NtCancelIoFileEx` cancels. Readiness comes from host `poll(2)` on the
//! socket, in one waiting thread per pending request.

use super::*;
use std::collections::HashMap;

/// Tag of AFD device handles ("AFD" in the high bytes).
const AFD_HANDLE_TAG: u64 = 0x4146_4400_0000_0000;
const IOCTL_AFD_POLL: u32 = 0x0001_2024;

const STATUS_SUCCESS: u32 = 0;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_CANCELLED: u32 = 0xC000_0120;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

const AFD_POLL_RECEIVE: u32 = 0x001;
const AFD_POLL_RECEIVE_EXPEDITED: u32 = 0x002;
const AFD_POLL_SEND: u32 = 0x004;
const AFD_POLL_DISCONNECT: u32 = 0x008;
const AFD_POLL_ABORT: u32 = 0x010;
const AFD_POLL_LOCAL_CLOSE: u32 = 0x020;
const AFD_POLL_ACCEPT: u32 = 0x080;
const AFD_POLL_CONNECT_FAIL: u32 = 0x100;

struct PendingPoll {
    /// An eventfd the waiting thread also polls; written to cancel.
    cancel: i32,
}

#[derive(Default)]
struct AfdDevice {
    completion: Option<(Arc<NativeCompletionPort>, u64)>,
    /// Pending polls by their IO_STATUS_BLOCK address.
    pending: HashMap<u64, PendingPoll>,
}

static AFD_DEVICES: LazyLock<Mutex<HashMap<u64, AfdDevice>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static AFD_NEXT: AtomicU64 = AtomicU64::new(1);

pub(super) fn is_afd_handle(handle: u64) -> bool {
    handle & 0xffff_ff00_0000_0000 == AFD_HANDLE_TAG
}

/// Whether an NT path names the AFD device (`\Device\Afd`, optionally with
/// an endpoint name such as mio's `\Device\Afd\Mio`).
pub(super) fn is_afd_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower == r"\device\afd" || lower.starts_with(r"\device\afd\")
}

pub(super) fn open_afd_device() -> u64 {
    let handle = AFD_HANDLE_TAG | AFD_NEXT.fetch_add(1, Ordering::AcqRel);
    if let Ok(mut devices) = AFD_DEVICES.lock() {
        devices.insert(handle, AfdDevice::default());
    }
    handle
}

/// Associate an AFD handle with a completion port (`CreateIoCompletionPort`).
pub(super) fn associate_afd_device(handle: u64, port: Arc<NativeCompletionPort>, key: u64) -> bool {
    let Ok(mut devices) = AFD_DEVICES.lock() else {
        return false;
    };
    match devices.get_mut(&handle) {
        Some(device) => {
            device.completion = Some((port, key));
            true
        }
        None => false,
    }
}

/// Close an AFD handle, cancelling its pending polls.
pub(super) fn close_afd_device(handle: u64) -> bool {
    let Some(device) = AFD_DEVICES.lock().ok().and_then(|mut devices| devices.remove(&handle)) else {
        return false;
    };
    for pending in device.pending.values() {
        signal_cancel(pending.cancel);
    }
    true
}

fn signal_cancel(eventfd: i32) {
    let one = 1u64;
    unsafe { libc::write(eventfd, (&one as *const u64).cast(), 8) };
}

/// `AFD_POLL_INFO` with one handle: timeout, count, exclusive, then
/// `{ handle, events, status }`.
const POLL_INFO_SIZE: usize = 32;

fn linux_events(requested: u32) -> i16 {
    let mut events = 0;
    if requested & (AFD_POLL_RECEIVE | AFD_POLL_ACCEPT) != 0 {
        events |= libc::POLLIN;
    }
    if requested & AFD_POLL_RECEIVE_EXPEDITED != 0 {
        events |= libc::POLLPRI;
    }
    if requested & AFD_POLL_SEND != 0 {
        events |= libc::POLLOUT;
    }
    if requested & AFD_POLL_DISCONNECT != 0 {
        events |= libc::POLLRDHUP;
    }
    events
}

/// The AFD events a host `poll` result reports for `fd`, and the NTSTATUS
/// of a failed connection.
fn afd_events(fd: i32, revents: i16) -> (u32, u32) {
    if revents & libc::POLLNVAL != 0 {
        return (AFD_POLL_LOCAL_CLOSE, STATUS_SUCCESS);
    }
    let mut listening = 0i32;
    let mut size = 4u32;
    unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ACCEPTCONN, (&mut listening as *mut i32).cast(), &mut size)
    };
    let mut events = 0;
    if revents & libc::POLLIN != 0 {
        events |= if listening != 0 { AFD_POLL_ACCEPT } else { AFD_POLL_RECEIVE };
    }
    if revents & libc::POLLPRI != 0 {
        events |= AFD_POLL_RECEIVE_EXPEDITED;
    }
    if revents & libc::POLLOUT != 0 {
        events |= AFD_POLL_SEND;
    }
    if revents & libc::POLLRDHUP != 0 {
        events |= AFD_POLL_DISCONNECT;
    }
    let mut status = STATUS_SUCCESS;
    if revents & libc::POLLERR != 0 {
        let mut error = 0i32;
        let mut size = 4u32;
        unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&mut error as *mut i32).cast(), &mut size) };
        // A socket that never connected reports its connect failure; an
        // established one was reset.
        let mut peer = [0u8; 128];
        let mut peer_length = peer.len() as u32;
        let connected = unsafe { libc::getpeername(fd, peer.as_mut_ptr().cast(), &mut peer_length) } == 0;
        if connected {
            events |= AFD_POLL_ABORT;
        } else {
            events |= AFD_POLL_CONNECT_FAIL;
            status = match error {
                libc::ECONNREFUSED => 0xC000_0236, // STATUS_CONNECTION_REFUSED
                libc::ETIMEDOUT => 0xC000_00B5,    // STATUS_IO_TIMEOUT
                libc::ENETUNREACH => 0xC000_023C,  // STATUS_NETWORK_UNREACHABLE
                libc::EHOSTUNREACH => 0xC000_023D, // STATUS_HOST_UNREACHABLE
                _ => 0xC000_0001,                  // STATUS_UNSUCCESSFUL
            };
        }
    }
    if revents & libc::POLLHUP != 0 {
        events |= AFD_POLL_ABORT;
    }
    (events, status)
}

/// `NtDeviceIoControlFile` on an AFD handle: `IOCTL_AFD_POLL` for one
/// socket, completed later through the handle's completion port with
/// `apc_context` as the packet's overlapped pointer.
#[allow(clippy::too_many_arguments)]
pub(super) fn afd_device_io_control(
    handle: u64,
    apc_context: u64,
    io_status: *mut u8,
    control_code: u32,
    input: *const u8,
    input_length: u32,
    output: *mut u8,
    output_length: u32,
) -> u32 {
    if control_code != IOCTL_AFD_POLL {
        return STATUS_NOT_IMPLEMENTED;
    }
    if io_status.is_null()
        || input.is_null()
        || output.is_null()
        || (input_length as usize) < POLL_INFO_SIZE
        || (output_length as usize) < POLL_INFO_SIZE
    {
        return STATUS_INVALID_PARAMETER;
    }
    let (timeout, count, socket, requested) = unsafe {
        (
            input.cast::<i64>().read_unaligned(),
            input.add(8).cast::<u32>().read_unaligned(),
            input.add(16).cast::<u64>().read_unaligned(),
            input.add(24).cast::<u32>().read_unaligned(),
        )
    };
    if count != 1 || socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
        return STATUS_INVALID_PARAMETER;
    }
    let cancel = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if cancel < 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let completion = {
        let Ok(mut devices) = AFD_DEVICES.lock() else {
            unsafe { libc::close(cancel) };
            return STATUS_INVALID_HANDLE;
        };
        let Some(device) = devices.get_mut(&handle) else {
            unsafe { libc::close(cancel) };
            return STATUS_INVALID_HANDLE;
        };
        device.pending.insert(io_status as u64, PendingPoll { cancel });
        device.completion.clone()
    };
    unsafe {
        io_status.cast::<u32>().write_unaligned(STATUS_PENDING);
        io_status.add(8).cast::<u64>().write_unaligned(0);
    }
    // A negative timeout is relative, in 100 ns units; others do not expire.
    let deadline = (timeout < 0).then(|| {
        std::time::Instant::now() + std::time::Duration::from_nanos((timeout.unsigned_abs()).saturating_mul(100))
    });
    let (io_status, output) = (io_status as usize, output as usize);
    std::thread::spawn(move || {
        let fd = socket as u32 as i32;
        let (events, status) = loop {
            let wait_ms = deadline.map_or(-1, |deadline| {
                deadline.saturating_duration_since(std::time::Instant::now()).as_millis().min(i32::MAX as u128) as i32
            });
            let mut fds = [
                libc::pollfd { fd, events: linux_events(requested), revents: 0 },
                libc::pollfd { fd: cancel, events: libc::POLLIN, revents: 0 },
            ];
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, wait_ms) };
            if ready < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break (0, STATUS_CANCELLED);
            }
            if fds[1].revents != 0 {
                break (0, STATUS_CANCELLED);
            }
            if ready == 0 {
                break (0, STATUS_SUCCESS); // timed out with nothing ready
            }
            let (events, status) = afd_events(fd, fds[0].revents);
            let reported = events & (requested | AFD_POLL_LOCAL_CLOSE);
            if reported != 0 {
                break (reported, status);
            }
            // Only unrequested conditions (such as a hang-up nobody asked
            // about): wait again rather than spin.
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        unsafe { libc::close(cancel) };
        // Closing the device cancels its polls; their packets still arrive,
        // as Windows queues them for cancelled I/O.
        if let Ok(mut devices) = AFD_DEVICES.lock() {
            if let Some(device) = devices.get_mut(&handle) {
                device.pending.remove(&(io_status as u64));
            }
        }
        let io_status = io_status as *mut u8;
        let output = output as *mut u8;
        unsafe {
            if events != 0 {
                output.add(8).cast::<u32>().write_unaligned(1);
                output.add(16).cast::<u64>().write_unaligned(socket);
                output.add(24).cast::<u32>().write_unaligned(events);
                output.add(28).cast::<u32>().write_unaligned(status);
            } else {
                output.add(8).cast::<u32>().write_unaligned(0);
            }
            io_status.add(8).cast::<u64>().write_unaligned(POLL_INFO_SIZE as u64);
            io_status.cast::<u32>().write_unaligned(if events == 0 && status == STATUS_CANCELLED {
                STATUS_CANCELLED
            } else {
                STATUS_SUCCESS
            });
        }
        if let Some((port, key)) = completion {
            port.post(NativeCompletion {
                key,
                overlapped: apc_context,
                bytes: POLL_INFO_SIZE as u32,
                status: u64::from(unsafe { io_status.cast::<u32>().read_unaligned() }),
            });
        }
    });
    STATUS_PENDING
}

/// `NtCancelIoFileEx(handle, io_status, cancel_status)` for AFD polls.
pub(super) fn afd_cancel(handle: u64, io_status: u64) -> u32 {
    let Ok(devices) = AFD_DEVICES.lock() else {
        return STATUS_INVALID_HANDLE;
    };
    let Some(device) = devices.get(&handle) else {
        return STATUS_INVALID_HANDLE;
    };
    let targets: Vec<i32> = if io_status == 0 {
        device.pending.values().map(|pending| pending.cancel).collect()
    } else {
        device.pending.get(&io_status).map(|pending| pending.cancel).into_iter().collect()
    };
    if targets.is_empty() {
        return STATUS_NOT_FOUND;
    }
    for cancel in targets {
        signal_cancel(cancel);
    }
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll_info(socket: u64, events: u32) -> [u8; POLL_INFO_SIZE] {
        let mut info = [0u8; POLL_INFO_SIZE];
        info[..8].copy_from_slice(&i64::MAX.to_le_bytes());
        info[8..12].copy_from_slice(&1u32.to_le_bytes());
        info[16..24].copy_from_slice(&socket.to_le_bytes());
        info[24..28].copy_from_slice(&events.to_le_bytes());
        info
    }

    fn wait_for(port: &NativeCompletionPort) -> NativeCompletion {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(completion) = port.queue.lock().unwrap().pop_front() {
                return completion;
            }
            assert!(std::time::Instant::now() < deadline, "no completion packet");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn afd_polls_complete_through_the_port_and_can_be_cancelled() {
        assert!(is_afd_path(r"\Device\Afd\Mio"));
        assert!(!is_afd_path(r"\Device\AfdX"));
        let device = open_afd_device();
        assert!(is_afd_handle(device));
        let port = Arc::new(NativeCompletionPort::new());
        assert!(associate_afd_device(device, port.clone(), 0x77));

        let mut pair = [0i32; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) }, 0);
        let socket = SOCKET_HANDLE_TAG | pair[0] as u64;

        // Writable at once: completes with AFD_POLL_SEND.
        let mut info = poll_info(socket, AFD_POLL_SEND | AFD_POLL_ABORT);
        let mut io_status = [0u8; 16];
        let status = afd_device_io_control(
            device, 0x1234, io_status.as_mut_ptr(), IOCTL_AFD_POLL,
            info.as_ptr(), 32, info.as_mut_ptr(), 32,
        );
        assert_eq!(status, STATUS_PENDING);
        let completion = wait_for(&port);
        assert_eq!((completion.key, completion.overlapped, completion.bytes), (0x77, 0x1234, 32));
        assert_eq!(u32::from_le_bytes(info[8..12].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(info[24..28].try_into().unwrap()), AFD_POLL_SEND);
        assert_eq!(u32::from_le_bytes(io_status[..4].try_into().unwrap()), STATUS_SUCCESS);

        // Nothing to read: pending until cancelled.
        let mut info = poll_info(socket, AFD_POLL_RECEIVE);
        let mut io_status = [0u8; 16];
        afd_device_io_control(
            device, 0x5678, io_status.as_mut_ptr(), IOCTL_AFD_POLL,
            info.as_ptr(), 32, info.as_mut_ptr(), 32,
        );
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(port.queue.lock().unwrap().is_empty(), "still pending");
        assert_eq!(afd_cancel(device, io_status.as_ptr() as u64), STATUS_SUCCESS);
        let completion = wait_for(&port);
        assert_eq!(completion.overlapped, 0x5678);
        assert_eq!(u32::from_le_bytes(io_status[..4].try_into().unwrap()), STATUS_CANCELLED);
        assert_eq!(afd_cancel(device, io_status.as_ptr() as u64), STATUS_NOT_FOUND);

        // Readable after the peer writes.
        let mut info = poll_info(socket, AFD_POLL_RECEIVE);
        let mut io_status = [0u8; 16];
        afd_device_io_control(
            device, 0x9abc, io_status.as_mut_ptr(), IOCTL_AFD_POLL,
            info.as_ptr(), 32, info.as_mut_ptr(), 32,
        );
        assert_eq!(unsafe { libc::write(pair[1], b"x".as_ptr().cast(), 1) }, 1);
        wait_for(&port);
        assert_eq!(u32::from_le_bytes(info[24..28].try_into().unwrap()), AFD_POLL_RECEIVE);

        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
        assert!(close_afd_device(device));
        assert!(!close_afd_device(device));
    }
}
