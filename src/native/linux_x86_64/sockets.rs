//! Winsock compatibility shims backed by Linux sockets.

use super::*;

#[repr(C)]
pub(super) struct NativeWsaData {
    version: u16,
    high_version: u16,
    description: [u8; 257],
    system_status: [u8; 129],
    max_sockets: u16,
    max_udp_datagram: u16,
    vendor_info: *const u8,
}

pub(super) extern "win64" fn native_wsa_startup(requested: u16, data: *mut NativeWsaData) -> i32 {
    if data.is_null() {
        return 10014; // WSAEFAULT
    }
    let major = requested as u8;
    let minor = (requested >> 8) as u8;
    if !matches!(major, 1 | 2) || (major == 2 && minor > 2) {
        return 10092; // WSAVERNOTSUPPORTED
    }
    let negotiated = if major == 1 {
        requested
    } else {
        0x0200 | minor as u16
    };
    let mut value = NativeWsaData {
        version: negotiated,
        high_version: 0x0202,
        description: [0; 257],
        system_status: [0; 129],
        max_sockets: 0,
        max_udp_datagram: 0,
        vendor_info: std::ptr::null(),
    };
    let description = b"Win-Runner";
    value.description[..description.len()].copy_from_slice(description);
    let status = b"Running";
    value.system_status[..status.len()].copy_from_slice(status);
    unsafe { data.write(value) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsa_startup_accepts_win_runner_description_and_status() {
        let mut data = std::mem::MaybeUninit::<NativeWsaData>::uninit();
        assert_eq!(native_wsa_startup(0x0202, data.as_mut_ptr()), 0);
        let data = unsafe { data.assume_init() };
        assert_eq!(data.version, 0x0202);
        assert_eq!(&data.description[..10], b"Win-Runner");
        assert_eq!(data.description[10], 0);
        assert_eq!(&data.system_status[..7], b"Running");
    }

    #[test]
    fn wsa_startup_rejects_null_data_without_panicking() {
        assert_eq!(native_wsa_startup(0x0202, std::ptr::null_mut()), 10014);
    }
}

pub(super) extern "win64" fn native_wsa_cleanup() -> i32 {
    0
}

pub(super) extern "win64" fn native_wsa_get_host_name(name: *mut u8, length: i32) -> i32 {
    if name.is_null() || length <= 0 {
        native_wsa_set_last_error(10014); // WSAEFAULT
        return -1;
    }
    let mut hostname = [0i8; 256];
    if unsafe { gethostname(hostname.as_mut_ptr(), hostname.len()) } != 0 {
        native_wsa_set_last_error(10093); // WSANOTINITIALISED / host failure
        return -1;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(hostname.as_ptr()) }.to_bytes();
    if bytes.len() + 1 > length as usize {
        native_wsa_set_last_error(10014);
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), name, bytes.len());
        name.add(bytes.len()).write(0);
    }
    0
}

pub(super) extern "win64" fn native_connect_socket(
    socket: u64,
    address: *const u8,
    length: i32,
) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
        native_wsa_set_last_error(10038); // WSAENOTSOCK
        return -1;
    }
    if address.is_null() || length < 2 || length as usize > 128 {
        native_wsa_set_last_error(10014); // WSAEFAULT
        return -1;
    }
    let mut translated = [0u8; 128];
    unsafe {
        ptr::copy_nonoverlapping(address, translated.as_mut_ptr(), length as usize);
        let family = (translated.as_ptr() as *const u16).read_unaligned();
        if family == 23 {
            (translated.as_mut_ptr() as *mut u16).write_unaligned(10);
        } else if family != 2 {
            native_wsa_set_last_error(10047); // WSAEAFNOSUPPORT
            return -1;
        }
    }
    if unsafe { connect(socket as i32, translated.as_ptr(), length as u32) } == 0 {
        socket_event_connect(socket);
        return 0;
    }
    if native_diagnostic_enabled() {
        eprintln!(
            "native connect socket={socket:#x} failed: {}",
            std::io::Error::last_os_error()
        );
    }
    native_wsa_set_last_error(match std::io::Error::last_os_error().raw_os_error() {
        Some(11 | 114 | 115) => 10035, // WSAEWOULDBLOCK / in progress
        Some(111) => 10061,            // WSAECONNREFUSED
        Some(110) => 10060,            // WSAETIMEDOUT
        Some(99) => 10049,             // WSAEADDRNOTAVAIL
        Some(101) => 10051,            // WSAENETUNREACH
        _ => 10022,                    // WSAEINVAL
    });
    if native_wsa_get_last_error() == 10035 {
        socket_event_connect(socket);
    }
    -1
}

pub(super) extern "win64" fn native_bind_socket(
    socket: u64,
    address: *const u8,
    length: i32,
) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG
        || address.is_null()
        || length < 2
        || length > 128
    {
        native_wsa_set_last_error(10014);
        return -1;
    }
    let mut translated = [0u8; 128];
    unsafe {
        ptr::copy_nonoverlapping(address, translated.as_mut_ptr(), length as usize);
        let family = (translated.as_ptr() as *const u16).read_unaligned();
        if family == 23 {
            (translated.as_mut_ptr() as *mut u16).write_unaligned(10);
        } else if family != 2 {
            native_wsa_set_last_error(10047);
            return -1;
        }
    }
    if unsafe { bind(socket as i32, translated.as_ptr(), length as u32) } == 0 {
        0
    } else {
        native_wsa_set_last_error(errno_to_wsa(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(22),
        ));
        -1
    }
}

pub(super) extern "win64" fn native_listen_socket(socket: u64, backlog: i32) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native listen socket={socket:#x} backlog={backlog}");
    }
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
        native_wsa_set_last_error(10038); // WSAENOTSOCK
        return -1;
    }
    if unsafe { listen(socket as i32, backlog.max(1)) } == 0 {
        0
    } else {
        native_wsa_set_last_error(errno_to_wsa(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(22),
        ));
        -1
    }
}

pub(super) extern "win64" fn native_send_socket(
    socket: u64,
    buffer: *const u8,
    length: i32,
    flags: i32,
) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG
        || (buffer.is_null() && length != 0)
        || length < 0
    {
        native_wsa_set_last_error(10014); // WSAEFAULT
        return -1;
    }
    let result = unsafe { send(socket as i32, buffer.cast(), length as usize, flags) };
    if result < 0 {
        let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(9);
        if error == libc::EAGAIN {
            socket_event_rearm(socket, 2);
        }
        // Linux can consume a pending connection error even on a zero-byte
        // send probe. Keep it available to the guest's subsequent SO_ERROR.
        if matches!(
            error,
            libc::ECONNREFUSED
                | libc::ECONNRESET
                | libc::ETIMEDOUT
                | libc::ENETUNREACH
                | libc::EHOSTUNREACH
        ) {
            if let Some(process) = process_ctx() {
                if let Ok(mut errors) = process.socket_errors.lock() {
                    errors.insert(socket, errno_to_wsa(error));
                }
            }
        }
        native_wsa_set_last_error(errno_to_wsa(error));
        -1
    } else {
        result.min(i32::MAX as isize) as i32
    }
}

pub(super) extern "win64" fn native_shutdown_socket(socket: u64, how: i32) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG || !(0..=2).contains(&how) {
        native_wsa_set_last_error(if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
            10038 // WSAENOTSOCK
        } else {
            10022 // WSAEINVAL
        });
        return -1;
    }
    if unsafe { shutdown(socket as i32, how) } == 0 {
        0
    } else {
        native_wsa_set_last_error(errno_to_wsa(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(9),
        ));
        -1
    }
}

pub(super) extern "win64" fn native_accept_ex(
    listen_socket: u64,
    accept_socket: u64,
    output: *mut u8,
    receive_data_length: u32,
    local_address_length: u32,
    remote_address_length: u32,
    bytes_received: *mut u32,
    overlapped: u64,
) -> i32 {
    if listen_socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG
        || accept_socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG
        || output.is_null()
        || overlapped == 0
        || local_address_length < 16
        || remote_address_length < 16
    {
        native_wsa_set_last_error(10014); // WSAEFAULT
        return 0;
    }
    if !bytes_received.is_null() {
        unsafe { bytes_received.write_unaligned(0) };
    }
    let Some(_process) = process_ctx() else {
        native_wsa_set_last_error(10022);
        return 0;
    };
    let listener = listen_socket as i32;
    let accepted = accept_socket as i32;
    let output = output as usize;
    let address_offsets = (
        receive_data_length as usize + local_address_length as usize - 16,
        receive_data_length as usize
            + local_address_length as usize
            + remote_address_length as usize
            - 16,
    );
    if native_diagnostic_enabled() {
        eprintln!("native AcceptEx listen={listen_socket:#x} accept={accept_socket:#x} overlapped={overlapped:#x}");
    }
    // The thread waits on its own descriptor for the listening socket, so
    // closing the guest's handle (and the number being reused) cannot point
    // it at another file.
    let watched = unsafe { dup(listener) };
    if watched < 0 {
        native_wsa_set_last_error(10038); // WSAENOTSOCK
        return 0;
    }
    let pending = Arc::new(PendingAccept {
        completed: AtomicBool::new(false),
        overlapped,
    });
    let listener_state = pending_accepts_of(listen_socket);
    if let Ok(mut state) = listener_state.accepts.lock() {
        state.retain(|other| !other.completed.load(Ordering::Acquire));
        state.push(Arc::clone(&pending));
    }
    *listener_state.threads.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    let thread_state = Arc::clone(&listener_state);
    let thread_pending = Arc::clone(&pending);
    let spawned = std::thread::Builder::new()
        .name("winrun-accept-ex".into())
        .spawn(move || {
            accept_ex_wait(watched, accepted, output, address_offsets, &thread_pending, listen_socket);
            unsafe { close(watched) };
            let mut threads = thread_state.threads.lock().unwrap_or_else(|e| e.into_inner());
            *threads -= 1;
            thread_state.exited.notify_all();
        });
    if spawned.is_err() {
        unsafe { close(watched) };
        *listener_state.threads.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        pending.completed.store(true, Ordering::Release);
        native_wsa_set_last_error(10055); // WSAENOBUFS
        return 0;
    }
    native_wsa_set_last_error(997); // WSA_IO_PENDING
    native_set_last_error(997); // ERROR_IO_PENDING
    0
}

/// One `AcceptEx` that has not completed yet.
struct PendingAccept {
    /// Set by whichever finishes it first: a connection or a cancellation.
    completed: AtomicBool,
    overlapped: u64,
}

/// A listening socket's pending `AcceptEx` operations and the threads that
/// wait for their connections.
#[derive(Default)]
struct ListenerAccepts {
    accepts: Mutex<Vec<Arc<PendingAccept>>>,
    threads: Mutex<usize>,
    exited: Condvar,
}

static PENDING_ACCEPTS: LazyLock<Mutex<HashMap<u64, Arc<ListenerAccepts>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn pending_accepts_of(listener: u64) -> Arc<ListenerAccepts> {
    let mut all = PENDING_ACCEPTS.lock().unwrap_or_else(|e| e.into_inner());
    Arc::clone(all.entry(listener).or_default())
}

/// Wait on `watched` (a duplicate of the listening socket) for a connection
/// and complete `pending` with it; give up once `pending` was cancelled.
fn accept_ex_wait(
    watched: i32,
    accepted: i32,
    output: usize,
    address_offsets: (usize, usize),
    pending: &PendingAccept,
    listen_socket: u64,
) {
    loop {
        if pending.completed.load(Ordering::Acquire) {
            return;
        }
        let mut descriptor = NativePollFd {
            fd: watched,
            events: 1,
            revents: 0,
        };
        let result = unsafe { poll(&mut descriptor, 1, 250) };
        if result <= 0 {
            continue; // timeout or EINTR: check for cancellation again
        }
        if pending.completed.load(Ordering::Acquire) {
            return;
        }
        if native_diagnostic_enabled() {
            eprintln!("native AcceptEx listener became readable");
        }
        let mut peer = [0u8; 128];
        let mut peer_length = peer.len() as u32;
        let connection =
            unsafe { libc::accept4(watched, peer.as_mut_ptr().cast(), &mut peer_length, libc::SOCK_NONBLOCK) };
        if connection < 0 {
            let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(9);
            if matches!(error, libc::EINTR | libc::EAGAIN | libc::ECONNABORTED) {
                continue; // another AcceptEx took it, or the client left
            }
            // The listener was shut down: its close cancels this operation.
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        // Blocking like a socket from `socket()`; the guest's ioctlsocket
        // decides otherwise.
        unsafe {
            let flags = libc::fcntl(connection, libc::F_GETFL);
            libc::fcntl(connection, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
        if pending.completed.swap(true, Ordering::AcqRel) {
            unsafe { close(connection) }; // cancelled meanwhile
            return;
        }
        if native_diagnostic_enabled() {
            eprintln!("native AcceptEx accepted fd={connection}");
        }
        if unsafe { dup2(connection, accepted) } < 0 {
            unsafe { close(connection) };
            native_post_socket_failure(listen_socket, pending.overlapped, STATUS_CANCELLED);
            return;
        }
        unsafe { close(connection) };
        write_accept_addresses(accepted, output, address_offsets);
        native_post_pending_socket_completion(listen_socket, pending.overlapped, 0);
        if native_diagnostic_enabled() {
            eprintln!("native AcceptEx completion posted");
        }
        return;
    }
}

/// Write the accepted socket's local and peer addresses where
/// `GetAcceptExSockaddrs` reads them, as Windows `sockaddr`s.
fn write_accept_addresses(accepted: i32, output: usize, offsets: (usize, usize)) {
    for (offset, peer) in [(offsets.0, false), (offsets.1, true)] {
        let mut address = [0u8; 128];
        let mut length = address.len() as u32;
        let found = unsafe {
            if peer {
                getpeername(accepted, address.as_mut_ptr(), &mut length)
            } else {
                getsockname(accepted, address.as_mut_ptr(), &mut length)
            }
        } == 0;
        if !found {
            continue;
        }
        // The slot holds a SOCKADDR_STORAGE-sized address (the slot is
        // `address_length - 16` bytes; libuv passes sizeof(sockaddr_storage)).
        let length = (length as usize).min(28);
        let target = (output + offset) as *mut u8;
        unsafe { ptr::copy_nonoverlapping(address.as_ptr(), target, length) };
        guest_sockaddr_family(target, length as u32);
    }
}

/// Complete every pending `AcceptEx` on `listener` with `STATUS_CANCELLED`
/// (`ERROR_OPERATION_ABORTED`), as closing a listening socket does on
/// Windows, and wait for their threads to let go of the socket.
fn cancel_pending_accepts(listener: u64) {
    let Some(state) = PENDING_ACCEPTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&listener)
    else {
        return;
    };
    let accepts = std::mem::take(&mut *state.accepts.lock().unwrap_or_else(|e| e.into_inner()));
    for pending in accepts {
        if !pending.completed.swap(true, Ordering::AcqRel) {
            native_post_socket_failure(listener, pending.overlapped, STATUS_CANCELLED);
        }
    }
    // Wake the threads (their poll reports the shutdown), so the port is
    // free once closesocket returns.
    unsafe { shutdown(listener as i32, 2) };
    let threads = state.threads.lock().unwrap_or_else(|e| e.into_inner());
    let _ = state
        .exited
        .wait_timeout_while(threads, std::time::Duration::from_secs(2), |threads| *threads != 0);
}

pub(super) extern "win64" fn native_get_accept_ex_sockaddrs(
    output: *mut u8,
    receive_data_length: u32,
    local_address_length: u32,
    remote_address_length: u32,
    local_address: *mut *mut u8,
    local_length: *mut i32,
    remote_address: *mut *mut u8,
    remote_length: *mut i32,
) {
    if output.is_null()
        || local_address.is_null()
        || local_length.is_null()
        || remote_address.is_null()
        || remote_length.is_null()
        || local_address_length < 16
        || remote_address_length < 16
    {
        return;
    }
    let local_offset = receive_data_length as usize + local_address_length as usize - 16;
    let remote_offset = receive_data_length as usize
        + local_address_length as usize
        + remote_address_length as usize
        - 16;
    unsafe {
        local_address.write(output.add(local_offset));
        local_length.write((local_address_length - 16) as i32);
        remote_address.write(output.add(remote_offset));
        remote_length.write((remote_address_length - 16) as i32);
    }
}

pub(super) extern "win64" fn native_getsockname(
    socket: u64,
    address: *mut u8,
    length: *mut i32,
) -> i32 {
    native_socket_name(socket, address, length, false)
}

pub(super) extern "win64" fn native_getpeername(
    socket: u64,
    address: *mut u8,
    length: *mut i32,
) -> i32 {
    native_socket_name(socket, address, length, true)
}

pub(super) fn native_socket_name(
    socket: u64,
    address: *mut u8,
    length: *mut i32,
    peer: bool,
) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
        native_wsa_set_last_error(10038);
        return -1;
    }
    if address.is_null() || length.is_null() || unsafe { length.read_unaligned() } < 0 {
        native_wsa_set_last_error(10014);
        return -1;
    }
    let mut host_length = unsafe { length.read_unaligned() } as u32;
    let result = unsafe {
        let length_ptr = (&mut host_length) as *mut u32;
        if peer {
            getpeername(socket as i32, address, length_ptr)
        } else {
            getsockname(socket as i32, address, length_ptr)
        }
    };
    if result != 0 {
        native_wsa_set_last_error(errno_to_wsa(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(22),
        ));
        return -1;
    }
    if host_length >= 2 {
        unsafe {
            let family = (address as *const u16).read_unaligned();
            if family == 10 {
                (address as *mut u16).write_unaligned(23);
            }
            length.write_unaligned(host_length as i32);
        }
    }
    0
}

pub(super) extern "win64" fn native_setsockopt(
    socket: u64,
    level: i32,
    option: i32,
    value: *const u8,
    length: i32,
) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
        native_wsa_set_last_error(10038);
        return -1;
    }
    if level == 0xffff && option == 0x7010 {
        return 0; // SO_UPDATE_CONNECT_CONTEXT
    }
    if level == 0xffff && option == 0x700b {
        return 0; // SO_UPDATE_ACCEPT_CONTEXT
    }
    if value.is_null() || length < 0 || length > 1024 {
        native_wsa_set_last_error(10014);
        return -1;
    }
    let (host_level, host_option) = match (level, option) {
        (0xffff, 0x0004) => (1, 2), // SO_REUSEADDR
        (0xffff, 0x0008) => (1, 9), // SO_KEEPALIVE
        (0xffff, 0x1001) => (1, 7), // SO_SNDBUF
        (0xffff, 0x1002) => (1, 8), // SO_RCVBUF
        (6, 1) => (6, 1),           // TCP_NODELAY
        (41, 27) => (41, 26),       // IPV6_V6ONLY
        _ => {
            native_wsa_set_last_error(10042);
            return -1;
        }
    };
    let result = unsafe {
        setsockopt(
            socket as i32,
            host_level,
            host_option,
            value.cast(),
            length as u32,
        )
    };
    if result == 0 {
        0
    } else {
        native_wsa_set_last_error(errno_to_wsa(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(22),
        ));
        -1
    }
}

pub(super) fn errno_to_wsa(errno: i32) -> i32 {
    match errno {
        4 => 10004,
        9 => 10009,
        11 | 114 | 115 => 10035,
        32 | 104 => 10054,
        107 => 10057,
        98 => 10048,
        99 => 10049,
        101 => 10051,
        110 => 10060,
        111 => 10061,
        113 => 10065,
        _ => 10022,
    }
}

#[repr(C)]
pub(super) struct NativeWsaBuf {
    length: u32,
    _padding: u32,
    buffer: *mut u8,
}

pub(super) extern "win64" fn native_wsa_send(
    socket: u64,
    buffers: *const NativeWsaBuf,
    buffer_count: u32,
    bytes_sent: *mut u32,
    _flags: u32,
    overlapped: u64,
    _completion: u64,
) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG
        || (buffers.is_null() && buffer_count != 0)
    {
        native_wsa_set_last_error(10014);
        return -1;
    }
    let mut total = 0u32;
    for i in 0..buffer_count as usize {
        let buf = unsafe { buffers.add(i).read_unaligned() };
        if buf.buffer.is_null() && buf.length != 0 {
            native_wsa_set_last_error(10014);
            return -1;
        }
        let mut offset = 0usize;
        while offset < buf.length as usize {
            let count = unsafe {
                send(
                    socket as i32,
                    buf.buffer.add(offset).cast(),
                    buf.length as usize - offset,
                    0x4000,
                )
            };
            if count <= 0 {
                native_wsa_set_last_error(errno_to_wsa(
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(9),
                ));
                return -1;
            }
            offset += count as usize;
            total = total.saturating_add(count as u32);
        }
    }
    if !bytes_sent.is_null() {
        unsafe {
            bytes_sent.write_unaligned(total);
        }
    }
    native_post_socket_completion(socket, overlapped, total);
    0
}

pub(super) extern "win64" fn native_wsa_recv(
    socket: u64,
    buffers: *const NativeWsaBuf,
    buffer_count: u32,
    bytes_received: *mut u32,
    flags: *mut u32,
    overlapped: u64,
    _completion: u64,
) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG
        || (buffers.is_null() && buffer_count != 0)
    {
        native_wsa_set_last_error(10014);
        return -1;
    }
    let mut all_zero = true;
    for i in 0..buffer_count as usize {
        let buf = unsafe { buffers.add(i).read_unaligned() };
        if buf.buffer.is_null() && buf.length != 0 {
            native_wsa_set_last_error(10014);
            return -1;
        }
        all_zero &= buf.length == 0;
    }
    if all_zero && overlapped != 0 {
        let Some(process) = process_ctx() else {
            native_wsa_set_last_error(10022);
            return -1;
        };
        let Some((port, key)) = process
            .socket_completion_ports
            .lock()
            .ok()
            .and_then(|map| map.get(&socket).cloned())
        else {
            native_wsa_set_last_error(10022);
            return -1;
        };
        let fd = socket as i32;
        std::thread::spawn(move || {
            let mut poll_fd = NativePollFd {
                fd,
                events: 1,
                revents: 0,
            };
            loop {
                poll_fd.revents = 0;
                let ready = unsafe { poll(&mut poll_fd, 1, -1) };
                if ready > 0 {
                    break;
                }
                if ready < 0 && std::io::Error::last_os_error().raw_os_error() != Some(4) {
                    break;
                }
            }
            native_set_overlapped_status(overlapped, 0, 0);
            port.post(NativeCompletion {
                key,
                overlapped,
                bytes: 0,
                status: 0,
            });
        });
        native_wsa_set_last_error(997); // WSA_IO_PENDING
        native_set_last_error(997); // libuv checks GetLastError for ERROR_IO_PENDING
        return -1;
    }
    let fd = socket as i32;
    let mut total = 0u32;
    for i in 0..buffer_count as usize {
        let buf = unsafe { buffers.add(i).read_unaligned() };
        let count = unsafe { recv(fd, buf.buffer.cast(), buf.length as usize, 0) };
        if count < 0 {
            let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(9);
            native_wsa_set_last_error(errno_to_wsa(error));
            return -1;
        }
        total = total.saturating_add(count as u32);
        if count == 0 || (count as u32) < buf.length {
            break;
        }
    }
    if !bytes_received.is_null() {
        unsafe {
            bytes_received.write_unaligned(total);
        }
    }
    if !flags.is_null() {
        unsafe {
            flags.write_unaligned(0);
        }
    }
    native_post_socket_completion(socket, overlapped, total);
    0
}

pub(super) extern "win64" fn native_wsa_ioctl(
    socket: u64,
    control_code: u32,
    input: *const u8,
    input_length: u32,
    output: *mut u8,
    output_length: u32,
    bytes_returned: *mut u32,
    _overlapped: u64,
    _completion_routine: u64,
) -> i32 {
    const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
    const WSAID_CONNECTEX: [u8; 16] = [
        0xB9, 0x07, 0xA2, 0x25, 0xF3, 0xDD, 0x60, 0x46, 0x8E, 0xE9, 0x76, 0xE5, 0x8C, 0x74, 0x06,
        0x3E,
    ];
    const WSAID_ACCEPTEX: [u8; 16] = [
        0xF1, 0x7D, 0x36, 0xB5, 0xAC, 0xCB, 0xCF, 0x11, 0x95, 0xCA, 0x00, 0x80, 0x5F, 0x48, 0xA1,
        0x92,
    ];
    const WSAID_GETACCEPTEXSOCKADDRS: [u8; 16] = [
        0xF2, 0x7D, 0x36, 0xB5, 0xAC, 0xCB, 0xCF, 0x11, 0x95, 0xCA, 0x00, 0x80, 0x5F, 0x48, 0xA1,
        0x92,
    ];
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
        native_wsa_set_last_error(10038);
        return -1;
    }
    // SIO_BSP_HANDLE, SIO_BSP_HANDLE_SELECT, SIO_BSP_HANDLE_POLL,
    // SIO_BASE_HANDLE: winrun installs no layered providers, so every
    // socket is its own base provider handle (mio polls it through AFD).
    if matches!(control_code, 0x4800_001B | 0x4800_001C | 0x4800_001D | 0x4800_0022) {
        if output.is_null() || output_length < 8 {
            native_wsa_set_last_error(10014); // WSAEFAULT
            return -1;
        }
        unsafe {
            output.cast::<u64>().write_unaligned(socket);
            if !bytes_returned.is_null() {
                bytes_returned.write_unaligned(8);
            }
        }
        return 0;
    }
    // SIO_KEEPALIVE_VALS: { onoff, keepalivetime ms, keepaliveinterval ms }.
    if control_code == 0x9800_0004 {
        if input.is_null() || input_length < 12 {
            native_wsa_set_last_error(10014);
            return -1;
        }
        let field = |index: usize| unsafe { input.add(index * 4).cast::<u32>().read_unaligned() };
        let fd = socket as u32 as i32;
        let set = |level: i32, name: i32, value: i32| unsafe {
            libc::setsockopt(fd, level, name, (&value as *const i32).cast(), 4) == 0
        };
        let enabled = field(0) != 0;
        let applied = set(libc::SOL_SOCKET, libc::SO_KEEPALIVE, i32::from(enabled))
            && (!enabled
                || (set(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, (field(1) / 1000).max(1) as i32)
                    && set(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, (field(2) / 1000).max(1) as i32)));
        if !applied {
            native_wsa_set_last_error(errno_to_wsa(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(22),
            ));
            return -1;
        }
        if !bytes_returned.is_null() {
            unsafe { bytes_returned.write_unaligned(0) };
        }
        return 0;
    }
    if control_code == SIO_GET_EXTENSION_FUNCTION_POINTER
        && !input.is_null()
        && input_length >= 16
        && !output.is_null()
        && output_length >= 8
        && !bytes_returned.is_null()
        && unsafe { std::slice::from_raw_parts(input, 16) } == WSAID_CONNECTEX
    {
        unsafe {
            output
                .cast::<u64>()
                .write_unaligned(native_connect_ex as *const () as usize as u64);
            bytes_returned.write_unaligned(8);
        }
        return 0;
    }
    if control_code == SIO_GET_EXTENSION_FUNCTION_POINTER
        && !input.is_null()
        && input_length >= 16
        && !output.is_null()
        && output_length >= 8
        && !bytes_returned.is_null()
    {
        let guid = unsafe { std::slice::from_raw_parts(input, 16) };
        let function = if guid == WSAID_ACCEPTEX {
            native_accept_ex as *const () as usize as u64
        } else if guid == WSAID_GETACCEPTEXSOCKADDRS {
            native_get_accept_ex_sockaddrs as *const () as usize as u64
        } else {
            0
        };
        if function != 0 {
            unsafe {
                output.cast::<u64>().write_unaligned(function);
                bytes_returned.write_unaligned(8);
            }
            return 0;
        }
    }
    native_wsa_set_last_error(10022);
    -1
}

pub(super) extern "win64" fn native_connect_ex(
    socket: u64,
    address: *const u8,
    length: i32,
    send_buffer: *const c_void,
    send_length: u32,
    bytes_sent: *mut u32,
    overlapped: u64,
) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG
        || address.is_null()
        || length < 2
        || length > 128
    {
        native_wsa_set_last_error(10014);
        return 0;
    }
    let fd = socket as i32;
    let old_flags = unsafe { fcntl(fd, 3) };
    if old_flags < 0 {
        native_wsa_set_last_error(errno_to_wsa(9));
        return 0;
    }
    if old_flags & 0x800 != 0 {
        unsafe {
            fcntl(fd, 4, old_flags & !0x800);
        }
    }
    let mut translated = [0u8; 128];
    unsafe {
        ptr::copy_nonoverlapping(address, translated.as_mut_ptr(), length as usize);
        let family = (translated.as_ptr() as *const u16).read_unaligned();
        if family == 23 {
            (translated.as_mut_ptr() as *mut u16).write_unaligned(10);
        } else if family != 2 {
            native_wsa_set_last_error(10047);
            if old_flags & 0x800 != 0 {
                fcntl(fd, 4, old_flags);
            }
            return 0;
        }
    }
    let result = unsafe { connect(fd, translated.as_ptr(), length as u32) };
    let error = if result == 0 {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(22)
    };
    if old_flags & 0x800 != 0 {
        unsafe {
            fcntl(fd, 4, old_flags);
        }
    }
    if result != 0 {
        native_wsa_set_last_error(errno_to_wsa(error));
        return 0;
    }
    let mut sent_total = 0u32;
    while sent_total < send_length {
        if send_buffer.is_null() {
            native_wsa_set_last_error(10014);
            return 0;
        }
        let sent = unsafe {
            send(
                fd,
                send_buffer.cast::<u8>().add(sent_total as usize).cast(),
                (send_length - sent_total) as usize,
                0x4000,
            )
        };
        if sent <= 0 {
            native_wsa_set_last_error(errno_to_wsa(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(9),
            ));
            return 0;
        }
        sent_total += sent as u32;
    }
    if !bytes_sent.is_null() {
        unsafe {
            bytes_sent.write_unaligned(sent_total);
        }
    }
    native_post_socket_completion(socket, overlapped, sent_total);
    1
}

pub(super) extern "win64" fn native_ioctlsocket(
    socket: u64,
    command: i32,
    argument: *mut u32,
) -> i32 {
    if socket & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
        native_wsa_set_last_error(10038); // WSAENOTSOCK
        return -1;
    }
    if argument.is_null() {
        native_wsa_set_last_error(10014); // WSAEFAULT
        return -1;
    }
    let host_command = match command as u32 {
        0x8004_667e => 0x5421, // FIONBIO
        0x4004_667f => 0x541b, // FIONREAD
        _ => {
            native_wsa_set_last_error(10022); // WSAEINVAL
            return -1;
        }
    };
    if unsafe { ioctl(socket as i32, host_command, argument.cast()) } == 0 {
        0
    } else {
        native_wsa_set_last_error(10022);
        -1
    }
}

pub(super) extern "win64" fn native_wsa_inet_addr(address: *const u8) -> u32 {
    if address.is_null() {
        return u32::MAX;
    }
    let text = unsafe { std::ffi::CStr::from_ptr(address.cast()) }.to_bytes();
    let Ok(text) = std::str::from_utf8(text) else {
        return u32::MAX;
    };
    text.parse::<std::net::Ipv4Addr>()
        .map(|ip| u32::from_ne_bytes(ip.octets()))
        .unwrap_or(u32::MAX)
}

pub(super) extern "win64" fn native_get_addr_info_w(
    node: *const u16,
    service: *const u16,
    hints: *const u8,
    result: *mut *mut u8,
) -> i32 {
    if result.is_null() {
        return 10014; // WSAEFAULT
    }
    unsafe { result.write(ptr::null_mut()) };
    let to_cstring = |value: *const u16| -> Result<Option<std::ffi::CString>, i32> {
        if value.is_null() {
            return Ok(None);
        }
        let Some(value) = wide(value) else {
            return Err(10014);
        };
        std::ffi::CString::new(value).map(Some).map_err(|_| 10022)
    };
    let node = match to_cstring(node) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let service = match to_cstring(service) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if node.is_none() && service.is_none() {
        return 11001; // WSAHOST_NOT_FOUND
    }
    let mut host_hints = HostAddrInfo {
        flags: 0,
        family: 0,
        socktype: 0,
        protocol: 0,
        addrlen: 0,
        addr: ptr::null_mut(),
        canonname: ptr::null_mut(),
        next: ptr::null_mut(),
    };
    let hints_ptr = if hints.is_null() {
        ptr::null()
    } else {
        let family = unsafe { (hints.add(4) as *const i32).read_unaligned() };
        let family = match family {
            0 | 2 => family,
            23 => 10,
            _ => return 10047, // WSAEAFNOSUPPORT
        };
        host_hints.flags = unsafe { (hints as *const i32).read_unaligned() };
        host_hints.family = family;
        host_hints.socktype = unsafe { (hints.add(8) as *const i32).read_unaligned() };
        host_hints.protocol = unsafe { (hints.add(12) as *const i32).read_unaligned() };
        &host_hints as *const HostAddrInfo
    };
    let (node_ptr, service_ptr) = (
        node.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
        service.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
    );
    if native_diagnostic_enabled() {
        eprintln!(
            "native GetAddrInfoW node={:?} service={:?}",
            node.as_ref().map(|value| value.to_string_lossy()),
            service.as_ref().map(|value| value.to_string_lossy())
        );
    }
    let mut host_result = ptr::null_mut();
    let status = unsafe { getaddrinfo(node_ptr, service_ptr, hints_ptr, &mut host_result) };
    if status != 0 {
        return match status {
            -3 => 11002,  // WSAEAI_AGAIN
            -6 => 10047,  // WSAEAFNOSUPPORT
            -7 => 10044,  // WSAESOCKTNOSUPPORT
            -8 => 10109,  // WSAESERVICE_NOT_FOUND
            -10 => 10055, // WSAENOBUFS
            _ => 11001,   // WSAHOST_NOT_FOUND
        };
    }
    let mut first: *mut u8 = ptr::null_mut();
    let mut tail: *mut u8 = ptr::null_mut();
    let mut current = host_result;
    let mut allocation_failed = false;
    while !current.is_null() {
        let item = unsafe { &*current };
        let record = unsafe { malloc(48) as *mut u8 };
        if record.is_null() {
            allocation_failed = true;
            break;
        }
        unsafe { std::ptr::write_bytes(record, 0, 48) };
        let mut address = ptr::null_mut();
        if !item.addr.is_null() && item.addrlen != 0 {
            address = unsafe { malloc(item.addrlen as usize) as *mut u8 };
            if address.is_null() {
                unsafe { free(record.cast()) };
                allocation_failed = true;
                break;
            }
            unsafe {
                ptr::copy_nonoverlapping(item.addr, address, item.addrlen as usize);
                if item.family == 10 {
                    (address as *mut u16).write_unaligned(23); // Windows AF_INET6
                }
                (record.add(16) as *mut u64).write_unaligned(item.addrlen as u64);
                (record.add(32) as *mut *mut u8).write_unaligned(address);
            }
        }
        if !item.canonname.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr(item.canonname) }.to_string_lossy();
            let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let canonical = unsafe { malloc(wide_name.len() * 2) as *mut u16 };
            if canonical.is_null() {
                if !address.is_null() {
                    unsafe { free(address.cast()) };
                }
                unsafe { free(record.cast()) };
                allocation_failed = true;
                break;
            }
            unsafe {
                ptr::copy_nonoverlapping(wide_name.as_ptr(), canonical, wide_name.len());
                (record.add(24) as *mut *mut u16).write_unaligned(canonical);
            }
        }
        unsafe {
            (record as *mut i32).write_unaligned(item.flags);
            (record.add(4) as *mut i32).write_unaligned(if item.family == 10 {
                23
            } else {
                item.family
            });
            (record.add(8) as *mut i32).write_unaligned(item.socktype);
            (record.add(12) as *mut i32).write_unaligned(item.protocol);
        }
        if first.is_null() {
            first = record;
        }
        if !tail.is_null() {
            unsafe { (tail.add(40) as *mut *mut u8).write_unaligned(record) };
        }
        tail = record;
        current = item.next;
    }
    unsafe { freeaddrinfo(host_result) };
    if allocation_failed {
        native_free_addr_info_w(first);
        return 10055; // WSAENOBUFS
    }
    unsafe { result.write(first) };
    if native_diagnostic_enabled() {
        eprintln!("native GetAddrInfoW status=0 result={first:p}");
    }
    0
}

pub(super) extern "win64" fn native_free_addr_info_w(mut result: *mut u8) {
    if native_diagnostic_enabled() {
        eprintln!("native FreeAddrInfoW result={result:p}");
    }
    while !result.is_null() {
        unsafe {
            let next = (result.add(40) as *mut *mut u8).read_unaligned();
            let address = (result.add(32) as *mut *mut u8).read_unaligned();
            let canonical = (result.add(24) as *mut *mut u16).read_unaligned();
            if native_diagnostic_enabled() {
                eprintln!("native FreeAddrInfoW entry={result:p} address={address:p} canonical={canonical:p} next={next:p}");
            }
            if !address.is_null() {
                free(address.cast());
            }
            if !canonical.is_null() {
                free(canonical.cast());
            }
            free(result.cast());
            result = next;
        }
    }
}

pub(super) extern "win64" fn native_wsa_create_event() -> u64 {
    native_create_event_w(0, 1, 0, ptr::null())
}

pub(super) extern "win64" fn native_wsa_close_event(event: u64) -> i32 {
    native_close_handle(event)
}

pub(super) extern "win64" fn native_wsa_reset_event(event: u64) -> i32 {
    native_reset_event(event)
}

pub(super) extern "win64" fn native_wsa_wait_for_multiple_events(
    count: u32,
    events: *const u64,
    wait_all: i32,
    milliseconds: u32,
    alertable: i32,
) -> u32 {
    if count == 0 || count > 64 || events.is_null() {
        native_wsa_set_last_error(10022);
        return u32::MAX;
    }
    native_wait_for_multiple_objects_ex(count, events, wait_all, milliseconds, alertable)
}

pub(super) extern "win64" fn native_socket(domain: i32, kind: i32, protocol: i32) -> u64 {
    let host_domain = match domain {
        2 => 2,   // AF_INET
        23 => 10, // AF_INET6
        _ => {
            native_wsa_set_last_error(10047); // WSAEAFNOSUPPORT
            return u64::MAX;
        }
    };
    // New WinSock handles are non-inheritable by default. Set CLOEXEC
    // atomically; SetHandleInformation can opt a socket into inheritance.
    const SOCK_CLOEXEC: i32 = 0x0008_0000;
    let fd = unsafe { socket(host_domain, kind | SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        native_wsa_set_last_error(10047);
        u64::MAX
    } else {
        let handle = SOCKET_HANDLE_TAG | fd as u64;
        if let Some(process) = process_ctx() {
            if let Ok(mut sockets) = process.socket_handles.lock() {
                sockets.insert(handle);
            }
        }
        handle
    }
}

pub(super) extern "win64" fn native_close_socket(handle: u64) -> i32 {
    if handle & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
        native_wsa_set_last_error(10038); // WSAENOTSOCK
        return -1;
    }
    // Pending AcceptEx operations complete as aborted, through the
    // completion port the socket is still associated with.
    cancel_pending_accepts(handle);
    if let Some(process) = process_ctx() {
        if let Ok(mut sockets) = process.socket_handles.lock() {
            sockets.remove(&handle);
        }
        if let Ok(mut events) = process.socket_events.lock() {
            events.remove(&handle);
        }
        if let Ok(mut errors) = process.socket_errors.lock() {
            errors.remove(&handle);
        }
        if let Ok(mut associations) = process.socket_completion_ports.lock() {
            associations.remove(&handle);
        }
        if let Ok(mut modes) = process.socket_completion_modes.lock() {
            modes.remove(&handle);
        }
    }
    unsafe {
        shutdown(handle as i32, 2);
    }
    if unsafe { close(handle as i32) } == 0 {
        0
    } else {
        native_wsa_set_last_error(10038);
        -1
    }
}

pub(super) extern "win64" fn native_getsockopt(
    handle: u64,
    level: i32,
    option: i32,
    value: *mut c_void,
    length: *mut u32,
) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native getsockopt level={level:#x} option={option:#x}");
    }
    if handle & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG || value.is_null() || length.is_null() {
        native_wsa_set_last_error(10014); // WSAEFAULT
        return -1;
    }
    if level == 0xffff && option == 0x2005 {
        // SO_PROTOCOL_INFOW
        const WSAPROTOCOL_INFO_W_SIZE: u32 = 628;
        if unsafe { length.read_unaligned() } < WSAPROTOCOL_INFO_W_SIZE {
            native_wsa_set_last_error(10014);
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(value.cast::<u8>(), 0, WSAPROTOCOL_INFO_W_SIZE as usize);
            value.cast::<u32>().write_unaligned(0x0002_0000); // XP1_IFS_HANDLES
            length.write_unaligned(WSAPROTOCOL_INFO_W_SIZE);
        }
        return 0;
    }
    let (host_level, host_option) = match (level, option) {
        (0xffff, 0x1008) => (1, 3),  // SOL_SOCKET, SO_TYPE
        (0xffff, 0x1007) => (1, 4),  // SO_ERROR
        (0xffff, 0x1002) => (1, 8),  // SO_RCVBUF
        (0xffff, 0x1001) => (1, 7),  // SO_SNDBUF
        (0xffff, 0x0002) => (1, 30), // SO_ACCEPTCONN
        (41, 27) => (41, 26),        // IPV6_V6ONLY
        _ => {
            native_wsa_set_last_error(10042); // WSAENOPROTOOPT
            return -1;
        }
    };
    if level == 0xffff && option == 0x1007 {
        if value.is_null() || length.is_null() || unsafe { length.read_unaligned() } < 4 {
            native_wsa_set_last_error(10014);
            return -1;
        }
        if let Some(error) = socket_event_take_error(handle) {
            unsafe {
                value.cast::<i32>().write_unaligned(error);
                length.write_unaligned(4);
            }
            return 0;
        }
    }
    let result = unsafe { getsockopt(handle as i32, host_level, host_option, value, length) };
    if result == 0 && level == 0xffff && option == 0x1007 {
        let error = unsafe { value.cast::<i32>().read_unaligned() };
        if error != 0 {
            unsafe {
                value.cast::<i32>().write_unaligned(errno_to_wsa(error));
            }
        }
    }
    if result != 0 {
        native_wsa_set_last_error(10042);
    }
    result
}

/// Winsock errors live in the thread's last-error value, as on Windows:
/// `WSAGetLastError` is `GetLastError`, which is what Rust's
/// `io::Error::last_os_error()` (and so std, mio, and socket2) reads after
/// a failed socket call.
pub(super) extern "win64" fn native_wsa_get_last_error() -> i32 {
    native_get_last_error() as i32
}

pub(super) extern "win64" fn native_wsa_set_last_error(value: i32) {
    native_set_last_error(value as u32);
}

pub(super) extern "win64" fn native_network_u16(value: u16) -> u16 {
    value.swap_bytes()
}

pub(super) extern "win64" fn native_network_u32(value: u32) -> u32 {
    value.swap_bytes()
}

fn is_socket(handle: u64) -> bool {
    handle & 0xffff_ffff_0000_0000 == SOCKET_HANDLE_TAG
}

fn set_wsa_error_from_errno() {
    native_wsa_set_last_error(errno_to_wsa(
        std::io::Error::last_os_error().raw_os_error().unwrap_or(22),
    ));
}

/// A guest `sockaddr` with the Windows `AF_INET6` (23) rewritten to Linux's
/// (10); only IPv4 and IPv6 are accepted.
fn host_sockaddr(address: *const u8, length: i32) -> Result<[u8; 128], i32> {
    if address.is_null() || !(2..=128).contains(&length) {
        return Err(10014); // WSAEFAULT
    }
    let mut translated = [0u8; 128];
    unsafe { ptr::copy_nonoverlapping(address, translated.as_mut_ptr(), length as usize) };
    match u16::from_le_bytes([translated[0], translated[1]]) {
        2 => {}
        23 => translated[..2].copy_from_slice(&10u16.to_le_bytes()),
        _ => return Err(10047), // WSAEAFNOSUPPORT
    }
    Ok(translated)
}

/// Rewrite a host `sockaddr` written back to the guest to Windows families.
fn guest_sockaddr_family(address: *mut u8, length: u32) {
    if !address.is_null() && length >= 2 && unsafe { (address as *const u16).read_unaligned() } == 10 {
        unsafe { (address as *mut u16).write_unaligned(23) };
    }
}

fn register_socket(fd: i32) -> u64 {
    let handle = SOCKET_HANDLE_TAG | fd as u64;
    if let Some(process) = process_ctx() {
        if let Ok(mut sockets) = process.socket_handles.lock() {
            sockets.insert(handle);
        }
    }
    handle
}

/// `accept(socket, address, length)`: a new non-inheritable socket.
pub(super) extern "win64" fn native_accept_socket(socket: u64, address: *mut u8, length: *mut i32) -> u64 {
    socket_event_rearm(socket, 8);
    if !is_socket(socket) {
        native_wsa_set_last_error(10038); // WSAENOTSOCK
        return u64::MAX;
    }
    let mut host_length = if length.is_null() { 0 } else { unsafe { length.read_unaligned() }.max(0) as u32 };
    let fd = unsafe {
        libc::accept4(
            socket as i32,
            if address.is_null() { ptr::null_mut() } else { address.cast() },
            if length.is_null() { ptr::null_mut() } else { &mut host_length },
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        set_wsa_error_from_errno();
        return u64::MAX;
    }
    if !length.is_null() {
        guest_sockaddr_family(address, host_length);
        unsafe { length.write_unaligned(host_length as i32) };
    }
    register_socket(fd)
}

/// `recv(socket, buffer, length, flags)`: bytes received, 0 at end of stream.
pub(super) extern "win64" fn native_recv_socket(socket: u64, buffer: *mut u8, length: i32, flags: i32) -> i32 {
    native_recvfrom_socket(socket, buffer, length, flags, ptr::null_mut(), ptr::null_mut())
}

pub(super) extern "win64" fn native_recvfrom_socket(
    socket: u64,
    buffer: *mut u8,
    length: i32,
    flags: i32,
    from: *mut u8,
    from_length: *mut i32,
) -> i32 {
    socket_event_rearm(socket, 1 | 4);
    if !is_socket(socket) {
        native_wsa_set_last_error(10038);
        return -1;
    }
    if (buffer.is_null() && length != 0) || length < 0 {
        native_wsa_set_last_error(10014);
        return -1;
    }
    let mut host_length = if from_length.is_null() { 0 } else { unsafe { from_length.read_unaligned() }.max(0) as u32 };
    let received = unsafe {
        libc::recvfrom(
            socket as i32,
            buffer.cast(),
            length as usize,
            flags,
            if from.is_null() { ptr::null_mut() } else { from.cast() },
            if from_length.is_null() { ptr::null_mut() } else { &mut host_length },
        )
    };
    if received < 0 {
        set_wsa_error_from_errno();
        return -1;
    }
    if !from_length.is_null() && !from.is_null() {
        guest_sockaddr_family(from, host_length);
        unsafe { from_length.write_unaligned(host_length as i32) };
    }
    received.min(i32::MAX as isize) as i32
}

pub(super) extern "win64" fn native_sendto_socket(
    socket: u64,
    buffer: *const u8,
    length: i32,
    flags: i32,
    to: *const u8,
    to_length: i32,
) -> i32 {
    if to.is_null() {
        return native_send_socket(socket, buffer, length, flags);
    }
    if !is_socket(socket) {
        native_wsa_set_last_error(10038);
        return -1;
    }
    if (buffer.is_null() && length != 0) || length < 0 {
        native_wsa_set_last_error(10014);
        return -1;
    }
    let address = match host_sockaddr(to, to_length) {
        Ok(address) => address,
        Err(error) => {
            native_wsa_set_last_error(error);
            return -1;
        }
    };
    let sent = unsafe {
        libc::sendto(socket as i32, buffer.cast(), length as usize, flags, address.as_ptr().cast(), to_length as u32)
    };
    if sent < 0 {
        set_wsa_error_from_errno();
        return -1;
    }
    sent.min(i32::MAX as isize) as i32
}

/// `WSASocketW(family, type, protocol, info, group, flags)`: the protocol
/// info and group are not supported; overlapped and non-inheritable
/// sockets need nothing extra.
pub(super) extern "win64" fn native_wsa_socket_w(
    family: i32,
    kind: i32,
    protocol: i32,
    info: *const u8,
    group: u32,
    _flags: u32,
) -> u64 {
    if !info.is_null() || group != 0 {
        native_wsa_set_last_error(10045); // WSAEOPNOTSUPP
        return u64::MAX;
    }
    native_socket(family, kind, protocol)
}

/// `getaddrinfo`: `GetAddrInfoW` with narrow names; canonical names in the
/// result are narrowed in place, so `freeaddrinfo` is `FreeAddrInfoW`.
pub(super) extern "win64" fn native_getaddrinfo(
    node: *const u8,
    service: *const u8,
    hints: *const u8,
    result: *mut *mut u8,
) -> i32 {
    let widen = |value: *const u8| -> Option<Vec<u16>> {
        (!value.is_null()).then(|| {
            let text = unsafe { std::ffi::CStr::from_ptr(value.cast()) }.to_string_lossy();
            text.encode_utf16().chain([0]).collect()
        })
    };
    let (node, service) = (widen(node), widen(service));
    let status = native_get_addr_info_w(
        node.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
        service.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
        hints,
        result,
    );
    if status != 0 || result.is_null() {
        return status;
    }
    let mut record = unsafe { result.read() };
    while !record.is_null() {
        unsafe {
            let canonical = (record.add(24) as *mut *mut u16).read_unaligned();
            if !canonical.is_null() {
                let name = wide(canonical).unwrap_or_default();
                let narrow = std::ffi::CString::new(name).unwrap_or_default();
                let bytes = narrow.as_bytes_with_nul();
                let copy = malloc(bytes.len()) as *mut u8;
                if !copy.is_null() {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), copy, bytes.len());
                }
                free(canonical.cast());
                (record.add(24) as *mut *mut u8).write_unaligned(copy);
            }
            record = (record.add(40) as *mut *mut u8).read_unaligned();
        }
    }
    0
}

#[cfg(test)]
mod named_socket_tests {
    use super::*;

    #[test]
    fn named_winsock_calls_accept_receive_and_datagrams() {
        let listener = native_wsa_socket_w(2, 1, 6, ptr::null(), 0, 0x81);
        assert_ne!(listener, u64::MAX);
        let mut address = [0u8; 16];
        address[..2].copy_from_slice(&2u16.to_le_bytes());
        address[4..8].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(native_bind_socket(listener, address.as_ptr(), 16), 0);
        assert_eq!(native_listen_socket(listener, 1), 0);
        let mut length = 16;
        assert_eq!(native_getsockname(listener, address.as_mut_ptr(), &mut length), 0);
        let client = native_socket(2, 1, 6);
        assert_eq!(native_connect_socket(client, address.as_ptr(), 16), 0);
        let mut peer = [0u8; 16];
        let mut peer_length = 16;
        let server = native_accept_socket(listener, peer.as_mut_ptr(), &mut peer_length);
        assert_ne!(server, u64::MAX);
        assert_eq!(u16::from_le_bytes([peer[0], peer[1]]), 2);
        assert_eq!(native_send_socket(client, b"ping".as_ptr(), 4, 0), 4);
        let mut buffer = [0u8; 8];
        assert_eq!(native_recv_socket(server, buffer.as_mut_ptr(), 8, 0), 4);
        assert_eq!(&buffer[..4], b"ping");
        native_close_socket(client);
        assert_eq!(native_recv_socket(server, buffer.as_mut_ptr(), 8, 0), 0, "end of stream");
        native_close_socket(server);
        native_close_socket(listener);
        assert_eq!(native_recv_socket(0x1234, buffer.as_mut_ptr(), 8, 0), -1);
        assert_eq!(native_wsa_get_last_error(), 10038, "WSAENOTSOCK");

        // UDP: sendto and recvfrom report the sender.
        let receiver = native_socket(2, 2, 17);
        address = [0u8; 16];
        address[..2].copy_from_slice(&2u16.to_le_bytes());
        address[4..8].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(native_bind_socket(receiver, address.as_ptr(), 16), 0);
        length = 16;
        native_getsockname(receiver, address.as_mut_ptr(), &mut length);
        let sender = native_socket(2, 2, 17);
        assert_eq!(native_sendto_socket(sender, b"dgram".as_ptr(), 5, 0, address.as_ptr(), 16), 5);
        let mut from = [0u8; 16];
        let mut from_length = 16;
        assert_eq!(
            native_recvfrom_socket(receiver, buffer.as_mut_ptr(), 8, 0, from.as_mut_ptr(), &mut from_length),
            5
        );
        assert_eq!(&from[4..8], &[127, 0, 0, 1]);
        native_close_socket(sender);
        native_close_socket(receiver);
    }

    #[test]
    fn wsa_ioctl_reports_base_handles_and_sets_keepalive() {
        let socket = native_socket(2, 1, 6);
        let mut base = 0u64;
        let mut returned = 0u32;
        for code in [0x4800_0022u32, 0x4800_001D, 0x4800_001C, 0x4800_001B] {
            assert_eq!(
                native_wsa_ioctl(socket, code, ptr::null(), 0, (&mut base as *mut u64).cast(), 8, &mut returned, 0, 0),
                0
            );
            assert_eq!((base, returned), (socket, 8));
        }
        let keepalive = [1u32, 30_000, 5_000];
        assert_eq!(
            native_wsa_ioctl(socket, 0x9800_0004, keepalive.as_ptr().cast(), 12, ptr::null_mut(), 0, &mut returned, 0, 0),
            0
        );
        let (mut idle, mut size) = (0i32, 4u32);
        unsafe {
            libc::getsockopt(socket as u32 as i32, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, (&mut idle as *mut i32).cast(), &mut size)
        };
        assert_eq!(idle, 30);
        native_close_socket(socket);
    }

    #[test]
    fn winsock_errors_are_the_thread_last_error() {
        native_set_last_error(203);
        assert_eq!(native_connect_socket(0x1234, ptr::null(), 0), -1);
        assert_eq!(native_get_last_error(), 10038, "GetLastError sees WSAENOTSOCK");
        native_set_last_error(5);
        assert_eq!(native_wsa_get_last_error(), 5);
    }

    #[test]
    fn narrow_getaddrinfo_resolves_numeric_hosts() {
        let mut result = ptr::null_mut();
        assert_eq!(native_getaddrinfo(b"127.0.0.1\0".as_ptr(), b"80\0".as_ptr(), ptr::null(), &mut result), 0);
        assert!(!result.is_null());
        let address = unsafe { (result.add(32) as *const *const u8).read_unaligned() };
        assert_eq!(unsafe { std::slice::from_raw_parts(address.add(2), 6) }, &[0, 80, 127, 0, 0, 1]);
        native_free_addr_info_w(result);
    }
}

/// The Linux socket backend has no Windows Winsock provider catalog.
pub(super) extern "win64" fn native_wsa_enum_protocols_w(
    _protocols: *const i32,
    _buffer: *mut u8,
    _length: *mut u32,
) -> i32 {
    native_wsa_set_last_error(10045); // WSAEOPNOTSUPP
    -1
}
