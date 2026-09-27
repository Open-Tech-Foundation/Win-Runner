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
    value.description[..6].copy_from_slice(b"WinCLI");
    value.system_status[..7].copy_from_slice(b"Running");
    unsafe { data.write(value) };
    0
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
        return 0;
    }
    native_wsa_set_last_error(match std::io::Error::last_os_error().raw_os_error() {
        Some(11 | 114 | 115) => 10035, // WSAEWOULDBLOCK / in progress
        Some(111) => 10061,            // WSAECONNREFUSED
        Some(110) => 10060,            // WSAETIMEDOUT
        Some(99) => 10049,             // WSAEADDRNOTAVAIL
        Some(101) => 10051,            // WSAENETUNREACH
        _ => 10022,                    // WSAEINVAL
    });
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
        native_wsa_set_last_error(errno_to_wsa(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(9),
        ));
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
    if std::thread::Builder::new()
        .name("wincli-accept-ex".into())
        .spawn(move || loop {
            let mut descriptor = NativePollFd {
                fd: listener,
                events: 1,
                revents: 0,
            };
            let result = unsafe { poll(&mut descriptor, 1, 250) };
            if result < 0 {
                let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(9);
                if error == 4 {
                    continue;
                }
                return;
            }
            if result == 0 {
                continue;
            }
            if native_diagnostic_enabled() {
                eprintln!("native AcceptEx listener became readable");
            }
            let mut peer = [0u8; 128];
            let mut peer_length = peer.len() as u32;
            let connection = unsafe { accept(listener, peer.as_mut_ptr(), &mut peer_length) };
            if connection < 0 {
                let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(9);
                if matches!(error, 4 | 11 | 35) {
                    continue;
                }
                return;
            }
            if native_diagnostic_enabled() {
                eprintln!("native AcceptEx accepted fd={connection}");
            }
            if unsafe { dup2(connection, accepted) } < 0 {
                unsafe { close(connection) };
                return;
            }
            unsafe { close(connection) };
            let mut local = [0u8; 128];
            let mut local_length = local.len() as u32;
            let mut peer = [0u8; 128];
            let mut peer_length = peer.len() as u32;
            if unsafe { getsockname(accepted, local.as_mut_ptr(), &mut local_length) } != 0
                || unsafe { getpeername(accepted, peer.as_mut_ptr(), &mut peer_length) } != 0
            {
                return;
            }
            unsafe {
                ptr::copy_nonoverlapping(
                    local.as_ptr(),
                    (output + address_offsets.0) as *mut u8,
                    16,
                );
                ptr::copy_nonoverlapping(
                    peer.as_ptr(),
                    (output + address_offsets.1) as *mut u8,
                    16,
                );
            }
            native_post_pending_socket_completion(listen_socket, overlapped, 0);
            if native_diagnostic_enabled() {
                eprintln!("native AcceptEx completion posted");
            }
            break;
        })
        .is_err()
    {
        native_wsa_set_last_error(10055); // WSAENOBUFS
        return 0;
    }
    native_wsa_set_last_error(997); // WSA_IO_PENDING
    native_set_last_error(997); // ERROR_IO_PENDING
    0
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

fn errno_to_wsa(errno: i32) -> i32 {
    match errno {
        4 => 10004,
        9 => 10009,
        11 | 114 | 115 => 10035,
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
            if let Ok(mut queue) = port.queue.lock() {
                queue.push_back(NativeCompletion {
                    key,
                    overlapped,
                    bytes: 0,
                    status: 0,
                });
                port.ready.notify_one();
            }
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

pub(super) extern "win64" fn native_socket(domain: i32, kind: i32, protocol: i32) -> u64 {
    let host_domain = match domain {
        2 => 2,   // AF_INET
        23 => 10, // AF_INET6
        _ => {
            native_wsa_set_last_error(10047); // WSAEAFNOSUPPORT
            return u64::MAX;
        }
    };
    let fd = unsafe { socket(host_domain, kind, protocol) };
    if fd < 0 {
        native_wsa_set_last_error(10047);
        u64::MAX
    } else {
        SOCKET_HANDLE_TAG | fd as u64
    }
}

pub(super) extern "win64" fn native_close_socket(handle: u64) -> i32 {
    if handle & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG {
        native_wsa_set_last_error(10038); // WSAENOTSOCK
        return -1;
    }
    if let Some(process) = process_ctx() {
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
    let result = unsafe { getsockopt(handle as i32, host_level, host_option, value, length) };
    if result != 0 {
        native_wsa_set_last_error(10042);
    }
    result
}

pub(super) extern "win64" fn native_wsa_get_last_error() -> i32 {
    THREAD_WSA_ERROR.with(|error| error.get())
}

pub(super) extern "win64" fn native_wsa_set_last_error(value: i32) {
    THREAD_WSA_ERROR.with(|error| error.set(value));
}
