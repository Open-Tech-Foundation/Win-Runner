//! Winsock event selection backed by Linux socket readiness.
use super::*;

pub(super) struct NativeSocketEvent {
    event: u64,
    mask: u32,
    armed: u32,
    pending: u32,
    errors: [i32; 10],
    connecting: bool,
}

unsafe fn fd_set_values(set: *const u8) -> Result<Vec<u64>, i32> {
    if set.is_null() {
        return Ok(Vec::new());
    }
    let count = unsafe { set.cast::<u32>().read_unaligned() } as usize;
    if count > 1024 {
        return Err(10022);
    }
    Ok((0..count)
        .map(|index| unsafe { set.add(8 + index * 8).cast::<u64>().read_unaligned() })
        .collect())
}

pub(super) extern "win64" fn native_wsa_fd_is_set(socket: u64, set: *const u8) -> i32 {
    unsafe { fd_set_values(set) }.is_ok_and(|values| values.contains(&socket)) as i32
}

pub(super) extern "win64" fn native_select(
    _nfds: i32,
    read: *mut u8,
    write: *mut u8,
    except: *mut u8,
    timeout: *const i32,
) -> i32 {
    let sets = [read, write, except];
    let values = match sets
        .iter()
        .map(|set| unsafe { fd_set_values(*set) })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(values) => values,
        Err(error) => {
            native_wsa_set_last_error(error);
            return -1;
        }
    };
    let Some(process) = process_ctx() else {
        return -1;
    };
    if values.iter().all(Vec::is_empty) {
        native_wsa_set_last_error(10022);
        return -1;
    }
    if !process.socket_handles.lock().is_ok_and(|sockets| {
        values
            .iter()
            .flatten()
            .all(|handle| sockets.contains(handle))
    }) {
        native_wsa_set_last_error(10038);
        return -1;
    }
    let milliseconds = if timeout.is_null() {
        -1
    } else {
        let seconds = unsafe { timeout.read_unaligned() };
        let micros = unsafe { timeout.add(1).read_unaligned() };
        if seconds < 0 || !(0..1_000_000).contains(&micros) {
            native_wsa_set_last_error(10022);
            return -1;
        }
        (seconds as i64 * 1000 + (micros as i64 + 999) / 1000).min(i32::MAX as i64) as i32
    };
    let mut handles = values.iter().flatten().copied().collect::<Vec<_>>();
    handles.sort();
    handles.dedup();
    let mut polls = handles
        .iter()
        .map(|handle| libc::pollfd {
            fd: *handle as i32,
            events: (if values[0].contains(handle) {
                libc::POLLIN
            } else {
                0
            }) | (if values[1].contains(handle) {
                libc::POLLOUT
            } else {
                0
            }) | (if values[2].contains(handle) {
                libc::POLLPRI
            } else {
                0
            }),
            revents: 0,
        })
        .collect::<Vec<_>>();
    if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, milliseconds) } < 0 {
        native_wsa_set_last_error(super::sockets::errno_to_wsa(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(9),
        ));
        return -1;
    }
    if polls.iter().any(|poll| poll.revents & libc::POLLNVAL != 0) {
        native_wsa_set_last_error(10038);
        return -1;
    }
    let mut total = 0;
    for (index, set) in sets.iter().enumerate() {
        if set.is_null() {
            continue;
        }
        let ready = values[index]
            .iter()
            .filter(|handle| {
                let bits = polls[handles.binary_search(handle).unwrap()].revents;
                match index {
                    0 => bits & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0,
                    1 => bits & libc::POLLOUT != 0 && bits & libc::POLLERR == 0,
                    _ => bits & (libc::POLLPRI | libc::POLLERR) != 0,
                }
            })
            .copied()
            .collect::<Vec<_>>();
        unsafe {
            set.cast::<u32>().write_unaligned(ready.len() as u32);
            for (i, handle) in ready.iter().enumerate() {
                set.add(8 + i * 8).cast::<u64>().write_unaligned(*handle);
            }
        }
        total += ready.len() as i32;
    }
    total
}

pub(super) extern "win64" fn native_inet_pton(
    family: i32,
    text: *const u8,
    output: *mut u8,
) -> i32 {
    if text.is_null() || output.is_null() {
        native_wsa_set_last_error(10014);
        return -1;
    }
    let Ok(text) = unsafe { std::ffi::CStr::from_ptr(text.cast()) }.to_str() else {
        return 0;
    };
    match family {
        2 => match text.parse::<std::net::Ipv4Addr>() {
            Ok(address) => {
                unsafe {
                    output.copy_from_nonoverlapping(address.octets().as_ptr(), 4);
                }
                1
            }
            Err(_) => 0,
        },
        23 => match text.parse::<std::net::Ipv6Addr>() {
            Ok(address) => {
                unsafe {
                    output.copy_from_nonoverlapping(address.octets().as_ptr(), 16);
                }
                1
            }
            Err(_) => 0,
        },
        _ => {
            native_wsa_set_last_error(10047);
            -1
        }
    }
}

pub(super) extern "win64" fn native_wsa_event_select(socket: u64, event: u64, mask: i32) -> i32 {
    let Some(process) = process_ctx() else {
        return -1;
    };
    if !process
        .socket_handles
        .lock()
        .is_ok_and(|sockets| sockets.contains(&socket))
    {
        native_wsa_set_last_error(10038);
        return -1;
    }
    if mask == 0 {
        if let Ok(mut events) = process.socket_events.lock() {
            events.remove(&socket);
        }
        return 0;
    }
    if mask < 0 || mask & !63 != 0 {
        native_wsa_set_last_error(10045);
        return -1;
    }
    if !process
        .events
        .lock()
        .is_ok_and(|events| events.contains_key(&event))
    {
        native_wsa_set_last_error(10022);
        return -1;
    }
    let fd = socket as i32;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        native_wsa_set_last_error(10038);
        return -1;
    }
    let Ok(mut events) = process.socket_events.lock() else {
        return -1;
    };
    events.insert(
        socket,
        NativeSocketEvent {
            event,
            mask: mask as u32,
            armed: mask as u32,
            pending: 0,
            errors: [0; 10],
            connecting: false,
        },
    );
    0
}

pub(super) fn socket_event_rearm(socket: u64, bits: u32) {
    if let Some(process) = process_ctx() {
        if let Ok(mut events) = process.socket_events.lock() {
            if let Some(event) = events.get_mut(&socket) {
                event.armed |= bits & event.mask;
            }
        }
    }
}

pub(super) fn socket_event_connect(socket: u64) {
    if let Some(process) = process_ctx() {
        if let Ok(mut events) = process.socket_events.lock() {
            if let Some(event) = events.get_mut(&socket) {
                event.connecting = true;
                event.armed |= 16 & event.mask;
            }
        }
    }
}

fn refresh(process: &NativeProcessContext, handle: u64) {
    let Ok(mut selections) = process.socket_events.lock() else {
        return;
    };
    for (socket, selection) in selections
        .iter_mut()
        .filter(|(_, selection)| selection.event == handle)
    {
        let mut poll = libc::pollfd {
            fd: *socket as i32,
            events: 0,
            revents: 0,
        };
        if selection.armed & (1 | 8 | 32) != 0 {
            poll.events |= libc::POLLIN | libc::POLLRDHUP;
        }
        if selection.armed & 2 != 0 || selection.connecting {
            poll.events |= libc::POLLOUT;
        }
        if selection.armed & 4 != 0 {
            poll.events |= libc::POLLPRI;
        }
        if unsafe { libc::poll(&mut poll, 1, 0) } <= 0 {
            continue;
        }
        let ready = poll.revents;
        let mut bits = 0;
        if ready & libc::POLLIN != 0 {
            bits |= selection.armed & (1 | 8);
        }
        if ready & libc::POLLPRI != 0 {
            bits |= selection.armed & 4;
        }
        if ready & libc::POLLOUT != 0 {
            bits |= selection.armed & 2;
        }
        if ready & (libc::POLLHUP | libc::POLLRDHUP) != 0 {
            bits |= selection.armed & 32;
        }
        if selection.connecting && ready & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0 {
            let mut error: i32 = 0;
            let mut size = 4;
            unsafe {
                libc::getsockopt(
                    *socket as i32,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut i32).cast(),
                    &mut size,
                );
            }
            selection.errors[4] = if error == 0 {
                0
            } else {
                super::sockets::errno_to_wsa(error)
            };
            if error != 0 {
                if let Ok(mut errors) = process.socket_errors.lock() {
                    errors.insert(*socket, selection.errors[4]);
                }
            }
            bits |= selection.armed & 16;
            selection.connecting = false;
        }
        selection.pending |= bits;
        selection.armed &= !bits;
        if bits != 0 {
            if let Some(event) = process
                .events
                .lock()
                .ok()
                .and_then(|events| events.get(&handle).cloned())
            {
                if let Ok(mut signaled) = event.signaled.lock() {
                    *signaled = true;
                    event.ready.notify_all();
                }
            }
        }
    }
}

pub(super) fn socket_event_take_error(socket: u64) -> Option<i32> {
    let process = process_ctx()?;
    let error = process.socket_errors.lock().ok()?.remove(&socket);
    error
}

pub(super) fn socket_event_wait(
    process: &NativeProcessContext,
    handle: u64,
    event: &NativeEvent,
    milliseconds: u32,
) -> Option<u32> {
    if !process
        .socket_events
        .lock()
        .is_ok_and(|events| events.values().any(|selection| selection.event == handle))
    {
        return None;
    }
    let deadline = (milliseconds != u32::MAX)
        .then(|| std::time::Instant::now() + std::time::Duration::from_millis(milliseconds as u64));
    loop {
        refresh(process, handle);
        if native_wait_event(event, 0) == 0 {
            return Some(0);
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Some(258);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

pub(super) extern "win64" fn native_wsa_enum_network_events(
    socket: u64,
    event: u64,
    output: *mut u8,
) -> i32 {
    if output.is_null() {
        native_wsa_set_last_error(10014);
        return -1;
    }
    let Some(process) = process_ctx() else {
        return -1;
    };
    if event != 0
        && !process
            .events
            .lock()
            .is_ok_and(|events| events.contains_key(&event))
    {
        native_wsa_set_last_error(10022);
        return -1;
    }
    let Ok(mut selections) = process.socket_events.lock() else {
        return -1;
    };
    let Some(selection) = selections.get_mut(&socket) else {
        native_wsa_set_last_error(10038);
        return -1;
    };
    unsafe {
        output.cast::<u32>().write_unaligned(selection.pending);
        for (index, error) in selection.errors.iter().enumerate() {
            output
                .add(4 + index * 4)
                .cast::<i32>()
                .write_unaligned(*error);
        }
    }
    selection.pending = 0;
    selection.errors = [0; 10];
    drop(selections);
    if event != 0 {
        native_reset_event(event);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn connected() -> (u64, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut address = [0u8; 16];
        address[0] = 2;
        address[2..4].copy_from_slice(&listener.local_addr().unwrap().port().to_be_bytes());
        address[4..8].copy_from_slice(&[127, 0, 0, 1]);
        let socket = native_socket(2, 1, 6);
        assert_eq!(native_connect_socket(socket, address.as_ptr(), 16), 0);
        (socket, listener.accept().unwrap().0)
    }
    #[test]
    fn winsock_events_record_reset_rearm_and_report_peer_close() {
        let process = new_test_process();
        let previous = THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(process)));
        let (socket, mut peer) = connected();
        let event = native_wsa_create_event();
        assert_eq!(native_wsa_event_select(socket, event, 1 | 2 | 32), 0);
        assert_eq!(native_wait_for_single_object(event, 1000), 0);
        let mut records = [0u32; 11];
        assert_eq!(
            native_wsa_enum_network_events(socket, event, records.as_mut_ptr().cast()),
            0
        );
        assert_eq!(records[0], 2);
        assert_eq!(native_wsa_wait_for_multiple_events(1, &event, 0, 0, 0), 258);
        peer.write_all(b"abc").unwrap();
        assert_eq!(
            native_wsa_wait_for_multiple_events(1, &event, 0, 1000, 0),
            0
        );
        assert_eq!(
            native_wsa_enum_network_events(socket, event, records.as_mut_ptr().cast()),
            0
        );
        assert_eq!(records[0], 1);
        assert_eq!(native_wait_for_single_object(event, 0), 258);
        let mut bytes = [0; 3];
        assert_eq!(native_recv_socket(socket, bytes.as_mut_ptr(), 1, 0), 1);
        assert_eq!(native_wait_for_single_object(event, 1000), 0);
        assert_eq!(
            native_wsa_enum_network_events(socket, event, records.as_mut_ptr().cast()),
            0
        );
        assert_eq!(records[0], 1);
        assert_eq!(
            native_recv_socket(socket, bytes.as_mut_ptr().wrapping_add(1), 2, 0),
            2
        );
        assert_eq!(bytes, *b"abc");
        drop(peer);
        assert_eq!(native_wait_for_single_object(event, 1000), 0);
        native_wsa_enum_network_events(socket, event, records.as_mut_ptr().cast());
        assert_ne!(records[0] & 32, 0);
        assert_eq!(native_wsa_event_select(socket, 0, 0), 0);
        assert_eq!(native_close_socket(socket), 0);
        assert_eq!(native_wsa_close_event(event), 1);
        assert_eq!(
            native_wsa_wait_for_multiple_events(0, ptr::null(), 0, 0, 0),
            u32::MAX
        );
        assert_eq!(native_wsa_get_last_error(), 10022);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(previous));
    }
    #[test]
    fn pending_socket_errors_survive_event_cancellation_and_are_consumed_once() {
        let previous = THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(new_test_process())));
        let (socket, _peer) = connected();
        let event = native_wsa_create_event();
        assert_eq!(native_wsa_event_select(socket, event, 16), 0);
        process_ctx()
            .unwrap()
            .socket_errors
            .lock()
            .unwrap()
            .insert(socket, 10061);
        assert_eq!(native_wsa_event_select(socket, 0, 0), 0);
        let mut error = 0i32;
        let mut size = 4u32;
        assert_eq!(
            native_getsockopt(
                socket,
                0xffff,
                0x1007,
                (&mut error as *mut i32).cast(),
                &mut size
            ),
            0
        );
        assert_eq!(error, 10061);
        assert_eq!(
            native_getsockopt(
                socket,
                0xffff,
                0x1007,
                (&mut error as *mut i32).cast(),
                &mut size
            ),
            0
        );
        assert_eq!(error, 0);
        assert_eq!(errno_to_wsa(libc::ECONNRESET), 10054);
        assert_eq!(errno_to_wsa(libc::EPIPE), 10054);
        native_close_socket(socket);
        native_wsa_close_event(event);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(previous));
    }
    #[test]
    fn select_uses_windows_fd_sets_and_validates_sockets_and_timeouts() {
        let previous = THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(new_test_process())));
        let (socket, mut peer) = connected();
        let mut read = [1u64, socket];
        let timeout = [0, 0];
        assert_eq!(native_wsa_fd_is_set(socket, read.as_ptr().cast()), 1);
        assert_eq!(
            native_select(
                0,
                read.as_mut_ptr().cast(),
                ptr::null_mut(),
                ptr::null_mut(),
                timeout.as_ptr()
            ),
            0
        );
        assert_eq!(read[0], 0);
        peer.write_all(b"x").unwrap();
        read[0] = 1;
        assert_eq!(
            native_select(
                0,
                read.as_mut_ptr().cast(),
                ptr::null_mut(),
                ptr::null_mut(),
                [1, 0].as_ptr()
            ),
            1
        );
        assert_eq!(read, [1, socket]);
        assert_eq!(
            native_select(
                0,
                read.as_mut_ptr().cast(),
                ptr::null_mut(),
                ptr::null_mut(),
                [-1, 0].as_ptr()
            ),
            -1
        );
        assert_eq!(native_wsa_get_last_error(), 10022);
        read[1] = 0xdead;
        assert_eq!(
            native_select(
                0,
                read.as_mut_ptr().cast(),
                ptr::null_mut(),
                ptr::null_mut(),
                timeout.as_ptr()
            ),
            -1
        );
        assert_eq!(native_wsa_get_last_error(), 10038);
        native_close_socket(socket);
        let mut address = [0; 16];
        assert_eq!(
            native_inet_pton(2, c"127.0.0.1".as_ptr().cast(), address.as_mut_ptr()),
            1
        );
        assert_eq!(&address[..4], &[127, 0, 0, 1]);
        assert_eq!(
            native_inet_pton(23, c"::1".as_ptr().cast(), address.as_mut_ptr()),
            1
        );
        assert_eq!(address[15], 1);
        assert_eq!(
            native_inet_pton(2, c"invalid".as_ptr().cast(), address.as_mut_ptr()),
            0
        );
        assert_eq!(
            native_inet_pton(99, c"127.0.0.1".as_ptr().cast(), address.as_mut_ptr()),
            -1
        );
        assert_eq!(native_wsa_get_last_error(), 10047);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(previous));
    }
}
