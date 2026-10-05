use super::*;

pub(in crate::native::linux_x86_64) fn native_submit_pipe_io(
    process: &Arc<NativeProcessContext>,
    handle: u64,
    pipe: NativePipeHandle,
    overlapped: u64,
    event: Option<Arc<NativeEvent>>,
    buffer: usize,
    data: Option<Vec<u8>>,
    length: usize,
    completion: Option<NativeIoCompletion>,
) -> Result<(), u32> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let issuer = std::thread::current().id();
    {
        let mut pipes = process.named_pipes.lock().map_err(|_| 6u32)?;
        if !pipe.overlapped || pipes.pending_io.contains_key(&(handle, overlapped)) {
            return Err(87);
        }
        pipes.pending_io.insert(
            (handle, overlapped),
            NativePendingPipeIo {
                cancelled: cancelled.clone(),
                issuer,
            },
        );
    }
    native_set_overlapped_status(overlapped, STATUS_PENDING, 0);
    let worker_pipe = pipe.clone();
    let worker_process = Arc::clone(process);
    let spawn = std::thread::Builder::new()
        .name("winrun-named-pipe-io".into())
        .spawn(move || {
            let is_write = data.is_some();
            let events = if is_write { 0x4 } else { 0x1 };
            let (status, bytes) = loop {
                if cancelled.load(Ordering::Acquire) {
                    // Cancellation races with readiness. If a read already
                    // has bytes (or EOF) waiting, Windows may complete it
                    // normally instead of reporting STATUS_CANCELLED. This
                    // matters for child-process capture, which cancels pipe
                    // reads as soon as the child exits while final output is
                    // still buffered.
                    if !is_write && length != 0 {
                        let count = unsafe {
                            recv(
                                worker_pipe.endpoint.fd,
                                buffer as *mut c_void,
                                length,
                                0x40, // MSG_DONTWAIT
                            )
                        };
                        if count > 0 {
                            break (0, count as u32);
                        }
                        if count == 0 {
                            break (0xc000_014b, 0); // STATUS_PIPE_BROKEN
                        }
                    }
                    break (0xc000_0120, 0); // STATUS_CANCELLED
                }
                let mut descriptor = NativePollFd {
                    fd: worker_pipe.endpoint.fd,
                    events,
                    revents: 0,
                };
                let ready = unsafe { poll(&mut descriptor, 1, 25) };
                if ready < 0 {
                    break (0xc000_0001, 0); // STATUS_UNSUCCESSFUL
                }
                if ready == 0 {
                    continue;
                }
                let count = if let Some(ref payload) = data {
                    unsafe {
                        send(
                            worker_pipe.endpoint.fd,
                            payload.as_ptr().cast(),
                            payload.len(),
                            0x4000,
                        )
                    }
                } else {
                    unsafe { recv(worker_pipe.endpoint.fd, buffer as *mut c_void, length, 0) }
                };
                if count < 0 {
                    continue;
                }
                if count == 0 && !is_write && length != 0 {
                    break (0xc000_014b, 0); // STATUS_PIPE_BROKEN
                }
                break (0, count as u32);
            };
            if native_diagnostic_enabled() {
                eprintln!("native named-pipe completion handle={handle:#x} overlap={overlapped:#x} status={status:#x} bytes={bytes}");
            }
            if let Ok(mut pipes) = worker_process.named_pipes.lock() {
                pipes.pending_io.remove(&(handle, overlapped));
            }
            // Publish completion only after the old request is removed:
            // callers may immediately reuse the same OVERLAPPED address.
            if let Some(completion) = completion {
                native_set_overlapped_status(overlapped, status as u64, bytes);
                completion.complete(overlapped, bytes, status as u64);
            } else {
                native_complete_pipe_io(&worker_pipe, overlapped, bytes, status, event.as_ref());
            }
        });
    if spawn.is_err() {
        if let Ok(mut pipes) = process.named_pipes.lock() {
            pipes.pending_io.remove(&(handle, overlapped));
        }
        return Err(8);
    }
    Ok(())
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_write_file(
    handle: u64,
    buf: *const u8,
    len: u32,
    written: *mut u32,
    overlapped: u64,
) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native WriteFile handle={handle:#x} len={len} overlap={overlapped:#x}");
    }
    if (buf.is_null() && len != 0) || len > 16 * 1024 * 1024 {
        native_set_last_error(87);
        return 0;
    }
    let pipe = process_ctx().and_then(|process| {
        process
            .named_pipes
            .lock()
            .ok()
            .and_then(|pipes| pipes.handles.get(&handle).cloned())
    });
    if let Some(pipe) = pipe {
        let can_write = if pipe.endpoint.server {
            pipe.access & 0x3 & 0x2 != 0
        } else {
            pipe.access & 0x4000_0000 != 0
        };
        if !can_write {
            native_set_last_error(5);
            return 0;
        }
        if len == 0 {
            if !written.is_null() {
                unsafe { written.write(0) };
            }
            return 1;
        }
        if pipe.overlapped && overlapped == 0 {
            native_set_last_error(87);
            return 0;
        }
        if overlapped != 0
            && (overlapped & 7 != 0 || native_overlapped_status(overlapped) == STATUS_PENDING)
        {
            native_set_last_error(87);
            return 0;
        }
        let event = match native_prepare_overlapped_event(overlapped) {
            Ok(event) => event,
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        };
        let payload = if len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(buf, len as usize).to_vec() }
        };
        if overlapped != 0 && pipe.overlapped {
            let Some(process) = process_ctx() else {
                return 0;
            };
            if let Err(error) = native_submit_pipe_io(
                &process,
                handle,
                pipe,
                overlapped,
                event,
                0,
                Some(payload),
                len as usize,
                None,
            ) {
                native_set_last_error(error);
                return 0;
            }
            native_set_last_error(997); // ERROR_IO_PENDING
            return 0;
        }
        let count = unsafe {
            send(
                pipe.endpoint.fd,
                payload.as_ptr().cast(),
                payload.len(),
                0x4000,
            )
        };
        if count < 0 {
            native_complete_synchronous_pipe_io(&pipe, overlapped, 0, 0xc000014b, event.as_ref());
            native_set_last_error(109);
            return 0;
        }
        if !written.is_null() {
            unsafe { written.write(count as u32) };
        }
        native_complete_synchronous_pipe_io(&pipe, overlapped, count as u32, 0, event.as_ref());
        return 1;
    }
    if let Some((device, access)) = native_device(handle) {
        if len != 0 && access & 0x4000_0000 == 0 {
            native_set_last_error(5); // ERROR_ACCESS_DENIED
            return 0;
        }
        let ok = match device {
            NativeDevice::Null => true,
            NativeDevice::Console { output, .. } | NativeDevice::ConsoleOut(output) => {
                let payload = if len == 0 {
                    &[]
                } else {
                    unsafe { std::slice::from_raw_parts(buf, len as usize) }
                };
                native_write_to_handle(output, payload)
            }
            NativeDevice::ConsoleIn(_) => {
                native_set_last_error(5); // ERROR_ACCESS_DENIED
                return 0;
            }
        };
        if !ok {
            native_set_last_error(109); // ERROR_BROKEN_PIPE
            return 0;
        }
        if !written.is_null() {
            unsafe { written.write(len) };
        }
        native_set_last_error(0);
        return 1;
    }
    if !matches!(host_standard_fd(handle), Some(1 | 2)) {
        let context = match fs_ctx() {
            Some(v) => v,
            None => return 0,
        };
        let mut ctx = match context.lock() {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let (path, offset) = match ctx.handles.get(&handle) {
            Some(v) => {
                if ctx
                    .file_access
                    .get(&handle)
                    .is_some_and(|access| access & 0xC000_0000 == 0x8000_0000)
                {
                    native_set_last_error(5);
                    return 0;
                }
                if v.overlapped && overlapped == 0 {
                    native_set_last_error(87);
                    return 0;
                }
                let offset = if overlapped == 0 {
                    Some(v.offset)
                } else {
                    native_overlapped_offset(overlapped)
                };
                let Some(offset) = offset else {
                    native_set_last_error(87);
                    return 0;
                };
                (v.path.clone(), offset)
            }
            None => {
                native_set_last_error(6);
                return 0;
            }
        };
        if !native_file_lock_allows(&ctx, handle, &path, offset as u64, len as u64, true) {
            native_set_last_error(33);
            return 0;
        }
        if overlapped != 0
            && ctx.handles.get(&handle).is_some_and(|file| file.overlapped)
            && (overlapped & 7 != 0 || native_overlapped_status(overlapped) == STATUS_PENDING)
        {
            native_set_last_error(87);
            return 0;
        }
        if overlapped != 0
            && len >= DEFERRED_FILE_IO_MIN
            && ctx.handles.get(&handle).is_some_and(|file| file.overlapped)
        {
            let Some(process) = process_ctx() else {
                return 0;
            };
            let file = ctx.handles.get(&handle).unwrap().clone();
            let data = unsafe { std::slice::from_raw_parts(buf, len as usize).to_vec() };
            if !written.is_null() {
                unsafe { written.write(0) };
            }
            drop(ctx);
            let result = native_submit_file_io(
                &process,
                handle,
                file,
                overlapped,
                offset,
                NativeFileIoOperation::Write { data },
            );
            native_set_last_error(result.err().unwrap_or(997)); // ERROR_IO_PENDING
            return 0;
        }
        let event = match native_prepare_overlapped_event(overlapped) {
            Ok(event) => event,
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        };
        let data = if len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(buf, len as usize) }
        };
        let end = match offset.checked_add(data.len()) {
            Some(v) => v,
            None => return 0,
        };
        if ctx.fs.write_at(&path, offset as u64, data).is_err() {
            native_set_last_error(112); // ERROR_DISK_FULL
            return 0;
        }
        if let Some(file) = ctx.handles.get_mut(&handle) {
            if overlapped == 0 {
                file.offset = end;
            }
            native_complete_file_io(file, overlapped, len, event.as_ref());
        }
        if !written.is_null() {
            unsafe { written.write(len) };
        }
        return 1;
    }
    if buf.is_null() && len != 0 {
        return 0;
    }
    if len == 0 && host_standard_fd(handle).is_some() {
        if !written.is_null() {
            unsafe { written.write(0) };
        }
        return 1;
    }
    // SAFETY: the guest supplied `buf`/`len`; a bad pointer terminates
    // only its isolated native child, never the parent runtime.
    let n = unsafe { write(host_standard_fd(handle).unwrap(), buf.cast(), len as usize) };
    if n < 0 {
        return 0;
    }
    if !written.is_null() {
        // SAFETY: same child-process containment as the input pointer.
        unsafe { written.write(n as u32) };
    }
    1
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_set_named_pipe_handle_state(
    handle: u64,
    mode: *const u32,
    _max_collection_count: *const u32,
    _collect_data_timeout: *const u32,
) -> i32 {
    if host_standard_fd(handle).is_some_and(|fd| unsafe { isatty(fd) } == 0)
        && (mode.is_null() || unsafe { mode.read() } & !0x3 == 0)
    {
        return 1;
    }
    if let Some(process) = process_ctx() {
        if let Ok(mut pipes) = process.named_pipes.lock() {
            if let Some(pipe) = pipes.handles.get_mut(&handle) {
                if mode.is_null() {
                    return 1;
                }
                let mode = unsafe { mode.read() };
                if mode & !0x3 != 0 {
                    native_set_last_error(87);
                    return 0;
                }
                pipe.mode = mode;
                return 1;
            }
        }
    }
    native_set_last_error(6);
    0
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_get_named_pipe_handle_state_w(
    handle: u64,
    mode: *mut u32,
    current_instances: *mut u32,
    _max_collection_count: *mut u32,
    _collect_data_timeout: *mut u32,
    _user_name: *mut u16,
    _max_user_name_size: u32,
) -> i32 {
    if host_standard_fd(handle).is_some_and(|fd| unsafe { isatty(fd) } == 0) {
        if !mode.is_null() {
            unsafe { mode.write(0) };
        }
        if !current_instances.is_null() {
            unsafe { current_instances.write(1) };
        }
        return 1;
    }
    let Some(pipe) = process_ctx().and_then(|process| {
        process
            .named_pipes
            .lock()
            .ok()
            .and_then(|pipes| pipes.handles.get(&handle).cloned())
    }) else {
        native_set_last_error(6);
        return 0;
    };
    if !mode.is_null() {
        unsafe { mode.write(pipe.mode) };
    }
    1
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_get_named_pipe_handle_state_a(
    handle: u64,
    mode: *mut u32,
    current_instances: *mut u32,
    max_collection_count: *mut u32,
    collect_data_timeout: *mut u32,
    user_name: *mut u8,
    max_user_name_size: u32,
) -> i32 {
    if !user_name.is_null() && max_user_name_size != 0 {
        native_set_last_error(50); // ERROR_NOT_SUPPORTED: client identity is not modeled.
        return 0;
    }
    native_get_named_pipe_handle_state_w(
        handle,
        mode,
        current_instances,
        max_collection_count,
        collect_data_timeout,
        std::ptr::null_mut(),
        0,
    )
}

#[cfg(test)]
mod named_pipe_tests {
    use super::*;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    fn server(name: &str, open_mode: u32) -> u64 {
        let path = wide(&format!(r"\\.\pipe\{name}"));
        native_create_named_pipe_w(
            path.as_ptr(),
            open_mode | 0x0004_0000, // WRITE_DAC, as used by libuv
            0,
            1,
            4096,
            4096,
            0,
            0,
        )
    }

    fn client(name: &str, access: u32, flags: u32) -> u64 {
        let path = wide(&format!(r"\\?\pipe\{name}"));
        native_create_file_w(path.as_ptr(), access, 0, 0, 3, flags, 0)
    }

    #[test]
    fn duplicated_pipe_survives_source_close_and_preserves_io() {
        let _process = crate::native::linux_x86_64::context::TestProcessGuard::new();
        let server = server("duplicate-lifetime", 3);
        let client = client("duplicate-lifetime", 0xc000_0000, 0);
        let mut duplicate = 0;
        assert_eq!(native_duplicate_handle(u64::MAX, client, u64::MAX, &mut duplicate, 0, 0, 2), 1);
        assert_ne!(duplicate, client);
        assert_eq!(native_close_handle(client), 1);
        assert_eq!(native_get_file_type(duplicate), 3);
        let mut count = 0;
        assert_eq!(native_write_file(server, b"x".as_ptr(), 1, &mut count, 0), 1);
        let mut byte = 0;
        assert_eq!(native_read_file(duplicate, &mut byte, 1, &mut count, 0), 1);
        assert_eq!((byte, count), (b'x', 1));
        assert_eq!(native_close_handle(duplicate), 1);
        assert_eq!(native_close_handle(server), 1);
    }

    #[test]
    fn named_pipe_pair_connects_and_transfers_duplex_bytes() {
        let name = format!("uv\\winrun-unit-{}", std::process::id());
        let server = server(&name, 3);
        assert_ne!(server, u64::MAX);
        let client = client(&name, 0xc000_0000, 0);
        assert_ne!(client, u64::MAX);
        assert_eq!(native_connect_named_pipe(server, 0), 0);
        assert_eq!(native_get_last_error(), 535);

        let payload = b"duplex-pipe";
        let mut written = 0;
        assert_eq!(
            native_write_file(
                server,
                payload.as_ptr(),
                payload.len() as u32,
                &mut written,
                0
            ),
            1
        );
        assert_eq!(written, payload.len() as u32);
        let mut received = [0u8; 16];
        let mut read = 0;
        assert_eq!(
            native_read_file(
                client,
                received.as_mut_ptr(),
                received.len() as u32,
                &mut read,
                0,
            ),
            1
        );
        assert_eq!(&received[..read as usize], payload);
        assert_eq!(native_get_file_type(server), 3);
        assert_eq!(native_close_handle(client), 1);
        assert_eq!(native_close_handle(server), 1);
    }

    #[test]
    fn connected_pipe_releases_pending_client_reference_for_eof() {
        let name = format!("uv\\winrun-eof-{}", std::process::id());
        let server = server(&name, 1); // Server reads; child client writes.
        assert_ne!(server, u64::MAX);
        let client = client(&name, 0x4000_0000, 0);
        assert_ne!(client, u64::MAX);
        assert_eq!(native_connect_named_pipe(server, 0), 0);
        assert_eq!(native_get_last_error(), 535);
        let payload = b"captured-output";
        let mut written = 0;
        assert_eq!(
            native_write_file(
                client,
                payload.as_ptr(),
                payload.len() as u32,
                &mut written,
                0
            ),
            1
        );
        assert_eq!(written, payload.len() as u32);
        assert_eq!(native_close_handle(client), 1);

        let process = process_ctx().expect("native process context");
        let pipes = process.named_pipes.lock().unwrap();
        let endpoint = pipes.handles.get(&server).unwrap().endpoint.fd;
        let mut captured = [0u8; 64];
        assert_eq!(
            unsafe { recv(endpoint, captured.as_mut_ptr().cast(), captured.len(), 0) },
            payload.len() as isize
        );
        assert_eq!(&captured[..payload.len()], payload);
        assert_eq!(
            unsafe { recv(endpoint, captured.as_mut_ptr().cast(), captured.len(), 0) },
            0,
            "closing the client write endpoint must deliver EOF after buffered output"
        );
        drop(pipes);
        assert_eq!(native_close_handle(server), 1);
    }

    #[test]
    fn named_pipe_checks_client_direction_and_supports_overlapped_completion() {
        let name = format!("uv\\winrun-io-{}", std::process::id());
        let server = server(&name, 2); // Server writes; client must read.
        assert_ne!(server, u64::MAX);
        assert_eq!(client(&name, 0x4000_0000, 0), u64::MAX);
        assert_eq!(native_get_last_error(), 5);
        let client = client(&name, 0x8000_0000, 0x4000_0000);
        assert_ne!(client, u64::MAX);
        assert_eq!(native_connect_named_pipe(server, 0), 0);
        assert_eq!(native_get_last_error(), 535);

        let port_handle = native_create_io_completion_port(u64::MAX, 0, 0, 1);
        assert_ne!(port_handle, 0);
        assert_eq!(
            native_create_io_completion_port(client, port_handle, 0x1234, 1),
            port_handle
        );
        assert_eq!(
            native_set_file_completion_notification_modes(client, 0x3),
            1
        );
        let mut overlapped = [0u64; 4];
        let mut received = [0u8; 32];
        assert_eq!(
            native_read_file(
                client,
                received.as_mut_ptr(),
                received.len() as u32,
                std::ptr::null_mut(),
                overlapped.as_mut_ptr() as u64,
            ),
            0
        );
        assert_eq!(native_get_last_error(), 997);
        let payload = b"async-pipe";
        let mut written = 0;
        assert_eq!(
            native_write_file(
                server,
                payload.as_ptr(),
                payload.len() as u32,
                &mut written,
                0
            ),
            1
        );
        let process = process_ctx().unwrap();
        let port = process
            .completion_ports
            .lock()
            .unwrap()
            .get(&port_handle)
            .unwrap()
            .clone();
        let mut queue = port.queue.lock().unwrap();
        while queue.is_empty() {
            queue = port.ready.wait(queue).unwrap();
        }
        let completion = queue.pop_front().unwrap();
        assert_eq!(completion.key, 0x1234);
        assert_eq!(completion.overlapped, overlapped.as_ptr() as u64);
        assert_eq!(completion.status, 0);
        assert_eq!(completion.bytes, payload.len() as u32);
        assert_eq!(&received[..completion.bytes as usize], payload);
        drop(queue);
        assert_eq!(native_close_handle(client), 1);
        assert_eq!(native_close_handle(server), 1);
        assert_eq!(native_close_handle(port_handle), 1);
    }

    #[test]
    fn named_pipe_overlapped_connect_completes_when_client_arrives_later() {
        let name = format!("uv\\winrun-connect-{}", std::process::id());
        let server = server(&name, 0x4000_0003);
        assert_ne!(server, u64::MAX);
        let port = native_create_io_completion_port(u64::MAX, 0, 0, 1);
        assert_eq!(
            native_create_io_completion_port(server, port, 0x5678, 1),
            port
        );
        let mut overlapped = [0u64; 4];
        assert_eq!(
            native_connect_named_pipe(server, overlapped.as_mut_ptr() as u64),
            0
        );
        assert_eq!(native_get_last_error(), 997);
        let client = client(&name, 0xc000_0000, 0x4000_0000);
        assert_ne!(client, u64::MAX);

        let process = process_ctx().unwrap();
        let completion_port = process
            .completion_ports
            .lock()
            .unwrap()
            .get(&port)
            .unwrap()
            .clone();
        let mut queue = completion_port.queue.lock().unwrap();
        while queue.is_empty() {
            queue = completion_port.ready.wait(queue).unwrap();
        }
        let completion = queue.pop_front().unwrap();
        assert_eq!(completion.key, 0x5678);
        assert_eq!(completion.overlapped, overlapped.as_ptr() as u64);
        assert_eq!(completion.status, 0);
        drop(queue);
        assert_eq!(native_close_handle(client), 1);
        assert_eq!(native_close_handle(server), 1);
        assert_eq!(native_close_handle(port), 1);
    }

    #[test]
    fn process_startup_inherits_the_requested_windows_standard_handles() {
        let mut startup = [0u8; 104];
        unsafe {
            startup
                .as_mut_ptr()
                .add(60)
                .cast::<u32>()
                .write_unaligned(0x100);
            startup
                .as_mut_ptr()
                .add(80)
                .cast::<u64>()
                .write_unaligned(0xb000_0001);
            startup
                .as_mut_ptr()
                .add(88)
                .cast::<u64>()
                .write_unaligned(0xb000_0003);
            startup
                .as_mut_ptr()
                .add(96)
                .cast::<u64>()
                .write_unaligned(0xb000_0005);
        }
        assert_eq!(
            native_startup_std_handles(
                startup.as_ptr() as u64,
                [0x5000_0000, 0x5000_0001, 0x5000_0002]
            ),
            [0xb000_0001, 0xb000_0003, 0xb000_0005]
        );
        unsafe {
            startup
                .as_mut_ptr()
                .add(60)
                .cast::<u32>()
                .write_unaligned(0)
        };
        assert_eq!(
            native_startup_std_handles(
                startup.as_ptr() as u64,
                [0x5000_0000, 0x5000_0001, 0x5000_0002]
            ),
            [0x5000_0000, 0x5000_0001, 0x5000_0002]
        );
    }
}
