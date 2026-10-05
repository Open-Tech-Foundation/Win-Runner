//! Windows standard streams and generic handle API shims.

use super::*;

pub(super) extern "win64" fn native_get_std_handle(which: u32) -> u64 {
    let index = match which as i32 {
        -10 => 0,
        -11 => 1,
        -12 => 2,
        _ => return u64::MAX,
    };
    let handle = process_ctx()
        .map(|process| process.std_handles[index].load(Ordering::Acquire))
        .unwrap_or(u64::MAX);
    if native_diagnostic_enabled() {
        eprintln!("native GetStdHandle which={which:#x} handle={handle:#x}");
    }
    handle
}
pub(super) extern "win64" fn native_crt_get_osfhandle(fd: i32) -> u64 {
    let Some(process) = process_ctx() else {
        return u64::MAX;
    };
    let handle = if (0..3).contains(&fd) {
        process.std_handles[fd as usize].load(Ordering::Acquire)
    } else {
        process
            .crt_fds
            .lock()
            .ok()
            .and_then(|fds| fds.get(&fd).copied())
            .unwrap_or(u64::MAX)
    };
    if native_diagnostic_enabled() {
        eprintln!("native CRT _get_osfhandle fd={fd} handle={handle:#x}");
    }
    handle
}
pub(super) extern "win64" fn native_crt_open_osfhandle(handle: u64, _flags: i32) -> i32 {
    let Some(process) = process_ctx() else {
        return -1;
    };
    let valid = host_standard_fd(handle).is_some()
        || process
            .named_pipes
            .lock()
            .is_ok_and(|pipes| pipes.handles.contains_key(&handle))
        || process
            .fs
            .lock()
            .is_ok_and(|fs| fs.handles.contains_key(&handle))
        || handle & 0xffff_ffff_0000_0000 == SOCKET_HANDLE_TAG;
    if !valid {
        native_set_last_error(6);
        return -1;
    }
    let fd = process.crt_fd_next.fetch_add(1, Ordering::AcqRel);
    if process.crt_fds.lock().is_ok_and(|mut fds| {
        fds.insert(fd, handle);
        true
    }) {
        if native_diagnostic_enabled() {
            eprintln!("native CRT _open_osfhandle handle={handle:#x} fd={fd}");
        }
        fd
    } else {
        -1
    }
}
pub(super) extern "win64" fn native_crt_close(fd: i32) -> i32 {
    if fd < 0 {
        native_set_last_error(9); // EBADF
        return -1;
    }
    if (0..3).contains(&fd) {
        return native_close_handle(native_crt_get_osfhandle(fd)) - 1;
    }
    let handle = process_ctx().and_then(|process| {
        process
            .crt_fds
            .lock()
            .ok()
            .and_then(|mut fds| fds.remove(&fd))
    });
    match handle {
        Some(handle) => native_close_handle(handle) - 1,
        None => {
            native_set_last_error(9);
            -1
        }
    }
}
pub(super) extern "win64" fn native_crt_read(fd: i32, buffer: *mut u8, length: u32) -> i32 {
    if fd < 0 {
        native_set_last_error(9);
        return -1;
    }
    let handle = native_crt_get_osfhandle(fd);
    if handle == u64::MAX {
        native_set_last_error(9);
        return -1;
    }
    let mut count = 0;
    if native_read_file(handle, buffer, length, &mut count, 0) == 0 {
        -1
    } else {
        count.min(i32::MAX as u32) as i32
    }
}
pub(super) extern "win64" fn native_crt_write(fd: i32, buffer: *const u8, length: u32) -> i32 {
    if fd < 0 {
        native_set_last_error(9);
        return -1;
    }
    let handle = native_crt_get_osfhandle(fd);
    if handle == u64::MAX {
        native_set_last_error(9);
        return -1;
    }
    let mut count = 0;
    if native_write_file(handle, buffer, length, &mut count, 0) == 0 {
        -1
    } else {
        count.min(i32::MAX as u32) as i32
    }
}
pub(super) extern "win64" fn native_crt_isatty(fd: i32) -> i32 {
    let handle = native_crt_get_osfhandle(fd);
    (handle != u64::MAX && native_get_file_type(handle) == 2) as i32
}

pub(super) extern "win64" fn native_set_std_handle(which: u32, handle: u64) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!(
            "native SetStdHandle which={} handle={handle:#x}",
            which as i32
        );
    }
    let index = match which as i32 {
        -10 => 0,
        -11 => 1,
        -12 => 2,
        _ => {
            native_set_last_error(87);
            return 0;
        }
    };
    let Some(process) = process_ctx() else {
        return 0;
    };
    process.std_handles[index].store(handle, Ordering::Release);
    1
}

pub(super) extern "win64" fn native_set_handle_information(
    handle: u64,
    mask: u32,
    flags: u32,
) -> i32 {
    if mask & !0x3 != 0 {
        native_set_last_error(87);
        return 0;
    }
    if let Some(process) = process_ctx() {
        if let Ok(mut handles) = process.apc_handles.lock() {
            if let Some(thread) = handles.get_mut(&handle) {
                thread.flags = (thread.flags & !mask) | (flags & mask);
                return 1;
            }
        }
        if let Ok(mut pipes) = process.named_pipes.lock() {
            if let Some(pipe) = pipes.handles.get_mut(&handle) {
                if mask & flags & 2 != 0 {
                    native_set_last_error(50); // Protect-from-close is unsupported.
                    return 0;
                }
                if mask & 1 != 0 {
                    pipe.inheritable = flags & 1 != 0;
                }
                return 1;
            }
        }
    }
    if handle & 0xffff_ffff_0000_0000 == SOCKET_HANDLE_TAG {
        let fd = handle as i32;
        let descriptor_flags = unsafe { fcntl(fd, 1) }; // F_GETFD
        if descriptor_flags < 0 {
            native_set_last_error(6);
            return 0;
        }
        if mask & 1 != 0 {
            let next_flags = if flags & 1 != 0 {
                descriptor_flags & !1 // inheritable: clear FD_CLOEXEC
            } else {
                descriptor_flags | 1
            };
            if unsafe { fcntl(fd, 2, next_flags) } < 0 {
                native_set_last_error(6);
                return 0;
            }
        }
        return 1;
    }
    if host_standard_fd(handle).is_some()
        || fs_ctx().is_some_and(|context| {
            context
                .lock()
                .is_ok_and(|fs| fs.handles.contains_key(&handle))
        })
    {
        return 1;
    }
    native_set_last_error(6);
    0
}

pub(super) extern "win64" fn native_duplicate_handle(
    source_process: u64,
    source_handle: u64,
    target_process: u64,
    target_handle: *mut u64,
    desired_access: u32,
    inherit: i32,
    options: u32,
) -> i32 {
    let close_source = options & 1 != 0
        && process_ctx().is_some_and(|process| source_process == process.process_handle);
    if close_source && target_process == 0 && target_handle.is_null() {
        return native_close_handle(source_handle);
    }
    let result = native_duplicate_handle_impl(
        source_process,
        source_handle,
        target_process,
        target_handle,
        desired_access,
        inherit,
        options & !1,
    );
    if close_source {
        // Windows closes the source even when duplication fails. Preserve
        // the duplication error rather than a close operation's last error.
        let error = native_get_last_error();
        native_close_handle(source_handle);
        native_set_last_error(error);
    }
    result
}

fn native_duplicate_handle_impl(
    source_process: u64,
    source_handle: u64,
    target_process: u64,
    target_handle: *mut u64,
    desired_access: u32,
    inherit: i32,
    options: u32,
) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native DuplicateHandle source_process={source_process:#x} source={source_handle:#x} target_process={target_process:#x} desired={desired_access:#x} inherit={inherit} options={options:#x}");
    }
    if target_handle.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    if source_process != process.process_handle || target_process != process.process_handle {
        native_set_last_error(6);
        return 0;
    }
    let original = process
        .duplicate_handles
        .lock()
        .ok()
        .and_then(|values| values.get(&source_handle).copied())
        .unwrap_or(source_handle);
    // A pipe duplicate owns another reference to the endpoint. It must be
    // present in the pipe table so IOCP, cancellation and close work normally.
    if let Ok(mut pipes) = process.named_pipes.lock() {
        if let Some(mut pipe) = pipes.handles.get(&original).cloned() {
            let duplicate = pipes.next;
            pipes.next += 1;
            pipe.inheritable = inherit != 0;
            pipes.handles.insert(duplicate, pipe);
            unsafe {
                target_handle.write(duplicate);
            }
            return 1;
        }
    }
    let apc = lookup_thread_handle(source_handle);
    let valid = apc.is_some()
        || matches!(original, u64::MAX | 0xffff_ffff_ffff_fffe)
        || host_standard_fd(original).is_some()
        || native_device(original).is_some()
        || process
            .completion_ports
            .lock()
            .is_ok_and(|values| values.contains_key(&original))
        || fs_ctx().is_some_and(|context| {
            context
                .lock()
                .is_ok_and(|fs| fs.handles.contains_key(&original))
        });
    if !valid {
        native_set_last_error(6);
        return 0;
    }
    let duplicate = process.duplicate_next.fetch_add(1, Ordering::AcqRel);
    match process.duplicate_handles.lock() {
        Ok(mut values) => {
            values.insert(duplicate, original);
        }
        Err(_) => return 0,
    }
    if let Some(mut apc) = apc {
        apc.flags = u32::from(inherit != 0);
        if options & 2 == 0 {
            apc.access = thread_access_mask(desired_access);
        }
        let Ok(mut handles) = process.apc_handles.lock() else {
            return 0;
        };
        handles.insert(duplicate, apc);
    }
    unsafe { target_handle.write(duplicate) };
    1
}

pub(super) fn host_standard_fd(handle: u64) -> Option<i32> {
    match handle {
        0..=2 => Some(handle as i32),
        STD_HANDLE_BASE..=0x5000_0002 => Some((handle - STD_HANDLE_BASE) as i32),
        _ => process_ctx()
            .and_then(|process| {
                process
                    .duplicate_handles
                    .lock()
                    .ok()
                    .and_then(|values| values.get(&handle).copied())
            })
            .and_then(|original| match original {
                0..=2 => Some(original as i32),
                STD_HANDLE_BASE..=0x5000_0002 => Some((original - STD_HANDLE_BASE) as i32),
                _ => None,
            }),
    }
}

pub(super) extern "win64" fn native_get_file_type(handle: u64) -> u32 {
    if native_device(handle).is_some() {
        native_set_last_error(0);
        return 0x0002; // FILE_TYPE_CHAR
    }
    if crate::control::is_control_session() && host_standard_fd(handle).is_some() {
        return 0x0002; // FILE_TYPE_CHAR for the controlled virtual console.
    }
    let kind = match host_standard_fd(handle) {
        Some(fd) if unsafe { isatty(fd) } != 0 => 0x0002,
        Some(_) => 0x0003, // anonymous launcher pipes
        None => {
            if process_ctx().is_some_and(|process| {
                process
                    .named_pipes
                    .lock()
                    .is_ok_and(|pipes| pipes.handles.contains_key(&handle))
            }) {
                0x0003 // FILE_TYPE_PIPE
            } else if fs_ctx().is_some_and(|context| {
                context
                    .lock()
                    .is_ok_and(|fs| fs.handles.contains_key(&handle))
            }) {
                0x0001 // FILE_TYPE_DISK
            } else {
                native_set_last_error(6);
                0
            }
        }
    };
    kind
}

pub(super) extern "win64" fn native_close_handle(h: u64) -> i32 {
    if h == PROCESS_TOKEN_HANDLE {
        return 1;
    }
    if is_afd_handle(h) {
        if close_afd_device(h) {
            return 1;
        }
        native_set_last_error(6);
        return 0;
    }
    let process = process_ctx();
    if process.as_ref().is_some_and(|process| {
        process
            .apc_handles
            .lock()
            .is_ok_and(|handles| handles.get(&h).is_some_and(|thread| thread.flags & 2 != 0))
    }) {
        native_set_last_error(5);
        return 0;
    }
    let thread_handle = process.as_ref().is_some_and(|process| {
        process
            .apc_handles
            .lock()
            .is_ok_and(|mut handles| handles.remove(&h).is_some())
    });
    if thread_handle {
        if let Some(process) = &process {
            if let Ok(mut duplicates) = process.duplicate_handles.lock() {
                duplicates.remove(&h);
            }
        }
        return 1;
    }
    if let Some(job) = process.as_ref().and_then(|process| {
        process
            .job_objects
            .lock()
            .ok()
            .and_then(|mut jobs| jobs.remove(&h))
    }) {
        if job.limit_flags & 0x2000 != 0 {
            for member in job.members {
                native_terminate_process(member, 1);
            }
        }
        return 1;
    }
    if process.as_ref().is_some_and(|process| {
        process.named_pipes.lock().is_ok_and(|mut pipes| {
            let pending_client = pipes
                .handles
                .get(&h)
                .and_then(|pipe| pipe.pending_client.as_ref().map(Arc::clone));
            if let Some(endpoint) = pending_client {
                if let Some(queue) = pipes.pending_clients.get_mut(&endpoint.name) {
                    queue.retain(|pending| !Arc::ptr_eq(pending, &endpoint));
                }
            }
            let pending: Vec<_> = pipes
                .pending_io
                .iter()
                .filter(|((handle, _), _)| *handle == h)
                .map(|(_, pending)| Arc::clone(&pending.cancelled))
                .collect();
            for cancelled in pending {
                cancelled.store(true, Ordering::Release);
            }
            pipes.handles.remove(&h).is_some()
        })
    }) {
        return 1;
    }
    if process.as_ref().is_some_and(|process| {
        process
            .duplicate_handles
            .lock()
            .is_ok_and(|mut values| values.remove(&h).is_some())
    }) {
        return 1;
    }
    if process.as_ref().is_some_and(|process| {
        process
            .semaphores
            .lock()
            .is_ok_and(|mut values| values.remove(&h).is_some())
    }) {
        return 1;
    }
    if process
        .as_ref()
        .is_some_and(|p| p.timers.lock().is_ok_and(|mut t| t.remove(&h).is_some()))
    {
        return 1;
    }
    if process.as_ref().is_some_and(|process| {
        process
            .events
            .lock()
            .is_ok_and(|mut values| values.remove(&h).is_some())
    }) {
        return 1;
    }
    if let Some(port) = process.as_ref().and_then(|process| {
        process
            .completion_ports
            .lock()
            .ok()
            .and_then(|mut ports| ports.remove(&h))
    }) {
        if let Ok(_guard) = port.queue.lock() {
            port.closed.store(true, Ordering::Release);
            port.ready.notify_all();
        }
        return 1;
    }
    if process.as_ref().is_some_and(|process| {
        process
            .file_mappings
            .lock()
            .is_ok_and(|mut values| values.remove(&h).is_some())
    }) {
        return 1;
    }
    if process
        .as_ref()
        .is_some_and(|process| h == process.process_handle || h == u64::MAX - 1)
    {
        native_set_last_error(6); // pseudo handles cannot be closed
        return 0;
    }
    if process
        .as_ref()
        .and_then(|process| {
            process.children.lock().ok().map(|mut children| {
                children.children.remove(&h).is_some()
                    || children.primary_threads.remove(&h).is_some()
            })
        })
        .unwrap_or(false)
    {
        return 1;
    }
    let closed = fs_ctx()
        .and_then(|context| {
            context.lock().ok().map(|mut c| {
                c.file_locks.retain(|(_, _, _, owner, _)| *owner != h);
                c.file_completion_modes.remove(&h);
                c.file_access.remove(&h);
                c.file_shares.remove(&h);
                let device_closed = c.devices.remove(&h).is_some();
                if c.delete_on_close.remove(&h) {
                    if let Some(file) = c.handles.get(&h) {
                        let path = file.path.clone();
                        let _ = if c.fs.is_dir(&path) {
                            c.fs.rmdir(&path)
                        } else {
                            c.fs.delete_file(&path)
                        };
                    }
                }
                device_closed || c.handles.remove(&h).is_some() || c.finds.remove(&h).is_some()
            })
        })
        .unwrap_or(false);
    if closed {
        if let Some(process) = process.as_ref() {
            native_cancel_pending_file_locks(process, Some(h));
        }
    } else {
        native_set_last_error(6);
    }
    closed as i32
}
