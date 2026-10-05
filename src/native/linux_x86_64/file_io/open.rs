use super::*;

/// Anonymous byte pipes use the same endpoints as named-pipe I/O and child
/// stdio, without a name, connection handshake, or overlapped operations.
pub(in crate::native::linux_x86_64) extern "win64" fn native_create_pipe(
    read_handle: *mut u64,
    write_handle: *mut u64,
    security: *const u8,
    _size: u32,
) -> i32 {
    if read_handle.is_null() || write_handle.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let inheritable = if security.is_null() {
        false
    } else {
        if unsafe { security.cast::<u32>().read_unaligned() } < 24 {
            native_set_last_error(87);
            return 0;
        }
        unsafe { security.add(16).cast::<i32>().read_unaligned() != 0 }
    };
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut pipes) = process.named_pipes.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        native_set_last_error(8);
        return 0;
    }
    // Each endpoint is unidirectional. EOF follows the last writer's close.
    unsafe {
        libc::shutdown(fds[0], libc::SHUT_WR);
        libc::shutdown(fds[1], libc::SHUT_RD);
    }
    let handles = [pipes.next, pipes.next + 1];
    pipes.next += 2;
    for (index, access) in [0x8000_0000, 0x4000_0000].into_iter().enumerate() {
        pipes.handles.insert(
            handles[index],
            NativePipeHandle {
                endpoint: Arc::new(NativePipeEndpoint {
                    fd: fds[index],
                    name: String::new(),
                    server: false,
                    access,
                }),
                pending_client: None,
                overlapped: false,
                inheritable,
                access,
                mode: 0,
                completion: None,
                completion_modes: 0,
            },
        );
    }
    unsafe {
        read_handle.write(handles[0]);
        write_handle.write(handles[1]);
    }
    1
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_create_file_w(
    path: *const u16,
    access: u32,
    share: u32,
    security: u64,
    creation: u32,
    flags: u32,
    _tmpl: u64,
) -> u64 {
    let path = match wide(path) {
        Some(v) => v,
        None => {
            native_set_last_error(87);
            return u64::MAX;
        }
    };
    if crate::winfs::is_unc_path(&path) {
        native_set_last_error(53); // ERROR_BAD_NETPATH: UNC shares are unsupported.
        return u64::MAX;
    }
    if matches!(
        crate::winfs::parse_win_path(&path),
        crate::winfs::ParsedWinPath::Invalid(_)
    ) {
        native_set_last_error(123); // ERROR_INVALID_NAME
        return u64::MAX;
    }
    if native_named_pipe_key(&path).is_some() {
        return native_open_named_pipe(&path, access, share, flags, security);
    }
    let path = path.strip_prefix(r"\\?\").unwrap_or(&path).to_string();
    let context = match fs_ctx() {
        Some(v) => v,
        None => return u64::MAX,
    };
    let mut ctx = match context.lock() {
        Ok(value) => value,
        Err(_) => return u64::MAX,
    };
    let device = match crate::winfs::dos_device_path(&path) {
        Some(crate::winfs::DosDevicePath::Null) => Some(NativeDevice::Null),
        Some(crate::winfs::DosDevicePath::Console) => {
            process_ctx().map(|process| NativeDevice::Console {
                input: process.parameters.std_handles[0].load(Ordering::Acquire),
                output: process.parameters.std_handles[1].load(Ordering::Acquire),
            })
        }
        Some(crate::winfs::DosDevicePath::ConsoleIn) => process_ctx()
            .map(|process| NativeDevice::ConsoleIn(process.parameters.std_handles[0].load(Ordering::Acquire))),
        Some(crate::winfs::DosDevicePath::ConsoleOut) => process_ctx().map(|process| {
            NativeDevice::ConsoleOut(process.parameters.std_handles[1].load(Ordering::Acquire))
        }),
        Some(crate::winfs::DosDevicePath::Reserved) => {
            native_set_last_error(123); // ERROR_INVALID_NAME
            return u64::MAX;
        }
        Some(crate::winfs::DosDevicePath::Pipe(_)) => {
            return native_open_named_pipe(&path, access, share, flags, security);
        }
        None => None,
    };
    if let Some(device) = device {
        let handle = ctx.next;
        ctx.next = ctx.next.saturating_add(1);
        ctx.devices.insert(handle, device);
        ctx.file_access.insert(handle, access);
        ctx.file_shares.insert(handle, share);
        native_set_last_error(0);
        return handle;
    }
    let exists = ctx.fs.exists(&path);
    let Ok(path_key) = ctx.fs.normalize(&path) else {
        native_set_last_error(3);
        return u64::MAX;
    };
    let path_key = path_key.key();
    let desired = access & 0xC000_0000;
    let required_share =
        ((desired & 0x8000_0000 != 0) as u32) | (((desired & 0x4000_0000 != 0) as u32) << 1);
    let sharing_conflict = ctx.handles.iter().any(|(handle, open)| {
        if ctx.fs.normalize(&open.path).ok().map(|key| key.key()) != Some(path_key.clone()) {
            return false;
        }
        let open_desired = ctx.file_access.get(handle).copied().unwrap_or(0);
        let open_share = ctx.file_shares.get(handle).copied().unwrap_or(7);
        let open_required = ((open_desired & 0x8000_0000 != 0) as u32)
            | (((open_desired & 0x4000_0000 != 0) as u32) << 1);
        required_share & !open_share != 0 || open_required & !share != 0
    });
    if sharing_conflict {
        native_set_last_error(32); // ERROR_SHARING_VIOLATION
        return u64::MAX;
    }
    if ctx.fs.file_named_as_directory(&path) {
        native_set_last_error(267); // ERROR_DIRECTORY
        return u64::MAX;
    }
    // A directory opens only with backup semantics, and is never replaced
    // or truncated as a file.
    if exists
        && ctx.fs.is_dir(&path)
        && ((matches!(creation, 3 | 4) && flags & 0x0200_0000 == 0) || matches!(creation, 2 | 5))
    {
        native_set_last_error(5); // ERROR_ACCESS_DENIED
        return u64::MAX;
    }
    let create_posix_directory = creation == 1 && flags & 0x0300_0000 == 0x0300_0000;
    let ok = match creation {
        1 if !exists && create_posix_directory => ctx.fs.mkdir_one(&path),
        1 if !exists => ctx.fs.write_file(&path, Vec::new()), // CREATE_NEW
        1 => Err("file already exists".into()),
        2 => ctx.fs.write_file(&path, Vec::new()), // CREATE_ALWAYS
        // OPEN_EXISTING can target either a file or a directory. The
        // caller supplies FILE_FLAG_BACKUP_SEMANTICS for directories;
        // enumeration support consumes the resulting handle next.
        3 | 4 if exists && (ctx.fs.is_file(&path) || ctx.fs.is_dir(&path)) => Ok(()),
        4 => ctx.fs.write_file(&path, Vec::new()), // OPEN_ALWAYS
        5 if ctx.fs.is_file(&path) => ctx.fs.write_file(&path, Vec::new()), // TRUNCATE_EXISTING
        _ => Err("unsupported create".into()),
    };
    if ok.is_err() {
        native_set_last_error(match (creation, exists) {
            (1, true) => 80, // ERROR_FILE_EXISTS
            // Not found: 2 with the parent there, else 3.
            (_, false) => ctx.fs.missing_path_error(&path),
            _ => 87, // ERROR_INVALID_PARAMETER
        });
        if native_diagnostic_enabled() {
            eprintln!("native CreateFileW failed path={path}");
        }
        return u64::MAX;
    }
    if exists && matches!(creation, 2 | 4) {
        native_set_last_error(183); // ERROR_ALREADY_EXISTS
    }
    let h = ctx.next;
    ctx.next += 1;
    // A handle names the file a link leads to, unless the caller opened the
    // link itself with FILE_FLAG_OPEN_REPARSE_POINT (to read its target).
    let path = if flags & 0x0020_0000 == 0 {
        ctx.fs.resolve_links(&path).unwrap_or(path)
    } else {
        path
    };
    // Windows records the canonical path of an opened file, so
    // GetFinalPathNameByHandle never echoes `/`, `..`, or the caller's casing.
    let path = ctx.fs.canonical_path(&path).unwrap_or(path);
    if native_diagnostic_enabled() {
        eprintln!("native CreateFileW opened path={path} handle={h:#x} flags={flags:#x} access={access:#x}");
    }
    ctx.handles.insert(
        h,
        NativeFile {
            path,
            offset: 0,
            overlapped: flags & 0x4000_0000 != 0,
            completion: None,
        },
    );
    ctx.file_access.insert(h, access);
    ctx.file_shares.insert(h, share);
    h
}

pub(in crate::native::linux_x86_64) fn native_named_pipe_key(path: &str) -> Option<String> {
    let path = path.replace('/', "\\").to_lowercase();
    let name = path
        .strip_prefix(r"\\.\pipe\")
        .or_else(|| path.strip_prefix(r"\\?\pipe\"))?;
    if name.is_empty()
        || name.len() > 250
        || name.contains(':')
        || name
            .split('\\')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return None;
    }
    Some(name.to_lowercase())
}

pub(in crate::native::linux_x86_64) fn native_open_named_pipe(
    path: &str,
    access: u32,
    share: u32,
    flags: u32,
    security: u64,
) -> u64 {
    let Some(name) = native_named_pipe_key(path) else {
        native_set_last_error(2); // ERROR_FILE_NOT_FOUND
        return u64::MAX;
    };
    if share != 0 {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return u64::MAX;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return u64::MAX;
    };
    let Ok(mut pipes) = process.named_pipes.lock() else {
        native_set_last_error(6);
        return u64::MAX;
    };
    let Some(queue) = pipes.pending_clients.get_mut(&name) else {
        native_set_last_error(2); // ERROR_FILE_NOT_FOUND
        return u64::MAX;
    };
    let Some(pending) = queue.front() else {
        native_set_last_error(231); // ERROR_PIPE_BUSY
        return u64::MAX;
    };
    let server_access = pending.access;
    let needs_read = access & 0x8000_0000 != 0;
    let needs_write = access & 0x4000_0000 != 0;
    let compatible = match server_access {
        1 => needs_write, // PIPE_ACCESS_INBOUND
        2 => needs_read,  // PIPE_ACCESS_OUTBOUND
        3 => needs_read || needs_write,
        _ => false,
    };
    if !compatible {
        native_set_last_error(5); // ERROR_ACCESS_DENIED
        return u64::MAX;
    }
    let endpoint = queue.pop_front().unwrap();
    let connected = [0xffu8];
    if unsafe {
        send(
            endpoint.fd,
            connected.as_ptr().cast(),
            connected.len(),
            0x4000, // MSG_NOSIGNAL
        )
    } != 1
    {
        native_set_last_error(109); // ERROR_BROKEN_PIPE
        return u64::MAX;
    }
    // The server stores this endpoint while it is waiting for a client so
    // CloseHandle can remove an unconnected endpoint from the pending queue.
    // Once accepted, that extra reference would keep the client's write side
    // alive after the client closes, preventing readers from observing EOF.
    if let Some(server) = pipes.handles.values_mut().find(|handle| {
        handle.endpoint.server
            && handle.endpoint.name == name
            && handle
                .pending_client
                .as_ref()
                .is_some_and(|candidate| Arc::ptr_eq(candidate, &endpoint))
    }) {
        server.pending_client = None;
    }
    let handle = pipes.next;
    pipes.next = pipes.next.saturating_add(1);
    pipes.handles.insert(
        handle,
        NativePipeHandle {
            overlapped: flags & 0x4000_0000 != 0,
            endpoint,
            pending_client: None,
            inheritable: security != 0
                && unsafe { ((security + 16) as *const i32).read_unaligned() } != 0,
            access,
            mode: 0, // PIPE_READMODE_BYTE | PIPE_WAIT
            completion: None,
            completion_modes: 0,
        },
    );
    handle
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_create_file_a(
    path: *const u8,
    access: u32,
    share: u32,
    security: u64,
    creation: u32,
    flags: u32,
    template: u64,
) -> u64 {
    let Some(wide_path) = native_ansi_path(path) else {
        native_set_last_error(87);
        return u64::MAX;
    };
    native_create_file_w(
        wide_path.as_ptr(),
        access,
        share,
        security,
        creation,
        flags,
        template,
    )
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_create_named_pipe_w(
    path: *const u16,
    open_mode: u32,
    pipe_mode: u32,
    max_instances: u32,
    _out_buffer_size: u32,
    _in_buffer_size: u32,
    _default_timeout: u32,
    security: u64,
) -> u64 {
    let Some(path) = wide(path) else {
        native_set_last_error(87);
        return u64::MAX;
    };
    let Some(name) = native_named_pipe_key(&path) else {
        native_set_last_error(123); // ERROR_INVALID_NAME
        return u64::MAX;
    };
    let access = open_mode & 0x3;
    // libuv adds WRITE_DAC so the pipe ACL can be adjusted for the
    // inheritable client endpoint it passes to CreateProcessW.
    let valid_open_flags = 0x4000_0000 | 0x0008_0000 | 0x0004_0000 | 0x8000_0000;
    if !(1..=3).contains(&access)
        || open_mode & !(0x3 | valid_open_flags) != 0
        || pipe_mode & !0x1 != 0
        || max_instances == 0
        || max_instances > 255
    {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return u64::MAX;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return u64::MAX;
    };
    let Ok(mut pipes) = process.named_pipes.lock() else {
        native_set_last_error(6);
        return u64::MAX;
    };
    let existing = pipes
        .handles
        .values()
        .filter(|handle| handle.endpoint.server && handle.endpoint.name == name)
        .count();
    let first_instance = open_mode & 0x0008_0000 != 0;
    if first_instance && existing != 0 {
        native_set_last_error(5); // ERROR_ACCESS_DENIED
        return u64::MAX;
    }
    if existing >= max_instances as usize {
        native_set_last_error(231); // ERROR_PIPE_BUSY
        return u64::MAX;
    }
    let mut fds = [-1; 2];
    if unsafe { socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
        native_set_last_error(8); // ERROR_NOT_ENOUGH_MEMORY
        return u64::MAX;
    }
    let overlapped = open_mode & 0x4000_0000 != 0;
    let server_endpoint = Arc::new(NativePipeEndpoint {
        fd: fds[0],
        name: name.clone(),
        server: true,
        access,
    });
    let client_endpoint = Arc::new(NativePipeEndpoint {
        fd: fds[1],
        name: name.clone(),
        server: false,
        access,
    });
    let handle = pipes.next;
    pipes.next = pipes.next.saturating_add(1);
    pipes.handles.insert(
        handle,
        NativePipeHandle {
            endpoint: server_endpoint,
            pending_client: Some(client_endpoint.clone()),
            overlapped,
            inheritable: security != 0
                && unsafe { ((security + 16) as *const i32).read_unaligned() } != 0,
            access,
            mode: pipe_mode & 0x1,
            completion: None,
            completion_modes: 0,
        },
    );
    pipes
        .pending_clients
        .entry(name)
        .or_default()
        .push_back(client_endpoint);
    handle
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_create_named_pipe_a(
    path: *const u8,
    open_mode: u32,
    pipe_mode: u32,
    max_instances: u32,
    out_buffer_size: u32,
    in_buffer_size: u32,
    default_timeout: u32,
    security: u64,
) -> u64 {
    let Some(wide_path) = native_ansi_path(path) else {
        native_set_last_error(87);
        return u64::MAX;
    };
    native_create_named_pipe_w(
        wide_path.as_ptr(),
        open_mode,
        pipe_mode,
        max_instances,
        out_buffer_size,
        in_buffer_size,
        default_timeout,
        security,
    )
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_connect_named_pipe(
    handle: u64,
    overlapped: u64,
) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let pipe = process
        .named_pipes
        .lock()
        .ok()
        .and_then(|pipes| pipes.handles.get(&handle).cloned());
    let Some(pipe) = pipe.filter(|pipe| pipe.endpoint.server) else {
        native_set_last_error(6);
        return 0;
    };
    if overlapped != 0 {
        if overlapped & 7 != 0 || native_overlapped_status(overlapped) == STATUS_PENDING {
            native_set_last_error(87);
            return 0;
        }
    }
    let event = if overlapped != 0 {
        match native_prepare_overlapped_event(overlapped) {
            Ok(event) => event,
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        }
    } else {
        None
    };
    let mut marker = [0u8; 1];
    loop {
        let count = unsafe {
            recv(
                pipe.endpoint.fd,
                marker.as_mut_ptr().cast(),
                1,
                0x42, // MSG_PEEK | MSG_DONTWAIT
            )
        };
        if count == 1 {
            if marker[0] != 0xff {
                native_set_last_error(87);
                return 0;
            }
            unsafe { recv(pipe.endpoint.fd, marker.as_mut_ptr().cast(), 1, 0x40) };
            if overlapped != 0 {
                native_complete_pipe_io(&pipe, overlapped, 0, 0, event.as_ref());
            }
            native_set_last_error(535); // ERROR_PIPE_CONNECTED
            return 0;
        }
        if count == 0 {
            native_set_last_error(109);
            return 0;
        }
        if overlapped != 0 {
            if let Err(error) =
                native_submit_pipe_connect(&process, handle, pipe, overlapped, event)
            {
                native_set_last_error(error);
                return 0;
            }
            native_set_last_error(997); // ERROR_IO_PENDING
            return 0;
        }
        if pipe.overlapped {
            native_set_last_error(87);
            return 0;
        }
        let mut descriptor = NativePollFd {
            fd: pipe.endpoint.fd,
            events: 0x1,
            revents: 0,
        };
        if unsafe { poll(&mut descriptor, 1, -1) } < 0 {
            native_set_last_error(6);
            return 0;
        }
    }
}
pub(in crate::native::linux_x86_64) fn native_submit_pipe_connect(
    process: &Arc<NativeProcessContext>,
    handle: u64,
    pipe: NativePipeHandle,
    overlapped: u64,
    event: Option<Arc<NativeEvent>>,
) -> Result<(), u32> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let issuer = std::thread::current().id();
    {
        let mut pipes = process.named_pipes.lock().map_err(|_| 6u32)?;
        if pipes.pending_io.contains_key(&(handle, overlapped)) {
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
    let worker_process = Arc::clone(process);
    let spawn = std::thread::Builder::new()
        .name("winrun-named-pipe-connect".into())
        .spawn(move || {
            let status = loop {
                if cancelled.load(Ordering::Acquire) {
                    break 0xc000_0120; // STATUS_CANCELLED
                }
                let mut descriptor = NativePollFd {
                    fd: pipe.endpoint.fd,
                    events: 0x1,
                    revents: 0,
                };
                let ready = unsafe { poll(&mut descriptor, 1, 25) };
                if ready < 0 {
                    break 0xc000_0001; // STATUS_UNSUCCESSFUL
                }
                if ready == 0 {
                    continue;
                }
                let mut marker = [0u8; 1];
                let count = unsafe {
                    recv(
                        pipe.endpoint.fd,
                        marker.as_mut_ptr().cast(),
                        1,
                        0x40, // MSG_DONTWAIT
                    )
                };
                if count == 1 && marker[0] == 0xff {
                    break 0;
                }
                break 0xc000_014b; // STATUS_PIPE_BROKEN
            };
            native_complete_pipe_io(&pipe, overlapped, 0, status, event.as_ref());
            if let Ok(mut pipes) = worker_process.named_pipes.lock() {
                pipes.pending_io.remove(&(handle, overlapped));
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
pub(in crate::native::linux_x86_64) extern "win64" fn native_wait_named_pipe_w(
    path: *const u16,
    _timeout: u32,
) -> i32 {
    let Some(path) = wide(path) else {
        native_set_last_error(87);
        return 0;
    };
    let Some(name) = native_named_pipe_key(&path) else {
        native_set_last_error(123);
        return 0;
    };
    let available = process_ctx().is_some_and(|process| {
        process.named_pipes.lock().is_ok_and(|pipes| {
            pipes
                .pending_clients
                .get(&name)
                .is_some_and(|queue| !queue.is_empty())
        })
    });
    if available {
        1
    } else {
        native_set_last_error(231); // ERROR_PIPE_BUSY
        0
    }
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_wait_named_pipe_a(
    path: *const u8,
    timeout: u32,
) -> i32 {
    let Some(wide_path) = native_ansi_path(path) else {
        native_set_last_error(87);
        return 0;
    };
    native_wait_named_pipe_w(wide_path.as_ptr(), timeout)
}
pub(in crate::native::linux_x86_64) fn native_file_attributes(is_directory: bool) -> u32 {
    if is_directory {
        0x10
    } else {
        0x80
    }
}
pub(in crate::native::linux_x86_64) fn native_file_attributes_at(
    ctx: &NativeFs,
    path: &str,
    is_directory: bool,
) -> u32 {
    let base = native_file_attributes(is_directory);
    let attributes = ctx.fs.file_metadata(path).attributes;
    if attributes == 0 {
        base
    } else {
        (attributes & !0x10) | if is_directory { 0x10 } else { 0 }
    }
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_get_file_attributes_w(
    path: *const u16,
) -> u32 {
    let Some(path) = wide(path) else {
        native_set_last_error(87);
        return u32::MAX;
    };
    let path = path.strip_prefix(r"\\?\").unwrap_or(&path);
    let Some(context) = fs_ctx() else {
        native_set_last_error(2);
        return u32::MAX;
    };
    let Ok(ctx) = context.lock() else {
        native_set_last_error(6);
        return u32::MAX;
    };
    if ctx.fs.file_named_as_directory(path) {
        native_set_last_error(267); // ERROR_DIRECTORY
        u32::MAX
    } else if !path.is_empty() && ctx.fs.is_dir(path) {
        native_file_attributes_at(&ctx, path, true)
    } else if !path.is_empty() && ctx.fs.is_file(path) {
        native_file_attributes_at(&ctx, path, false)
    } else {
        native_set_last_error(ctx.fs.missing_path_error(path));
        u32::MAX
    }
}

/// `path` as `GetLongPathNameW` returns it: in the form given (a relative
/// path stays relative, separators unchanged), with each name component
/// spelled as it is on disk.
fn long_path_form(fs: &crate::winfs::WinFs, path: &str) -> String {
    let mut output = String::new();
    let mut consumed = String::new();
    let mut component = String::new();
    let flush = |component: &mut String, consumed: &str, output: &mut String| {
        if component.is_empty() {
            return;
        }
        let is_name = component != "." && component != ".." && !component.ends_with(':');
        let on_disk = is_name
            .then(|| fs.canonical_path(consumed))
            .flatten()
            .and_then(|canonical| canonical.rsplit('\\').next().map(str::to_string));
        output.push_str(on_disk.as_deref().unwrap_or(component));
        component.clear();
    };
    for character in path.chars() {
        consumed.push(character);
        if character == '\\' || character == '/' {
            let prefix = consumed[..consumed.len() - 1].to_string();
            flush(&mut component, &prefix, &mut output);
            output.push(character);
        } else {
            component.push(character);
        }
    }
    flush(&mut component, &consumed, &mut output);
    output
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_long_path_name_w(
    path: *const u16,
    output: *mut u16,
    capacity: u32,
) -> u32 {
    let Some(path) = wide(path) else {
        native_set_last_error(87);
        return 0;
    };
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(fs) = process.fs.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if !fs.fs.exists(&path) || path.is_empty() {
        native_set_last_error(fs.fs.missing_path_error(&path));
        return 0;
    }
    let normalized = long_path_form(&fs.fs, &path);
    let encoded: Vec<u16> = normalized.encode_utf16().collect();
    if output.is_null() || capacity as usize <= encoded.len() {
        return (encoded.len() + 1) as u32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len());
        output.add(encoded.len()).write(0);
    }
    encoded.len() as u32
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_set_file_attributes_w(
    path: *const u16,
    attributes: u32,
) -> i32 {
    let Some(path) = wide(path) else {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    };
    let path = path.strip_prefix(r"\\?\").unwrap_or(&path);
    if attributes & !0x7fb7 != 0 || (attributes & 0x80 != 0 && attributes != 0x80) {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(2);
        return 0;
    };
    let Ok(mut ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if !ctx.fs.is_file(path) && !ctx.fs.is_dir(path) {
        native_set_last_error(2); // ERROR_FILE_NOT_FOUND
        return 0;
    }
    let mut metadata = ctx.fs.file_metadata(path);
    metadata.attributes = attributes;
    match ctx.fs.set_file_metadata(path, metadata) {
        Ok(()) => 1,
        Err(_) => {
            native_set_last_error(5);
            0
        }
    }
}
#[repr(C)]
pub(in crate::native::linux_x86_64) struct NativeWin32FileAttributeData {
    attributes: u32,
    creation_time_low: u32,
    creation_time_high: u32,
    last_access_time_low: u32,
    last_access_time_high: u32,
    last_write_time_low: u32,
    last_write_time_high: u32,
    file_size_high: u32,
    file_size_low: u32,
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_get_file_attributes_ex_w(
    path: *const u16,
    information_level: u32,
    output: *mut NativeWin32FileAttributeData,
) -> i32 {
    if information_level != 0 {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let Some(path) = wide(path) else {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    };
    if output.is_null() {
        native_set_last_error(998); // ERROR_NOACCESS
        return 0;
    }
    let path = path.strip_prefix(r"\\?\").unwrap_or(&path);
    let Some(context) = fs_ctx() else {
        native_set_last_error(2); // ERROR_FILE_NOT_FOUND
        return 0;
    };
    let Ok(ctx) = context.lock() else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let is_directory = ctx.fs.is_dir(path);
    let size = if is_directory {
        0
    } else {
        match ctx.fs.file_len(path) {
            Ok(length) => length,
            Err(_) => {
                native_set_last_error(2); // ERROR_FILE_NOT_FOUND
                return 0;
            }
        }
    };
    let metadata = ctx.fs.file_metadata(path);
    unsafe {
        output.write_unaligned(NativeWin32FileAttributeData {
            attributes: native_file_attributes_at(&ctx, path, is_directory),
            creation_time_low: metadata.creation_time as u32,
            creation_time_high: (metadata.creation_time >> 32) as u32,
            last_access_time_low: metadata.access_time as u32,
            last_access_time_high: (metadata.access_time >> 32) as u32,
            last_write_time_low: metadata.write_time as u32,
            last_write_time_high: (metadata.write_time >> 32) as u32,
            file_size_high: (size >> 32) as u32,
            file_size_low: size as u32,
        });
    }
    1
}
pub(in crate::native::linux_x86_64) fn native_extended_path(path: &str) -> String {
    let path = path.trim_end_matches('.').trim_end_matches('\\');
    if path.eq_ignore_ascii_case("C:") || path.is_empty() {
        "\\\\?\\C:\\".to_string()
    } else {
        format!("\\\\?\\{}", path)
    }
}
/// A final path in the volume form `GetFinalPathNameByHandleW` was asked
/// for: `\\?\C:\dir` (DOS), `\\?\Volume{guid}\dir` (GUID),
/// `\Device\HarddiskVolumeN\dir` (NT), or `\dir` (none).
fn final_path_form(path: &str, volume: u32) -> String {
    let dos = native_extended_path(path);
    let Some(rest) = path.get(2..).filter(|_| path.as_bytes().get(1) == Some(&b':')) else {
        return dos; // not a drive path (UNC, device): only the DOS form
    };
    let rest = if rest.is_empty() { "\\" } else { rest };
    let drive = path.as_bytes()[0].to_ascii_uppercase();
    let volume_number = u32::from(drive.saturating_sub(b'A'));
    match volume {
        1 => format!("\\\\?\\Volume{{{:08x}-0000-0000-0000-{:012x}}}{rest}", 0x7769_6e72, volume_number),
        2 => format!("\\Device\\HarddiskVolume{}{rest}", volume_number + 1),
        4 => rest.to_string(),
        _ => dos,
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_final_path_name_by_handle_w(
    handle: u64,
    output: *mut u16,
    output_len: u32,
    flags: u32,
) -> u32 {
    // FILE_NAME_OPENED (0x8) and FILE_NAME_NORMALIZED (0) name the same
    // path here; the low bits pick the volume form.
    if flags & !0xf != 0 || !matches!(flags & 0x7, 0 | 1 | 2 | 4) {
        native_set_last_error(87);
        return 0;
    }
    let context = match fs_ctx() {
        Some(value) => value,
        None => return 0,
    };
    let ctx = match context.lock() {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let path = match ctx.handles.get(&handle) {
        Some(value) => final_path_form(&value.path, flags & 0x7),
        None => {
            native_set_last_error(6);
            return 0;
        }
    };
    let encoded: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    if output.is_null() || output_len < encoded.len() as u32 {
        return encoded.len() as u32;
    }
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    (encoded.len() - 1) as u32
}
/// The `REPARSE_DATA_BUFFER` of a symbolic link to the absolute `target`:
/// an NT `\??\` substitute name and the plain print name, as
/// `CreateSymbolicLinkW` stores them.
pub(in crate::native::linux_x86_64) fn symlink_reparse_data(target: &str) -> Vec<u8> {
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xa000_000c;
    let substitute: Vec<u16> = format!(r"\??\{target}").encode_utf16().collect();
    let print: Vec<u16> = target.encode_utf16().collect();
    let substitute_bytes = (substitute.len() * 2) as u16;
    let print_bytes = (print.len() * 2) as u16;
    let mut data = Vec::new();
    data.extend_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
    data.extend_from_slice(&(12 + substitute_bytes + print_bytes).to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
    data.extend_from_slice(&substitute_bytes.to_le_bytes());
    data.extend_from_slice(&substitute_bytes.to_le_bytes()); // PrintNameOffset
    data.extend_from_slice(&print_bytes.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // Flags: absolute
    for unit in substitute.iter().chain(&print) {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    data
}

/// `DeviceIoControl` on a file handle. `FSCTL_GET_REPARSE_POINT` reads a
/// symbolic link's target; libuv's `readlink`, `lstat`, and `realpath` use it
/// on handles opened with `FILE_FLAG_OPEN_REPARSE_POINT`.
#[allow(clippy::too_many_arguments)]
pub(in crate::native::linux_x86_64) extern "win64" fn native_device_io_control(
    handle: u64,
    code: u32,
    _input: *const u8,
    _input_len: u32,
    output: *mut u8,
    output_len: u32,
    returned: *mut u32,
    overlapped: u64,
) -> i32 {
    const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00a8;
    if code != FSCTL_GET_REPARSE_POINT || overlapped != 0 {
        native_set_last_error(1); // ERROR_INVALID_FUNCTION
        return 0;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(file) = ctx.handles.get(&handle) else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let Some(target) = ctx.fs.symlink_target(&file.path) else {
        native_set_last_error(4390); // ERROR_NOT_A_REPARSE_POINT
        return 0;
    };
    let data = symlink_reparse_data(&target);
    if output.is_null() || (output_len as usize) < data.len() {
        native_set_last_error(122); // ERROR_INSUFFICIENT_BUFFER (Windows oracle)
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), output, data.len()) };
    if !returned.is_null() {
        unsafe { returned.write(data.len() as u32) };
    }
    1
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_file_information_by_handle(
    handle: u64,
    output: *mut u8,
) -> i32 {
    if output.is_null() {
        return 0;
    }
    let context = match fs_ctx() {
        Some(value) => value,
        None => return 0,
    };
    let ctx = match context.lock() {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let path = match ctx.handles.get(&handle) {
        Some(value) => &value.path,
        None => return 0,
    };
    let is_directory = ctx.fs.is_dir(path);
    let size = if is_directory {
        0
    } else {
        ctx.fs.file_len(path).unwrap_or(0)
    };
    let file_id = match ctx.fs.file_id(path) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let metadata = ctx.fs.file_metadata(path);
    unsafe {
        std::ptr::write_bytes(output, 0, 52);
        (output as *mut u32).write_unaligned(native_file_attributes_at(&ctx, path, is_directory));
        (output.add(4) as *mut u64).write_unaligned(metadata.creation_time);
        (output.add(12) as *mut u64).write_unaligned(metadata.access_time);
        (output.add(20) as *mut u64).write_unaligned(metadata.write_time);
        (output.add(28) as *mut u32).write_unaligned(0x5743_4C49);
        (output.add(32) as *mut u32).write_unaligned((size >> 32) as u32);
        (output.add(36) as *mut u32).write_unaligned(size as u32);
        (output.add(40) as *mut u32).write_unaligned(1);
        (output.add(44) as *mut u64).write_unaligned(file_id);
    }
    1
}
/// A directory-enumeration class of `GetFileInformationByHandleEx`: where
/// each record keeps its file id and name, and whether it restarts the scan.
#[derive(Clone, Copy)]
struct DirectoryInfoLayout {
    name_offset: usize,
    file_id_offset: Option<usize>,
    wide_file_id: bool,
    restart: bool,
}

impl DirectoryInfoLayout {
    fn for_class(class: i32) -> Option<Self> {
        let (name_offset, file_id_offset, wide_file_id) = match class {
            10 | 11 => (104, Some(96), false), // FileIdBothDirectory[Restart]Info
            14 | 15 => (68, None, false),      // FileFullDirectory[Restart]Info
            19 | 20 => (88, Some(72), true),   // FileIdExtdDirectory[Restart]Info
            _ => return None,
        };
        Some(Self {
            name_offset,
            file_id_offset,
            wide_file_id,
            restart: matches!(class, 11 | 15 | 20),
        })
    }
}

/// Fill `output` with as many directory records as fit, continuing from the
/// handle's enumeration position (NTFS order: `.`, `..`, then entries).
/// `ERROR_NO_MORE_FILES` once the listing is exhausted.
fn native_directory_information(handle: u64, layout: DirectoryInfoLayout, output: *mut u8, size: u32) -> i32 {
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(file) = ctx.handles.get(&handle) else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let path = file.path.clone();
    let start = if layout.restart { 0 } else { file.offset };
    if !ctx.fs.is_dir(&path) {
        native_set_last_error(267); // ERROR_DIRECTORY
        return 0;
    }
    let Ok(children) = ctx.fs.list_dir(&path) else {
        native_set_last_error(3);
        return 0;
    };
    let base = path.trim_end_matches('\\');
    let parent = match base.rsplit_once('\\') {
        Some((parent, _)) if parent.ends_with(':') => format!("{parent}\\"),
        Some((parent, _)) => parent.to_string(),
        None => path.clone(),
    };
    let mut entries = vec![(".".to_string(), path.clone()), ("..".to_string(), parent)];
    entries.extend(children.into_iter().map(|name| {
        let full = format!("{base}\\{name}");
        (name, full)
    }));
    if start >= entries.len() {
        native_set_last_error(18); // ERROR_NO_MORE_FILES
        return 0;
    }
    let mut written = 0usize;
    let mut previous: Option<usize> = None;
    let mut index = start;
    while let Some((name, entry_path)) = entries.get(index) {
        let encoded: Vec<u16> = name.encode_utf16().collect();
        let used = layout.name_offset + encoded.len() * 2;
        if written + used > size as usize {
            if written == 0 {
                native_set_last_error(234); // ERROR_MORE_DATA
                return 0;
            }
            break;
        }
        let metadata = ctx.fs.file_metadata(entry_path);
        let directory = ctx.fs.is_dir(entry_path);
        let mut attributes = metadata.attributes;
        if directory {
            attributes = (attributes & !0x80) | 0x10;
        } else if attributes == 0 {
            attributes = 0x80; // FILE_ATTRIBUTE_NORMAL
        }
        let length = if directory { 0 } else { ctx.fs.file_len(entry_path).unwrap_or(0) };
        let file_id = ctx.fs.file_id(entry_path).unwrap_or(0);
        unsafe {
            let record = output.add(written);
            ptr::write_bytes(record, 0, layout.name_offset);
            for (offset, time) in [
                (8, metadata.creation_time),
                (16, metadata.access_time),
                (24, metadata.write_time),
                (32, metadata.write_time), // ChangeTime
            ] {
                record.add(offset).cast::<u64>().write_unaligned(time);
            }
            record.add(40).cast::<u64>().write_unaligned(length);
            record.add(48).cast::<u64>().write_unaligned(length.div_ceil(4096) * 4096);
            record.add(56).cast::<u32>().write_unaligned(attributes);
            record.add(60).cast::<u32>().write_unaligned((encoded.len() * 2) as u32);
            if let Some(offset) = layout.file_id_offset {
                record.add(offset).cast::<u64>().write_unaligned(file_id);
                if layout.wide_file_id {
                    record.add(offset + 8).cast::<u64>().write_unaligned(0);
                }
            }
            record
                .add(layout.name_offset)
                .cast::<u16>()
                .copy_from_nonoverlapping(encoded.as_ptr(), encoded.len());
            if let Some(previous) = previous {
                output.add(previous).cast::<u32>().write_unaligned((written - previous) as u32);
            }
        }
        previous = Some(written);
        written += (used + 7) & !7;
        index += 1;
    }
    if let Some(file) = ctx.handles.get_mut(&handle) {
        file.offset = index;
    }
    1
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_volume_information_by_handle_w(
    handle: u64,
    volume_name: *mut u16,
    volume_capacity: u32,
    serial: *mut u32,
    maximum_component: *mut u32,
    flags: *mut u32,
    filesystem_name: *mut u16,
    filesystem_capacity: u32,
) -> i32 {
    if !fs_ctx().is_some_and(|context| {
        context
            .lock()
            .is_ok_and(|fs| fs.handles.contains_key(&handle))
    }) {
        native_set_last_error(6);
        return 0;
    }
    let name: Vec<u16> = "WinFS".encode_utf16().chain([0]).collect();
    if (!volume_name.is_null() && volume_capacity < name.len() as u32)
        || (!filesystem_name.is_null() && filesystem_capacity < name.len() as u32)
    {
        native_set_last_error(234);
        return 0;
    }
    unsafe {
        if !volume_name.is_null() {
            volume_name.copy_from_nonoverlapping(name.as_ptr(), name.len());
        }
        if !filesystem_name.is_null() {
            filesystem_name.copy_from_nonoverlapping(name.as_ptr(), name.len());
        }
        // Match BY_HANDLE_FILE_INFORMATION's stable guest volume serial.
        if !serial.is_null() {
            serial.write(0x5743_4c49);
        }
        if !maximum_component.is_null() {
            maximum_component.write(255);
        }
        // Case-preserved Unicode names and reparse points; no object-ID API.
        if !flags.is_null() {
            flags.write(0x86);
        }
    }
    1
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_file_information_by_handle_ex(
    handle: u64,
    information_class: i32,
    output: *mut u8,
    output_size: u32,
) -> i32 {
    if output.is_null() {
        native_set_last_error(998); // ERROR_NOACCESS
        return 0;
    }
    if let Some(layout) = DirectoryInfoLayout::for_class(information_class) {
        return native_directory_information(handle, layout, output, output_size);
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(file) = ctx.handles.get(&handle) else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let is_directory = ctx.fs.is_dir(&file.path);
    let size = if is_directory {
        0
    } else {
        match ctx.fs.file_len(&file.path) {
            Ok(length) => length,
            Err(_) => {
                native_set_last_error(2);
                return 0;
            }
        }
    };
    let required_size = match information_class {
        0 => 40,  // FileBasicInfo
        1 => 24,  // FileStandardInfo
        9 => 8,   // FileAttributeTagInfo
        18 => 24, // FileIdInfo
        _ => {
            native_set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
    };
    let metadata = ctx.fs.file_metadata(&file.path);
    if output_size < required_size {
        native_set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    unsafe {
        ptr::write_bytes(output, 0, required_size as usize);
        match information_class {
            0 => {
                (output as *mut u64).write_unaligned(metadata.creation_time);
                (output.add(8) as *mut u64).write_unaligned(metadata.access_time);
                (output.add(16) as *mut u64).write_unaligned(metadata.write_time);
                (output.add(24) as *mut u64).write_unaligned(metadata.write_time);
                (output.add(32) as *mut u32).write_unaligned(native_file_attributes_at(
                    &ctx,
                    &file.path,
                    is_directory,
                ));
            }
            1 => {
                let allocation_size = size.saturating_add(4095) & !4095;
                (output as *mut i64).write_unaligned(allocation_size as i64);
                (output.add(8) as *mut i64).write_unaligned(size as i64);
                (output.add(16) as *mut u32).write_unaligned(1);
                *output.add(21) = u8::from(is_directory);
            }
            9 => {
                (output as *mut u32).write_unaligned(native_file_attributes_at(
                    &ctx,
                    &file.path,
                    is_directory,
                ));
            }
            18 => {
                (output as *mut u64).write_unaligned(0x5743_4C49);
                (output.add(8) as *mut u64)
                    .write_unaligned(ctx.fs.file_id(&file.path).unwrap_or_default());
            }
            _ => unreachable!(),
        }
    }
    1
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_get_file_size_ex(
    handle: u64,
    output: *mut i64,
) -> i32 {
    if output.is_null() {
        native_set_last_error(998); // ERROR_NOACCESS
        return 0;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if ctx.devices.contains_key(&handle) {
        unsafe { output.write_unaligned(0) };
        return 1;
    }
    let Some(file) = ctx.handles.get(&handle) else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let size = if ctx.fs.is_dir(&file.path) {
        0
    } else {
        match ctx.fs.file_len(&file.path) {
            Ok(length) => length as i64,
            Err(_) => {
                native_set_last_error(2);
                return 0;
            }
        }
    };
    unsafe { output.write_unaligned(size) };
    1
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_set_file_pointer_ex(
    handle: u64,
    distance: i64,
    new_position: *mut i64,
    method: u32,
) -> i32 {
    if host_standard_fd(handle).is_some() {
        native_set_last_error(1); // ERROR_INVALID_FUNCTION
        return 0;
    }
    let context = match fs_ctx() {
        Some(value) => value,
        None => return 0,
    };
    let mut ctx = match context.lock() {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let Some(file) = ctx.handles.get(&handle) else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let base = match method {
        0 => 0_i64, // FILE_BEGIN
        1 => match i64::try_from(file.offset) {
            Ok(offset) => offset,
            Err(_) => {
                native_set_last_error(87);
                return 0;
            }
        },
        2 => match ctx.fs.file_len(&file.path) {
            Ok(length) => match i64::try_from(length) {
                Ok(length) => length,
                Err(_) => {
                    native_set_last_error(87);
                    return 0;
                }
            },
            Err(_) => {
                native_set_last_error(6);
                return 0;
            }
        },
        _ => {
            native_set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
    };
    let Some(position) = base.checked_add(distance) else {
        native_set_last_error(131); // ERROR_NEGATIVE_SEEK / overflow
        return 0;
    };
    if position < 0 {
        native_set_last_error(131);
        return 0;
    }
    let file = ctx.handles.get_mut(&handle).unwrap();
    file.offset = position as usize;
    if !new_position.is_null() {
        unsafe { new_position.write(position) };
    }
    1
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_set_file_pointer(
    handle: u64,
    distance_low: i32,
    distance_high: *mut i32,
    method: u32,
) -> u32 {
    let distance = if distance_high.is_null() {
        i64::from(distance_low)
    } else {
        let high = unsafe { distance_high.read_unaligned() };
        ((i64::from(high)) << 32) | i64::from(distance_low as u32)
    };
    let mut position = 0i64;
    native_set_last_error(0);
    if native_set_file_pointer_ex(handle, distance, &mut position, method) == 0 {
        return u32::MAX;
    }
    if !distance_high.is_null() {
        unsafe { distance_high.write_unaligned((position >> 32) as i32) };
    }
    position as u32
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_read_file(
    h: u64,
    buf: *mut u8,
    n: u32,
    read_count: *mut u32,
    ov: u64,
) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native ReadFile handle={h:#x} len={n} buf={buf:p} overlap={ov:#x}");
    }
    if buf.is_null() && n != 0 {
        native_set_last_error(87);
        return 0;
    }
    let pipe = process_ctx().and_then(|process| {
        process
            .named_pipes
            .lock()
            .ok()
            .and_then(|pipes| pipes.handles.get(&h).cloned())
    });
    if let Some(pipe) = pipe {
        let can_read = if pipe.endpoint.server {
            pipe.access & 0x3 & 0x1 != 0
        } else {
            pipe.access & 0x8000_0000 != 0
        };
        if !can_read {
            native_set_last_error(5);
            return 0;
        }
        if n == 0 && ov == 0 {
            if !read_count.is_null() {
                unsafe { read_count.write(0) };
            }
            return 1;
        }
        if pipe.overlapped && ov == 0 {
            native_set_last_error(87);
            return 0;
        }
        if ov != 0 && (ov & 7 != 0 || native_overlapped_status(ov) == STATUS_PENDING) {
            native_set_last_error(87);
            return 0;
        }
        let event = match native_prepare_overlapped_event(ov) {
            Ok(event) => event,
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        };
        if ov != 0 && pipe.overlapped {
            let Some(process) = process_ctx() else {
                return 0;
            };
            if let Err(error) =
                native_submit_pipe_io(&process, h, pipe, ov, event, buf as usize, None, n as usize, None)
            {
                native_set_last_error(error);
                return 0;
            }
            if !read_count.is_null() {
                unsafe { read_count.write(0) };
            }
            native_set_last_error(997); // ERROR_IO_PENDING
            return 0;
        }
        let count = if n == 0 { 0 } else { unsafe { recv(pipe.endpoint.fd, buf.cast(), n as usize, 0) } };
        if count < 0 {
            native_complete_synchronous_pipe_io(&pipe, ov, 0, 0xc000014b, event.as_ref());
            native_set_last_error(109);
            return 0;
        }
        if count == 0 && n != 0 {
            native_complete_synchronous_pipe_io(&pipe, ov, 0, 0xc000014b, event.as_ref());
            native_set_last_error(109); // ERROR_BROKEN_PIPE
            return 0;
        }
        if !read_count.is_null() {
            unsafe { read_count.write(count as u32) };
        }
        native_complete_synchronous_pipe_io(&pipe, ov, count as u32, 0, event.as_ref());
        return 1;
    }
    if let Some((device, access)) = native_device(h) {
        if n != 0 && access & 0x8000_0000 == 0 {
            native_set_last_error(5); // ERROR_ACCESS_DENIED
            return 0;
        }
        match device {
            NativeDevice::Null => {
                if !read_count.is_null() {
                    unsafe { read_count.write(0) };
                }
                native_set_last_error(0);
                return 1; // NUL reads as immediate EOF.
            }
            NativeDevice::Console { input, .. } | NativeDevice::ConsoleIn(input) => {
                if input == h {
                    native_set_last_error(6);
                    return 0;
                }
                return native_read_file(input, buf, n, read_count, ov);
            }
            NativeDevice::ConsoleOut(_) => {
                native_set_last_error(5); // ERROR_ACCESS_DENIED
                return 0;
            }
        }
    }
    if let Some(fd) = host_standard_fd(h) {
        let count = unsafe { read(fd, buf.cast(), n as usize) };
        if count < 0 {
            return 0;
        }
        if !read_count.is_null() {
            unsafe { read_count.write(count as u32) };
        }
        return 1;
    }
    let context = match fs_ctx() {
        Some(v) => v,
        None => return 0,
    };
    let mut ctx = match context.lock() {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let (path, offset) = match ctx.handles.get(&h) {
        Some(v) => {
            if v.overlapped && ov == 0 {
                native_set_last_error(87);
                return 0;
            }
            let offset = if ov == 0 {
                Some(v.offset)
            } else {
                native_overlapped_offset(ov)
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
    if !native_file_lock_allows(&ctx, h, &path, offset as u64, n as u64, false) {
        native_set_last_error(33);
        return 0;
    }
    if ov != 0
        && ctx.handles.get(&h).is_some_and(|file| file.overlapped)
        && (ov & 7 != 0 || native_overlapped_status(ov) == STATUS_PENDING)
    {
        native_set_last_error(87);
        return 0;
    }
    if ov != 0
        && n >= DEFERRED_FILE_IO_MIN
        && ctx.handles.get(&h).is_some_and(|file| file.overlapped)
    {
        let Some(process) = process_ctx() else {
            return 0;
        };
        let file = ctx.handles.get(&h).unwrap().clone();
        if !read_count.is_null() {
            unsafe { read_count.write(0) };
        }
        drop(ctx);
        let result = native_submit_file_io(
            &process,
            h,
            file,
            ov,
            offset,
            NativeFileIoOperation::Read {
                output: buf as u64,
                length: n,
            },
        );
        native_set_last_error(result.err().unwrap_or(997));
        return 0;
    }
    let event = match native_prepare_overlapped_event(ov) {
        Ok(event) => event,
        Err(error) => {
            native_set_last_error(error);
            return 0;
        }
    };
    let file_length = match ctx.fs.file_len(&path) {
        Ok(length) => length,
        Err(_) => return 0,
    };
    if native_diagnostic_enabled() {
        eprintln!(
            "native ReadFile path={path} offset={offset} length={file_length} image_base={:#x}",
            process_ctx().map_or(0, |p| p.image_base)
        );
    }
    if ov != 0 && n != 0 && offset as u64 >= file_length {
        native_set_last_error(38); // ERROR_HANDLE_EOF
        return 0;
    }
    let mut k = 0usize;
    while k < n as usize {
        let amount = (n as usize - k).min(64 * 1024);
        let data = match ctx.fs.read_file_range(&path, (offset + k) as u64, amount) {
            Ok(data) => data,
            Err(_) => return 0,
        };
        if data.is_empty() {
            break;
        }
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf.add(k), data.len()) };
        k += data.len();
        if data.len() < amount {
            break;
        }
    }
    if native_diagnostic_enabled() {
        eprintln!("native ReadFile copied={k}");
    }
    if let Some(file) = ctx.handles.get_mut(&h) {
        if ov == 0 {
            file.offset = offset + k;
        }
        native_complete_file_io(file, ov, k as u32, event.as_ref());
    }
    if !read_count.is_null() {
        unsafe { read_count.write(k as u32) };
    }
    1
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_create_directory_w(
    p: *const u16,
    _s: u64,
) -> i32 {
    let path = wide(p);
    let Some(path) = path else {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    };
    let Some(context) = fs_ctx() else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let Ok(mut context) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    match context.fs.mkdir_one(&path) {
        Ok(()) => 1,
        Err(_) if context.fs.exists(&path) => {
            native_set_last_error(183); // ERROR_ALREADY_EXISTS
            0
        }
        Err(_) => {
            native_set_last_error(3); // ERROR_PATH_NOT_FOUND
            0
        }
    }
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_remove_directory_w(
    p: *const u16,
) -> i32 {
    let Some(path) = wide(p) else {
        native_set_last_error(87);
        return 0;
    };
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut context) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    match context.fs.rmdir(&path) {
        Ok(()) => 1,
        Err(_) if context.fs.is_file(&path) => {
            native_set_last_error(267); // ERROR_DIRECTORY
            0
        }
        Err(_) if !context.fs.exists(&path) => {
            let error = context.fs.missing_path_error(&path);
            native_set_last_error(error);
            0
        }
        Err(_) => {
            native_set_last_error(145); // ERROR_DIR_NOT_EMPTY
            0
        }
    }
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_delete_file_w(p: *const u16) -> i32 {
    let Some(path) = wide(p) else {
        native_set_last_error(87);
        return 0;
    };
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut context) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if context.fs.file_metadata(&path).attributes & 1 != 0 {
        native_set_last_error(5); // ERROR_ACCESS_DENIED for read-only files
        return 0;
    }
    match context.fs.delete_file(&path) {
        Ok(()) => 1,
        Err(_) if context.fs.is_dir(&path) => {
            native_set_last_error(5); // ERROR_ACCESS_DENIED
            0
        }
        Err(_) => {
            native_set_last_error(2); // ERROR_FILE_NOT_FOUND
            0
        }
    }
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_move_file_w(
    a: *const u16,
    b: *const u16,
) -> i32 {
    let (a, b) = match (wide(a), wide(b)) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            native_set_last_error(87);
            return 0;
        }
    };
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut context) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if !context.fs.exists(&a) {
        native_set_last_error(2);
        return 0;
    }
    if context.fs.exists(&b) && !a.eq_ignore_ascii_case(&b) {
        native_set_last_error(183);
        return 0;
    }
    match context.fs.move_path(&a, &b) {
        Ok(()) => 1,
        Err(_) => {
            native_set_last_error(3);
            0
        }
    }
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_move_file_ex_w(
    a: *const u16,
    b: *const u16,
    flags: u32,
) -> i32 {
    if flags & !0x0b != 0 || flags & 0x04 != 0 {
        native_set_last_error(if flags & 0x04 != 0 { 50 } else { 87 });
        return 0;
    }
    let (Some(source), Some(destination)) = (wide(a), wide(b)) else {
        native_set_last_error(87);
        return 0;
    };
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if !ctx.fs.exists(&source) {
        native_set_last_error(2);
        return 0;
    }
    let same_entry = matches!(
        (ctx.fs.normalize(&source), ctx.fs.normalize(&destination)),
        (Ok(a), Ok(b)) if a.key() == b.key()
    );
    if ctx.fs.exists(&destination) && !same_entry {
        if flags & 0x01 == 0 {
            native_set_last_error(183);
            return 0;
        }
        if ctx.fs.delete_file(&destination).is_err() {
            native_set_last_error(5);
            return 0;
        }
    }
    if ctx.fs.move_path(&source, &destination).is_ok() {
        1
    } else {
        native_set_last_error(2);
        0
    }
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_copy_file_w(
    a: *const u16,
    b: *const u16,
    fail: i32,
) -> i32 {
    let (source, destination) = match (wide(a), wide(b)) {
        (Some(source), Some(destination)) => (source, destination),
        _ => {
            native_set_last_error(87);
            return 0;
        }
    };
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if !ctx.fs.exists(&source) {
        native_set_last_error(2);
        return 0;
    }
    if ctx.fs.exists(&destination) && fail != 0 {
        native_set_last_error(80);
        return 0;
    }
    match ctx.fs.copy_file(&source, &destination, fail != 0) {
        Ok(()) => 1,
        Err(_) => {
            let parent = destination.rsplit_once('\\').map(|(parent, _)| parent);
            native_set_last_error(if parent.is_some_and(|parent| ctx.fs.is_dir(parent)) {
                5
            } else {
                3
            });
            0
        }
    }
}

#[cfg(test)]
mod reparse_tests {
    use super::symlink_reparse_data;

    fn name(data: &[u8], offset: usize, length: usize) -> String {
        let units: Vec<u16> = data[20 + offset..20 + offset + length]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).unwrap()
    }

    #[test]
    fn a_symlink_reparse_buffer_holds_the_nt_and_print_names() {
        let target = r"C:\Program Files\nodejs\24.21.0";
        let data = symlink_reparse_data(target);
        let u16_at = |at: usize| u16::from_le_bytes([data[at], data[at + 1]]) as usize;
        assert_eq!(&data[0..4], &0xa000_000cu32.to_le_bytes());
        assert_eq!(8 + u16_at(4), data.len());
        assert_eq!(name(&data, u16_at(8), u16_at(10)), format!(r"\??\{target}"));
        assert_eq!(name(&data, u16_at(12), u16_at(14)), target);
        assert_eq!(&data[16..20], &0u32.to_le_bytes()); // absolute
    }
}

#[cfg(test)]
mod anonymous_pipe_tests {
    use super::*;

    #[test]
    fn anonymous_pipes_transfer_enforce_access_and_preserve_duplicate_lifetime() {
        let mut reader = 0;
        let mut writer = 0;
        assert_eq!(
            native_create_pipe(&mut reader, &mut writer, std::ptr::null(), 0),
            1
        );
        assert_eq!(native_get_file_type(reader), 3);
        let mut count = 0;
        assert_eq!(
            native_write_file(writer, b"pipe".as_ptr(), 4, &mut count, 0),
            1
        );
        assert_eq!(count, 4);
        let mut buffer = [0u8; 4];
        assert_eq!(
            native_read_file(reader, buffer.as_mut_ptr(), 4, &mut count, 0),
            1
        );
        assert_eq!(&buffer, b"pipe");
        assert_eq!(
            native_write_file(reader, b"x".as_ptr(), 1, &mut count, 0),
            0
        );
        assert_eq!(native_get_last_error(), 5);
        assert_eq!(
            native_read_file(writer, buffer.as_mut_ptr(), 1, &mut count, 0),
            0
        );
        assert_eq!(native_get_last_error(), 5);
        let mut duplicate = 0;
        assert_eq!(
            native_duplicate_handle(u64::MAX, writer, u64::MAX, &mut duplicate, 0, 0, 2),
            1
        );
        assert_eq!(native_close_handle(writer), 1);
        assert_eq!(
            native_write_file(duplicate, b"x".as_ptr(), 1, &mut count, 0),
            1
        );
        assert_eq!(
            native_read_file(reader, buffer.as_mut_ptr(), 1, &mut count, 0),
            1
        );
        assert_eq!(buffer[0], b'x');
        assert_eq!(native_close_handle(duplicate), 1);
        assert_eq!(
            native_read_file(reader, buffer.as_mut_ptr(), 1, &mut count, 0),
            0
        );
        assert_eq!(native_get_last_error(), 109);
        assert_eq!(native_close_handle(reader), 1);
    }

    #[test]
    fn anonymous_pipe_security_and_invalid_arguments() {
        let mut reader = 17;
        let mut writer = 18;
        assert_eq!(
            native_create_pipe(std::ptr::null_mut(), &mut writer, std::ptr::null(), 0),
            0
        );
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(writer, 18);
        let mut security = [0u8; 24];
        assert_eq!(
            native_create_pipe(&mut reader, &mut writer, security.as_ptr(), 0),
            0
        );
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(reader, 17);
        security[..4].copy_from_slice(&24u32.to_le_bytes());
        security[16..20].copy_from_slice(&1i32.to_le_bytes());
        assert_eq!(
            native_create_pipe(&mut reader, &mut writer, security.as_ptr(), 1024),
            1
        );
        {
            let process = process_ctx().unwrap();
            let pipes = process.named_pipes.lock().unwrap();
            assert!(pipes.handles[&reader].inheritable);
            assert!(pipes.handles[&writer].inheritable);
            assert!(!pipes.handles[&reader].overlapped);
        }
        assert_eq!(native_set_handle_information(reader, 1, 0), 1);
        assert!(!process_ctx().unwrap().named_pipes.lock().unwrap().handles[&reader].inheritable);
        assert_eq!(native_close_handle(reader), 1);
        assert_eq!(native_close_handle(writer), 1);
    }

    #[test]
    fn close_source_duplication_closes_even_when_the_target_is_invalid() {
        for target in [0, 42] {
            let mut reader = 0;
            let mut writer = 0;
            assert_eq!(
                native_create_pipe(&mut reader, &mut writer, std::ptr::null(), 0),
                1
            );
            let result =
                native_duplicate_handle(u64::MAX, writer, target, std::ptr::null_mut(), 0, 0, 1);
            if target == 0 {
                assert_eq!(result, 1);
            } else {
                assert_eq!(result, 0);
                assert_eq!(native_get_last_error(), 87);
            }
            let mut byte = 0;
            let mut count = 0;
            assert_eq!(native_read_file(reader, &mut byte, 1, &mut count, 0), 0);
            assert_eq!(native_get_last_error(), 109);
            assert_eq!(native_close_handle(reader), 1);
        }
    }
}

#[cfg(test)]
mod volume_information_tests {
    use super::*;
    #[test]
    fn volume_information_validates_handles_buffers_and_optional_outputs() {
        let path: Vec<u16> = r"C:\".encode_utf16().chain([0]).collect();
        let handle = native_create_file_w(path.as_ptr(), 0x80000000, 7, 0, 3, 0x02000000, 0);
        assert_ne!(handle, u64::MAX);
        let mut serial = 0;
        let mut maximum = 0;
        let mut flags = 0;
        let mut name = [0u16; 16];
        assert_eq!(
            native_get_volume_information_by_handle_w(
                handle,
                name.as_mut_ptr(),
                16,
                &mut serial,
                &mut maximum,
                &mut flags,
                std::ptr::null_mut(),
                0
            ),
            1
        );
        assert_eq!(String::from_utf16(&name[..5]).unwrap(), "WinFS");
        assert_eq!(name[5], 0);
        assert_eq!(serial, 0x57434c49);
        assert_eq!(maximum, 255);
        assert_eq!(flags, 0x86);
        assert_eq!(
            native_get_volume_information_by_handle_w(
                handle,
                name.as_mut_ptr(),
                1,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0
            ),
            0
        );
        assert_eq!(native_get_last_error(), 234);
        assert_eq!(native_close_handle(handle), 1);
        assert_eq!(
            native_get_volume_information_by_handle_w(
                handle,
                std::ptr::null_mut(),
                0,
                &mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0
            ),
            0
        );
        assert_eq!(native_get_last_error(), 6);
    }
}
