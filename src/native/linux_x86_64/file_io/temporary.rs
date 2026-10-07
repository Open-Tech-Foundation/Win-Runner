use super::*;
use crate::system_profile;

/// `GetTempPath` from this process's environment (`%TMP%`, `%TEMP%`,
/// `%USERPROFILE%`, then the Windows directory). The directory is created
/// so a fresh guest disk can use it immediately.
fn guest_temp_path() -> String {
    let environment = process_ctx()
        .and_then(|process| process.environment.lock().ok().map(|env| env.clone()))
        .unwrap_or_default();
    let path = system_profile::temp_path(&environment);
    if let Some(context) = fs_ctx() {
        if let Ok(mut ctx) = context.lock() {
            let _ = ctx.fs.mkdir(path.trim_end_matches('\\'));
        }
    }
    path
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_temp_path_w(
    capacity: u32,
    output: *mut u16,
) -> u32 {
    let path = guest_temp_path();
    let encoded = path.encode_utf16().chain([0]).collect::<Vec<_>>();
    if capacity == 0 || output.is_null() || (capacity as usize) < encoded.len() {
        return encoded.len() as u32;
    }
    unsafe { ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()) };
    (encoded.len() - 1) as u32
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_temp_path_a(
    capacity: u32,
    output: *mut u8,
) -> u32 {
    let mut path = guest_temp_path().into_bytes();
    path.push(0);
    if capacity == 0 || output.is_null() || (capacity as usize) < path.len() {
        return path.len() as u32;
    }
    unsafe { ptr::copy_nonoverlapping(path.as_ptr(), output, path.len()) };
    (path.len() - 1) as u32
}

pub(in crate::native::linux_x86_64) fn native_create_temp_file_path(
    directory: &str,
    prefix: &str,
    unique: u32,
) -> Option<String> {
    static NEXT_TEMP_FILE: AtomicU32 = AtomicU32::new(1);
    let create_file = unique == 0;
    let id = if create_file {
        NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed) & 0xffff
    } else {
        unique & 0xffff
    };
    let directory = directory.trim_end_matches(['\\', '/']);
    let path = format!(r"{directory}\{prefix}{id:04X}.tmp");
    if let Some(context) = fs_ctx() {
        if let Ok(mut ctx) = context.lock() {
            if create_file && ctx.fs.exists(&path) {
                native_set_last_error(80);
                return None;
            }
            if create_file && ctx.fs.write_file(&path, Vec::new()).is_err() {
                native_set_last_error(3);
                return None;
            }
        }
    }
    Some(path)
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_temp_file_name_w(
    directory: *const u16,
    prefix: *const u16,
    unique: u32,
    output: *mut u16,
) -> u32 {
    let (Some(directory), Some(prefix)) = (wide(directory), wide(prefix)) else {
        native_set_last_error(87);
        return 0;
    };
    if output.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(path) = native_create_temp_file_path(&directory, &prefix, unique) else {
        return 0;
    };
    let encoded = path.encode_utf16().chain([0]).collect::<Vec<_>>();
    unsafe { ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()) };
    1
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_temp_file_name_a(
    directory: *const u8,
    prefix: *const u8,
    unique: u32,
    output: *mut u8,
) -> u32 {
    let (Some(directory), Some(prefix)) = (native_ansi_path(directory), native_ansi_path(prefix))
    else {
        native_set_last_error(87);
        return 0;
    };
    if output.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let (Ok(directory), Ok(prefix)) = (
        String::from_utf16(&directory[..directory.len().saturating_sub(1)]),
        String::from_utf16(&prefix[..prefix.len().saturating_sub(1)]),
    ) else {
        native_set_last_error(87);
        return 0;
    };
    let Some(path) = native_create_temp_file_path(&directory, &prefix, unique) else {
        return 0;
    };
    let wide_path = path.encode_utf16().chain([0]).collect::<Vec<_>>();
    let Some(encoded) = native_wide_path_to_ansi(&wide_path) else {
        native_set_last_error(1113);
        return 0;
    };
    unsafe { ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()) };
    1
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_create_file2(
    path: *const u16,
    access: u32,
    share: u32,
    creation: u32,
    extended: *const u8,
) -> u64 {
    let (security, flags, template) = if extended.is_null() {
        (0, 0, 0)
    } else {
        unsafe {
            let size = extended.cast::<u32>().read_unaligned();
            if size < 32 {
                native_set_last_error(87);
                return u64::MAX;
            }
            (
                extended.add(16).cast::<u64>().read_unaligned(),
                extended.add(8).cast::<u32>().read_unaligned(),
                extended.add(24).cast::<u64>().read_unaligned(),
            )
        }
    };
    native_create_file_w(path, access, share, security, creation, flags, template)
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_open_file_by_id(
    volume: u64,
    descriptor: *const u8,
    access: u32,
    share: u32,
    _security: *const u8,
    flags: u32,
) -> u64 {
    if descriptor.is_null() {
        native_set_last_error(87);
        return u64::MAX;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return u64::MAX;
    };
    let (volume_path, file_id) = {
        let Ok(ctx) = context.lock() else {
            native_set_last_error(6);
            return u64::MAX;
        };
        let Some(volume) = ctx.handles.get(&volume) else {
            native_set_last_error(6);
            return u64::MAX;
        };
        let size = unsafe { descriptor.cast::<u32>().read_unaligned() };
        let kind = unsafe { descriptor.add(4).cast::<u32>().read_unaligned() };
        if size < 24 || kind != 0 || !ctx.fs.is_dir(&volume.path) {
            native_set_last_error(87);
            return u64::MAX;
        }
        let file_id = unsafe { descriptor.add(8).cast::<u64>().read_unaligned() };
        (volume.path.clone(), file_id)
    };
    let path = {
        let Ok(ctx) = context.lock() else {
            native_set_last_error(6);
            return u64::MAX;
        };
        let volume_bytes = volume_path.as_bytes();
        if volume_bytes.len() < 3
            || volume_bytes[1] != b':'
            || volume_bytes[2] != b'\\'
            || volume_bytes.len() != 3
        {
            native_set_last_error(6);
            return u64::MAX;
        }
        let Some(path) = ctx.fs.path_for_file_id(file_id) else {
            native_set_last_error(2);
            return u64::MAX;
        };
        path
    };
    let wide_path = path.encode_utf16().chain([0]).collect::<Vec<_>>();
    native_create_file_w(wide_path.as_ptr(), access, share, 0, 3, flags, 0)
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_set_file_valid_data(
    handle: u64,
    _length: i64,
) -> i32 {
    let valid = fs_ctx().is_some_and(|context| {
        context
            .lock()
            .is_ok_and(|ctx| ctx.handles.contains_key(&handle))
    });
    if !valid {
        native_set_last_error(6);
        return 0;
    }
    native_set_last_error(1314); // ERROR_PRIVILEGE_NOT_HELD
    0
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_write_file_gather(
    handle: u64,
    segments: *const u64,
    length: u32,
    _reserved: *mut u32,
    overlapped: *mut u8,
) -> i32 {
    if segments.is_null() || overlapped.is_null() || length == 0 || length % 4096 != 0 {
        native_set_last_error(87);
        return 0;
    }
    let valid = fs_ctx().is_some_and(|context| {
        context
            .lock()
            .is_ok_and(|ctx| ctx.handles.get(&handle).is_some_and(|file| file.overlapped))
    });
    if !valid {
        native_set_last_error(if handle == u64::MAX { 6 } else { 87 });
        return 0;
    }
    let mut data = Vec::with_capacity(length as usize);
    let segment_count = (length / 4096) as usize;
    for index in 0..segment_count {
        let pointer = unsafe { segments.add(index).read_unaligned() } as *const u8;
        if pointer.is_null() || pointer as usize & 4095 != 0 {
            native_set_last_error(87);
            return 0;
        }
        data.extend_from_slice(unsafe { std::slice::from_raw_parts(pointer, 4096) });
    }
    let mut written = 0;
    native_write_file(
        handle,
        data.as_ptr(),
        length,
        &mut written,
        overlapped as u64,
    )
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_find_first_stream_w(
    path: *const u16,
    level: i32,
    output: *mut u8,
    flags: u32,
) -> u64 {
    let Some(path) = wide(path) else {
        native_set_last_error(87);
        return u64::MAX;
    };
    if level != 0 || flags != 0 || output.is_null() {
        native_set_last_error(87);
        return u64::MAX;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return u64::MAX;
    };
    let Ok(mut ctx) = context.lock() else {
        native_set_last_error(6);
        return u64::MAX;
    };
    let size = match ctx.fs.file_len(&path) {
        Ok(size) => size as i64,
        Err(_) => {
            native_set_last_error(if ctx.fs.is_dir(&path) { 5 } else { 2 });
            return u64::MAX;
        }
    };
    unsafe {
        ptr::write_bytes(output, 0, 600);
        output.cast::<i64>().write_unaligned(size);
        let stream_name = r"::$DATA".encode_utf16().collect::<Vec<_>>();
        ptr::copy_nonoverlapping(
            stream_name.as_ptr(),
            output.add(8).cast(),
            stream_name.len(),
        );
    }
    let handle = ctx.next;
    ctx.next += 1;
    ctx.finds.insert(
        handle,
        NativeFind {
            names: vec![r"::$DATA".to_string()],
            index: 0,
        },
    );
    handle
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_flush_file_buffers(
    handle: u64,
) -> i32 {
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    if context
        .lock()
        .is_ok_and(|ctx| ctx.handles.contains_key(&handle))
    {
        1
    } else {
        native_set_last_error(6);
        0
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_set_end_of_file(handle: u64) -> i32 {
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(file) = ctx.handles.get(&handle) else {
        native_set_last_error(6);
        return 0;
    };
    let path = file.path.clone();
    let offset = file.offset;
    match ctx.fs.set_len(&path, offset as u64) {
        Ok(()) => 1,
        Err(_) => {
            native_set_last_error(5);
            0
        }
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_reopen_file(
    handle: u64,
    access: u32,
    share: u32,
    flags: u32,
) -> u64 {
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return u64::MAX;
    };
    let Some(path) = context
        .lock()
        .ok()
        .and_then(|ctx| ctx.handles.get(&handle).map(|file| file.path.clone()))
    else {
        native_set_last_error(6);
        return u64::MAX;
    };
    let wide_path = path.encode_utf16().chain([0]).collect::<Vec<_>>();
    native_create_file_w(wide_path.as_ptr(), access, share, 0, 3, flags, 0)
}

/// Whether a FileDispositionInfo (4) or FileDispositionInfoEx (21) record
/// asks for deletion.
fn delete_requested(class: i32, information: *const u8) -> bool {
    let flags = if class == 21 {
        (unsafe { information.cast::<u32>().read_unaligned() }) & 0x1
    } else {
        u32::from(unsafe { information.read() })
    };
    flags != 0
}

fn directory_not_empty(ctx: &NativeFs, handle: u64) -> bool {
    ctx.handles.get(&handle).is_some_and(|file| {
        ctx.fs.is_dir(&file.path) && ctx.fs.list_dir(&file.path).is_ok_and(|names| !names.is_empty())
    })
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_set_file_information_by_handle(
    handle: u64,
    class: i32,
    information: *const u8,
    size: u32,
) -> i32 {
    if information.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(path) = ctx.handles.get(&handle).map(|file| file.path.clone()) else {
        native_set_last_error(6);
        return 0;
    };
    match class {
        3 if size >= 20 => {
            let name_length = unsafe { information.add(16).cast::<u32>().read_unaligned() };
            if name_length % 2 != 0 || name_length > size - 20 {
                native_set_last_error(87);
                return 0;
            }
            let units = unsafe {
                std::slice::from_raw_parts(
                    information.add(20).cast::<u16>(),
                    (name_length / 2) as usize,
                )
            };
            let Ok(destination) = String::from_utf16(units) else {
                native_set_last_error(87);
                return 0;
            };
            if ctx.fs.move_path(&path, &destination).is_err() {
                native_set_last_error(if ctx.fs.exists(&destination) { 183 } else { 2 });
                return 0;
            }
            if let Some(file) = ctx.handles.get_mut(&handle) {
                file.path = destination;
            }
            1
        }
        // FileAllocationInfo with AllocationSize 0 truncates the file, which
        // runtimes rely on to empty an existing file opened with OPEN_ALWAYS
        // (Rust's File::create). Other sizes are not implemented yet.
        5 if size >= 8 && unsafe { information.cast::<i64>().read_unaligned() } == 0 => {
            match ctx.fs.set_len(&path, 0) {
                Ok(()) => 1,
                Err(_) => {
                    native_set_last_error(5);
                    0
                }
            }
        }
        // FileEndOfFileInfo: the new end of file.
        6 if size >= 8 => {
            let length = unsafe { information.cast::<i64>().read_unaligned() };
            if length < 0 {
                native_set_last_error(87);
                return 0;
            }
            match ctx.fs.set_len(&path, length as u64) {
                Ok(()) => 1,
                Err(_) => {
                    native_set_last_error(5);
                    0
                }
            }
        }
        4 | 21 if size >= 1 && delete_requested(class, information) && directory_not_empty(&ctx, handle) => {
            native_set_last_error(145); // ERROR_DIR_NOT_EMPTY
            0
        }
        4 if size >= 1 => {
            if unsafe { information.read() } != 0 {
                ctx.delete_on_close.insert(handle);
            } else {
                ctx.delete_on_close.remove(&handle);
            }
            1
        }
        // FileDispositionInfoEx: FILE_DISPOSITION_FLAG_DELETE (0x1); POSIX
        // semantics and the other modifiers need no extra work here, since
        // the name goes away when the handle closes.
        21 if size >= 4 => {
            if unsafe { information.cast::<u32>().read_unaligned() } & 0x1 != 0 {
                ctx.delete_on_close.insert(handle);
            } else {
                ctx.delete_on_close.remove(&handle);
            }
            1
        }
        _ => {
            native_set_last_error(87);
            0
        }
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_overlapped_result_ex(
    handle: u64,
    overlapped: u64,
    bytes: *mut u32,
    timeout: u32,
    alertable: i32,
) -> i32 {
    let valid = process_ctx().is_some_and(|process| {
        process
            .fs
            .lock()
            .is_ok_and(|fs| fs.handles.contains_key(&handle))
            || process
                .named_pipes
                .lock()
                .is_ok_and(|pipes| pipes.handles.contains_key(&handle))
    });
    if !valid {
        native_set_last_error(6);
        return 0;
    }
    if overlapped == 0 || overlapped & 7 != 0 || bytes.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let deadline = wait_deadline(timeout);
    loop {
        let result = native_get_overlapped_result(handle, overlapped, bytes, 0);
        if result != 0 || native_get_last_error() != 996 {
            return result;
        }
        if timeout == 0 {
            return 0;
        }
        let event = unsafe { ((overlapped + 24) as *const u64).read_unaligned() } & !1;
        if event != 0 {
            let waited = native_wait_for_single_object_ex(event, timeout, alertable);
            if waited == 0 {
                return native_get_overlapped_result(handle, overlapped, bytes, 0);
            }
            if waited != u32::MAX {
                native_set_last_error(waited);
            }
            return 0;
        }
        if alertable != 0 && dispatch_apcs() {
            native_set_last_error(WAIT_IO_COMPLETION);
            return 0;
        }
        if wait_expired(deadline) {
            native_set_last_error(258);
            return 0;
        }
        if alertable != 0 {
            apc_pause();
        } else {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

pub(in crate::native::linux_x86_64) fn native_device(handle: u64) -> Option<(NativeDevice, u32)> {
    let handle = process_ctx()
        .and_then(|process| {
            process
                .duplicate_handles
                .lock()
                .ok()
                .and_then(|values| values.get(&handle).copied())
        })
        .unwrap_or(handle);
    let context = fs_ctx()?;
    let context = context.lock().ok()?;
    let device = context.devices.get(&handle).copied()?;
    Some((
        device,
        context.file_access.get(&handle).copied().unwrap_or(0),
    ))
}
