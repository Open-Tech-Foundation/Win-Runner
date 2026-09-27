//! NTDLL file, process, and system-information compatibility shims.

use super::*;

pub(super) extern "win64" fn native_nt_device_io_control_file(
    _file: u64,
    _event: u64,
    _apc_routine: u64,
    _apc_context: u64,
    io_status: *mut u8,
    _control_code: u32,
    _input: *const u8,
    _input_len: u32,
    _output: *mut u8,
    _output_len: u32,
) -> u32 {
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    if !io_status.is_null() {
        unsafe {
            (io_status as *mut u32).write_unaligned(STATUS_NOT_IMPLEMENTED);
            (io_status.add(8) as *mut u64).write_unaligned(0);
        }
    }
    STATUS_NOT_IMPLEMENTED
}

pub(super) extern "win64" fn native_nt_read_file(
    file: u64,
    event: u64,
    apc_routine: u64,
    _apc_context: u64,
    io_status: *mut u8,
    buffer: *mut u8,
    length: u32,
    byte_offset: *const i64,
    _key: *const u32,
) -> u32 {
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_END_OF_FILE: u32 = 0xC000_0011;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
    let finish = |status: u32, bytes: usize| {
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(bytes as u64);
            }
        }
        status
    };
    if io_status.is_null() || (buffer.is_null() && length != 0) {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    if event != 0 || apc_routine != 0 {
        return finish(STATUS_NOT_SUPPORTED, 0);
    }
    if length == 0 {
        return finish(STATUS_SUCCESS, 0);
    }
    let requested_offset = if byte_offset.is_null() {
        None
    } else {
        let value = unsafe { byte_offset.read_unaligned() };
        if value == -2 {
            None
        } else if value < 0 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        } else {
            Some(value as u64)
        }
    };
    if let Some(fd) = host_standard_fd(file) {
        if requested_offset.is_some() {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let count = unsafe { read(fd, buffer.cast(), length as usize) };
        return if count < 0 {
            finish(0xC000_0001, 0)
        } else if count == 0 {
            finish(STATUS_END_OF_FILE, 0)
        } else {
            finish(STATUS_SUCCESS, count as usize)
        };
    }
    let Some(context) = fs_ctx() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Ok(mut fs) = context.lock() else {
        return finish(0xC000_0001, 0);
    };
    let Some((path, current_offset)) = fs
        .handles
        .get(&file)
        .map(|item| (item.path.clone(), item.offset))
    else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let offset = requested_offset.unwrap_or(current_offset as u64);
    let Ok(offset) = usize::try_from(offset) else {
        return finish(STATUS_INVALID_PARAMETER, 0);
    };
    let Ok(file_length) = fs.fs.file_len(&path) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    if offset as u64 >= file_length {
        return finish(STATUS_END_OF_FILE, 0);
    }
    let mut count = 0usize;
    while count < length as usize {
        let amount = (length as usize - count).min(64 * 1024);
        let Ok(contents) = fs
            .fs
            .read_file_range(&path, (offset + count) as u64, amount)
        else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        if contents.is_empty() {
            break;
        }
        unsafe { ptr::copy_nonoverlapping(contents.as_ptr(), buffer.add(count), contents.len()) };
        count += contents.len();
        if contents.len() < amount {
            break;
        }
    }
    if let Some(item) = fs.handles.get_mut(&file) {
        item.offset = offset + count;
    }
    finish(STATUS_SUCCESS, count)
}

pub(super) extern "win64" fn native_nt_write_file(
    file: u64,
    event: u64,
    apc_routine: u64,
    _apc_context: u64,
    io_status: *mut u8,
    buffer: *const u8,
    length: u32,
    byte_offset: *const i64,
    _key: *const u32,
) -> u32 {
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
    let finish = |status: u32, bytes: usize| {
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(bytes as u64);
            }
        }
        status
    };
    if io_status.is_null() || (buffer.is_null() && length != 0) {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    if event != 0 || apc_routine != 0 {
        return finish(STATUS_NOT_SUPPORTED, 0);
    }
    if length == 0 {
        return finish(STATUS_SUCCESS, 0);
    }
    let requested_offset = if byte_offset.is_null() {
        None
    } else {
        let value = unsafe { byte_offset.read_unaligned() };
        if value == -2 {
            None
        } else if value < 0 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        } else {
            Some(value as u64)
        }
    };
    if let Some(fd) = host_standard_fd(file) {
        if requested_offset.is_some() {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let count = unsafe { write(fd, buffer.cast(), length as usize) };
        return if count < 0 {
            finish(0xC000_0001, 0)
        } else {
            finish(STATUS_SUCCESS, count as usize)
        };
    }
    let Some(context) = fs_ctx() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Ok(mut fs) = context.lock() else {
        return finish(0xC000_0001, 0);
    };
    let Some((path, current_offset)) = fs
        .handles
        .get(&file)
        .map(|item| (item.path.clone(), item.offset))
    else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let offset = requested_offset.unwrap_or(current_offset as u64);
    let Ok(offset) = usize::try_from(offset) else {
        return finish(STATUS_INVALID_PARAMETER, 0);
    };
    let Ok(mut contents) = fs.fs.read_file(&path) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let count = length as usize;
    let Some(end) = offset.checked_add(count) else {
        return finish(STATUS_INVALID_PARAMETER, 0);
    };
    if contents.len() < end {
        if contents.try_reserve(end - contents.len()).is_err() {
            return finish(0xC000_0017, 0); // STATUS_NO_MEMORY
        }
        contents.resize(end, 0);
    }
    unsafe { ptr::copy_nonoverlapping(buffer, contents.as_mut_ptr().add(offset), count) };
    if fs.fs.write_file(&path, contents).is_err() {
        return finish(0xC000_0001, 0);
    }
    if let Some(item) = fs.handles.get_mut(&file) {
        item.offset = end;
    }
    finish(STATUS_SUCCESS, count)
}

pub(super) extern "win64" fn native_nt_query_information_file(
    file: u64,
    io_status: *mut u8,
    information: *mut u8,
    length: u32,
    information_class: u32,
) -> u32 {
    let original = process_ctx()
        .and_then(|process| {
            process
                .duplicate_handles
                .lock()
                .ok()
                .and_then(|values| values.get(&file).copied())
        })
        .unwrap_or(file);
    if let Some(fd) = host_standard_fd(original) {
        if !information.is_null() && length >= 4 && matches!(information_class, 8 | 16) {
            let value = match information_class {
                8 if fd == 0 => 1, // FILE_READ_DATA
                8 => 2,            // FILE_WRITE_DATA
                16 => 0x20,        // FILE_SYNCHRONOUS_IO_NONALERT
                _ => unreachable!(),
            };
            unsafe { (information as *mut u32).write_unaligned(value) };
            if !io_status.is_null() {
                unsafe {
                    (io_status as *mut u32).write_unaligned(0);
                    (io_status.add(8) as *mut u64).write_unaligned(4);
                }
            }
            return 0;
        }
    }
    if information_class == 16 && !information.is_null() && length >= 4 {
        if let Some(pipe) = process_ctx().and_then(|process| {
            process
                .named_pipes
                .lock()
                .ok()
                .and_then(|pipes| pipes.handles.get(&original).cloned())
        }) {
            let mode = if pipe.overlapped { 0 } else { 0x20 }; // FILE_SYNCHRONOUS_IO_NONALERT
            unsafe { (information as *mut u32).write_unaligned(mode) };
            if !io_status.is_null() {
                unsafe {
                    (io_status as *mut u32).write_unaligned(0);
                    (io_status.add(8) as *mut u64).write_unaligned(4);
                }
            }
            return 0; // STATUS_SUCCESS
        }
    }
    if information_class == 18 && !information.is_null() && length >= 96 {
        if let Some(context) = fs_ctx() {
            if let Ok(ctx) = context.lock() {
                if let Some(file) = ctx.handles.get(&original) {
                    let is_directory = ctx.fs.is_dir(&file.path);
                    let size = if is_directory {
                        0
                    } else {
                        ctx.fs
                            .read_file(&file.path)
                            .map_or(0, |data| data.len() as u64)
                    };
                    let file_id = ctx.fs.file_id(&file.path).unwrap_or(0);
                    let metadata = ctx.fs.file_metadata(&file.path);
                    let written = length.min(104) as usize;
                    unsafe {
                        std::ptr::write_bytes(information, 0, written);
                        (information as *mut u64).write_unaligned(metadata.creation_time);
                        (information.add(8) as *mut u64).write_unaligned(metadata.access_time);
                        (information.add(16) as *mut u64).write_unaligned(metadata.write_time);
                        (information.add(24) as *mut u64).write_unaligned(metadata.write_time);
                        (information.add(32) as *mut u32).write_unaligned(
                            native_file_attributes_at(&ctx, &file.path, is_directory),
                        );
                        (information.add(40) as *mut u64).write_unaligned(size);
                        (information.add(48) as *mut u64).write_unaligned(size);
                        (information.add(56) as *mut u32).write_unaligned(1);
                        information.add(61).write(is_directory as u8);
                        (information.add(64) as *mut u64).write_unaligned(file_id);
                    }
                    if !io_status.is_null() {
                        unsafe {
                            (io_status as *mut u32).write_unaligned(0);
                            (io_status.add(8) as *mut u64).write_unaligned(written as u64);
                        }
                    }
                    return 0;
                }
            }
        }
    }
    if information_class == 18 {
        let status = if information.is_null() || length < 96 {
            0xC000_0004 // STATUS_INFO_LENGTH_MISMATCH
        } else {
            0xC000_0008 // STATUS_INVALID_HANDLE
        };
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(0);
            }
        }
        return status;
    }
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    if !io_status.is_null() {
        unsafe {
            (io_status as *mut u32).write_unaligned(STATUS_NOT_IMPLEMENTED);
            (io_status.add(8) as *mut u64).write_unaligned(0);
        }
    }
    STATUS_NOT_IMPLEMENTED
}

pub(super) extern "win64" fn native_nt_set_information_file(
    file: u64,
    io_status: *mut u8,
    information: *const u8,
    length: u32,
    information_class: u32,
) -> u32 {
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    let finish = |status: u32, information: u64| {
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(information);
            }
        }
        status
    };
    if information_class == 20 {
        if information.is_null() || length < 8 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let end = unsafe { information.cast::<i64>().read_unaligned() };
        if end < 0 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let Some(context) = fs_ctx() else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let Ok(mut context) = context.lock() else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let Some(path) = context.handles.get(&file).map(|handle| handle.path.clone()) else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let mapped = process_ctx()
            .and_then(|process| {
                process.mapping_views.lock().ok().map(|views| {
                    views.values().any(|view| {
                        view.backing.as_ref().is_some_and(|(mapped_path, _)| {
                            context.fs.normalize(mapped_path).ok()
                                == context.fs.normalize(&path).ok()
                        })
                    })
                })
            })
            .unwrap_or(false);
        let mut contents = match context.fs.read_file(&path) {
            Ok(contents) => contents,
            Err(_) => return finish(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        };
        if (end as usize) < contents.len() && mapped {
            return finish(STATUS_ACCESS_DENIED, 0);
        }
        let Ok(end) = usize::try_from(end) else {
            return finish(STATUS_INVALID_PARAMETER, 0);
        };
        contents.resize(end, 0);
        return match context.fs.write_file(&path, contents) {
            Ok(()) => finish(STATUS_SUCCESS, end as u64),
            Err(_) => finish(STATUS_ACCESS_DENIED, 0),
        };
    }
    if information_class == 10 {
        if information.is_null() || length < 20 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let replace = unsafe { information.read() != 0 };
        let name_length = unsafe { information.add(16).cast::<u32>().read_unaligned() } as usize;
        if name_length == 0 || name_length % 2 != 0 || name_length > length as usize - 20 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let name = unsafe {
            std::slice::from_raw_parts(information.add(20).cast::<u16>(), name_length / 2)
        };
        let destination = String::from_utf16_lossy(name);
        let Some(context) = fs_ctx() else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let Ok(mut context) = context.lock() else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let Some(source) = context.handles.get(&file).map(|handle| handle.path.clone()) else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        if context.fs.exists(&destination) {
            if !replace {
                return finish(0xC000_0035, 0); // STATUS_OBJECT_NAME_COLLISION
            }
            let is_dir = context.fs.is_dir(&destination);
            let removed = if is_dir {
                context.fs.rmdir(&destination)
            } else {
                context.fs.delete_file(&destination)
            };
            if removed.is_err() {
                return finish(STATUS_ACCESS_DENIED, 0);
            }
        }
        return match context.fs.move_path(&source, &destination) {
            Ok(()) => {
                for handle in context.handles.values_mut() {
                    if handle.path.eq_ignore_ascii_case(&source) {
                        handle.path = destination.clone();
                    }
                }
                finish(STATUS_SUCCESS, 0)
            }
            Err(_) => finish(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        };
    }
    let disposition = match information_class {
        13 if !information.is_null() && length >= 1 => unsafe {
            u32::from(information.read() != 0)
        },
        // FILE_DISPOSITION_INFORMATION_EX: Flags is a ULONG; DELETE is
        // bit 0. libuv uses this class for recursive fs.rm/unlink on
        // current Windows releases.
        64 if !information.is_null() && length >= 4 => unsafe {
            information.cast::<u32>().read_unaligned()
        },
        13 | 64 => return finish(STATUS_INVALID_PARAMETER, 0),
        _ => return finish(STATUS_NOT_IMPLEMENTED, 0),
    };
    // A zero disposition cancels deletion. The in-memory filesystem only
    // removes names on a set operation, so clearing is a successful no-op.
    if disposition == 0 {
        return finish(STATUS_SUCCESS, 0);
    }
    if disposition & !0x3f != 0 {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    let Some(context) = fs_ctx() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Ok(mut context) = context.lock() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Some(path) = context.handles.get(&file).map(|handle| handle.path.clone()) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let status = if context.fs.is_dir(&path) {
        context.fs.rmdir(&path)
    } else {
        context.fs.delete_file(&path)
    };
    match status {
        Ok(()) => finish(STATUS_SUCCESS, 0),
        Err(_) if !context.fs.exists(&path) => finish(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        Err(_) => finish(STATUS_ACCESS_DENIED, 0),
    }
}

pub(super) extern "win64" fn native_nt_query_volume_information_file(
    file: u64,
    io_status: *mut u8,
    information: *mut u8,
    length: u32,
    information_class: u32,
) -> u32 {
    if information_class == 4 && !information.is_null() && length >= 8 {
        if fs_ctx().is_some_and(|context| {
            context
                .lock()
                .is_ok_and(|fs| fs.handles.contains_key(&file))
        }) {
            unsafe {
                (information as *mut u32).write_unaligned(7); // FILE_DEVICE_DISK
                (information.add(4) as *mut u32).write_unaligned(0);
            }
            if !io_status.is_null() {
                unsafe {
                    (io_status as *mut u32).write_unaligned(0);
                    (io_status.add(8) as *mut u64).write_unaligned(8);
                }
            }
            return 0;
        }
    }
    if information_class == 4 {
        let status = if information.is_null() || length < 8 {
            0xC000_0004 // STATUS_INFO_LENGTH_MISMATCH
        } else {
            0xC000_0008 // STATUS_INVALID_HANDLE
        };
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(0);
            }
        }
        return status;
    }
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    if !io_status.is_null() {
        unsafe {
            (io_status as *mut u32).write_unaligned(STATUS_NOT_IMPLEMENTED);
            (io_status.add(8) as *mut u64).write_unaligned(0);
        }
    }
    STATUS_NOT_IMPLEMENTED
}

pub(super) extern "win64" fn native_nt_query_directory_file(
    file: u64,
    _event: u64,
    _apc_routine: u64,
    _apc_context: u64,
    io_status: *mut u8,
    information: *mut u8,
    length: u32,
    information_class: u32,
    return_single_entry: u8,
    _file_name: *const u8,
    restart_scan: u8,
) -> u32 {
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
    let finish = |status: u32, bytes: usize| {
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(bytes as u64);
            }
        }
        status
    };
    if io_status.is_null() || (information.is_null() && length != 0) {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    if information_class != 1 || return_single_entry > 1 || length < 64 {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    let Some(context) = fs_ctx() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Ok(mut ctx) = context.lock() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Some(file_info) = ctx.handles.get(&file) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let path = file_info.path.clone();
    if !ctx.fs.is_dir(&path) {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    let Ok(names) = ctx.fs.list_dir(&path) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let index = if restart_scan != 0 {
        0
    } else {
        file_info.offset
    };
    if index >= names.len() {
        if let Some(file_info) = ctx.handles.get_mut(&file) {
            file_info.offset = names.len();
        }
        return finish(STATUS_NO_MORE_FILES, 0);
    }
    let mut written = 0usize;
    let mut current = index;
    loop {
        let encoded: Vec<u16> = names[current].encode_utf16().collect();
        let entry_size = (64 + encoded.len() * 2 + 7) & !7;
        if written + entry_size > length as usize {
            if written == 0 {
                return finish(STATUS_INVALID_PARAMETER, 0);
            }
            break;
        }
        unsafe {
            let entry = information.add(written);
            std::ptr::write_bytes(entry, 0, entry_size);
            (entry.add(60) as *mut u32).write_unaligned((encoded.len() * 2) as u32);
            entry
                .add(56)
                .cast::<u32>()
                .write_unaligned(native_file_attributes(
                    ctx.fs.is_dir(&format!("{path}\\{}", names[current])),
                ));
            entry
                .add(64)
                .cast::<u16>()
                .copy_from_nonoverlapping(encoded.as_ptr(), encoded.len());
        }
        let next = current + 1;
        if return_single_entry != 0 || next == names.len() {
            written += 64 + encoded.len() * 2;
            current = next;
            break;
        }
        let next_size = (64 + names[next].encode_utf16().count() * 2 + 7) & !7;
        if written + entry_size + next_size > length as usize {
            written += 64 + encoded.len() * 2;
            current = next;
            break;
        }
        unsafe {
            (information.add(written) as *mut u32).write_unaligned(entry_size as u32);
        }
        written += entry_size;
        current = next;
    }
    if let Some(file_info) = ctx.handles.get_mut(&file) {
        file_info.offset = current;
    }
    finish(STATUS_SUCCESS, written)
}

pub(super) extern "win64" fn native_nt_query_system_information(
    _information_class: u32,
    _information: *mut u8,
    _length: u32,
    return_length: *mut u32,
) -> u32 {
    if !return_length.is_null() {
        unsafe { return_length.write(0) };
    }
    0xC000_0002 // STATUS_NOT_IMPLEMENTED
}

pub(super) extern "win64" fn native_nt_query_information_process(
    _process: u64,
    _information_class: u32,
    _information: *mut u8,
    _length: u32,
    return_length: *mut u32,
) -> u32 {
    if !return_length.is_null() {
        unsafe { return_length.write(0) };
    }
    0xC000_0002 // STATUS_NOT_IMPLEMENTED
}
