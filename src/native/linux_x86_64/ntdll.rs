//! NTDLL file, process, and system-information compatibility shims.

use super::*;

#[cfg(test)]
mod startup_tests {
    use super::*;
    #[test]
    fn module_identity_and_static_nt_bindings_match_dynamic_exports() {
        let _guard = TestProcessGuard::new();
        native_set_last_error(42);
        let module = native_get_module_handle_a(ptr::null());
        assert_ne!(module, 0);
        assert_eq!(module, native_get_module_handle_w(ptr::null()));
        assert_eq!(native_get_last_error(), 42);
        for name in [
            "NtClose",
            "NtWaitForSingleObject",
            "NtQueryDirectoryFile",
            "NtQueryInformationFile",
            "NtQueryVolumeInformationFile",
            "NtSetInformationFile",
            "NtQueryAttributesFile",
            "RtlWaitOnAddress",
            "RtlWakeAddressAll",
            "RtlWakeAddressSingle",
        ] {
            assert!(
                super::super::registry::supports_import("ntdll.dll", name),
                "{name}"
            );
            let c_name = format!("{name}\0");
            assert_eq!(
                native_get_proc_address(API_SET_MODULE, c_name.as_ptr()),
                baseline_trampoline(name).unwrap(),
                "{name}"
            );
        }
        let socket = native_load_library_a(b"WSOCK32.dll\0".as_ptr());
        assert_ne!(socket, 0);
        assert_eq!(
            native_get_proc_address(socket, 111usize as *const u8),
            native_get_proc_address(socket, b"WSAGetLastError\0".as_ptr())
        );
        for (ordinal, name) in [(10, "inet_addr"), (11, "inet_ntoa"), (12, "ioctlsocket"), (18, "select"), (151, "__WSAFDIsSet")] {
            let name = format!("{name}\0");
            assert_eq!(native_get_proc_address(socket, ordinal as *const u8), native_get_proc_address(socket, name.as_ptr()));
        }
        let modern = native_load_library_a(b"WS2_32.dll\0".as_ptr());
        assert_ne!(modern, socket);
        for (ordinal, name) in [(10, "ioctlsocket"), (11, "inet_addr"), (12, "inet_ntoa")] {
            let c_name = format!("{name}\0");
            assert_eq!(native_get_proc_address(modern, c_name.as_ptr()), baseline_trampoline(name).unwrap());
            let expected = baseline_trampoline(name).unwrap();
            assert_eq!(native_get_proc_address(modern, ordinal as *const u8), expected);
            for dll in ["WSOCK32.dll", "WS2_32.dll"] {
                let selector = format!("#{ordinal}");
                let name = super::super::registry::ordinal_export_name(dll, &selector).unwrap();
                assert!(super::super::registry::supports_import(dll, &selector));
                assert!(baseline_trampoline(name).is_some());
            }
        }
        assert_eq!(native_free_library(socket), 1);
        assert_eq!(native_free_library(modern), 1);
        assert_eq!(native_get_proc_address(socket, 65535usize as *const u8), 0);
        assert_eq!(native_get_last_error(), 127);
    }
    #[test]
    fn nt_device_names_round_trip_to_the_same_guest_file() {
        let _guard = TestProcessGuard::new();
        let path = r"C:\nt-device.txt";
        fs_ctx().unwrap().lock().unwrap().fs.write_file(path, b"device-path".to_vec()).unwrap();
        for (name, expected) in [(r"\Device\HarddiskVolume3\nt-device.txt", path), (r"\device\harddiskvolume3", r"C:\")] {
            let units: Vec<u16> = name.encode_utf16().collect();
            let unicode = [units.len() as u64 * 2 | ((units.len() as u64 * 2) << 16), units.as_ptr() as u64];
            let attributes = [48u64, 0, unicode.as_ptr() as u64, 0, 0, 0];
            assert_eq!(object_attributes_path(attributes.as_ptr().cast()).unwrap(), expected);
            let mut info = [0u64;5];
            assert_eq!(native_nt_query_attributes_file(attributes.as_ptr().cast(), info.as_mut_ptr().cast()), 0);
        }
    }

    #[test]
    fn nt_pipe_access_queries_map_generic_client_rights_and_duplicates() {
        let _guard = TestProcessGuard::new();
        let mut read = 0;
        let mut write = 0;
        assert_eq!(native_create_pipe(&mut read, &mut write, ptr::null(), 0), 1);
        let process = process_ctx().unwrap().process_handle;
        let mut duplicate = 0;
        assert_eq!(native_duplicate_handle(process, read, process, &mut duplicate, 0, 0, 2), 1);
        for (handle, expected) in [(read, 1u32), (write, 2), (duplicate, 1)] {
            let mut access = 0u32;
            let mut status = [u64::MAX; 2];
            assert_eq!(native_nt_query_information_file(handle, status.as_mut_ptr().cast(), (&mut access as *mut u32).cast(), 4, 8), 0);
            assert_eq!(access, expected);
            assert_eq!(status[0] as u32, 0);
            assert_eq!(status[1], 4);
        }
        let mut overlap_write = [0u64;4];
        let mut overlap_read = [0u64;4];
        let mut transferred = 0;
        assert_eq!(native_write_file(write, b"sync-pipe".as_ptr(), 9, &mut transferred, overlap_write.as_mut_ptr() as u64), 1);
        assert_eq!(transferred, 9);
        assert_eq!(overlap_write[1], 9);
        let mut buffer = [0u8;9];
        assert_eq!(native_read_file(duplicate, buffer.as_mut_ptr(), 9, &mut transferred, overlap_read.as_mut_ptr() as u64), 1);
        assert_eq!(buffer, *b"sync-pipe");
        assert_eq!(overlap_read[1], 9);
        native_close_handle(write);
        overlap_read.fill(0);
        assert_eq!(native_read_file(read, buffer.as_mut_ptr(), 9, &mut transferred, overlap_read.as_mut_ptr() as u64), 0);
        assert_eq!(native_get_last_error(), 109);
        assert_eq!(overlap_read[0], 0xc000014b);
        native_close_handle(read); native_close_handle(duplicate);
    }

    #[test]
    fn duplicated_file_handles_keep_their_file_type() {
        let _guard = TestProcessGuard::new();
        let path = r"C:\duplicate-file-type.txt";
        fs_ctx().unwrap().lock().unwrap().fs.write_file(path, b"abc".to_vec()).unwrap();
        let name: Vec<_> = path.encode_utf16().chain([0]).collect();
        let file = native_create_file_w(name.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(file, u64::MAX);
        let process = process_ctx().unwrap().process_handle;
        let mut duplicate = 0;
        assert_eq!(native_duplicate_handle(process, file, process, &mut duplicate, 0, 0, 2), 1);
        assert_eq!(native_get_file_type(file), 1);
        assert_eq!(native_get_file_type(duplicate), 1);
        assert_eq!(native_close_handle(duplicate), 1);
        assert_eq!(native_get_file_type(duplicate), 0);
        assert_eq!(native_get_last_error(), 6);
        assert_eq!(native_get_file_type(file), 1);
        assert_eq!(native_close_handle(file), 1);
    }
    #[test]
    fn nt_close_preserves_last_error_and_protected_handles() {
        let _guard = TestProcessGuard::new();
        let handle = native_open_thread(0x800, 0, native_get_current_thread_id());
        assert_ne!(handle, 0);
        native_set_last_error(42);
        assert_eq!(native_set_handle_information(handle, 2, 2), 1);
        assert_eq!(native_nt_close(handle), 0xc0000235);
        assert_eq!(native_get_last_error(), 42);
        assert_eq!(native_set_handle_information(handle, 2, 0), 1);
        assert_eq!(native_nt_close(handle), 0);
        assert_eq!(native_get_last_error(), 42);
        assert_eq!(native_nt_close(handle), 0xc0000008);
        assert_eq!(native_get_last_error(), 42);
    }
    #[test]
    fn rtl_wait_translates_nt_timeouts_and_preserves_last_error() {
        let address = 1u32;
        let different = 2u32;
        let poll = 0i64;
        let relative = -10_000i64;
        native_set_last_error(42);
        let a = (&address as *const u32).cast();
        assert_eq!(
            native_rtl_wait_on_address(a, (&different as *const u32).cast(), 4, ptr::null()),
            0
        );
        assert_eq!(native_rtl_wait_on_address(a, a, 4, &poll), 0x102);
        assert_eq!(native_rtl_wait_on_address(a, a, 4, &relative), 0x102);
        assert_eq!(native_rtl_wait_on_address(a, a, 3, &poll), 0xc000000d);
        assert_eq!(native_get_last_error(), 42);
    }
    #[test]
    fn nt_attributes_return_metadata_and_leave_error_outputs_untouched() {
        let _guard = TestProcessGuard::new();
        let path = r"C:\native-startup-unit.txt";
        fs_ctx()
            .unwrap()
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"abc".to_vec())
            .unwrap();
        let units: Vec<u16> = path.encode_utf16().collect();
        let bytes = units.len() * 2;
        let unicode = [bytes | (bytes << 16), units.as_ptr() as usize];
        let mut attributes = [48usize, 0, unicode.as_ptr() as usize, 0x40, 0, 0];
        let mut basic = [0u64; 5];
        native_set_last_error(42);
        assert_eq!(
            native_nt_query_attributes_file(attributes.as_ptr().cast(), basic.as_mut_ptr().cast()),
            0
        );
        assert_eq!(
            basic[0],
            fs_ctx()
                .unwrap()
                .lock()
                .unwrap()
                .fs
                .file_metadata(path)
                .creation_time
        );
        assert_eq!(basic[4] as u32 & 0x10, 0);
        assert_eq!(native_get_last_error(), 42);
        attributes[1] = 0xdead;
        basic.fill(42);
        assert_eq!(
            native_nt_query_attributes_file(attributes.as_ptr().cast(), basic.as_mut_ptr().cast()),
            0xc0000008
        );
        assert_eq!(basic, [42; 5]);
        assert_eq!(
            native_nt_query_attributes_file(ptr::null(), ptr::null_mut()),
            0xc000000d
        );
    }
    #[test]
    fn wide_hostname_matches_narrow_and_rejects_small_buffers() {
        let mut narrow = [0u8; 256];
        let mut wide = [0u16; 256];
        assert_eq!(native_wsa_get_host_name(narrow.as_mut_ptr(), 256), 0);
        assert_eq!(native_wsa_get_host_name_w(wide.as_mut_ptr(), 256), 0);
        let n = narrow.iter().position(|value| *value == 0).unwrap();
        let w = wide.iter().position(|value| *value == 0).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&narrow[..n]),
            String::from_utf16_lossy(&wide[..w])
        );
        let mut small = [42u16];
        assert_eq!(native_wsa_get_host_name_w(small.as_mut_ptr(), 1), -1);
        assert_eq!(native_wsa_get_last_error(), 10014);
        assert_eq!(small, [42]);
        assert_eq!(native_wsa_get_host_name_w(ptr::null_mut(), 256), -1);
    }
}

pub(super) extern "win64" fn native_nt_close(handle: u64) -> u32 {
    let previous_error = native_get_last_error();
    let status = if native_close_handle(handle) != 0 {
        0 // STATUS_SUCCESS
    } else {
        match native_get_last_error() {
            5 => 0xC000_0235, // STATUS_HANDLE_NOT_CLOSABLE
            _ => 0xC000_0008, // STATUS_INVALID_HANDLE
        }
    };
    native_set_last_error(previous_error);
    status
}

/// Native object waits use NT 100-nanosecond timeouts and preserve Win32 last error.
pub(super) extern "win64" fn native_nt_wait_for_single_object(
    handle: u64,
    alertable: u8,
    timeout: *const i64,
) -> u32 {
    if handle == 0 {
        return 0xc0000008; // NULL is never a waitable NT handle.
    }
    let milliseconds = if timeout.is_null() {
        u32::MAX
    } else {
        let ticks = unsafe { timeout.read_unaligned() };
        let remaining = if ticks < 0 {
            ticks.unsigned_abs()
        } else {
            (ticks as u64).saturating_sub(process_filetime_now())
        };
        remaining.div_ceil(10_000).min(u32::MAX as u64 - 1) as u32
    };
    let previous = native_get_last_error();
    let result = native_wait_for_single_object_ex(handle, milliseconds, alertable as i32);
    let status = match result {
        0 | 0x80 | 0xc0 | 0x102 => result,
        _ => match native_get_last_error() {
            5 => 0xc0000022, // STATUS_ACCESS_DENIED
            87 => 0xc000000d,
            _ => 0xc0000008,
        },
    };
    native_set_last_error(previous);
    status
}

pub(super) extern "win64" fn native_rtl_wait_on_address(
    address: *const u8,
    compare: *const u8,
    size: usize,
    timeout: *const i64,
) -> u32 {
    if !matches!(size, 1 | 2 | 4 | 8) {
        return 0xC000_000D;
    }
    let milliseconds = if timeout.is_null() {
        u32::MAX
    } else {
        let ticks = unsafe { timeout.read_unaligned() };
        let remaining = if ticks < 0 {
            ticks.unsigned_abs()
        } else {
            (ticks as u64).saturating_sub(process_filetime_now())
        };
        remaining.div_ceil(10_000).min(u32::MAX as u64 - 1) as u32
    };
    let previous_error = native_get_last_error();
    let status = if native_wait_on_address(address, compare, size, milliseconds) != 0 {
        0
    } else if native_get_last_error() == 1460 {
        0x102 // STATUS_TIMEOUT
    } else {
        0xC000_000D // STATUS_INVALID_PARAMETER
    };
    native_set_last_error(previous_error);
    status
}

pub(super) extern "win64" fn native_nt_device_io_control_file(
    file: u64,
    _event: u64,
    _apc_routine: u64,
    apc_context: u64,
    io_status: *mut u8,
    control_code: u32,
    input: *const u8,
    input_len: u32,
    output: *mut u8,
    output_len: u32,
) -> u32 {
    if is_afd_handle(file) {
        return afd_device_io_control(file, apc_context, io_status, control_code, input, input_len, output, output_len);
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
    let count = length as usize;
    let Some(end) = offset.checked_add(count) else {
        return finish(STATUS_INVALID_PARAMETER, 0);
    };
    let data = if count == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(buffer, count) }
    };
    if fs.fs.write_at(&path, offset as u64, data).is_err() {
        return finish(0xC000_007F, 0); // STATUS_DISK_FULL
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
    if information_class == 8 && !information.is_null() && length >= 4 {
        if let Some(pipe) = process_ctx().and_then(|process| {
            process
                .named_pipes
                .lock()
                .ok()
                .and_then(|pipes| pipes.handles.get(&original).cloned())
        }) {
            let access = pipe.access;
            let flags = if pipe.endpoint.server {
                access & 3 // PIPE_ACCESS_INBOUND/OUTBOUND on server handles
            } else {
                (if access & (0x8000_0000 | 0x1000_0000 | 1) != 0 { 1 } else { 0 })
                    | (if access & (0x4000_0000 | 0x1000_0000 | 2) != 0 { 2 } else { 0 })
            };
            unsafe { (information as *mut u32).write_unaligned(flags) };
            if !io_status.is_null() {
                unsafe {
                    (io_status as *mut u32).write_unaligned(0);
                    (io_status.add(8) as *mut u64).write_unaligned(4);
                }
            }
            return 0; // STATUS_SUCCESS
        }
    }
    // FilePipeLocalInformation is used by libuv to avoid an unnecessary
    // FlushFileBuffers call when the pipe has no queued writes. Return the
    // fixed byte-stream pipe quotas and a fully available outbound quota for
    // these in-memory named pipes.
    if information_class == 24 && !information.is_null() && length >= 40 {
        if let Some(pipe) = process_ctx().and_then(|process| {
            process
                .named_pipes
                .lock()
                .ok()
                .and_then(|pipes| pipes.handles.get(&original).cloned())
        }) {
            let values = [
                0,                               // FILE_PIPE_BYTE_STREAM_TYPE
                2,                               // FILE_PIPE_FULL_DUPLEX
                255,                             // maximum instances
                1,                               // current instances
                65_536,                          // inbound quota
                0,                               // read data available
                65_536,                          // outbound quota
                65_536,                          // write quota available
                3,                               // FILE_PIPE_CONNECTED_STATE
                u32::from(pipe.endpoint.server), // server or client end
            ];
            unsafe {
                ptr::copy_nonoverlapping(values.as_ptr(), information as *mut u32, values.len());
            }
            if !io_status.is_null() {
                unsafe {
                    (io_status as *mut u32).write_unaligned(0);
                    (io_status.add(8) as *mut u64).write_unaligned(40);
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
        let Ok(end) = u64::try_from(unsafe { information.cast::<i64>().read_unaligned() }) else {
            return finish(STATUS_INVALID_PARAMETER, 0);
        };
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
        let Ok(size) = context.fs.file_len(&path) else {
            return finish(STATUS_OBJECT_NAME_NOT_FOUND, 0);
        };
        if end < size && mapped {
            return finish(STATUS_ACCESS_DENIED, 0);
        }
        return match context.fs.set_len(&path, end) {
            Ok(()) => finish(STATUS_SUCCESS, end),
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
        Err(error) if error.starts_with("directory not empty:") => {
            finish(0xC000_0101, 0) // STATUS_DIRECTORY_NOT_EMPTY
        }
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

/// The path an `OBJECT_ATTRIBUTES` names: `ObjectName`, relative to the
/// `RootDirectory` handle's path when one is given, with the NT `\??\`
/// prefix removed.
fn object_attributes_path(attributes: *const u8) -> Result<String, u32> {
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    if attributes.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let root = unsafe { attributes.add(8).cast::<u64>().read_unaligned() };
    let name = unsafe { attributes.add(16).cast::<*const u8>().read_unaligned() };
    if name.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let length = unsafe { name.cast::<u16>().read_unaligned() } as usize / 2;
    let buffer = unsafe { name.add(8).cast::<*const u16>().read_unaligned() };
    if buffer.is_null() && length != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let units = if length == 0 { &[][..] } else { unsafe { std::slice::from_raw_parts(buffer, length) } };
    let relative = String::from_utf16_lossy(units);
    if root == 0 {
        let path = relative
            .strip_prefix(r"\??\")
            .or_else(|| relative.strip_prefix(r"\\?\"))
            .unwrap_or(&relative);
        let device = r"\Device\HarddiskVolume";
        if path.get(..device.len()).is_some_and(|prefix| prefix.eq_ignore_ascii_case(device)) {
            let remainder = &path[device.len()..];
            let (number, tail) = remainder.split_once('\\').unwrap_or((remainder, ""));
            let number = number.parse::<u8>().ok().filter(|number| (1..=26).contains(number)).ok_or(0xc0000034u32)?;
            let drive = (b'A' + number - 1) as char;
            return Ok(format!("{drive}:\\{tail}"));
        }
        return Ok(path.to_string());
    }
    let context = fs_ctx().ok_or(STATUS_INVALID_HANDLE)?;
    let ctx = context.lock().map_err(|_| STATUS_INVALID_HANDLE)?;
    let directory = ctx.handles.get(&root).ok_or(STATUS_INVALID_HANDLE)?.path.clone();
    Ok(if relative.is_empty() {
        directory
    } else {
        format!("{}\\{relative}", directory.trim_end_matches('\\'))
    })
}

pub(super) extern "win64" fn native_nt_query_attributes_file(
    attributes: *const u8,
    information: *mut u8,
) -> u32 {
    if information.is_null() {
        return 0xC000_000D;
    }
    let path = match object_attributes_path(attributes) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let previous_error = native_get_last_error();
    let mut metadata = [0u8; 36];
    let status = if native_get_file_attributes_ex_w(path.as_ptr(), 0, metadata.as_mut_ptr().cast()) != 0 {
        unsafe {
            ptr::write_bytes(information, 0, 40);
            ptr::copy_nonoverlapping(metadata.as_ptr().add(4), information, 24);
            ptr::copy_nonoverlapping(metadata.as_ptr().add(20), information.add(24), 8);
            ptr::copy_nonoverlapping(metadata.as_ptr(), information.add(32), 4);
        }
        0
    } else {
        match native_get_last_error() {
            2 => 0xC000_0034,
            3 => 0xC000_003A,
            5 => 0xC000_0022,
            123 => 0xC000_0033,
            _ => 0xC000_000D,
        }
    };
    native_set_last_error(previous_error);
    status
}

/// `NtCreateFile` over `CreateFileW`: NT dispositions and options mapped to
/// Win32 ones, and the Win32 error mapped back to an NTSTATUS.
#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_nt_create_file(
    handle: *mut u64,
    access: u32,
    attributes: *const u8,
    io_status: *mut u8,
    _allocation_size: *const i64,
    file_attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
    _ea_buffer: *const u8,
    _ea_length: u32,
) -> u32 {
    const FILE_DIRECTORY_FILE: u32 = 0x1;
    const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x10;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
    const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x20_0000;
    if handle.is_null() || io_status.is_null() {
        return 0xC000_000D;
    }
    let path = match object_attributes_path(attributes) {
        Ok(path) => path,
        Err(status) => return status,
    };
    if native_diagnostic_enabled() {
        eprintln!(
            "native NtCreateFile path={path} access={access:#x} disposition={disposition} options={options:#x}"
        );
    }
    if is_afd_path(&path) {
        unsafe {
            handle.write(open_afd_device());
            io_status.cast::<u32>().write_unaligned(0);
            io_status.add(8).cast::<u64>().write_unaligned(1); // FILE_OPENED
        }
        return 0;
    }
    // FILE_SUPERSEDE, OPEN, CREATE, OPEN_IF, OVERWRITE, OVERWRITE_IF.
    let creation = match disposition {
        0 | 5 => 2, // CREATE_ALWAYS
        1 => 3,     // OPEN_EXISTING
        2 => 1,     // CREATE_NEW
        3 => 4,     // OPEN_ALWAYS
        4 => 5,     // TRUNCATE_EXISTING
        _ => return 0xC000_000D,
    };
    let directory = options & FILE_DIRECTORY_FILE != 0;
    let existed = fs_ctx().and_then(|context| context.lock().ok().map(|ctx| (ctx.fs.exists(&path), ctx.fs.is_dir(&path))));
    let (exists, is_directory) = existed.unwrap_or((false, false));
    if exists && directory && !is_directory {
        return 0xC000_0103; // STATUS_NOT_A_DIRECTORY
    }
    if exists && options & FILE_NON_DIRECTORY_FILE != 0 && is_directory {
        return 0xC000_00BA; // STATUS_FILE_IS_A_DIRECTORY
    }
    if directory && !exists && matches!(disposition, 2 | 3) {
        let wide_path: Vec<u16> = path.encode_utf16().chain([0]).collect();
        if native_create_directory_w(wide_path.as_ptr(), 0) == 0 {
            return 0xC000_003A; // STATUS_OBJECT_PATH_NOT_FOUND
        }
    }
    let mut flags = file_attributes & 0xffff | 0x0200_0000; // FILE_FLAG_BACKUP_SEMANTICS
    if options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) == 0 {
        flags |= 0x4000_0000; // FILE_FLAG_OVERLAPPED
    }
    if options & FILE_OPEN_REPARSE_POINT != 0 {
        flags |= 0x0020_0000; // FILE_FLAG_OPEN_REPARSE_POINT
    }
    if options & FILE_DELETE_ON_CLOSE != 0 {
        flags |= 0x0400_0000; // FILE_FLAG_DELETE_ON_CLOSE
    }
    let wide_path: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let creation = if directory && creation != 3 { 3 } else { creation };
    let opened = native_create_file_w(wide_path.as_ptr(), access, share, 0, creation, flags, 0);
    if opened == u64::MAX {
        return match native_get_last_error() {
            2 => 0xC000_0034,         // STATUS_OBJECT_NAME_NOT_FOUND
            3 => 0xC000_003A,         // STATUS_OBJECT_PATH_NOT_FOUND
            5 => 0xC000_0022,         // STATUS_ACCESS_DENIED
            32 => 0xC000_0043,        // STATUS_SHARING_VIOLATION
            80 | 183 => 0xC000_0035,  // STATUS_OBJECT_NAME_COLLISION
            _ => 0xC000_000D,
        };
    }
    // FILE_SUPERSEDED 0, FILE_OPENED 1, FILE_CREATED 2, FILE_OVERWRITTEN 3.
    let information: u64 = match (exists, disposition) {
        (false, _) => 2,
        (true, 0) => 0,
        (true, 4 | 5) => 3,
        (true, _) => 1,
    };
    unsafe {
        handle.write(opened);
        io_status.cast::<u32>().write_unaligned(0);
        io_status.add(8).cast::<u64>().write_unaligned(information);
    }
    0
}

/// `NtOpenFile`: `NtCreateFile` with `FILE_OPEN`.
pub(super) extern "win64" fn native_nt_open_file(
    handle: *mut u64,
    access: u32,
    attributes: *const u8,
    io_status: *mut u8,
    share: u32,
    options: u32,
) -> u32 {
    native_nt_create_file(handle, access, attributes, io_status, ptr::null(), 0, share, 1, options, ptr::null(), 0)
}

/// `NtCancelIoFileEx(handle, io_status, cancel_status)`: cancels a pending
/// AFD poll (or all of the handle's, for a null `io_status`).
pub(super) extern "win64" fn native_nt_cancel_io_file_ex(handle: u64, io_status: u64, cancel_status: *mut u8) -> u32 {
    let status = if is_afd_handle(handle) {
        afd_cancel(handle, io_status)
    } else if native_cancel_io_ex(handle, io_status) != 0 {
        0
    } else {
        0xC000_0225 // STATUS_NOT_FOUND
    };
    if !cancel_status.is_null() {
        unsafe {
            cancel_status.cast::<u32>().write_unaligned(status);
            cancel_status.add(8).cast::<u64>().write_unaligned(0);
        }
    }
    status
}

/// The loader currently creates no side-by-side activation contexts, so a query
/// of the current thread has no active context to retain. Context creation and
/// activation imports remain unsupported rather than accepting fake handles.
pub(super) extern "win64" fn native_rtl_get_active_activation_context(out: *mut u64) -> u32 {
    if out.is_null() {
        return 0xc000000d;
    }
    unsafe { out.write_unaligned(0) };
    0
}
#[cfg(test)]
mod inactive_activation_context_tests {
    use super::*;
    #[test]
    fn reports_no_active_context_and_preserves_last_error() {
        let mut context = u64::MAX;
        native_set_last_error(0x4567);
        assert_eq!(native_rtl_get_active_activation_context(&mut context), 0);
        assert_eq!(context, 0);
        assert_eq!(native_rtl_get_active_activation_context(std::ptr::null_mut()), 0xc000000d);
        assert_eq!(native_get_last_error(), 0x4567);
    }
}

#[cfg(test)]
mod nt_object_wait_tests {
    use super::*;
    extern "win64" fn record_apc(value: u64) {
        unsafe { (*(value as *const AtomicU32)).fetch_add(1, Ordering::SeqCst); }
    }
    #[test]
    fn object_waits_translate_deadlines_errors_and_alertable_apcs() {
        let _guard = TestProcessGuard::new();
        let event = native_create_event_w(0, 0, 0, ptr::null());
        let poll = 0;
        let relative = -10_000;
        let absolute = 1;
        native_set_last_error(0x1234);
        for timeout in [&poll, &relative, &absolute] {
            assert_eq!(native_nt_wait_for_single_object(event, 0, timeout), 0x102);
            assert_eq!(native_get_last_error(), 0x1234);
        }
        assert_eq!(native_nt_wait_for_single_object(0, 0, &poll), 0xc0000008);
        assert_eq!(native_get_last_error(), 0x1234);
        let count = AtomicU32::new(0);
        assert_eq!(native_queue_user_apc(record_apc as *const () as u64, native_get_current_thread(), &count as *const _ as u64), 1);
        assert_eq!(native_nt_wait_for_single_object(event, 0, &poll), 0x102);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(native_nt_wait_for_single_object(event, 1, ptr::null()), 0xc0);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(native_get_last_error(), 0x1234);
        assert_eq!(native_set_event(event), 1);
        assert_eq!(native_nt_wait_for_single_object(event, 0, ptr::null()), 0);
        assert_eq!(native_nt_wait_for_single_object(event, 0, &poll), 0x102);
        native_close_handle(event);
    }
}
