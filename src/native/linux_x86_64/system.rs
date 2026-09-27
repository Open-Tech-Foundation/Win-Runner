//! Windows host identity, version, processor, and system-information APIs.

use super::*;

pub(super) extern "win64" fn native_open_process_token(
    process: u64,
    _access: u32,
    token: *mut u64,
) -> i32 {
    if token.is_null() {
        native_set_last_error(87);
        return 0;
    }
    if process != u64::MAX
        && !process_ctx().is_some_and(|context| context.process_handle == process)
    {
        native_set_last_error(6);
        return 0;
    }
    unsafe { token.write(PROCESS_TOKEN_HANDLE) };
    1
}
pub(super) extern "win64" fn native_get_user_name_w(name: *mut u16, size: *mut u32) -> i32 {
    if name.is_null() || size.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let value = std::env::var("USERNAME").unwrap_or_else(|_| "WinCLI".to_string());
    let encoded: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let capacity = unsafe { size.read() } as usize;
    if capacity < encoded.len() {
        unsafe { size.write(encoded.len() as u32) };
        native_set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    unsafe {
        name.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len());
        size.write(encoded.len() as u32);
    }
    1
}

pub(super) extern "win64" fn native_is_processor_feature_present(feature: u32) -> i32 {
    let present = match feature {
        2 | 3 | 6 | 8 | 9 | 10 | 12 => true,
        13 => std::is_x86_feature_detected!("sse3"),
        17 => std::is_x86_feature_detected!("xsave"),
        36 => std::is_x86_feature_detected!("ssse3"),
        37 => std::is_x86_feature_detected!("sse4.1"),
        38 => std::is_x86_feature_detected!("sse4.2"),
        39 => std::is_x86_feature_detected!("avx"),
        40 => std::is_x86_feature_detected!("avx2"),
        41 => std::is_x86_feature_detected!("avx512f"),
        60 => std::is_x86_feature_detected!("bmi2"),
        _ => false,
    };
    present as i32
}
pub(super) extern "win64" fn native_rtl_get_version(info: *mut u8) -> u32 {
    if info.is_null() || unsafe { (info as *const u32).read_unaligned() } < 276 {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }
    unsafe {
        (info.add(4) as *mut u32).write_unaligned(10);
        (info.add(8) as *mut u32).write_unaligned(0);
        (info.add(12) as *mut u32).write_unaligned(19045);
        (info.add(16) as *mut u32).write_unaligned(2); // VER_PLATFORM_WIN32_NT
        std::ptr::write_bytes(info.add(20), 0, 256);
    }
    0
}
pub(super) extern "win64" fn native_rtl_nt_status_to_dos_error(status: u32) -> u32 {
    match status {
        0 => 0,
        0xC000_0005 => 998, // STATUS_ACCESS_VIOLATION
        0xC000_0008 => 6,   // STATUS_INVALID_HANDLE
        0xC000_000D => 87,  // STATUS_INVALID_PARAMETER
        0xC000_0017 => 8,   // STATUS_NO_MEMORY
        0xC000_0022 => 5,   // STATUS_ACCESS_DENIED
        0xC000_0034 => 2,   // STATUS_OBJECT_NAME_NOT_FOUND
        _ => 317,           // ERROR_MR_MID_NOT_FOUND
    }
}

pub(super) extern "win64" fn native_get_logical_processor_information(
    buffer: *mut u8,
    returned_length: *mut u32,
) -> i32 {
    const ENTRY_SIZE: u32 = 32;
    if returned_length.is_null() {
        native_set_last_error(87);
        return 0;
    }
    if buffer.is_null() {
        unsafe { returned_length.write(ENTRY_SIZE) };
        native_set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    // SYSTEM_LOGICAL_PROCESSOR_INFORMATION is 32 bytes on x64. Report
    // one processor core, matching the CPU affinity exposed to a guest.
    unsafe {
        std::ptr::write_bytes(buffer, 0, ENTRY_SIZE as usize);
        (buffer as *mut u64).write_unaligned(1);
        (buffer.add(8) as *mut u32).write_unaligned(0); // RelationProcessorCore
        returned_length.write(ENTRY_SIZE);
    }
    1
}
pub(super) extern "win64" fn native_get_adapters_addresses(
    family: u32,
    _flags: u32,
    _reserved: u64,
    adapters: *mut u8,
    size: *mut u32,
) -> u32 {
    const REQUIRED: u32 = 240;
    const STRUCT_SIZE: u32 = 176;
    if size.is_null() || !matches!(family, 0 | 2 | 23) {
        return 87; // ERROR_INVALID_PARAMETER
    }
    if adapters.is_null() || unsafe { size.read() } < REQUIRED {
        unsafe { size.write(REQUIRED) };
        return 111; // ERROR_BUFFER_OVERFLOW
    }
    let base = adapters as usize;
    unsafe {
        std::ptr::write_bytes(adapters, 0, REQUIRED as usize);
        (adapters as *mut u32).write_unaligned(STRUCT_SIZE);
        (adapters.add(4) as *mut u32).write_unaligned(1); // IfIndex
        (adapters.add(16) as *mut *const u8).write_unaligned((base + 192) as *const u8);
        (adapters.add(72) as *mut *const u16).write_unaligned((base + 208) as *const u16);
        (adapters.add(88) as *mut u32).write_unaligned(0); // no MAC address
        (adapters.add(100) as *mut u32).write_unaligned(24); // IF_TYPE_SOFTWARE_LOOPBACK
        (adapters.add(104) as *mut u32).write_unaligned(1); // IfOperStatusUp
        (adapters.add(108) as *mut u32).write_unaligned(1); // Ipv6IfIndex
        adapters
            .add(192)
            .copy_from_nonoverlapping(b"lo\0".as_ptr(), 3);
        (adapters.add(208) as *mut u16).write_unaligned(b'l' as u16);
        (adapters.add(210) as *mut u16).write_unaligned(b'o' as u16);
        (adapters.add(212) as *mut u16).write_unaligned(0);
        size.write(REQUIRED);
    }
    0
}

pub(super) extern "win64" fn native_get_version() -> u32 {
    // Windows 10.0, build 19045, encoded using the legacy GetVersion layout.
    (19045u32 << 16) | 0x0a00
}
pub(super) extern "win64" fn native_set_default_dll_directories(_flags: u32) -> i32 {
    1
}
pub(super) extern "win64" fn native_set_file_apis_to_oem() {}
pub(super) extern "win64" fn native_co_initialize(_reserved: *mut u8) -> i32 {
    0 // S_OK
}
pub(super) extern "win64" fn native_lookup_privilege_value_w(
    _system: *const u16,
    name: *const u16,
    luid: *mut u8,
) -> i32 {
    if name.is_null() || luid.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let value = wide(name).unwrap_or_default();
    let low = value.bytes().fold(0u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(byte as u32)
    });
    unsafe {
        luid.cast::<u32>().write_unaligned(low);
        luid.add(4).cast::<i32>().write_unaligned(0);
    }
    1
}
pub(super) extern "win64" fn native_adjust_token_privileges(
    _token: u64,
    _disable_all: i32,
    _new_state: *const u8,
    _buffer_len: u32,
    _previous_state: *mut u8,
    _return_len: *mut u32,
) -> i32 {
    1
}
pub(super) extern "win64" fn native_lstrlen_w(input: *const u16) -> i32 {
    wide(input)
        .map(|value| value.encode_utf16().count() as i32)
        .unwrap_or(0)
}
pub(super) extern "win64" fn native_lstrcpy_w(output: *mut u16, input: *const u16) -> u64 {
    if output.is_null() {
        return 0;
    }
    let Some(value) = wide(input) else {
        return 0;
    };
    let encoded: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    output as u64
}
pub(super) extern "win64" fn native_lstrcat_w(output: *mut u16, input: *const u16) -> u64 {
    if output.is_null() {
        return 0;
    }
    let Some(left) = wide(output) else {
        return 0;
    };
    let Some(right) = wide(input) else {
        return 0;
    };
    let end = output.wrapping_add(left.encode_utf16().count());
    let encoded: Vec<u16> = right.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { end.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    output as u64
}
pub(super) extern "win64" fn native_get_computer_name_ex_w(
    _name_type: u32,
    output: *mut u16,
    len: *mut u32,
) -> i32 {
    const NAME: [u16; 7] = [
        'w' as u16, 'i' as u16, 'n' as u16, 'c' as u16, 'l' as u16, 'i' as u16, 0,
    ];
    if len.is_null() {
        return 0;
    }
    let capacity = unsafe { len.read() };
    if output.is_null() || capacity < NAME.len() as u32 {
        unsafe { len.write(NAME.len() as u32) };
        native_set_last_error(234);
        return 0;
    }
    unsafe {
        output.copy_from_nonoverlapping(NAME.as_ptr(), NAME.len());
        len.write((NAME.len() - 1) as u32)
    };
    1
}
pub(super) extern "win64" fn native_get_system_info(output: *mut u8) {
    if output.is_null() {
        return;
    }
    unsafe {
        std::ptr::write_bytes(output, 0, 48);
        (output as *mut u16).write_unaligned(9);
        (output.add(4) as *mut u32).write_unaligned(4096);
        (output.add(8) as *mut u64).write_unaligned(0x1_0000);
        (output.add(16) as *mut u64).write_unaligned(0x7fff_ffff_ffff);
        (output.add(24) as *mut u64).write_unaligned(1);
        (output.add(32) as *mut u32).write_unaligned(1);
        (output.add(36) as *mut u32).write_unaligned(8664);
        (output.add(40) as *mut u32).write_unaligned(65_536);
    }
}
pub(super) extern "win64" fn native_get_process_affinity_mask(
    process: u64,
    process_mask: *mut u64,
    system_mask: *mut u64,
) -> i32 {
    let current = process_ctx()
        .is_some_and(|context| process == context.process_handle || process == u64::MAX);
    if !current || process_mask.is_null() || system_mask.is_null() {
        native_set_last_error(if current { 87 } else { 6 });
        return 0;
    }
    unsafe {
        process_mask.write(1);
        system_mask.write(1);
    }
    1
}
pub(super) extern "win64" fn native_get_native_system_info(output: *mut u8) {
    native_get_system_info(output)
}

pub(super) extern "win64" fn native_get_system_metrics(_index: i32) -> i32 {
    // The native CLI guest has no Windows desktop session. The documented
    // value for absent/unsupported system metrics is zero.
    0
}

pub(super) extern "win64" fn native_message_beep(_kind: u32) -> i32 {
    // The CLI guest has no Windows sound device; match the successful
    // best-effort behavior of MessageBeep without producing host audio.
    1
}

pub(super) extern "win64" fn native_encode_pointer(value: u64) -> u64 {
    let cookie = process_ctx()
        .map(|process| process.pointer_cookie)
        .unwrap_or(1);
    value.rotate_left(17) ^ cookie
}
pub(super) extern "win64" fn native_decode_pointer(value: u64) -> u64 {
    let cookie = process_ctx()
        .map(|process| process.pointer_cookie)
        .unwrap_or(1);
    (value ^ cookie).rotate_right(17)
}

pub(super) extern "win64" fn native_ver_set_condition_mask(
    mask: u64,
    types: u32,
    condition: u8,
) -> u64 {
    let shift = if types & 0x80 != 0 {
        21
    }
    // VER_PRODUCT_TYPE
    else if types & 0x40 != 0 {
        18
    }
    // VER_SUITENAME
    else if types & 0x20 != 0 {
        15
    }
    // VER_SERVICEPACKMAJOR
    else if types & 0x10 != 0 {
        12
    }
    // VER_SERVICEPACKMINOR
    else if types & 0x08 != 0 {
        9
    }
    // VER_PLATFORMID
    else if types & 0x04 != 0 {
        6
    }
    // VER_BUILDNUMBER
    else if types & 0x02 != 0 {
        3
    }
    // VER_MAJORVERSION
    else if types & 0x01 != 0 {
        0
    }
    // VER_MINORVERSION
    else {
        return mask;
    };
    mask | (((condition & 7) as u64) << shift)
}

pub(super) extern "win64" fn native_verify_version_info_w(
    info: *const u8,
    types: u32,
    mask: u64,
) -> i32 {
    if info.is_null() || types == 0 {
        native_set_last_error(87);
        return 0;
    }
    let read32 = |offset| unsafe { (info.add(offset) as *const u32).read_unaligned() };
    let read16 = |offset| unsafe { (info.add(offset) as *const u16).read_unaligned() };
    let matches = |actual: u32, expected: u32, shift: u32| match (mask >> shift) & 7 {
        1 => actual == expected,
        2 => actual > expected,
        3 => actual >= expected,
        4 => actual < expected,
        5 => actual <= expected,
        _ => false,
    };
    let checks = [
        (0x02, 10, read32(4), 3),
        (0x01, 0, read32(8), 0),
        (0x04, 19045, read32(12), 6),
        (0x08, 2, read32(16), 9),
        (0x20, 0, read16(276) as u32, 15),
        (0x10, 0, read16(278) as u32, 12),
        (0x80, 1, unsafe { *info.add(282) } as u32, 21),
    ];
    if checks.iter().any(|(bit, actual, expected, shift)| {
        types & bit != 0 && !matches(*actual, *expected, *shift)
    }) {
        native_set_last_error(1150); // ERROR_OLD_WIN_VERSION
        0
    } else {
        1
    }
}

pub(super) struct MissingImportStubs {
    pub(super) _code: Mapping,
    pub(super) _messages: Vec<Vec<u8>>,
}
