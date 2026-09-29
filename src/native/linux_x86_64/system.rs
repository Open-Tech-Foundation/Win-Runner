//! Windows host identity, version, processor, and system-information APIs.

use super::*;
use crate::system_profile;

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
    let value = process_ctx()
        .and_then(|context| {
            context.environment.lock().ok().and_then(|environment| {
                environment
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("USERNAME"))
                    .map(|(_, value)| value.clone())
            })
        })
        .unwrap_or_else(|| system_profile::USER_NAME.to_string());
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
        (info.add(12) as *mut u32).write_unaligned(system_profile::OS_BUILD_NUMBER);
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
        0xC000_0120 => 995, // STATUS_CANCELLED
        0xC000_014B => 109, // STATUS_PIPE_BROKEN
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
    (system_profile::OS_BUILD_NUMBER << 16) | 0x0a00
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
    let name: Vec<u16> = system_profile::COMPUTER_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    if len.is_null() {
        return 0;
    }
    let capacity = unsafe { len.read() };
    if output.is_null() || capacity < name.len() as u32 {
        unsafe { len.write(name.len() as u32) };
        native_set_last_error(234);
        return 0;
    }
    unsafe {
        output.copy_from_nonoverlapping(name.as_ptr(), name.len());
        len.write((name.len() - 1) as u32)
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
        (output.add(32) as *mut u32).write_unaligned(system_profile::PROCESSOR_COUNT);
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
        (0x04, system_profile::OS_BUILD_NUMBER, read32(12), 6),
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

/// A native x64 process is never running under WOW64.
pub(super) extern "win64" fn native_is_wow64_process(_process: u64, wow64: *mut i32) -> i32 {
    if wow64.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { wow64.write_unaligned(0) };
    1
}

/// `IsWow64Process2`: not WOW64, and the machine is the host's.
pub(super) extern "win64" fn native_is_wow64_process2(
    _process: u64,
    process_machine: *mut u16,
    native_machine: *mut u16,
) -> i32 {
    if process_machine.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe {
        process_machine.write_unaligned(0); // IMAGE_FILE_MACHINE_UNKNOWN
        if !native_machine.is_null() {
            native_machine.write_unaligned(0x8664);
        }
    }
    1
}

/// Copy `text` as UTF-16 into a caller buffer of `capacity` characters with
/// the Get*DirectoryW protocol: the length without the terminator on
/// success, or the required size including it when the buffer is short.
fn copy_directory_w(text: &str, output: *mut u16, capacity: u32) -> u32 {
    let encoded: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    if output.is_null() || (capacity as usize) < encoded.len() {
        return encoded.len() as u32;
    }
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    (encoded.len() - 1) as u32
}

pub(super) extern "win64" fn native_get_windows_directory_w(
    output: *mut u16,
    capacity: u32,
) -> u32 {
    copy_directory_w(system_profile::WINDOWS, output, capacity)
}

pub(super) extern "win64" fn native_get_windows_directory_a(output: *mut u8, capacity: u32) -> u32 {
    let text = system_profile::WINDOWS.as_bytes();
    if output.is_null() || (capacity as usize) <= text.len() {
        return text.len() as u32 + 1;
    }
    unsafe {
        output.copy_from_nonoverlapping(text.as_ptr(), text.len());
        output.add(text.len()).write(0);
    }
    text.len() as u32
}

/// No debugger is ever attached to a guest process.
pub(super) extern "win64" fn native_is_debugger_present() -> i32 {
    0
}

/// Debug output goes to an attached debugger; there is none.
pub(super) extern "win64" fn native_output_debug_string(_text: u64) {}
