//! Windows code-page, character classification, and locale conversion shims.

pub(super) extern "win64" fn native_get_acp() -> u32 {
    1252
}

pub(super) extern "win64" fn native_get_oem_cp() -> u32 {
    1252
}

pub(super) fn native_resolve_code_page(code_page: u32) -> u32 {
    match code_page {
        0 | 3 => native_get_acp(), // CP_ACP, CP_THREAD_ACP
        1 => native_get_oem_cp(),  // CP_OEMCP
        _ => code_page,
    }
}

fn decode_windows_1252(byte: u8) -> u16 {
    const EXTENDED: [u16; 32] = [
        0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160,
        0x2039, 0x0152, 0x008d, 0x017d, 0x008f, 0x0090, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022,
        0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178,
    ];
    if (0x80..=0x9f).contains(&byte) {
        EXTENDED[(byte - 0x80) as usize]
    } else {
        byte as u16
    }
}

fn encode_windows_1252(unit: u16) -> Option<u8> {
    if unit <= 0x7f || (0xa0..=0xff).contains(&unit) {
        return Some(unit as u8);
    }
    const EXTENDED: [u16; 32] = [
        0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160,
        0x2039, 0x0152, 0x008d, 0x017d, 0x008f, 0x0090, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022,
        0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178,
    ];
    EXTENDED
        .iter()
        .position(|value| *value == unit)
        .map(|index| index as u8 + 0x80)
}

pub(super) extern "win64" fn native_is_valid_code_page(code_page: u32) -> i32 {
    matches!(native_resolve_code_page(code_page), 1252 | 65001) as i32
}

pub(super) extern "win64" fn native_get_cp_info(code_page: u32, info: *mut u8) -> i32 {
    if info.is_null() {
        return 0;
    }
    let max_char_size = match native_resolve_code_page(code_page) {
        1252 => 1,
        65001 => 4,
        _ => return 0,
    };
    // CPINFO is 16 bytes: DWORD MaxCharSize, 2-byte DefaultChar, and a
    // 12-byte lead-byte range table.
    unsafe {
        std::ptr::write_bytes(info, 0, 16);
        (info as *mut u32).write_unaligned(max_char_size);
        info.add(4).write(b'?');
    }
    1
}

pub(super) unsafe fn multibyte_input(input: *const u8, len: i32) -> Option<(Vec<u8>, bool)> {
    if input.is_null() || len < -1 {
        return None;
    }
    if len >= 0 {
        return Some((
            unsafe { std::slice::from_raw_parts(input, len as usize) }.to_vec(),
            false,
        ));
    }
    let mut size = 0;
    while size < 64 * 1024 && unsafe { *input.add(size) } != 0 {
        size += 1;
    }
    (size < 64 * 1024).then(|| {
        (
            unsafe { std::slice::from_raw_parts(input, size) }.to_vec(),
            true,
        )
    })
}

pub(super) extern "win64" fn native_multi_byte_to_wide_char(
    code_page: u32,
    _flags: u32,
    input: *const u8,
    input_len: i32,
    output: *mut u16,
    output_len: i32,
) -> i32 {
    if output_len < 0 {
        return 0;
    }
    let (input, append_nul) = match unsafe { multibyte_input(input, input_len) } {
        Some(value) => value,
        None => return 0,
    };
    let mut wide: Vec<u16> = match native_resolve_code_page(code_page) {
        1252 => input.into_iter().map(decode_windows_1252).collect(),
        65001 => match std::str::from_utf8(&input) {
            Ok(value) => value.encode_utf16().collect(),
            Err(_) => return 0,
        },
        _ => return 0,
    };
    if append_nul {
        wide.push(0);
    }
    if output.is_null() {
        return wide.len().try_into().unwrap_or(0);
    }
    if wide.len() > output_len as usize {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), output, wide.len()) };
    wide.len().try_into().unwrap_or(0)
}

fn ctype1(unit: u16) -> u16 {
    match char::from_u32(unit as u32) {
        Some(ch) if ch.is_ascii_uppercase() => 0x0001 | 0x0100,
        Some(ch) if ch.is_ascii_lowercase() => 0x0002 | 0x0100,
        Some(ch) if ch.is_ascii_digit() => 0x0004 | 0x0080,
        Some(' ') => 0x0008 | 0x0040,
        Some('\t') => 0x0008 | 0x0040,
        Some(ch) if ch.is_ascii_control() => 0x0020,
        Some(ch) if ch.is_ascii_punctuation() => 0x0010,
        _ => 0,
    }
}

pub(super) extern "win64" fn native_get_string_type_w(
    info_type: u32,
    input: *const u16,
    input_len: i32,
    output: *mut u16,
) -> i32 {
    if info_type != 1 || input.is_null() || output.is_null() || input_len < -1 {
        return 0;
    }
    let len = if input_len >= 0 {
        input_len as usize
    } else {
        let mut len = 0;
        while len < 64 * 1024 && unsafe { *input.add(len) } != 0 {
            len += 1;
        }
        if len == 64 * 1024 {
            return 0;
        }
        len + 1
    };
    for index in 0..len {
        unsafe { output.add(index).write(ctype1(*input.add(index))) };
    }
    1
}

pub(super) extern "win64" fn native_lc_map_string_w(
    _locale: *const u16,
    flags: u32,
    input: *const u16,
    input_len: i32,
    output: *mut u16,
    output_len: i32,
) -> i32 {
    if input.is_null() || input_len < -1 || output_len < 0 || flags & !0x300 != 0 {
        return 0;
    }
    if flags & 0x300 == 0x300 {
        return 0;
    }
    let len = if input_len >= 0 {
        input_len as usize
    } else {
        let mut len = 0;
        while len < 64 * 1024 && unsafe { *input.add(len) } != 0 {
            len += 1;
        }
        if len == 64 * 1024 {
            return 0;
        }
        len + 1
    };
    if output.is_null() {
        return len.try_into().unwrap_or(0);
    }
    if len > output_len as usize {
        return 0;
    }
    for index in 0..len {
        let mut unit = unsafe { *input.add(index) };
        if flags & 0x100 != 0 && (b'A' as u16..=b'Z' as u16).contains(&unit) {
            unit += (b'a' - b'A') as u16;
        } else if flags & 0x200 != 0 && (b'a' as u16..=b'z' as u16).contains(&unit) {
            unit -= (b'a' - b'A') as u16;
        }
        unsafe { output.add(index).write(unit) };
    }
    len.try_into().unwrap_or(0)
}

pub(super) extern "win64" fn native_wide_char_to_multi_byte(
    code_page: u32,
    _flags: u32,
    input: *const u16,
    input_len: i32,
    output: *mut u8,
    output_len: i32,
    _default_char: *const u8,
    used_default_char: *mut i32,
) -> i32 {
    if input.is_null() || input_len < -1 || output_len < 0 {
        return 0;
    }
    let (len, append_nul) = if input_len >= 0 {
        (input_len as usize, false)
    } else {
        let mut len = 0;
        while len < 64 * 1024 && unsafe { *input.add(len) } != 0 {
            len += 1;
        }
        if len == 64 * 1024 {
            return 0;
        }
        (len, true)
    };
    let units = unsafe { std::slice::from_raw_parts(input, len) };
    let mut used_default = false;
    let mut bytes = match native_resolve_code_page(code_page) {
        1252 => units
            .iter()
            .map(|unit| {
                encode_windows_1252(*unit).unwrap_or_else(|| {
                    used_default = true;
                    b'?'
                })
            })
            .collect(),
        65001 => match String::from_utf16(units) {
            Ok(value) => value.into_bytes(),
            Err(_) => return 0,
        },
        _ => return 0,
    };
    if append_nul {
        bytes.push(0);
    }
    if !used_default_char.is_null() {
        unsafe { used_default_char.write(used_default as i32) };
    }
    if output.is_null() {
        return bytes.len().try_into().unwrap_or(0);
    }
    if bytes.len() > output_len as usize {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
    bytes.len().try_into().unwrap_or(0)
}
