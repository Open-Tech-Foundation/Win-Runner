//! UCRT text conversion, secure string, and character-class functions.

use super::*;

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;
const STRUNCATE: i32 = 80;
/// `_TRUNCATE` as a `count` argument.
const TRUNCATE: usize = usize::MAX;
const MAX_SCAN: usize = 1 << 20;

fn set_errno(value: i32) {
    THREAD_CRT_ERRNO.with(|errno| errno.set(value));
}

/// Parse an integer the way `strtoul`/`wcstoul` do from code units read by
/// `unit`: skip whitespace, take a sign, honor a `0x` prefix for base 16
/// or 0 and a leading `0` for octal under base 0. Returns the index after
/// the last digit (or 0 when no digits), the magnitude saturated at
/// `limit`, whether it was negative, and whether it overflowed.
fn parse_unsigned(unit: impl Fn(usize) -> u32, base: u32, limit: u64) -> (usize, u64, bool, bool) {
    let is_space = |value: u32| matches!(value, 0x20 | 0x09..=0x0d);
    let mut index = 0;
    while index < MAX_SCAN && is_space(unit(index)) {
        index += 1;
    }
    let negative = match unit(index) {
        0x2d => {
            index += 1;
            true
        }
        0x2b => {
            index += 1;
            false
        }
        _ => false,
    };
    let mut radix = base;
    let hex_prefix = unit(index) == u32::from(b'0')
        && matches!(unit(index + 1), 0x78 | 0x58)
        && char::from_u32(unit(index + 2)).is_some_and(|c| c.is_ascii_hexdigit());
    if (radix == 0 || radix == 16) && hex_prefix {
        radix = 16;
        index += 2;
    } else if radix == 0 {
        radix = if unit(index) == u32::from(b'0') {
            8
        } else {
            10
        };
    }
    let start = index;
    let (mut value, mut overflow) = (0u64, false);
    while index < MAX_SCAN {
        let digit = match char::from_u32(unit(index)).and_then(|c| c.to_digit(36)) {
            Some(digit) if digit < radix => u64::from(digit),
            _ => break,
        };
        match value
            .checked_mul(u64::from(radix))
            .and_then(|value| value.checked_add(digit))
            .filter(|value| *value <= limit)
        {
            Some(next) => value = next,
            None => overflow = true,
        }
        index += 1;
    }
    if index == start {
        return (0, 0, false, false);
    }
    (
        index,
        if overflow { limit } else { value },
        negative,
        overflow,
    )
}

fn unsigned_result(value: u64, negative: bool, overflow: bool, max: u64) -> u64 {
    if overflow {
        set_errno(ERANGE);
        return max;
    }
    if negative {
        value.wrapping_neg() & max
    } else {
        value
    }
}

fn valid_base(base: i32) -> bool {
    base == 0 || (2..=36).contains(&base)
}

pub(super) extern "win64" fn native_crt_strtoul(
    input: *const u8,
    end: *mut *mut u8,
    base: i32,
) -> u32 {
    if input.is_null() || !valid_base(base) {
        set_errno(EINVAL);
        return 0;
    }
    let (consumed, value, negative, overflow) = parse_unsigned(
        |i| u32::from(unsafe { input.add(i).read() }),
        base as u32,
        u64::from(u32::MAX),
    );
    if !end.is_null() {
        unsafe { end.write_unaligned(input.add(consumed) as *mut u8) };
    }
    unsigned_result(value, negative, overflow, u64::from(u32::MAX)) as u32
}

pub(super) extern "win64" fn native_crt_strtoull(
    input: *const u8,
    end: *mut *mut u8,
    base: i32,
) -> u64 {
    if input.is_null() || !valid_base(base) {
        set_errno(EINVAL);
        return 0;
    }
    let (consumed, value, negative, overflow) = parse_unsigned(
        |i| u32::from(unsafe { input.add(i).read() }),
        base as u32,
        u64::MAX,
    );
    if !end.is_null() {
        unsafe { end.write_unaligned(input.add(consumed) as *mut u8) };
    }
    unsigned_result(value, negative, overflow, u64::MAX)
}

/// `strtoll` / `_strtoi64`: a signed 64-bit `strtol`, saturating at the
/// range ends with `ERANGE`.
pub(super) extern "win64" fn native_crt_strtoll(
    input: *const u8,
    end: *mut *mut u8,
    base: i32,
) -> i64 {
    if input.is_null() || !valid_base(base) {
        set_errno(EINVAL);
        return 0;
    }
    const MAGNITUDE: u64 = 1 << 63;
    let (consumed, value, negative, overflow) = parse_unsigned(
        |i| u32::from(unsafe { input.add(i).read() }),
        base as u32,
        MAGNITUDE,
    );
    if !end.is_null() {
        unsafe { end.write_unaligned(input.add(consumed) as *mut u8) };
    }
    match (negative, overflow || (!negative && value == MAGNITUDE)) {
        (false, true) => {
            set_errno(ERANGE);
            i64::MAX
        }
        (true, true) => {
            set_errno(ERANGE);
            i64::MIN
        }
        (true, false) => (value as i64).wrapping_neg(),
        (false, false) => value as i64,
    }
}

pub(super) extern "win64" fn native_crt_byteswap_ushort(value: u16) -> u16 {
    value.swap_bytes()
}
pub(super) extern "win64" fn native_crt_byteswap_ulong(value: u32) -> u32 {
    value.swap_bytes()
}
pub(super) extern "win64" fn native_crt_byteswap_uint64(value: u64) -> u64 {
    value.swap_bytes()
}
/// `_difftime64`: seconds from `start` to `end`.
pub(super) extern "win64" fn native_crt_difftime64(end: i64, start: i64) -> f64 {
    end as f64 - start as f64
}

pub(super) extern "win64" fn native_crt_wcstoul(
    input: *const u16,
    end: *mut *mut u16,
    base: i32,
) -> u32 {
    if input.is_null() || !valid_base(base) {
        set_errno(EINVAL);
        return 0;
    }
    let (consumed, value, negative, overflow) = parse_unsigned(
        |i| u32::from(unsafe { input.add(i).read() }),
        base as u32,
        u64::from(u32::MAX),
    );
    if !end.is_null() {
        unsafe { end.write_unaligned(input.add(consumed) as *mut u16) };
    }
    unsigned_result(value, negative, overflow, u64::from(u32::MAX)) as u32
}

pub(super) extern "win64" fn native_crt_wcstoui64(
    input: *const u16,
    end: *mut *mut u16,
    base: i32,
) -> u64 {
    if input.is_null() || !valid_base(base) {
        set_errno(EINVAL);
        return 0;
    }
    let (consumed, value, negative, overflow) = parse_unsigned(
        |i| u32::from(unsafe { input.add(i).read() }),
        base as u32,
        u64::MAX,
    );
    if !end.is_null() {
        unsafe { end.write_unaligned(input.add(consumed) as *mut u16) };
    }
    unsigned_result(value, negative, overflow, u64::MAX)
}

/// Signed decimal conversion without error reporting (`atoi` family):
/// out-of-range values saturate.
fn parse_signed_decimal(unit: impl Fn(usize) -> u32, min: i64, max: i64) -> i64 {
    let (_, value, negative, overflow) = parse_unsigned(unit, 10, max.unsigned_abs() + 1);
    if negative {
        if overflow {
            min
        } else {
            (value as i64).wrapping_neg().max(min)
        }
    } else if overflow || value > max as u64 {
        max
    } else {
        value as i64
    }
}

pub(super) extern "win64" fn native_crt_wtoi(input: *const u16) -> i32 {
    if input.is_null() {
        set_errno(EINVAL);
        return 0;
    }
    parse_signed_decimal(
        |i| u32::from(unsafe { input.add(i).read() }),
        i64::from(i32::MIN),
        i64::from(i32::MAX),
    ) as i32
}

pub(super) extern "win64" fn native_crt_atol(input: *const u8) -> i32 {
    if input.is_null() {
        set_errno(EINVAL);
        return 0;
    }
    parse_signed_decimal(
        |i| u32::from(unsafe { input.add(i).read() }),
        i64::from(i32::MIN),
        i64::from(i32::MAX),
    ) as i32
}

pub(super) extern "win64" fn native_crt_atoi64(input: *const u8) -> i64 {
    if input.is_null() {
        set_errno(EINVAL);
        return 0;
    }
    parse_signed_decimal(
        |i| u32::from(unsafe { input.add(i).read() }),
        i64::MIN,
        i64::MAX,
    )
}

/// `_ltow_s(value, buffer, size, radix)`.
pub(super) extern "win64" fn native_crt_ltow_s(
    value: i32,
    output: *mut u16,
    size: usize,
    radix: i32,
) -> i32 {
    if output.is_null() || size == 0 || !(2..=36).contains(&radix) {
        set_errno(EINVAL);
        return EINVAL;
    }
    let negative = radix == 10 && value < 0;
    let mut magnitude = if radix == 10 {
        i64::from(value).unsigned_abs()
    } else {
        u64::from(value as u32)
    };
    let mut digits = Vec::new();
    loop {
        let digit = (magnitude % radix as u64) as u32;
        digits.push(char::from_digit(digit, radix as u32).unwrap() as u16);
        magnitude /= radix as u64;
        if magnitude == 0 {
            break;
        }
    }
    if negative {
        digits.push(u16::from(b'-'));
    }
    digits.reverse();
    if digits.len() + 1 > size {
        unsafe { output.write(0) };
        set_errno(ERANGE);
        return ERANGE;
    }
    unsafe {
        output.copy_from_nonoverlapping(digits.as_ptr(), digits.len());
        output.add(digits.len()).write(0);
    }
    0
}

// ---- lengths and duplication ------------------------------------------------

fn length<T: Copy + PartialEq + Default>(text: *const T, limit: usize) -> usize {
    let mut index = 0;
    while index < limit && unsafe { text.add(index).read() } != T::default() {
        index += 1;
    }
    index
}

pub(super) extern "win64" fn native_crt_strnlen(text: *const u8, limit: usize) -> usize {
    if text.is_null() {
        return 0;
    }
    length(text, limit)
}

pub(super) extern "win64" fn native_crt_wcsnlen(text: *const u16, limit: usize) -> usize {
    if text.is_null() {
        return 0;
    }
    length(text, limit)
}

pub(super) extern "win64" fn native_crt_wcsdup(text: *const u16) -> *mut u16 {
    if text.is_null() {
        return std::ptr::null_mut();
    }
    let count = length(text, MAX_SCAN) + 1;
    let copy = native_crt_malloc(count * 2).cast::<u16>();
    if !copy.is_null() {
        unsafe { copy.copy_from_nonoverlapping(text, count) };
    }
    copy
}

// ---- secure copies ----------------------------------------------------------

/// The `strcpy_s`/`strcat_s`/`strncpy_s`/`strncat_s` family, generic over
/// code units: append (or copy) at most `count` units of `source` (all of
/// it for `TRUNCATE` or when `count` is `None`) into `destination` of
/// `size` units. On overflow the destination is emptied and `ERANGE`
/// returned, unless `count` is `_TRUNCATE`, which truncates and returns
/// `STRUNCATE`.
fn secure_copy<T: Copy + PartialEq + Default>(
    destination: *mut T,
    size: usize,
    source: *const T,
    count: Option<usize>,
    append: bool,
) -> i32 {
    if destination.is_null() || size == 0 {
        set_errno(EINVAL);
        return EINVAL;
    }
    if source.is_null() && count != Some(0) {
        unsafe { destination.write(T::default()) };
        set_errno(EINVAL);
        return EINVAL;
    }
    let start = if append {
        let existing = length(destination.cast_const(), size);
        if existing == size {
            unsafe { destination.write(T::default()) };
            set_errno(EINVAL);
            return EINVAL;
        }
        existing
    } else {
        0
    };
    let wanted = match count {
        Some(TRUNCATE) | None => length(source, MAX_SCAN),
        Some(count) => length(source, count),
    };
    let room = size - start - 1;
    if wanted > room {
        if count == Some(TRUNCATE) {
            unsafe {
                destination.add(start).copy_from(source, room);
                destination.add(start + room).write(T::default());
            }
            return STRUNCATE;
        }
        unsafe { destination.write(T::default()) };
        set_errno(ERANGE);
        return ERANGE;
    }
    unsafe {
        destination.add(start).copy_from(source, wanted);
        destination.add(start + wanted).write(T::default());
    }
    0
}

pub(super) extern "win64" fn native_crt_strcpy_s(
    destination: *mut u8,
    size: usize,
    source: *const u8,
) -> i32 {
    secure_copy(destination, size, source, None, false)
}
pub(super) extern "win64" fn native_crt_strcat_s(
    destination: *mut u8,
    size: usize,
    source: *const u8,
) -> i32 {
    secure_copy(destination, size, source, None, true)
}
pub(super) extern "win64" fn native_crt_strncpy_s(
    destination: *mut u8,
    size: usize,
    source: *const u8,
    count: usize,
) -> i32 {
    secure_copy(destination, size, source, Some(count), false)
}
pub(super) extern "win64" fn native_crt_strncat_s(
    destination: *mut u8,
    size: usize,
    source: *const u8,
    count: usize,
) -> i32 {
    secure_copy(destination, size, source, Some(count), true)
}
pub(super) extern "win64" fn native_crt_wcscpy_s(
    destination: *mut u16,
    size: usize,
    source: *const u16,
) -> i32 {
    secure_copy(destination, size, source, None, false)
}
pub(super) extern "win64" fn native_crt_wcscat_s(
    destination: *mut u16,
    size: usize,
    source: *const u16,
) -> i32 {
    secure_copy(destination, size, source, None, true)
}
pub(super) extern "win64" fn native_crt_wcsncpy_s(
    destination: *mut u16,
    size: usize,
    source: *const u16,
    count: usize,
) -> i32 {
    secure_copy(destination, size, source, Some(count), false)
}
pub(super) extern "win64" fn native_crt_wcsncat_s(
    destination: *mut u16,
    size: usize,
    source: *const u16,
    count: usize,
) -> i32 {
    secure_copy(destination, size, source, Some(count), true)
}

// ---- comparison and tokenizing ---------------------------------------------

fn fold_wide(unit: u16) -> u16 {
    // The C locale folds ASCII only.
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
        unit + 32
    } else {
        unit
    }
}

fn compare_wide_folded(left: *const u16, right: *const u16, limit: usize) -> i32 {
    for index in 0..limit {
        let (a, b) = unsafe {
            (
                fold_wide(left.add(index).read()),
                fold_wide(right.add(index).read()),
            )
        };
        if a != b {
            return i32::from(a) - i32::from(b);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

pub(super) extern "win64" fn native_crt_wcsicmp(left: *const u16, right: *const u16) -> i32 {
    if left.is_null() || right.is_null() {
        set_errno(EINVAL);
        return i32::MAX;
    }
    compare_wide_folded(left, right, usize::MAX)
}

pub(super) extern "win64" fn native_crt_wcsnicmp(
    left: *const u16,
    right: *const u16,
    count: usize,
) -> i32 {
    if count == 0 {
        return 0;
    }
    if left.is_null() || right.is_null() {
        set_errno(EINVAL);
        return i32::MAX;
    }
    compare_wide_folded(left, right, count)
}

/// `strtok_s(text, delimiters, &context)`: reentrant tokenizing.
pub(super) extern "win64" fn native_crt_strtok_s(
    text: *mut u8,
    delimiters: *const u8,
    context: *mut *mut u8,
) -> *mut u8 {
    if delimiters.is_null() || context.is_null() {
        set_errno(EINVAL);
        return std::ptr::null_mut();
    }
    let mut cursor = if text.is_null() {
        unsafe { context.read_unaligned() }
    } else {
        text
    };
    if cursor.is_null() {
        return std::ptr::null_mut();
    }
    let delimiter_count = length(delimiters, MAX_SCAN);
    let is_delimiter = |byte: u8| {
        (0..delimiter_count).any(|index| unsafe { delimiters.add(index).read() } == byte)
    };
    unsafe {
        while *cursor != 0 && is_delimiter(*cursor) {
            cursor = cursor.add(1);
        }
        if *cursor == 0 {
            context.write_unaligned(cursor);
            return std::ptr::null_mut();
        }
        let token = cursor;
        while *cursor != 0 && !is_delimiter(*cursor) {
            cursor = cursor.add(1);
        }
        if *cursor != 0 {
            *cursor = 0;
            cursor = cursor.add(1);
        }
        context.write_unaligned(cursor);
        token
    }
}

// ---- character classes (C locale) ------------------------------------------

pub(super) extern "win64" fn native_crt_isalpha(value: i32) -> i32 {
    i32::from(u8::try_from(value).is_ok_and(|byte| byte.is_ascii_alphabetic()))
}
pub(super) extern "win64" fn native_crt_isdigit(value: i32) -> i32 {
    i32::from(u8::try_from(value).is_ok_and(|byte| byte.is_ascii_digit()))
}
pub(super) extern "win64" fn native_crt_isxdigit(value: i32) -> i32 {
    i32::from(u8::try_from(value).is_ok_and(|byte| byte.is_ascii_hexdigit()))
}
pub(super) extern "win64" fn native_crt_isspace(value: i32) -> i32 {
    i32::from(matches!(value, 0x20 | 0x09..=0x0d))
}
pub(super) extern "win64" fn native_crt_iswspace(value: u16) -> i32 {
    i32::from(char::from_u32(u32::from(value)).is_some_and(char::is_whitespace))
}
pub(super) extern "win64" fn native_crt_iswupper(value: u16) -> i32 {
    i32::from(char::from_u32(u32::from(value)).is_some_and(char::is_uppercase))
}
pub(super) extern "win64" fn native_crt_iswascii(value: u16) -> i32 {
    i32::from(value < 0x80)
}
pub(super) extern "win64" fn native_crt_towlower(value: u16) -> u16 {
    char::from_u32(u32::from(value))
        .and_then(|c| {
            let mut lower = c.to_lowercase();
            (lower.len() == 1).then(|| lower.next().unwrap())
        })
        .and_then(|c| u16::try_from(u32::from(c)).ok())
        .unwrap_or(value)
}
pub(super) extern "win64" fn native_crt_towupper(value: u16) -> u16 {
    char::from_u32(u32::from(value))
        .and_then(|c| {
            let mut upper = c.to_uppercase();
            (upper.len() == 1).then(|| upper.next().unwrap())
        })
        .and_then(|c| u16::try_from(u32::from(c)).ok())
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    #[test]
    fn unsigned_conversions_follow_prefix_sign_and_range_rules() {
        let mut end = std::ptr::null_mut();
        let text = wide("  0x1Fz");
        assert_eq!(native_crt_wcstoul(text.as_ptr(), &mut end, 0), 31);
        assert_eq!((end as usize - text.as_ptr() as usize) / 2, 6);
        assert_eq!(
            native_crt_wcstoul(wide("017").as_ptr(), std::ptr::null_mut(), 0),
            15
        );
        assert_eq!(
            native_crt_wcstoul(wide("-1").as_ptr(), std::ptr::null_mut(), 10),
            u32::MAX
        );
        assert_eq!(
            native_crt_wcstoul(wide("99999999999").as_ptr(), std::ptr::null_mut(), 10),
            u32::MAX
        );
        assert_eq!(THREAD_CRT_ERRNO.with(|errno| errno.get()), ERANGE);
        let text = wide("zz");
        let mut end = std::ptr::null_mut();
        assert_eq!(native_crt_wcstoul(text.as_ptr(), &mut end, 10), 0);
        assert_eq!(
            end as usize,
            text.as_ptr() as usize,
            "no digits: end is the input"
        );
        assert_eq!(
            native_crt_wcstoui64(
                wide("18446744073709551615").as_ptr(),
                std::ptr::null_mut(),
                10
            ),
            u64::MAX
        );
        assert_eq!(
            native_crt_strtoull(b"42x\0".as_ptr(), std::ptr::null_mut(), 16),
            0x42
        );
        assert_eq!(
            native_crt_strtoul(b"101\0".as_ptr(), std::ptr::null_mut(), 2),
            5
        );
        assert_eq!(native_crt_wtoi(wide(" -12abc").as_ptr()), -12);
        assert_eq!(native_crt_atol(b"99999999999\0".as_ptr()), i32::MAX);
        assert_eq!(
            native_crt_atoi64(b"-9223372036854775808\0".as_ptr()),
            i64::MIN
        );
    }

    #[test]
    fn secure_copies_report_overflow_or_truncate_on_request() {
        let mut buffer = [0xffu8; 6];
        assert_eq!(
            native_crt_strcpy_s(buffer.as_mut_ptr(), 6, b"hello\0".as_ptr()),
            0
        );
        assert_eq!(&buffer, b"hello\0");
        assert_eq!(
            native_crt_strcat_s(buffer.as_mut_ptr(), 6, b"!\0".as_ptr()),
            ERANGE
        );
        assert_eq!(buffer[0], 0, "overflow empties the destination");
        assert_eq!(
            native_crt_strcpy_s(buffer.as_mut_ptr(), 6, b"ab\0".as_ptr()),
            0
        );
        assert_eq!(
            native_crt_strncat_s(buffer.as_mut_ptr(), 6, b"cdefgh\0".as_ptr(), TRUNCATE),
            STRUNCATE
        );
        assert_eq!(&buffer, b"abcde\0");
        assert_eq!(
            native_crt_strncpy_s(buffer.as_mut_ptr(), 6, b"xyz\0".as_ptr(), 2),
            0
        );
        assert_eq!(&buffer[..3], b"xy\0");
        let mut wide_buffer = [0u16; 8];
        assert_eq!(
            native_crt_wcscpy_s(wide_buffer.as_mut_ptr(), 8, wide("C:\\").as_ptr()),
            0
        );
        assert_eq!(
            native_crt_wcscat_s(wide_buffer.as_mut_ptr(), 8, wide("dir").as_ptr()),
            0
        );
        assert_eq!(String::from_utf16_lossy(&wide_buffer[..6]), "C:\\dir");
    }

    #[test]
    fn strings_compare_duplicate_and_tokenize() {
        assert_eq!(
            native_crt_wcsicmp(
                wide("Program Files").as_ptr(),
                wide("PROGRAM files").as_ptr()
            ),
            0
        );
        assert!(native_crt_wcsicmp(wide("a").as_ptr(), wide("B").as_ptr()) < 0);
        assert_eq!(
            native_crt_wcsnicmp(wide("hostfxr.dll").as_ptr(), wide("HOSTFXR.x").as_ptr(), 8),
            0
        );
        assert_eq!(native_crt_wcsnlen(wide("abcdef").as_ptr(), 4), 4);
        assert_eq!(native_crt_strnlen(b"abc\0".as_ptr(), 10), 3);
        let copy = native_crt_wcsdup(wide("dup").as_ptr());
        assert_eq!(
            unsafe { std::slice::from_raw_parts(copy, 4) },
            &wide("dup")[..]
        );
        unsafe { free(copy.cast()) };

        let mut text = *b"a,,b;c\0";
        let mut context = std::ptr::null_mut();
        let mut tokens = Vec::new();
        let mut token = native_crt_strtok_s(text.as_mut_ptr(), b",;\0".as_ptr(), &mut context);
        while !token.is_null() {
            tokens.push(
                unsafe { std::ffi::CStr::from_ptr(token.cast()) }
                    .to_str()
                    .unwrap()
                    .to_string(),
            );
            token = native_crt_strtok_s(std::ptr::null_mut(), b",;\0".as_ptr(), &mut context);
        }
        assert_eq!(tokens, ["a", "b", "c"]);
    }

    #[test]
    fn character_classes_and_case_mapping() {
        assert_eq!(native_crt_isalpha(i32::from(b'q')), 1);
        assert_eq!(native_crt_isdigit(i32::from(b'q')), 0);
        assert_eq!(native_crt_isspace(0x0b), 1);
        assert_eq!(native_crt_iswspace(0x3000), 1);
        assert_eq!(native_crt_towlower(u16::from(b'Q')), u16::from(b'q'));
        assert_eq!(native_crt_towupper(0xe9), 0xc9);
        assert_eq!(native_crt_iswascii(0x80), 0);
    }

    #[test]
    fn ltow_s_formats_signed_decimal_and_unsigned_other_radixes() {
        let mut buffer = [0u16; 12];
        assert_eq!(native_crt_ltow_s(-42, buffer.as_mut_ptr(), 12, 10), 0);
        assert_eq!(String::from_utf16_lossy(&buffer[..3]), "-42");
        assert_eq!(native_crt_ltow_s(255, buffer.as_mut_ptr(), 12, 16), 0);
        assert_eq!(String::from_utf16_lossy(&buffer[..2]), "ff");
        assert_eq!(native_crt_ltow_s(12345, buffer.as_mut_ptr(), 3, 10), ERANGE);
    }
}

#[cfg(test)]
mod integer_utility_tests {
    use super::*;

    fn strtoll(text: &str, base: i32) -> (i64, usize, i32) {
        let bytes: Vec<u8> = text.bytes().chain([0]).collect();
        let mut end = std::ptr::null_mut();
        THREAD_CRT_ERRNO.with(|errno| errno.set(0));
        let value = native_crt_strtoll(bytes.as_ptr(), &mut end, base);
        let used = if end.is_null() { 0 } else { end as usize - bytes.as_ptr() as usize };
        (value, used, THREAD_CRT_ERRNO.with(|errno| errno.get()))
    }

    #[test]
    fn strtoll_parses_signs_bases_and_saturates() {
        assert_eq!(strtoll("  -42x", 10), (-42, 5, 0));
        assert_eq!(strtoll("0x7fffffffffffffff", 0), (i64::MAX, 18, 0));
        assert_eq!(strtoll("9223372036854775808", 10), (i64::MAX, 19, ERANGE));
        assert_eq!(strtoll("-9223372036854775808", 10), (i64::MIN, 20, 0));
        assert_eq!(strtoll("-9223372036854775809", 10), (i64::MIN, 20, ERANGE));
        assert_eq!(strtoll("zz", 10), (0, 0, 0));
        assert_eq!(strtoll("1", 1).2, EINVAL);
    }

    #[test]
    fn byte_swaps_hex_digits_and_time_differences() {
        assert_eq!(native_crt_byteswap_ushort(0x1234), 0x3412);
        assert_eq!(native_crt_byteswap_ulong(0x1234_5678), 0x7856_3412);
        assert_eq!(native_crt_byteswap_uint64(0x0102_0304_0506_0708), 0x0807_0605_0403_0201);
        assert_eq!(
            (native_crt_isxdigit(b'F' as i32), native_crt_isxdigit(b'g' as i32), native_crt_isxdigit(300)),
            (1, 0, 0)
        );
        assert_eq!(native_crt_difftime64(10, 25), -15.0);
    }
}
