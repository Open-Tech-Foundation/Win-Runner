//! UCRT and VCRUNTIME odds and ends: restartable multibyte conversion in
//! the "C" locale, aligned heap blocks, searching, error text, stream
//! setup, and the `type_info`/`std::exception` helpers of VCRUNTIME140.

use super::*;

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;
const EILSEQ: i32 = 42;

fn set_errno(value: i32) {
    THREAD_CRT_ERRNO.with(|errno| errno.set(value));
}

// ---- multibyte conversion ("C" locale: one byte per character) -------------

/// `___mb_cur_max_l_func(locale)`: one byte per character.
pub(super) extern "win64" fn native_crt_mb_cur_max_l(_locale: *const u64) -> i32 {
    1
}

/// `mbrtowc(output, input, count, state)`: 0 for NUL, 1 for any other
/// byte, and `(size_t)-2` when no byte is available.
pub(super) extern "win64" fn native_crt_mbrtowc(
    output: *mut u16,
    input: *const u8,
    count: usize,
    _state: *mut u32,
) -> usize {
    if input.is_null() {
        return 0;
    }
    if count == 0 {
        return usize::MAX - 1;
    }
    let byte = unsafe { input.read() };
    if !output.is_null() {
        unsafe { output.write(u16::from(byte)) };
    }
    usize::from(byte != 0)
}

pub(super) extern "win64" fn native_crt_mbrlen(input: *const u8, count: usize, state: *mut u32) -> usize {
    native_crt_mbrtowc(ptr::null_mut(), input, count, state)
}

/// `mbsrtowcs(output, source, count, state)`: converts up to `count`
/// characters and advances `*source` (to null once the terminator is
/// converted); with a null `output` it only counts.
pub(super) extern "win64" fn native_crt_mbsrtowcs(
    output: *mut u16,
    source: *mut *const u8,
    count: usize,
    _state: *mut u32,
) -> usize {
    if source.is_null() || unsafe { source.read() }.is_null() {
        set_errno(EINVAL);
        return usize::MAX;
    }
    let input = unsafe { source.read() };
    let mut converted = 0;
    loop {
        if !output.is_null() && converted == count {
            unsafe { source.write(input.add(converted)) };
            return converted;
        }
        let byte = unsafe { input.add(converted).read() };
        if !output.is_null() {
            unsafe { output.add(converted).write(u16::from(byte)) };
        }
        if byte == 0 {
            if !output.is_null() {
                unsafe { source.write(ptr::null()) };
            }
            return converted;
        }
        converted += 1;
    }
}

/// `wcrtomb(output, character, state)`: code units above 0xff have no
/// "C" locale byte (`EILSEQ`).
pub(super) extern "win64" fn native_crt_wcrtomb(output: *mut u8, character: u16, _state: *mut u32) -> usize {
    if output.is_null() {
        return 1;
    }
    let Ok(byte) = u8::try_from(character) else {
        set_errno(EILSEQ);
        return usize::MAX;
    };
    unsafe { output.write(byte) };
    1
}

pub(super) extern "win64" fn native_crt_wcrtomb_s(
    written: *mut usize,
    output: *mut u8,
    size: usize,
    character: u16,
    state: *mut u32,
) -> i32 {
    if !output.is_null() && size == 0 {
        set_errno(EINVAL);
        return EINVAL;
    }
    let result = native_crt_wcrtomb(output, character, state);
    if !written.is_null() {
        unsafe { written.write(result) };
    }
    if result == usize::MAX { EILSEQ } else { 0 }
}

// ---- character classes and strings ----------------------------------------

pub(super) extern "win64" fn native_crt_isalnum(value: i32) -> i32 {
    i32::from(u8::try_from(value).is_ok_and(|byte| byte.is_ascii_alphanumeric()))
}

pub(super) extern "win64" fn native_crt_isprint(value: i32) -> i32 {
    i32::from(matches!(value, 0x20..=0x7e))
}

pub(super) extern "win64" fn native_crt_strcpy(destination: *mut u8, source: *const u8) -> *mut u8 {
    let length = unsafe { std::ffi::CStr::from_ptr(source.cast()) }.to_bytes().len();
    unsafe { ptr::copy(source, destination, length + 1) };
    destination
}

pub(super) extern "win64" fn native_crt_strcat(destination: *mut u8, source: *const u8) -> *mut u8 {
    let end = unsafe { std::ffi::CStr::from_ptr(destination.cast()) }.to_bytes().len();
    native_crt_strcpy(unsafe { destination.add(end) }, source);
    destination
}

pub(super) extern "win64" fn native_crt_memchr(buffer: *const u8, value: i32, count: usize) -> *const u8 {
    if count == 0 {
        return ptr::null();
    }
    let bytes = unsafe { std::slice::from_raw_parts(buffer, count) };
    bytes
        .iter()
        .position(|&byte| byte == value as u8)
        .map_or(ptr::null(), |index| unsafe { buffer.add(index) })
}

/// `strtof` and the `_l` variants of `strtod`/`strtof`/`strtold` (long
/// double is double on Windows x64).
pub(super) extern "win64" fn native_crt_strtof(input: *const u8, end: *mut *mut u8) -> f32 {
    let value = native_crt_strtod(input, end);
    let single = value as f32;
    if value.is_finite() && single.is_infinite() {
        set_errno(ERANGE);
    }
    single
}
pub(super) extern "win64" fn native_crt_strtod_l(input: *const u8, end: *mut *mut u8, _locale: *const u64) -> f64 {
    native_crt_strtod(input, end)
}
pub(super) extern "win64" fn native_crt_strtof_l(input: *const u8, end: *mut *mut u8, _locale: *const u64) -> f32 {
    native_crt_strtof(input, end)
}

/// `_wtoi64`: leading spaces, an optional sign, then decimal digits;
/// overflow saturates, as the UCRT does.
pub(super) extern "win64" fn native_crt_wtoi64(input: *const u16) -> i64 {
    if input.is_null() {
        set_errno(EINVAL);
        return 0;
    }
    let unit = |index: usize| unsafe { input.add(index).read() };
    let mut index = 0;
    while matches!(unit(index), 0x20 | 0x09..=0x0d) {
        index += 1;
    }
    let negative = unit(index) == u16::from(b'-');
    if matches!(unit(index), 0x2b | 0x2d) {
        index += 1;
    }
    let mut value: i64 = 0;
    while let Some(digit) = char::from_u32(u32::from(unit(index))).and_then(|c| c.to_digit(10)) {
        let next = value.checked_mul(10).and_then(|v| v.checked_add(i64::from(digit)));
        match next {
            Some(next) => value = next,
            None => {
                set_errno(ERANGE);
                return if negative { i64::MIN } else { i64::MAX };
            }
        }
        index += 1;
    }
    if negative { -value } else { value }
}

// ---- heap -----------------------------------------------------------------

pub(super) extern "win64" fn native_crt_aligned_malloc(size: usize, alignment: usize) -> *mut c_void {
    if !alignment.is_power_of_two() {
        set_errno(EINVAL);
        return ptr::null_mut();
    }
    let mut block = ptr::null_mut();
    let alignment = alignment.max(std::mem::size_of::<usize>());
    if unsafe { libc::posix_memalign(&mut block, alignment, size.max(1)) } != 0 {
        set_errno(12); // ENOMEM
        return ptr::null_mut();
    }
    block
}

pub(super) extern "win64" fn native_crt_aligned_free(block: *mut c_void) {
    if !block.is_null() {
        unsafe { libc::free(block) };
    }
}

/// `_msize(block)`: the usable size of a `malloc` block.
pub(super) extern "win64" fn native_crt_msize(block: *mut c_void) -> usize {
    if block.is_null() {
        set_errno(EINVAL);
        return usize::MAX;
    }
    unsafe { libc::malloc_usable_size(block) }
}

// ---- utility ----------------------------------------------------------------

/// `bsearch(key, base, count, width, compare)` with a win64 comparator.
pub(super) extern "win64" fn native_crt_bsearch(
    key: *const c_void,
    base: *const u8,
    count: usize,
    width: usize,
    compare: extern "win64" fn(*const c_void, *const c_void) -> i32,
) -> *const u8 {
    let (mut low, mut high) = (0usize, count);
    while low < high {
        let middle = low + (high - low) / 2;
        let element = unsafe { base.add(middle * width) };
        match compare(key, element.cast()) {
            0 => return element,
            order if order < 0 => high = middle,
            _ => low = middle + 1,
        }
    }
    ptr::null()
}

/// `div(numerator, denominator)`: the 8-byte `div_t` comes back in RAX.
pub(super) extern "win64" fn native_crt_div(numerator: i32, denominator: i32) -> u64 {
    let quotient = numerator.wrapping_div(denominator);
    let remainder = numerator.wrapping_rem(denominator);
    u64::from(quotient as u32) | (u64::from(remainder as u32) << 32)
}

/// `rand_s(value)`: a cryptographically random `unsigned int`.
pub(super) extern "win64" fn native_crt_rand_s(value: *mut u32) -> i32 {
    if value.is_null() {
        set_errno(EINVAL);
        return EINVAL;
    }
    let mut bytes = [0u8; 4];
    if unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), 4, 0) } != 4 {
        return EINVAL;
    }
    unsafe { value.write(u32::from_ne_bytes(bytes)) };
    0
}

// ---- errors -----------------------------------------------------------------

/// The UCRT's `strerror` texts for the POSIX-style errno values.
fn error_text(errnum: i32) -> &'static str {
    match errnum {
        0 => "No error",
        1 => "Operation not permitted",
        2 => "No such file or directory",
        3 => "No such process",
        4 => "Interrupted function call",
        5 => "Input/output error",
        6 => "No such device or address",
        7 => "Arg list too long",
        8 => "Exec format error",
        9 => "Bad file descriptor",
        10 => "No child processes",
        11 => "Resource temporarily unavailable",
        12 => "Not enough space",
        13 => "Permission denied",
        14 => "Bad address",
        16 => "Resource device",
        17 => "File exists",
        18 => "Improper link",
        19 => "No such device",
        20 => "Not a directory",
        21 => "Is a directory",
        22 => "Invalid argument",
        23 => "Too many open files in system",
        24 => "Too many open files",
        25 => "Inappropriate I/O control operation",
        27 => "File too large",
        28 => "No space left on device",
        29 => "Invalid seek",
        30 => "Read-only file system",
        31 => "Too many links",
        32 => "Broken pipe",
        33 => "Domain error",
        34 => "Result too large",
        36 => "Resource deadlock avoided",
        38 => "Filename too long",
        39 => "No locks available",
        40 => "Function not implemented",
        41 => "Directory not empty",
        42 => "Illegal byte sequence",
        _ => "Unknown error",
    }
}

/// `strerror_s(buffer, size, errnum)`: the text, truncated to fit.
pub(super) extern "win64" fn native_crt_strerror_s(output: *mut u8, size: usize, errnum: i32) -> i32 {
    if output.is_null() || size == 0 {
        set_errno(EINVAL);
        return EINVAL;
    }
    let text = error_text(errnum).as_bytes();
    let length = text.len().min(size - 1);
    unsafe {
        output.copy_from_nonoverlapping(text.as_ptr(), length);
        output.add(length).write(0);
    }
    if length < text.len() { ERANGE } else { 0 }
}

/// `feclearexcept(excepts)`: clears the SSE status flags named by the
/// `FE_*` bits (which match MXCSR's low flags).
pub(super) extern "win64" fn native_crt_feclearexcept(excepts: i32) -> i32 {
    let mut control = 0u32;
    unsafe {
        std::arch::asm!("stmxcsr [{}]", in(reg) &mut control, options(nostack));
        control &= !(excepts as u32 & 0x3f);
        std::arch::asm!("ldmxcsr [{}]", in(reg) &control, options(nostack));
    }
    0
}

/// `_wassert(message, file, line)`: the UCRT's console report, then abort.
pub(super) extern "win64" fn native_crt_wassert(message: *const u16, file: *const u16, line: u32) -> ! {
    let report = format!(
        "Assertion failed: {}, file {}, line {line}\r\n",
        wide(message).unwrap_or_default(),
        wide(file).unwrap_or_default()
    );
    native_write_to_handle(STD_HANDLE_BASE + 2, report.as_bytes());
    native_crt_abort()
}

// ---- stream setup -----------------------------------------------------------

/// `setvbuf(stream, buffer, mode, size)`: winrun's streams write through,
/// so any valid mode is accepted.
pub(super) extern "win64" fn native_crt_setvbuf(stream: *mut u8, _buffer: *mut u8, mode: i32, size: usize) -> i32 {
    // _IOFBF 0, _IOLBF 0x40, _IONBF 4.
    if stream.is_null() || !matches!(mode, 0 | 0x40 | 4) || (mode != 4 && !(2..=i32::MAX as usize).contains(&size)) {
        set_errno(EINVAL);
        return -1;
    }
    0
}

pub(super) extern "win64" fn native_crt_setbuf(stream: *mut u8, buffer: *mut u8) {
    native_crt_setvbuf(stream, buffer, if buffer.is_null() { 4 } else { 0 }, 512);
}

/// `_setmode(fd, mode)`: descriptors are binary-transparent here; the
/// previous mode is reported as `_O_TEXT`.
pub(super) extern "win64" fn native_crt_setmode(fd: i32, mode: i32) -> i32 {
    const MODES: [i32; 5] = [0x4000, 0x8000, 0x10000, 0x20000, 0x40000];
    if native_crt_get_osfhandle(fd) == u64::MAX {
        set_errno(9); // EBADF
        return -1;
    }
    if !MODES.contains(&mode) {
        set_errno(EINVAL);
        return -1;
    }
    0x4000
}

// ---- VCRUNTIME140 helpers -----------------------------------------------------

/// `__std_type_info_compare(left, right)`: `type_info` data is an
/// undecorated-name cache pointer followed by the decorated name.
pub(super) extern "win64" fn native_std_type_info_compare(left: *const u8, right: *const u8) -> i32 {
    if left == right {
        return 0;
    }
    let name = |data: *const u8| unsafe { std::ffi::CStr::from_ptr(data.add(9).cast()) };
    match name(left).cmp(name(right)) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// `std::exception`'s payload: the message and whether it owns a copy.
#[repr(C)]
pub(super) struct StdExceptionData {
    what: *const u8,
    owned: bool,
}

/// `__std_exception_copy(source, destination)`: owned messages are
/// duplicated, borrowed ones shared.
pub(super) extern "win64" fn native_std_exception_copy(
    source: *const StdExceptionData,
    destination: *mut StdExceptionData,
) {
    let source = unsafe { &*source };
    let destination = unsafe { &mut *destination };
    if source.owned && !source.what.is_null() {
        destination.what = native_crt_strdup(source.what);
        destination.owned = !destination.what.is_null();
    } else {
        destination.what = source.what;
        destination.owned = false;
    }
}

pub(super) extern "win64" fn native_std_exception_destroy(data: *mut StdExceptionData) {
    let data = unsafe { &mut *data };
    if data.owned {
        native_crt_free(data.what.cast_mut().cast());
    }
    data.what = ptr::null();
    data.owned = false;
}

pub(super) extern "win64" fn native_std_terminate() -> ! {
    native_crt_abort()
}

/// `_purecall`: a call through an unset virtual function slot.
pub(super) extern "win64" fn native_crt_purecall() -> ! {
    native_crt_abort()
}

pub(super) extern "win64" fn native_crt_uncaught_exceptions() -> i32 {
    0
}

thread_local! {
    static CURRENT_EXCEPTION: std::cell::Cell<[u64; 2]> = const { std::cell::Cell::new([0; 2]) };
}

/// `__current_exception()` / `__current_exception_context()`: the
/// per-thread slots for the exception being handled.
pub(super) extern "win64" fn native_current_exception() -> *mut u64 {
    CURRENT_EXCEPTION.with(|slots| slots.as_ptr().cast())
}
pub(super) extern "win64" fn native_current_exception_context() -> *mut u64 {
    CURRENT_EXCEPTION.with(|slots| unsafe { slots.as_ptr().cast::<u64>().add(1) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restartable_conversions_use_single_byte_c_characters() {
        let mut unit = 0u16;
        assert_eq!(native_crt_mbrtowc(&mut unit, b"z".as_ptr(), 1, ptr::null_mut()), 1);
        assert_eq!(unit, u16::from(b'z'));
        assert_eq!(native_crt_mbrtowc(&mut unit, b"z".as_ptr(), 0, ptr::null_mut()), usize::MAX - 1);
        assert_eq!(native_crt_mbrlen(b"\0".as_ptr(), 1, ptr::null_mut()), 0);
        let text = b"hi!\0";
        let mut source = text.as_ptr();
        assert_eq!(native_crt_mbsrtowcs(ptr::null_mut(), &mut source, 0, ptr::null_mut()), 3);
        let mut output = [0u16; 8];
        assert_eq!(native_crt_mbsrtowcs(output.as_mut_ptr(), &mut source, 2, ptr::null_mut()), 2);
        assert_eq!(source, unsafe { text.as_ptr().add(2) });
        assert_eq!(native_crt_mbsrtowcs(output.as_mut_ptr(), &mut source, 8, ptr::null_mut()), 1);
        assert!(source.is_null(), "the terminator was converted");
        let mut byte = 0u8;
        assert_eq!(native_crt_wcrtomb(&mut byte, 0xe9, ptr::null_mut()), 1);
        assert_eq!(byte, 0xe9);
        assert_eq!(native_crt_wcrtomb(&mut byte, 0x263a, ptr::null_mut()), usize::MAX);
        let mut written = 0;
        assert_eq!(native_crt_wcrtomb_s(&mut written, &mut byte, 1, 0x263a, ptr::null_mut()), EILSEQ);
        assert_eq!(native_crt_mb_cur_max_l(ptr::null()), 1);
    }

    #[test]
    fn strings_numbers_and_searches_follow_the_crt() {
        let mut buffer = [0u8; 16];
        native_crt_strcpy(buffer.as_mut_ptr(), b"es\0".as_ptr());
        native_crt_strcat(buffer.as_mut_ptr(), b"run\0".as_ptr());
        assert_eq!(&buffer[..6], b"esrun\0");
        assert_eq!(native_crt_memchr(buffer.as_ptr(), b'r' as i32, 5), unsafe { buffer.as_ptr().add(2) });
        assert!(native_crt_memchr(buffer.as_ptr(), b'x' as i32, 5).is_null());
        assert_eq!((native_crt_isalnum(b'7' as i32), native_crt_isalnum(b'-' as i32)), (1, 0));
        assert_eq!((native_crt_isprint(b' ' as i32), native_crt_isprint(0x7f)), (1, 0));
        let number: Vec<u16> = "  -9223372036854775808".encode_utf16().chain([0]).collect();
        assert_eq!(native_crt_wtoi64(number.as_ptr()), i64::MIN);
        assert_eq!(native_crt_strtof(b"1.5\0".as_ptr(), ptr::null_mut()), 1.5);
        assert_eq!(native_crt_div(-7, 2), u64::from(-3i32 as u32) | (u64::from(-1i32 as u32) << 32));
        extern "win64" fn compare(key: *const c_void, element: *const c_void) -> i32 {
            unsafe { *key.cast::<i32>() - *element.cast::<i32>() }
        }
        let sorted = [1i32, 3, 5, 7, 9];
        let found = native_crt_bsearch((&7i32 as *const i32).cast(), sorted.as_ptr().cast(), 5, 4, compare);
        assert_eq!(found, unsafe { sorted.as_ptr().add(3) }.cast());
        assert!(native_crt_bsearch((&4i32 as *const i32).cast(), sorted.as_ptr().cast(), 5, 4, compare).is_null());
        let mut random = 0u32;
        assert_eq!(native_crt_rand_s(&mut random), 0);
    }

    #[test]
    fn heap_errors_and_exception_payloads() {
        let block = native_crt_aligned_malloc(100, 64);
        assert_eq!(block as usize % 64, 0);
        native_crt_aligned_free(block);
        assert!(native_crt_aligned_malloc(8, 3).is_null());
        let block = native_crt_malloc(24);
        assert!(native_crt_msize(block) >= 24);
        native_crt_free(block);
        let mut text = [0u8; 8];
        assert_eq!(native_crt_strerror_s(text.as_mut_ptr(), 8, 2), ERANGE);
        assert_eq!(&text, b"No such\0");
        let mut text = [0u8; 64];
        assert_eq!(native_crt_strerror_s(text.as_mut_ptr(), 64, 13), 0);
        assert!(text.starts_with(b"Permission denied\0"));

        let message = native_crt_strdup(b"boom\0".as_ptr());
        let source = StdExceptionData { what: message, owned: true };
        let mut copy = StdExceptionData { what: ptr::null(), owned: false };
        native_std_exception_copy(&source, &mut copy);
        assert!(copy.owned && copy.what != source.what);
        native_std_exception_destroy(&mut copy);
        assert!(copy.what.is_null());
        native_crt_free(message.cast());

        let int_info = b"\0\0\0\0\0\0\0\0.H\0";
        let other = b"\0\0\0\0\0\0\0\0.N\0";
        assert_eq!(native_std_type_info_compare(int_info.as_ptr(), int_info.as_ptr()), 0);
        assert_eq!(native_std_type_info_compare(int_info.as_ptr(), other.as_ptr()), -1);
        assert_eq!(native_crt_setmode(1, 0x8000), 0x4000);
        assert_eq!(native_crt_setmode(9999, 0x8000), -1);
        assert_eq!(native_crt_feclearexcept(0x3f), 0);
        assert_ne!(native_current_exception(), native_current_exception_context());
    }
}
