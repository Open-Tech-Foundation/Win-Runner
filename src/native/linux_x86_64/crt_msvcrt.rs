//! Functions the system `msvcrt.dll` exports that the UCRT names
//! differently or no longer has: MinGW-built programs (Git for Windows)
//! import these. Each keeps msvcrt's own contract where it differs from the
//! UCRT's (`_vsnprintf`'s truncation, the count-less `swprintf`).

use super::*;

const EINVAL: i32 = 22;

fn set_errno(value: i32) {
    THREAD_CRT_ERRNO.with(|errno| errno.set(value));
}

/// `__wgetmainargs(argc, argv, env, wildcard, startup)`: the wide
/// arguments and environment, as `__getmainargs` gives the narrow ones.
pub(super) extern "win64" fn native_crt_wgetmainargs(
    argc_out: *mut i32,
    argv_out: *mut *mut *mut u16,
    env_out: *mut *mut *mut u16,
    _wildcard: i32,
    _startup: *mut u8,
) -> i32 {
    let argv = native_crt_p_wargv();
    let Some(process) = process_ctx() else {
        return -1;
    };
    let Ok(mut startup) = process.crt_startup.lock() else {
        return -1;
    };
    let Some(startup) = startup.as_mut() else {
        return -1;
    };
    unsafe {
        if !argc_out.is_null() {
            argc_out.write_unaligned(startup.argc);
        }
        if !argv_out.is_null() && !argv.is_null() {
            argv_out.write_unaligned(argv.read());
        }
        if !env_out.is_null() {
            env_out.write_unaligned(startup.wide_environment.as_mut_ptr().cast());
        }
    }
    0
}

/// `_amsg_exit(code)`: the runtime's fatal-error exit, status 255.
pub(super) extern "win64" fn native_crt_amsg_exit(code: i32) -> ! {
    let message = format!("\r\nruntime error R60{code:02}\r\n");
    native_crt_fwrite(message.as_ptr(), 1, message.len(), native_crt_acrt_iob_func(2));
    native_exit_process(255)
}

/// `_assert(message, file, line)`: `_wassert` with narrow strings.
pub(super) extern "win64" fn native_crt_assert(message: *const u8, file: *const u8, line: u32) -> ! {
    let wide = |text: *const u8| -> Vec<u16> {
        let text = if text.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(text.cast()) }.to_string_lossy().into_owned()
        };
        text.encode_utf16().chain([0]).collect()
    };
    let (message, file) = (wide(message), wide(file));
    native_crt_wassert(message.as_ptr(), file.as_ptr(), line)
}

/// `_endthreadex(code)`: end the calling thread.
pub(super) extern "win64" fn native_crt_endthreadex(code: u32) -> ! {
    native_exit_thread(code)
}

/// The "C" locale's character classes, as msvcrt's `_ctype` table holds
/// them: `_UPPER` 0x1, `_LOWER` 0x2, `_DIGIT` 0x4, `_SPACE` 0x8, `_PUNCT`
/// 0x10, `_CONTROL` 0x20, `_BLANK` 0x40, `_HEX` 0x80, alphabetic 0x100.
fn character_class(value: i32) -> i32 {
    match value {
        0x09 => 0x68,
        0x0a..=0x0d => 0x28,
        0x00..=0x1f | 0x7f => 0x20,
        0x20 => 0x48,
        0x30..=0x39 => 0x84,
        0x41..=0x46 => 0x181,
        0x47..=0x5a => 0x101,
        0x61..=0x66 => 0x182,
        0x67..=0x7a => 0x102,
        0x21..=0x7e => 0x10,
        _ => 0,
    }
}

pub(super) extern "win64" fn native_crt_isctype(value: i32, mask: i32) -> i32 {
    character_class(value) & mask
}
pub(super) extern "win64" fn native_crt_iscntrl(value: i32) -> i32 {
    character_class(value) & 0x20
}
pub(super) extern "win64" fn native_crt_isgraph(value: i32) -> i32 {
    character_class(value) & (0x10 | 0x100 | 0x4)
}
pub(super) extern "win64" fn native_crt_islower(value: i32) -> i32 {
    character_class(value) & 0x2
}
pub(super) extern "win64" fn native_crt_isupper(value: i32) -> i32 {
    character_class(value) & 0x1
}
pub(super) extern "win64" fn native_crt_ispunct(value: i32) -> i32 {
    character_class(value) & 0x10
}

/// Set `errno` from the last Win32 error of a failed directory call.
fn directory_errno() -> i32 {
    set_errno(match native_get_last_error() {
        2 | 3 | 123 => 2, // ENOENT
        5 | 32 => 13,     // EACCES
        80 | 183 => 17,   // EEXIST
        145 => 41,        // ENOTEMPTY
        _ => EINVAL,
    });
    -1
}

fn narrow_to_wide(path: *const u8) -> Option<Vec<u16>> {
    if path.is_null() {
        return None;
    }
    let text = unsafe { std::ffi::CStr::from_ptr(path.cast()) }.to_string_lossy();
    Some(text.encode_utf16().chain([0]).collect())
}

pub(super) extern "win64" fn native_crt_wmkdir(path: *const u16) -> i32 {
    if native_create_directory_w(path, 0) != 0 { 0 } else { directory_errno() }
}
pub(super) extern "win64" fn native_crt_wrmdir(path: *const u16) -> i32 {
    if native_remove_directory_w(path) != 0 { 0 } else { directory_errno() }
}
pub(super) extern "win64" fn native_crt_rmdir(path: *const u8) -> i32 {
    let Some(path) = narrow_to_wide(path) else {
        set_errno(EINVAL);
        return -1;
    };
    native_crt_wrmdir(path.as_ptr())
}
pub(super) extern "win64" fn native_crt_wchdir(path: *const u16) -> i32 {
    if native_set_current_directory_w(path) != 0 { 0 } else { directory_errno() }
}

/// `_telli64(fd)`: the descriptor's position.
pub(super) extern "win64" fn native_crt_telli64(fd: i32) -> i64 {
    native_crt_lseeki64(fd, 0, 1)
}

/// `_flushall()`: flush every stream. It returns the number of open
/// streams; only the three standard streams are counted, as files opened
/// with `fopen` are not tracked.
pub(super) extern "win64" fn native_crt_flushall() -> i32 {
    native_crt_fflush(ptr::null_mut());
    3
}

/// `_vscprintf(format, arguments)`: the formatted length.
pub(super) extern "win64" fn native_crt_vscprintf(format: *const u8, arguments: *mut c_void) -> i32 {
    native_crt_stdio_common_vsprintf(0, ptr::null_mut(), 0, format, ptr::null_mut(), arguments)
}

/// msvcrt's `_vsnprintf` truncation: text shorter than `count` is copied
/// and terminated and its length returned; text of exactly `count`
/// characters is copied without a terminator; longer text is cut to
/// `count` characters, unterminated, and -1 returned.
fn legacy_counted<T: Copy>(formatted: Option<Vec<T>>, output: *mut T, count: usize, terminator: T) -> i32 {
    let Some(units) = formatted else {
        set_errno(EINVAL);
        return -1;
    };
    if output.is_null() {
        if count == 0 {
            return units.len().min(i32::MAX as usize) as i32;
        }
        set_errno(EINVAL);
        return -1;
    }
    let copied = units.len().min(count);
    unsafe { ptr::copy_nonoverlapping(units.as_ptr(), output, copied) };
    if units.len() < count {
        unsafe { output.add(units.len()).write(terminator) };
    }
    if units.len() > count { -1 } else { units.len().min(i32::MAX as usize) as i32 }
}

pub(super) extern "win64" fn native_crt_vsnprintf(
    output: *mut u8,
    count: usize,
    format: *const u8,
    arguments: *mut c_void,
) -> i32 {
    legacy_counted(crt_format_narrow(format, arguments), output, count, 0)
}

pub(super) extern "win64" fn native_crt_vsnwprintf(
    output: *mut u16,
    count: usize,
    format: *const u16,
    arguments: *mut c_void,
) -> i32 {
    legacy_counted(crt_format_wide(format, arguments), output, count, 0)
}

/// `vfprintf(stream, format, arguments)`.
pub(super) extern "win64" fn native_crt_vfprintf(stream: *mut u8, format: *const u8, arguments: *mut c_void) -> i32 {
    native_crt_stdio_common_vfprintf(0, stream, format, ptr::null_mut(), arguments)
}

/// `fwprintf(stream, format, ...)`.
#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_crt_fwprintf(
    stream: *mut u8,
    format: *const u16,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
) -> i32 {
    let mut arguments = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9];
    native_crt_stdio_common_vfwprintf(0, stream, format, ptr::null_mut(), arguments.as_mut_ptr().cast())
}

/// msvcrt's `swprintf(buffer, format, ...)`: the count-less form, which
/// writes the whole text and a terminator.
#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_crt_swprintf(
    output: *mut u16,
    format: *const u16,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
) -> i32 {
    let mut arguments = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9];
    let Some(units) = crt_format_wide(format, arguments.as_mut_ptr().cast()) else {
        set_errno(EINVAL);
        return -1;
    };
    if output.is_null() {
        set_errno(EINVAL);
        return -1;
    }
    unsafe {
        ptr::copy_nonoverlapping(units.as_ptr(), output, units.len());
        output.add(units.len()).write(0);
    }
    units.len().min(i32::MAX as usize) as i32
}

/// `wcsspn(text, accept)`: the length of `text`'s prefix made only of
/// characters in `accept`.
pub(super) extern "win64" fn native_crt_wcsspn(text: *const u16, accept: *const u16) -> usize {
    let read = |pointer: *const u16| {
        let mut units = Vec::new();
        let mut index = 0;
        loop {
            let unit = unsafe { pointer.add(index).read() };
            if unit == 0 {
                return units;
            }
            units.push(unit);
            index += 1;
        }
    };
    let accept = read(accept);
    read(text).iter().take_while(|unit| accept.contains(unit)).count()
}

/// `perror(message)`: `message: <errno text>` on standard error.
pub(super) extern "win64" fn native_crt_perror(message: *const u8) {
    let errno = THREAD_CRT_ERRNO.with(|errno| errno.get());
    let text = unsafe { std::ffi::CStr::from_ptr(native_crt_strerror(errno).cast()) }.to_string_lossy().into_owned();
    let prefix = if message.is_null() {
        String::new()
    } else {
        let message = unsafe { std::ffi::CStr::from_ptr(message.cast()) }.to_string_lossy().into_owned();
        if message.is_empty() { message } else { format!("{message}: ") }
    };
    let line = format!("{prefix}{text}\n");
    native_crt_fwrite(line.as_ptr(), 1, line.len(), native_crt_acrt_iob_func(2));
}

/// `raise(signal)`: run the handler `signal()` installed, which is reset to
/// the default first; ignored signals do nothing, and the default action
/// ends the process with status 3.
pub(super) extern "win64" fn native_crt_raise(signal: i32) -> i32 {
    if !matches!(signal, 2 | 4 | 6 | 8 | 11 | 15 | 21 | 22) {
        set_errno(EINVAL);
        return -1;
    }
    let pid = process_ctx().map_or(0, |process| process.process_id);
    let handler = NATIVE_CRT_SIGNAL_HANDLERS
        .lock()
        .ok()
        .and_then(|mut handlers| {
            let handler = handlers.get(&(pid, signal)).copied().unwrap_or(0);
            if handler > 1 {
                handlers.insert((pid, signal), 0);
            }
            Some(handler)
        })
        .unwrap_or(0);
    match handler {
        0 => native_exit_process(3),
        1 => 0,
        handler => {
            let handler: extern "win64" fn(i32) = unsafe { std::mem::transmute(handler as usize) };
            handler(signal);
            0
        }
    }
}

std::thread_local! {
    static RAND_SEED: std::cell::Cell<u32> = const { std::cell::Cell::new(1) };
}

/// `srand(seed)` and `rand()`: msvcrt's per-thread linear congruential
/// generator (multiplier 214013, increment 2531011, bits 16-30).
pub(super) extern "win64" fn native_crt_srand(seed: u32) {
    RAND_SEED.with(|state| state.set(seed));
}
pub(super) extern "win64" fn native_crt_rand() -> i32 {
    RAND_SEED.with(|state| {
        let next = state.get().wrapping_mul(214_013).wrapping_add(2_531_011);
        state.set(next);
        ((next >> 16) & 0x7fff) as i32
    })
}

/// The "C" locale's `struct lconv`: "." as the decimal point, every other
/// string empty and every number `CHAR_MAX`; the UCRT's wide fields follow.
#[repr(C)]
pub(super) struct Lconv {
    strings: [*const u8; 10],
    numbers: [i8; 8],
    wide: [*const u16; 10],
}
unsafe impl Sync for Lconv {}

static DECIMAL_POINT: [u8; 2] = *b".\0";
static EMPTY: [u8; 1] = [0];
static WIDE_DECIMAL_POINT: [u16; 2] = [b'.' as u16, 0];
static WIDE_EMPTY: [u16; 1] = [0];
static C_LCONV: Lconv = Lconv {
    strings: [
        DECIMAL_POINT.as_ptr(),
        EMPTY.as_ptr(),
        EMPTY.as_ptr(),
        EMPTY.as_ptr(),
        EMPTY.as_ptr(),
        EMPTY.as_ptr(),
        EMPTY.as_ptr(),
        EMPTY.as_ptr(),
        EMPTY.as_ptr(),
        EMPTY.as_ptr(),
    ],
    numbers: [i8::MAX; 8],
    wide: [
        WIDE_DECIMAL_POINT.as_ptr(),
        WIDE_EMPTY.as_ptr(),
        WIDE_EMPTY.as_ptr(),
        WIDE_EMPTY.as_ptr(),
        WIDE_EMPTY.as_ptr(),
        WIDE_EMPTY.as_ptr(),
        WIDE_EMPTY.as_ptr(),
        WIDE_EMPTY.as_ptr(),
        WIDE_EMPTY.as_ptr(),
        WIDE_EMPTY.as_ptr(),
    ],
};

pub(super) extern "win64" fn native_crt_localeconv() -> *const Lconv {
    &C_LCONV
}

/// `LocalAlloc(flags, size)`: a block from the process heap (zeroed with
/// `LMEM_ZEROINIT`), freed by `LocalFree`. Blocks never move, so a
/// `LMEM_MOVEABLE` handle is the block itself.
pub(super) extern "win64" fn native_local_alloc(flags: u32, size: usize) -> u64 {
    if flags & !(0x2 | 0x40 | 0x2000) != 0 {
        native_set_last_error(87);
        return 0;
    }
    native_heap_alloc(PROCESS_HEAP_HANDLE, if flags & 0x40 != 0 { 0x8 } else { 0 }, size)
}

/// The runtime's internal locks `_lock(n)` and `_unlock(n)` take: one
/// reentrant lock per number, as critical sections.
static RUNTIME_LOCKS: [[u8; 40]; 64] = [[0; 40]; 64];

fn runtime_lock(number: i32) -> Option<*mut u8> {
    RUNTIME_LOCKS.get(usize::try_from(number).ok()?).map(|lock| lock.as_ptr().cast_mut())
}

pub(super) extern "win64" fn native_crt_lock(number: i32) {
    if let Some(lock) = runtime_lock(number) {
        native_enter_critical_section(lock);
    }
}

pub(super) extern "win64" fn native_crt_unlock(number: i32) {
    if let Some(lock) = runtime_lock(number) {
        native_leave_critical_section(lock);
    }
}

/// msvcrt's `_fstat(fd, buffer)`: `struct _stat` with 32-bit size and
/// times, from `_fstat64`'s fields.
pub(super) extern "win64" fn native_crt_fstat32(fd: i32, output: *mut u8) -> i32 {
    if output.is_null() {
        set_errno(EINVAL);
        return -1;
    }
    let mut wide = [0u8; 56];
    let result = native_crt_fstat64(fd, wide.as_mut_ptr());
    if result != 0 {
        return result;
    }
    let read64 = |offset: usize| i64::from_le_bytes(wide[offset..offset + 8].try_into().unwrap());
    let mut narrow = [0u8; 36];
    narrow[..20].copy_from_slice(&wide[..20]); // dev, ino, mode, nlink, uid, gid, rdev
    let size = read64(24);
    if size > i64::from(i32::MAX) {
        set_errno(132); // EOVERFLOW
        return -1;
    }
    narrow[20..24].copy_from_slice(&(size as i32).to_le_bytes());
    for (index, offset) in [32, 40, 48].into_iter().enumerate() {
        narrow[24 + index * 4..28 + index * 4].copy_from_slice(&(read64(offset) as i32).to_le_bytes());
    }
    unsafe { ptr::copy_nonoverlapping(narrow.as_ptr(), output, narrow.len()) };
    0
}

/// `fgetpos(stream, position)`: the stream's offset as an `fpos_t`.
pub(super) extern "win64" fn native_crt_fgetpos(stream: *mut u8, position: *mut i64) -> i32 {
    if position.is_null() {
        set_errno(EINVAL);
        return -1;
    }
    let offset = native_crt_ftelli64(stream);
    if offset < 0 {
        return -1;
    }
    unsafe { position.write_unaligned(offset) };
    0
}

/// `isleadbyte(c)`: the "C" locale has no multibyte lead bytes.
pub(super) extern "win64" fn native_crt_isleadbyte(_value: i32) -> i32 {
    0
}

/// `GetLocaleInfoA`: `GetLocaleInfoW`'s text in the ANSI code page. With
/// `LOCALE_RETURN_NUMBER` the value is a DWORD (four bytes).
pub(super) extern "win64" fn native_get_locale_info_a(lcid: u32, kind: u32, output: *mut u8, capacity: i32) -> i32 {
    let mut wide = [0u16; 256];
    let length = native_get_locale_info_w(lcid, kind, wide.as_mut_ptr(), wide.len() as i32);
    if length == 0 {
        return 0;
    }
    if kind & 0x2000_0000 != 0 {
        if capacity == 0 {
            return 4;
        }
        if capacity < 4 || output.is_null() {
            native_set_last_error(122);
            return 0;
        }
        unsafe { ptr::copy_nonoverlapping(wide.as_ptr().cast::<u8>(), output, 4) };
        return 4;
    }
    native_wide_char_to_multi_byte(0, 0, wide.as_ptr(), length, output, capacity, ptr::null(), ptr::null_mut())
}

/// SHLWAPI's `PathRemoveFileSpecW(path)`: cut the last component (and the
/// backslash before it, except a root's); TRUE when something was removed.
pub(super) extern "win64" fn native_path_remove_file_spec_w(path: *mut u16) -> i32 {
    if path.is_null() {
        return 0;
    }
    let mut cursor = path;
    let mut cut = path;
    let backslash = u16::from(b'\\');
    unsafe {
        // A leading `\\` or `\\\\` (a root or UNC prefix) stays.
        for _ in 0..2 {
            if cursor.read() == backslash {
                cursor = cursor.add(1);
                cut = cursor;
            }
        }
        while cursor.read() != 0 {
            if cursor.read() == backslash {
                cut = cursor;
            } else if cursor.read() == u16::from(b':') {
                cut = cursor.add(1);
                if cut.read() == backslash {
                    // The root's backslash stays, and is not a separator.
                    cursor = cut;
                    cut = cut.add(1);
                }
            }
            cursor = cursor.add(1);
        }
        if cut.read() == 0 {
            return 0;
        }
        cut.write(0);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rand_follows_msvcrt_sequence() {
        native_crt_srand(1);
        assert_eq!([native_crt_rand(), native_crt_rand(), native_crt_rand()], [41, 18467, 6334]);
    }

    #[test]
    fn character_classes_match_the_c_locale() {
        assert_eq!(native_crt_isctype(b'A' as i32, 0x1), 0x1);
        assert_eq!(native_crt_isctype(b'a' as i32, 0x80), 0x80);
        assert_eq!(native_crt_isctype(b'\t' as i32, 0x40), 0x40);
        assert_ne!(native_crt_iscntrl(0x7f), 0);
        assert_eq!(native_crt_isgraph(b' ' as i32), 0);
        assert_ne!(native_crt_isgraph(b'~' as i32), 0);
        assert_ne!(native_crt_ispunct(b'!' as i32), 0);
        assert_eq!(native_crt_isupper(0xc0), 0);
        assert_eq!(native_crt_isctype(-1, 0xffff), 0);
    }

    #[test]
    fn legacy_counted_output_keeps_msvcrt_truncation() {
        let mut buffer = [b'x'; 6];
        assert_eq!(legacy_counted(Some(b"abc".to_vec()), buffer.as_mut_ptr(), 5, 0), 3);
        assert_eq!(&buffer[..4], b"abc\0");
        let mut buffer = [b'x'; 6];
        assert_eq!(legacy_counted(Some(b"abcde".to_vec()), buffer.as_mut_ptr(), 5, 0), 5);
        assert_eq!(&buffer, b"abcdex", "exact fit: no terminator");
        let mut buffer = [b'x'; 6];
        assert_eq!(legacy_counted(Some(b"abcdefg".to_vec()), buffer.as_mut_ptr(), 5, 0), -1);
        assert_eq!(&buffer, b"abcdex");
        assert_eq!(legacy_counted(Some(b"abcdefg".to_vec()), ptr::null_mut(), 0, 0), 7);
    }

    #[test]
    fn path_remove_file_spec_keeps_roots() {
        let cases = [
            (r"C:\dir\file.exe", r"C:\dir", 1),
            (r"C:\file.exe", r"C:\", 1),
            (r"C:\", r"C:\", 0),
            ("file.exe", "", 1),
            (r"\file", r"\", 1),
            (r"\\server\share", r"\\server", 1),
        ];
        for (input, expected, result) in cases {
            let mut path: Vec<u16> = input.encode_utf16().chain([0]).collect();
            assert_eq!(native_path_remove_file_spec_w(path.as_mut_ptr()), result, "{input}");
            let end = path.iter().position(|unit| *unit == 0).unwrap();
            assert_eq!(String::from_utf16_lossy(&path[..end]), expected, "{input}");
        }
    }

    #[test]
    fn wcsspn_counts_the_accepted_prefix() {
        let text: Vec<u16> = "aabxa\0".encode_utf16().collect();
        let accept: Vec<u16> = "ab\0".encode_utf16().collect();
        assert_eq!(native_crt_wcsspn(text.as_ptr(), accept.as_ptr()), 3);
    }
}
