//! The CRT's low-level I/O on file descriptors: `_open`/`_wopen`, `_lseek`,
//! `_dup`/`_dup2`, `_commit`, `_chsize_s`, `_umask`, `_chmod`/`_wchmod`,
//! and the `i32`-sized stat variants. Descriptors map to Windows handles in
//! the process's descriptor table, as the UCRT's lowio does.

use super::*;

const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const EMFILE: i32 = 24;
const ENOENT: i32 = 2;
const ENOSPC: i32 = 28;

fn set_errno(value: i32) {
    THREAD_CRT_ERRNO.with(|errno| errno.set(value));
}

/// The UCRT's `_dosmaperr`: errno for a Windows error code.
pub(super) fn errno_for_win32(code: u32) -> i32 {
    match code {
        2 | 3 | 15 | 18 | 53 | 67 | 123 | 161 | 206 => ENOENT,
        4 => EMFILE,
        5 | 19..=36 | 65 | 82 | 108 | 1816 => EACCES,
        6 | 130 => EBADF,
        8 | 9 | 14 => 12, // ENOMEM
        80 | 183 => EEXIST,
        89 => 11, // EAGAIN
        109 => 32, // EPIPE
        112 => ENOSPC,
        145 => 41, // ENOTEMPTY
        _ => EINVAL,
    }
}

fn fail_with_last_error() -> i32 {
    let code = native_get_last_error();
    set_doserrno(code);
    set_errno(errno_for_win32(code));
    -1
}

/// `_open` flags as CreateFileW access, sharing, and disposition.
fn open(path: &[u16], flags: i32, mode: i32) -> i32 {
    const O_WRONLY: i32 = 0x1;
    const O_RDWR: i32 = 0x2;
    const O_APPEND: i32 = 0x8;
    const O_CREAT: i32 = 0x100;
    const O_TRUNC: i32 = 0x200;
    const O_EXCL: i32 = 0x400;
    const O_NOINHERIT: i32 = 0x80;
    const O_TEMPORARY: i32 = 0x40;
    const S_IWRITE: i32 = 0x80;
    let access = match flags & 3 {
        0 => 0x8000_0000u32,
        O_WRONLY => 0x4000_0000,
        O_RDWR => 0xC000_0000,
        _ => {
            set_errno(EINVAL);
            return -1;
        }
    };
    let disposition = match (flags & O_CREAT != 0, flags & O_EXCL != 0, flags & O_TRUNC != 0) {
        (true, true, _) => 1, // CREATE_NEW
        (true, false, true) => 2, // CREATE_ALWAYS
        (true, false, false) => 4, // OPEN_ALWAYS
        (false, _, true) => 5, // TRUNCATE_EXISTING
        (false, _, false) => 3, // OPEN_EXISTING
    };
    let mut attributes = 0x80u32; // FILE_ATTRIBUTE_NORMAL
    if flags & O_CREAT != 0 && mode & S_IWRITE == 0 {
        attributes = 0x1; // FILE_ATTRIBUTE_READONLY
    }
    if flags & O_TEMPORARY != 0 {
        attributes |= 0x0400_0000; // FILE_FLAG_DELETE_ON_CLOSE
    }
    // SECURITY_ATTRIBUTES inheriting the handle unless _O_NOINHERIT.
    let mut security = [0u8; 24];
    security[..4].copy_from_slice(&24u32.to_le_bytes());
    if flags & O_NOINHERIT == 0 {
        security[16..20].copy_from_slice(&1u32.to_le_bytes());
    }
    let mut wide = path.to_vec();
    wide.push(0);
    // _SH_DENYNO, plus delete sharing for _O_TEMPORARY.
    let share = if flags & O_TEMPORARY != 0 { 7 } else { 3 };
    let handle = native_create_file_w(wide.as_ptr(), access, share, security.as_ptr() as u64, disposition, attributes, 0);
    if handle == u64::MAX || handle == 0 {
        return fail_with_last_error();
    }
    if flags & O_APPEND != 0 {
        native_set_file_pointer_ex(handle, 0, ptr::null_mut(), 2);
    }
    let fd = native_crt_open_osfhandle(handle, flags);
    if fd < 0 {
        native_close_handle(handle);
        set_errno(EMFILE);
    }
    fd
}

fn wide_path(path: *const u16) -> Option<Vec<u16>> {
    if path.is_null() {
        return None;
    }
    let mut units = Vec::new();
    for index in 0..32768usize {
        let unit = unsafe { path.add(index).read() };
        if unit == 0 {
            return Some(units);
        }
        units.push(unit);
    }
    None
}

fn ansi_path(path: *const u8) -> Option<Vec<u16>> {
    let mut wide = native_ansi_path(path)?;
    if wide.last() == Some(&0) {
        wide.pop();
    }
    Some(wide)
}

/// `_wopen(path, flags, mode)`; `mode` is read only with `_O_CREAT`.
pub(super) extern "win64" fn native_crt_wopen(path: *const u16, flags: i32, mode: i32) -> i32 {
    match wide_path(path) {
        Some(path) => open(&path, flags, mode),
        None => {
            set_errno(EINVAL);
            -1
        }
    }
}

pub(super) extern "win64" fn native_crt_open(path: *const u8, flags: i32, mode: i32) -> i32 {
    match (!path.is_null()).then(|| ansi_path(path)).flatten() {
        Some(path) => open(&path, flags, mode),
        None => {
            set_errno(EINVAL);
            -1
        }
    }
}

/// `_lseek`: a 32-bit offset; a position past 2 GiB is EINVAL.
pub(super) extern "win64" fn native_crt_lseek(fd: i32, offset: i32, origin: i32) -> i32 {
    let position = native_crt_lseeki64(fd, i64::from(offset), origin);
    if position > i64::from(i32::MAX) {
        set_errno(EINVAL);
        return -1;
    }
    position as i32
}

fn duplicate(handle: u64) -> Option<u64> {
    let process = process_ctx()?.process_handle;
    let mut copy = 0u64;
    // DUPLICATE_SAME_ACCESS, inheritable as the CRT's _dup makes it.
    (native_duplicate_handle(process, handle, process, &mut copy, 0, 1, 2) != 0).then_some(copy)
}

pub(super) extern "win64" fn native_crt_dup(fd: i32) -> i32 {
    let handle = native_crt_get_osfhandle(fd);
    if handle == u64::MAX {
        set_errno(EBADF);
        return -1;
    }
    let Some(copy) = duplicate(handle) else {
        return fail_with_last_error();
    };
    let new = native_crt_open_osfhandle(copy, 0);
    if new < 0 {
        native_close_handle(copy);
        set_errno(EMFILE);
    }
    new
}

/// `_dup2(from, to)`: `to` closes if open, then names a copy of `from`'s
/// handle; descriptors 0-2 also become the standard handles.
pub(super) extern "win64" fn native_crt_dup2(from: i32, to: i32) -> i32 {
    let handle = native_crt_get_osfhandle(from);
    if handle == u64::MAX || to < 0 {
        set_errno(EBADF);
        return -1;
    }
    if from == to {
        return 0;
    }
    let Some(copy) = duplicate(handle) else {
        return fail_with_last_error();
    };
    let Some(process) = process_ctx() else {
        set_errno(EBADF);
        return -1;
    };
    if (0..3).contains(&to) {
        let previous = process.parameters.std_handles[to as usize].swap(copy, Ordering::AcqRel);
        if previous != u64::MAX && previous != copy {
            native_close_handle(previous);
        }
        return 0;
    }
    let previous = process.crt_fds.lock().ok().and_then(|mut fds| fds.insert(to, copy));
    if let Some(previous) = previous {
        native_close_handle(previous);
    }
    0
}

pub(super) extern "win64" fn native_crt_commit(fd: i32) -> i32 {
    let handle = native_crt_get_osfhandle(fd);
    if handle == u64::MAX {
        set_errno(EBADF);
        return -1;
    }
    if native_flush_file_buffers(handle) == 0 {
        return fail_with_last_error();
    }
    0
}

/// `_chsize_s(fd, size)`: set the file's length, keeping the position;
/// returns an errno value.
pub(super) extern "win64" fn native_crt_chsize_s(fd: i32, size: i64) -> i32 {
    let handle = native_crt_get_osfhandle(fd);
    if handle == u64::MAX {
        set_errno(EBADF);
        return EBADF;
    }
    if size < 0 {
        set_errno(EINVAL);
        return EINVAL;
    }
    let mut position = 0i64;
    if native_set_file_pointer_ex(handle, 0, &mut position, 1) == 0
        || native_set_file_pointer_ex(handle, size, ptr::null_mut(), 0) == 0
        || native_set_end_of_file(handle) == 0
    {
        let errno = errno_for_win32(native_get_last_error());
        set_errno(errno);
        return errno;
    }
    native_set_file_pointer_ex(handle, position, ptr::null_mut(), 0);
    0
}

static UMASK: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// `_umask(mask)`: the previous mask; only `_S_IWRITE` matters on Windows.
pub(super) extern "win64" fn native_crt_umask(mask: i32) -> i32 {
    UMASK.swap(mask & 0x180, Ordering::AcqRel)
}

fn chmod(path: &[u16], mode: i32) -> i32 {
    let mut wide = path.to_vec();
    wide.push(0);
    let attributes = native_get_file_attributes_w(wide.as_ptr());
    if attributes == u32::MAX {
        return fail_with_last_error();
    }
    // Without _S_IWRITE the file becomes read-only.
    let next = if mode & 0x80 == 0 { attributes | 1 } else { attributes & !1 };
    if native_set_file_attributes_w(wide.as_ptr(), next) == 0 {
        return fail_with_last_error();
    }
    0
}

pub(super) extern "win64" fn native_crt_wchmod(path: *const u16, mode: i32) -> i32 {
    match wide_path(path) {
        Some(path) => chmod(&path, mode),
        None => {
            set_errno(EINVAL);
            -1
        }
    }
}

pub(super) extern "win64" fn native_crt_chmod(path: *const u8, mode: i32) -> i32 {
    match (!path.is_null()).then(|| ansi_path(path)).flatten() {
        Some(path) => chmod(&path, mode),
        None => {
            set_errno(EINVAL);
            -1
        }
    }
}

/// A `__stat64` (56 bytes) narrowed to `_stat64i32` (48 bytes): the size
/// becomes 32-bit; a larger file is EOVERFLOW (132), as the UCRT reports.
fn narrow_stat(wide: &[u8; 56], output: *mut u8) -> i32 {
    let size = i64::from_le_bytes(wide[24..32].try_into().unwrap());
    if size > i64::from(i32::MAX) {
        set_errno(132);
        return -1;
    }
    unsafe {
        std::ptr::write_bytes(output, 0, 48);
        output.copy_from_nonoverlapping(wide.as_ptr(), 20);
        output.add(20).cast::<i32>().write_unaligned(size as i32);
        output.add(24).copy_from_nonoverlapping(wide[32..56].as_ptr(), 24);
    }
    0
}

pub(super) extern "win64" fn native_crt_wstat64i32(path: *const u16, output: *mut u8) -> i32 {
    if output.is_null() {
        set_errno(EINVAL);
        return -1;
    }
    let mut wide = [0u8; 56];
    if native_crt_wstat64(path, wide.as_mut_ptr()) != 0 {
        return -1;
    }
    narrow_stat(&wide, output)
}

pub(super) extern "win64" fn native_crt_stat64i32(path: *const u8, output: *mut u8) -> i32 {
    if output.is_null() {
        set_errno(EINVAL);
        return -1;
    }
    let mut wide = [0u8; 56];
    if native_crt_stat64(path, wide.as_mut_ptr()) != 0 {
        return -1;
    }
    narrow_stat(&wide, output)
}

pub(super) extern "win64" fn native_crt_fstat64i32(fd: i32, output: *mut u8) -> i32 {
    if output.is_null() {
        set_errno(EINVAL);
        return -1;
    }
    let mut wide = [0u8; 56];
    if native_crt_fstat64(fd, wide.as_mut_ptr()) != 0 {
        return -1;
    }
    narrow_stat(&wide, output)
}

/// The current directory into `buffer` (`count` characters, terminator
/// included) for `_getcwd`/`_wgetcwd`: a null `buffer` gets a `malloc`ed
/// one of at least `count` characters; too small a buffer is `ERANGE`.
fn getcwd_into(buffer: *mut u8, count: i32, char_size: usize) -> *mut u8 {
    const ERANGE: i32 = 34;
    let cwd = fs_ctx()
        .and_then(|context| context.lock().ok().map(|ctx| ctx.fs.cwd()))
        .unwrap_or_else(|| "C:\\".to_string());
    let units: Vec<u16> = if char_size == 2 {
        cwd.encode_utf16().chain(std::iter::once(0)).collect()
    } else {
        cwd.bytes().map(u16::from).chain(std::iter::once(0)).collect()
    };
    let output = if buffer.is_null() {
        let capacity = units.len().max(count.max(0) as usize);
        let allocated = native_crt_malloc(capacity * char_size).cast::<u8>();
        if allocated.is_null() {
            set_errno(12); // ENOMEM
            return ptr::null_mut();
        }
        allocated
    } else {
        if count <= 0 {
            set_errno(EINVAL);
            return ptr::null_mut();
        }
        if (count as usize) < units.len() {
            set_errno(ERANGE);
            return ptr::null_mut();
        }
        buffer
    };
    unsafe {
        for (index, unit) in units.iter().enumerate() {
            if char_size == 2 {
                output.cast::<u16>().add(index).write_unaligned(*unit);
            } else {
                output.add(index).write(*unit as u8);
            }
        }
    }
    output
}

pub(super) extern "win64" fn native_crt_wgetcwd(buffer: *mut u16, count: i32) -> *mut u16 {
    getcwd_into(buffer.cast(), count, 2).cast()
}

pub(super) extern "win64" fn native_crt_getcwd(buffer: *mut u8, count: i32) -> *mut u8 {
    getcwd_into(buffer, count, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_flags_create_read_write_and_reject_existing() {
        let path: Vec<u16> = r"C:\crt-io-open.txt".encode_utf16().chain(Some(0)).collect();
        // _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE.
        let fd = native_crt_wopen(path.as_ptr(), 0x1 | 0x100 | 0x200 | 0x8000, 0x180);
        assert!(fd >= 3, "fd {fd}");
        assert_eq!(native_crt_write(fd, b"hello".as_ptr(), 5), 5);
        assert_eq!(native_crt_chsize_s(fd, 3), 0);
        assert_eq!(native_crt_lseek(fd, 0, 2), 3, "the size changed and the position stayed");
        let copy = native_crt_dup(fd);
        assert!(copy >= 3 && copy != fd);
        assert_eq!(native_crt_close(fd), 0);
        assert_eq!(native_crt_close(copy), 0);
        // _O_CREAT | _O_EXCL on an existing file: EEXIST.
        assert_eq!(native_crt_wopen(path.as_ptr(), 0x100 | 0x400, 0x180), -1);
        assert_eq!(THREAD_CRT_ERRNO.with(|errno| errno.get()), EEXIST);
        let fd = native_crt_wopen(path.as_ptr(), 0, 0);
        let mut buffer = [0u8; 8];
        assert_eq!(native_crt_read(fd, buffer.as_mut_ptr(), 8), 3);
        assert_eq!(&buffer[..3], b"hel");
        let mut stat = [0u8; 48];
        assert_eq!(native_crt_fstat64i32(fd, stat.as_mut_ptr()), 0);
        assert_eq!(i32::from_le_bytes(stat[20..24].try_into().unwrap()), 3);
        assert_eq!(native_crt_close(fd), 0);
        let missing: Vec<u16> = r"C:\crt-io-missing.txt".encode_utf16().chain(Some(0)).collect();
        assert_eq!(native_crt_wopen(missing.as_ptr(), 0, 0), -1);
        assert_eq!(THREAD_CRT_ERRNO.with(|errno| errno.get()), ENOENT);
    }
}

thread_local! {
    static DOSERRNO: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// `__doserrno()`: the thread's `_doserrno`, the Windows error behind the
/// last errno a CRT call set from one.
pub(super) extern "win64" fn native_crt_doserrno() -> *mut u32 {
    DOSERRNO.with(|value| value.as_ptr())
}

pub(super) fn set_doserrno(code: u32) {
    DOSERRNO.with(|value| value.set(code));
}

pub(super) extern "win64" fn native_crt_set_errno(value: i32) -> i32 {
    set_errno(value);
    0
}

pub(super) extern "win64" fn native_crt_getpid() -> i32 {
    native_get_current_process_id() as i32
}

static ABORT_BEHAVIOR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x3);

/// `_set_abort_behavior(flags, mask)`: the previous flags
/// (`_WRITE_ABORT_MSG` 1, `_CALL_REPORTFAULT` 2).
pub(super) extern "win64" fn native_crt_set_abort_behavior(flags: u32, mask: u32) -> u32 {
    let mut previous = ABORT_BEHAVIOR.load(Ordering::Acquire);
    loop {
        let next = (previous & !mask) | (flags & mask);
        match ABORT_BEHAVIOR.compare_exchange(previous, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return previous,
            Err(current) => previous = current,
        }
    }
}

static QUICK_EXIT: Mutex<Vec<u64>> = Mutex::new(Vec::new());

/// `_crt_at_quick_exit(function)`: registered for `quick_exit`.
pub(super) extern "win64" fn native_crt_at_quick_exit(function: u64) -> i32 {
    if function == 0 {
        return -1;
    }
    QUICK_EXIT.lock().map_or(-1, |mut functions| {
        functions.push(function);
        0
    })
}

/// `clock()`: milliseconds (`CLOCKS_PER_SEC` 1000) since the process
/// started.
pub(super) extern "win64" fn native_crt_clock() -> i32 {
    let Some(process) = process_ctx() else {
        return -1;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64 / 100 + 116_444_736_000_000_000);
    (now.saturating_sub(process.times.creation) / 10_000).min(i32::MAX as u64) as i32
}
