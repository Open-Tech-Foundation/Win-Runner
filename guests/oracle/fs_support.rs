// File-system helpers shared by the file-system oracle probes: each runs
// one Win32 call on a templated path (see `input` in common.rs) and prints
// the outcome as one line. Included with `include!` after common.rs.

type GetCurrentDirectoryWFn = unsafe extern "system" fn(u32, *mut u16) -> u32;
type SetCurrentDirectoryWFn = unsafe extern "system" fn(*const u16) -> i32;
type CreateDirectoryWFn = unsafe extern "system" fn(*const u16, usize) -> i32;
type DeleteFileWFn = unsafe extern "system" fn(*const u16) -> i32;
type GetFullPathNameWFn = unsafe extern "system" fn(*const u16, u32, *mut u16, *mut *mut u16) -> u32;
type GetFileAttributesWFn = unsafe extern "system" fn(*const u16) -> u32;
type CreateFileWFn = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
type CloseHandleFn = unsafe extern "system" fn(usize) -> i32;
type GetFinalPathNameByHandleWFn = unsafe extern "system" fn(usize, *mut u16, u32, u32) -> u32;
type FindFirstFileWFn = unsafe extern "system" fn(*const u16, *mut u8) -> usize;
type FindNextFileWFn = unsafe extern "system" fn(usize, *mut u8) -> i32;
type FindCloseFn = unsafe extern "system" fn(usize) -> i32;
type MoveFileExWFn = unsafe extern "system" fn(*const u16, *const u16, u32) -> i32;
type CopyFileWFn = unsafe extern "system" fn(*const u16, *const u16, i32) -> i32;
type GetLongPathNameWFn = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
type GetFileSizeExFn = unsafe extern "system" fn(usize, *mut i64) -> i32;

const INVALID_HANDLE: usize = usize::MAX;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const SHARE_ALL: u32 = 7;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const BACKUP_SEMANTICS: u32 = 0x0200_0000;

fn ok_or_error(name: &str, result: i32) {
    case(name);
    if result != 0 {
        out_str("ok");
    } else {
        out_str("fail");
        out_error();
    }
    out_byte(b'\n');
}

fn full_path(name: &str, template: &str) {
    let get = api!(name, "GetFullPathNameW", GetFullPathNameWFn);
    let mut buffer = [0u16; 1024];
    let path = input(template, &mut buffer);
    let mut output = [0u16; 1024];
    let mut file_part: *mut u16 = core::ptr::null_mut();
    clear_error();
    let length = unsafe { get(path.as_ptr(), 1024, output.as_mut_ptr(), &mut file_part) };
    case(name);
    if length == 0 {
        out_str("fail");
        out_error();
    } else {
        let actual = wide_len(&output);
        out_len_relation("len", length, actual);
        out_str(" path=");
        out_path(&output);
        // Where the file part starts, relative to just after the last
        // separator (where Windows puts it).
        out_str(" file=");
        if file_part.is_null() {
            out_str("null");
        } else {
            let offset = (file_part as usize - output.as_ptr() as usize) / 2;
            let after_last = output[..actual].iter().rposition(|&unit| unit == 0x5c).map_or(0, |index| index + 1);
            if offset == after_last {
                out_str("last");
            } else {
                out_str("other");
            }
        }
    }
    out_byte(b'\n');
}

fn attributes(name: &str, template: &str) {
    let get = api!(name, "GetFileAttributesW", GetFileAttributesWFn);
    let mut buffer = [0u16; 1024];
    let path = input(template, &mut buffer);
    clear_error();
    let value = unsafe { get(path.as_ptr()) };
    case(name);
    if value == u32::MAX {
        out_str("INVALID");
        out_error();
    } else {
        // Only the stable bits: directory, read-only, hidden, system.
        out_hex((value & 0x17) as u64);
        out_str(if value & 0x10 != 0 { " dir" } else { " file" });
    }
    out_byte(b'\n');
}

/// Open `template` and report the outcome; returns the handle.
fn open(name: &str, template: &str, access: u32, disposition: u32, flags: u32) -> usize {
    let address = kernel32(b"CreateFileW\0");
    if address == 0 {
        unavailable(name);
        return INVALID_HANDLE;
    }
    let create: CreateFileWFn = unsafe { core::mem::transmute(address) };
    let mut buffer = [0u16; 1024];
    let path = input(template, &mut buffer);
    clear_error();
    let handle = unsafe { create(path.as_ptr(), access, SHARE_ALL, 0, disposition, flags, 0) };
    case(name);
    if handle == INVALID_HANDLE {
        out_str("INVALID");
        out_error();
    } else {
        out_str("ok");
    }
    out_byte(b'\n');
    handle
}

fn close(handle: usize) {
    let address = kernel32(b"CloseHandle\0");
    if address != 0 && handle != INVALID_HANDLE {
        let close: CloseHandleFn = unsafe { core::mem::transmute(address) };
        unsafe { close(handle) };
    }
}

fn open_and_close(name: &str, template: &str, access: u32, disposition: u32, flags: u32) {
    let handle = open(name, template, access, disposition, flags);
    close(handle);
}

fn write_file(name: &str, template: &str, contents: &[u8]) {
    let handle = open(name, template, GENERIC_WRITE, CREATE_NEW, 0);
    if handle != INVALID_HANDLE {
        let mut written = 0u32;
        unsafe { WriteFile(handle, contents.as_ptr(), contents.len() as u32, &mut written, 0) };
        close(handle);
    }
}

fn final_path(name: &str, handle: usize, flags: u32, capacity: u32) {
    let get = api!(name, "GetFinalPathNameByHandleW", GetFinalPathNameByHandleWFn);
    let mut full = [0u16; 1024];
    let full_length = unsafe { get(handle, full.as_mut_ptr(), 1024, flags) };
    let mut output = [0u16; 1024];
    clear_error();
    let length = unsafe { get(handle, output.as_mut_ptr(), capacity, flags) };
    case(name);
    if length == 0 {
        out_str("fail");
        out_error();
    } else if length >= capacity {
        let actual = if full_length == 0 { 0 } else { wide_len(&full) };
        out_len_relation("needs", length, actual);
    } else {
        out_len_relation("len", length, wide_len(&output));
        out_str(" path=");
        out_path(&output);
    }
    out_byte(b'\n');
}

/// List what `FindFirstFileW`/`FindNextFileW` return, in their order.
fn find(name: &str, template: &str) {
    let first = api!(name, "FindFirstFileW", FindFirstFileWFn);
    let next = api!(name, "FindNextFileW", FindNextFileWFn);
    let close = api!(name, "FindClose", FindCloseFn);
    let mut buffer = [0u16; 1024];
    let pattern = input(template, &mut buffer);
    let mut data = [0u8; 592];
    clear_error();
    let search = unsafe { first(pattern.as_ptr(), data.as_mut_ptr()) };
    case(name);
    if search == INVALID_HANDLE {
        out_str("INVALID");
        out_error();
        out_byte(b'\n');
        return;
    }
    let mut count = 0;
    loop {
        let attributes = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let size = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let mut entry = [0u16; 260];
        for (index, unit) in entry.iter_mut().enumerate() {
            *unit = u16::from_le_bytes([data[44 + index * 2], data[45 + index * 2]]);
        }
        if count > 0 {
            out_str(", ");
        }
        out_wide_quoted(&entry[..wide_len(&entry)]);
        if attributes & 0x10 != 0 {
            out_str("/");
        } else {
            out_str(":");
            out_dec(size as u64);
        }
        count += 1;
        clear_error();
        if unsafe { next(search, data.as_mut_ptr()) } == 0 {
            out_str(" end");
            out_error();
            break;
        }
    }
    unsafe { close(search) };
    out_byte(b'\n');
}

fn long_path(name: &str, template: &str) {
    let get = api!(name, "GetLongPathNameW", GetLongPathNameWFn);
    let mut buffer = [0u16; 1024];
    let path = input(template, &mut buffer);
    let mut output = [0u16; 1024];
    clear_error();
    let length = unsafe { get(path.as_ptr(), output.as_mut_ptr(), 1024) };
    case(name);
    if length == 0 {
        out_str("fail");
        out_error();
    } else {
        out_str("path=");
        out_path(&output);
    }
    out_byte(b'\n');
}

fn simple_1(name: &str, api_name: &[u8], template: &str) {
    let address = kernel32(api_name);
    if address == 0 {
        unavailable(name);
        return;
    }
    let call: DeleteFileWFn = unsafe { core::mem::transmute(address) };
    let mut buffer = [0u16; 1024];
    let path = input(template, &mut buffer);
    clear_error();
    let result = unsafe { call(path.as_ptr()) };
    ok_or_error(name, result);
}

fn mkdir(name: &str, template: &str) {
    let create = api!(name, "CreateDirectoryW", CreateDirectoryWFn);
    let mut buffer = [0u16; 1024];
    let path = input(template, &mut buffer);
    clear_error();
    let result = unsafe { create(path.as_ptr(), 0) };
    ok_or_error(name, result);
}

fn move_file(name: &str, from: &str, to: &str, flags: u32) {
    let rename = api!(name, "MoveFileExW", MoveFileExWFn);
    let (mut a, mut b) = ([0u16; 1024], [0u16; 1024]);
    let from = input(from, &mut a);
    let to = input(to, &mut b);
    clear_error();
    let result = unsafe { rename(from.as_ptr(), to.as_ptr(), flags) };
    ok_or_error(name, result);
}

fn copy_file(name: &str, from: &str, to: &str, fail_if_exists: i32) {
    let copy = api!(name, "CopyFileW", CopyFileWFn);
    let (mut a, mut b) = ([0u16; 1024], [0u16; 1024]);
    let from = input(from, &mut a);
    let to = input(to, &mut b);
    clear_error();
    let result = unsafe { copy(from.as_ptr(), to.as_ptr(), fail_if_exists) };
    ok_or_error(name, result);
}

fn file_size(name: &str, template: &str) {
    let size = api!(name, "GetFileSizeEx", GetFileSizeExFn);
    let handle = open("size.open", template, GENERIC_READ, OPEN_EXISTING, 0);
    if handle == INVALID_HANDLE {
        return;
    }
    let mut value = 0i64;
    clear_error();
    let result = unsafe { size(handle, &mut value) };
    case(name);
    if result == 0 {
        out_str("fail");
        out_error();
    } else {
        out_dec(value as u64);
    }
    out_byte(b'\n');
    close(handle);
}

