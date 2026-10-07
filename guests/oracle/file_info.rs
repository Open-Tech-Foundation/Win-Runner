//! Windows-oracle probe: what `CreateFileW` leaves in the last error for each
//! creation disposition (on new and existing files; the probe sets it to
//! 1234 first so "left unchanged" shows), and how `SetFileInformationByHandle`
//! changes a file's size through `FileAllocationInfo` and
//! `FileEndOfFileInfo`. Works on `oracle-fileinfo.tmp` in the current
//! directory.

#![no_std]
#![no_main]
#![allow(dead_code)] // shared helpers a probe does not use

include!("common.rs");

type CreateFileWFn = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
type SetInfoFn = unsafe extern "system" fn(usize, i32, *const u8, u32) -> i32;
type SizeFn = unsafe extern "system" fn(usize, *mut i64) -> i32;
type HandleFn = unsafe extern "system" fn(usize) -> i32;
type DeleteFn = unsafe extern "system" fn(*const u16) -> i32;

const GENERIC_READ_WRITE: u32 = 0xc000_0000;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;

struct Api {
    create: CreateFileWFn,
    set_error: SetLastErrorFn,
    set_info: SetInfoFn,
    size: SizeFn,
    close: HandleFn,
    delete: DeleteFn,
}

fn file_name(buffer: &mut [u16; 32]) -> &[u16] {
    wide("oracle-fileinfo.tmp", buffer)
}

/// Open with `disposition` after setting the last error to 1234, and print
/// what the call left there; returns the handle (or 0 on failure).
fn open(api: &Api, name: &str, disposition: u32) -> usize {
    let mut buffer = [0u16; 32];
    let path = file_name(&mut buffer);
    unsafe { (api.set_error)(1234) };
    let handle = unsafe { (api.create)(path.as_ptr(), GENERIC_READ_WRITE, 0, 0, disposition, 0x80, 0) };
    let error = last_error();
    case(name);
    out_str(if handle == usize::MAX { "failed" } else { "opened" });
    out_str(" err=");
    out_dec(error as u64);
    out_byte(b'\n');
    if handle == usize::MAX { 0 } else { handle }
}

fn delete(api: &Api) {
    let mut buffer = [0u16; 32];
    let path = file_name(&mut buffer);
    unsafe { (api.delete)(path.as_ptr()) };
}

fn close(api: &Api, handle: usize) {
    if handle != 0 {
        unsafe { (api.close)(handle) };
    }
}

/// A fresh 10-byte file, open for reading and writing.
fn ten_bytes(api: &Api) -> usize {
    delete(api);
    let mut buffer = [0u16; 32];
    let path = file_name(&mut buffer);
    let handle = unsafe { (api.create)(path.as_ptr(), GENERIC_READ_WRITE, 0, 0, CREATE_ALWAYS, 0x80, 0) };
    if handle == usize::MAX {
        return 0;
    }
    let mut written = 0;
    unsafe { WriteFile(handle, b"0123456789".as_ptr(), 10, &mut written, 0) };
    handle
}

/// Set an 8-byte information class and print the result and new size.
fn set_size(api: &Api, name: &str, handle: usize, class: i32, value: i64) {
    let bytes = value.to_le_bytes();
    clear_error();
    let result = unsafe { (api.set_info)(handle, class, bytes.as_ptr(), 8) };
    let error = last_error();
    let mut size = -1i64;
    unsafe { (api.size)(handle, &mut size) };
    case(name);
    out_str("ret=");
    out_dec(result as u64);
    if result == 0 {
        out_str(" err=");
        out_dec(error as u64);
    }
    out_str(" size=");
    out_dec(size as u64);
    out_byte(b'\n');
}

fn run() {
    let api = Api {
        create: api!("file.create_api", "CreateFileW", CreateFileWFn),
        set_error: api!("file.set_error_api", "SetLastError", SetLastErrorFn),
        set_info: api!("file.set_info_api", "SetFileInformationByHandle", SetInfoFn),
        size: api!("file.size_api", "GetFileSizeEx", SizeFn),
        close: api!("file.close_api", "CloseHandle", HandleFn),
        delete: api!("file.delete_api", "DeleteFileW", DeleteFn),
    };
    delete(&api);
    let dispositions = [
        ("create_always", CREATE_ALWAYS),
        ("open_always", OPEN_ALWAYS),
        ("create_new", CREATE_NEW),
    ];
    for (label, disposition) in dispositions {
        let mut name = [0u8; 48];
        let new = join(&mut name, "create.", label, ".new");
        close(&api, open(&api, new, disposition));
        let mut name = [0u8; 48];
        let existing = join(&mut name, "create.", label, ".existing");
        close(&api, open(&api, existing, disposition));
        delete(&api);
    }
    close(&api, open(&api, "create.open_existing.missing", OPEN_EXISTING));
    close(&api, ten_bytes(&api));
    close(&api, open(&api, "create.open_existing.existing", OPEN_EXISTING));
    close(&api, open(&api, "create.truncate_existing.existing", TRUNCATE_EXISTING));

    // FileAllocationInfo (5) and FileEndOfFileInfo (6) on a 10-byte file.
    for (name, class, value) in [
        ("info.allocation_zero", 5, 0i64),
        ("info.allocation_smaller", 5, 4),
        ("info.allocation_larger", 5, 4096),
        ("info.end_of_file_shrink", 6, 4),
        ("info.end_of_file_grow", 6, 12),
    ] {
        let handle = ten_bytes(&api);
        if handle == 0 {
            unavailable(name);
            continue;
        }
        set_size(&api, name, handle, class, value);
        close(&api, handle);
    }
    delete(&api);
}

/// `a` + `b` + `c` as a `&str` in `buffer`.
fn join<'a>(buffer: &'a mut [u8; 48], a: &str, b: &str, c: &str) -> &'a str {
    let mut length = 0;
    for part in [a, b, c] {
        for &byte in part.as_bytes() {
            buffer[length] = byte;
            length += 1;
        }
    }
    unsafe { core::str::from_utf8_unchecked(&buffer[..length]) }
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe file_info\n");
    run();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
