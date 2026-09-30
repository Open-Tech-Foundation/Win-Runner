//! Windows-oracle probe: path resolution and file-system semantics.
//!
//! Prints what kernel32 does for path normalization (separators, `.`/`..`,
//! trailing dots and spaces, drive- and root-relative forms, device names,
//! `\\?\`), opening files and directories, final-path queries, directory
//! listings, and the error codes of common failures. Works inside
//! `<W>` = `<current directory>\oracle-fs`, which it creates and removes.

#![no_std]
#![no_main]

include!("common.rs");

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

/// An input path: ASCII, with `{W}` standing for the work directory and
/// `{D}` for its drive letter.
fn input<'a>(template: &str, buffer: &'a mut [u16; 1024]) -> &'a [u16] {
    let (work, work_len) = unsafe { (&*core::ptr::addr_of!(WORK), WORK_LEN) };
    let bytes = template.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"{W}") {
            buffer[n..n + work_len].copy_from_slice(&work[..work_len]);
            n += work_len;
            i += 3;
        } else if bytes[i..].starts_with(b"{D}") {
            buffer[n] = work[0];
            n += 1;
            i += 3;
        } else {
            buffer[n] = bytes[i] as u16;
            n += 1;
            i += 1;
        }
    }
    buffer[n] = 0;
    &buffer[..=n]
}

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
        out_str("len=");
        out_dec(length as u64);
        out_str(" path=");
        out_path(&output);
        out_str(" file=");
        if file_part.is_null() {
            out_str("null");
        } else {
            out_dec(((file_part as usize - output.as_ptr() as usize) / 2) as u64);
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
    let mut output = [0u16; 1024];
    clear_error();
    let length = unsafe { get(handle, output.as_mut_ptr(), capacity, flags) };
    case(name);
    if length == 0 {
        out_str("fail");
        out_error();
    } else if length >= capacity {
        out_str("needs=");
        out_dec(length as u64);
    } else {
        out_str("len=");
        out_dec(length as u64);
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

fn run() {
    let get_cwd = api!("setup.cwd", "GetCurrentDirectoryW", GetCurrentDirectoryWFn);
    let set_cwd = api!("setup.chdir", "SetCurrentDirectoryW", SetCurrentDirectoryWFn);
    let mut base = [0u16; 520];
    let base_len = unsafe { get_cwd(520, base.as_mut_ptr()) } as usize;
    if base_len == 0 || base_len > 480 {
        out_str("setup: no current directory\n");
        return;
    }
    // <W> = <base>\oracle-fs (without a doubled separator at a drive root).
    let mut work = [0u16; 520];
    work[..base_len].copy_from_slice(&base[..base_len]);
    let mut work_len = base_len;
    if work[work_len - 1] != 0x5c {
        work[work_len] = 0x5c;
        work_len += 1;
    }
    for byte in b"oracle-fs" {
        work[work_len] = *byte as u16;
        work_len += 1;
    }
    set_work_dir(&work[..work_len]);
    set_base_dir(&base[..base_len]);

    // ---- setup ----
    mkdir("setup.mkdir", "{W}");
    let mut buffer = [0u16; 1024];
    let work_path = input("{W}", &mut buffer);
    clear_error();
    ok_or_error("setup.chdir", unsafe { set_cwd(work_path.as_ptr()) });
    write_file("setup.one", "One.txt", b"hello");
    mkdir("setup.subdir", "Sub Dir");
    write_file("setup.two", "Sub Dir\\two.txt", b"22");

    // ---- GetFullPathNameW ----
    full_path("full.plain", "One.txt");
    full_path("full.case", "one.TXT");
    full_path("full.dot", ".\\One.txt");
    full_path("full.dotdot", "Sub Dir\\..\\One.txt");
    full_path("full.slash", "Sub Dir/two.txt");
    full_path("full.double_sep", "Sub Dir//two.txt");
    full_path("full.dot_in_middle", "Sub Dir\\.\\two.txt");
    full_path("full.trailing_dot", "One.txt.");
    full_path("full.trailing_dots_spaces", "One.txt. .");
    full_path("full.trailing_spaces", "One.txt  ");
    full_path("full.three_dots", "a\\...\\b");
    full_path("full.root_relative", "\\One.txt");
    full_path("full.drive_relative", "{D}:One.txt");
    full_path("full.drive_forward", "{D}:/x/../One.txt");
    full_path("full.parent", "..");
    full_path("full.current", ".");
    full_path("full.trailing_sep", "Sub Dir\\");
    full_path("full.above_root", "{D}:\\..\\..\\x");
    full_path("full.stream", "One.txt:alt");
    full_path("full.verbatim", "\\\\?\\{W}\\One.txt/x/..");
    full_path("full.device_nul", "nul");
    full_path("full.device_nul_ext", "NUL.txt");
    full_path("full.device_con", "con");
    full_path("full.device_com1", "com1.log");
    full_path("full.device_path", "\\\\.\\nul");
    full_path("full.unc", "\\\\server\\share\\a\\..\\b");
    full_path("full.empty", "");
    {
        let get = api!("full.small_buffer", "GetFullPathNameW", GetFullPathNameWFn);
        let mut buffer = [0u16; 1024];
        let path = input("One.txt", &mut buffer);
        let mut output = [0u16; 4];
        clear_error();
        let needed = unsafe { get(path.as_ptr(), 4, output.as_mut_ptr(), core::ptr::null_mut()) };
        case("full.small_buffer");
        out_str("needs=");
        out_dec(needed as u64);
        out_byte(b'\n');
    }

    // ---- GetFileAttributesW ----
    attributes("attr.file", "One.txt");
    attributes("attr.case", "ONE.TXT");
    attributes("attr.dir", "Sub Dir");
    attributes("attr.dir_trailing_sep", "Sub Dir\\");
    attributes("attr.file_trailing_sep", "One.txt\\");
    attributes("attr.trailing_dot", "One.txt.");
    attributes("attr.slash", "Sub Dir/two.txt");
    attributes("attr.missing", "missing");
    attributes("attr.missing_parent", "missing\\x");
    attributes("attr.through_file", "One.txt\\x");
    attributes("attr.empty", "");

    // ---- CreateFileW ----
    open_and_close("open.plain", "One.txt", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.trailing_dot", "one.txt.", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.missing", "missing.txt", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.missing_parent", "missing\\x.txt", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.through_file", "One.txt\\x", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.dir_plain", "Sub Dir", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.dir_backup", "Sub Dir", GENERIC_READ, OPEN_EXISTING, BACKUP_SEMANTICS);
    open_and_close("open.file_trailing_sep", "One.txt\\", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.invalid_lt", "a<b", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.invalid_star", "a*b", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.invalid_quote", "a\"b", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.device_nul", "nul", GENERIC_READ, OPEN_EXISTING, 0);
    open_and_close("open.create_new_existing", "One.txt", GENERIC_WRITE, CREATE_NEW, 0);
    open_and_close("open.create_always_dir", "Sub Dir", GENERIC_WRITE, CREATE_ALWAYS, 0);
    open_and_close("open.dotdot", "Sub Dir\\two.txt\\..\\two.txt", GENERIC_READ, OPEN_EXISTING, 0);

    // ---- GetFinalPathNameByHandleW ----
    let handle = open("final.open", "sub dir/TWO.txt", GENERIC_READ, OPEN_EXISTING, 0);
    if handle != INVALID_HANDLE {
        final_path("final.normalized", handle, 0, 1024);
        final_path("final.opened_name", handle, 0x8, 1024);
        final_path("final.volume_none", handle, 0x4, 1024);
        final_path("final.small_buffer", handle, 0, 4);
        close(handle);
    }
    let handle = open("final.dir_open", "Sub Dir\\", GENERIC_READ, OPEN_EXISTING, BACKUP_SEMANTICS);
    if handle != INVALID_HANDLE {
        final_path("final.dir", handle, 0, 1024);
        close(handle);
    }

    // ---- FindFirstFileW ----
    find("find.all", "*");
    find("find.ext_upper", "*.TXT");
    find("find.prefix", "Sub*");
    find("find.in_subdir", "sub dir\\*");
    find("find.exact", "one.txt");
    find("find.dir_itself", "Sub Dir");
    find("find.question", "O?e.txt");
    find("find.nomatch", "nomatch*");
    find("find.missing_dir", "missing\\*");

    // ---- other queries ----
    long_path("long.case", "sub dir\\TWO.TXT");
    long_path("long.missing", "missing");
    file_size("size.one", "One.txt");

    // ---- operations and their failures ----
    move_file("move.case_only", "One.txt", "one.txt", 0);
    find("move.case_only.listing", "one*");
    copy_file("copy.fail_if_exists", "one.txt", "Sub Dir\\two.txt", 1);
    copy_file("copy.overwrite", "one.txt", "Sub Dir\\copy.txt", 0);
    move_file("move.onto_existing", "one.txt", "Sub Dir\\two.txt", 0);
    move_file("move.replace_existing", "one.txt", "Sub Dir\\two.txt", 1);
    move_file("move.missing", "missing.txt", "x.txt", 0);
    mkdir("mkdir.existing", "Sub Dir");
    mkdir("mkdir.missing_parent", "a\\b");
    simple_1("delete.dir", b"DeleteFileW\0", "Sub Dir");
    simple_1("delete.missing", b"DeleteFileW\0", "missing.txt");
    simple_1("rmdir.nonempty", b"RemoveDirectoryW\0", "Sub Dir");
    simple_1("rmdir.file", b"RemoveDirectoryW\0", "Sub Dir\\two.txt");
    simple_1("chdir.file", b"SetCurrentDirectoryW\0", "Sub Dir\\two.txt");
    simple_1("chdir.missing", b"SetCurrentDirectoryW\0", "missing");
    find("after_ops.listing", "sub dir\\*");

    // ---- cleanup ----
    simple_1("cleanup.two", b"DeleteFileW\0", "Sub Dir\\two.txt");
    simple_1("cleanup.copy", b"DeleteFileW\0", "Sub Dir\\copy.txt");
    simple_1("cleanup.subdir", b"RemoveDirectoryW\0", "Sub Dir");
    base[base_len] = 0;
    clear_error();
    ok_or_error("cleanup.chdir", unsafe { set_cwd(base.as_ptr()) });
    simple_1("cleanup.work", b"RemoveDirectoryW\0", "{W}");
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe fs_paths\n");
    run();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
