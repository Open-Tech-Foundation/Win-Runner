//! Windows-oracle probe: symbolic links. `CreateSymbolicLinkW` for a file
//! and a directory, which file a handle names with and without
//! `FILE_FLAG_OPEN_REPARSE_POINT` (`GetFinalPathNameByHandleW`), and the
//! `REPARSE_DATA_BUFFER` that `DeviceIoControl(FSCTL_GET_REPARSE_POINT)`
//! returns, which libuv's `readlink` and `realpath` read. Works inside
//! `<W>` = `<current directory>\oracle-links`.

#![no_std]
#![no_main]
#![allow(dead_code)] // shared helpers a probe does not use

include!("common.rs");
include!("fs_support.rs");

type CreateSymbolicLinkWFn = unsafe extern "system" fn(*const u16, *const u16, u32) -> u8;
type DeviceIoControlFn =
    unsafe extern "system" fn(usize, u32, *const u8, u32, *mut u8, u32, *mut u32, usize) -> i32;

const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00a8;
const SYMBOLIC_LINK_FLAG_DIRECTORY: u32 = 0x1;
const SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE: u32 = 0x2;

fn symlink(name: &str, link: &str, target: &str, flags: u32) {
    let create = api!(name, "CreateSymbolicLinkW", CreateSymbolicLinkWFn);
    let mut link_buffer = [0u16; 1024];
    let mut target_buffer = [0u16; 1024];
    let link = input(link, &mut link_buffer);
    let target = input(target, &mut target_buffer);
    clear_error();
    let created = unsafe {
        create(link.as_ptr(), target.as_ptr(), flags | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)
    };
    ok_or_error(name, created as i32);
}

fn u16_at(data: &[u8], at: usize) -> usize {
    u16::from_le_bytes([data[at], data[at + 1]]) as usize
}

/// Print the UTF-16 name at `offset`/`length` (bytes) of a symlink reparse
/// buffer's path area, which starts at byte 20.
fn out_reparse_name(label: &str, data: &[u8], offset: usize, length: usize) {
    out_str(label);
    out_byte(b'=');
    let mut name = [0u16; 512];
    let count = (length / 2).min(511);
    for (index, slot) in name.iter_mut().take(count).enumerate() {
        *slot = u16_at(data, 20 + offset + index * 2) as u16;
    }
    // An NT path prints its `\??\` prefix, then the path in probe form.
    let nt = count >= 4 && name[..4] == [0x5c, 0x3f, 0x3f, 0x5c];
    if nt {
        out_str("\\??\\");
    }
    out_path(&name[if nt { 4 } else { 0 }..count]);
}

/// `FSCTL_GET_REPARSE_POINT` with an output buffer of `capacity` bytes.
fn reparse(name: &str, handle: usize, capacity: u32) {
    let control = api!(name, "DeviceIoControl", DeviceIoControlFn);
    let mut data = [0u8; 2048];
    let mut returned = 0u32;
    clear_error();
    let ok = unsafe {
        control(
            handle,
            FSCTL_GET_REPARSE_POINT,
            core::ptr::null(),
            0,
            data.as_mut_ptr(),
            capacity,
            &mut returned,
            0,
        )
    };
    case(name);
    if ok == 0 {
        out_str("fail");
        out_error();
        out_byte(b'\n');
        return;
    }
    let total = 8 + u16_at(&data, 4);
    out_str("tag=");
    out_hex(u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64);
    out_len_relation(" returned", returned, total);
    out_str(" flags=");
    out_dec(u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as u64);
    out_byte(b' ');
    out_reparse_name("substitute", &data, u16_at(&data, 8), u16_at(&data, 10));
    out_byte(b' ');
    out_reparse_name("print", &data, u16_at(&data, 12), u16_at(&data, 14));
    out_byte(b'\n');
}

/// Whether `template` carries FILE_ATTRIBUTE_REPARSE_POINT.
fn reparse_attribute(name: &str, template: &str) {
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
        out_str(if value & 0x400 != 0 { "reparse" } else { "plain" });
    }
    out_byte(b'\n');
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
    let mut work = [0u16; 520];
    work[..base_len].copy_from_slice(&base[..base_len]);
    let mut work_len = base_len;
    if work[work_len - 1] != 0x5c {
        work[work_len] = 0x5c;
        work_len += 1;
    }
    for byte in b"oracle-links" {
        work[work_len] = *byte as u16;
        work_len += 1;
    }
    set_work_dir(&work[..work_len]);
    set_base_dir(&base[..base_len]);

    mkdir("setup.mkdir", "{W}");
    let mut buffer = [0u16; 1024];
    let work_path = input("{W}", &mut buffer);
    clear_error();
    ok_or_error("setup.chdir", unsafe { set_cwd(work_path.as_ptr()) });
    mkdir("setup.target_dir", "Target");
    write_file("setup.target_file", "file.txt", b"hello");

    symlink("link.dir", "{W}\\dirlink", "{W}\\Target", SYMBOLIC_LINK_FLAG_DIRECTORY);
    symlink("link.file", "{W}\\filelink.txt", "{W}\\file.txt", 0);
    attributes("attr.dirlink", "dirlink");
    attributes("attr.filelink", "filelink.txt");
    reparse_attribute("attr.dirlink_reparse", "dirlink");
    reparse_attribute("attr.filelink_reparse", "filelink.txt");
    reparse_attribute("attr.target_reparse", "file.txt");

    // Without FILE_FLAG_OPEN_REPARSE_POINT a handle names the link's target.
    let handle = open("open.dirlink", "dirlink", GENERIC_READ, OPEN_EXISTING, BACKUP_SEMANTICS);
    if handle != INVALID_HANDLE {
        final_path("final.dirlink", handle, 0, 1024);
        reparse("reparse.dirlink_followed", handle, 2048);
        close(handle);
    }
    let handle = open("open.filelink", "filelink.txt", GENERIC_READ, OPEN_EXISTING, 0);
    if handle != INVALID_HANDLE {
        final_path("final.filelink", handle, 0, 1024);
        close(handle);
    }
    file_size("size.filelink", "filelink.txt");

    // With it, the handle is the link, whose reparse data holds the target.
    let handle = open(
        "open.dirlink_itself",
        "dirlink",
        GENERIC_READ,
        OPEN_EXISTING,
        BACKUP_SEMANTICS | OPEN_REPARSE_POINT,
    );
    if handle != INVALID_HANDLE {
        final_path("final.dirlink_itself", handle, 0, 1024);
        reparse("reparse.dirlink", handle, 2048);
        reparse("reparse.dirlink_small", handle, 16);
        reparse("reparse.dirlink_tiny", handle, 4);
        close(handle);
    }
    let handle = open(
        "open.filelink_itself",
        "filelink.txt",
        GENERIC_READ,
        OPEN_EXISTING,
        OPEN_REPARSE_POINT,
    );
    if handle != INVALID_HANDLE {
        reparse("reparse.filelink", handle, 2048);
        close(handle);
    }
    let handle = open("open.plain", "file.txt", GENERIC_READ, OPEN_EXISTING, OPEN_REPARSE_POINT);
    if handle != INVALID_HANDLE {
        reparse("reparse.plain_file", handle, 2048);
        close(handle);
    }

    simple_1("cleanup.dirlink", b"RemoveDirectoryW\0", "dirlink");
    simple_1("cleanup.filelink", b"DeleteFileW\0", "filelink.txt");
    attributes("cleanup.target_kept", "file.txt");
    simple_1("cleanup.target_file", b"DeleteFileW\0", "file.txt");
    simple_1("cleanup.target_dir", b"RemoveDirectoryW\0", "Target");
    base[base_len] = 0;
    clear_error();
    ok_or_error("cleanup.chdir", unsafe { set_cwd(base.as_ptr()) });
    simple_1("cleanup.work", b"RemoveDirectoryW\0", "{W}");
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe links\n");
    run();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
