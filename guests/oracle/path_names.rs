//! Windows-oracle probe: how path spellings come back from the APIs that
//! return names: `GetLongPathNameW` with relative, forward-slash, `..`, and
//! lowercase-drive inputs, and the drive-letter case `GetFullPathNameW` and
//! `GetFinalPathNameByHandleW` report. Works inside
//! `<W>` = `<current directory>\oracle-names`.

#![no_std]
#![no_main]
#![allow(dead_code)] // shared helpers a probe does not use

include!("common.rs");
include!("fs_support.rs");

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
    for byte in b"oracle-names" {
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
    write_file("setup.one", "One.txt", b"hello");
    mkdir("setup.subdir", "Sub Dir");
    write_file("setup.two", "Sub Dir\\two.txt", b"22");

    long_path("long.relative", "sub dir\\TWO.TXT");
    long_path("long.forward", "sub dir/TWO.TXT");
    long_path("long.dotdot", "sub dir\\..\\one.txt");
    long_path("long.dot", ".");
    long_path("long.trailing_sep", "sub dir\\");
    long_path("long.absolute", "{W}\\SUB DIR\\two.txt");
    long_path("long.lower_drive", "{d}:{w}\\sub dir\\two.txt");
    long_path("long.missing", "missing");
    long_path("long.missing_parent", "missing\\x");
    long_path("long.through_file", "one.txt\\x");

    full_path("full.lower_drive", "{d}:{w}\\One.txt");
    full_path("full.lower_drive_relative", "{d}:One.txt");

    let handle = open("final.lower_drive_open", "{d}:{w}\\one.TXT", GENERIC_READ, OPEN_EXISTING, 0);
    if handle != INVALID_HANDLE {
        final_path("final.lower_drive", handle, 0, 1024);
        close(handle);
    }

    simple_1("cleanup.two", b"DeleteFileW\0", "Sub Dir\\two.txt");
    simple_1("cleanup.subdir", b"RemoveDirectoryW\0", "Sub Dir");
    simple_1("cleanup.one", b"DeleteFileW\0", "One.txt");
    base[base_len] = 0;
    clear_error();
    ok_or_error("cleanup.chdir", unsafe { set_cwd(base.as_ptr()) });
    simple_1("cleanup.work", b"RemoveDirectoryW\0", "{W}");
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe path_names\n");
    run();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
