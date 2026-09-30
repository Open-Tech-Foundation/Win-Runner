//! Windows-oracle probe: path resolution and file-system semantics.
//!
//! Prints what kernel32 does for path normalization (separators, `.`/`..`,
//! trailing dots and spaces, drive- and root-relative forms, device names,
//! `\\?\`), opening files and directories, final-path queries, directory
//! listings, and the error codes of common failures. Works inside
//! `<W>` = `<current directory>\oracle-fs`, which it creates and removes.

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
        let mut full = [0u16; 1024];
        unsafe { get(path.as_ptr(), 1024, full.as_mut_ptr(), core::ptr::null_mut()) };
        let mut output = [0u16; 4];
        clear_error();
        let needed = unsafe { get(path.as_ptr(), 4, output.as_mut_ptr(), core::ptr::null_mut()) };
        case("full.small_buffer");
        out_len_relation("needs", needed, wide_len(&full));
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
