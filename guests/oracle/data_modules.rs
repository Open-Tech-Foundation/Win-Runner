//! DLLs loaded as data (`LOAD_LIBRARY_AS_DATAFILE`, `_AS_IMAGE_RESOURCE`,
//! `_AS_DATAFILE_EXCLUSIVE`): handle tags, string tables through
//! `LoadStringW`, resource lookups, what module queries see of them, and
//! `FreeLibrary`. The probe writes its own small resource-only DLL, so the
//! strings it reads are known.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");

type Create = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
type Close = unsafe extern "system" fn(usize) -> i32;
type Cwd = unsafe extern "system" fn(u32, *mut u16) -> u32;
type LoadEx = unsafe extern "system" fn(*const u16, usize, u32) -> usize;
type Load = unsafe extern "system" fn(*const u16) -> usize;
type Free = unsafe extern "system" fn(usize) -> i32;
type LoadString = unsafe extern "system" fn(usize, u32, *mut u16, i32) -> i32;
type Find = unsafe extern "system" fn(usize, usize, usize) -> usize;
type Size = unsafe extern "system" fn(usize, usize) -> u32;
type LoadResource = unsafe extern "system" fn(usize, usize) -> usize;
type Lock = unsafe extern "system" fn(usize) -> *const u16;
type FileName = unsafe extern "system" fn(usize, *mut u16, u32) -> u32;
type Handle = unsafe extern "system" fn(*const u16) -> usize;

const IMAGE_SIZE: usize = 0x2000;
static mut IMAGE: [u8; 0x400] = [0; 0x400];

fn put16(at: usize, value: u16) {
    unsafe { (&mut *core::ptr::addr_of_mut!(IMAGE))[at..at + 2].copy_from_slice(&value.to_le_bytes()) };
}
fn put32(at: usize, value: u32) {
    unsafe { (&mut *core::ptr::addr_of_mut!(IMAGE))[at..at + 4].copy_from_slice(&value.to_le_bytes()) };
}
fn put64(at: usize, value: u64) {
    unsafe { (&mut *core::ptr::addr_of_mut!(IMAGE))[at..at + 8].copy_from_slice(&value.to_le_bytes()) };
}

/// Sixteen counted strings, ids `16 * (block - 1)` and on; `None` is empty.
fn put_block(mut at: usize, strings: &[Option<&str>; 16]) -> usize {
    for text in strings {
        let text = text.unwrap_or("");
        put16(at, text.len() as u16);
        at += 2;
        for byte in text.bytes() {
            put16(at, byte as u16);
            at += 2;
        }
    }
    at
}

/// A resource-only PE32+ DLL: one `.rsrc` section (RVA 0x1000, file offset
/// 0x200) with RT_STRING blocks 1 and 2, language 0x409.
fn build_image() -> usize {
    put16(0, 0x5a4d);
    put32(0x3c, 0x40);
    put32(0x40, 0x4550);
    put16(0x44, 0x8664); // machine
    put16(0x46, 1); // sections
    put16(0x54, 0xf0); // optional header size
    put16(0x56, 0x2022); // executable, large addresses, DLL
    let optional = 0x58;
    put16(optional, 0x20b);
    put64(optional + 24, 0x1_8000_0000); // image base
    put32(optional + 32, 0x1000); // section alignment
    put32(optional + 36, 0x200); // file alignment
    put16(optional + 40, 6);
    put16(optional + 48, 6);
    put32(optional + 56, IMAGE_SIZE as u32);
    put32(optional + 60, 0x200); // headers
    put16(optional + 68, 3); // console
    put64(optional + 72, 0x10_0000);
    put64(optional + 80, 0x1000);
    put64(optional + 88, 0x10_0000);
    put64(optional + 96, 0x1000);
    put32(optional + 108, 16);
    let section = optional + 0xf0;
    unsafe { (&mut *core::ptr::addr_of_mut!(IMAGE))[section..section + 5].copy_from_slice(b".rsrc") };
    put32(section + 12, 0x1000); // RVA
    put32(section + 16, 0x200); // raw size
    put32(section + 20, 0x200); // raw offset
    put32(section + 36, 0x4000_0040); // initialized data, readable

    // Directories: root (type 6) at 0, type (names 1, 2) at 0x18, the two
    // name directories at 0x38 and 0x50, data entries at 0x68 and 0x78.
    let rsrc = 0x200;
    let rva = 0x1000u32;
    put16(rsrc + 14, 1);
    put32(rsrc + 16, 6);
    put32(rsrc + 20, 0x8000_0018);
    put16(rsrc + 0x18 + 14, 2);
    put32(rsrc + 0x18 + 16, 1);
    put32(rsrc + 0x18 + 20, 0x8000_0038);
    put32(rsrc + 0x18 + 24, 2);
    put32(rsrc + 0x18 + 28, 0x8000_0050);
    for (directory, entry) in [(0x38, 0x68), (0x50, 0x78)] {
        put16(rsrc + directory + 14, 1);
        put32(rsrc + directory + 16, 0x409);
        put32(rsrc + directory + 20, entry);
    }
    let first = 0x88;
    let mut block1 = [None; 16];
    block1[1] = Some("one");
    block1[3] = Some("three words");
    block1[15] = Some("fifteen");
    let end1 = put_block(rsrc + first, &block1);
    let mut block2 = [None; 16];
    block2[0] = Some("sixteen");
    let second = end1 - rsrc;
    let end2 = put_block(end1, &block2);
    put32(rsrc + 0x68, rva + first as u32);
    put32(rsrc + 0x6c, (second - first) as u32);
    put32(rsrc + 0x78, rva + second as u32);
    put32(rsrc + 0x7c, (end2 - end1) as u32);
    put32(section + 8, (end2 - rsrc) as u32); // virtual size
    put32(optional + 112 + 16, rva); // resource directory
    put32(optional + 112 + 20, (end2 - rsrc) as u32);
    0x400
}

/// `<W>\<name>` as a NUL-terminated path.
fn path_in(cwd: Cwd, name: &str, buffer: &mut [u16; 600]) -> usize {
    let length = unsafe { cwd(500, buffer.as_mut_ptr()) } as usize;
    set_work_dir(&buffer[..length]);
    let mut at = length;
    buffer[at] = b'\\' as u16;
    at += 1;
    for byte in name.bytes() {
        buffer[at] = byte as u16;
        at += 1;
    }
    buffer[at] = 0;
    at
}

fn write_file(create: Create, close: Close, path: &[u16], bytes: &[u8]) -> bool {
    unsafe {
        let file = create(path.as_ptr(), 0x4000_0000, 0, 0, 2, 0x80, 0);
        if file == usize::MAX {
            return false;
        }
        let mut written = 0;
        let ok = WriteFile(file, bytes.as_ptr(), bytes.len() as u32, &mut written, 0) != 0;
        close(file);
        ok && written as usize == bytes.len()
    }
}

/// `<case>: ret=<n> text="<…>"` (or ` err=<n>` when 0).
fn string_case(name: &str, load_string: LoadString, module: usize, id: u32, size: i32) {
    let mut buffer = [0x2au16; 64];
    clear_error();
    let result = unsafe { load_string(module, id, buffer.as_mut_ptr(), size) };
    case(name);
    out_str("ret=");
    out_dec(result as u64);
    if result == 0 {
        out_error();
        out_str(" first=");
        out_hex(buffer[0] as u64);
    } else {
        out_str(" text=");
        out_wide_quoted(&buffer[..wide_len(&buffer)]);
    }
    out_byte(b'\n');
}

/// `<case>: tag=<handle & 3>` or `fail err=<n>`.
fn load_case(name: &str, load: LoadEx, path: &[u16], flags: u32) -> usize {
    clear_error();
    let module = unsafe { load(path.as_ptr(), 0, flags) };
    case(name);
    if module == 0 {
        out_str("fail");
        out_error();
    } else {
        out_str("tag=");
        out_dec((module & 3) as u64);
    }
    out_byte(b'\n');
    module
}

fn probe() {
    let create = api!("setup.create", "CreateFileW", Create);
    let close = api!("setup.close", "CloseHandle", Close);
    let cwd = api!("setup.cwd", "GetCurrentDirectoryW", Cwd);
    let load_ex = api!("setup.load_ex", "LoadLibraryExW", LoadEx);
    let load = api!("setup.load", "LoadLibraryW", Load);
    let free = api!("setup.free", "FreeLibrary", Free);
    let find = api!("setup.find", "FindResourceW", Find);
    let size = api!("setup.size", "SizeofResource", Size);
    let load_resource = api!("setup.load_resource", "LoadResource", LoadResource);
    let lock = api!("setup.lock", "LockResource", Lock);
    let file_name = api!("setup.file_name", "GetModuleFileNameW", FileName);
    let handle = api!("setup.handle", "GetModuleHandleW", Handle);
    let mut name = [0u16; 16];
    let user32 = unsafe { load(wide("user32.dll", &mut name).as_ptr()) };
    let load_string = unsafe { GetProcAddress(user32, b"LoadStringW\0".as_ptr()) };
    if load_string == 0 {
        unavailable("setup.load_string");
        return;
    }
    let load_string: LoadString = unsafe { core::mem::transmute(load_string) };

    let mut path = [0u16; 600];
    path_in(cwd, "res.dll", &mut path);
    let length = build_image();
    let image = unsafe { &(&*core::ptr::addr_of!(IMAGE))[..length] };
    case("setup.write");
    out_str(if write_file(create, close, &path, image) { "ok\n" } else { "fail\n" });

    let module = load_case("datafile.load", load_ex, &path, 0x2);
    if module == 0 {
        out_str("END\n");
        return;
    }
    string_case("string.one", load_string, module, 1, 64);
    string_case("string.empty", load_string, module, 2, 64);
    string_case("string.truncated", load_string, module, 3, 4);
    string_case("string.size_one", load_string, module, 3, 1);
    string_case("string.last_in_block", load_string, module, 15, 64);
    string_case("string.second_block", load_string, module, 16, 64);
    string_case("string.empty_in_second_block", load_string, module, 17, 64);
    string_case("string.missing_block", load_string, module, 40, 64);
    string_case("string.id_zero", load_string, module, 0, 64);

    // Size 0: a read-only pointer to the string, not terminated.
    let mut pointer = [0u16; 4];
    clear_error();
    let result = unsafe { load_string(module, 3, pointer.as_mut_ptr(), 0) };
    case("string.pointer");
    out_str("ret=");
    out_dec(result as u64);
    let text = unsafe { (pointer.as_ptr() as *const usize).read_unaligned() };
    let base = module & !3;
    if result > 0 && text != 0 {
        out_str(if text >= base && text < base + IMAGE_SIZE { " in_module" } else { " outside" });
        out_str(" text=");
        out_wide_quoted(unsafe { core::slice::from_raw_parts(text as *const u16, result as usize) });
    } else {
        out_error();
    }
    out_byte(b'\n');

    clear_error();
    let found = unsafe { find(module, 1, 6) };
    case("resource.find");
    if found == 0 {
        out_str("fail");
        out_error();
    } else {
        out_str("size=");
        out_dec(unsafe { size(module, found) } as u64);
        let data = unsafe { lock(load_resource(module, found)) };
        out_str(" first_counts=");
        if data.is_null() {
            out_str("null");
        } else {
            unsafe {
                out_dec(*data as u64);
                out_byte(b',');
                out_dec(*data.add(1) as u64);
            }
        }
    }
    out_byte(b'\n');
    clear_error();
    let missing = unsafe { find(module, 9, 6) };
    case("resource.find_missing");
    out_dec(missing as u64);
    out_error();
    out_byte(b'\n');

    clear_error();
    let address = unsafe { GetProcAddress(module, b"Anything\0".as_ptr()) };
    case("module.proc_address");
    out_dec(address as u64);
    out_error();
    out_byte(b'\n');
    clear_error();
    let listed = unsafe { handle(path.as_ptr()) };
    case("module.handle_by_path");
    out_str(if listed == 0 { "none" } else if listed == module { "same" } else { "other" });
    out_error();
    out_byte(b'\n');
    let mut filename = [0u16; 600];
    clear_error();
    let written = unsafe { file_name(module, filename.as_mut_ptr(), 600) };
    case("module.file_name");
    if written == 0 {
        out_str("fail");
        out_error();
    } else {
        out_path(&filename[..written as usize]);
    }
    out_byte(b'\n');

    let second = load_case("datafile.second_load", load_ex, &path, 0x2);
    case("datafile.second_same");
    out_str(if second == module { "same\n" } else { "distinct\n" });
    if second != 0 && second != module {
        unsafe { free(second) };
    }
    let resource = load_case("image_resource.load", load_ex, &path, 0x20);
    if resource != 0 {
        string_case("image_resource.string", load_string, resource, 1, 64);
        case("image_resource.free");
        out_dec(unsafe { free(resource) } as u64);
        out_byte(b'\n');
    }
    let both = load_case("datafile_and_image_resource.load", load_ex, &path, 0x22);
    if both != 0 {
        unsafe { free(both) };
    }
    let exclusive = load_case("exclusive.load", load_ex, &path, 0x40);
    if exclusive != 0 {
        string_case("exclusive.string", load_string, exclusive, 15, 64);
        unsafe { free(exclusive) };
    }

    clear_error();
    case("datafile.free");
    out_dec(unsafe { free(module) } as u64);
    out_error();
    out_byte(b'\n');

    let mut missing_path = [0u16; 600];
    path_in(cwd, "missing.dll", &mut missing_path);
    load_case("datafile.missing", load_ex, &missing_path, 0x2);
    let mut text_path = [0u16; 600];
    path_in(cwd, "text.dll", &mut text_path);
    write_file(create, close, &text_path, b"not a module\r\n");
    load_case("datafile.not_pe", load_ex, &text_path, 0x2);

    // The probe itself has no resources.
    string_case("string.no_resources", load_string, unsafe { GetModuleHandleW(core::ptr::null()) }, 1, 64);
    out_str("END\n");
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe data_modules\n");
    probe();
    flush();
    unsafe { ExitProcess(0) }
}
