//! A process's own module list through PSAPI's kernel32 exports
//! (`K32EnumProcessModules(Ex)`, `K32GetModuleBaseNameW`,
//! `K32GetModuleFileNameExW`, `K32GetModuleInformation`),
//! `QueryFullProcessImageNameW`, and `OpenProcess` on itself and on ids
//! that name no process.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");

type Current = unsafe extern "system" fn() -> usize;
type Id = unsafe extern "system" fn() -> u32;
type Open = unsafe extern "system" fn(u32, i32, u32) -> usize;
type Close = unsafe extern "system" fn(usize) -> i32;
type Enum = unsafe extern "system" fn(usize, *mut usize, u32, *mut u32) -> i32;
type EnumEx = unsafe extern "system" fn(usize, *mut usize, u32, *mut u32, u32) -> i32;
type BaseName = unsafe extern "system" fn(usize, usize, *mut u16, u32) -> u32;
type Info = unsafe extern "system" fn(usize, usize, *mut usize, u32) -> i32;
type ImageName = unsafe extern "system" fn(usize, u32, *mut u16, *mut u32) -> i32;
type ModuleFileName = unsafe extern "system" fn(usize, *mut u16, u32) -> u32;
type Load = unsafe extern "system" fn(*const u16) -> usize;

fn fail_line() {
    out_str("fail");
    out_error();
    out_byte(b'\n');
}

fn text_case(name: &str, written: u32, buffer: &[u16]) {
    case(name);
    if written == 0 {
        fail_line();
        return;
    }
    out_str("ret=ok ");
    out_wide_quoted(&buffer[..written as usize]);
    out_byte(b'\n');
}

fn probe() {
    let current = api!("setup.current", "GetCurrentProcess", Current);
    let pid = api!("setup.pid", "GetCurrentProcessId", Id);
    let open = api!("setup.open", "OpenProcess", Open);
    let close = api!("setup.close", "CloseHandle", Close);
    let enumerate = api!("setup.enum", "K32EnumProcessModules", Enum);
    let enumerate_ex = api!("setup.enum_ex", "K32EnumProcessModulesEx", EnumEx);
    let base_name = api!("setup.base_name", "K32GetModuleBaseNameW", BaseName);
    let file_name_ex = api!("setup.file_name_ex", "K32GetModuleFileNameExW", BaseName);
    let information = api!("setup.info", "K32GetModuleInformation", Info);
    let image_name = api!("setup.image_name", "QueryFullProcessImageNameW", ImageName);
    let module_file_name = api!("setup.module_file_name", "GetModuleFileNameW", ModuleFileName);
    let load = api!("setup.load", "LoadLibraryW", Load);
    let image = unsafe { GetModuleHandleW(core::ptr::null()) };
    let mut name = [0u16; 32];
    let kernel = unsafe { GetModuleHandleW(wide("kernel32.dll", &mut name).as_ptr()) };
    unsafe { load(wide("user32.dll", &mut name).as_ptr()) };
    let mut own_path = [0u16; 600];
    let own_length = unsafe { module_file_name(0, own_path.as_mut_ptr(), 600) } as usize;
    // Paths differ between machines, so they are compared with the
    // module's own GetModuleFileNameW path rather than printed.
    let own = &own_path[..own_length];

    unsafe {
        let me = current();
        let mut modules = [0usize; 256];
        let mut needed = 0u32;
        clear_error();
        let ok = enumerate(me, modules.as_mut_ptr(), (modules.len() * 8) as u32, &mut needed);
        case("enum.pseudo");
        if ok == 0 {
            fail_line();
        } else {
            let count = needed as usize / 8;
            out_str(if modules[0] == image { "first=image" } else { "first=other" });
            out_str(if modules[..count].contains(&kernel) { " kernel32=listed" } else { " kernel32=missing" });
            out_str(if needed % 8 == 0 { " needed=multiple\n" } else { " needed=odd\n" });
        }
        let mut small = [0usize; 1];
        let mut small_needed = 0u32;
        clear_error();
        let ok = enumerate(me, small.as_mut_ptr(), 8, &mut small_needed);
        case("enum.one_slot");
        if ok == 0 {
            fail_line();
        } else {
            out_str(if small[0] == image { "first=image" } else { "first=other" });
            out_str(if small_needed == needed { " needed=full\n" } else { " needed=differs\n" });
        }
        clear_error();
        let ok = enumerate(me, core::ptr::null_mut(), 0, &mut small_needed);
        case("enum.size_query");
        if ok == 0 { fail_line() } else { out_str(if small_needed == needed { "needed=full\n" } else { "needed=differs\n" }) }
        clear_error();
        let ok = enumerate_ex(me, modules.as_mut_ptr(), (modules.len() * 8) as u32, &mut small_needed, 0x3);
        case("enum_ex.all");
        if ok == 0 { fail_line() } else { out_str(if small_needed == needed { "same\n" } else { "differs\n" }) }

        let mut text = [0u16; 600];
        clear_error();
        text_case("base_name.main", base_name(me, 0, text.as_mut_ptr(), 600), &text);
        clear_error();
        text_case("base_name.image", base_name(me, image, text.as_mut_ptr(), 600), &text);
        clear_error();
        text_case("base_name.kernel32", base_name(me, kernel, text.as_mut_ptr(), 600), &text);
        clear_error();
        let written = base_name(me, image, text.as_mut_ptr(), 5);
        case("base_name.truncated");
        out_dec(written as u64);
        out_error();
        out_str(" text=");
        out_wide_quoted(&text[..wide_len(&text[..5])]);
        out_byte(b'\n');
        clear_error();
        let written = base_name(me, image + 0x10, text.as_mut_ptr(), 600);
        case("base_name.not_a_module");
        out_dec(written as u64);
        out_error();
        out_byte(b'\n');
        clear_error();
        let written = file_name_ex(me, 0, text.as_mut_ptr(), 600);
        case("file_name_ex.main");
        if written == 0 {
            fail_line();
        } else {
            out_str(if &text[..written as usize] == own { "same_as_module_file_name\n" } else { "differs\n" });
        }

        let mut info = [0usize; 3];
        clear_error();
        let ok = information(me, image, info.as_mut_ptr(), 24);
        case("info.image");
        if ok == 0 {
            fail_line();
        } else {
            let headers = image + *((image + 0x3c) as *const u32) as usize;
            let size = *((headers + 24 + 56) as *const u32) as usize;
            let entry = *((headers + 24 + 16) as *const u32) as usize;
            out_str(if info[0] == image { "base=ok" } else { "base=wrong" });
            out_str(if info[1] as u32 as usize == size { " size=ok" } else { " size=wrong" });
            out_str(if info[2] == image + entry { " entry=ok\n" } else { " entry=wrong\n" });
        }
        clear_error();
        let ok = information(me, image, info.as_mut_ptr(), 16);
        case("info.small");
        if ok == 0 { fail_line() } else { out_str("ok\n") }

        let mut size = 600u32;
        clear_error();
        let ok = image_name(me, 0, text.as_mut_ptr(), &mut size);
        case("image_name.win32");
        if ok == 0 {
            fail_line();
        } else {
            out_str(if &text[..size as usize] == own { "same_as_module_file_name" } else { "differs" });
            out_str(if text[size as usize] == 0 { " terminated\n" } else { " unterminated\n" });
        }
        let mut size = 600u32;
        clear_error();
        let ok = image_name(me, 1, text.as_mut_ptr(), &mut size);
        case("image_name.native");
        if ok == 0 {
            fail_line();
        } else {
            let prefix = [b'\\' as u16, b'D' as u16, b'e' as u16, b'v' as u16, b'i' as u16, b'c' as u16, b'e' as u16, b'\\' as u16];
            out_str(if text[..8] == prefix { "device_path\n" } else { "other\n" });
        }
        let mut size = 4u32;
        clear_error();
        let ok = image_name(me, 0, text.as_mut_ptr(), &mut size);
        case("image_name.small");
        out_dec(ok as u64);
        out_error();
        out_str(" size=");
        out_dec(size as u64);
        out_byte(b'\n');
        let mut size = 600u32;
        clear_error();
        let ok = image_name(me, 2, text.as_mut_ptr(), &mut size);
        case("image_name.bad_flags");
        out_dec(ok as u64);
        out_error();
        out_byte(b'\n');

        // OpenProcess on itself, with query rights.
        clear_error();
        let opened = open(0x400 | 0x10, 0, pid());
        case("open.self");
        if opened == 0 {
            fail_line();
        } else {
            out_str("ok\n");
            clear_error();
            text_case("open.self_base_name", base_name(opened, 0, text.as_mut_ptr(), 600), &text);
            let mut size = 600u32;
            clear_error();
            let ok = image_name(opened, 0, text.as_mut_ptr(), &mut size);
            case("open.self_image_name");
            if ok == 0 { fail_line() } else { out_str("ok\n") }
            close(opened);
        }
        // Limited query rights cover image names but not module lists.
        clear_error();
        let limited = open(0x1000, 0, pid());
        case("open.limited");
        if limited == 0 {
            fail_line();
        } else {
            out_str("ok\n");
            let mut size = 600u32;
            clear_error();
            let ok = image_name(limited, 0, text.as_mut_ptr(), &mut size);
            case("open.limited_image_name");
            if ok == 0 { fail_line() } else { out_str("ok\n") }
            clear_error();
            let ok = enumerate(limited, modules.as_mut_ptr(), (modules.len() * 8) as u32, &mut needed);
            case("open.limited_enum");
            if ok == 0 { fail_line() } else { out_str("ok\n") }
            close(limited);
        }
        clear_error();
        let none = open(0x1000, 0, 0xFFFF_FFF0);
        case("open.no_such_pid");
        out_dec(none as u64);
        out_error();
        out_byte(b'\n');
        clear_error();
        let idle = open(0x1000, 0, 0);
        case("open.pid_zero");
        out_dec(idle as u64);
        out_error();
        out_byte(b'\n');
    }
    out_str("END\n");
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe process_modules\n");
    probe();
    flush();
    unsafe { ExitProcess(0) }
}
