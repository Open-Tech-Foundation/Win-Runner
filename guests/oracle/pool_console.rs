//! Windows-oracle probe: the thread pool and console input APIs libuv uses
//! for terminals. `QueueUserWorkItem` runs its callback with the context;
//! `MapVirtualKeyW` maps keys and scan codes (libuv cancels a console line
//! read with an Enter key event built from it); the console input functions
//! reject a handle that is not a console. Works inside
//! `<W>` = `<current directory>\oracle-pool`.

#![no_std]
#![no_main]
#![allow(dead_code)] // shared helpers a probe does not use

include!("common.rs");
include!("fs_support.rs");

type QueueUserWorkItemFn = unsafe extern "system" fn(usize, usize, u32) -> i32;
type CreateEventWFn = unsafe extern "system" fn(usize, i32, i32, *const u16) -> usize;
type SetEventFn = unsafe extern "system" fn(usize) -> i32;
type WaitForSingleObjectFn = unsafe extern "system" fn(usize, u32) -> u32;
type LoadLibraryWFn = unsafe extern "system" fn(*const u16) -> usize;
type MapVirtualKeyWFn = unsafe extern "system" fn(u32, u32) -> u32;
type ReadConsoleWFn = unsafe extern "system" fn(usize, *mut u16, u32, *mut u32, usize) -> i32;
type ReadConsoleInputWFn = unsafe extern "system" fn(usize, *mut u8, u32, *mut u32) -> i32;
type WriteConsoleInputWFn = unsafe extern "system" fn(usize, *const u8, u32, *mut u32) -> i32;
type GetNumberOfConsoleInputEventsFn = unsafe extern "system" fn(usize, *mut u32) -> i32;

static mut WORK_EVENT: usize = 0;
static mut WORK_CONTEXT: usize = 0;

unsafe extern "system" fn work_item(context: usize) -> u32 {
    WORK_CONTEXT = context;
    let set = kernel32(b"SetEvent\0");
    if set != 0 {
        core::mem::transmute::<usize, SetEventFn>(set)(WORK_EVENT);
    }
    0
}

fn queue_work() {
    let queue = api!("pool.queue", "QueueUserWorkItem", QueueUserWorkItemFn);
    let create_event = api!("pool.event", "CreateEventW", CreateEventWFn);
    let wait = api!("pool.wait", "WaitForSingleObject", WaitForSingleObjectFn);
    let event = unsafe { create_event(0, 1, 0, core::ptr::null()) };
    unsafe { WORK_EVENT = event };
    clear_error();
    // WT_EXECUTELONGFUNCTION, as libuv queues its console line reader.
    let queued = unsafe { queue(work_item as *const () as usize, 0x5eed, 0x10) };
    ok_or_error("pool.queue", queued);
    let waited = unsafe { wait(event, 10_000) };
    case("pool.ran");
    out_str("wait=");
    out_dec(waited as u64);
    out_str(if unsafe { WORK_CONTEXT } == 0x5eed { " context=ok" } else { " context=wrong" });
    out_byte(b'\n');
    close(event);
}

fn map_virtual_key(name: &str, map: MapVirtualKeyWFn, code: u32, map_type: u32) {
    case(name);
    out_hex(unsafe { map(code, map_type) } as u64);
    out_byte(b'\n');
}

fn map_keys() {
    let load = api!("keys.load", "LoadLibraryW", LoadLibraryWFn);
    let mut name = [0u16; 16];
    let user32 = unsafe { load(wide("user32.dll", &mut name).as_ptr()) };
    let address = if user32 == 0 { 0 } else { unsafe { GetProcAddress(user32, b"MapVirtualKeyW\0".as_ptr()) } };
    if address == 0 {
        unavailable("keys");
        return;
    }
    let map: MapVirtualKeyWFn = unsafe { core::mem::transmute(address) };
    map_virtual_key("keys.return_scan", map, 0x0d, 0);
    map_virtual_key("keys.a_scan", map, 0x41, 0);
    map_virtual_key("keys.zero_scan", map, 0x30, 0);
    map_virtual_key("keys.space_scan", map, 0x20, 0);
    map_virtual_key("keys.escape_scan", map, 0x1b, 0);
    map_virtual_key("keys.f1_scan", map, 0x70, 0);
    map_virtual_key("keys.f12_scan", map, 0x7b, 0);
    map_virtual_key("keys.scan_to_return", map, 0x1c, 1);
    map_virtual_key("keys.scan_to_q", map, 0x10, 1);
    map_virtual_key("keys.scan_zero", map, 0, 1);
    map_virtual_key("keys.a_char", map, 0x41, 2);
    map_virtual_key("keys.nine_char", map, 0x39, 2);
    map_virtual_key("keys.back_char", map, 0x08, 2);
    map_virtual_key("keys.bad_type", map, 0x41, 9);
}

fn console_on_file() {
    let read_console = api!("console.read", "ReadConsoleW", ReadConsoleWFn);
    let read_input = api!("console.read_input", "ReadConsoleInputW", ReadConsoleInputWFn);
    let write_input = api!("console.write_input", "WriteConsoleInputW", WriteConsoleInputWFn);
    let count_events =
        api!("console.events", "GetNumberOfConsoleInputEvents", GetNumberOfConsoleInputEventsFn);
    let handle = open("console.open_file", "input.txt", GENERIC_READ, OPEN_EXISTING, 0);
    if handle == INVALID_HANDLE {
        return;
    }
    let mut text = [0u16; 16];
    let mut records = [0u8; 40];
    let mut count = 0u32;
    clear_error();
    ok_or_error("console.read_file", unsafe {
        read_console(handle, text.as_mut_ptr(), 16, &mut count, 0)
    });
    clear_error();
    ok_or_error("console.read_input_file", unsafe {
        read_input(handle, records.as_mut_ptr(), 2, &mut count)
    });
    clear_error();
    ok_or_error("console.write_input_file", unsafe {
        write_input(handle, records.as_ptr(), 1, &mut count)
    });
    clear_error();
    ok_or_error("console.events_file", unsafe { count_events(handle, &mut count) });
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
    let mut work = [0u16; 520];
    work[..base_len].copy_from_slice(&base[..base_len]);
    let mut work_len = base_len;
    if work[work_len - 1] != 0x5c {
        work[work_len] = 0x5c;
        work_len += 1;
    }
    for byte in b"oracle-pool" {
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
    write_file("setup.input", "input.txt", b"y\r\n");

    queue_work();
    map_keys();
    console_on_file();

    simple_1("cleanup.input", b"DeleteFileW\0", "input.txt");
    base[base_len] = 0;
    clear_error();
    ok_or_error("cleanup.chdir", unsafe { set_cwd(base.as_ptr()) });
    simple_1("cleanup.work", b"RemoveDirectoryW\0", "{W}");
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe pool_console\n");
    run();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
