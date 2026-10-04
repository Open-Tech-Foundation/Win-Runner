//! CRT callback and conversion contracts used by native Windows programs.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
use core::sync::atomic::{AtomicU32, Ordering};

static GLOBAL: AtomicU32 = AtomicU32::new(0);
static LOCAL: AtomicU32 = AtomicU32::new(0);
static METADATA: AtomicU32 = AtomicU32::new(0);
extern "system" fn global_handler(
    expression: usize,
    function: usize,
    file: usize,
    line: u32,
    reserved: usize,
) {
    GLOBAL.fetch_add(1, Ordering::SeqCst);
    if [expression, function, file, line as usize, reserved] == [0, 0, 0, 0, 0] {
        METADATA.store(1, Ordering::SeqCst);
    }
}
extern "system" fn local_handler(_: usize, _: usize, _: usize, _: u32, _: usize) {
    LOCAL.fetch_add(1, Ordering::SeqCst);
}
fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}
fn load(name: &[u16]) -> usize {
    type Load = unsafe extern "system" fn(*const u16) -> usize;
    let address = kernel32(b"LoadLibraryW\0");
    if address == 0 {
        unavailable("module.load");
        return 0;
    }
    let function: Load = unsafe { core::mem::transmute(address) };
    unsafe { function(name.as_ptr()) }
}
macro_rules! resolve {
    ($module:expr, $name:literal, $ty:ty) => {{
        let address = unsafe { GetProcAddress($module, concat!($name, "\0").as_ptr()) };
        if address == 0 {
            unavailable($name);
            return;
        }
        unsafe { core::mem::transmute::<usize, $ty>(address) }
    }};
}
fn callbacks(module: usize) {
    type Set = unsafe extern "system" fn(usize) -> usize;
    type Get = unsafe extern "system" fn() -> usize;
    type Convert = unsafe extern "system" fn(*mut usize, *mut u16, usize, *const u8, usize) -> i32;
    let set = resolve!(module, "_set_invalid_parameter_handler", Set);
    let get = resolve!(module, "_get_invalid_parameter_handler", Get);
    let set_local = resolve!(module, "_set_thread_local_invalid_parameter_handler", Set);
    let get_local = resolve!(module, "_get_thread_local_invalid_parameter_handler", Get);
    // Dispatch helpers are CRT implementation details and are not exported
    // by every Windows UCRT. Trigger validation through a public secure API.
    let convert = resolve!(module, "mbstowcs_s", Convert);
    let trigger = || {
        let mut converted = 99;
        let mut destination = [77u16; 2];
        let error = unsafe {
            convert(
                &mut converted,
                destination.as_mut_ptr(),
                2,
                core::ptr::null(),
                1,
            )
        };
        error == 22 && converted == 0 && destination[0] == 0
    };
    unsafe {
        let previous = set(global_handler as *const () as usize);
        let previous_local = set_local(0);
        boolean(
            "invalid.global_get",
            get() == global_handler as *const () as usize,
        );
        let global_recovered = trigger();
        set_local(local_handler as *const () as usize);
        boolean(
            "invalid.local_get",
            get_local() == local_handler as *const () as usize,
        );
        let local_recovered = trigger();
        boolean(
            "invalid.local_previous",
            set_local(0) == local_handler as *const () as usize,
        );
        let fallback_recovered = trigger();
        boolean(
            "invalid.recovery",
            global_recovered && local_recovered && fallback_recovered,
        );
        boolean("invalid.metadata", METADATA.load(Ordering::SeqCst) == 1);
        boolean(
            "invalid.global_dispatch",
            GLOBAL.load(Ordering::SeqCst) == 2,
        );
        boolean("invalid.local_dispatch", LOCAL.load(Ordering::SeqCst) == 1);
        set_local(previous_local);
        boolean(
            "invalid.global_previous",
            set(previous) == global_handler as *const () as usize,
        );
    }
}
fn strings(module: usize) {
    type Span = unsafe extern "system" fn(*const u8, *const u8) -> usize;
    type Find = unsafe extern "system" fn(*const u8, *const u8) -> *const u8;
    type Error = unsafe extern "system" fn(i32) -> *const u8;
    type ToWide = unsafe extern "system" fn(*mut usize, *mut u16, usize, *const u8, usize) -> i32;
    type ToNarrow = unsafe extern "system" fn(*mut usize, *mut u8, usize, *const u16, usize) -> i32;
    let cspn = resolve!(module, "strcspn", Span);
    let spn = resolve!(module, "strspn", Span);
    let find = resolve!(module, "strpbrk", Find);
    let error = resolve!(module, "strerror", Error);
    let wide = resolve!(module, "mbstowcs_s", ToWide);
    let narrow = resolve!(module, "wcstombs_s", ToNarrow);
    let input = b"ab12cd\0";
    unsafe {
        boolean("string.cspn", cspn(input.as_ptr(), b"012\0".as_ptr()) == 2);
        boolean("string.spn", spn(input.as_ptr(), b"ab\0".as_ptr()) == 2);
        boolean(
            "string.find",
            find(input.as_ptr(), b"012\0".as_ptr()) == input.as_ptr().add(2),
        );
        let text = error(22);
        boolean(
            "string.error",
            !text.is_null() && core::slice::from_raw_parts(text, 17) == b"Invalid argument\0",
        );
        let mut length = 0;
        boolean(
            "convert.query",
            wide(
                &mut length,
                core::ptr::null_mut(),
                0,
                b"abc\0".as_ptr(),
                usize::MAX,
            ) == 0
                && length == 4,
        );
        let mut output = [0u16; 2];
        boolean(
            "convert.truncate",
            wide(
                &mut length,
                output.as_mut_ptr(),
                2,
                b"abc\0".as_ptr(),
                usize::MAX,
            ) == 80
                && length == 2
                && output == [97, 0],
        );
        let mut bytes = [0u8; 4];
        boolean(
            "convert.narrow",
            narrow(
                &mut length,
                bytes.as_mut_ptr(),
                4,
                [97u16, 98, 99, 0].as_ptr(),
                usize::MAX,
            ) == 0
                && length == 4
                && &bytes == b"abc\0",
        );
    }
}
fn descriptors(module: usize) {
    type Open = unsafe extern "system" fn(*mut i32, *const u8, i32, i32, i32) -> i32;
    type Stream = unsafe extern "system" fn(i32, *const u8) -> usize;
    type Transfer = unsafe extern "system" fn(*mut u8, usize, usize, usize) -> usize;
    type Seek = unsafe extern "system" fn(i32, i64, i32) -> i64;
    type Stat = unsafe extern "system" fn(i32, *mut u8) -> i32;
    type Close = unsafe extern "system" fn(usize) -> i32;
    let open = resolve!(module, "_sopen_s", Open);
    let stream = resolve!(module, "_fdopen", Stream);
    let write = resolve!(module, "fwrite", Transfer);
    let read = resolve!(module, "fread", Transfer);
    let seek = resolve!(module, "_lseeki64", Seek);
    let stat = resolve!(module, "_fstat64", Stat);
    let close = resolve!(module, "fclose", Close);
    let mut fd = -1;
    let opened =
        unsafe { open(&mut fd, b"crt-oracle.bin\0".as_ptr(), 0x8302, 0x40, 0x180) } == 0 && fd >= 0;
    boolean("fd.open", opened);
    if !opened {
        return;
    }
    let file = unsafe { stream(fd, b"w+b\0".as_ptr()) };
    boolean("fd.stream", file != 0);
    if file == 0 {
        return;
    }
    let mut bytes = *b"data";
    // fwrite on Windows may buffer: flush before seeking its underlying fd.
    type Flush = unsafe extern "system" fn(usize) -> i32;
    let flush = resolve!(module, "fflush", Flush);
    boolean(
        "fd.write",
        unsafe { write(bytes.as_mut_ptr(), 1, 4, file) } == 4 && unsafe { flush(file) } == 0,
    );
    boolean("fd.seek", unsafe { seek(fd, 0, 0) } == 0);
    bytes = [0; 4];
    boolean(
        "fd.read",
        unsafe { read(bytes.as_mut_ptr(), 1, 4, file) } == 4 && &bytes == b"data",
    );
    let mut info = [0u8; 56];
    boolean(
        "fd.stat",
        unsafe { stat(fd, info.as_mut_ptr()) } == 0
            && i64::from_le_bytes(info[24..32].try_into().unwrap()) == 4,
    );
    boolean("fd.close", unsafe { close(file) } == 0);
    boolean(
        "fd.missing",
        unsafe {
            open(
                &mut fd,
                b"missing-crt-oracle.bin\0".as_ptr(),
                0x8000,
                0x40,
                0,
            )
        } == 2
            && fd == -1,
    );
}
fn module_name() {
    type Name = unsafe extern "system" fn(usize, *mut u8, u32) -> u32;
    let name = api!("module.name", "GetModuleFileNameA", Name);
    let mut full = [0u8; 1024];
    let length = unsafe { name(0, full.as_mut_ptr(), 1024) };
    boolean(
        "module.name",
        length > 0 && length < 1024 && full[length as usize] == 0,
    );
    let mut short = [0u8; 3];
    boolean(
        "module.truncated",
        unsafe { name(0, short.as_mut_ptr(), 3) } == 3 && short[2] == 0 && last_error() == 122,
    );
}
fn security() {
    let module = load(&[115, 101, 99, 117, 114, 51, 50, 46, 100, 108, 108, 0]);
    type Init = unsafe extern "system" fn() -> *const usize;
    let init = resolve!(module, "InitSecurityInterfaceA", Init);
    let table = unsafe { init() };
    if table.is_null() {
        boolean("security.table", false);
        return;
    }
    boolean(
        "security.table",
        unsafe { *table } as u32 >= 1 && unsafe { *table.add(3) } != 0,
    );
    type Query = unsafe extern "system" fn(*const u8, *mut usize) -> i32;
    let query: Query = unsafe { core::mem::transmute(*table.add(17)) };
    let mut info = 0;
    boolean(
        "security.unknown_package",
        unsafe {
            query(
                b"WinRunner-Nonexistent-Oracle-SSP-554433\0".as_ptr(),
                &mut info,
            )
        } as u32
            == 0x80090305,
    );
}
#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe crt_runtime\n");
    let module = load(&[117, 99, 114, 116, 98, 97, 115, 101, 46, 100, 108, 108, 0]);
    callbacks(module);
    strings(module);
    descriptors(module);
    module_name();
    security();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
