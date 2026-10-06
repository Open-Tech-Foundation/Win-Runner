//! Windows-oracle probe: mutex objects (ownership, recursion, names,
//! non-owner release), file times (`CompareFileTime`, `GetFileTime`), the
//! system RNG (`BCryptGenRandom`), certificate key-usage bits and system
//! stores, and the CRT integer helpers TLS libraries call (`strtoll`,
//! `_byteswap_*`, `isxdigit`, `_difftime64`).

#![no_std]
#![no_main]
#![allow(dead_code)] // shared helpers a probe does not use

include!("common.rs");

type CreateMutexAFn = unsafe extern "system" fn(usize, i32, *const u8) -> usize;
type OpenMutexAFn = unsafe extern "system" fn(u32, i32, *const u8) -> usize;
type HandleFn = unsafe extern "system" fn(usize) -> i32;
type WaitFn = unsafe extern "system" fn(usize, u32) -> u32;
type CreateThreadFn = unsafe extern "system" fn(usize, usize, usize, usize, u32, *mut u32) -> usize;
type LoadLibraryAFn = unsafe extern "system" fn(*const u8) -> usize;

static mut MUTEX: usize = 0;
static mut OTHER_WAIT: u32 = 0;
static mut OTHER_RELEASE: i32 = 0;
static mut OTHER_ERROR: u32 = 0;
static mut OTHER_LATER: u32 = 0;

fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}

fn number(name: &str, value: u64) {
    case(name);
    out_dec(value);
    out_byte(b'\n');
}

/// Another thread tries a mutex the main thread owns: the wait times out
/// and a release fails with ERROR_NOT_OWNER.
extern "system" fn contend(_: usize) -> u32 {
    let wait = kernel32(b"WaitForSingleObject\0");
    let release = kernel32(b"ReleaseMutex\0");
    unsafe {
        OTHER_WAIT = core::mem::transmute::<usize, WaitFn>(wait)(MUTEX, 0);
        clear_error();
        OTHER_RELEASE = core::mem::transmute::<usize, HandleFn>(release)(MUTEX);
        OTHER_ERROR = last_error();
    }
    0
}

/// Once the main thread released it, another thread acquires and releases.
extern "system" fn acquire_later(_: usize) -> u32 {
    let wait = kernel32(b"WaitForSingleObject\0");
    let release = kernel32(b"ReleaseMutex\0");
    unsafe {
        OTHER_LATER = core::mem::transmute::<usize, WaitFn>(wait)(MUTEX, 5000);
        core::mem::transmute::<usize, HandleFn>(release)(MUTEX);
    }
    0
}

fn on_thread(entry: extern "system" fn(usize) -> u32) -> bool {
    let create = kernel32(b"CreateThread\0");
    let wait = kernel32(b"WaitForSingleObject\0");
    let close = kernel32(b"CloseHandle\0");
    if create == 0 || wait == 0 || close == 0 {
        return false;
    }
    unsafe {
        let thread = core::mem::transmute::<usize, CreateThreadFn>(create)(
            0,
            0,
            entry as *const () as usize,
            0,
            0,
            core::ptr::null_mut(),
        );
        if thread == 0 {
            return false;
        }
        let done = core::mem::transmute::<usize, WaitFn>(wait)(thread, 10_000) == 0;
        core::mem::transmute::<usize, HandleFn>(close)(thread);
        done
    }
}

fn mutexes() {
    let create = api!("mutex.api", "CreateMutexA", CreateMutexAFn);
    let open = api!("mutex.open_api", "OpenMutexA", OpenMutexAFn);
    let release = api!("mutex.release_api", "ReleaseMutex", HandleFn);
    let wait = api!("mutex.wait_api", "WaitForSingleObject", WaitFn);
    let close = api!("mutex.close_api", "CloseHandle", HandleFn);
    unsafe {
        clear_error();
        MUTEX = create(0, 1, core::ptr::null());
        boolean("mutex.create_owned", MUTEX != 0 && last_error() == 0);
        number("mutex.recursive_wait", wait(MUTEX, 0) as u64);
        boolean("mutex.other_thread", on_thread(contend));
        number("mutex.other_wait", OTHER_WAIT as u64);
        case("mutex.other_release");
        out_dec(OTHER_RELEASE as u64);
        out_error_value(OTHER_ERROR);
        number("mutex.release", release(MUTEX) as u64);
        number("mutex.release_last", release(MUTEX) as u64);
        clear_error();
        case("mutex.release_free");
        out_dec(release(MUTEX) as u64);
        out_error();
        out_byte(b'\n');
        boolean("mutex.handoff", on_thread(acquire_later));
        number("mutex.handoff_wait", OTHER_LATER as u64);
        close(MUTEX);

        let name = b"WinRunOracleMutex\0".as_ptr();
        clear_error();
        let first = create(0, 0, name);
        number("mutex.named_first_error", last_error() as u64);
        clear_error();
        let second = create(0, 1, name);
        number("mutex.named_second_error", last_error() as u64);
        // Opening an existing mutex never takes ownership.
        clear_error();
        case("mutex.named_not_owner");
        out_dec(release(second) as u64);
        out_error();
        out_byte(b'\n');
        clear_error();
        let opened = open(0x1f_0001, 0, name);
        boolean("mutex.open", opened != 0);
        number("mutex.open_wait", wait(opened, 0) as u64);
        number("mutex.open_release", release(opened) as u64);
        for handle in [first, second, opened] {
            close(handle);
        }
        clear_error();
        case("mutex.open_missing");
        out_dec(open(0x1f_0001, 0, name) as u64);
        out_error();
        out_byte(b'\n');
    }
}

fn out_error_value(code: u32) {
    out_str(" err=");
    out_dec(code as u64);
    out_byte(b'\n');
}

fn file_times() {
    type Compare = unsafe extern "system" fn(*const u64, *const u64) -> i32;
    type CreateFileW = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
    type SetTime = unsafe extern "system" fn(usize, *const u64, *const u64, *const u64) -> i32;
    type GetTime = unsafe extern "system" fn(usize, *mut u64, *mut u64, *mut u64) -> i32;
    type Delete = unsafe extern "system" fn(*const u16) -> i32;
    let compare = api!("filetime.compare_api", "CompareFileTime", Compare);
    let (early, late) = (100u64, 200u64);
    case("filetime.compare");
    for (a, b) in [(&early, &late), (&late, &late), (&late, &early)] {
        let result = unsafe { compare(a, b) };
        out_str(match result {
            -1 => "-1 ",
            0 => "0 ",
            1 => "1 ",
            _ => "? ",
        });
    }
    out_byte(b'\n');
    let create = api!("filetime.create_api", "CreateFileW", CreateFileW);
    let set = api!("filetime.set_api", "SetFileTime", SetTime);
    let get = api!("filetime.get_api", "GetFileTime", GetTime);
    let close = api!("filetime.close_api", "CloseHandle", HandleFn);
    let delete = api!("filetime.delete_api", "DeleteFileW", Delete);
    let mut name = [0u16; 32];
    let name = wide("oracle-filetime.tmp", &mut name);
    let file = unsafe { create(name.as_ptr(), 0xc000_0000, 0, 0, 2, 0x80, 0) };
    if file == usize::MAX {
        unavailable("filetime.file");
        return;
    }
    // 2001-01-01T00:00:00Z and an hour later, in 100 ns units.
    let (created, written) = (126_227_808_000_000_000u64, 126_227_844_000_000_000u64);
    let set_ok = unsafe { set(file, &created, core::ptr::null(), &written) } != 0;
    let (mut c, mut w) = (0u64, 0u64);
    let get_ok = unsafe { get(file, &mut c, core::ptr::null_mut(), &mut w) } != 0;
    boolean("filetime.roundtrip", set_ok && get_ok && c == created && w == written);
    clear_error();
    case("filetime.invalid_handle");
    out_dec(unsafe { get(0x1234_5678, &mut c, core::ptr::null_mut(), &mut w) } as u64);
    out_error();
    out_byte(b'\n');
    unsafe {
        close(file);
        delete(name.as_ptr());
    }
}

fn library(case_name: &str, name: &[u8]) -> usize {
    let load = kernel32(b"LoadLibraryA\0");
    let module = if load == 0 {
        0
    } else {
        unsafe { core::mem::transmute::<usize, LoadLibraryAFn>(load)(name.as_ptr()) }
    };
    if module == 0 {
        unavailable(case_name);
    }
    module
}

fn proc(module: usize, name: &[u8]) -> usize {
    unsafe { GetProcAddress(module, name.as_ptr()) }
}

fn system_random() {
    type GenRandom = unsafe extern "system" fn(usize, *mut u8, u32, u32) -> u32;
    let module = library("bcrypt.load", b"bcrypt.dll\0");
    let address = proc(module, b"BCryptGenRandom\0");
    if address == 0 {
        unavailable("bcrypt.api");
        return;
    }
    let generate = unsafe { core::mem::transmute::<usize, GenRandom>(address) };
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    let a = unsafe { generate(0, first.as_mut_ptr(), 32, 2) };
    let b = unsafe { generate(0, second.as_mut_ptr(), 32, 2) };
    boolean("bcrypt.system_preferred", a == 0 && b == 0 && first != second);
    case("bcrypt.no_algorithm");
    out_hex(unsafe { generate(0, first.as_mut_ptr(), 8, 0) } as u64);
    out_byte(b'\n');
}

fn certificates() {
    type IntendedUsage = unsafe extern "system" fn(u32, *const u64, *mut u8, u32) -> i32;
    type OpenSystem = unsafe extern "system" fn(usize, *const u8) -> usize;
    type CloseStore = unsafe extern "system" fn(usize, u32) -> i32;
    let module = library("cert.load", b"crypt32.dll\0");
    let usage_api = proc(module, b"CertGetIntendedKeyUsage\0");
    if usage_api == 0 {
        unavailable("cert.intended_api");
    } else {
        let usage_fn = unsafe { core::mem::transmute::<usize, IntendedUsage>(usage_api) };
        let key_usage = b"2.5.29.15\0";
        let basic = b"2.5.29.19\0";
        // BIT STRING, one unused bit: 0x84 0x80.
        let value = [0x03u8, 0x03, 0x01, 0x84, 0x80];
        let constraints = [0x30u8, 0x00];
        let extensions: [[u64; 4]; 2] = [
            [basic.as_ptr() as u64, 0, 2, constraints.as_ptr() as u64],
            [key_usage.as_ptr() as u64, 1, value.len() as u64, value.as_ptr() as u64],
        ];
        // CERT_INFO: cExtension and rgExtension are its last two words.
        let mut info = [0u64; 26];
        info[24] = 2;
        info[25] = extensions.as_ptr() as u64;
        let mut bytes = [0xffu8; 4];
        let found = unsafe { usage_fn(1, info.as_ptr(), bytes.as_mut_ptr(), 4) };
        case("cert.intended");
        out_dec(found as u64);
        // Only the extension's bytes; what follows them is not specified.
        for byte in &bytes[..2] {
            out_byte(b' ');
            out_hex(*byte as u64);
        }
        out_byte(b'\n');
        info[24] = 1;
        let mut none = [0xffu8; 2];
        clear_error();
        let missing = unsafe { usage_fn(1, info.as_ptr(), none.as_mut_ptr(), 2) };
        case("cert.intended_none");
        out_dec(missing as u64);
        out_str(if none == [0, 0] { " zeroed" } else { " kept" });
        out_error();
        out_byte(b'\n');
    }
    let open_api = proc(module, b"CertOpenSystemStoreA\0");
    let close_api = proc(module, b"CertCloseStore\0");
    if open_api == 0 || close_api == 0 {
        unavailable("cert.system_store_api");
        return;
    }
    let store = unsafe { core::mem::transmute::<usize, OpenSystem>(open_api)(0, b"ROOT\0".as_ptr()) };
    boolean(
        "cert.system_store",
        store != 0 && unsafe { core::mem::transmute::<usize, CloseStore>(close_api)(store, 0) } != 0,
    );
}

fn crt_helpers() {
    type StrToLl = unsafe extern "C" fn(*const u8, *mut *const u8, i32) -> i64;
    type Swap32 = unsafe extern "C" fn(u32) -> u32;
    type Swap16 = unsafe extern "C" fn(u16) -> u16;
    type IsXDigit = unsafe extern "C" fn(i32) -> i32;
    type DiffTime = unsafe extern "C" fn(i64, i64) -> f64;
    let module = library("crt.load", b"ucrtbase.dll\0");
    if module == 0 {
        return;
    }
    let strtoll = proc(module, b"strtoll\0");
    if strtoll == 0 {
        unavailable("crt.strtoll");
    } else {
        let parse = unsafe { core::mem::transmute::<usize, StrToLl>(strtoll) };
        for (name, text) in [
            ("crt.strtoll_negative", &b"  -42x\0"[..]),
            ("crt.strtoll_hex", &b"0x7fffffffffffffff\0"[..]),
            ("crt.strtoll_overflow", &b"-9223372036854775809\0"[..]),
        ] {
            let mut end = core::ptr::null();
            let value = unsafe { parse(text.as_ptr(), &mut end, 0) };
            case(name);
            if value < 0 {
                out_byte(b'-');
            }
            out_dec(value.unsigned_abs());
            out_str(" used=");
            out_dec(end as u64 - text.as_ptr() as u64);
            out_byte(b'\n');
        }
    }
    let swap32 = proc(module, b"_byteswap_ulong\0");
    let swap16 = proc(module, b"_byteswap_ushort\0");
    if swap32 == 0 || swap16 == 0 {
        unavailable("crt.byteswap");
    } else {
        case("crt.byteswap");
        out_hex(unsafe { core::mem::transmute::<usize, Swap32>(swap32)(0x1234_5678) } as u64);
        out_byte(b' ');
        out_hex(unsafe { core::mem::transmute::<usize, Swap16>(swap16)(0x1234) } as u64);
        out_byte(b'\n');
    }
    let xdigit = proc(module, b"isxdigit\0");
    if xdigit == 0 {
        unavailable("crt.isxdigit");
    } else {
        let test = unsafe { core::mem::transmute::<usize, IsXDigit>(xdigit) };
        boolean(
            "crt.isxdigit",
            unsafe { test(b'F' as i32) != 0 && test(b'9' as i32) != 0 && test(b'g' as i32) == 0 },
        );
    }
    let difftime = proc(module, b"_difftime64\0");
    if difftime == 0 {
        unavailable("crt.difftime");
    } else {
        let seconds = unsafe { core::mem::transmute::<usize, DiffTime>(difftime)(10, 25) };
        boolean("crt.difftime", seconds == -15.0);
    }
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe sync_crypto\n");
    mutexes();
    file_times();
    system_random();
    certificates();
    crt_helpers();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
