//! Microsoft C runtime compatibility shims for Linux-hosted PE programs.

use super::*;

thread_local! {
    pub(super) static THREAD_CRT_ERRNO: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
    static THREAD_CRT_LOCALE_MODE: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
    pub(super) static THREAD_CRT_GETENV_VALUE: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) static NATIVE_CRT_SIGNAL_HANDLERS: LazyLock<Mutex<HashMap<(u32, i32), u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
pub(super) static NATIVE_CRT_FMODE: AtomicI32 = AtomicI32::new(0);
pub(super) static NATIVE_CRT_COMMODE: AtomicI32 = AtomicI32::new(0);
pub(super) static NATIVE_CRT_C_LOCALE: [u8; 2] = *b"C\0";
pub(super) static NATIVE_CRT_ACMDLN: AtomicU64 = AtomicU64::new(0);
pub(super) static NATIVE_CRT_WCMDLN: AtomicU64 = AtomicU64::new(0);
pub(super) static NATIVE_CRT_INITENV: AtomicU64 = AtomicU64::new(0);
pub(super) static NATIVE_CRT_WINITENV: AtomicU64 = AtomicU64::new(0);
pub(super) static NATIVE_CRT_PGMPTR: AtomicU64 = AtomicU64::new(0);
pub(super) static NATIVE_CRT_WPGMPTR: AtomicU64 = AtomicU64::new(0);
pub(super) static NATIVE_CRT_IOB: [AtomicU64; 24] = [const { AtomicU64::new(0) }; 24];
const NATIVE_CRT_FILE_SIGNATURE: u64 = 0x5749_4e52_554e_4649;

#[repr(C)]
struct NativeCrtFile {
    signature: u64,
    handle: u64,
    readable: u8,
    writable: u8,
    append: u8,
    reserved: [u8; 45],
}

pub(super) extern "win64" fn native_crt_set_app_type(_app_type: i32) {}
pub(super) extern "win64" fn native_crt_p_fmode() -> *mut i32 {
    NATIVE_CRT_FMODE.as_ptr()
}
pub(super) extern "win64" fn native_crt_p_commode() -> *mut i32 {
    NATIVE_CRT_COMMODE.as_ptr()
}
pub(super) extern "win64" fn native_crt_iob_func() -> *mut u8 {
    NATIVE_CRT_IOB.as_ptr().cast_mut().cast()
}
pub(super) extern "win64" fn native_crt_acrt_iob_func(index: u32) -> *mut u8 {
    if index >= 3 {
        return std::ptr::null_mut();
    }
    unsafe {
        NATIVE_CRT_IOB
            .as_ptr()
            .cast_mut()
            .cast::<u8>()
            .add(index as usize * 64)
    }
}
fn native_crt_standard_stream_index(stream: *mut u8) -> Option<usize> {
    if stream.is_null() {
        return None;
    }
    let base = NATIVE_CRT_IOB.as_ptr() as usize;
    let address = stream as usize;
    let offset = address.checked_sub(base)?;
    (offset < 192 && offset % 64 == 0).then_some(offset / 64)
}
pub(super) extern "win64" fn native_crt_errno() -> *mut i32 {
    THREAD_CRT_ERRNO.with(std::cell::Cell::as_ptr)
}
pub(super) extern "win64" fn native_crt_signal(signal: i32, handler: u64) -> u64 {
    let Some(process) = process_ctx() else {
        return u64::MAX;
    };
    if !(1..=22).contains(&signal) {
        return u64::MAX; // SIG_ERR
    }
    let Ok(mut handlers) = NATIVE_CRT_SIGNAL_HANDLERS.lock() else {
        return u64::MAX;
    };
    handlers
        .insert((process.process_id, signal), handler)
        .unwrap_or(0)
}

fn native_crt_exception_signal(exception: u32) -> Option<(i32, Option<i32>)> {
    Some(match exception {
        0xc000_0005 => (11, None), // STATUS_ACCESS_VIOLATION -> SIGSEGV
        0xc000_001d | 0xc000_0096 => (4, None), // illegal/privileged -> SIGILL
        0xc000_008d => (8, Some(0x82)), // _FPE_DENORMAL
        0xc000_008e => (8, Some(0x83)), // _FPE_ZERODIVIDE
        0xc000_008f => (8, Some(0x86)), // _FPE_INEXACT
        0xc000_0090 => (8, Some(0x81)), // _FPE_INVALID
        0xc000_0091 => (8, Some(0x84)), // _FPE_OVERFLOW
        0xc000_0092 => (8, Some(0x8a)), // _FPE_STACKOVERFLOW
        0xc000_0093 => (8, Some(0x85)), // _FPE_UNDERFLOW
        _ => return None,
    })
}

pub(super) extern "win64" fn native_crt_seh_filter_exe(
    exception: u32,
    _exception_pointers: *const c_void,
) -> i32 {
    let Some((signal, fpe_code)) = native_crt_exception_signal(exception) else {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    };
    let Some(process) = process_ctx() else {
        return 0;
    };
    let key = (process.process_id, signal);
    let handler = match NATIVE_CRT_SIGNAL_HANDLERS.lock() {
        Ok(handlers) => handlers.get(&key).copied().unwrap_or(0),
        Err(_) => return 0,
    };
    match handler {
        0 => 0,  // SIG_DFL: leave the exception for the next handler.
        1 => -1, // SIG_IGN: continue execution.
        handler => {
            if let Ok(mut handlers) = NATIVE_CRT_SIGNAL_HANDLERS.lock() {
                // The CRT resets a caught exception signal to SIG_DFL before
                // invoking its handler, so recursive faults continue search.
                handlers.insert(key, 0);
            }
            unsafe {
                if let Some(fpe_code) = fpe_code {
                    let callback: unsafe extern "win64" fn(i32, i32) =
                        std::mem::transmute(handler as usize);
                    callback(signal, fpe_code);
                } else {
                    let callback: unsafe extern "win64" fn(i32) =
                        std::mem::transmute(handler as usize);
                    callback(signal);
                }
            }
            -1 // EXCEPTION_CONTINUE_EXECUTION
        }
    }
}
pub(super) extern "win64" fn native_crt_getenv(name: *const u8) -> *mut u8 {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let mut key = Vec::new();
    for index in 0..32768usize {
        let byte = unsafe { name.add(index).read() };
        if byte == 0 {
            break;
        }
        key.push(byte);
    }
    if key.is_empty() {
        return std::ptr::null_mut();
    }
    let key = String::from_utf8_lossy(&key);
    let Some(value) = process_ctx().and_then(|process| {
        process.environment.lock().ok().and_then(|environment| {
            environment
                .iter()
                .find_map(|(name, value)| name.eq_ignore_ascii_case(&key).then(|| value.clone()))
        })
    }) else {
        return std::ptr::null_mut();
    };
    THREAD_CRT_GETENV_VALUE.with(|buffer| {
        let mut buffer = buffer.borrow_mut();
        buffer.clear();
        buffer.extend_from_slice(value.as_bytes());
        buffer.push(0);
        buffer.as_mut_ptr()
    })
}
// The native runtime starts in the C locale, whose initial locale
// conversion data is zero-initialized. MinGW CRTs call this initializer
// during startup; no additional setup is needed for that default locale.
pub(super) extern "win64" fn native_crt_lconv_init() {}
pub(super) extern "win64" fn native_crt_setlocale(category: i32, locale: *const u8) -> *const u8 {
    if !(0..=5).contains(&category) {
        return std::ptr::null();
    }
    if !locale.is_null() {
        let mut value = Vec::new();
        for index in 0..128usize {
            let byte = unsafe { locale.add(index).read() };
            if byte == 0 {
                break;
            }
            value.push(byte.to_ascii_lowercase());
        }
        if !value.is_empty() && value != b"c" && value != b"posix" {
            return std::ptr::null();
        }
    }
    NATIVE_CRT_C_LOCALE.as_ptr()
}
fn build_crt_startup(
    command_line: &[u8],
    environment: &[(String, String)],
    module_path: &str,
) -> NativeCrtStartup {
    let line = String::from_utf8_lossy(command_line);
    let args = parse_windows_command_line(line.trim_end_matches('\0')).unwrap_or_default();
    let argv_storage = args
        .iter()
        .map(|arg| nul_terminated_bytes(arg))
        .collect::<Vec<_>>();
    let mut argv = argv_storage
        .iter()
        .map(|arg| arg.as_ptr() as usize)
        .collect::<Vec<_>>();
    argv.push(0);
    let argv_value = argv.as_mut_ptr() as usize;
    let wide_argv_storage = args
        .iter()
        .map(|arg| nul_terminated_wide(arg))
        .collect::<Vec<_>>();
    let mut wide_argv = wide_argv_storage
        .iter()
        .map(|arg| arg.as_ptr() as usize)
        .collect::<Vec<_>>();
    wide_argv.push(0);
    let wide_argv_value = wide_argv.as_mut_ptr() as usize;
    let environment_storage = environment
        .iter()
        .map(|(name, value)| nul_terminated_bytes(&format!("{name}={value}")))
        .collect::<Vec<_>>();
    let wide_environment_storage = environment
        .iter()
        .map(|(name, value)| nul_terminated_wide(&format!("{name}={value}")))
        .collect::<Vec<_>>();
    let mut environment = environment_storage
        .iter()
        .map(|entry| entry.as_ptr() as usize)
        .collect::<Vec<_>>();
    environment.push(0);
    let environment_value = environment.as_mut_ptr() as usize;
    let mut wide_environment = wide_environment_storage
        .iter()
        .map(|entry| entry.as_ptr() as usize)
        .collect::<Vec<_>>();
    wide_environment.push(0);
    let wide_environment_value = wide_environment.as_mut_ptr() as usize;
    let program_name_w_storage = nul_terminated_wide(module_path);
    let program_name_a_storage = command_line_a(&program_name_w_storage).into_boxed_slice();
    NativeCrtStartup {
        argc: argv.len().saturating_sub(1) as i32,
        _argv_storage: argv_storage,
        argv,
        argv_value,
        _wide_argv_storage: wide_argv_storage,
        wide_argv,
        wide_argv_value,
        _environment_storage: environment_storage,
        environment,
        environment_value,
        _wide_environment_storage: wide_environment_storage,
        wide_environment,
        wide_environment_value,
        _program_name_a_storage: program_name_a_storage,
        _program_name_w_storage: program_name_w_storage,
    }
}

fn nul_terminated_bytes(value: &str) -> Box<[u8]> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    bytes.into_boxed_slice()
}

fn nul_terminated_wide(value: &str) -> Box<[u16]> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn ensure_crt_startup(process: &NativeProcessContext) {
    if let Ok(mut startup) = process.crt_startup.lock() {
        if startup.is_none() {
            let environment = process.environment.lock().map(|env| env.clone());
            *startup = Some(build_crt_startup(
                &process.command_line_a,
                environment.as_deref().unwrap_or_default(),
                &process.module_path,
            ));
        }
        if let Some(startup) = startup.as_mut() {
            NATIVE_CRT_ACMDLN.store(process.command_line_a.as_ptr() as u64, Ordering::Release);
            NATIVE_CRT_WCMDLN.store(process.command_line_w.as_ptr() as u64, Ordering::Release);
            NATIVE_CRT_INITENV.store(startup.environment.as_mut_ptr() as u64, Ordering::Release);
            NATIVE_CRT_WINITENV.store(
                startup.wide_environment.as_mut_ptr() as u64,
                Ordering::Release,
            );
            NATIVE_CRT_PGMPTR.store(
                startup._program_name_a_storage.as_ptr() as u64,
                Ordering::Release,
            );
            NATIVE_CRT_WPGMPTR.store(
                startup._program_name_w_storage.as_ptr() as u64,
                Ordering::Release,
            );
        }
    }
}

pub(super) extern "win64" fn native_crt_configure_narrow_argv(_mode: i32) -> i32 {
    if (0..=2).contains(&_mode) {
        0
    } else {
        -1
    }
}

pub(super) extern "win64" fn native_crt_configure_wide_argv(mode: i32) -> i32 {
    native_crt_configure_narrow_argv(mode)
}

pub(super) extern "win64" fn native_crt_initialize_narrow_environment() {
    if let Some(process) = process_ctx() {
        ensure_crt_startup(&process);
    }
}

pub(super) extern "win64" fn native_crt_initialize_wide_environment() {
    native_crt_initialize_narrow_environment();
}

pub(super) extern "win64" fn native_crt_p_argc() -> *mut i32 {
    let Some(process) = process_ctx() else {
        return std::ptr::null_mut();
    };
    ensure_crt_startup(&process);
    process
        .crt_startup
        .lock()
        .ok()
        .and_then(|mut startup| {
            startup
                .as_mut()
                .map(|startup| std::ptr::addr_of_mut!(startup.argc))
        })
        .unwrap_or(std::ptr::null_mut())
}

pub(super) extern "win64" fn native_crt_p_argv() -> *mut *mut *mut i8 {
    let Some(process) = process_ctx() else {
        return std::ptr::null_mut();
    };
    ensure_crt_startup(&process);
    process
        .crt_startup
        .lock()
        .ok()
        .and_then(|mut startup| {
            startup
                .as_mut()
                .map(|startup| std::ptr::addr_of_mut!(startup.argv_value).cast::<*mut *mut i8>())
        })
        .unwrap_or(std::ptr::null_mut())
}

pub(super) extern "win64" fn native_crt_p_wargv() -> *mut *mut *mut u16 {
    let Some(process) = process_ctx() else {
        return std::ptr::null_mut();
    };
    ensure_crt_startup(&process);
    process
        .crt_startup
        .lock()
        .ok()
        .and_then(|mut startup| {
            startup.as_mut().map(|startup| {
                std::ptr::addr_of_mut!(startup.wide_argv_value).cast::<*mut *mut u16>()
            })
        })
        .unwrap_or(std::ptr::null_mut())
}

pub(super) extern "win64" fn native_crt_p_acmdln() -> *mut *mut u8 {
    if let Some(process) = process_ctx() {
        ensure_crt_startup(&process);
    }
    NATIVE_CRT_ACMDLN.as_ptr().cast()
}

pub(super) extern "win64" fn native_crt_p_wcmdln() -> *mut *mut u16 {
    if let Some(process) = process_ctx() {
        ensure_crt_startup(&process);
    }
    NATIVE_CRT_WCMDLN.as_ptr().cast()
}

pub(super) extern "win64" fn native_crt_p_pgmptr() -> *mut *mut u8 {
    if let Some(process) = process_ctx() {
        ensure_crt_startup(&process);
    }
    NATIVE_CRT_PGMPTR.as_ptr().cast()
}

pub(super) extern "win64" fn native_crt_p_wpgmptr() -> *mut *mut u16 {
    if let Some(process) = process_ctx() {
        ensure_crt_startup(&process);
    }
    NATIVE_CRT_WPGMPTR.as_ptr().cast()
}

pub(super) extern "win64" fn native_crt_get_initial_narrow_environment() -> *mut *mut i8 {
    let Some(process) = process_ctx() else {
        return std::ptr::null_mut();
    };
    ensure_crt_startup(&process);
    process
        .crt_startup
        .lock()
        .ok()
        .and_then(|mut startup| {
            startup
                .as_mut()
                .map(|startup| startup.environment.as_mut_ptr().cast::<*mut i8>())
        })
        .unwrap_or(std::ptr::null_mut())
}

pub(super) extern "win64" fn native_crt_get_initial_wide_environment() -> *mut *mut u16 {
    let Some(process) = process_ctx() else {
        return std::ptr::null_mut();
    };
    ensure_crt_startup(&process);
    process
        .crt_startup
        .lock()
        .ok()
        .and_then(|mut startup| {
            startup
                .as_mut()
                .map(|startup| startup.wide_environment.as_mut_ptr().cast::<*mut u16>())
        })
        .unwrap_or(std::ptr::null_mut())
}

pub(super) extern "win64" fn native_crt_p_environ() -> *mut *mut *mut i8 {
    let Some(process) = process_ctx() else {
        return std::ptr::null_mut();
    };
    ensure_crt_startup(&process);
    process
        .crt_startup
        .lock()
        .ok()
        .and_then(|mut startup| {
            startup.as_mut().map(|startup| {
                std::ptr::addr_of_mut!(startup.environment_value).cast::<*mut *mut i8>()
            })
        })
        .unwrap_or(std::ptr::null_mut())
}

pub(super) extern "win64" fn native_crt_p_wenviron() -> *mut *mut *mut u16 {
    let Some(process) = process_ctx() else {
        return std::ptr::null_mut();
    };
    ensure_crt_startup(&process);
    process
        .crt_startup
        .lock()
        .ok()
        .and_then(|mut startup| {
            startup.as_mut().map(|startup| {
                std::ptr::addr_of_mut!(startup.wide_environment_value).cast::<*mut *mut u16>()
            })
        })
        .unwrap_or(std::ptr::null_mut())
}

pub(super) extern "win64" fn native_crt_p_initenv() -> *mut *mut *mut i8 {
    if let Some(process) = process_ctx() {
        ensure_crt_startup(&process);
    }
    NATIVE_CRT_INITENV.as_ptr().cast()
}

pub(super) extern "win64" fn native_crt_p_winitenv() -> *mut *mut *mut u16 {
    if let Some(process) = process_ctx() {
        ensure_crt_startup(&process);
    }
    NATIVE_CRT_WINITENV.as_ptr().cast()
}

pub(super) extern "win64" fn native_crt_set_new_mode(mode: i32) -> i32 {
    if !matches!(mode, 0 | 1) {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22)); // EINVAL
        return -1;
    }
    process_ctx()
        .map(|process| process.crt_new_mode.swap(mode, Ordering::AcqRel))
        .unwrap_or(0)
}

pub(super) extern "win64" fn native_crt_config_thread_locale(mode: i32) -> i32 {
    if !matches!(mode, -1..=1) {
        return -1;
    }
    THREAD_CRT_LOCALE_MODE.with(|locale| locale.replace(mode))
}

pub(super) extern "win64" fn native_crt_atexit(callback: u64) -> i32 {
    let Some(process) = process_ctx() else {
        return -1;
    };
    if callback == 0 {
        return -1;
    }
    process
        .crt_exit_functions
        .lock()
        .map(|mut callbacks| callbacks.push(callback))
        .map(|()| 0)
        .unwrap_or(-1)
}

pub(super) extern "win64" fn native_crt_register_onexit_function(
    table: *mut c_void,
    callback: u64,
) -> i32 {
    if table.is_null() || callback == 0 {
        return -1;
    }
    let Some((mut first, mut last, mut end)) = native_crt_onexit_fields(table) else {
        return -1;
    };
    if first == NATIVE_CRT_ONEXIT_EMPTY
        && last == NATIVE_CRT_ONEXIT_EMPTY
        && end == NATIVE_CRT_ONEXIT_EMPTY
    {
        let initial_count = 32usize;
        let Some(bytes) = initial_count.checked_mul(std::mem::size_of::<u64>()) else {
            return -1;
        };
        first = unsafe { malloc(bytes) } as usize;
        if first == 0 {
            return -1;
        }
        last = first;
        end = first + bytes;
    } else if first == 0
        || last < first
        || end < last
        || (last - first) % 8 != 0
        || (end - first) % 8 != 0
    {
        return -1;
    }
    if last == end {
        let old_capacity = (end - first) / 8;
        let new_capacity = old_capacity.saturating_mul(2).max(32);
        let Some(bytes) = new_capacity.checked_mul(8) else {
            return -1;
        };
        let grown = unsafe { realloc(first as *mut c_void, bytes) } as usize;
        if grown == 0 {
            return -1;
        }
        first = grown;
        last = grown + old_capacity * 8;
        end = grown + bytes;
    }
    unsafe {
        (last as *mut u64).write_unaligned(callback);
        let fields = table.cast::<u64>();
        fields.write_unaligned(first as u64);
        fields.add(1).write_unaligned(last as u64 + 8);
        fields.add(2).write_unaligned(end as u64);
    }
    0
}

const NATIVE_CRT_ONEXIT_EMPTY: usize = 1;

fn native_crt_onexit_fields(table: *mut c_void) -> Option<(usize, usize, usize)> {
    if table.is_null() {
        return None;
    }
    let fields = table.cast::<u64>();
    Some(unsafe {
        (
            fields.read_unaligned() as usize,
            fields.add(1).read_unaligned() as usize,
            fields.add(2).read_unaligned() as usize,
        )
    })
}

pub(super) extern "win64" fn native_crt_initialize_onexit_table(table: *mut c_void) -> i32 {
    let Some((first, last, end)) = native_crt_onexit_fields(table) else {
        return -1;
    };
    let initialized_empty = first == NATIVE_CRT_ONEXIT_EMPTY
        && last == NATIVE_CRT_ONEXIT_EMPTY
        && end == NATIVE_CRT_ONEXIT_EMPTY;
    let initialized_storage = first != 0
        && first != NATIVE_CRT_ONEXIT_EMPTY
        && first <= last
        && last <= end
        && (last - first) % 8 == 0
        && (end - first) % 8 == 0;
    if !initialized_empty && !initialized_storage {
        let fields = table.cast::<u64>();
        unsafe {
            fields.write_unaligned(NATIVE_CRT_ONEXIT_EMPTY as u64);
            fields
                .add(1)
                .write_unaligned(NATIVE_CRT_ONEXIT_EMPTY as u64);
            fields
                .add(2)
                .write_unaligned(NATIVE_CRT_ONEXIT_EMPTY as u64);
        }
    }
    0
}

pub(super) extern "win64" fn native_crt_execute_onexit_table(table: *mut c_void) -> i32 {
    let Some((mut first, mut last, _end)) = native_crt_onexit_fields(table) else {
        return -1;
    };
    if first == 0 {
        return 0;
    }
    if first == NATIVE_CRT_ONEXIT_EMPTY {
        let fields = table.cast::<u64>();
        unsafe {
            fields.write_unaligned(0);
            fields.add(1).write_unaligned(0);
            fields.add(2).write_unaligned(0);
        }
        return 0;
    }
    if first == 0 || last < first || (last - first) % 8 != 0 {
        return -1;
    }
    let mut scan_first = first;
    let mut scan_last = last;
    loop {
        while scan_last > scan_first {
            scan_last -= 8;
            let slot = scan_last as *mut u64;
            let callback = unsafe { slot.read_unaligned() };
            unsafe { slot.write_unaligned(0) };
            if callback != 0 {
                let callback: extern "win64" fn() =
                    unsafe { std::mem::transmute(callback as usize) };
                callback();
                if let Some((new_first, new_last, _)) = native_crt_onexit_fields(table) {
                    if new_first != scan_first || new_last != last {
                        first = new_first;
                        scan_first = new_first;
                        scan_last = new_last;
                        last = new_last;
                        break;
                    }
                } else {
                    return -1;
                }
            }
        }
        if scan_last <= scan_first {
            break;
        }
    }
    if first != NATIVE_CRT_ONEXIT_EMPTY {
        unsafe { free(first as *mut c_void) };
    }
    let fields = table.cast::<u64>();
    unsafe {
        fields.write_unaligned(0);
        fields.add(1).write_unaligned(0);
        fields.add(2).write_unaligned(0);
    }
    0
}

pub(super) fn native_crt_run_exit_handlers() {
    let Some(process) = process_ctx() else {
        return;
    };
    let callbacks = process
        .crt_exit_functions
        .lock()
        .map(|mut callbacks| std::mem::take(&mut *callbacks))
        .unwrap_or_default();
    for callback in callbacks.into_iter().rev() {
        let callback: extern "win64" fn() = unsafe { std::mem::transmute(callback as usize) };
        callback();
    }
}

pub(super) extern "win64" fn native_crt_cexit() {
    native_crt_run_exit_handlers();
}
pub(super) extern "win64" fn native_crt_c_exit() {}
pub(super) extern "win64" fn native_crt_onexit(callback: u64) -> u64 {
    if native_crt_atexit(callback) == 0 {
        callback
    } else {
        0
    }
}
pub(super) extern "win64" fn native_crt_strlen(input: *const u8) -> usize {
    if input.is_null() {
        return 0;
    }
    for len in 0..1_048_576usize {
        if unsafe { input.add(len).read() } == 0 {
            return len;
        }
    }
    0
}
pub(super) extern "win64" fn native_crt_strcmp(left: *const u8, right: *const u8) -> i32 {
    for index in 0..1_048_576usize {
        let (a, b) = unsafe { (left.add(index).read(), right.add(index).read()) };
        if a != b || a == 0 {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
pub(super) extern "win64" fn native_crt_strncmp(
    left: *const u8,
    right: *const u8,
    count: usize,
) -> i32 {
    for index in 0..count {
        let (a, b) = unsafe { (left.add(index).read(), right.add(index).read()) };
        if a != b || a == 0 {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
pub(super) extern "win64" fn native_crt_strchr(input: *const u8, value: i32) -> *mut u8 {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let target = value as u8;
    for index in 0..1_048_576usize {
        let byte = unsafe { input.add(index).read() };
        if byte == target {
            return unsafe { input.add(index) as *mut u8 };
        }
        if byte == 0 {
            return std::ptr::null_mut();
        }
    }
    std::ptr::null_mut()
}
pub(super) extern "win64" fn native_crt_strrchr(input: *const u8, value: i32) -> *mut u8 {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let target = value as u8;
    let mut found = std::ptr::null_mut();
    for index in 0..1_048_576usize {
        let byte = unsafe { input.add(index).read() };
        if byte == target {
            found = unsafe { input.add(index) as *mut u8 };
        }
        if byte == 0 {
            return found;
        }
    }
    found
}
pub(super) extern "win64" fn native_crt_strstr(haystack: *const u8, needle: *const u8) -> *mut u8 {
    if haystack.is_null() || needle.is_null() {
        return std::ptr::null_mut();
    }
    if unsafe { needle.read() } == 0 {
        return haystack as *mut u8;
    }
    for start in 0..1_048_576usize {
        if unsafe { haystack.add(start).read() } == 0 {
            return std::ptr::null_mut();
        }
        let mut offset = 0usize;
        while offset < 1_048_576 {
            let (left, right) = unsafe {
                (
                    haystack.add(start + offset).read(),
                    needle.add(offset).read(),
                )
            };
            if right == 0 {
                return unsafe { haystack.add(start) as *mut u8 };
            }
            if left == 0 || left != right {
                break;
            }
            offset += 1;
        }
    }
    std::ptr::null_mut()
}
fn native_crt_fold_ascii(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + (b'a' - b'A')
    } else {
        byte
    }
}
pub(super) extern "win64" fn native_crt_stricmp(left: *const u8, right: *const u8) -> i32 {
    for index in 0..1_048_576usize {
        let (a, b) = unsafe { (left.add(index).read(), right.add(index).read()) };
        let (a, b) = (native_crt_fold_ascii(a), native_crt_fold_ascii(b));
        if a != b || a == 0 {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
pub(super) extern "win64" fn native_crt_strnicmp(
    left: *const u8,
    right: *const u8,
    count: usize,
) -> i32 {
    for index in 0..count {
        let (a, b) = unsafe { (left.add(index).read(), right.add(index).read()) };
        let (a, b) = (native_crt_fold_ascii(a), native_crt_fold_ascii(b));
        if a != b || a == 0 {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
pub(super) extern "win64" fn native_crt_atoi(input: *const u8) -> i32 {
    if input.is_null() {
        return 0;
    }
    let mut index = 0usize;
    while index < 1_048_576 && unsafe { input.add(index).read() }.is_ascii_whitespace() {
        index += 1;
    }
    let negative = match unsafe { input.add(index).read() } {
        b'-' => {
            index += 1;
            true
        }
        b'+' => {
            index += 1;
            false
        }
        _ => false,
    };
    let mut value = 0i32;
    let mut digits = 0usize;
    while index < 1_048_576 {
        let byte = unsafe { input.add(index).read() };
        if !byte.is_ascii_digit() {
            break;
        }
        value = value.wrapping_mul(10).wrapping_add(i32::from(byte - b'0'));
        index += 1;
        digits += 1;
    }
    if digits == 0 {
        0
    } else if negative {
        value.wrapping_neg()
    } else {
        value
    }
}

pub(super) extern "win64" fn native_crt_strtol(
    input: *const u8,
    end: *mut *mut u8,
    base: i32,
) -> i32 {
    if input.is_null() || !(base == 0 || (2..=36).contains(&base)) {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        if !end.is_null() && !input.is_null() {
            unsafe { end.write_unaligned(input as *mut u8) };
        }
        return 0;
    }
    let mut index = 0usize;
    while index < 1_048_576 && unsafe { input.add(index).read() }.is_ascii_whitespace() {
        index += 1;
    }
    let negative = match unsafe { input.add(index).read() } {
        b'-' => {
            index += 1;
            true
        }
        b'+' => {
            index += 1;
            false
        }
        _ => false,
    };
    let mut radix = base as u32;
    if (radix == 0 || radix == 16)
        && unsafe { input.add(index).read() } == b'0'
        && matches!(unsafe { input.add(index + 1).read() }, b'x' | b'X')
        && unsafe { input.add(index + 2).read() }.is_ascii_hexdigit()
    {
        radix = 16;
        index += 2;
    } else if radix == 0 {
        radix = if unsafe { input.add(index).read() } == b'0' {
            8
        } else {
            10
        };
    }
    let digits_start = index;
    let mut magnitude = 0u64;
    let limit = if negative {
        (i32::MAX as u64) + 1
    } else {
        i32::MAX as u64
    };
    let mut overflow = false;
    while index < 1_048_576 {
        let byte = unsafe { input.add(index).read() };
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'z' => u32::from(byte - b'a') + 10,
            b'A'..=b'Z' => u32::from(byte - b'A') + 10,
            _ => break,
        };
        if digit >= radix {
            break;
        }
        if magnitude > (limit.saturating_sub(u64::from(digit))) / u64::from(radix) {
            overflow = true;
            magnitude = limit;
        } else if !overflow {
            magnitude = magnitude * u64::from(radix) + u64::from(digit);
        }
        index += 1;
    }
    if index == digits_start {
        if !end.is_null() {
            unsafe { end.write_unaligned(input as *mut u8) };
        }
        return 0;
    }
    if !end.is_null() {
        unsafe { end.write_unaligned(input.add(index) as *mut u8) };
    }
    if overflow {
        THREAD_CRT_ERRNO.with(|errno| errno.set(34)); // ERANGE
    }
    if negative {
        if magnitude == (i32::MAX as u64) + 1 {
            i32::MIN
        } else {
            -(magnitude as i32)
        }
    } else {
        magnitude as i32
    }
}

pub(super) extern "win64" fn native_crt_strtod(input: *const u8, end: *mut *mut u8) -> f64 {
    if input.is_null() {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        if !end.is_null() {
            unsafe { end.write_unaligned(input as *mut u8) };
        }
        return 0.0;
    }
    let mut start = 0usize;
    while start < 1_048_576 && unsafe { input.add(start).read() }.is_ascii_whitespace() {
        start += 1;
    }
    let mut number_start = start;
    if matches!(unsafe { input.add(number_start).read() }, b'+' | b'-') {
        number_start += 1;
    }
    let special = [b"infinity".as_slice(), b"inf".as_slice(), b"nan".as_slice()]
        .into_iter()
        .find(|word| {
            word.iter().enumerate().all(|(offset, expected)| {
                unsafe { input.add(number_start + offset).read() }.eq_ignore_ascii_case(expected)
            })
        });
    if let Some(word) = special {
        let mut end_index = number_start + word.len();
        let is_nan = word == b"nan";
        if is_nan && unsafe { input.add(end_index).read() } == b'(' {
            end_index += 1;
            while end_index < 1_048_576
                && unsafe { input.add(end_index).read() } != 0
                && unsafe { input.add(end_index).read() } != b')'
            {
                end_index += 1;
            }
            if unsafe { input.add(end_index).read() } == b')' {
                end_index += 1;
            } else {
                end_index = number_start + word.len();
            }
        }
        if !end.is_null() {
            unsafe { end.write_unaligned(input.add(end_index) as *mut u8) };
        }
        let negative = unsafe { input.add(start).read() } == b'-';
        return if is_nan {
            f64::NAN
        } else if negative {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }

    let mut index = number_start;
    let mut digits = 0usize;
    while index < 1_048_576 && unsafe { input.add(index).read() }.is_ascii_digit() {
        index += 1;
        digits += 1;
    }
    if index < 1_048_576 && unsafe { input.add(index).read() } == b'.' {
        index += 1;
        while index < 1_048_576 && unsafe { input.add(index).read() }.is_ascii_digit() {
            index += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        if !end.is_null() {
            unsafe { end.write_unaligned(input as *mut u8) };
        }
        return 0.0;
    }
    let mantissa_end = index;
    if index < 1_048_576 && matches!(unsafe { input.add(index).read() }, b'e' | b'E') {
        let mut exponent = index + 1;
        if matches!(unsafe { input.add(exponent).read() }, b'+' | b'-') {
            exponent += 1;
        }
        let exponent_digits = exponent;
        while exponent < 1_048_576 && unsafe { input.add(exponent).read() }.is_ascii_digit() {
            exponent += 1;
        }
        if exponent > exponent_digits {
            index = exponent;
        } else {
            index = mantissa_end;
        }
    }
    if !end.is_null() {
        unsafe { end.write_unaligned(input.add(index) as *mut u8) };
    }
    let text = unsafe { std::slice::from_raw_parts(input.add(start), index - start) };
    match std::str::from_utf8(text)
        .ok()
        .and_then(|text| text.parse::<f64>().ok())
    {
        Some(value) => {
            let mantissa_has_nonzero_digit = text
                .split(|byte| matches!(*byte, b'e' | b'E'))
                .next()
                .is_some_and(|mantissa| mantissa.iter().any(|byte| matches!(*byte, b'1'..=b'9')));
            if value.is_infinite() || (value == 0.0 && mantissa_has_nonzero_digit) {
                THREAD_CRT_ERRNO.with(|errno| errno.set(34)); // ERANGE
            }
            value
        }
        None => 0.0,
    }
}

pub(super) extern "win64" fn native_crt_time64(destination: *mut i64) -> i64 {
    let now = std::time::SystemTime::now();
    let seconds = match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().min(i64::MAX as u64) as i64,
        Err(error) => -(error.duration().as_secs().min(i64::MAX as u64) as i64),
    };
    if !destination.is_null() {
        unsafe { destination.write_unaligned(seconds) };
    }
    seconds
}

unsafe fn crt_compare_qsort_elements(
    base: *mut u8,
    element_size: usize,
    compare: unsafe extern "win64" fn(*const c_void, *const c_void) -> i32,
    left: usize,
    right: usize,
) -> i32 {
    let left = unsafe { base.add(left * element_size).cast() };
    let right = unsafe { base.add(right * element_size).cast() };
    unsafe { compare(left, right) }
}

pub(super) extern "win64" fn native_crt_qsort(
    base: *mut c_void,
    count: usize,
    element_size: usize,
    compare: u64,
) {
    if base.is_null() || count < 2 || element_size == 0 || compare == 0 {
        return;
    }
    let Some(total_size) = count.checked_mul(element_size) else {
        return;
    };
    if total_size > isize::MAX as usize {
        return;
    }
    let compare: unsafe extern "win64" fn(*const c_void, *const c_void) -> i32 =
        unsafe { std::mem::transmute(compare as usize) };
    let base = base.cast::<u8>();

    let sift_down = |mut root: usize, end: usize| loop {
        let Some(left) = root.checked_mul(2).and_then(|value| value.checked_add(1)) else {
            break;
        };
        if left >= end {
            break;
        }
        let mut larger = left;
        let right = left + 1;
        if right < end
            && unsafe { crt_compare_qsort_elements(base, element_size, compare, left, right) } < 0
        {
            larger = right;
        }
        if unsafe { crt_compare_qsort_elements(base, element_size, compare, root, larger) } >= 0 {
            break;
        }
        unsafe {
            std::ptr::swap_nonoverlapping(
                base.add(root * element_size),
                base.add(larger * element_size),
                element_size,
            );
        }
        root = larger;
    };

    for start in (0..count / 2).rev() {
        sift_down(start, count);
    }
    for end in (1..count).rev() {
        unsafe { std::ptr::swap_nonoverlapping(base, base.add(end * element_size), element_size) };
        sift_down(0, end);
    }
}
pub(super) extern "win64" fn native_crt_tolower(value: i32) -> i32 {
    if (b'A' as i32..=b'Z' as i32).contains(&value) {
        value + (b'a' - b'A') as i32
    } else {
        value
    }
}
pub(super) extern "win64" fn native_crt_toupper(value: i32) -> i32 {
    if (b'a' as i32..=b'z' as i32).contains(&value) {
        value - (b'a' - b'A') as i32
    } else {
        value
    }
}
pub(super) extern "win64" fn native_crt_strncpy(
    output: *mut u8,
    input: *const u8,
    count: usize,
) -> *mut u8 {
    if count == 0 {
        return output;
    }
    let mut index = 0usize;
    while index < count {
        let byte = unsafe { input.add(index).read() };
        unsafe { output.add(index).write(byte) };
        index += 1;
        if byte == 0 {
            while index < count {
                unsafe { output.add(index).write(0) };
                index += 1;
            }
            break;
        }
    }
    output
}
pub(super) extern "win64" fn native_crt_wcstombs(
    output: *mut u8,
    input: *const u16,
    count: usize,
) -> usize {
    if input.is_null() {
        return usize::MAX;
    }
    let mut converted = 0usize;
    for index in 0..32768usize {
        if !output.is_null() && converted == count {
            return converted;
        }
        let wide = unsafe { input.add(index).read() };
        if wide == 0 {
            if !output.is_null() && converted < count {
                unsafe { output.add(converted).write(0) };
            }
            return converted;
        }
        if wide > 0x7f {
            THREAD_CRT_ERRNO.with(|error| error.set(42)); // EILSEQ in the C locale.
            return usize::MAX;
        }
        if !output.is_null() && converted < count {
            unsafe { output.add(converted).write(wide as u8) };
        }
        converted += 1;
    }
    THREAD_CRT_ERRNO.with(|error| error.set(22)); // EINVAL: no terminator in bounded scan.
    usize::MAX
}
pub(super) extern "win64" fn native_crt_mbstowcs(
    output: *mut u16,
    input: *const u8,
    count: usize,
) -> usize {
    if input.is_null() {
        return usize::MAX;
    }
    let mut converted = 0usize;
    for index in 0..32768usize {
        if !output.is_null() && converted == count {
            return converted;
        }
        let byte = unsafe { input.add(index).read() };
        if byte == 0 {
            if !output.is_null() && converted < count {
                unsafe { output.add(converted).write(0) };
            }
            return converted;
        }
        // Win-Runner's CRT currently uses the C locale: multibyte input is
        // ASCII, with bytes outside that range reported as EILSEQ.
        if byte > 0x7f {
            THREAD_CRT_ERRNO.with(|error| error.set(42));
            return usize::MAX;
        }
        if !output.is_null() && converted < count {
            unsafe { output.add(converted).write(byte as u16) };
        }
        converted += 1;
    }
    THREAD_CRT_ERRNO.with(|error| error.set(22));
    usize::MAX
}
pub(super) extern "win64" fn native_crt_stat64(path: *const u8, output: *mut u8) -> i32 {
    if path.is_null() || output.is_null() {
        THREAD_CRT_ERRNO.with(|error| error.set(22)); // EINVAL
        return -1;
    }
    let Some(wide_path) = native_ansi_path(path) else {
        THREAD_CRT_ERRNO.with(|error| error.set(2)); // ENOENT
        return -1;
    };
    let path =
        String::from_utf16_lossy(wide_path.strip_suffix(&[0]).unwrap_or(wide_path.as_slice()));
    let Some(context) = fs_ctx() else {
        THREAD_CRT_ERRNO.with(|error| error.set(2));
        return -1;
    };
    let Ok(ctx) = context.lock() else {
        THREAD_CRT_ERRNO.with(|error| error.set(22));
        return -1;
    };
    let is_directory = ctx.fs.is_dir(&path);
    let is_file = ctx.fs.is_file(&path);
    if !is_directory && !is_file {
        THREAD_CRT_ERRNO.with(|error| error.set(2));
        return -1;
    }

    // MSVC's x64 __stat64 layout: scalar fields through st_rdev, then
    // 8-byte aligned size and three 64-bit Unix timestamps.
    unsafe { std::ptr::write_bytes(output, 0, 56) };
    let device = path
        .as_bytes()
        .first()
        .filter(|_| path.as_bytes().get(1) == Some(&b':'))
        .map(|letter| letter.to_ascii_uppercase().saturating_sub(b'A'))
        .unwrap_or(2) as u32;
    let inode = ctx.fs.file_id(&path).unwrap_or_default() as u16;
    let mode = if is_directory {
        0x4000u16
    } else {
        0x8000u16 | 0x0180
    };
    unsafe {
        output.cast::<u32>().write_unaligned(device);
        output.add(4).cast::<u16>().write_unaligned(inode);
        output.add(6).cast::<u16>().write_unaligned(mode);
        output.add(8).cast::<u16>().write_unaligned(1);
        output.add(14).cast::<u32>().write_unaligned(device);
        output.add(24).cast::<i64>().write_unaligned(if is_file {
            ctx.fs.file_len(&path).unwrap_or_default() as i64
        } else {
            0
        });
    }
    let metadata = ctx.fs.file_metadata(&path);
    let to_unix_seconds = |filetime: u64| (filetime / 10_000_000) as i64 - 11_644_473_600i64;
    unsafe {
        output
            .add(32)
            .cast::<i64>()
            .write_unaligned(to_unix_seconds(metadata.access_time));
        output
            .add(40)
            .cast::<i64>()
            .write_unaligned(to_unix_seconds(metadata.write_time));
        output
            .add(48)
            .cast::<i64>()
            .write_unaligned(to_unix_seconds(metadata.creation_time));
    }
    0
}
pub(super) extern "win64" fn native_crt_access(path: *const u8, mode: i32) -> i32 {
    if path.is_null() || !(0..=6).contains(&mode) || mode & !6 != 0 {
        THREAD_CRT_ERRNO.with(|error| error.set(22)); // EINVAL
        return -1;
    }
    let Some(wide_path) = native_ansi_path(path) else {
        THREAD_CRT_ERRNO.with(|error| error.set(2));
        return -1;
    };
    let path =
        String::from_utf16_lossy(wide_path.strip_suffix(&[0]).unwrap_or(wide_path.as_slice()));
    let exists = fs_ctx().is_some_and(|context| {
        context
            .lock()
            .is_ok_and(|ctx| ctx.fs.is_file(&path) || ctx.fs.is_dir(&path))
    });
    if exists {
        0
    } else {
        THREAD_CRT_ERRNO.with(|error| error.set(2));
        -1
    }
}
pub(super) extern "win64" fn native_crt_sprintf(
    output: *mut u8,
    format: *const u8,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
) -> i32 {
    if output.is_null() || format.is_null() {
        return -1;
    }
    let args = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9];
    let mut arg = 0usize;
    let mut index = 0usize;
    let mut result = Vec::new();
    while index < 1_048_576 {
        let ch = unsafe { format.add(index).read() };
        if ch == 0 {
            break;
        }
        index += 1;
        if ch != b'%' {
            result.push(ch);
            continue;
        }
        if unsafe { format.add(index).read() } == b'%' {
            result.push(b'%');
            index += 1;
            continue;
        }
        let mut zero_pad = false;
        if unsafe { format.add(index).read() } == b'0' {
            zero_pad = true;
            index += 1;
        }
        let mut width = 0usize;
        while unsafe { format.add(index).read() }.is_ascii_digit() {
            width = (width * 10 + (unsafe { format.add(index).read() } - b'0') as usize).min(4096);
            index += 1;
        }
        let mut precision = None;
        if unsafe { format.add(index).read() } == b'.' {
            index += 1;
            let mut value = 0usize;
            while unsafe { format.add(index).read() }.is_ascii_digit() {
                value =
                    (value * 10 + (unsafe { format.add(index).read() } - b'0') as usize).min(4096);
                index += 1;
            }
            precision = Some(value);
        }
        let mut long_long = false;
        if unsafe { format.add(index).read() } == b'l' {
            index += 1;
            if unsafe { format.add(index).read() } == b'l' {
                long_long = true;
                index += 1;
            }
        } else if matches!(unsafe { format.add(index).read() }, b'z' | b'I') {
            long_long = true;
            index += 1;
        }
        let spec = unsafe { format.add(index).read() };
        if spec == 0 {
            break;
        }
        index += 1;
        let value = args.get(arg).copied().unwrap_or(0);
        arg += 1;
        let mut part = match spec {
            b's' => {
                let mut bytes = Vec::new();
                if value != 0 {
                    for offset in 0..1_048_576usize {
                        let byte = unsafe { (value as *const u8).add(offset).read() };
                        if byte == 0 {
                            break;
                        }
                        bytes.push(byte);
                    }
                } else {
                    bytes.extend_from_slice(b"(null)");
                }
                if let Some(limit) = precision {
                    bytes.truncate(limit);
                }
                bytes
            }
            b'c' => vec![value as u8],
            b'd' | b'i' => {
                let number = if long_long {
                    value as i64
                } else {
                    value as i32 as i64
                };
                number.to_string().into_bytes()
            }
            b'u' => {
                let number = if long_long {
                    value
                } else {
                    value as u32 as u64
                };
                number.to_string().into_bytes()
            }
            b'x' | b'X' | b'p' => {
                let number = if spec == b'p' || long_long {
                    value
                } else {
                    value as u32 as u64
                };
                let mut digits = format!("{number:x}").into_bytes();
                if spec == b'X' {
                    digits.make_ascii_uppercase();
                }
                if spec == b'p' {
                    let mut prefixed = b"0x".to_vec();
                    prefixed.extend(digits);
                    prefixed
                } else {
                    digits
                }
            }
            _ => return -1,
        };
        if part.len() < width {
            let pad = width - part.len();
            let byte = if zero_pad { b'0' } else { b' ' };
            let mut padded = Vec::with_capacity(width);
            if zero_pad && part.first() == Some(&b'-') {
                padded.push(b'-');
                padded.resize(1 + pad, b'0');
                padded.extend_from_slice(&part[1..]);
            } else {
                padded.resize(pad, byte);
                padded.extend_from_slice(&part);
            }
            part = padded;
        }
        result.extend(part);
        if result.len() > 1_048_576 {
            return -1;
        }
    }
    unsafe {
        output.copy_from_nonoverlapping(result.as_ptr(), result.len());
        output.add(result.len()).write(0);
    }
    result.len() as i32
}
pub(super) extern "win64" fn native_crt_wcscmp(left: *const u16, right: *const u16) -> i32 {
    for index in 0..1_048_576usize {
        let (a, b) = unsafe { (left.add(index).read(), right.add(index).read()) };
        if a != b || a == 0 {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
pub(super) extern "win64" fn native_crt_wcslen(input: *const u16) -> usize {
    for length in 0..1_048_576usize {
        if unsafe { input.add(length).read() } == 0 {
            return length;
        }
    }
    1_048_576
}
pub(super) extern "win64" fn native_crt_wcsncmp(
    left: *const u16,
    right: *const u16,
    count: usize,
) -> i32 {
    for index in 0..count.min(1_048_576) {
        let (a, b) = unsafe { (left.add(index).read(), right.add(index).read()) };
        if a != b || a == 0 {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
pub(super) extern "win64" fn native_crt_wcschr(input: *const u16, value: u32) -> *mut u16 {
    let value = value as u16;
    for index in 0..1_048_576usize {
        let current = unsafe { input.add(index).read() };
        if current == value {
            return unsafe { input.add(index).cast_mut() };
        }
        if current == 0 {
            return std::ptr::null_mut();
        }
    }
    std::ptr::null_mut()
}
pub(super) extern "win64" fn native_crt_wcsrchr(input: *const u16, value: u32) -> *mut u16 {
    let value = value as u16;
    let mut found = std::ptr::null_mut();
    for index in 0..1_048_576usize {
        let current = unsafe { input.add(index).read() };
        if current == value {
            found = unsafe { input.add(index).cast_mut() };
        }
        if current == 0 {
            return found;
        }
    }
    found
}
pub(super) extern "win64" fn native_crt_wcscpy(output: *mut u16, input: *const u16) -> *mut u16 {
    for index in 0..1_048_576usize {
        let value = unsafe { input.add(index).read() };
        unsafe { output.add(index).write(value) };
        if value == 0 {
            break;
        }
    }
    output
}
pub(super) extern "win64" fn native_crt_wcsncpy(
    output: *mut u16,
    input: *const u16,
    count: usize,
) -> *mut u16 {
    let mut index = 0usize;
    while index < count.min(1_048_576) {
        let value = unsafe { input.add(index).read() };
        unsafe { output.add(index).write(value) };
        index += 1;
        if value == 0 {
            while index < count.min(1_048_576) {
                unsafe { output.add(index).write(0) };
                index += 1;
            }
            break;
        }
    }
    output
}
pub(super) extern "win64" fn native_crt_wcscat(output: *mut u16, input: *const u16) -> *mut u16 {
    let length = native_crt_wcslen(output);
    if length < 1_048_576 {
        unsafe { native_crt_wcscpy(output.add(length), input) };
    }
    output
}
pub(super) extern "win64" fn native_crt_wcsncat(
    output: *mut u16,
    input: *const u16,
    count: usize,
) -> *mut u16 {
    let length = native_crt_wcslen(output);
    if length >= 1_048_576 {
        return output;
    }
    let limit = count.min(1_048_575usize.saturating_sub(length));
    let mut copied = 0usize;
    while copied < limit {
        let value = unsafe { input.add(copied).read() };
        if value == 0 {
            break;
        }
        unsafe { output.add(length + copied).write(value) };
        copied += 1;
    }
    unsafe { output.add(length + copied).write(0) };
    output
}
pub(super) extern "win64" fn native_crt_wcsstr(
    haystack: *const u16,
    needle: *const u16,
) -> *mut u16 {
    if haystack.is_null() || needle.is_null() {
        return std::ptr::null_mut();
    }
    let mut needle_len = 0usize;
    while needle_len < 32768 && unsafe { needle.add(needle_len).read() } != 0 {
        needle_len += 1;
    }
    if needle_len == 0 {
        return haystack.cast_mut();
    }
    let mut offset = 0usize;
    while offset < 1_048_576 {
        if unsafe { haystack.add(offset).read() } == 0 {
            return std::ptr::null_mut();
        }
        let mut matched = true;
        for index in 0..needle_len {
            if unsafe { haystack.add(offset + index).read() != needle.add(index).read() } {
                matched = false;
                break;
            }
        }
        if matched {
            return haystack.wrapping_add(offset) as *mut u16;
        }
        offset += 1;
    }
    std::ptr::null_mut()
}
pub(super) extern "win64" fn native_crt_fflush(_file: *mut u8) -> i32 {
    0
}

fn crt_read_argument(arguments: *mut c_void, index: &mut usize, limit: usize) -> Option<u64> {
    if arguments.is_null() || *index >= limit {
        return None;
    }
    let address = (arguments as usize).checked_add(index.checked_mul(8)?)?;
    *index += 1;
    Some(unsafe { (address as *const u64).read_unaligned() })
}

fn crt_read_argument_string(pointer: u64) -> Vec<u8> {
    if pointer == 0 {
        return b"(null)".to_vec();
    }
    let pointer = pointer as *const u8;
    let mut output = Vec::new();
    for index in 0..1_048_576usize {
        let byte = unsafe { pointer.add(index).read() };
        if byte == 0 {
            break;
        }
        output.push(byte);
    }
    output
}

fn crt_format_narrow(format: *const u8, arguments: *mut c_void) -> Option<Vec<u8>> {
    crt_format_narrow_limited(format, arguments, 256)
}

fn crt_format_narrow_limited(
    format: *const u8,
    arguments: *mut c_void,
    argument_limit: usize,
) -> Option<Vec<u8>> {
    if format.is_null() {
        return None;
    }
    const MAX_FORMAT_BYTES: usize = 65_536;
    const MAX_OUTPUT_BYTES: usize = 1_048_576;
    let format_byte = |offset: usize| -> Option<u8> {
        (offset < MAX_FORMAT_BYTES).then(|| unsafe { format.add(offset).read() })
    };
    let mut output = Vec::new();
    let mut arg_index = 0usize;
    let mut cursor = 0usize;
    while cursor < MAX_FORMAT_BYTES {
        let byte = format_byte(cursor)?;
        cursor += 1;
        if byte == 0 {
            return Some(output);
        }
        if byte != b'%' {
            output.push(byte);
            continue;
        }
        if format_byte(cursor)? == b'%' {
            cursor += 1;
            output.push(b'%');
            continue;
        }
        let mut left = false;
        let mut plus = false;
        let mut space = false;
        let mut zero = false;
        let mut alternate = false;
        loop {
            match format_byte(cursor)? {
                b'-' => left = true,
                b'+' => plus = true,
                b' ' => space = true,
                b'0' => zero = true,
                b'#' => alternate = true,
                _ => break,
            }
            cursor += 1;
        }
        let mut width = 0usize;
        if format_byte(cursor)? == b'*' {
            let value = crt_read_argument(arguments, &mut arg_index, argument_limit)? as i32;
            cursor += 1;
            if value < 0 {
                left = true;
                width = (value.unsigned_abs() as usize).min(MAX_OUTPUT_BYTES);
            } else {
                width = (value as usize).min(MAX_OUTPUT_BYTES);
            }
        } else {
            while cursor < MAX_FORMAT_BYTES {
                let digit = format_byte(cursor)?;
                if !digit.is_ascii_digit() {
                    break;
                }
                width = width
                    .saturating_mul(10)
                    .saturating_add(usize::from(digit - b'0'))
                    .min(MAX_OUTPUT_BYTES);
                cursor += 1;
            }
        }
        let mut precision = None;
        if format_byte(cursor)? == b'.' {
            cursor += 1;
            if format_byte(cursor)? == b'*' {
                let value = crt_read_argument(arguments, &mut arg_index, argument_limit)? as i32;
                cursor += 1;
                if value >= 0 {
                    precision = Some((value as usize).min(MAX_OUTPUT_BYTES));
                }
            } else {
                let mut value = 0usize;
                while cursor < MAX_FORMAT_BYTES {
                    let digit = format_byte(cursor)?;
                    if !digit.is_ascii_digit() {
                        break;
                    }
                    value = value
                        .saturating_mul(10)
                        .saturating_add(usize::from(digit - b'0'))
                        .min(MAX_OUTPUT_BYTES);
                    cursor += 1;
                }
                precision = Some(value);
            }
        }
        let mut integer_bits = 32u32;
        if format_byte(cursor)? == b'I'
            && format_byte(cursor + 1)? == b'6'
            && format_byte(cursor + 2)? == b'4'
        {
            cursor += 3;
            integer_bits = 64;
        } else if format_byte(cursor)? == b'h' {
            cursor += 1;
            if format_byte(cursor)? == b'h' {
                cursor += 1;
                integer_bits = 8;
            } else {
                integer_bits = 16;
            }
        } else if format_byte(cursor)? == b'l' && format_byte(cursor + 1)? == b'l' {
            cursor += 2;
            integer_bits = 64;
        } else if matches!(format_byte(cursor)?, b'z' | b't') {
            cursor += 1;
            integer_bits = 64;
        } else {
            while matches!(
                format_byte(cursor)?,
                b'h' | b'l' | b'z' | b't' | b'L' | b'w'
            ) {
                cursor += 1;
            }
        }
        let specifier = format_byte(cursor)?;
        if specifier == 0 {
            return None;
        }
        cursor += 1;
        if specifier == b'n' {
            let pointer = crt_read_argument(arguments, &mut arg_index, argument_limit)? as *mut i32;
            unsafe { pointer.write_unaligned(output.len() as i32) };
            continue;
        }
        let mut field = match specifier {
            b's' => {
                let value = crt_read_argument(arguments, &mut arg_index, argument_limit)?;
                let mut value = crt_read_argument_string(value);
                if let Some(limit) = precision {
                    value.truncate(limit);
                }
                if width > value.len() {
                    let padding = width - value.len();
                    if left {
                        output.extend_from_slice(&value);
                        output.resize(output.len() + padding, b' ');
                    } else {
                        output.resize(output.len() + padding, b' ');
                        output.extend_from_slice(&value);
                    }
                } else {
                    output.extend_from_slice(&value);
                }
                if output.len() > MAX_OUTPUT_BYTES {
                    return None;
                }
                continue;
            }
            b'c' => vec![crt_read_argument(arguments, &mut arg_index, argument_limit)? as u8],
            b'd' | b'i' => {
                let raw = crt_read_argument(arguments, &mut arg_index, argument_limit)?;
                let value = match integer_bits {
                    8 => raw as i8 as i64,
                    16 => raw as i16 as i64,
                    32 => raw as i32 as i64,
                    _ => raw as i64,
                };
                let mut rendered = value.unsigned_abs().to_string();
                if let Some(precision) = precision {
                    if rendered.len() < precision {
                        rendered.insert_str(0, &"0".repeat(precision - rendered.len()));
                    }
                }
                if value < 0 {
                    rendered.insert(0, '-');
                } else if plus {
                    rendered.insert(0, '+');
                } else if space {
                    rendered.insert(0, ' ');
                }
                rendered.into_bytes()
            }
            b'u' | b'x' | b'X' | b'o' => {
                let raw = crt_read_argument(arguments, &mut arg_index, argument_limit)?;
                let value = match integer_bits {
                    8 => raw as u8 as u64,
                    16 => raw as u16 as u64,
                    32 => raw as u32 as u64,
                    _ => raw,
                };
                let mut rendered = match specifier {
                    b'x' => format!("{value:x}"),
                    b'X' => format!("{value:X}"),
                    b'o' => format!("{value:o}"),
                    _ => value.to_string(),
                };
                if let Some(precision) = precision {
                    if rendered.len() < precision {
                        rendered.insert_str(0, &"0".repeat(precision - rendered.len()));
                    }
                }
                if alternate && specifier == b'x' {
                    rendered.insert_str(0, "0x");
                } else if alternate && specifier == b'X' {
                    rendered.insert_str(0, "0X");
                } else if alternate && specifier == b'o' && !rendered.starts_with('0') {
                    rendered.insert(0, '0');
                }
                rendered.into_bytes()
            }
            b'p' => format!(
                "0x{:x}",
                crt_read_argument(arguments, &mut arg_index, argument_limit)?
            )
            .into_bytes(),
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                let value = f64::from_bits(crt_read_argument(
                    arguments,
                    &mut arg_index,
                    argument_limit,
                )?);
                let rendered = match (specifier, precision) {
                    (b'e' | b'E', Some(precision)) => format!("{value:.precision$e}"),
                    (_, Some(precision)) => format!("{value:.precision$}"),
                    (b'e' | b'E', None) => format!("{value:e}"),
                    _ => value.to_string(),
                };
                rendered.into_bytes()
            }
            _ => {
                output.extend_from_slice(&[b'%', specifier]);
                continue;
            }
        };
        if width > field.len() {
            let padding = width - field.len();
            if left {
                field.resize(field.len() + padding, b' ');
            } else if zero {
                let sign = usize::from(matches!(field.first(), Some(b'-' | b'+' | b' ')));
                field.splice(sign..sign, std::iter::repeat_n(b'0', padding));
            } else {
                field.splice(0..0, std::iter::repeat_n(b' ', padding));
            }
        }
        output.extend_from_slice(&field);
        if output.len() > MAX_OUTPUT_BYTES {
            return None;
        }
    }
    None
}

fn crt_read_argument_wide_string(pointer: u64, limit: usize) -> Option<Vec<u16>> {
    if pointer == 0 {
        return Some("(null)".encode_utf16().collect());
    }
    let pointer = pointer as *const u16;
    let mut output = Vec::new();
    for index in 0..limit.min(1_048_576) {
        let unit = unsafe { pointer.add(index).read() };
        if unit == 0 {
            return Some(output);
        }
        output.push(unit);
    }
    None
}

fn crt_format_wide(format: *const u16, arguments: *mut c_void) -> Option<Vec<u16>> {
    const MAX_FORMAT_UNITS: usize = 1_048_576;
    const MAX_OUTPUT_UNITS: usize = 1_048_576;
    if format.is_null() {
        return None;
    }
    let mut output = Vec::new();
    let mut arg_index = 0usize;
    let mut cursor = 0usize;
    let read_format = |offset: usize| {
        if offset >= MAX_FORMAT_UNITS {
            0
        } else {
            unsafe { format.add(offset).read() }
        }
    };
    while cursor < MAX_FORMAT_UNITS {
        let unit = read_format(cursor);
        if unit == 0 {
            return Some(output);
        }
        cursor += 1;
        if unit != b'%' as u16 {
            output.push(unit);
            continue;
        }
        if read_format(cursor) == b'%' as u16 {
            cursor += 1;
            output.push(b'%' as u16);
            continue;
        }

        let mut left = false;
        let mut plus = false;
        let mut space = false;
        let mut zero = false;
        let mut alternate = false;
        loop {
            match read_format(cursor) {
                value if value == b'-' as u16 => left = true,
                value if value == b'+' as u16 => plus = true,
                value if value == b' ' as u16 => space = true,
                value if value == b'0' as u16 => zero = true,
                value if value == b'#' as u16 => alternate = true,
                _ => break,
            }
            cursor += 1;
        }

        let mut width = 0usize;
        if read_format(cursor) == b'*' as u16 {
            let value = crt_read_argument(arguments, &mut arg_index, 256)? as i32;
            cursor += 1;
            if value < 0 {
                left = true;
                width = value.unsigned_abs() as usize;
            } else {
                width = value as usize;
            }
        } else {
            while (b'0' as u16..=b'9' as u16).contains(&read_format(cursor)) {
                width = width
                    .saturating_mul(10)
                    .saturating_add(usize::from(read_format(cursor) - b'0' as u16))
                    .min(MAX_OUTPUT_UNITS);
                cursor += 1;
            }
        }
        width = width.min(MAX_OUTPUT_UNITS);
        let mut precision = None;
        if read_format(cursor) == b'.' as u16 {
            cursor += 1;
            if read_format(cursor) == b'*' as u16 {
                let value = crt_read_argument(arguments, &mut arg_index, 256)? as i32;
                cursor += 1;
                if value >= 0 {
                    precision = Some((value as usize).min(MAX_OUTPUT_UNITS));
                }
            } else {
                let mut value = 0usize;
                while (b'0' as u16..=b'9' as u16).contains(&read_format(cursor)) {
                    value = value
                        .saturating_mul(10)
                        .saturating_add(usize::from(read_format(cursor) - b'0' as u16))
                        .min(MAX_OUTPUT_UNITS);
                    cursor += 1;
                }
                precision = Some(value);
            }
        }

        let mut integer_bits = 32u32;
        let mut narrow_string = false;
        match read_format(cursor) {
            value
                if value == b'I' as u16
                    && read_format(cursor + 1) == b'6' as u16
                    && read_format(cursor + 2) == b'4' as u16 =>
            {
                cursor += 3;
                integer_bits = 64;
            }
            value if value == b'h' as u16 => {
                cursor += 1;
                if read_format(cursor) == b'h' as u16 {
                    cursor += 1;
                    integer_bits = 8;
                } else {
                    integer_bits = 16;
                }
                narrow_string = true;
            }
            value if value == b'l' as u16 => {
                cursor += 1;
                if read_format(cursor) == b'l' as u16 {
                    cursor += 1;
                    integer_bits = 64;
                } else if matches!(read_format(cursor), value if value == b'd' as u16 || value == b'i' as u16 || value == b'u' as u16 || value == b'x' as u16 || value == b'X' as u16 || value == b'o' as u16)
                {
                    integer_bits = 64;
                }
            }
            value if matches!(value, value if value == b'z' as u16 || value == b't' as u16) => {
                cursor += 1;
                integer_bits = 64;
            }
            value if value == b'w' as u16 => {
                cursor += 1;
            }
            _ => {}
        }
        let specifier_unit = read_format(cursor);
        if specifier_unit == 0 || specifier_unit > u8::MAX as u16 {
            return None;
        }
        let specifier = specifier_unit as u8;
        cursor += 1;
        if specifier == b'n' {
            let pointer = crt_read_argument(arguments, &mut arg_index, 256)? as *mut i32;
            unsafe { pointer.write_unaligned(output.len().min(i32::MAX as usize) as i32) };
            continue;
        }

        let mut field = match specifier {
            b's' => {
                let pointer = crt_read_argument(arguments, &mut arg_index, 256)?;
                let mut text = if narrow_string {
                    crt_read_argument_string(pointer)
                        .into_iter()
                        .map(u16::from)
                        .collect::<Vec<_>>()
                } else {
                    crt_read_argument_wide_string(pointer, MAX_OUTPUT_UNITS)?
                };
                if let Some(limit) = precision {
                    text.truncate(limit);
                }
                if text.len() < width {
                    let pad = width - text.len();
                    if left {
                        text.resize(text.len() + pad, b' ' as u16);
                        output.extend(text);
                    } else {
                        output.resize(output.len() + pad, b' ' as u16);
                        output.extend(text);
                    }
                } else {
                    output.extend(text);
                }
                if output.len() > MAX_OUTPUT_UNITS {
                    return None;
                }
                continue;
            }
            b'c' => {
                let value = crt_read_argument(arguments, &mut arg_index, 256)?;
                vec![if narrow_string {
                    value as u8 as u16
                } else {
                    value as u16
                }]
            }
            b'd' | b'i' => {
                let raw = crt_read_argument(arguments, &mut arg_index, 256)?;
                let value = match integer_bits {
                    8 => raw as i8 as i64,
                    16 => raw as i16 as i64,
                    32 => raw as i32 as i64,
                    _ => raw as i64,
                };
                let mut rendered = value.unsigned_abs().to_string();
                if let Some(precision) = precision {
                    if rendered.len() < precision {
                        rendered.insert_str(0, &"0".repeat(precision - rendered.len()));
                    }
                }
                if value < 0 {
                    rendered.insert(0, '-');
                } else if plus {
                    rendered.insert(0, '+');
                } else if space {
                    rendered.insert(0, ' ');
                }
                rendered.encode_utf16().collect()
            }
            b'u' | b'x' | b'X' | b'o' => {
                let raw = crt_read_argument(arguments, &mut arg_index, 256)?;
                let value = match integer_bits {
                    8 => raw as u8 as u64,
                    16 => raw as u16 as u64,
                    32 => raw as u32 as u64,
                    _ => raw,
                };
                let mut rendered = match specifier {
                    b'x' => format!("{value:x}"),
                    b'X' => format!("{value:X}"),
                    b'o' => format!("{value:o}"),
                    _ => value.to_string(),
                };
                if let Some(precision) = precision {
                    if rendered.len() < precision {
                        rendered.insert_str(0, &"0".repeat(precision - rendered.len()));
                    }
                }
                if alternate && specifier == b'x' {
                    rendered.insert_str(0, "0x");
                } else if alternate && specifier == b'X' {
                    rendered.insert_str(0, "0X");
                } else if alternate && specifier == b'o' && !rendered.starts_with('0') {
                    rendered.insert(0, '0');
                }
                rendered.encode_utf16().collect()
            }
            b'p' => format!("0x{:x}", crt_read_argument(arguments, &mut arg_index, 256)?)
                .encode_utf16()
                .collect(),
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                let value = f64::from_bits(crt_read_argument(arguments, &mut arg_index, 256)?);
                let mut rendered = match (specifier, precision) {
                    (b'e' | b'E', Some(precision)) => format!("{value:.precision$e}"),
                    (_, Some(precision)) => format!("{value:.precision$}"),
                    (b'e' | b'E', None) => format!("{value:e}"),
                    _ => value.to_string(),
                };
                if specifier.is_ascii_uppercase() {
                    rendered.make_ascii_uppercase();
                }
                rendered.encode_utf16().collect()
            }
            _ => return None,
        };

        if precision.is_some() && matches!(specifier, b'd' | b'i' | b'u' | b'x' | b'X' | b'o') {
            zero = false;
        }

        if width > field.len() {
            let padding = width - field.len();
            let pad = if zero && !left {
                b'0' as u16
            } else {
                b' ' as u16
            };
            if left {
                field.resize(field.len() + padding, b' ' as u16);
            } else if zero {
                let sign = usize::from(
                    field
                        .first()
                        .is_some_and(|unit| matches!(*unit, 45 | 43 | 32)),
                );
                field.splice(sign..sign, std::iter::repeat_n(pad, padding));
            } else {
                field.splice(0..0, std::iter::repeat_n(pad, padding));
            }
        }
        output.extend(field);
        if output.len() > MAX_OUTPUT_UNITS {
            return None;
        }
    }
    None
}

pub(super) extern "win64" fn native_crt_stdio_common_vfprintf(
    _options: u64,
    stream: *mut u8,
    format: *const u8,
    _locale: *mut c_void,
    arguments: *mut c_void,
) -> i32 {
    let Some(bytes) = crt_format_narrow(format, arguments) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return -1;
    };
    if native_crt_standard_stream_index(stream) == Some(0)
        || (native_crt_standard_stream_index(stream).is_none() && native_crt_file(stream).is_none())
    {
        THREAD_CRT_ERRNO.with(|errno| errno.set(9)); // EBADF
        return -1;
    }
    let written = native_crt_fwrite(bytes.as_ptr(), 1, bytes.len(), stream);
    if written != bytes.len() {
        return -1;
    }
    written as i32
}

pub(super) extern "win64" fn native_crt_stdio_common_vsprintf(
    _options: u64,
    output: *mut u8,
    output_count: usize,
    format: *const u8,
    _locale: *mut c_void,
    arguments: *mut c_void,
) -> i32 {
    if output.is_null() || output_count == 0 {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return -1;
    }
    let Some(bytes) = crt_format_narrow(format, arguments) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return -1;
    };
    let copied = bytes.len().min(output_count - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, copied);
        output.add(copied).write(0);
    }
    bytes.len().min(i32::MAX as usize) as i32
}

pub(super) extern "win64" fn native_crt_stdio_common_vswprintf(
    _options: u64,
    output: *mut u16,
    output_count: usize,
    format: *const u16,
    _locale: *mut c_void,
    arguments: *mut c_void,
) -> i32 {
    if output.is_null() || output_count == 0 {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return -1;
    }
    let Some(units) = crt_format_wide(format, arguments) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return -1;
    };
    let copied = units.len().min(output_count - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(units.as_ptr(), output, copied);
        output.add(copied).write(0);
    }
    units.len().min(i32::MAX as usize) as i32
}

fn native_crt_format_to_stream(stream: *mut u8, format: *const u8, arguments: &[u64]) -> i32 {
    let Some(bytes) =
        crt_format_narrow_limited(format, arguments.as_ptr() as *mut c_void, arguments.len())
    else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return -1;
    };
    let written = native_crt_fwrite(bytes.as_ptr(), 1, bytes.len(), stream);
    if written == bytes.len() {
        written.min(i32::MAX as usize) as i32
    } else {
        -1
    }
}

pub(super) extern "win64" fn native_crt_printf(
    format: *const u8,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
) -> i32 {
    native_crt_format_to_stream(
        native_crt_acrt_iob_func(1),
        format,
        &[a0, a1, a2, a3, a4, a5, a6, a7, a8, a9],
    )
}

pub(super) extern "win64" fn native_crt_fprintf(
    stream: *mut u8,
    format: *const u8,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
) -> i32 {
    native_crt_format_to_stream(stream, format, &[a0, a1, a2, a3, a4, a5, a6, a7, a8, a9])
}
pub(super) extern "win64" fn native_crt_fputs(input: *const u8, _file: *mut u8) -> i32 {
    let len = native_crt_strlen(input);
    if native_crt_fwrite(input, 1, len, _file) == len {
        0
    } else {
        -1
    }
}
pub(super) extern "win64" fn native_crt_fputc(byte: i32, file: *mut u8) -> i32 {
    let value = [byte as u8];
    if native_crt_fwrite(value.as_ptr(), 1, 1, file) == 1 {
        byte & 0xff
    } else {
        -1
    }
}
pub(super) extern "win64" fn native_crt_putchar(byte: i32) -> i32 {
    native_crt_fputc(byte, native_crt_acrt_iob_func(1))
}
pub(super) extern "win64" fn native_crt_getchar() -> i32 {
    native_crt_fgetc(native_crt_acrt_iob_func(0))
}
pub(super) extern "win64" fn native_crt_puts(input: *const u8) -> i32 {
    let output = native_crt_acrt_iob_func(1);
    if native_crt_fputs(input, output) < 0 || native_crt_fputc(b'\n' as i32, output) < 0 {
        -1
    } else {
        0
    }
}
pub(super) extern "win64" fn native_crt_fopen(path: *const u8, mode: *const u8) -> *mut u8 {
    if path.is_null() || mode.is_null() {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return std::ptr::null_mut();
    }
    let mut mode_bytes = Vec::new();
    for offset in 0..64usize {
        let byte = unsafe { mode.add(offset).read() };
        if byte == 0 {
            break;
        }
        mode_bytes.push(byte);
    }
    if mode_bytes.is_empty() || mode_bytes.len() == 64 {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return std::ptr::null_mut();
    }
    let mode_char = mode_bytes[0];
    if !matches!(mode_char, b'r' | b'w' | b'a')
        || mode_bytes[1..]
            .iter()
            .any(|flag| !matches!(flag, b'+' | b'b' | b't' | b'x' | b'c' | b'n' | b'S' | b'R'))
    {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return std::ptr::null_mut();
    }
    let update = mode_bytes.contains(&b'+');
    let exclusive = mode_bytes.contains(&b'x');
    if exclusive && !matches!(mode_char, b'w' | b'a') {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return std::ptr::null_mut();
    }
    let readable = mode_char == b'r' || update;
    let writable = mode_char != b'r' || update;
    let access =
        (if readable { 0x8000_0000 } else { 0 }) | (if writable { 0x4000_0000 } else { 0 });
    let creation = match (mode_char, exclusive) {
        (b'r', _) => 3,     // OPEN_EXISTING
        (b'w', false) => 2, // CREATE_ALWAYS
        (b'a', false) => 4, // OPEN_ALWAYS
        (_, true) => 1,     // CREATE_NEW
        _ => {
            THREAD_CRT_ERRNO.with(|errno| errno.set(22));
            return std::ptr::null_mut();
        }
    };
    let Some(wide_path) = native_ansi_path(path) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return std::ptr::null_mut();
    };
    let handle = native_create_file_w(wide_path.as_ptr(), access, 7, 0, creation, 0, 0);
    if handle == u64::MAX {
        THREAD_CRT_ERRNO.with(|errno| {
            errno.set(match native_get_last_error() {
                2 | 3 => 2, // ENOENT
                5 => 13,    // EACCES
                _ => 22,    // EINVAL
            });
        });
        return std::ptr::null_mut();
    }
    if mode_char == b'a' && native_set_file_pointer_ex(handle, 0, std::ptr::null_mut(), 2) == 0 {
        native_close_handle(handle);
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return std::ptr::null_mut();
    }
    let file = unsafe { malloc(std::mem::size_of::<NativeCrtFile>()) }.cast::<NativeCrtFile>();
    if file.is_null() {
        native_close_handle(handle);
        THREAD_CRT_ERRNO.with(|errno| errno.set(12)); // ENOMEM
        return std::ptr::null_mut();
    }
    unsafe {
        file.write(NativeCrtFile {
            signature: NATIVE_CRT_FILE_SIGNATURE,
            handle,
            readable: u8::from(readable),
            writable: u8::from(writable),
            append: u8::from(mode_char == b'a'),
            reserved: [0; 45],
        });
    }
    file.cast()
}

fn native_crt_file(stream: *mut u8) -> Option<*mut NativeCrtFile> {
    if stream.is_null() || native_crt_standard_stream_index(stream).is_some() {
        return None;
    }
    let file = stream.cast::<NativeCrtFile>();
    (unsafe { stream.cast::<u64>().read_unaligned() == NATIVE_CRT_FILE_SIGNATURE }).then_some(file)
}

pub(super) extern "win64" fn native_crt_fread(
    buffer: *mut u8,
    size: usize,
    count: usize,
    stream: *mut u8,
) -> usize {
    let Some(length) = size.checked_mul(count) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(75)); // EOVERFLOW
        return 0;
    };
    if length == 0 {
        return 0;
    }
    if buffer.is_null() || stream.is_null() {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return 0;
    }
    let (handle, readable, file_state) =
        if let Some(index) = native_crt_standard_stream_index(stream) {
            if index != 0 {
                THREAD_CRT_ERRNO.with(|errno| errno.set(9));
                return 0;
            }
            let Some(process) = process_ctx() else {
                return 0;
            };
            (process.std_handles[0].load(Ordering::Acquire), true, None)
        } else if let Some(file) = native_crt_file(stream) {
            (
                unsafe { (*file).handle },
                unsafe { (*file).readable != 0 },
                Some(file),
            )
        } else {
            THREAD_CRT_ERRNO.with(|errno| errno.set(9));
            return 0;
        };
    if !readable {
        if let Some(file) = file_state {
            unsafe { (*file).reserved[1] = 1 };
        }
        THREAD_CRT_ERRNO.with(|errno| errno.set(9));
        return 0;
    }
    if file_state.is_some_and(|file| unsafe { (*file).reserved[0] != 0 }) {
        return 0;
    }
    let mut total = 0usize;
    if let Some(file) = file_state {
        unsafe {
            if (*file).reserved[2] != 0 {
                buffer.write((*file).reserved[3]);
                (*file).reserved[2] = 0;
                total = 1;
            }
        }
    }
    while total < length {
        let chunk = (length - total).min(16 * 1024 * 1024) as u32;
        let mut received = 0u32;
        if native_read_file(
            handle,
            unsafe { buffer.add(total) },
            chunk,
            &mut received,
            0,
        ) == 0
        {
            if let Some(file) = file_state {
                unsafe { (*file).reserved[1] = 1 };
            }
            if total == 0 {
                THREAD_CRT_ERRNO.with(|errno| errno.set(5));
            }
            break;
        }
        total += received as usize;
        if received < chunk {
            if let Some(file) = file_state {
                unsafe { (*file).reserved[0] = 1 };
            }
            break;
        }
    }
    total / size
}

pub(super) extern "win64" fn native_crt_fclose(stream: *mut u8) -> i32 {
    if stream.is_null() {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return -1;
    }
    if native_crt_standard_stream_index(stream).is_some() {
        return 0;
    }
    let Some(file) = native_crt_file(stream) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(9));
        return -1;
    };
    let handle = unsafe { (*file).handle };
    unsafe { (*file).signature = 0 };
    unsafe { free(file.cast()) };
    if native_close_handle(handle) != 0 {
        0
    } else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(9));
        -1
    }
}

pub(super) extern "win64" fn native_crt_feof(stream: *mut u8) -> i32 {
    if native_crt_standard_stream_index(stream).is_some() {
        return 0;
    }
    let Some(file) = native_crt_file(stream) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(9));
        return 0;
    };
    i32::from(unsafe { (*file).reserved[0] != 0 })
}

pub(super) extern "win64" fn native_crt_ferror(stream: *mut u8) -> i32 {
    if native_crt_standard_stream_index(stream).is_some() {
        return 0;
    }
    let Some(file) = native_crt_file(stream) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(9));
        return 0;
    };
    i32::from(unsafe { (*file).reserved[1] != 0 })
}

pub(super) extern "win64" fn native_crt_clearerr(stream: *mut u8) {
    if let Some(file) = native_crt_file(stream) {
        unsafe {
            (*file).reserved[0] = 0;
            (*file).reserved[1] = 0;
        }
    }
}

pub(super) extern "win64" fn native_crt_fgetc(stream: *mut u8) -> i32 {
    let mut byte = 0u8;
    if native_crt_fread(&mut byte, 1, 1, stream) == 1 {
        i32::from(byte)
    } else {
        -1 // EOF
    }
}

pub(super) extern "win64" fn native_crt_ungetc(byte: i32, stream: *mut u8) -> i32 {
    if byte == -1 {
        return -1;
    }
    let Some(file) = native_crt_file(stream) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(9));
        return -1;
    };
    unsafe {
        if (*file).readable == 0 || (*file).reserved[2] != 0 {
            return -1;
        }
        (*file).reserved[2] = 1;
        (*file).reserved[3] = byte as u8;
        (*file).reserved[0] = 0;
    }
    byte as u8 as i32
}

pub(super) extern "win64" fn native_crt_fgets(
    output: *mut u8,
    capacity: i32,
    stream: *mut u8,
) -> *mut u8 {
    if output.is_null() || capacity <= 0 {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return std::ptr::null_mut();
    }
    if capacity == 1 {
        unsafe { output.write(0) };
        return output;
    }
    let mut length = 0usize;
    while length < (capacity - 1) as usize {
        let byte = native_crt_fgetc(stream);
        if byte < 0 {
            break;
        }
        unsafe { output.add(length).write(byte as u8) };
        length += 1;
        if byte == b'\n' as i32 {
            break;
        }
    }
    if length == 0 {
        return std::ptr::null_mut();
    }
    unsafe { output.add(length).write(0) };
    output
}

fn native_crt_file_handle_for_seek(stream: *mut u8) -> Option<u64> {
    let file = native_crt_file(stream)?;
    Some(unsafe { (*file).handle })
}

pub(super) extern "win64" fn native_crt_fseeki64(stream: *mut u8, offset: i64, origin: i32) -> i32 {
    let Some(handle) = native_crt_file_handle_for_seek(stream) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(9));
        return -1;
    };
    if !(0..=2).contains(&origin)
        || native_set_file_pointer_ex(handle, offset, std::ptr::null_mut(), origin as u32) == 0
    {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return -1;
    }
    if let Some(file) = native_crt_file(stream) {
        unsafe {
            (*file).reserved[0] = 0;
            (*file).reserved[2] = 0;
        }
    }
    0
}

pub(super) extern "win64" fn native_crt_fseek(stream: *mut u8, offset: i32, origin: i32) -> i32 {
    native_crt_fseeki64(stream, i64::from(offset), origin)
}

pub(super) extern "win64" fn native_crt_ftelli64(stream: *mut u8) -> i64 {
    let Some(handle) = native_crt_file_handle_for_seek(stream) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(9));
        return -1;
    };
    let mut position = 0i64;
    if native_set_file_pointer_ex(handle, 0, &mut position, 1) == 0 {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        -1
    } else {
        position
    }
}

pub(super) extern "win64" fn native_crt_ftell(stream: *mut u8) -> i32 {
    let position = native_crt_ftelli64(stream);
    if position < 0 {
        return -1;
    }
    match i32::try_from(position) {
        Ok(position) => position,
        Err(_) => {
            THREAD_CRT_ERRNO.with(|errno| errno.set(75)); // EOVERFLOW
            -1
        }
    }
}

pub(super) extern "win64" fn native_crt_rewind(stream: *mut u8) {
    if native_crt_fseeki64(stream, 0, 0) == 0 {
        native_crt_clearerr(stream);
        THREAD_CRT_ERRNO.with(|errno| errno.set(0));
    }
}
pub(super) extern "win64" fn native_crt_malloc(size: usize) -> *mut c_void {
    unsafe { malloc(size.max(1)) }
}
pub(super) extern "win64" fn native_crt_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    unsafe { realloc(ptr, size.max(1)) }
}
pub(super) extern "win64" fn native_crt_strdup(input: *const u8) -> *mut u8 {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let length = native_crt_strlen(input);
    let Some(allocation_size) = length.checked_add(1) else {
        return std::ptr::null_mut();
    };
    let output = native_crt_malloc(allocation_size).cast::<u8>();
    if output.is_null() {
        return output;
    }
    unsafe { std::ptr::copy_nonoverlapping(input, output, allocation_size) };
    output
}
pub(super) extern "win64" fn native_crt_calloc(count: usize, size: usize) -> *mut c_void {
    let Some(length) = count.checked_mul(size) else {
        return std::ptr::null_mut();
    };
    let ptr = unsafe { malloc(length.max(1)) };
    if !ptr.is_null() && length != 0 {
        unsafe { std::ptr::write_bytes(ptr, 0, length) };
    }
    ptr
}
pub(super) extern "win64" fn native_crt_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe { free(ptr) };
    }
}
pub(super) extern "win64" fn native_crt_fwrite(
    buffer: *const u8,
    size: usize,
    count: usize,
    stream: *mut u8,
) -> usize {
    let Some(length) = size.checked_mul(count) else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(75)); // EOVERFLOW
        return 0;
    };
    if size == 0 || length == 0 {
        return 0;
    }
    if buffer.is_null() || stream.is_null() {
        THREAD_CRT_ERRNO.with(|errno| errno.set(22));
        return 0;
    }
    let (handle, append, file_state) = if let Some(index) = native_crt_standard_stream_index(stream)
    {
        if index == 0 {
            THREAD_CRT_ERRNO.with(|errno| errno.set(9));
            return 0;
        }
        let Some(process) = process_ctx() else {
            return 0;
        };
        (
            process.std_handles[index].load(Ordering::Acquire),
            false,
            None,
        )
    } else if let Some(file) = native_crt_file(stream) {
        if unsafe { (*file).writable == 0 } {
            unsafe { (*file).reserved[1] = 1 };
            THREAD_CRT_ERRNO.with(|errno| errno.set(9));
            return 0;
        }
        (
            unsafe { (*file).handle },
            unsafe { (*file).append != 0 },
            Some(file),
        )
    } else {
        THREAD_CRT_ERRNO.with(|errno| errno.set(9));
        return 0;
    };
    if append && native_set_file_pointer_ex(handle, 0, std::ptr::null_mut(), 2) == 0 {
        if let Some(file) = file_state {
            unsafe { (*file).reserved[1] = 1 };
        }
        THREAD_CRT_ERRNO.with(|errno| errno.set(5));
        return 0;
    }
    let mut written = 0usize;
    while written < length {
        let chunk = (length - written).min(16 * 1024 * 1024) as u32;
        let mut chunk_written = 0u32;
        if native_write_file(
            handle,
            unsafe { buffer.add(written) },
            chunk,
            &mut chunk_written,
            0,
        ) == 0
        {
            if let Some(file) = file_state {
                unsafe { (*file).reserved[1] = 1 };
            }
            THREAD_CRT_ERRNO
                .with(|errno| errno.set(if native_get_last_error() == 5 { 13 } else { 5 }));
            break;
        }
        written += chunk_written as usize;
        if chunk_written < chunk {
            if let Some(file) = file_state {
                unsafe { (*file).reserved[1] = 1 };
            }
            break;
        }
    }
    written / size
}
pub(super) extern "win64" fn native_crt_memcmp(
    left: *const u8,
    right: *const u8,
    len: usize,
) -> i32 {
    for index in 0..len {
        let (a, b) = unsafe { (left.add(index).read(), right.add(index).read()) };
        if a != b {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
pub(super) extern "win64" fn native_crt_memcpy(
    output: *mut c_void,
    input: *const c_void,
    len: usize,
) -> *mut c_void {
    if len != 0 {
        unsafe { std::ptr::copy_nonoverlapping(input.cast::<u8>(), output.cast(), len) };
    }
    output
}
pub(super) extern "win64" fn native_crt_memmove(
    output: *mut c_void,
    input: *const c_void,
    len: usize,
) -> *mut c_void {
    if len != 0 {
        unsafe { std::ptr::copy(input.cast::<u8>(), output.cast(), len) };
    }
    output
}
pub(super) extern "win64" fn native_crt_memset(
    output: *mut c_void,
    value: i32,
    len: usize,
) -> *mut c_void {
    if len != 0 {
        unsafe { std::ptr::write_bytes(output.cast::<u8>(), value as u8, len) };
    }
    output
}
pub(super) extern "win64" fn native_crt_initterm(first: *const u64, last: *const u64) {
    if first.is_null() || last.is_null() {
        return;
    }
    let start = first as usize;
    let end = last as usize;
    if end < start || (end - start) % std::mem::size_of::<u64>() != 0 {
        return;
    }
    let count = ((end - start) / std::mem::size_of::<u64>()).min(4096);
    for index in 0..count {
        let address = unsafe { first.add(index).read_unaligned() };
        if address != 0 {
            let init: extern "win64" fn() = unsafe { std::mem::transmute(address as usize) };
            init();
        }
    }
}
pub(super) extern "win64" fn native_crt_getmainargs(
    argc_out: *mut i32,
    argv_out: *mut *mut *mut i8,
    env_out: *mut *mut *mut i8,
    _wildcard: i32,
    _startup: *mut u8,
) -> i32 {
    let Some(process) = process_ctx() else {
        return 12;
    };
    ensure_crt_startup(&process);
    let Ok(mut startup) = process.crt_startup.lock() else {
        return 12;
    };
    let Some(startup) = startup.as_mut() else {
        return 12;
    };
    unsafe {
        if !argc_out.is_null() {
            argc_out.write_unaligned(startup.argc);
        }
        if !argv_out.is_null() {
            argv_out.write_unaligned(startup.argv.as_mut_ptr().cast());
        }
        if !env_out.is_null() {
            env_out.write_unaligned(startup.environment.as_mut_ptr().cast());
        }
    }
    0
}

pub(super) extern "win64" fn native_crt_exit(code: u32) -> ! {
    native_crt_run_exit_handlers();
    native_exit_process(code)
}

#[cfg(test)]
mod startup_tests {
    use super::build_crt_startup;

    #[test]
    fn narrow_startup_arrays_keep_windows_arguments_and_environment_alive() {
        let environment = vec![("PATH".to_string(), "C:\\bin".to_string())];
        let mut startup = build_crt_startup(
            b"tool.exe \"hello world\" arg\0",
            &environment,
            r"C:\tools\tool.exe",
        );
        assert_eq!(startup.argc, 3);
        let argv = startup.argv.as_mut_ptr().cast::<*mut i8>();
        let read_arg = |index| unsafe { std::ffi::CStr::from_ptr(*argv.add(index)) };
        assert_eq!(read_arg(0).to_bytes(), b"tool.exe");
        assert_eq!(read_arg(1).to_bytes(), b"hello world");
        assert_eq!(read_arg(2).to_bytes(), b"arg");
        assert!(unsafe { (*argv.add(3)).is_null() });
        let env = startup.environment.as_mut_ptr().cast::<*mut i8>();
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(*env) }.to_bytes(),
            b"PATH=C:\\bin"
        );
        assert!(unsafe { (*env.add(1)).is_null() });
        assert_eq!(startup.argv_value, startup.argv.as_mut_ptr() as usize);
    }

    #[test]
    fn wide_startup_arrays_keep_utf16_arguments_and_environment_alive() {
        let environment = vec![("GREETING".to_string(), "héllo 🌍".to_string())];
        let mut startup = build_crt_startup(
            "tool.exe \"héllo 世界\" arg\0".as_bytes(),
            &environment,
            r"C:\工具\run.exe",
        );
        assert_eq!(startup.argc, 3);

        let argv = startup.wide_argv.as_mut_ptr().cast::<*mut u16>();
        let read_wide = |index| unsafe {
            let mut length = 0;
            while *(*argv.add(index)).add(length) != 0 {
                length += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(*argv.add(index), length)).unwrap()
        };
        assert_eq!(read_wide(0), "tool.exe");
        assert_eq!(read_wide(1), "héllo 世界");
        assert_eq!(read_wide(2), "arg");
        assert!(unsafe { (*argv.add(3)).is_null() });

        let env = startup.wide_environment.as_mut_ptr().cast::<*mut u16>();
        let mut length = 0;
        while unsafe { *(*env).add(length) != 0 } {
            length += 1;
        }
        assert_eq!(
            unsafe { String::from_utf16(std::slice::from_raw_parts(*env, length)).unwrap() },
            "GREETING=héllo 🌍"
        );
        assert!(unsafe { (*env.add(1)).is_null() });
        assert_eq!(
            startup.wide_argv_value,
            startup.wide_argv.as_mut_ptr() as usize
        );
        assert_eq!(
            startup.wide_environment_value,
            startup.wide_environment.as_mut_ptr() as usize
        );
        assert_eq!(
            std::ffi::CStr::from_bytes_with_nul(&startup._program_name_a_storage)
                .unwrap()
                .to_bytes(),
            r"C:\??\run.exe".as_bytes()
        );
        assert_eq!(
            String::from_utf16(
                &startup._program_name_w_storage[..startup._program_name_w_storage.len() - 1]
            )
            .unwrap(),
            r"C:\工具\run.exe"
        );
    }
}
