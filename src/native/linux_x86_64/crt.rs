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
pub(super) static NATIVE_CRT_EMPTY_COMMAND_LINE: [u8; 1] = [0];
pub(super) static NATIVE_CRT_INITENV: AtomicU64 = AtomicU64::new(0);
pub(super) static NATIVE_CRT_IOB: [AtomicU64; 24] = [const { AtomicU64::new(0) }; 24];

pub(super) extern "win64" fn native_crt_set_app_type(_app_type: i32) {}
pub(super) extern "win64" fn native_crt_iob_func() -> *mut u8 {
    NATIVE_CRT_IOB.as_ptr().cast_mut().cast()
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
fn build_crt_startup(command_line: &[u8], environment: &[(String, String)]) -> NativeCrtStartup {
    let line = String::from_utf8_lossy(command_line);
    let args = parse_windows_command_line(line.trim_end_matches('\0')).unwrap_or_default();
    let argv_storage = args
        .into_iter()
        .map(|arg| {
            let mut bytes = arg.into_bytes();
            bytes.push(0);
            bytes.into_boxed_slice()
        })
        .collect::<Vec<_>>();
    let mut argv = argv_storage
        .iter()
        .map(|arg| arg.as_ptr() as usize)
        .collect::<Vec<_>>();
    argv.push(0);
    let argv_value = argv.as_mut_ptr() as usize;
    let environment_storage = environment
        .iter()
        .map(|(name, value)| {
            let mut bytes = format!("{name}={value}").into_bytes();
            bytes.push(0);
            bytes.into_boxed_slice()
        })
        .collect::<Vec<_>>();
    let mut environment = environment_storage
        .iter()
        .map(|entry| entry.as_ptr() as usize)
        .collect::<Vec<_>>();
    environment.push(0);
    NativeCrtStartup {
        argc: argv.len().saturating_sub(1) as i32,
        _argv_storage: argv_storage,
        argv,
        argv_value,
        _environment_storage: environment_storage,
        environment,
    }
}

fn ensure_crt_startup(process: &NativeProcessContext) {
    if let Ok(mut startup) = process.crt_startup.lock() {
        if startup.is_none() {
            let environment = process.environment.lock().map(|env| env.clone());
            *startup = Some(build_crt_startup(
                &process.command_line_a,
                environment.as_deref().unwrap_or_default(),
            ));
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

pub(super) extern "win64" fn native_crt_initialize_narrow_environment() {
    if let Some(process) = process_ctx() {
        ensure_crt_startup(&process);
    }
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
    _table: *mut c_void,
    callback: u64,
) -> i32 {
    native_crt_atexit(callback)
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
pub(super) extern "win64" fn native_crt_fputs(input: *const u8, _file: *mut u8) -> i32 {
    let len = native_crt_strlen(input);
    if len == 0 {
        return 0;
    }
    let written = unsafe { write(1, input.cast(), len) };
    if written < 0 {
        -1
    } else {
        0
    }
}
pub(super) extern "win64" fn native_crt_fputc(byte: i32, _file: *mut u8) -> i32 {
    let value = [byte as u8];
    if unsafe { write(1, value.as_ptr().cast(), 1) } == 1 {
        byte & 0xff
    } else {
        -1
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
    _stream: *mut u8,
) -> usize {
    let Some(length) = size.checked_mul(count) else {
        return 0;
    };
    if size == 0 || length == 0 {
        return 0;
    }
    if buffer.is_null() {
        return 0;
    }
    let mut written = 0usize;
    while written < length {
        let result = unsafe {
            write(
                1,
                buffer.add(written).cast(),
                length.saturating_sub(written),
            )
        };
        if result <= 0 {
            break;
        }
        written += result as usize;
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
        let mut startup = build_crt_startup(b"tool.exe \"hello world\" arg\0", &environment);
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
}
