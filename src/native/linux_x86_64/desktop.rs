//! Session clipboard, global memory and nonvisual built-in STATIC windows.
use super::*;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;

#[derive(Default)]
pub(super) struct NativeDesktop {
    next: u64,
    memory: HashMap<u64, GlobalMemory>,
    windows: HashMap<u64, u32>,
    messages: HashMap<u32, VecDeque<Message>>,
    opened: Option<ClipboardOpen>,
    cache: HashMap<u32, u64>,
}
struct GlobalMemory {
    bytes: Vec<u8>,
    size: usize,
    movable: bool,
    locks: u8,
    clipboard: bool,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Message {
    window: u64,
    message: u32,
    wparam: u64,
    lparam: u64,
    time: u32,
    point: [i32; 2],
    private: u32,
}
struct ClipboardOpen {
    _lock: File,
    thread: u32,
    window: u64,
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct ClipboardData {
    owner: u64,
    data: HashMap<u32, Vec<u8>>,
}
fn fail(error: u32) -> u64 {
    native_set_last_error(error);
    0
}
fn with_desktop<T>(f: impl FnOnce(&mut NativeDesktop) -> T) -> Option<T> {
    let process = process_ctx()?;
    let mut desktop = process.desktop.lock().ok()?;
    Some(f(&mut desktop))
}
fn session_path(name: &str) -> Result<std::path::PathBuf, u32> {
    let process = process_ctx().ok_or(6u32)?;
    let fs = process.fs.lock().map_err(|_| 6u32)?;
    fs.fs.blob_dir().map(|dir| dir.join(name)).ok_or(50)
}
fn io_error(error: impl std::fmt::Display) -> u32 {
    eprintln!("winrun: clipboard storage failed: {error}");
    5
}
fn lock_file(name: &str, nonblocking: bool) -> Result<File, u32> {
    let path = session_path(name)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(io_error)?;
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), flags) } != 0 {
        return Err(5);
    }
    Ok(file)
}
fn load<T: serde::de::DeserializeOwned + Default>(name: &str) -> Result<T, u32> {
    match std::fs::read(session_path(name)?) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io_error),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(io_error(error)),
    }
}
fn save<T: serde::Serialize>(name: &str, value: &T) -> Result<(), u32> {
    let path = session_path(name)?;
    let temporary = path.with_extension(format!("{}.pending", std::process::id()));
    let bytes = serde_json::to_vec(value).map_err(io_error)?;
    std::fs::write(&temporary, bytes).map_err(io_error)?;
    std::fs::rename(temporary, path).map_err(io_error)
}
fn wide(ptr: *const u16) -> Option<String> {
    if ptr.is_null() || ptr as usize <= 0xffff {
        return None;
    }
    let mut length = 0;
    while length < 32768 && unsafe { ptr.add(length).read() } != 0 {
        length += 1
    }
    if length == 32768 {
        return None;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(ptr, length) }).ok()
}
fn allocate(state: &mut NativeDesktop, flags: u32, size: usize) -> u64 {
    if flags & !(2 | 0x40 | 0x100 | 0x2000) != 0 {
        return fail(87);
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(size.max(1)).is_err() {
        return fail(8);
    }
    bytes.resize(size.max(1), if flags & 0x40 != 0 { 0 } else { 0xcd });
    let movable = flags & 2 != 0;
    state.next += 1;
    let handle = if movable {
        0x474c_4f42_0000_0000 | state.next
    } else {
        bytes.as_ptr() as u64
    };
    state.memory.insert(
        handle,
        GlobalMemory {
            bytes,
            size,
            movable,
            locks: 0,
            clipboard: false,
        },
    );
    handle
}
pub(super) extern "win64" fn native_global_alloc(flags: u32, size: usize) -> u64 {
    with_desktop(|state| allocate(state, flags, size)).unwrap_or_else(|| fail(6))
}
pub(super) extern "win64" fn native_global_free(handle: u64) -> u64 {
    if handle == 0 {
        return 0;
    }
    with_desktop(|state| {
        if state
            .memory
            .get(&handle)
            .is_none_or(|memory| memory.clipboard)
        {
            native_set_last_error(6);
            return handle;
        }
        state.memory.remove(&handle);
        0
    })
    .unwrap_or(handle)
}
pub(super) extern "win64" fn native_global_lock(handle: u64) -> u64 {
    with_desktop(|state| {
        let Some(memory) = state.memory.get_mut(&handle) else {
            return fail(6);
        };
        if memory.size == 0 && memory.movable {
            return fail(157);
        }
        if memory.movable {
            memory.locks = memory.locks.saturating_add(1)
        }
        memory.bytes.as_mut_ptr() as u64
    })
    .unwrap_or_else(|| fail(6))
}
pub(super) extern "win64" fn native_global_unlock(handle: u64) -> i32 {
    with_desktop(|state| {
        let Some(memory) = state.memory.get_mut(&handle) else {
            return fail(6) as i32;
        };
        if !memory.movable {
            return 1;
        }
        if memory.locks == 0 {
            return fail(158) as i32;
        }
        memory.locks -= 1;
        if memory.locks == 0 {
            native_set_last_error(0);
            0
        } else {
            1
        }
    })
    .unwrap_or_else(|| fail(6) as i32)
}
pub(super) extern "win64" fn native_global_size(handle: u64) -> usize {
    with_desktop(|state| {
        state
            .memory
            .get(&handle)
            .map(|memory| memory.size)
            .unwrap_or_else(|| fail(6) as usize)
    })
    .unwrap_or_else(|| fail(6) as usize)
}
fn fold_format(name: &str) -> String {
    name.chars()
        .map(|unit| {
            let mut uppercase = unit.to_uppercase();
            let first = uppercase.next().unwrap();
            if uppercase.next().is_none() {
                first
            } else {
                unit
            }
        })
        .collect()
}
pub(super) fn release_thread_desktop(process: &NativeProcessContext, id: u32) {
    if let Ok(mut state) = process.desktop.lock() {
        if state.opened.as_ref().is_some_and(|open| open.thread == id) {
            state.opened.take();
        }
        state.windows.retain(|_, thread| *thread != id);
        state.messages.remove(&id);
    }
}
pub(super) extern "win64" fn native_register_clipboard_format_w(name: *const u16) -> u32 {
    let Some(name) = wide(name).filter(|name| !name.is_empty()) else {
        return fail(87) as u32;
    };
    let result = (|| {
        let _lock = lock_file("clipboard-formats.lock", false)?;
        let mut formats: Vec<String> = load("clipboard-formats.json")?;
        if let Some(index) = formats
            .iter()
            .position(|format| fold_format(format) == fold_format(&name))
        {
            return Ok(0xc000 + index as u32);
        }
        if formats.len() >= 0x4000 {
            return Err(8);
        }
        let id = 0xc000 + formats.len() as u32;
        formats.push(name);
        save("clipboard-formats.json", &formats)?;
        Ok(id)
    })();
    result.unwrap_or_else(|error| fail(error) as u32)
}
pub(super) extern "win64" fn native_create_window_ex_w(
    extended: u32,
    class: *const u16,
    _title: *const u16,
    style: u32,
    _x: i32,
    _y: i32,
    _width: i32,
    _height: i32,
    parent: u64,
    menu: u64,
    _instance: u64,
    parameter: u64,
) -> u64 {
    let Some(class) = wide(class) else {
        return fail(1407);
    };
    if !class.eq_ignore_ascii_case("STATIC") {
        return fail(1407);
    }
    // Nonvisual built-in windows provide identity/ownership to CLI services.
    // Window painting, child controls, custom procedures and GUI styles are not supported.
    if extended != 0
        || style != 0
        || (parent != 0 && parent != u64::MAX - 2)
        || menu != 0
        || parameter != 0
    {
        eprintln!("winrun: unsupported CreateWindowExW window style or GUI feature");
        return fail(50);
    }
    with_desktop(|state| {
        state.next += 1;
        let handle = 0x5749_0000_0000_0000 | ((std::process::id() as u64) << 24) | state.next;
        state.windows.insert(handle, native_get_current_thread_id());
        handle
    })
    .unwrap_or_else(|| fail(6))
}
pub(super) extern "win64" fn native_destroy_window(handle: u64) -> i32 {
    with_desktop(|state| {
        let Some(thread) = state.windows.get(&handle) else {
            return fail(1400) as i32;
        };
        if *thread != native_get_current_thread_id() {
            return fail(5) as i32;
        }
        state.windows.remove(&handle);
        for messages in state.messages.values_mut() {
            messages.retain(|message| message.window != handle)
        }
        1
    })
    .unwrap_or_else(|| fail(1400) as i32)
}
pub(super) extern "win64" fn native_is_window(handle: u64) -> i32 {
    with_desktop(|state| state.windows.contains_key(&handle) as i32).unwrap_or(0)
}
pub(super) extern "win64" fn native_post_message_w(
    handle: u64,
    message: u32,
    wparam: u64,
    lparam: u64,
) -> i32 {
    if message < 0x400 {
        eprintln!("winrun: unsupported PostMessageW system message {message:#x}");
        return fail(50) as i32;
    }
    with_desktop(|state| {
        let Some(thread) = state.windows.get(&handle).copied() else {
            return fail(1400) as i32;
        };
        state
            .messages
            .entry(thread)
            .or_default()
            .push_back(Message {
                window: handle,
                message,
                wparam,
                lparam,
                ..Message::default()
            });
        1
    })
    .unwrap_or_else(|| fail(1400) as i32)
}
pub(super) extern "win64" fn native_peek_message_w(
    out: *mut u8,
    window: u64,
    minimum: u32,
    maximum: u32,
    remove: u32,
) -> i32 {
    if out.is_null() || remove & !3 != 0 {
        return fail(87) as i32;
    }
    with_desktop(|state| {
        if window != 0 && window != u64::MAX && !state.windows.contains_key(&window) {
            return fail(1400) as i32;
        }
        let messages = state
            .messages
            .entry(native_get_current_thread_id())
            .or_default();
        let index = messages.iter().position(|message| {
            (window == 0 || message.window == window)
                && (minimum == 0 && maximum == 0
                    || message.message >= minimum && message.message <= maximum)
        });
        let Some(index) = index else { return 0 };
        let message = if remove & 1 != 0 {
            messages.remove(index).unwrap()
        } else {
            messages[index]
        };
        unsafe { out.cast::<Message>().write_unaligned(message) }
        1
    })
    .unwrap_or(0)
}
pub(super) extern "win64" fn native_translate_message(message: *const u8) -> i32 {
    if message.is_null() {
        return fail(87) as i32;
    }
    let message = unsafe { message.cast::<Message>().read_unaligned() };
    if matches!(message.message, 0x100 | 0x101 | 0x104 | 0x105) {
        eprintln!("winrun: TranslateMessage keyboard translation is unsupported");
        return fail(50) as i32;
    }
    0 // Non-keyboard messages require no translation.
}
pub(super) extern "win64" fn native_dispatch_message_w(message: *const u8) -> i64 {
    if message.is_null() {
        return fail(87) as i64;
    }
    let message = unsafe { message.cast::<Message>().read_unaligned() };
    if message.message >= 0x400 {
        return 0;
    } // STATIC ignores application-defined messages.
    eprintln!(
        "winrun: unsupported DispatchMessageW system message {:#x}",
        message.message
    );
    fail(50) as i64
}
fn opened(state: &NativeDesktop) -> bool {
    state
        .opened
        .as_ref()
        .is_some_and(|opened| opened.thread == native_get_current_thread_id())
}
pub(super) extern "win64" fn native_open_clipboard(window: u64) -> i32 {
    with_desktop(|state| {
        if window != 0 && !state.windows.contains_key(&window) {
            return fail(1400) as i32;
        }
        if let Some(open) = &state.opened {
            if open.thread == native_get_current_thread_id() && open.window == window {
                return 1;
            }
            return fail(5) as i32;
        }
        let lock = match lock_file("clipboard.lock", true) {
            Ok(file) => file,
            Err(error) => return fail(error) as i32,
        };
        state.memory.retain(|_, memory| !memory.clipboard);
        state.cache.clear();
        state.opened = Some(ClipboardOpen {
            _lock: lock,
            thread: native_get_current_thread_id(),
            window,
        });
        1
    })
    .unwrap_or_else(|| fail(6) as i32)
}
pub(super) extern "win64" fn native_close_clipboard() -> i32 {
    with_desktop(|state| {
        if !opened(state) {
            return fail(1418) as i32;
        }
        state.opened.take();
        1
    })
    .unwrap_or_else(|| fail(1418) as i32)
}
pub(super) extern "win64" fn native_empty_clipboard() -> i32 {
    with_desktop(|state| {
        if !opened(state) {
            return fail(1418) as i32;
        }
        let owner = state.opened.as_ref().unwrap().window;
        match save(
            "clipboard.json",
            &ClipboardData {
                owner,
                ..ClipboardData::default()
            },
        ) {
            Ok(()) => {
                state.memory.retain(|_, memory| !memory.clipboard);
                state.cache.clear();
                1
            }
            Err(error) => fail(error) as i32,
        }
    })
    .unwrap_or_else(|| fail(1418) as i32)
}
pub(super) extern "win64" fn native_is_clipboard_format_available(format: u32) -> i32 {
    load::<ClipboardData>("clipboard.json")
        .map(|data| data.data.contains_key(&format) as i32)
        .unwrap_or_else(|error| fail(error) as i32)
}
pub(super) extern "win64" fn native_set_clipboard_data(format: u32, handle: u64) -> u64 {
    with_desktop(|state| {
        if !opened(state) {
            return fail(1418);
        }
        if handle == 0 {
            eprintln!("winrun: clipboard delayed rendering is unsupported");
            return fail(50);
        }
        // Only formats represented by HGLOBAL payloads are supported.
        if !matches!(format, 1 | 7 | 8 | 13 | 15 | 16 | 17 | 0xc000..=0xffff) {
            eprintln!("winrun: clipboard format {format:#x} does not support HGLOBAL payloads");
            return fail(50);
        }
        let Some(memory) = state.memory.get(&handle) else {
            return fail(6);
        };
        if !memory.movable || memory.locks != 0 || memory.size == 0 {
            return fail(87);
        }
        let mut data: ClipboardData = match load("clipboard.json") {
            Ok(data) => data,
            Err(error) => return fail(error),
        };
        if data.owner == 0 {
            return fail(1418);
        }
        data.data
            .insert(format, memory.bytes[..memory.size].to_vec());
        if let Err(error) = save("clipboard.json", &data) {
            return fail(error);
        }
        state.memory.get_mut(&handle).unwrap().clipboard = true;
        if let Some(old) = state.cache.insert(format, handle) {
            if old != handle {
                state.memory.remove(&old);
            }
        }
        handle
    })
    .unwrap_or_else(|| fail(1418))
}
pub(super) extern "win64" fn native_get_clipboard_data(format: u32) -> u64 {
    with_desktop(|state| {
        if !opened(state) {
            return fail(1418);
        }
        if let Some(handle) = state.cache.get(&format) {
            return *handle;
        }
        let data: ClipboardData = match load("clipboard.json") {
            Ok(data) => data,
            Err(error) => return fail(error),
        };
        let Some(bytes) = data.data.get(&format) else {
            return 0;
        };
        let handle = allocate(state, 2, bytes.len());
        if handle == 0 {
            return 0;
        }
        let memory = state.memory.get_mut(&handle).unwrap();
        memory.bytes[..bytes.len()].copy_from_slice(bytes);
        memory.clipboard = true;
        state.cache.insert(format, handle);
        handle
    })
    .unwrap_or_else(|| fail(1418))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Scope(Option<Arc<NativeProcessContext>>);
    impl Scope {
        fn new() -> Self {
            Self(THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(context::new_test_process()))))
        }
    }
    impl Drop for Scope {
        fn drop(&mut self) {
            THREAD_NATIVE_PROCESS.with(|slot| slot.replace(self.0.take()));
        }
    }
    fn window() -> u64 {
        let class: Vec<u16> = "STATIC".encode_utf16().chain([0]).collect();
        native_create_window_ex_w(
            0,
            class.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
    extern "win64" fn abandoned_clipboard(parameter: u64) -> u32 {
        let owner = window();
        unsafe { (parameter as *mut u64).write(owner) }
        assert_eq!(native_open_clipboard(owner), 1);
        0
    }
    #[test]
    fn thread_exit_releases_clipboard_lock_and_hidden_windows() {
        let _scope = Scope::new();
        let mut owner = 0u64;
        let thread = native_create_thread(
            0,
            0,
            abandoned_clipboard as *const () as u64,
            &mut owner as *mut _ as u64,
            0,
            std::ptr::null_mut(),
        );
        assert_ne!(thread, 0);
        assert_eq!(native_wait_for_single_object(thread, 5000), 0);
        assert_ne!(owner, 0);
        assert_eq!(native_is_window(owner), 0);
        assert_eq!(native_open_clipboard(0), 1);
        assert_eq!(native_close_clipboard(), 1);
        native_close_handle(thread);
        let upper: Vec<u16> = "Clipboard Ω".encode_utf16().chain([0]).collect();
        let lower: Vec<u16> = "clipboard ω".encode_utf16().chain([0]).collect();
        assert_eq!(
            native_register_clipboard_format_w(upper.as_ptr()),
            native_register_clipboard_format_w(lower.as_ptr())
        );
    }
    #[test]
    fn global_memory_distinguishes_handles_tracks_locks_and_rejects_invalid_handles() {
        let _scope = Scope::new();
        let memory = native_global_alloc(0x42, 8);
        assert_ne!(memory, 0);
        let pointer = native_global_lock(memory);
        assert_ne!(pointer, memory);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(pointer as *const u8, 8) },
            &[0; 8]
        );
        assert_eq!(native_global_lock(memory), pointer);
        assert_eq!(native_global_size(memory), 8);
        assert_eq!(native_global_unlock(memory), 1);
        assert_eq!(native_global_unlock(memory), 0);
        assert_eq!(native_get_last_error(), 0);
        assert_eq!(native_global_unlock(memory), 0);
        assert_eq!(native_get_last_error(), 158);
        assert_eq!(native_global_free(memory), 0);
        assert_eq!(native_global_lock(memory), 0);
        assert_eq!(native_get_last_error(), 6);
        let fixed = native_global_alloc(0x40, 8);
        assert_eq!(native_global_lock(fixed), fixed);
        assert_eq!(native_global_unlock(fixed), 1);
        assert_eq!(native_global_free(fixed), 0);
        let discarded = native_global_alloc(2, 0);
        assert_ne!(discarded, 0);
        assert_eq!(native_global_lock(discarded), 0);
        assert_eq!(native_get_last_error(), 157);
        native_global_free(discarded);
        assert_eq!(native_global_alloc(0x80000000, 8), 0);
        assert_eq!(native_get_last_error(), 87);
    }
    #[test]
    fn hidden_windows_and_messages_enforce_thread_ownership_and_filters() {
        let _scope = Scope::new();
        let handle = window();
        assert_ne!(handle, 0);
        assert_eq!(native_is_window(handle), 1);
        assert_eq!(native_post_message_w(handle, 0x401, 12, 34), 1);
        let mut message = Message::default();
        assert_eq!(
            native_peek_message_w(
                (&mut message as *mut Message).cast(),
                handle,
                0x402,
                0x402,
                0
            ),
            0
        );
        assert_eq!(
            native_peek_message_w((&mut message as *mut Message).cast(), handle, 0, 0, 0),
            1
        );
        assert_eq!(
            (
                message.window,
                message.message,
                message.wparam,
                message.lparam
            ),
            (handle, 0x401, 12, 34)
        );
        assert_eq!(
            native_peek_message_w((&mut message as *mut Message).cast(), handle, 0, 0, 1),
            1
        );
        assert_eq!(
            native_peek_message_w((&mut message as *mut Message).cast(), handle, 0, 0, 1),
            0
        );
        let process = process_ctx().unwrap();
        let other = std::thread::spawn(move || {
            THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(process)));
            THREAD_NATIVE_HANDLE.set(123);
            assert_eq!(native_destroy_window(handle), 0);
            assert_eq!(native_get_last_error(), 5);
        });
        other.join().unwrap();
        assert_eq!(native_destroy_window(handle), 1);
        assert_eq!(native_is_window(handle), 0);
        assert_eq!(native_destroy_window(handle), 0);
        assert_eq!(native_get_last_error(), 1400);
    }
    #[test]
    fn clipboard_transfers_memory_and_shares_payloads_and_registration_between_contexts() {
        let _scope = Scope::new();
        let owner = window();
        let name: Vec<u16> = "Winrun.Native.Test".encode_utf16().chain([0]).collect();
        let format = native_register_clipboard_format_w(name.as_ptr());
        assert!((0xc000..=0xffff).contains(&format));
        let lower: Vec<u16> = "winrun.native.test".encode_utf16().chain([0]).collect();
        assert_eq!(native_register_clipboard_format_w(lower.as_ptr()), format);
        assert_eq!(native_get_clipboard_data(format), 0);
        assert_eq!(native_get_last_error(), 1418);
        assert_eq!(native_open_clipboard(owner), 1);
        assert_eq!(native_empty_clipboard(), 1);
        let memory = native_global_alloc(2, 6);
        let pointer = native_global_lock(memory);
        unsafe { std::ptr::copy_nonoverlapping(b"hello\0".as_ptr(), pointer as *mut u8, 6) };
        native_global_unlock(memory);
        assert_eq!(native_set_clipboard_data(format, memory), memory);
        assert_eq!(native_global_free(memory), memory);
        assert_eq!(native_get_last_error(), 6);
        assert_eq!(native_is_clipboard_format_available(format), 1);
        let first = process_ctx().unwrap();
        let directory = first
            .fs
            .lock()
            .unwrap()
            .fs
            .blob_dir()
            .unwrap()
            .to_path_buf();
        let other = context::new_test_process();
        other.fs.lock().unwrap().fs = WinFs::attached(Some(&directory)).unwrap();
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(other)));
        assert_eq!(native_register_clipboard_format_w(lower.as_ptr()), format);
        assert_eq!(native_open_clipboard(0), 0);
        assert_eq!(native_get_last_error(), 5);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(first.clone())));
        assert_eq!(native_close_clipboard(), 1);
        let other = context::new_test_process();
        other.fs.lock().unwrap().fs = WinFs::attached(Some(&directory)).unwrap();
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(other)));
        assert_eq!(native_open_clipboard(0), 1);
        let fetched = native_get_clipboard_data(format);
        assert_ne!(fetched, 0);
        let pointer = native_global_lock(fetched);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(pointer as *const u8, 6) },
            b"hello\0"
        );
        native_global_unlock(fetched);
        assert_eq!(native_close_clipboard(), 1);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(first)));
        assert_eq!(native_open_clipboard(owner), 1);
        assert_eq!(native_empty_clipboard(), 1);
        assert_eq!(native_is_clipboard_format_available(format), 0);
        assert_eq!(native_close_clipboard(), 1);
        assert_eq!(native_close_clipboard(), 0);
        assert_eq!(native_get_last_error(), 1418);
        native_destroy_window(owner);
    }
}

#[cfg(test)]
mod message_translation_tests {
    use super::*;
    #[test]
    fn non_keyboard_messages_need_no_translation_and_keyboard_requests_fail_explicitly() {
        native_set_last_error(42);
        let mut message = Message {
            message: 0x401,
            ..Message::default()
        };
        assert_eq!(
            native_translate_message((&message as *const Message).cast()),
            0
        );
        assert_eq!(native_get_last_error(), 42);
        message.message = 0x100;
        assert_eq!(
            native_translate_message((&message as *const Message).cast()),
            0
        );
        assert_eq!(native_get_last_error(), 50);
        assert_eq!(native_translate_message(ptr::null()), 0);
        assert_eq!(native_get_last_error(), 87);
    }
}
