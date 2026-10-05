//! Global memory, hidden window identity and session clipboard ownership.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
fn boolean(label: &str, value: bool) {
    case(label);
    out_str(if value { "ok\n" } else { "wrong\n" });
}
macro_rules! user_api {
    ($module:expr, $name:literal, $ty:ty) => {{
        let address = unsafe { GetProcAddress($module, concat!($name, "\0").as_ptr()) };
        if address == 0 {
            unavailable($name);
            return;
        }
        unsafe { core::mem::transmute::<usize, $ty>(address) }
    }};
}
fn run() {
    type Load = unsafe extern "system" fn(*const u8) -> usize;
    type Alloc = unsafe extern "system" fn(u32, usize) -> usize;
    type Handle = unsafe extern "system" fn(usize) -> usize;
    type BoolHandle = unsafe extern "system" fn(usize) -> i32;
    type NoArgs = unsafe extern "system" fn() -> i32;
    type Register = unsafe extern "system" fn(*const u16) -> u32;
    type Format = unsafe extern "system" fn(u32) -> usize;
    type Set = unsafe extern "system" fn(u32, usize) -> usize;
    type Window = unsafe extern "system" fn(
        u32,
        *const u16,
        *const u16,
        u32,
        i32,
        i32,
        i32,
        i32,
        usize,
        usize,
        usize,
        usize,
    ) -> usize;
    type Post = unsafe extern "system" fn(usize, u32, usize, usize) -> i32;
    type Peek = unsafe extern "system" fn(*mut usize, usize, u32, u32, u32) -> i32;
    let load = api!("user.load", "LoadLibraryA", Load);
    let user = unsafe { load(b"user32.dll\0".as_ptr()) };
    let alloc = api!("global.alloc", "GlobalAlloc", Alloc);
    let lock = api!("global.lock", "GlobalLock", Handle);
    let unlock = api!("global.unlock", "GlobalUnlock", BoolHandle);
    let size = api!("global.size", "GlobalSize", Handle);
    let free = api!("global.free", "GlobalFree", Handle);
    let register = user_api!(user, "RegisterClipboardFormatW", Register);
    let create = user_api!(user, "CreateWindowExW", Window);
    let destroy = user_api!(user, "DestroyWindow", BoolHandle);
    let is_window = user_api!(user, "IsWindow", BoolHandle);
    let open = user_api!(user, "OpenClipboard", BoolHandle);
    let close = user_api!(user, "CloseClipboard", NoArgs);
    let empty = user_api!(user, "EmptyClipboard", NoArgs);
    let set = user_api!(user, "SetClipboardData", Set);
    let get = user_api!(user, "GetClipboardData", Format);
    let available = user_api!(
        user,
        "IsClipboardFormatAvailable",
        unsafe extern "system" fn(u32) -> i32
    );
    let post = user_api!(user, "PostMessageW", Post);
    let peek = user_api!(user, "PeekMessageW", Peek);
    let command = api!(
        "child.command",
        "GetCommandLineW",
        unsafe extern "system" fn() -> *const u16
    );
    unsafe {
        let name = [
            87u16, 105, 110, 114, 117, 110, 46, 67, 108, 105, 112, 98, 111, 97, 114, 100, 46, 80,
            114, 111, 98, 101, 0,
        ];
        let lower = [
            119u16, 105, 110, 114, 117, 110, 46, 99, 108, 105, 112, 98, 111, 97, 114, 100, 46, 112,
            114, 111, 98, 101, 0,
        ];
        let format = register(name.as_ptr());
        let cmd = command();
        let mut length = 0;
        while length < 4096 && *cmd.add(length) != 0 {
            length += 1
        }
        if core::slice::from_raw_parts(cmd, length)
            .windows(17)
            .any(|units| {
                units
                    .iter()
                    .zip(b"--clipboard-child")
                    .all(|(a, b)| *a == *b as u16)
            })
        {
            let ok = open(0) != 0;
            let memory = if ok { get(format) } else { 0 };
            let pointer = if memory != 0 { lock(memory) } else { 0 };
            let valid =
                pointer != 0 && core::slice::from_raw_parts(pointer as *const u8, 6) == b"hello\0";
            if pointer != 0 {
                unlock(memory);
            }
            if ok {
                close();
            }
            ExitProcess(if valid { 42 } else { 1 });
        }
        boolean(
            "format.register",
            (0xc000..=0xffff).contains(&format) && register(lower.as_ptr()) == format,
        );
        let memory = alloc(0x42, 8);
        let pointer = lock(memory);
        boolean(
            "global.movable",
            memory != 0 && pointer != 0 && pointer != memory && size(memory) >= 8,
        );
        boolean(
            "global.zeroed",
            pointer != 0 && core::slice::from_raw_parts(pointer as *const u8, 8) == &[0; 8],
        );
        boolean(
            "global.nested_lock",
            lock(memory) == pointer && unlock(memory) != 0,
        );
        clear_error();
        boolean(
            "global.final_unlock",
            unlock(memory) == 0 && last_error() == 0,
        );
        clear_error();
        boolean(
            "global.not_locked",
            unlock(memory) == 0 && last_error() == 158,
        );
        boolean("global.free", free(memory) == 0);
        let fixed = alloc(0x40, 8);
        boolean(
            "global.fixed",
            fixed != 0 && lock(fixed) == fixed && unlock(fixed) != 0,
        );
        free(fixed);
        let mut class = [0u16; 8];
        let owner = create(
            0,
            wide("STATIC", &mut class).as_ptr(),
            core::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        boolean("window.create", owner != 0 && is_window(owner) != 0);
        if owner == 0 {
            return;
        }
        // Restrict PeekMessage to our explicit application-defined message.
        let mut message = [0usize; 6];
        boolean("window.post", post(owner, 0x401, 12, 34) != 0);
        boolean(
            "window.peek",
            peek(message.as_mut_ptr(), owner, 0x401, 0x401, 0) != 0
                && message[0] == owner
                && message[1] as u32 == 0x401
                && message[2] == 12
                && message[3] == 34,
        );
        boolean(
            "window.remove",
            peek(message.as_mut_ptr(), owner, 0x401, 0x401, 1) != 0
                && peek(message.as_mut_ptr(), owner, 0x401, 0x401, 1) == 0,
        );
        clear_error();
        boolean("clipboard.not_open", empty() == 0 && last_error() == 1418);
        boolean("clipboard.open", open(owner) != 0 && empty() != 0);
        let memory = alloc(2, 6);
        let pointer = lock(memory);
        core::ptr::copy_nonoverlapping(b"hello\0".as_ptr(), pointer as *mut u8, 6);
        unlock(memory);
        boolean(
            "clipboard.set",
            set(format, memory) == memory && available(format) != 0,
        );
        let fetched = get(format);
        let pointer = lock(fetched);
        boolean(
            "clipboard.roundtrip",
            pointer != 0 && core::slice::from_raw_parts(pointer as *const u8, 6) == b"hello\0",
        );
        unlock(fetched);
        boolean("clipboard.close", close() != 0);
        // A child must see the same registered format and payload.
        let module = api!(
            "child.module",
            "GetModuleFileNameW",
            unsafe extern "system" fn(usize, *mut u16, u32) -> u32
        );
        let spawn = api!(
            "child.spawn",
            "CreateProcessW",
            unsafe extern "system" fn(
                *const u16,
                *mut u16,
                usize,
                usize,
                i32,
                u32,
                usize,
                usize,
                *mut u8,
                *mut usize,
            ) -> i32
        );
        let wait = api!(
            "child.wait",
            "WaitForSingleObject",
            unsafe extern "system" fn(usize, u32) -> u32
        );
        let exit = api!(
            "child.exit",
            "GetExitCodeProcess",
            unsafe extern "system" fn(usize, *mut u32) -> i32
        );
        let close_handle = api!("child.close", "CloseHandle", BoolHandle);
        let mut path = [0u16; 512];
        let n = module(0, path.as_mut_ptr(), 512) as usize;
        let mut cmd = [0u16; 600];
        cmd[0] = 34;
        cmd[1..n + 1].copy_from_slice(&path[..n]);
        for (i, b) in br#"" --clipboard-child"#.iter().enumerate() {
            cmd[n + 1 + i] = *b as u16;
        }
        let mut startup = [0u64; 13];
        startup[0] = 104;
        let mut info = [0usize; 3];
        let created = spawn(
            path.as_ptr(),
            cmd.as_mut_ptr(),
            0,
            0,
            0,
            0,
            0,
            0,
            startup.as_mut_ptr().cast(),
            info.as_mut_ptr(),
        );
        let mut code = 0;
        boolean(
            "clipboard.child",
            created != 0 && wait(info[0], 5000) == 0 && exit(info[0], &mut code) != 0 && code == 42,
        );
        if created != 0 {
            close_handle(info[0]);
            close_handle(info[1]);
        }
        boolean(
            "clipboard.clear",
            open(owner) != 0 && empty() != 0 && available(format) == 0 && close() != 0,
        );
        boolean(
            "window.destroy",
            destroy(owner) != 0 && is_window(owner) == 0,
        );
        clear_error();
        boolean(
            "window.invalid",
            destroy(owner) == 0 && last_error() == 1400,
        );
    }
}
#[no_mangle]
pub extern "system" fn probe_entry() -> ! {
    // Child mode exits before printing the parent's transcript header.
    run();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
