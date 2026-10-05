//! Console code pages shared with child processes and current thread stacks.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
include!("fs_support.rs");

type GetPage = unsafe extern "system" fn() -> u32;
type SetPage = unsafe extern "system" fn(u32) -> i32;
type StackLimits = unsafe extern "system" fn(*mut usize, *mut usize);
type Wait = unsafe extern "system" fn(usize, u32) -> u32;
type Close = unsafe extern "system" fn(usize) -> i32;

fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}

fn stack_valid() -> bool {
    let address = kernel32(b"GetCurrentThreadStackLimits\0");
    if address == 0 {
        return false;
    }
    let query: StackLimits = unsafe { core::mem::transmute(address) };
    let mut low = 0;
    let mut high = 0;
    unsafe { query(&mut low, &mut high) };
    let marker = &low as *const usize as usize;
    let base: usize;
    let committed: usize;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x08]", out(reg) base, options(nostack, readonly));
        core::arch::asm!("mov {}, gs:[0x10]", out(reg) committed, options(nostack, readonly));
    }
    // Windows can reserve more stack than is currently committed.
    low != 0 && low <= marker && marker < high && high == base && low <= committed
}

unsafe extern "system" fn thread(_: usize) -> u32 {
    if stack_valid() {
        0
    } else {
        1
    }
}

fn stacks() {
    let _query = api!("stack.query", "GetCurrentThreadStackLimits", StackLimits);
    boolean("stack.main", stack_valid());
    type Create = unsafe extern "system" fn(usize, usize, usize, usize, u32, *mut u32) -> usize;
    type ExitCode = unsafe extern "system" fn(usize, *mut u32) -> i32;
    let create = api!("stack.create", "CreateThread", Create);
    let wait = api!("stack.wait", "WaitForSingleObject", Wait);
    let code = api!("stack.exit", "GetExitCodeThread", ExitCode);
    let close = api!("stack.close", "CloseHandle", Close);
    let handle = unsafe {
        create(
            0,
            1024 * 1024,
            thread as *const () as usize,
            0,
            0,
            core::ptr::null_mut(),
        )
    };
    let mut result = 259;
    boolean(
        "stack.thread",
        handle != 0
            && unsafe { wait(handle, 5000) } == 0
            && unsafe { code(handle, &mut result) } != 0
            && result == 0,
    );
    if handle != 0 {
        unsafe { close(handle) };
    }
}

fn child() -> Option<u32> {
    type CommandLine = unsafe extern "system" fn() -> *const u16;
    let query: CommandLine = unsafe { core::mem::transmute(kernel32(b"GetCommandLineW\0")) };
    let command = unsafe { query() };
    let mut length = 0;
    while unsafe { *command.add(length) } != 0 && length < 2048 {
        length += 1;
    }
    let marker = b"--console-child";
    if length < marker.len()
        || !marker
            .iter()
            .enumerate()
            .all(|(i, byte)| unsafe { *command.add(length - marker.len() + i) } == *byte as u16)
    {
        return None;
    }
    let input: GetPage = unsafe { core::mem::transmute(kernel32(b"GetConsoleCP\0")) };
    let output: GetPage = unsafe { core::mem::transmute(kernel32(b"GetConsoleOutputCP\0")) };
    let set_input: SetPage = unsafe { core::mem::transmute(kernel32(b"SetConsoleCP\0")) };
    let set_output: SetPage = unsafe { core::mem::transmute(kernel32(b"SetConsoleOutputCP\0")) };
    Some(
        if unsafe { input() } == 1252
            && unsafe { output() } == 65001
            && unsafe { set_input(65001) } != 0
            && unsafe { set_output(1252) } != 0
        {
            0
        } else {
            1
        },
    )
}

fn shared_child() {
    type Module = unsafe extern "system" fn(usize, *mut u16, u32) -> u32;
    type Create = unsafe extern "system" fn(
        *const u16,
        *mut u16,
        usize,
        usize,
        i32,
        u32,
        usize,
        usize,
        *mut u8,
        *mut u8,
    ) -> i32;
    type ExitCode = unsafe extern "system" fn(usize, *mut u32) -> i32;
    let module = api!("pages.module", "GetModuleFileNameW", Module);
    let create = api!("pages.spawn", "CreateProcessW", Create);
    let wait = api!("pages.wait", "WaitForSingleObject", Wait);
    let exit = api!("pages.exit", "GetExitCodeProcess", ExitCode);
    let close = api!("pages.close", "CloseHandle", Close);
    let mut path = [0u16; 1024];
    let length = unsafe { module(0, path.as_mut_ptr(), 1024) } as usize;
    let mut command = [0u16; 2048];
    command[0] = b'"' as u16;
    command[1..length + 1].copy_from_slice(&path[..length]);
    for (i, byte) in b"\" --console-child".iter().enumerate() {
        command[length + 1 + i] = *byte as u16;
    }
    let mut startup = [0u64; 13];
    startup[0] = 104;
    let mut info = [0u64; 3];
    // Shared consoles are independent of bInheritHandles.
    let created = unsafe {
        create(
            path.as_ptr(),
            command.as_mut_ptr(),
            0,
            0,
            0,
            0,
            0,
            0,
            startup.as_mut_ptr().cast(),
            info.as_mut_ptr().cast(),
        )
    };
    let mut code = 259;
    boolean(
        "pages.child",
        created != 0
            && unsafe { wait(info[0] as usize, 5000) } == 0
            && unsafe { exit(info[0] as usize, &mut code) } != 0
            && code == 0,
    );
    if created != 0 {
        unsafe {
            close(info[0] as usize);
            close(info[1] as usize);
        }
    }
}

fn pages() {
    let input = api!("pages.input", "GetConsoleCP", GetPage);
    let output = api!("pages.output", "GetConsoleOutputCP", GetPage);
    let set_input = api!("pages.set_input", "SetConsoleCP", SetPage);
    let set_output = api!("pages.set_output", "SetConsoleOutputCP", SetPage);
    let acp = api!("pages.acp", "GetACP", GetPage);
    if unsafe { input() } == 0 {
        // Windows CI may launch without an attached console. Preserve the
        // transcript pipe while creating a console for this process tree.
        type Allocate = unsafe extern "system" fn() -> i32;
        type Standard = unsafe extern "system" fn(u32, usize) -> i32;
        let allocate = api!("pages.allocate", "AllocConsole", Allocate);
        let standard = api!("pages.stdout", "SetStdHandle", Standard);
        let stdout = unsafe { GetStdHandle(-11i32 as u32) };
        unsafe {
            allocate();
            standard(-11i32 as u32, stdout);
        }
    }
    let initial_input = unsafe { input() };
    let initial_output = unsafe { output() };
    let initial_acp = unsafe { acp() };
    boolean("pages.attached", initial_input != 0 && initial_output != 0);
    boolean(
        "pages.input_roundtrip",
        unsafe { set_input(1252) } != 0 && unsafe { input() } == 1252,
    );
    boolean(
        "pages.output_roundtrip",
        unsafe { set_output(65001) } != 0 && unsafe { output() } == 65001,
    );
    boolean(
        "pages.independent",
        unsafe { input() } == 1252 && unsafe { acp() } == initial_acp,
    );
    clear_error();
    ok_or_error("pages.invalid_input", unsafe { set_input(u32::MAX) });
    clear_error();
    ok_or_error("pages.invalid_output", unsafe { set_output(u32::MAX) });
    boolean(
        "pages.invalid_preserves",
        unsafe { input() } == 1252 && unsafe { output() } == 65001,
    );
    shared_child();
    boolean(
        "pages.child_updates",
        unsafe { input() } == 65001 && unsafe { output() } == 1252,
    );
    unsafe {
        set_input(initial_input);
        set_output(initial_output);
    }
    boolean(
        "pages.restored",
        unsafe { input() } == initial_input && unsafe { output() } == initial_output,
    );
}

#[no_mangle]
pub extern "system" fn probe_entry() -> ! {
    if let Some(code) = child() {
        unsafe { ExitProcess(code) }
    }
    out_str("probe console_runtime\n");
    pages();
    stacks();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
