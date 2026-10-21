//! Files shared between processes: renaming and deleting a file another
//! handle has open, data a killed process wrote, byte-range locks held by a
//! process that is killed or exits, and change notifications for a
//! directory another process changes. Children are this probe again,
//! started with `child:<mode>:<file>`.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");

type Create = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
type Close = unsafe extern "system" fn(usize) -> i32;
type Read = unsafe extern "system" fn(usize, *mut u8, u32, *mut u32, usize) -> i32;
type Move = unsafe extern "system" fn(*const u16, *const u16, u32) -> i32;
type Delete = unsafe extern "system" fn(*const u16) -> i32;
type Attributes = unsafe extern "system" fn(*const u16) -> u32;
type Lock = unsafe extern "system" fn(usize, u32, u32, u32, u32, *mut u8) -> i32;
type Sleep = unsafe extern "system" fn(u32);
type Wait = unsafe extern "system" fn(usize, u32) -> u32;
type Terminate = unsafe extern "system" fn(usize, u32) -> i32;
type CommandLine = unsafe extern "system" fn() -> *const u16;
type ModuleName = unsafe extern "system" fn(usize, *mut u16, u32) -> u32;
type CreateProcess = unsafe extern "system" fn(
    *const u16, *mut u16, usize, usize, i32, u32, usize, *const u16, *const u8, *mut usize,
) -> i32;
type Notify = unsafe extern "system" fn(*const u16, i32, u32) -> usize;
type Changes = unsafe extern "system" fn(usize, *mut u8, u32, i32, u32, *mut u32, *mut u8, usize) -> i32;
type Event = unsafe extern "system" fn(usize, i32, i32, usize) -> usize;
type Overlapped = unsafe extern "system" fn(usize, *mut u8, *mut u32, i32) -> i32;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const SHARE_ALL: u32 = 0x7;
const SHARE_READ_WRITE: u32 = 0x3;
const OPEN_EXISTING: u32 = 3;
const CREATE_ALWAYS: u32 = 2;

struct Api {
    create: Create,
    close: Close,
    read: Read,
    sleep: Sleep,
    wait: Wait,
    attributes: Attributes,
}

fn name<'a>(text: &str, buffer: &'a mut [u16; 64]) -> &'a [u16] {
    wide(text, buffer)
}

fn write_all(handle: usize, bytes: &[u8]) -> bool {
    let mut written = 0;
    unsafe { WriteFile(handle, bytes.as_ptr(), bytes.len() as u32, &mut written, 0) != 0 }
}

/// A file's contents (up to 64 bytes) as quoted text, or `fail err=<n>`.
fn out_contents(api: &Api, file: &str) {
    let mut path = [0u16; 64];
    clear_error();
    let handle = unsafe { (api.create)(name(file, &mut path).as_ptr(), GENERIC_READ, SHARE_ALL, 0, OPEN_EXISTING, 0, 0) };
    if handle == usize::MAX {
        out_str("fail");
        out_error();
        return;
    }
    let mut buffer = [0u8; 64];
    let mut count = 0;
    unsafe { (api.read)(handle, buffer.as_mut_ptr(), 64, &mut count, 0) };
    unsafe { (api.close)(handle) };
    out_byte(b'"');
    for &byte in &buffer[..count as usize] {
        out_byte(byte);
    }
    out_byte(b'"');
}

/// Wait up to five seconds for `file` to exist.
fn wait_for(api: &Api, file: &str) -> bool {
    let mut path = [0u16; 64];
    for _ in 0..500 {
        if unsafe { (api.attributes)(name(file, &mut path).as_ptr()) } != u32::MAX {
            return true;
        }
        unsafe { (api.sleep)(10) };
    }
    false
}

/// Start this probe as `child:<mode>:<file>`; the process handle, or 0.
fn spawn(mode: &str, file: &str) -> usize {
    let module_name = kernel32(b"GetModuleFileNameW\0");
    let create_process = kernel32(b"CreateProcessW\0");
    if module_name == 0 || create_process == 0 {
        return 0;
    }
    let module_name: ModuleName = unsafe { core::mem::transmute(module_name) };
    let create_process: CreateProcess = unsafe { core::mem::transmute(create_process) };
    let mut line = [0u16; 700];
    line[0] = b'"' as u16;
    let length = unsafe { module_name(0, line.as_mut_ptr().add(1), 600) } as usize;
    let mut at = length + 1;
    for byte in "\" child:".bytes().chain(mode.bytes()).chain(":".bytes()).chain(file.bytes()) {
        line[at] = byte as u16;
        at += 1;
    }
    line[at] = 0;
    let mut startup = [0u8; 104];
    startup[0] = 104;
    let mut information = [0usize; 3];
    let ok = unsafe {
        create_process(core::ptr::null(), line.as_mut_ptr(), 0, 0, 0, 0, 0, core::ptr::null(), startup.as_ptr(), information.as_mut_ptr())
    };
    if ok == 0 {
        return 0;
    }
    unsafe { (core::mem::transmute::<usize, Close>(kernel32(b"CloseHandle\0")))(information[1]) };
    information[0]
}

/// The child: `write` writes and holds the file open; `lock` locks it
/// whole; `lockexit` locks it and exits; `touch` creates the file. Each
/// signals by creating `<file>.ready`, then waits to be killed (`touch` and
/// `lockexit` exit instead).
fn child(api: &Api, mode: &[u16], file: &[u16]) -> ! {
    let lock: Lock = unsafe { core::mem::transmute(kernel32(b"LockFileEx\0")) };
    let mut path = [0u16; 64];
    path[..file.len()].copy_from_slice(file);
    let is = |text: &str| mode.len() == text.len() && mode.iter().zip(text.bytes()).all(|(a, b)| *a == b as u16);
    let disposition = if is("touch") || is("write") { CREATE_ALWAYS } else { OPEN_EXISTING };
    let handle = unsafe { (api.create)(path.as_ptr(), GENERIC_READ | GENERIC_WRITE, SHARE_READ_WRITE, 0, disposition, 0, 0) };
    if is("write") {
        write_all(handle, b"persisted");
    }
    if is("lock") || is("lockexit") {
        let mut overlapped = [0u8; 32];
        unsafe { lock(handle, 0x2, 0, 100, 0, overlapped.as_mut_ptr()) };
    }
    if is("touch") || is("lockexit") {
        unsafe { ExitProcess(0) }
    }
    let mut ready = [0u16; 64];
    ready[..file.len()].copy_from_slice(file);
    for (index, byte) in ".ready".bytes().enumerate() {
        ready[file.len() + index] = byte as u16;
    }
    let marker = unsafe { (api.create)(ready.as_ptr(), GENERIC_WRITE, SHARE_ALL, 0, CREATE_ALWAYS, 0, 0) };
    unsafe { (api.close)(marker) };
    loop {
        unsafe { (api.sleep)(1000) };
    }
}

fn probe() {
    let api = Api {
        create: api!("setup.create", "CreateFileW", Create),
        close: api!("setup.close", "CloseHandle", Close),
        read: api!("setup.read", "ReadFile", Read),
        sleep: api!("setup.sleep", "Sleep", Sleep),
        wait: api!("setup.wait", "WaitForSingleObject", Wait),
        attributes: api!("setup.attributes", "GetFileAttributesW", Attributes),
    };
    let command_line = api!("setup.command_line", "GetCommandLineW", CommandLine);
    let rename = api!("setup.move", "MoveFileExW", Move);
    let delete = api!("setup.delete", "DeleteFileW", Delete);
    let lock = api!("setup.lock", "LockFileEx", Lock);
    let terminate = api!("setup.terminate", "TerminateProcess", Terminate);
    let notify = kernel32(b"FindFirstChangeNotificationW\0");
    let changes = kernel32(b"ReadDirectoryChangesW\0");
    let event = api!("setup.event", "CreateEventW", Event);
    let overlapped_result = api!("setup.overlapped", "GetOverlappedResult", Overlapped);

    // A child: `child:<mode>:<file>` after the program name.
    let line = unsafe { command_line() };
    let length = wide_len(unsafe { core::slice::from_raw_parts(line, 2048) });
    let text = unsafe { core::slice::from_raw_parts(line, length) };
    let marker: [u16; 6] = [b'c' as u16, b'h' as u16, b'i' as u16, b'l' as u16, b'd' as u16, b':' as u16];
    if let Some(start) = text.windows(6).position(|window| window == marker) {
        let rest = &text[start + 6..];
        let split = rest.iter().position(|&unit| unit == b':' as u16).unwrap_or(rest.len());
        child(&api, &rest[..split], &rest[(split + 1).min(rest.len())..]);
    }
    out_str("probe process_files\n");

    let mut a = [0u16; 64];
    let mut b = [0u16; 64];
    unsafe {
        // Rename and delete while another handle is open.
        let shared = (api.create)(name("open.txt", &mut a).as_ptr(), GENERIC_READ | GENERIC_WRITE, SHARE_ALL, 0, CREATE_ALWAYS, 0, 0);
        write_all(shared, b"open data");
        clear_error();
        let moved = rename(name("open.txt", &mut a).as_ptr(), name("moved.txt", &mut b).as_ptr(), 0);
        case("rename.share_delete");
        out_dec(moved as u64);
        out_error();
        out_byte(b'\n');
        let mut buffer = [0u8; 16];
        let mut count = 0;
        let mut position = [0u8; 32];
        let set_pointer: unsafe extern "system" fn(usize, i64, *mut i64, u32) -> i32 =
            core::mem::transmute(kernel32(b"SetFilePointerEx\0"));
        set_pointer(shared, 0, position.as_mut_ptr().cast(), 0);
        clear_error();
        let read_ok = (api.read)(shared, buffer.as_mut_ptr(), 16, &mut count, 0);
        case("rename.read_old_handle");
        out_dec(read_ok as u64);
        out_str(" count=");
        out_dec(count as u64);
        out_byte(b'\n');
        case("rename.new_name");
        out_contents(&api, "moved.txt");
        out_byte(b'\n');
        clear_error();
        let deleted = delete(name("moved.txt", &mut a).as_ptr());
        case("delete.share_delete");
        out_dec(deleted as u64);
        out_error();
        out_byte(b'\n');
        clear_error();
        let attributes = (api.attributes)(name("moved.txt", &mut a).as_ptr());
        case("delete.name_while_open");
        out_str(if attributes == u32::MAX { "gone" } else { "present" });
        out_error();
        out_byte(b'\n');
        (api.close)(shared);
        clear_error();
        case("delete.name_after_close");
        out_str(if (api.attributes)(name("moved.txt", &mut a).as_ptr()) == u32::MAX { "gone" } else { "present" });
        out_byte(b'\n');

        let held = (api.create)(name("held.txt", &mut a).as_ptr(), GENERIC_READ, SHARE_READ_WRITE, 0, CREATE_ALWAYS, 0, 0);
        clear_error();
        let moved = rename(name("held.txt", &mut a).as_ptr(), name("held2.txt", &mut b).as_ptr(), 0);
        case("rename.no_share_delete");
        out_dec(moved as u64);
        out_error();
        out_byte(b'\n');
        (api.close)(held);

        // Data a killed process wrote.
        let writer = spawn("write", "killed.txt");
        case("kill.ready");
        out_str(if writer != 0 && wait_for(&api, "killed.txt.ready") { "ok\n" } else { "no\n" });
        terminate(writer, 9);
        (api.wait)(writer, 5000);
        case("kill.data");
        out_contents(&api, "killed.txt");
        out_byte(b'\n');

        // A lock held by a process that is killed, then one that exits.
        let file = (api.create)(name("locked.txt", &mut a).as_ptr(), GENERIC_READ | GENERIC_WRITE, SHARE_READ_WRITE, 0, CREATE_ALWAYS, 0, 0);
        write_all(file, b"0123456789");
        let locker = spawn("lock", "locked.txt");
        case("lock.ready");
        out_str(if locker != 0 && wait_for(&api, "locked.txt.ready") { "ok\n" } else { "no\n" });
        let mut overlapped = [0u8; 32];
        clear_error();
        let locked = lock(file, 0x3, 0, 100, 0, overlapped.as_mut_ptr());
        case("lock.while_held");
        out_dec(locked as u64);
        out_error();
        out_byte(b'\n');
        let mut buffer = [0u8; 4];
        let mut count = 0;
        set_pointer(file, 0, position.as_mut_ptr().cast(), 0);
        clear_error();
        let read_ok = (api.read)(file, buffer.as_mut_ptr(), 4, &mut count, 0);
        case("lock.read_locked_range");
        out_dec(read_ok as u64);
        out_error();
        out_byte(b'\n');
        terminate(locker, 9);
        (api.wait)(locker, 5000);
        clear_error();
        let locked = lock(file, 0x3, 0, 100, 0, overlapped.as_mut_ptr());
        case("lock.after_kill");
        out_dec(locked as u64);
        out_error();
        out_byte(b'\n');
        let unlock: unsafe extern "system" fn(usize, u32, u32, u32, *mut u8) -> i32 =
            core::mem::transmute(kernel32(b"UnlockFileEx\0"));
        unlock(file, 0, 100, 0, overlapped.as_mut_ptr());
        let exiter = spawn("lockexit", "locked.txt");
        (api.wait)(exiter, 5000);
        clear_error();
        let locked = lock(file, 0x3, 0, 100, 0, overlapped.as_mut_ptr());
        case("lock.after_exit");
        out_dec(locked as u64);
        out_error();
        out_byte(b'\n');
        (api.close)(file);

        // Change notifications for another process's changes.
        let mut directory = [0u16; 600];
        let cwd: unsafe extern "system" fn(u32, *mut u16) -> u32 = core::mem::transmute(kernel32(b"GetCurrentDirectoryW\0"));
        cwd(600, directory.as_mut_ptr());
        if notify == 0 || changes == 0 {
            unavailable("notify.api");
            out_str("END\n");
            return;
        }
        let notify: Notify = core::mem::transmute(notify);
        let changes: Changes = core::mem::transmute(changes);
        let watch = notify(directory.as_ptr(), 0, 0x1 | 0x10); // file names, last write
        let toucher = spawn("touch", "notified.txt");
        (api.wait)(toucher, 5000);
        case("notify.child_create");
        out_dec(if watch == usize::MAX { 99 } else { (api.wait)(watch, 5000) } as u64);
        out_byte(b'\n');

        let handle = (api.create)(directory.as_ptr(), 0x1, SHARE_ALL, 0, OPEN_EXISTING, 0x0200_0000 | 0x4000_0000, 0);
        let signal = event(0, 1, 0, 0);
        let mut io = [0usize; 4];
        io[3] = signal;
        let mut records = [0u32; 256];
        clear_error();
        let started = changes(handle, records.as_mut_ptr().cast(), 1024, 0, 0x1 | 0x10, core::ptr::null_mut(), io.as_mut_ptr().cast(), 0);
        case("changes.start");
        out_dec(started as u64);
        out_error();
        out_byte(b'\n');
        let toucher = spawn("touch", "changed.txt");
        (api.wait)(toucher, 5000);
        case("changes.wait");
        out_dec((api.wait)(signal, 5000) as u64);
        out_byte(b'\n');
        let mut transferred = 0;
        if overlapped_result(handle, io.as_mut_ptr().cast(), &mut transferred, 0) != 0 && transferred >= 12 {
            let action = records[1];
            let length = records[2] as usize / 2;
            let file = core::slice::from_raw_parts(records.as_ptr().add(3).cast::<u16>(), length);
            case("changes.first");
            out_str("action=");
            out_dec(action as u64);
            out_str(" name=");
            out_wide_quoted(file);
            out_byte(b'\n');
        } else {
            case("changes.first");
            out_str("none");
            out_error();
            out_byte(b'\n');
        }
    }
    out_str("END\n");
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    probe();
    flush();
    unsafe { ExitProcess(0) }
}
