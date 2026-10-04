//! Byte-range lock sharing, I/O exclusion, and asynchronous completion.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}
fn locks() {
    type Open = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
    type Lock = unsafe extern "system" fn(usize, u32, u32, u32, u32, *mut usize) -> i32;
    type Unlock = unsafe extern "system" fn(usize, u32, u32, u32, *mut usize) -> i32;
    type Close = unsafe extern "system" fn(usize) -> i32;
    type Read = unsafe extern "system" fn(usize, *mut u8, u32, *mut u32, usize) -> i32;
    type Event = unsafe extern "system" fn(usize, i32, i32, *const u16) -> usize;
    type Wait = unsafe extern "system" fn(usize, u32) -> u32;
    type Result = unsafe extern "system" fn(usize, *mut usize, *mut u32, i32) -> i32;
    type Cancel = unsafe extern "system" fn(usize, *mut usize) -> i32;
    let open = api!("file.open", "CreateFileW", Open);
    let lock = api!("lock.api", "LockFileEx", Lock);
    let unlock = api!("unlock.api", "UnlockFileEx", Unlock);
    let close = api!("file.close", "CloseHandle", Close);
    let read = api!("file.read", "ReadFile", Read);
    let create_event = api!("event.api", "CreateEventW", Event);
    let wait = api!("wait.api", "WaitForSingleObject", Wait);
    let result = api!("result.api", "GetOverlappedResult", Result);
    let cancel = api!("cancel.api", "CancelIoEx", Cancel);
    let path = [108u16, 111, 99, 107, 115, 46, 98, 105, 110, 0];
    let first = unsafe { open(path.as_ptr(), 0xc0000000, 7, 0, 2, 0, 0) };
    let second = unsafe { open(path.as_ptr(), 0xc0000000, 7, 0, 3, 0, 0) };
    if first == usize::MAX || second == usize::MAX {
        boolean("file.open", false);
        return;
    }
    let mut count = 0;
    unsafe {
        WriteFile(first, b"data".as_ptr(), 4, &mut count, 0);
    }
    let mut a = [0usize; 4];
    let mut b = [0usize; 4];
    boolean(
        "lock.exclusive",
        unsafe { lock(first, 3, 0, 4, 0, a.as_mut_ptr()) } != 0,
    );
    boolean(
        "lock.self_conflict",
        unsafe { lock(first, 3, 0, 4, 0, b.as_mut_ptr()) } == 0 && last_error() == 33,
    );
    boolean(
        "lock.other_conflict",
        unsafe { lock(second, 3, 0, 4, 0, b.as_mut_ptr()) } == 0 && last_error() == 33,
    );
    let mut bytes = [0u8; 4];
    boolean(
        "lock.blocks_read",
        unsafe { read(second, bytes.as_mut_ptr(), 4, &mut count, 0) } == 0 && last_error() == 33,
    );
    boolean(
        "unlock.exact",
        unsafe { unlock(first, 0, 3, 0, a.as_mut_ptr()) } == 0 && last_error() == 158,
    );
    boolean(
        "unlock.exclusive",
        unsafe { unlock(first, 0, 4, 0, a.as_mut_ptr()) } != 0,
    );
    a = [0; 4];
    b = [0; 4];
    boolean(
        "lock.shared_first",
        unsafe { lock(first, 1, 0, 4, 0, a.as_mut_ptr()) } != 0,
    );
    boolean(
        "lock.shared_second",
        unsafe { lock(second, 1, 0, 4, 0, b.as_mut_ptr()) } != 0,
    );
    boolean(
        "lock.shared_read",
        unsafe { read(second, bytes.as_mut_ptr(), 4, &mut count, 0) } != 0 && &bytes == b"data",
    );
    boolean(
        "lock.shared_blocks_write",
        unsafe { WriteFile(first, b"x".as_ptr(), 1, &mut count, a.as_ptr() as usize) } == 0
            && last_error() == 33,
    );
    unsafe {
        unlock(first, 0, 4, 0, a.as_mut_ptr());
        close(second);
    }
    a = [0; 4];
    boolean(
        "lock.close_releases",
        unsafe { lock(first, 3, 0, 4, 0, a.as_mut_ptr()) } != 0,
    );
    unsafe {
        unlock(first, 0, 4, 0, a.as_mut_ptr());
    }
    a = [0, 0, 1usize << 32, 0];
    boolean(
        "lock.large_range",
        unsafe { lock(first, 3, 0, 0, 1, a.as_mut_ptr()) } != 0,
    );
    boolean(
        "unlock.large_range",
        unsafe { unlock(first, 0, 0, 1, a.as_mut_ptr()) } != 0,
    );
    let third = unsafe { open(path.as_ptr(), 0xc0000000, 7, 0, 3, 0x40000000, 0) };
    let event = unsafe { create_event(0, 1, 0, core::ptr::null()) };
    if third == usize::MAX || event == 0 {
        boolean("async.setup", false);
        return;
    }
    a = [0; 4];
    b = [0, 0, 0, event];
    unsafe {
        lock(first, 3, 0, 4, 0, a.as_mut_ptr());
    }
    let pending = unsafe { lock(third, 2, 0, 4, 0, b.as_mut_ptr()) } == 0 && last_error() == 997;
    boolean("async.pending", pending);
    boolean("async.unarmed", unsafe { wait(event, 0) } == 258);
    unsafe {
        unlock(first, 0, 4, 0, a.as_mut_ptr());
    }
    boolean(
        "async.granted",
        unsafe { wait(event, 2000) } == 0
            && unsafe { result(third, b.as_mut_ptr(), &mut count, 0) } != 0
            && count == 0,
    );
    unsafe {
        unlock(third, 0, 4, 0, b.as_mut_ptr());
    }
    a = [0; 4];
    b = [0, 0, 0, event];
    unsafe {
        lock(first, 3, 0, 4, 0, a.as_mut_ptr());
    }
    let pending = unsafe { lock(third, 2, 0, 4, 0, b.as_mut_ptr()) } == 0 && last_error() == 997;
    boolean(
        "async.cancel",
        pending
            && unsafe { cancel(third, b.as_mut_ptr()) } != 0
            && unsafe { wait(event, 2000) } == 0,
    );
    boolean(
        "async.cancel_result",
        unsafe { result(third, b.as_mut_ptr(), &mut count, 0) } == 0 && last_error() == 995,
    );
    unsafe {
        unlock(first, 0, 4, 0, a.as_mut_ptr());
        close(third);
        close(first);
        close(event);
    }
}
#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe file_locks\n");
    locks();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
