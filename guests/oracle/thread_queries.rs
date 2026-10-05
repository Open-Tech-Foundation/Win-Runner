//! Thread identity, handle rights, names and retained termination accounting.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
use core::sync::atomic::{AtomicU32, Ordering};
static WORKER_ID: AtomicU32 = AtomicU32::new(0);
static OWNER_ID: AtomicU32 = AtomicU32::new(0);
#[repr(C)]
struct Worker {
    owner: usize,
    id: usize,
    query_id: usize,
    tick: usize,
    name: usize,
    current: usize,
}
unsafe extern "system" fn worker(data: usize) -> u32 {
    let data = &*(data as *const Worker);
    let id: unsafe extern "system" fn() -> u32 = core::mem::transmute(data.id);
    let query: unsafe extern "system" fn(usize) -> u32 = core::mem::transmute(data.query_id);
    let tick: unsafe extern "system" fn() -> u64 = core::mem::transmute(data.tick);
    let current: unsafe extern "system" fn() -> usize = core::mem::transmute(data.current);
    let name: unsafe extern "system" fn(usize, *const u16) -> i32 = core::mem::transmute(data.name);
    WORKER_ID.store(id(), Ordering::SeqCst);
    OWNER_ID.store(query(data.owner), Ordering::SeqCst);
    name(current(), [b'w' as u16, 0x4e2d, 0xd83d, 0xde00, 0].as_ptr());
    let start = tick();
    let mut value = 1u64;
    while tick().wrapping_sub(start) < 100 {
        for _ in 0..1000 {
            value = value.wrapping_mul(1664525).wrapping_add(1013904223);
        }
        core::ptr::read_volatile(&value);
    }
    42
}
unsafe extern "system" fn active_code(_: usize) -> u32 {
    259
}
fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}
fn probe() {
    type Current = unsafe extern "system" fn() -> usize;
    type Id = unsafe extern "system" fn() -> u32;
    type QueryId = unsafe extern "system" fn(usize) -> u32;
    type Open = unsafe extern "system" fn(u32, i32, u32) -> usize;
    type Code = unsafe extern "system" fn(usize, *mut u32) -> i32;
    type Times = unsafe extern "system" fn(usize, *mut u64, *mut u64, *mut u64, *mut u64) -> i32;
    type Name = unsafe extern "system" fn(usize, *const u16) -> i32;
    type GetName = unsafe extern "system" fn(usize, *mut *mut u16) -> i32;
    type Free = unsafe extern "system" fn(usize) -> usize;
    type Close = unsafe extern "system" fn(usize) -> i32;
    type Thread = unsafe extern "system" fn(usize, usize, usize, usize, u32, *mut u32) -> usize;
    type Resume = unsafe extern "system" fn(usize) -> u32;
    type Wait = unsafe extern "system" fn(usize, u32) -> u32;
    type Duplicate =
        unsafe extern "system" fn(usize, usize, usize, *mut usize, u32, i32, u32) -> i32;
    type Tick = unsafe extern "system" fn() -> u64;
    let current = api!("current.api", "GetCurrentThread", Current);
    let process = api!("process.api", "GetCurrentProcess", Current);
    let id = api!("id.api", "GetCurrentThreadId", Id);
    let pid = api!("pid.api", "GetCurrentProcessId", Id);
    let query_id = api!("query.api", "GetThreadId", QueryId);
    let owner = api!("owner.api", "GetProcessIdOfThread", QueryId);
    let open = api!("open.api", "OpenThread", Open);
    let code = api!("code.api", "GetExitCodeThread", Code);
    let times = api!("times.api", "GetThreadTimes", Times);
    let name = api!("name.api", "SetThreadDescription", Name);
    let get_name = api!("getname.api", "GetThreadDescription", GetName);
    let free = api!("free.api", "LocalFree", Free);
    let close = api!("close.api", "CloseHandle", Close);
    let thread = api!("thread.api", "CreateThread", Thread);
    let resume = api!("resume.api", "ResumeThread", Resume);
    let wait = api!("wait.api", "WaitForSingleObject", Wait);
    let duplicate = api!("duplicate.api", "DuplicateHandle", Duplicate);
    let tick = api!("tick.api", "GetTickCount64", Tick);
    unsafe {
        let me = current();
        let my_id = id();
        let my_pid = pid();
        boolean(
            "identity.pseudo",
            query_id(me) == my_id && owner(me) == my_pid,
        );
        let opened = open(0x800 | 0x400, 0, my_id);
        boolean(
            "identity.open",
            opened != 0 && query_id(opened) == my_id && owner(opened) == my_pid,
        );
        let mut owner_copy = 0;
        boolean(
            "identity.duplicate",
            duplicate(process(), me, process(), &mut owner_copy, 0x800, 0, 0) != 0
                && query_id(owner_copy) == my_id,
        );
        let mut text = core::ptr::null_mut();
        let empty = get_name(me, &mut text) >= 0 && !text.is_null() && *text == 0;
        boolean("name.empty", empty);
        if !text.is_null() {
            free(text as usize);
        }
        let expected = [b'm' as u16, 0x4e2d, 0xd83d, 0xde00, 0];
        let named = name(opened, expected.as_ptr()) >= 0
            && get_name(me, &mut text) >= 0
            && !text.is_null()
            && core::slice::from_raw_parts(text, expected.len()) == expected;
        boolean("name.roundtrip", named);
        let mut other = core::ptr::null_mut();
        boolean(
            "name.independent_copy",
            get_name(me, &mut other) >= 0 && !other.is_null() && other != text,
        );
        name(me, [0].as_ptr());
        boolean("name.copy_stable", !text.is_null() && *text == expected[0]);
        if !text.is_null() {
            free(text as usize);
        }
        if !other.is_null() {
            free(other as usize);
        }
        // Request a documented non-query right. OpenThread with an empty
        // access mask need not produce a usable handle on Windows, so it
        // cannot establish the precondition for the access-denial checks.
        let denied = open(0x1, 0, my_id); // THREAD_TERMINATE
        boolean("rights.restricted_open", denied != 0);
        boolean("rights.id", query_id(denied) == 0 && last_error() == 5);
        boolean("rights.owner", owner(denied) == 0 && last_error() == 5);
        let mut result = 123;
        boolean(
            "rights.code",
            code(denied, &mut result) == 0 && last_error() == 5 && result == 123,
        );
        let mut c = 0;
        let mut e = 0;
        let mut k = 0;
        let mut u = 0;
        boolean(
            "rights.times",
            times(denied, &mut c, &mut e, &mut k, &mut u) == 0 && last_error() == 5,
        );
        boolean(
            "rights.wait",
            wait(denied, 0) == u32::MAX && last_error() == 5,
        );
        boolean("rights.get_name", get_name(denied, &mut text) < 0);
        boolean("rights.set_name", name(denied, expected.as_ptr()) < 0);
        boolean(
            "rights.query_cannot_set",
            name(owner_copy, expected.as_ptr()) < 0,
        );
        let full_query = open(0x40, 0, my_id);
        boolean(
            "rights.implied_query",
            query_id(full_query) == my_id && get_name(full_query, &mut text) >= 0,
        );
        if !text.is_null() {
            free(text as usize);
        }
        let set = open(0x20, 0, my_id);
        boolean("rights.implied_set", name(set, expected.as_ptr()) >= 0);
        boolean("invalid.handle", query_id(0) == 0 && last_error() == 6);
        boolean("invalid.id", open(0x800, 0, 0) == 0 && last_error() == 87);
        // A suspended worker lets us query its active state without a race.
        let data = Worker {
            owner: owner_copy,
            id: id as usize,
            query_id: query_id as usize,
            tick: tick as usize,
            name: name as usize,
            current: current as usize,
        };
        let mut worker_id = 0;
        let creation = thread(
            0,
            0,
            worker as *const () as usize,
            &data as *const _ as usize,
            4,
            &mut worker_id,
        );
        let retained = open(0x800 | 0x100000 | 2, 0, worker_id);
        boolean(
            "thread.open",
            creation != 0
                && retained != 0
                && query_id(retained) == worker_id
                && worker_id != my_id
                && owner(retained) == my_pid,
        );
        boolean(
            "thread.active",
            code(retained, &mut result) != 0 && result == 259,
        );
        boolean("thread.suspended_wait", wait(retained, 0) == 258);
        let before_ok = times(retained, &mut c, &mut e, &mut k, &mut u) != 0 && c != 0;
        let creation_time = c;
        boolean("thread.creation_time", before_ok);
        boolean(
            "thread.close_original",
            close(creation) != 0 && query_id(creation) == 0 && last_error() == 6,
        );
        boolean("thread.resume_opened", resume(retained) == 1);
        let done = wait(retained, 5000) == 0;
        boolean(
            "thread.completed",
            done && code(retained, &mut result) != 0 && result == 42,
        );
        boolean(
            "thread.identity",
            WORKER_ID.load(Ordering::SeqCst) == worker_id
                && OWNER_ID.load(Ordering::SeqCst) == my_id,
        );
        boolean(
            "thread.final_times",
            times(retained, &mut c, &mut e, &mut k, &mut u) != 0
                && c == creation_time
                && e >= c
                && k + u > 0,
        );
        let saved = [c, e, k, u];
        boolean(
            "thread.times_stable",
            times(retained, &mut c, &mut e, &mut k, &mut u) != 0 && saved == [c, e, k, u],
        );
        boolean(
            "thread.name_retained",
            get_name(retained, &mut text) >= 0
                && !text.is_null()
                && core::slice::from_raw_parts(text, 5) == [b'w' as u16, 0x4e2d, 0xd83d, 0xde00, 0],
        );
        if !text.is_null() {
            free(text as usize);
        }
        let reopened = open(0x800, 0, worker_id);
        boolean(
            "thread.reopen_terminated",
            reopened != 0
                && query_id(reopened) == worker_id
                && code(reopened, &mut result) != 0
                && result == 42,
        );
        let returns_active = thread(
            0,
            0,
            active_code as *const () as usize,
            0,
            0,
            core::ptr::null_mut(),
        );
        boolean(
            "thread.exit_259",
            wait(returns_active, 5000) == 0
                && code(returns_active, &mut result) != 0
                && result == 259,
        );
        for handle in [
            opened,
            owner_copy,
            denied,
            full_query,
            set,
            retained,
            reopened,
            returns_active,
        ] {
            close(handle);
        }
    }
    out_str("END\n");
}
#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe thread_queries\n");
    probe();
    flush();
    unsafe { ExitProcess(0) }
}
