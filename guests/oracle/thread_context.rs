//! Suspending running threads and their registers: `SuspendThread` and
//! `ResumeThread` counts on running, blocked, created-suspended and exited
//! threads, `GetThreadContext` parts by `ContextFlags`, redirecting a
//! suspended thread with `SetThreadContext`, and the rights each needs.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

type Thread = unsafe extern "system" fn(usize, usize, usize, usize, u32, *mut u32) -> usize;
type Count = unsafe extern "system" fn(usize) -> u32;
type Context = unsafe extern "system" fn(usize, *mut u8) -> i32;
type Wait = unsafe extern "system" fn(usize, u32) -> u32;
type Sleep = unsafe extern "system" fn(u32);
type Close = unsafe extern "system" fn(usize) -> i32;
type Code = unsafe extern "system" fn(usize, *mut u32) -> i32;
type Open = unsafe extern "system" fn(u32, i32, u32) -> usize;
type QueryId = unsafe extern "system" fn(usize) -> u32;
type Current = unsafe extern "system" fn() -> usize;
type Event = unsafe extern "system" fn(usize, i32, i32, usize) -> usize;
type SetEvent = unsafe extern "system" fn(usize) -> i32;

const CONTEXT_CONTROL: u32 = 0x10_0001;
const CONTEXT_INTEGER: u32 = 0x10_0002;
const CONTEXT_FULL: u32 = 0x10_000b;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x10_0010;
const RAX: usize = 120;
const RSP: usize = 152;
const RIP: usize = 248;

#[repr(C, align(16))]
struct WindowsContext([u8; 1232]);

impl WindowsContext {
    fn new(flags: u32, fill: u8) -> Self {
        let mut context = Self([fill; 1232]);
        context.0[48..52].copy_from_slice(&flags.to_le_bytes());
        context
    }
    fn get(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.0[at..at + 8].try_into().unwrap())
    }
    fn set(&mut self, at: usize, value: u64) {
        self.0[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
}

static STOP: AtomicU32 = AtomicU32::new(0);
static COUNTER: AtomicU64 = AtomicU64::new(0);
static EVENT: AtomicUsize = AtomicUsize::new(0);
static WAIT: AtomicUsize = AtomicUsize::new(0);
static AFTER_WAIT: AtomicU32 = AtomicU32::new(0);
static EXIT_THREAD: AtomicUsize = AtomicUsize::new(0);
static REDIRECTED: AtomicU32 = AtomicU32::new(0);

unsafe extern "system" fn spinner(_: usize) -> u32 {
    while STOP.load(Ordering::Relaxed) == 0 {
        COUNTER.fetch_add(1, Ordering::Relaxed);
    }
    7
}

unsafe extern "system" fn waiter(_: usize) -> u32 {
    let wait: Wait = core::mem::transmute(WAIT.load(Ordering::SeqCst));
    wait(EVENT.load(Ordering::SeqCst), 0xFFFF_FFFF);
    AFTER_WAIT.store(1, Ordering::SeqCst);
    9
}

unsafe extern "system" fn quick(_: usize) -> u32 {
    3
}

/// Where a redirected thread continues: it records that it ran and ends
/// with its own exit code.
unsafe extern "system" fn redirected() -> ! {
    REDIRECTED.store(1, Ordering::SeqCst);
    let exit: unsafe extern "system" fn(u32) -> ! = core::mem::transmute(EXIT_THREAD.load(Ordering::SeqCst));
    exit(77)
}

fn ret_case(name: &str, value: u32) {
    case(name);
    if value == u32::MAX {
        out_str("fail");
        out_error();
    } else {
        out_dec(value as u64);
    }
    out_byte(b'\n');
}

fn bool_case(name: &str, ok: i32) {
    case(name);
    if ok == 0 {
        out_str("fail");
        out_error();
    } else {
        out_str("ok");
    }
    out_byte(b'\n');
}

/// Whether the spinner advances across `ms` milliseconds.
fn moving(sleep: Sleep, ms: u32) -> &'static str {
    let before = COUNTER.load(Ordering::SeqCst);
    unsafe { sleep(ms) };
    if COUNTER.load(Ordering::SeqCst) == before { "stopped" } else { "running" }
}

fn probe() {
    let thread = api!("setup.thread", "CreateThread", Thread);
    let suspend = api!("setup.suspend", "SuspendThread", Count);
    let resume = api!("setup.resume", "ResumeThread", Count);
    let get = api!("setup.get_context", "GetThreadContext", Context);
    let set = api!("setup.set_context", "SetThreadContext", Context);
    let wait = api!("setup.wait", "WaitForSingleObject", Wait);
    let sleep = api!("setup.sleep", "Sleep", Sleep);
    let close = api!("setup.close", "CloseHandle", Close);
    let code = api!("setup.code", "GetExitCodeThread", Code);
    let open = api!("setup.open", "OpenThread", Open);
    let query_id = api!("setup.id", "GetThreadId", QueryId);
    let current = api!("setup.current", "GetCurrentThread", Current);
    let event = api!("setup.event", "CreateEventW", Event);
    let set_event = api!("setup.set_event", "SetEvent", SetEvent);
    EXIT_THREAD.store(kernel32(b"ExitThread\0"), Ordering::SeqCst);
    WAIT.store(wait as usize, Ordering::SeqCst);
    let image = unsafe { GetModuleHandleW(core::ptr::null()) };
    let image_end = image + unsafe { *((image + *((image + 0x3c) as *const u32) as usize + 24 + 56) as *const u32) } as usize;

    unsafe {
        let mut id = 0;
        let worker = thread(0, 0, spinner as usize, 0, 0, &mut id);
        while COUNTER.load(Ordering::SeqCst) == 0 {
            sleep(1);
        }
        clear_error();
        ret_case("running.suspend", suspend(worker));
        // SuspendThread may return before the thread stops; let it settle.
        sleep(20);
        case("running.suspended");
        out_str(moving(sleep, 50));
        out_byte(b'\n');
        ret_case("running.suspend_again", suspend(worker));
        ret_case("running.resume_to_one", resume(worker));
        case("running.still_suspended");
        out_str(moving(sleep, 50));
        out_byte(b'\n');

        let mut full = WindowsContext::new(CONTEXT_FULL, 0);
        clear_error();
        bool_case("context.full", get(worker, full.0.as_mut_ptr()));
        case("context.full_rip");
        let rip = full.get(RIP) as usize;
        out_str(if rip >= image && rip < image_end { "in_image" } else { "outside" });
        out_byte(b'\n');
        case("context.full_flags");
        out_hex(u32::from_le_bytes(full.0[48..52].try_into().unwrap()) as u64);
        out_byte(b'\n');

        let mut control = WindowsContext::new(CONTEXT_CONTROL, 0xaa);
        clear_error();
        bool_case("context.control", get(worker, control.0.as_mut_ptr()));
        case("context.control_parts");
        out_str(if control.get(RAX) == 0xaaaa_aaaa_aaaa_aaaa { "rax_kept" } else { "rax_written" });
        out_str(if control.get(RIP) == full.get(RIP) { " rip_same" } else { " rip_differs" });
        out_str(if control.get(RSP) == full.get(RSP) { " rsp_same" } else { " rsp_differs" });
        out_byte(b'\n');
        let mut integer = WindowsContext::new(CONTEXT_INTEGER, 0xaa);
        clear_error();
        bool_case("context.integer", get(worker, integer.0.as_mut_ptr()));
        case("context.integer_parts");
        out_str(if integer.get(RIP) == 0xaaaa_aaaa_aaaa_aaaa { "rip_kept" } else { "rip_written" });
        out_str(if integer.get(RAX) == full.get(RAX) { " rax_same" } else { " rax_differs" });
        out_byte(b'\n');
        let mut debug = WindowsContext::new(CONTEXT_DEBUG_REGISTERS, 0xaa);
        clear_error();
        bool_case("context.debug", get(worker, debug.0.as_mut_ptr()));
        case("context.debug_registers");
        out_str(if debug.0[72..120].iter().all(|&b| b == 0) { "zero" } else { "other" });
        out_byte(b'\n');
        let mut repeat = WindowsContext::new(CONTEXT_FULL, 0);
        get(worker, repeat.0.as_mut_ptr());
        case("context.stable_while_suspended");
        out_str(if repeat.get(RIP) == full.get(RIP) && repeat.get(RSP) == full.get(RSP) { "same" } else { "moved" });
        out_byte(b'\n');

        ret_case("running.resume_to_zero", resume(worker));
        case("running.resumed");
        out_str(moving(sleep, 50));
        out_byte(b'\n');
        ret_case("running.resume_idle", resume(worker));

        let mut live = WindowsContext::new(CONTEXT_CONTROL, 0);
        clear_error();
        bool_case("context.running_thread", get(worker, live.0.as_mut_ptr()));
        let mut own = WindowsContext::new(CONTEXT_CONTROL, 0);
        clear_error();
        bool_case("context.current_thread", get(current(), own.0.as_mut_ptr()));

        // Rights: query-only handles may neither suspend nor read registers.
        let query_only = open(0x40, 0, query_id(worker));
        clear_error();
        ret_case("rights.suspend", suspend(query_only));
        let mut denied = WindowsContext::new(CONTEXT_CONTROL, 0);
        clear_error();
        bool_case("rights.get_context", get(query_only, denied.0.as_mut_ptr()));
        let suspend_only = open(0x2 | 0x40, 0, query_id(worker));
        clear_error();
        ret_case("rights.suspend_right", suspend(suspend_only));
        clear_error();
        bool_case("rights.get_without_right", get(suspend_only, denied.0.as_mut_ptr()));
        ret_case("rights.resume_right", resume(suspend_only));
        close(query_only);
        close(suspend_only);

        // The suspend count's ceiling.
        let mut reached = 0u32;
        let mut failure = 0;
        for _ in 0..200 {
            clear_error();
            if suspend(worker) == u32::MAX {
                failure = last_error();
                break;
            }
            reached += 1;
        }
        case("limit.suspends");
        out_dec(reached as u64);
        out_str(" err=");
        out_dec(failure as u64);
        out_byte(b'\n');
        let mut last = 0;
        for _ in 0..reached {
            last = resume(worker);
        }
        case("limit.last_resume");
        out_dec(last as u64);
        out_byte(b'\n');

        // Redirect the suspended spinner.
        ret_case("redirect.suspend", suspend(worker));
        let mut context = WindowsContext::new(CONTEXT_FULL, 0);
        get(worker, context.0.as_mut_ptr());
        let stack = (context.get(RSP) - 512) & !0xf;
        context.set(RSP, stack - 8);
        context.set(RIP, redirected as usize as u64);
        clear_error();
        bool_case("redirect.set", set(worker, context.0.as_mut_ptr()));
        let mut readback = WindowsContext::new(CONTEXT_CONTROL, 0);
        get(worker, readback.0.as_mut_ptr());
        case("redirect.readback");
        out_str(if readback.get(RIP) == redirected as usize as u64 && readback.get(RSP) == stack - 8 { "new" } else { "old" });
        out_byte(b'\n');
        case("redirect.not_yet");
        out_dec(REDIRECTED.load(Ordering::SeqCst) as u64);
        out_byte(b'\n');
        ret_case("redirect.resume", resume(worker));
        ret_case("redirect.wait", wait(worker, 5000));
        let mut exit = 0;
        code(worker, &mut exit);
        case("redirect.exit_code");
        out_dec(exit as u64);
        out_str(" ran=");
        out_dec(REDIRECTED.load(Ordering::SeqCst) as u64);
        out_byte(b'\n');

        // An exited thread.
        clear_error();
        ret_case("exited.suspend", suspend(worker));
        clear_error();
        ret_case("exited.resume", resume(worker));
        let mut gone = WindowsContext::new(CONTEXT_CONTROL, 0);
        clear_error();
        bool_case("exited.get_context", get(worker, gone.0.as_mut_ptr()));
        clear_error();
        bool_case("exited.set_context", set(worker, context.0.as_mut_ptr()));
        close(worker);

        // A thread blocked in a wait stays held after the wait is satisfied.
        let signal = event(0, 1, 0, 0);
        EVENT.store(signal, Ordering::SeqCst);
        let blocked = thread(0, 0, waiter as usize, 0, 0, &mut id);
        sleep(50);
        ret_case("blocked.suspend", suspend(blocked));
        set_event(signal);
        sleep(50);
        case("blocked.held");
        out_dec(AFTER_WAIT.load(Ordering::SeqCst) as u64);
        out_byte(b'\n');
        ret_case("blocked.resume", resume(blocked));
        ret_case("blocked.wait", wait(blocked, 5000));
        case("blocked.finished");
        out_dec(AFTER_WAIT.load(Ordering::SeqCst) as u64);
        out_byte(b'\n');
        close(blocked);
        close(signal);

        // A thread created suspended counts from one.
        let created = thread(0, 0, quick as usize, 0x1234, 4, &mut id);
        ret_case("created.suspend", suspend(created));
        let mut start = WindowsContext::new(CONTEXT_FULL, 0);
        clear_error();
        bool_case("created.get_context", get(created, start.0.as_mut_ptr()));
        case("created.registers");
        let entry = quick as usize as u64;
        let rip = start.get(RIP) as usize;
        out_str(if start.get(RIP) == entry { "rip=start" } else if rip >= image && rip < image_end { "rip=in_image" } else { "rip=outside" });
        out_str(if start.get(128) == entry { " rcx=start" } else { " rcx=other" });
        out_str(if start.get(136) == 0x1234 { " rdx=parameter" } else { " rdx=other" });
        out_byte(b'\n');
        clear_error();
        bool_case("created.set_context", set(created, start.0.as_mut_ptr()));
        ret_case("created.resume_to_one", resume(created));
        ret_case("created.waits", wait(created, 50));
        ret_case("created.resume_to_zero", resume(created));
        ret_case("created.wait", wait(created, 5000));
        let mut exit = 0;
        code(created, &mut exit);
        case("created.exit_code");
        out_dec(exit as u64);
        out_byte(b'\n');
        close(created);
    }
    out_str("END\n");
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe thread_context\n");
    probe();
    flush();
    unsafe { ExitProcess(0) }
}
