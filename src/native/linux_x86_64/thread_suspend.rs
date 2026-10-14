//! `SuspendThread`, `ResumeThread`, `GetThreadContext` and
//! `SetThreadContext` on running guest threads.
//!
//! Guest threads are host threads. Suspending one sends it a real-time
//! signal; its handler saves the registers as a Windows CONTEXT in the
//! thread's slot, marks it parked, and waits (on a futex) to be released.
//! `GetThreadContext` reads the saved CONTEXT, `SetThreadContext` changes
//! it, and the handler applies the change to the signal frame when
//! `ResumeThread` releases it, so execution continues from the new
//! registers, as runtimes that redirect suspended threads (CoreCLR's
//! garbage collector) expect.
//!
//! A thread created suspended and not yet started waits at its start gate
//! instead; suspending it only counts.

use super::*;
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

const SLOTS: usize = 1024;
const CONTEXT_CONTROL: u32 = 0x0010_0001;
const CONTEXT_INTEGER: u32 = 0x0010_0002;
const CONTEXT_SEGMENTS: u32 = 0x0010_0004;
const CONTEXT_FLOATING_POINT: u32 = 0x0010_0008;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;

/// One thread's suspension state; slots are claimed by thread id and never
/// freed, so the signal handler can find its slot without allocating.
struct SuspendSlot {
    tid: AtomicI32,
    /// 1 while the thread waits in the handler with its registers saved.
    parked: AtomicU32,
    /// Bumped to release a parked thread.
    release: AtomicU32,
    modified: AtomicBool,
    context: UnsafeCell<NativeExceptionContext>,
}

unsafe impl Sync for SuspendSlot {}

static SUSPEND_SLOTS: [SuspendSlot; SLOTS] = [const {
    SuspendSlot {
        tid: AtomicI32::new(0),
        parked: AtomicU32::new(0),
        release: AtomicU32::new(0),
        modified: AtomicBool::new(false),
        context: UnsafeCell::new(NativeExceptionContext { bytes: [0; 1232] }),
    }
}; SLOTS];

static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

fn suspend_signal() -> i32 {
    libc::SIGRTMIN() + 3
}

fn find_slot(tid: i32) -> Option<&'static SuspendSlot> {
    SUSPEND_SLOTS.iter().find(|slot| slot.tid.load(Ordering::Acquire) == tid)
}

fn claim_slot(tid: i32) -> Option<&'static SuspendSlot> {
    if let Some(slot) = find_slot(tid) {
        return Some(slot);
    }
    SUSPEND_SLOTS.iter().find(|slot| slot.tid.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire).is_ok())
}

fn futex_wait(word: &AtomicU32, expected: u32, timeout: Option<libc::timespec>) {
    let timeout = timeout.as_ref().map_or(ptr::null(), |t| t as *const libc::timespec);
    unsafe {
        libc::syscall(libc::SYS_futex, word.as_ptr(), libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG, expected, timeout);
    }
}

fn futex_wake(word: &AtomicU32) {
    unsafe {
        libc::syscall(libc::SYS_futex, word.as_ptr(), libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG, i32::MAX);
    }
}

fn install_handler() -> bool {
    if HANDLER_INSTALLED.load(Ordering::Acquire) {
        return true;
    }
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = suspend_signal_handler as *const () as usize;
    // Interrupted system calls restart once the thread resumes.
    action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
    unsafe { libc::sigfillset(&mut action.sa_mask) };
    for fault in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE] {
        unsafe { libc::sigdelset(&mut action.sa_mask, fault) };
    }
    if unsafe { libc::sigaction(suspend_signal(), &action, ptr::null_mut()) } != 0 {
        return false;
    }
    HANDLER_INSTALLED.store(true, Ordering::Release);
    true
}

extern "C" fn suspend_signal_handler(_: libc::c_int, _: *mut libc::siginfo_t, context: *mut std::ffi::c_void) {
    let Some(slot) = find_slot(unsafe { linux_current_thread_id() }) else {
        return;
    };
    let frame = context.cast::<libc::ucontext_t>();
    let generation = slot.release.load(Ordering::Acquire);
    unsafe { *slot.context.get() = context_from_linux_ucontext(&*frame) };
    slot.modified.store(false, Ordering::Release);
    slot.parked.store(1, Ordering::Release);
    futex_wake(&slot.parked);
    while slot.release.load(Ordering::Acquire) == generation {
        futex_wait(&slot.release, generation, None);
    }
    if slot.modified.load(Ordering::Acquire) {
        unsafe { apply_windows_context_to_linux_ucontext(&*slot.context.get(), &mut *frame) };
    }
    slot.parked.store(0, Ordering::Release);
    futex_wake(&slot.parked);
}

/// Stop the running thread `tid` and wait until its registers are saved.
pub(super) fn stop_thread(tid: i32) -> Result<(), u32> {
    if !install_handler() {
        return Err(31); // ERROR_GEN_FAILURE
    }
    let slot = claim_slot(tid).ok_or(8u32)?; // ERROR_NOT_ENOUGH_MEMORY
    if slot.parked.load(Ordering::Acquire) == 1 {
        return Ok(());
    }
    let pid = unsafe { libc::getpid() };
    if unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, suspend_signal()) } != 0 {
        return Err(5); // the thread has exited
    }
    // The calling thread suspending itself returns once it is resumed.
    if tid == unsafe { libc::gettid() } {
        return Ok(());
    }
    let timeout = libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 };
    for _ in 0..200 {
        if slot.parked.load(Ordering::Acquire) == 1 {
            return Ok(());
        }
        futex_wait(&slot.parked, 0, Some(timeout));
        // Still running and gone: the thread exited before stopping.
        if unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, 0) } != 0 {
            return Err(5);
        }
    }
    Err(1460) // ERROR_TIMEOUT
}

/// Release the stopped thread `tid`.
pub(super) fn release_thread(tid: i32) {
    if let Some(slot) = find_slot(tid) {
        if slot.parked.load(Ordering::Acquire) == 1 {
            slot.release.fetch_add(1, Ordering::AcqRel);
            futex_wake(&slot.release);
        }
    }
}

/// The saved CONTEXT of the stopped thread `tid`.
fn stopped_context(tid: i32) -> Option<&'static SuspendSlot> {
    find_slot(tid).filter(|slot| slot.parked.load(Ordering::Acquire) == 1)
}

pub(super) extern "win64" fn native_suspend_thread(handle: u64) -> u32 {
    let thread = match require_thread_handle(handle, 0x2) {
        Ok(thread) => thread,
        Err(error) => {
            native_set_last_error(error);
            return u32::MAX;
        }
    };
    let info = &thread.queue.thread;
    if native_diagnostic_enabled() {
        eprintln!("native SuspendThread handle={handle:#x} tid={} running={}", info.host_tid.load(Ordering::Acquire), info.running.load(Ordering::Acquire));
    }
    let (count, _) = &*info.suspension;
    let Ok(mut count) = count.lock() else {
        return u32::MAX;
    };
    let previous = *count;
    if previous >= 127 {
        native_set_last_error(156); // ERROR_SIGNAL_REFUSED: MAXIMUM_SUSPEND_COUNT
        return u32::MAX;
    }
    *count += 1;
    if previous == 0 && info.running.load(Ordering::Acquire) {
        let tid = info.host_tid.load(Ordering::Acquire);
        drop(count);
        if let Err(error) = stop_thread(tid) {
            if let Ok(mut count) = info.suspension.0.lock() {
                *count -= 1;
            }
            native_set_last_error(error);
            return u32::MAX;
        }
    }
    previous
}

/// Release a running thread whose suspend count reached zero.
pub(super) fn resume_running_thread(info: &NativeThreadInfo) {
    if info.running.load(Ordering::Acquire) {
        release_thread(info.host_tid.load(Ordering::Acquire));
    }
}

/// The thread a handle names, or the calling thread.
fn context_thread(handle: u64) -> Result<Option<i32>, u32> {
    let thread = require_thread_handle(handle, 0x8)?; // THREAD_GET_CONTEXT
    let tid = thread.queue.thread.host_tid.load(Ordering::Acquire);
    Ok((tid != unsafe { libc::gettid() }).then_some(tid))
}

/// Copy the parts of `source` that `flags` asks for into `destination`.
fn copy_context(source: &[u8], destination: &mut [u8], flags: u32, include_rsp_rip: bool) {
    let mut copy = |start: usize, end: usize| destination[start..end].copy_from_slice(&source[start..end]);
    if flags & CONTEXT_CONTROL == CONTEXT_CONTROL {
        copy(56, 58); // SegCs
        copy(66, 72); // SegSs, EFlags
        if include_rsp_rip {
            copy(152, 160); // Rsp
            copy(248, 256); // Rip
        }
    }
    if flags & CONTEXT_INTEGER == CONTEXT_INTEGER {
        copy(120, 152); // Rax, Rcx, Rdx, Rbx
        copy(160, 248); // Rbp .. R15
    }
    if flags & CONTEXT_SEGMENTS == CONTEXT_SEGMENTS {
        copy(58, 66); // SegDs, SegEs, SegFs, SegGs
    }
    if flags & CONTEXT_FLOATING_POINT == CONTEXT_FLOATING_POINT {
        copy(52, 56); // MxCsr
        copy(256, 768); // FltSave
    }
}

pub(super) extern "win64" fn native_get_thread_context(handle: u64, context: *mut u8) -> i32 {
    if context.is_null() {
        native_set_last_error(998);
        return 0;
    }
    let flags = unsafe { context.add(48).cast::<u32>().read_unaligned() };
    let destination = unsafe { std::slice::from_raw_parts_mut(context, 1232) };
    if native_diagnostic_enabled() {
        eprintln!("native GetThreadContext handle={handle:#x} flags={flags:#x}");
    }
    match context_thread(handle) {
        Ok(Some(tid)) => {
            let Some(slot) = stopped_context(tid) else {
                native_set_last_error(5); // a running thread's registers move
                return 0;
            };
            copy_context(unsafe { &(*slot.context.get()).bytes }, destination, flags, true);
        }
        Ok(None) => {
            // The calling thread: its registers here, as RtlCaptureContext.
            let mut captured = NativeExceptionContext { bytes: [0; 1232] };
            unsafe { winrun_native_rtl_capture_context(captured.bytes.as_mut_ptr()) };
            copy_context(&captured.bytes, destination, flags, true);
        }
        Err(error) => {
            native_set_last_error(error);
            return 0;
        }
    }
    if flags & CONTEXT_DEBUG_REGISTERS == CONTEXT_DEBUG_REGISTERS {
        destination[72..120].fill(0); // no hardware breakpoints are set
    }
    1
}

pub(super) extern "win64" fn native_set_thread_context(handle: u64, context: *const u8) -> i32 {
    if context.is_null() {
        native_set_last_error(998);
        return 0;
    }
    let flags = unsafe { context.add(48).cast::<u32>().read_unaligned() };
    let source = unsafe { std::slice::from_raw_parts(context, 1232) };
    if native_diagnostic_enabled() {
        let rip = u64::from_le_bytes(source[248..256].try_into().unwrap());
        let rsp = u64::from_le_bytes(source[152..160].try_into().unwrap());
        eprintln!("native SetThreadContext handle={handle:#x} flags={flags:#x} rip={rip:#x} rsp={rsp:#x}");
    }
    match context_thread(handle) {
        Ok(Some(tid)) => {
            let Some(slot) = stopped_context(tid) else {
                native_set_last_error(5);
                return 0;
            };
            copy_context(source, unsafe { &mut (*slot.context.get()).bytes }, flags, true);
            slot.modified.store(true, Ordering::Release);
            1
        }
        Ok(None) => {
            native_set_last_error(50); // the calling thread's own registers
            0
        }
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_thread_stops_with_its_registers_and_resumes_where_set() {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        static TID: AtomicI32 = AtomicI32::new(0);
        let worker = std::thread::spawn(|| {
            TID.store(unsafe { libc::gettid() }, Ordering::Release);
            while COUNTER.load(Ordering::Relaxed) < u32::MAX {
                COUNTER.fetch_add(1, Ordering::Relaxed);
                if COUNTER.load(Ordering::Relaxed) == u32::MAX - 1 {
                    break;
                }
            }
        });
        while TID.load(Ordering::Acquire) == 0 {
            std::thread::yield_now();
        }
        let tid = TID.load(Ordering::Acquire);
        stop_thread(tid).unwrap();
        let slot = stopped_context(tid).expect("parked with its registers");
        let before = COUNTER.load(Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(COUNTER.load(Ordering::Relaxed), before, "a stopped thread does not run");
        let rip = context_register(unsafe { &*slot.context.get() }, 16).unwrap();
        assert_ne!(rip, 0, "the saved context has the thread's instruction pointer");
        release_thread(tid);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(COUNTER.load(Ordering::Relaxed) > before, "a released thread runs again");
        COUNTER.store(u32::MAX - 1, Ordering::Relaxed);
        worker.join().unwrap();
    }

    #[test]
    fn context_parts_copy_by_flag() {
        let source: Vec<u8> = (0..1232).map(|i| (i % 251) as u8 + 1).collect();
        let mut destination = vec![0u8; 1232];
        copy_context(&source, &mut destination, CONTEXT_INTEGER, true);
        assert_eq!(destination[120..152], source[120..152], "rax..rbx");
        assert_eq!(destination[248..256], [0; 8], "rip is control, not integer");
        copy_context(&source, &mut destination, CONTEXT_CONTROL, true);
        assert_eq!(destination[248..256], source[248..256]);
        assert_eq!(destination[256..768], [0; 512][..], "no floating point without the flag");
    }
}
