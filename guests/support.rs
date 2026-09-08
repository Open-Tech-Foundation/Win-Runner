// Shared no_std guest support: allocator, OOM gates, C intrinsics.
// Included via `include!("support.rs")` by the `alloc`-family guests
// (plain `rustc` builds, no cargo). See alloc.rs for the full story.

use core::alloc::{GlobalAlloc, Layout};

extern "C" {
    fn GetProcessHeap() -> u64;
    fn HeapAlloc(h: u64, flags: u32, bytes: u32) -> u64;
    fn HeapFree(h: u64, flags: u32, ptr: u64) -> i32;
    fn ExitProcess(code: u32) -> !;
}

pub struct WinHeap;

unsafe impl GlobalAlloc for WinHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > 16 {
            return core::ptr::null_mut();
        }
        let size = layout.size().max(1);
        if size > u32::MAX as usize {
            return core::ptr::null_mut();
        }
        HeapAlloc(GetProcessHeap(), 0, size as u32) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if !ptr.is_null() {
            HeapFree(GetProcessHeap(), 0, ptr as u64);
        }
    }
}

#[global_allocator]
static HEAP: WinHeap = WinHeap;

/// Link gate called on every `alloc::alloc::{alloc, ...}` call. Empty by
/// design; toolchain-specific name fails loudly at link on mismatch.
#[export_name = "_RNvCsfLfy6EI15iL_7___rustc35___rust_no_alloc_shim_is_unstable_v2"]
pub extern "C" fn alloc_shim_gate() {}

/// OOM handler the alloc crate calls via this exact symbol. Clean halt.
#[export_name = "_RNvCsfLfy6EI15iL_7___rustc26___rust_alloc_error_handler"]
pub extern "C" fn oom_halt(_size: usize, _align: usize) -> ! {
    unsafe { ExitProcess(70) }
}

/// C memory intrinsics the compiler may reference (no CRT provides them).
/// Volatile ops throughout so LLVM can never re-lower these bodies into
/// recursive calls to themselves.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) < (src as usize) || dst.wrapping_add(n) <= src as *mut u8 {
        let mut i = 0;
        while i < n {
            core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        }
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(s.add(i), c as u8);
        i += 1;
    }
    s
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let x = core::ptr::read_volatile(a.add(i));
        let y = core::ptr::read_volatile(b.add(i));
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

/// Byte length of a NUL-terminated string (volatile: never re-lowered).
#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut n = 0;
    while core::ptr::read_volatile(s.add(n)) != 0 {
        n += 1;
    }
    n
}

/// Stack prober for large frames (driftsort etc.). Probes each page so the
/// guard page grows the stack; ours is fully committed, so probes always
/// succeed. Standard MSVC x64 sequence; `#[naked]` keeps it exact.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __chkstk() {
    core::arch::naked_asm!(
        "push rcx",
        "cmp rax, 0x1000",
        "lea rcx, [rsp + 8]",
        "jb 2f",
        "0:",
        "sub rcx, 0x1000",
        "test dword ptr [rcx], eax",
        "sub rax, 0x1000",
        "cmp rax, 0x1000",
        "ja 0b",
        "2:",
        "sub rcx, rax",
        "mov rax, rcx",
        "pop rcx",
        "ret",
    )
}

/// C++ unwinder personality. Unreachable under `panic=abort` (no unwinding
/// ever runs); present only to satisfy `.xdata` references at link time.
#[no_mangle]
pub extern "C" fn __CxxFrameHandler3(
    _rec: *mut u8,
    _frame: *mut u8,
    _ctx: *mut u8,
    _disp: *mut u8,
) -> u32 {
    1 // ExceptionContinueSearch (never actually invoked)
}

/// FP marker normally satisfied by the CRT.
#[no_mangle]
pub static _fltused: i32 = 0;

#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(99) }
}

#[allow(dead_code)]
pub const INVALID_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFFF;
