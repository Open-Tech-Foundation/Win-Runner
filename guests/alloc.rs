//! Allocator guest for WinCLI: `Vec`/`String`/`format!` on a HeapAlloc heap.
//!
//! A `#[global_allocator]` backed by `HeapAlloc`/`HeapFree` plus an
//! `#[alloc_error_handler]` give `extern crate alloc` everything it needs:
//! no CRT, no extra imports. Each phase prints `A<n>`; mismatch prints
//! `FAIl<n>`-style `FAIL<n>` and exits 1; final `PASS` + exit 0.
//! Build with `guests/build.sh`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};

extern "C" {
    fn GetStdHandle(nStdHandle: i32) -> u64;
    fn WriteFile(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: u64) -> i32;
    fn ExitProcess(code: u32) -> !;
    fn GetProcessHeap() -> u64;
    fn HeapAlloc(h: u64, flags: u32, bytes: u32) -> u64;
    fn HeapFree(h: u64, flags: u32, ptr: u64) -> i32;
}

struct WinHeap;

unsafe impl GlobalAlloc for WinHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // HeapAlloc aligns to 16; layouts needing more get a clear OOM.
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
/// design: upstream uses it only to gate stable use, and our toolchain is
/// fixed (a mismatch fails loudly at link with "undefined symbol").
///
/// The mangled name is toolchain-specific (`rustc --version`): if a
/// toolchain upgrade breaks the guest link on this symbol, update the
/// `export_name` below from the linker's error message.
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

#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(99) }
}

/// FP marker normally satisfied by the CRT (see fp.rs).
#[no_mangle]
pub static _fltused: i32 = 0;

fn print(s: &[u8]) {
    unsafe {
        let mut w: u32 = 0;
        WriteFile(GetStdHandle(-11), s.as_ptr(), s.len() as u32, &mut w, 0);
    }
}

fn fail(n: u8) -> ! {
    print(b"FAIL");
    print(&[b'0' + n]);
    print(b"\n");
    unsafe { ExitProcess(1) }
}

fn check(ok: bool, n: u8) {
    if !ok {
        fail(n);
    }
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    // A1: Vec push/extend/pop/len/sum.
    let mut v: Vec<u32> = Vec::new();
    for i in 1..=10u32 {
        v.push(i);
    }
    check(v.len() == 10, 1);
    check(v.iter().sum::<u32>() == 55, 1);
    check(v.pop() == Some(10), 1);
    v.extend([20, 30].iter().copied());
    check(v.len() == 11 && v[9] == 20 && v[10] == 30, 1);
    print(b"A1\n");

    // A2: String + format!.
    let s: String = format!("{}+{}={}", 20, 22, 42);
    check(s == "20+22=42", 2);
    let mut t = String::from("ab");
    t.push_str("cd");
    t.push('!');
    check(t == "abcd!", 2);
    print(b"A2\n");

    // A3: closures over iterators.
    let q: u32 = (0..10u32).filter(|x| x % 2 == 0).map(|x| x * x).sum();
    check(q == 120, 3);
    let words = ["pear", "fig", "apple", "kiwi"];
    let mut long: Vec<&str> = words.iter().copied().filter(|w| w.len() > 4).collect();
    long.sort();
    check(long == ["apple"], 3);
    print(b"A3\n");

    // A4: Box + BTreeMap.
    let b = alloc::boxed::Box::new(7u32);
    check(*b == 7, 4);
    let mut m: BTreeMap<&str, u32> = BTreeMap::new();
    m.insert("one", 1);
    m.insert("two", 2);
    check(m.get("one") == Some(&1), 4);
    check(m.len() == 2, 4);
    check(m.remove("one") == Some(1), 4);
    check(m.get("one").is_none(), 4);
    print(b"A4\n");

    // A5: Vec<String> + join.
    let parts: Vec<String> = ["x", "yy", "zzz"].iter().map(|s| String::from(*s)).collect();
    check(parts.join(",") == "x,yy,zzz", 5);
    print(b"A5\n");

    print(b"PASS\n");
    unsafe { ExitProcess(0) }
}
