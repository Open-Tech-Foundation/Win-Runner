//! Floating-point guest for Win-Runner: scalar-double arithmetic and compare.
//!
//! Exercises MOVSD/ADDSD/SUBSD/MULSD/DIVSD/CMPLTSD/UCOMISD/ANDPD via real
//! rustc output (`black_box` defeats constant folding). Prints `FP-OK` +
//! exit 0 on success. Build with `guests/build.sh`.

#![no_std]
#![no_main]

use core::hint::black_box;

extern "C" {
    fn GetStdHandle(nStdHandle: i32) -> u64;
    fn WriteFile(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: u64) -> i32;
    fn ExitProcess(code: u32) -> !;
}

#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(99) }
}

/// MSVC emits a `_fltused` reference for FP code (normally satisfied by the
/// CRT); no-CRT guests define it themselves. Value is irrelevant here.
#[no_mangle]
pub static _fltused: i32 = 0;

fn print(s: &[u8]) {
    unsafe {
        let mut w: u32 = 0;
        WriteFile(GetStdHandle(-11), s.as_ptr(), s.len() as u32, &mut w, 0);
    }
}

fn fail() -> ! {
    print(b"FP-BAD\n");
    unsafe { ExitProcess(1) }
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    let a: f64 = black_box(1.5);
    let b: f64 = black_box(2.25);
    let c = a + b * 2.0 - a / b;
    // c should be 1.5 + 4.5 - 0.666... = 5.333...; check tightly
    let d = if c > 5.333333333333334 {
        c - 5.333333333333334
    } else {
        5.333333333333334 - c
    };
    if d > 0.000001 {
        fail();
    }
    // comparisons incl. unordered path (NaN never less/equal)
    if !(a < b) {
        fail();
    }
    if !(b > a) {
        fail();
    }
    if a == b {
        fail();
    }
    let nan = black_box(0.0) / black_box(0.0);
    if nan == nan {
        fail();
    }
    print(b"FP-OK\n");
    unsafe { ExitProcess(0) }
}
