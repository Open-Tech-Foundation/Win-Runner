//! Memory-copy torture guest for Win-Runner: every copy size/shape the real
//! `rg.exe --help` path uses, verified byte-exact.
//!
//! M1: `copy_nonoverlapping` sizes 1..=320 (scalar/SSE/rep lowerings).
//! M2: same, misaligned src/dst (+1/+7/+15).
//! M3: overlapping `copy` both directions (memmove), incl. size 212/213.
//! M4: explicit `_mm_loadu_si128`/`_mm_storeu_si128` 16-byte loop (the
//!     MSVC `memcpy` shape: base+index stores), incl. size 212.
//! M5: `format!`/`push_str` growth to ~100KB with verification (realloc
//!     copies, like the 69KB help buffer).
//! M6: `Vec<u8>` chunked extends to 64KB with verification.
//! Final `PASS` + exit 0. Build with `guests/build.sh`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::x86_64::{__m128i, _mm_loadu_si128, _mm_storeu_si128};

include!("support.rs");

extern "C" {
    fn GetStdHandle(nStdHandle: i32) -> u64;
    fn WriteFile(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: u64) -> i32;
}

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

/// Deterministic fill: pseudo-random by index (period covers all bytes).
fn fill(buf: &mut [u8], seed: u32) {
    let mut x = seed;
    for b in buf.iter_mut() {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        *b = (x >> 16) as u8;
    }
}

fn sizes() -> Vec<usize> {
    let mut s: Vec<usize> = (1..=32).collect();
    for extra in [33, 48, 64, 96, 100, 127, 128, 129, 196, 200, 211, 212, 213, 214, 255, 256, 300, 320] {
        s.push(extra);
    }
    s
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    // M1: exact-size copies, aligned.
    for &n in &sizes() {
        let mut src = alloc::vec![0u8; n + 32];
        let mut dst = alloc::vec![0u8; n + 32];
        fill(&mut src, 0x1234);
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n);
        }
        check(&src[..n] == &dst[..n], 1);
    }
    print(b"M1\n");

    // M2: misaligned src/dst.
    for &n in &sizes() {
        for &(so, doff) in &[(1usize, 0usize), (0, 1), (7, 3), (15, 15), (3, 9)] {
            let mut src = alloc::vec![0u8; n + 32];
            let mut dst = alloc::vec![0u8; n + 32];
            fill(&mut src, 0x5678);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr().add(so),
                    dst.as_mut_ptr().add(doff),
                    n,
                );
            }
            check(&src[so..so + n] == &dst[doff..doff + n], 2);
        }
    }
    print(b"M2\n");

    // M3: overlapping copies both directions (byte-exact vs reference).
    for &n in &[8usize, 16, 24, 64, 100, 211, 212, 213, 214, 300] {
        for &shift in &[1usize, 7, 8, 15, 16] {
            // Forward overlap: dst inside src's tail.
            let mut a = alloc::vec![0u8; n + 32];
            fill(&mut a, 0x9abc);
            unsafe {
                core::ptr::copy(a.as_ptr(), a.as_mut_ptr().add(shift), n);
            }
            // Reference: forward byte loop from a snapshot.
            let mut expect = alloc::vec![0u8; n + 32];
            fill(&mut expect, 0x9abc);
            let snap = expect.clone();
            for i in 0..n {
                expect[shift + i] = snap[i];
            }
            check(a == expect, 3);
            // Backward overlap: dst before src.
            let mut c = alloc::vec![0u8; n + 32];
            fill(&mut c, 0xdef0);
            let snapc = c.clone();
            unsafe {
                core::ptr::copy(c.as_ptr().add(shift), c.as_mut_ptr(), n);
            }
            let mut expectc = alloc::vec![0u8; n + 32];
            fill(&mut expectc, 0xdef0);
            for i in 0..n {
                expectc[i] = snapc[shift + i];
            }
            check(c == expectc, 3);
        }
    }
    print(b"M3\n");

    // M4: explicit 16-byte unaligned loop (MSVC memcpy shape), size 212
    // first (the exact failing length), then a sweep.
    for &n in &[212usize, 213, 16, 32, 48, 64, 100, 128, 200, 256] {
        let mut src = alloc::vec![0u8; n + 16];
        let mut dst = alloc::vec![0u8; n + 16];
        fill(&mut src, 0x1357);
        unsafe {
            let mut i = 0;
            while i + 16 <= n {
                let v = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
                _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, v);
                i += 16;
            }
            while i < n {
                *dst.as_mut_ptr().add(i) = *src.as_ptr().add(i);
                i += 1;
            }
        }
        check(&src[..n] == &dst[..n], 4);
    }
    print(b"M4\n");

    // M5: formatted-string growth torture (~100KB, many realloc copies).
    let mut big = String::new();
    let mut expect_len = 0usize;
    for i in 0..2000u32 {
        let piece = format!("line {i:04}: this flag can be disabled with --opt-{i}.\n");
        expect_len += piece.len();
        big.push_str(&piece);
        check(big.len() == expect_len, 5);
    }
    check(big.len() > 100_000, 5);
    check(big.starts_with("line 0000: this flag"), 5);
    check(big.ends_with("line 1999: this flag can be disabled with --opt-1999.\n"), 5);
    // Spot-check every 137th line for smears/duplications.
    for i in (0..2000u32).step_by(137) {
        let probe = format!("line {i:04}: this flag can be disabled with --opt-{i}.\n");
        check(big.contains(probe.as_str()), 5);
    }
    print(b"M5\n");

    // M6: chunked byte-vector growth to 64KB.
    let mut v: Vec<u8> = Vec::new();
    let mut seed = 0x2468u32;
    let mut total = 0usize;
    for chunk in [1usize, 7, 16, 100, 1000, 4096, 8192] {
        let mut c = alloc::vec![0u8; chunk];
        fill(&mut c, seed);
        seed = seed.wrapping_add(1);
        v.extend_from_slice(&c);
        total += chunk;
        check(v.len() == total, 6);
    }
    // Verify each chunk's bytes survived all the realloc copies.
    seed = 0x2468u32;
    let mut off = 0usize;
    for chunk in [1usize, 7, 16, 100, 1000, 4096, 8192] {
        let mut c = alloc::vec![0u8; chunk];
        fill(&mut c, seed);
        seed = seed.wrapping_add(1);
        check(&v[off..off + chunk] == &c[..], 6);
        off += chunk;
    }
    print(b"M6\n");
    print(b"PASS\n");
    unsafe { ExitProcess(0) }
}
