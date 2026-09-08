//! Allocator guest for WinCLI: `Vec`/`String`/`format!` on a HeapAlloc heap.
//!
//! `include!("support.rs")` provides the allocator, OOM gates and C
//! intrinsics; this file adds the `A<n>` phases. Final `PASS` + exit 0.
//! Build with `guests/build.sh`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

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
