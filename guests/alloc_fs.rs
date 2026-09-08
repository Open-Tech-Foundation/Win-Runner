//! Alloc + WinFS guest for WinCLI: formatted file write/read roundtrip.
//!
//! Builds file content with `format!` (width, precision, padding, floats),
//! writes it via CreateFileW/WriteFile, reads it back, and verifies exact
//! equality. Then cleans up. Prints `F<n>` phases, final `PASS`, exit 0.
//! Shared allocator/support via `include!("support.rs")`. Build with `guests/build.sh`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
include!("support.rs");

extern "C" {
    fn GetStdHandle(nStdHandle: i32) -> u64;
    fn WriteFile(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: u64) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        sec: u64,
        creation: u32,
        flags: u32,
        tmpl: u64,
    ) -> u64;
    fn ReadFile(h: u64, buf: *mut u8, n: u32, read: *mut u32, ov: u64) -> i32;
    fn CloseHandle(h: u64) -> i32;
    fn CreateDirectoryW(path: *const u16, sec: u64) -> i32;
    fn RemoveDirectoryW(path: *const u16, sec: u64) -> i32;
    fn DeleteFileW(path: *const u16) -> i32;
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

fn to_utf16(dst: &mut [u16], src: &[u8]) -> *const u16 {
    let mut i = 0;
    while i < src.len() && i + 1 < dst.len() {
        dst[i] = src[i] as u16;
        i += 1;
    }
    dst[i] = 0;
    dst.as_ptr()
}

fn open(path: *const u16, access: u32, creation: u32) -> u64 {
    unsafe { CreateFileW(path, access, 0, 0, creation, 0x80, 0) }
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    let mut raw_dir = core::mem::MaybeUninit::<[u16; 32]>::uninit();
    let mut raw_path = core::mem::MaybeUninit::<[u16; 32]>::uninit();
    let dir = to_utf16(unsafe { &mut *raw_dir.as_mut_ptr() }, b"C:\\afstest");
    let path = to_utf16(unsafe { &mut *raw_path.as_mut_ptr() }, b"C:\\afstest\\out.txt");

    // F1: formatting (width, precision, padding, float).
    let head = format!("{:>8}|{:<8}|{:08}|{:#x}", "hi", "hi", 42, 255);
    check(head == "      hi|hi      |00000042|0xff", 1);
    let pi = format!("{:.2}", 3.14159);
    check(pi == "3.14", 1);
    print(b"F1\n");

    // F2: mkdir + write formatted content.
    check(unsafe { CreateDirectoryW(dir, 0) } != 0, 2);
    let body: String = format!("n={}\npi={}\nhead={}\n", 7, pi, head);
    let h = open(path, 0x4000_0000, 2);
    check(h != INVALID_HANDLE, 2);
    let mut w: u32 = 0;
    check(
        unsafe { WriteFile(h, body.as_ptr(), body.len() as u32, &mut w, 0) } != 0
            && w == body.len() as u32,
        2,
    );
    check(unsafe { CloseHandle(h) } != 0, 2);
    print(b"F2\n");

    // F3: read back + exact verify.
    let h = open(path, 0x8000_0000, 3);
    check(h != INVALID_HANDLE, 3);
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(256, 0);
    let mut n: u32 = 0;
    check(
        unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, 0) } != 0,
        3,
    );
    check(unsafe { CloseHandle(h) } != 0, 3);
    buf.truncate(n as usize);
    check(buf == body.as_bytes(), 3);
    let back = String::from_utf8(buf).unwrap_or_default();
    check(back.contains("n=7") && back.contains("pi=3.14"), 3);
    print(b"F3\n");

    // F4: delete + rmdir (second delete must fail).
    check(unsafe { DeleteFileW(path) } != 0, 4);
    check(unsafe { DeleteFileW(path) } == 0, 4);
    check(unsafe { RemoveDirectoryW(dir, 0) } != 0, 4);
    print(b"F4\n");

    print(b"PASS\n");
    unsafe { ExitProcess(0) }
}
