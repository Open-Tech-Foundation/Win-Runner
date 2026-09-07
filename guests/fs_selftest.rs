//! Rust FS self-test guest for WinCLI (`x86_64-pc-windows-msvc`).
//!
//! `no_std` + `no_main` + custom entry: exercises every Win32 FS API WinCLI
//! implements, verifies results inside the guest, and reports `PASS` + exit 0
//! (or `FAIL` + exit 1). Build with `guests/build.sh`.
//!
//! Deliberately plain code (byte slices, `while` loops, scalar stores) so the
//! compiler emits only basic x86_64: no `memcpy`/`memset` calls, no SSE, no
//! 64-bit division.

#![no_std]
#![no_main]

extern "C" {
    fn GetStdHandle(nStdHandle: i32) -> u64;
    fn WriteFile(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: u64) -> i32;
    fn ExitProcess(code: u32) -> !;
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
    fn RemoveDirectoryW(path: *const u16) -> i32;
    fn DeleteFileW(path: *const u16) -> i32;
    fn MoveFileW(src: *const u16, dst: *const u16) -> i32;
    fn CopyFileW(src: *const u16, dst: *const u16, fail_if_exists: i32) -> i32;
}

const INVALID_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;

#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(99) }
}

fn print(s: &[u8]) {
    unsafe {
        let mut written: u32 = 0;
        WriteFile(GetStdHandle(-11), s.as_ptr(), s.len() as u32, &mut written, 0);
    }
}

fn fail() -> ! {
    print(b"FAIL\n");
    unsafe { ExitProcess(1) }
}

fn check(ok: bool) {
    if !ok {
        fail();
    }
}

/// ASCII bytes -> NUL-terminated UTF-16 in `dst`. Returns stable pointer.
fn to_utf16<'a>(dst: &'a mut [u16], src: &[u8]) -> *const u16 {
    let mut i = 0;
    while i < src.len() && i + 1 < dst.len() {
        dst[i] = src[i] as u16;
        i += 1;
    }
    dst[i] = 0;
    dst.as_ptr()
}

fn zero_bytes(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        buf[i] = 0;
        i += 1;
    }
}

fn open(path: *const u16, access: u32, creation: u32) -> u64 {
    unsafe { CreateFileW(path, access, 0, 0, creation, 0x80, 0) }
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    // Scratch buffers. Declared as MaybeUninit and filled explicitly, so the
    // compiler emits plain scalar stores (no memset/SSE lowering).
    let mut raw_dir = core::mem::MaybeUninit::<[u16; 32]>::uninit();
    let mut raw_a = core::mem::MaybeUninit::<[u16; 32]>::uninit();
    let mut raw_b = core::mem::MaybeUninit::<[u16; 32]>::uninit();
    let mut raw_c = core::mem::MaybeUninit::<[u16; 32]>::uninit();
    let mut raw_buf = core::mem::MaybeUninit::<[u8; 64]>::uninit();
    let buf: &mut [u8] = unsafe { &mut *raw_buf.as_mut_ptr() };
    zero_bytes(&mut *buf);

    let dir = to_utf16(unsafe { &mut *raw_dir.as_mut_ptr() }, b"C:\\gdir");
    let a = to_utf16(unsafe { &mut *raw_a.as_mut_ptr() }, b"C:\\gdir\\a.txt");
    let b = to_utf16(unsafe { &mut *raw_b.as_mut_ptr() }, b"C:\\gdir\\b.txt");
    let c = to_utf16(unsafe { &mut *raw_c.as_mut_ptr() }, b"C:\\GDIR\\C.txt");

    let data = b"rust-fs-bytes-7";

    // mkdir: success, then duplicate must fail.
    check(unsafe { CreateDirectoryW(dir, 0) } != 0);
    check(unsafe { CreateDirectoryW(dir, 0) } == 0);

    // create + write a.
    let h = open(a, GENERIC_WRITE, CREATE_ALWAYS);
    check(h != INVALID_HANDLE);
    let mut w: u32 = 0;
    check(unsafe { WriteFile(h, data.as_ptr(), data.len() as u32, &mut w, 0) } != 0);
    check(w == data.len() as u32);
    check(unsafe { CloseHandle(h) } != 0);

    // open + read a back, verify length and bytes.
    let h = open(a, GENERIC_READ, OPEN_EXISTING);
    check(h != INVALID_HANDLE);
    let mut n: u32 = 0;
    check(unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, 0) } != 0);
    check(unsafe { CloseHandle(h) } != 0);
    check(n == data.len() as u32);
    let mut i = 0;
    while i < data.len() {
        check(buf[i] == data[i]);
        i += 1;
    }

    // copy a -> b, move b -> c.
    check(unsafe { CopyFileW(a, b, 0) } != 0);
    check(unsafe { MoveFileW(b, c) } != 0);

    // read c (mixed-case path) to stdout: observable content.
    let h = open(c, GENERIC_READ, OPEN_EXISTING);
    check(h != INVALID_HANDLE);
    zero_bytes(&mut *buf);
    let mut m: u32 = 0;
    check(unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut m, 0) } != 0);
    check(unsafe { CloseHandle(h) } != 0);
    check(m == data.len() as u32);
    print(&buf[..m as usize]);

    // delete a + c, then duplicate delete must fail.
    check(unsafe { DeleteFileW(a) } != 0);
    check(unsafe { DeleteFileW(c) } != 0);
    check(unsafe { DeleteFileW(c) } == 0);

    // rmdir, then duplicate must fail.
    check(unsafe { RemoveDirectoryW(dir) } != 0);
    check(unsafe { RemoveDirectoryW(dir) } == 0);

    print(b"PASS\n");
    unsafe { ExitProcess(0) }
}
