//! argv echo guest for Win-Runner: prints `GetCommandLineW()` as UTF-8.
//!
//! Proves guest argv plumbing with a real rustc binary. ASCII passes
//! through; other units become `?`. Build with `guests/build.sh`.
//!
//! Guest rule: no unproven bounds checks. We link with `/NODEFAULTLIB`
//! without core's rlib, so `panic_bounds_check` is undefined at link time;
//! indexing uses `get_unchecked` with manually maintained invariants
//! (a link error naming that symbol means a check slipped in).

#![no_std]
#![no_main]

extern "C" {
    fn GetStdHandle(nStdHandle: i32) -> u64;
    fn GetCommandLineW() -> *const u16;
    fn WriteFile(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: u64) -> i32;
    fn ExitProcess(code: u32) -> !;
}

#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(99) }
}

fn write_all(h: u64, mut ptr: *const u8, mut left: u32) {
    while left > 0 {
        let mut w: u32 = 0;
        let ok = unsafe { WriteFile(h, ptr, left, &mut w, 0) };
        if ok == 0 || w == 0 {
            unsafe { ExitProcess(1) }
        }
        ptr = unsafe { ptr.offset(w as isize) };
        left -= w;
    }
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    unsafe {
        let out = GetStdHandle(-11);
        let cmd = GetCommandLineW();
        let mut raw = core::mem::MaybeUninit::<[u8; 512]>::uninit();
        let buf: &mut [u8] = &mut *raw.as_mut_ptr();
        let mut n = 0usize;
        let mut i: isize = 0;
        loop {
            let u = *cmd.offset(i);
            if u == 0 {
                break;
            }
            if n == buf.len() {
                write_all(out, buf.as_ptr(), n as u32);
                n = 0;
            }
            // INVARIANT: n < buf.len() here (flushed above).
            *buf.get_unchecked_mut(n) = if u < 0x80 { u as u8 } else { b'?' };
            n += 1;
            i += 1;
        }
        // INVARIANT: n < buf.len() (loop writes at most buf.len() then flushes;
        // the '\n' slot always exists because n <= buf.len() - 1... see below).
        // n can equal buf.len() if the line exactly filled the buffer: flush first.
        if n == buf.len() {
            write_all(out, buf.as_ptr(), n as u32);
            n = 0;
        }
        *buf.get_unchecked_mut(n) = b'\n';
        n += 1;
        write_all(out, buf.as_ptr(), n as u32);
        ExitProcess(0);
    }
}
