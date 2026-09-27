//! Minimal Rust guest for Win-Runner (`x86_64-pc-windows-msvc`).
//!
//! `no_std` + `no_main` + custom entry: no CRT startup, no TEB/PEB access,
//! only the Win32 APIs Win-Runner implements. Build with `guests/build.sh`.

#![no_std]
#![no_main]

extern "C" {
    fn GetStdHandle(nStdHandle: i32) -> u64;
    fn WriteFile(
        h: u64,
        buf: *const u8,
        n: u32,
        written: *mut u32,
        overlapped: u64,
    ) -> i32;
    fn ExitProcess(code: u32) -> !;
}

#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    // Panics abort the guest with a distinct exit code.
    unsafe { ExitProcess(99) }
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    let msg = b"Hello from Rust";
    let mut written: u32 = 0;
    unsafe {
        let stdout = GetStdHandle(-11);
        WriteFile(
            stdout,
            msg.as_ptr(),
            msg.len() as u32,
            &mut written as *mut u32,
            0,
        );
        ExitProcess(0);
    }
}
