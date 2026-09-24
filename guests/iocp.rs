//! Native overlapped WinFS and completion-port integration fixture.
#![no_std]
#![no_main]

extern "C" {
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        sec: u64,
        creation: u32,
        flags: u32,
        tmpl: u64,
    ) -> u64;
    fn ReadFile(h: u64, buf: *mut u8, n: u32, read: *mut u32, ov: *mut Overlapped) -> i32;
    fn WriteFile(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: *mut Overlapped) -> i32;
    fn CreateIoCompletionPort(file: u64, port: u64, key: u64, threads: u32) -> u64;
    fn GetQueuedCompletionStatus(
        port: u64,
        bytes: *mut u32,
        key: *mut u64,
        ov: *mut u64,
        timeout: u32,
    ) -> i32;
    fn GetLastError() -> u32;
    fn CloseHandle(h: u64) -> i32;
    fn ExitProcess(code: u32) -> !;
}

#[repr(C)]
struct Overlapped {
    internal: u64,
    internal_high: u64,
    offset: u32,
    offset_high: u32,
    event: u64,
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(99) }
}
fn check(ok: bool) {
    if !ok {
        unsafe { ExitProcess(1) }
    }
}
fn ov(offset: u32) -> Overlapped {
    Overlapped {
        internal: !0,
        internal_high: !0,
        offset,
        offset_high: 0,
        event: 0,
    }
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    let path: [u16; 12] = [67, 58, 92, 105, 111, 99, 112, 46, 116, 120, 116, 0]; // C:\iocp.txt
    let mut count = 0;
    let file = unsafe { CreateFileW(path.as_ptr(), 0xc000_0000, 0, 0, 2, 0x80, 0) };
    check(file != !0);
    check(
        unsafe {
            WriteFile(
                file,
                b"abcdef".as_ptr(),
                6,
                &mut count,
                core::ptr::null_mut(),
            )
        } != 0
            && count == 6,
    );
    // A synchronous file cannot be associated with a completion port.
    check(unsafe { CreateIoCompletionPort(file, 0, 1, 0) } == 0);
    check(unsafe { GetLastError() } == 87);
    check(unsafe { CloseHandle(file) } != 0);

    let file = unsafe { CreateFileW(path.as_ptr(), 0xc000_0000, 0, 0, 3, 0x4000_0080, 0) };
    check(file != !0);
    let port = unsafe { CreateIoCompletionPort(file, 0, 0x1234, 0) };
    check(port != 0);
    check(unsafe { CreateIoCompletionPort(file, port, 9, 0) } == 0);
    check(unsafe { GetLastError() } == 87);
    // An overlapped handle requires an OVERLAPPED pointer.
    let mut buf = [0u8; 4];
    check(unsafe { ReadFile(file, buf.as_mut_ptr(), 2, &mut count, core::ptr::null_mut()) } == 0);
    check(unsafe { GetLastError() } == 87);

    let mut read_ov = ov(2);
    check(unsafe { ReadFile(file, buf.as_mut_ptr(), 3, &mut count, &mut read_ov) } != 0);
    check(count == 3 && &buf[..3] == b"cde" && read_ov.internal == 0 && read_ov.internal_high == 3);
    let mut bytes = 0;
    let mut key = 0;
    let mut returned = 0;
    check(unsafe { GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, 0) } != 0);
    check(bytes == 3 && key == 0x1234 && returned == (&mut read_ov as *mut Overlapped as u64));
    check(unsafe { GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, 0) } == 0);
    check(unsafe { GetLastError() } == 258 && returned == 0);

    let mut write_ov = ov(1);
    check(unsafe { WriteFile(file, b"XY".as_ptr(), 2, &mut count, &mut write_ov) } != 0);
    check(count == 2 && write_ov.internal_high == 2);
    check(unsafe { GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, 0) } != 0);
    check(bytes == 2 && key == 0x1234 && returned == (&mut write_ov as *mut Overlapped as u64));
    let mut eof_ov = ov(99);
    check(unsafe { ReadFile(file, buf.as_mut_ptr(), 1, &mut count, &mut eof_ov) } == 0);
    check(unsafe { GetLastError() } == 38);
    check(unsafe { GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, 0) } == 0);
    check(unsafe { GetLastError() } == 258);
    let second = unsafe { CreateFileW(path.as_ptr(), 0x8000_0000, 0, 0, 3, 0x4000_0080, 0) };
    check(second != !0);
    check(unsafe { CreateIoCompletionPort(second, port, 0x5678, 0) } == port);
    let mut second_ov = ov(0);
    check(unsafe { ReadFile(second, buf.as_mut_ptr(), 1, &mut count, &mut second_ov) } != 0);
    check(unsafe { GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, 0) } != 0);
    check(bytes == 1 && key == 0x5678 && returned == (&mut second_ov as *mut Overlapped as u64));
    // The low event bit requests no IOCP packet for this operation.
    let mut quiet_ov = ov(0);
    quiet_ov.event = 1;
    check(unsafe { ReadFile(second, buf.as_mut_ptr(), 1, &mut count, &mut quiet_ov) } != 0);
    check(unsafe { GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, 0) } == 0);
    check(unsafe { GetLastError() } == 258);
    check(unsafe { CloseHandle(second) } != 0);
    check(unsafe { CloseHandle(file) } != 0 && unsafe { CloseHandle(port) } != 0);

    let file = unsafe { CreateFileW(path.as_ptr(), 0x8000_0000, 0, 0, 3, 0x80, 0) };
    check(file != !0);
    let mut all = [0u8; 6];
    check(unsafe { ReadFile(file, all.as_mut_ptr(), 6, &mut count, core::ptr::null_mut()) } != 0);
    check(count == 6 && &all == b"aXYdef");
    check(unsafe { CloseHandle(file) } != 0);
    unsafe { ExitProcess(0) }
}
