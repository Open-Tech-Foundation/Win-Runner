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
    fn GetOverlappedResult(file: u64, ov: *mut Overlapped, bytes: *mut u32, wait: i32) -> i32;
    fn CreateEventW(attrs: u64, manual: i32, initial: i32, name: *const u16) -> u64;
    fn CreateEventA(attrs: u64, manual: i32, initial: i32, name: *const u8) -> u64;
    fn CreateEventExW(attrs: u64, name: *const u16, flags: u32, access: u32) -> u64;
    fn CreateEventExA(attrs: u64, name: *const u8, flags: u32, access: u32) -> u64;
    fn SetEvent(handle: u64) -> i32;
    fn ResetEvent(handle: u64) -> i32;
    fn WaitForSingleObject(handle: u64, timeout: u32) -> u32;
    fn CloseHandle(h: u64) -> i32;
    fn ExitProcess(code: u32) -> !;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Overlapped {
    internal: u64,
    internal_high: u64,
    offset: u32,
    offset_high: u32,
    event: u64,
}

static LARGE: [u8; 65536] = [b'Q'; 65536];
static mut OUTPUT: [u8; 65536] = [0; 65536];
static mut BATCH_OUTPUT: [[u8; 65536]; 8] = [[0; 65536]; 8];

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
    let event = unsafe { CreateEventW(0, 1, 0, core::ptr::null()) };
    check(event != 0 && event & 1 == 0);
    check(unsafe { WaitForSingleObject(event, 0) } == 258);
    check(unsafe { SetEvent(event) } != 0);
    check(unsafe { WaitForSingleObject(event, 0) } == 0);
    check(unsafe { WaitForSingleObject(event, 0) } == 0);
    check(unsafe { ResetEvent(event) } != 0);
    check(unsafe { WaitForSingleObject(event, 0) } == 258);
    let auto = unsafe { CreateEventW(0, 0, 1, core::ptr::null()) };
    check(auto != 0 && unsafe { WaitForSingleObject(auto, 0) } == 0);
    check(unsafe { WaitForSingleObject(auto, 0) } == 258);
    check(unsafe { SetEvent(auto) } != 0 && unsafe { WaitForSingleObject(auto, 0) } == 0);
    check(unsafe { CloseHandle(auto) } != 0);
    check(unsafe { SetEvent(auto) } == 0 && unsafe { GetLastError() } == 6);
    check(unsafe { ResetEvent(auto) } == 0 && unsafe { GetLastError() } == 6);
    check(unsafe { WaitForSingleObject(auto, 0) } == u32::MAX);
    check(unsafe { GetLastError() } == 6);
    check(unsafe { CreateEventExW(0, core::ptr::null(), 4, 0x1f0003) } == 0);
    check(unsafe { GetLastError() } == 87);
    let ex = unsafe { CreateEventExW(0, core::ptr::null(), 3, 0x1f0003) };
    check(ex != 0 && unsafe { WaitForSingleObject(ex, 0) } == 0);
    check(unsafe { WaitForSingleObject(ex, 0) } == 0 && unsafe { CloseHandle(ex) } != 0);
    let ex_auto = unsafe { CreateEventExA(0, core::ptr::null(), 2, 0x1f0003) };
    check(ex_auto != 0 && unsafe { WaitForSingleObject(ex_auto, 0) } == 0);
    check(
        unsafe { WaitForSingleObject(ex_auto, 0) } == 258 && unsafe { CloseHandle(ex_auto) } != 0,
    );
    let name: [u16; 10] = [119, 105, 110, 99, 108, 105, 45, 105, 111, 0];
    let named = unsafe { CreateEventW(0, 1, 0, name.as_ptr()) };
    check(named != 0);
    let named_again = unsafe { CreateEventW(0, 0, 1, name.as_ptr()) };
    check(named_again != 0 && named_again != named && unsafe { GetLastError() } == 183);
    check(unsafe { WaitForSingleObject(named_again, 0) } == 258);
    check(unsafe { SetEvent(named) } != 0 && unsafe { WaitForSingleObject(named_again, 0) } == 0);
    let named_ansi = unsafe { CreateEventA(0, 0, 0, b"wincli-io\0".as_ptr()) };
    check(named_ansi != 0 && unsafe { GetLastError() } == 183);
    check(
        unsafe { WaitForSingleObject(named_ansi, 0) } == 0
            && unsafe { CloseHandle(named_ansi) } != 0,
    );
    check(unsafe { CloseHandle(named) } != 0 && unsafe { CloseHandle(named_again) } != 0);
    let reopened = unsafe { CreateEventW(0, 1, 1, name.as_ptr()) };
    check(reopened != 0 && unsafe { GetLastError() } == 0);
    check(
        unsafe { WaitForSingleObject(reopened, 0) } == 0 && unsafe { CloseHandle(reopened) } != 0,
    );
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
    let mut bad_event_ov = ov(0);
    bad_event_ov.event = auto;
    check(unsafe { ReadFile(file, buf.as_mut_ptr(), 1, &mut count, &mut bad_event_ov) } == 0);
    check(unsafe { GetLastError() } == 6);

    let mut read_ov = ov(2);
    read_ov.event = event;
    check(unsafe { ReadFile(file, buf.as_mut_ptr(), 3, &mut count, &mut read_ov) } != 0);
    check(unsafe { WaitForSingleObject(event, 0) } == 0);
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
    quiet_ov.event = event | 1;
    check(unsafe { ResetEvent(event) } != 0);
    check(unsafe { ReadFile(second, buf.as_mut_ptr(), 1, &mut count, &mut quiet_ov) } != 0);
    check(unsafe { WaitForSingleObject(event, 0) } == 0);
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

    // Large transfers are dispatched to a host worker and complete later.
    let file = unsafe { CreateFileW(path.as_ptr(), 0xc000_0000, 0, 0, 2, 0x80, 0) };
    check(file != !0);
    check(
        unsafe {
            WriteFile(
                file,
                LARGE.as_ptr(),
                LARGE.len() as u32,
                &mut count,
                core::ptr::null_mut(),
            )
        } != 0,
    );
    check(count == LARGE.len() as u32 && unsafe { CloseHandle(file) } != 0);
    let file = unsafe { CreateFileW(path.as_ptr(), 0xc000_0000, 0, 0, 3, 0x4000_0080, 0) };
    check(file != !0);
    let port = unsafe { CreateIoCompletionPort(file, 0, 0x7777, 0) };
    check(port != 0);
    let output = core::ptr::addr_of_mut!(OUTPUT).cast::<u8>();
    let mut large_ov = ov(0);
    large_ov.event = event;
    check(unsafe { SetEvent(event) } != 0);
    check(unsafe { ReadFile(file, output, 65536, &mut count, &mut large_ov) } == 0);
    check(unsafe { GetLastError() } == 997 && count == 0);
    check(unsafe { WaitForSingleObject(event, u32::MAX) } == 0);
    check(unsafe { GetOverlappedResult(file, &mut large_ov, &mut count, 1) } != 0);
    check(count == 65536 && unsafe { output.read() == b'Q' && output.add(65535).read() == b'Q' });
    check(
        unsafe { GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, u32::MAX) }
            != 0,
    );
    check(bytes == 65536 && key == 0x7777 && returned == (&mut large_ov as *mut Overlapped as u64));

    let mut write_ov = ov(0);
    write_ov.event = event;
    check(unsafe { ResetEvent(event) } != 0);
    check(unsafe { WriteFile(file, LARGE.as_ptr(), 65536, &mut count, &mut write_ov) } == 0);
    check(unsafe { GetLastError() } == 997 && count == 0);
    check(unsafe { WaitForSingleObject(event, u32::MAX) } == 0);
    check(
        unsafe { GetOverlappedResult(file, &mut write_ov, &mut count, 1) } != 0 && count == 65536,
    );
    check(
        unsafe { GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, u32::MAX) }
            != 0,
    );
    check(bytes == 65536 && key == 0x7777 && returned == (&mut write_ov as *mut Overlapped as u64));

    let mut eof_ov = ov(65536);
    eof_ov.event = event;
    check(unsafe { ResetEvent(event) } != 0);
    check(unsafe { ReadFile(file, output, 65536, &mut count, &mut eof_ov) } == 0);
    check(unsafe { GetLastError() } == 997);
    check(unsafe { WaitForSingleObject(event, u32::MAX) } == 0);
    check(unsafe { GetOverlappedResult(file, &mut eof_ov, &mut count, 1) } == 0);
    check(unsafe { GetLastError() } == 38);
    check(
        unsafe { GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, u32::MAX) }
            == 0,
    );
    check(unsafe { GetLastError() } == 38 && returned == (&mut eof_ov as *mut Overlapped as u64));
    let mut requests = [ov(0); 8];
    let mut seen = [false; 8];
    let batch_output = core::ptr::addr_of_mut!(BATCH_OUTPUT).cast::<u8>();
    let mut i = 0;
    while i < requests.len() {
        let destination = unsafe { batch_output.add(i * 65536) };
        check(unsafe { ReadFile(file, destination, 65536, &mut count, &mut requests[i]) } == 0);
        check(unsafe { GetLastError() } == 997 && count == 0);
        i += 1;
    }
    i = 0;
    while i < requests.len() {
        check(
            unsafe {
                GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut returned, u32::MAX)
            } != 0,
        );
        check(bytes == 65536 && key == 0x7777);
        let mut matched = false;
        let mut j = 0;
        while j < requests.len() {
            if returned == (&mut requests[j] as *mut Overlapped as u64) {
                check(!seen[j]);
                seen[j] = true;
                check(unsafe {
                    batch_output.add(j * 65536).read() == b'Q'
                        && batch_output.add(j * 65536 + 65535).read() == b'Q'
                });
                matched = true;
                break;
            }
            j += 1;
        }
        check(matched);
        i += 1;
    }
    check(unsafe { CloseHandle(file) } != 0 && unsafe { CloseHandle(port) } != 0);
    check(unsafe { CloseHandle(event) } != 0);
    unsafe { ExitProcess(0) }
}
