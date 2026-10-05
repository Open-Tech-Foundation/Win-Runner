//! User APCs, alertable waits, and extended file completion callbacks.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
static ORDER: AtomicU32 = AtomicU32::new(0);
static RECORD_PTR: AtomicUsize = AtomicUsize::new(0);
static GET_ID: AtomicUsize = AtomicUsize::new(0);
static SLEEP_EX: AtomicUsize = AtomicUsize::new(0);
static SET_EVENT: AtomicUsize = AtomicUsize::new(0);
static THREAD_OWNER: AtomicU32 = AtomicU32::new(0);
static THREAD_WAIT: AtomicU32 = AtomicU32::new(0);
fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}
fn wide_text(text: &str) -> [u16; 128] {
    let mut output = [0; 128];
    for (i, c) in text.encode_utf16().enumerate() {
        output[i] = c;
    }
    output
}
unsafe extern "system" fn apc(data: usize) {
    ORDER.store(
        ORDER.load(Ordering::SeqCst) * 10 + data as u32,
        Ordering::SeqCst,
    );
}
unsafe extern "system" fn thread_apc(_: usize) {
    let id: unsafe extern "system" fn() -> u32 =
        core::mem::transmute(GET_ID.load(Ordering::SeqCst));
    THREAD_OWNER.store(id(), Ordering::SeqCst);
}
#[repr(C)]
struct ThreadContext {
    event: usize,
    target: usize,
    queue: usize,
}
unsafe extern "system" fn thread_start(context: usize) -> u32 {
    let context = &*(context as *const ThreadContext);
    let queue: unsafe extern "system" fn(usize, usize, usize) -> u32 =
        core::mem::transmute(context.queue);
    queue(apc as *const () as usize, context.target, 7);
    let set: unsafe extern "system" fn(usize) -> i32 =
        core::mem::transmute(SET_EVENT.load(Ordering::SeqCst));
    let sleep: unsafe extern "system" fn(u32, i32) -> u32 =
        core::mem::transmute(SLEEP_EX.load(Ordering::SeqCst));
    set(context.event);
    THREAD_WAIT.store(sleep(3000, 1), Ordering::SeqCst);
    0
}
unsafe extern "system" fn suspended_start(_: usize) -> u32 {
    let id: unsafe extern "system" fn() -> u32 =
        core::mem::transmute(GET_ID.load(Ordering::SeqCst));
    THREAD_WAIT.store(
        if THREAD_OWNER.load(Ordering::SeqCst) == id() {
            42
        } else {
            0
        },
        Ordering::SeqCst,
    );
    0
}
#[repr(C)]
struct Record {
    calls: u32,
    error: u32,
    bytes: u32,
    owner: u32,
}
unsafe extern "system" fn complete(error: u32, bytes: u32, _ov: *mut usize) {
    let record = &mut *(RECORD_PTR.load(Ordering::SeqCst) as *mut Record);
    let id: unsafe extern "system" fn() -> u32 =
        core::mem::transmute(GET_ID.load(Ordering::SeqCst));
    record.calls += 1;
    record.error = error;
    record.bytes = bytes;
    record.owner = id();
}
fn probe() {
    type Queue = unsafe extern "system" fn(usize, usize, usize) -> u32;
    type Current = unsafe extern "system" fn() -> usize;
    type Id = unsafe extern "system" fn() -> u32;
    type Sleep = unsafe extern "system" fn(u32, i32) -> u32;
    type Wait = unsafe extern "system" fn(usize, u32, i32) -> u32;
    type Multi = unsafe extern "system" fn(u32, *const usize, i32, u32, i32) -> u32;
    type Event = unsafe extern "system" fn(usize, i32, i32, *const u16) -> usize;
    type Close = unsafe extern "system" fn(usize) -> i32;
    type CreateThread =
        unsafe extern "system" fn(usize, usize, usize, usize, u32, *mut u32) -> usize;
    type Open = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
    type ReadEx = unsafe extern "system" fn(usize, *mut u8, u32, *mut usize, usize) -> i32;
    type WriteEx = unsafe extern "system" fn(usize, *const u8, u32, *mut usize, usize) -> i32;
    type ResultEx = unsafe extern "system" fn(usize, *mut usize, *mut u32, u32, i32) -> i32;
    type Port = unsafe extern "system" fn(usize, usize, usize, u32) -> usize;
    type GetPort = unsafe extern "system" fn(usize, *mut usize, u32, *mut u32, u32, i32) -> i32;
    type Pipe = unsafe extern "system" fn(*const u16, u32, u32, u32, u32, u32, u32, usize) -> usize;
    type Connect = unsafe extern "system" fn(usize, *mut usize) -> i32;
    type Cancel = unsafe extern "system" fn(usize, *mut usize) -> i32;
    let queue = api!("queue.api", "QueueUserAPC", Queue);
    let current = api!("current.api", "GetCurrentThread", Current);
    let id = api!("id.api", "GetCurrentThreadId", Id);
    let sleep = api!("sleep.api", "SleepEx", Sleep);
    let wait = api!("wait.api", "WaitForSingleObjectEx", Wait);
    let multi = api!("multi.api", "WaitForMultipleObjectsEx", Multi);
    let event = api!("event.api", "CreateEventW", Event);
    let set = api!("set.api", "SetEvent", Close);
    let close = api!("close.api", "CloseHandle", Close);
    let thread = api!("thread.api", "CreateThread", CreateThread);
    let open = api!("open.api", "CreateFileW", Open);
    let read = api!("read.api", "ReadFileEx", ReadEx);
    let write = api!("write.api", "WriteFileEx", WriteEx);
    let result = api!("result.api", "GetOverlappedResultEx", ResultEx);
    let port = api!("port.api", "CreateIoCompletionPort", Port);
    let get_port = api!("getport.api", "GetQueuedCompletionStatusEx", GetPort);
    let pipe = api!("pipe.api", "CreateNamedPipeW", Pipe);
    let connect = api!("connect.api", "ConnectNamedPipe", Connect);
    let cancel = api!("cancel.api", "CancelIoEx", Cancel);
    GET_ID.store(id as usize, Ordering::SeqCst);
    SLEEP_EX.store(sleep as usize, Ordering::SeqCst);
    SET_EVENT.store(set as usize, Ordering::SeqCst);
    type Duplicate =
        unsafe extern "system" fn(usize, usize, usize, *mut usize, u32, i32, u32) -> i32;
    let duplicate = api!("duplicate.api", "DuplicateHandle", Duplicate);
    let process = api!("process.api", "GetCurrentProcess", Current);
    let self_thread = unsafe { current() };
    let self_id = unsafe { id() };
    unsafe {
        queue(apc as *const () as usize, self_thread, 1);
        queue(apc as *const () as usize, self_thread, 2);
    }
    boolean(
        "apc.nonalertable",
        unsafe { sleep(0, 0) } == 0 && ORDER.load(Ordering::SeqCst) == 0,
    );
    boolean(
        "apc.fifo",
        unsafe { sleep(0, 1) } == 192 && ORDER.load(Ordering::SeqCst) == 12,
    );
    boolean("apc.drained", unsafe { sleep(0, 1) } == 0);
    let pending = unsafe { event(0, 1, 0, core::ptr::null()) };
    unsafe {
        queue(apc as *const () as usize, self_thread, 3);
    }
    boolean(
        "wait.single_apc",
        unsafe { wait(pending, 1000, 1) } == 192 && ORDER.load(Ordering::SeqCst) == 123,
    );
    unsafe {
        queue(apc as *const () as usize, self_thread, 4);
    }
    boolean(
        "wait.multiple_apc",
        unsafe { multi(1, &pending, 0, 1000, 1) } == 192 && ORDER.load(Ordering::SeqCst) == 1234,
    );
    let first = unsafe { event(0, 0, 1, core::ptr::null()) };
    let second = unsafe { event(0, 0, 0, core::ptr::null()) };
    let handles = [first, second];
    boolean(
        "wait.all_timeout",
        unsafe { multi(2, handles.as_ptr(), 1, 10, 1) } == 258,
    );
    boolean(
        "wait.all_preserves_event",
        unsafe { wait(first, 0, 0) } == 0,
    );
    unsafe {
        set(first);
        set(second);
    }
    boolean(
        "wait.all_ready",
        unsafe { multi(2, handles.as_ptr(), 1, 1000, 1) } == 0
            && unsafe { wait(first, 0, 0) } == 258
            && unsafe { wait(second, 0, 0) } == 258,
    );
    type SignalWait = unsafe extern "system" fn(usize, usize, u32, i32) -> u32;
    let signal_wait = api!("signal_wait.api", "SignalObjectAndWait", SignalWait);
    unsafe {
        queue(apc as *const () as usize, self_thread, 0);
    }
    boolean(
        "wait.signal_apc",
        unsafe { signal_wait(first, pending, 1000, 1) } == 192
            && ORDER.load(Ordering::SeqCst) == 12340
            && unsafe { wait(first, 0, 0) } == 0,
    );
    ORDER.store(1234, Ordering::SeqCst);
    let ready = unsafe { event(0, 1, 0, core::ptr::null()) };
    let mut target = 0;
    boolean(
        "thread.duplicate",
        unsafe { duplicate(process(), self_thread, process(), &mut target, 0, 0, 2) } != 0,
    );
    let mut restricted = 0;
    boolean(
        "apc.access_denied",
        unsafe { duplicate(process(), self_thread, process(), &mut restricted, 0, 0, 0) } != 0
            && unsafe { queue(apc as *const () as usize, restricted, 9) } == 0
            && last_error() == 5,
    );
    unsafe {
        close(restricted);
    }
    let context = ThreadContext {
        event: ready,
        target,
        queue: queue as usize,
    };
    let mut thread_id = 0;
    let worker = unsafe {
        thread(
            0,
            0,
            thread_start as *const () as usize,
            &context as *const _ as usize,
            0,
            &mut thread_id,
        )
    };
    boolean(
        "thread.ready",
        worker != 0 && unsafe { wait(ready, 3000, 0) } == 0,
    );
    unsafe {
        queue(thread_apc as *const () as usize, worker, 0);
    }
    boolean(
        "apc.thread_owner",
        unsafe { wait(worker, 3000, 0) } == 0
            && THREAD_OWNER.load(Ordering::SeqCst) == thread_id
            && THREAD_WAIT.load(Ordering::SeqCst) == 192,
    );
    boolean(
        "apc.duplicated_owner",
        ORDER.load(Ordering::SeqCst) == 1234
            && unsafe { sleep(0, 1) } == 192
            && ORDER.load(Ordering::SeqCst) == 12347,
    );
    ORDER.store(1234, Ordering::SeqCst);
    boolean(
        "apc.terminated",
        unsafe { queue(thread_apc as *const () as usize, worker, 0) } == 0 && last_error() == 31,
    );
    THREAD_OWNER.store(0, Ordering::SeqCst);
    THREAD_WAIT.store(0, Ordering::SeqCst);
    type Resume = unsafe extern "system" fn(usize) -> u32;
    let resume = api!("resume.api", "ResumeThread", Resume);
    let mut suspended_id = 0;
    let suspended = unsafe {
        thread(
            0,
            0,
            suspended_start as *const () as usize,
            0,
            4,
            &mut suspended_id,
        )
    };
    boolean(
        "apc.prestart_queued",
        suspended != 0
            && unsafe { queue(thread_apc as *const () as usize, suspended, 0) } != 0
            && unsafe { resume(suspended) } == 1,
    );
    boolean(
        "apc.prestart_delivery",
        unsafe { wait(suspended, 3000, 0) } == 0
            && THREAD_OWNER.load(Ordering::SeqCst) == suspended_id
            && THREAD_WAIT.load(Ordering::SeqCst) == 42,
    );
    let file = unsafe {
        open(
            wide_text("apc.bin").as_ptr(),
            0xc0000000,
            7,
            0,
            2,
            0x40000000,
            0,
        )
    };
    if file == usize::MAX {
        boolean("file.setup", false);
        return;
    }
    let mut record = Record {
        calls: 0,
        error: 0,
        bytes: 0,
        owner: 0,
    };
    let mut ov = [0usize; 4];
    RECORD_PTR.store(&mut record as *mut _ as usize, Ordering::SeqCst);
    boolean(
        "io.write_queued",
        unsafe {
            write(
                file,
                b"test".as_ptr(),
                4,
                ov.as_mut_ptr(),
                complete as *const () as usize,
            )
        } != 0
            && record.calls == 0,
    );
    let mut bytes = 0;
    boolean(
        "io.write_result",
        unsafe { result(file, ov.as_mut_ptr(), &mut bytes, 3000, 0) } != 0
            && bytes == 4
            && record.calls == 0,
    );
    boolean(
        "io.write_callback",
        unsafe { sleep(3000, 1) } == 192
            && record.calls == 1
            && record.error == 0
            && record.bytes == 4
            && record.owner == self_id,
    );
    let mut data = [0u8; 4];
    ov[3] = 0xdeadbeef; // ReadFileEx ignores this caller-owned value.
    boolean(
        "io.read_queued",
        unsafe {
            read(
                file,
                data.as_mut_ptr(),
                4,
                ov.as_mut_ptr(),
                complete as *const () as usize,
            )
        } != 0,
    );
    boolean(
        "io.read_callback",
        unsafe { sleep(3000, 1) } == 192
            && record.calls == 2
            && ov[3] == 0xdeadbeef
            && record.bytes == 4
            && data == *b"test"
            && record.owner == self_id,
    );
    ov[2] = 4;
    boolean(
        "io.eof_queued",
        unsafe {
            read(
                file,
                data.as_mut_ptr(),
                4,
                ov.as_mut_ptr(),
                complete as *const () as usize,
            )
        } != 0,
    );
    boolean(
        "io.eof_callback",
        unsafe { sleep(3000, 1) } == 192
            && record.calls == 3
            && record.error == 38
            && record.bytes == 0,
    );
    ov[2] = 128;
    boolean(
        "io.zero_write",
        unsafe {
            write(
                file,
                core::ptr::null(),
                0,
                ov.as_mut_ptr(),
                complete as *const () as usize,
            )
        } != 0
            && unsafe { sleep(3000, 1) } == 192
            && record.calls == 4
            && record.error == 0
            && record.bytes == 0,
    );
    type Size = unsafe extern "system" fn(usize, *mut i64) -> i32;
    let size = api!("size.api", "GetFileSizeEx", Size);
    let mut length = 0;
    boolean(
        "io.zero_preserves_size",
        unsafe { size(file, &mut length) } != 0 && length == 4,
    );
    ov[2] = usize::MAX;
    boolean(
        "io.append",
        unsafe {
            write(
                file,
                b"!".as_ptr(),
                1,
                ov.as_mut_ptr(),
                complete as *const () as usize,
            )
        } != 0
            && unsafe { sleep(3000, 1) } == 192
            && record.calls == 5
            && record.error == 0
            && record.bytes == 1
            && unsafe { size(file, &mut length) } != 0
            && length == 5,
    );
    let completion_port = unsafe { port(usize::MAX, 0, 0, 0) };
    let mut entries = [0usize; 4];
    let mut removed = 99;
    unsafe {
        queue(apc as *const () as usize, self_thread, 5);
    }
    boolean(
        "port.alertable",
        unsafe {
            get_port(
                completion_port,
                entries.as_mut_ptr(),
                1,
                &mut removed,
                1000,
                1,
            )
        } == 0
            && last_error() == 192
            && ORDER.load(Ordering::SeqCst) == 12345,
    );
    boolean(
        "port.timeout",
        unsafe { get_port(completion_port, entries.as_mut_ptr(), 1, &mut removed, 0, 0) } == 0
            && last_error() == 258,
    );
    let path = wide_text(r"\\.\pipe\oracle-apc-io");
    let server = unsafe { pipe(path.as_ptr(), 0x40000003, 0, 1, 4096, 4096, 1000, 0) };
    let client = unsafe { open(path.as_ptr(), 0xc0000000, 0, 0, 3, 0, 0) };
    if server == usize::MAX || client == usize::MAX {
        boolean("pipe.setup", false);
        return;
    }
    let mut connection = [0usize; 4];
    unsafe {
        connect(server, connection.as_mut_ptr());
    }
    // GetOverlappedResultEx can wait on hEvent; use a real event for ordinary
    // overlapped I/O rather than the caller-owned value accepted by ReadFileEx.
    type Read = unsafe extern "system" fn(usize, *mut u8, u32, *mut u32, usize) -> i32;
    let regular_read = api!("regular_read.api", "ReadFile", Read);
    let mut pipe_ov = [0usize; 4];
    pipe_ov[3] = pending;
    boolean(
        "pipe.overlapped_queued",
        unsafe {
            regular_read(
                server,
                data.as_mut_ptr(),
                4,
                &mut bytes,
                pipe_ov.as_mut_ptr() as usize,
            )
        } == 0
            && last_error() == 997,
    );
    boolean(
        "result.poll",
        unsafe { result(server, pipe_ov.as_mut_ptr(), &mut bytes, 0, 0) } == 0
            && last_error() == 996,
    );
    boolean(
        "result.timeout",
        unsafe { result(server, pipe_ov.as_mut_ptr(), &mut bytes, 10, 0) } == 0
            && last_error() == 258,
    );
    unsafe {
        queue(apc as *const () as usize, self_thread, 6);
    }
    boolean(
        "result.alertable",
        unsafe { result(server, pipe_ov.as_mut_ptr(), &mut bytes, 1000, 1) } == 0
            && last_error() == 192
            && ORDER.load(Ordering::SeqCst) == 123456,
    );
    boolean(
        "pipe.cancel",
        unsafe { cancel(server, pipe_ov.as_mut_ptr()) } != 0,
    );
    boolean(
        "pipe.cancel_result",
        unsafe { result(server, pipe_ov.as_mut_ptr(), &mut bytes, 3000, 0) } == 0
            && last_error() == 995,
    );
    pipe_ov[3] = 0xdeadbeef;
    boolean(
        "pipe.read_queued",
        unsafe {
            read(
                server,
                data.as_mut_ptr(),
                4,
                pipe_ov.as_mut_ptr(),
                complete as *const () as usize,
            )
        } != 0,
    );
    boolean(
        "pipe.cancel_callback_request",
        unsafe { cancel(server, pipe_ov.as_mut_ptr()) } != 0,
    );
    boolean(
        "io.cancel_callback",
        unsafe { sleep(3000, 1) } == 192
            && record.calls == 6
            && record.error == 995
            && record.bytes == 0
            && record.owner == self_id,
    );
    boolean(
        "io.no_duplicate",
        unsafe { sleep(0, 1) } == 0 && record.calls == 6,
    );
    let associated = unsafe { port(file, completion_port, 0, 0) };
    boolean(
        "io.port_rejected",
        associated != 0
            && unsafe {
                write(
                    file,
                    b"x".as_ptr(),
                    1,
                    ov.as_mut_ptr(),
                    complete as *const () as usize,
                )
            } == 0,
    );
    for handle in [
        server,
        client,
        file,
        completion_port,
        first,
        second,
        pending,
        ready,
        worker,
        suspended,
        target,
    ] {
        unsafe {
            close(handle);
        }
    }
    out_str("END\n");
}
#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe apc_io\n");
    probe();
    flush();
    unsafe { ExitProcess(0) }
}
