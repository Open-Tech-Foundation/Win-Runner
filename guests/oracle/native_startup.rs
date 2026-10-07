//! Module identity, Winsock ordinal exports and statically imported NT APIs.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
include!("fs_support.rs");
extern "system" {
    fn NtClose(handle: usize) -> u32;
    fn NtWaitForSingleObject(handle: usize, alertable: u8, timeout: *const i64) -> u32;
    fn NtCreateThreadEx(out: *mut usize, desired: u32, object: usize, process: usize, start: usize, parameter: usize, flags: u32, zero_bits: usize, stack: usize, maximum: usize, attributes: *const usize) -> u32;
    fn NtResumeThread(handle: usize, previous: *mut u32) -> u32;
    fn RtlGetActiveActivationContext(out: *mut usize) -> u32;
    fn RtlNtStatusToDosError(status: u32) -> u32;
    fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> usize;
    fn RtlReAllocateHeap(heap: usize, flags: u32, ptr: usize, size: usize) -> usize;
    fn RtlFreeHeap(heap: usize, flags: u32, ptr: usize) -> u8;
    fn RtlSizeHeap(heap: usize, flags: u32, ptr: usize) -> usize;
    fn NtWaitForAlertByThreadId(address: usize, timeout: *const i64) -> u32;
    fn NtAlertThreadByThreadId(id: usize) -> u32;
    fn NtQueryInformationFile(
        handle: usize,
        status: *mut u64,
        information: *mut u32,
        size: u32,
        class: u32,
    ) -> u32;
    fn NtAllocateVirtualMemory(
        process: usize,
        base: *mut usize,
        zero: usize,
        size: *mut usize,
        kind: u32,
        protection: u32,
    ) -> u32;
    fn NtFreeVirtualMemory(process: usize, base: *mut usize, size: *mut usize, kind: u32) -> u32;
    fn NtProtectVirtualMemory(
        process: usize,
        base: *mut usize,
        size: *mut usize,
        protection: u32,
        previous: *mut u32,
    ) -> u32;
    fn RtlGetSystemTimePrecise() -> u64;
    fn RtlQueryPerformanceCounter(out: *mut u64) -> i32;
    fn RtlQueryPerformanceFrequency(out: *mut u64) -> i32;
    fn NtQueryDirectoryFile(
        handle: usize,
        event: usize,
        apc: usize,
        context: usize,
        status: *mut u64,
        entries: *mut u8,
        length: u32,
        class: u32,
        single: u8,
        name: usize,
        restart: u8,
    ) -> u32;
    fn NtQueryAttributesFile(attributes: *const usize, information: *mut u64) -> u32;
    fn RtlWaitOnAddress(
        address: *const u32,
        compare: *const u32,
        size: usize,
        timeout: *const i64,
    ) -> u32;
    fn RtlWakeAddressAll(address: *const u32);
    fn RtlWakeAddressSingle(address: *const u32);
}
fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}
extern "system" fn nt_thread_entry(parameter: usize) -> u32 {
    unsafe { (parameter as *mut u32).write(42) }
    42
}
fn nt_threads() {
    type Id = unsafe extern "system" fn(usize) -> u32;
    type Wait = unsafe extern "system" fn(usize, u32) -> u32;
    let id = api!("nt_thread.id_api", "GetThreadId", Id);
    let wait = api!("nt_thread.wait_api", "WaitForSingleObject", Wait);
    unsafe {
        let mut client = [0usize;2];
        let mut teb = 0usize;
        let mut size = 0usize;
        let attributes = [72usize, 0x10003, 16, client.as_mut_ptr() as usize, 0, 0x10004, 8, &mut teb as *mut _ as usize, &mut size as *mut _ as usize];
        let mut handle = 0usize;
        let mut output = 0u32;
        let empty_name = [0usize; 2];
        let object = [48usize, 0, empty_name.as_ptr() as usize, 0x40, 0, 0];
        let status = NtCreateThreadEx(&mut handle, 0x1fffff, object.as_ptr() as usize, usize::MAX, nt_thread_entry as *const () as usize, &mut output as *mut _ as usize, 1, 0, 0, 0, attributes.as_ptr());
        boolean("nt_thread.create", status == 0 && handle != 0);
        if handle == 0 { return }
        boolean("nt_thread.outputs", client[0] != 0 && client[1] == id(handle) as usize && teb != 0 && size == 8);
        boolean("nt_thread.teb_identity", teb != 0 && *((teb + 0x40) as *const usize) == client[0] && *((teb + 0x48) as *const usize) == client[1]);
        let primary_peb: usize;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) primary_peb, options(nostack, readonly));
        let thread_peb = *((teb + 0x60) as *const usize);
        boolean("nt_thread.parameters_shared", *((primary_peb + 0x20) as *const usize) != 0 && *((primary_peb + 0x20) as *const usize) == *((thread_peb + 0x20) as *const usize));
        boolean("nt_thread.suspended", wait(handle, 0) == 258 && output == 0);
        let mut count = 0;
        boolean("nt_thread.resume", NtResumeThread(handle, &mut count) == 0 && count == 1);
        boolean("nt_thread.completed", wait(handle, 5000) == 0 && output == 42);
        boolean("nt_wait.thread", NtWaitForSingleObject(handle, 0, core::ptr::null()) == 0);
        NtClose(handle);
        count = 0x1234;
        boolean("nt_thread.invalid", NtResumeThread(0, &mut count) == 0xc0000008 && count == 0x1234);
    }
}
extern "system" fn nt_wait_apc(parameter: usize) {
    unsafe { (parameter as *mut u32).write(1) }
}
fn nt_heap() {
    type Heap = unsafe extern "system" fn() -> usize;
    type Size = unsafe extern "system" fn(usize, u32, usize) -> usize;
    let get = api!("heap.get", "GetProcessHeap", Heap);
    let size = api!("heap.size", "HeapSize", Size);
    let set_error = api!("heap.error", "SetLastError", SetLastErrorFn);
    unsafe {
        boolean("nt_error.missing_parent", RtlNtStatusToDosError(0xc000003a) == 3);
        boolean("nt_error.invalid_name", RtlNtStatusToDosError(0xc0000033) == 123);
        type Event = unsafe extern "system" fn(usize, i32, i32, *const u16) -> usize;
        let create_event = api!("nt_wait.event_api", "CreateEventW", Event);
        let event = create_event(0, 0, 0, core::ptr::null());
        let poll = 0i64;
        let relative = -10_000i64;
        let expired = 1i64;
        set_error(0x5678);
        boolean("nt_wait.poll", NtWaitForSingleObject(event, 0, &poll) == 0x102);
        boolean("nt_wait.relative", NtWaitForSingleObject(event, 0, &relative) == 0x102);
        boolean("nt_wait.absolute", NtWaitForSingleObject(event, 0, &expired) == 0x102);
        boolean("nt_wait.invalid", NtWaitForSingleObject(0, 0, &poll) == 0xc0000008);
        boolean("nt_wait.last_error", last_error() == 0x5678);
        type Queue = unsafe extern "system" fn(usize, usize, usize) -> u32;
        let queue = api!("nt_wait.queue_api", "QueueUserAPC", Queue);
        let current = api!("nt_wait.current_api", "GetCurrentThread", Heap);
        let mut calls = 0u32;
        let queued = queue(nt_wait_apc as *const () as usize, current(), &mut calls as *mut _ as usize);
        boolean("nt_wait.nonalertable", queued != 0 && NtWaitForSingleObject(event, 0, &poll) == 0x102 && calls == 0);
        boolean("nt_wait.apc", NtWaitForSingleObject(event, 1, &poll) == 0xc0 && calls == 1);
        close(event);
        let mut activation = usize::MAX;
        boolean("activation.absent", RtlGetActiveActivationContext(&mut activation) == 0 && activation == 0);
        let peb: usize;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, readonly));
        type SetStd = unsafe extern "system" fn(u32, usize) -> i32;
        let set_std = api!("peb.set_std_api", "SetStdHandle", SetStd);
        let parameters = *((peb + 0x20) as *const usize);
        let handles = core::slice::from_raw_parts((parameters + 0x20) as *const usize, 3);
        boolean("peb.standard_handles", (0..3).all(|index| handles[index] == GetStdHandle((-10i32 - index as i32) as u32)));
        // ImagePathName (0x60) and CommandLine (0x70) are UNICODE_STRINGs
        // that runtimes read directly instead of calling the APIs.
        let unicode = |offset: usize| -> &[u16] {
            let length = *((parameters + offset) as *const u16) as usize / 2;
            let buffer = *((parameters + offset + 8) as *const usize);
            if buffer == 0 { &[] } else { core::slice::from_raw_parts(buffer as *const u16, length) }
        };
        type ModuleName = unsafe extern "system" fn(usize, *mut u16, u32) -> u32;
        let module_name = api!("peb.module_api", "GetModuleFileNameW", ModuleName);
        let mut image = [0u16; 1024];
        let image_length = module_name(0, image.as_mut_ptr(), 1024) as usize;
        boolean("peb.image_path", image_length > 0 && unicode(0x60) == &image[..image_length]);
        type CommandLine = unsafe extern "system" fn() -> *const u16;
        let command_line = api!("peb.command_api", "GetCommandLineW", CommandLine);
        let line = command_line();
        let mut line_length = 0;
        while *line.add(line_length) != 0 {
            line_length += 1;
        }
        boolean("peb.command_line", unicode(0x70) == core::slice::from_raw_parts(line, line_length));
        let original = GetStdHandle((-12i32) as u32);
        let replacement = GetStdHandle((-11i32) as u32);
        boolean("peb.set_standard_handle", set_std((-12i32) as u32, replacement) != 0 && *((parameters + 0x30) as *const usize) == replacement);
        set_std((-12i32) as u32, original);
        let heap = get();
        boolean("heap.peb", heap != 0 && *((peb + 0x30) as *const usize) == heap);
        set_error(0x1234);
        let ptr = RtlAllocateHeap(heap, 8, 8);
        boolean("heap.allocate", ptr != 0 && size(heap, 0, ptr) == 8 && core::slice::from_raw_parts(ptr as *const u8, 8) == &[0;8]);
        if ptr != 0 {
            *(ptr as *mut u8) = 42;
            let grown = RtlReAllocateHeap(heap, 8, ptr, 16);
            boolean("heap.reallocate", grown != 0 && *(grown as *const u8) == 42 && RtlSizeHeap(heap, 0, grown) == 16);
            boolean("heap.free", RtlFreeHeap(heap, 0, if grown == 0 {ptr} else {grown}) != 0);
        }
        boolean("heap.last_error", last_error() == 0x1234);
    }
}
fn modules() {
    type ModuleA = unsafe extern "system" fn(*const u8) -> usize;
    type Load = unsafe extern "system" fn(*const u8) -> usize;
    let module = api!("module.ansi", "GetModuleHandleA", ModuleA);
    unsafe {
        let a = module(core::ptr::null());
        let w = GetModuleHandleW(core::ptr::null());
        boolean(
            "module.main",
            a != 0 && a == w && *(a as *const u16) == 0x5a4d,
        );
    }
    let load = api!("socket.load", "LoadLibraryA", Load);
    unsafe {
        let module = load(b"WSOCK32.dll\0".as_ptr());
        let ordinal = GetProcAddress(module, 111usize as *const u8);
        let named = GetProcAddress(module, b"WSAGetLastError\0".as_ptr());
        boolean(
            "socket.ordinal",
            module != 0 && ordinal != 0 && ordinal == named,
        );
        boolean(
            "socket.ordinal_text",
            GetProcAddress(module, 11usize as *const u8) != 0
                && GetProcAddress(module, 11usize as *const u8)
                    == GetProcAddress(module, b"inet_ntoa\0".as_ptr()),
        );
        boolean(
            "socket.ordinal_select",
            GetProcAddress(module, 18usize as *const u8) != 0
                && GetProcAddress(module, 18usize as *const u8)
                    == GetProcAddress(module, b"select\0".as_ptr()),
        );
        for (ordinal, name, label) in [
            (10usize, b"inet_addr\0".as_slice(), "socket.ordinal_addr"),
            (12usize, b"ioctlsocket\0".as_slice(), "socket.ordinal_ioctl"),
            (
                151usize,
                b"__WSAFDIsSet\0".as_slice(),
                "socket.ordinal_fdset",
            ),
        ] {
            let pointer = GetProcAddress(module, ordinal as *const u8);
            boolean(
                label,
                pointer != 0 && pointer == GetProcAddress(module, name.as_ptr()),
            );
        }
        let ws2 = load(b"WS2_32.dll\0".as_ptr());
        for (ordinal, name, label) in [
            (10usize, b"ioctlsocket\0".as_slice(), "socket.modern_ioctl"),
            (11usize, b"inet_addr\0".as_slice(), "socket.modern_addr"),
            (12usize, b"inet_ntoa\0".as_slice(), "socket.modern_text"),
        ] {
            let pointer = GetProcAddress(ws2, ordinal as *const u8);
            boolean(
                label,
                pointer != 0 && pointer == GetProcAddress(ws2, name.as_ptr()),
            );
        }
        let wide = GetProcAddress(ws2, b"GetHostNameW\0".as_ptr());
        let narrow = GetProcAddress(ws2, b"gethostname\0".as_ptr());
        let startup = GetProcAddress(ws2, b"WSAStartup\0".as_ptr());
        let cleanup = GetProcAddress(ws2, b"WSACleanup\0".as_ptr());
        if [wide, narrow, startup, cleanup].contains(&0) {
            unavailable("socket.hostname");
            return;
        }
        let startup: unsafe extern "system" fn(u16, *mut usize) -> i32 =
            core::mem::transmute(startup);
        let cleanup: unsafe extern "system" fn() -> i32 = core::mem::transmute(cleanup);
        let narrow: unsafe extern "system" fn(*mut u8, i32) -> i32 = core::mem::transmute(narrow);
        let wide: unsafe extern "system" fn(*mut u16, i32) -> i32 = core::mem::transmute(wide);
        let mut data = [0usize; 64];
        let mut a = [0u8; 256];
        let mut w = [0u16; 256];
        boolean(
            "socket.hostname",
            startup(0x202, data.as_mut_ptr()) == 0
                && narrow(a.as_mut_ptr(), 256) == 0
                && wide(w.as_mut_ptr(), 256) == 0
                && a.iter().zip(w.iter()).all(|(a, w)| *a as u16 == *w),
        );
        cleanup();
    }
}
macro_rules! wsa_api {
    ($module:expr, $name:literal, $ty:ty) => {{
        let pointer = unsafe { GetProcAddress($module, concat!($name, "\0").as_ptr()) };
        if pointer == 0 {
            unavailable($name);
            return;
        }
        unsafe { core::mem::transmute::<usize, $ty>(pointer) }
    }};
}
fn socket_options() {
    type Load = unsafe extern "system" fn(*const u8) -> usize;
    let load = api!("socket.options_load", "LoadLibraryA", Load);
    let module = unsafe { load(b"WS2_32.dll\0".as_ptr()) };
    let startup = wsa_api!(
        module,
        "WSAStartup",
        unsafe extern "system" fn(u16, *mut usize) -> i32
    );
    let cleanup = wsa_api!(module, "WSACleanup", unsafe extern "system" fn() -> i32);
    let socket = wsa_api!(
        module,
        "socket",
        unsafe extern "system" fn(i32, i32, i32) -> usize
    );
    let set = wsa_api!(
        module,
        "setsockopt",
        unsafe extern "system" fn(usize, i32, i32, *const i32, i32) -> i32
    );
    let get = wsa_api!(
        module,
        "getsockopt",
        unsafe extern "system" fn(usize, i32, i32, *mut i32, *mut i32) -> i32
    );
    let bind = wsa_api!(
        module,
        "bind",
        unsafe extern "system" fn(usize, *const u8, i32) -> i32
    );
    let name = wsa_api!(
        module,
        "getsockname",
        unsafe extern "system" fn(usize, *mut u8, *mut i32) -> i32
    );
    let close = wsa_api!(
        module,
        "closesocket",
        unsafe extern "system" fn(usize) -> i32
    );
    let ntoa = wsa_api!(
        module,
        "inet_ntoa",
        unsafe extern "system" fn(u32) -> *const u8
    );
    let mut data = [0usize; 64];
    unsafe {
        startup(0x202, data.as_mut_ptr());
        let text = ntoa(u32::from_ne_bytes([127, 0, 0, 1]));
        boolean(
            "socket.ipv4_text",
            !text.is_null() && core::slice::from_raw_parts(text, 10) == b"127.0.0.1\0",
        );
        let first = socket(2, 1, 6);
        let second = socket(2, 1, 6);
        let enabled = 1;
        let mut actual = 0;
        let mut size = 4;
        boolean(
            "socket.exclusive",
            set(first, 0xffff, -5, &enabled, 4) == 0
                && get(first, 0xffff, -5, &mut actual, &mut size) == 0
                && actual == 1
                && size == 4,
        );
        boolean(
            "socket.exclusive_reuse",
            set(first, 0xffff, 4, &enabled, 4) == -1,
        );
        let mut address = [2u8, 0, 0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let bound = bind(first, address.as_ptr(), 16) == 0;
        let mut length = 16;
        boolean(
            "socket.exclusive_bind",
            bound && name(first, address.as_mut_ptr(), &mut length) == 0,
        );
        boolean(
            "socket.exclusive_competitor",
            set(second, 0xffff, 4, &enabled, 4) == 0 && bind(second, address.as_ptr(), 16) == -1,
        );
        // IP-level and broadcast options on a UDP socket: each set must
        // succeed; the value read back prints for comparison.
        let udp = socket(2, 2, 17);
        for (name, level, option, value) in [
            ("socket.ip_ttl", 0, 4, 7),
            ("socket.ip_multicast_ttl", 0, 10, 3),
            ("socket.ip_multicast_loop", 0, 11, 0),
            ("socket.broadcast", 0xffff, 0x20, 1),
        ] {
            let set_ok = set(udp, level, option, &value, 4) == 0;
            let mut read_back = -1;
            let mut size = 4;
            let got = get(udp, level, option, &mut read_back, &mut size);
            case(name);
            out_str(if set_ok { "set " } else { "failed " });
            if got == 0 {
                out_str("get=");
                out_dec(read_back as u64);
                out_str(" size=");
                out_dec(size as u64);
            } else {
                out_str("get=failed");
            }
            out_byte(b'\n');
        }
        let interface = [127u8, 0, 0, 1];
        boolean(
            "socket.ip_multicast_if",
            set(udp, 0, 9, interface.as_ptr().cast(), 4) == 0,
        );
        close(udp);
        let listen = wsa_api!(
            module,
            "listen",
            unsafe extern "system" fn(usize, i32) -> i32
        );
        let connect = wsa_api!(
            module,
            "connect",
            unsafe extern "system" fn(usize, *const u8, i32) -> i32
        );
        let accept = wsa_api!(
            module,
            "accept",
            unsafe extern "system" fn(usize, *mut u8, *mut i32) -> usize
        );
        let send = wsa_api!(
            module,
            "send",
            unsafe extern "system" fn(usize, *const u8, i32, i32) -> i32
        );
        let recv = wsa_api!(
            module,
            "recv",
            unsafe extern "system" fn(usize, *mut u8, i32, i32) -> i32
        );
        let client = socket(2, 1, 6);
        let listening = listen(first, 1) == 0;
        let connected = connect(client, address.as_ptr(), 16) == 0;
        let accepted = if listening && connected {
            accept(first, core::ptr::null_mut(), core::ptr::null_mut())
        } else {
            usize::MAX
        };
        boolean("socket.accept", accepted != usize::MAX);
        let mut buffer = [0u8; 4];
        boolean(
            "socket.recv_push_peek",
            accepted != usize::MAX
                && send(client, b"ping".as_ptr(), 4, 0) == 4
                && recv(accepted, buffer.as_mut_ptr(), 4, 0x22) == 4
                && &buffer == b"ping",
        );
        buffer.fill(0);
        // Windows rejects MSG_WAITALL combined with MSG_PUSH_IMMEDIATE and
        // leaves the queued bytes for the next receive.
        case("socket.recv_push_waitall");
        clear_error();
        let received = if accepted != usize::MAX { recv(accepted, buffer.as_mut_ptr(), 4, 0x28) } else { -2 };
        if received == 4 && &buffer == b"ping" {
            out_str("ok\n");
        } else {
            out_str("failed");
            out_error();
            out_byte(b'\n');
        }
        buffer.fill(0);
        boolean(
            "socket.recv_waitall",
            accepted != usize::MAX
                && (received == 4 || recv(accepted, buffer.as_mut_ptr(), 4, 0x8) == 4 && &buffer == b"ping"),
        );
        close(accepted);
        close(client);
        close(second);
        close(first);
        cleanup();
    }
}
fn files() {
    write_file("file.seed", "native-startup.txt", b"abc");
    let handle = open(
        "file.open",
        "native-startup.txt",
        GENERIC_READ,
        OPEN_EXISTING,
        0,
    );
    type Duplicate =
        unsafe extern "system" fn(usize, usize, usize, *mut usize, u32, i32, u32) -> i32;
    type FileType = unsafe extern "system" fn(usize) -> u32;
    let duplicate = api!("file.duplicate_api", "DuplicateHandle", Duplicate);
    let kind = api!("file.type_api", "GetFileType", FileType);
    let mut copy = 0usize;
    unsafe {
        boolean(
            "file.duplicate_type",
            duplicate(usize::MAX, handle, usize::MAX, &mut copy, 0, 0, 2) != 0
                && kind(handle) == 1
                && kind(copy) == 1,
        );
        boolean(
            "file.duplicate_closed",
            NtClose(copy) == 0 && kind(copy) == 0 && kind(handle) == 1,
        );
        type Final = unsafe extern "system" fn(usize, *mut u16, u32, u32) -> u32;
        let final_name = api!("device.final_api", "GetFinalPathNameByHandleW", Final);
        let mut name = [0u16; 512];
        let length = final_name(handle, name.as_mut_ptr(), 512, 2);
        let unicode = [
            length as usize * 2 | ((length as usize * 2) << 16),
            name.as_ptr() as usize,
        ];
        let attributes = [48usize, 0, unicode.as_ptr() as usize, 0x40, 0, 0];
        let mut basic = [0u64; 5];
        boolean(
            "device.attributes_roundtrip",
            length > 0
                && length < 512
                && NtQueryAttributesFile(attributes.as_ptr(), basic.as_mut_ptr()) == 0,
        );
        boolean("close.success", NtClose(handle) == 0);
        boolean("close.invalid", NtClose(handle) == 0xc0000008);
    }
    let root = open(
        "directory.open",
        ".",
        GENERIC_READ,
        OPEN_EXISTING,
        BACKUP_SEMANTICS,
    );
    let name: [u16; 18] = [
        110, 97, 116, 105, 118, 101, 45, 115, 116, 97, 114, 116, 117, 112, 46, 116, 120, 116,
    ];
    // UNICODE_STRING and OBJECT_ATTRIBUTES, using a directory-relative name.
    let unicode = [36usize | (36 << 16), name.as_ptr() as usize];
    let attributes = [48usize, root, unicode.as_ptr() as usize, 0x40, 0, 0];
    let mut basic = [0u64; 5];
    type Attributes = unsafe extern "system" fn(*const u16, u32, *mut u32) -> i32;
    let get = api!("attributes.win32", "GetFileAttributesExW", Attributes);
    let mut full_name = [0u16; 19];
    full_name[..18].copy_from_slice(&name);
    let mut win32 = [0u32; 9];
    unsafe {
        boolean(
            "attributes.file",
            NtQueryAttributesFile(attributes.as_ptr(), basic.as_mut_ptr()) == 0
                && get(full_name.as_ptr(), 0, win32.as_mut_ptr()) != 0
                && basic[0] == win32[1] as u64 | ((win32[2] as u64) << 32)
                && basic[4] as u32 == win32[0]
                && (basic[4] as u32) & 0x10 == 0,
        );
    }
    let mut found = false;
    let mut completed = false;
    for scan in 0..16 {
        let mut status = [0u64; 2];
        let mut entries = [0u8; 1024];
        let result = unsafe {
            NtQueryDirectoryFile(
                root,
                0,
                0,
                0,
                status.as_mut_ptr(),
                entries.as_mut_ptr(),
                1024,
                1,
                0,
                0,
                (scan == 0) as u8,
            )
        };
        if result == 0x80000006 {
            completed = true;
            break;
        }
        if result != 0 || status[1] == 0 {
            break;
        }
        let mut offset = 0usize;
        loop {
            let length =
                u32::from_le_bytes(entries[offset + 60..offset + 64].try_into().unwrap()) as usize;
            if length == 36
                && name.iter().enumerate().all(|(i, unit)| {
                    u16::from_le_bytes([entries[offset + 64 + i * 2], entries[offset + 65 + i * 2]])
                        == *unit
                })
            {
                found = true;
            }
            let next = u32::from_le_bytes(entries[offset..offset + 4].try_into().unwrap()) as usize;
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
    boolean("directory.entries", found && completed);
    unsafe {
        NtClose(root);
    }
}
fn suspended_child_mode() {
    type Command = unsafe extern "system" fn() -> *const u16;
    let command = api!("child.command", "GetCommandLineW", Command);
    unsafe {
        let pointer = command();
        let mut length = 0;
        while length < 4096 && *pointer.add(length) != 0 {
            length += 1;
        }
        let units = core::slice::from_raw_parts(pointer, length);
        let marker = b"--startup-child";
        if !units
            .windows(marker.len())
            .any(|part| part.iter().zip(marker).all(|(a, b)| *a == *b as u16))
        {
            return;
        }
        type Sleep = unsafe extern "system" fn(u32);
        let sleep = api!("child.sleep", "Sleep", Sleep);
        let create = api!("child.file_api", "CreateFileW", CreateFileWFn);
        let mut path = [0u16; 64];
        for (index, byte) in b"child-live.txt".iter().enumerate() {
            path[index] = *byte as u16;
        }
        let file = create(
            path.as_ptr(),
            GENERIC_WRITE,
            SHARE_ALL,
            0,
            CREATE_ALWAYS,
            0,
            0,
        );
        let mut written = 0;
        if file == INVALID_HANDLE
            || WriteFile(file, b"live".as_ptr(), 4, &mut written, 0) == 0
            || written != 4
        {
            ExitProcess(24);
        }
        NtClose(file);
        sleep(2000);
        ExitProcess(23);
    }
}

fn suspended_process() {
    type Module = unsafe extern "system" fn(usize, *mut u16, u32) -> u32;
    type Process = unsafe extern "system" fn(
        *const u16,
        *mut u16,
        usize,
        usize,
        i32,
        u32,
        usize,
        usize,
        *mut u8,
        *mut usize,
    ) -> i32;
    type Wait = unsafe extern "system" fn(usize, u32) -> u32;
    type Resume = unsafe extern "system" fn(usize) -> u32;
    type ExitCode = unsafe extern "system" fn(usize, *mut u32) -> i32;
    type Io = unsafe extern "system" fn(usize, *mut u64) -> i32;
    let module = api!("suspend.module_api", "GetModuleFileNameW", Module);
    let create = api!("suspend.create_api", "CreateProcessW", Process);
    let wait = api!("suspend.wait_api", "WaitForSingleObject", Wait);
    let resume = api!("suspend.resume_api", "ResumeThread", Resume);
    let exit = api!("suspend.exit_api", "GetExitCodeProcess", ExitCode);
    let io = api!("suspend.io_api", "GetProcessIoCounters", Io);
    let mut path = [0u16; 512];
    let length = unsafe { module(0, path.as_mut_ptr(), 512) } as usize;
    let mut command = [0u16; 600];
    command[0] = 34;
    command[1..length + 1].copy_from_slice(&path[..length]);
    for (i, byte) in br#"" --startup-child"#.iter().enumerate() {
        command[length + 1 + i] = *byte as u16;
    }
    let mut startup = [0u64; 13];
    startup[0] = 104;
    let mut information = [0usize; 3];
    let created = unsafe {
        create(
            path.as_ptr(),
            command.as_mut_ptr(),
            0,
            0,
            0,
            4,
            0,
            0,
            startup.as_mut_ptr().cast(),
            information.as_mut_ptr(),
        )
    };
    boolean("suspend.created", created != 0);
    if created == 0 {
        return;
    }
    type ProcessId = unsafe extern "system" fn(usize) -> u32;
    let process_id = api!("suspend.process_id_api", "GetProcessId", ProcessId);
    unsafe {
        boolean("suspend.process_id", process_id(information[0]) == information[2] as u32);
        clear_error();
        case("suspend.process_id_of_thread_handle");
        out_dec(process_id(information[1]) as u64);
        out_error();
        out_byte(b'\n');
        boolean("suspend.before_resume", wait(information[0], 20) == 258);
        boolean("suspend.invalid_handle", resume(information[0]) == u32::MAX);
        boolean("suspend.resume", resume(information[1]) == 1);
        boolean("suspend.second_resume", resume(information[1]) == 0);
        type Sleep = unsafe extern "system" fn(u32);
        let sleep = api!("live.sleep_api", "Sleep", Sleep);
        let attributes = api!(
            "live.attributes_api",
            "GetFileAttributesW",
            GetFileAttributesWFn
        );
        let remove = api!("live.remove_api", "DeleteFileW", DeleteFileWFn);
        let mut path = [0u16; 64];
        for (index, byte) in b"child-live.txt".iter().enumerate() {
            path[index] = *byte as u16;
        }
        let mut visible = false;
        for _ in 0..50 {
            if attributes(path.as_ptr()) != u32::MAX {
                visible = true;
                break;
            }
            sleep(20);
        }
        boolean(
            "live.before_exit",
            visible && wait(information[0], 0) == 258,
        );
        boolean("live.parent_remove", visible && remove(path.as_ptr()) != 0);
        let finished = wait(information[0], 5000) == 0;
        let mut code = 0;
        boolean(
            "suspend.exit",
            finished && exit(information[0], &mut code) != 0 && code == 23,
        );
        let mut counts = [0u64; 6];
        boolean(
            "suspend.final_io",
            io(information[0], counts.as_mut_ptr()) != 0,
        );
        boolean(
            "live.no_final_replay",
            attributes(path.as_ptr()) == u32::MAX,
        );
        NtClose(information[1]);
        NtClose(information[0]);
    }
}

fn resources() {
    type Io = unsafe extern "system" fn(usize, *mut u64) -> i32;
    type Memory = unsafe extern "system" fn(usize, *mut u8, u32) -> i32;
    let io = api!("process.io_api", "GetProcessIoCounters", Io);
    let memory = api!("process.memory_api", "K32GetProcessMemoryInfo", Memory);
    let mut counts = [0u64; 6];
    let mut usage = [0u64; 11];
    usage[10] = u64::MAX;
    unsafe {
        boolean("process.io", io(usize::MAX, counts.as_mut_ptr()) != 0);
        let saved = counts;
        boolean(
            "process.io_invalid",
            io(0, counts.as_mut_ptr()) == 0 && counts == saved,
        );
        boolean(
            "process.memory",
            memory(usize::MAX, usage.as_mut_ptr().cast(), 80) != 0
                && usage[0] as u32 == 80
                && usage[1] >= usage[2]
                && usage[2] > 0
                && usage[8] >= usage[7]
                && usage[9] == usage[7]
                && usage[10] == u64::MAX,
        );
        let saved = usage;
        boolean(
            "process.memory_invalid",
            memory(0, usage.as_mut_ptr().cast(), 80) == 0 && usage == saved,
        );
        boolean(
            "process.memory_small",
            memory(usize::MAX, usage.as_mut_ptr().cast(), 71) == 0 && usage == saved,
        );
        boolean(
            "process.memory_basic",
            memory(usize::MAX, usage.as_mut_ptr().cast(), 72) != 0
                && usage[0] as u32 == 72
                && usage[9] == saved[9]
                && usage[10] == u64::MAX,
        );
    }
}
fn certificates() {
    type Load = unsafe extern "system" fn(*const u8) -> usize;
    let load = api!("cert.load", "LoadLibraryA", Load);
    let module = unsafe { load(b"CRYPT32.dll\0".as_ptr()) };
    let open = wsa_api!(
        module,
        "CertOpenStore",
        unsafe extern "system" fn(usize, u32, usize, u32, *const u16) -> usize
    );
    let next = wsa_api!(
        module,
        "CertEnumCertificatesInStore",
        unsafe extern "system" fn(usize, usize) -> usize
    );
    let duplicate = wsa_api!(
        module,
        "CertDuplicateCertificateContext",
        unsafe extern "system" fn(usize) -> usize
    );
    let free = wsa_api!(
        module,
        "CertFreeCertificateContext",
        unsafe extern "system" fn(usize) -> i32
    );
    let close = wsa_api!(
        module,
        "CertCloseStore",
        unsafe extern "system" fn(usize, u32) -> i32
    );
    let usage = wsa_api!(
        module,
        "CertGetEnhancedKeyUsage",
        unsafe extern "system" fn(usize, u32, *mut u8, *mut u32) -> i32
    );
    let root = [82u16, 79, 79, 84, 0];
    unsafe {
        let memory = open(2, 0, 0, 0, core::ptr::null());
        boolean(
            "cert.memory_empty",
            memory != 0 && next(memory, 0) == 0 && last_error() == 0x80092004,
        );
        boolean("cert.memory_close", close(memory, 0) != 0);
        let store = open(10, 0, 0, 0x2c000, root.as_ptr());
        let first = if store != 0 { next(store, 0) } else { 0 };
        boolean("cert.root_open", store != 0 && first != 0);
        if first == 0 {
            if store != 0 {
                close(store, 0);
            }
            return;
        }
        let context = first as *const u8;
        let encoding = (context as *const u32).read_unaligned();
        let data = (context.add(8) as *const usize).read_unaligned();
        let encoded_size = (context.add(16) as *const u32).read_unaligned();
        let info = (context.add(24) as *const usize).read_unaligned();
        boolean(
            "cert.root_context",
            encoding == 1
                && encoded_size > 100
                && data != 0
                && *(data as *const u8) == 48
                && info != 0
                && *(info as *const u32) <= 2
                && *((info + 48) as *const u32) > 0,
        );
        let mut size = 0;
        let queried = usage(first, 0, core::ptr::null_mut(), &mut size) != 0;
        boolean("cert.usage_size", queried && size >= 16 && size <= 4096);
        let mut buffer = [0x5555555555555555u64; 512];
        let mut small = 1;
        boolean(
            "cert.usage_small",
            usage(first, 0, buffer.as_mut_ptr().cast(), &mut small) == 0
                && last_error() == 234
                && small == size
                && buffer[0] == 0x5555555555555555,
        );
        // Each observation prints separately (sizes as relations to the
        // size query, never machine-specific numbers).
        let mut capacity = 4096u32;
        let base = buffer.as_ptr() as usize;
        clear_error();
        let read = usage(first, 0, buffer.as_mut_ptr().cast(), &mut capacity);
        case("cert.usage_read");
        out_dec(read as u64);
        if read == 0 {
            out_error();
        }
        out_byte(b'\n');
        case("cert.usage_read_size");
        out_str(if capacity == size {
            "=query"
        } else if capacity == 4096 {
            "=buffer"
        } else if capacity < size {
            "<query"
        } else {
            ">query"
        });
        out_byte(b'\n');
        let count = buffer[0] as u32 as usize;
        let array = buffer[1] as usize;
        case("cert.usage_read_layout");
        out_str(if count == 0 {
            "empty"
        } else if array >= base + 16 && array + count * 8 <= base + 4096 {
            "inside"
        } else {
            "outside"
        });
        out_byte(b'\n');
        boolean("cert.duplicate", duplicate(first) == first);
        let mut current = first;
        let mut complete = false;
        for _ in 0..4096 {
            current = next(store, current);
            if current == 0 {
                complete = last_error() == 0x80092004;
                break;
            }
        }
        boolean("cert.enum_end", complete);
        boolean(
            "cert.pending_close",
            close(store, 2) == 0 && last_error() == 0x8009200f,
        );
        boolean(
            "cert.copy_survives_close",
            *(data as *const u8) == 48 && (context.add(16) as *const u32).read_unaligned() == encoded_size,
        );
        boolean("cert.free", free(first) != 0 && free(0) != 0);
    }
}

unsafe extern "system" fn alert_waiter(_: usize) -> u32 {
    let timeout = -10_000_000i64;
    NtWaitForAlertByThreadId(0, &timeout)
}
fn alerts_and_console_flush() {
    type Id = unsafe extern "system" fn() -> u32;
    type Thread = unsafe extern "system" fn(usize, usize, usize, usize, u32, *mut u32) -> usize;
    type Wait = unsafe extern "system" fn(usize, u32) -> u32;
    type Code = unsafe extern "system" fn(usize, *mut u32) -> i32;
    let id = api!("alert.id_api", "GetCurrentThreadId", Id);
    let create = api!("alert.thread_api", "CreateThread", Thread);
    let wait = api!("alert.wait_api", "WaitForSingleObject", Wait);
    let code = api!("alert.code_api", "GetExitCodeThread", Code);
    unsafe {
        let poll = 0i64;
        boolean("alert.timeout", NtWaitForAlertByThreadId(0, &poll) == 0x102);
        boolean(
            "alert.pending",
            NtAlertThreadByThreadId(id() as usize) == 0
                && NtAlertThreadByThreadId(id() as usize) == 0
                && NtWaitForAlertByThreadId(0, &poll) == 0x101
                && NtWaitForAlertByThreadId(0, &poll) == 0x102,
        );
        let mut target = 0;
        let thread = create(0, 0, alert_waiter as *const () as usize, 0, 0, &mut target);
        let notified = thread != 0 && NtAlertThreadByThreadId(target as usize) == 0;
        let mut result = 0;
        boolean(
            "alert.other_thread",
            notified
                && wait(thread, 2000) == 0
                && code(thread, &mut result) != 0
                && result == 0x101,
        );
        NtClose(thread);
        type Flush = unsafe extern "system" fn(usize) -> i32;
        type Inject = unsafe extern "system" fn(usize, *const u8, u32, *mut u32) -> i32;
        type Count = unsafe extern "system" fn(usize, *mut u32) -> i32;
        let flush_input = api!("console.flush_api", "FlushConsoleInputBuffer", Flush);
        let inject = api!("console.inject_api", "WriteConsoleInputW", Inject);
        let count = api!("console.count_api", "GetNumberOfConsoleInputEvents", Count);
        let mut record = [0u8; 20];
        record[0] = 1;
        record[4] = 1;
        record[8] = 1;
        record[14] = 65;
        // Standard input may be redirected; the console input buffer is CONIN$.
        let create = api!("console.conin_api", "CreateFileW", CreateFileWFn);
        let mut name = [0u16; 8];
        let input = create(wide("CONIN$", &mut name).as_ptr(), 0xc0000000, 3, 0, 3, 0, 0);
        let mut written = 0;
        let mut remaining = u32::MAX;
        boolean(
            "console.flush_input",
            inject(input, record.as_ptr(), 1, &mut written) != 0
                && written == 1
                && flush_input(input) != 0
                && count(input, &mut remaining) != 0
                && remaining == 0,
        );
        if input != usize::MAX {
            NtClose(input);
        }
        // Both oracle runners redirect stdout and stderr to pipes, which
        // are not consoles: console-mode queries fail on them.
        type ConsoleMode = unsafe extern "system" fn(usize, *mut u32) -> i32;
        let console_mode = api!("console.mode_api", "GetConsoleMode", ConsoleMode);
        for (name, which) in [("console.stdout_redirected", 0xfffffff5u32), ("console.stderr_redirected", 0xfffffff4)] {
            let mut mode = 0;
            clear_error();
            case(name);
            out_dec(console_mode(GetStdHandle(which), &mut mode) as u64);
            out_error();
            out_byte(b'\n');
        }
        boolean(
            "console.flush_output",
            flush_input(GetStdHandle(0xfffffff5)) == 0 && last_error() == 6,
        );
    }
}

fn sync_pipes() {
    type Peek = unsafe extern "system" fn(usize,*mut u8,u32,*mut u32,*mut u32,*mut u32)->i32;
    let peek = api!("pipe.peek_api", "PeekNamedPipe", Peek);
    type Pipe = unsafe extern "system" fn(*mut usize, *mut usize, usize, u32) -> i32;
    type Read = unsafe extern "system" fn(usize, *mut u8, u32, *mut u32, *mut u64) -> i32;
    let pipe = api!("sync_pipe.api", "CreatePipe", Pipe);
    let read = api!("sync_pipe.read_api", "ReadFile", Read);
    let mut reader = 0;
    let mut writer = 0;
    unsafe {
        let created = pipe(&mut reader, &mut writer, 0, 0) != 0;
        boolean("sync_pipe.created", created);
        if !created {
            return;
        }
        let mut status = [0u64; 2];
        let mut access = 0;
        boolean(
            "sync_pipe.read_access",
            NtQueryInformationFile(reader, status.as_mut_ptr(), &mut access, 4, 8) == 0
                && access & 3 == 1,
        );
        boolean(
            "sync_pipe.write_access",
            NtQueryInformationFile(writer, status.as_mut_ptr(), &mut access, 4, 8) == 0
                && access & 3 == 2,
        );
        let mut write_overlap = [0u64; 4];
        let mut read_overlap = [0u64; 4];
        let mut transferred = 0;
        boolean(
            "sync_pipe.write",
            WriteFile(
                writer,
                b"sync".as_ptr(),
                4,
                &mut transferred,
                write_overlap.as_mut_ptr() as usize,
            ) != 0
                && transferred == 4,
        );
        let mut peeked = [0u8; 1];
        let mut peek_count = 99;
        let mut available = 99;
        let mut left = 99;
        boolean("pipe.peek", peek(reader,peeked.as_mut_ptr(),1,&mut peek_count,&mut available,&mut left)!=0 && peeked[0]==b's' && peek_count==1 && available==4 && left==u32::MAX);
        boolean("pipe.peek_query", peek(reader,core::ptr::null_mut(),0,&mut peek_count,&mut available,&mut left)!=0 && peek_count==0 && available==4 && left==0);
        let mut buffer = [0u8; 4];
        boolean(
            "sync_pipe.read",
            read(
                reader,
                buffer.as_mut_ptr(),
                4,
                &mut transferred,
                read_overlap.as_mut_ptr(),
            ) != 0
                && transferred == 4
                && &buffer == b"sync",
        );
        NtClose(writer);
        read_overlap.fill(0);
        boolean(
            "sync_pipe.eof",
            read(
                reader,
                buffer.as_mut_ptr(),
                4,
                &mut transferred,
                read_overlap.as_mut_ptr(),
            ) == 0
                && last_error() == 109,
        );
        boolean("pipe.peek_eof", peek(reader,core::ptr::null_mut(),0,&mut peek_count,&mut available,&mut left)==0 && last_error()==109);
        NtClose(reader);
    }
}

fn nt_memory() {
    let mut base = 0;
    let mut size = 3;
    unsafe {
        let allocated =
            NtAllocateVirtualMemory(usize::MAX, &mut base, 0, &mut size, 0x3000, 4) == 0;
        boolean("nt_memory.allocate", allocated && base != 0 && size == 4096);
        if !allocated {
            return;
        }
        *(base as *mut u8) = 23;
        let original = base;
        base += 1;
        size = 1;
        let mut old = 0;
        boolean(
            "nt_memory.protect",
            NtProtectVirtualMemory(usize::MAX, &mut base, &mut size, 2, &mut old) == 0
                && base == original
                && size == 4096
                && old == 4
                && *(base as *const u8) == 23,
        );
        size = 0;
        boolean(
            "nt_memory.release",
            NtFreeVirtualMemory(usize::MAX, &mut base, &mut size, 0x8000) == 0,
        );
        type Time = unsafe extern "system" fn(*mut u64);
        let clock = api!("nt_time.api", "GetSystemTimePreciseAsFileTime", Time);
        let mut before = 0;
        let mut after = 0;
        clock(&mut before);
        let precise = RtlGetSystemTimePrecise();
        clock(&mut after);
        boolean("nt_time.precise", before <= precise && precise <= after);
        let mut counter1 = 0;
        let mut counter2 = 0;
        let mut frequency = 0;
        boolean(
            "nt_time.performance",
            RtlQueryPerformanceFrequency(&mut frequency) != 0
                && frequency > 0
                && RtlQueryPerformanceCounter(&mut counter1) != 0
                && RtlQueryPerformanceCounter(&mut counter2) != 0
                && counter2 >= counter1,
        );
    }
}

fn waits() {
    let address = 1u32;
    let different = 2u32;
    let poll = 0i64;
    unsafe {
        boolean(
            "wait.different",
            RtlWaitOnAddress(&address, &different, 4, core::ptr::null()) == 0,
        );
        boolean(
            "wait.timeout",
            RtlWaitOnAddress(&address, &address, 4, &poll) == 0x102,
        );
        boolean(
            "wait.invalid",
            RtlWaitOnAddress(&address, &address, 3, &poll) == 0xc000000d,
        );
        RtlWakeAddressAll(&address);
        RtlWakeAddressSingle(&address);
    }
}
#[no_mangle]
pub extern "system" fn probe_entry() -> ! {
    suspended_child_mode();
    out_str("probe native_startup\n");
    modules();
    nt_heap();
    nt_threads();
    files();
    socket_options();
    waits();
    nt_memory();
    sync_pipes();
    alerts_and_console_flush();
    resources();
    certificates();
    suspended_process();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
