//! Module identity, Winsock ordinal exports and statically imported NT APIs.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
include!("fs_support.rs");
extern "system" {
    fn NtClose(handle: usize) -> u32;
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
        boolean(
            "socket.recv_push_waitall",
            accepted != usize::MAX
                && recv(accepted, buffer.as_mut_ptr(), 4, 0x28) == 4
                && &buffer == b"ping",
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
        sleep(50);
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
    unsafe {
        boolean("suspend.before_resume", wait(information[0], 20) == 258);
        boolean("suspend.invalid_handle", resume(information[0]) == u32::MAX);
        boolean("suspend.resume", resume(information[1]) == 1);
        boolean("suspend.second_resume", resume(information[1]) == 0);
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
    files();
    socket_options();
    waits();
    resources();
    suspended_process();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
