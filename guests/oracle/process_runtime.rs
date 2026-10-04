//! Windows oracle for the process startup APIs and anonymous child pipes.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
include!("fs_support.rs");

type Pipe = unsafe extern "system" fn(*mut usize, *mut usize, usize, u32) -> i32;
type Read = unsafe extern "system" fn(usize, *mut u8, u32, *mut u32, usize) -> i32;
type Duplicate = unsafe extern "system" fn(usize, usize, usize, *mut usize, u32, i32, u32) -> i32;
type GetMode = unsafe extern "system" fn() -> u32;
type SetMode = unsafe extern "system" fn(u32) -> u32;
type CreateTimer = unsafe extern "system" fn(usize, *const u16, u32, u32) -> usize;
type SetTimer = unsafe extern "system" fn(usize, *const i64, i32, usize, usize, i32) -> i32;
type CancelTimer = unsafe extern "system" fn(usize) -> i32;
type Wait = unsafe extern "system" fn(usize, u32) -> u32;
type Sleep = unsafe extern "system" fn(u32);
type Directory = unsafe extern "system" fn(*mut u8, u32) -> u32;
type AddHandler = unsafe extern "system" fn(u32, usize) -> usize;
type RemoveHandler = unsafe extern "system" fn(usize) -> u32;

fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}
fn number(name: &str, value: u32) {
    case(name);
    out_dec(value as u64);
    out_byte(b'\n');
}

fn pipes() {
    let create = api!("pipe.create", "CreatePipe", Pipe);
    let read = api!("pipe.read", "ReadFile", Read);
    let duplicate = api!("pipe.duplicate", "DuplicateHandle", Duplicate);
    let mut r = 0;
    let mut w = 0;
    let mut count = 0;
    ok_or_error("pipe.create", unsafe { create(&mut r, &mut w, 0, 0) });
    if r == 0 || w == 0 {
        return;
    }
    type SetInformation = unsafe extern "system" fn(usize, u32, u32) -> i32;
    let set_info = api!("pipe.inherit", "SetHandleInformation", SetInformation);
    ok_or_error("pipe.inherit", unsafe { set_info(r, 1, 0) });
    ok_or_error("pipe.write", unsafe {
        WriteFile(w, b"abc".as_ptr(), 3, &mut count, 0)
    });
    number("pipe.written", count);
    let mut buffer = [0; 8];
    ok_or_error("pipe.read", unsafe {
        read(r, buffer.as_mut_ptr(), 8, &mut count, 0)
    });
    boolean("pipe.bytes", count == 3 && &buffer[..3] == b"abc");
    clear_error();
    ok_or_error("pipe.write_reader", unsafe {
        WriteFile(r, b"x".as_ptr(), 1, &mut count, 0)
    });
    clear_error();
    ok_or_error("pipe.read_writer", unsafe {
        read(w, buffer.as_mut_ptr(), 1, &mut count, 0)
    });
    let mut copy = 0;
    ok_or_error("pipe.duplicate", unsafe {
        duplicate(usize::MAX, w, usize::MAX, &mut copy, 0, 0, 2)
    });
    close(w);
    ok_or_error("pipe.write_duplicate", unsafe {
        WriteFile(copy, b"x".as_ptr(), 1, &mut count, 0)
    });
    ok_or_error("pipe.read_duplicate", unsafe {
        read(r, buffer.as_mut_ptr(), 1, &mut count, 0)
    });
    boolean("pipe.duplicate_bytes", count == 1 && buffer[0] == b'x');
    close(copy);
    clear_error();
    ok_or_error("pipe.eof", unsafe {
        read(r, buffer.as_mut_ptr(), 1, &mut count, 0)
    });
    close(r);
}

fn flags_and_paths() {
    let get = api!("mode.get", "GetErrorMode", GetMode);
    let set = api!("mode.set", "SetErrorMode", SetMode);
    let old = unsafe { get() };
    unsafe {
        set(3);
    }
    number("mode.roundtrip", unsafe { get() });
    unsafe {
        set(old);
    }
    let get_directory = api!("system_directory", "GetSystemDirectoryA", Directory);
    let required = unsafe { get_directory(core::ptr::null_mut(), 0) };
    let mut buffer = [0; 512];
    let small = unsafe { get_directory(buffer.as_mut_ptr(), 1) };
    let length = unsafe { get_directory(buffer.as_mut_ptr(), 512) };
    boolean(
        "system_directory.capacity",
        required == small && required == length + 1 && buffer[length as usize] == 0,
    );
    type Boost = unsafe extern "system" fn(usize, i32) -> i32;
    let boost = api!("priority_boost", "SetProcessPriorityBoost", Boost);
    ok_or_error("priority_boost.current", unsafe { boost(usize::MAX, 1) });
    clear_error();
    ok_or_error("priority_boost.invalid", unsafe { boost(0, 1) });
    type WerSet = unsafe extern "system" fn(u32) -> u32;
    type WerGet = unsafe extern "system" fn(usize, *mut u32) -> u32;
    let wer_get = api!("wer.get", "WerGetFlags", WerGet);
    let wer_set = api!("wer.set", "WerSetFlags", WerSet);
    let mut flags = 0;
    number("wer.set", unsafe { wer_set(2) });
    number("wer.get", unsafe { wer_get(usize::MAX, &mut flags) });
    number("wer.flags", flags);
}

static CONTINUED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
unsafe extern "system" fn continue_handler(_: usize) -> i32 {
    CONTINUED.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    0
}
unsafe extern "system" fn exception_handler(_: usize) -> i32 {
    -1
}
fn continuations() {
    let add = api!("continue.add", "AddVectoredContinueHandler", AddHandler);
    let remove = api!(
        "continue.remove",
        "RemoveVectoredContinueHandler",
        RemoveHandler
    );
    let handle = unsafe { add(1, continue_handler as *const () as usize) };
    boolean("continue.register", handle != 0);
    if handle != 0 {
        let add_exception = api!(
            "continue.exception",
            "AddVectoredExceptionHandler",
            AddHandler
        );
        let remove_exception = api!(
            "continue.exception_remove",
            "RemoveVectoredExceptionHandler",
            RemoveHandler
        );
        type Raise = unsafe extern "system" fn(u32, u32, u32, usize);
        let raise = api!("continue.raise", "RaiseException", Raise);
        let exception = unsafe { add_exception(1, exception_handler as *const () as usize) };
        if exception != 0 {
            unsafe {
                raise(0xe0420001, 0, 0, 0);
            }
            number(
                "continue.dispatched",
                CONTINUED.load(core::sync::atomic::Ordering::SeqCst),
            );
            unsafe {
                remove_exception(exception);
            }
        }
        number("continue.remove", unsafe { remove(handle) });
    }
}

fn timers() {
    let create = api!("timer.create", "CreateWaitableTimerExW", CreateTimer);
    let set = api!("timer.set", "SetWaitableTimer", SetTimer);
    let cancel = api!("timer.cancel", "CancelWaitableTimer", CancelTimer);
    let wait = api!("timer.wait", "WaitForSingleObject", Wait);
    let timer = unsafe { create(0, core::ptr::null(), 1, 0x1f0003) };
    boolean("timer.created", timer != 0);
    if timer == 0 {
        return;
    }
    number("timer.unarmed", unsafe { wait(timer, 0) });
    let due = -5_000_000;
    ok_or_error("timer.set", unsafe { set(timer, &due, 0, 0, 0, 0) });
    number("timer.expires", unsafe { wait(timer, 5000) });
    number("timer.manual_sticky", unsafe { wait(timer, 0) });
    ok_or_error("timer.rearm", unsafe { set(timer, &due, 0, 0, 0, 0) });
    ok_or_error("timer.cancel", unsafe { cancel(timer) });
    number("timer.cancelled", unsafe { wait(timer, 25) });
    clear_error();
    ok_or_error("timer.bad_period", unsafe { set(timer, &due, -1, 0, 0, 0) });
    close(timer);
    type CreateA = unsafe extern "system" fn(usize, i32, *const u8) -> usize;
    let create_a = api!("timer.create_a", "CreateWaitableTimerA", CreateA);
    let auto = unsafe { create_a(0, 0, core::ptr::null()) };
    boolean("timer.auto_created", auto != 0);
    if auto != 0 {
        let immediate = 0;
        ok_or_error("timer.auto_set", unsafe {
            set(auto, &immediate, 0, 0, 0, 0)
        });
        number("timer.auto_expired", unsafe { wait(auto, 5000) });
        number("timer.auto_reset", unsafe { wait(auto, 0) });
        ok_or_error("timer.periodic_set", unsafe {
            set(auto, &immediate, 50, 0, 0, 0)
        });
        number("timer.periodic_first", unsafe { wait(auto, 5000) });
        number("timer.periodic_second", unsafe { wait(auto, 5000) });
        close(auto);
    }
}

fn shared_clock() {
    let sleep = api!("clock.sleep", "Sleep", Sleep);
    unsafe {
        let monotonic = (0x7ffe0008 as *const u64).read_volatile();
        let system = (0x7ffe0014 as *const u64).read_unaligned();
        sleep(25);
        boolean(
            "clock.monotonic",
            (0x7ffe0008 as *const u64).read_volatile() > monotonic,
        );
        boolean(
            "clock.system",
            (0x7ffe0014 as *const u64).read_unaligned() > system,
        );
        let mut name = [0; 32];
        let module = GetModuleHandleW(wide("ntdll.dll", &mut name).as_ptr());
        let address = GetProcAddress(module, b"RtlGetCurrentPeb\0".as_ptr());
        if address == 0 {
            unavailable("peb");
        } else {
            let query: unsafe extern "system" fn() -> usize = core::mem::transmute(address);
            let teb_peb: usize;
            core::arch::asm!("mov {}, gs:[0x60]", out(reg) teb_peb, options(nostack, readonly));
            boolean("peb.current", query() == teb_peb && teb_peb != 0);
        }
    }
}

fn console_modes() {
    type Open = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
    type Get = unsafe extern "system" fn(usize, *mut u32) -> i32;
    type Set = unsafe extern "system" fn(usize, u32) -> i32;
    let open = api!("console.open", "CreateFileW", Open);
    let get = api!("console.mode", "GetConsoleMode", Get);
    let set = api!("console.set", "SetConsoleMode", Set);
    let mut name = [0; 16];
    let mut output = unsafe {
        open(
            wide("CONOUT$", &mut name).as_ptr(),
            0xc0000000,
            3,
            0,
            3,
            0,
            0,
        )
    };
    if output == usize::MAX {
        // CI may start the Windows probe without a console. Allocate one,
        // retaining its redirected stdout so the transcript is captured.
        type Allocate = unsafe extern "system" fn() -> i32;
        type Standard = unsafe extern "system" fn(u32, usize) -> i32;
        let allocate = api!("console.allocate", "AllocConsole", Allocate);
        let standard = api!("console.stdout", "SetStdHandle", Standard);
        let stdout = unsafe { GetStdHandle(-11i32 as u32) };
        unsafe {
            allocate();
            standard(-11i32 as u32, stdout);
        }
        output = unsafe {
            open(
                wide("CONOUT$", &mut name).as_ptr(),
                0xc0000000,
                3,
                0,
                3,
                0,
                0,
            )
        };
    }
    boolean("console.read_write_output", output != usize::MAX);
    if output == usize::MAX {
        return;
    }
    let mut old = 0;
    ok_or_error("console.get_output", unsafe { get(output, &mut old) });
    ok_or_error("console.enable_vt", unsafe { set(output, old | 5) });
    let mut mode = 0;
    ok_or_error("console.get_vt", unsafe { get(output, &mut mode) });
    boolean("console.vt_preserved", mode & 5 == 5);
    unsafe {
        set(output, old);
    }
    close(output);
    let input = unsafe {
        open(
            wide("CONIN$", &mut name).as_ptr(),
            0xc0000000,
            3,
            0,
            3,
            0,
            0,
        )
    };
    boolean("console.read_write_input", input != usize::MAX);
    if input != usize::MAX {
        ok_or_error("console.get_input", unsafe { get(input, &mut mode) });
        close(input);
    }
}

fn volume() {
    type Open = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
    type Volume = unsafe extern "system" fn(
        usize,
        *mut u16,
        u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u16,
        u32,
    ) -> i32;
    type Information = unsafe extern "system" fn(usize, *mut u8) -> i32;
    let open = api!("volume.open", "CreateFileW", Open);
    let query = api!("volume.query", "GetVolumeInformationByHandleW", Volume);
    let information = api!(
        "volume.file_info",
        "GetFileInformationByHandle",
        Information
    );
    let mut path = [0; 4];
    let handle = unsafe {
        open(
            wide(".", &mut path).as_ptr(),
            0x80000000,
            7,
            0,
            3,
            0x02000000,
            0,
        )
    };
    boolean("volume.open_directory", handle != usize::MAX);
    if handle == usize::MAX {
        return;
    }
    let mut serial = 0;
    let mut maximum = 0;
    let mut flags = 0;
    let mut name = [0u16; 256];
    let mut filesystem = [0u16; 256];
    ok_or_error("volume.query", unsafe {
        query(
            handle,
            name.as_mut_ptr(),
            256,
            &mut serial,
            &mut maximum,
            &mut flags,
            filesystem.as_mut_ptr(),
            256,
        )
    });
    boolean(
        "volume.names",
        name.contains(&0) && filesystem[0] != 0 && filesystem.contains(&0),
    );
    boolean("volume.component_limit", maximum >= 255);
    boolean("volume.unicode_case_preserved", flags & 6 == 6);
    let mut info = [0u8; 64];
    ok_or_error("volume.file_info", unsafe {
        information(handle, info.as_mut_ptr())
    });
    boolean(
        "volume.serial_consistent",
        serial == u32::from_le_bytes(info[28..32].try_into().unwrap()),
    );
    clear_error();
    ok_or_error("volume.invalid", unsafe {
        query(
            usize::MAX,
            core::ptr::null_mut(),
            0,
            &mut serial,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
        )
    });
    close(handle);
}

fn child_mode() -> bool {
    type CommandLine = unsafe extern "system" fn() -> *const u16;
    let address = kernel32(b"GetCommandLineW\0");
    if address == 0 {
        return false;
    }
    let query: CommandLine = unsafe { core::mem::transmute(address) };
    let command = unsafe { query() };
    let marker = b"--pipe-child ";
    let mut index = 0;
    while unsafe { *command.add(index) } != 0 && index < 2048 {
        if marker
            .iter()
            .enumerate()
            .all(|(offset, byte)| unsafe { *command.add(index + offset) } == *byte as u16)
        {
            let mut number = 0usize;
            index += marker.len();
            while unsafe { *command.add(index) } >= b'0' as u16
                && unsafe { *command.add(index) } <= b'9' as u16
            {
                number = number * 10 + unsafe { *command.add(index) } as usize - b'0' as usize;
                index += 1;
            }
            type FileType = unsafe extern "system" fn(usize) -> u32;
            let kind: FileType = unsafe { core::mem::transmute(kernel32(b"GetFileType\0")) };
            clear_error();
            boolean("child.excluded", unsafe { kind(number) } == 0);
            out_str("child-output\n");
            flush();
            return true;
        }
        index += 1;
    }
    false
}

fn extended_process() {
    type Initialize = unsafe extern "system" fn(*mut u8, u32, u32, *mut usize) -> i32;
    type Update =
        unsafe extern "system" fn(*mut u8, u32, usize, *const u8, usize, usize, usize) -> i32;
    type Delete = unsafe extern "system" fn(*mut u8);
    type ModuleName = unsafe extern "system" fn(usize, *mut u16, u32) -> u32;
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
        *mut u8,
    ) -> i32;
    type Times = unsafe extern "system" fn(usize, *mut u64, *mut u64, *mut u64, *mut u64) -> i32;
    let initialize = api!(
        "startup.initialize",
        "InitializeProcThreadAttributeList",
        Initialize
    );
    let update = api!("startup.update", "UpdateProcThreadAttribute", Update);
    let delete = api!("startup.delete", "DeleteProcThreadAttributeList", Delete);
    let module = api!("startup.module", "GetModuleFileNameW", ModuleName);
    let process = api!("startup.process", "CreateProcessW", Process);
    let times = api!("startup.times", "GetProcessTimes", Times);
    let pipe = api!("startup.pipe", "CreatePipe", Pipe);
    let duplicate = api!("startup.duplicate", "DuplicateHandle", Duplicate);
    let read = api!("startup.read", "ReadFile", Read);
    let wait = api!("startup.wait", "WaitForSingleObject", Wait);
    let mut size = 0;
    clear_error();
    ok_or_error("startup.size_query", unsafe {
        initialize(core::ptr::null_mut(), 1, 0, &mut size)
    });
    let mut attributes = [0u64; 512];
    if size > 4096 {
        boolean("startup.size_fits", false);
        return;
    }
    ok_or_error("startup.initialize", unsafe {
        initialize(attributes.as_mut_ptr().cast(), 1, 0, &mut size)
    });
    let mut reader = 0;
    let mut writer = 0;
    let mut inherited = 0;
    if unsafe { pipe(&mut reader, &mut writer, 0, 0) } == 0 {
        unavailable("startup.pipe");
        return;
    }
    ok_or_error("startup.writer", unsafe {
        duplicate(usize::MAX, writer, usize::MAX, &mut inherited, 0, 1, 2)
    });
    let mut extra_reader = 0;
    let mut extra_writer = 0;
    unsafe {
        pipe(&mut extra_reader, &mut extra_writer, 0, 0);
    }
    type SetInfo = unsafe extern "system" fn(usize, u32, u32) -> i32;
    let set_info = api!("startup.extra", "SetHandleInformation", SetInfo);
    unsafe {
        set_info(extra_writer, 1, 1);
    }
    ok_or_error("startup.handle_list", unsafe {
        update(
            attributes.as_mut_ptr().cast(),
            0,
            0x20002,
            (&inherited as *const usize).cast(),
            8,
            0,
            0,
        )
    });
    let mut path = [0u16; 1024];
    let length = unsafe { module(0, path.as_mut_ptr(), 1024) } as usize;
    let mut command = [0u16; 2048];
    let mut cursor = 0;
    command[cursor] = b'"' as u16;
    cursor += 1;
    for character in &path[..length] {
        command[cursor] = *character;
        cursor += 1;
    }
    for character in b"\" --pipe-child " {
        command[cursor] = *character as u16;
        cursor += 1;
    }
    let mut digits = [0u16; 24];
    let mut used = 0;
    let mut value = extra_writer;
    loop {
        digits[used] = (value % 10) as u16 + b'0' as u16;
        used += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for index in (0..used).rev() {
        command[cursor] = digits[index];
        cursor += 1;
    }
    let mut startup = [0u64; 14];
    startup[0] = 112;
    unsafe {
        startup
            .as_mut_ptr()
            .cast::<u8>()
            .add(60)
            .cast::<u32>()
            .write_unaligned(0x100);
    }
    startup[11] = inherited as u64;
    startup[12] = inherited as u64;
    startup[13] = attributes.as_ptr() as u64;
    let mut info = [0u64; 3];
    let created = unsafe {
        process(
            path.as_ptr(),
            command.as_mut_ptr(),
            0,
            0,
            1,
            0x08080000,
            0,
            0,
            startup.as_mut_ptr().cast(),
            info.as_mut_ptr().cast(),
        )
    };
    ok_or_error("startup.process", created);
    // The NULL-target close-source idiom must close the inherited writer.
    unsafe {
        duplicate(usize::MAX, inherited, 0, core::ptr::null_mut(), 0, 0, 1);
    }
    close(writer);
    if created != 0 {
        let waited = unsafe { wait(info[0] as usize, 5000) };
        number("startup.child_wait", waited);
        if waited != 0 {
            close(info[0] as usize);
            close(info[1] as usize);
            close(reader);
            close(extra_reader);
            close(extra_writer);
            unsafe { delete(attributes.as_mut_ptr().cast()) };
            return;
        }
        let mut creation = 0;
        let mut exit = 0;
        let mut kernel = 0;
        let mut user = 0;
        ok_or_error("startup.child_times", unsafe {
            times(
                info[0] as usize,
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        });
        boolean("startup.time_order", creation != 0 && exit >= creation);
        let mut bytes = [0u8; 128];
        let mut count = 0;
        ok_or_error("startup.read", unsafe {
            read(reader, bytes.as_mut_ptr(), 128, &mut count, 0)
        });
        // Line endings differ by output API, so compare the two markers.
        boolean(
            "startup.output",
            bytes[..count as usize]
                .windows(18)
                .any(|part| part == b"child.excluded: ok")
                && bytes[..count as usize]
                    .windows(12)
                    .any(|part| part == b"child-output"),
        );
        close(info[0] as usize);
        close(info[1] as usize);
    }
    close(reader);
    close(extra_reader);
    close(extra_writer);
    unsafe {
        delete(attributes.as_mut_ptr().cast());
    }
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    if child_mode() {
        unsafe { ExitProcess(0) }
    }
    out_str("probe process_runtime\n");
    pipes();
    flags_and_paths();
    continuations();
    timers();
    shared_clock();
    console_modes();
    volume();
    extended_process();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
