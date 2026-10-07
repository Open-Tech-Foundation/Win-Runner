//! Windows-oracle probe: pipes through the NT API. `NtWriteFile` and
//! `NtReadFile` on `CreatePipe` ends, and the unnamed-pipe sequence current
//! runtimes use for a child's standard streams (Rust's std among them):
//! `NtOpenFile` of `\Device\NamedPipe\`, `NtCreateNamedPipeFile` with an
//! empty name relative to it, and `NtOpenFile` of the pipe itself for the
//! other end. Statuses print as raw NTSTATUS values.

#![no_std]
#![no_main]
#![allow(dead_code)] // shared helpers a probe does not use

include!("common.rs");

type CreatePipeFn = unsafe extern "system" fn(*mut usize, *mut usize, usize, u32) -> i32;
type HandleFn = unsafe extern "system" fn(usize) -> i32;
type WriteFileFn = unsafe extern "system" fn(usize, *const u8, u32, *mut u32, usize) -> i32;
type ReadFileFn = unsafe extern "system" fn(usize, *mut u8, u32, *mut u32, usize) -> i32;
type NtTransferFn = unsafe extern "system" fn(usize, usize, usize, usize, *mut u64, *mut u8, u32, *const i64, *const u32) -> u32;
type NtOpenFileFn = unsafe extern "system" fn(*mut usize, u32, *const u64, *mut u64, u32, u32) -> u32;
type NtCreateNamedPipeFileFn = unsafe extern "system" fn(
    *mut usize, u32, *const u64, *mut u64, u32, u32, u32, u32, u32, u32, u32, u32, u32, *const i64,
) -> u32;

const SYNCHRONIZE: u32 = 0x0010_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_CREATE: u32 = 2;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;

fn ntdll(name: &[u8]) -> usize {
    let mut module = [0u16; 16];
    unsafe { GetProcAddress(GetModuleHandleW(wide("ntdll.dll", &mut module).as_ptr()), name.as_ptr()) }
}

fn status_line(name: &str, status: u32, io: &[u64; 2], extra: &str) {
    case(name);
    out_str("status=");
    out_hex(status as u64);
    if status == 0 {
        out_str(" bytes=");
        out_dec(io[1]);
    }
    out_str(extra);
    out_byte(b'\n');
}

/// UNICODE_STRING and OBJECT_ATTRIBUTES (48 bytes) for `name` under `root`.
fn object(root: usize, name: &[u16], unicode: &mut [u64; 2]) -> [u64; 6] {
    let bytes = (name.len() * 2) as u64;
    unicode[0] = bytes | bytes << 16;
    unicode[1] = name.as_ptr() as u64;
    [48, root as u64, unicode.as_ptr() as u64, 0, 0, 0]
}

fn win32_pipes() {
    let create = api!("nt_pipe.create_api", "CreatePipe", CreatePipeFn);
    let close = api!("nt_pipe.close_api", "CloseHandle", HandleFn);
    let (write_api, read_api) = (ntdll(b"NtWriteFile\0"), ntdll(b"NtReadFile\0"));
    if write_api == 0 || read_api == 0 {
        unavailable("nt_pipe.transfer_api");
        return;
    }
    let nt_write = unsafe { core::mem::transmute::<usize, NtTransferFn>(write_api) };
    let nt_read = unsafe { core::mem::transmute::<usize, NtTransferFn>(read_api) };
    let (mut reader, mut writer) = (0usize, 0usize);
    if unsafe { create(&mut reader, &mut writer, 0, 0) } == 0 {
        unavailable("nt_pipe.created");
        return;
    }
    let mut io = [0u64; 2];
    let message = b"nt-pipe";
    let status = unsafe {
        nt_write(writer, 0, 0, 0, io.as_mut_ptr(), message.as_ptr() as *mut u8, 7, core::ptr::null(), core::ptr::null())
    };
    status_line("nt_pipe.write", status, &io, "");
    let mut buffer = [0u8; 16];
    io = [0; 2];
    let status = unsafe {
        nt_read(reader, 0, 0, 0, io.as_mut_ptr(), buffer.as_mut_ptr(), 16, core::ptr::null(), core::ptr::null())
    };
    status_line("nt_pipe.read", status, &io, if &buffer[..7] == message { " data=ok" } else { " data=wrong" });
    unsafe { close(writer) };
    io = [0; 2];
    let status = unsafe {
        nt_read(reader, 0, 0, 0, io.as_mut_ptr(), buffer.as_mut_ptr(), 16, core::ptr::null(), core::ptr::null())
    };
    status_line("nt_pipe.read_after_close", status, &io, "");
    unsafe { close(reader) };
}

fn unnamed_pipes() {
    let (open_api, create_api) = (ntdll(b"NtOpenFile\0"), ntdll(b"NtCreateNamedPipeFile\0"));
    if open_api == 0 || create_api == 0 {
        unavailable("unnamed_pipe.api");
        return;
    }
    let nt_open = unsafe { core::mem::transmute::<usize, NtOpenFileFn>(open_api) };
    let nt_create = unsafe { core::mem::transmute::<usize, NtCreateNamedPipeFileFn>(create_api) };
    let write = api!("unnamed_pipe.write_api", "WriteFile", WriteFileFn);
    let read = api!("unnamed_pipe.read_api", "ReadFile", ReadFileFn);
    let close = api!("unnamed_pipe.close_api", "CloseHandle", HandleFn);

    let mut device = [0u16; 32];
    let device = wide(r"\Device\NamedPipe\", &mut device);
    let device = &device[..device.len() - 1];
    let mut unicode = [0u64; 2];
    let attributes = object(0, device, &mut unicode);
    let mut io = [0u64; 2];
    let mut root = 0usize;
    let status = unsafe {
        nt_open(&mut root, SYNCHRONIZE | GENERIC_READ, attributes.as_ptr(), io.as_mut_ptr(),
            FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT)
    };
    case("unnamed_pipe.open_root");
    out_str("status=");
    out_hex(status as u64);
    out_byte(b'\n');
    if status != 0 {
        return;
    }
    let empty: [u16; 0] = [];
    let attributes = object(root, &empty, &mut unicode);
    let timeout = -500_000i64;
    let mut ours = 0usize;
    let status = unsafe {
        nt_create(&mut ours, SYNCHRONIZE | GENERIC_READ, attributes.as_ptr(), io.as_mut_ptr(),
            FILE_SHARE_WRITE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0, 0, 1, 4096, 4096, &timeout)
    };
    case("unnamed_pipe.create");
    out_str("status=");
    out_hex(status as u64);
    out_byte(b'\n');
    if status != 0 {
        unsafe { close(root) };
        return;
    }
    let attributes = object(ours, &empty, &mut unicode);
    let mut theirs = 0usize;
    let status = unsafe {
        nt_open(&mut theirs, SYNCHRONIZE | GENERIC_WRITE | FILE_READ_ATTRIBUTES, attributes.as_ptr(),
            io.as_mut_ptr(), FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT)
    };
    case("unnamed_pipe.open_peer");
    out_str("status=");
    out_hex(status as u64);
    out_byte(b'\n');
    if status == 0 {
        let mut count = 0u32;
        let wrote = unsafe { write(theirs, b"unnamed".as_ptr(), 7, &mut count, 0) } != 0 && count == 7;
        let mut buffer = [0u8; 16];
        let got = unsafe { read(ours, buffer.as_mut_ptr(), 16, &mut count, 0) } != 0
            && count == 7
            && &buffer[..7] == b"unnamed";
        case("unnamed_pipe.transfer");
        out_str(if wrote && got { "ok\n" } else { "wrong\n" });
        unsafe { close(theirs) };
    }
    unsafe {
        close(ours);
        close(root);
    }
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe nt_pipes\n");
    win32_pipes();
    unnamed_pipes();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
