//! Overlapped Winsock through an I/O completion port, as proactor event
//! loops (Python's asyncio, libuv) use it: AcceptEx, WSARecv that pends
//! (also on a non-blocking socket), completion delivery, and CancelIoEx.
//! OVERLAPPED.Internal is reported as `pending` while it is STATUS_PENDING.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");

macro_rules! socket_api {
    ($module:expr, $name:literal, $ty:ty) => {{
        let address = unsafe { GetProcAddress($module, concat!($name, "\0").as_ptr()) };
        if address == 0 {
            unavailable($name);
            return;
        }
        unsafe { core::mem::transmute::<usize, $ty>(address) }
    }};
}

/// OVERLAPPED: Internal, InternalHigh, Offset/OffsetHigh, hEvent.
#[repr(C)]
struct Overlapped([usize; 4]);

fn internal(overlapped: &Overlapped) -> usize {
    unsafe { core::ptr::read_volatile(&overlapped.0[0]) }
}

fn pending_state(name: &str, overlapped: &Overlapped) {
    case(name);
    out_str(if internal(overlapped) == 0x103 { "pending\n" } else { "not pending\n" });
}

fn probe() {
    type Load = unsafe extern "system" fn(*const u16) -> usize;
    type Startup = unsafe extern "system" fn(u16, *mut u8) -> i32;
    type Socket = unsafe extern "system" fn(i32, i32, i32) -> usize;
    type Address = unsafe extern "system" fn(usize, *const u8, i32) -> i32;
    type GetAddress = unsafe extern "system" fn(usize, *mut u8, *mut i32) -> i32;
    type Listen = unsafe extern "system" fn(usize, i32) -> i32;
    type Send = unsafe extern "system" fn(usize, *const u8, i32, i32) -> i32;
    type Ioctl = unsafe extern "system" fn(usize, u32, *const u8, u32, *mut u8, u32, *mut u32, usize, usize) -> i32;
    type IoctlSocket = unsafe extern "system" fn(usize, i32, *mut u32) -> i32;
    type SetOption = unsafe extern "system" fn(usize, i32, i32, *const u8, i32) -> i32;
    type Recv = unsafe extern "system" fn(usize, *const [usize; 2], u32, *mut u32, *mut u32, *mut Overlapped, usize) -> i32;
    type LastError = unsafe extern "system" fn() -> i32;
    type Close = unsafe extern "system" fn(usize) -> i32;
    type AcceptEx = unsafe extern "system" fn(usize, usize, *mut u8, u32, u32, u32, *mut u32, *mut Overlapped) -> i32;
    type CreatePort = unsafe extern "system" fn(usize, usize, usize, u32) -> usize;
    type GetQueued = unsafe extern "system" fn(usize, *mut u32, *mut usize, *mut *mut Overlapped, u32) -> i32;
    type CancelIoEx = unsafe extern "system" fn(usize, *mut Overlapped) -> i32;

    let load = api!("socket.load", "LoadLibraryW", Load);
    let module = unsafe { load([119u16, 115, 50, 95, 51, 50, 46, 100, 108, 108, 0].as_ptr()) };
    let startup = socket_api!(module, "WSAStartup", Startup);
    let socket = socket_api!(module, "socket", Socket);
    let bind = socket_api!(module, "bind", Address);
    let connect = socket_api!(module, "connect", Address);
    let name = socket_api!(module, "getsockname", GetAddress);
    let peer = socket_api!(module, "getpeername", GetAddress);
    let listen = socket_api!(module, "listen", Listen);
    let send = socket_api!(module, "send", Send);
    let ioctl = socket_api!(module, "WSAIoctl", Ioctl);
    let ioctl_socket = socket_api!(module, "ioctlsocket", IoctlSocket);
    let set_option = socket_api!(module, "setsockopt", SetOption);
    let recv = socket_api!(module, "WSARecv", Recv);
    let wsa_error = socket_api!(module, "WSAGetLastError", LastError);
    let close = socket_api!(module, "closesocket", Close);
    let create_port = api!("iocp.create_api", "CreateIoCompletionPort", CreatePort);
    let get_queued = api!("iocp.get_api", "GetQueuedCompletionStatus", GetQueued);
    let cancel = api!("iocp.cancel_api", "CancelIoEx", CancelIoEx);

    let mut data = [0u8; 512];
    if unsafe { startup(0x202, data.as_mut_ptr()) } != 0 {
        unavailable("socket.startup");
        return;
    }
    let listener = unsafe { socket(2, 1, 6) };
    let accepted = unsafe { socket(2, 1, 6) };
    let client = unsafe { socket(2, 1, 6) };
    let mut address = [0u8; 16];
    address[0] = 2;
    address[4..8].copy_from_slice(&[127, 0, 0, 1]);
    let mut length = 16;
    if unsafe { bind(listener, address.as_ptr(), 16) } != 0
        || unsafe { listen(listener, 4) } != 0
        || unsafe { name(listener, address.as_mut_ptr(), &mut length) } != 0
    {
        unavailable("socket.listener");
        return;
    }
    let port = unsafe { create_port(usize::MAX, 0, 0, 0) };
    unsafe { create_port(listener, port, 1, 0) };

    // AcceptEx from WSAID_ACCEPTEX.
    let guid: [u8; 16] = [0xF1, 0x7D, 0x36, 0xB5, 0xAC, 0xCB, 0xCF, 0x11, 0x95, 0xCA, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92];
    let mut function = 0usize;
    let mut returned = 0u32;
    let found = unsafe {
        ioctl(listener, 0xC800_0006, guid.as_ptr(), 16, (&mut function as *mut usize).cast(), 8, &mut returned, 0, 0)
    } == 0;
    if !found || function == 0 {
        unavailable("accept_ex.function");
        return;
    }
    let accept_ex = unsafe { core::mem::transmute::<usize, AcceptEx>(function) };
    let mut accept_buffer = [0u8; 128];
    let mut accept_overlapped = Overlapped([0; 4]);
    let mut bytes = 0u32;
    let started = unsafe { accept_ex(listener, accepted, accept_buffer.as_mut_ptr(), 0, 32, 32, &mut bytes, &mut accept_overlapped) };
    case("accept_ex.start");
    out_str("ret=");
    out_dec(started as u64);
    out_str(" wsa=");
    out_dec(unsafe { wsa_error() } as u64);
    out_byte(b'\n');
    pending_state("accept_ex.before_connect", &accept_overlapped);

    if unsafe { connect(client, address.as_ptr(), 16) } != 0 {
        unavailable("socket.connect");
        return;
    }
    let (mut count, mut key, mut completed) = (0u32, 0usize, core::ptr::null_mut());
    let ok = unsafe { get_queued(port, &mut count, &mut key, &mut completed, 5000) };
    case("accept_ex.completion");
    out_str(if ok != 0 && completed == &mut accept_overlapped as *mut _ { "ok key=" } else { "wrong key=" });
    out_dec(key as u64);
    out_byte(b'\n');
    let listener_value = listener;
    unsafe { set_option(accepted, 0xffff, 0x700b, (&listener_value as *const usize).cast(), 8) };
    let mut peer_address = [0u8; 16];
    let mut peer_length = 16;
    case("accept_ex.peer");
    out_str(if unsafe { peer(accepted, peer_address.as_mut_ptr(), &mut peer_length) } == 0 { "connected\n" } else { "not connected\n" });

    unsafe { create_port(accepted, port, 2, 0) };
    let mut receive = [0u8; 16];
    let buffer = [receive.len(), receive.as_mut_ptr() as usize];
    let mut flags = 0u32;
    let mut receive_overlapped = Overlapped([0; 4]);
    let ret = unsafe { recv(accepted, &buffer, 1, &mut bytes, &mut flags, &mut receive_overlapped, 0) };
    case("wsa_recv.no_data");
    out_str("ret=");
    out_dec(ret as u32 as u64);
    out_str(" wsa=");
    out_dec(unsafe { wsa_error() } as u64);
    out_byte(b'\n');
    pending_state("wsa_recv.state", &receive_overlapped);
    unsafe { send(client, b"hey".as_ptr(), 3, 0) };
    let ok = unsafe { get_queued(port, &mut count, &mut key, &mut completed, 5000) };
    case("wsa_recv.completion");
    out_str(if ok != 0 && completed == &mut receive_overlapped as *mut _ { "ok bytes=" } else { "wrong bytes=" });
    out_dec(count as u64);
    out_str(if &receive[..3] == b"hey" { " data=ok\n" } else { " data=wrong\n" });

    // Non-blocking mode does not make an overlapped receive fail.
    let mut on = 1u32;
    unsafe { ioctl_socket(accepted, 0x8004_667E_u32 as i32, &mut on) };
    let mut nonblocking_overlapped = Overlapped([0; 4]);
    let ret = unsafe { recv(accepted, &buffer, 1, &mut bytes, &mut flags, &mut nonblocking_overlapped, 0) };
    case("wsa_recv.nonblocking");
    out_str("ret=");
    out_dec(ret as u32 as u64);
    out_str(" wsa=");
    out_dec(unsafe { wsa_error() } as u64);
    out_byte(b'\n');
    case("cancel.first");
    out_dec(unsafe { cancel(accepted, &mut nonblocking_overlapped) } as u64);
    out_byte(b'\n');
    let ok = unsafe { get_queued(port, &mut count, &mut key, &mut completed, 5000) };
    case("cancel.completion");
    out_str("ret=");
    out_dec(ok as u64);
    out_str(if completed == &mut nonblocking_overlapped as *mut _ { " same" } else { " other" });
    out_error();
    out_byte(b'\n');
    case("cancel.again");
    out_str("ret=");
    out_dec(unsafe { cancel(accepted, &mut nonblocking_overlapped) } as u64);
    out_error();
    out_byte(b'\n');
    unsafe {
        close(client);
        close(accepted);
        close(listener);
    }
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe overlapped_sockets\n");
    probe();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
