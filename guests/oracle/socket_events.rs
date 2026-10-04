//! Winsock event selection and fd_set layout against a loopback TCP peer.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}
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
fn sockets() {
    type Load = unsafe extern "system" fn(*const u16) -> usize;
    let load = api!("socket.load", "LoadLibraryW", Load);
    let module = unsafe { load([119u16, 115, 50, 95, 51, 50, 46, 100, 108, 108, 0].as_ptr()) };
    type Startup = unsafe extern "system" fn(u16, *mut u8) -> i32;
    type Socket = unsafe extern "system" fn(i32, i32, i32) -> usize;
    type Address = unsafe extern "system" fn(usize, *const u8, i32) -> i32;
    type GetAddress = unsafe extern "system" fn(usize, *mut u8, *mut i32) -> i32;
    type Listen = unsafe extern "system" fn(usize, i32) -> i32;
    type Accept = unsafe extern "system" fn(usize, *mut u8, *mut i32) -> usize;
    type Transfer = unsafe extern "system" fn(usize, *mut u8, i32, i32) -> i32;
    type CreateEvent = unsafe extern "system" fn() -> usize;
    type EventSelect = unsafe extern "system" fn(usize, usize, i32) -> i32;
    type Wait = unsafe extern "system" fn(u32, *const usize, i32, u32, i32) -> u32;
    type Enum = unsafe extern "system" fn(usize, usize, *mut i32) -> i32;
    type Close = unsafe extern "system" fn(usize) -> i32;
    type Select =
        unsafe extern "system" fn(i32, *mut usize, *mut usize, *mut usize, *const i32) -> i32;
    type IsSet = unsafe extern "system" fn(usize, *const usize) -> i32;
    let startup = socket_api!(module, "WSAStartup", Startup);
    let socket = socket_api!(module, "socket", Socket);
    let bind = socket_api!(module, "bind", Address);
    let connect = socket_api!(module, "connect", Address);
    let name = socket_api!(module, "getsockname", GetAddress);
    let listen = socket_api!(module, "listen", Listen);
    let accept = socket_api!(module, "accept", Accept);
    let send = socket_api!(module, "send", Transfer);
    let recv = socket_api!(module, "recv", Transfer);
    let create = socket_api!(module, "WSACreateEvent", CreateEvent);
    let event_select = socket_api!(module, "WSAEventSelect", EventSelect);
    let wait = socket_api!(module, "WSAWaitForMultipleEvents", Wait);
    let enumerate = socket_api!(module, "WSAEnumNetworkEvents", Enum);
    let close = socket_api!(module, "closesocket", Close);
    let close_event = socket_api!(module, "WSACloseEvent", Close);
    let select = socket_api!(module, "select", Select);
    let is_set = socket_api!(module, "__WSAFDIsSet", IsSet);
    let mut data = [0u8; 512];
    boolean(
        "socket.startup",
        unsafe { startup(0x202, data.as_mut_ptr()) } == 0,
    );
    let server = unsafe { socket(2, 1, 6) };
    let client = unsafe { socket(2, 1, 6) };
    if server == usize::MAX || client == usize::MAX {
        boolean("socket.create", false);
        return;
    }
    let mut address = [0u8; 16];
    address[0] = 2;
    address[4..8].copy_from_slice(&[127, 0, 0, 1]);
    let bound = unsafe { bind(server, address.as_ptr(), 16) } == 0;
    boolean("socket.bind", bound);
    if !bound {
        return;
    }
    let listening = unsafe { listen(server, 1) } == 0;
    boolean("socket.listen", listening);
    if !listening {
        return;
    }
    let mut length = 16;
    boolean(
        "socket.address",
        unsafe { name(server, address.as_mut_ptr(), &mut length) } == 0,
    );
    let connected = unsafe { connect(client, address.as_ptr(), 16) } == 0;
    boolean("socket.connect", connected);
    if !connected {
        return;
    }
    let peer = unsafe { accept(server, core::ptr::null_mut(), core::ptr::null_mut()) };
    if peer == usize::MAX {
        boolean("socket.accept", false);
        return;
    }
    let event = unsafe { create() };
    boolean("event.create", event != 0);
    boolean(
        "event.select",
        unsafe { event_select(client, event, 33) } == 0,
    );
    boolean("event.unarmed", unsafe { wait(1, &event, 0, 0, 0) } == 258);
    let mut set = [1usize, client];
    boolean(
        "select.member",
        unsafe { is_set(client, set.as_ptr()) } == 1,
    );
    boolean(
        "select.empty",
        unsafe {
            select(
                0,
                set.as_mut_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                [0, 0].as_ptr(),
            )
        } == 0
            && set[0] == 0,
    );
    let mut bytes = *b"abc";
    boolean(
        "socket.send",
        unsafe { send(peer, bytes.as_mut_ptr(), 3, 0) } == 3,
    );
    boolean(
        "event.readable",
        unsafe { wait(1, &event, 0, 1000, 0) } == 0,
    );
    let mut record = [0i32; 11];
    boolean(
        "event.enumerate",
        unsafe { enumerate(client, event, record.as_mut_ptr()) } == 0
            && record[0] == 1
            && record[1] == 0,
    );
    boolean("event.reset", unsafe { wait(1, &event, 0, 0, 0) } == 258);
    bytes = [0; 3];
    boolean(
        "socket.read_part",
        unsafe { recv(client, bytes.as_mut_ptr(), 1, 0) } == 1,
    );
    boolean("event.rearmed", unsafe { wait(1, &event, 0, 1000, 0) } == 0);
    unsafe {
        enumerate(client, event, record.as_mut_ptr());
    }
    boolean(
        "socket.read_rest",
        unsafe { recv(client, bytes.as_mut_ptr().add(1), 2, 0) } == 2 && &bytes == b"abc",
    );
    unsafe {
        close(peer);
    }
    boolean("event.closed", unsafe { wait(1, &event, 0, 1000, 0) } == 0);
    boolean(
        "event.close_record",
        unsafe { enumerate(client, event, record.as_mut_ptr()) } == 0 && record[0] & 32 != 0,
    );
    boolean("event.cancel", unsafe { event_select(client, 0, 0) } == 0);
    unsafe {
        close(client);
        close(server);
    }
    boolean("event.close", unsafe { close_event(event) } != 0);
}
#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe socket_events\n");
    sockets();
    out_str("END\n");
    flush();
    unsafe { ExitProcess(0) }
}
