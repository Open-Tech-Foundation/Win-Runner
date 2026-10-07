//! Unnamed pipes through the named-pipe file system, the way current
//! Windows runtimes create a child's standard streams (Rust's std among
//! them): open `\Device\NamedPipe\`, `NtCreateNamedPipeFile` an unnamed pipe
//! relative to it, then `NtOpenFile` the pipe itself (empty name, the pipe as
//! root) for the other end. The ends are the same unidirectional endpoints
//! `CreatePipe` makes.

use super::*;

/// The handle of the opened named-pipe file system root.
pub(super) const PIPE_FS_HANDLE: u64 = 0x4e50_4653_0000_0001;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x10;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const OBJ_INHERIT: u32 = 0x2;
const FILE_OPENED: u64 = 1;
const FILE_CREATED: u64 = 2;

/// Ends created by `NtCreateNamedPipeFile` whose other end is still to be
/// opened, by the created end's handle.
static UNOPENED_PEERS: LazyLock<Mutex<HashMap<u64, Arc<NativePipeEndpoint>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// `OBJECT_ATTRIBUTES` as (root directory, object name, attributes).
fn read_attributes(attributes: *const u8) -> Option<(u64, String, u32)> {
    if attributes.is_null() {
        return None;
    }
    let root = unsafe { attributes.add(8).cast::<u64>().read_unaligned() };
    let name = unsafe { attributes.add(16).cast::<*const u8>().read_unaligned() };
    let flags = unsafe { attributes.add(24).cast::<u32>().read_unaligned() };
    let text = if name.is_null() {
        String::new()
    } else {
        let length = unsafe { name.cast::<u16>().read_unaligned() } as usize / 2;
        let buffer = unsafe { name.add(8).cast::<*const u16>().read_unaligned() };
        if buffer.is_null() || length == 0 {
            String::new()
        } else {
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(buffer, length) })
        }
    };
    Some((root, text, flags))
}

fn complete(io_status: *mut u8, information: u64) {
    if !io_status.is_null() {
        unsafe {
            io_status.cast::<u32>().write_unaligned(STATUS_SUCCESS);
            io_status.add(8).cast::<u64>().write_unaligned(information);
        }
    }
}

/// Readable or writable end for an access mask (GENERIC_READ/FILE_READ_DATA
/// against GENERIC_WRITE/FILE_WRITE_DATA).
fn end_access(access: u32) -> Option<u32> {
    let read = access & (0x8000_0000 | 0x1) != 0;
    let write = access & (0x4000_0000 | 0x2) != 0;
    match (read, write) {
        (true, false) => Some(0x8000_0000),
        (false, true) => Some(0x4000_0000),
        _ => None,
    }
}

fn insert_end(
    endpoint: Arc<NativePipeEndpoint>,
    access: u32,
    overlapped: bool,
    inheritable: bool,
) -> Option<u64> {
    let process = process_ctx()?;
    let mut pipes = process.named_pipes.lock().ok()?;
    let handle = pipes.next;
    pipes.next += 1;
    pipes.handles.insert(
        handle,
        NativePipeHandle {
            endpoint,
            pending_client: None,
            overlapped,
            inheritable,
            access,
            mode: 0,
            completion: None,
            completion_modes: 0,
        },
    );
    Some(handle)
}

/// The pipe-file-system opens `NtCreateFile`/`NtOpenFile` handle here:
/// `None` when `attributes` names something else.
pub(super) fn open_pipe_object(
    handle: *mut u64,
    access: u32,
    attributes: *const u8,
    io_status: *mut u8,
    options: u32,
) -> Option<u32> {
    let (root, name, flags) = read_attributes(attributes)?;
    if root == 0 {
        let trimmed = name.trim_end_matches('\\');
        if !trimmed.eq_ignore_ascii_case(r"\Device\NamedPipe") {
            return None;
        }
        unsafe { handle.write(PIPE_FS_HANDLE) };
        complete(io_status, FILE_OPENED);
        return Some(STATUS_SUCCESS);
    }
    if !name.is_empty() {
        return None;
    }
    // The other end of an unnamed pipe: the pipe itself as root.
    let peer = UNOPENED_PEERS.lock().ok()?.remove(&root)?;
    let Some(end) = end_access(access) else {
        return Some(STATUS_INVALID_PARAMETER);
    };
    let overlapped = options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) == 0;
    let Some(opened) = insert_end(peer, end, overlapped, flags & OBJ_INHERIT != 0) else {
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    };
    unsafe { handle.write(opened) };
    complete(io_status, FILE_OPENED);
    Some(STATUS_SUCCESS)
}

/// `NtCreateNamedPipeFile`: unnamed pipes under the pipe-file-system root.
/// Named pipes go through `CreateNamedPipeW`.
#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_nt_create_named_pipe_file(
    handle: *mut u64,
    access: u32,
    attributes: *const u8,
    io_status: *mut u8,
    _share: u32,
    _disposition: u32,
    options: u32,
    _pipe_type: u32,
    _read_mode: u32,
    _completion_mode: u32,
    _maximum_instances: u32,
    _inbound_quota: u32,
    _outbound_quota: u32,
    _default_timeout: *const i64,
) -> u32 {
    if handle.is_null() || io_status.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let Some((root, name, flags)) = read_attributes(attributes) else {
        return STATUS_INVALID_PARAMETER;
    };
    if root != PIPE_FS_HANDLE {
        return if root == 0 { STATUS_NOT_SUPPORTED } else { STATUS_INVALID_HANDLE };
    }
    if !name.is_empty() {
        return STATUS_NOT_SUPPORTED;
    }
    let Some(end) = end_access(access) else {
        return STATUS_INVALID_PARAMETER;
    };
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr())
    } != 0
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // fds[0] reads, fds[1] writes; EOF follows the writer's close.
    unsafe {
        libc::shutdown(fds[0], libc::SHUT_WR);
        libc::shutdown(fds[1], libc::SHUT_RD);
    }
    let endpoint = |fd: i32, access: u32| {
        Arc::new(NativePipeEndpoint {
            fd,
            name: String::new(),
            server: false,
            access,
        })
    };
    let readable = end == 0x8000_0000;
    let (ours, theirs) = if readable {
        (endpoint(fds[0], 0x8000_0000), endpoint(fds[1], 0x4000_0000))
    } else {
        (endpoint(fds[1], 0x4000_0000), endpoint(fds[0], 0x8000_0000))
    };
    let overlapped = options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) == 0;
    let Some(created) = insert_end(ours, end, overlapped, flags & OBJ_INHERIT != 0) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    if let Ok(mut peers) = UNOPENED_PEERS.lock() {
        peers.insert(created, theirs);
    }
    unsafe { handle.write(created) };
    complete(io_status, FILE_CREATED);
    STATUS_SUCCESS
}

/// Closing a created end before its peer was opened drops the peer too.
pub(super) fn forget_unopened_peer(handle: u64) {
    if let Ok(mut peers) = UNOPENED_PEERS.lock() {
        peers.remove(&handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attributes(root: u64, name: &[u16], flags: u32) -> ([u8; 16], [u8; 48]) {
        let mut unicode = [0u8; 16];
        unicode[..2].copy_from_slice(&((name.len() * 2) as u16).to_le_bytes());
        unicode[2..4].copy_from_slice(&((name.len() * 2) as u16).to_le_bytes());
        unicode[8..].copy_from_slice(&(name.as_ptr() as u64).to_le_bytes());
        let mut object = [0u8; 48];
        object[..4].copy_from_slice(&48u32.to_le_bytes());
        object[8..16].copy_from_slice(&root.to_le_bytes());
        object[24..28].copy_from_slice(&flags.to_le_bytes());
        (unicode, object)
    }

    fn with_name(object: &mut [u8; 48], unicode: &[u8; 16]) {
        object[16..24].copy_from_slice(&(unicode.as_ptr() as u64).to_le_bytes());
    }

    #[test]
    fn unnamed_pipes_open_their_peer_once_and_carry_data() {
        let _process = crate::native::linux_x86_64::context::TestProcessGuard::new();
        let device: Vec<u16> = r"\Device\NamedPipe\".encode_utf16().collect();
        let (unicode, mut object) = attributes(0, &device, 0);
        with_name(&mut object, &unicode);
        let mut root = 0;
        let mut io = [0u8; 16];
        assert_eq!(open_pipe_object(&mut root, 0x8010_0000, object.as_ptr(), io.as_mut_ptr(), 0x20), Some(0));
        assert_eq!(root, PIPE_FS_HANDLE);

        // Our end reads; theirs (inheritable, synchronous) writes.
        let empty: [u16; 0] = [];
        let (unicode, mut object) = attributes(PIPE_FS_HANDLE, &empty, 0);
        with_name(&mut object, &unicode);
        let mut ours = 0;
        let status = native_nt_create_named_pipe_file(
            &mut ours, 0x8010_0000, object.as_ptr(), io.as_mut_ptr(), 2, 2, 0, 0, 0, 0, 1, 65536, 65536,
            std::ptr::null(),
        );
        assert_eq!(status, 0);
        assert_eq!(u64::from_le_bytes(io[8..].try_into().unwrap()), FILE_CREATED);
        let (unicode, mut object) = attributes(ours, &empty, OBJ_INHERIT);
        with_name(&mut object, &unicode);
        let mut theirs = 0;
        assert_eq!(open_pipe_object(&mut theirs, 0x4010_0080, object.as_ptr(), io.as_mut_ptr(), 0x20), Some(0));
        assert_eq!(open_pipe_object(&mut theirs, 0x4010_0080, object.as_ptr(), io.as_mut_ptr(), 0x20), None, "one peer");
        let pipes = process_ctx().unwrap();
        let pipes = pipes.named_pipes.lock().unwrap();
        let (reader, writer) = (&pipes.handles[&ours], &pipes.handles[&theirs]);
        assert!(reader.overlapped && !reader.inheritable && reader.access == 0x8000_0000);
        assert!(!writer.overlapped && writer.inheritable && writer.access == 0x4000_0000);
        let message = b"through the pipe";
        assert_eq!(unsafe { libc::write(writer.endpoint.fd, message.as_ptr().cast(), message.len()) }, message.len() as isize);
        let mut buffer = [0u8; 32];
        let read = unsafe { libc::read(reader.endpoint.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        assert_eq!(&buffer[..read as usize], message);
    }

    #[test]
    fn named_or_unrooted_pipe_creation_is_refused() {
        let name: Vec<u16> = "x".encode_utf16().collect();
        let (unicode, mut object) = attributes(PIPE_FS_HANDLE, &name, 0);
        with_name(&mut object, &unicode);
        let (mut handle, mut io) = (0u64, [0u8; 16]);
        let create = |object: &[u8; 48], handle: &mut u64, io: &mut [u8; 16]| {
            native_nt_create_named_pipe_file(
                handle, 0x8000_0000, object.as_ptr(), io.as_mut_ptr(), 0, 2, 0, 0, 0, 0, 1, 0, 0,
                std::ptr::null(),
            )
        };
        assert_eq!(create(&object, &mut handle, &mut io), STATUS_NOT_SUPPORTED);
        let (unicode, mut object) = attributes(0x1234, &[], 0);
        with_name(&mut object, &unicode);
        assert_eq!(create(&object, &mut handle, &mut io), STATUS_INVALID_HANDLE);
    }
}
