//! Linux backend data structures for per-process Windows state.

use super::*;

#[derive(Clone)]
pub(super) struct NativeFile {
    pub(super) path: String,
    pub(super) offset: usize,
    pub(super) overlapped: bool,
    pub(super) completion: Option<(Arc<NativeCompletionPort>, u64)>,
}

pub(super) struct NativePipeEndpoint {
    pub(super) fd: i32,
    pub(super) name: String,
    pub(super) server: bool,
    pub(super) access: u32,
}

impl Drop for NativePipeEndpoint {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

#[derive(Clone)]
pub(super) struct NativePipeHandle {
    pub(super) endpoint: Arc<NativePipeEndpoint>,
    pub(super) pending_client: Option<Arc<NativePipeEndpoint>>,
    pub(super) overlapped: bool,
    pub(super) inheritable: bool,
    pub(super) access: u32,
    pub(super) mode: u32,
    pub(super) completion: Option<(Arc<NativeCompletionPort>, u64)>,
    pub(super) completion_modes: u8,
}

pub(super) struct NativeNamedPipeTable {
    pub(super) handles: HashMap<u64, NativePipeHandle>,
    pub(super) pending_clients:
        HashMap<String, std::collections::VecDeque<Arc<NativePipeEndpoint>>>,
    pub(super) pending_io: HashMap<(u64, u64), NativePendingPipeIo>,
    pub(super) next: u64,
}

pub(super) struct NativePendingPipeIo {
    pub(super) cancelled: Arc<AtomicBool>,
    pub(super) issuer: std::thread::ThreadId,
}

impl NativeNamedPipeTable {
    pub(super) fn new() -> Self {
        Self {
            handles: HashMap::new(),
            pending_clients: HashMap::new(),
            pending_io: HashMap::new(),
            next: 0xb000_0000,
        }
    }
}
#[derive(Clone)]
pub(super) struct NativeFind {
    pub(super) names: Vec<String>,
    pub(super) index: usize,
}
pub(super) struct NativeTls {
    pub(super) teb: Box<[u8; 0x1000]>,
    pub(super) slots: Box<[u64; 64]>,
    pub(super) _data: Vec<u8>,
    pub(super) _ldr: Box<[u8; 64]>,
}
impl NativeTls {
    pub(super) fn clone_for_thread(&self) -> Self {
        let mut out = Self {
            teb: self.teb.clone(),
            slots: self.slots.clone(),
            _data: self._data.clone(),
            _ldr: self._ldr.clone(),
        };
        let teb = out.teb.as_ptr() as u64;
        put64(&mut out.teb[..], 0x30, teb);
        put64(&mut out.teb[..], 0x58, out.slots.as_ptr() as u64);
        put64(&mut out.teb[..], 0x60, teb + 0x800);
        out.slots[0] = out._data.as_ptr() as u64;
        put64(&mut out.teb[..], 0x800 + 0x20, out._ldr.as_ptr() as u64);
        out
    }
}

pub(super) struct NativeFs {
    pub(super) fs: WinFs,
    pub(super) handles: HashMap<u64, NativeFile>,
    pub(super) devices: HashMap<u64, NativeDevice>,
    pub(super) file_access: HashMap<u64, u32>,
    pub(super) file_shares: HashMap<u64, u32>,
    pub(super) finds: HashMap<u64, NativeFind>,
    pub(super) file_completion_modes: HashMap<u64, u8>,
    pub(super) delete_on_close: std::collections::HashSet<u64>,
    pub(super) file_locks: Vec<(String, u64, u64, u64)>,
    pub(super) next: u64,
}

impl NativeFs {
    pub(super) fn clone_for_child(&self, current_directory: &str) -> Result<Self, String> {
        let mut fs = self.fs.clone();
        fs.set_cwd(current_directory)?;
        Ok(Self {
            fs,
            handles: self.handles.clone(),
            devices: self.devices.clone(),
            file_access: self.file_access.clone(),
            file_shares: self.file_shares.clone(),
            finds: self.finds.clone(),
            file_completion_modes: self.file_completion_modes.clone(),
            delete_on_close: self.delete_on_close.clone(),
            file_locks: self.file_locks.clone(),
            next: self.next,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeDevice {
    Null,
    Console { input: u64, output: u64 },
    ConsoleIn(u64),
    ConsoleOut(u64),
}

/// Mutable state owned by one Windows guest process.
pub(super) struct NativeProcessContext {
    pub(super) image_base: u64,
    pub(super) image_size: u32,
    pub(super) module_path: String,
    pub(super) process_id: u32,
    pub(super) process_handle: u64,
    pub(super) parent_process_id: u32,
    pub(super) command_line_w: Vec<u16>,
    pub(super) command_line_a: Vec<u8>,
    pub(super) environment: Mutex<Vec<(String, String)>>,
    pub(super) environment_block: Mutex<Vec<u16>>,
    pub(super) std_handles: [AtomicU64; 3],
    pub(super) crt_fds: Mutex<HashMap<i32, u64>>,
    pub(super) crt_fd_next: AtomicI32,
    pub(super) fs: Arc<Mutex<NativeFs>>,
    pub(super) named_pipes: Mutex<NativeNamedPipeTable>,
    pub(super) error_mode: AtomicU32,
    pub(super) pointer_cookie: u64,
    pub(super) heap_allocations: Mutex<HashMap<u64, usize>>,
    pub(super) virtual_allocations: Mutex<HashMap<u64, NativeVirtualAllocation>>,
    pub(super) file_mappings: Mutex<HashMap<u64, NativeFileMapping>>,
    pub(super) mapping_views: Mutex<HashMap<u64, NativeMappingView>>,
    pub(super) mapping_next: AtomicU64,
    pub(super) gs_base: AtomicU64,
    pub(super) tls_template: Mutex<Option<NativeTls>>,
    pub(super) dynamic_tls: Mutex<DynamicTlsSlots>,
    pub(super) threads: Mutex<HashMap<u64, NativeThread>>,
    pub(super) thread_next: AtomicU64,
    pub(super) semaphores: Mutex<HashMap<u64, Arc<NativeSemaphore>>>,
    pub(super) semaphore_next: AtomicU64,
    pub(super) events: Mutex<HashMap<u64, Arc<NativeEvent>>>,
    pub(super) event_names: Mutex<HashMap<String, std::sync::Weak<NativeEvent>>>,
    pub(super) event_next: AtomicU64,
    pub(super) job_objects: Mutex<HashMap<u64, NativeJobObject>>,
    pub(super) wait_registrations: Mutex<HashMap<u64, Arc<NativeWaitRegistration>>>,
    pub(super) completion_ports: Mutex<HashMap<u64, Arc<NativeCompletionPort>>>,
    pub(super) socket_handles: Mutex<std::collections::HashSet<u64>>,
    pub(super) socket_completion_ports: Mutex<HashMap<u64, (Arc<NativeCompletionPort>, u64)>>,
    pub(super) socket_completion_modes: Mutex<HashMap<u64, u8>>,
    pub(super) completion_next: AtomicU64,
    pub(super) io_wait: Mutex<()>,
    pub(super) io_ready: Condvar,
    pub(super) pending_file_io: AtomicU64,
    pub(super) pending_requests: Mutex<HashMap<(u64, u64), Arc<NativePendingIo>>>,
    pub(super) file_io_queue: Mutex<Option<Arc<NativeFileIoQueue>>>,
    pub(super) duplicate_handles: Mutex<HashMap<u64, u64>>,
    pub(super) duplicate_next: AtomicU64,
    pub(super) timer_next: AtomicU64,
    pub(super) state_fd: AtomicU32,
    pub(super) fls_value: AtomicU64,
    pub(super) unhandled_exception_filter: AtomicU64,
    pub(super) vectored_exception_handler: AtomicU64,
    pub(super) exit_status: AtomicU32,
    pub(super) exited: AtomicBool,
    pub(super) children: Mutex<NativeProcessTable>,
    /// Real PE DLLs loaded through LoadLibrary in this guest process.
    pub(super) loaded_modules: Mutex<HashMap<u64, NativeLoadedModule>>,
}

pub(super) struct NativeLoadedModule {
    pub(super) path: String,
    pub(super) name: String,
    pub(super) base: u64,
    pub(super) size_of_image: u32,
    pub(super) exports: Vec<crate::pe::Export>,
}

pub(super) struct NativeThread {
    pub(super) join: Option<std::thread::JoinHandle<u32>>,
    pub(super) exit_code: Option<u32>,
    pub(super) suspension: Arc<(Mutex<u32>, Condvar)>,
}

pub(super) struct NativeSemaphore {
    pub(super) count: Mutex<i32>,
    pub(super) changed: Condvar,
    pub(super) maximum: i32,
}

pub(super) struct NativeJobObject {
    pub(super) limit_flags: u32,
    pub(super) members: std::collections::HashSet<u64>,
}

pub(super) struct NativeWaitRegistration {
    pub(super) callback: u64,
    pub(super) context: u64,
    pub(super) child: Arc<NativeChildProcess>,
    pub(super) cancelled: Arc<AtomicBool>,
    pub(super) execute_once: bool,
}

pub(super) struct NativeEvent {
    pub(super) signaled: Mutex<bool>,
    pub(super) ready: Condvar,
    pub(super) manual_reset: bool,
}

pub(super) struct NativeFileIoQueue {
    pub(super) state: Mutex<NativeFileIoQueueState>,
    pub(super) ready: Condvar,
}
pub(super) struct NativeFileIoQueueState {
    pub(super) jobs: std::collections::VecDeque<NativeFileIoJob>,
    pub(super) stop: bool,
}
pub(super) struct NativeFileIoJob {
    pub(super) process: Arc<NativeProcessContext>,
    pub(super) request: Arc<NativePendingIo>,
    pub(super) file: NativeFile,
    pub(super) overlapped: u64,
    pub(super) event: Option<Arc<NativeEvent>>,
    pub(super) offset: usize,
    pub(super) operation: NativeFileIoOperation,
}
pub(super) struct NativePendingIo {
    pub(super) handle: u64,
    pub(super) overlapped: u64,
    pub(super) cancelled: AtomicBool,
    pub(super) issuer: std::thread::ThreadId,
}
pub(super) enum NativeFileIoOperation {
    Read { output: u64, length: u32 },
    Write { data: Vec<u8> },
}

pub(super) struct NativeVirtualAllocation {
    pub(super) length: usize,
}
#[derive(Clone)]
pub(super) struct NativeFileMapping {
    pub(super) length: usize,
    pub(super) protection: u32,
    pub(super) path: Option<String>,
}
pub(super) struct NativeMappingView {
    pub(super) length: usize,
    pub(super) view_length: usize,
    pub(super) backing: Option<(String, usize)>,
    pub(super) writable: bool,
}
pub(super) struct NativeCompletionPort {
    pub(super) queue: Mutex<std::collections::VecDeque<NativeCompletion>>,
    pub(super) ready: Condvar,
    worker_sender: Mutex<Option<std::os::unix::net::UnixStream>>,
}
pub(super) struct NativeCompletion {
    pub(super) key: u64,
    pub(super) overlapped: u64,
    pub(super) bytes: u32,
    pub(super) status: u64,
}

impl NativeCompletionPort {
    pub(super) fn new() -> Self {
        Self {
            queue: Mutex::new(std::collections::VecDeque::new()),
            ready: Condvar::new(),
            worker_sender: Mutex::new(None),
        }
    }

    pub(super) fn create_worker_sender(self: &Arc<Self>) -> Result<std::os::fd::OwnedFd, String> {
        use std::os::fd::{FromRawFd, IntoRawFd};

        let (mut receiver, sender) = std::os::unix::net::UnixStream::pair()
            .map_err(|error| format!("cannot create completion-port worker channel: {error}"))?;
        let port = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("winrun-iocp-worker-forward".to_string())
            .spawn(move || {
                use std::io::Read;

                let mut packet = [0u8; 28];
                loop {
                    match receiver.read_exact(&mut packet) {
                        Ok(()) => {
                            let Some(port) = port.upgrade() else {
                                break;
                            };
                            if let Some(completion) = NativeCompletion::decode(&packet) {
                                port.post(completion);
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|error| format!("cannot start completion-port forwarder: {error}"))?;
        // SAFETY: sender owns its descriptor and ownership transfers to OwnedFd.
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(sender.into_raw_fd()) })
    }

    pub(super) fn attach_worker_sender(&self, fd: i32) -> Result<(), String> {
        use std::os::fd::FromRawFd;

        // SAFETY: fd is received from the parent with SCM_RIGHTS and ownership
        // transfers to the UnixDatagram stored on this worker-side proxy.
        let sender = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        *self
            .worker_sender
            .lock()
            .map_err(|_| "completion-port sender lock is poisoned".to_string())? = Some(sender);
        Ok(())
    }

    pub(super) fn post(&self, completion: NativeCompletion) -> bool {
        if let Ok(mut sender) = self.worker_sender.lock() {
            if let Some(sender) = sender.as_mut() {
                use std::io::Write;
                return sender.write_all(&completion.encode()).is_ok();
            }
        }
        let Ok(mut queue) = self.queue.lock() else {
            return false;
        };
        queue.push_back(completion);
        self.ready.notify_one();
        true
    }
}

impl NativeCompletion {
    fn encode(&self) -> [u8; 28] {
        let mut packet = [0; 28];
        packet[0..8].copy_from_slice(&self.key.to_le_bytes());
        packet[8..16].copy_from_slice(&self.overlapped.to_le_bytes());
        packet[16..20].copy_from_slice(&self.bytes.to_le_bytes());
        packet[20..28].copy_from_slice(&self.status.to_le_bytes());
        packet
    }

    fn decode(packet: &[u8; 28]) -> Option<Self> {
        Some(Self {
            key: u64::from_le_bytes(packet[0..8].try_into().ok()?),
            overlapped: u64::from_le_bytes(packet[8..16].try_into().ok()?),
            bytes: u32::from_le_bytes(packet[16..20].try_into().ok()?),
            status: u64::from_le_bytes(packet[20..28].try_into().ok()?),
        })
    }
}

pub(super) struct DynamicTlsSlots {
    pub(super) active: [bool; 64],
    pub(super) generation: [u64; 64],
    pub(super) reserved: [bool; 64],
    pub(super) reserved_static: bool,
}

// CreateProcessW will allocate these once PE mapping is attached to the
// registry; they are already consumed by the process-handle APIs.
#[allow(dead_code)]
pub(super) struct NativeChildProcess {
    pub(super) process_id: u32,
    pub(super) parent_process_id: u32,
    pub(super) host_pid: AtomicI32,
    pub(super) termination_code: Mutex<Option<u32>>,
    pub(super) state: Mutex<Option<u32>>,
    pub(super) exited: Condvar,
}

pub(super) struct NativeProcessTable {
    pub(super) next_handle: u64,
    pub(super) next_thread_handle: u64,
    pub(super) next_process_id: u32,
    pub(super) children: HashMap<u64, Arc<NativeChildProcess>>,
    pub(super) primary_threads: HashMap<u64, Arc<NativeChildProcess>>,
}

#[allow(dead_code)]
impl NativeProcessTable {
    pub(super) fn new() -> Self {
        Self {
            next_handle: 0x6000_0000,
            next_thread_handle: 0x6100_0000,
            next_process_id: 2,
            children: HashMap::new(),
            primary_threads: HashMap::new(),
        }
    }

    pub(super) fn allocate(
        &mut self,
        parent_process_id: u32,
    ) -> (u64, u64, Arc<NativeChildProcess>) {
        let handle = self.next_handle;
        self.next_handle += 1;
        let thread_handle = self.next_thread_handle;
        self.next_thread_handle += 1;
        let child = Arc::new(NativeChildProcess {
            process_id: self.next_process_id,
            parent_process_id,
            host_pid: AtomicI32::new(0),
            termination_code: Mutex::new(None),
            state: Mutex::new(None),
            exited: Condvar::new(),
        });
        self.next_process_id += 1;
        self.children.insert(handle, Arc::clone(&child));
        self.primary_threads
            .insert(thread_handle, Arc::clone(&child));
        (handle, thread_handle, child)
    }
}
