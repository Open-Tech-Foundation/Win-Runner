//! Per-thread and active-process context access for the Linux backend.

use super::*;

thread_local! {
    /// `TlsAlloc` values of a thread without a TEB (host threads in tests).
    pub(super) static THREAD_TLS_VALUES: std::cell::RefCell<Vec<(u64, u64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    pub(super) static THREAD_FLS_VALUES: std::cell::RefCell<Vec<(u64, u64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    pub(super) static THREAD_NATIVE_HANDLE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    pub(super) static THREAD_NATIVE_PROCESS: std::cell::RefCell<Option<Arc<NativeProcessContext>>> =
        const { std::cell::RefCell::new(None) };
    pub(super) static THREAD_LAST_ERROR: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    pub(super) static THREAD_TEB_BASE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
pub(super) static NATIVE_REGISTRY_HANDLE_NEXT: AtomicU64 = AtomicU64::new(0x5500_0000);

// Import trampolines have no guest-context argument. This is therefore a
// narrow dispatcher slot, while every mutable Windows-process datum lives
// in the context it points at. A future CreateProcessW child installs its
// own context in its guest host process.
pub(super) static NATIVE_PROCESS: Mutex<Option<Arc<NativeProcessContext>>> = Mutex::new(None);
#[cfg(test)]
pub(super) static NATIVE_GUEST_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(super) static TEST_PROCESS: LazyLock<Arc<NativeProcessContext>> =
    LazyLock::new(new_test_process);

#[cfg(test)]
pub(super) fn new_test_process() -> Arc<NativeProcessContext> {
    Arc::new(NativeProcessContext {
        image_base: 0x0001_4000_0000,
        image_size: 0x10000,
        module_path: r"C:\winrun\winrun.exe".to_string(),
        process_id: 1,
        process_handle: u64::MAX,
        parent_process_id: 0,
        command_line_w: vec![0],
        command_line_a: vec![0],
        environment: Mutex::new(Vec::new()),
        environment_block: Mutex::new(vec![0, 0]),
        crt_startup: Mutex::new(None),
        crt_exit_functions: Mutex::new(Vec::new()),
        crt_new_mode: AtomicI32::new(0),
        std_handles: [
            AtomicU64::new(STD_HANDLE_BASE),
            AtomicU64::new(STD_HANDLE_BASE + 1),
            AtomicU64::new(STD_HANDLE_BASE + 2),
        ],
        crt_fds: Mutex::new(HashMap::new()),
        crt_fd_next: AtomicI32::new(3),
        fs: Arc::new(Mutex::new(NativeFs {
            fs: WinFs::new(),
            handles: HashMap::new(),
            devices: HashMap::new(),
            file_access: HashMap::new(),
            file_shares: HashMap::new(),
            finds: HashMap::new(),
            file_completion_modes: HashMap::new(),
            delete_on_close: std::collections::HashSet::new(),
            file_locks: Vec::new(),
            next: 0x100,
        })),
        named_pipes: Mutex::new(NativeNamedPipeTable::new()),
        console_output_modes: [AtomicU32::new(1), AtomicU32::new(1)],
        error_mode: AtomicU32::new(0),
        wer_flags: AtomicU32::new(0),
        priority_boost_disabled: AtomicBool::new(false),
        pointer_cookie: random_pointer_cookie(),
        heap_allocations: Mutex::new(HashMap::new()),
        virtual_allocations: Mutex::new(HashMap::new()),
        image_page_protections: Mutex::new(HashMap::new()),
        file_mappings: Mutex::new(HashMap::new()),
        mapping_views: Mutex::new(HashMap::new()),
        mapping_next: AtomicU64::new(0x9800_0000),
        gs_base: AtomicU64::new(0),
        tls_template: Mutex::new(None),
        tls_blocks: Mutex::new(HashMap::new()),
        dynamic_tls: Mutex::new(DynamicTlsSlots::new(false)),
        threads: Mutex::new(HashMap::new()),
        thread_next: AtomicU64::new(0x8000_0000),
        semaphores: Mutex::new(HashMap::new()),
        semaphore_next: AtomicU64::new(0x6000_0000),
        events: Mutex::new(HashMap::new()),
        event_names: Mutex::new(HashMap::new()),
        event_next: AtomicU64::new(0x6100_0000),
        job_objects: Mutex::new(HashMap::new()),
        wait_registrations: Mutex::new(HashMap::new()),
        completion_ports: Mutex::new(HashMap::new()),
        socket_handles: Mutex::new(std::collections::HashSet::new()),
        socket_completion_ports: Mutex::new(HashMap::new()),
        socket_completion_modes: Mutex::new(HashMap::new()),
        completion_next: AtomicU64::new(0x9000_0000),
        io_wait: Mutex::new(()),
        io_ready: Condvar::new(),
        pending_file_io: AtomicU64::new(0),
        pending_requests: Mutex::new(HashMap::new()),
        file_io_queue: Mutex::new(None),
        duplicate_handles: Mutex::new(HashMap::new()),
        duplicate_next: AtomicU64::new(0xa000_0000),
        timer_next: AtomicU64::new(0x7000_0000),
        timers: Mutex::new(HashMap::new()),
        state_fd: AtomicU32::new(u32::MAX),
        fls: Mutex::new(FlsSlots::default()),
        unhandled_exception_filter: AtomicU64::new(0),
        vectored_exception_handlers: Mutex::new(Vec::new()),
        vectored_exception_handler_next: AtomicU64::new(0xe100_0000),
        vectored_continue_handlers: Mutex::new(Vec::new()),
        dynamic_function_tables: Mutex::new(Vec::new()),
        exit_status: AtomicU32::new(259),
        exited: AtomicBool::new(false),
        children: Mutex::new(NativeProcessTable::new()),
        loaded_modules: Mutex::new(HashMap::new()),
        module_next: AtomicU64::new(1),
    })
}

pub(super) fn process_ctx() -> Option<Arc<NativeProcessContext>> {
    if let Some(process) = THREAD_NATIVE_PROCESS.with(|active| active.borrow().clone()) {
        return Some(process);
    }
    #[cfg(test)]
    if !NATIVE_GUEST_ACTIVE.load(Ordering::Acquire) {
        return Some(Arc::clone(&TEST_PROCESS));
    }
    if let Some(process) = NATIVE_PROCESS.lock().ok()?.as_ref().cloned() {
        return Some(process);
    }
    #[cfg(test)]
    return None;
    #[cfg(not(test))]
    None
}

pub(super) fn fs_ctx() -> Option<Arc<Mutex<NativeFs>>> {
    process_ctx().map(|process| Arc::clone(&process.fs))
}

pub(super) fn random_pointer_cookie() -> u64 {
    let mut cookie = 0u64;
    if unsafe { getrandom((&mut cookie as *mut u64).cast(), 8, 0) } != 8 {
        cookie = 0x7f3a_5e91_c62d_b408;
    }
    cookie | 1
}
impl DynamicTlsSlots {
    pub(super) fn new(static_tls: bool) -> Self {
        let mut active = vec![false; TLS_INDEXES];
        active[0] = static_tls;
        Self {
            active,
            generation: vec![0; TLS_INDEXES],
            reserved: vec![false; TLS_INDEXES],
            reserved_static: static_tls,
        }
    }
}

#[cfg(test)]
pub(super) struct TestProcessGuard(Option<Arc<NativeProcessContext>>);
#[cfg(test)]
impl TestProcessGuard {
    pub(super) fn new() -> Self {
        Self(THREAD_NATIVE_PROCESS.with(|active| active.replace(Some(new_test_process()))))
    }
}
#[cfg(test)]
impl Drop for TestProcessGuard {
    fn drop(&mut self) {
        THREAD_NATIVE_PROCESS.with(|active| active.replace(self.0.take()));
    }
}
