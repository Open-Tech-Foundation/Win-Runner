//! Shared identity, lifetime, descriptions and CPU accounting for guest threads.
//! APC handles retain the thread object even when its creation handle is closed.
use super::*;

pub(super) const THREAD_ALL_ACCESS: u32 = 0x1f_ffff;
const QUERY: u32 = 0x800;
const SET: u32 = 0x400;
#[derive(Default)]
pub(super) struct NativeThreadStatus {
    pub(super) exit_code: Option<u32>,
    exit: u64,
    kernel: u64,
    user: u64,
    description: Vec<u16>,
}
pub(super) struct NativeThreadInfo {
    pub(super) id: AtomicU32,
    pub(super) host_tid: AtomicI32,
    pub(super) creation: AtomicU64,
    pub(super) suspension: Arc<(Mutex<u32>, Condvar)>,
    pub(super) status: Mutex<NativeThreadStatus>,
}
impl Default for NativeThreadInfo {
    fn default() -> Self {
        Self {
            id: AtomicU32::new(0),
            host_tid: AtomicI32::new(0),
            creation: AtomicU64::new(process_filetime_now()),
            suspension: Arc::new((Mutex::new(0), Condvar::new())),
            status: Mutex::new(NativeThreadStatus::default()),
        }
    }
}
impl NativeThreadInfo {
    pub(super) fn finish(&self, code: u32) {
        if let Ok(mut status) = self.status.lock() {
            if status.exit_code.is_some() {
                return;
            }
            let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
            unsafe {
                libc::getrusage(libc::RUSAGE_THREAD, &mut usage);
            }
            let ticks = |t: libc::timeval| t.tv_sec as u64 * 10_000_000 + t.tv_usec as u64 * 10;
            status.kernel = ticks(usage.ru_stime);
            status.user = ticks(usage.ru_utime);
            status.exit = process_filetime_now();
            status.exit_code = Some(code);
        }
    }
}
pub(super) fn register_thread_object(process: &NativeProcessContext, queue: &Arc<NativeApcQueue>) {
    if let Ok(mut threads) = process.thread_objects.lock() {
        threads.retain(|_, object| object.strong_count() != 0);
        threads.insert(
            queue.thread.id.load(Ordering::Acquire),
            Arc::downgrade(queue),
        );
    }
}
pub(super) fn thread_access_mask(mut access: u32) -> u32 {
    // Map the thread object's generic rights, then add the implied limited rights.
    if access & (0x1000_0000 | 0x0200_0000) != 0 {
        access |= THREAD_ALL_ACCESS;
    }
    if access & 0x8000_0000 != 0 {
        access |= 0x20000 | 0x8 | 0x40;
    }
    if access & 0x4000_0000 != 0 {
        access |= 0x20000 | 0x1 | 0x2 | 0x10 | 0x20;
    }
    if access & 0x2000_0000 != 0 {
        access |= 0x20000 | 0x100000;
    }
    access &= !(0xf000_0000 | 0x0200_0000);
    if access & 0x40 != 0 {
        access |= QUERY;
    }
    if access & 0x20 != 0 {
        access |= SET;
    }
    access
}
pub(super) fn lookup_thread_handle(handle: u64) -> Option<NativeApcHandle> {
    if handle == u64::MAX - 1 {
        return current_apc_queue().map(|queue| NativeApcHandle {
            queue,
            access: THREAD_ALL_ACCESS,
            flags: 0,
        });
    }
    let process = process_ctx()?;
    let result = process.apc_handles.lock().ok()?.get(&handle).cloned();
    result
}
pub(super) fn require_thread_handle(handle: u64, access: u32) -> Result<NativeApcHandle, u32> {
    let handle = lookup_thread_handle(handle).ok_or(6u32)?;
    if thread_access_mask(handle.access) & access != access {
        return Err(5);
    }
    Ok(handle)
}
pub(super) extern "win64" fn native_open_thread(access: u32, inherit: i32, id: u32) -> u64 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    // Register the main thread too, even if its first API is OpenThread.
    let _ = current_apc_queue();
    let queue = process
        .thread_objects
        .lock()
        .ok()
        .and_then(|threads| threads.get(&id).and_then(Weak::upgrade));
    let Some(queue) = queue else {
        native_set_last_error(87);
        return 0;
    };
    let access = thread_access_mask(access);
    if access & !THREAD_ALL_ACCESS != 0 {
        native_set_last_error(5);
        return 0;
    }
    let handle = process.duplicate_next.fetch_add(1, Ordering::AcqRel);
    if process.apc_handles.lock().is_ok_and(|mut handles| {
        handles.insert(
            handle,
            NativeApcHandle {
                queue,
                access,
                flags: u32::from(inherit != 0),
            },
        );
        true
    }) {
        handle
    } else {
        native_set_last_error(8);
        0
    }
}
fn query_thread(handle: u64) -> Option<NativeApcHandle> {
    match require_thread_handle(handle, QUERY) {
        Ok(handle) => Some(handle),
        Err(error) => {
            native_set_last_error(error);
            None
        }
    }
}
pub(super) extern "win64" fn native_get_thread_id(handle: u64) -> u32 {
    query_thread(handle)
        .map(|h| h.queue.thread.id.load(Ordering::Acquire))
        .unwrap_or(0)
}
pub(super) extern "win64" fn native_get_process_id_of_thread(handle: u64) -> u32 {
    if query_thread(handle).is_none() {
        return 0;
    }
    native_get_current_process_id()
}
pub(super) extern "win64" fn native_get_exit_code_thread(handle: u64, code: *mut u32) -> i32 {
    if code.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(handle) = query_thread(handle) else {
        return 0;
    };
    let Ok(status) = handle.queue.thread.status.lock() else {
        native_set_last_error(6);
        return 0;
    };
    unsafe {
        code.write_unaligned(status.exit_code.unwrap_or(259));
    }
    1
}
fn live_thread_cpu(tid: i32) -> Option<(u64, u64)> {
    if tid <= 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
    let (_, fields) = stat.rsplit_once(") ")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    let user: u64 = fields.get(11)?.parse().ok()?;
    let kernel: u64 = fields.get(12)?.parse().ok()?;
    let frequency = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if frequency <= 0 {
        return None;
    }
    Some((
        kernel * 10_000_000 / frequency as u64,
        user * 10_000_000 / frequency as u64,
    ))
}
pub(super) extern "win64" fn native_get_thread_times(
    handle: u64,
    creation: *mut u64,
    exit: *mut u64,
    kernel: *mut u64,
    user: *mut u64,
) -> i32 {
    if creation.is_null() || exit.is_null() || kernel.is_null() || user.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(handle) = query_thread(handle) else {
        return 0;
    };
    let info = &handle.queue.thread;
    let Ok(status) = info.status.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let (k, u) = if status.exit_code.is_some() {
        (status.kernel, status.user)
    } else {
        live_thread_cpu(info.host_tid.load(Ordering::Acquire)).unwrap_or((0, 0))
    };
    unsafe {
        creation.write_unaligned(info.creation.load(Ordering::Acquire));
        exit.write_unaligned(status.exit);
        kernel.write_unaligned(k);
        user.write_unaligned(u);
    }
    1
}
fn thread_hresult(error: u32) -> i32 {
    (0x8007_0000 | error) as i32
}
pub(super) extern "win64" fn native_set_thread_description(handle: u64, name: *const u16) -> i32 {
    if name.is_null() {
        return thread_hresult(87);
    }
    let handle = match require_thread_handle(handle, SET) {
        Ok(h) => h,
        Err(e) => return thread_hresult(e),
    };
    // Preserve UTF-16 code units, including unpaired surrogates.
    let mut description = Vec::new();
    for index in 0..32768 {
        let unit = unsafe { name.add(index).read_unaligned() };
        if unit == 0 {
            let Ok(mut status) = handle.queue.thread.status.lock() else {
                return thread_hresult(6);
            };
            status.description = description;
            return 0;
        }
        description.push(unit);
    }
    thread_hresult(87)
}
pub(super) extern "win64" fn native_get_thread_description(
    handle: u64,
    output: *mut *mut u16,
) -> i32 {
    if output.is_null() {
        return thread_hresult(87);
    }
    unsafe {
        output.write_unaligned(ptr::null_mut());
    }
    let handle = match require_thread_handle(handle, QUERY) {
        Ok(h) => h,
        Err(e) => return thread_hresult(e),
    };
    let Ok(status) = handle.queue.thread.status.lock() else {
        return thread_hresult(6);
    };
    let data = native_crt_malloc((status.description.len() + 1) * 2) as *mut u16;
    if data.is_null() {
        return thread_hresult(8);
    }
    unsafe {
        ptr::copy_nonoverlapping(status.description.as_ptr(), data, status.description.len());
        data.add(status.description.len()).write(0);
        output.write_unaligned(data);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    fn duplicate(handle: u64, access: u32) -> u64 {
        let mut output = 0;
        assert_eq!(
            native_duplicate_handle(u64::MAX, handle, u64::MAX, &mut output, access, 0, 0),
            1
        );
        output
    }
    fn times(handle: u64) -> [u64; 4] {
        let mut values = [0; 4];
        assert_eq!(
            native_get_thread_times(
                handle,
                &mut values[0],
                &mut values[1],
                &mut values[2],
                &mut values[3]
            ),
            1
        );
        values
    }
    fn description(handle: u64) -> Vec<u16> {
        let mut output = ptr::null_mut();
        assert_eq!(native_get_thread_description(handle, &mut output), 0);
        assert!(!output.is_null());
        let mut result = Vec::new();
        unsafe {
            let mut next = output;
            while next.read() != 0 {
                result.push(next.read());
                next = next.add(1);
            }
        }
        super::super::registry::native_local_free(output as u64);
        result
    }
    #[test]
    fn query_exports_are_bound_for_kernel32_and_api_sets() {
        for name in [
            "OpenThread",
            "GetThreadId",
            "GetProcessIdOfThread",
            "GetExitCodeThread",
            "GetThreadTimes",
            "GetThreadDescription",
            "SetThreadDescription",
        ] {
            assert!(baseline_trampoline(name).is_some(), "{name}");
            assert!(supports_import("kernel32.dll", name), "{name}");
            assert!(
                supports_import("api-ms-win-core-processthreads-l1-1-3.dll", name),
                "{name}"
            );
        }
    }
    #[test]
    fn pseudo_opened_and_duplicated_handles_share_identity_and_description() {
        let _guard = TestProcessGuard::new();
        let current = native_get_current_thread();
        let id = native_get_current_thread_id();
        assert_eq!(native_get_thread_id(current), id);
        assert_eq!(
            native_get_process_id_of_thread(current),
            native_get_current_process_id()
        );
        let opened = native_open_thread(QUERY | SET, 0, id);
        assert_ne!(opened, 0);
        let copy = duplicate(opened, QUERY | SET);
        let text = [b'W' as u16, 0x4e2d, 0xd83d, 0xde00, 0xd800, 0];
        assert_eq!(native_set_thread_description(copy, text.as_ptr()), 0);
        assert_eq!(description(opened), text[..5]);
        assert_eq!(description(current), text[..5]);
        assert_eq!(native_close_handle(opened), 1);
        assert_eq!(native_get_thread_id(copy), id);
        assert_eq!(native_set_thread_description(copy, [0].as_ptr()), 0);
        assert!(description(current).is_empty());
        native_close_handle(copy);
    }
    #[test]
    fn descriptions_return_independent_local_free_allocations() {
        let _guard = TestProcessGuard::new();
        let current = native_get_current_thread();
        let mut first = ptr::null_mut();
        let mut second = ptr::null_mut();
        assert_eq!(native_get_thread_description(current, &mut first), 0);
        assert_eq!(native_get_thread_description(current, &mut second), 0);
        assert_ne!(first, second);
        unsafe {
            assert_eq!(first.read(), 0);
            assert_eq!(second.read(), 0);
        }
        assert_eq!(native_set_thread_description(current, [65, 0].as_ptr()), 0);
        unsafe {
            assert_eq!(first.read(), 0);
        }
        super::super::registry::native_local_free(first as u64);
        super::super::registry::native_local_free(second as u64);
    }
    #[test]
    fn handles_enforce_query_set_and_synchronize_rights() {
        let _guard = TestProcessGuard::new();
        let current = native_get_current_thread();
        let restricted = duplicate(current, 0);
        assert_eq!(native_get_thread_id(restricted), 0);
        assert_eq!(native_get_last_error(), 5);
        assert_eq!(native_get_process_id_of_thread(restricted), 0);
        assert_eq!(native_get_last_error(), 5);
        let mut code = 42;
        assert_eq!(native_get_exit_code_thread(restricted, &mut code), 0);
        assert_eq!(code, 42);
        let mut values = [42; 4];
        assert_eq!(
            native_get_thread_times(
                restricted,
                &mut values[0],
                &mut values[1],
                &mut values[2],
                &mut values[3]
            ),
            0
        );
        assert_eq!(values, [42; 4]);
        assert_eq!(native_wait_for_single_object(restricted, 0), u32::MAX);
        assert_eq!(native_get_last_error(), 5);
        assert_eq!(
            native_set_thread_description(restricted, [65, 0].as_ptr()),
            thread_hresult(5)
        );
        let mut output = 1usize as *mut u16;
        assert_eq!(
            native_get_thread_description(restricted, &mut output),
            thread_hresult(5)
        );
        assert!(output.is_null());
        let query = duplicate(current, 0x40);
        assert_ne!(native_get_thread_id(query), 0);
        assert_eq!(
            native_set_thread_description(query, [0].as_ptr()),
            thread_hresult(5)
        );
        let set = duplicate(current, 0x20);
        assert_eq!(native_set_thread_description(set, [65, 0].as_ptr()), 0);
        assert_eq!(native_get_thread_id(set), 0);
        for handle in [restricted, query, set] {
            native_close_handle(handle);
        }
    }
    extern "win64" fn return_code(code: u64) -> u32 {
        code as u32
    }
    #[test]
    fn opened_handles_survive_original_close_and_keep_terminated_thread_state() {
        let _guard = TestProcessGuard::new();
        let mut id = 0;
        let original = native_create_thread(0, 0, return_code as *const () as u64, 259, 4, &mut id);
        assert_ne!(original, 0);
        let opened = native_open_thread(QUERY | 0x100000 | 2, 0, id);
        let copy = duplicate(opened, QUERY | 0x100000);
        assert_eq!(native_get_thread_id(opened), id);
        let mut code = 0;
        assert_eq!(native_get_exit_code_thread(opened, &mut code), 1);
        assert_eq!(code, 259);
        let before = times(opened);
        assert_eq!(native_close_handle(original), 1);
        assert_eq!(native_get_thread_id(original), 0);
        assert_eq!(native_get_last_error(), 6);
        assert_eq!(native_resume_thread(opened), 1);
        assert_eq!(native_wait_for_single_object(copy, 3000), 0);
        assert_eq!(native_get_exit_code_thread(copy, &mut code), 1);
        assert_eq!(code, 259); // A terminated thread may itself return STILL_ACTIVE.
        let after = times(copy);
        assert_eq!(before[0], after[0]);
        assert!(after[1] >= after[0]);
        assert_eq!(after, times(copy));
        let retained = native_open_thread(QUERY, 0, id);
        assert_ne!(retained, 0);
        native_close_handle(opened);
        native_close_handle(copy);
        assert_eq!(native_get_thread_id(retained), id);
        native_close_handle(retained);
    }
    #[test]
    fn duplicate_of_main_thread_keeps_owner_when_used_on_another_host_thread() {
        let _guard = TestProcessGuard::new();
        let id = native_get_current_thread_id();
        let owner = duplicate(native_get_current_thread(), QUERY | SET);
        let process = process_ctx().unwrap();
        std::thread::spawn(move || {
            THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(process)));
            THREAD_NATIVE_HANDLE.set(0x80000042);
            assert_ne!(native_get_thread_id(native_get_current_thread()), id);
            assert_eq!(native_get_thread_id(owner), id);
            let copy = duplicate(owner, QUERY | SET);
            assert_eq!(native_get_thread_id(copy), id);
            assert_eq!(native_set_thread_description(copy, [66, 0].as_ptr()), 0);
            native_close_handle(copy);
            native_close_handle(owner);
        })
        .join()
        .unwrap();
        assert_eq!(description(native_get_current_thread()), vec![66]);
    }
    #[test]
    fn invalid_handles_ids_and_null_outputs_fail_without_modifying_results() {
        let _guard = TestProcessGuard::new();
        assert_eq!(native_open_thread(QUERY, 0, 0), 0);
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(
            native_open_thread(0x1000000, 0, native_get_current_thread_id()),
            0
        );
        assert_eq!(native_get_last_error(), 5);
        assert_eq!(native_get_thread_id(0xdead), 0);
        assert_eq!(native_get_last_error(), 6);
        assert_eq!(
            native_get_exit_code_thread(native_get_current_thread(), ptr::null_mut()),
            0
        );
        assert_eq!(native_get_last_error(), 87);
        let mut value = 42;
        assert_eq!(
            native_get_thread_times(
                native_get_current_thread(),
                ptr::null_mut(),
                &mut value,
                &mut value,
                &mut value
            ),
            0
        );
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(value, 42);
        assert!(native_get_thread_description(native_get_current_thread(), ptr::null_mut()) < 0);
        assert!(native_set_thread_description(native_get_current_thread(), ptr::null()) < 0);
        let handle = native_open_thread(0, 0, native_get_current_thread_id());
        assert_ne!(handle, 0);
        assert_eq!(native_close_handle(handle), 1);
        assert_eq!(native_close_handle(handle), 0);
        assert_eq!(native_get_last_error(), 6);
    }
    #[test]
    fn opened_terminate_only_handle_denies_query_and_wait_access() {
        let _guard = TestProcessGuard::new();
        let handle = native_open_thread(1, 0, native_get_current_thread_id());
        assert_ne!(handle, 0);
        assert_eq!(lookup_thread_handle(handle).unwrap().access, 1);
        assert_eq!(native_get_thread_id(handle), 0);
        assert_eq!(native_get_last_error(), 5);
        assert_eq!(native_get_process_id_of_thread(handle), 0);
        assert_eq!(native_get_last_error(), 5);
        let mut code = 42;
        assert_eq!(native_get_exit_code_thread(handle, &mut code), 0);
        assert_eq!(native_get_last_error(), 5);
        assert_eq!(code, 42);
        let mut values = [42; 4];
        assert_eq!(
            native_get_thread_times(
                handle,
                &mut values[0],
                &mut values[1],
                &mut values[2],
                &mut values[3]
            ),
            0
        );
        assert_eq!(native_get_last_error(), 5);
        assert_eq!(values, [42; 4]);
        assert_eq!(native_wait_for_single_object(handle, 0), u32::MAX);
        assert_eq!(native_get_last_error(), 5);
        let mut name = ptr::null_mut();
        assert!(native_get_thread_description(handle, &mut name) < 0);
        assert!(native_set_thread_description(handle, [65, 0].as_ptr()) < 0);
        assert_eq!(native_close_handle(handle), 1);
    }
    #[test]
    fn opened_thread_handle_flags_and_duplicate_flags_are_independent() {
        let _guard = TestProcessGuard::new();
        let handle = native_open_thread(QUERY, 1, native_get_current_thread_id());
        assert_eq!(lookup_thread_handle(handle).unwrap().flags, 1);
        assert_eq!(native_set_handle_information(handle, 2, 2), 1);
        assert_eq!(native_close_handle(handle), 0);
        assert_eq!(native_get_last_error(), 5);
        let copy = duplicate(handle, QUERY);
        assert_eq!(lookup_thread_handle(copy).unwrap().flags, 0);
        assert_eq!(native_close_handle(copy), 1);
        assert_eq!(native_set_handle_information(handle, 3, 0), 1);
        assert_eq!(lookup_thread_handle(handle).unwrap().flags, 0);
        assert_eq!(native_close_handle(handle), 1);
    }
    #[test]
    fn published_termination_rejects_apcs_before_queue_cleanup() {
        let queue = NativeApcQueue::default();
        queue.thread.finish(42);
        assert!(!queue.post(1, [0; 3]));
    }
    #[test]
    fn thread_times_capture_cpu_usage_and_freeze_at_exit() {
        let info = NativeThreadInfo::default();
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(20) {
            std::hint::black_box((1u64..100).sum::<u64>());
        }
        info.finish(42);
        let status = info.status.lock().unwrap();
        assert_eq!(status.exit_code, Some(42));
        assert!(status.user + status.kernel > 0);
        assert!(status.exit >= info.creation.load(Ordering::Acquire));
        let exit = status.exit;
        drop(status);
        info.finish(99);
        let status = info.status.lock().unwrap();
        assert_eq!(status.exit_code, Some(42));
        assert_eq!(status.exit, exit);
    }
}
