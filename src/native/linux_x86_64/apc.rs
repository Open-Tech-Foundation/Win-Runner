//! Per-thread user APCs and file I/O completion routines.
use super::*;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub(super) const WAIT_IO_COMPLETION: u32 = 192;
#[derive(Default)]
struct NativeApcState {
    closed: bool,
    callbacks: VecDeque<(u64, [u64; 3])>,
}
#[derive(Default)]
pub(super) struct NativeApcQueue {
    state: Mutex<NativeApcState>,
    ready: Condvar,
}
impl NativeApcQueue {
    pub(super) fn post(&self, function: u64, arguments: [u64; 3]) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.closed {
            return false;
        }
        state.callbacks.push_back((function, arguments));
        self.ready.notify_all();
        true
    }
    pub(super) fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.callbacks.clear();
            self.ready.notify_all();
        }
    }
}
#[derive(Clone)]
pub(super) struct NativeApcHandle {
    pub(super) queue: Arc<NativeApcQueue>,
    pub(super) access: u32,
}
pub(super) struct NativeThreadApcGuard {
    pub(super) queue: Arc<NativeApcQueue>,
    pub(super) process: Arc<NativeProcessContext>,
}
impl Drop for NativeThreadApcGuard {
    fn drop(&mut self) {
        self.queue.close();
        if let Ok(mut queues) = self.process.apc_queues.lock() {
            queues.remove(&std::thread::current().id());
        }
    }
}
#[derive(Clone)]
pub(super) struct NativeIoCompletion {
    pub(super) queue: Arc<NativeApcQueue>,
    pub(super) function: u64,
}
impl NativeIoCompletion {
    pub(super) fn complete(&self, overlapped: u64, bytes: u32, status: u64) {
        self.queue.post(
            self.function,
            [
                if status == 0 {
                    0
                } else {
                    native_file_error(status) as u64
                },
                bytes as u64,
                overlapped,
            ],
        );
    }
}
pub(super) fn current_apc_queue() -> Option<Arc<NativeApcQueue>> {
    let process = process_ctx()?;
    let mut queues = process.apc_queues.lock().ok()?;
    Some(
        queues
            .entry(std::thread::current().id())
            .or_default()
            .clone(),
    )
}
pub(super) fn dispatch_apcs() -> bool {
    let Some(queue) = current_apc_queue() else {
        return false;
    };
    let mut called = false;
    loop {
        let callback = queue
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.callbacks.pop_front());
        let Some((function, arguments)) = callback else {
            break;
        };
        called = true;
        // Guest callbacks run with this thread's TEB and exception recovery gate.
        if let Err(code) =
            unsafe { super::exceptions::invoke_guest_with_arguments(function, arguments) }
        {
            native_exit_process(code);
        }
    }
    called
}
pub(super) fn apc_pause() {
    let Some(queue) = current_apc_queue() else {
        std::thread::sleep(Duration::from_millis(1));
        return;
    };
    if let Ok(state) = queue.state.lock() {
        if state.callbacks.is_empty() {
            let _ = queue.ready.wait_timeout(state, Duration::from_millis(1));
        }
    };
}
pub(super) fn wait_deadline(timeout: u32) -> Option<Instant> {
    (timeout != u32::MAX).then(|| Instant::now() + Duration::from_millis(timeout as u64))
}
pub(super) fn wait_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}
pub(super) extern "win64" fn native_queue_user_apc(function: u64, thread: u64, data: u64) -> u32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    if function == 0 {
        native_set_last_error(87);
        return 0;
    }
    let queue = if thread == u64::MAX - 1 {
        current_apc_queue()
    } else {
        let handle = process
            .apc_handles
            .lock()
            .ok()
            .and_then(|handles| handles.get(&thread).cloned());
        if let Some(handle) = handle {
            if handle.access & (0x10 | 0x1000_0000 | 0x4000_0000) == 0 {
                native_set_last_error(5);
                return 0;
            }
            Some(handle.queue)
        } else {
            let thread = process
                .duplicate_handles
                .lock()
                .ok()
                .and_then(|handles| handles.get(&thread).copied())
                .unwrap_or(thread);
            process
                .threads
                .lock()
                .ok()
                .and_then(|threads| threads.get(&thread).map(|thread| thread.apc.clone()))
        }
    };
    let Some(queue) = queue else {
        native_set_last_error(6);
        return 0;
    };
    if queue.post(function, [data, 0, 0]) {
        1
    } else {
        native_set_last_error(31);
        0
    }
}

pub(super) extern "win64" fn native_read_file_ex(
    handle: u64,
    buffer: *mut u8,
    length: u32,
    overlapped: u64,
    callback: u64,
) -> i32 {
    submit_io_callback(handle, buffer as u64, length, overlapped, callback, false)
}
pub(super) extern "win64" fn native_write_file_ex(
    handle: u64,
    buffer: *const u8,
    length: u32,
    overlapped: u64,
    callback: u64,
) -> i32 {
    submit_io_callback(handle, buffer as u64, length, overlapped, callback, true)
}
fn submit_io_callback(
    handle: u64,
    buffer: u64,
    length: u32,
    overlapped: u64,
    callback: u64,
    write: bool,
) -> i32 {
    let result = (|| {
        if overlapped == 0
            || overlapped & 7 != 0
            || callback == 0
            || (buffer == 0 && length != 0)
            || length > 16 * 1024 * 1024
        {
            return Err(87);
        }
        let process = process_ctx().ok_or(6u32)?;
        let completion = NativeIoCompletion {
            queue: current_apc_queue().ok_or(6u32)?,
            function: callback,
        };
        let pipe = process
            .named_pipes
            .lock()
            .map_err(|_| 6u32)?
            .handles
            .get(&handle)
            .cloned();
        if let Some(pipe) = pipe {
            if !pipe.overlapped || pipe.completion.is_some() {
                return Err(87);
            }
            let access = if pipe.endpoint.server {
                if write {
                    2
                } else {
                    1
                }
            } else if write {
                0x4000_0000
            } else {
                0x8000_0000
            };
            if pipe.access & access == 0 {
                return Err(5);
            }
            let data = write.then(|| {
                if length == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(buffer as *const u8, length as usize).to_vec()
                    }
                }
            });
            return native_submit_pipe_io(
                &process,
                handle,
                pipe,
                overlapped,
                None,
                buffer as usize,
                data,
                length as usize,
                Some(completion),
            );
        }
        let fs = process.fs.lock().map_err(|_| 6u32)?;
        let file = fs.handles.get(&handle).cloned().ok_or(6u32)?;
        if !file.overlapped || file.completion.is_some() {
            return Err(87);
        }
        let access = fs.file_access.get(&handle).copied().unwrap_or(0);
        if access & if write { 0x4000_0000 } else { 0x8000_0000 } == 0 {
            return Err(5);
        }
        let offset = native_overlapped_offset(overlapped).ok_or(87u32)?;
        let lock_offset = if write && offset == usize::MAX {
            fs.fs.file_len(&file.path).map_err(|_| 1u32)?
        } else {
            offset as u64
        };
        if !native_file_lock_allows(&fs, handle, &file.path, lock_offset, length as u64, write) {
            return Err(33);
        }
        drop(fs);
        let operation = if write {
            NativeFileIoOperation::Write {
                data: if length == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(buffer as *const u8, length as usize).to_vec()
                    }
                },
            }
        } else {
            NativeFileIoOperation::Read {
                output: buffer,
                length,
            }
        };
        native_submit_file_io_callback(
            &process, handle, file, overlapped, offset, operation, completion,
        )
    })();
    match result {
        Ok(()) => {
            native_set_last_error(0);
            1
        }
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern "win64" fn record(data: u64) {
        let value = unsafe { &*(data as *const AtomicU64) };
        value.fetch_add(1, Ordering::SeqCst);
    }
    #[test]
    fn callbacks_wait_for_alertable_dispatch_and_are_process_local() {
        let _guard = TestProcessGuard::new();
        let count = AtomicU64::new(0);
        let data = &count as *const _ as u64;
        assert_eq!(
            native_queue_user_apc(
                record as *const () as u64,
                native_get_current_thread(),
                data
            ),
            1
        );
        assert_eq!(
            native_queue_user_apc(
                record as *const () as u64,
                native_get_current_thread(),
                data
            ),
            1
        );
        assert_eq!(native_sleep_ex(0, 0), 0);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        let previous = THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(new_test_process())));
        assert_eq!(native_sleep_ex(0, 1), 0);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(previous));
        assert_eq!(native_sleep_ex(0, 1), WAIT_IO_COMPLETION);
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(native_sleep_ex(0, 1), 0);
        assert_eq!(
            native_queue_user_apc(record as *const () as u64, 0xdead, data),
            0
        );
        assert_eq!(native_get_last_error(), 6);
    }
    #[test]
    fn alertable_wait_wakes_when_another_thread_posts_a_callback() {
        let _guard = TestProcessGuard::new();
        let queue = current_apc_queue().unwrap();
        let count = AtomicU64::new(0);
        let data = &count as *const _ as u64;
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            assert!(queue.post(record as *const () as u64, [data, 0, 0]));
        });
        assert_eq!(native_sleep_ex(u32::MAX, 1), WAIT_IO_COMPLETION);
        sender.join().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let queue = current_apc_queue().unwrap();
        queue.close();
        assert!(!queue.post(record as *const () as u64, [data, 0, 0]));
    }
    #[repr(C)]
    struct CompletionRecord {
        calls: u32,
        error: u32,
        bytes: u32,
    }
    extern "win64" fn complete(error: u32, bytes: u32, overlapped: u64) {
        let context = unsafe { ((overlapped + 24) as *const u64).read() };
        let record = unsafe { &mut *(context as *mut CompletionRecord) };
        record.calls += 1;
        record.error = error;
        record.bytes = bytes;
    }
    fn file() -> u64 {
        let path: Vec<u16> = r"C:\apc.txt".encode_utf16().chain([0]).collect();
        native_create_file_w(path.as_ptr(), 0xc0000000, 7, 0, 2, 0x40000000, 0)
    }
    #[test]
    fn file_completion_ignores_event_and_reports_eof_without_inline_callback() {
        let _guard = TestProcessGuard::new();
        let file = file();
        assert_ne!(file, u64::MAX);
        let mut record = CompletionRecord {
            calls: 0,
            error: 0,
            bytes: 0,
        };
        let mut ov = [0u64; 4];
        ov[3] = &mut record as *mut _ as u64; // hEvent is caller-owned context.
        assert_eq!(
            native_write_file_ex(
                file,
                b"test".as_ptr(),
                4,
                ov.as_ptr() as u64,
                complete as *const () as u64
            ),
            1
        );
        native_wait_file_io(&process_ctx().unwrap());
        assert_eq!(record.calls, 0);
        assert_eq!(native_sleep_ex(0, 1), WAIT_IO_COMPLETION);
        assert_eq!((record.calls, record.error, record.bytes), (1, 0, 4));
        let mut buffer = [0u8; 4];
        ov[2] = 4;
        assert_eq!(
            native_read_file_ex(
                file,
                buffer.as_mut_ptr(),
                4,
                ov.as_ptr() as u64,
                complete as *const () as u64
            ),
            1
        );
        native_wait_file_io(&process_ctx().unwrap());
        assert_eq!(native_sleep_ex(0, 1), WAIT_IO_COMPLETION);
        assert_eq!((record.calls, record.error, record.bytes), (2, 38, 0));
        assert_eq!(
            native_write_file_ex(
                file,
                ptr::null(),
                0,
                ov.as_ptr() as u64,
                complete as *const () as u64
            ),
            1
        );
        native_wait_file_io(&process_ctx().unwrap());
        assert_eq!(native_sleep_ex(0, 1), WAIT_IO_COMPLETION);
        assert_eq!((record.calls, record.error, record.bytes), (3, 0, 0));
        ov[2] = usize::MAX as u64;
        assert_eq!(
            native_write_file_ex(
                file,
                b"!".as_ptr(),
                1,
                ov.as_ptr() as u64,
                complete as *const () as u64
            ),
            1
        );
        native_wait_file_io(&process_ctx().unwrap());
        assert_eq!(native_sleep_ex(0, 1), WAIT_IO_COMPLETION);
        assert_eq!((record.calls, record.error, record.bytes), (4, 0, 1));
        assert_eq!(
            process_ctx()
                .unwrap()
                .fs
                .lock()
                .unwrap()
                .fs
                .read_file(r"C:\apc.txt")
                .unwrap(),
            b"test!"
        );
        assert_eq!(native_close_handle(file), 1);
    }
    #[test]
    fn completion_port_files_and_invalid_io_are_rejected() {
        let _guard = TestProcessGuard::new();
        let file = file();
        let mut ov = [0u64; 4];
        assert_eq!(
            native_read_file_ex(
                file,
                ptr::null_mut(),
                1,
                ov.as_ptr() as u64,
                complete as *const () as u64
            ),
            0
        );
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(
            native_read_file_ex(
                0xdead,
                ptr::null_mut(),
                0,
                ov.as_ptr() as u64,
                complete as *const () as u64
            ),
            0
        );
        assert_eq!(native_get_last_error(), 6);
        let port = native_create_io_completion_port(file, 0, 0, 0);
        assert_ne!(port, 0);
        assert_eq!(
            native_write_file_ex(
                file,
                ptr::null(),
                0,
                ov.as_ptr() as u64,
                complete as *const () as u64
            ),
            0
        );
        assert_eq!(native_get_last_error(), 87);
        native_close_handle(file);
        native_close_handle(port);
        ov[0] = STATUS_PENDING;
        let mut bytes = 0;
        assert_eq!(
            native_get_overlapped_result_ex(0xdead, ov.as_ptr() as u64, &mut bytes, 0, 0),
            0
        );
        assert_eq!(native_get_last_error(), 6);
    }
    #[test]
    fn duplicate_pseudo_thread_handle_keeps_the_original_thread_queue() {
        let _guard = TestProcessGuard::new();
        let process = process_ctx().unwrap();
        let mut duplicate = 0;
        assert_eq!(
            native_duplicate_handle(
                u64::MAX,
                native_get_current_thread(),
                u64::MAX,
                &mut duplicate,
                0,
                0,
                2
            ),
            1
        );
        let count = AtomicU64::new(0);
        let data = &count as *const _ as u64;
        let mut restricted = 0;
        assert_eq!(
            native_duplicate_handle(
                u64::MAX,
                native_get_current_thread(),
                u64::MAX,
                &mut restricted,
                0,
                0,
                0
            ),
            1
        );
        assert_eq!(
            native_queue_user_apc(record as *const () as u64, restricted, data),
            0
        );
        assert_eq!(native_get_last_error(), 5);
        native_close_handle(restricted);
        let worker = std::thread::spawn(move || {
            THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(process)));
            assert_eq!(
                native_queue_user_apc(record as *const () as u64, duplicate, data),
                1
            );
            let mut copied = 0;
            assert_eq!(
                native_duplicate_handle(u64::MAX, duplicate, u64::MAX, &mut copied, 0, 0, 2),
                1
            );
            assert_eq!(
                native_queue_user_apc(record as *const () as u64, copied, data),
                1
            );
            assert_eq!(native_sleep_ex(0, 1), 0);
            native_close_handle(copied);
        });
        worker.join().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(native_sleep_ex(0, 1), WAIT_IO_COMPLETION);
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(native_close_handle(duplicate), 1);
        assert_eq!(
            native_queue_user_apc(record as *const () as u64, duplicate, data),
            0
        );
        assert_eq!(native_get_last_error(), 6);
    }
    extern "win64" fn nested(data: u64) {
        record(data);
        native_queue_user_apc(
            record as *const () as u64,
            native_get_current_thread(),
            data,
        );
        native_sleep_ex(0, 1);
    }
    #[test]
    fn callbacks_can_reenter_alertable_waits_without_holding_queue_locks() {
        let _guard = TestProcessGuard::new();
        let count = AtomicU64::new(0);
        native_queue_user_apc(
            nested as *const () as u64,
            native_get_current_thread(),
            &count as *const _ as u64,
        );
        assert_eq!(native_sleep_ex(0, 1), WAIT_IO_COMPLETION);
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(native_sleep_ex(0, 1), 0);
    }
    #[test]
    fn wait_all_does_not_consume_events_on_timeout_or_apc_interruption() {
        let _guard = TestProcessGuard::new();
        let first = native_create_event_w(0, 0, 1, ptr::null());
        let second = native_create_event_w(0, 0, 0, ptr::null());
        let handles = [first, second];
        assert_eq!(
            native_wait_for_multiple_objects_ex(2, handles.as_ptr(), 1, 0, 1),
            258
        );
        let queue = current_apc_queue().unwrap();
        let count = AtomicU64::new(0);
        let data = &count as *const _ as u64;
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            queue.post(record as *const () as u64, [data, 0, 0]);
        });
        assert_eq!(
            native_wait_for_multiple_objects_ex(2, handles.as_ptr(), 1, 1000, 1),
            WAIT_IO_COMPLETION
        );
        sender.join().unwrap();
        assert_eq!(native_wait_for_single_object(first, 0), 0);
        native_set_event(first);
        native_set_event(second);
        assert_eq!(
            native_wait_for_multiple_objects_ex(2, handles.as_ptr(), 1, 0, 1),
            0
        );
        assert_eq!(native_wait_for_single_object(first, 0), 258);
        assert_eq!(native_wait_for_single_object(second, 0), 258);
        native_close_handle(first);
        native_close_handle(second);
        let semaphore = native_create_semaphore_a(ptr::null(), 1, 1, ptr::null());
        let event = native_create_event_w(0, 0, 0, ptr::null());
        let mixed = [semaphore, event];
        assert_eq!(
            native_wait_for_multiple_objects_ex(2, mixed.as_ptr(), 1, 0, 1),
            258
        );
        assert_eq!(native_wait_for_single_object(semaphore, 0), 0);
        native_release_semaphore(semaphore, 1, ptr::null_mut());
        native_set_event(event);
        assert_eq!(
            native_wait_for_multiple_objects_ex(2, mixed.as_ptr(), 1, 0, 1),
            0
        );
        assert_eq!(native_wait_for_single_object(semaphore, 0), 258);
        native_close_handle(semaphore);
        native_close_handle(event);
    }
    #[test]
    fn closing_a_port_wakes_an_existing_nonalertable_wait() {
        let _guard = TestProcessGuard::new();
        let process = process_ctx().unwrap();
        let handle = native_create_io_completion_port(u64::MAX, 0, 0, 0);
        let port = process
            .completion_ports
            .lock()
            .unwrap()
            .get(&handle)
            .unwrap()
            .clone();
        let worker = std::thread::spawn(move || {
            THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(process)));
            let mut entries = [0u64; 4];
            let mut removed = 99;
            let result = native_get_queued_completion_status_ex(
                handle,
                entries.as_mut_ptr().cast(),
                1,
                &mut removed,
                2000,
                0,
            );
            (result, native_get_last_error(), removed)
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while Arc::strong_count(&port) < 3 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(
            Arc::strong_count(&port) >= 3,
            "waiter did not retain the port"
        );
        assert_eq!(native_close_handle(handle), 1);
        assert_eq!(worker.join().unwrap(), (0, 735, 0));
        assert!(!port.post(NativeCompletion {
            key: 0,
            overlapped: 0,
            bytes: 0,
            status: 0
        }));
    }
}
