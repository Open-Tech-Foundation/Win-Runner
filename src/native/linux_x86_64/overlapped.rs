//! Completion ports, directory notifications, and overlapped I/O support.

use super::*;

pub(super) extern "win64" fn native_create_io_completion_port(
    file: u64,
    existing_port: u64,
    completion_key: u64,
    _concurrent_threads: u32,
) -> u64 {
    if native_diagnostic_enabled() {
        eprintln!("native CreateIoCompletionPort file={file:#x} existing={existing_port:#x} key={completion_key:#x}");
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    if file != u64::MAX
        && process
            .named_pipes
            .lock()
            .is_ok_and(|pipes| pipes.handles.contains_key(&file))
    {
        let mut pipes = match process.named_pipes.lock() {
            Ok(pipes) => pipes,
            Err(_) => return 0,
        };
        let Some(pipe) = pipes.handles.get(&file) else {
            native_set_last_error(6);
            return 0;
        };
        if !pipe.overlapped || pipe.completion.is_some() {
            native_set_last_error(87);
            return 0;
        }
        let (handle, port) = if existing_port != 0 {
            let Some(port) = process
                .completion_ports
                .lock()
                .ok()
                .and_then(|ports| ports.get(&existing_port).cloned())
            else {
                native_set_last_error(6);
                return 0;
            };
            (existing_port, port)
        } else {
            let handle = process.completion_next.fetch_add(1, Ordering::AcqRel);
            let port = Arc::new(NativeCompletionPort::new());
            if let Ok(mut ports) = process.completion_ports.lock() {
                ports.insert(handle, port.clone());
            } else {
                return 0;
            }
            (handle, port)
        };
        pipes.handles.get_mut(&file).unwrap().completion = Some((port, completion_key));
        return handle;
    }
    if file == u64::MAX && existing_port != 0 {
        native_set_last_error(87);
        return 0;
    }
    if is_afd_handle(file) {
        let (handle, port) = if existing_port != 0 {
            let Some(port) = process
                .completion_ports
                .lock()
                .ok()
                .and_then(|ports| ports.get(&existing_port).cloned())
            else {
                native_set_last_error(6);
                return 0;
            };
            (existing_port, port)
        } else {
            let handle = process.completion_next.fetch_add(1, Ordering::AcqRel);
            let port = Arc::new(NativeCompletionPort::new());
            let Ok(mut ports) = process.completion_ports.lock() else {
                return 0;
            };
            ports.insert(handle, port.clone());
            (handle, port)
        };
        if !associate_afd_device(file, port, completion_key) {
            native_set_last_error(6);
            return 0;
        }
        return handle;
    }
    if file & 0xffff_ffff_0000_0000 == SOCKET_HANDLE_TAG {
        let (handle, port) = if existing_port != 0 {
            let Some(port) = process
                .completion_ports
                .lock()
                .ok()
                .and_then(|ports| ports.get(&existing_port).cloned())
            else {
                native_set_last_error(6);
                return 0;
            };
            (existing_port, port)
        } else {
            let handle = process.completion_next.fetch_add(1, Ordering::AcqRel);
            let port = Arc::new(NativeCompletionPort::new());
            if let Ok(mut ports) = process.completion_ports.lock() {
                ports.insert(handle, port.clone());
            } else {
                return 0;
            }
            (handle, port)
        };
        let Ok(mut associations) = process.socket_completion_ports.lock() else {
            return 0;
        };
        if associations.contains_key(&file) {
            native_set_last_error(87);
            return 0;
        }
        associations.insert(file, (port, completion_key));
        return handle;
    }
    let mut fs = match process.fs.lock() {
        Ok(fs) => fs,
        Err(_) => return 0,
    };
    if file != u64::MAX {
        let Some(open) = fs.handles.get(&file) else {
            native_set_last_error(6);
            return 0;
        };
        if !open.overlapped || open.completion.is_some() {
            native_set_last_error(87);
            return 0;
        }
    }
    let (handle, port) = if existing_port != 0 {
        let Some(port) = process
            .completion_ports
            .lock()
            .ok()
            .and_then(|ports| ports.get(&existing_port).cloned())
        else {
            native_set_last_error(6);
            return 0;
        };
        (existing_port, port)
    } else {
        let handle = process.completion_next.fetch_add(1, Ordering::AcqRel);
        let port = Arc::new(NativeCompletionPort::new());
        let Ok(mut ports) = process.completion_ports.lock() else {
            return 0;
        };
        ports.insert(handle, port.clone());
        (handle, port)
    };
    if file != u64::MAX {
        fs.handles.get_mut(&file).unwrap().completion = Some((port, completion_key));
    }
    handle
}
pub(super) extern "win64" fn native_set_file_completion_notification_modes(
    handle: u64,
    flags: u32,
) -> i32 {
    // The Windows API declares UCHAR flags. Ignore unrelated high bits in
    // RDX, which are not part of the argument on the x64 ABI.
    let modes = flags as u8;
    if let Some(process) = process_ctx() {
        if let Ok(mut pipes) = process.named_pipes.lock() {
            if let Some(pipe) = pipes.handles.get_mut(&handle) {
                if modes & !0x3 != 0 {
                    native_set_last_error(87);
                    return 0;
                }
                pipe.completion_modes = modes;
                return 1;
            }
        }
    }
    if modes & !0x3 != 0 {
        native_set_last_error(87);
        return 0;
    }
    if is_afd_handle(handle) {
        // Completions always go to the port; there is no event to skip.
        return 1;
    }
    if let Some(process) = process_ctx() {
        if let Ok(mut fs) = process.fs.lock() {
            if let Some(file) = fs.handles.get(&handle) {
                if !file.overlapped {
                    native_set_last_error(87);
                    return 0;
                }
                fs.file_completion_modes.insert(handle, modes);
                return 1;
            }
        }
    }
    if handle & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG || unsafe { fcntl(handle as i32, 3) } < 0
    {
        native_set_last_error(6);
        return 0;
    }
    if let Some(process) = process_ctx() {
        if let Ok(mut socket_modes) = process.socket_completion_modes.lock() {
            socket_modes.insert(handle, modes);
        }
    }
    1
}
pub(super) fn native_post_socket_completion(socket: u64, overlapped: u64, bytes: u32) {
    native_post_socket_completion_inner(socket, overlapped, bytes, false);
}
pub(super) fn native_post_pending_socket_completion(socket: u64, overlapped: u64, bytes: u32) {
    native_post_socket_completion_inner(socket, overlapped, bytes, true);
}
fn native_post_socket_completion_inner(socket: u64, overlapped: u64, bytes: u32, pending: bool) {
    if overlapped == 0 {
        return;
    }
    let Some(process) = process_ctx() else { return };
    let skip_port_on_success = process
        .socket_completion_modes
        .lock()
        .ok()
        .and_then(|modes| modes.get(&socket).copied())
        .is_some_and(|modes| modes & 0x2 != 0);
    if skip_port_on_success && !pending {
        return;
    }
    let association = process
        .socket_completion_ports
        .lock()
        .ok()
        .and_then(|associations| associations.get(&socket).cloned());
    if let Some((port, key)) = association {
        native_set_overlapped_status(overlapped, 0, bytes);
        port.post(NativeCompletion {
            key,
            overlapped,
            bytes,
            status: 0,
        });
    }
}
pub(super) fn native_prepare_overlapped_event(
    overlapped: u64,
) -> Result<Option<Arc<NativeEvent>>, u32> {
    if overlapped == 0 {
        return Ok(None);
    }
    let raw = unsafe { ((overlapped + 24) as *const u64).read_unaligned() };
    let handle = raw & !1;
    if handle == 0 {
        return Ok(None);
    }
    let process = process_ctx().ok_or(6u32)?;
    let event = process
        .events
        .lock()
        .map_err(|_| 6u32)?
        .get(&handle)
        .cloned()
        .ok_or(6u32)?;
    *event.signaled.lock().map_err(|_| 6u32)? = false;
    Ok(Some(event))
}
pub(super) fn native_complete_file_io(
    file: &NativeFile,
    overlapped: u64,
    bytes: u32,
    event: Option<&Arc<NativeEvent>>,
) {
    if overlapped == 0 {
        return;
    }
    unsafe {
        (overlapped as *mut u64).write_unaligned(0); // OVERLAPPED.Internal = STATUS_SUCCESS
        ((overlapped + 8) as *mut u64).write_unaligned(bytes as u64); // InternalHigh
    }
    if let Some(event) = event {
        native_signal_event(event);
    }
    if let Some((port, key)) = &file.completion {
        // The low bit of hEvent suppresses completion-port notification.
        let event = unsafe { ((overlapped + 24) as *const u64).read_unaligned() };
        if event & 1 == 0 {
            port.post(NativeCompletion {
                key: *key,
                overlapped,
                bytes,
                status: 0,
            });
        }
    }
}

pub(super) fn native_complete_pipe_io(
    pipe: &NativePipeHandle,
    overlapped: u64,
    bytes: u32,
    status: u32,
    event: Option<&Arc<NativeEvent>>,
) {
    if overlapped == 0 {
        return;
    }
    unsafe {
        (overlapped as *mut u64).write_unaligned(status as u64);
        ((overlapped + 8) as *mut u64).write_unaligned(bytes as u64);
    }
    if let Some(event) = event {
        native_signal_event(event);
    }
    if let Some((port, key)) = &pipe.completion {
        let event_handle = unsafe { ((overlapped + 24) as *const u64).read_unaligned() };
        // FILE_SKIP_COMPLETION_PORT_ON_SUCCESS only applies to I/O that
        // completes before returning from the API. This helper is used
        // only after an operation was queued as pending.
        if event_handle & 1 == 0 {
            port.post(NativeCompletion {
                key: *key,
                overlapped,
                bytes,
                status: status as u64,
            });
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeDirectoryEntry {
    is_directory: bool,
    size: usize,
    content_hash: u64,
}

fn native_directory_snapshot(
    fs: &WinFs,
    directory: &str,
    subtree: bool,
) -> HashMap<String, NativeDirectoryEntry> {
    fn visit(
        fs: &WinFs,
        directory: &str,
        prefix: &str,
        recursive: bool,
        output: &mut HashMap<String, NativeDirectoryEntry>,
    ) {
        let Ok(names) = fs.list_dir(directory) else {
            return;
        };
        for name in names {
            let full_path = format!("{directory}\\{name}");
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}\\{name}")
            };
            let is_directory = fs.is_dir(&full_path);
            let size = if is_directory {
                0
            } else {
                fs.file_len(&full_path).unwrap_or(0) as usize
            };
            let content_hash = if is_directory {
                0
            } else {
                fs.file_version(&full_path).unwrap_or_default()
            };
            output.insert(
                relative.clone(),
                NativeDirectoryEntry {
                    is_directory,
                    size,
                    content_hash,
                },
            );
            if recursive && is_directory {
                visit(fs, &full_path, &relative, true, output);
            }
        }
    }
    let mut entries = HashMap::new();
    visit(fs, directory, "", subtree, &mut entries);
    entries
}

fn native_directory_changes(
    before: &HashMap<String, NativeDirectoryEntry>,
    after: &HashMap<String, NativeDirectoryEntry>,
    filter: u32,
) -> Vec<(u32, String)> {
    let mut changes = Vec::new();
    for (name, entry) in after {
        match before.get(name) {
            None if (entry.is_directory && filter & 0x2 != 0)
                || (!entry.is_directory && filter & 0x1 != 0) =>
            {
                changes.push((1, name.clone())); // FILE_ACTION_ADDED
            }
            Some(old)
                if (old.size != entry.size || old.content_hash != entry.content_hash)
                    && !entry.is_directory
                    && filter & (0x8 | 0x10) != 0 =>
            {
                changes.push((3, name.clone())); // FILE_ACTION_MODIFIED
            }
            _ => {}
        }
    }
    for (name, entry) in before {
        if !after.contains_key(name)
            && ((entry.is_directory && filter & 0x2 != 0)
                || (!entry.is_directory && filter & 0x1 != 0))
        {
            changes.push((2, name.clone())); // FILE_ACTION_REMOVED
        }
    }
    changes.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
    changes
}

fn native_encode_directory_changes(changes: &[(u32, String)], capacity: usize) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    for (index, (action, name)) in changes.iter().enumerate() {
        let encoded: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = encoded.len().checked_mul(2)?;
        let entry_len = 12usize.checked_add(name_bytes)?;
        let padded_len = (entry_len + 3) & !3;
        let offset = output.len();
        if offset.checked_add(padded_len)? > capacity {
            return None;
        }
        output.resize(offset + padded_len, 0);
        let next = if index + 1 == changes.len() {
            0
        } else {
            padded_len as u32
        };
        output[offset..offset + 4].copy_from_slice(&next.to_le_bytes());
        output[offset + 4..offset + 8].copy_from_slice(&action.to_le_bytes());
        output[offset + 8..offset + 12].copy_from_slice(&(name_bytes as u32).to_le_bytes());
        for (i, unit) in encoded.iter().enumerate() {
            output[offset + 12 + i * 2..offset + 14 + i * 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    Some(output)
}

#[cfg(test)]
mod directory_change_tests {
    use super::*;

    #[test]
    fn snapshots_recursive_changes_and_encodes_win32_records() {
        let mut fs = WinFs::new();
        fs.mkdir(r"C:\watch\nested").unwrap();
        fs.write_file(r"C:\watch\old.txt", b"old".to_vec()).unwrap();
        let before = native_directory_snapshot(&fs, r"C:\watch", true);
        fs.delete_file(r"C:\watch\old.txt").unwrap();
        fs.write_file(r"C:\watch\nested\new.txt", b"new".to_vec())
            .unwrap();
        let after = native_directory_snapshot(&fs, r"C:\watch", true);
        let changes = native_directory_changes(&before, &after, 0x1 | 0x2);
        assert_eq!(
            changes,
            vec![(1, "nested\\new.txt".into()), (2, "old.txt".into())]
        );

        let records = native_encode_directory_changes(&changes, 80).unwrap();
        assert_eq!(u32::from_le_bytes(records[0..4].try_into().unwrap()), 40);
        assert_eq!(u32::from_le_bytes(records[4..8].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(records[8..12].try_into().unwrap()), 28);
        assert_eq!(u32::from_le_bytes(records[40..44].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(records[44..48].try_into().unwrap()), 2);
        assert!(native_encode_directory_changes(&changes, 40).is_none());
    }

    #[test]
    fn filters_file_content_updates_by_win32_change_filter() {
        let mut fs = WinFs::new();
        fs.mkdir(r"C:\watch").unwrap();
        fs.write_file(r"C:\watch\item.txt", b"a".to_vec()).unwrap();
        let before = native_directory_snapshot(&fs, r"C:\watch", false);
        fs.write_file(r"C:\watch\item.txt", b"changed".to_vec())
            .unwrap();
        let after = native_directory_snapshot(&fs, r"C:\watch", false);
        assert!(native_directory_changes(&before, &after, 0x1).is_empty());
        assert_eq!(
            native_directory_changes(&before, &after, 0x8),
            vec![(3, "item.txt".into())]
        );
    }
}

pub(super) extern "win64" fn native_read_directory_changes_w(
    handle: u64,
    buffer: *mut u8,
    length: u32,
    subtree: i32,
    filter: u32,
    bytes_returned: *mut u32,
    overlapped: u64,
    _completion_routine: u64,
) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native ReadDirectoryChangesW handle={handle:#x} length={length} subtree={subtree} filter={filter:#x} overlapped={overlapped:#x}");
    }
    const VALID_FILTER: u32 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x100;
    if buffer.is_null()
        || length < 12
        || overlapped == 0
        || overlapped & 7 != 0
        || filter == 0
        || filter & !VALID_FILTER != 0
    {
        if native_diagnostic_enabled() {
            eprintln!("native ReadDirectoryChangesW invalid args");
        }
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let (file, directory, baseline) = {
        let Ok(fs) = process.fs.lock() else {
            native_set_last_error(6);
            return 0;
        };
        let Some(file) = fs.handles.get(&handle).cloned() else {
            native_set_last_error(6);
            return 0;
        };
        if !fs.fs.is_dir(&file.path) {
            if native_diagnostic_enabled() {
                eprintln!(
                    "native ReadDirectoryChangesW not directory path={}",
                    file.path
                );
            }
            native_set_last_error(267); // ERROR_DIRECTORY
            return 0;
        }
        if !file.overlapped || native_overlapped_status(overlapped) == STATUS_PENDING {
            if native_diagnostic_enabled() {
                eprintln!(
                    "native ReadDirectoryChangesW invalid handle mode overlapped={} status={:#x}",
                    file.overlapped,
                    native_overlapped_status(overlapped)
                );
            }
            native_set_last_error(87);
            return 0;
        }
        let baseline = native_directory_snapshot(&fs.fs, &file.path, subtree != 0);
        (file.clone(), file.path.clone(), baseline)
    };
    let event = match native_prepare_overlapped_event(overlapped) {
        Ok(event) => event,
        Err(error) => {
            if native_diagnostic_enabled() {
                eprintln!("native ReadDirectoryChangesW event error={error}");
            }
            native_set_last_error(error);
            return 0;
        }
    };
    let buffer_address = buffer as usize;
    native_set_overlapped_status(overlapped, STATUS_PENDING, 0);
    if !bytes_returned.is_null() {
        unsafe { bytes_returned.write(0) };
    }
    native_set_last_error(997); // ERROR_IO_PENDING
    std::thread::spawn(move || {
        let mut previous = baseline;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(25));
            if native_overlapped_status(overlapped) != STATUS_PENDING {
                return;
            }
            let current = {
                let Ok(fs) = process.fs.lock() else { return };
                if !fs.handles.contains_key(&handle) || !fs.fs.is_dir(&directory) {
                    return;
                }
                native_directory_snapshot(&fs.fs, &directory, subtree != 0)
            };
            let changes = native_directory_changes(&previous, &current, filter);
            if changes.is_empty() {
                previous = current;
                continue;
            }
            let Some(encoded) = native_encode_directory_changes(&changes, length as usize) else {
                native_set_overlapped_status(overlapped, 0x8000_0005, 0); // STATUS_BUFFER_OVERFLOW
                if let Some(event) = &event {
                    native_signal_event(event);
                }
                if let Some((port, key)) = &file.completion {
                    let event_value = unsafe { ((overlapped + 24) as *const u64).read_unaligned() };
                    if event_value & 1 == 0 {
                        port.post(NativeCompletion {
                            key: *key,
                            overlapped,
                            bytes: 0,
                            status: 0x8000_0005,
                        });
                    }
                }
                return;
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    encoded.as_ptr(),
                    buffer_address as *mut u8,
                    encoded.len(),
                );
            }
            native_complete_file_io(&file, overlapped, encoded.len() as u32, event.as_ref());
            return;
        }
    });
    // libuv treats a false return as an immediate failure, even when the
    // last error is ERROR_IO_PENDING. Windows reports that the async
    // notification request was successfully queued with a nonzero return.
    1
}
pub(super) fn native_overlapped_offset(overlapped: u64) -> Option<usize> {
    let low = unsafe { ((overlapped + 16) as *const u32).read_unaligned() };
    let high = unsafe { ((overlapped + 20) as *const u32).read_unaligned() };
    usize::try_from(((high as u64) << 32) | low as u64).ok()
}
pub(super) const STATUS_PENDING: u64 = 0x103;
const STATUS_END_OF_FILE: u64 = 0xC000_0011;
const STATUS_UNSUCCESSFUL: u64 = 0xC000_0001;
pub(super) const STATUS_CANCELLED: u64 = 0xC000_0120;
pub(super) const DEFERRED_FILE_IO_MIN: u32 = 64 * 1024;
const FILE_IO_WORKERS: usize = 4;
pub(super) const MAX_QUEUED_FILE_IO: usize = 128;
pub(super) fn native_file_io_queue_full(state: &NativeFileIoQueueState) -> bool {
    state.jobs.len() >= MAX_QUEUED_FILE_IO
}
pub(super) fn native_overlapped_status(overlapped: u64) -> u64 {
    unsafe { (*(overlapped as *const AtomicU64)).load(Ordering::Acquire) }
}
pub(super) fn native_set_overlapped_status(overlapped: u64, status: u64, bytes: u32) {
    unsafe {
        (*(overlapped.wrapping_add(8) as *const AtomicU64)).store(bytes as u64, Ordering::Release);
        (*(overlapped as *const AtomicU64)).store(status, Ordering::Release);
    }
}
fn native_file_error(status: u64) -> u32 {
    if status == STATUS_END_OF_FILE {
        38
    } else if status == STATUS_CANCELLED {
        995 // ERROR_OPERATION_ABORTED
    } else if status == 0xc000_014b {
        109 // ERROR_BROKEN_PIPE
    } else {
        1
    }
}
fn native_finish_pending_file_io(
    process: &NativeProcessContext,
    file: &NativeFile,
    overlapped: u64,
    event: Option<Arc<NativeEvent>>,
    request: Arc<NativePendingIo>,
    result: Result<u32, u64>,
) {
    let (bytes, status) = match result {
        Ok(bytes) => (bytes, 0),
        Err(status) => (0, status),
    };
    if let Ok(_guard) = process.io_wait.lock() {
        native_set_overlapped_status(overlapped, status, bytes);
        process.io_ready.notify_all();
    }
    if let Some(event) = event {
        native_signal_event(&event);
    }
    if let Some((port, key)) = &file.completion {
        let event = unsafe { ((overlapped + 24) as *const u64).read_unaligned() };
        if event & 1 == 0 {
            port.post(NativeCompletion {
                key: *key,
                overlapped,
                bytes,
                status,
            });
        }
    }
    if let Ok(_guard) = process.io_wait.lock() {
        process.pending_file_io.fetch_sub(1, Ordering::AcqRel);
        process.io_ready.notify_all();
    }
    if let Ok(mut pending) = process.pending_requests.lock() {
        let key = (request.handle, overlapped);
        if pending
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &request))
        {
            pending.remove(&key);
        }
    }
}
pub(super) fn native_wait_file_io(process: &NativeProcessContext) {
    let Ok(mut guard) = process.io_wait.lock() else {
        return;
    };
    while process.pending_file_io.load(Ordering::Acquire) != 0 {
        guard = match process.io_ready.wait(guard) {
            Ok(guard) => guard,
            Err(_) => return,
        };
    }
}
fn native_file_io_queue(
    process: &Arc<NativeProcessContext>,
) -> Result<Arc<NativeFileIoQueue>, u32> {
    let mut slot = process.file_io_queue.lock().map_err(|_| 6u32)?;
    if let Some(queue) = slot.as_ref() {
        return Ok(Arc::clone(queue));
    }
    let queue = Arc::new(NativeFileIoQueue {
        state: Mutex::new(NativeFileIoQueueState {
            jobs: std::collections::VecDeque::new(),
            stop: false,
        }),
        ready: Condvar::new(),
    });
    for index in 0..FILE_IO_WORKERS {
        let worker_queue = Arc::clone(&queue);
        if std::thread::Builder::new()
            .name(format!("winrun-file-io-{index}"))
            .spawn(move || native_file_io_worker(worker_queue))
            .is_err()
        {
            if let Ok(mut state) = queue.state.lock() {
                state.stop = true;
                queue.ready.notify_all();
            }
            return Err(8);
        }
    }
    *slot = Some(Arc::clone(&queue));
    Ok(queue)
}
pub(super) fn native_submit_file_io(
    process: &Arc<NativeProcessContext>,
    handle: u64,
    file: NativeFile,
    overlapped: u64,
    offset: usize,
    operation: NativeFileIoOperation,
) -> Result<(), u32> {
    let queue = native_file_io_queue(process)?;
    native_enqueue_file_io(&queue, process, handle, file, overlapped, offset, operation)
}
pub(super) fn native_enqueue_file_io(
    queue: &NativeFileIoQueue,
    process: &Arc<NativeProcessContext>,
    handle: u64,
    file: NativeFile,
    overlapped: u64,
    offset: usize,
    operation: NativeFileIoOperation,
) -> Result<(), u32> {
    let mut state = queue.state.lock().map_err(|_| 6u32)?;
    if native_file_io_queue_full(&state) {
        return Err(8);
    }
    let mut pending = process.pending_requests.lock().map_err(|_| 6u32)?;
    if pending.contains_key(&(handle, overlapped)) {
        return Err(87);
    }
    let event = native_prepare_overlapped_event(overlapped)?;
    let request = Arc::new(NativePendingIo {
        handle,
        overlapped,
        cancelled: AtomicBool::new(false),
        issuer: std::thread::current().id(),
    });
    native_set_overlapped_status(overlapped, STATUS_PENDING, 0);
    process.pending_file_io.fetch_add(1, Ordering::AcqRel);
    pending.insert((handle, overlapped), Arc::clone(&request));
    state.jobs.push_back(NativeFileIoJob {
        process: Arc::clone(process),
        request,
        file,
        overlapped,
        event,
        offset,
        operation,
    });
    queue.ready.notify_one();
    Ok(())
}
fn native_file_io_worker(queue: Arc<NativeFileIoQueue>) {
    loop {
        let job = {
            let Ok(mut state) = queue.state.lock() else {
                return;
            };
            while state.jobs.is_empty() && !state.stop {
                state = match queue.ready.wait(state) {
                    Ok(state) => state,
                    Err(_) => return,
                };
            }
            if state.stop {
                return;
            }
            state.jobs.pop_front().unwrap()
        };
        let result = if job.request.cancelled.load(Ordering::Acquire) {
            Err(STATUS_CANCELLED)
        } else {
            match job.operation {
                NativeFileIoOperation::Read { output, length } => match job.process.fs.lock() {
                    Ok(fs) => match fs.fs.file_len(&job.file.path) {
                        Ok(file_len) if job.offset as u64 >= file_len => Err(STATUS_END_OF_FILE),
                        Ok(_) => {
                            let mut copied = 0usize;
                            let mut failure = None;
                            while copied < length as usize {
                                let amount = (length as usize - copied).min(64 * 1024);
                                let data = match fs.fs.read_file_range(
                                    &job.file.path,
                                    (job.offset + copied) as u64,
                                    amount,
                                ) {
                                    Ok(data) => data,
                                    Err(_) => {
                                        failure = Some(STATUS_UNSUCCESSFUL);
                                        break;
                                    }
                                };
                                if data.is_empty() {
                                    break;
                                }
                                if job.request.cancelled.load(Ordering::Acquire) {
                                    failure = Some(STATUS_CANCELLED);
                                    break;
                                }
                                unsafe {
                                    std::ptr::copy_nonoverlapping(
                                        data.as_ptr(),
                                        (output as *mut u8).add(copied),
                                        data.len(),
                                    )
                                };
                                copied += data.len();
                                if data.len() < amount {
                                    break;
                                }
                            }
                            match failure {
                                Some(error) => Err(error),
                                None => Ok(copied as u32),
                            }
                        }
                        Err(_) => Err(STATUS_UNSUCCESSFUL),
                    },
                    Err(_) => Err(STATUS_UNSUCCESSFUL),
                },
                NativeFileIoOperation::Write { data } => match job.process.fs.lock() {
                    Ok(_) if job.request.cancelled.load(Ordering::Acquire) => {
                        Err(STATUS_CANCELLED)
                    }
                    Ok(mut fs) => fs
                        .fs
                        .write_at(&job.file.path, job.offset as u64, &data)
                        .map(|_| data.len() as u32)
                        .map_err(|_| STATUS_UNSUCCESSFUL),
                    Err(_) => Err(STATUS_UNSUCCESSFUL),
                },
            }
        };
        native_finish_pending_file_io(
            &job.process,
            &job.file,
            job.overlapped,
            job.event,
            job.request,
            result,
        );
    }
}
pub(super) fn native_cancel_file_io_requests(
    process: &Arc<NativeProcessContext>,
    queue: &NativeFileIoQueue,
    handle: u64,
    overlapped: u64,
    issuer: Option<std::thread::ThreadId>,
) -> Result<(), u32> {
    let matching = {
        let pending = process.pending_requests.lock().map_err(|_| 6u32)?;
        let matching: Vec<_> = pending
            .values()
            .filter(|request| {
                request.handle == handle
                    && (overlapped == 0 || request.overlapped == overlapped)
                    && issuer.is_none_or(|issuer| issuer == request.issuer)
            })
            .cloned()
            .collect();
        for request in &matching {
            request.cancelled.store(true, Ordering::Release);
        }
        matching
    };
    if matching.is_empty() {
        return Err(1168);
    } // ERROR_NOT_FOUND
    let mut removed = Vec::new();
    {
        let mut state = queue.state.lock().map_err(|_| 6u32)?;
        let mut index = 0;
        while index < state.jobs.len() {
            if matching
                .iter()
                .any(|request| Arc::ptr_eq(request, &state.jobs[index].request))
            {
                removed.push(state.jobs.remove(index).unwrap());
            } else {
                index += 1;
            }
        }
    }
    for job in removed {
        native_finish_pending_file_io(
            &job.process,
            &job.file,
            job.overlapped,
            job.event,
            job.request,
            Err(STATUS_CANCELLED),
        );
    }
    Ok(())
}
pub(super) fn native_cancel_file_io(
    handle: u64,
    overlapped: u64,
    issuer: Option<std::thread::ThreadId>,
) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    if let Ok(pipes) = process.named_pipes.lock() {
        if pipes.handles.contains_key(&handle) {
            let matching: Vec<_> = pipes
                .pending_io
                .iter()
                .filter(|((pipe_handle, ov), pending)| {
                    *pipe_handle == handle
                        && (overlapped == 0 || *ov == overlapped)
                        && issuer.map_or(true, |issuer| issuer == pending.issuer)
                })
                .map(|(_, pending)| Arc::clone(&pending.cancelled))
                .collect();
            drop(pipes);
            if matching.is_empty() {
                native_set_last_error(1168);
                return 0;
            }
            for cancelled in matching {
                cancelled.store(true, Ordering::Release);
            }
            return 1;
        }
    }
    if !process
        .fs
        .lock()
        .is_ok_and(|fs| fs.handles.contains_key(&handle))
    {
        native_set_last_error(6);
        return 0;
    }
    let queue = process
        .file_io_queue
        .lock()
        .ok()
        .and_then(|slot| slot.clone());
    let Some(queue) = queue else {
        native_set_last_error(1168);
        return 0;
    };
    match native_cancel_file_io_requests(&process, &queue, handle, overlapped, issuer) {
        Ok(()) => 1,
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}
pub(super) extern "win64" fn native_cancel_io_ex(handle: u64, overlapped: u64) -> i32 {
    native_cancel_file_io(handle, overlapped, None)
}
pub(super) extern "win64" fn native_cancel_io(handle: u64) -> i32 {
    native_cancel_file_io(handle, 0, Some(std::thread::current().id()))
}
pub(super) extern "win64" fn native_post_queued_completion_status(
    handle: u64,
    bytes: u32,
    key: u64,
    overlapped: u64,
) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native PostQueuedCompletionStatus key={key:#x} overlap={overlapped:#x}");
    }
    let Some(port) = process_ctx().and_then(|process| {
        process
            .completion_ports
            .lock()
            .ok()
            .and_then(|values| values.get(&handle).cloned())
    }) else {
        native_set_last_error(6);
        return 0;
    };
    if !port.post(NativeCompletion {
        key,
        overlapped,
        bytes,
        status: 0,
    }) {
        native_set_last_error(6);
        return 0;
    }
    1
}
#[repr(C)]
pub(super) struct NativeOverlappedEntry {
    key: u64,
    overlapped: u64,
    internal: u64,
    bytes: u32,
    _padding: u32,
}
pub(super) extern "win64" fn native_get_queued_completion_status_ex(
    handle: u64,
    entries: *mut NativeOverlappedEntry,
    count: u32,
    removed: *mut u32,
    timeout: u32,
    _alertable: i32,
) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native GetQueuedCompletionStatusEx timeout={timeout} count={count}");
    }
    if entries.is_null() || removed.is_null() || count == 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(port) = process_ctx().and_then(|process| {
        process
            .completion_ports
            .lock()
            .ok()
            .and_then(|values| values.get(&handle).cloned())
    }) else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut queue) = port.queue.lock() else {
        return 0;
    };
    if timeout == u32::MAX {
        while queue.is_empty() {
            queue = match port.ready.wait(queue) {
                Ok(queue) => queue,
                Err(_) => return 0,
            };
        }
    } else if queue.is_empty() {
        let Ok((new_queue, _)) = port.ready.wait_timeout_while(
            queue,
            std::time::Duration::from_millis(timeout as u64),
            |queue| queue.is_empty(),
        ) else {
            return 0;
        };
        queue = new_queue;
    }
    if queue.is_empty() {
        unsafe { removed.write(0) };
        native_set_last_error(258); // WAIT_TIMEOUT
        return 0;
    }
    let mut n = 0;
    while n < count {
        let Some(completion) = queue.pop_front() else {
            break;
        };
        unsafe {
            entries.add(n as usize).write(NativeOverlappedEntry {
                key: completion.key,
                overlapped: completion.overlapped,
                internal: completion.status,
                bytes: completion.bytes,
                _padding: 0,
            })
        };
        n += 1;
    }
    unsafe { removed.write(n) };
    1
}
pub(super) extern "win64" fn native_get_queued_completion_status(
    handle: u64,
    bytes: *mut u32,
    key: *mut u64,
    overlapped: *mut u64,
    timeout: u32,
) -> i32 {
    if bytes.is_null() || key.is_null() || overlapped.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let mut entry = NativeOverlappedEntry {
        key: 0,
        overlapped: 0,
        internal: 0,
        bytes: 0,
        _padding: 0,
    };
    let mut removed = 0;
    if native_get_queued_completion_status_ex(handle, &mut entry, 1, &mut removed, timeout, 0) == 0
    {
        unsafe { overlapped.write(0) };
        return 0;
    }
    unsafe {
        bytes.write(entry.bytes);
        key.write(entry.key);
        overlapped.write(entry.overlapped);
    }
    if entry.internal != 0 {
        native_set_last_error(native_file_error(entry.internal));
        0
    } else {
        1
    }
}
pub(super) extern "win64" fn native_get_overlapped_result(
    handle: u64,
    overlapped: u64,
    bytes: *mut u32,
    wait: i32,
) -> i32 {
    if overlapped == 0 || overlapped & 7 != 0 || bytes.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let is_pipe = process
        .named_pipes
        .lock()
        .is_ok_and(|pipes| pipes.handles.contains_key(&handle));
    if is_pipe {
        while native_overlapped_status(overlapped) == STATUS_PENDING {
            if wait == 0 {
                native_set_last_error(996); // ERROR_IO_INCOMPLETE
                return 0;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let status = native_overlapped_status(overlapped);
        if status != 0 {
            native_set_last_error(native_file_error(status));
            return 0;
        }
        unsafe {
            bytes.write(
                (*(overlapped.wrapping_add(8) as *const AtomicU64)).load(Ordering::Acquire) as u32,
            )
        };
        return 1;
    }
    if !process
        .fs
        .lock()
        .is_ok_and(|fs| fs.handles.contains_key(&handle))
    {
        native_set_last_error(6);
        return 0;
    }
    let mut guard = match process.io_wait.lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    while native_overlapped_status(overlapped) == STATUS_PENDING {
        if wait == 0 {
            native_set_last_error(996); // ERROR_IO_INCOMPLETE
            return 0;
        }
        guard = match process.io_ready.wait(guard) {
            Ok(guard) => guard,
            Err(_) => return 0,
        };
    }
    drop(guard);
    let status = native_overlapped_status(overlapped);
    if status != 0 {
        native_set_last_error(native_file_error(status));
        return 0;
    }
    unsafe {
        bytes.write(
            (*(overlapped.wrapping_add(8) as *const AtomicU64)).load(Ordering::Acquire) as u32,
        )
    };
    1
}
