//! Windows byte-range locks over the guest filesystem.
use super::*;

fn overlaps(start: u64, length: u64, other: u64, other_length: u64) -> bool {
    length != 0
        && other_length != 0
        && start < other.saturating_add(other_length)
        && other < start.saturating_add(length)
}

pub(in crate::native::linux_x86_64) fn native_try_file_lock(
    fs: &mut NativeFs,
    handle: u64,
    start: u64,
    length: u64,
    exclusive: bool,
) -> Result<NativeFile, u32> {
    if length == 0 || start.checked_add(length).is_none() {
        return Err(87);
    }
    let file = fs.handles.get(&handle).cloned().ok_or(6u32)?;
    if fs
        .file_access
        .get(&handle)
        .is_some_and(|access| access & 0xc000_0000 == 0)
    {
        return Err(5);
    }
    if fs
        .file_locks
        .iter()
        .any(|(path, offset, size, owner, old_exclusive)| {
            path == &file.path
                && overlaps(start, length, *offset, *size)
                && (exclusive || (*old_exclusive && *owner != handle))
        })
    {
        return Err(33);
    }
    fs.file_locks
        .push((file.path.clone(), start, length, handle, exclusive));
    Ok(file)
}

pub(in crate::native::linux_x86_64) fn native_file_lock_allows(
    fs: &NativeFs,
    handle: u64,
    path: &str,
    start: u64,
    length: u64,
    write: bool,
) -> bool {
    !fs.file_locks
        .iter()
        .any(|(locked_path, offset, size, owner, exclusive)| {
            locked_path == path
                && overlaps(start, length, *offset, *size)
                && if *exclusive { *owner != handle } else { write }
        })
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_lock_file(
    handle: u64,
    offset_low: u32,
    offset_high: u32,
    length_low: u32,
    length_high: u32,
) -> i32 {
    let start = (u64::from(offset_high) << 32) | u64::from(offset_low);
    let length = (u64::from(length_high) << 32) | u64::from(length_low);
    let result = fs_ctx().ok_or(6u32).and_then(|context| {
        let mut fs = context.lock().map_err(|_| 6u32)?;
        native_try_file_lock(&mut fs, handle, start, length, true)
    });
    match result {
        Ok(_) => 1,
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_unlock_file(
    handle: u64,
    offset_low: u32,
    offset_high: u32,
    length_low: u32,
    length_high: u32,
) -> i32 {
    let start = (u64::from(offset_high) << 32) | u64::from(offset_low);
    let length = (u64::from(length_high) << 32) | u64::from(length_low);
    let result = fs_ctx().ok_or(6u32).and_then(|context| {
        let mut fs = context.lock().map_err(|_| 6u32)?;
        let path = fs.handles.get(&handle).ok_or(6u32)?.path.clone();
        let index = fs
            .file_locks
            .iter()
            .position(|(locked_path, offset, size, owner, _)| {
                locked_path == &path && *offset == start && *size == length && *owner == handle
            })
            .ok_or(158u32)?; // ERROR_NOT_LOCKED: exact range and owner required.
        fs.file_locks.remove(index);
        Ok(())
    });
    match result {
        Ok(()) => 1,
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_lock_file_ex(
    handle: u64,
    flags: u32,
    reserved: u32,
    length_low: u32,
    length_high: u32,
    overlapped: *mut u8,
) -> i32 {
    if flags & !3 != 0 || reserved != 0 || overlapped.is_null() || overlapped as usize & 7 != 0 {
        native_set_last_error(87);
        return 0;
    }
    let ov = overlapped as u64;
    let start = unsafe { overlapped.add(16).cast::<u64>().read_unaligned() };
    let length = (u64::from(length_high) << 32) | u64::from(length_low);
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    if native_overlapped_status(ov) == STATUS_PENDING {
        native_set_last_error(87);
        return 0;
    }
    let event = match native_prepare_overlapped_event(ov) {
        Ok(event) => event,
        Err(error) => {
            native_set_last_error(error);
            return 0;
        }
    };
    loop {
        let result = process.fs.lock().map_err(|_| 6u32).and_then(|mut fs| {
            native_try_file_lock(&mut fs, handle, start, length, flags & 2 != 0)
        });
        match result {
            Ok(file) => {
                native_complete_file_io(&file, ov, 0, event.as_ref());
                return 1;
            }
            Err(33) if flags & 1 == 0 => {
                let file = process
                    .fs
                    .lock()
                    .ok()
                    .and_then(|fs| fs.handles.get(&handle).cloned());
                let Some(file) = file else {
                    native_set_last_error(6);
                    return 0;
                };
                if file.overlapped {
                    let result = native_submit_file_io(
                        &process,
                        handle,
                        file,
                        ov,
                        start as usize,
                        NativeFileIoOperation::Lock {
                            length,
                            exclusive: flags & 2 != 0,
                        },
                    );
                    native_set_last_error(result.err().unwrap_or(997));
                    return 0;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        }
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_unlock_file_ex(
    handle: u64,
    reserved: u32,
    length_low: u32,
    length_high: u32,
    overlapped: *mut u8,
) -> i32 {
    if reserved != 0 || overlapped.is_null() || overlapped as usize & 7 != 0 {
        native_set_last_error(87);
        return 0;
    }
    let ov = overlapped as u64;
    let start = unsafe { overlapped.add(16).cast::<u64>().read_unaligned() };
    let result = native_unlock_file(
        handle,
        start as u32,
        (start >> 32) as u32,
        length_low,
        length_high,
    );
    if result != 0 {
        // Unlock completes synchronously; completion-port notifications
        // belong to the LockFileEx request that acquires the lock.
        native_set_overlapped_status(ov, 0, 0);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn open(flags: u32) -> u64 {
        let path: Vec<u16> = "C:\\locks.bin".encode_utf16().chain([0]).collect();
        let handle = native_create_file_w(path.as_ptr(), 0xc000_0000, 7, 0, 4, flags, 0);
        assert_ne!(handle, u64::MAX);
        handle
    }
    fn lock(handle: u64, flags: u32, start: u64, length: u64, ov: &mut [u64; 4]) -> i32 {
        ov[2] = start;
        native_lock_file_ex(
            handle,
            flags,
            0,
            length as u32,
            (length >> 32) as u32,
            ov.as_mut_ptr().cast(),
        )
    }
    fn unlock(handle: u64, length: u64, ov: &mut [u64; 4]) -> i32 {
        native_unlock_file_ex(
            handle,
            0,
            length as u32,
            (length >> 32) as u32,
            ov.as_mut_ptr().cast(),
        )
    }
    #[test]
    fn shared_exclusive_locks_enforce_io_and_close_releases_them() {
        let _guard = TestProcessGuard::new();
        let first = open(0);
        let second = open(0);
        let mut count = 0;
        assert_eq!(
            native_write_file(first, b"data".as_ptr(), 4, &mut count, 0),
            1
        );
        let mut a = [0u64; 4];
        let mut b = [0u64; 4];
        assert_eq!(lock(first, 3, 0, 4, &mut a), 1);
        assert_eq!(lock(first, 3, 0, 4, &mut b), 0);
        assert_eq!(native_get_last_error(), 33);
        let mut bytes = [0; 4];
        assert_eq!(
            native_read_file(second, bytes.as_mut_ptr(), 4, &mut count, 0),
            0
        );
        assert_eq!(native_get_last_error(), 33);
        assert_eq!(unlock(first, 3, &mut a), 0);
        assert_eq!(native_get_last_error(), 158);
        assert_eq!(unlock(first, 4, &mut a), 1);
        a = [0; 4];
        b = [0; 4];
        assert_eq!(lock(first, 1, 0, 4, &mut a), 1);
        assert_eq!(lock(second, 1, 0, 4, &mut b), 1);
        assert_eq!(
            native_read_file(second, bytes.as_mut_ptr(), 4, &mut count, 0),
            1
        );
        assert_eq!(bytes, *b"data");
        assert_eq!(
            native_write_file(first, b"x".as_ptr(), 1, &mut count, a.as_ptr() as u64),
            0
        );
        assert_eq!(native_get_last_error(), 33);
        assert_eq!(unlock(first, 4, &mut a), 1);
        assert_eq!(native_close_handle(second), 1);
        a = [0; 4];
        assert_eq!(lock(first, 3, 1u64 << 32, 1u64 << 32, &mut a), 1);
        assert_eq!(unlock(first, 1u64 << 32, &mut a), 1);
        assert_eq!(native_close_handle(first), 1);
    }
    #[test]
    fn pending_locks_complete_on_unlock_and_can_be_cancelled() {
        let _guard = TestProcessGuard::new();
        let first = open(0);
        let second = open(0x4000_0000);
        let port = native_create_io_completion_port(second, 0, 77, 0);
        assert_ne!(port, 0);
        let event = native_create_event_w(0, 1, 0, ptr::null());
        let mut a = [0u64; 4];
        let mut b = [0, 0, 0, event];
        assert_eq!(lock(first, 3, 0, 4, &mut a), 1);
        assert_eq!(lock(second, 2, 0, 4, &mut b), 0);
        assert_eq!(native_get_last_error(), 997);
        assert_eq!(native_wait_for_single_object(event, 0), 258);
        assert_eq!(unlock(first, 4, &mut a), 1);
        assert_eq!(native_wait_for_single_object(event, 1000), 0);
        let mut count = 99;
        assert_eq!(
            native_get_overlapped_result(second, b.as_ptr() as u64, &mut count, 0),
            1
        );
        assert_eq!(count, 0);
        let mut key = 0;
        let mut completed = 0;
        assert_eq!(
            native_get_queued_completion_status(port, &mut count, &mut key, &mut completed, 1000),
            1
        );
        assert_eq!((key, completed, count), (77, b.as_ptr() as u64, 0));
        assert_eq!(unlock(second, 4, &mut b), 1);
        a = [0; 4];
        b = [0, 0, 0, event];
        assert_eq!(lock(first, 3, 0, 4, &mut a), 1);
        assert_eq!(lock(second, 2, 0, 4, &mut b), 0);
        assert_eq!(native_cancel_io_ex(second, b.as_ptr() as u64), 1);
        assert_eq!(native_wait_for_single_object(event, 1000), 0);
        assert_eq!(
            native_get_overlapped_result(second, b.as_ptr() as u64, &mut count, 0),
            0
        );
        assert_eq!(native_get_last_error(), 995);
        native_wait_file_io(&process_ctx().unwrap());
        assert_eq!(unlock(first, 4, &mut a), 1);
        native_close_handle(first);
        native_close_handle(second);
        native_close_handle(event);
        native_close_handle(port);
    }
    #[test]
    fn synchronous_wait_resumes_when_another_thread_unlocks() {
        let _guard = TestProcessGuard::new();
        let process = process_ctx().unwrap();
        let first = open(0);
        let second = open(0);
        let mut a = [0u64; 4];
        assert_eq!(lock(first, 3, 0, 4, &mut a), 1);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(process)));
            let mut b = [0u64; 4];
            started_tx.send(()).unwrap();
            let result = lock(second, 2, 0, 4, &mut b);
            if result == 1 {
                unlock(second, 4, &mut b);
            }
            done_tx.send(result).unwrap();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(done_rx.try_recv().is_err());
        assert_eq!(unlock(first, 4, &mut a), 1);
        assert_eq!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            1
        );
        worker.join().unwrap();
        native_close_handle(first);
        native_close_handle(second);
    }
    #[test]
    fn closing_a_handle_and_process_exit_cancel_pending_locks() {
        let _guard = TestProcessGuard::new();
        let first = open(0);
        let second = open(0x4000_0000);
        let mut a = [0u64; 4];
        let mut b = [0u64; 4];
        assert_eq!(lock(first, 3, 0, 4, &mut a), 1);
        assert_eq!(lock(second, 2, 0, 4, &mut b), 0);
        native_close_handle(second);
        native_wait_file_io(&process_ctx().unwrap());
        assert_eq!(
            native_overlapped_status(b.as_ptr() as u64),
            STATUS_CANCELLED
        );
        let third = open(0x4000_0000);
        b = [0; 4];
        assert_eq!(lock(third, 2, 0, 4, &mut b), 0);
        native_shutdown_file_io(&process_ctx().unwrap());
        assert_eq!(
            native_overlapped_status(b.as_ptr() as u64),
            STATUS_CANCELLED
        );
        assert!(process_ctx()
            .unwrap()
            .fs
            .lock()
            .unwrap()
            .file_locks
            .is_empty());
        native_close_handle(third);
        native_close_handle(first);
    }
    #[test]
    fn queued_reads_and_writes_check_locks_when_the_worker_executes() {
        let _guard = TestProcessGuard::new();
        let process = process_ctx().unwrap();
        let first = open(0);
        let second = open(0x4000_0000);
        let mut count = 0;
        assert_eq!(
            native_write_file(first, b"data".as_ptr(), 4, &mut count, 0),
            1
        );
        let file = process.fs.lock().unwrap().handles[&second].clone();
        let event = native_create_event_w(0, 1, 0, ptr::null());
        let mut a = [0u64; 4];
        let mut b = [0u64; 4];
        let mut bytes = [0u8; 4];
        assert_eq!(lock(first, 3, 0, 4, &mut a), 1);
        for operation in [
            NativeFileIoOperation::Read {
                output: bytes.as_mut_ptr() as u64,
                length: 4,
            },
            NativeFileIoOperation::Write {
                data: b"oops".to_vec(),
            },
        ] {
            b.fill(0);
            b[3] = event;
            assert!(native_submit_file_io(
                &process,
                second,
                file.clone(),
                b.as_ptr() as u64,
                0,
                operation
            )
            .is_ok());
            assert_eq!(native_wait_for_single_object(event, 1000), 0);
            assert_eq!(
                native_get_overlapped_result(second, b.as_ptr() as u64, &mut count, 0),
                0
            );
            assert_eq!(native_get_last_error(), 33);
            native_wait_file_io(&process);
        }
        assert_eq!(bytes, [0; 4]);
        assert_eq!(
            process
                .fs
                .lock()
                .unwrap()
                .fs
                .read_file("C:\\locks.bin")
                .unwrap(),
            b"data"
        );
        unlock(first, 4, &mut a);
        native_close_handle(first);
        native_close_handle(second);
        native_close_handle(event);
    }
    #[test]
    fn locks_validate_handles_flags_reserved_and_ranges() {
        let _guard = TestProcessGuard::new();
        let handle = open(0);
        let mut ov = [0u64; 4];
        assert!(supports_import("KERNEL32.dll", "LockFileEx"));
        assert!(supports_import(
            "api-ms-win-core-file-l1-2-0.dll",
            "UnlockFileEx"
        ));
        assert_eq!(lock(0xdead, 3, 0, 1, &mut ov), 0);
        assert_eq!(native_get_last_error(), 6);
        assert_eq!(lock(handle, 4, 0, 1, &mut ov), 0);
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(lock(handle, 3, u64::MAX, 1, &mut ov), 0);
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(
            native_lock_file_ex(handle, 3, 1, 1, 0, ov.as_mut_ptr().cast()),
            0
        );
        assert_eq!(native_lock_file_ex(handle, 3, 0, 1, 0, ptr::null_mut()), 0);
        assert_eq!(
            native_unlock_file_ex(handle, 1, 1, 0, ov.as_mut_ptr().cast()),
            0
        );
        native_close_handle(handle);
    }
}
