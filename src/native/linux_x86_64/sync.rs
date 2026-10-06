//! Windows critical sections, SRW locks, condition variables, and InitOnce.

use super::*;

pub(super) extern "win64" fn native_initialize_critical_section_ex(
    section: *mut u8,
    _spin: u32,
    _flags: u32,
) -> i32 {
    if section.is_null() {
        return 0;
    }
    unsafe { std::ptr::write_bytes(section, 0, 40) };
    if let Ok(mut sections) = NATIVE_CRITICAL_SECTIONS.lock() {
        sections.insert(section as usize, Arc::new(NativeCriticalSection::new()));
    }
    1
}
pub(super) extern "win64" fn native_initialize_critical_section_and_spin_count(
    section: *mut u8,
    spin_count: u32,
) -> i32 {
    native_initialize_critical_section_ex(section, spin_count, 0)
}
pub(super) extern "win64" fn native_initialize_critical_section(section: *mut u8) {
    let _ = native_initialize_critical_section_ex(section, 0, 0);
}
// Windows stores these synchronization objects in one pointer-sized word and
// requires no destructor. Keep state inline; Linux futex queues exist only
// while a thread is waiting, so object churn never allocates permanent locks.
fn sync_word<'a>(ptr: *mut u64) -> Option<&'a AtomicU64> {
    if ptr.is_null() || (ptr as usize) % 8 != 0 {
        return None;
    }
    Some(unsafe { &*ptr.cast::<AtomicU64>() })
}
fn wake_word(word: &AtomicU64, all: bool) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word as *const AtomicU64,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            if all { i32::MAX } else { 1 },
        );
    }
}
fn wait_word(word: &AtomicU64, value: u64, timeout: Option<std::time::Duration>) {
    let ts = timeout.map(|t| libc::timespec {
        tv_sec: t.as_secs() as _,
        tv_nsec: t.subsec_nanos() as _,
    });
    let time = ts
        .as_ref()
        .map_or(std::ptr::null(), |t| t as *const libc::timespec);
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word as *const AtomicU64,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            value as u32,
            time,
        );
    }
}
pub(super) extern "win64" fn native_initialize_srw_lock(ptr: *mut u64) {
    if let Some(word) = sync_word(ptr) {
        word.store(0, Ordering::Release);
    }
}
fn try_srw(ptr: *mut u64, exclusive: bool) -> i32 {
    let Some(word) = sync_word(ptr) else {
        return 0;
    };
    if exclusive {
        return word
            .compare_exchange(0, u64::MAX, Ordering::Acquire, Ordering::Relaxed)
            .is_ok() as i32;
    }
    word.fetch_update(Ordering::Acquire, Ordering::Relaxed, |value| {
        (value < u32::MAX as u64 - 1).then(|| value + 1)
    })
    .is_ok() as i32
}
fn acquire_srw(ptr: *mut u64, exclusive: bool) {
    let Some(word) = sync_word(ptr) else {
        return;
    };
    loop {
        if try_srw(ptr, exclusive) != 0 {
            return;
        }
        // Observe the blocking state after the failed acquisition. Waiting
        // on an earlier zero can miss an unlock between the CAS and futex.
        let value = word.load(Ordering::Acquire);
        if value == 0 || (!exclusive && value != u64::MAX) {
            continue;
        }
        wait_word(word, value, None);
    }
}
pub(super) extern "win64" fn native_acquire_srw_lock_exclusive(ptr: *mut u64) {
    acquire_srw(ptr, true);
}
pub(super) extern "win64" fn native_acquire_srw_lock_shared(ptr: *mut u64) {
    acquire_srw(ptr, false);
}
pub(super) extern "win64" fn native_try_acquire_srw_lock_exclusive(ptr: *mut u64) -> i32 {
    try_srw(ptr, true)
}
pub(super) extern "win64" fn native_try_acquire_srw_lock_shared(ptr: *mut u64) -> i32 {
    try_srw(ptr, false)
}
pub(super) extern "win64" fn native_release_srw_lock_exclusive(ptr: *mut u64) {
    if let Some(word) = sync_word(ptr) {
        word.store(0, Ordering::Release);
        wake_word(word, true);
    }
}
pub(super) extern "win64" fn native_release_srw_lock_shared(ptr: *mut u64) {
    if let Some(word) = sync_word(ptr) {
        if word.fetch_sub(1, Ordering::Release) == 1 {
            wake_word(word, true);
        }
    }
}
pub(super) extern "win64" fn native_init_once_initialize(ptr: *mut u64) {
    native_initialize_srw_lock(ptr);
}
pub(super) extern "win64" fn native_init_once_begin_initialize(
    once: *mut u64,
    flags: u32,
    pending: *mut i32,
    context: *mut u64,
) -> i32 {
    let Some(word) = sync_word(once) else {
        native_set_last_error(87);
        return 0;
    };
    if pending.is_null() || flags & !3 != 0 || flags == 3 {
        native_set_last_error(87);
        return 0;
    }
    loop {
        let value = word.load(Ordering::Acquire);
        if value & 3 == 2 {
            unsafe {
                pending.write(0);
                if !context.is_null() {
                    context.write(value & !3);
                }
            }
            return 1;
        }
        if flags & 1 != 0 {
            native_set_last_error(31);
            return 0;
        }
        let running = if flags & 2 != 0 { 3 } else { 1 };
        if value == 0 {
            if word
                .compare_exchange(0, running, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
        } else if value != running {
            native_set_last_error(87);
            return 0;
        } else if running == 1 {
            wait_word(word, value, None);
            continue;
        }
        unsafe {
            pending.write(1);
        }
        return 1;
    }
}
pub(super) extern "win64" fn native_init_once_complete(
    once: *mut u64,
    flags: u32,
    context: u64,
) -> i32 {
    let Some(word) = sync_word(once) else {
        native_set_last_error(87);
        return 0;
    };
    if flags & !6 != 0 || context & 3 != 0 || (flags & 4 != 0 && (context != 0 || flags & 2 != 0)) {
        native_set_last_error(87);
        return 0;
    }
    let running = if flags & 2 != 0 { 3 } else { 1 };
    let completed = if flags & 4 != 0 { 0 } else { context | 2 };
    if word
        .compare_exchange(running, completed, Ordering::Release, Ordering::Relaxed)
        .is_err()
    {
        native_set_last_error(87);
        return 0;
    }
    wake_word(word, true);
    1
}
pub(super) extern "win64" fn native_init_once_execute_once(
    once: *mut u64,
    callback: u64,
    parameter: u64,
    context_out: *mut u64,
) -> i32 {
    if callback == 0 {
        native_set_last_error(87);
        return 0;
    }
    let mut pending = 0;
    if native_init_once_begin_initialize(once, 0, &mut pending, context_out) == 0 {
        return 0;
    }
    if pending == 0 {
        return 1;
    }
    let mut context = 0;
    let callback: unsafe extern "win64" fn(*mut u64, u64, *mut u64) -> i32 =
        unsafe { std::mem::transmute(callback) };
    let success = unsafe { callback(once, parameter, &mut context) } != 0;
    if native_init_once_complete(
        once,
        if success { 0 } else { 4 },
        if success { context } else { 0 },
    ) == 0
    {
        return 0;
    }
    if success && !context_out.is_null() {
        unsafe {
            context_out.write(context);
        }
    }
    success as i32
}
pub(super) extern "win64" fn native_initialize_condition_variable(ptr: *mut u64) {
    native_initialize_srw_lock(ptr);
}
pub(super) extern "win64" fn native_wake_condition_variable(ptr: *mut u64) {
    if let Some(word) = sync_word(ptr) {
        word.fetch_add(1, Ordering::Release);
        wake_word(word, false);
    }
}
pub(super) extern "win64" fn native_wake_all_condition_variable(ptr: *mut u64) {
    if let Some(word) = sync_word(ptr) {
        word.fetch_add(1, Ordering::Release);
        wake_word(word, true);
    }
}
fn wait_condition(word: &AtomicU64, before: u64, milliseconds: u32) -> i32 {
    let start = std::time::Instant::now();
    loop {
        if word.load(Ordering::Acquire) != before {
            return 1;
        }
        let timeout = if milliseconds == u32::MAX {
            None
        } else {
            let Some(remaining) =
                std::time::Duration::from_millis(milliseconds as u64).checked_sub(start.elapsed())
            else {
                native_set_last_error(1460);
                return 0;
            };
            Some(remaining)
        };
        wait_word(word, before, timeout);
    }
}
pub(super) extern "win64" fn native_sleep_condition_variable_srw(
    condition: *mut u64,
    lock: *mut u64,
    milliseconds: u32,
    flags: u32,
) -> i32 {
    let Some(word) = sync_word(condition) else {
        native_set_last_error(87);
        return 0;
    };
    if flags & !1 != 0 || sync_word(lock).is_none() {
        native_set_last_error(87);
        return 0;
    }
    let before = word.load(Ordering::Acquire);
    if flags & 1 != 0 {
        native_release_srw_lock_shared(lock);
    } else {
        native_release_srw_lock_exclusive(lock);
    }
    let result = wait_condition(word, before, milliseconds);
    acquire_srw(lock, flags & 1 == 0);
    result
}
pub(super) extern "win64" fn native_sleep_condition_variable_cs(
    condition: *mut u64,
    section: *mut u8,
    milliseconds: u32,
) -> i32 {
    let Some(word) = sync_word(condition) else {
        native_set_last_error(87);
        return 0;
    };
    if section.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let before = word.load(Ordering::Acquire);
    native_leave_critical_section(section);
    let result = wait_condition(word, before, milliseconds);
    native_enter_critical_section(section);
    result
}

pub(super) extern "win64" fn native_wait_for_single_object(handle: u64, milliseconds: u32) -> u32 {
    if native_diagnostic_enabled() {
        eprintln!("native WaitForSingleObject handle={handle:#x} timeout={milliseconds}");
    }
    if console_fd(handle) == Some(0) {
        return if console_input_ready(if milliseconds == u32::MAX {
            -1
        } else {
            milliseconds.min(i32::MAX as u32) as i32
        }) {
            0
        } else {
            258
        };
    }
    let process = process_ctx();
    if let Some(event) = process.as_ref().and_then(|process| {
        process
            .events
            .lock()
            .ok()
            .and_then(|events| events.get(&handle).cloned())
    }) {
        if let Some(process) = process.as_ref() {
            if let Some(result) = socket_event_wait(process, handle, &event, milliseconds) {
                return result;
            }
        }
        return native_wait_event(&event, milliseconds);
    }
    if let Some(timer) = process
        .as_ref()
        .and_then(|p| p.timers.lock().ok().and_then(|t| t.get(&handle).cloned()))
    {
        return wait_timer(&timer, milliseconds);
    }
    if let Some(semaphore) = process.as_ref().and_then(|process| {
        process
            .semaphores
            .lock()
            .ok()
            .and_then(|semaphores| semaphores.get(&handle).cloned())
    }) {
        let Ok(mut count) = semaphore.count.lock() else {
            return u32::MAX;
        };
        if milliseconds == u32::MAX {
            while *count == 0 {
                count = match semaphore.changed.wait(count) {
                    Ok(count) => count,
                    Err(_) => return u32::MAX,
                };
            }
        } else {
            let Ok((new_count, _)) = semaphore.changed.wait_timeout_while(
                count,
                std::time::Duration::from_millis(milliseconds as u64),
                |count| *count == 0,
            ) else {
                return u32::MAX;
            };
            count = new_count;
            if *count == 0 {
                return 258;
            } // WAIT_TIMEOUT
        }
        *count -= 1;
        return 0; // WAIT_OBJECT_0
    }
    if let Some(mutex) = lookup_mutex(handle) {
        return wait_mutex(&mutex, milliseconds);
    }
    if let Some(thread) = lookup_thread_handle(handle) {
        if thread.access & 0x100000 == 0 {
            native_set_last_error(5);
            return u32::MAX;
        }
        let deadline = wait_deadline(milliseconds);
        loop {
            if thread
                .queue
                .thread
                .status
                .lock()
                .is_ok_and(|status| status.exit_code.is_some())
            {
                return 0;
            }
            if wait_expired(deadline) {
                return 258;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    match handle {
        _ => {
            let Some(process) = process else {
                native_set_last_error(6);
                return 0xffff_ffff; // WAIT_FAILED
            };
            let Some(child) = child_process(&process, handle) else {
                native_set_last_error(6);
                return 0xffff_ffff;
            };
            let Ok(mut state) = child.state.lock() else {
                return 0xffff_ffff;
            };
            if state.is_some() {
                return 0; // WAIT_OBJECT_0
            }
            if milliseconds == 0 {
                return 258; // WAIT_TIMEOUT
            }
            if milliseconds == u32::MAX {
                while state.is_none() {
                    state = match child.exited.wait(state) {
                        Ok(state) => state,
                        Err(_) => return 0xffff_ffff,
                    };
                }
                return 0;
            }
            let result = match child.exited.wait_timeout_while(
                state,
                std::time::Duration::from_millis(milliseconds as u64),
                |state| state.is_none(),
            ) {
                Ok((state, _)) if state.is_some() => 0,
                Ok(_) => 258,
                Err(_) => 0xffff_ffff,
            };
            result
        }
    }
}
pub(super) fn native_wait_event(event: &NativeEvent, milliseconds: u32) -> u32 {
    let Ok(mut signaled) = event.signaled.lock() else {
        return u32::MAX;
    };
    if milliseconds == u32::MAX {
        while !*signaled {
            signaled = match event.ready.wait(signaled) {
                Ok(state) => state,
                Err(_) => return u32::MAX,
            };
        }
    } else if !*signaled {
        let Ok((state, _)) = event.ready.wait_timeout_while(
            signaled,
            std::time::Duration::from_millis(milliseconds as u64),
            |state| !*state,
        ) else {
            return u32::MAX;
        };
        signaled = state;
    }
    if !*signaled {
        return 258;
    }
    if !event.manual_reset {
        *signaled = false;
    }
    0
}
pub(super) fn native_signal_event(event: &NativeEvent) {
    if let Ok(mut signaled) = event.signaled.lock() {
        *signaled = true;
        if event.manual_reset {
            event.ready.notify_all();
        } else {
            event.ready.notify_one();
        }
    }
}
pub(super) extern "win64" fn native_create_event_w(
    _attributes: u64,
    manual_reset: i32,
    initial_state: i32,
    name: *const u16,
) -> u64 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let name = if name.is_null() {
        None
    } else {
        match wide(name) {
            Some(name) if !name.is_empty() => Some(name),
            _ => {
                native_set_last_error(87);
                return 0;
            }
        }
    };
    let event = if let Some(name) = name {
        let Ok(mut names) = process.event_names.lock() else {
            return 0;
        };
        if let Some(event) = names.get(&name).and_then(std::sync::Weak::upgrade) {
            native_set_last_error(183); // ERROR_ALREADY_EXISTS
            event
        } else {
            let event = Arc::new(NativeEvent {
                signaled: Mutex::new(initial_state != 0),
                ready: Condvar::new(),
                manual_reset: manual_reset != 0,
            });
            names.insert(name, Arc::downgrade(&event));
            native_set_last_error(0);
            event
        }
    } else {
        Arc::new(NativeEvent {
            signaled: Mutex::new(initial_state != 0),
            ready: Condvar::new(),
            manual_reset: manual_reset != 0,
        })
    };
    let handle = process.event_next.fetch_add(4, Ordering::AcqRel);
    let result = match process.events.lock() {
        Ok(mut events) => {
            events.insert(handle, event);
            handle
        }
        Err(_) => 0,
    };
    result
}
/// `OpenEventW`: a new handle to an existing named event of this process,
/// or `ERROR_FILE_NOT_FOUND`.
pub(super) extern "win64" fn native_open_event_w(
    _access: u32,
    _inherit: i32,
    name: *const u16,
) -> u64 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Some(name) = wide(name).filter(|name| !name.is_empty()) else {
        native_set_last_error(87);
        return 0;
    };
    let event = process
        .event_names
        .lock()
        .ok()
        .and_then(|names| names.get(&name).and_then(std::sync::Weak::upgrade));
    let Some(event) = event else {
        native_set_last_error(2);
        return 0;
    };
    let handle = process.event_next.fetch_add(4, Ordering::AcqRel);
    let inserted = match process.events.lock() {
        Ok(mut events) => {
            events.insert(handle, event);
            true
        }
        Err(_) => false,
    };
    if !inserted {
        return 0;
    }
    native_set_last_error(0);
    handle
}

pub(super) extern "win64" fn native_create_event_ex_w(
    attributes: u64,
    name: *const u16,
    flags: u32,
    _access: u32,
) -> u64 {
    if flags & !3 != 0 {
        native_set_last_error(87);
        return 0;
    }
    native_create_event_w(attributes, (flags & 1) as i32, (flags & 2) as i32, name)
}
pub(super) extern "win64" fn native_create_event_a(
    attributes: u64,
    manual_reset: i32,
    initial_state: i32,
    name: *const u8,
) -> u64 {
    if name.is_null() {
        return native_create_event_w(attributes, manual_reset, initial_state, std::ptr::null());
    }
    let Some((bytes, _)) = (unsafe { multibyte_input(name, -1) }) else {
        native_set_last_error(87);
        return 0;
    };
    let wide: Vec<u16> = bytes
        .into_iter()
        .map(u16::from)
        .chain(std::iter::once(0))
        .collect();
    native_create_event_w(attributes, manual_reset, initial_state, wide.as_ptr())
}
pub(super) extern "win64" fn native_create_event_ex_a(
    attributes: u64,
    name: *const u8,
    flags: u32,
    _access: u32,
) -> u64 {
    if flags & !3 != 0 {
        native_set_last_error(87);
        return 0;
    }
    native_create_event_a(attributes, (flags & 1) as i32, (flags & 2) as i32, name)
}
pub(super) extern "win64" fn native_set_event(handle: u64) -> i32 {
    let event = process_ctx().and_then(|process| {
        process
            .events
            .lock()
            .ok()
            .and_then(|events| events.get(&handle).cloned())
    });
    let Some(event) = event else {
        native_set_last_error(6);
        return 0;
    };
    native_signal_event(&event);
    1
}
pub(super) extern "win64" fn native_reset_event(handle: u64) -> i32 {
    let event = process_ctx().and_then(|process| {
        process
            .events
            .lock()
            .ok()
            .and_then(|events| events.get(&handle).cloned())
    });
    let Some(event) = event else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut signaled) = event.signaled.lock() else {
        return 0;
    };
    *signaled = false;
    1
}
pub(super) extern "win64" fn native_create_semaphore_a(
    _attributes: *const u8,
    initial: i32,
    maximum: i32,
    _name: *const u8,
) -> u64 {
    if initial < 0 || maximum <= 0 || initial > maximum {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let handle = process.semaphore_next.fetch_add(1, Ordering::AcqRel);
    let semaphore = Arc::new(NativeSemaphore {
        count: Mutex::new(initial),
        changed: Condvar::new(),
        maximum,
    });
    if process.semaphores.lock().is_ok_and(|mut values| {
        values.insert(handle, semaphore);
        true
    }) {
        handle
    } else {
        0
    }
}
pub(super) extern "win64" fn native_release_semaphore(
    handle: u64,
    release: i32,
    previous: *mut i32,
) -> i32 {
    let Some(semaphore) = process_ctx().and_then(|process| {
        process
            .semaphores
            .lock()
            .ok()
            .and_then(|values| values.get(&handle).cloned())
    }) else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut count) = semaphore.count.lock() else {
        return 0;
    };
    if release <= 0 || release > semaphore.maximum - *count {
        native_set_last_error(298); // ERROR_TOO_MANY_POSTS
        return 0;
    }
    if !previous.is_null() {
        unsafe { previous.write(*count) };
    }
    *count += release;
    semaphore.changed.notify_all();
    1
}

struct NativeWaitCallbackInvocation {
    callback: u64,
    context: u64,
}
pub(super) extern "win64" fn native_wait_callback_entry(parameter: u64) -> u32 {
    if parameter == 0 {
        return 0;
    }
    let invocation = unsafe { Box::from_raw(parameter as *mut NativeWaitCallbackInvocation) };
    let callback: unsafe extern "win64" fn(u64, i32) =
        unsafe { std::mem::transmute(invocation.callback) };
    unsafe { callback(invocation.context, 0) };
    0
}
pub(super) extern "win64" fn native_register_wait_for_single_object(
    output: *mut u64,
    object: u64,
    callback: u64,
    context: u64,
    milliseconds: u32,
    flags: u32,
) -> i32 {
    if output.is_null() || callback == 0 || milliseconds != u32::MAX || flags & !0x3f != 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let target = if console_fd(object) == Some(0) {
        NativeWaitTarget::ConsoleInput
    } else if let Some(child) = child_process(&process, object) {
        NativeWaitTarget::Child(child)
    } else {
        native_set_last_error(6);
        return 0;
    };
    let handle = process.completion_next.fetch_add(1, Ordering::AcqRel);
    let registration = Arc::new(NativeWaitRegistration {
        callback,
        context,
        target,
        cancelled: Arc::new(AtomicBool::new(false)),
        execute_once: flags & 0x8 != 0,
    });
    if !process.wait_registrations.lock().is_ok_and(|mut waits| {
        waits.insert(handle, Arc::clone(&registration));
        true
    }) {
        native_set_last_error(6);
        return 0;
    }
    let worker_process = Arc::clone(&process);
    if std::thread::Builder::new()
        .name("winrun-object-wait".into())
        .spawn(move || {
            loop {
                if registration.cancelled.load(Ordering::Acquire) {
                    break;
                }
                let signaled = match &registration.target {
                    NativeWaitTarget::Child(child) => {
                        child.state.lock().is_ok_and(|state| state.is_some())
                    }
                    NativeWaitTarget::ConsoleInput => console_input_ready(0),
                };
                if signaled {
                    let invocation = Box::new(NativeWaitCallbackInvocation {
                        callback: registration.callback,
                        context: registration.context,
                    });
                    let parameter = Box::into_raw(invocation) as u64;
                    if native_create_thread(
                        0,
                        0,
                        native_wait_callback_entry as *const () as usize as u64,
                        parameter,
                        0,
                        std::ptr::null_mut(),
                    ) == 0
                    {
                        unsafe {
                            drop(Box::from_raw(
                                parameter as *mut NativeWaitCallbackInvocation,
                            ));
                        }
                    }
                    if registration.execute_once {
                        break;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if registration.execute_once {
                if let Ok(mut waits) = worker_process.wait_registrations.lock() {
                    waits.remove(&handle);
                }
            }
        })
        .is_err()
    {
        process
            .wait_registrations
            .lock()
            .ok()
            .map(|mut waits| waits.remove(&handle));
        native_set_last_error(8);
        return 0;
    }
    unsafe { output.write(handle) };
    1
}
pub(super) extern "win64" fn native_unregister_wait_ex(wait: u64, completion_event: u64) -> i32 {
    let registration = process_ctx().and_then(|process| {
        process
            .wait_registrations
            .lock()
            .ok()
            .and_then(|mut waits| waits.remove(&wait))
    });
    let Some(registration) = registration else {
        native_set_last_error(6);
        return 0;
    };
    registration.cancelled.store(true, Ordering::Release);
    if completion_event != 0 && completion_event != u64::MAX {
        let _ = native_set_event(completion_event);
    }
    1
}

static NATIVE_SLIST_LOCK: Mutex<()> = Mutex::new(());
static NATIVE_CRITICAL_SECTIONS: LazyLock<Mutex<HashMap<usize, Arc<NativeCriticalSection>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NATIVE_ADDRESS_WAITERS: LazyLock<Mutex<HashMap<usize, Weak<NativeAddressWaiters>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct NativeCriticalSection {
    owner_and_recursion: Mutex<(Option<u64>, u32)>,
    ready: Condvar,
}

impl NativeCriticalSection {
    fn new() -> Self {
        Self {
            owner_and_recursion: Mutex::new((None, 0)),
            ready: Condvar::new(),
        }
    }
}

struct NativeAddressWaiters {
    generation: Mutex<u64>,
    ready: Condvar,
}

impl NativeAddressWaiters {
    fn new() -> Self {
        Self {
            generation: Mutex::new(0),
            ready: Condvar::new(),
        }
    }
}

pub(super) extern "win64" fn native_wait_on_address(
    address: *const u8,
    compare: *const u8,
    size: usize,
    milliseconds: u32,
) -> i32 {
    if address.is_null()
        || compare.is_null()
        || !(1..=8).contains(&size)
        || (address as usize) % size != 0
    {
        native_set_last_error(87);
        return 0;
    }
    let expected = unsafe { native_compare_value(compare, size) };
    let equal = || unsafe { native_address_value(address, size) == expected };
    if !equal() {
        return 1;
    }
    let waiter = match NATIVE_ADDRESS_WAITERS.lock() {
        Ok(mut waiters) => {
            waiters.retain(|_, waiter| waiter.strong_count() > 0);
            if let Some(waiter) = waiters.get(&(address as usize)).and_then(Weak::upgrade) {
                waiter
            } else {
                let waiter = Arc::new(NativeAddressWaiters::new());
                waiters.insert(address as usize, Arc::downgrade(&waiter));
                waiter
            }
        }
        Err(_) => return 0,
    };
    let Ok(generation) = waiter.generation.lock() else {
        return 0;
    };
    let before = *generation;
    if !equal() {
        return 1;
    }
    let changed = if milliseconds == u32::MAX {
        waiter
            .ready
            .wait_while(generation, |current| equal() && *current == before)
            .is_ok_and(|generation| !equal() || *generation != before)
    } else {
        waiter
            .ready
            .wait_timeout_while(
                generation,
                std::time::Duration::from_millis(milliseconds as u64),
                |current| equal() && *current == before,
            )
            .map(|(generation, _)| !equal() || *generation != before)
            .unwrap_or(false)
    };
    if changed {
        1
    } else {
        native_set_last_error(1460);
        0
    }
}

unsafe fn native_address_value(address: *const u8, size: usize) -> u64 {
    match size {
        1 => (*(address as *const std::sync::atomic::AtomicU8)).load(Ordering::Acquire) as u64,
        2 => (*(address as *const std::sync::atomic::AtomicU16)).load(Ordering::Acquire) as u64,
        4 => (*(address as *const AtomicU32)).load(Ordering::Acquire) as u64,
        8 => (*(address as *const AtomicU64)).load(Ordering::Acquire),
        _ => 0,
    }
}

unsafe fn native_compare_value(address: *const u8, size: usize) -> u64 {
    match size {
        1 => address.read() as u64,
        2 => address.cast::<u16>().read_unaligned() as u64,
        4 => address.cast::<u32>().read_unaligned() as u64,
        8 => address.cast::<u64>().read_unaligned(),
        _ => 0,
    }
}

fn native_wake_address(address: *const u8, all: bool) {
    if address.is_null() {
        return;
    }
    let waiter = NATIVE_ADDRESS_WAITERS
        .lock()
        .ok()
        .and_then(|waiters| waiters.get(&(address as usize)).and_then(Weak::upgrade));
    let Some(waiter) = waiter else { return };
    if let Ok(mut generation) = waiter.generation.lock() {
        *generation = generation.wrapping_add(1);
        if all {
            waiter.ready.notify_all();
        } else {
            waiter.ready.notify_one();
        }
    };
}

pub(super) extern "win64" fn native_wake_by_address_all(address: *const u8) {
    native_wake_address(address, true);
}

pub(super) extern "win64" fn native_wake_by_address_single(address: *const u8) {
    native_wake_address(address, false);
}
pub(super) extern "win64" fn native_create_waitable_timer_ex_w(
    _attributes: *const u8,
    _name: *const u16,
    flags: u32,
    _access: u32,
) -> u64 {
    if flags & !3 != 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let handle = process.timer_next.fetch_add(1, Ordering::AcqRel);
    process.timers.lock().unwrap().insert(
        handle,
        Arc::new(NativeWaitableTimer {
            manual_reset: flags & 1 != 0,
            state: Mutex::new(NativeTimerState {
                deadline: None,
                period: 0,
                signaled: false,
            }),
            changed: Condvar::new(),
        }),
    );
    handle
}
pub(super) extern "win64" fn native_create_waitable_timer_a(
    attributes: *const u8,
    manual: i32,
    name: *const u8,
) -> u64 {
    let name = unsafe { ascii_z(name) }.map(|s| s.encode_utf16().chain([0]).collect::<Vec<_>>());
    native_create_waitable_timer_ex_w(
        attributes,
        name.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
        u32::from(manual != 0),
        0x1f0003,
    )
}
pub(super) extern "win64" fn native_set_waitable_timer(
    handle: u64,
    due_time: *const i64,
    period: i32,
    completion: u64,
    _arg: u64,
    _resume: i32,
) -> i32 {
    if due_time.is_null() || period < 0 {
        native_set_last_error(87);
        return 0;
    }
    if completion != 0 {
        native_set_last_error(50);
        return 0;
    }
    let Some(timer) =
        process_ctx().and_then(|p| p.timers.lock().ok().and_then(|t| t.get(&handle).cloned()))
    else {
        native_set_last_error(6);
        return 0;
    };
    let due = unsafe { due_time.read_unaligned() };
    let ticks = if due < 0 {
        due.unsigned_abs()
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            / 100
            + 116_444_736_000_000_000;
        (due as u64).saturating_sub(now as u64)
    };
    let Some(nanos) = ticks.checked_mul(100) else {
        native_set_last_error(87);
        return 0;
    };
    let Some(deadline) =
        std::time::Instant::now().checked_add(std::time::Duration::from_nanos(nanos))
    else {
        native_set_last_error(87);
        return 0;
    };
    let mut state = timer.state.lock().unwrap();
    state.deadline = Some(deadline);
    state.period = period as u32;
    state.signaled = false;
    timer.changed.notify_all();
    1
}
pub(super) extern "win64" fn native_cancel_waitable_timer(handle: u64) -> i32 {
    let Some(timer) =
        process_ctx().and_then(|p| p.timers.lock().ok().and_then(|t| t.get(&handle).cloned()))
    else {
        native_set_last_error(6);
        return 0;
    };
    let mut state = timer.state.lock().unwrap();
    update_timer_state(&mut state);
    state.deadline = None;
    timer.changed.notify_all();
    1
}
fn update_timer_state(state: &mut NativeTimerState) {
    let now = std::time::Instant::now();
    if state.deadline.is_some_and(|deadline| deadline <= now) {
        state.signaled = true;
        state.deadline = if state.period != 0 {
            Some(now + std::time::Duration::from_millis(state.period as u64))
        } else {
            None
        };
    }
}

fn wait_timer(timer: &NativeWaitableTimer, milliseconds: u32) -> u32 {
    let expires = (milliseconds != u32::MAX)
        .then(|| std::time::Instant::now() + std::time::Duration::from_millis(milliseconds as u64));
    let mut state = timer.state.lock().unwrap();
    loop {
        let now = std::time::Instant::now();
        update_timer_state(&mut state);
        if state.signaled {
            state.signaled = timer.manual_reset;
            return 0;
        }
        if expires.is_some_and(|expires| expires <= now) {
            return 258;
        }
        let wake = match (expires, state.deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        state = if let Some(wake) = wake {
            timer
                .changed
                .wait_timeout(state, wake.saturating_duration_since(now))
                .unwrap()
                .0
        } else {
            timer.changed.wait(state).unwrap()
        };
    }
}

fn native_critical_section(section: *mut u8) -> Option<Arc<NativeCriticalSection>> {
    if section.is_null() {
        return None;
    }
    let mut sections = NATIVE_CRITICAL_SECTIONS.lock().ok()?;
    Some(
        sections
            .entry(section as usize)
            .or_insert_with(|| Arc::new(NativeCriticalSection::new()))
            .clone(),
    )
}

fn native_critical_section_owner() -> u64 {
    THREAD_NATIVE_HANDLE.with(|handle| handle.get())
}

pub(super) extern "win64" fn native_enter_critical_section(section: *mut u8) {
    let Some(section) = native_critical_section(section) else {
        return;
    };
    let owner = native_critical_section_owner();
    let Ok(mut state) = section.owner_and_recursion.lock() else {
        return;
    };
    while state.0.is_some_and(|current| current != owner) {
        state = match section.ready.wait(state) {
            Ok(state) => state,
            Err(_) => return,
        };
    }
    state.0 = Some(owner);
    state.1 = state.1.saturating_add(1);
}

pub(super) extern "win64" fn native_leave_critical_section(section: *mut u8) {
    let Some(section) = native_critical_section(section) else {
        return;
    };
    let owner = native_critical_section_owner();
    let Ok(mut state) = section.owner_and_recursion.lock() else {
        return;
    };
    if state.0 != Some(owner) || state.1 == 0 {
        return;
    }
    state.1 -= 1;
    if state.1 == 0 {
        state.0 = None;
        section.ready.notify_one();
    }
}

pub(super) extern "win64" fn native_delete_critical_section(section: *mut u8) {
    if !section.is_null() {
        if let Ok(mut sections) = NATIVE_CRITICAL_SECTIONS.lock() {
            sections.remove(&(section as usize));
        }
        unsafe { std::ptr::write_bytes(section, 0, 40) };
    }
}

pub(super) extern "win64" fn native_initialize_slist_head(head: *mut u8) {
    if !head.is_null() {
        // SLIST_HEADER occupies 16 bytes on 64-bit Windows.
        unsafe { std::ptr::write_bytes(head, 0, 16) };
    }
}

pub(super) extern "win64" fn native_interlocked_push_entry_slist(
    head: *mut u8,
    entry: *mut u8,
) -> *mut u8 {
    if native_diagnostic_enabled() {
        eprintln!("native InterlockedPushEntrySList head={head:p} entry={entry:p}");
    }
    if head.is_null() || entry.is_null() || (head as usize) & 15 != 0 || (entry as usize) & 15 != 0
    {
        return ptr::null_mut();
    }
    let Ok(_guard) = NATIVE_SLIST_LOCK.lock() else {
        return ptr::null_mut();
    };
    unsafe {
        let first = head as *mut u64;
        let depth = head.add(8) as *mut u16;
        let previous = first.read();
        (entry as *mut u64).write(previous);
        first.write(entry as u64);
        depth.write(depth.read().wrapping_add(1));
        previous as *mut u8
    }
}

pub(super) extern "win64" fn native_interlocked_pop_entry_slist(head: *mut u8) -> *mut u8 {
    if native_diagnostic_enabled() {
        eprintln!("native InterlockedPopEntrySList head={head:p}");
    }
    if head.is_null() || (head as usize) & 15 != 0 {
        return ptr::null_mut();
    }
    let Ok(_guard) = NATIVE_SLIST_LOCK.lock() else {
        return ptr::null_mut();
    };
    unsafe {
        let first = head as *mut u64;
        let depth = head.add(8) as *mut u16;
        let entry = first.read();
        if entry == 0 {
            return ptr::null_mut();
        }
        first.write((entry as *const u64).read());
        depth.write(depth.read().wrapping_sub(1));
        entry as *mut u8
    }
}

pub(super) extern "win64" fn native_interlocked_flush_slist(head: *mut u8) -> *mut u8 {
    if native_diagnostic_enabled() {
        eprintln!("native InterlockedFlushSList head={head:p}");
    }
    if head.is_null() || (head as usize) & 15 != 0 {
        return ptr::null_mut();
    }
    let Ok(_guard) = NATIVE_SLIST_LOCK.lock() else {
        return ptr::null_mut();
    };
    unsafe {
        let first = head as *mut u64;
        let depth = head.add(8) as *mut u16;
        let entries = first.read();
        first.write(0);
        depth.write(0);
        entries as *mut u8
    }
}

pub(super) extern "win64" fn native_query_depth_slist(head: *const u8) -> u16 {
    if native_diagnostic_enabled() {
        eprintln!("native QueryDepthSList head={head:p}");
    }
    if head.is_null() || (head as usize) & 15 != 0 {
        return 0;
    }
    let Ok(_guard) = NATIVE_SLIST_LOCK.lock() else {
        return 0;
    };
    unsafe { head.add(8).cast::<u16>().read() }
}

pub(super) extern "win64" fn native_sleep(milliseconds: u32) {
    std::thread::sleep(std::time::Duration::from_millis(milliseconds as u64));
}
pub(super) extern "win64" fn native_switch_to_thread() -> i32 {
    std::thread::yield_now();
    1
}

const WAIT_TIMEOUT: u32 = 258;
const WAIT_ABANDONED_0: u32 = 0x80;
const WAIT_FAILED: u32 = u32::MAX;

/// `WaitForMultipleObjects(Ex)` over the single-object wait: "any" polls
/// each handle until one is signaled (returning `WAIT_OBJECT_0 + i` or
/// `WAIT_ABANDONED_0 + i`); "all" consumes object states only when every
/// object is ready. Alertable waits dispatch callbacks on the calling thread.
pub(super) extern "win64" fn native_wait_for_multiple_objects_ex(
    count: u32,
    handles: *const u64,
    wait_all: i32,
    milliseconds: u32,
    alertable: i32,
) -> u32 {
    if count == 0 || count > 64 || handles.is_null() {
        native_set_last_error(87);
        return WAIT_FAILED;
    }
    let handles: Vec<u64> = (0..count as usize)
        .map(|index| unsafe { handles.add(index).read_unaligned() })
        .collect();
    let deadline = (milliseconds != u32::MAX).then(|| {
        std::time::Instant::now() + std::time::Duration::from_millis(u64::from(milliseconds))
    });
    let remaining = || match deadline {
        None => u32::MAX,
        Some(deadline) => deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .min(u128::from(u32::MAX - 1)) as u32,
    };
    if wait_all != 0 {
        loop {
            if alertable != 0 && dispatch_apcs() {
                return WAIT_IO_COMPLETION;
            }
            let result = poll_wait_all(&handles);
            if result != WAIT_TIMEOUT {
                return result;
            }
            if remaining() == 0 {
                return WAIT_TIMEOUT;
            }
            if alertable != 0 {
                apc_pause();
            } else {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
    loop {
        if alertable != 0 && dispatch_apcs() {
            return WAIT_IO_COMPLETION;
        }
        for (index, handle) in handles.iter().enumerate() {
            match native_wait_for_single_object(*handle, 0) {
                0 => return index as u32,
                WAIT_ABANDONED_0 => return WAIT_ABANDONED_0 + index as u32,
                WAIT_TIMEOUT => {}
                failed => return failed,
            }
        }
        if remaining() == 0 {
            return WAIT_TIMEOUT;
        }
        if alertable != 0 {
            apc_pause();
        } else {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

// Hold all consuming object states until every object is signaled. An APC or
// timeout must not consume an earlier auto-reset event or semaphore count.
enum WaitAllObject {
    Event(Arc<NativeEvent>),
    Semaphore(Arc<NativeSemaphore>),
    Timer(Arc<NativeWaitableTimer>),
    Mutex(Arc<NativeMutex>),
    Other(u64),
}
enum WaitAllState<'a> {
    Event(std::sync::MutexGuard<'a, bool>, bool),
    Semaphore(std::sync::MutexGuard<'a, i32>),
    Timer(std::sync::MutexGuard<'a, NativeTimerState>, bool),
    Mutex(HeldMutex<'a>),
    Other,
}
fn poll_wait_all(handles: &[u64]) -> u32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return WAIT_FAILED;
    };
    let mut sorted = handles.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        native_set_last_error(87);
        return WAIT_FAILED;
    }
    let mut objects: Vec<_> = sorted
        .into_iter()
        .map(|handle| {
            if let Some(event) = process
                .events
                .lock()
                .ok()
                .and_then(|objects| objects.get(&handle).cloned())
            {
                refresh_socket_event(&process, handle);
                return WaitAllObject::Event(event);
            }
            if let Some(semaphore) = process
                .semaphores
                .lock()
                .ok()
                .and_then(|objects| objects.get(&handle).cloned())
            {
                return WaitAllObject::Semaphore(semaphore);
            }
            if let Some(timer) = process
                .timers
                .lock()
                .ok()
                .and_then(|objects| objects.get(&handle).cloned())
            {
                return WaitAllObject::Timer(timer);
            }
            if let Some(mutex) = lookup_mutex(handle) {
                return WaitAllObject::Mutex(mutex);
            }
            WaitAllObject::Other(handle)
        })
        .collect();
    let identity = |object: &WaitAllObject| match object {
        WaitAllObject::Event(event) => (0, Arc::as_ptr(event) as usize),
        WaitAllObject::Semaphore(semaphore) => (1, Arc::as_ptr(semaphore) as usize),
        WaitAllObject::Timer(timer) => (2, Arc::as_ptr(timer) as usize),
        WaitAllObject::Mutex(mutex) => (3, Arc::as_ptr(mutex) as usize),
        WaitAllObject::Other(handle) => (4, *handle as usize),
    };
    objects.sort_unstable_by_key(identity);
    if objects
        .windows(2)
        .any(|pair| identity(&pair[0]) == identity(&pair[1]))
    {
        native_set_last_error(87);
        return WAIT_FAILED;
    }
    let mut states = Vec::new();
    let mut ready = true;
    for object in &objects {
        let state = match object {
            WaitAllObject::Event(event) => match event.signaled.lock() {
                Ok(state) => {
                    ready &= *state;
                    WaitAllState::Event(state, event.manual_reset)
                }
                Err(_) => return WAIT_FAILED,
            },
            WaitAllObject::Semaphore(semaphore) => match semaphore.count.lock() {
                Ok(state) => {
                    ready &= *state > 0;
                    WaitAllState::Semaphore(state)
                }
                Err(_) => return WAIT_FAILED,
            },
            WaitAllObject::Timer(timer) => match timer.state.lock() {
                Ok(mut state) => {
                    update_timer_state(&mut state);
                    ready &= state.signaled;
                    WaitAllState::Timer(state, timer.manual_reset)
                }
                Err(_) => return WAIT_FAILED,
            },
            WaitAllObject::Mutex(mutex) => match HeldMutex::lock(mutex) {
                Some(state) => {
                    ready &= state.ready();
                    WaitAllState::Mutex(state)
                }
                None => return WAIT_FAILED,
            },
            WaitAllObject::Other(handle) => match native_wait_for_single_object(*handle, 0) {
                0 => WaitAllState::Other,
                WAIT_TIMEOUT => {
                    ready = false;
                    WaitAllState::Other
                }
                failed => return failed,
            },
        };
        states.push(state);
    }
    if !ready {
        return WAIT_TIMEOUT;
    }
    for state in &mut states {
        match state {
            WaitAllState::Event(state, manual) => **state = *manual,
            WaitAllState::Semaphore(state) => **state -= 1,
            WaitAllState::Timer(state, manual) => state.signaled = *manual,
            WaitAllState::Mutex(state) => state.acquire(),
            WaitAllState::Other => {}
        }
    }
    0
}

pub(super) extern "win64" fn native_wait_for_multiple_objects(
    count: u32,
    handles: *const u64,
    wait_all: i32,
    milliseconds: u32,
) -> u32 {
    native_wait_for_multiple_objects_ex(count, handles, wait_all, milliseconds, 0)
}

/// `SignalObjectAndWait`: signal an event (or release a semaphore), then
/// wait on the other object.
pub(super) extern "win64" fn native_signal_object_and_wait(
    signal: u64,
    wait: u64,
    milliseconds: u32,
    alertable: i32,
) -> u32 {
    if native_set_event(signal) == 0
        && native_release_semaphore(signal, 1, std::ptr::null_mut()) == 0
    {
        native_set_last_error(6);
        return WAIT_FAILED;
    }
    native_wait_for_single_object_ex(wait, milliseconds, alertable)
}

#[cfg(test)]
mod inline_sync_tests {
    use super::*;

    #[test]
    fn srw_churn_returns_to_zero_and_contended_writers_preserve_updates() {
        for _ in 0..10000 {
            let mut lock = 0;
            native_acquire_srw_lock_exclusive(&mut lock);
            native_release_srw_lock_exclusive(&mut lock);
            assert_eq!(lock, 0);
            native_acquire_srw_lock_shared(&mut lock);
            native_release_srw_lock_shared(&mut lock);
            assert_eq!(lock, 0);
        }
        let lock = AtomicU64::new(0);
        let value = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let ptr = (&lock as *const AtomicU64).cast_mut().cast();
                    for _ in 0..1000 {
                        native_acquire_srw_lock_exclusive(ptr);
                        value.store(value.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
                        native_release_srw_lock_exclusive(ptr);
                    }
                });
            }
        });
        assert_eq!(value.load(Ordering::Relaxed), 8000);
        assert_eq!(lock.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn concurrent_init_once_publishes_context_and_runs_callback_once() {
        unsafe extern "win64" fn initialize(_: *mut u64, parameter: u64, context: *mut u64) -> i32 {
            unsafe {
                (*(parameter as *const AtomicU64)).fetch_add(1, Ordering::Relaxed);
                context.write(0x1000);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            1
        }
        let once = AtomicU64::new(0);
        let calls = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let mut context = 0;
                    assert_eq!(
                        native_init_once_execute_once(
                            (&once as *const AtomicU64).cast_mut().cast(),
                            initialize as *const () as u64,
                            &calls as *const AtomicU64 as u64,
                            &mut context
                        ),
                        1
                    );
                    assert_eq!(context, 0x1000);
                });
            }
        });
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(once.load(Ordering::Relaxed), 0x1002);
    }
}
