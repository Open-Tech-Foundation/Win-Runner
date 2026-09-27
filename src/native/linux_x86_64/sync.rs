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
pub(super) extern "win64" fn native_initialize_srw_lock(lock: *mut u64) {
    if !lock.is_null() {
        unsafe { lock.write_unaligned(0) };
    }
}
// The guard fields are held for their lock lifetime and released by Drop.
#[allow(dead_code)]
enum HeldSrwLock {
    Shared(std::sync::RwLockReadGuard<'static, ()>),
    Exclusive(std::sync::RwLockWriteGuard<'static, ()>),
}
thread_local! {
    static HELD_SRW_LOCKS: std::cell::RefCell<Vec<(usize, HeldSrwLock)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
fn native_srw_lock(lock: *mut u64) -> Option<&'static std::sync::RwLock<()>> {
    if lock.is_null() || (lock as usize) % std::mem::align_of::<AtomicU64>() != 0 {
        return None;
    }
    let slot = unsafe { &*(lock as *const AtomicU64) };
    let mut value = slot.load(Ordering::Acquire);
    if value == 0 {
        let created = Box::into_raw(Box::new(std::sync::RwLock::new(()))) as u64;
        match slot.compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => value = created,
            Err(existing) => {
                unsafe { drop(Box::from_raw(created as *mut std::sync::RwLock<()>)) };
                value = existing;
            }
        }
    }
    (value != 0).then(|| unsafe { &*(value as *const std::sync::RwLock<()>) })
}
pub(super) extern "win64" fn native_acquire_srw_lock_exclusive(lock: *mut u64) {
    if let Some(host) = native_srw_lock(lock) {
        let guard = host.write().unwrap_or_else(|poison| poison.into_inner());
        HELD_SRW_LOCKS.with(|held| {
            held.borrow_mut()
                .push((lock as usize, HeldSrwLock::Exclusive(guard)))
        });
    }
}
pub(super) extern "win64" fn native_acquire_srw_lock_shared(lock: *mut u64) {
    if let Some(host) = native_srw_lock(lock) {
        let guard = host.read().unwrap_or_else(|poison| poison.into_inner());
        HELD_SRW_LOCKS.with(|held| {
            held.borrow_mut()
                .push((lock as usize, HeldSrwLock::Shared(guard)))
        });
    }
}
pub(super) extern "win64" fn native_try_acquire_srw_lock_exclusive(lock: *mut u64) -> i32 {
    let Some(host) = native_srw_lock(lock) else {
        return 0;
    };
    let Ok(guard) = host.try_write() else {
        return 0;
    };
    HELD_SRW_LOCKS.with(|held| {
        held.borrow_mut()
            .push((lock as usize, HeldSrwLock::Exclusive(guard)))
    });
    1
}
pub(super) extern "win64" fn native_try_acquire_srw_lock_shared(lock: *mut u64) -> i32 {
    let Some(host) = native_srw_lock(lock) else {
        return 0;
    };
    let Ok(guard) = host.try_read() else { return 0 };
    HELD_SRW_LOCKS.with(|held| {
        held.borrow_mut()
            .push((lock as usize, HeldSrwLock::Shared(guard)))
    });
    1
}
fn take_srw_lock(lock: *mut u64, exclusive: bool) -> Option<HeldSrwLock> {
    HELD_SRW_LOCKS.with(|held| {
        let mut held = held.borrow_mut();
        held.iter()
            .rposition(|(address, guard)| {
                *address == lock as usize
                    && matches!(
                        (exclusive, guard),
                        (true, HeldSrwLock::Exclusive(_)) | (false, HeldSrwLock::Shared(_))
                    )
            })
            .map(|index| held.remove(index).1)
    })
}
fn native_release_srw_lock(lock: *mut u64, exclusive: bool) {
    drop(take_srw_lock(lock, exclusive));
}
pub(super) extern "win64" fn native_release_srw_lock_exclusive(lock: *mut u64) {
    native_release_srw_lock(lock, true);
}
pub(super) extern "win64" fn native_release_srw_lock_shared(lock: *mut u64) {
    native_release_srw_lock(lock, false);
}
struct NativeConditionVariable {
    generation: Mutex<u64>,
    ready: Condvar,
}
struct NativeInitOnce {
    state: Mutex<InitOnceState>,
    ready: Condvar,
}
enum InitOnceState {
    Uninitialized,
    Running,
    Complete(u64),
}
fn native_init_once(ptr: *mut u64) -> Option<&'static NativeInitOnce> {
    if ptr.is_null() || (ptr as usize) % std::mem::align_of::<AtomicU64>() != 0 {
        return None;
    }
    let slot = unsafe { &*(ptr as *const AtomicU64) };
    let mut value = slot.load(Ordering::Acquire);
    if value == 0 {
        let created = Box::into_raw(Box::new(NativeInitOnce {
            state: Mutex::new(InitOnceState::Uninitialized),
            ready: Condvar::new(),
        })) as u64;
        match slot.compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => value = created,
            Err(existing) => {
                unsafe { drop(Box::from_raw(created as *mut NativeInitOnce)) };
                value = existing;
            }
        }
    }
    (value != 0).then(|| unsafe { &*(value as *const NativeInitOnce) })
}
pub(super) extern "win64" fn native_init_once_initialize(ptr: *mut u64) {
    if !ptr.is_null() {
        unsafe { ptr.write_unaligned(0) };
    }
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
    let Some(init) = native_init_once(once) else {
        native_set_last_error(87);
        return 0;
    };
    loop {
        let Ok(mut state) = init.state.lock() else {
            return 0;
        };
        match *state {
            InitOnceState::Complete(context) => {
                if !context_out.is_null() {
                    unsafe { context_out.write_unaligned(context) };
                }
                return 1;
            }
            InitOnceState::Running => {
                drop(init.ready.wait(state));
            }
            InitOnceState::Uninitialized => {
                *state = InitOnceState::Running;
                drop(state);
                let mut context = 0u64;
                let callback: unsafe extern "win64" fn(*mut u64, u64, *mut u64) -> i32 =
                    unsafe { std::mem::transmute(callback) };
                let success = unsafe { callback(once, parameter, &mut context) } != 0;
                let Ok(mut state) = init.state.lock() else {
                    return 0;
                };
                *state = if success {
                    InitOnceState::Complete(context)
                } else {
                    InitOnceState::Uninitialized
                };
                init.ready.notify_all();
                if success && !context_out.is_null() {
                    unsafe { context_out.write_unaligned(context) };
                }
                return success as i32;
            }
        }
    }
}
pub(super) extern "win64" fn native_init_once_begin_initialize(
    once: *mut u64,
    flags: u32,
    pending: *mut i32,
    context_out: *mut u64,
) -> i32 {
    if pending.is_null() || flags & !0x3 != 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(init) = native_init_once(once) else {
        native_set_last_error(87);
        return 0;
    };
    loop {
        let Ok(mut state) = init.state.lock() else {
            return 0;
        };
        match *state {
            InitOnceState::Complete(context) => {
                unsafe { pending.write(0) };
                if !context_out.is_null() {
                    unsafe { context_out.write(context) };
                }
                return 1;
            }
            InitOnceState::Uninitialized => {
                unsafe { pending.write(1) };
                if flags & 1 == 0 {
                    *state = InitOnceState::Running;
                }
                return 1;
            }
            InitOnceState::Running => {
                if flags & 1 != 0 {
                    unsafe { pending.write(1) };
                    return 1;
                }
                drop(init.ready.wait(state));
            }
        }
    }
}
pub(super) extern "win64" fn native_init_once_complete(
    once: *mut u64,
    flags: u32,
    context: u64,
) -> i32 {
    if flags & !0x6 != 0 || (flags & 4 != 0 && context != 0) {
        native_set_last_error(87);
        return 0;
    }
    let Some(init) = native_init_once(once) else {
        native_set_last_error(87);
        return 0;
    };
    let Ok(mut state) = init.state.lock() else {
        return 0;
    };
    if !matches!(*state, InitOnceState::Running) {
        native_set_last_error(87);
        return 0;
    }
    *state = if flags & 4 != 0 {
        InitOnceState::Uninitialized
    } else {
        InitOnceState::Complete(context)
    };
    init.ready.notify_all();
    1
}
fn native_condition_variable(ptr: *mut u64) -> Option<&'static NativeConditionVariable> {
    if ptr.is_null() || (ptr as usize) % std::mem::align_of::<AtomicU64>() != 0 {
        return None;
    }
    let slot = unsafe { &*(ptr as *const AtomicU64) };
    let mut value = slot.load(Ordering::Acquire);
    if value == 0 {
        let created = Box::into_raw(Box::new(NativeConditionVariable {
            generation: Mutex::new(0),
            ready: Condvar::new(),
        })) as u64;
        match slot.compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => value = created,
            Err(existing) => {
                unsafe { drop(Box::from_raw(created as *mut NativeConditionVariable)) };
                value = existing;
            }
        }
    }
    (value != 0).then(|| unsafe { &*(value as *const NativeConditionVariable) })
}
pub(super) extern "win64" fn native_initialize_condition_variable(ptr: *mut u64) {
    if !ptr.is_null() {
        unsafe { ptr.write_unaligned(0) };
    }
}
pub(super) extern "win64" fn native_wake_condition_variable(ptr: *mut u64) {
    if let Some(cv) = native_condition_variable(ptr) {
        if let Ok(mut generation) = cv.generation.lock() {
            *generation = generation.wrapping_add(1);
            cv.ready.notify_one();
        }
    }
}
pub(super) extern "win64" fn native_wake_all_condition_variable(ptr: *mut u64) {
    if let Some(cv) = native_condition_variable(ptr) {
        if let Ok(mut generation) = cv.generation.lock() {
            *generation = generation.wrapping_add(1);
            cv.ready.notify_all();
        }
    }
}
pub(super) extern "win64" fn native_sleep_condition_variable_srw(
    condition: *mut u64,
    lock: *mut u64,
    milliseconds: u32,
    flags: u32,
) -> i32 {
    if flags & !1 != 0 {
        native_set_last_error(87);
        return 0;
    }
    let shared = flags & 1 != 0;
    let Some(cv) = native_condition_variable(condition) else {
        native_set_last_error(87);
        return 0;
    };
    let Ok(generation) = cv.generation.lock() else {
        return 0;
    };
    let before = *generation;
    let Some(guard) = take_srw_lock(lock, !shared) else {
        native_set_last_error(87);
        return 0;
    };
    drop(guard);
    let awakened = if milliseconds == u32::MAX {
        cv.ready
            .wait_while(generation, |value| *value == before)
            .is_ok()
    } else {
        cv.ready
            .wait_timeout_while(
                generation,
                std::time::Duration::from_millis(milliseconds as u64),
                |value| *value == before,
            )
            .map(|(value, _)| *value != before)
            .unwrap_or(false)
    };
    if shared {
        native_acquire_srw_lock_shared(lock);
    } else {
        native_acquire_srw_lock_exclusive(lock);
    }
    if awakened {
        1
    } else {
        native_set_last_error(1460);
        0
    }
}
pub(super) extern "win64" fn native_sleep_condition_variable_cs(
    condition: *mut u64,
    critical_section: *mut u8,
    milliseconds: u32,
) -> i32 {
    if critical_section.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(cv) = native_condition_variable(condition) else {
        native_set_last_error(87);
        return 0;
    };
    let Ok(generation) = cv.generation.lock() else {
        return 0;
    };
    let before = *generation;
    native_leave_critical_section(critical_section);
    let awakened = if milliseconds == u32::MAX {
        cv.ready
            .wait_while(generation, |value| *value == before)
            .is_ok()
    } else {
        cv.ready
            .wait_timeout_while(
                generation,
                std::time::Duration::from_millis(milliseconds as u64),
                |value| *value == before,
            )
            .map(|(value, _)| *value != before)
            .unwrap_or(false)
    };
    native_enter_critical_section(critical_section);
    if awakened {
        1
    } else {
        native_set_last_error(1460);
        0
    }
}

pub(super) extern "win64" fn native_wait_for_single_object(handle: u64, milliseconds: u32) -> u32 {
    if native_diagnostic_enabled() {
        eprintln!("native WaitForSingleObject handle={handle:#x} timeout={milliseconds}");
    }
    let process = process_ctx();
    if let Some(event) = process.as_ref().and_then(|process| {
        process
            .events
            .lock()
            .ok()
            .and_then(|events| events.get(&handle).cloned())
    }) {
        return native_wait_event(&event, milliseconds);
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
    if process.as_ref().is_some_and(|process| {
        process
            .threads
            .lock()
            .ok()
            .is_some_and(|threads| threads.contains_key(&handle))
    }) {
        let deadline = if milliseconds == u32::MAX {
            None
        } else {
            std::time::Instant::now()
                .checked_add(std::time::Duration::from_millis(milliseconds as u64))
        };
        loop {
            let join = {
                let Some(process) = process.as_ref() else {
                    return 0xffff_ffff;
                };
                let Ok(mut threads) = process.threads.lock() else {
                    return 0xffff_ffff;
                };
                let Some(thread) = threads.get_mut(&handle) else {
                    return 0xffff_ffff;
                };
                if thread.exit_code.is_some() {
                    return 0;
                }
                if thread.join.as_ref().is_some_and(|join| join.is_finished()) {
                    thread.join.take()
                } else {
                    None
                }
            };
            if let Some(join) = join {
                let code = join.join().unwrap_or(1);
                if let Some(process) = process.as_ref() {
                    if let Ok(mut threads) = process.threads.lock() {
                        if let Some(thread) = threads.get_mut(&handle) {
                            thread.exit_code = Some(code);
                        }
                    }
                }
                return 0;
            }
            if milliseconds == 0 || deadline.is_some_and(|at| std::time::Instant::now() >= at) {
                return 258; // WAIT_TIMEOUT; handle remains valid
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    match handle {
        0x7000_0000..0x8000_0000 => 0,
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
fn native_wait_event(event: &NativeEvent, milliseconds: u32) -> u32 {
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
