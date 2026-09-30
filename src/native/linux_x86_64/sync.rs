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
/// `OpenEventW`: a new handle to an existing named event of this process,
/// or `ERROR_FILE_NOT_FOUND`.
pub(super) extern "win64" fn native_open_event_w(_access: u32, _inherit: i32, name: *const u16) -> u64 {
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
    let Some(child) = child_process(&process, object) else {
        native_set_last_error(6);
        return 0;
    };
    let handle = process.completion_next.fetch_add(1, Ordering::AcqRel);
    let registration = Arc::new(NativeWaitRegistration {
        callback,
        context,
        child,
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
        .name("winrun-process-wait".into())
        .spawn(move || {
            loop {
                if registration.cancelled.load(Ordering::Acquire) {
                    break;
                }
                let signaled = registration
                    .child
                    .state
                    .lock()
                    .is_ok_and(|state| state.is_some());
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
    _flags: u32,
    _access: u32,
) -> u64 {
    process_ctx()
        .map(|process| process.timer_next.fetch_add(1, Ordering::AcqRel))
        .unwrap_or(0)
}
pub(super) extern "win64" fn native_set_waitable_timer(
    handle: u64,
    _due_time: *const i64,
    _period: i32,
    _completion: u64,
    _arg: u64,
    _resume: i32,
) -> i32 {
    (0x7000_0000..0x8000_0000).contains(&handle) as i32
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
/// `WAIT_ABANDONED_0 + i`); "all" waits on each in turn within the one
/// timeout. No APCs are ever queued, so alertable waits behave the same.
pub(super) extern "win64" fn native_wait_for_multiple_objects_ex(
    count: u32,
    handles: *const u64,
    wait_all: i32,
    milliseconds: u32,
    _alertable: i32,
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
        for handle in &handles {
            match native_wait_for_single_object(*handle, remaining()) {
                0 | WAIT_ABANDONED_0 => {}
                other => return other,
            }
        }
        return 0;
    }
    loop {
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
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
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
    _alertable: i32,
) -> u32 {
    if native_set_event(signal) == 0
        && native_release_semaphore(signal, 1, std::ptr::null_mut()) == 0
    {
        native_set_last_error(6);
        return WAIT_FAILED;
    }
    native_wait_for_single_object(wait, milliseconds)
}
