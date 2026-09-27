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
