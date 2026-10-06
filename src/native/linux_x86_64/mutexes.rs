//! Win32 mutex objects: owned by the thread that acquires them, recursive
//! for that owner, released only by it, and optionally named so another
//! `CreateMutex`/`OpenMutex` in the process reaches the same object.

use super::*;
use std::sync::Weak;

pub(super) struct NativeMutex {
    state: Mutex<MutexState>,
    released: Condvar,
}

struct MutexState {
    /// Owning thread id; 0 when the mutex is free.
    owner: u32,
    recursion: u32,
}

impl NativeMutex {
    fn new(owner: Option<u32>) -> Self {
        Self {
            state: Mutex::new(MutexState {
                owner: owner.unwrap_or(0),
                recursion: owner.is_some() as u32,
            }),
            released: Condvar::new(),
        }
    }
}

static MUTEXES: LazyLock<Mutex<HashMap<u64, Arc<NativeMutex>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static MUTEX_NAMES: LazyLock<Mutex<HashMap<String, Weak<NativeMutex>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static MUTEX_NEXT: AtomicU64 = AtomicU64::new(0x6c00_0000);

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_NOT_OWNER: u32 = 288;
const CREATE_MUTEX_INITIAL_OWNER: u32 = 1;

fn insert_handle(mutex: Arc<NativeMutex>) -> u64 {
    let handle = MUTEX_NEXT.fetch_add(4, Ordering::AcqRel);
    match MUTEXES.lock() {
        Ok(mut mutexes) => {
            mutexes.insert(handle, mutex);
            handle
        }
        Err(_) => 0,
    }
}

pub(super) fn lookup_mutex(handle: u64) -> Option<Arc<NativeMutex>> {
    MUTEXES.lock().ok()?.get(&handle).cloned()
}

/// `CloseHandle` for a mutex handle; false when `handle` is not one. A
/// named mutex lives while any handle to it does.
pub(super) fn close_mutex(handle: u64) -> bool {
    MUTEXES
        .lock()
        .is_ok_and(|mut mutexes| mutexes.remove(&handle).is_some())
}

/// `DuplicateHandle`: another handle to the same mutex.
pub(super) fn duplicate_mutex(handle: u64) -> Option<u64> {
    let mutex = lookup_mutex(handle)?;
    Some(insert_handle(mutex)).filter(|&h| h != 0)
}

fn ansi_name(name: *const u8) -> Result<Option<Vec<u16>>, ()> {
    if name.is_null() {
        return Ok(None);
    }
    let Some((bytes, _)) = (unsafe { multibyte_input(name, -1) }) else {
        return Err(());
    };
    Ok(Some(bytes.into_iter().map(u16::from).chain([0]).collect()))
}

pub(super) extern "win64" fn native_create_mutex_w(
    _attributes: u64,
    initial_owner: i32,
    name: *const u16,
) -> u64 {
    let flags = if initial_owner != 0 { CREATE_MUTEX_INITIAL_OWNER } else { 0 };
    native_create_mutex_ex_w(0, name, flags, 0)
}

pub(super) extern "win64" fn native_create_mutex_a(
    attributes: u64,
    initial_owner: i32,
    name: *const u8,
) -> u64 {
    let Ok(wide) = ansi_name(name) else {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let name = wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());
    native_create_mutex_w(attributes, initial_owner, name)
}

/// `CreateMutexExW`: a named mutex that already exists is opened (its
/// ownership untouched) with `ERROR_ALREADY_EXISTS`.
pub(super) extern "win64" fn native_create_mutex_ex_w(
    _attributes: u64,
    name: *const u16,
    flags: u32,
    _access: u32,
) -> u64 {
    if flags & !CREATE_MUTEX_INITIAL_OWNER != 0 {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let owner = (flags & CREATE_MUTEX_INITIAL_OWNER != 0).then(|| native_get_current_thread_id());
    let name = if name.is_null() {
        None
    } else {
        match wide(name) {
            Some(name) if !name.is_empty() => Some(name),
            _ => {
                native_set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
        }
    };
    let Some(name) = name else {
        native_set_last_error(0);
        return insert_handle(Arc::new(NativeMutex::new(owner)));
    };
    let Ok(mut names) = MUTEX_NAMES.lock() else {
        return 0;
    };
    if let Some(existing) = names.get(&name).and_then(Weak::upgrade) {
        drop(names);
        let handle = insert_handle(existing);
        native_set_last_error(ERROR_ALREADY_EXISTS);
        return handle;
    }
    let mutex = Arc::new(NativeMutex::new(owner));
    names.insert(name, Arc::downgrade(&mutex));
    drop(names);
    native_set_last_error(0);
    insert_handle(mutex)
}

pub(super) extern "win64" fn native_create_mutex_ex_a(
    attributes: u64,
    name: *const u8,
    flags: u32,
    access: u32,
) -> u64 {
    let Ok(wide) = ansi_name(name) else {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let name = wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());
    native_create_mutex_ex_w(attributes, name, flags, access)
}

/// `OpenMutexW`: a new handle to an existing named mutex.
pub(super) extern "win64" fn native_open_mutex_w(
    _access: u32,
    _inherit: i32,
    name: *const u16,
) -> u64 {
    let Some(name) = wide(name).filter(|name| !name.is_empty()) else {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let existing = MUTEX_NAMES
        .lock()
        .ok()
        .and_then(|names| names.get(&name).and_then(Weak::upgrade));
    let Some(mutex) = existing else {
        native_set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    };
    native_set_last_error(0);
    insert_handle(mutex)
}

pub(super) extern "win64" fn native_open_mutex_a(access: u32, inherit: i32, name: *const u8) -> u64 {
    match ansi_name(name) {
        Ok(Some(wide)) => native_open_mutex_w(access, inherit, wide.as_ptr()),
        _ => {
            native_set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
    }
}

/// `ReleaseMutex`: only the owner may release; the last release frees it.
pub(super) extern "win64" fn native_release_mutex(handle: u64) -> i32 {
    let Some(mutex) = lookup_mutex(handle) else {
        native_set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    let Ok(mut state) = mutex.state.lock() else {
        return 0;
    };
    if state.owner == 0 || state.owner != native_get_current_thread_id() {
        native_set_last_error(ERROR_NOT_OWNER);
        return 0;
    }
    state.recursion -= 1;
    if state.recursion == 0 {
        state.owner = 0;
        mutex.released.notify_one();
    }
    1
}

fn acquirable(state: &MutexState, me: u32) -> bool {
    state.owner == 0 || state.owner == me
}

fn take(state: &mut MutexState, me: u32) {
    state.owner = me;
    state.recursion += 1;
}

/// Wait for and acquire a mutex: `WAIT_OBJECT_0` or `WAIT_TIMEOUT`.
pub(super) fn wait_mutex(mutex: &NativeMutex, milliseconds: u32) -> u32 {
    let me = native_get_current_thread_id();
    let Ok(mut state) = mutex.state.lock() else {
        return u32::MAX;
    };
    if milliseconds == u32::MAX {
        while !acquirable(&state, me) {
            state = match mutex.released.wait(state) {
                Ok(state) => state,
                Err(_) => return u32::MAX,
            };
        }
    } else if !acquirable(&state, me) {
        let Ok((guard, _)) = mutex.released.wait_timeout_while(
            state,
            std::time::Duration::from_millis(milliseconds as u64),
            |state| !acquirable(state, me),
        ) else {
            return u32::MAX;
        };
        state = guard;
        if !acquirable(&state, me) {
            return 258; // WAIT_TIMEOUT
        }
    }
    take(&mut state, me);
    0
}

/// A held mutex state for an all-or-nothing wait: whether this thread may
/// take it now, and `acquire` to take it once every object is ready.
pub(super) struct HeldMutex<'a>(std::sync::MutexGuard<'a, MutexState>);

impl<'a> HeldMutex<'a> {
    pub(super) fn lock(mutex: &'a NativeMutex) -> Option<Self> {
        mutex.state.lock().ok().map(HeldMutex)
    }
    pub(super) fn ready(&self) -> bool {
        acquirable(&self.0, native_get_current_thread_id())
    }
    pub(super) fn acquire(&mut self) {
        take(&mut self.0, native_get_current_thread_id());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide_name(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    #[test]
    fn owners_recurse_and_only_the_owner_releases() {
        let handle = native_create_mutex_w(0, 1, std::ptr::null());
        assert_ne!(handle, 0);
        let mutex = lookup_mutex(handle).unwrap();
        assert_eq!(wait_mutex(&mutex, 0), 0, "the owner re-enters");
        let other = std::thread::spawn({
            let mutex = Arc::clone(&mutex);
            move || {
                THREAD_NATIVE_HANDLE.with(|id| id.set(0x8000_0004));
                let blocked = wait_mutex(&mutex, 10);
                let released = native_release_mutex(handle);
                (blocked, released, native_get_last_error())
            }
        })
        .join()
        .unwrap();
        assert_eq!(other, (258, 0, ERROR_NOT_OWNER));
        assert_eq!(native_release_mutex(handle), 1);
        assert_eq!(native_release_mutex(handle), 1);
        assert_eq!(native_release_mutex(handle), 0, "already free");
        let taken = std::thread::spawn({
            let mutex = Arc::clone(&mutex);
            move || {
                THREAD_NATIVE_HANDLE.with(|id| id.set(0x8000_0008));
                wait_mutex(&mutex, 1000)
            }
        })
        .join()
        .unwrap();
        assert_eq!(taken, 0);
        assert!(close_mutex(handle));
        assert!(!close_mutex(handle));
        assert_eq!(native_release_mutex(handle), 0);
        assert_eq!(native_get_last_error(), ERROR_INVALID_HANDLE);
    }

    #[test]
    fn names_reach_one_object_while_a_handle_lives() {
        let name = wide_name("winrun-test-mutex-names");
        let first = native_create_mutex_w(0, 0, name.as_ptr());
        assert_eq!(native_get_last_error(), 0);
        let second = native_create_mutex_ex_w(0, name.as_ptr(), 1, 0);
        assert_eq!(native_get_last_error(), ERROR_ALREADY_EXISTS);
        assert!(Arc::ptr_eq(&lookup_mutex(first).unwrap(), &lookup_mutex(second).unwrap()));
        // Opening an existing mutex does not take ownership.
        assert_eq!(native_release_mutex(second), 0);
        let opened = native_open_mutex_a(0x1f0001, 0, b"winrun-test-mutex-names\0".as_ptr());
        assert!(Arc::ptr_eq(&lookup_mutex(first).unwrap(), &lookup_mutex(opened).unwrap()));
        let duplicate = duplicate_mutex(opened).unwrap();
        for handle in [first, second, opened, duplicate] {
            assert!(close_mutex(handle));
        }
        assert_eq!(native_open_mutex_w(0, 0, name.as_ptr()), 0);
        assert_eq!(native_get_last_error(), ERROR_FILE_NOT_FOUND);
        assert_eq!(native_create_mutex_ex_w(0, std::ptr::null(), 2, 0), 0);
        assert_eq!(native_get_last_error(), ERROR_INVALID_PARAMETER);
    }
}
