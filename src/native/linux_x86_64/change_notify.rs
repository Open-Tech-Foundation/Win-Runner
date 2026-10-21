//! Directory change notifications: `FindFirstChangeNotificationW`,
//! `FindNextChangeNotification` and `FindCloseChangeNotification`.
//!
//! Other processes' changes (and a mounted host folder's) reach this
//! process's view of the file system, so a notification polls its
//! directory with the snapshots `ReadDirectoryChangesW` compares, and
//! signals its handle (an event) when they differ in a way its filter
//! names.

use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

static NOTIFICATIONS: Mutex<Option<HashMap<u64, Arc<AtomicBool>>>> = Mutex::new(None);

fn wide_text(text: *const u16) -> Option<String> {
    if text.is_null() {
        return None;
    }
    let mut length = 0;
    while unsafe { text.add(length).read() } != 0 {
        length += 1;
    }
    Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) }))
}

pub(super) extern "win64" fn native_find_first_change_notification_w(path: *const u16, subtree: i32, filter: u32) -> u64 {
    let (Some(path), Some(process)) = (wide_text(path), process_ctx()) else {
        native_set_last_error(87);
        return u64::MAX;
    };
    if filter == 0 || filter & !0x17f != 0 {
        native_set_last_error(87);
        return u64::MAX;
    }
    let directory = {
        let Ok(fs) = process.fs.lock() else {
            native_set_last_error(6);
            return u64::MAX;
        };
        let Ok(normalized) = fs.fs.normalize(&path).map(|path| path.display()) else {
            native_set_last_error(3);
            return u64::MAX;
        };
        if !fs.fs.is_dir(&normalized) {
            native_set_last_error(if fs.fs.exists(&normalized) { 267 } else { 2 });
            return u64::MAX;
        }
        normalized
    };
    let handle = native_create_event_w(0, 1, 0, std::ptr::null());
    let event = process.events.lock().ok().and_then(|events| events.get(&handle).cloned());
    let Some(event) = event else {
        native_set_last_error(8);
        return u64::MAX;
    };
    let stop = Arc::new(AtomicBool::new(false));
    if let Ok(mut notifications) = NOTIFICATIONS.lock() {
        notifications.get_or_insert_with(HashMap::new).insert(handle, stop.clone());
    }
    let fs = Arc::clone(&process.fs);
    let subtree = subtree != 0;
    let snapshot = move || fs.lock().ok().map(|fs| native_directory_snapshot(&fs.fs, &directory, subtree));
    let Some(mut previous) = snapshot() else {
        return handle;
    };
    std::thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(25));
            let Some(current) = snapshot() else {
                return;
            };
            if !native_directory_changes(&previous, &current, filter).is_empty() {
                native_signal_event(&event);
            }
            previous = current;
        }
    });
    handle
}

/// `FindNextChangeNotification`: wait for the next change.
pub(super) extern "win64" fn native_find_next_change_notification(handle: u64) -> i32 {
    let known = NOTIFICATIONS
        .lock()
        .is_ok_and(|notifications| notifications.as_ref().is_some_and(|map| map.contains_key(&handle)));
    if !known {
        native_set_last_error(6);
        return 0;
    }
    native_reset_event(handle)
}

pub(super) extern "win64" fn native_find_close_change_notification(handle: u64) -> i32 {
    let stop = NOTIFICATIONS.lock().ok().and_then(|mut notifications| notifications.as_mut()?.remove(&handle));
    let Some(stop) = stop else {
        native_set_last_error(6);
        return 0;
    };
    stop.store(true, Ordering::Release);
    native_close_handle(handle)
}
