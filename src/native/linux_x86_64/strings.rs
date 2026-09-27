//! Shared Windows string pointer and encoding helpers.

pub(super) fn wide(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut units = Vec::new();
    for i in 0..32768 {
        let u = unsafe { ptr.add(i).read() };
        if u == 0 {
            return String::from_utf16(&units).ok();
        }
        units.push(u);
    }
    None
}
