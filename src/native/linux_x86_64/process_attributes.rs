//! Caller-owned Windows extended process startup attributes.
use super::*;

const MAGIC: u64 = 0x5752_4154_5452_0001;
const HEADER: usize = 24;
const ENTRY: usize = 24;
const HANDLE_LIST: u64 = 0x0002_0002;

pub(super) extern "win64" fn native_initialize_proc_thread_attribute_list(
    list: *mut u8,
    count: u32,
    flags: u32,
    size: *mut usize,
) -> i32 {
    if size.is_null() || flags != 0 || count == 0 || count > 128 {
        native_set_last_error(87);
        return 0;
    }
    let required = HEADER + ENTRY * count as usize;
    let capacity = unsafe { size.read_unaligned() };
    unsafe { size.write_unaligned(required) };
    if list.is_null() || capacity < required {
        native_set_last_error(122);
        return 0;
    }
    unsafe {
        ptr::write_bytes(list, 0, required);
        list.cast::<u64>().write_unaligned(MAGIC);
        list.add(8).cast::<u64>().write_unaligned(count as u64);
    }
    1
}

fn list_count(list: *const u8) -> Result<(usize, usize), u32> {
    if list.is_null() {
        return Err(87);
    }
    unsafe {
        if list.cast::<u64>().read_unaligned() != MAGIC {
            return Err(87);
        }
        let capacity = list.add(8).cast::<u64>().read_unaligned() as usize;
        let used = list.add(16).cast::<u64>().read_unaligned() as usize;
        if capacity == 0 || capacity > 128 || used > capacity {
            return Err(87);
        }
        Ok((capacity, used))
    }
}

pub(super) extern "win64" fn native_update_proc_thread_attribute(
    list: *mut u8,
    flags: u32,
    attribute: u64,
    value: *const u8,
    size: usize,
    previous: *mut u8,
    returned: *mut usize,
) -> i32 {
    let (capacity, used) = match list_count(list) {
        Ok(value) => value,
        Err(error) => {
            native_set_last_error(error);
            return 0;
        }
    };
    if flags != 0
        || !previous.is_null()
        || !returned.is_null()
        || value.is_null()
        || size == 0
        || size % 8 != 0
    {
        native_set_last_error(87);
        return 0;
    }
    if attribute != HANDLE_LIST {
        native_set_last_error(50);
        return 0;
    }
    for index in 0..used {
        if unsafe {
            list.add(HEADER + ENTRY * index)
                .cast::<u64>()
                .read_unaligned()
        } == attribute
        {
            native_set_last_error(87);
            return 0;
        }
    }
    if used == capacity {
        native_set_last_error(87);
        return 0;
    }
    unsafe {
        let entry = list.add(HEADER + ENTRY * used);
        entry.cast::<u64>().write_unaligned(attribute);
        entry.add(8).cast::<u64>().write_unaligned(value as u64);
        entry.add(16).cast::<u64>().write_unaligned(size as u64);
        list.add(16)
            .cast::<u64>()
            .write_unaligned((used + 1) as u64);
    }
    1
}

pub(super) extern "win64" fn native_delete_proc_thread_attribute_list(list: *mut u8) {
    if list_count(list).is_ok() {
        unsafe {
            list.cast::<u64>().write_unaligned(0);
        }
    }
}

pub(super) fn startup_handle_list(
    startup: u64,
    flags: u32,
    inherit: bool,
) -> Result<Option<Vec<u64>>, u32> {
    if flags & 0x0008_0000 == 0 {
        return Ok(None);
    }
    if startup == 0 || unsafe { (startup as *const u32).read_unaligned() } < 112 {
        return Err(87);
    }
    let list = unsafe { ((startup + 104) as *const u64).read_unaligned() } as *const u8;
    if list.is_null() {
        return Ok(None);
    }
    let (_, used) = list_count(list)?;
    for index in 0..used {
        let entry = unsafe { list.add(HEADER + ENTRY * index) };
        let attribute = unsafe { entry.cast::<u64>().read_unaligned() };
        if attribute == HANDLE_LIST {
            if !inherit {
                return Err(87);
            }
            let value = unsafe { entry.add(8).cast::<u64>().read_unaligned() } as *const u64;
            let size = unsafe { entry.add(16).cast::<u64>().read_unaligned() } as usize;
            if value.is_null() || size == 0 || size % 8 != 0 || size > 1024 * 1024 {
                return Err(87);
            }
            let handles = (0..size / 8)
                .map(|index| unsafe { value.add(index).read_unaligned() })
                .collect();
            return Ok(Some(handles));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_attributes_use_caller_storage_and_extract_only_the_handle_list() {
        let mut size = 0;
        assert_eq!(
            native_initialize_proc_thread_attribute_list(ptr::null_mut(), 2, 0, &mut size),
            0
        );
        assert_eq!(native_get_last_error(), 122);
        let mut storage = vec![0u8; size];
        assert_eq!(
            native_initialize_proc_thread_attribute_list(storage.as_mut_ptr(), 2, 0, &mut size),
            1
        );
        let handles = [12u64, 34];
        assert_eq!(
            native_update_proc_thread_attribute(
                storage.as_mut_ptr(),
                0,
                HANDLE_LIST,
                handles.as_ptr().cast(),
                16,
                ptr::null_mut(),
                ptr::null_mut()
            ),
            1
        );
        let mut startup = [0u8; 112];
        startup[..4].copy_from_slice(&112u32.to_le_bytes());
        startup[104..112].copy_from_slice(&(storage.as_ptr() as u64).to_le_bytes());
        assert_eq!(
            startup_handle_list(startup.as_ptr() as u64, 0x80000, true),
            Ok(Some(handles.to_vec()))
        );
        assert_eq!(
            startup_handle_list(startup.as_ptr() as u64, 0x80000, false),
            Err(87)
        );
        assert_eq!(
            startup_handle_list(startup.as_ptr() as u64, 0, false),
            Ok(None)
        );
        assert_eq!(
            native_update_proc_thread_attribute(
                storage.as_mut_ptr(),
                0,
                0x20000,
                handles.as_ptr().cast(),
                8,
                ptr::null_mut(),
                ptr::null_mut()
            ),
            0
        );
        assert_eq!(native_get_last_error(), 50);
        assert_eq!(
            native_update_proc_thread_attribute(
                storage.as_mut_ptr(),
                0,
                HANDLE_LIST,
                handles.as_ptr().cast(),
                16,
                ptr::null_mut(),
                ptr::null_mut()
            ),
            0
        );
        native_delete_proc_thread_attribute_list(storage.as_mut_ptr());
        assert_eq!(
            startup_handle_list(startup.as_ptr() as u64, 0x80000, true),
            Err(87)
        );
    }
    #[test]
    fn startup_attributes_reject_invalid_sizes_and_flags() {
        let mut size = 0;
        assert_eq!(
            native_initialize_proc_thread_attribute_list(ptr::null_mut(), 1, 1, &mut size),
            0
        );
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(
            native_initialize_proc_thread_attribute_list(ptr::null_mut(), 1, 0, &mut size),
            0
        );
        let mut storage = vec![0; size];
        let mut short = size - 1;
        assert_eq!(
            native_initialize_proc_thread_attribute_list(storage.as_mut_ptr(), 1, 0, &mut short),
            0
        );
        assert_eq!(native_get_last_error(), 122);
        assert_eq!(short, size);
        assert_eq!(
            native_initialize_proc_thread_attribute_list(storage.as_mut_ptr(), 1, 0, &mut size),
            1
        );
        let value = [0u8; 8];
        assert_eq!(
            native_update_proc_thread_attribute(
                storage.as_mut_ptr(),
                0,
                HANDLE_LIST,
                value.as_ptr(),
                7,
                ptr::null_mut(),
                ptr::null_mut()
            ),
            0
        );
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(startup_handle_list(0, 0x80000, true), Err(87));
    }
}
