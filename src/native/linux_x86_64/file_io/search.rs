use super::*;

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_full_path_name_w(
    input: *const u16,
    output_len: u32,
    output: *mut u16,
    _part: *mut *mut u16,
) -> u32 {
    let Some(raw) = wide(input) else {
        return 0;
    };
    let path = fs_ctx()
        .and_then(|context| {
            context
                .lock()
                .ok()
                .and_then(|ctx| ctx.fs.normalize(&raw).ok().map(|path| path.display()))
        })
        .unwrap_or_else(|| {
            if raw == "." || raw.is_empty() {
                "C:\\".to_string()
            } else if raw.len() >= 2 && raw.as_bytes()[1] == b':' {
                raw.replace('/', "\\")
            } else {
                format!("C:\\{}", raw.replace('/', "\\"))
            }
        });
    let encoded: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    if output.is_null() || output_len < encoded.len() as u32 {
        return encoded.len() as u32;
    }
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    (encoded.len() - 1) as u32
}
fn native_find_parts(pattern: &str) -> (String, String) {
    let path = pattern
        .strip_prefix(r"\\?\")
        .unwrap_or(pattern)
        .replace('/', "\\");
    let Some((parent, leaf)) = path.rsplit_once('\\') else {
        return (".".to_string(), path);
    };
    let parent = if parent.ends_with(':') {
        format!("{parent}\\")
    } else {
        parent.to_string()
    };
    (parent, leaf.to_string())
}
fn native_name_matches_pattern(pattern: &str, name: &str) -> bool {
    let pattern = pattern.to_lowercase().chars().collect::<Vec<_>>();
    let name = name.to_lowercase().chars().collect::<Vec<_>>();
    let mut previous = vec![false; name.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut current = vec![false; name.len() + 1];
        if token == '*' {
            current[0] = previous[0];
            for index in 1..=name.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=name.len() {
                current[index] = previous[index - 1] && (token == '?' || token == name[index - 1]);
            }
        }
        previous = current;
    }
    previous[name.len()]
}
fn native_write_find_data(output: *mut u8, name: &str) -> bool {
    let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    if output.is_null() || name.len() > 260 {
        return false;
    }
    unsafe {
        std::ptr::write_bytes(output, 0, 592);
        output
            .add(44)
            .cast::<u16>()
            .copy_from_nonoverlapping(name.as_ptr(), name.len());
    }
    true
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_find_first_file_ex_w(
    pattern: *const u16,
    info_level: u32,
    output: *mut u8,
    search_op: u32,
    _filter: u64,
    flags: u32,
) -> u64 {
    let Some(pattern) = wide(pattern) else {
        native_set_last_error(87);
        return u64::MAX;
    };
    if info_level > 1 || search_op > 1 || flags > 2 || output.is_null() {
        native_set_last_error(87);
        return u64::MAX;
    }
    let context = match fs_ctx() {
        Some(value) => value,
        None => {
            native_set_last_error(6);
            return u64::MAX;
        }
    };
    let mut ctx = match context.lock() {
        Ok(value) => value,
        Err(_) => {
            native_set_last_error(6);
            return u64::MAX;
        }
    };
    let (directory, name_pattern) = native_find_parts(&pattern);
    let mut names = match ctx.fs.list_dir(&directory) {
        Ok(value) => value,
        Err(_) => {
            native_set_last_error(3);
            return u64::MAX;
        }
    };
    names.retain(|name| native_name_matches_pattern(&name_pattern, name));
    names.sort_by_key(|name| name.to_lowercase());
    let Some(first) = names.first() else {
        native_set_last_error(2);
        return u64::MAX;
    };
    if !native_write_find_data(output, first) {
        native_set_last_error(87);
        return u64::MAX;
    }
    let handle = ctx.next;
    ctx.next += 1;
    ctx.finds.insert(handle, NativeFind { names, index: 0 });
    handle
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_find_first_file_w(
    pattern: *const u16,
    output: *mut u8,
) -> u64 {
    native_find_first_file_ex_w(pattern, 0, output, 0, 0, 0)
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_find_next_file_w(
    handle: u64,
    output: *mut u8,
) -> i32 {
    let context = match fs_ctx() {
        Some(value) => value,
        None => return 0,
    };
    let mut ctx = match context.lock() {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let find = match ctx.finds.get_mut(&handle) {
        Some(value) => value,
        None => return 0,
    };
    find.index += 1;
    let Some(name) = find.names.get(find.index) else {
        native_set_last_error(18);
        return 0;
    };
    native_write_find_data(output, name) as i32
}
pub(in crate::native::linux_x86_64) extern "win64" fn native_find_close(handle: u64) -> i32 {
    fs_ctx()
        .and_then(|context| {
            context
                .lock()
                .ok()
                .map(|mut ctx| ctx.finds.remove(&handle).is_some())
        })
        .unwrap_or(false) as i32
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_set_file_time(
    handle: u64,
    creation: *const u64,
    access: *const u64,
    write: *const u64,
) -> i32 {
    if host_standard_fd(handle).is_some() {
        return 1;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut context) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(path) = context.handles.get(&handle).map(|file| file.path.clone()) else {
        native_set_last_error(6);
        return 0;
    };
    let mut metadata = context.fs.file_metadata(&path);
    unsafe {
        if !creation.is_null() {
            metadata.creation_time = creation.read_unaligned();
        }
        if !access.is_null() {
            metadata.access_time = access.read_unaligned();
        }
        if !write.is_null() {
            metadata.write_time = write.read_unaligned();
        }
    }
    match context.fs.set_file_metadata(&path, metadata) {
        Ok(()) => 1,
        Err(_) => {
            native_set_last_error(5);
            0
        }
    }
}
