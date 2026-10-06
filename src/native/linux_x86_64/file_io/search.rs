use super::*;

/// `GetFullPathNameW(path, length, buffer, file_part)`, a pure string
/// transformation against the current directory (see
/// [`crate::winfs::full_path`]).
pub(in crate::native::linux_x86_64) extern "win64" fn native_get_full_path_name_w(
    input: *const u16,
    output_len: u32,
    output: *mut u16,
    part: *mut *mut u16,
) -> u32 {
    let Some(raw) = wide(input) else {
        native_set_last_error(87);
        return 0;
    };
    let (cwd, drives) = fs_ctx()
        .and_then(|context| {
            context
                .lock()
                .ok()
                .map(|ctx| (ctx.fs.cwd(), ctx.fs.drive_current_directories()))
        })
        .unwrap_or_else(|| ("C:\\".to_string(), Vec::new()));
    let resolved = crate::winfs::full_path::full_path_name(&raw, &cwd, |drive| {
        drives
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(&drive))
            .map(|(_, directory)| directory.clone())
    });
    let full = match resolved {
        Ok(full) => full,
        Err(error) => {
            native_set_last_error(error);
            return 0;
        }
    };
    let encoded: Vec<u16> = full.path.encode_utf16().chain(std::iter::once(0)).collect();
    if output.is_null() || output_len < encoded.len() as u32 {
        return encoded.len() as u32;
    }
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    if !part.is_null() {
        let file_part = full
            .file_part
            .map(|index| unsafe { output.add(full.path[..index].encode_utf16().count()) })
            .unwrap_or(ptr::null_mut());
        unsafe { part.write(file_part) };
    }
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
/// Fill a `WIN32_FIND_DATAW` for the entry at `path`: attributes
/// (directories always carry `FILE_ATTRIBUTE_DIRECTORY`), the three
/// timestamps, the size, and the file name.
fn native_write_find_data(output: *mut u8, fs: &WinFs, path: &str) -> bool {
    let leaf = path.rsplit('\\').next().unwrap_or(path);
    let name: Vec<u16> = leaf.encode_utf16().chain(std::iter::once(0)).collect();
    if output.is_null() || name.len() > 260 {
        return false;
    }
    let metadata = fs.file_metadata(path);
    let directory = fs.is_dir(path);
    let mut attributes = metadata.attributes;
    if directory {
        attributes = (attributes & !0x80) | 0x10;
    } else if attributes == 0 {
        attributes = 0x80; // FILE_ATTRIBUTE_NORMAL
    }
    let size = if directory {
        0
    } else {
        fs.file_len(path).unwrap_or(0)
    };
    unsafe {
        std::ptr::write_bytes(output, 0, 592);
        output.cast::<u32>().write_unaligned(attributes);
        output
            .add(4)
            .cast::<u64>()
            .write_unaligned(metadata.creation_time);
        output
            .add(12)
            .cast::<u64>()
            .write_unaligned(metadata.access_time);
        output
            .add(20)
            .cast::<u64>()
            .write_unaligned(metadata.write_time);
        output
            .add(28)
            .cast::<u32>()
            .write_unaligned((size >> 32) as u32);
        output.add(32).cast::<u32>().write_unaligned(size as u32);
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
    // Every directory but a drive root lists `.` and `..` first, when the
    // pattern matches them (as `*` does).
    let is_root = ctx.fs.normalize(&directory).is_ok_and(|path| path.parts.is_empty());
    if !is_root {
        for (index, special) in [".", ".."].into_iter().enumerate() {
            if native_name_matches_pattern(&name_pattern, special) {
                names.insert(index.min(names.len()), special.to_string());
            }
        }
    }
    // Keep full paths so each result can report its attributes and size.
    let names: Vec<String> = names
        .into_iter()
        .map(|name| format!(r"{}\{name}", directory.trim_end_matches('\\')))
        .collect();
    let Some(first) = names.first() else {
        native_set_last_error(2);
        return u64::MAX;
    };
    if !native_write_find_data(output, &ctx.fs, first) {
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
    let Some(entry) = find.names.get(find.index).cloned() else {
        native_set_last_error(18);
        return 0;
    };
    native_write_find_data(output, &ctx.fs, &entry) as i32
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

/// `CompareFileTime`: -1, 0 or 1 as the first time is earlier, equal or
/// later.
pub(in crate::native::linux_x86_64) extern "win64" fn native_compare_file_time(
    first: *const u64,
    second: *const u64,
) -> i32 {
    if first.is_null() || second.is_null() {
        return 0;
    }
    let (a, b) = unsafe { (first.read_unaligned(), second.read_unaligned()) };
    match a.cmp(&b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// `GetFileTime`: the creation, access and write times recorded for an
/// open file (each output optional).
pub(in crate::native::linux_x86_64) extern "win64" fn native_get_file_time(
    handle: u64,
    creation: *mut u64,
    access: *mut u64,
    write: *mut u64,
) -> i32 {
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(context) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(path) = context.handles.get(&handle).map(|file| file.path.clone()) else {
        native_set_last_error(6);
        return 0;
    };
    let metadata = context.fs.file_metadata(&path);
    unsafe {
        for (out, value) in [
            (creation, metadata.creation_time),
            (access, metadata.access_time),
            (write, metadata.write_time),
        ] {
            if !out.is_null() {
                out.write_unaligned(value);
            }
        }
    }
    1
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
