use super::*;

pub(in crate::native::linux_x86_64) fn native_ansi_z_bytes(
    path: *const u8,
) -> Option<&'static [u8]> {
    if path.is_null() {
        return None;
    }
    let mut length = 0usize;
    while length < 32 * 1024 && unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    (length < 32 * 1024).then(|| unsafe { std::slice::from_raw_parts(path, length + 1) })
}

pub(in crate::native::linux_x86_64) fn native_ansi_path(path: *const u8) -> Option<Vec<u16>> {
    let bytes = native_ansi_z_bytes(path)?;
    let length = native_multi_byte_to_wide_char(0, 0, bytes.as_ptr(), -1, ptr::null_mut(), 0);
    if length <= 0 {
        return None;
    }
    let mut wide = vec![0u16; length as usize];
    (native_multi_byte_to_wide_char(0, 0, bytes.as_ptr(), -1, wide.as_mut_ptr(), length) == length)
        .then_some(wide)
}

pub(in crate::native::linux_x86_64) fn native_wide_path_to_ansi(path: &[u16]) -> Option<Vec<u8>> {
    let length = native_wide_char_to_multi_byte(
        0,
        0,
        path.as_ptr(),
        -1,
        ptr::null_mut(),
        0,
        ptr::null(),
        ptr::null_mut(),
    );
    if length <= 0 {
        return None;
    }
    let mut bytes = vec![0u8; length as usize];
    (native_wide_char_to_multi_byte(
        0,
        0,
        path.as_ptr(),
        -1,
        bytes.as_mut_ptr(),
        length,
        ptr::null(),
        ptr::null_mut(),
    ) == length)
        .then_some(bytes)
}

pub(in crate::native::linux_x86_64) fn native_find_data_w_to_a(
    source: &[u8; 592],
    output: *mut u8,
) -> bool {
    if output.is_null() {
        native_set_last_error(87);
        return false;
    }
    let file_name =
        unsafe { std::slice::from_raw_parts(source.as_ptr().add(44).cast::<u16>(), 260) };
    let alternate_name =
        unsafe { std::slice::from_raw_parts(source.as_ptr().add(564).cast::<u16>(), 14) };
    let convert = |units: &[u16]| {
        let length = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        let mut converted = native_wide_char_to_multi_byte(
            0,
            0,
            units.as_ptr(),
            length as i32,
            ptr::null_mut(),
            0,
            ptr::null(),
            ptr::null_mut(),
        );
        if converted < 0 {
            return None;
        }
        let mut bytes = vec![0u8; converted as usize];
        converted = native_wide_char_to_multi_byte(
            0,
            0,
            units.as_ptr(),
            length as i32,
            bytes.as_mut_ptr(),
            converted,
            ptr::null(),
            ptr::null_mut(),
        );
        (converted >= 0).then_some(bytes)
    };
    let Some(file_name) = convert(file_name) else {
        native_set_last_error(1113);
        return false;
    };
    let Some(alternate_name) = convert(alternate_name) else {
        native_set_last_error(1113);
        return false;
    };
    if file_name.len() >= 260 || alternate_name.len() >= 14 {
        native_set_last_error(1113);
        return false;
    }
    unsafe {
        ptr::write_bytes(output, 0, 320);
        ptr::copy_nonoverlapping(source.as_ptr(), output, 44);
        ptr::copy_nonoverlapping(file_name.as_ptr(), output.add(44), file_name.len());
        ptr::copy_nonoverlapping(
            alternate_name.as_ptr(),
            output.add(304),
            alternate_name.len(),
        );
    }
    true
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_find_first_file_a(
    pattern: *const u8,
    output: *mut u8,
) -> u64 {
    let Some(pattern) = native_ansi_path(pattern) else {
        native_set_last_error(87);
        return u64::MAX;
    };
    let mut wide_data = [0u8; 592];
    let handle = native_find_first_file_w(pattern.as_ptr(), wide_data.as_mut_ptr());
    if handle != u64::MAX && !native_find_data_w_to_a(&wide_data, output) {
        let _ = native_find_close(handle);
        return u64::MAX;
    }
    handle
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_find_next_file_a(
    handle: u64,
    output: *mut u8,
) -> i32 {
    if output.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let mut wide_data = [0u8; 592];
    if native_find_next_file_w(handle, wide_data.as_mut_ptr()) == 0 {
        return 0;
    }
    native_find_data_w_to_a(&wide_data, output) as i32
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_find_first_file_ex_a(
    pattern: *const u8,
    info_level: i32,
    output: *mut u8,
    search_op: i32,
    filter: *const u8,
    flags: u32,
) -> u64 {
    if !(0..=1).contains(&info_level)
        || !(0..=1).contains(&search_op)
        || flags > 2
        || output.is_null()
    {
        native_set_last_error(87);
        return u64::MAX;
    }
    let Some(pattern) = native_ansi_path(pattern) else {
        native_set_last_error(87);
        return u64::MAX;
    };
    let mut wide_data = [0u8; 592];
    let handle = native_find_first_file_ex_w(
        pattern.as_ptr(),
        info_level as u32,
        wide_data.as_mut_ptr(),
        search_op as u32,
        filter as u64,
        flags,
    );
    if handle != u64::MAX && !native_find_data_w_to_a(&wide_data, output) {
        let _ = native_find_close(handle);
        return u64::MAX;
    }
    handle
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_delete_file_a(path: *const u8) -> i32 {
    let Some(path) = native_ansi_path(path) else {
        native_set_last_error(87);
        return 0;
    };
    native_delete_file_w(path.as_ptr())
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_move_file_a(
    source: *const u8,
    destination: *const u8,
) -> i32 {
    let (Some(source), Some(destination)) =
        (native_ansi_path(source), native_ansi_path(destination))
    else {
        native_set_last_error(87);
        return 0;
    };
    native_move_file_w(source.as_ptr(), destination.as_ptr())
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_copy_file_a(
    source: *const u8,
    destination: *const u8,
    fail: i32,
) -> i32 {
    let (Some(source), Some(destination)) =
        (native_ansi_path(source), native_ansi_path(destination))
    else {
        native_set_last_error(87);
        return 0;
    };
    native_copy_file_w(source.as_ptr(), destination.as_ptr(), fail)
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_copy_file_ex_w(
    source: *const u16,
    destination: *const u16,
    _progress: u64,
    _data: u64,
    _cancel: *mut i32,
    flags: u32,
) -> i32 {
    if flags & !0x3 != 0 {
        native_set_last_error(87);
        return 0;
    }
    native_copy_file_w(source, destination, (flags & 1 != 0) as i32)
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_copy_file2(
    source: *const u16,
    destination: *const u16,
    _parameters: *const u8,
) -> i32 {
    if native_copy_file_w(source, destination, 0) != 0 {
        0 // S_OK
    } else {
        let error = native_get_last_error();
        (((error | 0x1000_0000) as u32) << 16 | 1) as i32
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_set_file_attributes_a(
    path: *const u8,
    attributes: u32,
) -> i32 {
    let Some(path) = native_ansi_path(path) else {
        native_set_last_error(87);
        return 0;
    };
    native_set_file_attributes_w(path.as_ptr(), attributes)
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_remove_directory_a(
    path: *const u8,
) -> i32 {
    let Some(path) = native_ansi_path(path) else {
        native_set_last_error(87);
        return 0;
    };
    native_remove_directory_w(path.as_ptr())
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_get_final_path_name_by_handle_a(
    handle: u64,
    output: *mut u8,
    output_len: u32,
    flags: u32,
) -> u32 {
    let required = native_get_final_path_name_by_handle_w(handle, ptr::null_mut(), 0, flags);
    if required == 0 {
        return 0;
    }
    let mut wide_output = vec![0u16; required as usize];
    let written =
        native_get_final_path_name_by_handle_w(handle, wide_output.as_mut_ptr(), required, flags);
    if written == 0 {
        return 0;
    }
    let bytes = wide_output[..written as usize]
        .iter()
        .map(|unit| u8::try_from(*unit).unwrap_or(b'?'))
        .collect::<Vec<_>>();
    if output.is_null() || (output_len as usize) < bytes.len() + 1 {
        return (bytes.len() + 1) as u32;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        output.add(bytes.len()).write(0);
    }
    bytes.len() as u32
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_create_hard_link_w(
    link: *const u16,
    existing: *const u16,
    _security: *const u8,
) -> i32 {
    let (Some(link), Some(existing)) = (wide(link), wide(existing)) else {
        native_set_last_error(87);
        return 0;
    };
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    match context
        .lock()
        .map_err(|_| ())
        .and_then(|mut ctx| ctx.fs.create_hard_link(&link, &existing).map_err(|_| ()))
    {
        Ok(()) => 1,
        Err(()) => {
            let exists = context.lock().is_ok_and(|ctx| ctx.fs.exists(&link));
            native_set_last_error(if exists { 183 } else { 2 });
            0
        }
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_create_hard_link_a(
    link: *const u8,
    existing: *const u8,
    security: *const u8,
) -> i32 {
    let (Some(link), Some(existing)) = (native_ansi_path(link), native_ansi_path(existing)) else {
        native_set_last_error(87);
        return 0;
    };
    native_create_hard_link_w(link.as_ptr(), existing.as_ptr(), security)
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_create_symbolic_link_w(
    link: *const u16,
    target: *const u16,
    flags: u32,
) -> i32 {
    let (Some(link), Some(target)) = (wide(link), wide(target)) else {
        native_set_last_error(87);
        return 0;
    };
    if flags & !0x3 != 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if ctx.fs.exists(&link) {
        native_set_last_error(183);
        return 0;
    }
    let is_directory = flags & 1 != 0 || ctx.fs.is_dir(&target);
    match ctx.fs.create_symlink(&link, &target, is_directory) {
        Ok(()) => 1,
        Err(_) => {
            native_set_last_error(if ctx.fs.exists(&target) { 5 } else { 2 });
            0
        }
    }
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_create_symbolic_link_a(
    link: *const u8,
    target: *const u8,
    flags: u32,
) -> i32 {
    let (Some(link), Some(target)) = (native_ansi_path(link), native_ansi_path(target)) else {
        native_set_last_error(87);
        return 0;
    };
    native_create_symbolic_link_w(link.as_ptr(), target.as_ptr(), flags)
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_replace_file_w(
    destination: *const u16,
    replacement: *const u16,
    backup: *const u16,
    _flags: u32,
    _exclude: u64,
    _reserved: u64,
) -> i32 {
    let (Some(destination), Some(replacement)) = (wide(destination), wide(replacement)) else {
        native_set_last_error(87);
        return 0;
    };
    let backup = if backup.is_null() { None } else { wide(backup) };
    if backup.as_ref().is_some_and(|path| path.is_empty()) {
        native_set_last_error(87);
        return 0;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut ctx) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if !ctx.fs.exists(&destination) || !ctx.fs.exists(&replacement) {
        native_set_last_error(2);
        return 0;
    }
    if backup.as_ref().is_some_and(|path| ctx.fs.exists(path)) {
        native_set_last_error(80);
        return 0;
    }
    let old_contents = match ctx.fs.read_file(&destination) {
        Ok(bytes) => bytes,
        Err(_) => {
            native_set_last_error(5);
            return 0;
        }
    };
    let new_contents = match ctx.fs.read_file(&replacement) {
        Ok(bytes) => bytes,
        Err(_) => {
            native_set_last_error(5);
            return 0;
        }
    };
    if let Some(backup) = backup.as_ref() {
        if ctx.fs.write_file(backup, old_contents).is_err() {
            native_set_last_error(3);
            return 0;
        }
    }
    if ctx.fs.write_file(&destination, new_contents).is_err()
        || ctx.fs.delete_file(&replacement).is_err()
    {
        native_set_last_error(5);
        return 0;
    }
    1
}

pub(in crate::native::linux_x86_64) extern "win64" fn native_replace_file_a(
    destination: *const u8,
    replacement: *const u8,
    backup: *const u8,
    flags: u32,
    exclude: u64,
    reserved: u64,
) -> i32 {
    let (Some(destination), Some(replacement)) =
        (native_ansi_path(destination), native_ansi_path(replacement))
    else {
        native_set_last_error(87);
        return 0;
    };
    let backup = if backup.is_null() {
        vec![0]
    } else {
        let Some(backup) = native_ansi_path(backup) else {
            native_set_last_error(87);
            return 0;
        };
        backup
    };
    native_replace_file_w(
        destination.as_ptr(),
        replacement.as_ptr(),
        if backup.len() == 1 {
            ptr::null()
        } else {
            backup.as_ptr()
        },
        flags,
        exclude,
        reserved,
    )
}
