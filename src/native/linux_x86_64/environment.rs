//! Guest environment and current-directory APIs.

use super::*;

pub(super) fn environment_block(ptr: u64) -> Result<Vec<(String, String)>, u32> {
    if ptr == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        let mut units = Vec::new();
        while offset < 32 * 1024 {
            let unit = unsafe { (ptr as *const u16).add(offset).read() };
            offset += 1;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        if offset == 32 * 1024 && !units.is_empty() {
            return Err(87);
        }
        if units.is_empty() {
            return Ok(out);
        }
        let entry = String::from_utf16(&units).map_err(|_| 87u32)?;
        let (name, value) = entry
            .split_once('=')
            .filter(|(name, _)| !name.is_empty())
            .ok_or(87u32)?;
        out.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        out.push((name.to_string(), value.to_string()));
    }
}

pub(super) fn environment_strings(environment: &[(String, String)]) -> Vec<u16> {
    let mut block = Vec::new();
    for (name, value) in environment {
        block.extend(format!("{name}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    if environment.is_empty() {
        block.push(0);
    }
    block
}

pub(super) extern "win64" fn native_get_environment_strings_w() -> *const u16 {
    process_ctx()
        .and_then(|process| {
            process
                .environment_block
                .lock()
                .ok()
                .map(|block| block.as_ptr())
        })
        .unwrap_or(EMPTY_ENVIRONMENT_BLOCK.as_ptr())
}

pub(super) extern "win64" fn native_free_environment_strings_w(block: *const u16) -> i32 {
    process_ctx()
        .map(|process| {
            process
                .environment_block
                .lock()
                .is_ok_and(|value| block == value.as_ptr()) as i32
        })
        .unwrap_or((block == EMPTY_ENVIRONMENT_BLOCK.as_ptr()) as i32)
}

pub(super) extern "win64" fn native_get_environment_variable_w(
    name: *const u16,
    output: *mut u16,
    output_len: u32,
) -> u32 {
    if name.is_null() {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let Some(name) = wide(name) else {
        native_set_last_error(87);
        return 0;
    };
    let Some(value) = process_ctx().and_then(|process| {
        process.environment.lock().ok().and_then(|environment| {
            environment
                .iter()
                .find_map(|(key, value)| key.eq_ignore_ascii_case(&name).then(|| value.clone()))
        })
    }) else {
        native_set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    };
    let value: Vec<u16> = value.encode_utf16().collect();
    let required = value.len() + 1;
    if output.is_null() || output_len == 0 {
        return required as u32;
    }
    if (output_len as usize) < required {
        return required as u32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len());
        output.add(value.len()).write(0);
    }
    value.len() as u32
}
pub(super) extern "win64" fn native_set_environment_variable_w(
    name: *const u16,
    value: *const u16,
) -> i32 {
    let (Some(name), value) = (wide(name), if value.is_null() { None } else { wide(value) }) else {
        native_set_last_error(87);
        return 0;
    };
    if name.is_empty() || name.contains('=') {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(mut environment) = process.environment.lock() else {
        return 0;
    };
    if let Some(index) = environment
        .iter()
        .position(|(key, _)| key.eq_ignore_ascii_case(&name))
    {
        if let Some(value) = value {
            environment[index].1 = value;
        } else {
            environment.remove(index);
        }
    } else if let Some(value) = value {
        environment.push((name, value));
    }
    if let Ok(mut block) = process.environment_block.lock() {
        *block = environment_strings(&environment);
    }
    1
}
pub(super) extern "win64" fn native_need_current_directory_for_exe_path_w(
    exe_name: *const u16,
) -> i32 {
    let Some(exe_name) = wide(exe_name) else {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    };
    if exe_name.contains('\\') {
        return 1;
    }
    i32::from(!process_ctx().is_some_and(|process| {
        process.environment.lock().is_ok_and(|environment| {
            environment
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("NoDefaultCurrentDirectoryInExePath"))
        })
    }))
}
pub(super) extern "win64" fn native_get_current_directory_w(
    output_len: u32,
    output: *mut u16,
) -> u32 {
    let cwd = fs_ctx()
        .and_then(|context| context.lock().ok().map(|ctx| ctx.fs.cwd()))
        .unwrap_or_else(|| "C:\\".to_string());
    let encoded: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();
    if output.is_null() || output_len < encoded.len() as u32 {
        return encoded.len() as u32;
    }
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    (encoded.len() - 1) as u32
}
pub(super) extern "win64" fn native_get_system_directory_w(output: *mut u16, capacity: u32) -> u32 {
    const SYSTEM_DIR: &str = r"C:\Windows\System32";
    let encoded: Vec<u16> = SYSTEM_DIR
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    if output.is_null() || capacity < encoded.len() as u32 {
        return encoded.len() as u32 - 1;
    }
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    encoded.len() as u32 - 1
}
pub(super) extern "win64" fn native_sh_get_folder_path_w(
    _window: u64,
    csidl: i32,
    _token: u64,
    _flags: u32,
    output: *mut u16,
) -> i32 {
    let path = match csidl & 0x7fff {
        0x1a => r"C:\Users\runneradmin\AppData\Roaming",
        0x1c => r"C:\Users\runneradmin\AppData\Local",
        0x23 => r"C:\ProgramData",
        0x24 => r"C:\Windows",
        0x25 => r"C:\Windows\System32",
        0x26 => r"C:\Program Files",
        0x2b => r"C:\Program Files\Common Files",
        0x28 => r"C:\Users\runneradmin",
        _ => return 0x8007_0049u32 as i32, // E_FAIL
    };
    if output.is_null() {
        return 0x8007_0057u32 as i32; // E_INVALIDARG
    }
    let encoded: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    0 // S_OK
}
