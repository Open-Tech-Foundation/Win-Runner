//! PSAPI's view of a process's modules: `EnumProcessModules(Ex)`,
//! `GetModuleBaseNameW`, `GetModuleFileNameExW` and `GetModuleInformation`
//! (also under their `K32` names). Only this process's modules can be read:
//! the main image first, then the DLLs it loaded, in load order. Another
//! process's handle is ERROR_ACCESS_DENIED. Also
//! `QueryFullProcessImageNameA/W`.

use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

/// The access `OpenProcess` granted each handle it returned.
static OPENED_ACCESS: Mutex<Option<HashMap<u64, u32>>> = Mutex::new(None);

pub(super) fn remember_process_access(handle: u64, access: u32) {
    if let Ok(mut opened) = OPENED_ACCESS.lock() {
        opened.get_or_insert_with(HashMap::new).insert(handle, access);
    }
}

pub(super) fn forget_process_access(handle: u64) {
    if let Ok(mut opened) = OPENED_ACCESS.lock() {
        if let Some(opened) = opened.as_mut() {
            opened.remove(&handle);
        }
    }
}

/// Whether `handle` grants every right in `needed`; handles not made by
/// `OpenProcess` (the pseudo handle, the process's own) grant all.
fn grants(handle: u64, needed: u32) -> bool {
    const PROCESS_ALL_ACCESS: u32 = 0x1f_ffff;
    let access = OPENED_ACCESS.lock().ok().and_then(|opened| opened.as_ref()?.get(&handle).copied());
    let access = access.map_or(PROCESS_ALL_ACCESS, |access| if access & 0x1000_0000 != 0 { PROCESS_ALL_ACCESS } else { access });
    access & needed == needed
}

/// The current process's modules as (base, size, path), main image first.
fn modules() -> Option<Vec<(u64, u32, String)>> {
    let process = process_ctx()?;
    let mut list = vec![(process.image_base, process.image_size, process.module_path.clone())];
    let loaded = process.loaded_modules.lock().ok()?;
    let mut others: Vec<_> = loaded.values().collect();
    others.sort_by_key(|module| module.load_order);
    list.extend(others.into_iter().map(|module| (module.base, module.size_of_image, module.path.clone())));
    Some(list)
}

/// Whether `handle` names this process (its pseudo handle, or a handle
/// OpenProcess or DuplicateHandle made for it).
fn is_current_process(handle: u64) -> bool {
    let Some(process) = process_ctx() else { return false };
    let original = original_handle(handle);
    original == process.process_handle || original == u64::MAX
}

/// The module `handle` names (0: the main image).
fn module(handle: u64) -> Result<(u64, u32, String), u32> {
    let modules = modules().ok_or(6u32)?;
    let wanted = if handle == 0 { modules[0].0 } else { handle };
    modules.into_iter().find(|(base, _, _)| *base == wanted).ok_or(6) // ERROR_INVALID_HANDLE
}

/// Module queries read the process's memory: PROCESS_QUERY_INFORMATION
/// and PROCESS_VM_READ.
fn check_process(process: u64) -> bool {
    if is_current_process(process) && grants(process, 0x400 | 0x10) {
        return true;
    }
    native_set_last_error(5); // ERROR_ACCESS_DENIED
    false
}

pub(super) extern "win64" fn native_enum_process_modules_ex(
    process: u64,
    output: *mut u64,
    size: u32,
    needed: *mut u32,
    _filter: u32,
) -> i32 {
    if needed.is_null() || (output.is_null() && size != 0) {
        native_set_last_error(998); // ERROR_NOACCESS
        return 0;
    }
    if !check_process(process) {
        return 0;
    }
    let Some(modules) = modules() else {
        native_set_last_error(6);
        return 0;
    };
    let fits = (size as usize / 8).min(modules.len());
    for (index, (base, _, _)) in modules.iter().take(fits).enumerate() {
        unsafe { output.add(index).write_unaligned(*base) };
    }
    unsafe { needed.write((modules.len() * 8) as u32) };
    1
}

pub(super) extern "win64" fn native_enum_process_modules(process: u64, output: *mut u64, size: u32, needed: *mut u32) -> i32 {
    native_enum_process_modules_ex(process, output, size, needed, 0x3) // LIST_MODULES_ALL
}

/// Copy `text` into a caller's buffer of `size` characters, cut to fit and
/// terminated; the characters copied.
fn copy_text(text: &str, output: *mut u16, size: u32) -> u32 {
    if output.is_null() || size == 0 {
        native_set_last_error(122);
        return 0;
    }
    let units: Vec<u16> = text.encode_utf16().collect();
    let copied = units.len().min(size as usize - 1);
    unsafe {
        output.copy_from_nonoverlapping(units.as_ptr(), copied);
        output.add(copied).write(0);
    }
    if copied < units.len() {
        native_set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
    }
    copied as u32
}

/// PSAPI's copy: a short buffer gets what fits and a terminator, and the
/// call returns the buffer's size, leaving the last error alone.
fn truncating_copy(text: &str, output: *mut u16, size: u32) -> u32 {
    let units: Vec<u16> = text.encode_utf16().collect();
    if output.is_null() || size == 0 {
        native_set_last_error(122);
        return 0;
    }
    let copied = units.len().min(size as usize - 1);
    unsafe {
        output.copy_from_nonoverlapping(units.as_ptr(), copied);
        output.add(copied).write(0);
    }
    if copied < units.len() { size } else { copied as u32 }
}

pub(super) extern "win64" fn native_get_module_base_name_w(process: u64, handle: u64, output: *mut u16, size: u32) -> u32 {
    if !check_process(process) {
        return 0;
    }
    match module(handle) {
        Ok((_, _, path)) => {
            let name: Vec<u16> = path.rsplit(['\\', '/']).next().unwrap_or(&path).encode_utf16().collect();
            if output.is_null() || size == 0 {
                native_set_last_error(122);
                return 0;
            }
            // A short buffer gets what fits and a terminator, and the call
            // returns the buffer's size, leaving the last error alone.
            let copied = name.len().min(size as usize - 1);
            unsafe {
                output.copy_from_nonoverlapping(name.as_ptr(), copied);
                output.add(copied).write(0);
            }
            if copied < name.len() { size } else { copied as u32 }
        }
        Err(code) => {
            native_set_last_error(code);
            0
        }
    }
}

pub(super) extern "win64" fn native_get_module_file_name_ex_w(process: u64, handle: u64, output: *mut u16, size: u32) -> u32 {
    if !check_process(process) {
        return 0;
    }
    match module(handle) {
        Ok((_, _, path)) => truncating_copy(&path, output, size),
        Err(code) => {
            native_set_last_error(code);
            0
        }
    }
}

/// `GetModuleInformation`: MODULEINFO is base, size of image, and entry
/// point (read from the mapped image's headers).
pub(super) extern "win64" fn native_get_module_information(process: u64, handle: u64, info: *mut u8, size: u32) -> i32 {
    if !check_process(process) {
        return 0;
    }
    if info.is_null() || size < 24 {
        native_set_last_error(122);
        return 0;
    }
    let (base, image_size, _) = match module(handle) {
        Ok(found) => found,
        Err(code) => {
            native_set_last_error(code);
            return 0;
        }
    };
    let entry = unsafe {
        let headers = base + u64::from((base as *const u8).add(0x3c).cast::<u32>().read_unaligned());
        let rva = (headers as *const u8).add(24 + 16).cast::<u32>().read_unaligned();
        if rva == 0 { 0 } else { base + u64::from(rva) }
    };
    unsafe {
        info.cast::<u64>().write_unaligned(base);
        info.add(8).cast::<u32>().write_unaligned(image_size);
        info.add(12).cast::<u32>().write_unaligned(0);
        info.add(16).cast::<u64>().write_unaligned(entry);
    }
    1
}

/// The image path of the process `handle` names: this process's own, or
/// another guest process's from the session's process table.
fn process_image(handle: u64) -> Option<String> {
    let process = process_ctx()?;
    if is_current_process(handle) {
        return Some(process.module_path.clone());
    }
    let pid = native_get_process_id(handle);
    if pid == 0 {
        return None;
    }
    crate::native::process_table::list().into_iter().find(|guest| guest.pid == pid).map(|guest| guest.image)
}

/// `QueryFullProcessImageNameW(process, flags, buffer, size)`: the image's
/// path (`PROCESS_NAME_NATIVE`, flag 1, gives its NT form); `size` is the
/// buffer's characters going in and the path's length coming out.
fn query_full_process_image_name(process: u64, flags: u32, size: *mut u32) -> Result<Vec<u16>, u32> {
    if size.is_null() || flags & !1 != 0 {
        return Err(87);
    }
    let path = process_image(process).ok_or(6u32)?;
    let path = if flags & 1 != 0 {
        let drive = path.as_bytes().first().copied().unwrap_or(b'C').to_ascii_uppercase();
        format!("\\Device\\HarddiskVolume{}{}", u32::from(drive.saturating_sub(b'A')) + 1, &path[2.min(path.len())..])
    } else {
        path
    };
    let units: Vec<u16> = path.encode_utf16().collect();
    if unsafe { size.read() } as usize <= units.len() {
        return Err(122); // ERROR_INSUFFICIENT_BUFFER
    }
    Ok(units)
}

pub(super) extern "win64" fn native_query_full_process_image_name_w(process: u64, flags: u32, output: *mut u16, size: *mut u32) -> i32 {
    match query_full_process_image_name(process, flags, size) {
        Ok(units) if !output.is_null() => {
            unsafe {
                output.copy_from_nonoverlapping(units.as_ptr(), units.len());
                output.add(units.len()).write(0);
                size.write(units.len() as u32);
            }
            1
        }
        Ok(_) => {
            native_set_last_error(998);
            0
        }
        Err(code) => {
            native_set_last_error(code);
            0
        }
    }
}

pub(super) extern "win64" fn native_query_full_process_image_name_a(process: u64, flags: u32, output: *mut u8, size: *mut u32) -> i32 {
    match query_full_process_image_name(process, flags, size) {
        Ok(units) if !output.is_null() => {
            let bytes: Vec<u8> = String::from_utf16_lossy(&units).bytes().collect();
            unsafe {
                output.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
                output.add(bytes.len()).write(0);
                size.write(bytes.len() as u32);
            }
            1
        }
        Ok(_) => {
            native_set_last_error(998);
            0
        }
        Err(code) => {
            native_set_last_error(code);
            0
        }
    }
}
