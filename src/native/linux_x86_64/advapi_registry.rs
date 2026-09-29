//! `Reg*` APIs over the guest registry stored in this process's WinFS.
//!
//! Key handles map to a hive and key path; every call reads the hive files
//! from the process filesystem and every change writes them back, so child
//! processes, later sessions, and snapshots all see the same registry.

use super::*;
use crate::winreg::{self, Hive, RegValue, Registry};

const ERROR_SUCCESS: u32 = 0;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_UNSUPPORTED_TYPE: u32 = 1630;

const HKEY_CLASSES_ROOT: u32 = 0x8000_0000;
const HKEY_CURRENT_USER: u32 = 0x8000_0001;
const HKEY_LOCAL_MACHINE: u32 = 0x8000_0002;
const HKEY_USERS: u32 = 0x8000_0003;

const RRF_NOEXPAND: u32 = 0x1000_0000;

static REGISTRY_HANDLES: LazyLock<Mutex<HashMap<u64, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The full key name (`HKEY_...\path`) a handle stands for. Predefined keys
/// arrive sign-extended on x64 (`(HKEY)(LONG)0x80000002`) or zero-extended.
fn handle_name(key: u64) -> Option<String> {
    let predefined = if key >> 32 == 0xffff_ffff || key >> 32 == 0 {
        Some(key as u32)
    } else {
        None
    };
    match predefined {
        Some(HKEY_CLASSES_ROOT) => Some("HKEY_CLASSES_ROOT".to_string()),
        Some(HKEY_CURRENT_USER) => Some("HKEY_CURRENT_USER".to_string()),
        Some(HKEY_LOCAL_MACHINE) => Some("HKEY_LOCAL_MACHINE".to_string()),
        Some(HKEY_USERS) => Some("HKEY_USERS".to_string()),
        _ => REGISTRY_HANDLES.lock().ok()?.get(&key).cloned(),
    }
}

/// Resolve `key` plus an optional relative `subkey` to a hive and path.
fn resolve(key: u64, subkey: Option<&str>) -> Result<(String, Hive, String), u32> {
    let base = handle_name(key).ok_or(ERROR_INVALID_HANDLE)?;
    let name = match subkey.map(|subkey| subkey.trim_matches('\\')) {
        Some(subkey) if !subkey.is_empty() => format!(r"{base}\{subkey}"),
        _ => base,
    };
    let (hive, path) = winreg::parse_key_name(&name).ok_or(ERROR_FILE_NOT_FOUND)?;
    Ok((name, hive, path))
}

fn new_handle(name: String) -> u64 {
    let handle = NATIVE_REGISTRY_HANDLE_NEXT.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut handles) = REGISTRY_HANDLES.lock() {
        handles.insert(handle, name);
    }
    handle
}

fn with_registry<T>(action: impl FnOnce(&WinFs) -> Result<T, u32>) -> Result<T, u32> {
    let context = fs_ctx().ok_or(ERROR_INVALID_HANDLE)?;
    let ctx = context.lock().map_err(|_| ERROR_INVALID_HANDLE)?;
    action(&ctx.fs)
}

/// Load, change, and save one hive under the filesystem lock.
fn update_registry(
    hive: Hive,
    action: impl FnOnce(&mut Registry) -> Result<(), u32>,
) -> Result<(), u32> {
    let context = fs_ctx().ok_or(ERROR_INVALID_HANDLE)?;
    let mut ctx = context.lock().map_err(|_| ERROR_INVALID_HANDLE)?;
    let mut registry = Registry::load(&ctx.fs).map_err(|_| ERROR_ACCESS_DENIED)?;
    action(&mut registry)?;
    registry
        .save(&mut ctx.fs, hive)
        .map_err(|_| ERROR_ACCESS_DENIED)
}

fn load() -> Result<Registry, u32> {
    with_registry(|fs| Registry::load(fs).map_err(|_| ERROR_ACCESS_DENIED))
}

fn optional_wide(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        wide(ptr)
    }
}

fn status(result: Result<(), u32>) -> u32 {
    match result {
        Ok(()) => ERROR_SUCCESS,
        Err(error) => error,
    }
}

/// Copy `bytes` into a caller buffer with the usual registry size protocol:
/// a null buffer asks for the size, a short one gets `ERROR_MORE_DATA`.
fn copy_out(bytes: &[u8], data: *mut u8, data_len: *mut u32) -> Result<(), u32> {
    let needed = bytes.len() as u32;
    if data.is_null() {
        if !data_len.is_null() {
            unsafe { data_len.write_unaligned(needed) };
        }
        return Ok(());
    }
    if data_len.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let capacity = unsafe { data_len.read_unaligned() };
    unsafe { data_len.write_unaligned(needed) };
    if capacity < needed {
        return Err(ERROR_MORE_DATA);
    }
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), data, bytes.len()) };
    Ok(())
}

/// Copy a name into a character buffer whose length (in characters)
/// includes room for the terminator; report the length without it.
fn copy_name(name: &str, output: *mut u16, output_len: *mut u32) -> Result<(), u32> {
    if output.is_null() || output_len.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let units: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let capacity = unsafe { output_len.read_unaligned() } as usize;
    if capacity < units.len() {
        return Err(ERROR_MORE_DATA);
    }
    unsafe {
        ptr::copy_nonoverlapping(units.as_ptr(), output, units.len());
        output_len.write_unaligned((units.len() - 1) as u32);
    }
    Ok(())
}

fn write_out<T>(target: *mut T, value: T) {
    if !target.is_null() {
        unsafe { target.write_unaligned(value) };
    }
}

pub(super) extern "win64" fn native_reg_open_key_ex_w(
    key: u64,
    subkey: *const u16,
    _options: u32,
    _access: u32,
    out: *mut u64,
) -> u32 {
    if out.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe { out.write_unaligned(0) };
    status((|| {
        let (name, hive, path) = resolve(key, optional_wide(subkey).as_deref())?;
        if load()?.key(hive, &path).is_none() {
            return Err(ERROR_FILE_NOT_FOUND);
        }
        unsafe { out.write_unaligned(new_handle(name)) };
        Ok(())
    })())
}

pub(super) extern "win64" fn native_reg_open_key_ex_a(
    key: u64,
    name: *const u8,
    options: u32,
    access: u32,
    out: *mut u64,
) -> u32 {
    if name.is_null() {
        return native_reg_open_key_ex_w(key, ptr::null(), options, access, out);
    }
    let mut units = Vec::new();
    for index in 0..32768 {
        let byte = unsafe { name.add(index).read() };
        units.push(byte as u16);
        if byte == 0 {
            return native_reg_open_key_ex_w(key, units.as_ptr(), options, access, out);
        }
    }
    native_set_last_error(ERROR_INVALID_PARAMETER);
    ERROR_INVALID_PARAMETER
}

#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_reg_create_key_ex_w(
    key: u64,
    subkey: *const u16,
    _reserved: u32,
    _class: *mut u16,
    _options: u32,
    _access: u32,
    _security: u64,
    out: *mut u64,
    disposition: *mut u32,
) -> u32 {
    if subkey.is_null() || out.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    status((|| {
        let (name, hive, path) = resolve(key, optional_wide(subkey).as_deref())?;
        let mut existed = false;
        update_registry(hive, |registry| {
            existed = registry.create_key(hive, &path).1;
            Ok(())
        })?;
        unsafe { out.write_unaligned(new_handle(name)) };
        // REG_CREATED_NEW_KEY or REG_OPENED_EXISTING_KEY.
        write_out(disposition, if existed { 2 } else { 1 });
        Ok(())
    })())
}

pub(super) extern "win64" fn native_reg_set_value_ex_w(
    key: u64,
    value_name: *const u16,
    _reserved: u32,
    value_type: u32,
    data: *const u8,
    data_len: u32,
) -> u32 {
    if data.is_null() && data_len != 0 {
        return ERROR_INVALID_PARAMETER;
    }
    status((|| {
        let (_, hive, path) = resolve(key, None)?;
        let name = optional_wide(value_name).unwrap_or_default();
        let bytes = if data.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, data_len as usize) }.to_vec()
        };
        update_registry(hive, |registry| {
            let key = registry.key_mut(hive, &path).ok_or(ERROR_FILE_NOT_FOUND)?;
            key.set_value(
                &name,
                RegValue {
                    kind: value_type,
                    data: bytes,
                },
            );
            Ok(())
        })
    })())
}

pub(super) extern "win64" fn native_reg_query_value_ex_w(
    key: u64,
    value_name: *const u16,
    _reserved: *mut u32,
    value_type: *mut u32,
    data: *mut u8,
    data_len: *mut u32,
) -> u32 {
    status((|| {
        let (_, hive, path) = resolve(key, None)?;
        let registry = load()?;
        let value = registry
            .key(hive, &path)
            .ok_or(ERROR_FILE_NOT_FOUND)?
            .value(&optional_wide(value_name).unwrap_or_default())
            .ok_or(ERROR_FILE_NOT_FOUND)?;
        write_out(value_type, value.kind);
        copy_out(&value.data, data, data_len)
    })())
}

/// `RegGetValueW`: typed read with optional subkey; `REG_EXPAND_SZ` data is
/// expanded against the process environment unless `RRF_NOEXPAND` is set.
pub(super) extern "win64" fn native_reg_get_value_w(
    key: u64,
    subkey: *const u16,
    value_name: *const u16,
    flags: u32,
    value_type: *mut u32,
    data: *mut u8,
    data_len: *mut u32,
) -> u32 {
    status((|| {
        let (_, hive, path) = resolve(key, optional_wide(subkey).as_deref())?;
        let registry = load()?;
        let value = registry
            .key(hive, &path)
            .ok_or(ERROR_FILE_NOT_FOUND)?
            .value(&optional_wide(value_name).unwrap_or_default())
            .ok_or(ERROR_FILE_NOT_FOUND)?
            .clone();
        let value = if value.kind == winreg::REG_EXPAND_SZ && flags & RRF_NOEXPAND == 0 {
            let environment = process_ctx()
                .and_then(|process| process.environment.lock().ok().map(|env| env.clone()))
                .unwrap_or_default();
            RegValue::string(&winreg::expand_environment_strings(
                &value.as_str().unwrap_or_default(),
                &environment,
            ))
        } else {
            value
        };
        let type_bit = match value.kind {
            0 => 0x01,
            winreg::REG_SZ => 0x02,
            winreg::REG_EXPAND_SZ => 0x04,
            winreg::REG_BINARY => 0x08,
            winreg::REG_DWORD => 0x10,
            winreg::REG_MULTI_SZ => 0x20,
            winreg::REG_QWORD => 0x40,
            _ => 0,
        };
        if flags & 0xffff & type_bit == 0 {
            return Err(ERROR_UNSUPPORTED_TYPE);
        }
        write_out(value_type, value.kind);
        copy_out(&value.data, data, data_len)
    })())
}

pub(super) extern "win64" fn native_reg_delete_value_w(key: u64, value_name: *const u16) -> u32 {
    status((|| {
        let (_, hive, path) = resolve(key, None)?;
        let name = optional_wide(value_name).unwrap_or_default();
        update_registry(hive, |registry| {
            let key = registry.key_mut(hive, &path).ok_or(ERROR_FILE_NOT_FOUND)?;
            if key.delete_value(&name) {
                Ok(())
            } else {
                Err(ERROR_FILE_NOT_FOUND)
            }
        })
    })())
}

fn delete_key(key: u64, subkey: *const u16, tree: bool) -> u32 {
    status((|| {
        let subkey = optional_wide(subkey);
        let (_, hive, path) = resolve(key, subkey.as_deref())?;
        update_registry(hive, |registry| {
            if registry.key(hive, &path).is_none() {
                return Err(ERROR_FILE_NOT_FOUND);
            }
            if tree && subkey.as_deref().unwrap_or_default().is_empty() {
                // RegDeleteTree without a subkey empties the key itself.
                let key = registry.key_mut(hive, &path).unwrap();
                let names: Vec<String> = key
                    .values()
                    .into_iter()
                    .map(|(name, _)| name.to_string())
                    .collect();
                for name in names {
                    key.delete_value(&name);
                }
                let subkeys: Vec<String> = registry
                    .key(hive, &path)
                    .unwrap()
                    .subkey_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                for subkey in subkeys {
                    let _ = registry.delete_key(hive, &format!(r"{path}\{subkey}"), true);
                }
                return Ok(());
            }
            registry
                .delete_key(hive, &path, tree)
                .map_err(|_| ERROR_ACCESS_DENIED)
        })
    })())
}

pub(super) extern "win64" fn native_reg_delete_key_w(key: u64, subkey: *const u16) -> u32 {
    if subkey.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    delete_key(key, subkey, false)
}

pub(super) extern "win64" fn native_reg_delete_tree_w(key: u64, subkey: *const u16) -> u32 {
    delete_key(key, subkey, true)
}

#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_reg_enum_key_ex_w(
    key: u64,
    index: u32,
    name: *mut u16,
    name_len: *mut u32,
    _reserved: *mut u32,
    class: *mut u16,
    class_len: *mut u32,
    last_write: *mut u64,
) -> u32 {
    status((|| {
        let (_, hive, path) = resolve(key, None)?;
        let registry = load()?;
        let key = registry.key(hive, &path).ok_or(ERROR_FILE_NOT_FOUND)?;
        let subkey = *key
            .subkey_names()
            .get(index as usize)
            .ok_or(ERROR_NO_MORE_ITEMS)?;
        copy_name(subkey, name, name_len)?;
        if !class.is_null() && !class_len.is_null() {
            copy_name("", class, class_len)?;
        }
        write_out(last_write, 0);
        Ok(())
    })())
}

#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_reg_enum_value_w(
    key: u64,
    index: u32,
    name: *mut u16,
    name_len: *mut u32,
    _reserved: *mut u32,
    value_type: *mut u32,
    data: *mut u8,
    data_len: *mut u32,
) -> u32 {
    status((|| {
        let (_, hive, path) = resolve(key, None)?;
        let registry = load()?;
        let key = registry.key(hive, &path).ok_or(ERROR_FILE_NOT_FOUND)?;
        let values = key.values();
        let (value_name, value) = values.get(index as usize).ok_or(ERROR_NO_MORE_ITEMS)?;
        copy_name(value_name, name, name_len)?;
        write_out(value_type, value.kind);
        copy_out(&value.data, data, data_len)
    })())
}

#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_reg_query_info_key_w(
    key: u64,
    class: *mut u16,
    class_len: *mut u32,
    _reserved: *mut u32,
    subkeys: *mut u32,
    max_subkey_len: *mut u32,
    max_class_len: *mut u32,
    values: *mut u32,
    max_value_name_len: *mut u32,
    max_value_len: *mut u32,
    security_descriptor_len: *mut u32,
    last_write: *mut u64,
) -> u32 {
    status((|| {
        let (_, hive, path) = resolve(key, None)?;
        let registry = load()?;
        let key = registry.key(hive, &path).ok_or(ERROR_FILE_NOT_FOUND)?;
        let names = key.subkey_names();
        let entries = key.values();
        if !class.is_null() && !class_len.is_null() {
            copy_name("", class, class_len)?;
        }
        write_out(subkeys, names.len() as u32);
        write_out(
            max_subkey_len,
            names
                .iter()
                .map(|name| name.encode_utf16().count() as u32)
                .max()
                .unwrap_or(0),
        );
        write_out(max_class_len, 0);
        write_out(values, entries.len() as u32);
        write_out(
            max_value_name_len,
            entries
                .iter()
                .map(|(name, _)| name.encode_utf16().count() as u32)
                .max()
                .unwrap_or(0),
        );
        write_out(
            max_value_len,
            entries
                .iter()
                .map(|(_, value)| value.data.len() as u32)
                .max()
                .unwrap_or(0),
        );
        write_out(security_descriptor_len, 0);
        write_out(last_write, 0);
        Ok(())
    })())
}

pub(super) extern "win64" fn native_reg_close_key(key: u64) -> u32 {
    if let Ok(mut handles) = REGISTRY_HANDLES.lock() {
        if handles.remove(&key).is_some() {
            return ERROR_SUCCESS;
        }
    }
    if handle_name(key).is_some() {
        ERROR_SUCCESS
    } else {
        ERROR_INVALID_HANDLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(HKEY)(LONG)0x8000000x` as x64 code passes it.
    fn predefined(key: u32) -> u64 {
        key as i32 as i64 as u64
    }

    fn wide_z(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn open(key: u64, subkey: &str) -> Result<u64, u32> {
        let mut handle = 0;
        match native_reg_open_key_ex_w(key, wide_z(subkey).as_ptr(), 0, 0x20019, &mut handle) {
            0 => Ok(handle),
            error => Err(error),
        }
    }

    fn create(key: u64, subkey: &str) -> (u64, u32) {
        let mut handle = 0;
        let mut disposition = 0;
        assert_eq!(
            native_reg_create_key_ex_w(
                key,
                wide_z(subkey).as_ptr(),
                0,
                ptr::null_mut(),
                0,
                0xf003f,
                0,
                &mut handle,
                &mut disposition,
            ),
            0
        );
        (handle, disposition)
    }

    fn query(key: u64, name: &str) -> Result<(u32, Vec<u8>), u32> {
        let name = wide_z(name);
        let mut kind = 0;
        let mut len = 0;
        let status = native_reg_query_value_ex_w(
            key,
            name.as_ptr(),
            ptr::null_mut(),
            &mut kind,
            ptr::null_mut(),
            &mut len,
        );
        if status != 0 {
            return Err(status);
        }
        let mut data = vec![0u8; len as usize];
        assert_eq!(
            native_reg_query_value_ex_w(
                key,
                name.as_ptr(),
                ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut len,
            ),
            0
        );
        Ok((kind, data))
    }

    #[test]
    fn stock_keys_answer_version_and_folder_queries() {
        let key = open(
            predefined(HKEY_LOCAL_MACHINE),
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        )
        .unwrap();
        let (kind, data) = query(key, "CurrentMajorVersionNumber").unwrap();
        assert_eq!(
            (kind, data),
            (winreg::REG_DWORD, 10u32.to_le_bytes().to_vec())
        );
        let (kind, data) = query(key, "CurrentBuildNumber").unwrap();
        assert_eq!(kind, winreg::REG_SZ);
        assert_eq!(data, RegValue::string("19045").data);
        assert_eq!(query(key, "NoSuchValue"), Err(ERROR_FILE_NOT_FOUND));
        assert_eq!(native_reg_close_key(key), 0);

        // A short buffer reports ERROR_MORE_DATA and the size it needs.
        let key = open(predefined(HKEY_CURRENT_USER), "Environment").unwrap();
        let name = wide_z("TEMP");
        let mut small = [0u8; 4];
        let mut len = small.len() as u32;
        assert_eq!(
            native_reg_query_value_ex_w(
                key,
                name.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                small.as_mut_ptr(),
                &mut len,
            ),
            ERROR_MORE_DATA
        );
        assert_eq!(
            len as usize,
            RegValue::expand_string(r"%USERPROFILE%\AppData\Local\Temp")
                .data
                .len()
        );
        native_reg_close_key(key);

        assert_eq!(
            open(predefined(HKEY_CURRENT_USER), r"Software\NoSuchVendor"),
            Err(ERROR_FILE_NOT_FOUND)
        );
        assert_eq!(open(0x1234, "x"), Err(ERROR_INVALID_HANDLE));
    }

    #[test]
    fn created_keys_and_values_persist_in_the_guest_hive() {
        let (key, disposition) = create(
            predefined(HKEY_CURRENT_USER),
            r"Software\WinRunnerTests\Persist",
        );
        assert_eq!(disposition, 1);
        let data = RegValue::string("value").data;
        assert_eq!(
            native_reg_set_value_ex_w(
                key,
                wide_z("Name").as_ptr(),
                0,
                winreg::REG_SZ,
                data.as_ptr(),
                data.len() as u32,
            ),
            0
        );
        let dword = 42u32.to_le_bytes();
        native_reg_set_value_ex_w(key, ptr::null(), 0, winreg::REG_DWORD, dword.as_ptr(), 4);
        native_reg_close_key(key);

        let (again, disposition) = create(
            predefined(HKEY_CURRENT_USER),
            r"Software\WinRunnerTests\Persist",
        );
        assert_eq!(disposition, 2);
        assert_eq!(query(again, "name").unwrap(), (winreg::REG_SZ, data));
        assert_eq!(
            query(again, "").unwrap(),
            (winreg::REG_DWORD, dword.to_vec())
        );

        // The hive file in WinFS holds the change for later processes.
        let registry = with_registry(|fs| Ok(Registry::load(fs).unwrap())).unwrap();
        assert_eq!(
            registry
                .value(
                    Hive::CurrentUser,
                    r"Software\WinRunnerTests\Persist",
                    "Name"
                )
                .and_then(RegValue::as_str)
                .as_deref(),
            Some("value")
        );

        assert_eq!(native_reg_delete_value_w(again, wide_z("Name").as_ptr()), 0);
        assert_eq!(
            native_reg_delete_value_w(again, wide_z("Name").as_ptr()),
            ERROR_FILE_NOT_FOUND
        );
        native_reg_close_key(again);
        let parent = open(predefined(HKEY_CURRENT_USER), r"Software\WinRunnerTests").unwrap();
        assert_eq!(
            native_reg_delete_key_w(parent, wide_z("Persist").as_ptr()),
            0
        );
        assert_eq!(open(parent, "Persist"), Err(ERROR_FILE_NOT_FOUND));
        native_reg_close_key(parent);
    }

    #[test]
    fn enumeration_and_info_walk_subkeys_and_values_in_order() {
        let (key, _) = create(
            predefined(HKEY_CURRENT_USER),
            r"Software\WinRunnerTests\Enum",
        );
        for (name, value) in [("beta", "2"), ("Alpha", "1")] {
            let data = RegValue::string(value).data;
            native_reg_set_value_ex_w(
                key,
                wide_z(name).as_ptr(),
                0,
                winreg::REG_SZ,
                data.as_ptr(),
                data.len() as u32,
            );
        }
        for subkey in ["Zed", "Mid"] {
            let (child, _) = create(key, subkey);
            native_reg_close_key(child);
        }

        let (mut subkeys, mut values, mut max_name, mut max_data) = (0, 0, 0, 0);
        assert_eq!(
            native_reg_query_info_key_w(
                key,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut subkeys,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut values,
                &mut max_name,
                &mut max_data,
                ptr::null_mut(),
                ptr::null_mut(),
            ),
            0
        );
        assert_eq!((subkeys, values, max_name), (2, 2, 5));
        assert_eq!(max_data, 4);

        let mut names = Vec::new();
        for index in 0.. {
            let mut buffer = [0u16; 32];
            let mut len = buffer.len() as u32;
            let status = native_reg_enum_key_ex_w(
                key,
                index,
                buffer.as_mut_ptr(),
                &mut len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            assert_eq!(status, 0);
            names.push(String::from_utf16(&buffer[..len as usize]).unwrap());
        }
        assert_eq!(names, ["Mid", "Zed"]);

        let mut buffer = [0u16; 32];
        let mut len = buffer.len() as u32;
        let mut kind = 0;
        let mut data = [0u8; 16];
        let mut data_len = data.len() as u32;
        assert_eq!(
            native_reg_enum_value_w(
                key,
                0,
                buffer.as_mut_ptr(),
                &mut len,
                ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_len,
            ),
            0
        );
        assert_eq!(
            String::from_utf16(&buffer[..len as usize]).unwrap(),
            "Alpha"
        );
        assert_eq!(&data[..data_len as usize], RegValue::string("1").data);
        let mut tiny = [0u16; 2];
        let mut tiny_len = tiny.len() as u32;
        assert_eq!(
            native_reg_enum_value_w(
                key,
                1,
                tiny.as_mut_ptr(),
                &mut tiny_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            ),
            ERROR_MORE_DATA
        );

        let parent = open(predefined(HKEY_CURRENT_USER), r"Software\WinRunnerTests").unwrap();
        assert_eq!(
            native_reg_delete_key_w(parent, wide_z("Enum").as_ptr()),
            ERROR_ACCESS_DENIED
        );
        assert_eq!(native_reg_delete_tree_w(parent, wide_z("Enum").as_ptr()), 0);
        assert_eq!(open(parent, "Enum"), Err(ERROR_FILE_NOT_FOUND));
        native_reg_close_key(parent);
        native_reg_close_key(key);
    }

    #[test]
    fn get_value_filters_types_and_expands_environment_strings() {
        let (key, _) = create(
            predefined(HKEY_CURRENT_USER),
            r"Software\WinRunnerTests\GetValue",
        );
        let data = RegValue::expand_string(r"%SystemRoot%\x").data;
        native_reg_set_value_ex_w(
            key,
            wide_z("Where").as_ptr(),
            0,
            winreg::REG_EXPAND_SZ,
            data.as_ptr(),
            data.len() as u32,
        );
        let process = process_ctx().unwrap();
        let saved = process.environment.lock().unwrap().clone();
        *process.environment.lock().unwrap() =
            vec![("SystemRoot".to_string(), r"C:\Windows".to_string())];
        let read = |flags: u32| {
            let mut kind = 0;
            let mut buffer = [0u8; 64];
            let mut len = buffer.len() as u32;
            let status = native_reg_get_value_w(
                predefined(HKEY_CURRENT_USER),
                wide_z(r"Software\WinRunnerTests\GetValue").as_ptr(),
                wide_z("Where").as_ptr(),
                flags,
                &mut kind,
                buffer.as_mut_ptr(),
                &mut len,
            );
            (status, kind, buffer[..len as usize].to_vec())
        };
        // RRF_RT_REG_SZ expands; RRF_NOEXPAND keeps the raw text.
        let (status, kind, bytes) = read(0x02);
        *process.environment.lock().unwrap() = saved;
        assert_eq!((status, kind), (0, winreg::REG_SZ));
        assert_eq!(bytes, RegValue::string(r"C:\Windows\x").data);
        let (status, kind, bytes) = read(0x04 | RRF_NOEXPAND);
        assert_eq!((status, kind), (0, winreg::REG_EXPAND_SZ));
        assert_eq!(bytes, data);
        assert_eq!(read(0x10).0, ERROR_UNSUPPORTED_TYPE);
        native_reg_close_key(key);
    }
}
