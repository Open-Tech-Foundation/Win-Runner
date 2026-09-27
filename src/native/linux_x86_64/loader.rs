//! PE image mapping, relocation, and executable protection for Linux x86-64.

use super::*;

pub(super) fn map(img: &PeImage) -> Result<Mapping, String> {
    if img.image_base & 4095 != 0 {
        return Err(format!(
            "native backend requires a page-aligned image base, got 0x{:x}",
            img.image_base
        ));
    }
    let len = page_len(img.image.len())?;
    // SAFETY: mmap is called with a page-aligned requested address and a
    // checked non-zero length. MAP_FIXED_NOREPLACE prevents clobbering a
    // host mapping if the PE preferred base is occupied.
    let raw = unsafe {
        mmap(
            img.image_base as *mut c_void,
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if raw == MAP_FAILED {
        return Err(format!(
            "native backend could not map preferred base 0x{:x}: {}",
            img.image_base,
            std::io::Error::last_os_error()
        ));
    }
    if raw as u64 != img.image_base {
        // Defensive: MAP_FIXED_NOREPLACE should guarantee this.
        unsafe { munmap(raw, len) };
        return Err("native backend mapped image at an unexpected address".to_string());
    }
    // SAFETY: `raw` names a fresh mapping at least `len` bytes long; the
    // source slice is exactly the loaded PE image and fits in that range.
    unsafe { ptr::copy_nonoverlapping(img.image.as_ptr(), raw.cast(), img.image.len()) };
    Ok(Mapping {
        ptr: raw.cast(),
        len,
    })
}

/// Reserve a non-conflicting host address and rebase a child image to the
/// address actually chosen by the kernel.
#[allow(dead_code)] // attached to CreateProcessW's child launcher next
pub(super) fn map_relocated(img: &PeImage) -> Result<(Mapping, PeImage), String> {
    let len = page_len(img.image.len())?;
    let raw = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if raw == MAP_FAILED {
        return Err(format!(
            "native backend could not reserve relocated image: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mapping = Mapping {
        ptr: raw.cast(),
        len,
    };
    let mut relocated = img.clone();
    if let Err(error) = crate::pe::rebase(&mut relocated, raw as u64) {
        return Err(format!("native backend could not rebase image: {error}"));
    }
    unsafe {
        ptr::copy_nonoverlapping(relocated.image.as_ptr(), mapping.ptr, relocated.image.len())
    };
    Ok((mapping, relocated))
}

#[cfg(test)]
mod relocated_map_tests {
    use super::{map_relocated, PeImage};

    #[test]
    fn maps_at_the_reserved_address_and_applies_dir64_delta() {
        let mut bytes = vec![0; 16];
        bytes[..8].copy_from_slice(&0x0001_4000_0100u64.to_le_bytes());
        let image = PeImage {
            is_dll: false,
            image_base: 0x0001_4000_0000,
            entry_rva: 0,
            size_of_image: 16,
            image: bytes,
            imports: vec![],
            exports: vec![],
            unsupported: vec![],
            tls: None,
            code_ranges: vec![],
            relocations: vec![0],
        };
        let (mapping, relocated) = map_relocated(&image).unwrap();
        assert_eq!(relocated.image_base, mapping.ptr as u64);
        let value = unsafe {
            u64::from_le_bytes(
                std::slice::from_raw_parts(mapping.ptr, 8)
                    .try_into()
                    .unwrap(),
            )
        };
        assert_eq!(value, mapping.ptr as u64 + 0x100);
    }
}

#[cfg(test)]
mod module_export_tests {
    use super::{
        load_guest_module, native_free_library, native_get_module_handle_w,
        native_get_proc_address, API_SET_MODULE,
    };
    use crate::native::linux_x86_64::state::NativeLoadedModule;
    use crate::pe::Export;
    use std::ffi::CString;

    #[test]
    fn get_proc_address_resolves_named_and_ordinal_dll_exports() {
        let handle = 0x7a00_0000;
        let module = NativeLoadedModule {
            path: r"C:\bin\sample.dll".to_string(),
            name: "sample.dll".to_string(),
            base: handle,
            size_of_image: 0x4000,
            exports: vec![Export {
                ordinal: 7,
                name: Some("SampleEntry".to_string()),
                target_rva: 0x1234,
                forwarder: None,
            }],
        };
        let process = &*super::TEST_PROCESS;
        process
            .loaded_modules
            .lock()
            .unwrap()
            .insert(handle, module);
        let name = CString::new("SampleEntry").unwrap();
        assert_eq!(
            native_get_proc_address(handle, name.as_ptr().cast()),
            handle + 0x1234
        );
        assert_eq!(
            native_get_proc_address(handle, 7usize as *const u8),
            handle + 0x1234
        );
        process.loaded_modules.lock().unwrap().remove(&handle);
    }

    #[test]
    fn get_proc_address_follows_system_module_forwarder() {
        let handle = 0x7a00_1000;
        let module = NativeLoadedModule {
            path: r"C:\bin\forwarder.dll".to_string(),
            name: "forwarder.dll".to_string(),
            base: handle,
            size_of_image: 0x4000,
            exports: vec![Export {
                ordinal: 1,
                name: Some("ForwardedTick".to_string()),
                target_rva: 0x200,
                forwarder: Some("kernel32.GetTickCount".to_string()),
            }],
        };
        let process = &*super::TEST_PROCESS;
        process
            .loaded_modules
            .lock()
            .unwrap()
            .insert(handle, module);
        let name = CString::new("ForwardedTick").unwrap();
        assert_ne!(native_get_proc_address(handle, name.as_ptr().cast()), 0);
        assert_eq!(API_SET_MODULE, crate::native::linux_x86_64::API_SET_MODULE);
        process.loaded_modules.lock().unwrap().remove(&handle);
    }

    #[test]
    fn load_library_maps_a_guest_dll_from_winfs() {
        let mut asm = crate::pe::builder::Asm::new();
        asm.mov_r32_imm(0, 1); // DllMain reports successful process attach
        asm.ret();
        let mut bytes = crate::pe::builder::build(asm, &[]);
        let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let coff = pe + 4;
        let opt = coff + 20;
        let characteristics = u16::from_le_bytes(bytes[coff + 18..coff + 20].try_into().unwrap());
        bytes[coff + 18..coff + 20].copy_from_slice(&(characteristics | 0x2000).to_le_bytes());
        bytes[opt + 24..opt + 32].copy_from_slice(&0x0000_5000_0000_0000u64.to_le_bytes());

        let process = &*super::TEST_PROCESS;
        let path = r"C:\loader-tests\sample-runtime.dll";
        {
            let mut native_fs = process.fs.lock().unwrap();
            native_fs.fs.mkdir(r"C:\loader-tests").unwrap();
            native_fs.fs.write_file(path, bytes).unwrap();
        }
        let name: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = load_guest_module(path);
        let handle = handle.expect("WinFS DLL loads");
        assert_ne!(handle, API_SET_MODULE);
        assert_eq!(handle, native_get_module_handle_w(name.as_ptr()));
        assert_eq!(native_free_library(handle), 1);
        process.fs.lock().unwrap().fs.delete_file(path).unwrap();
    }
}

pub(super) fn protect_exec(mapping: &Mapping) -> Result<(), String> {
    // PE sections need individual protections. Until the native mapper
    // carries section characteristics, keep the image RWX so CRT startup
    // can initialize `.data`; the guest still runs in a forked child.
    if unsafe {
        mprotect(
            mapping.ptr.cast(),
            mapping.len,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        return Err(format!(
            "native backend could not mark image executable: {e}"
        ));
    }
    Ok(())
}

pub(super) extern "win64" fn native_get_module_handle_w(name: *const u16) -> u64 {
    if name.is_null() {
        process_ctx().map(|process| process.image_base).unwrap_or(0)
    } else {
        wide(name)
            .and_then(|name| module_handle_by_name(&name))
            .unwrap_or_else(|| {
                native_set_last_error(126);
                0
            })
    }
}
fn native_module_name_supported(name: &str) -> bool {
    let module = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    matches!(
        module.as_str(),
        "kernel32"
            | "kernel32.dll"
            | "kernelbase"
            | "kernelbase.dll"
            | "ntdll"
            | "ntdll.dll"
            | "advapi32"
            | "advapi32.dll"
            | "bcryptprimitives"
            | "bcryptprimitives.dll"
            | "userenv"
            | "userenv.dll"
            | "winmm"
            | "winmm.dll"
            | "ws2_32"
            | "ws2_32.dll"
    )
}
pub(super) extern "win64" fn native_get_module_handle_ex_w(
    flags: u32,
    name: *const u16,
    output: *mut u64,
) -> i32 {
    if output.is_null() {
        native_set_last_error(87);
        return 0;
    }
    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
    let module = if flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 {
        if name.is_null() {
            return 0;
        }
        let address = name as u64;
        let Some(process) = process_ctx() else {
            return 0;
        };
        let modules = process.loaded_modules.lock().ok();
        modules
            .and_then(|modules| {
                modules.values().find_map(|module| {
                    let end = module.base.checked_add(module.size_of_image as u64)?;
                    (address >= module.base && address < end).then_some(module.base)
                })
            })
            .or_else(|| {
                let end = process.image_base.checked_add(process.image_size as u64)?;
                (address >= process.image_base && address < end).then_some(process.image_base)
            })
            .unwrap_or(0)
    } else if name.is_null() {
        process_ctx().map(|process| process.image_base).unwrap_or(0)
    } else {
        wide(name)
            .and_then(|name| module_handle_by_name(&name))
            .unwrap_or(0)
    };
    if module == 0 {
        native_set_last_error(126);
        return 0;
    }
    unsafe { output.write(module) };
    1
}

pub(super) unsafe fn ascii_z(ptr: *const u8) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while len < 128 && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    if len == 128 {
        return None;
    }
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(ptr, len) }).ok()
}

pub(super) extern "win64" fn native_load_library_ex_w(
    path: *const u16,
    _file: u64,
    _flags: u32,
) -> u64 {
    let Some(path) = wide(path) else {
        native_set_last_error(126);
        return 0;
    };
    load_guest_module(&path).unwrap_or_else(|| {
        native_set_last_error(126); // ERROR_MOD_NOT_FOUND
        0
    })
}

pub(super) extern "win64" fn native_load_library_ex_a(
    path: *const u8,
    _file: u64,
    _flags: u32,
) -> u64 {
    let Some(path) = (unsafe { ascii_z(path) }) else {
        native_set_last_error(126);
        return 0;
    };
    load_guest_module(path).unwrap_or_else(|| {
        native_set_last_error(126);
        0
    })
}

pub(super) extern "win64" fn native_get_module_handle_a(name: *const u8) -> u64 {
    match unsafe { ascii_z(name) } {
        Some(value) => module_handle_by_name(value).unwrap_or(0),
        _ => {
            native_set_last_error(126);
            0
        }
    }
}

fn module_handle_by_name(name: &str) -> Option<u64> {
    if native_module_name_supported(name) {
        return Some(API_SET_MODULE);
    }
    let process = process_ctx()?;
    if process.module_path.eq_ignore_ascii_case(name)
        || module_basename(&process.module_path).eq_ignore_ascii_case(name)
    {
        return Some(process.image_base);
    }
    let modules = process.loaded_modules.lock().ok()?;
    modules
        .values()
        .find(|module| {
            module.name.eq_ignore_ascii_case(name)
                || module.name.eq_ignore_ascii_case(&module_basename(name))
                || module.path.eq_ignore_ascii_case(name)
        })
        .map(|module| module.base)
}

fn module_basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn guest_module_path(name: &str) -> Option<(String, Vec<u8>)> {
    let process = process_ctx()?;
    let fs = process.fs.lock().ok()?;
    let suffixed = if name.rsplit(['\\', '/']).next()?.contains('.') {
        name.to_string()
    } else {
        format!("{name}.dll")
    };
    let path = if fs.fs.exists(&suffixed) {
        Some(suffixed.clone())
    } else {
        fs.fs
            .find_file_path_suffix(&format!("\\{}", module_basename(&suffixed)))
    }?;
    let bytes = fs.fs.read_file(&path).ok()?;
    Some((path, bytes))
}

fn load_guest_module(name: &str) -> Option<u64> {
    if native_module_name_supported(name) {
        return Some(API_SET_MODULE);
    }
    if let Some(handle) = module_handle_by_name(name) {
        return Some(handle);
    }
    let (path, bytes) = guest_module_path(name)?;
    let image = crate::pe::load_lenient(&bytes).ok()?;
    if !image.is_dll {
        return None;
    }
    // This first loader slice supports DLLs whose dependencies are already
    // backed by native shims. Recursive guest-DLL resolution and DLL TLS are
    // added in subsequent loader work.
    if image.tls.is_some()
        || image
            .imports
            .iter()
            .chain(&image.unsupported)
            .any(|import| !super::registry::supports_import(&import.dll, &import.func))
    {
        return None;
    }
    let (mapping, image) = match map_relocated(&image) {
        Ok(mapped) => mapped,
        Err(_) if image.relocations.is_empty() => (map(&image).ok()?, image),
        Err(_) => return None,
    };
    let stubs = super::registry::patch_baseline_imports(&mapping, &image, false).ok()?;
    protect_exec(&mapping).ok()?;
    let base = mapping.ptr as u64;
    let module = NativeLoadedModule {
        path: path.clone(),
        name: module_basename(&path),
        base,
        size_of_image: image.size_of_image,
        exports: image.exports,
    };
    let process = process_ctx()?;
    let handle = module.base;
    {
        let mut modules = process.loaded_modules.lock().ok()?;
        if let Some(existing) = modules.values().find(|loaded| {
            loaded.path.eq_ignore_ascii_case(&path)
                || loaded.name.eq_ignore_ascii_case(&module.name)
        }) {
            return Some(existing.base);
        }
        modules.insert(handle, module);
    }
    if image.entry_rva != 0 {
        let entry = base.checked_add(image.entry_rva as u64)?;
        // SAFETY: the validated PE entry RVA is inside the executable mapping.
        let dll_main: unsafe extern "win64" fn(u64, u32, u64) -> i32 =
            unsafe { std::mem::transmute(entry as usize) };
        if unsafe { dll_main(base, 1, 0) } == 0 {
            if let Ok(mut modules) = process.loaded_modules.lock() {
                modules.remove(&handle);
            }
            return None;
        }
    }
    if let Some(stubs) = stubs {
        std::mem::forget(stubs);
    }
    // The mapping belongs to the guest process and remains live until that
    // worker exits. FreeLibrary reference counting will own unmapping later.
    std::mem::forget(mapping);
    Some(handle)
}

pub(super) extern "win64" fn native_get_proc_address(module: u64, name: *const u8) -> u64 {
    if name.is_null() {
        native_set_last_error(127);
        return 0;
    }
    let selector = if (name as usize) <= u16::MAX as usize {
        format!("#{}", name as usize)
    } else if let Some(name) = unsafe { ascii_z(name) } {
        name.to_string()
    } else {
        native_set_last_error(127);
        return 0;
    };
    if module != API_SET_MODULE {
        return resolve_module_export(module, &selector, 0).unwrap_or_else(|| {
            native_set_last_error(127); // ERROR_PROC_NOT_FOUND
            0
        });
    }
    match selector
        .strip_prefix('#')
        .is_none()
        .then_some(selector.as_str())
    {
        Some("CompareStringEx") => native_compare_string_ex as *const () as usize as u64,
        Some("CompareStringOrdinal") => native_compare_string_ordinal as *const () as usize as u64,
        Some("GetEnvironmentVariableW") => {
            native_get_environment_variable_w as *const () as usize as u64
        }
        Some("GetCurrentDirectoryW") => native_get_current_directory_w as *const () as usize as u64,
        Some("NtDeviceIoControlFile") => {
            native_nt_device_io_control_file as *const () as usize as u64
        }
        Some("NtQueryInformationFile") => {
            native_nt_query_information_file as *const () as usize as u64
        }
        Some("NtSetInformationFile") => native_nt_set_information_file as *const () as usize as u64,
        Some("NtQueryVolumeInformationFile") => {
            native_nt_query_volume_information_file as *const () as usize as u64
        }
        Some("NtQueryDirectoryFile") => native_nt_query_directory_file as *const () as usize as u64,
        Some("NtQuerySystemInformation") => {
            native_nt_query_system_information as *const () as usize as u64
        }
        Some("NtQueryInformationProcess") => {
            native_nt_query_information_process as *const () as usize as u64
        }
        Some(function) => baseline_trampoline(function).unwrap_or_else(|| {
            if native_diagnostic_enabled() {
                let message = format!("unsupported native dynamic import: {function}\n");
                unsafe { write(2, message.as_ptr().cast(), message.len()) };
            }
            native_set_last_error(127); // ERROR_PROC_NOT_FOUND
            0
        }),
        None => {
            native_set_last_error(127);
            0
        }
    }
}

fn resolve_module_export(module: u64, selector: &str, depth: usize) -> Option<u64> {
    if depth >= 16 {
        return None;
    }
    let process = process_ctx()?;
    let (base, export) = {
        let modules = process.loaded_modules.lock().ok()?;
        let loaded = modules.get(&module)?;
        let export = if let Some(ordinal) = selector.strip_prefix('#') {
            let ordinal = ordinal.parse::<u32>().ok()?;
            loaded
                .exports
                .iter()
                .find(|export| export.ordinal == ordinal)?
        } else {
            loaded
                .exports
                .iter()
                .find(|export| export.name.as_deref() == Some(selector))?
        };
        (loaded.base, export.clone())
    };
    if let Some(forwarder) = export.forwarder {
        let (dll, function) = forwarder.rsplit_once('.')?;
        let forwarded_module = module_handle_by_name(dll).or_else(|| load_guest_module(dll))?;
        if forwarded_module == API_SET_MODULE {
            let function = std::ffi::CString::new(function).ok()?;
            let address = native_get_proc_address(forwarded_module, function.as_ptr().cast());
            return (address != 0).then_some(address);
        }
        return resolve_module_export(forwarded_module, function, depth + 1);
    }
    base.checked_add(export.target_rva as u64)
}

// libuv resolves this NTDLL entry during startup. Until a device-I/O
// translation exists, return a real NT failure code to callers instead
// of pretending that the operation succeeded.
pub(super) extern "win64" fn native_free_library(module: u64) -> i32 {
    if module == API_SET_MODULE {
        return 1;
    }
    process_ctx()
        .and_then(|process| {
            process
                .loaded_modules
                .lock()
                .ok()
                .map(|mut modules| modules.remove(&module).is_some() as i32)
        })
        .unwrap_or(0)
}

pub(super) struct Mapping {
    pub(super) ptr: *mut u8,
    pub(super) len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `len` come from a successful mmap in `map`.
        unsafe { munmap(self.ptr.cast(), self.len) };
    }
}
