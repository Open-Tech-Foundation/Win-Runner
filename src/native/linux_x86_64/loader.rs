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
            .filter(|name| native_module_name_supported(name))
            .map(|_| API_SET_MODULE)
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
    _flags: u32,
    _name: *const u16,
    output: *mut u64,
) -> i32 {
    if output.is_null() {
        return 0;
    }
    let module = process_ctx().map(|process| process.image_base).unwrap_or(0);
    if module == 0 {
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
    (!path.is_null()).then_some(API_SET_MODULE).unwrap_or(0)
}

pub(super) extern "win64" fn native_load_library_ex_a(
    path: *const u8,
    _file: u64,
    _flags: u32,
) -> u64 {
    if unsafe { ascii_z(path) }.is_some() {
        API_SET_MODULE
    } else {
        native_set_last_error(126); // ERROR_MOD_NOT_FOUND
        0
    }
}

pub(super) extern "win64" fn native_get_module_handle_a(name: *const u8) -> u64 {
    match unsafe { ascii_z(name) } {
        Some(value) if native_module_name_supported(value) => API_SET_MODULE,
        _ => 0,
    }
}

pub(super) extern "win64" fn native_get_proc_address(module: u64, name: *const u8) -> u64 {
    if module != API_SET_MODULE {
        native_set_last_error(6);
        return 0;
    }
    match unsafe { ascii_z(name) } {
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

// libuv resolves this NTDLL entry during startup. Until a device-I/O
// translation exists, return a real NT failure code to callers instead
// of pretending that the operation succeeded.
pub(super) extern "win64" fn native_free_library(module: u64) -> i32 {
    (module == API_SET_MODULE) as i32
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
