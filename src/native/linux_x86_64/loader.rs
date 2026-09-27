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
