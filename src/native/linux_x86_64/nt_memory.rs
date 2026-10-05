//! NT virtual-memory entry points over the same native allocation backend.
use super::*;
const INVALID_PARAMETER: u32 = 0xc000000d;
fn current(handle: u64) -> bool {
    process_ctx().is_some_and(|process| handle == u64::MAX || handle == process.process_handle)
}
fn status(error: u32) -> u32 {
    match error {
        6 => 0xc0000008,
        8 | 14 => 0xc0000017,
        487 => 0xc0000018,
        50 => 0xc00000bb,
        _ => INVALID_PARAMETER,
    }
}
fn range(base: u64, size: usize) -> Option<(u64, usize)> {
    if size == 0 {
        return None;
    }
    let start = base & !4095;
    let length = size
        .checked_add((base - start) as usize)?
        .checked_add(4095)?
        & !4095;
    start.checked_add(length as u64)?;
    (length != 0).then_some((start, length))
}
pub(super) extern "win64" fn native_nt_allocate_virtual_memory(
    process: u64,
    base: *mut u64,
    zero_bits: usize,
    size: *mut usize,
    kind: u32,
    protection: u32,
) -> u32 {
    if !current(process) {
        return 0xc0000008;
    }
    if base.is_null() || size.is_null() {
        return INVALID_PARAMETER;
    }
    if zero_bits != 0 {
        return 0xc00000bb;
    }
    let requested_base = unsafe { base.read_unaligned() };
    let requested_size = unsafe { size.read_unaligned() };
    let Some((address, length)) = range(requested_base, requested_size) else {
        return INVALID_PARAMETER;
    };
    let saved = native_get_last_error();
    let pointer = native_virtual_alloc(address as *mut u8, length, kind, protection);
    let result = if pointer.is_null() {
        status(native_get_last_error())
    } else {
        unsafe {
            base.write_unaligned(pointer as u64);
            size.write_unaligned(length);
        }
        0
    };
    native_set_last_error(saved);
    result
}
pub(super) extern "win64" fn native_nt_free_virtual_memory(
    process: u64,
    base: *mut u64,
    size: *mut usize,
    kind: u32,
) -> u32 {
    if !current(process) {
        return 0xc0000008;
    }
    if base.is_null() || size.is_null() {
        return INVALID_PARAMETER;
    }
    let address = unsafe { base.read_unaligned() };
    let length = unsafe { size.read_unaligned() };
    let (address, length) = if kind == 0x8000 {
        if length != 0 {
            return INVALID_PARAMETER;
        }
        (address & !4095, 0)
    } else if kind == 0x4000 {
        let length = if length == 0 {
            let Some(process) = process_ctx() else {
                return 0xc0000008;
            };
            let value = process
                .virtual_allocations
                .lock()
                .ok()
                .and_then(|allocations| {
                    allocations
                        .get(&address)
                        .map(|allocation| allocation.length)
                });
            let Some(length) = value else {
                return 0xc0000018;
            };
            length
        } else {
            length
        };
        let Some(range) = range(address, length) else {
            return INVALID_PARAMETER;
        };
        range
    } else {
        return INVALID_PARAMETER;
    };
    let saved = native_get_last_error();
    let result = if native_virtual_free(address as *mut u8, length, kind) == 0 {
        status(native_get_last_error())
    } else {
        unsafe {
            base.write_unaligned(if kind == 0x8000 { 0 } else { address });
            size.write_unaligned(if kind == 0x8000 { 0 } else { length });
        }
        0
    };
    native_set_last_error(saved);
    result
}
pub(super) extern "win64" fn native_nt_protect_virtual_memory(
    process: u64,
    base: *mut u64,
    size: *mut usize,
    protection: u32,
    previous: *mut u32,
) -> u32 {
    if !current(process) {
        return 0xc0000008;
    }
    if base.is_null() || size.is_null() || previous.is_null() {
        return INVALID_PARAMETER;
    }
    let Some((address, length)) = range(unsafe { base.read_unaligned() }, unsafe {
        size.read_unaligned()
    }) else {
        return INVALID_PARAMETER;
    };
    let saved = native_get_last_error();
    let result =
        if native_virtual_protect(address as *mut c_void, length, protection, previous) == 0 {
            status(native_get_last_error())
        } else {
            unsafe {
                base.write_unaligned(address);
                size.write_unaligned(length);
            }
            0
        };
    native_set_last_error(saved);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nt_memory_allocates_rounds_protects_and_frees_without_changing_last_error() {
        let _guard = TestProcessGuard::new();
        native_set_last_error(42);
        let mut base = 0u64;
        let mut size = 3usize;
        assert_eq!(
            native_nt_allocate_virtual_memory(u64::MAX, &mut base, 0, &mut size, 0x3000, 4),
            0
        );
        assert_ne!(base, 0);
        assert_eq!(size, 4096);
        unsafe {
            *(base as *mut u8) = 23;
        }
        let original = base;
        base += 1;
        size = 1;
        let mut old = 0;
        assert_eq!(
            native_nt_protect_virtual_memory(u64::MAX, &mut base, &mut size, 2, &mut old),
            0
        );
        assert_eq!(base, original);
        assert_eq!(size, 4096);
        assert_eq!(old, 4);
        assert_eq!(unsafe { *(base as *const u8) }, 23);
        size = 0;
        assert_eq!(
            native_nt_free_virtual_memory(u64::MAX, &mut base, &mut size, 0x8000),
            0
        );
        assert_eq!(base, 0);
        assert_eq!(size, 0);
        assert_eq!(native_get_last_error(), 42);
        size = 0;
        assert_eq!(
            native_nt_allocate_virtual_memory(u64::MAX, &mut base, 0, &mut size, 0x3000, 4),
            INVALID_PARAMETER
        );
        assert_eq!((base, size), (0, 0));
        assert_eq!(
            native_nt_allocate_virtual_memory(0, &mut base, 0, &mut size, 0x3000, 4),
            0xc0000008
        );
    }
}
