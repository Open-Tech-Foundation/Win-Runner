//! Windows crypto compatibility APIs for the Linux native backend.

use super::*;

pub(super) extern "win64" fn native_process_prng(out: *mut u8, len: usize) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native ProcessPrng length={len}");
    }
    if out.is_null() && len != 0 {
        return 0;
    }
    (unsafe { getrandom(out.cast(), len, 0) } == len as isize) as i32
}

fn fill_random_bytes(out: *mut u8, len: usize) -> bool {
    if out.is_null() && len != 0 {
        return false;
    }
    let mut offset = 0;
    while offset < len {
        let n = unsafe { getrandom(out.add(offset).cast(), len - offset, 0) };
        if n <= 0 {
            return false;
        }
        offset += n as usize;
    }
    true
}
/// `BCryptGenRandom` with the system-preferred generator, the form callers
/// use without opening an algorithm provider.
pub(super) extern "win64" fn native_bcrypt_gen_random(
    algorithm: u64,
    buffer: *mut u8,
    length: u32,
    flags: u32,
) -> u32 {
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
    const USE_SYSTEM_PREFERRED_RNG: u32 = 2;
    if flags & !(USE_SYSTEM_PREFERRED_RNG | 1) != 0 || (buffer.is_null() && length != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if algorithm != 0 || flags & USE_SYSTEM_PREFERRED_RNG == 0 {
        return STATUS_INVALID_HANDLE;
    }
    if fill_random_bytes(buffer, length as usize) {
        0
    } else {
        STATUS_UNSUCCESSFUL
    }
}

#[cfg(test)]
mod bcrypt_tests {
    use super::*;
    #[test]
    fn system_preferred_random_fills_and_rejects_bad_requests() {
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        assert_eq!(native_bcrypt_gen_random(0, first.as_mut_ptr(), 64, 2), 0);
        assert_eq!(native_bcrypt_gen_random(0, second.as_mut_ptr(), 64, 2), 0);
        assert_ne!(first, second);
        assert_eq!(native_bcrypt_gen_random(0, std::ptr::null_mut(), 0, 2), 0);
        assert_eq!(native_bcrypt_gen_random(0, first.as_mut_ptr(), 8, 0), 0xC000_0008);
        assert_eq!(native_bcrypt_gen_random(0x10, first.as_mut_ptr(), 8, 2), 0xC000_0008);
        assert_eq!(native_bcrypt_gen_random(0, std::ptr::null_mut(), 8, 2), 0xC000_000D);
        assert_eq!(native_bcrypt_gen_random(0, first.as_mut_ptr(), 8, 0x10), 0xC000_000D);
    }
}

pub(super) extern "win64" fn native_crypt_acquire_context_w(
    provider_out: *mut u64,
    _container: *const u16,
    _provider: *const u16,
    _provider_type: u32,
    _flags: u32,
) -> i32 {
    if provider_out.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { provider_out.write(CRYPTO_PROVIDER_HANDLE) };
    1
}
pub(super) extern "win64" fn native_crypt_gen_random(provider: u64, len: u32, out: *mut u8) -> i32 {
    if provider != CRYPTO_PROVIDER_HANDLE || !fill_random_bytes(out, len as usize) {
        native_set_last_error(6);
        return 0;
    }
    1
}
pub(super) extern "win64" fn native_crypt_release_context(provider: u64, _flags: u32) -> i32 {
    if provider != CRYPTO_PROVIDER_HANDLE {
        native_set_last_error(6);
        return 0;
    }
    1
}
pub(super) extern "win64" fn native_rtl_gen_random(out: *mut u8, len: u32) -> i32 {
    fill_random_bytes(out, len as usize) as i32
}
