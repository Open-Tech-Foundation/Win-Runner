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
