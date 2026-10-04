//! SSPI discovery on a guest without Windows authentication providers.
use super::*;

const SEC_E_UNSUPPORTED_FUNCTION: i32 = 0x8009_0302u32 as i32;
const SEC_E_SECPKG_NOT_FOUND: i32 = 0x8009_0305u32 as i32;
const SEC_E_INVALID_TOKEN: i32 = 0x8009_0308u32 as i32;

// Windows x64 places the version DWORD and padding in the first slot,
// followed by the documented SecurityFunctionTable function pointers.
// Error-only callbacks ignore all arguments under the Windows x64 ABI.
static SECURITY_FUNCTION_TABLE: LazyLock<[usize; 33]> = LazyLock::new(|| {
    let mut table = [native_security_unsupported as *const () as usize; 33];
    table[0] = 1;
    table[1] = native_enumerate_security_packages as *const () as usize;
    table[17] = native_query_security_package_info as *const () as usize;
    for index in [5, 18, 19, 23, 30, 31, 32] {
        table[index] = 0;
    }
    table
});

pub(super) extern "win64" fn native_init_security_interface() -> *const usize {
    SECURITY_FUNCTION_TABLE.as_ptr()
}

extern "win64" fn native_security_unsupported() -> i32 {
    SEC_E_UNSUPPORTED_FUNCTION
}

pub(super) extern "win64" fn native_query_security_package_info(_name: u64, info: *mut u64) -> i32 {
    if info.is_null() {
        return SEC_E_INVALID_TOKEN;
    }
    unsafe { info.write_unaligned(0) };
    SEC_E_SECPKG_NOT_FOUND
}

pub(super) extern "win64" fn native_enumerate_security_packages(
    count: *mut u32,
    info: *mut u64,
) -> i32 {
    if count.is_null() || info.is_null() {
        return SEC_E_INVALID_TOKEN;
    }
    unsafe {
        count.write_unaligned(0);
        info.write_unaligned(0);
    }
    SEC_E_UNSUPPORTED_FUNCTION
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn security_table_initializes_and_reports_missing_providers() {
        let table = native_init_security_interface();
        assert_eq!(table, native_init_security_interface());
        assert_eq!(unsafe { table.read() }, 1);
        let query: extern "win64" fn(u64, *mut u64) -> i32 =
            unsafe { std::mem::transmute(*table.add(17)) };
        let mut info = 123;
        assert_eq!(query(0, &mut info), SEC_E_SECPKG_NOT_FOUND);
        assert_eq!(info, 0);
        assert_eq!(query(0, ptr::null_mut()), SEC_E_INVALID_TOKEN);
        let enumerate: extern "win64" fn(*mut u32, *mut u64) -> i32 =
            unsafe { std::mem::transmute(*table.add(1)) };
        let mut count = 123;
        assert_eq!(enumerate(&mut count, &mut info), SEC_E_UNSUPPORTED_FUNCTION);
        assert_eq!((count, info), (0, 0));
        assert_eq!(enumerate(ptr::null_mut(), &mut info), SEC_E_INVALID_TOKEN);
        let acquire: extern "win64" fn(u64, u64, u32, u64, u64, u64, u64, u64, u64) -> i32 =
            unsafe { std::mem::transmute(*table.add(3)) };
        assert_eq!(
            acquire(0, 0, 0, 0, 0, 0, 0, 0, 0),
            SEC_E_UNSUPPORTED_FUNCTION
        );
    }
}
