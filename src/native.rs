//! Native x86-64 PE execution backend.
//!
//! This is deliberately a small first step toward a Wine-style execution
//! path.  On an x86-64 Linux host, instructions in a PE32+ image do not need
//! interpretation: they can run directly on the processor once the image is
//! mapped at its preferred base.  What still needs building is the Windows
//! personality around that code (DLL loading, import trampolines, TEB/PEB,
//! exceptions, threads, and isolation).
//!
//! The first bridge supports the three APIs used by `rust_hello.exe`:
//! `GetStdHandle`, `WriteFile`, and `ExitProcess`.  Other images deliberately
//! remain on the interpreter until their imports have real trampolines. It is
//! intentionally opt-in and is not used by the normal CLI execution path.

use crate::pe::PeImage;

/// True when this build can execute the initial native backend.
pub const AVAILABLE: bool = cfg!(all(target_os = "linux", target_arch = "x86_64"));

/// Run an import-free PE entry point directly on the host CPU.
///
/// This is unsuitable for arbitrary or untrusted binaries: native guest code
/// runs in the current process until the planned child-process sandbox exists.
/// It is exposed now for bring-up fixtures and backend development only.
pub fn run_import_free(img: &PeImage) -> Result<u32, String> {
    imp::run_import_free(img)
}

/// Run the initial native Rust-guest baseline in a child process.
///
/// The supported imports are exactly `GetStdHandle`, `WriteFile`, and
/// `ExitProcess`. Guest stdout is captured and returned. The child boundary
/// makes `ExitProcess` safe and is the beginning of the native backend's
/// isolation model.
pub fn run_rust_baseline(img: &PeImage) -> Result<(u32, Vec<u8>), String> {
    run_rust_baseline_argv(img, "<exe>", &[])
}

/// Same as [`run_rust_baseline`], with the Windows command line supplied to
/// guests importing `GetCommandLineW`.
pub fn run_rust_baseline_argv(
    img: &PeImage,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>), String> {
    imp::run_rust_baseline_argv(img, prog, args)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use super::PeImage;
    use crate::winfs::WinFs;
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::Mutex;

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const PROT_EXEC: i32 = 0x4;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANONYMOUS: i32 = 0x20;
    // Linux-specific. Unlike MAP_FIXED, this never replaces an existing map.
    const MAP_FIXED_NOREPLACE: i32 = 0x100000;
    const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;
    // A child-local stand-in for the API-set modules dynamically requested by
    // the Universal CRT. It is deliberately not a host `dlopen` handle.
    const API_SET_MODULE: u64 = 0x5749_4e43_4c49_0001;

    // Preferred-base PE mappings collide by design. Serialize native runs in
    // this process until relocations allow separate address-space layouts.
    static NATIVE_RUN_LOCK: Mutex<()> = Mutex::new(());
    static NATIVE_LAST_ERROR: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" {
        fn mmap(
            addr: *mut c_void,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: isize,
        ) -> *mut c_void;
        fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
        fn munmap(addr: *mut c_void, len: usize) -> i32;
        fn pipe(fds: *mut i32) -> i32;
        fn fork() -> i32;
        fn dup2(oldfd: i32, newfd: i32) -> i32;
        fn close(fd: i32) -> i32;
        fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
        fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(status: i32) -> !;
        fn malloc(size: usize) -> *mut c_void;
        fn free(ptr: *mut c_void);
    }

    struct Mapping {
        ptr: *mut u8,
        len: usize,
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: `ptr` and `len` come from a successful mmap in `map`.
            unsafe { munmap(self.ptr.cast(), self.len) };
        }
    }

    fn page_len(len: usize) -> Result<usize, String> {
        len.checked_add(4095)
            .map(|n| n & !4095)
            .ok_or_else(|| "native image size overflows page rounding".to_string())
    }

    fn linux_protection(page_protection: u32) -> Option<i32> {
        // The low byte specifies the page access mode. Guard/cache modifiers
        // are intentionally not implemented by the native backend yet.
        match page_protection & 0xff {
            0x01 => Some(0),                                  // PAGE_NOACCESS
            0x02 => Some(PROT_READ),                          // PAGE_READONLY
            0x04 => Some(PROT_READ | PROT_WRITE),             // PAGE_READWRITE
            0x10 => Some(PROT_EXEC),                          // PAGE_EXECUTE
            0x20 => Some(PROT_READ | PROT_EXEC),              // PAGE_EXECUTE_READ
            0x40 => Some(PROT_READ | PROT_WRITE | PROT_EXEC), // PAGE_EXECUTE_READWRITE
            _ => None,
        }
    }

    #[cfg(test)]
    mod protection_tests {
        use super::{
            command_line_a, linux_protection, native_delete_critical_section,
            native_enter_critical_section, native_get_acp, native_get_cp_info,
            native_get_file_type, native_get_last_error, native_get_oem_cp,
            native_get_proc_address, native_get_startup_info_w, native_get_string_type_w,
            native_initialize_critical_section_ex, native_is_valid_code_page,
            native_lc_map_string_w, native_leave_critical_section, native_multi_byte_to_wide_char,
            native_set_last_error, native_wide_char_to_multi_byte, uppercase_ascii_utf16,
            API_SET_MODULE, PROT_EXEC, PROT_READ, PROT_WRITE,
        };

        #[test]
        fn translates_standard_windows_page_protections() {
            assert_eq!(linux_protection(0x01), Some(0));
            assert_eq!(linux_protection(0x02), Some(PROT_READ));
            assert_eq!(linux_protection(0x04), Some(PROT_READ | PROT_WRITE));
            assert_eq!(linux_protection(0x10), Some(PROT_EXEC));
            assert_eq!(linux_protection(0x20), Some(PROT_READ | PROT_EXEC));
            assert_eq!(
                linux_protection(0x40),
                Some(PROT_READ | PROT_WRITE | PROT_EXEC)
            );
        }

        #[test]
        fn rejects_unsupported_windows_page_protections() {
            assert_eq!(linux_protection(0x08), None);
            assert_eq!(linux_protection(0x100), None);
        }

        #[test]
        fn resolves_only_the_supported_dynamic_api_set_export() {
            assert_ne!(
                native_get_proc_address(API_SET_MODULE, c"CompareStringEx".as_ptr().cast()),
                0
            );
            assert_eq!(
                native_get_proc_address(API_SET_MODULE, c"UnknownExport".as_ptr().cast()),
                0
            );
        }

        #[test]
        fn folds_ascii_case_without_changing_non_ascii_utf16() {
            let mut value = ['a' as u16, 'Z' as u16, 0x00e9];
            uppercase_ascii_utf16(&mut value);
            assert_eq!(value, ['A' as u16, 'Z' as u16, 0x00e9]);
        }

        #[test]
        fn single_threaded_critical_sections_initialize_and_are_callable() {
            let mut section = [0xa5; 40];
            assert_eq!(
                native_initialize_critical_section_ex(section.as_mut_ptr(), 0, 0),
                1
            );
            assert_eq!(section, [0; 40]);
            native_enter_critical_section(section.as_mut_ptr());
            native_leave_critical_section(section.as_mut_ptr());
            native_delete_critical_section(section.as_mut_ptr());
        }

        #[test]
        fn preserves_the_native_child_last_error() {
            native_set_last_error(87);
            assert_eq!(native_get_last_error(), 87);
            native_set_last_error(0);
        }

        #[test]
        fn provides_a_zeroed_64_bit_startup_info_record() {
            let mut startup_info = [0xa5; 104];
            native_get_startup_info_w(startup_info.as_mut_ptr());
            assert_eq!(
                u32::from_le_bytes(startup_info[..4].try_into().unwrap()),
                104
            );
            assert!(startup_info[4..].iter().all(|byte| *byte == 0));
        }

        #[test]
        fn classifies_native_standard_descriptors_as_console_handles() {
            assert_eq!(native_get_file_type(0), 2);
            assert_eq!(native_get_file_type(1), 2);
            assert_eq!(native_get_file_type(2), 2);
            assert_eq!(native_get_file_type(0x100), 0);
        }

        #[test]
        fn converts_command_lines_to_a_null_terminated_ansi_view() {
            assert_eq!(command_line_a(&['r' as u16, 'g' as u16, 0]), b"rg\0");
            assert_eq!(command_line_a(&[0x00e9, 0]), b"?\0");
        }

        #[test]
        fn reports_a_consistent_single_byte_windows_code_page() {
            assert_eq!(native_get_acp(), 1252);
            assert_eq!(native_get_oem_cp(), 1252);
        }

        #[test]
        fn validates_only_implemented_code_pages() {
            assert_eq!(native_is_valid_code_page(1252), 1);
            assert_eq!(native_is_valid_code_page(65001), 1);
            assert_eq!(native_is_valid_code_page(932), 0);
        }

        #[test]
        fn fills_code_page_info_for_supported_pages() {
            let mut cp_info = [0xa5; 16];
            assert_eq!(native_get_cp_info(1252, cp_info.as_mut_ptr()), 1);
            assert_eq!(u32::from_le_bytes(cp_info[..4].try_into().unwrap()), 1);
            assert_eq!(cp_info[4], b'?');
            assert!(cp_info[5..].iter().all(|byte| *byte == 0));
            assert_eq!(native_get_cp_info(65001, cp_info.as_mut_ptr()), 1);
            assert_eq!(u32::from_le_bytes(cp_info[..4].try_into().unwrap()), 4);
            assert_eq!(native_get_cp_info(932, cp_info.as_mut_ptr()), 0);
        }

        #[test]
        fn converts_supported_multibyte_inputs_to_utf16() {
            let input = b"rg\0";
            let mut output = [0; 4];
            assert_eq!(
                native_multi_byte_to_wide_char(1252, 0, input.as_ptr(), -1, output.as_mut_ptr(), 4),
                3
            );
            assert_eq!(&output[..3], &['r' as u16, 'g' as u16, 0]);
            assert_eq!(
                native_multi_byte_to_wide_char(65001, 0, "é".as_ptr(), 2, std::ptr::null_mut(), 0),
                1
            );
            assert_eq!(
                native_multi_byte_to_wide_char(932, 0, input.as_ptr(), -1, output.as_mut_ptr(), 4),
                0
            );
        }

        #[test]
        fn classifies_ascii_characters_for_the_crt() {
            let input = ['A' as u16, '7' as u16, ' ' as u16, '!' as u16];
            let mut output = [0; 4];
            assert_eq!(
                native_get_string_type_w(1, input.as_ptr(), 4, output.as_mut_ptr()),
                1
            );
            assert_eq!(output, [0x0101, 0x0084, 0x0048, 0x0010]);
            assert_eq!(
                native_get_string_type_w(2, input.as_ptr(), 4, output.as_mut_ptr()),
                0
            );
        }

        #[test]
        fn maps_ascii_case_and_reports_wide_output_size() {
            let input = ['R' as u16, 'g' as u16, 0];
            let mut output = [0; 3];
            assert_eq!(
                native_lc_map_string_w(
                    std::ptr::null(),
                    0x100,
                    input.as_ptr(),
                    -1,
                    output.as_mut_ptr(),
                    3
                ),
                3
            );
            assert_eq!(output, ['r' as u16, 'g' as u16, 0]);
            assert_eq!(
                native_lc_map_string_w(
                    std::ptr::null(),
                    0,
                    input.as_ptr(),
                    -1,
                    std::ptr::null_mut(),
                    0
                ),
                3
            );
        }

        #[test]
        fn converts_wide_input_to_supported_multibyte_pages() {
            let input = ['r' as u16, 'g' as u16, 0];
            let mut output = [0; 3];
            assert_eq!(
                native_wide_char_to_multi_byte(
                    1252,
                    0,
                    input.as_ptr(),
                    -1,
                    output.as_mut_ptr(),
                    3,
                    std::ptr::null(),
                    std::ptr::null_mut()
                ),
                3
            );
            assert_eq!(output, *b"rg\0");
            assert_eq!(
                native_wide_char_to_multi_byte(
                    65001,
                    0,
                    ['é' as u16].as_ptr(),
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut()
                ),
                2
            );
        }
    }

    fn map(img: &PeImage) -> Result<Mapping, String> {
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

    fn protect_exec(mapping: &Mapping) -> Result<(), String> {
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

    pub(super) fn run_import_free(img: &PeImage) -> Result<u32, String> {
        let _run = NATIVE_RUN_LOCK
            .lock()
            .map_err(|_| "native backend execution lock is poisoned".to_string())?;
        if !img.imports.is_empty() || !img.stubs.is_empty() {
            return Err(
                "native backend does not yet support PE imports; use the interpreter backend"
                    .to_string(),
            );
        }
        if img.tls.is_some() {
            return Err(
                "native backend does not yet set up TLS; use the interpreter backend".to_string(),
            );
        }
        let entry = img
            .image_base
            .checked_add(img.entry_rva as u64)
            .ok_or_else(|| "native entry address overflows".to_string())?;
        let image_end = img.image_base + img.image.len() as u64;
        if entry < img.image_base || entry >= image_end {
            return Err("native entry point lies outside the loaded image".to_string());
        }
        let mapping = map(img)?;
        protect_exec(&mapping)?;
        // SAFETY: `entry` lies in the RX mapping just created. The caller is
        // limited to bring-up PE fixtures that implement this ABI and return;
        // arbitrary Windows entry points require the planned process sandbox.
        let entry_fn: unsafe extern "win64" fn() -> u32 = unsafe { std::mem::transmute(entry) };
        Ok(unsafe { entry_fn() })
    }

    // The command-line buffer is owned by the parent until it reaps the
    // native guest. The child inherits it on fork, so the guest receives a
    // normal process-valid UTF-16 pointer. Native runs are CLI-process local;
    // broader concurrent execution will replace this bootstrap slot with a
    // per-process shim context.
    static COMMAND_LINE_W: AtomicU64 = AtomicU64::new(0);
    static COMMAND_LINE_A: AtomicU64 = AtomicU64::new(0);
    static NATIVE_FS: AtomicU64 = AtomicU64::new(0);
    static FLS_VALUE: AtomicU64 = AtomicU64::new(0);

    struct NativeFile {
        path: String,
        offset: usize,
    }
    struct NativeTls {
        teb: Box<[u8; 0x1000]>,
        slots: Box<[u64; 64]>,
        _data: Vec<u8>,
        _ldr: Box<[u8; 64]>,
    }

    fn put64(dst: &mut [u8], off: usize, value: u64) {
        dst[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn setup_tls(mapping: &Mapping, img: &PeImage) -> Result<Option<NativeTls>, String> {
        let Some(tls) = &img.tls else { return Ok(None) };
        let mut data = tls.raw_data.clone();
        data.resize(data.len() + tls.zero_fill as usize, 0);
        let mut out = NativeTls {
            teb: Box::new([0; 0x1000]),
            slots: Box::new([0; 64]),
            _data: data,
            _ldr: Box::new([0; 64]),
        };
        out.slots[0] = out._data.as_ptr() as u64;
        let teb = out.teb.as_ptr() as u64;
        let peb = teb + 0x800;
        put64(&mut out.teb[..], 0x30, teb);
        put64(&mut out.teb[..], 0x58, out.slots.as_ptr() as u64);
        put64(&mut out.teb[..], 0x60, peb);
        put64(&mut out.teb[..], 0x800 + 0x10, img.image_base);
        put64(&mut out.teb[..], 0x800 + 0x20, out._ldr.as_ptr() as u64);
        let off = tls.index_rva as usize;
        if off.checked_add(4).is_none_or(|end| end > mapping.len) {
            return Err("native TLS index lies outside image".to_string());
        }
        unsafe { (mapping.ptr.add(off) as *mut u32).write_unaligned(0) };
        Ok(Some(out))
    }
    unsafe fn set_gs(base: u64) -> bool {
        let result: u64;
        core::arch::asm!("syscall", inlateout("rax") 158u64 => result, in("rdi") 0x1001u64, in("rsi") base, lateout("rcx") _, lateout("r11") _);
        result == 0
    }
    struct NativeFs {
        fs: WinFs,
        handles: HashMap<u64, NativeFile>,
        next: u64,
    }

    fn wide(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut units = Vec::new();
        for i in 0..32768 {
            let u = unsafe { ptr.add(i).read() };
            if u == 0 {
                return String::from_utf16(&units).ok();
            }
            units.push(u);
        }
        None
    }
    unsafe fn fs_ctx() -> Option<&'static mut NativeFs> {
        (NATIVE_FS.load(Ordering::Acquire) as *mut NativeFs).as_mut()
    }

    extern "win64" fn native_get_command_line_w() -> u64 {
        COMMAND_LINE_W.load(Ordering::Acquire)
    }
    extern "win64" fn native_get_command_line_a() -> u64 {
        COMMAND_LINE_A.load(Ordering::Acquire)
    }

    extern "win64" fn native_get_std_handle(which: u32) -> u64 {
        match which as i32 {
            -10 => 0,
            -11 => 1,
            -12 => 2,
            _ => u64::MAX,
        }
    }

    extern "win64" fn native_get_file_type(handle: u64) -> u32 {
        match handle {
            0..=2 => 0x0002, // FILE_TYPE_CHAR
            _ => 0,
        }
    }

    extern "win64" fn native_get_acp() -> u32 {
        1252
    }

    extern "win64" fn native_get_oem_cp() -> u32 {
        1252
    }

    extern "win64" fn native_is_valid_code_page(code_page: u32) -> i32 {
        matches!(code_page, 1252 | 65001) as i32
    }

    extern "win64" fn native_get_cp_info(code_page: u32, info: *mut u8) -> i32 {
        if info.is_null() {
            return 0;
        }
        let max_char_size = match code_page {
            1252 => 1,
            65001 => 4,
            _ => return 0,
        };
        // CPINFO is 16 bytes: DWORD MaxCharSize, 2-byte DefaultChar, and a
        // 12-byte lead-byte range table.
        unsafe {
            std::ptr::write_bytes(info, 0, 16);
            (info as *mut u32).write_unaligned(max_char_size);
            info.add(4).write(b'?');
        }
        1
    }

    unsafe fn multibyte_input(input: *const u8, len: i32) -> Option<(Vec<u8>, bool)> {
        if input.is_null() || len < -1 {
            return None;
        }
        if len >= 0 {
            return Some((
                unsafe { std::slice::from_raw_parts(input, len as usize) }.to_vec(),
                false,
            ));
        }
        let mut size = 0;
        while size < 64 * 1024 && unsafe { *input.add(size) } != 0 {
            size += 1;
        }
        (size < 64 * 1024).then(|| {
            (
                unsafe { std::slice::from_raw_parts(input, size) }.to_vec(),
                true,
            )
        })
    }

    extern "win64" fn native_multi_byte_to_wide_char(
        code_page: u32,
        _flags: u32,
        input: *const u8,
        input_len: i32,
        output: *mut u16,
        output_len: i32,
    ) -> i32 {
        if output_len < 0 {
            return 0;
        }
        let (input, append_nul) = match unsafe { multibyte_input(input, input_len) } {
            Some(value) => value,
            None => return 0,
        };
        let mut wide: Vec<u16> = match code_page {
            1252 => input.into_iter().map(u16::from).collect(),
            65001 => match std::str::from_utf8(&input) {
                Ok(value) => value.encode_utf16().collect(),
                Err(_) => return 0,
            },
            _ => return 0,
        };
        if append_nul {
            wide.push(0);
        }
        if output.is_null() {
            return wide.len().try_into().unwrap_or(0);
        }
        if wide.len() > output_len as usize {
            return 0;
        }
        unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), output, wide.len()) };
        wide.len().try_into().unwrap_or(0)
    }

    fn ctype1(unit: u16) -> u16 {
        match char::from_u32(unit as u32) {
            Some(ch) if ch.is_ascii_uppercase() => 0x0001 | 0x0100,
            Some(ch) if ch.is_ascii_lowercase() => 0x0002 | 0x0100,
            Some(ch) if ch.is_ascii_digit() => 0x0004 | 0x0080,
            Some(' ') => 0x0008 | 0x0040,
            Some('\t') => 0x0008 | 0x0040,
            Some(ch) if ch.is_ascii_control() => 0x0020,
            Some(ch) if ch.is_ascii_punctuation() => 0x0010,
            _ => 0,
        }
    }

    extern "win64" fn native_get_string_type_w(
        info_type: u32,
        input: *const u16,
        input_len: i32,
        output: *mut u16,
    ) -> i32 {
        if info_type != 1 || input.is_null() || output.is_null() || input_len < -1 {
            return 0;
        }
        let len = if input_len >= 0 {
            input_len as usize
        } else {
            let mut len = 0;
            while len < 64 * 1024 && unsafe { *input.add(len) } != 0 {
                len += 1;
            }
            if len == 64 * 1024 {
                return 0;
            }
            len + 1
        };
        for index in 0..len {
            unsafe { output.add(index).write(ctype1(*input.add(index))) };
        }
        1
    }

    extern "win64" fn native_lc_map_string_w(
        _locale: *const u16,
        flags: u32,
        input: *const u16,
        input_len: i32,
        output: *mut u16,
        output_len: i32,
    ) -> i32 {
        if input.is_null() || input_len < -1 || output_len < 0 || flags & !0x300 != 0 {
            return 0;
        }
        if flags & 0x300 == 0x300 {
            return 0;
        }
        let len = if input_len >= 0 {
            input_len as usize
        } else {
            let mut len = 0;
            while len < 64 * 1024 && unsafe { *input.add(len) } != 0 {
                len += 1;
            }
            if len == 64 * 1024 {
                return 0;
            }
            len + 1
        };
        if output.is_null() {
            return len.try_into().unwrap_or(0);
        }
        if len > output_len as usize {
            return 0;
        }
        for index in 0..len {
            let mut unit = unsafe { *input.add(index) };
            if flags & 0x100 != 0 && (b'A' as u16..=b'Z' as u16).contains(&unit) {
                unit += (b'a' - b'A') as u16;
            } else if flags & 0x200 != 0 && (b'a' as u16..=b'z' as u16).contains(&unit) {
                unit -= (b'a' - b'A') as u16;
            }
            unsafe { output.add(index).write(unit) };
        }
        len.try_into().unwrap_or(0)
    }

    extern "win64" fn native_wide_char_to_multi_byte(
        code_page: u32,
        _flags: u32,
        input: *const u16,
        input_len: i32,
        output: *mut u8,
        output_len: i32,
        _default_char: *const u8,
        used_default_char: *mut i32,
    ) -> i32 {
        if input.is_null() || input_len < -1 || output_len < 0 {
            return 0;
        }
        let (len, append_nul) = if input_len >= 0 {
            (input_len as usize, false)
        } else {
            let mut len = 0;
            while len < 64 * 1024 && unsafe { *input.add(len) } != 0 {
                len += 1;
            }
            if len == 64 * 1024 {
                return 0;
            }
            (len, true)
        };
        let units = unsafe { std::slice::from_raw_parts(input, len) };
        let mut used_default = false;
        let mut bytes = match code_page {
            1252 => units
                .iter()
                .map(|unit| {
                    if *unit <= 0xff {
                        *unit as u8
                    } else {
                        used_default = true;
                        b'?'
                    }
                })
                .collect(),
            65001 => match String::from_utf16(units) {
                Ok(value) => value.into_bytes(),
                Err(_) => return 0,
            },
            _ => return 0,
        };
        if append_nul {
            bytes.push(0);
        }
        if !used_default_char.is_null() {
            unsafe { used_default_char.write(used_default as i32) };
        }
        if output.is_null() {
            return bytes.len().try_into().unwrap_or(0);
        }
        if bytes.len() > output_len as usize {
            return 0;
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
        bytes.len().try_into().unwrap_or(0)
    }

    extern "win64" fn native_get_process_heap() -> u64 {
        0x400
    }
    extern "win64" fn native_get_current_thread_id() -> u32 {
        1
    }
    extern "win64" fn native_get_current_process_id() -> u32 {
        1
    }
    extern "win64" fn native_get_current_process() -> u64 {
        u64::MAX
    }
    extern "win64" fn native_query_performance_counter(out: *mut i64) -> i32 {
        if out.is_null() {
            return 0;
        }
        let ticks = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
            .unwrap_or(0);
        unsafe { out.write_unaligned(ticks) };
        1
    }
    extern "win64" fn native_initialize_critical_section_ex(
        section: *mut u8,
        _spin: u32,
        _flags: u32,
    ) -> i32 {
        if section.is_null() {
            return 0;
        }
        unsafe { std::ptr::write_bytes(section, 0, 40) };
        1
    }
    extern "win64" fn native_fls_alloc(_callback: u64) -> u32 {
        0
    }
    extern "win64" fn native_fls_free(index: u32) -> i32 {
        if index != 0 {
            return 0;
        }
        FLS_VALUE.store(0, Ordering::Release);
        1
    }
    extern "win64" fn native_fls_get_value(index: u32) -> u64 {
        if index == 0 {
            FLS_VALUE.load(Ordering::Acquire)
        } else {
            0
        }
    }
    extern "win64" fn native_fls_set_value(index: u32, value: u64) -> i32 {
        if index != 0 {
            return 0;
        }
        FLS_VALUE.store(value, Ordering::Release);
        1
    }
    extern "win64" fn native_get_system_time_as_file_time(out: *mut u64) {
        if out.is_null() {
            return;
        }
        let ticks = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().saturating_mul(10_000_000) + (d.subsec_nanos() / 100) as u64)
            .unwrap_or(0)
            .saturating_add(116_444_736_000_000_000);
        unsafe { out.write_unaligned(ticks) };
    }
    extern "win64" fn native_heap_alloc(_heap: u64, _flags: u32, size: u32) -> u64 {
        let size = (size as usize).max(1);
        unsafe { malloc(size).cast::<u8>() as u64 }
    }
    extern "win64" fn native_heap_free(_heap: u64, _flags: u32, ptr: u64) -> i32 {
        if ptr == 0 {
            return 0;
        }
        unsafe {
            free(ptr as *mut c_void);
        }
        1
    }
    extern "win64" fn native_enter_critical_section(_section: *mut u8) {}
    extern "win64" fn native_leave_critical_section(_section: *mut u8) {}
    extern "win64" fn native_delete_critical_section(_section: *mut u8) {}

    extern "win64" fn native_write_file(
        handle: u64,
        buf: *const u8,
        len: u32,
        written: *mut u32,
        _overlapped: u64,
    ) -> i32 {
        if buf.is_null() || len > 16 * 1024 * 1024 {
            return 0;
        }
        if handle != 1 && handle != 2 {
            let ctx = match unsafe { fs_ctx() } {
                Some(v) => v,
                None => return 0,
            };
            let file = match ctx.handles.get_mut(&handle) {
                Some(v) => v,
                None => return 0,
            };
            let data = unsafe { std::slice::from_raw_parts(buf, len as usize) };
            let mut content = match ctx.fs.read_file(&file.path) {
                Ok(v) => v,
                Err(_) => return 0,
            };
            let end = match file.offset.checked_add(data.len()) {
                Some(v) => v,
                None => return 0,
            };
            if content.len() < end {
                content.resize(end, 0);
            }
            content[file.offset..end].copy_from_slice(data);
            if ctx.fs.write_file(&file.path, content).is_err() {
                return 0;
            }
            file.offset = end;
            if !written.is_null() {
                unsafe { written.write(len) };
            }
            return 1;
        }
        if buf.is_null() {
            return 0;
        }
        // SAFETY: the guest supplied `buf`/`len`; a bad pointer terminates
        // only its isolated native child, never the parent runtime.
        let n = unsafe { write(handle as i32, buf.cast(), len as usize) };
        if n < 0 {
            return 0;
        }
        if !written.is_null() {
            // SAFETY: same child-process containment as the input pointer.
            unsafe { written.write(n as u32) };
        }
        1
    }

    extern "win64" fn native_exit_process(code: u32) -> ! {
        // SAFETY: this runs only in the forked guest child.
        unsafe { _exit(code as i32) }
    }
    extern "win64" fn native_unimplemented() -> u64 {
        0
    }

    extern "win64" fn native_get_last_error() -> u32 {
        NATIVE_LAST_ERROR.load(Ordering::Acquire)
    }

    extern "win64" fn native_set_last_error(error: u32) {
        NATIVE_LAST_ERROR.store(error, Ordering::Release);
    }

    extern "win64" fn native_get_startup_info_w(startup_info: *mut u8) {
        if startup_info.is_null() {
            return;
        }
        // STARTUPINFOW is 104 bytes on 64-bit Windows. The native runner has
        // no inherited Windows handles, so a zeroed record is the appropriate
        // console-process baseline.
        unsafe {
            std::ptr::write_bytes(startup_info, 0, 104);
            (startup_info as *mut u32).write_unaligned(104);
        }
    }

    unsafe fn ascii_z(ptr: *const u8) -> Option<&'static str> {
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

    unsafe fn utf16_argument(ptr: *const u16, len: i32) -> Option<Vec<u16>> {
        if ptr.is_null() || len < -1 {
            return None;
        }
        if len >= 0 {
            return Some(unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec());
        }
        let mut count = 0;
        while count < 32 * 1024 && unsafe { *ptr.add(count) } != 0 {
            count += 1;
        }
        (count < 32 * 1024).then(|| unsafe { std::slice::from_raw_parts(ptr, count) }.to_vec())
    }

    fn uppercase_ascii_utf16(value: &mut [u16]) {
        for unit in value {
            if (b'a' as u16..=b'z' as u16).contains(unit) {
                *unit -= (b'a' - b'A') as u16;
            }
        }
    }

    extern "win64" fn native_compare_string_ex(
        _locale: *const u16,
        flags: u32,
        left: *const u16,
        left_len: i32,
        right: *const u16,
        right_len: i32,
        _version: *const c_void,
        _reserved: *const c_void,
        _param: isize,
    ) -> i32 {
        let (mut left, mut right) = match unsafe {
            (
                utf16_argument(left, left_len),
                utf16_argument(right, right_len),
            )
        } {
            (Some(left), Some(right)) => (left, right),
            _ => return 0,
        };
        // NORM_IGNORECASE is the only comparison flag needed by the CRT's
        // API-set probing path. Full Windows locale collation is future work.
        if flags & 0x1 != 0 {
            uppercase_ascii_utf16(&mut left);
            uppercase_ascii_utf16(&mut right);
        }
        match left.cmp(&right) {
            std::cmp::Ordering::Less => 1,
            std::cmp::Ordering::Equal => 2,
            std::cmp::Ordering::Greater => 3,
        }
    }

    extern "win64" fn native_load_library_ex_w(path: *const u16, _file: u64, _flags: u32) -> u64 {
        (!path.is_null()).then_some(API_SET_MODULE).unwrap_or(0)
    }

    extern "win64" fn native_get_proc_address(module: u64, name: *const u8) -> u64 {
        if module != API_SET_MODULE {
            return 0;
        }
        match unsafe { ascii_z(name) } {
            Some("CompareStringEx") => native_compare_string_ex as *const () as usize as u64,
            _ => 0,
        }
    }

    extern "win64" fn native_free_library(module: u64) -> i32 {
        (module == API_SET_MODULE) as i32
    }

    extern "win64" fn native_virtual_protect(
        address: *mut c_void,
        size: usize,
        page_protection: u32,
        old_page_protection: *mut u32,
    ) -> i32 {
        if address.is_null() || size == 0 {
            return 0;
        }
        let protection = match linux_protection(page_protection) {
            Some(value) => value,
            None => return 0,
        };
        let start = (address as usize) & !4095;
        let end = match (address as usize)
            .checked_add(size)
            .and_then(|value| value.checked_add(4095))
        {
            Some(value) => value & !4095,
            None => return 0,
        };
        if end <= start {
            return 0;
        }
        // SAFETY: `mprotect` receives a page-aligned range derived from the
        // guest's requested range. Invalid guest ranges fail without harming
        // the parent because the PE runs in its forked child.
        if unsafe { mprotect(start as *mut c_void, end - start, protection) } != 0 {
            return 0;
        }
        if !old_page_protection.is_null() {
            // The loader initially maps native PE images RWX. This is the
            // accurate old protection until section-aware initial mapping is
            // introduced.
            unsafe { old_page_protection.write(0x40) };
        }
        1
    }

    extern "win64" fn native_create_file_w(
        path: *const u16,
        access: u32,
        _share: u32,
        _sec: u64,
        creation: u32,
        _flags: u32,
        _tmpl: u64,
    ) -> u64 {
        let path = match wide(path) {
            Some(v) => v,
            None => return u64::MAX,
        };
        let ctx = match unsafe { fs_ctx() } {
            Some(v) => v,
            None => return u64::MAX,
        };
        let exists = ctx.fs.exists(&path);
        let ok = match creation {
            2 => ctx.fs.write_file(&path, Vec::new()),
            3 if exists && ctx.fs.is_file(&path) => Ok(()),
            _ => Err("unsupported create".into()),
        };
        if ok.is_err() || (access & 0xC000_0000) == 0 {
            return u64::MAX;
        }
        let h = ctx.next;
        ctx.next += 1;
        ctx.handles.insert(h, NativeFile { path, offset: 0 });
        h
    }
    extern "win64" fn native_read_file(
        h: u64,
        buf: *mut u8,
        n: u32,
        read: *mut u32,
        _ov: u64,
    ) -> i32 {
        if buf.is_null() {
            return 0;
        }
        let ctx = match unsafe { fs_ctx() } {
            Some(v) => v,
            None => return 0,
        };
        let file = match ctx.handles.get_mut(&h) {
            Some(v) => v,
            None => return 0,
        };
        let data = match ctx.fs.read_file(&file.path) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let k = (data.len().saturating_sub(file.offset)).min(n as usize);
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr().add(file.offset), buf, k) };
        file.offset += k;
        if !read.is_null() {
            unsafe { read.write(k as u32) };
        }
        1
    }
    extern "win64" fn native_close_handle(h: u64) -> i32 {
        unsafe {
            fs_ctx()
                .map(|c| c.handles.remove(&h).is_some())
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_create_directory_w(p: *const u16, _s: u64) -> i32 {
        unsafe {
            fs_ctx()
                .and_then(|c| wide(p).map(|p| c.fs.mkdir_one(&p).is_ok()))
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_remove_directory_w(p: *const u16) -> i32 {
        unsafe {
            fs_ctx()
                .and_then(|c| wide(p).map(|p| c.fs.rmdir(&p).is_ok()))
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_delete_file_w(p: *const u16) -> i32 {
        unsafe {
            fs_ctx()
                .and_then(|c| wide(p).map(|p| c.fs.delete_file(&p).is_ok()))
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_move_file_w(a: *const u16, b: *const u16) -> i32 {
        let (a, b) = match (wide(a), wide(b)) {
            (Some(a), Some(b)) => (a, b),
            _ => return 0,
        };
        unsafe {
            fs_ctx()
                .map(|c| c.fs.move_path(&a, &b).is_ok())
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_copy_file_w(a: *const u16, b: *const u16, fail: i32) -> i32 {
        let (a, b) = match (wide(a), wide(b)) {
            (Some(a), Some(b)) => (a, b),
            _ => return 0,
        };
        unsafe {
            fs_ctx()
                .map(|c| c.fs.copy_file(&a, &b, fail != 0).is_ok())
                .unwrap_or(false) as i32
        }
    }

    fn baseline_trampoline(name: &str) -> Option<u64> {
        match name {
            "GetCommandLineW" => Some(native_get_command_line_w as *const () as usize as u64),
            "GetCommandLineA" => Some(native_get_command_line_a as *const () as usize as u64),
            "GetLastError" => Some(native_get_last_error as *const () as usize as u64),
            "SetLastError" => Some(native_set_last_error as *const () as usize as u64),
            "GetStartupInfoW" => Some(native_get_startup_info_w as *const () as usize as u64),
            "GetProcessHeap" => Some(native_get_process_heap as *const () as usize as u64),
            "GetCurrentThreadId" => Some(native_get_current_thread_id as *const () as usize as u64),
            "GetCurrentProcessId" => {
                Some(native_get_current_process_id as *const () as usize as u64)
            }
            "GetCurrentProcess" => Some(native_get_current_process as *const () as usize as u64),
            "VirtualProtect" => Some(native_virtual_protect as *const () as usize as u64),
            "LoadLibraryExW" => Some(native_load_library_ex_w as *const () as usize as u64),
            "GetProcAddress" => Some(native_get_proc_address as *const () as usize as u64),
            "FreeLibrary" => Some(native_free_library as *const () as usize as u64),
            "QueryPerformanceCounter" => {
                Some(native_query_performance_counter as *const () as usize as u64)
            }
            "InitializeCriticalSectionEx" => {
                Some(native_initialize_critical_section_ex as *const () as usize as u64)
            }
            "EnterCriticalSection" => {
                Some(native_enter_critical_section as *const () as usize as u64)
            }
            "LeaveCriticalSection" => {
                Some(native_leave_critical_section as *const () as usize as u64)
            }
            "DeleteCriticalSection" => {
                Some(native_delete_critical_section as *const () as usize as u64)
            }
            "FlsAlloc" => Some(native_fls_alloc as *const () as usize as u64),
            "FlsFree" => Some(native_fls_free as *const () as usize as u64),
            "FlsGetValue" => Some(native_fls_get_value as *const () as usize as u64),
            "FlsSetValue" => Some(native_fls_set_value as *const () as usize as u64),
            "GetSystemTimeAsFileTime" => {
                Some(native_get_system_time_as_file_time as *const () as usize as u64)
            }
            "GetStdHandle" => Some(native_get_std_handle as *const () as usize as u64),
            "GetFileType" => Some(native_get_file_type as *const () as usize as u64),
            "GetACP" => Some(native_get_acp as *const () as usize as u64),
            "GetOEMCP" => Some(native_get_oem_cp as *const () as usize as u64),
            "IsValidCodePage" => Some(native_is_valid_code_page as *const () as usize as u64),
            "GetCPInfo" => Some(native_get_cp_info as *const () as usize as u64),
            "MultiByteToWideChar" => {
                Some(native_multi_byte_to_wide_char as *const () as usize as u64)
            }
            "GetStringTypeW" => Some(native_get_string_type_w as *const () as usize as u64),
            "LCMapStringW" => Some(native_lc_map_string_w as *const () as usize as u64),
            "WideCharToMultiByte" => {
                Some(native_wide_char_to_multi_byte as *const () as usize as u64)
            }
            "HeapAlloc" => Some(native_heap_alloc as *const () as usize as u64),
            "HeapFree" => Some(native_heap_free as *const () as usize as u64),
            "WriteFile" => Some(native_write_file as *const () as usize as u64),
            "ExitProcess" => Some(native_exit_process as *const () as usize as u64),
            "CreateFileW" => Some(native_create_file_w as *const () as usize as u64),
            "ReadFile" => Some(native_read_file as *const () as usize as u64),
            "CloseHandle" => Some(native_close_handle as *const () as usize as u64),
            "CreateDirectoryW" => Some(native_create_directory_w as *const () as usize as u64),
            "RemoveDirectoryW" => Some(native_remove_directory_w as *const () as usize as u64),
            "DeleteFileW" => Some(native_delete_file_w as *const () as usize as u64),
            "MoveFileW" => Some(native_move_file_w as *const () as usize as u64),
            "CopyFileW" => Some(native_copy_file_w as *const () as usize as u64),
            _ => Some(native_unimplemented as *const () as usize as u64),
        }
    }

    fn patch_baseline_imports(mapping: &Mapping, img: &PeImage) -> Result<(), String> {
        // `stubs` are loader-recognized APIs that normally route to an
        // interpreter fail-stub. Native mode gives them a contained fallback
        // (or a real native trampoline when one has been added) as well.
        for import in img.imports.iter().chain(&img.stubs) {
            let value = baseline_trampoline(&import.func).expect("fallback trampoline exists");
            let off = import.iat_rva as usize;
            if off.checked_add(8).is_none_or(|end| end > mapping.len) {
                return Err(format!(
                    "native IAT slot out of range: {}!{}",
                    import.dll, import.func
                ));
            }
            // SAFETY: the mapping is still RW and the checked IAT slot is in it.
            unsafe { (mapping.ptr.add(off) as *mut u64).write_unaligned(value) };
        }
        Ok(())
    }

    fn entry(img: &PeImage) -> Result<u64, String> {
        let entry = img
            .image_base
            .checked_add(img.entry_rva as u64)
            .ok_or_else(|| "native entry address overflows".to_string())?;
        if entry < img.image_base || entry >= img.image_base + img.image.len() as u64 {
            return Err("native entry point lies outside the loaded image".to_string());
        }
        Ok(entry)
    }

    fn command_line_w(prog: &str, args: &[String]) -> Result<Vec<u16>, String> {
        let mut line = crate::pe::emu::quote_arg(prog);
        for arg in args {
            line.push(' ');
            line.push_str(&crate::pe::emu::quote_arg(arg));
        }
        let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
        if wide.len() * 2 > crate::pe::emu::CMDLINE_SIZE {
            return Err("command line too long (64K guest block)".to_string());
        }
        Ok(wide)
    }

    fn command_line_a(command_line: &[u16]) -> Vec<u8> {
        let end = command_line
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(command_line.len());
        let text = String::from_utf16_lossy(&command_line[..end]);
        let mut bytes = text
            .chars()
            .map(|ch| if ch.is_ascii() { ch as u8 } else { b'?' })
            .collect::<Vec<_>>();
        bytes.push(0);
        bytes
    }

    pub(super) fn run_rust_baseline_argv(
        img: &PeImage,
        prog: &str,
        args: &[String],
    ) -> Result<(u32, Vec<u8>), String> {
        let _run = NATIVE_RUN_LOCK
            .lock()
            .map_err(|_| "native backend execution lock is poisoned".to_string())?;
        let entry = entry(img)?;
        let mapping = map(img)?;
        patch_baseline_imports(&mapping, img)?;
        let tls = setup_tls(&mapping, img)?;
        let cmdline = command_line_w(prog, args)?;
        let cmdline_a = command_line_a(&cmdline);
        let mut fs = NativeFs {
            fs: WinFs::new(),
            handles: HashMap::new(),
            next: 0x100,
        };
        COMMAND_LINE_W.store(cmdline.as_ptr() as u64, Ordering::Release);
        COMMAND_LINE_A.store(cmdline_a.as_ptr() as u64, Ordering::Release);
        NATIVE_FS.store((&mut fs as *mut NativeFs) as u64, Ordering::Release);
        let mut fds = [-1, -1];
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            return Err(format!(
                "native backend could not create stdout pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let pid = unsafe { fork() };
        if pid < 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
            }
            return Err(format!(
                "native backend could not fork guest: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            unsafe {
                close(fds[0]);
                if dup2(fds[1], 1) < 0 {
                    _exit(127);
                }
                close(fds[1]);
            }
            if protect_exec(&mapping).is_err() {
                unsafe { _exit(127) };
            }
            if let Some(tls) = tls.as_ref() {
                if !unsafe { set_gs(tls.teb.as_ptr() as u64) } {
                    unsafe { _exit(127) };
                }
            }
            // SAFETY: the entry is in the child-owned RX PE mapping. Its
            // imported ExitProcess trampoline terminates this child.
            let guest: unsafe extern "win64" fn() -> u32 = unsafe { std::mem::transmute(entry) };
            let code = unsafe { guest() };
            unsafe { _exit(code as i32) };
        }
        unsafe {
            close(fds[1]);
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                break;
            }
            if n < 0 {
                unsafe {
                    close(fds[0]);
                }
                return Err(format!(
                    "native backend could not read guest stdout: {}",
                    std::io::Error::last_os_error()
                ));
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        unsafe {
            close(fds[0]);
        }
        let mut status = 0;
        if unsafe { waitpid(pid, &mut status, 0) } != pid {
            return Err(format!(
                "native backend could not reap guest: {}",
                std::io::Error::last_os_error()
            ));
        }
        COMMAND_LINE_W.store(0, Ordering::Release);
        COMMAND_LINE_A.store(0, Ordering::Release);
        NATIVE_FS.store(0, Ordering::Release);
        if status & 0x7f != 0 {
            return Err(format!(
                "native guest terminated by signal {}",
                status & 0x7f
            ));
        }
        Ok(((status >> 8) as u32, out))
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    use super::PeImage;

    pub(super) fn run_import_free(_: &PeImage) -> Result<u32, String> {
        Err("native backend is available only on Linux x86_64".to_string())
    }

    pub(super) fn run_rust_baseline_argv(
        _: &PeImage,
        _: &str,
        _: &[String],
    ) -> Result<(u32, Vec<u8>), String> {
        Err("native backend is available only on Linux x86_64".to_string())
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::pe::{
        builder::{build, Asm},
        load,
    };

    #[test]
    fn executes_an_import_free_pe_at_native_speed() {
        let mut asm = Asm::new();
        asm.mov_r32_imm(0, 37);
        asm.ret();
        let img = load(&build(asm, &[])).expect("fixture PE loads");
        assert_eq!(run_import_free(&img).expect("native PE runs"), 37);
    }

    #[test]
    fn imports_remain_on_the_interpreter_until_trampolines_exist() {
        let mut asm = Asm::new();
        asm.ret();
        let img = load(&build(asm, &[("KERNEL32.DLL", "ExitProcess")])).expect("fixture PE loads");
        let err = run_import_free(&img).expect_err("imports need shims");
        assert!(err.contains("does not yet support PE imports"));
    }

    #[test]
    fn executes_the_checked_in_rust_hello_guest_with_native_trampolines() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_hello.exe"
        );
        let bytes = std::fs::read(path).expect("checked-in guest exists");
        let img = load(&bytes).expect("rust hello loads");
        let (code, out) = run_rust_baseline(&img).expect("native rust hello runs");
        assert_eq!(code, 0);
        assert_eq!(out, b"Hello from Rust");
    }

    #[test]
    fn executes_the_checked_in_rust_argv_guest_with_native_trampolines() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_argv.exe"
        );
        let bytes = std::fs::read(path).expect("checked-in guest exists");
        let img = load(&bytes).expect("rust argv loads");
        let args = [
            "hello".to_string(),
            "a b".to_string(),
            "--version".to_string(),
        ];
        let (code, out) =
            run_rust_baseline_argv(&img, "myprog.exe", &args).expect("native rust argv runs");
        assert_eq!(code, 0);
        assert_eq!(out, b"myprog.exe hello \"a b\" --version\n");
    }
}
