//! Native x86-64 PE execution backend.
//!
//! This is deliberately a small first step toward a Wine-style execution
//! path.  On an x86-64 Linux host, instructions in a PE32+ image do not need
//! interpretation: they can run directly on the processor once the image is
//! mapped at its preferred base.  What still needs building is the Windows
//! personality around that code (DLL loading, import trampolines, TEB/PEB,
//! exceptions, threads, and isolation).
//!
//! PE instructions execute in a contained Linux child. Windows APIs require
//! explicit native trampolines; unsupported imports fail before guest entry.

use crate::pe::PeImage;

const COMMAND_LINE_BYTES: usize = 0x10000;

fn quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg.chars().any(|ch| matches!(ch, ' ' | '\t' | '"' | '\n')) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat('\\').take(backslashes));
                backslashes = 0;
                out.push(ch);
            }
        }
    }
    out.extend(std::iter::repeat('\\').take(backslashes * 2));
    out.push('"');
    out
}

/// True when this build can execute the initial native backend.
pub const AVAILABLE: bool = cfg!(all(target_os = "linux", target_arch = "x86_64"));

/// Whether this host backend can bind a PE import without a fallback thunk.
pub fn supports_import(dll: &str, func: &str) -> bool {
    imp::supports_import(dll, func)
}

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

/// Run a native guest against an existing isolated instance filesystem and
/// return the child-committed filesystem with its exit status and console
/// output. The guest still executes in a forked child; state crosses that
/// boundary as a validated in-memory snapshot, never through a host mount.
pub fn run_rust_baseline_argv_with_fs(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), String> {
    imp::run_rust_baseline_argv_with_fs(img, fs, prog, args)
}

/// As [`run_rust_baseline_argv_with_fs`], forwarding stdout chunks while the
/// isolated native child is still running.
pub fn run_rust_baseline_argv_with_fs_streaming(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), String> {
    imp::run_rust_baseline_argv_with_fs_streaming(img, fs, prog, args, output)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use super::{PeImage, COMMAND_LINE_BYTES, quote_arg};
    use crate::winfs::WinFs;
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
    #[cfg(test)]
    use std::sync::LazyLock;
    use std::sync::{Arc, Condvar, Mutex};

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const PROT_EXEC: i32 = 0x4;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANONYMOUS: i32 = 0x20;
    // Linux-specific. Unlike MAP_FIXED, this never replaces an existing map.
    const MAP_FIXED_NOREPLACE: i32 = 0x100000;
    const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;
    const PROCESS_HEAP_HANDLE: u64 = 0x400;
    // A child-local stand-in for the API-set modules dynamically requested by
    // the Universal CRT. It is deliberately not a host `dlopen` handle.
    const API_SET_MODULE: u64 = 0x5749_4e43_4c49_0001;
    const MODULE_FILE_NAME: &[u16] = &[
        b'C' as u16,
        b':' as u16,
        b'\\' as u16,
        b'w' as u16,
        b'i' as u16,
        b'n' as u16,
        b'c' as u16,
        b'l' as u16,
        b'i' as u16,
        b'\\' as u16,
        b'w' as u16,
        b'i' as u16,
        b'n' as u16,
        b'c' as u16,
        b'l' as u16,
        b'i' as u16,
        b'.' as u16,
        b'e' as u16,
        b'x' as u16,
        b'e' as u16,
    ];
    static EMPTY_ENVIRONMENT_BLOCK: [u16; 2] = [0, 0];

    // Preferred-base PE mappings collide by design. Serialize native runs in
    // this process until relocations allow separate address-space layouts.
    static NATIVE_RUN_LOCK: Mutex<()> = Mutex::new(());

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
        #[cfg(test)]
        fn pause() -> i32;
        fn dup2(oldfd: i32, newfd: i32) -> i32;
        fn close(fd: i32) -> i32;
        fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
        fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn kill(pid: i32, signal: i32) -> i32;
        fn _exit(status: i32) -> !;
        fn malloc(size: usize) -> *mut c_void;
        fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
        fn free(ptr: *mut c_void);
        fn getrandom(buf: *mut c_void, buflen: usize, flags: u32) -> isize;
        fn clock_gettime(clock_id: i32, time: *mut NativeTimespec) -> i32;
    }

    #[repr(C)]
    struct NativeTimespec {
        seconds: i64,
        nanoseconds: i64,
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
            _exit, command_line_a, environment_block, linux_protection, load_native_child_image,
            native_add_vectored_exception_handler, native_close_handle, native_create_process_w,
            native_create_waitable_timer_ex_w, native_delete_critical_section,
            native_enter_critical_section, native_extended_path, native_file_attributes,
            native_encode_pointer, native_decode_pointer,
            native_format_message_w, native_free_environment_strings_w, native_get_acp,
            native_format_message_a,
            native_get_computer_name_ex_w, native_get_console_mode, native_get_console_output_cp,
            native_get_console_screen_buffer_info, native_get_cp_info,
            native_get_current_directory_w, native_get_current_process,
            native_get_current_process_id, native_get_current_thread,
            native_get_environment_strings_w, native_get_environment_variable_w,
            native_get_exit_code_process, native_get_file_type, native_get_full_path_name_w,
            native_get_last_error, native_get_module_file_name_w, native_get_module_handle_a,
            native_global_memory_status_ex, NativeMemoryStatus,
            native_get_module_handle_ex_w, native_get_module_handle_w, native_get_oem_cp,
            native_get_proc_address, native_get_startup_info_w, native_get_string_type_w,
            native_get_system_info, native_get_user_profile_directory_w, native_heap_alloc,
            native_heap_free, native_heap_realloc, native_initialize_critical_section_ex,
            native_heap_size,
            native_initialize_critical_section_and_spin_count,
            native_initialize_srw_lock,
            native_is_processor_feature_present,
            native_rtl_get_version, native_rtl_nt_status_to_dos_error,
            native_acquire_srw_lock_exclusive, native_release_srw_lock_exclusive,
            native_try_acquire_srw_lock_shared, native_release_srw_lock_shared,
            native_initialize_condition_variable, native_sleep_condition_variable_srw,
            native_wake_all_condition_variable,
            native_init_once_execute_once,
            native_initialize_slist_head, native_is_valid_code_page, native_launch_spec,
            native_lc_map_string_w, native_leave_critical_section, native_multi_byte_to_wide_char,
            native_process_prng, native_query_performance_frequency, native_set_console_mode,
            native_set_file_time, native_set_last_error, native_set_thread_stack_guarantee,
            native_set_unhandled_exception_filter, native_set_waitable_timer,
            native_terminate_process, native_wait_for_single_object, native_wait_on_address,
            native_wide_char_to_multi_byte, native_write_console_w, parse_windows_command_line,
            process_ctx, uppercase_ascii_utf16, waitpid, write_process_information,
            NativeLaunchSpec, API_SET_MODULE, PROT_EXEC, PROT_READ, PROT_WRITE,
        };
        use crate::winfs::WinFs;

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
        fn import_binding_checks_the_dll_as_well_as_the_function() {
            assert!(super::supports_import("KERNEL32.dll", "ExitProcess"));
            assert!(super::supports_import("WINMM.dll", "timeGetTime"));
            assert!(!super::supports_import("USER32.dll", "ExitProcess"));
            assert!(!super::supports_import("KERNEL32.dll", "timeGetTime"));
            assert!(!super::supports_import("KERNEL32.dll", "NoSuchApi"));
        }

        #[test]
        fn initializes_critical_section_with_spin_count() {
            let mut section = [0x5au8; 40];
            assert_eq!(native_initialize_critical_section_and_spin_count(section.as_mut_ptr(), 4000), 1);
            assert_eq!(section, [0; 40]);
            assert_eq!(native_initialize_critical_section_and_spin_count(std::ptr::null_mut(), 0), 0);
        }

        #[test]
        fn pointer_encoding_round_trips_null_and_non_null_values() {
            for value in [0, 1, 0x1234_5678_9abc_def0] {
                let encoded = native_encode_pointer(value);
                assert_ne!(encoded, value);
                assert_eq!(native_decode_pointer(encoded), value);
            }
        }

        #[test]
        fn tracks_exact_native_heap_sizes_and_rejects_freed_blocks() {
            let ptr = super::native_heap_alloc(super::PROCESS_HEAP_HANDLE, 0x8, 3);
            assert_ne!(ptr, 0);
            assert_eq!(native_heap_size(super::PROCESS_HEAP_HANDLE, 0, ptr), 3);
            assert_eq!(unsafe { std::slice::from_raw_parts(ptr as *const u8, 3) }, &[0, 0, 0]);
            let grown = native_heap_realloc(super::PROCESS_HEAP_HANDLE, 0x8, ptr, 9);
            assert_ne!(grown, 0);
            assert_eq!(native_heap_size(super::PROCESS_HEAP_HANDLE, 0, grown), 9);
            assert_eq!(unsafe { std::slice::from_raw_parts(grown as *const u8, 9) }, &[0; 9]);
            assert_eq!(native_heap_free(super::PROCESS_HEAP_HANDLE, 0, grown), 1);
            assert_eq!(native_heap_size(super::PROCESS_HEAP_HANDLE, 0, grown), usize::MAX);
            assert_eq!(native_heap_free(super::PROCESS_HEAP_HANDLE, 0, grown), 0);
        }

        #[test]
        fn initializes_srw_lock_to_unlocked_state() {
            let mut lock = u64::MAX;
            native_initialize_srw_lock(&mut lock);
            assert_eq!(lock, 0);
            native_initialize_srw_lock(std::ptr::null_mut());
        }

        #[test]
        fn srw_lock_blocks_shared_try_while_exclusive_is_held() {
            let mut lock = 0u64;
            native_initialize_srw_lock(&mut lock);
            native_acquire_srw_lock_exclusive(&mut lock);
            assert_eq!(native_try_acquire_srw_lock_shared(&mut lock), 0);
            native_release_srw_lock_exclusive(&mut lock);
            assert_eq!(native_try_acquire_srw_lock_shared(&mut lock), 1);
            native_release_srw_lock_shared(&mut lock);
        }

        #[test]
        fn processor_feature_query_reports_host_isa_and_rejects_unknown_ids() {
            assert_eq!(native_is_processor_feature_present(10), 1); // SSE2 is required by x86-64
            assert_eq!(native_is_processor_feature_present(40), std::is_x86_feature_detected!("avx2") as i32);
            assert_eq!(native_is_processor_feature_present(999), 0);
        }

        #[test]
        fn ntdll_version_and_status_translation_report_windows_baseline() {
            let mut info = [0u8; 276];
            info[..4].copy_from_slice(&276u32.to_le_bytes());
            assert_eq!(native_rtl_get_version(info.as_mut_ptr()), 0);
            assert_eq!(u32::from_le_bytes(info[4..8].try_into().unwrap()), 10);
            assert_eq!(u32::from_le_bytes(info[12..16].try_into().unwrap()), 19045);
            info[..4].copy_from_slice(&275u32.to_le_bytes());
            assert_eq!(native_rtl_get_version(info.as_mut_ptr()), 0xC000_000D);
            assert_eq!(native_rtl_nt_status_to_dos_error(0xC000_0022), 5);
            assert_eq!(native_rtl_nt_status_to_dos_error(0xDEAD_BEEF), 317);
        }

        #[test]
        fn condition_wait_releases_and_reacquires_exclusive_srw_lock() {
            let mut lock = 0u64;
            let mut condition = 0u64;
            native_initialize_srw_lock(&mut lock);
            native_initialize_condition_variable(&mut condition);
            native_acquire_srw_lock_exclusive(&mut lock);
            assert_eq!(native_sleep_condition_variable_srw(&mut condition, &mut lock, 0, 0), 0);
            assert_eq!(native_try_acquire_srw_lock_shared(&mut lock), 0);
            let condition_address = (&mut condition as *mut u64) as usize;
            let worker = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(5));
                native_wake_all_condition_variable(condition_address as *mut u64);
            });
            assert_eq!(native_sleep_condition_variable_srw(&mut condition, &mut lock, 1000, 0), 1);
            native_release_srw_lock_exclusive(&mut lock);
            worker.join().unwrap();
        }

        #[test]
        fn init_once_retries_failed_callback_and_caches_context() {
            extern "win64" fn callback(_once: *mut u64, parameter: u64, context: *mut u64) -> i32 {
                let calls = unsafe { &*(parameter as *const std::sync::atomic::AtomicU32) };
                if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 { return 0; }
                unsafe { context.write(0x1234) };
                1
            }
            let calls = std::sync::atomic::AtomicU32::new(0);
            let mut once = 0u64;
            let mut context = 0u64;
            let param = (&calls as *const std::sync::atomic::AtomicU32) as u64;
            let cb = callback as *const () as usize as u64;
            assert_eq!(native_init_once_execute_once(&mut once, cb, param, &mut context), 0);
            assert_eq!(native_init_once_execute_once(&mut once, cb, param, &mut context), 1);
            assert_eq!(context, 0x1234);
            context = 0;
            assert_eq!(native_init_once_execute_once(&mut once, cb, param, &mut context), 1);
            assert_eq!(context, 0x1234);
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        }

        #[test]
        fn validates_native_memory_status_buffer_length() {
            assert_eq!(native_global_memory_status_ex(std::ptr::null_mut()), 0);
            let mut status = NativeMemoryStatus {
                length: 63, load: 0, total_physical: 0, available_physical: 0,
                total_page_file: 0, available_page_file: 0, total_virtual: 0,
                available_virtual: 0, available_extended_virtual: 0,
            };
            assert_eq!(native_global_memory_status_ex(&mut status), 0);
            assert_eq!(status.total_physical, 0);
            status.length = 64;
            assert_eq!(native_global_memory_status_ex(&mut status), 1);
            assert_eq!(status.total_physical, 512 * 1024 * 1024);
            assert_eq!(status.available_physical, 256 * 1024 * 1024);
        }

        #[test]
        fn exposes_the_windows_current_thread_pseudo_handle() {
            assert_eq!(native_get_current_thread(), u64::MAX - 1);
        }

        #[test]
        fn writes_the_x64_process_information_layout() {
            let mut info = [0u8; 24];
            assert!(write_process_information(
                info.as_mut_ptr() as u64,
                0x6000,
                0x6100,
                42
            ));
            assert_eq!(u64::from_le_bytes(info[..8].try_into().unwrap()), 0x6000);
            assert_eq!(u64::from_le_bytes(info[8..16].try_into().unwrap()), 0x6100);
            assert_eq!(u32::from_le_bytes(info[16..20].try_into().unwrap()), 42);
            assert_eq!(u32::from_le_bytes(info[20..24].try_into().unwrap()), 1);
            assert!(!write_process_information(0, 0, 0, 0));
        }

        #[test]
        fn exposes_a_process_owned_id_and_active_exit_status() {
            let process = native_get_current_process();
            assert_eq!(process, u64::MAX);
            assert_eq!(native_get_current_process_id(), 1);
            let mut exit_code = 0;
            assert_eq!(native_get_exit_code_process(process, &mut exit_code), 1);
            assert_eq!(exit_code, 259); // STILL_ACTIVE
        }

        #[test]
        fn rejects_invalid_process_queries_and_pseudo_handle_closes() {
            native_set_last_error(0);
            let mut exit_code = 0;
            assert_eq!(native_get_exit_code_process(0x1234, &mut exit_code), 0);
            assert_eq!(native_get_last_error(), 6); // ERROR_INVALID_HANDLE
            assert_eq!(native_close_handle(native_get_current_process()), 0);
            assert_eq!(native_get_last_error(), 6);
        }

        #[test]
        fn owns_child_process_handles_until_explicit_close() {
            let process = process_ctx().unwrap();
            let (handle, thread_handle, child) = process
                .children
                .lock()
                .unwrap()
                .allocate(process.process_id);
            assert_eq!(child.parent_process_id, 1);
            assert_ne!(handle, thread_handle);
            assert!(child.process_id >= 2);
            let mut exit_code = 0;
            assert_eq!(native_get_exit_code_process(handle, &mut exit_code), 1);
            assert_eq!(exit_code, 259); // STILL_ACTIVE
            assert_eq!(native_wait_for_single_object(handle, 0), 258); // WAIT_TIMEOUT
            assert_eq!(native_wait_for_single_object(thread_handle, 0), 258); // WAIT_TIMEOUT
            assert_eq!(native_terminate_process(handle, 23), 1);
            assert_eq!(native_wait_for_single_object(handle, 0), 0);
            assert_eq!(native_wait_for_single_object(thread_handle, 0), 0);
            assert_eq!(native_get_exit_code_process(handle, &mut exit_code), 1);
            assert_eq!(exit_code, 23);
            assert_eq!(native_close_handle(handle), 1);
            assert_eq!(native_get_exit_code_process(handle, &mut exit_code), 0);
            assert_eq!(
                native_get_exit_code_process(thread_handle, &mut exit_code),
                1
            );
            assert_eq!(exit_code, 23);
            assert_eq!(native_close_handle(thread_handle), 1);
        }

        #[test]
        fn terminate_process_signals_a_launched_host_child() {
            let process = process_ctx().unwrap();
            let (handle, _, child) = process
                .children
                .lock()
                .unwrap()
                .allocate(process.process_id);
            let pid = unsafe { super::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                unsafe {
                    super::pause();
                    _exit(0);
                }
            }
            child
                .host_pid
                .store(pid, std::sync::atomic::Ordering::Release);
            assert_eq!(native_terminate_process(handle, 23), 1);
            assert_eq!(*child.termination_code.lock().unwrap(), Some(23));
            let mut status = 0;
            assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
            assert_eq!(status & 0x7f, 15);
            assert_eq!(native_close_handle(handle), 1);
        }

        #[test]
        fn parses_quoted_create_process_command_lines() {
            assert_eq!(
                parse_windows_command_line(r#"  "C:\Program Files\tool.exe" --flag "two words""#)
                    .unwrap(),
                [r"C:\Program Files\tool.exe", "--flag", "two words"]
            );
            assert_eq!(
                parse_windows_command_line(r#"tool.exe "a\"b""#).unwrap(),
                ["tool.exe", "a\"b"]
            );
            assert!(parse_windows_command_line("\"unterminated").is_err());
        }

        #[test]
        fn parses_a_unicode_child_environment_block() {
            let block: Vec<u16> = "Path=one\0NAME=value\0\0".encode_utf16().collect();
            assert_eq!(
                environment_block(block.as_ptr() as u64).unwrap(),
                [
                    ("Path".to_string(), "one".to_string()),
                    ("NAME".to_string(), "value".to_string())
                ]
            );
            let invalid: Vec<u16> = "missing-equals\0\0".encode_utf16().collect();
            assert_eq!(environment_block(invalid.as_ptr() as u64), Err(87));
        }

        #[test]
        fn derives_create_process_target_and_validates_working_directory() {
            let mut fs = WinFs::new();
            fs.mkdir(r"C:\work").unwrap();
            let launch = native_launch_spec(
                None,
                Some(r#""C:\tools\child.exe" --check"#.to_string()),
                Some(r"C:\work".to_string()),
                &fs,
            )
            .unwrap();
            assert_eq!(launch.application, r"C:\tools\child.exe");
            assert_eq!(launch.arguments, [r"C:\tools\child.exe", "--check"]);
            assert_eq!(launch.current_directory, r"C:\work");
            assert_eq!(
                native_launch_spec(Some(String::new()), None, None, &fs),
                Err(87)
            );
            assert_eq!(
                native_launch_spec(
                    Some(r"C:\child.exe".to_string()),
                    None,
                    Some(r"C:\missing".to_string()),
                    &fs,
                ),
                Err(267)
            );
        }

        #[test]
        fn loads_child_pe_images_only_from_the_guest_filesystem() {
            let mut fs = WinFs::new();
            fs.write_file(r"C:\child.exe", crate::pe::builder::hello("child"))
                .unwrap();
            let launch =
                native_launch_spec(Some(r"C:\child.exe".to_string()), None, None, &fs).unwrap();
            assert!(!load_native_child_image(&fs, &launch)
                .unwrap()
                .image
                .is_empty());
            assert_eq!(
                load_native_child_image(
                    &fs,
                    &NativeLaunchSpec {
                        application: r"C:\missing.exe".to_string(),
                        command_line: String::new(),
                        arguments: vec![],
                        current_directory: r"C:\".to_string(),
                    },
                )
                .unwrap_err(),
                2
            );
            fs.write_file(r"C:\bad.exe", b"not a PE".to_vec()).unwrap();
            let invalid =
                native_launch_spec(Some(r"C:\bad.exe".to_string()), None, None, &fs).unwrap();
            assert_eq!(load_native_child_image(&fs, &invalid).unwrap_err(), 193);
        }

        #[test]
        fn create_process_rejects_missing_output_record_before_launching() {
            let mut application: Vec<u16> = r"C:\child.exe"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            native_set_last_error(0);
            assert_eq!(
                native_create_process_w(
                    application.as_mut_ptr(),
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null(),
                    0,
                    0,
                ),
                0
            );
            assert_eq!(native_get_last_error(), 87); // ERROR_INVALID_PARAMETER
        }

        #[test]
        fn resolves_the_kernel32_ansi_module_handle() {
            assert_eq!(
                native_get_module_handle_a(b"kernel32\0".as_ptr()),
                API_SET_MODULE
            );
            assert_eq!(native_get_module_handle_a(b"user32\0".as_ptr()), 0);
        }

        #[test]
        fn reallocates_process_heap_memory_without_losing_contents() {
            let allocation = native_heap_alloc(super::PROCESS_HEAP_HANDLE, 0, 4);
            assert_ne!(allocation, 0);
            unsafe { std::ptr::copy_nonoverlapping(b"rg!\0".as_ptr(), allocation as *mut u8, 4) };
            let grown = native_heap_realloc(super::PROCESS_HEAP_HANDLE, 0, allocation, 8);
            assert_ne!(grown, 0);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(grown as *const u8, 4) },
                b"rg!\0"
            );
            assert_eq!(native_heap_free(super::PROCESS_HEAP_HANDLE, 0, grown), 1);
        }

        #[test]
        fn fills_process_prng_output() {
            let mut output = [0; 16];
            assert_eq!(native_process_prng(output.as_mut_ptr(), output.len()), 1);
            assert!(output.iter().any(|byte| *byte != 0));
            assert_eq!(native_process_prng(std::ptr::null_mut(), 1), 0);
        }

        #[test]
        fn reports_a_basic_console_mode_for_standard_output() {
            let mut mode = 0;
            assert_eq!(native_get_console_mode(1, &mut mode), 1);
            assert_eq!(mode, 1);
            assert_eq!(native_get_console_mode(99, &mut mode), 0);
            assert_eq!(native_get_console_mode(1, std::ptr::null_mut()), 0);
        }

        #[test]
        fn reports_the_native_console_output_code_page() {
            assert_eq!(native_get_console_output_cp(), 1252);
        }

        #[test]
        fn accepts_timestamp_updates_on_native_standard_handles() {
            assert_eq!(
                native_set_file_time(1, std::ptr::null(), std::ptr::null(), std::ptr::null()),
                1
            );
            assert_eq!(
                native_set_file_time(99, std::ptr::null(), std::ptr::null(), std::ptr::null()),
                0
            );
        }

        #[test]
        fn rejects_console_writes_to_non_console_handles() {
            assert_eq!(
                native_write_console_w(99, std::ptr::null(), 0, std::ptr::null_mut(), 0),
                0
            );
        }

        #[test]
        fn reports_missing_variables_from_the_empty_native_environment() {
            native_set_last_error(0);
            let name = ['R' as u16, 0];
            assert_eq!(
                native_get_environment_variable_w(name.as_ptr(), std::ptr::null_mut(), 0),
                0
            );
            assert_eq!(native_get_last_error(), 203);
        }

        #[test]
        fn supplies_a_root_current_directory() {
            let mut output = [0; 4];
            assert_eq!(native_get_current_directory_w(4, output.as_mut_ptr()), 3);
            assert_eq!(&output, &['C' as u16, ':' as u16, '\\' as u16, 0]);
            assert_eq!(native_get_current_directory_w(3, output.as_mut_ptr()), 4);
        }

        #[test]
        fn supplies_a_synthetic_computer_name() {
            let mut len = 0;
            assert_eq!(
                native_get_computer_name_ex_w(5, std::ptr::null_mut(), &mut len),
                0
            );
            assert_eq!(len, 7);
            let mut output = [0; 7];
            assert_eq!(
                native_get_computer_name_ex_w(5, output.as_mut_ptr(), &mut len),
                1
            );
            assert_eq!(
                &output[..6],
                &['w' as u16, 'i' as u16, 'n' as u16, 'c' as u16, 'l' as u16, 'i' as u16]
            );
        }

        #[test]
        fn supplies_x64_system_information() {
            let mut output = [0; 48];
            native_get_system_info(output.as_mut_ptr());
            assert_eq!(u16::from_le_bytes(output[..2].try_into().unwrap()), 9);
            assert_eq!(u32::from_le_bytes(output[4..8].try_into().unwrap()), 4096);
            assert_eq!(
                u32::from_le_bytes(output[36..40].try_into().unwrap()),
                65_536
            );
        }

        #[test]
        fn supplies_a_nanosecond_performance_frequency() {
            let mut frequency = 0;
            assert_eq!(native_query_performance_frequency(&mut frequency), 1);
            assert_eq!(frequency, 1_000_000_000);
        }

        #[test]
        fn cooperatively_wakes_address_waiters() {
            let expected = 0u8;
            assert_eq!(
                native_wait_on_address(
                    (&expected as *const u8).cast(),
                    (&expected as *const u8).cast(),
                    1,
                    u32::MAX
                ),
                1
            );
            assert_eq!(
                native_wait_on_address(std::ptr::null(), (&expected as *const u8).cast(), 1, 0),
                0
            );
        }

        #[test]
        fn creates_an_immediately_signaled_waitable_timer() {
            let timer = native_create_waitable_timer_ex_w(std::ptr::null(), std::ptr::null(), 0, 0);
            assert_ne!(timer, 0);
            assert_eq!(
                native_set_waitable_timer(timer, std::ptr::null(), 0, 0, 0, 0),
                1
            );
        }

        #[test]
        fn expands_relative_paths_from_the_native_root() {
            let input = ['.' as u16, 0];
            let mut output = [0; 4];
            assert_eq!(
                native_get_full_path_name_w(
                    input.as_ptr(),
                    4,
                    output.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                3
            );
            assert_eq!(&output, &['C' as u16, ':' as u16, '\\' as u16, 0]);
        }

        #[test]
        fn classifies_native_file_metadata_attributes() {
            assert_eq!(native_file_attributes(true), 0x10);
            assert_eq!(native_file_attributes(false), 0x80);
        }

        #[test]
        fn encodes_extended_final_paths() {
            assert_eq!(native_extended_path("C:\\"), "\\\\?\\C:\\");
        }

        #[test]
        fn supplies_a_synthetic_user_profile_directory() {
            let mut len = 0;
            assert_eq!(
                native_get_user_profile_directory_w(u64::MAX - 3, std::ptr::null_mut(), &mut len),
                0
            );
            assert_eq!(len, 16);
            let mut output = [0; 16];
            assert_eq!(
                native_get_user_profile_directory_w(u64::MAX - 3, output.as_mut_ptr(), &mut len),
                1
            );
            assert_eq!(String::from_utf16_lossy(&output[..15]), "C:\\Users\\wincli");
        }

        #[test]
        fn supplies_a_standard_console_screen_buffer() {
            let mut output = [0; 22];
            assert_eq!(
                native_get_console_screen_buffer_info(1, output.as_mut_ptr()),
                1
            );
            assert_eq!(i16::from_le_bytes(output[..2].try_into().unwrap()), 80);
            assert_eq!(i16::from_le_bytes(output[2..4].try_into().unwrap()), 25);
        }

        #[test]
        fn accepts_console_mode_changes_for_standard_handles() {
            assert_eq!(native_set_console_mode(1, 5), 1);
            assert_eq!(native_set_console_mode(99, 5), 0);
        }

        #[test]
        fn formats_a_native_system_error_message() {
            let mut output = [0; 32];
            let count = native_format_message_w(0, 0, 5, 0, output.as_mut_ptr(), 32, 0);
            assert_eq!(
                String::from_utf16_lossy(&output[..count as usize]),
                "WinCLI native error.\r\n"
            );
        }

        #[test]
        fn formats_ansi_system_error_and_rejects_short_buffer() {
            let mut short = [0u8; 4];
            assert_eq!(native_format_message_a(0x1000, 0, 5, 0, short.as_mut_ptr(), 4, 0), 0);
            let mut output = [0u8; 64];
            let count = native_format_message_a(0x1000, 0, 5, 0, output.as_mut_ptr(), 64, 0);
            assert_eq!(&output[..count as usize], b"WinCLI native error.\r\n");
            assert_eq!(output[count as usize], 0);
        }

        #[test]
        fn exposes_the_main_module_handle() {
            assert_eq!(native_get_module_handle_w(std::ptr::null()), 0x1400_0000_0);
        }

        #[test]
        fn exposes_the_main_module_through_module_handle_ex() {
            let mut handle = 0;
            assert_eq!(
                native_get_module_handle_ex_w(0, std::ptr::null(), &mut handle),
                1
            );
            assert_eq!(handle, 0x1400_0000_0);
        }

        #[test]
        fn resolves_supported_dynamic_api_set_exports() {
            assert_ne!(
                native_get_proc_address(API_SET_MODULE, c"CompareStringEx".as_ptr().cast()),
                0
            );
            assert_eq!(
                native_get_proc_address(API_SET_MODULE, c"GetEnvironmentVariableW".as_ptr().cast()),
                native_get_environment_variable_w as *const () as usize as u64
            );
            assert_ne!(native_get_proc_address(API_SET_MODULE, c"FlsAlloc".as_ptr().cast()), 0);
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
        fn initializes_an_empty_64_bit_slist_header() {
            let mut header = [0xa5; 16];
            native_initialize_slist_head(header.as_mut_ptr());
            assert_eq!(header, [0; 16]);
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
        fn exposes_a_synthetic_windows_module_path() {
            let mut path = [0; 32];
            let len = native_get_module_file_name_w(0, path.as_mut_ptr(), path.len() as u32);
            assert_eq!(
                String::from_utf16(&path[..len as usize]).unwrap(),
                "C:\\wincli\\wincli.exe"
            );
            let mut short = [0; 3];
            assert_eq!(native_get_module_file_name_w(0, short.as_mut_ptr(), 3), 3);
            assert_eq!(short, ['C' as u16, ':' as u16, '\\' as u16]);
        }

        #[test]
        fn resolves_loaded_windows_module_names_in_wide_form() {
            let kernel: Vec<u16> = "KERNEL32.dll".encode_utf16().chain(std::iter::once(0)).collect();
            assert_eq!(native_get_module_handle_w(kernel.as_ptr()), API_SET_MODULE);
            let missing: Vec<u16> = "missing.dll".encode_utf16().chain(std::iter::once(0)).collect();
            assert_eq!(native_get_module_handle_w(missing.as_ptr()), 0);
        }

        #[test]
        fn exposes_and_frees_a_child_local_empty_environment_block() {
            let block = native_get_environment_strings_w();
            assert_eq!(unsafe { std::slice::from_raw_parts(block, 2) }, &[0, 0]);
            assert_eq!(native_free_environment_strings_w(block), 1);
            assert_eq!(native_free_environment_strings_w(std::ptr::null()), 0);
        }

        #[test]
        fn stores_the_child_unhandled_exception_filter() {
            assert_eq!(native_set_unhandled_exception_filter(0x1234), 0);
            assert_eq!(native_set_unhandled_exception_filter(0), 0x1234);
        }

        #[test]
        fn registers_a_non_null_vectored_exception_handler() {
            assert_eq!(native_add_vectored_exception_handler(1, 0), 0);
            assert_eq!(native_add_vectored_exception_handler(1, 0x1234), 0x1235);
        }

        #[test]
        fn accepts_a_thread_stack_guarantee_request() {
            let mut size = 0x5000;
            assert_eq!(native_set_thread_stack_guarantee(&mut size), 1);
            assert_eq!(native_set_thread_stack_guarantee(std::ptr::null_mut()), 0);
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

    /// Reserve a non-conflicting host address and rebase a child image to the
    /// address actually chosen by the kernel.
    #[allow(dead_code)] // attached to CreateProcessW's child launcher next
    fn map_relocated(img: &PeImage) -> Result<(Mapping, PeImage), String> {
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
            bytes[..8].copy_from_slice(&0x1400_0010_0u64.to_le_bytes());
            let image = PeImage {
                image_base: 0x1400_0000_0,
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
        if !img.imports.is_empty() || !img.unsupported.is_empty() {
            return Err(
                "import-free native entry point cannot bind PE imports"
                    .to_string(),
            );
        }
        if img.tls.is_some() {
            return Err("import-free native entry point cannot initialize TLS".to_string());
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

    struct NativeFile {
        path: String,
        offset: usize,
    }
    struct NativeFind {
        names: Vec<String>,
        index: usize,
    }
    struct NativeTls {
        teb: Box<[u8; 0x1000]>,
        slots: Box<[u64; 64]>,
        _data: Vec<u8>,
        _ldr: Box<[u8; 64]>,
    }
    impl NativeTls {
        fn clone_for_thread(&self) -> Self {
            let mut out = Self {
                teb: self.teb.clone(),
                slots: self.slots.clone(),
                _data: self._data.clone(),
                _ldr: self._ldr.clone(),
            };
            let teb = out.teb.as_ptr() as u64;
            put64(&mut out.teb[..], 0x30, teb);
            put64(&mut out.teb[..], 0x58, out.slots.as_ptr() as u64);
            put64(&mut out.teb[..], 0x60, teb + 0x800);
            out.slots[0] = out._data.as_ptr() as u64;
            put64(&mut out.teb[..], 0x800 + 0x20, out._ldr.as_ptr() as u64);
            out
        }
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
    extern "win64" fn native_create_thread(
        _security: u64,
        stack_size: usize,
        start: u64,
        parameter: u64,
        _flags: u32,
        thread_id: *mut u32,
    ) -> u64 {
        if start == 0 {
            native_set_last_error(87);
            return 0;
        }
        let Some(process) = process_ctx() else {
            native_set_last_error(6);
            return 0;
        };
        let tls = process
            .tls_template
            .lock()
            .ok()
            .and_then(|value| value.as_ref().map(NativeTls::clone_for_thread));
        let handle = process.thread_next.fetch_add(1, Ordering::AcqRel);
        let builder = std::thread::Builder::new().stack_size(stack_size.max(64 * 1024));
        let thread_process = Arc::clone(&process);
        let spawned = builder.spawn(move || {
            let _tls = tls;
            if let Some(tls) = _tls.as_ref() {
                if !unsafe { set_gs(tls.teb.as_ptr() as u64) } {
                    return 1;
                }
            } else if thread_process.gs_base.load(Ordering::Acquire) != 0 {
                return 1;
            }
            let entry: unsafe extern "win64" fn(u64) -> u32 = unsafe { std::mem::transmute(start) };
            unsafe { entry(parameter) }
        });
        let Ok(join) = spawned else {
            native_set_last_error(8);
            return 0;
        };
        if !thread_id.is_null() {
            unsafe { thread_id.write(handle as u32) }
        }
        let result = match process.threads.lock() {
            Ok(mut threads) => {
                threads.insert(handle, NativeThread { join: Some(join), exit_code: None });
                handle
            }
            Err(_) => {
                native_set_last_error(6);
                0
            }
        };
        result
    }
    extern "win64" fn native_wait_for_single_object(handle: u64, milliseconds: u32) -> u32 {
        let process = process_ctx();
        if process.as_ref().is_some_and(|process| process.threads.lock().ok()
            .is_some_and(|threads| threads.contains_key(&handle))) {
            let deadline = if milliseconds == u32::MAX { None } else {
                std::time::Instant::now()
                    .checked_add(std::time::Duration::from_millis(milliseconds as u64))
            };
            loop {
                let join = {
                    let Some(process) = process.as_ref() else { return 0xffff_ffff; };
                    let Ok(mut threads) = process.threads.lock() else { return 0xffff_ffff; };
                    let Some(thread) = threads.get_mut(&handle) else { return 0xffff_ffff; };
                    if thread.exit_code.is_some() { return 0; }
                    if thread.join.as_ref().is_some_and(|join| join.is_finished()) {
                        thread.join.take()
                    } else { None }
                };
                if let Some(join) = join {
                    let code = join.join().unwrap_or(1);
                    if let Some(process) = process.as_ref() {
                        if let Ok(mut threads) = process.threads.lock() {
                            if let Some(thread) = threads.get_mut(&handle) {
                                thread.exit_code = Some(code);
                            }
                        }
                    }
                    return 0;
                }
                if milliseconds == 0 || deadline.is_some_and(|at| std::time::Instant::now() >= at) {
                    return 258; // WAIT_TIMEOUT; handle remains valid
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        match handle {
            0x7000_0000..0x8000_0000 => 0,
            _ => {
                let Some(process) = process else {
                    return 0xffff_ffff; // WAIT_FAILED
                };
                let Some(child) = child_process(&process, handle) else {
                    return 0xffff_ffff;
                };
                let Ok(mut state) = child.state.lock() else {
                    return 0xffff_ffff;
                };
                if state.is_some() {
                    return 0; // WAIT_OBJECT_0
                }
                if milliseconds == 0 {
                    return 258; // WAIT_TIMEOUT
                }
                if milliseconds == u32::MAX {
                    while state.is_none() {
                        state = match child.exited.wait(state) {
                            Ok(state) => state,
                            Err(_) => return 0xffff_ffff,
                        };
                    }
                    return 0;
                }
                let result = match child.exited.wait_timeout_while(
                    state,
                    std::time::Duration::from_millis(milliseconds as u64),
                    |state| state.is_none(),
                ) {
                    Ok((state, _)) if state.is_some() => 0,
                    Ok(_) => 258,
                    Err(_) => 0xffff_ffff,
                };
                result
            }
        }
    }
    extern "win64" fn native_wait_on_address(
        address: *const u8,
        compare: *const u8,
        size: usize,
        _milliseconds: u32,
    ) -> i32 {
        if address.is_null() || compare.is_null() || !(1..=8).contains(&size) {
            return 0;
        }
        std::thread::yield_now();
        1
    }
    extern "win64" fn native_wake_by_address(_address: *const u8) {}
    extern "win64" fn native_create_waitable_timer_ex_w(
        _attributes: *const u8,
        _name: *const u16,
        _flags: u32,
        _access: u32,
    ) -> u64 {
        process_ctx()
            .map(|process| process.timer_next.fetch_add(1, Ordering::AcqRel))
            .unwrap_or(0)
    }
    extern "win64" fn native_set_waitable_timer(
        handle: u64,
        _due_time: *const i64,
        _period: i32,
        _completion: u64,
        _arg: u64,
        _resume: i32,
    ) -> i32 {
        (0x7000_0000..0x8000_0000).contains(&handle) as i32
    }
    struct NativeFs {
        fs: WinFs,
        handles: HashMap<u64, NativeFile>,
        finds: HashMap<u64, NativeFind>,
        next: u64,
    }

    // CreateProcessW will allocate these once PE mapping is attached to the
    // registry; they are already consumed by the process-handle APIs.
    #[allow(dead_code)]
    struct NativeChildProcess {
        process_id: u32,
        parent_process_id: u32,
        host_pid: AtomicI32,
        termination_code: Mutex<Option<u32>>,
        state: Mutex<Option<u32>>,
        exited: Condvar,
    }

    struct NativeProcessTable {
        next_handle: u64,
        next_thread_handle: u64,
        next_process_id: u32,
        children: HashMap<u64, Arc<NativeChildProcess>>,
        primary_threads: HashMap<u64, Arc<NativeChildProcess>>,
    }

    #[allow(dead_code)]
    impl NativeProcessTable {
        fn new() -> Self {
            Self {
                next_handle: 0x6000_0000,
                next_thread_handle: 0x6100_0000,
                next_process_id: 2,
                children: HashMap::new(),
                primary_threads: HashMap::new(),
            }
        }

        fn allocate(&mut self, parent_process_id: u32) -> (u64, u64, Arc<NativeChildProcess>) {
            let handle = self.next_handle;
            self.next_handle += 1;
            let thread_handle = self.next_thread_handle;
            self.next_thread_handle += 1;
            let child = Arc::new(NativeChildProcess {
                process_id: self.next_process_id,
                parent_process_id,
                host_pid: AtomicI32::new(0),
                termination_code: Mutex::new(None),
                state: Mutex::new(None),
                exited: Condvar::new(),
            });
            self.next_process_id += 1;
            self.children.insert(handle, Arc::clone(&child));
            self.primary_threads
                .insert(thread_handle, Arc::clone(&child));
            (handle, thread_handle, child)
        }
    }

    #[allow(dead_code)] // called when the child launcher returns success
    fn write_process_information(output: u64, process: u64, thread: u64, process_id: u32) -> bool {
        if output == 0 {
            return false;
        }
        unsafe {
            let output = output as *mut u8;
            (output as *mut u64).write_unaligned(process);
            (output.add(8) as *mut u64).write_unaligned(thread);
            (output.add(16) as *mut u32).write_unaligned(process_id);
            (output.add(20) as *mut u32).write_unaligned(1);
        }
        true
    }

    fn finish_native_child(
        child: Arc<NativeChildProcess>,
        fs: Arc<Mutex<NativeFs>>,
        state_fd: i32,
        pid: i32,
    ) {
        let mut encoded = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read_count = unsafe { read(state_fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if read_count <= 0 {
                break;
            }
            encoded.extend_from_slice(&buffer[..read_count as usize]);
        }
        unsafe { close(state_fd) };
        let mut status = 0;
        let reaped = unsafe { waitpid(pid, &mut status, 0) } == pid;
        if reaped && !encoded.is_empty() {
            if let Ok(snapshot) = crate::snapshot::load(&encoded) {
                if let Ok(mut native_fs) = fs.lock() {
                    // A child process owns its working directory. Preserve
                    // the parent's directory while accepting its WinFs file
                    // changes from the snapshot transport.
                    let parent_cwd = native_fs.fs.cwd();
                    let mut snapshot = snapshot;
                    let _ = snapshot.set_cwd(&parent_cwd);
                    native_fs.fs = snapshot;
                }
            }
        }
        if let Ok(mut state) = child.state.lock() {
            if state.is_none() {
                let terminated = child.termination_code.lock().ok().and_then(|code| *code);
                *state = Some(terminated.unwrap_or_else(|| {
                    if reaped && status & 0x7f == 0 {
                        (status >> 8) as u32
                    } else {
                        1
                    }
                }));
            }
            child.exited.notify_all();
        }
    }

    /// State that belongs to exactly one Windows guest process. The current
    /// launcher still initializes legacy accessors from this bundle; keeping
    /// the ownership explicit is the migration seam for native CreateProcessW.
    struct NativeProcessContext {
        image_base: u64,
        process_id: u32,
        process_handle: u64,
        parent_process_id: u32,
        command_line_w: Vec<u16>,
        command_line_a: Vec<u8>,
        environment: Vec<(String, String)>,
        environment_block: Vec<u16>,
        fs: Arc<Mutex<NativeFs>>,
        last_error: AtomicU32,
        error_mode: AtomicU32,
        pointer_cookie: u64,
        heap_allocations: Mutex<HashMap<u64, usize>>,
        gs_base: AtomicU64,
        tls_template: Mutex<Option<NativeTls>>,
        dynamic_tls: Mutex<DynamicTlsSlots>,
        threads: Mutex<HashMap<u64, NativeThread>>,
        thread_next: AtomicU64,
        timer_next: AtomicU64,
        state_fd: AtomicU32,
        fls_value: AtomicU64,
        unhandled_exception_filter: AtomicU64,
        vectored_exception_handler: AtomicU64,
        exit_status: AtomicU32,
        exited: AtomicBool,
        children: Mutex<NativeProcessTable>,
    }

    struct NativeThread {
        join: Option<std::thread::JoinHandle<u32>>,
        exit_code: Option<u32>,
    }

    struct DynamicTlsSlots {
        active: [bool; 64],
        generation: [u64; 64],
        reserved_static: bool,
    }
    fn random_pointer_cookie() -> u64 {
        let mut cookie = 0u64;
        if unsafe { getrandom((&mut cookie as *mut u64).cast(), 8, 0) } != 8 {
            cookie = 0x7f3a_5e91_c62d_b408;
        }
        cookie | 1
    }
    impl DynamicTlsSlots {
        fn new(static_tls: bool) -> Self {
            let mut active = [false; 64];
            active[0] = static_tls;
            Self { active, generation: [0; 64], reserved_static: static_tls }
        }
    }
    thread_local! {
        static THREAD_TLS_VALUES: std::cell::RefCell<[(u64, u64); 64]> =
            const { std::cell::RefCell::new([(0, 0); 64]) };
    }

    // Import trampolines have no guest-context argument. This is therefore a
    // narrow dispatcher slot, while every mutable Windows-process datum lives
    // in the context it points at. A future CreateProcessW child installs its
    // own context in its guest host process.
    static NATIVE_PROCESS: Mutex<Option<Arc<NativeProcessContext>>> = Mutex::new(None);
    #[cfg(test)]
    static NATIVE_GUEST_ACTIVE: AtomicBool = AtomicBool::new(false);

    #[cfg(test)]
    static TEST_PROCESS: LazyLock<Arc<NativeProcessContext>> = LazyLock::new(|| {
        Arc::new(NativeProcessContext {
            image_base: 0x1400_0000_0,
            process_id: 1,
            process_handle: u64::MAX,
            parent_process_id: 0,
            command_line_w: vec![0],
            command_line_a: vec![0],
            environment: Vec::new(),
            environment_block: vec![0, 0],
            fs: Arc::new(Mutex::new(NativeFs {
                fs: WinFs::new(),
                handles: HashMap::new(),
                finds: HashMap::new(),
                next: 0x100,
            })),
            last_error: AtomicU32::new(0),
            error_mode: AtomicU32::new(0),
            pointer_cookie: random_pointer_cookie(),
            heap_allocations: Mutex::new(HashMap::new()),
            gs_base: AtomicU64::new(0),
            tls_template: Mutex::new(None),
            dynamic_tls: Mutex::new(DynamicTlsSlots::new(false)),
            threads: Mutex::new(HashMap::new()),
            thread_next: AtomicU64::new(0x8000_0000),
            timer_next: AtomicU64::new(0x7000_0000),
            state_fd: AtomicU32::new(u32::MAX),
            fls_value: AtomicU64::new(0),
            unhandled_exception_filter: AtomicU64::new(0),
            vectored_exception_handler: AtomicU64::new(0),
            exit_status: AtomicU32::new(259),
            exited: AtomicBool::new(false),
            children: Mutex::new(NativeProcessTable::new()),
        })
    });

    fn process_ctx() -> Option<Arc<NativeProcessContext>> {
        #[cfg(test)]
        if !NATIVE_GUEST_ACTIVE.load(Ordering::Acquire) {
            return Some(Arc::clone(&TEST_PROCESS));
        }
        if let Some(process) = NATIVE_PROCESS.lock().ok()?.as_ref().cloned() {
            return Some(process);
        }
        #[cfg(test)]
        return None;
        #[cfg(not(test))]
        None
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

    fn environment_block(ptr: u64) -> Result<Vec<(String, String)>, u32> {
        if ptr == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut offset = 0usize;
        loop {
            let mut units = Vec::new();
            while offset < 32 * 1024 {
                let unit = unsafe { (ptr as *const u16).add(offset).read() };
                offset += 1;
                if unit == 0 {
                    break;
                }
                units.push(unit);
            }
            if offset == 32 * 1024 && !units.is_empty() {
                return Err(87);
            }
            if units.is_empty() {
                return Ok(out);
            }
            let entry = String::from_utf16(&units).map_err(|_| 87u32)?;
            let (name, value) = entry
                .split_once('=')
                .filter(|(name, _)| !name.is_empty())
                .ok_or(87u32)?;
            out.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            out.push((name.to_string(), value.to_string()));
        }
    }

    fn environment_strings(environment: &[(String, String)]) -> Vec<u16> {
        let mut block = Vec::new();
        for (name, value) in environment {
            block.extend(format!("{name}={value}").encode_utf16());
            block.push(0);
        }
        block.push(0);
        if environment.is_empty() {
            block.push(0);
        }
        block
    }

    #[derive(Debug, PartialEq, Eq)]
    struct NativeLaunchSpec {
        application: String,
        command_line: String,
        arguments: Vec<String>,
        current_directory: String,
    }

    /// Parse the subset of Windows command-line syntax needed to identify an
    /// executable. Backslashes are literal except when immediately before a
    /// quote, following the CommandLineToArgvW/MSVC escaping rules.
    fn parse_windows_command_line(line: &str) -> Result<Vec<String>, String> {
        let mut args = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let mut index = 0;
        while index < chars.len() {
            while index < chars.len() && chars[index].is_ascii_whitespace() {
                index += 1;
            }
            if index == chars.len() {
                break;
            }
            let mut arg = String::new();
            let mut quoted = false;
            while index < chars.len() {
                let mut slashes = 0;
                while index < chars.len() && chars[index] == '\\' {
                    slashes += 1;
                    index += 1;
                }
                if index < chars.len() && chars[index] == '"' {
                    arg.extend(std::iter::repeat_n('\\', slashes / 2));
                    if slashes % 2 == 1 {
                        arg.push('"');
                    } else if quoted && index + 1 < chars.len() && chars[index + 1] == '"' {
                        arg.push('"');
                        index += 1;
                    } else {
                        quoted = !quoted;
                    }
                    index += 1;
                    continue;
                }
                arg.extend(std::iter::repeat_n('\\', slashes));
                if index == chars.len() || (!quoted && chars[index].is_ascii_whitespace()) {
                    break;
                }
                arg.push(chars[index]);
                index += 1;
            }
            if quoted {
                return Err("unterminated quote in command line".to_string());
            }
            args.push(arg);
        }
        Ok(args)
    }

    fn native_launch_spec(
        application: Option<String>,
        command_line: Option<String>,
        current_directory: Option<String>,
        fs: &WinFs,
    ) -> Result<NativeLaunchSpec, u32> {
        let command_line = command_line.unwrap_or_default();
        let arguments = parse_windows_command_line(&command_line).map_err(|_| 87u32)?;
        let application = application
            .filter(|value| !value.is_empty())
            .or_else(|| arguments.first().cloned())
            .ok_or(87u32)?;
        let application = fs.normalize(&application).map_err(|_| 3u32)?.display();
        let current_directory = match current_directory.filter(|value| !value.is_empty()) {
            Some(value) => {
                let path = fs.normalize(&value).map_err(|_| 3u32)?.display();
                if !fs.is_dir(&path) {
                    return Err(267u32); // ERROR_DIRECTORY
                }
                path
            }
            None => fs.cwd(),
        };
        Ok(NativeLaunchSpec {
            application,
            command_line,
            arguments,
            current_directory,
        })
    }

    fn load_native_child_image(fs: &WinFs, launch: &NativeLaunchSpec) -> Result<PeImage, u32> {
        let bytes = fs.read_file(&launch.application).map_err(|_| 2u32)?; // ERROR_FILE_NOT_FOUND
        crate::pe::load(&bytes).map_err(|_| 193u32) // ERROR_BAD_EXE_FORMAT
    }
    fn fs_ctx() -> Option<Arc<Mutex<NativeFs>>> {
        process_ctx().map(|process| Arc::clone(&process.fs))
    }

    extern "win64" fn native_get_command_line_w() -> u64 {
        process_ctx()
            .map(|process| process.command_line_w.as_ptr() as u64)
            .unwrap_or(0)
    }
    extern "win64" fn native_get_command_line_a() -> u64 {
        process_ctx()
            .map(|process| process.command_line_a.as_ptr() as u64)
            .unwrap_or(0)
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

    extern "win64" fn native_get_module_file_name_w(
        _module: u64,
        output: *mut u16,
        output_len: u32,
    ) -> u32 {
        if output.is_null() || output_len == 0 {
            return 0;
        }
        let capacity = output_len as usize;
        let copied = MODULE_FILE_NAME.len().min(capacity);
        unsafe { std::ptr::copy_nonoverlapping(MODULE_FILE_NAME.as_ptr(), output, copied) };
        if copied < capacity {
            unsafe { output.add(copied).write(0) };
        }
        copied as u32
    }
    extern "win64" fn native_get_module_handle_w(name: *const u16) -> u64 {
        if name.is_null() {
            process_ctx().map(|process| process.image_base).unwrap_or(0)
        } else {
            wide(name)
                .filter(|name| native_module_name_supported(name))
                .map(|_| API_SET_MODULE)
                .unwrap_or_else(|| { native_set_last_error(126); 0 })
        }
    }
    fn native_module_name_supported(name: &str) -> bool {
        let module = name.rsplit(['\\', '/']).next().unwrap_or(name).to_ascii_lowercase();
        matches!(module.as_str(),
            "kernel32" | "kernel32.dll" | "kernelbase" | "kernelbase.dll" |
            "ntdll" | "ntdll.dll" | "advapi32" | "advapi32.dll" |
            "bcryptprimitives" | "bcryptprimitives.dll" | "userenv" | "userenv.dll" |
            "winmm" | "winmm.dll" | "ws2_32" | "ws2_32.dll"
        )
    }
    extern "win64" fn native_get_module_handle_ex_w(
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

    extern "win64" fn native_get_environment_strings_w() -> *const u16 {
        process_ctx()
            .map(|process| process.environment_block.as_ptr())
            .unwrap_or(EMPTY_ENVIRONMENT_BLOCK.as_ptr())
    }

    extern "win64" fn native_free_environment_strings_w(block: *const u16) -> i32 {
        process_ctx()
            .map(|process| (block == process.environment_block.as_ptr()) as i32)
            .unwrap_or((block == EMPTY_ENVIRONMENT_BLOCK.as_ptr()) as i32)
    }

    extern "win64" fn native_set_unhandled_exception_filter(filter: u64) -> u64 {
        process_ctx()
            .map(|process| {
                process
                    .unhandled_exception_filter
                    .swap(filter, Ordering::AcqRel)
            })
            .unwrap_or(0)
    }

    extern "win64" fn native_add_vectored_exception_handler(_first: u32, handler: u64) -> u64 {
        if handler == 0 {
            return 0;
        }
        if let Some(process) = process_ctx() {
            process
                .vectored_exception_handler
                .store(handler, Ordering::Release);
        }
        handler | 1
    }

    extern "win64" fn native_set_thread_stack_guarantee(size: *mut u32) -> i32 {
        (!size.is_null()) as i32
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
        PROCESS_HEAP_HANDLE
    }
    extern "win64" fn native_get_current_thread_id() -> u32 {
        1
    }
    extern "win64" fn native_get_current_process_id() -> u32 {
        process_ctx()
            .map(|process| {
                debug_assert!(process.parent_process_id <= process.process_id);
                process.process_id
            })
            .unwrap_or(0)
    }
    extern "win64" fn native_get_current_process() -> u64 {
        process_ctx()
            .map(|process| process.process_handle)
            .unwrap_or(u64::MAX)
    }

    fn child_process(
        process: &NativeProcessContext,
        handle: u64,
    ) -> Option<Arc<NativeChildProcess>> {
        let table = process.children.lock().ok()?;
        table
            .children
            .get(&handle)
            .or_else(|| table.primary_threads.get(&handle))
            .cloned()
    }

    extern "win64" fn native_get_exit_code_process(handle: u64, code: *mut u32) -> i32 {
        if code.is_null() {
            native_set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        let Some(process) = process_ctx() else {
            native_set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        };
        if handle == process.process_handle {
            let exit_code = if process.exited.load(Ordering::Acquire) {
                process.exit_status.load(Ordering::Acquire)
            } else {
                259 // STILL_ACTIVE
            };
            unsafe { code.write(exit_code) };
            return 1;
        }
        let Some(child) = child_process(&process, handle) else {
            native_set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        };
        let exit_code = child
            .state
            .lock()
            .ok()
            .and_then(|state| *state)
            .unwrap_or(259);
        unsafe { code.write(exit_code) };
        1
    }
    extern "win64" fn native_terminate_process(handle: u64, code: u32) -> i32 {
        let Some(process) = process_ctx() else {
            native_set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        };
        if handle == process.process_handle {
            process.exit_status.store(code, Ordering::Release);
            process.exited.store(true, Ordering::Release);
            native_exit_process(code)
        }
        let Some(child) = child_process(&process, handle) else {
            native_set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        };
        let host_pid = child.host_pid.load(Ordering::Acquire);
        if host_pid > 0 {
            // SIGTERM is the contained host-side equivalent of terminating a
            // guest child. The monitor remains responsible for reaping it and
            // publishing completion to WaitForSingleObject/GetExitCodeProcess.
            if let Ok(mut termination_code) = child.termination_code.lock() {
                *termination_code = Some(code);
            } else {
                native_set_last_error(6);
                return 0;
            }
            if unsafe { kill(host_pid, 15) } == 0 {
                return 1;
            }
            native_set_last_error(6);
            return 0;
        }
        let Ok(mut state) = child.state.lock() else {
            native_set_last_error(6);
            return 0;
        };
        if state.is_none() {
            *state = Some(code);
            child.exited.notify_all();
        }
        1
    }
    extern "win64" fn native_get_current_thread() -> u64 {
        u64::MAX - 1
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
    extern "win64" fn native_query_performance_frequency(out: *mut i64) -> i32 {
        if out.is_null() {
            return 0;
        }
        unsafe { out.write_unaligned(1_000_000_000) };
        1
    }
    extern "win64" fn native_sleep(milliseconds: u32) {
        std::thread::sleep(std::time::Duration::from_millis(milliseconds as u64));
    }
    extern "win64" fn native_time_get_time() -> u32 {
        let mut time = NativeTimespec { seconds: 0, nanoseconds: 0 };
        if unsafe { clock_gettime(1, &mut time) } != 0 { // CLOCK_MONOTONIC
            return 0;
        }
        (time.seconds as u64 * 1000 + time.nanoseconds as u64 / 1_000_000) as u32
    }
    #[repr(C)]
    struct NativeMemoryStatus {
        length: u32,
        load: u32,
        total_physical: u64,
        available_physical: u64,
        total_page_file: u64,
        available_page_file: u64,
        total_virtual: u64,
        available_virtual: u64,
        available_extended_virtual: u64,
    }
    extern "win64" fn native_global_memory_status_ex(status: *mut NativeMemoryStatus) -> i32 {
        if status.is_null() {
            native_set_last_error(998); // ERROR_NOACCESS
            return 0;
        }
        if unsafe { std::ptr::addr_of!((*status).length).read_unaligned() } != 64 {
            native_set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        // Keep the reported budget consistent with the guest's finite WinFS
        // process model rather than exposing an arbitrary host memory size.
        let budget = 512 * 1024 * 1024u64;
        let available = budget / 2;
        let value = NativeMemoryStatus {
            length: 64,
            load: 50,
            total_physical: budget,
            available_physical: available,
            total_page_file: budget,
            available_page_file: available,
            total_virtual: budget,
            available_virtual: available,
            available_extended_virtual: 0,
        };
        unsafe { status.write_unaligned(value) };
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
    extern "win64" fn native_initialize_critical_section_and_spin_count(
        section: *mut u8,
        spin_count: u32,
    ) -> i32 {
        native_initialize_critical_section_ex(section, spin_count, 0)
    }
    extern "win64" fn native_initialize_critical_section(section: *mut u8) {
        let _ = native_initialize_critical_section_ex(section, 0, 0);
    }
    extern "win64" fn native_initialize_srw_lock(lock: *mut u64) {
        if !lock.is_null() {
            unsafe { lock.write_unaligned(0) };
        }
    }
    // The guard fields are held for their lock lifetime and released by Drop.
    #[allow(dead_code)]
    enum HeldSrwLock {
        Shared(std::sync::RwLockReadGuard<'static, ()>),
        Exclusive(std::sync::RwLockWriteGuard<'static, ()>),
    }
    thread_local! {
        static HELD_SRW_LOCKS: std::cell::RefCell<Vec<(usize, HeldSrwLock)>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }
    fn native_srw_lock(lock: *mut u64) -> Option<&'static std::sync::RwLock<()>> {
        if lock.is_null() || (lock as usize) % std::mem::align_of::<AtomicU64>() != 0 {
            return None;
        }
        let slot = unsafe { &*(lock as *const AtomicU64) };
        let mut value = slot.load(Ordering::Acquire);
        if value == 0 {
            let created = Box::into_raw(Box::new(std::sync::RwLock::new(()))) as u64;
            match slot.compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => value = created,
                Err(existing) => {
                    unsafe { drop(Box::from_raw(created as *mut std::sync::RwLock<()>)) };
                    value = existing;
                }
            }
        }
        (value != 0).then(|| unsafe { &*(value as *const std::sync::RwLock<()>) })
    }
    extern "win64" fn native_acquire_srw_lock_exclusive(lock: *mut u64) {
        if let Some(host) = native_srw_lock(lock) {
            let guard = host.write().unwrap_or_else(|poison| poison.into_inner());
            HELD_SRW_LOCKS.with(|held| held.borrow_mut().push((lock as usize, HeldSrwLock::Exclusive(guard))));
        }
    }
    extern "win64" fn native_acquire_srw_lock_shared(lock: *mut u64) {
        if let Some(host) = native_srw_lock(lock) {
            let guard = host.read().unwrap_or_else(|poison| poison.into_inner());
            HELD_SRW_LOCKS.with(|held| held.borrow_mut().push((lock as usize, HeldSrwLock::Shared(guard))));
        }
    }
    extern "win64" fn native_try_acquire_srw_lock_exclusive(lock: *mut u64) -> i32 {
        let Some(host) = native_srw_lock(lock) else { return 0 };
        let Ok(guard) = host.try_write() else { return 0 };
        HELD_SRW_LOCKS.with(|held| held.borrow_mut().push((lock as usize, HeldSrwLock::Exclusive(guard))));
        1
    }
    extern "win64" fn native_try_acquire_srw_lock_shared(lock: *mut u64) -> i32 {
        let Some(host) = native_srw_lock(lock) else { return 0 };
        let Ok(guard) = host.try_read() else { return 0 };
        HELD_SRW_LOCKS.with(|held| held.borrow_mut().push((lock as usize, HeldSrwLock::Shared(guard))));
        1
    }
    fn take_srw_lock(lock: *mut u64, exclusive: bool) -> Option<HeldSrwLock> {
        HELD_SRW_LOCKS.with(|held| {
            let mut held = held.borrow_mut();
            held.iter().rposition(|(address, guard)| {
                *address == lock as usize && matches!((exclusive, guard), (true, HeldSrwLock::Exclusive(_)) | (false, HeldSrwLock::Shared(_)))
            }).map(|index| held.remove(index).1)
        })
    }
    fn native_release_srw_lock(lock: *mut u64, exclusive: bool) {
        drop(take_srw_lock(lock, exclusive));
    }
    extern "win64" fn native_release_srw_lock_exclusive(lock: *mut u64) {
        native_release_srw_lock(lock, true);
    }
    extern "win64" fn native_release_srw_lock_shared(lock: *mut u64) {
        native_release_srw_lock(lock, false);
    }
    struct NativeConditionVariable {
        generation: Mutex<u64>,
        ready: Condvar,
    }
    struct NativeInitOnce {
        state: Mutex<InitOnceState>,
        ready: Condvar,
    }
    enum InitOnceState {
        Uninitialized,
        Running,
        Complete(u64),
    }
    fn native_init_once(ptr: *mut u64) -> Option<&'static NativeInitOnce> {
        if ptr.is_null() || (ptr as usize) % std::mem::align_of::<AtomicU64>() != 0 {
            return None;
        }
        let slot = unsafe { &*(ptr as *const AtomicU64) };
        let mut value = slot.load(Ordering::Acquire);
        if value == 0 {
            let created = Box::into_raw(Box::new(NativeInitOnce {
                state: Mutex::new(InitOnceState::Uninitialized), ready: Condvar::new(),
            })) as u64;
            match slot.compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => value = created,
                Err(existing) => {
                    unsafe { drop(Box::from_raw(created as *mut NativeInitOnce)) };
                    value = existing;
                }
            }
        }
        (value != 0).then(|| unsafe { &*(value as *const NativeInitOnce) })
    }
    extern "win64" fn native_init_once_initialize(ptr: *mut u64) {
        if !ptr.is_null() {
            unsafe { ptr.write_unaligned(0) };
        }
    }
    extern "win64" fn native_init_once_execute_once(
        once: *mut u64,
        callback: u64,
        parameter: u64,
        context_out: *mut u64,
    ) -> i32 {
        if callback == 0 {
            native_set_last_error(87);
            return 0;
        }
        let Some(init) = native_init_once(once) else { native_set_last_error(87); return 0 };
        loop {
            let Ok(mut state) = init.state.lock() else { return 0 };
            match *state {
                InitOnceState::Complete(context) => {
                    if !context_out.is_null() { unsafe { context_out.write_unaligned(context) }; }
                    return 1;
                }
                InitOnceState::Running => {
                    drop(init.ready.wait(state));
                }
                InitOnceState::Uninitialized => {
                    *state = InitOnceState::Running;
                    drop(state);
                    let mut context = 0u64;
                    let callback: unsafe extern "win64" fn(*mut u64, u64, *mut u64) -> i32 = unsafe { std::mem::transmute(callback) };
                    let success = unsafe { callback(once, parameter, &mut context) } != 0;
                    let Ok(mut state) = init.state.lock() else { return 0 };
                    *state = if success { InitOnceState::Complete(context) } else { InitOnceState::Uninitialized };
                    init.ready.notify_all();
                    if success && !context_out.is_null() { unsafe { context_out.write_unaligned(context) }; }
                    return success as i32;
                }
            }
        }
    }
    fn native_condition_variable(ptr: *mut u64) -> Option<&'static NativeConditionVariable> {
        if ptr.is_null() || (ptr as usize) % std::mem::align_of::<AtomicU64>() != 0 {
            return None;
        }
        let slot = unsafe { &*(ptr as *const AtomicU64) };
        let mut value = slot.load(Ordering::Acquire);
        if value == 0 {
            let created = Box::into_raw(Box::new(NativeConditionVariable {
                generation: Mutex::new(0), ready: Condvar::new(),
            })) as u64;
            match slot.compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => value = created,
                Err(existing) => {
                    unsafe { drop(Box::from_raw(created as *mut NativeConditionVariable)) };
                    value = existing;
                }
            }
        }
        (value != 0).then(|| unsafe { &*(value as *const NativeConditionVariable) })
    }
    extern "win64" fn native_initialize_condition_variable(ptr: *mut u64) {
        if !ptr.is_null() {
            unsafe { ptr.write_unaligned(0) };
        }
    }
    extern "win64" fn native_wake_condition_variable(ptr: *mut u64) {
        if let Some(cv) = native_condition_variable(ptr) {
            if let Ok(mut generation) = cv.generation.lock() {
                *generation = generation.wrapping_add(1);
                cv.ready.notify_one();
            }
        }
    }
    extern "win64" fn native_wake_all_condition_variable(ptr: *mut u64) {
        if let Some(cv) = native_condition_variable(ptr) {
            if let Ok(mut generation) = cv.generation.lock() {
                *generation = generation.wrapping_add(1);
                cv.ready.notify_all();
            }
        }
    }
    extern "win64" fn native_sleep_condition_variable_srw(
        condition: *mut u64,
        lock: *mut u64,
        milliseconds: u32,
        flags: u32,
    ) -> i32 {
        if flags & !1 != 0 {
            native_set_last_error(87);
            return 0;
        }
        let shared = flags & 1 != 0;
        let Some(cv) = native_condition_variable(condition) else { native_set_last_error(87); return 0 };
        let Ok(generation) = cv.generation.lock() else { return 0 };
        let before = *generation;
        let Some(guard) = take_srw_lock(lock, !shared) else { native_set_last_error(87); return 0 };
        drop(guard);
        let awakened = if milliseconds == u32::MAX {
            cv.ready.wait_while(generation, |value| *value == before).is_ok()
        } else {
            cv.ready.wait_timeout_while(generation, std::time::Duration::from_millis(milliseconds as u64), |value| *value == before)
                .map(|(value, _)| *value != before).unwrap_or(false)
        };
        if shared { native_acquire_srw_lock_shared(lock); } else { native_acquire_srw_lock_exclusive(lock); }
        if awakened { 1 } else { native_set_last_error(1460); 0 }
    }
    extern "win64" fn native_tls_alloc() -> u32 {
        let Some(process) = process_ctx() else { return u32::MAX };
        let Ok(mut slots) = process.dynamic_tls.lock() else { return u32::MAX };
        let Some(index) = slots.active.iter().position(|active| !active) else {
            native_set_last_error(8);
            return u32::MAX;
        };
        slots.active[index] = true;
        slots.generation[index] = slots.generation[index].wrapping_add(1);
        index as u32
    }
    extern "win64" fn native_tls_free(index: u32) -> i32 {
        let Some(process) = process_ctx() else { return 0 };
        let Ok(mut slots) = process.dynamic_tls.lock() else { return 0 };
        let reserved = index == 0 && slots.reserved_static;
        let Some(active) = slots.active.get_mut(index as usize) else {
            native_set_last_error(87);
            return 0;
        };
        if !*active || reserved {
            native_set_last_error(87);
            return 0;
        }
        *active = false;
        slots.generation[index as usize] = slots.generation[index as usize].wrapping_add(1);
        1
    }
    extern "win64" fn native_tls_get_value(index: u32) -> u64 {
        let Some(process) = process_ctx() else { return 0 };
        let Ok(slots) = process.dynamic_tls.lock() else { return 0 };
        if !slots.active.get(index as usize).copied().unwrap_or(false) {
            native_set_last_error(87);
            return 0;
        }
        let generation = slots.generation[index as usize];
        let value = THREAD_TLS_VALUES.with(|values| {
            let (slot_generation, value) = values.borrow()[index as usize];
            if slot_generation == generation { value } else { 0 }
        });
        native_set_last_error(0);
        value
    }
    extern "win64" fn native_tls_set_value(index: u32, value: u64) -> i32 {
        let Some(process) = process_ctx() else { return 0 };
        let Ok(slots) = process.dynamic_tls.lock() else { return 0 };
        if !slots.active.get(index as usize).copied().unwrap_or(false) {
            native_set_last_error(87);
            return 0;
        }
        let generation = slots.generation[index as usize];
        THREAD_TLS_VALUES.with(|values| values.borrow_mut()[index as usize] = (generation, value));
        native_set_last_error(0);
        1
    }
    extern "win64" fn native_encode_pointer(value: u64) -> u64 {
        let cookie = process_ctx().map(|process| process.pointer_cookie).unwrap_or(1);
        value.rotate_left(17) ^ cookie
    }
    extern "win64" fn native_decode_pointer(value: u64) -> u64 {
        let cookie = process_ctx().map(|process| process.pointer_cookie).unwrap_or(1);
        (value ^ cookie).rotate_right(17)
    }
    extern "win64" fn native_is_processor_feature_present(feature: u32) -> i32 {
        let present = match feature {
            2 | 3 | 6 | 8 | 9 | 10 | 12 => true,
            13 => std::is_x86_feature_detected!("sse3"),
            17 => std::is_x86_feature_detected!("xsave"),
            36 => std::is_x86_feature_detected!("ssse3"),
            37 => std::is_x86_feature_detected!("sse4.1"),
            38 => std::is_x86_feature_detected!("sse4.2"),
            39 => std::is_x86_feature_detected!("avx"),
            40 => std::is_x86_feature_detected!("avx2"),
            41 => std::is_x86_feature_detected!("avx512f"),
            60 => std::is_x86_feature_detected!("bmi2"),
            _ => false,
        };
        present as i32
    }
    extern "win64" fn native_rtl_get_version(info: *mut u8) -> u32 {
        if info.is_null() || unsafe { (info as *const u32).read_unaligned() } < 276 {
            return 0xC000_000D; // STATUS_INVALID_PARAMETER
        }
        unsafe {
            (info.add(4) as *mut u32).write_unaligned(10);
            (info.add(8) as *mut u32).write_unaligned(0);
            (info.add(12) as *mut u32).write_unaligned(19045);
            (info.add(16) as *mut u32).write_unaligned(2); // VER_PLATFORM_WIN32_NT
            std::ptr::write_bytes(info.add(20), 0, 256);
        }
        0
    }
    extern "win64" fn native_rtl_nt_status_to_dos_error(status: u32) -> u32 {
        match status {
            0 => 0,
            0xC000_0005 => 998, // STATUS_ACCESS_VIOLATION
            0xC000_0008 => 6,   // STATUS_INVALID_HANDLE
            0xC000_000D => 87,  // STATUS_INVALID_PARAMETER
            0xC000_0017 => 8,   // STATUS_NO_MEMORY
            0xC000_0022 => 5,   // STATUS_ACCESS_DENIED
            0xC000_0034 => 2,   // STATUS_OBJECT_NAME_NOT_FOUND
            _ => 317,           // ERROR_MR_MID_NOT_FOUND
        }
    }
    extern "win64" fn native_fls_alloc(_callback: u64) -> u32 {
        0
    }
    extern "win64" fn native_fls_free(index: u32) -> i32 {
        if index != 0 {
            return 0;
        }
        if let Some(process) = process_ctx() {
            process.fls_value.store(0, Ordering::Release);
        }
        1
    }
    extern "win64" fn native_fls_get_value(index: u32) -> u64 {
        if index == 0 {
            process_ctx()
                .map(|process| process.fls_value.load(Ordering::Acquire))
                .unwrap_or(0)
        } else {
            0
        }
    }
    extern "win64" fn native_fls_set_value(index: u32, value: u64) -> i32 {
        if index != 0 {
            return 0;
        }
        if let Some(process) = process_ctx() {
            process.fls_value.store(value, Ordering::Release);
        } else {
            return 0;
        }
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
    extern "win64" fn native_heap_alloc(heap: u64, flags: u32, size: usize) -> u64 {
        if heap != PROCESS_HEAP_HANDLE {
            native_set_last_error(6);
            return 0;
        }
        let ptr = unsafe { malloc(size.max(1)) } as u64;
        if ptr == 0 {
            native_set_last_error(8);
            return 0;
        }
        if flags & 0x8 != 0 {
            unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, size) };
        }
        let Some(process) = process_ctx() else { unsafe { free(ptr as *mut c_void) }; return 0 };
        let Ok(mut allocations) = process.heap_allocations.lock() else { unsafe { free(ptr as *mut c_void) }; return 0 };
        allocations.insert(ptr, size);
        ptr
    }
    extern "win64" fn native_heap_realloc(heap: u64, flags: u32, ptr: u64, size: usize) -> u64 {
        if heap != PROCESS_HEAP_HANDLE || ptr == 0 {
            native_set_last_error(87);
            return 0;
        }
        let Some(process) = process_ctx() else { return 0 };
        let Ok(mut allocations) = process.heap_allocations.lock() else { return 0 };
        let Some(old_size) = allocations.get(&ptr).copied() else {
            native_set_last_error(87);
            return 0;
        };
        let new_ptr = unsafe { realloc(ptr as *mut c_void, size.max(1)) } as u64;
        if new_ptr == 0 {
            native_set_last_error(8);
            return 0;
        }
        if flags & 0x8 != 0 && size > old_size {
            unsafe { std::ptr::write_bytes((new_ptr as *mut u8).add(old_size), 0, size - old_size) };
        }
        allocations.remove(&ptr);
        allocations.insert(new_ptr, size);
        new_ptr
    }
    extern "win64" fn native_heap_size(heap: u64, _flags: u32, ptr: u64) -> usize {
        if heap != PROCESS_HEAP_HANDLE || ptr == 0 {
            native_set_last_error(87);
            return usize::MAX;
        }
        let size = process_ctx()
            .and_then(|process| process.heap_allocations.lock().ok().and_then(|allocations| allocations.get(&ptr).copied()));
        match size {
            Some(size) => size,
            None => {
                native_set_last_error(87);
                usize::MAX
            }
        }
    }
    extern "win64" fn native_process_prng(out: *mut u8, len: usize) -> i32 {
        if out.is_null() && len != 0 {
            return 0;
        }
        (unsafe { getrandom(out.cast(), len, 0) } == len as isize) as i32
    }
    extern "win64" fn native_get_console_mode(handle: u64, mode: *mut u32) -> i32 {
        if !matches!(handle, 0..=2) || mode.is_null() {
            return 0;
        }
        // ENABLE_PROCESSED_OUTPUT. The native child exposes only its three
        // standard descriptors as consoles.
        unsafe { mode.write(1) };
        1
    }
    extern "win64" fn native_get_console_output_cp() -> u32 {
        native_get_acp()
    }
    extern "win64" fn native_get_console_screen_buffer_info(handle: u64, output: *mut u8) -> i32 {
        if !matches!(handle, 0..=2) || output.is_null() {
            return 0;
        }
        unsafe {
            std::ptr::write_bytes(output, 0, 22);
            (output as *mut i16).write_unaligned(80);
            (output.add(2) as *mut i16).write_unaligned(25);
            (output.add(8) as *mut u16).write_unaligned(7);
            (output.add(14) as *mut i16).write_unaligned(79);
            (output.add(16) as *mut i16).write_unaligned(24);
            (output.add(18) as *mut i16).write_unaligned(80);
            (output.add(20) as *mut i16).write_unaligned(25);
        }
        1
    }
    extern "win64" fn native_set_console_mode(handle: u64, _mode: u32) -> i32 {
        matches!(handle, 0..=2) as i32
    }
    extern "win64" fn native_format_message_w(
        _flags: u32,
        _source: u64,
        _message_id: u32,
        _language: u32,
        output: *mut u16,
        output_len: u32,
        _arguments: u64,
    ) -> u32 {
        const MESSAGE: &[u16] = &[
            b'W' as u16,
            b'i' as u16,
            b'n' as u16,
            b'C' as u16,
            b'L' as u16,
            b'I' as u16,
            b' ' as u16,
            b'n' as u16,
            b'a' as u16,
            b't' as u16,
            b'i' as u16,
            b'v' as u16,
            b'e' as u16,
            b' ' as u16,
            b'e' as u16,
            b'r' as u16,
            b'r' as u16,
            b'o' as u16,
            b'r' as u16,
            b'.' as u16,
            b'\r' as u16,
            b'\n' as u16,
        ];
        if output.is_null() || output_len <= MESSAGE.len() as u32 {
            return 0;
        }
        unsafe {
            output.copy_from_nonoverlapping(MESSAGE.as_ptr(), MESSAGE.len());
            output.add(MESSAGE.len()).write(0)
        };
        MESSAGE.len() as u32
    }
    extern "win64" fn native_format_message_a(
        flags: u32,
        _source: u64,
        _message_id: u32,
        _language: u32,
        output: *mut u8,
        output_len: u32,
        _arguments: u64,
    ) -> u32 {
        const MESSAGE: &[u8] = b"WinCLI native error.\r\n";
        if flags & 0x100 != 0 || output.is_null() || output_len <= MESSAGE.len() as u32 {
            native_set_last_error(122);
            return 0;
        }
        unsafe {
            output.copy_from_nonoverlapping(MESSAGE.as_ptr(), MESSAGE.len());
            output.add(MESSAGE.len()).write(0);
        }
        MESSAGE.len() as u32
    }
    extern "win64" fn native_get_environment_variable_w(
        name: *const u16,
        output: *mut u16,
        output_len: u32,
    ) -> u32 {
        if name.is_null() {
            native_set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        let Some(name) = wide(name) else {
            native_set_last_error(87);
            return 0;
        };
        let Some(value) = process_ctx().and_then(|process| {
            process
                .environment
                .iter()
                .find_map(|(key, value)| key.eq_ignore_ascii_case(&name).then(|| value.clone()))
        }) else {
            native_set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
            return 0;
        };
        let value: Vec<u16> = value.encode_utf16().collect();
        let required = value.len() + 1;
        if output.is_null() || output_len == 0 {
            return required as u32;
        }
        if (output_len as usize) < required {
            return required as u32;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len());
            output.add(value.len()).write(0);
        }
        value.len() as u32
    }
    extern "win64" fn native_get_current_directory_w(output_len: u32, output: *mut u16) -> u32 {
        let cwd = fs_ctx()
            .and_then(|context| context.lock().ok().map(|ctx| ctx.fs.cwd()))
            .unwrap_or_else(|| "C:\\".to_string());
        let encoded: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();
        if output.is_null() || output_len < encoded.len() as u32 {
            return encoded.len() as u32;
        }
        unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
        (encoded.len() - 1) as u32
    }
    extern "win64" fn native_get_computer_name_ex_w(
        _name_type: u32,
        output: *mut u16,
        len: *mut u32,
    ) -> i32 {
        const NAME: [u16; 7] = [
            'w' as u16, 'i' as u16, 'n' as u16, 'c' as u16, 'l' as u16, 'i' as u16, 0,
        ];
        if len.is_null() {
            return 0;
        }
        let capacity = unsafe { len.read() };
        if output.is_null() || capacity < NAME.len() as u32 {
            unsafe { len.write(NAME.len() as u32) };
            native_set_last_error(234);
            return 0;
        }
        unsafe {
            output.copy_from_nonoverlapping(NAME.as_ptr(), NAME.len());
            len.write((NAME.len() - 1) as u32)
        };
        1
    }
    extern "win64" fn native_get_system_info(output: *mut u8) {
        if output.is_null() {
            return;
        }
        unsafe {
            std::ptr::write_bytes(output, 0, 48);
            (output as *mut u16).write_unaligned(9);
            (output.add(4) as *mut u32).write_unaligned(4096);
            (output.add(8) as *mut u64).write_unaligned(0x1_0000);
            (output.add(16) as *mut u64).write_unaligned(0x7fff_ffff_ffff);
            (output.add(24) as *mut u64).write_unaligned(1);
            (output.add(32) as *mut u32).write_unaligned(8664);
            (output.add(36) as *mut u32).write_unaligned(65_536);
        }
    }
    extern "win64" fn native_get_full_path_name_w(
        input: *const u16,
        output_len: u32,
        output: *mut u16,
        _part: *mut *mut u16,
    ) -> u32 {
        let Some(raw) = wide(input) else {
            return 0;
        };
        let path = fs_ctx()
            .and_then(|context| {
                context
                    .lock()
                    .ok()
                    .and_then(|ctx| ctx.fs.normalize(&raw).ok().map(|path| path.display()))
            })
            .unwrap_or_else(|| {
                if raw == "." || raw.is_empty() {
                    "C:\\".to_string()
                } else if raw.len() >= 2 && raw.as_bytes()[1] == b':' {
                    raw.replace('/', "\\")
                } else {
                    format!("C:\\{}", raw.replace('/', "\\"))
                }
            });
        let encoded: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        if output.is_null() || output_len < encoded.len() as u32 {
            return encoded.len() as u32;
        }
        unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
        (encoded.len() - 1) as u32
    }
    fn native_find_directory(pattern: &str) -> String {
        let path = pattern
            .strip_prefix(r"\\?\")
            .unwrap_or(pattern)
            .replace('/', "\\");
        path.strip_suffix("\\*")
            .unwrap_or(&path)
            .trim_end_matches('\\')
            .to_string()
    }
    fn native_write_find_data(output: *mut u8, name: &str) -> bool {
        let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        if output.is_null() || name.len() > 260 {
            return false;
        }
        unsafe {
            std::ptr::write_bytes(output, 0, 592);
            output
                .add(44)
                .cast::<u16>()
                .copy_from_nonoverlapping(name.as_ptr(), name.len());
        }
        true
    }
    extern "win64" fn native_find_first_file_ex_w(
        pattern: *const u16,
        _info_level: u32,
        output: *mut u8,
        _search_op: u32,
        _filter: u64,
        _flags: u32,
    ) -> u64 {
        let pattern = match wide(pattern) {
            Some(value) => value,
            None => return u64::MAX,
        };
        let context = match fs_ctx() {
            Some(value) => value,
            None => return u64::MAX,
        };
        let mut ctx = match context.lock() {
            Ok(value) => value,
            Err(_) => return u64::MAX,
        };
        let names = match ctx.fs.list_dir(&native_find_directory(&pattern)) {
            Ok(value) => value,
            Err(_) => {
                native_set_last_error(3);
                return u64::MAX;
            }
        };
        let Some(first) = names.first() else {
            native_set_last_error(2);
            return u64::MAX;
        };
        if !native_write_find_data(output, first) {
            native_set_last_error(87);
            return u64::MAX;
        }
        let handle = ctx.next;
        ctx.next += 1;
        ctx.finds.insert(handle, NativeFind { names, index: 0 });
        handle
    }
    extern "win64" fn native_find_next_file_w(handle: u64, output: *mut u8) -> i32 {
        let context = match fs_ctx() {
            Some(value) => value,
            None => return 0,
        };
        let mut ctx = match context.lock() {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let find = match ctx.finds.get_mut(&handle) {
            Some(value) => value,
            None => return 0,
        };
        find.index += 1;
        let Some(name) = find.names.get(find.index) else {
            native_set_last_error(18);
            return 0;
        };
        native_write_find_data(output, name) as i32
    }
    extern "win64" fn native_find_close(handle: u64) -> i32 {
        fs_ctx()
            .and_then(|context| {
                context
                    .lock()
                    .ok()
                    .map(|mut ctx| ctx.finds.remove(&handle).is_some())
            })
            .unwrap_or(false) as i32
    }
    extern "win64" fn native_get_user_profile_directory_w(
        _token: u64,
        output: *mut u16,
        len: *mut u32,
    ) -> i32 {
        const PROFILE: &[u16] = &[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            b'U' as u16,
            b's' as u16,
            b'e' as u16,
            b'r' as u16,
            b's' as u16,
            b'\\' as u16,
            b'w' as u16,
            b'i' as u16,
            b'n' as u16,
            b'c' as u16,
            b'l' as u16,
            b'i' as u16,
            0,
        ];
        if len.is_null() {
            return 0;
        }
        if output.is_null() || unsafe { len.read() } < PROFILE.len() as u32 {
            unsafe { len.write(PROFILE.len() as u32) };
            native_set_last_error(122);
            return 0;
        }
        unsafe {
            output.copy_from_nonoverlapping(PROFILE.as_ptr(), PROFILE.len());
            len.write((PROFILE.len() - 1) as u32)
        };
        1
    }
    extern "win64" fn native_set_file_time(
        handle: u64,
        _creation: *const u64,
        _access: *const u64,
        _write: *const u64,
    ) -> i32 {
        matches!(handle, 0..=2) as i32
    }
    extern "win64" fn native_heap_free(heap: u64, _flags: u32, ptr: u64) -> i32 {
        if heap != PROCESS_HEAP_HANDLE || ptr == 0 {
            native_set_last_error(87);
            return 0;
        }
        let Some(process) = process_ctx() else { return 0 };
        let Ok(mut allocations) = process.heap_allocations.lock() else { return 0 };
        if allocations.remove(&ptr).is_none() {
            native_set_last_error(87);
            return 0;
        }
        unsafe { free(ptr as *mut c_void) };
        1
    }
    extern "win64" fn native_enter_critical_section(_section: *mut u8) {}
    extern "win64" fn native_leave_critical_section(_section: *mut u8) {}
    extern "win64" fn native_delete_critical_section(_section: *mut u8) {}

    extern "win64" fn native_initialize_slist_head(head: *mut u8) {
        if !head.is_null() {
            // SLIST_HEADER occupies 16 bytes on 64-bit Windows.
            unsafe { std::ptr::write_bytes(head, 0, 16) };
        }
    }

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
            let context = match fs_ctx() {
                Some(v) => v,
                None => return 0,
            };
            let mut ctx = match context.lock() {
                Ok(value) => value,
                Err(_) => return 0,
            };
            let (path, offset) = match ctx.handles.get(&handle) {
                Some(v) => (v.path.clone(), v.offset),
                None => return 0,
            };
            let data = unsafe { std::slice::from_raw_parts(buf, len as usize) };
            let mut content = match ctx.fs.read_file(&path) {
                Ok(v) => v,
                Err(_) => return 0,
            };
            let end = match offset.checked_add(data.len()) {
                Some(v) => v,
                None => return 0,
            };
            if content.len() < end {
                content.resize(end, 0);
            }
            content[offset..end].copy_from_slice(data);
            if ctx.fs.write_file(&path, content).is_err() {
                return 0;
            }
            if let Some(file) = ctx.handles.get_mut(&handle) {
                file.offset = end;
            }
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

    extern "win64" fn native_write_console_w(
        handle: u64,
        text: *const u16,
        len: u32,
        written: *mut u32,
        _reserved: u64,
    ) -> i32 {
        if !matches!(handle, 1 | 2) || (text.is_null() && len != 0) {
            return 0;
        }
        let units = if len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(text, len as usize) }
        };
        let encoded = String::from_utf16_lossy(units);
        if unsafe { write(handle as i32, encoded.as_ptr().cast(), encoded.len()) } < 0 {
            return 0;
        }
        if !written.is_null() {
            unsafe { written.write(len) };
        }
        1
    }

    extern "win64" fn native_exit_process(code: u32) -> ! {
        // Closing stdout lets the parent drain console output before the
        // snapshot pipe can block on a large guest disk image.
        unsafe { close(1) };
        native_flush_instance_state();
        // SAFETY: this runs only in the forked guest child.
        unsafe { _exit(code as i32) }
    }
    extern "win64" fn native_create_process_w(
        application: *const u16,
        command_line: *mut u16,
        _process_attributes: u64,
        _thread_attributes: u64,
        _inherit_handles: i32,
        _creation_flags: u32,
        environment: u64,
        current_directory: *const u16,
        _startup_info: u64,
        process_information: u64,
    ) -> i32 {
        if process_information == 0 {
            native_set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        let Some(context) = fs_ctx() else {
            native_set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        };
        let Ok(fs) = context.lock() else {
            native_set_last_error(6);
            return 0;
        };
        let has_application = !application.is_null();
        let has_command_line = !command_line.is_null();
        let has_current_directory = !current_directory.is_null();
        let application = has_application.then(|| wide(application)).flatten();
        let command_line = has_command_line
            .then(|| wide(command_line.cast_const()))
            .flatten();
        let current_directory = has_current_directory
            .then(|| wide(current_directory))
            .flatten();
        if (has_application && application.is_none())
            || (has_command_line && command_line.is_none())
            || (has_current_directory && current_directory.is_none())
        {
            native_set_last_error(87);
            return 0;
        }
        let launch = match native_launch_spec(application, command_line, current_directory, &fs.fs)
        {
            Ok(launch) => launch,
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        };
        let explicit_environment = if environment == 0 {
            None
        } else {
            match environment_block(environment) {
                Ok(environment) => Some(environment),
                Err(error) => {
                    native_set_last_error(error);
                    return 0;
                }
            }
        };
        let image = match load_native_child_image(&fs.fs, &launch) {
            Ok(image) => image,
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        };
        drop(fs);
        let (mapping, image) = match map_relocated(&image) {
            Ok(value) => value,
            Err(_) => {
                native_set_last_error(193); // ERROR_BAD_EXE_FORMAT
                return 0;
            }
        };
        if patch_baseline_imports(&mapping, &image, false).is_err() {
            native_set_last_error(193);
            return 0;
        }
        let tls = match setup_tls(&mapping, &image) {
            Ok(value) => value,
            Err(_) => {
                native_set_last_error(193);
                return 0;
            }
        };
        let entry = match entry(&image) {
            Ok(value) => value,
            Err(_) => {
                native_set_last_error(193);
                return 0;
            }
        };
        let Some(parent) = process_ctx() else {
            native_set_last_error(6);
            return 0;
        };
        let environment = explicit_environment.unwrap_or_else(|| parent.environment.clone());
        let (process_handle, thread_handle, child) = match parent.children.lock() {
            Ok(mut children) => children.allocate(parent.process_id),
            Err(_) => {
                native_set_last_error(6);
                return 0;
            }
        };
        let mut state_fds = [-1, -1];
        if unsafe { pipe(state_fds.as_mut_ptr()) } != 0 {
            native_set_last_error(8); // ERROR_NOT_ENOUGH_MEMORY
            return 0;
        }
        let pid = unsafe { fork() };
        if pid < 0 {
            unsafe {
                close(state_fds[0]);
                close(state_fds[1]);
            }
            native_set_last_error(8);
            return 0;
        }
        if pid == 0 {
            #[cfg(test)]
            NATIVE_GUEST_ACTIVE.store(true, Ordering::Release);
            unsafe { close(state_fds[0]) };
            if let Ok(mut child_fs) = context.lock() {
                let _ = child_fs.fs.set_cwd(&launch.current_directory);
            }
            let command_line_w = command_line_w(
                &launch.application,
                launch.arguments.get(1..).unwrap_or(&[]),
            )
            .unwrap_or_else(|_| vec![0]);
            let child_context = Arc::new(NativeProcessContext {
                image_base: image.image_base,
                process_id: child.process_id,
                process_handle,
                parent_process_id: parent.process_id,
                command_line_a: command_line_a(&command_line_w),
                command_line_w,
                environment_block: environment_strings(&environment),
                environment,
                fs: Arc::clone(&context),
                last_error: AtomicU32::new(0),
                error_mode: AtomicU32::new(0),
                pointer_cookie: random_pointer_cookie(),
                heap_allocations: Mutex::new(HashMap::new()),
                gs_base: AtomicU64::new(0),
                tls_template: Mutex::new(tls.as_ref().map(NativeTls::clone_for_thread)),
                dynamic_tls: Mutex::new(DynamicTlsSlots::new(tls.is_some())),
                threads: Mutex::new(HashMap::new()),
                thread_next: AtomicU64::new(0x8000_0000),
                timer_next: AtomicU64::new(0x7000_0000),
                state_fd: AtomicU32::new(state_fds[1] as u32),
                fls_value: AtomicU64::new(0),
                unhandled_exception_filter: AtomicU64::new(0),
                vectored_exception_handler: AtomicU64::new(0),
                exit_status: AtomicU32::new(259),
                exited: AtomicBool::new(false),
                children: Mutex::new(NativeProcessTable::new()),
            });
            if let Ok(mut active) = NATIVE_PROCESS.lock() {
                *active = Some(child_context);
            }
            if protect_exec(&mapping).is_err() {
                unsafe { _exit(127) };
            }
            if let Some(tls) = tls.as_ref() {
                if !unsafe { set_gs(tls.teb.as_ptr() as u64) } {
                    unsafe { _exit(127) };
                }
            }
            let guest: unsafe extern "win64" fn() -> u32 = unsafe { std::mem::transmute(entry) };
            let code = unsafe { guest() };
            native_flush_instance_state();
            unsafe { _exit(code as i32) };
        }
        child.host_pid.store(pid, Ordering::Release);
        unsafe { close(state_fds[1]) };
        let monitor_child = Arc::clone(&child);
        let monitor_fs = Arc::clone(&context);
        if std::thread::Builder::new()
            .name("wincli-native-child".to_string())
            .spawn(move || finish_native_child(monitor_child, monitor_fs, state_fds[0], pid))
            .is_err()
        {
            unsafe { close(state_fds[0]) };
            native_set_last_error(8);
            return 0;
        }
        if !write_process_information(
            process_information,
            process_handle,
            thread_handle,
            child.process_id,
        ) {
            native_set_last_error(87);
            return 0;
        }
        native_set_last_error(0);
        1
    }

    fn native_flush_instance_state() {
        let Some(process) = process_ctx() else {
            return;
        };
        let fd = process.state_fd.load(Ordering::Acquire);
        if fd == u32::MAX {
            return;
        }
        let Some(context) = fs_ctx() else {
            return;
        };
        let Ok(ctx) = context.lock() else {
            return;
        };
        let encoded = crate::snapshot::encode(&ctx.fs);
        let mut written = 0;
        while written < encoded.len() {
            let n = unsafe {
                write(
                    fd as i32,
                    encoded[written..].as_ptr().cast(),
                    encoded.len() - written,
                )
            };
            if n <= 0 {
                break;
            }
            written += n as usize;
        }
        unsafe { close(fd as i32) };
        process.state_fd.store(u32::MAX, Ordering::Release);
    }
    extern "win64" fn native_get_last_error() -> u32 {
        process_ctx()
            .map(|process| process.last_error.load(Ordering::Acquire))
            .unwrap_or(6)
    }

    extern "win64" fn native_set_last_error(error: u32) {
        if let Some(process) = process_ctx() {
            process.last_error.store(error, Ordering::Release);
        }
    }
    extern "win64" fn native_set_error_mode(mode: u32) -> u32 {
        process_ctx()
            .map(|process| process.error_mode.swap(mode, Ordering::AcqRel))
            .unwrap_or(0)
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

    extern "win64" fn native_get_module_handle_a(name: *const u8) -> u64 {
        match unsafe { ascii_z(name) } {
            Some(value) if native_module_name_supported(value) => API_SET_MODULE,
            _ => 0,
        }
    }

    extern "win64" fn native_get_proc_address(module: u64, name: *const u8) -> u64 {
        if module != API_SET_MODULE {
            native_set_last_error(6);
            return 0;
        }
        match unsafe { ascii_z(name) } {
            Some("CompareStringEx") => native_compare_string_ex as *const () as usize as u64,
            Some("GetEnvironmentVariableW") => {
                native_get_environment_variable_w as *const () as usize as u64
            }
            Some("GetCurrentDirectoryW") => {
                native_get_current_directory_w as *const () as usize as u64
            }
            Some(function) => baseline_trampoline(function).unwrap_or_else(|| {
                if std::env::var("WINCLI_NATIVE_DIAGNOSTIC").as_deref() == Ok("1") {
                    let message = format!("unsupported native dynamic import: {function}\n");
                    unsafe { write(2, message.as_ptr().cast(), message.len()) };
                }
                native_set_last_error(127); // ERROR_PROC_NOT_FOUND
                0
            }),
            None => { native_set_last_error(127); 0 },
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
        _access: u32,
        _share: u32,
        _sec: u64,
        creation: u32,
        _flags: u32,
        _tmpl: u64,
    ) -> u64 {
        let path = match wide(path) {
            Some(v) => v.strip_prefix(r"\\?\").unwrap_or(&v).to_string(),
            None => return u64::MAX,
        };
        let context = match fs_ctx() {
            Some(v) => v,
            None => return u64::MAX,
        };
        let mut ctx = match context.lock() {
            Ok(value) => value,
            Err(_) => return u64::MAX,
        };
        let exists = ctx.fs.exists(&path);
        let ok = match creation {
            2 => ctx.fs.write_file(&path, Vec::new()),
            // OPEN_EXISTING can target either a file or a directory. The
            // caller supplies FILE_FLAG_BACKUP_SEMANTICS for directories;
            // enumeration support consumes the resulting handle next.
            3 if exists && (ctx.fs.is_file(&path) || ctx.fs.is_dir(&path)) => Ok(()),
            _ => Err("unsupported create".into()),
        };
        if ok.is_err() {
            return u64::MAX;
        }
        let h = ctx.next;
        ctx.next += 1;
        ctx.handles.insert(h, NativeFile { path, offset: 0 });
        h
    }
    fn native_file_attributes(is_directory: bool) -> u32 {
        if is_directory {
            0x10
        } else {
            0x80
        }
    }
    fn native_extended_path(path: &str) -> String {
        let path = path.trim_end_matches('.').trim_end_matches('\\');
        if path.eq_ignore_ascii_case("C:") || path.is_empty() {
            "\\\\?\\C:\\".to_string()
        } else {
            format!("\\\\?\\{}", path)
        }
    }
    extern "win64" fn native_get_final_path_name_by_handle_w(
        handle: u64,
        output: *mut u16,
        output_len: u32,
        _flags: u32,
    ) -> u32 {
        let context = match fs_ctx() {
            Some(value) => value,
            None => return 0,
        };
        let ctx = match context.lock() {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let path = match ctx.handles.get(&handle) {
            Some(value) => native_extended_path(&value.path),
            None => return 0,
        };
        let encoded: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        if output.is_null() || output_len < encoded.len() as u32 {
            return encoded.len() as u32;
        }
        unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
        (encoded.len() - 1) as u32
    }
    extern "win64" fn native_get_file_information_by_handle(handle: u64, output: *mut u8) -> i32 {
        if output.is_null() {
            return 0;
        }
        let context = match fs_ctx() {
            Some(value) => value,
            None => return 0,
        };
        let ctx = match context.lock() {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let path = match ctx.handles.get(&handle) {
            Some(value) => &value.path,
            None => return 0,
        };
        let is_directory = ctx.fs.is_dir(path);
        let size = if is_directory {
            0
        } else {
            ctx.fs
                .read_file(path)
                .map(|data| data.len() as u64)
                .unwrap_or(0)
        };
        let file_id = match ctx.fs.file_id(path) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        unsafe {
            std::ptr::write_bytes(output, 0, 52);
            (output as *mut u32).write_unaligned(native_file_attributes(is_directory));
            (output.add(28) as *mut u32).write_unaligned(0x5743_4C49);
            (output.add(32) as *mut u32).write_unaligned((size >> 32) as u32);
            (output.add(36) as *mut u32).write_unaligned(size as u32);
            (output.add(40) as *mut u32).write_unaligned(1);
            (output.add(44) as *mut u64).write_unaligned(file_id);
        }
        1
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
        let context = match fs_ctx() {
            Some(v) => v,
            None => return 0,
        };
        let mut ctx = match context.lock() {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let (path, offset) = match ctx.handles.get(&h) {
            Some(v) => (v.path.clone(), v.offset),
            None => return 0,
        };
        let data = match ctx.fs.read_file(&path) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let k = (data.len().saturating_sub(offset)).min(n as usize);
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr().add(offset), buf, k) };
        if let Some(file) = ctx.handles.get_mut(&h) {
            file.offset = offset + k;
        }
        if !read.is_null() {
            unsafe { read.write(k as u32) };
        }
        1
    }
    extern "win64" fn native_close_handle(h: u64) -> i32 {
        let process = process_ctx();
        if process
            .as_ref()
            .and_then(|process| process.threads.lock().ok().map(|mut threads| threads.remove(&h).is_some()))
            .unwrap_or(false)
        {
            return 1;
        }
        if process
            .as_ref()
            .is_some_and(|process| h == process.process_handle || h == u64::MAX - 1)
        {
            native_set_last_error(6); // pseudo handles cannot be closed
            return 0;
        }
        if process
            .as_ref()
            .and_then(|process| {
                process.children.lock().ok().map(|mut children| {
                    children.children.remove(&h).is_some()
                        || children.primary_threads.remove(&h).is_some()
                })
            })
            .unwrap_or(false)
        {
            return 1;
        }
        let closed = fs_ctx()
            .and_then(|context| {
                context
                    .lock()
                    .ok()
                    .map(|mut c| c.handles.remove(&h).is_some() || c.finds.remove(&h).is_some())
            })
            .unwrap_or(false);
        if !closed {
            native_set_last_error(6);
        }
        closed as i32
    }
    extern "win64" fn native_create_directory_w(p: *const u16, _s: u64) -> i32 {
        fs_ctx()
            .and_then(|context| {
                context
                    .lock()
                    .ok()
                    .and_then(|mut c| wide(p).map(|p| c.fs.mkdir_one(&p).is_ok()))
            })
            .unwrap_or(false) as i32
    }
    extern "win64" fn native_remove_directory_w(p: *const u16) -> i32 {
        fs_ctx()
            .and_then(|context| {
                context
                    .lock()
                    .ok()
                    .and_then(|mut c| wide(p).map(|p| c.fs.rmdir(&p).is_ok()))
            })
            .unwrap_or(false) as i32
    }
    extern "win64" fn native_delete_file_w(p: *const u16) -> i32 {
        fs_ctx()
            .and_then(|context| {
                context
                    .lock()
                    .ok()
                    .and_then(|mut c| wide(p).map(|p| c.fs.delete_file(&p).is_ok()))
            })
            .unwrap_or(false) as i32
    }
    extern "win64" fn native_move_file_w(a: *const u16, b: *const u16) -> i32 {
        let (a, b) = match (wide(a), wide(b)) {
            (Some(a), Some(b)) => (a, b),
            _ => return 0,
        };
        fs_ctx()
            .and_then(|context| {
                context
                    .lock()
                    .ok()
                    .map(|mut c| c.fs.move_path(&a, &b).is_ok())
            })
            .unwrap_or(false) as i32
    }
    extern "win64" fn native_copy_file_w(a: *const u16, b: *const u16, fail: i32) -> i32 {
        let (a, b) = match (wide(a), wide(b)) {
            (Some(a), Some(b)) => (a, b),
            _ => return 0,
        };
        fs_ctx()
            .and_then(|context| {
                context
                    .lock()
                    .ok()
                    .map(|mut c| c.fs.copy_file(&a, &b, fail != 0).is_ok())
            })
            .unwrap_or(false) as i32
    }

    pub(super) fn supports_import(dll: &str, func: &str) -> bool {
        let module = dll.to_ascii_uppercase();
        let allowed = match module.as_str() {
            "WINMM.DLL" => func == "timeGetTime",
            "USERENV.DLL" => func == "GetUserProfileDirectoryW",
            "BCRYPTPRIMITIVES.DLL" => func == "ProcessPrng",
            "NTDLL.DLL" => matches!(func, "RtlGetVersion" | "RtlNtStatusToDosError"),
            "API-MS-WIN-CORE-SYNCH-L1-2-0.DLL" => {
                matches!(func, "WaitOnAddress" | "WakeByAddressAll" | "WakeByAddressSingle")
            }
            "KERNEL32.DLL" | "KERNELBASE.DLL" => !matches!(
                func, "timeGetTime" | "GetUserProfileDirectoryW" | "ProcessPrng"
            ),
            _ => false,
        };
        allowed && baseline_trampoline(func).is_some()
    }

    fn baseline_trampoline(name: &str) -> Option<u64> {
        match name {
            "GetCommandLineW" => Some(native_get_command_line_w as *const () as usize as u64),
            "GetCommandLineA" => Some(native_get_command_line_a as *const () as usize as u64),
            "GetLastError" => Some(native_get_last_error as *const () as usize as u64),
            "SetLastError" => Some(native_set_last_error as *const () as usize as u64),
            "SetErrorMode" => Some(native_set_error_mode as *const () as usize as u64),
            "GetStartupInfoW" => Some(native_get_startup_info_w as *const () as usize as u64),
            "GetProcessHeap" => Some(native_get_process_heap as *const () as usize as u64),
            "GetCurrentThreadId" => Some(native_get_current_thread_id as *const () as usize as u64),
            "GetCurrentProcessId" => {
                Some(native_get_current_process_id as *const () as usize as u64)
            }
            "GetCurrentProcess" => Some(native_get_current_process as *const () as usize as u64),
            "GetExitCodeProcess" => Some(native_get_exit_code_process as *const () as usize as u64),
            "TerminateProcess" => Some(native_terminate_process as *const () as usize as u64),
            "GetCurrentThread" => Some(native_get_current_thread as *const () as usize as u64),
            "GetModuleHandleA" => Some(native_get_module_handle_a as *const () as usize as u64),
            "VirtualProtect" => Some(native_virtual_protect as *const () as usize as u64),
            "LoadLibraryExW" => Some(native_load_library_ex_w as *const () as usize as u64),
            "GetProcAddress" => Some(native_get_proc_address as *const () as usize as u64),
            "FreeLibrary" => Some(native_free_library as *const () as usize as u64),
            "QueryPerformanceCounter" => {
                Some(native_query_performance_counter as *const () as usize as u64)
            }
            "QueryPerformanceFrequency" => {
                Some(native_query_performance_frequency as *const () as usize as u64)
            }
            "Sleep" => Some(native_sleep as *const () as usize as u64),
            "timeGetTime" => Some(native_time_get_time as *const () as usize as u64),
            "GlobalMemoryStatusEx" => {
                Some(native_global_memory_status_ex as *const () as usize as u64)
            }
            "InitializeCriticalSectionEx" => {
                Some(native_initialize_critical_section_ex as *const () as usize as u64)
            }
            "InitializeCriticalSectionAndSpinCount" => {
                Some(native_initialize_critical_section_and_spin_count as *const () as usize as u64)
            }
            "InitializeCriticalSection" => {
                Some(native_initialize_critical_section as *const () as usize as u64)
            }
            "InitializeSRWLock" => Some(native_initialize_srw_lock as *const () as usize as u64),
            "AcquireSRWLockExclusive" => Some(native_acquire_srw_lock_exclusive as *const () as usize as u64),
            "AcquireSRWLockShared" => Some(native_acquire_srw_lock_shared as *const () as usize as u64),
            "TryAcquireSRWLockExclusive" => Some(native_try_acquire_srw_lock_exclusive as *const () as usize as u64),
            "TryAcquireSRWLockShared" => Some(native_try_acquire_srw_lock_shared as *const () as usize as u64),
            "ReleaseSRWLockExclusive" => Some(native_release_srw_lock_exclusive as *const () as usize as u64),
            "ReleaseSRWLockShared" => Some(native_release_srw_lock_shared as *const () as usize as u64),
            "InitializeConditionVariable" => Some(native_initialize_condition_variable as *const () as usize as u64),
            "WakeConditionVariable" => Some(native_wake_condition_variable as *const () as usize as u64),
            "WakeAllConditionVariable" => Some(native_wake_all_condition_variable as *const () as usize as u64),
            "SleepConditionVariableSRW" => Some(native_sleep_condition_variable_srw as *const () as usize as u64),
            "InitOnceInitialize" => Some(native_init_once_initialize as *const () as usize as u64),
            "InitOnceExecuteOnce" => Some(native_init_once_execute_once as *const () as usize as u64),
            "TlsAlloc" => Some(native_tls_alloc as *const () as usize as u64),
            "TlsFree" => Some(native_tls_free as *const () as usize as u64),
            "TlsGetValue" => Some(native_tls_get_value as *const () as usize as u64),
            "TlsSetValue" => Some(native_tls_set_value as *const () as usize as u64),
            "EncodePointer" => Some(native_encode_pointer as *const () as usize as u64),
            "DecodePointer" => Some(native_decode_pointer as *const () as usize as u64),
            "IsProcessorFeaturePresent" => Some(native_is_processor_feature_present as *const () as usize as u64),
            "RtlGetVersion" => Some(native_rtl_get_version as *const () as usize as u64),
            "RtlNtStatusToDosError" => Some(native_rtl_nt_status_to_dos_error as *const () as usize as u64),
            "EnterCriticalSection" => {
                Some(native_enter_critical_section as *const () as usize as u64)
            }
            "LeaveCriticalSection" => {
                Some(native_leave_critical_section as *const () as usize as u64)
            }
            "DeleteCriticalSection" => {
                Some(native_delete_critical_section as *const () as usize as u64)
            }
            "InitializeSListHead" => {
                Some(native_initialize_slist_head as *const () as usize as u64)
            }
            "FlsAlloc" => Some(native_fls_alloc as *const () as usize as u64),
            "FlsFree" => Some(native_fls_free as *const () as usize as u64),
            "FlsGetValue" => Some(native_fls_get_value as *const () as usize as u64),
            "FlsSetValue" => Some(native_fls_set_value as *const () as usize as u64),
            "GetSystemTimeAsFileTime" => {
                Some(native_get_system_time_as_file_time as *const () as usize as u64)
            }
            "GetSystemInfo" => Some(native_get_system_info as *const () as usize as u64),
            "GetFullPathNameW" => Some(native_get_full_path_name_w as *const () as usize as u64),
            "FormatMessageW" => Some(native_format_message_w as *const () as usize as u64),
            "FormatMessageA" => Some(native_format_message_a as *const () as usize as u64),
            "GetUserProfileDirectoryW" => {
                Some(native_get_user_profile_directory_w as *const () as usize as u64)
            }
            "GetStdHandle" => Some(native_get_std_handle as *const () as usize as u64),
            "GetFileType" => Some(native_get_file_type as *const () as usize as u64),
            "GetModuleFileNameW" => {
                Some(native_get_module_file_name_w as *const () as usize as u64)
            }
            "GetModuleHandleW" => Some(native_get_module_handle_w as *const () as usize as u64),
            "GetModuleHandleExW" => {
                Some(native_get_module_handle_ex_w as *const () as usize as u64)
            }
            "GetEnvironmentStringsW" => {
                Some(native_get_environment_strings_w as *const () as usize as u64)
            }
            "FreeEnvironmentStringsW" => {
                Some(native_free_environment_strings_w as *const () as usize as u64)
            }
            "SetUnhandledExceptionFilter" => {
                Some(native_set_unhandled_exception_filter as *const () as usize as u64)
            }
            "AddVectoredExceptionHandler" => {
                Some(native_add_vectored_exception_handler as *const () as usize as u64)
            }
            "SetThreadStackGuarantee" => {
                Some(native_set_thread_stack_guarantee as *const () as usize as u64)
            }
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
            "HeapReAlloc" => Some(native_heap_realloc as *const () as usize as u64),
            "HeapSize" => Some(native_heap_size as *const () as usize as u64),
            "HeapFree" => Some(native_heap_free as *const () as usize as u64),
            "ProcessPrng" => Some(native_process_prng as *const () as usize as u64),
            "GetConsoleMode" => Some(native_get_console_mode as *const () as usize as u64),
            "GetConsoleOutputCP" => Some(native_get_console_output_cp as *const () as usize as u64),
            "GetConsoleScreenBufferInfo" => {
                Some(native_get_console_screen_buffer_info as *const () as usize as u64)
            }
            "SetConsoleMode" => Some(native_set_console_mode as *const () as usize as u64),
            "GetEnvironmentVariableW" => {
                Some(native_get_environment_variable_w as *const () as usize as u64)
            }
            "GetCurrentDirectoryW" => {
                Some(native_get_current_directory_w as *const () as usize as u64)
            }
            "GetComputerNameExW" => {
                Some(native_get_computer_name_ex_w as *const () as usize as u64)
            }
            "SetFileTime" => Some(native_set_file_time as *const () as usize as u64),
            "WriteFile" => Some(native_write_file as *const () as usize as u64),
            "WriteConsoleW" => Some(native_write_console_w as *const () as usize as u64),
            "ExitProcess" => Some(native_exit_process as *const () as usize as u64),
            "CreateProcessW" => Some(native_create_process_w as *const () as usize as u64),
            "CreateFileW" => Some(native_create_file_w as *const () as usize as u64),
            "GetFileInformationByHandle" => {
                Some(native_get_file_information_by_handle as *const () as usize as u64)
            }
            "GetFinalPathNameByHandleW" => {
                Some(native_get_final_path_name_by_handle_w as *const () as usize as u64)
            }
            "FindFirstFileExW" => Some(native_find_first_file_ex_w as *const () as usize as u64),
            "FindNextFileW" => Some(native_find_next_file_w as *const () as usize as u64),
            "FindClose" => Some(native_find_close as *const () as usize as u64),
            "CreateThread" => Some(native_create_thread as *const () as usize as u64),
            "WaitForSingleObject" => {
                Some(native_wait_for_single_object as *const () as usize as u64)
            }
            "WaitOnAddress" => Some(native_wait_on_address as *const () as usize as u64),
            "WakeByAddressAll" | "WakeByAddressSingle" => {
                Some(native_wake_by_address as *const () as usize as u64)
            }
            "CreateWaitableTimerExW" => {
                Some(native_create_waitable_timer_ex_w as *const () as usize as u64)
            }
            "SetWaitableTimer" => Some(native_set_waitable_timer as *const () as usize as u64),
            "ReadFile" => Some(native_read_file as *const () as usize as u64),
            "CloseHandle" => Some(native_close_handle as *const () as usize as u64),
            "CreateDirectoryW" => Some(native_create_directory_w as *const () as usize as u64),
            "RemoveDirectoryW" => Some(native_remove_directory_w as *const () as usize as u64),
            "DeleteFileW" => Some(native_delete_file_w as *const () as usize as u64),
            "MoveFileW" => Some(native_move_file_w as *const () as usize as u64),
            "CopyFileW" => Some(native_copy_file_w as *const () as usize as u64),
            _ => None,
        }
    }

    struct MissingImportStubs {
        _code: Mapping,
        _messages: Vec<Vec<u8>>,
    }

    extern "win64" fn native_missing_import(message: *const u8, len: u64) -> ! {
        let mut offset = 0;
        while offset < len as usize {
            let written = unsafe { write(2, message.add(offset).cast(), len as usize - offset) };
            if written <= 0 {
                break;
            }
            offset += written as usize;
        }
        unsafe { _exit(126) }
    }

    fn patch_baseline_imports(
        mapping: &Mapping,
        img: &PeImage,
        diagnostic: bool,
    ) -> Result<Option<MissingImportStubs>, String> {
        let imports: Vec<_> = img.imports.iter().chain(&img.unsupported).collect();
        let missing = imports.iter().filter(|import| !supports_import(&import.dll, &import.func)).count();
        if missing > 0 && !diagnostic {
            let import = imports.iter().find(|import| !supports_import(&import.dll, &import.func)).unwrap();
            return Err(format!("unsupported native import: {}!{}", import.dll, import.func));
        }
        let mut stubs = if missing == 0 {
            None
        } else {
            let size = page_len(missing.checked_mul(32).ok_or("too many native import stubs")?)?;
            let ptr = unsafe { mmap(ptr::null_mut(), size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
            if ptr == MAP_FAILED {
                return Err(format!("native import stub allocation failed: {}", std::io::Error::last_os_error()));
            }
            Some(MissingImportStubs { _code: Mapping { ptr: ptr.cast(), len: size }, _messages: Vec::with_capacity(missing) })
        };
        let mut stub_index = 0;
        for import in imports {
            let value = if supports_import(&import.dll, &import.func) {
                baseline_trampoline(&import.func).unwrap()
            } else {
                let stubs = stubs.as_mut().unwrap();
                let message = format!("unsupported native import called: {}!{}\n", import.dll, import.func).into_bytes();
                let message_ptr = message.as_ptr() as u64;
                let message_len = message.len() as u64;
                stubs._messages.push(message);
                let code = unsafe { std::slice::from_raw_parts_mut(stubs._code.ptr.add(stub_index * 32), 32) };
                code[0..2].copy_from_slice(&[0x48, 0xB9]); // mov rcx, message
                code[2..10].copy_from_slice(&message_ptr.to_le_bytes());
                code[10..12].copy_from_slice(&[0x48, 0xBA]); // mov rdx, length
                code[12..20].copy_from_slice(&message_len.to_le_bytes());
                code[20..22].copy_from_slice(&[0x48, 0xB8]); // mov rax, handler
                code[22..30].copy_from_slice(&(native_missing_import as *const () as usize as u64).to_le_bytes());
                code[30..32].copy_from_slice(&[0xFF, 0xE0]); // jmp rax
                stub_index += 1;
                code.as_ptr() as u64
            };
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
        if let Some(stubs) = &stubs {
            if unsafe { mprotect(stubs._code.ptr.cast(), stubs._code.len, PROT_READ | PROT_EXEC) } != 0 {
                return Err(format!("native import stubs could not be made executable: {}", std::io::Error::last_os_error()));
            }
        }
        Ok(stubs)
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
        let mut line = quote_arg(prog);
        for arg in args {
            line.push(' ');
            line.push_str(&quote_arg(arg));
        }
        let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
        if wide.len() * 2 > COMMAND_LINE_BYTES {
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
        run_rust_baseline_argv_with_fs(img, WinFs::ephemeral_runner(), prog, args)
            .map(|(code, out, _)| (code, out))
    }

    pub(super) fn run_rust_baseline_argv_with_fs(
        img: &PeImage,
        instance_fs: WinFs,
        prog: &str,
        args: &[String],
    ) -> Result<(u32, Vec<u8>, WinFs), String> {
        run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, None)
    }

    pub(super) fn run_rust_baseline_argv_with_fs_streaming(
        img: &PeImage,
        instance_fs: WinFs,
        prog: &str,
        args: &[String],
        output: &dyn Fn(&[u8]),
    ) -> Result<(u32, Vec<u8>, WinFs), String> {
        run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, Some(output))
    }

    fn run_rust_baseline_argv_with_fs_impl(
        img: &PeImage,
        instance_fs: WinFs,
        prog: &str,
        args: &[String],
        output: Option<&dyn Fn(&[u8])>,
    ) -> Result<(u32, Vec<u8>, WinFs), String> {
        let _run = NATIVE_RUN_LOCK
            .lock()
            .map_err(|_| "native backend execution lock is poisoned".to_string())?;
        let entry = entry(img)?;
        let mapping = map(img)?;
        let diagnostic = std::env::var("WINCLI_NATIVE_DIAGNOSTIC").as_deref() == Ok("1");
        let _import_stubs = patch_baseline_imports(&mapping, img, diagnostic)?;
        let tls = setup_tls(&mapping, img)?;
        let fs = Arc::new(Mutex::new(NativeFs {
            fs: instance_fs,
            handles: HashMap::new(),
            finds: HashMap::new(),
            next: 0x100,
        }));
        let command_line_w = command_line_w(prog, args)?;
        let command_line_a = command_line_a(&command_line_w);
        let process = Arc::new(NativeProcessContext {
            image_base: img.image_base,
            process_id: 1,
            process_handle: u64::MAX,
            parent_process_id: 0,
            command_line_w,
            command_line_a,
            environment: Vec::new(),
            environment_block: vec![0, 0],
            fs,
            last_error: AtomicU32::new(0),
            error_mode: AtomicU32::new(0),
            pointer_cookie: random_pointer_cookie(),
            heap_allocations: Mutex::new(HashMap::new()),
            gs_base: AtomicU64::new(0),
            tls_template: Mutex::new(tls.as_ref().map(NativeTls::clone_for_thread)),
            dynamic_tls: Mutex::new(DynamicTlsSlots::new(tls.is_some())),
            threads: Mutex::new(HashMap::new()),
            thread_next: AtomicU64::new(0x8000_0000),
            timer_next: AtomicU64::new(0x7000_0000),
            state_fd: AtomicU32::new(u32::MAX),
            fls_value: AtomicU64::new(0),
            unhandled_exception_filter: AtomicU64::new(0),
            vectored_exception_handler: AtomicU64::new(0),
            exit_status: AtomicU32::new(259), // STILL_ACTIVE
            exited: AtomicBool::new(false),
            children: Mutex::new(NativeProcessTable::new()),
        });
        if let Ok(mut context) = NATIVE_PROCESS.lock() {
            *context = Some(Arc::clone(&process));
        }
        let mut fds = [-1, -1];
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            return Err(format!(
                "native backend could not create stdout pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut state_fds = [-1, -1];
        if unsafe { pipe(state_fds.as_mut_ptr()) } != 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
            }
            return Err(format!(
                "native backend could not create state pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let pid = unsafe { fork() };
        if pid < 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
                close(state_fds[0]);
                close(state_fds[1]);
            }
            return Err(format!(
                "native backend could not fork guest: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            #[cfg(test)]
            NATIVE_GUEST_ACTIVE.store(true, Ordering::Release);
            unsafe {
                close(fds[0]);
                close(state_fds[0]);
                if dup2(fds[1], 1) < 0 {
                    _exit(127);
                }
                close(fds[1]);
            }
            process
                .state_fd
                .store(state_fds[1] as u32, Ordering::Release);
            if protect_exec(&mapping).is_err() {
                unsafe { _exit(127) };
            }
            if let Some(tls) = tls.as_ref() {
                process
                    .gs_base
                    .store(tls.teb.as_ptr() as u64, Ordering::Release);
                if !unsafe { set_gs(tls.teb.as_ptr() as u64) } {
                    unsafe { _exit(127) };
                }
            }
            // SAFETY: the entry is in the child-owned RX PE mapping. Its
            // imported ExitProcess trampoline terminates this child.
            let guest: unsafe extern "win64" fn() -> u32 = unsafe { std::mem::transmute(entry) };
            let code = unsafe { guest() };
            unsafe { close(1) };
            native_flush_instance_state();
            unsafe { _exit(code as i32) };
        }
        unsafe {
            close(fds[1]);
            close(state_fds[1]);
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
            if let Some(output) = output {
                output(&buf[..n as usize]);
            }
        }
        unsafe {
            close(fds[0]);
        }
        let mut state = Vec::new();
        loop {
            let n = unsafe { read(state_fds[0], buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                break;
            }
            if n < 0 {
                unsafe { close(state_fds[0]) };
                return Err(format!(
                    "native backend could not read guest filesystem state: {}",
                    std::io::Error::last_os_error()
                ));
            }
            state.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { close(state_fds[0]) };
        let mut status = 0;
        if unsafe { waitpid(pid, &mut status, 0) } != pid {
            return Err(format!(
                "native backend could not reap guest: {}",
                std::io::Error::last_os_error()
            ));
        }
        process
            .exit_status
            .store((status >> 8) as u32, Ordering::Release);
        process.exited.store(true, Ordering::Release);
        if let Ok(mut context) = NATIVE_PROCESS.lock() {
            *context = None;
        }
        let final_fs = if state.is_empty() {
            process
                .fs
                .lock()
                .map_err(|_| "native backend filesystem lock is poisoned".to_string())?
                .fs
                .clone()
        } else {
            crate::snapshot::load(&state)
                .map_err(|e| format!("native backend returned invalid filesystem state: {e}"))?
        };
        if status & 0x7f != 0 {
            return Err(format!(
                "native guest terminated by signal {}",
                status & 0x7f
            ));
        }
        Ok(((status >> 8) as u32, out, final_fs))
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    use super::PeImage;

    pub(super) fn supports_import(_: &str, _: &str) -> bool {
        false
    }

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

    pub(super) fn run_rust_baseline_argv_with_fs(
        _: &PeImage,
        _: crate::winfs::WinFs,
        _: &str,
        _: &[String],
    ) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), String> {
        Err("native backend is available only on Linux x86_64".to_string())
    }

    pub(super) fn run_rust_baseline_argv_with_fs_streaming(
        _: &PeImage,
        _: crate::winfs::WinFs,
        _: &str,
        _: &[String],
        _: &dyn Fn(&[u8]),
    ) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), String> {
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
    use crate::winfs::WinFs;

    #[test]
    fn executes_an_import_free_pe_at_native_speed() {
        let mut asm = Asm::new();
        asm.mov_r32_imm(0, 37);
        asm.ret();
        let img = load(&build(asm, &[])).expect("fixture PE loads");
        assert_eq!(run_import_free(&img).expect("native PE runs"), 37);
    }

    #[test]
    fn import_free_entry_rejects_imported_images() {
        let mut asm = Asm::new();
        asm.ret();
        let img = load(&build(asm, &[("KERNEL32.DLL", "ExitProcess")])).expect("fixture PE loads");
        let err = run_import_free(&img).expect_err("imports need shims");
        assert!(err.contains("cannot bind PE imports"));
    }

    #[test]
    fn executes_the_checked_in_rust_hello_guest_with_native_trampolines() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_hello.exe"
        );
        let bytes = std::fs::read(path).expect("checked-in guest exists");
        let img = load(&bytes).expect("rust hello loads");
        assert!(
            !img.relocations.is_empty(),
            "native child images are relocatable"
        );
        let (code, out) = run_rust_baseline(&img).expect("native rust hello runs");
        assert_eq!(code, 0);
        assert_eq!(out, b"Hello from Rust");
    }

    #[test]
    fn forwards_native_child_stdout_chunks() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_hello.exe"
        );
        let img = load(&std::fs::read(path).unwrap()).unwrap();
        let output = std::sync::Mutex::new(Vec::new());
        let (code, returned, _) = run_rust_baseline_argv_with_fs_streaming(
            &img,
            WinFs::ephemeral_runner(),
            "hello.exe",
            &[],
            &|chunk| output.lock().unwrap().extend_from_slice(chunk),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(returned, b"Hello from Rust");
        assert_eq!(*output.lock().unwrap(), b"Hello from Rust");
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

    #[test]
    fn native_guest_commits_filesystem_state_across_child_boundary() {
        let writer = load(&crate::pe::builder::write_file(
            r"C:\work\state.txt",
            b"native",
        ))
        .expect("writer loads");
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\work").unwrap();
        let (code, _, fs) = run_rust_baseline_argv_with_fs(&writer, fs, "writer.exe", &[])
            .expect("native writer runs");
        assert_eq!(code, 0);
        assert_eq!(fs.read_file(r"C:\work\state.txt").unwrap(), b"native");

        let reader = load(&crate::pe::builder::read_file_to_stdout(
            r"C:\work\state.txt",
        ))
        .expect("reader loads");
        let (code, out, _) = run_rust_baseline_argv_with_fs(&reader, fs, "reader.exe", &[])
            .expect("native reader runs");
        assert_eq!(code, 0);
        assert_eq!(out, b"native");
    }

    #[test]
    fn native_guest_can_create_wait_for_and_reap_a_relocated_child() {
        let child = crate::pe::builder::hello("child\n");
        let parent = load(&crate::pe::builder::create_process_wait(
            r"C:\child.exe",
            None,
        ))
        .expect("parent loads");
        let mut fs = WinFs::ephemeral_runner();
        fs.write_file(r"C:\child.exe", child).unwrap();
        let (code, output, _) = run_rust_baseline_argv_with_fs(&parent, fs, "parent.exe", &[])
            .expect("native parent runs");
        assert_eq!(code, 0);
        assert_eq!(output, b"child\n");
    }

    #[test]
    fn native_child_uses_its_requested_working_directory() {
        let child = crate::pe::builder::write_file("child.txt", b"cwd");
        let parent = load(&crate::pe::builder::create_process_wait(
            r"C:\child.exe",
            Some(r"C:\work"),
        ))
        .expect("parent loads");
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\work").unwrap();
        let parent_cwd = fs.cwd();
        fs.write_file(r"C:\child.exe", child).unwrap();
        let (code, _, fs) = run_rust_baseline_argv_with_fs(&parent, fs, "parent.exe", &[])
            .expect("native parent runs");
        assert_eq!(code, 0);
        assert_eq!(fs.read_file(r"C:\work\child.txt").unwrap(), b"cwd");
        assert_eq!(fs.cwd(), parent_cwd);
    }
}
