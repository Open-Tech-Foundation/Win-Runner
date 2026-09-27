//! Linux x86-64 implementation of the native PE backend.

use super::{quote_arg, PeImage, COMMAND_LINE_BYTES};
use crate::winfs::WinFs;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::LazyLock;

static NATIVE_DIAGNOSTIC_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var_os("WINCLI_NATIVE_DIAGNOSTIC").is_some_and(|value| value == "1")
});

#[inline]
fn native_diagnostic_enabled() -> bool {
    *NATIVE_DIAGNOSTIC_ENABLED
}
use std::sync::{Arc, Condvar, Mutex, Weak};

#[path = "linux_host.rs"]
mod host;
use host::*;

#[path = "linux_x86_64/loader.rs"]
mod loader;
use loader::{map, map_relocated, protect_exec};
#[path = "linux_x86_64/process.rs"]
mod process;
use process::*;
#[path = "linux_x86_64/registry.rs"]
mod registry;
use registry::baseline_trampoline;
pub(super) use registry::supports_import;
#[path = "linux_x86_64/sockets.rs"]
mod sockets;
use sockets::*;
#[path = "linux_x86_64/file_io.rs"]
mod file_io;
use file_io::*;
#[path = "linux_x86_64/handles.rs"]
mod handles;
use handles::*;
#[path = "linux_x86_64/sync.rs"]
mod sync;
use sync::*;
#[path = "linux_x86_64/crt.rs"]
mod crt;
use crt::*;
#[path = "linux_x86_64/console.rs"]
mod console;
use console::*;
#[path = "linux_x86_64/overlapped.rs"]
mod overlapped;
use overlapped::*;

#[cfg(test)]
pub(super) fn test_socket_handle_inheritability() -> bool {
    let socket = native_socket(2, 1, 0);
    if socket == u64::MAX {
        return false;
    }
    let result = native_set_handle_information(socket, 1, 1) == 1
        && unsafe { fcntl(socket as i32, 1) } & 1 == 0
        && native_set_handle_information(socket, 1, 0) == 1
        && unsafe { fcntl(socket as i32, 1) } & 1 != 0;
    let _ = native_close_socket(socket);
    result
}

const PROCESS_HEAP_HANDLE: u64 = 0x400;
const PROCESS_TOKEN_HANDLE: u64 = 0x544f_4b45_4e00_0001;
const STD_HANDLE_BASE: u64 = 0x5000_0000;
const SOCKET_HANDLE_TAG: u64 = 0x534f_434b_0000_0000;
const CRYPTO_PROVIDER_HANDLE: u64 = 0x4352_5950_544f_0001;
// A child-local stand-in for the API-set modules dynamically requested by
// the Universal CRT. It is deliberately not a host `dlopen` handle.
const API_SET_MODULE: u64 = 0x5749_4e43_4c49_0001;
static EMPTY_ENVIRONMENT_BLOCK: [u16; 2] = [0, 0];

// Preferred-base PE mappings collide by design. Serialize native runs in
// this process until relocations allow separate address-space layouts.
static NATIVE_RUN_LOCK: Mutex<()> = Mutex::new(());
static NATIVE_SLIST_LOCK: Mutex<()> = Mutex::new(());
static NATIVE_CRITICAL_SECTIONS: LazyLock<Mutex<HashMap<usize, Arc<NativeCriticalSection>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NATIVE_ADDRESS_WAITERS: LazyLock<Mutex<HashMap<usize, Weak<NativeAddressWaiters>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct NativeCriticalSection {
    owner_and_recursion: Mutex<(Option<u64>, u32)>,
    ready: Condvar,
}

impl NativeCriticalSection {
    fn new() -> Self {
        Self {
            owner_and_recursion: Mutex::new((None, 0)),
            ready: Condvar::new(),
        }
    }
}

struct NativeAddressWaiters {
    generation: Mutex<u64>,
    ready: Condvar,
}

impl NativeAddressWaiters {
    fn new() -> Self {
        Self {
            generation: Mutex::new(0),
            ready: Condvar::new(),
        }
    }
}

// RtlCaptureContext is called directly from guest code. Capture the live
// Windows x64 call frame before a Rust trampoline can alter volatile
// registers. CONTEXT is 16-byte aligned and 1,232 bytes on x64.
std::arch::global_asm!(
    ".text",
    ".global wincli_native_rtl_capture_context",
    ".type wincli_native_rtl_capture_context,@function",
    "wincli_native_rtl_capture_context:",
    "mov [rcx + 208], r11",
    "mov r11, rcx",
    "mov qword ptr [r11 + 0], 0",
    "mov qword ptr [r11 + 8], 0",
    "mov qword ptr [r11 + 16], 0",
    "mov qword ptr [r11 + 24], 0",
    "mov qword ptr [r11 + 32], 0",
    "mov qword ptr [r11 + 40], 0",
    "mov dword ptr [r11 + 48], 0x0010001f",
    "mov [r11 + 120], rax",
    "mov [r11 + 128], rcx",
    "mov [r11 + 136], rdx",
    "mov [r11 + 144], rbx",
    "lea rax, [rsp + 8]",
    "mov [r11 + 152], rax",
    "mov [r11 + 160], rbp",
    "mov [r11 + 168], rsi",
    "mov [r11 + 176], rdi",
    "mov [r11 + 184], r8",
    "mov [r11 + 192], r9",
    "mov [r11 + 200], r10",
    "mov [r11 + 216], r12",
    "mov [r11 + 224], r13",
    "mov [r11 + 232], r14",
    "mov [r11 + 240], r15",
    "mov rax, [rsp]",
    "mov [r11 + 248], rax",
    "pushfq",
    "pop rax",
    "mov [r11 + 68], eax",
    "mov ax, cs",
    "mov [r11 + 56], ax",
    "mov ax, ds",
    "mov [r11 + 58], ax",
    "mov ax, es",
    "mov [r11 + 60], ax",
    "mov ax, fs",
    "mov [r11 + 62], ax",
    "mov ax, gs",
    "mov [r11 + 64], ax",
    "mov ax, ss",
    "mov [r11 + 66], ax",
    "mov qword ptr [r11 + 72], 0",
    "mov qword ptr [r11 + 80], 0",
    "mov qword ptr [r11 + 88], 0",
    "mov qword ptr [r11 + 96], 0",
    "mov qword ptr [r11 + 104], 0",
    "mov qword ptr [r11 + 112], 0",
    "stmxcsr [r11 + 52]",
    "fxsave64 [r11 + 256]",
    "lea rdi, [r11 + 768]",
    "xor eax, eax",
    "mov ecx, 58",
    "rep stosq",
    "mov rdi, [r11 + 176]",
    "ret",
    ".size wincli_native_rtl_capture_context, .-wincli_native_rtl_capture_context",
);
unsafe extern "win64" {
    fn wincli_native_rtl_capture_context(context: *mut u8);
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
        native_acquire_srw_lock_exclusive, native_add_vectored_exception_handler,
        native_close_handle, native_connect_socket, native_create_process_w,
        native_create_waitable_timer_ex_w, native_decode_pointer, native_delete_critical_section,
        native_encode_pointer, native_enter_critical_section, native_extended_path,
        native_file_attributes, native_format_message_a, native_format_message_w,
        native_free_environment_strings_w, native_get_acp, native_get_computer_name_ex_w,
        native_get_console_cursor_info, native_get_console_mode, native_get_console_output_cp,
        native_get_console_screen_buffer_info, native_get_cp_info, native_get_current_directory_w,
        native_get_current_process, native_get_current_process_id, native_get_current_thread,
        native_get_current_thread_id, native_get_environment_strings_w,
        native_get_environment_variable_w, native_get_exit_code_process, native_get_file_type,
        native_get_full_path_name_w, native_get_last_error, native_get_module_file_name_w,
        native_get_module_handle_a, native_get_module_handle_ex_w, native_get_module_handle_w,
        native_get_oem_cp, native_get_proc_address, native_get_startup_info_w,
        native_get_string_type_w, native_get_system_info, native_get_user_profile_directory_w,
        native_global_memory_status_ex, native_heap_alloc, native_heap_free, native_heap_realloc,
        native_heap_size, native_init_once_execute_once, native_initialize_condition_variable,
        native_initialize_critical_section_and_spin_count, native_initialize_critical_section_ex,
        native_initialize_slist_head, native_initialize_srw_lock, native_interlocked_flush_slist,
        native_interlocked_pop_entry_slist, native_interlocked_push_entry_slist,
        native_ioctlsocket, native_is_processor_feature_present, native_is_valid_code_page,
        native_launch_spec, native_lc_map_string_w, native_leave_critical_section,
        native_listen_socket, native_multi_byte_to_wide_char,
        native_need_current_directory_for_exe_path_w, native_process_prng,
        native_query_depth_slist, native_query_performance_frequency,
        native_release_srw_lock_exclusive, native_release_srw_lock_shared,
        native_resolve_code_page, native_rtl_get_version, native_rtl_nt_status_to_dos_error,
        native_set_console_active_screen_buffer, native_set_console_cursor_info,
        native_set_console_cursor_position, native_set_console_mode,
        native_set_console_screen_buffer_size, native_set_console_window_info,
        native_set_environment_variable_w, native_set_file_time, native_set_last_error,
        native_set_thread_stack_guarantee, native_set_unhandled_exception_filter,
        native_set_waitable_timer, native_shutdown_socket, native_sleep_condition_variable_srw,
        native_terminate_process, native_try_acquire_srw_lock_shared,
        native_wait_for_single_object, native_wait_on_address, native_wake_all_condition_variable,
        native_wake_by_address_all, native_wide_char_to_multi_byte, native_write_console_w,
        native_wsa_get_last_error, native_wsa_inet_addr, parse_windows_command_line, process_ctx,
        uppercase_ascii_utf16, waitpid, write_process_information, NativeLaunchSpec,
        NativeMemoryStatus, API_SET_MODULE, PROT_EXEC, PROT_READ, PROT_WRITE, THREAD_NATIVE_HANDLE,
    };
    use crate::winfs::WinFs;

    fn require_kernel32_api(name: &'static [u8]) -> u64 {
        let address = super::native_get_proc_address(super::API_SET_MODULE, name.as_ptr());
        let label = String::from_utf8_lossy(&name[..name.len().saturating_sub(1)]);
        assert_ne!(address, 0, "KERNEL32 API is not available: {label}");
        address
    }

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
    fn system_info_uses_windows_x64_field_offsets() {
        let mut info = [0u8; 48];
        native_get_system_info(info.as_mut_ptr());
        assert_eq!(u32::from_le_bytes(info[4..8].try_into().unwrap()), 4096);
        assert_eq!(u32::from_le_bytes(info[32..36].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(info[36..40].try_into().unwrap()), 8664);
        assert_eq!(u32::from_le_bytes(info[40..44].try_into().unwrap()), 65_536);
    }

    #[test]
    fn locale_name_query_supports_sizing_and_short_buffers() {
        assert_eq!(
            super::native_get_locale_info_ex(std::ptr::null(), 0x5c, std::ptr::null_mut(), 0),
            6
        );
        let mut short = [0u16; 2];
        assert_eq!(
            super::native_get_locale_info_ex(std::ptr::null(), 0x5c, short.as_mut_ptr(), 2),
            0
        );
        let mut value = [0u16; 6];
        assert_eq!(
            super::native_get_locale_info_ex(std::ptr::null(), 0x5c, value.as_mut_ptr(), 6),
            6
        );
        assert_eq!(String::from_utf16_lossy(&value[..5]), "en-US");
    }

    #[test]
    fn nt_read_file_tracks_offsets_and_reports_eof_and_invalid_handles() {
        let path = r"C:\nt_read_file_unit.txt";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(path, b"abcde".to_vec()).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };
        let mut io_status = [0u8; 16];
        let mut buffer = [0u8; 3];
        let read = |handle, offset: *const i64, io: &mut [u8; 16], output: &mut [u8; 3]| {
            super::native_nt_read_file(
                handle,
                0,
                0,
                0,
                io.as_mut_ptr(),
                output.as_mut_ptr(),
                3,
                offset,
                std::ptr::null(),
            )
        };
        assert_eq!(
            read(handle, std::ptr::null(), &mut io_status, &mut buffer),
            0
        );
        assert_eq!(&buffer, b"abc");
        assert_eq!(u64::from_le_bytes(io_status[8..16].try_into().unwrap()), 3);
        let explicit = 1i64;
        assert_eq!(read(handle, &explicit, &mut io_status, &mut buffer), 0);
        assert_eq!(&buffer, b"bcd");
        assert_eq!(
            read(handle, std::ptr::null(), &mut io_status, &mut buffer),
            0
        );
        assert_eq!(io_status[8], 1);
        assert_eq!(buffer[0], b'e');
        assert_eq!(
            read(handle, std::ptr::null(), &mut io_status, &mut buffer),
            0xC000_0011
        );
        assert_eq!(u64::from_le_bytes(io_status[8..16].try_into().unwrap()), 0);
        assert_eq!(
            read(u64::MAX - 10, std::ptr::null(), &mut io_status, &mut buffer),
            0xC000_0008
        );
        assert_eq!(
            super::native_nt_read_file(
                handle,
                1,
                0,
                0,
                io_status.as_mut_ptr(),
                buffer.as_mut_ptr(),
                3,
                std::ptr::null(),
                std::ptr::null()
            ),
            0xC000_00BB
        );
        let mut fs = context.lock().unwrap();
        fs.handles.remove(&handle);
        fs.fs.delete_file(path).unwrap();
    }

    #[test]
    fn nt_write_file_creates_and_extends_guest_files() {
        let path = r"C:\nt_write_file_unit.txt";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(path, b"abc".to_vec()).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };
        let mut io_status = [0u8; 16];
        let replacement = *b"XY";
        assert_eq!(
            super::native_nt_write_file(
                handle,
                0,
                0,
                0,
                io_status.as_mut_ptr(),
                replacement.as_ptr(),
                replacement.len() as u32,
                std::ptr::null(),
                std::ptr::null(),
            ),
            0
        );
        assert_eq!(u64::from_le_bytes(io_status[8..16].try_into().unwrap()), 2);
        assert_eq!(context.lock().unwrap().fs.read_file(path).unwrap(), b"XYc");

        let offset = 4i64;
        assert_eq!(
            super::native_nt_write_file(
                handle,
                0,
                0,
                0,
                io_status.as_mut_ptr(),
                replacement.as_ptr(),
                replacement.len() as u32,
                &offset,
                std::ptr::null(),
            ),
            0
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"XYc\0XY"
        );

        let mut fs = context.lock().unwrap();
        fs.handles.remove(&handle);
        fs.fs.delete_file(path).unwrap();
    }

    #[test]
    fn nt_query_directory_file_returns_native_winfs_entries() {
        let directory = r"C:\nt_query_directory_unit";
        let context = super::fs_ctx().unwrap();
        {
            let mut fs = context.lock().unwrap();
            fs.fs.mkdir(directory).unwrap();
            fs.fs.mkdir(&format!(r"{directory}\nested")).unwrap();
            fs.fs
                .write_file(&format!(r"{directory}\alpha.txt"), b"a".to_vec())
                .unwrap();
            fs.fs
                .write_file(&format!(r"{directory}\nested\beta.txt"), b"b".to_vec())
                .unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: directory.to_string(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            drop(fs);

            let mut io_status = [0u8; 16];
            let mut entries = [0u8; 1024];
            assert_eq!(
                super::native_nt_query_directory_file(
                    handle,
                    0,
                    0,
                    0,
                    io_status.as_mut_ptr(),
                    entries.as_mut_ptr(),
                    entries.len() as u32,
                    1,
                    0,
                    std::ptr::null(),
                    1,
                ),
                0
            );
            assert_eq!(
                u64::from_le_bytes(io_status[8..16].try_into().unwrap()) as usize,
                88 + 76
            );
            let mut names = Vec::new();
            let mut offset = 0;
            loop {
                let next =
                    u32::from_le_bytes(entries[offset..offset + 4].try_into().unwrap()) as usize;
                let name_len =
                    u32::from_le_bytes(entries[offset + 60..offset + 64].try_into().unwrap())
                        as usize;
                let name = std::char::decode_utf16(
                    entries[offset + 64..offset + 64 + name_len]
                        .chunks_exact(2)
                        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]])),
                )
                .map(|character| character.unwrap())
                .collect::<String>();
                names.push(name);
                if next == 0 {
                    break;
                }
                offset += next;
            }
            names.sort();
            assert_eq!(names, ["alpha.txt", "nested"]);
            assert_eq!(
                super::native_nt_query_directory_file(
                    handle,
                    0,
                    0,
                    0,
                    io_status.as_mut_ptr(),
                    entries.as_mut_ptr(),
                    entries.len() as u32,
                    1,
                    0,
                    std::ptr::null(),
                    0,
                ),
                0x8000_0006
            );
            assert_eq!(
                super::native_nt_query_directory_file(
                    handle,
                    0,
                    0,
                    0,
                    io_status.as_mut_ptr(),
                    entries.as_mut_ptr(),
                    entries.len() as u32,
                    1,
                    0,
                    std::ptr::null(),
                    1,
                ),
                0
            );
            let mut fs = context.lock().unwrap();
            fs.handles.remove(&handle);
            fs.fs
                .delete_file(&format!(r"{directory}\alpha.txt"))
                .unwrap();
            fs.fs
                .delete_file(&format!(r"{directory}\nested\beta.txt"))
                .unwrap();
            fs.fs.rmdir(&format!(r"{directory}\nested")).unwrap();
            fs.fs.rmdir(directory).unwrap();
        }
    }

    #[test]
    fn get_file_information_by_handle_ex_reports_basic_metadata() {
        let path = r"C:\handle_ex_unit.txt";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(path, b"abcde".to_vec()).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };

        let mut standard = [0u8; 24];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                1,
                standard.as_mut_ptr(),
                standard.len() as u32,
            ),
            1
        );
        assert_eq!(i64::from_le_bytes(standard[8..16].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(standard[16..20].try_into().unwrap()), 1);
        assert_eq!(standard[21], 0);
        let mut file_size = -1i64;
        assert_eq!(super::native_get_file_size_ex(handle, &mut file_size), 1);
        assert_eq!(file_size, 5);

        let mut attrs = [0u8; 8];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                9,
                attrs.as_mut_ptr(),
                attrs.len() as u32,
            ),
            1
        );
        assert_eq!(u32::from_le_bytes(attrs[..4].try_into().unwrap()), 0x80);

        assert_eq!(
            super::native_get_file_information_by_handle_ex(handle, 1, standard.as_mut_ptr(), 8,),
            0
        );
        assert_eq!(super::native_get_last_error(), 122);

        let mut basic = [0u8; 40];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                0,
                basic.as_mut_ptr(),
                basic.len() as u32,
            ),
            1
        );
        assert_eq!(u32::from_le_bytes(basic[32..36].try_into().unwrap()), 0x80);

        let mut file_id = [0u8; 24];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                18,
                file_id.as_mut_ptr(),
                file_id.len() as u32,
            ),
            1
        );
        assert_eq!(
            u64::from_le_bytes(file_id[..8].try_into().unwrap()),
            0x5743_4C49
        );
        assert_eq!(
            u64::from_le_bytes(file_id[8..16].try_into().unwrap()),
            context.lock().unwrap().fs.file_id(path).unwrap()
        );
        assert_eq!(
            super::native_get_file_information_by_handle_ex(handle, 18, file_id.as_mut_ptr(), 8,),
            0
        );
        assert_eq!(super::native_get_last_error(), 122);
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                2,
                standard.as_mut_ptr(),
                standard.len() as u32,
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 87);
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                1,
                std::ptr::null_mut(),
                standard.len() as u32,
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 998);
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                u64::MAX,
                1,
                standard.as_mut_ptr(),
                standard.len() as u32,
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn get_file_information_by_handle_ex_reports_directory_metadata() {
        let path = r"C:\handle_ex_directory_unit";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.mkdir(path).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };

        let mut standard = [0u8; 24];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                1,
                standard.as_mut_ptr(),
                standard.len() as u32,
            ),
            1
        );
        assert_eq!(i64::from_le_bytes(standard[8..16].try_into().unwrap()), 0);
        assert_eq!(standard[21], 1);

        let mut attrs = [0u8; 8];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                9,
                attrs.as_mut_ptr(),
                attrs.len() as u32,
            ),
            1
        );
        assert_eq!(u32::from_le_bytes(attrs[..4].try_into().unwrap()), 0x10);

        let mut fs = context.lock().unwrap();
        fs.handles.remove(&handle);
        fs.fs.rmdir(path).unwrap();
    }

    #[test]
    fn create_file_supports_common_creation_dispositions() {
        let path = r"C:\create_disposition_unit.txt";
        let context = super::fs_ctx().unwrap();
        let wide_path = path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let create = |disposition| {
            super::native_create_file_w(wide_path.as_ptr(), 0, 0, 0, disposition, 0, 0)
        };

        let created = create(1); // CREATE_NEW
        assert_ne!(created, u64::MAX);
        assert!(context
            .lock()
            .unwrap()
            .fs
            .read_file(path)
            .unwrap()
            .is_empty());
        assert_eq!(super::native_close_handle(created), 1);
        assert_eq!(create(1), u64::MAX);
        assert_eq!(super::native_get_last_error(), 80);

        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"keep me".to_vec())
            .unwrap();
        let opened = create(4); // OPEN_ALWAYS preserves existing contents
        assert_ne!(opened, u64::MAX);
        assert_eq!(super::native_get_last_error(), 183);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"keep me"
        );
        let mut high = -1i32;
        assert_eq!(super::native_set_file_pointer(opened, -1, &mut high, 2), 6);
        assert_eq!(high, 0);
        assert_eq!(
            super::native_set_file_pointer(opened, 0, std::ptr::null_mut(), 0),
            0
        );
        assert_eq!(super::native_close_handle(opened), 1);

        let truncated = create(5); // TRUNCATE_EXISTING
        assert_ne!(truncated, u64::MAX);
        assert!(context
            .lock()
            .unwrap()
            .fs
            .read_file(path)
            .unwrap()
            .is_empty());
        assert_eq!(super::native_close_handle(truncated), 1);

        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_create_file_ansi_uses_windows_creation_dispositions() {
        let path = b"C:\\modern_create_file_ansi.txt\0";
        let context = super::fs_ctx().unwrap();
        let create =
            |disposition| super::native_create_file_a(path.as_ptr(), 0, 0, 0, disposition, 0, 0);

        let created = create(1); // CREATE_NEW
        assert_ne!(created, u64::MAX);
        assert_eq!(super::native_get_file_type(created), 1); // FILE_TYPE_DISK
        assert_eq!(super::native_close_handle(created), 1);
        assert_eq!(create(1), u64::MAX);
        assert_eq!(super::native_get_last_error(), 80); // ERROR_FILE_EXISTS

        context
            .lock()
            .unwrap()
            .fs
            .write_file(r"C:\modern_create_file_ansi.txt", b"preserve".to_vec())
            .unwrap();
        let opened = create(4); // OPEN_ALWAYS preserves existing data
        assert_ne!(opened, u64::MAX);
        assert_eq!(super::native_close_handle(opened), 1);
        assert_eq!(
            context
                .lock()
                .unwrap()
                .fs
                .read_file(r"C:\modern_create_file_ansi.txt")
                .unwrap(),
            b"preserve"
        );
        context
            .lock()
            .unwrap()
            .fs
            .delete_file(r"C:\modern_create_file_ansi.txt")
            .unwrap();
    }

    #[test]
    fn modern_find_first_file_ex_covers_all_reference_option_combinations() {
        let directory = r"C:\modern_find_ex_options";
        let pattern = format!(r"{directory}\*");
        let wide = |value: &str| value.encode_utf16().chain([0]).collect::<Vec<_>>();
        let pattern_wide = wide(&pattern);
        let context = super::fs_ctx().unwrap();
        {
            let mut fs = context.lock().unwrap();
            fs.fs.mkdir(directory).unwrap();
            fs.fs.mkdir(&format!(r"{directory}\nested")).unwrap();
            fs.fs
                .write_file(&format!(r"{directory}\Alpha.txt"), b"a".to_vec())
                .unwrap();
            fs.fs
                .write_file(&format!(r"{directory}\beta.bin"), b"b".to_vec())
                .unwrap();
        }

        for (info_level, search_op, flags) in [
            (0, 0, 0),
            (0, 0, 1),
            (0, 0, 2),
            (1, 0, 0),
            (0, 1, 0),
            (0, 1, 1),
            (0, 1, 2),
            (1, 1, 0),
        ] {
            let mut data = [0u8; 592];
            let find = super::native_find_first_file_ex_w(
                pattern_wide.as_ptr(),
                info_level,
                data.as_mut_ptr(),
                search_op,
                0,
                flags,
            );
            assert_ne!(find, u64::MAX, "{info_level}/{search_op}/{flags}");
            let mut names = Vec::new();
            loop {
                let encoded = unsafe {
                    std::slice::from_raw_parts(data.as_ptr().add(44).cast::<u16>(), 260)
                        .iter()
                        .copied()
                        .take_while(|unit| *unit != 0)
                        .collect::<Vec<_>>()
                };
                names.push(String::from_utf16(&encoded).unwrap());
                if super::native_find_next_file_w(find, data.as_mut_ptr()) == 0 {
                    break;
                }
            }
            names.sort();
            assert_eq!(
                names,
                ["Alpha.txt", "beta.bin", "nested"],
                "{info_level}/{search_op}/{flags}"
            );
            assert_eq!(super::native_find_close(find), 1);
        }

        let mut fs = context.lock().unwrap();
        fs.fs.remove(directory, true).unwrap();
        drop(fs);
    }

    #[test]
    fn modern_find_first_file_ex_reports_empty_missing_and_invalid_outputs() {
        let empty = r"C:\modern_find_ex_empty";
        let missing_pattern = r"C:\modern_find_ex_missing\*";
        let empty_pattern = format!(r"{empty}\*");
        let wide = |value: &str| value.encode_utf16().chain([0]).collect::<Vec<_>>();
        let empty_wide = wide(&empty_pattern);
        let missing_wide = wide(missing_pattern);
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(empty).unwrap();
        let mut data = [0u8; 592];

        assert_eq!(
            super::native_find_first_file_ex_w(empty_wide.as_ptr(), 0, data.as_mut_ptr(), 0, 0, 0,),
            u64::MAX
        );
        assert_eq!(super::native_get_last_error(), 2); // ERROR_FILE_NOT_FOUND
        assert_eq!(
            super::native_find_first_file_ex_w(
                missing_wide.as_ptr(),
                0,
                data.as_mut_ptr(),
                0,
                0,
                0,
            ),
            u64::MAX
        );
        assert_eq!(super::native_get_last_error(), 3); // ERROR_PATH_NOT_FOUND

        context
            .lock()
            .unwrap()
            .fs
            .write_file(&format!(r"{empty}\entry.txt"), b"x".to_vec())
            .unwrap();
        assert_eq!(
            super::native_find_first_file_ex_w(
                empty_wide.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                0,
            ),
            u64::MAX
        );
        assert_eq!(super::native_get_last_error(), 87); // ERROR_INVALID_PARAMETER

        let find =
            super::native_find_first_file_ex_w(empty_wide.as_ptr(), 0, data.as_mut_ptr(), 0, 0, 0);
        assert_ne!(find, u64::MAX);
        assert_eq!(
            super::native_find_next_file_w(u64::MAX, data.as_mut_ptr()),
            0
        );
        assert_eq!(super::native_find_close(find), 1);
        assert_eq!(super::native_find_close(find), 0);

        context.lock().unwrap().fs.remove(empty, true).unwrap();
    }

    #[test]
    fn modern_create_file_requires_backup_semantics_for_directory_handles() {
        let directory = r"C:\modern_create_file_directory_flags";
        let directory_wide = directory.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(directory).unwrap();

        let with_backup = super::native_create_file_w(
            directory_wide.as_ptr(),
            0,
            0,
            0,
            3,
            0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS
            0,
        );
        assert_ne!(with_backup, u64::MAX);
        assert_eq!(super::native_close_handle(with_backup), 1);

        let without_backup = super::native_create_file_w(
            directory_wide.as_ptr(),
            0,
            0,
            0,
            3, // OPEN_EXISTING
            0,
            0,
        );
        assert_eq!(without_backup, u64::MAX);
        assert_eq!(super::native_get_last_error(), 5); // ERROR_ACCESS_DENIED
        context.lock().unwrap().fs.remove(directory, true).unwrap();
    }

    #[test]
    fn modern_create_file_posix_directory_attributes_create_a_directory() {
        let directory = r"C:\modern_posix_directory_creation";
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(directory).unwrap();
        let posix_directory = format!(r"{directory}\posix-created");
        let posix_wide = posix_directory
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        let dispositions = [(1, true), (4, false), (5, false), (2, true)];
        let flags = [0x0200_0000, 0x0200_0010, 0x0300_0010, 0x0100_0010];
        let mut mismatches = Vec::new();
        for (disposition, cleanup) in dispositions {
            for flag in flags {
                let handle = super::native_create_file_w(
                    posix_wide.as_ptr(),
                    0x4000_0000,
                    0x0000_0004,
                    0,
                    disposition,
                    flag,
                    0,
                );
                if handle == u64::MAX {
                    mismatches.push(format!(
                        "disposition={disposition} flags={flag:#x}: open failed"
                    ));
                    continue;
                }
                let is_directory = context.lock().unwrap().fs.is_dir(&posix_directory);
                let expect_directory = disposition == 1 && flag == 0x0300_0010;
                if is_directory != expect_directory {
                    mismatches.push(format!(
                        "disposition={disposition} flags={flag:#x}: directory={is_directory}, expected={expect_directory}"
                    ));
                }
                assert_eq!(super::native_close_handle(handle), 1);
                if cleanup {
                    let mut fs = context.lock().unwrap();
                    if fs.fs.exists(&posix_directory) {
                        fs.fs.remove(&posix_directory, true).unwrap();
                    }
                }
            }
        }
        assert!(mismatches.is_empty(), "POSIX create cases: {mismatches:?}");
        context.lock().unwrap().fs.remove(directory, true).unwrap();
    }

    #[test]
    fn move_file_ex_honors_replace_existing_and_rejects_bad_flags() {
        let context = super::fs_ctx().unwrap();
        let source = r"C:\move_file_ex_source.txt";
        let destination = r"C:\move_file_ex_destination.txt";
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.write_file(source, b"new".to_vec()).unwrap();
            ctx.fs.write_file(destination, b"old".to_vec()).unwrap();
        }
        let source_wide = source
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let destination_wide = destination
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        assert_eq!(
            super::native_move_file_ex_w(source_wide.as_ptr(), destination_wide.as_ptr(), 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 183);
        assert_eq!(
            super::native_move_file_ex_w(source_wide.as_ptr(), destination_wide.as_ptr(), 1),
            1
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"new"
        );
        assert!(!context.lock().unwrap().fs.exists(source));
        assert_eq!(
            super::native_move_file_ex_w(source_wide.as_ptr(), destination_wide.as_ptr(), 4),
            0
        );
        assert_eq!(super::native_get_last_error(), 50);
        context.lock().unwrap().fs.delete_file(destination).unwrap();
    }

    #[test]
    fn win32_file_copy_move_enumerate_and_delete_roundtrip() {
        let directory = r"C:\winfs_compat_file_api_cases";
        let source = r"C:\winfs_compat_file_api_cases\source.txt";
        let copy = r"C:\winfs_compat_file_api_cases\copy.txt";
        let moved = r"C:\winfs_compat_file_api_cases\moved.txt";
        let wide = |value: &str| value.encode_utf16().chain([0]).collect::<Vec<_>>();
        let directory_wide = wide(directory);
        let source_wide = wide(source);
        let copy_wide = wide(copy);
        let moved_wide = wide(moved);
        let context = super::fs_ctx().unwrap();
        assert_eq!(
            super::native_create_directory_w(directory_wide.as_ptr(), 0),
            1
        );
        assert_eq!(
            super::native_create_directory_w(directory_wide.as_ptr(), 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 183);

        let file = super::native_create_file_w(source_wide.as_ptr(), 0xC000_0000, 0, 0, 1, 0, 0);
        assert_ne!(file, u64::MAX);
        let payload = b"winfs-file-api";
        let mut written = 0;
        assert_eq!(
            super::native_write_file(
                file,
                payload.as_ptr(),
                payload.len() as u32,
                &mut written,
                0
            ),
            1
        );
        assert_eq!(written as usize, payload.len());
        assert_eq!(
            super::native_set_file_pointer(file, 0, std::ptr::null_mut(), 0),
            0
        );
        let mut read_buffer = [0u8; 32];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(
                file,
                read_buffer.as_mut_ptr(),
                payload.len() as u32,
                &mut read,
                0
            ),
            1
        );
        assert_eq!(read as usize, payload.len());
        assert_eq!(&read_buffer[..read as usize], payload);
        let mut size = -1;
        assert_eq!(super::native_get_file_size_ex(file, &mut size), 1);
        assert_eq!(size, payload.len() as i64);
        assert_eq!(super::native_close_handle(file), 1);

        assert_eq!(
            super::native_copy_file_w(source_wide.as_ptr(), copy_wide.as_ptr(), 1),
            1
        );
        assert_eq!(
            super::native_copy_file_w(source_wide.as_ptr(), copy_wide.as_ptr(), 1),
            0
        );
        assert_eq!(context.lock().unwrap().fs.read_file(copy).unwrap(), payload);
        assert_eq!(
            super::native_move_file_w(copy_wide.as_ptr(), moved_wide.as_ptr()),
            1
        );
        assert!(!context.lock().unwrap().fs.exists(copy));

        let pattern = wide(r"C:\winfs_compat_file_api_cases\*");
        let mut find_data = [0u8; 592];
        let find = super::native_find_first_file_ex_w(
            pattern.as_ptr(),
            0,
            find_data.as_mut_ptr(),
            0,
            0,
            0,
        );
        assert_ne!(find, u64::MAX);
        let mut names = Vec::new();
        loop {
            let name = unsafe {
                std::slice::from_raw_parts(find_data.as_ptr().add(44).cast::<u16>(), 260)
                    .iter()
                    .copied()
                    .take_while(|unit| *unit != 0)
                    .collect::<Vec<_>>()
            };
            names.push(String::from_utf16(&name).unwrap());
            if super::native_find_next_file_w(find, find_data.as_mut_ptr()) == 0 {
                break;
            }
        }
        names.sort();
        assert_eq!(names, ["moved.txt", "source.txt"]);
        assert_eq!(super::native_find_close(find), 1);

        assert_eq!(super::native_delete_file_w(source_wide.as_ptr()), 1);
        assert_eq!(super::native_delete_file_w(moved_wide.as_ptr()), 1);
        assert_eq!(super::native_remove_directory_w(directory_wide.as_ptr()), 1);
        assert!(!context.lock().unwrap().fs.exists(directory));
    }

    #[test]
    fn win32_read_only_handle_rejects_write() {
        let path = r"C:\winfs_compat_readonly_access.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"read-only".to_vec())
            .unwrap();

        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut written = 0;
        let write = super::native_write_file(handle, b"x".as_ptr(), 1, &mut written, 0);
        assert_eq!(write, 0, "a GENERIC_READ handle must not allow writes");
        assert_eq!(super::native_get_last_error(), 5);
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn win32_share_mode_rejects_conflicting_open() {
        let path = r"C:\winfs_compat_sharing.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"shared".to_vec())
            .unwrap();

        let first = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 0, 0, 3, 0, 0);
        assert_ne!(first, u64::MAX);
        let conflicting = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 0, 0, 3, 0, 0);
        assert_eq!(conflicting, u64::MAX);
        assert_eq!(super::native_get_last_error(), 32);
        assert_eq!(super::native_close_handle(first), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn win32_find_first_file_filters_the_requested_name_pattern() {
        let directory = r"C:\winfs_compat_find_pattern";
        let directory_wide = directory.encode_utf16().chain([0]).collect::<Vec<_>>();
        let pattern = r"C:\winfs_compat_find_pattern\*.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.mkdir(directory).unwrap();
            ctx.fs
                .write_file(r"C:\winfs_compat_find_pattern\match.txt", b"x".to_vec())
                .unwrap();
            ctx.fs
                .write_file(r"C:\winfs_compat_find_pattern\ignore.bin", b"y".to_vec())
                .unwrap();
        }

        let mut data = [0u8; 592];
        let find =
            super::native_find_first_file_ex_w(pattern.as_ptr(), 0, data.as_mut_ptr(), 0, 0, 0);
        assert_ne!(find, u64::MAX);
        let name = unsafe {
            std::slice::from_raw_parts(data.as_ptr().add(44).cast::<u16>(), 260)
                .iter()
                .copied()
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>()
        };
        let mut names = vec![String::from_utf16(&name).unwrap()];
        while super::native_find_next_file_w(find, data.as_mut_ptr()) != 0 {
            let name = unsafe {
                std::slice::from_raw_parts(data.as_ptr().add(44).cast::<u16>(), 260)
                    .iter()
                    .copied()
                    .take_while(|unit| *unit != 0)
                    .collect::<Vec<_>>()
            };
            names.push(String::from_utf16(&name).unwrap());
        }
        assert_eq!(super::native_find_close(find), 1);
        assert_eq!(names, ["match.txt"]);

        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file(r"C:\winfs_compat_find_pattern\match.txt")
            .unwrap();
        ctx.fs
            .delete_file(r"C:\winfs_compat_find_pattern\ignore.bin")
            .unwrap();
        drop(ctx);
        assert_eq!(super::native_remove_directory_w(directory_wide.as_ptr()), 1);
    }

    #[test]
    fn win32_set_file_time_accepts_a_guest_file_handle() {
        let path = r"C:\winfs_compat_set_time.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"time".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let timestamp = 132_537_600_000_000_000u64;
        assert_eq!(
            super::native_set_file_time(handle, &timestamp, &timestamp, &timestamp),
            1
        );
        let metadata = context.lock().unwrap().fs.file_metadata(path);
        assert_eq!(metadata.creation_time, timestamp);
        assert_eq!(metadata.access_time, timestamp);
        assert_eq!(metadata.write_time, timestamp);
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn win32_readonly_attribute_blocks_delete_file() {
        let path = r"C:\winfs_compat_readonly_delete.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"keep".to_vec())
            .unwrap();

        assert_eq!(super::native_set_file_attributes_w(wide.as_ptr(), 1), 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 0);
        assert_eq!(super::native_get_last_error(), 5);
        assert!(context.lock().unwrap().fs.exists(path));
        assert_eq!(super::native_set_file_attributes_w(wide.as_ptr(), 0x80), 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 1);
    }

    #[test]
    fn win32_get_final_path_supports_size_query_and_extended_path() {
        let path = r"C:\winfs_compat_final_path.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"path".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let required =
            super::native_get_final_path_name_by_handle_w(handle, std::ptr::null_mut(), 0, 0);
        assert_eq!(
            required as usize,
            r"\\?\C:\winfs_compat_final_path.txt".encode_utf16().count() + 1
        );
        let mut short = vec![0xaaaa; required as usize - 1];
        assert_eq!(
            super::native_get_final_path_name_by_handle_w(
                handle,
                short.as_mut_ptr(),
                short.len() as u32,
                0,
            ),
            required
        );
        assert!(short.iter().all(|unit| *unit == 0xaaaa));
        let mut output = vec![0u16; required as usize];
        let written = super::native_get_final_path_name_by_handle_w(
            handle,
            output.as_mut_ptr(),
            output.len() as u32,
            0,
        );
        assert_eq!(written + 1, required);
        assert_eq!(
            String::from_utf16(&output[..written as usize]).unwrap(),
            r"\\?\C:\winfs_compat_final_path.txt"
        );
        let mut dos_path = vec![0u16; required as usize];
        let dos_written = super::native_get_final_path_name_by_handle_w(
            handle,
            dos_path.as_mut_ptr(),
            dos_path.len() as u32,
            1,
        );
        assert_eq!(dos_written, written);
        assert_eq!(
            &dos_path[..dos_written as usize],
            &output[..written as usize]
        );
        assert_eq!(
            super::native_get_final_path_name_by_handle_w(
                u64::MAX,
                output.as_mut_ptr(),
                output.len() as u32,
                0,
            ),
            0
        );

        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn nt_set_end_of_file_truncates_and_extends_guest_files() {
        let path = r"C:\winfs_compat_eof_resize.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"abcdef".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let mut io_status = [0u8; 16];
        let mut eof = 3i64;
        let truncated = super::native_nt_set_information_file(
            handle,
            io_status.as_mut_ptr(),
            (&mut eof as *mut i64).cast(),
            8,
            20, // FileEndOfFileInformation
        );
        assert_eq!(truncated, 0);
        assert_eq!(context.lock().unwrap().fs.read_file(path).unwrap(), b"abc");

        eof = 6;
        let extended = super::native_nt_set_information_file(
            handle,
            io_status.as_mut_ptr(),
            (&mut eof as *mut i64).cast(),
            8,
            20,
        );
        assert_eq!(extended, 0);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"abc\0\0\0"
        );
        assert_eq!(super::native_close_handle(handle), 1);
    }

    #[test]
    fn nt_set_file_rename_information_renames_by_open_handle() {
        let source = r"C:\winfs_compat_rename_source.txt";
        let destination = r"C:\winfs_compat_rename_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"rename-me".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(source_wide.as_ptr(), 0xC000_0000, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        // FILE_RENAME_INFORMATION: ReplaceIfExists, RootDirectory,
        // FileNameLength, then the UTF-16 destination path.
        let encoded = destination.encode_utf16().collect::<Vec<_>>();
        let mut information = vec![0u8; 20 + encoded.len() * 2];
        information[16..20].copy_from_slice(&((encoded.len() * 2) as u32).to_le_bytes());
        for (index, unit) in encoded.iter().enumerate() {
            information[20 + index * 2..22 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        let mut io_status = [0u8; 16];
        let status = super::native_nt_set_information_file(
            handle,
            io_status.as_mut_ptr(),
            information.as_ptr(),
            information.len() as u32,
            10, // FileRenameInformation
        );
        assert_eq!(status, 0);
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"rename-me"
        );
        assert!(!context.lock().unwrap().fs.exists(source));
        assert_eq!(super::native_close_handle(handle), 1);
    }

    #[test]
    fn nt_set_end_of_file_rejects_shrinking_an_active_mapped_view() {
        let path = r"C:\winfs_compat_eof_mapped.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"12345678".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mapping = super::native_create_file_mapping_w(handle, 0, 0x04, 0, 8, std::ptr::null());
        assert_ne!(mapping, 0);
        let view = super::native_map_view_of_file(mapping, 0x2, 0, 0, 8);
        assert!(!view.is_null());

        let mut io_status = [0u8; 16];
        let mut eof = 4i64;
        let status = super::native_nt_set_information_file(
            handle,
            io_status.as_mut_ptr(),
            (&mut eof as *mut i64).cast(),
            8,
            20,
        );
        assert_eq!(super::native_unmap_view_of_file(view.cast()), 1);
        assert_eq!(super::native_close_handle(mapping), 1);
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(status, 0xC000_0022); // STATUS_ACCESS_DENIED while mapped
    }

    #[test]
    fn file_mapping_views_read_and_commit_guest_file_bytes() {
        let path = r"C:\file_mapping_unit.txt";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(path, b"abcdef".to_vec()).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };
        let mapping = super::native_create_file_mapping_w(handle, 0, 0x04, 0, 6, std::ptr::null());
        assert_ne!(mapping, 0);
        let view = super::native_map_view_of_file(mapping, 0x2, 0, 0, 0);
        assert!(!view.is_null());
        unsafe {
            assert_eq!(std::slice::from_raw_parts(view, 6), b"abcdef");
            view.add(1).write(b'Z');
        }
        assert_eq!(super::native_flush_view_of_file(view.cast(), 0), 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"aZcdef"
        );
        assert_eq!(super::native_unmap_view_of_file(view.cast()), 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"aZcdef"
        );
        assert_eq!(super::native_close_handle(mapping), 1);

        let extended = super::native_create_file_mapping_w(handle, 0, 0x04, 0, 9, std::ptr::null());
        assert_ne!(extended, 0);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"aZcdef\0\0\0"
        );
        let view = super::native_map_view_of_file(extended, 0x2, 0, 6, 3);
        assert!(!view.is_null());
        unsafe { std::ptr::copy_nonoverlapping(b"xyz".as_ptr(), view, 3) };
        assert_eq!(super::native_unmap_view_of_file(view.cast()), 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"aZcdefxyz"
        );
        assert_eq!(super::native_close_handle(extended), 1);

        let mut fs = context.lock().unwrap();
        fs.handles.remove(&handle);
        fs.fs.delete_file(path).unwrap();
    }

    #[test]
    fn overlapped_offset_combines_both_dwords() {
        let mut overlapped = [0u8; 32];
        overlapped[16..20].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
        overlapped[20..24].copy_from_slice(&0x1234u32.to_le_bytes());
        assert_eq!(
            super::native_overlapped_offset(overlapped.as_ptr() as u64),
            Some(0x1234_89ab_cdefusize)
        );
    }

    #[test]
    fn overlapped_result_reports_pending_completion_and_bad_handle() {
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: r"C:\pending_result.txt".into(),
                    offset: 0,
                    overlapped: true,
                    completion: None,
                },
            );
            handle
        };
        let mut ov = [0u64; 4];
        let pointer = ov.as_mut_ptr() as u64;
        super::native_set_overlapped_status(pointer, super::STATUS_PENDING, 0);
        let mut bytes = 99;
        assert_eq!(
            super::native_get_overlapped_result(handle, pointer, &mut bytes, 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 996);
        super::native_set_overlapped_status(pointer, 0, 7);
        assert_eq!(
            super::native_get_overlapped_result(handle, pointer, &mut bytes, 0),
            1
        );
        assert_eq!(bytes, 7);
        context.lock().unwrap().handles.remove(&handle);
        assert_eq!(
            super::native_get_overlapped_result(handle, pointer, &mut bytes, 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn overlapped_event_resets_before_io_and_signals_on_completion() {
        let handle = super::native_create_event_w(0, 1, 1, std::ptr::null());
        assert_ne!(handle, 0);
        assert_eq!(super::native_wait_for_single_object(handle, 0), 0);
        let mut ov = [0u64; 4];
        ov[3] = handle | 1;
        let event = super::native_prepare_overlapped_event(ov.as_ptr() as u64)
            .unwrap()
            .unwrap();
        assert_eq!(super::native_wait_for_single_object(handle, 0), 258);
        super::native_signal_event(&event);
        assert_eq!(super::native_wait_for_single_object(handle, 0), 0);
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(
            super::native_prepare_overlapped_event(ov.as_ptr() as u64).err(),
            Some(6)
        );
    }

    #[test]
    fn file_io_queue_reaches_its_fixed_capacity() {
        let process = super::process_ctx().unwrap();
        let file = super::NativeFile {
            path: r"C:\queue_unit.txt".into(),
            offset: 0,
            overlapped: true,
            completion: None,
        };
        let mut state = super::NativeFileIoQueueState {
            jobs: std::collections::VecDeque::new(),
            stop: false,
        };
        for _ in 0..super::MAX_QUEUED_FILE_IO {
            assert!(!super::native_file_io_queue_full(&state));
            state.jobs.push_back(super::NativeFileIoJob {
                process: std::sync::Arc::clone(&process),
                request: std::sync::Arc::new(super::NativePendingIo {
                    handle: 0,
                    overlapped: 0,
                    cancelled: super::AtomicBool::new(false),
                    issuer: std::thread::current().id(),
                }),
                file: file.clone(),
                overlapped: 0,
                event: None,
                offset: 0,
                operation: super::NativeFileIoOperation::Write { data: Vec::new() },
            });
        }
        assert!(super::native_file_io_queue_full(&state));
        let queue = super::NativeFileIoQueue {
            state: std::sync::Mutex::new(state),
            ready: std::sync::Condvar::new(),
        };
        let mut ov = [0u64; 4];
        ov[0] = 0x77;
        ov[3] = 0xdead; // invalid event must not be consulted when the queue is full
        assert_eq!(
            super::native_enqueue_file_io(
                &queue,
                &process,
                0,
                file,
                ov.as_mut_ptr() as u64,
                0,
                super::NativeFileIoOperation::Write { data: Vec::new() },
            ),
            Err(8)
        );
        assert_eq!(ov[0], 0x77);
        let mut state = queue.state.lock().unwrap();
        state.jobs.pop_front();
        assert!(!super::native_file_io_queue_full(&state));
    }

    #[test]
    fn queued_file_io_cancellation_signals_event_and_posts_failure() {
        let process = super::process_ctx().unwrap();
        let port = std::sync::Arc::new(super::NativeCompletionPort {
            queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
            ready: std::sync::Condvar::new(),
        });
        let file = super::NativeFile {
            path: r"C:\cancel_unit.txt".into(),
            offset: 0,
            overlapped: true,
            completion: Some((std::sync::Arc::clone(&port), 0x1234)),
        };
        let handle = {
            let mut fs = process.fs.lock().unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(handle, file.clone());
            handle
        };
        let event_handle = super::native_create_event_w(0, 1, 0, std::ptr::null());
        assert_ne!(event_handle, 0);
        let mut ov = [0u64; 4];
        ov[3] = event_handle;
        let pointer = ov.as_mut_ptr() as u64;
        let event = super::native_prepare_overlapped_event(pointer).unwrap();
        super::native_set_overlapped_status(pointer, super::STATUS_PENDING, 0);
        let request = std::sync::Arc::new(super::NativePendingIo {
            handle,
            overlapped: pointer,
            cancelled: super::AtomicBool::new(false),
            issuer: std::thread::current().id(),
        });
        process
            .pending_requests
            .lock()
            .unwrap()
            .insert((handle, pointer), std::sync::Arc::clone(&request));
        let before = process
            .pending_file_io
            .fetch_add(1, super::Ordering::AcqRel);
        let queue = super::NativeFileIoQueue {
            state: std::sync::Mutex::new(super::NativeFileIoQueueState {
                jobs: std::collections::VecDeque::from([super::NativeFileIoJob {
                    process: std::sync::Arc::clone(&process),
                    request,
                    file,
                    overlapped: pointer,
                    event,
                    offset: 0,
                    operation: super::NativeFileIoOperation::Write { data: Vec::new() },
                }]),
                stop: false,
            }),
            ready: std::sync::Condvar::new(),
        };
        let another_issuer = std::thread::spawn(|| std::thread::current().id())
            .join()
            .unwrap();
        assert_eq!(
            super::native_cancel_file_io_requests(
                &process,
                &queue,
                handle,
                pointer,
                Some(another_issuer),
            ),
            Err(1168)
        );
        assert_eq!(
            super::native_overlapped_status(pointer),
            super::STATUS_PENDING
        );
        assert_eq!(
            super::native_cancel_file_io_requests(
                &process,
                &queue,
                handle,
                pointer,
                Some(std::thread::current().id()),
            ),
            Ok(())
        );
        assert_eq!(
            super::native_overlapped_status(pointer),
            super::STATUS_CANCELLED
        );
        let mut bytes = 9;
        assert_eq!(
            super::native_get_overlapped_result(handle, pointer, &mut bytes, 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 995);
        assert_eq!(super::native_wait_for_single_object(event_handle, 0), 0);
        let packet = port.queue.lock().unwrap().pop_front().unwrap();
        assert_eq!(
            (packet.key, packet.overlapped, packet.bytes, packet.status),
            (0x1234, pointer, 0, super::STATUS_CANCELLED)
        );
        assert!(queue.state.lock().unwrap().jobs.is_empty());
        assert!(!process
            .pending_requests
            .lock()
            .unwrap()
            .contains_key(&(handle, pointer)));
        assert_eq!(
            process.pending_file_io.load(super::Ordering::Acquire),
            before
        );
        assert_eq!(
            super::native_cancel_file_io_requests(&process, &queue, handle, pointer, None),
            Err(1168)
        );
        assert_eq!(super::native_close_handle(event_handle), 1);
        process.fs.lock().unwrap().handles.remove(&handle);
    }

    #[test]
    fn last_error_is_private_to_each_native_thread() {
        native_set_last_error(87);
        let other = std::thread::spawn(|| {
            assert_eq!(native_get_last_error(), 0);
            native_set_last_error(6);
            native_get_last_error()
        });
        assert_eq!(other.join().unwrap(), 6);
        assert_eq!(native_get_last_error(), 87);
        native_set_last_error(0);
    }

    #[test]
    fn rejects_unsupported_windows_page_protections() {
        assert_eq!(linux_protection(0x08), None);
        assert_eq!(linux_protection(0x100), None);
    }

    #[test]
    fn tick_count_apis_report_monotonic_milliseconds() {
        let before = super::native_get_tick_count64();
        let tick32 = super::native_get_tick_count();
        let after = super::native_get_tick_count64();
        assert!(after >= before);
        assert!(tick32.wrapping_sub(before as u32) < 1000);
        assert!(super::baseline_trampoline("GetTickCount").is_some());
        assert!(super::baseline_trampoline("GetTickCount64").is_some());
    }

    #[test]
    fn user32_message_beep_is_a_successful_headless_noop() {
        assert!(super::supports_import("USER32.DLL", "MessageBeep"));
        assert_ne!(super::native_message_beep(0), 0);
    }

    #[test]
    fn crt_strncmp_compares_unsigned_bytes_within_the_requested_limit() {
        let left = b"nano\0";
        let same_prefix = b"name\0";
        let non_ascii = [0x80, 0];
        let ascii = [0x7f, 0];
        assert_eq!(
            super::native_crt_strncmp(left.as_ptr(), same_prefix.as_ptr(), 2),
            0
        );
        assert!(super::native_crt_strncmp(left.as_ptr(), same_prefix.as_ptr(), 3) > 0);
        assert!(super::native_crt_strncmp(non_ascii.as_ptr(), ascii.as_ptr(), 1) > 0);
        assert_eq!(
            super::native_crt_strncmp(std::ptr::null(), std::ptr::null(), 0),
            0
        );
    }

    #[test]
    fn crt_setlocale_exposes_the_supported_c_locale() {
        let c_locale = b"C\0";
        let locale = super::native_crt_setlocale(0, c_locale.as_ptr());
        assert!(!locale.is_null());
        assert_eq!(unsafe { std::slice::from_raw_parts(locale, 2) }, b"C\0");
        assert_eq!(super::native_crt_setlocale(0, std::ptr::null()), locale);
        assert!(super::native_crt_setlocale(6, std::ptr::null()).is_null());
        assert!(super::native_crt_setlocale(0, b"fr_FR\0".as_ptr()).is_null());
    }

    #[test]
    fn crt_strchr_finds_bytes_and_the_terminating_nul() {
        let text = b"nano\0";
        let found = super::native_crt_strchr(text.as_ptr(), b'n' as i32);
        assert_eq!(found, text.as_ptr() as *mut u8);
        assert_eq!(super::native_crt_strchr(text.as_ptr(), 0), unsafe {
            text.as_ptr().add(text.len() - 1) as *mut u8
        });
        assert!(super::native_crt_strchr(text.as_ptr(), b'z' as i32).is_null());
    }

    #[test]
    fn crt_strrchr_returns_the_last_matching_byte() {
        let text = b"nanometer\0";
        assert_eq!(
            super::native_crt_strrchr(text.as_ptr(), b'e' as i32),
            unsafe { text.as_ptr().add(7) as *mut u8 }
        );
        assert_eq!(super::native_crt_strrchr(text.as_ptr(), 0), unsafe {
            text.as_ptr().add(text.len() - 1) as *mut u8
        });
        assert!(super::native_crt_strrchr(text.as_ptr(), b'z' as i32).is_null());
    }

    #[test]
    fn crt_case_insensitive_string_comparisons_fold_ascii() {
        let upper = b"NaNo\0";
        let lower = b"nano\0";
        assert_eq!(super::native_crt_stricmp(upper.as_ptr(), lower.as_ptr()), 0);
        assert_eq!(
            super::native_crt_strnicmp(upper.as_ptr(), b"NAtch\0".as_ptr(), 2),
            0
        );
        assert!(super::native_crt_strnicmp(upper.as_ptr(), b"NAtch\0".as_ptr(), 3) < 0);
    }

    #[test]
    fn crt_atoi_parses_signed_decimal_prefixes() {
        assert_eq!(super::native_crt_atoi(b"  -42tail\0".as_ptr()), -42);
        assert_eq!(super::native_crt_atoi(b"+17\0".as_ptr()), 17);
        assert_eq!(super::native_crt_atoi(b"tail\0".as_ptr()), 0);
        assert_eq!(super::native_crt_atoi(std::ptr::null()), 0);
    }

    #[test]
    fn crt_case_conversion_matches_the_c_locale() {
        assert_eq!(super::native_crt_tolower(b'Q' as i32), b'q' as i32);
        assert_eq!(super::native_crt_tolower(b'?' as i32), b'?' as i32);
        assert_eq!(super::native_crt_toupper(b'q' as i32), b'Q' as i32);
        assert_eq!(super::native_crt_toupper(-1), -1);
    }

    #[test]
    fn crt_strncpy_zero_pads_short_sources() {
        let input = b"xy\0";
        let mut output = [0xff; 5];
        assert_eq!(
            super::native_crt_strncpy(output.as_mut_ptr(), input.as_ptr(), output.len()),
            output.as_mut_ptr()
        );
        assert_eq!(output, [b'x', b'y', 0, 0, 0]);
        let mut truncated = [0; 2];
        super::native_crt_strncpy(truncated.as_mut_ptr(), input.as_ptr(), 2);
        assert_eq!(truncated, [b'x', b'y']);
    }

    #[test]
    fn crt_calloc_zeroes_and_checks_size_overflow() {
        let allocation = super::native_crt_calloc(4, 2).cast::<u8>();
        assert!(!allocation.is_null());
        assert_eq!(
            unsafe { std::slice::from_raw_parts(allocation, 8) },
            &[0; 8]
        );
        super::native_crt_free(allocation.cast());
        assert!(super::native_crt_calloc(usize::MAX, 2).is_null());
    }

    #[test]
    fn crt_fwrite_handles_empty_and_overflowing_requests() {
        assert_eq!(
            super::native_crt_fwrite(std::ptr::null(), 0, 5, std::ptr::null_mut()),
            0
        );
        assert_eq!(
            super::native_crt_fwrite(std::ptr::null(), usize::MAX, 2, std::ptr::null_mut()),
            0
        );
    }

    #[test]
    fn crt_sprintf_formats_strings_integers_and_escaped_percent() {
        let name = b"nano\0";
        let format = b"%s:%04d %%\0";
        let mut output = [0u8; 32];
        let written = super::native_crt_sprintf(
            output.as_mut_ptr(),
            format.as_ptr(),
            name.as_ptr() as u64,
            (-7i32 as i64) as u64,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        assert_eq!(written, 11);
        assert_eq!(&output[..written as usize], b"nano:-007 %");
    }

    #[test]
    fn crt_strdup_returns_an_independent_nul_terminated_copy() {
        let input = b"nano\0";
        let duplicate = super::native_crt_strdup(input.as_ptr());
        assert!(!duplicate.is_null());
        assert_ne!(duplicate, input.as_ptr() as *mut u8);
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(duplicate.cast()) }.to_bytes(),
            b"nano"
        );
        super::native_crt_free(duplicate.cast());
        assert!(super::native_crt_strdup(std::ptr::null()).is_null());
    }

    #[test]
    fn crt_realloc_preserves_existing_bytes() {
        let allocation = super::native_crt_malloc(2).cast::<u8>();
        assert!(!allocation.is_null());
        unsafe { std::ptr::copy_nonoverlapping(b"ok".as_ptr(), allocation, 2) };
        let grown = super::native_crt_realloc(allocation.cast(), 8).cast::<u8>();
        assert!(!grown.is_null());
        assert_eq!(unsafe { std::slice::from_raw_parts(grown, 2) }, b"ok");
        super::native_crt_free(grown.cast());
        let fresh = super::native_crt_realloc(std::ptr::null_mut(), 8);
        assert!(!fresh.is_null());
        super::native_crt_free(fresh);
    }

    #[test]
    fn crt_wcstombs_converts_c_locale_and_reports_unrepresentable_text() {
        let input = [b'n' as u16, b'a' as u16, b'n' as u16, b'o' as u16, 0];
        let mut output = [0xff; 5];
        assert_eq!(
            super::native_crt_wcstombs(output.as_mut_ptr(), input.as_ptr(), output.len()),
            4
        );
        assert_eq!(&output, b"nano\0");
        assert_eq!(
            super::native_crt_wcstombs(std::ptr::null_mut(), input.as_ptr(), 0),
            4
        );
        assert_eq!(
            super::native_crt_wcstombs(output.as_mut_ptr(), input.as_ptr(), 2),
            2
        );
        let non_ascii = [0x00e9, 0];
        assert_eq!(
            super::native_crt_wcstombs(output.as_mut_ptr(), non_ascii.as_ptr(), output.len()),
            usize::MAX
        );
        assert_eq!(super::THREAD_CRT_ERRNO.with(std::cell::Cell::get), 42);
    }

    #[test]
    fn crt_mbstowcs_converts_c_locale_and_reports_unrepresentable_text() {
        let input = b"nano\0";
        let mut output = [u16::MAX; 5];
        assert_eq!(
            super::native_crt_mbstowcs(output.as_mut_ptr(), input.as_ptr(), output.len()),
            4
        );
        assert_eq!(
            &output,
            &[b'n' as u16, b'a' as u16, b'n' as u16, b'o' as u16, 0]
        );
        assert_eq!(
            super::native_crt_mbstowcs(std::ptr::null_mut(), input.as_ptr(), 0),
            4
        );
        assert_eq!(
            super::native_crt_mbstowcs(output.as_mut_ptr(), input.as_ptr(), 2),
            2
        );
        assert_eq!(
            super::native_crt_mbstowcs(output.as_mut_ptr(), b"\xe9\0".as_ptr(), output.len()),
            usize::MAX
        );
        assert_eq!(super::THREAD_CRT_ERRNO.with(std::cell::Cell::get), 42);
    }

    #[test]
    fn crt_stat64_reports_winfs_file_type_and_size() {
        let context = super::fs_ctx().unwrap();
        let path = r"C:\stat64_probe.txt";
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"probe".to_vec())
            .unwrap();
        let path = b"C:\\stat64_probe.txt\0";
        let mut status = [0u8; 56];
        assert_eq!(
            super::native_crt_stat64(path.as_ptr(), status.as_mut_ptr()),
            0
        );
        assert_eq!(u32::from_ne_bytes(status[..4].try_into().unwrap()), 2);
        assert_eq!(u16::from_ne_bytes(status[6..8].try_into().unwrap()), 0x8180);
        assert_eq!(i64::from_ne_bytes(status[24..32].try_into().unwrap()), 5);
        assert_eq!(
            super::native_crt_stat64(b"C:\\missing-stat64\0".as_ptr(), status.as_mut_ptr()),
            -1
        );
        assert_eq!(super::THREAD_CRT_ERRNO.with(std::cell::Cell::get), 2);
        context
            .lock()
            .unwrap()
            .fs
            .delete_file(r"C:\stat64_probe.txt")
            .unwrap();
    }

    #[test]
    fn crt_access_checks_winfs_paths_and_validates_modes() {
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(r"C:\access_probe.txt", b"x".to_vec())
            .unwrap();
        assert_eq!(
            super::native_crt_access(b"C:\\access_probe.txt\0".as_ptr(), 0),
            0
        );
        assert_eq!(
            super::native_crt_access(b"C:\\missing-access\0".as_ptr(), 0),
            -1
        );
        assert_eq!(
            super::native_crt_access(b"C:\\access_probe.txt\0".as_ptr(), 1),
            -1
        );
        assert_eq!(super::THREAD_CRT_ERRNO.with(std::cell::Cell::get), 22);
        context
            .lock()
            .unwrap()
            .fs
            .delete_file(r"C:\access_probe.txt")
            .unwrap();
    }

    #[test]
    fn crt_signal_records_handlers_per_process_and_rejects_invalid_numbers() {
        let process_id = super::process_ctx().unwrap().process_id;
        assert_eq!(super::native_crt_signal(2, 0x1234), 0);
        assert_eq!(super::native_crt_signal(2, 0x5678), 0x1234);
        assert_eq!(super::native_crt_signal(2, 0), 0x5678);
        assert_eq!(super::native_crt_signal(0, 0x1234), u64::MAX);
        assert!(super::supports_import("msvcrt.dll", "signal"));
        assert!(super::supports_import("MSVCRT.DLL", "signal"));
        super::NATIVE_CRT_SIGNAL_HANDLERS
            .lock()
            .unwrap()
            .remove(&(process_id, 2));
    }

    #[test]
    fn crt_errno_returns_thread_local_storage() {
        let errno = super::native_crt_errno();
        unsafe { errno.write(22) };
        let other_value = std::thread::spawn(|| {
            let other_errno = super::native_crt_errno();
            unsafe {
                other_errno.write(5);
                other_errno.read()
            }
        })
        .join()
        .unwrap();
        assert_eq!(other_value, 5);
        assert_eq!(unsafe { errno.read() }, 22);
    }

    #[test]
    fn crt_iob_func_returns_the_static_stream_table() {
        assert_eq!(
            super::native_crt_iob_func(),
            super::NATIVE_CRT_IOB.as_ptr().cast_mut().cast()
        );
    }

    #[test]
    fn crt_getenv_reads_guest_environment_case_insensitively() {
        let key: Vec<u16> = "WINCLI_TEST_CRT_GETENV"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let value: Vec<u16> = "guest-value"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(
            super::native_set_environment_variable_w(key.as_ptr(), value.as_ptr()),
            1
        );
        let lookup = b"wincli_test_crt_getenv\0";
        let result = super::native_crt_getenv(lookup.as_ptr());
        assert!(!result.is_null());
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(result.cast()) }.to_bytes(),
            b"guest-value"
        );
        assert!(super::native_crt_getenv(b"WINCLI_MISSING_CRT_GETENV\0".as_ptr()).is_null());
        assert_eq!(
            super::native_set_environment_variable_w(key.as_ptr(), std::ptr::null()),
            1
        );
    }

    #[test]
    fn import_binding_checks_the_dll_as_well_as_the_function() {
        assert!(super::supports_import("MSVCRT.dll", "__lconv_init"));
        assert!(super::supports_import("MSVCRT.dll", "strncmp"));
        assert!(super::supports_import("MSVCRT.dll", "setlocale"));
        assert!(super::supports_import("MSVCRT.dll", "strchr"));
        assert!(super::supports_import("MSVCRT.dll", "strrchr"));
        assert!(super::supports_import("MSVCRT.dll", "_stricmp"));
        assert!(super::supports_import("MSVCRT.dll", "_strnicmp"));
        assert!(super::supports_import("MSVCRT.dll", "atoi"));
        assert!(super::supports_import("MSVCRT.dll", "tolower"));
        assert!(super::supports_import("MSVCRT.dll", "toupper"));
        assert!(super::supports_import("MSVCRT.dll", "strncpy"));
        assert!(super::supports_import("MSVCRT.dll", "mbstowcs"));
        assert!(super::supports_import("MSVCRT.dll", "calloc"));
        assert!(super::supports_import("MSVCRT.dll", "fwrite"));
        assert!(super::supports_import("MSVCRT.dll", "sprintf"));
        assert!(super::supports_import("MSVCRT.dll", "_errno"));
        assert!(super::supports_import("MSVCRT.dll", "getenv"));
        assert!(super::supports_import("MSVCRT.dll", "__iob_func"));
        assert!(super::supports_import("KERNEL32.dll", "ExitProcess"));
        assert!(super::supports_import("KERNEL32.dll", "GetShortPathNameW"));
        assert!(super::supports_import(
            "KERNEL32.dll",
            "GetConsoleCursorInfo"
        ));
        assert!(super::supports_import("KERNEL32.dll", "GetTickCount"));
        assert!(super::supports_import("KERNEL32.dll", "GetTickCount64"));
        assert!(super::supports_import(
            "KERNEL32.dll",
            "NeedCurrentDirectoryForExePathW"
        ));
        assert!(super::supports_import("WINMM.dll", "timeGetTime"));
        assert!(!super::supports_import("USER32.dll", "ExitProcess"));
        assert!(!super::supports_import("KERNEL32.dll", "timeGetTime"));
        assert!(!super::supports_import("KERNEL32.dll", "NoSuchApi"));
        assert!(super::supports_import("WS2_32.dll", "#4"));
        assert!(super::supports_import("WS2_32.dll", "#10"));
        assert!(super::supports_import("WS2_32.dll", "#11"));
    }

    #[test]
    fn modern_file_api_imports_are_registered_for_compatibility_coverage() {
        // Keep the modern file-operation surface visible to Rust tests.
        // A missing binding is reported as a test failure so the API can
        // be added to the compatibility suite before its implementation.
        let apis = [
            "GetTempPathA",
            "GetTempPathW",
            "GetTempFileNameA",
            "GetTempFileNameW",
            "CopyFileA",
            "CopyFileW",
            "CopyFileExW",
            "CopyFile2",
            "CreateFileA",
            "CreateFileW",
            "CreateFile2",
            "DeleteFileA",
            "DeleteFileW",
            "MoveFileA",
            "MoveFileW",
            "FindFirstFileA",
            "FindFirstFileW",
            "FindNextFileA",
            "FindNextFileW",
            "FindFirstFileExA",
            "FindFirstFileExW",
            "LockFile",
            "UnlockFile",
            "GetFileType",
            "RemoveDirectoryA",
            "RemoveDirectoryW",
            "ReplaceFileA",
            "ReplaceFileW",
            "GetFileInformationByHandleEx",
            "OpenFileById",
            "SetFileValidData",
            "WriteFileGather",
            "GetFinalPathNameByHandleA",
            "GetFinalPathNameByHandleW",
            "SetFileInformationByHandle",
            "GetFileAttributesExW",
            "SetFileTime",
            "ReOpenFile",
            "CreateHardLinkW",
            "CreateSymbolicLinkW",
            "SetEndOfFile",
            "SetFilePointer",
            "SetFilePointerEx",
            "GetFileSizeEx",
            "GetFileInformationByHandle",
            "FlushFileBuffers",
            "GetOverlappedResult",
            "GetOverlappedResultEx",
            "CreateFileMappingA",
            "CreateFileMappingW",
            "MapViewOfFile",
            "UnmapViewOfFile",
            "GetQueuedCompletionStatus",
            "GetQueuedCompletionStatusEx",
            "PostQueuedCompletionStatus",
            "FindFirstStreamW",
            "SetFileCompletionNotificationModes",
            "CreateHardLinkA",
            "CreateSymbolicLinkA",
            "SetFileAttributesA",
            "SetFileAttributesW",
            "CreateDirectoryW",
            "MoveFileExW",
            "ReadFile",
            "WriteFile",
        ];
        let missing = apis
            .into_iter()
            .filter(|api| !super::supports_import("KERNEL32.dll", api))
            .collect::<Vec<_>>();
        assert!(missing.is_empty(), "unbound modern file APIs: {missing:?}");
    }

    macro_rules! modern_file_binding_cases {
        ($($test_name:ident: [$($api:literal),+ $(,)?]),+ $(,)?) => {
            $(
                #[test]
                fn $test_name() {
                    let missing = [$($api),+]
                        .into_iter()
                        .filter(|api| !super::supports_import("KERNEL32.dll", api))
                        .collect::<Vec<_>>();
                    assert!(missing.is_empty(), "unbound APIs: {missing:?}");
                }
            )+
        };
    }

    modern_file_binding_cases! {
        modern_temp_file_name_apis_are_bound: ["GetTempPathA", "GetTempPathW", "GetTempFileNameA", "GetTempFileNameW"],
        modern_copy_file_variants_are_bound: ["CopyFileA", "CopyFile2", "CopyFileExW"],
        modern_create_file2_is_bound: ["CreateFile2"],
        modern_ansi_delete_and_move_apis_are_bound: ["DeleteFileA", "MoveFileA"],
        modern_ansi_enumeration_apis_are_bound: ["FindFirstFileA", "FindNextFileA"],
        modern_ansi_extended_enumeration_is_bound: ["FindFirstFileExA"],
        modern_file_lock_apis_are_bound: ["LockFile", "UnlockFile"],
        modern_file_replace_apis_are_bound: ["ReplaceFileA", "ReplaceFileW"],
        modern_open_file_by_id_is_bound: ["OpenFileById"],
        modern_set_file_valid_data_is_bound: ["SetFileValidData"],
        modern_write_file_gather_is_bound: ["WriteFileGather"],
        modern_ansi_final_path_api_is_bound: ["GetFinalPathNameByHandleA"],
        modern_set_file_information_by_handle_is_bound: ["SetFileInformationByHandle"],
        modern_stream_enumeration_is_bound: ["FindFirstStreamW"],
        modern_reopen_file_is_bound: ["ReOpenFile"],
        modern_hard_link_apis_are_bound: ["CreateHardLinkA", "CreateHardLinkW"],
        modern_symbolic_link_apis_are_bound: ["CreateSymbolicLinkA", "CreateSymbolicLinkW"],
        modern_set_end_of_file_api_is_bound: ["SetEndOfFile"],
        modern_flush_file_buffers_api_is_bound: ["FlushFileBuffers"],
        modern_extended_overlapped_result_api_is_bound: ["GetOverlappedResultEx"],
        modern_ansi_file_attributes_api_is_bound: ["SetFileAttributesA"],
    }

    #[test]
    fn modern_reopen_file_preserves_guest_file_contents() {
        type ReOpenFile = unsafe extern "win64" fn(u64, u32, u32, u32) -> u64;
        let reopen: ReOpenFile =
            unsafe { std::mem::transmute(require_kernel32_api(b"ReOpenFile\0") as usize) };
        let path = r"C:\modern_reopen_file.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"reopen-data".to_vec())
            .unwrap();

        let original = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(original, u64::MAX);
        let reopened = unsafe { reopen(original, 0x8000_0000, 7, 0) };
        assert_ne!(reopened, u64::MAX);
        assert_eq!(super::native_get_file_type(reopened), 1);

        let mut bytes = [0u8; 11];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(reopened, bytes.as_mut_ptr(), 11, &mut read, 0),
            1
        );
        assert_eq!(read, 11);
        assert_eq!(&bytes, b"reopen-data");
        assert_eq!(super::native_close_handle(reopened), 1);
        assert_eq!(super::native_close_handle(original), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_hard_link_shares_guest_file_identity_and_contents() {
        type CreateHardLinkW = unsafe extern "win64" fn(*const u16, *const u16, u64) -> i32;
        let create_link: CreateHardLinkW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateHardLinkW\0") as usize) };
        let source = r"C:\modern_hard_link_source.txt";
        let link = r"C:\modern_hard_link_alias.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let link_wide = link.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"linked-content".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { create_link(link_wide.as_ptr(), source_wide.as_ptr(), 0) },
            1
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(link).unwrap(),
            b"linked-content"
        );
        let source_handle =
            super::native_create_file_w(source_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        let link_handle =
            super::native_create_file_w(link_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(source_handle, u64::MAX);
        assert_ne!(link_handle, u64::MAX);
        let mut source_info = [0u8; 52];
        let mut link_info = [0u8; 52];
        assert_eq!(
            super::native_get_file_information_by_handle(source_handle, source_info.as_mut_ptr()),
            1
        );
        assert_eq!(
            super::native_get_file_information_by_handle(link_handle, link_info.as_mut_ptr()),
            1
        );
        assert_eq!(&source_info[44..52], &link_info[44..52]);
        assert_eq!(super::native_close_handle(link_handle), 1);
        assert_eq!(super::native_close_handle(source_handle), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(link).unwrap();
        ctx.fs.delete_file(source).unwrap();
    }

    #[test]
    fn modern_hard_link_does_not_replace_existing_destination() {
        type CreateHardLinkW = unsafe extern "win64" fn(*const u16, *const u16, u64) -> i32;
        let create_link: CreateHardLinkW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateHardLinkW\0") as usize) };
        let source = r"C:\modern_hard_link_conflict_source.txt";
        let link = r"C:\modern_hard_link_conflict_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let link_wide = link.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.write_file(source, b"source-data".to_vec()).unwrap();
            ctx.fs
                .write_file(link, b"destination-data".to_vec())
                .unwrap();
        }

        let result = unsafe { create_link(link_wide.as_ptr(), source_wide.as_ptr(), 0) };
        let source_bytes = context.lock().unwrap().fs.read_file(source).unwrap();
        let link_bytes = context.lock().unwrap().fs.read_file(link).unwrap();
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(link).unwrap();
        ctx.fs.delete_file(source).unwrap();
        assert_eq!(result, 0);
        assert_eq!(source_bytes, b"source-data");
        assert_eq!(link_bytes, b"destination-data");
    }

    #[test]
    fn modern_replace_file_moves_old_contents_to_backup() {
        type ReplaceFileW =
            unsafe extern "win64" fn(*const u16, *const u16, *const u16, u32, u64, u64) -> i32;
        let replace: ReplaceFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"ReplaceFileW\0") as usize) };
        let destination = r"C:\modern_replace_destination.txt";
        let replacement = r"C:\modern_replace_new.txt";
        let backup = r"C:\modern_replace_backup.txt";
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let replacement_wide = replacement.encode_utf16().chain([0]).collect::<Vec<_>>();
        let backup_wide = backup.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(destination, b"old-value".to_vec())
                .unwrap();
            ctx.fs
                .write_file(replacement, b"new-value".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe {
                replace(
                    destination_wide.as_ptr(),
                    replacement_wide.as_ptr(),
                    backup_wide.as_ptr(),
                    0,
                    0,
                    0,
                )
            },
            1
        );
        let ctx = context.lock().unwrap();
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"new-value");
        assert_eq!(ctx.fs.read_file(backup).unwrap(), b"old-value");
        assert!(!ctx.fs.exists(replacement));
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(backup).unwrap();
        ctx.fs.delete_file(destination).unwrap();
    }

    #[test]
    fn modern_lock_file_locks_and_unlocks_a_byte_range() {
        type FileRangeOperation = unsafe extern "win64" fn(u64, u32, u32, u32, u32) -> i32;
        let lock: FileRangeOperation =
            unsafe { std::mem::transmute(require_kernel32_api(b"LockFile\0") as usize) };
        let unlock: FileRangeOperation =
            unsafe { std::mem::transmute(require_kernel32_api(b"UnlockFile\0") as usize) };
        let path = r"C:\modern_lock_file.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"lock".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        assert_eq!(unsafe { lock(handle, 1, 0, 1, 0) }, 1);
        assert_eq!(unsafe { unlock(handle, 1, 0, 1, 0) }, 1);
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_lock_file_rejects_overlapping_lock_until_unlocked() {
        type FileRangeOperation = unsafe extern "win64" fn(u64, u32, u32, u32, u32) -> i32;
        let lock: FileRangeOperation =
            unsafe { std::mem::transmute(require_kernel32_api(b"LockFile\0") as usize) };
        let unlock: FileRangeOperation =
            unsafe { std::mem::transmute(require_kernel32_api(b"UnlockFile\0") as usize) };
        let path = r"C:\modern_lock_conflict.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"locked-range".to_vec())
            .unwrap();
        let first = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        let second = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(first, u64::MAX);
        assert_ne!(second, u64::MAX);

        assert_eq!(unsafe { lock(first, 2, 0, 4, 0) }, 1);
        assert_eq!(unsafe { lock(second, 4, 0, 2, 0) }, 0);
        let conflict_error = super::native_get_last_error();
        assert_eq!(unsafe { unlock(first, 2, 0, 4, 0) }, 1);
        let after_unlock = unsafe { lock(second, 2, 0, 4, 0) };
        assert_eq!(unsafe { unlock(second, 2, 0, 4, 0) }, 1);
        assert_eq!(super::native_close_handle(second), 1);
        assert_eq!(super::native_close_handle(first), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();

        assert_eq!(conflict_error, 33); // ERROR_LOCK_VIOLATION
        assert_eq!(after_unlock, 1);
    }

    #[test]
    fn modern_ansi_move_file_moves_guest_data_without_changing_contents() {
        type MoveFileA = unsafe extern "win64" fn(*const u8, *const u8) -> i32;
        let move_file: MoveFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileA\0") as usize) };
        let source = b"C:\\modern_move_ansi_source.txt\0";
        let destination = b"C:\\modern_move_ansi_destination.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file("C:\\modern_move_ansi_source.txt", b"move-data".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { move_file(source.as_ptr(), destination.as_ptr()) },
            1
        );
        let ctx = context.lock().unwrap();
        assert!(!ctx.fs.exists("C:\\modern_move_ansi_source.txt"));
        assert_eq!(
            ctx.fs
                .read_file("C:\\modern_move_ansi_destination.txt")
                .unwrap(),
            b"move-data"
        );
        drop(ctx);
        context
            .lock()
            .unwrap()
            .fs
            .delete_file("C:\\modern_move_ansi_destination.txt")
            .unwrap();
    }

    #[test]
    fn modern_ansi_delete_file_removes_guest_file() {
        type DeleteFileA = unsafe extern "win64" fn(*const u8) -> i32;
        let delete_file: DeleteFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"DeleteFileA\0") as usize) };
        let path = b"C:\\modern_delete_ansi.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file("C:\\modern_delete_ansi.txt", b"delete-me".to_vec())
            .unwrap();

        assert_eq!(unsafe { delete_file(path.as_ptr()) }, 1);
        assert!(!context
            .lock()
            .unwrap()
            .fs
            .exists("C:\\modern_delete_ansi.txt"));
    }

    #[test]
    fn modern_wide_move_file_moves_guest_data_without_changing_contents() {
        type MoveFileW = unsafe extern "win64" fn(*const u16, *const u16) -> i32;
        let move_file: MoveFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileW\0") as usize) };
        let source = r"C:\modern_move_wide_source.txt";
        let destination = r"C:\modern_move_wide_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"wide-move-data".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { move_file(source_wide.as_ptr(), destination_wide.as_ptr()) },
            1
        );
        let ctx = context.lock().unwrap();
        assert!(!ctx.fs.exists(source));
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"wide-move-data");
        drop(ctx);
        context.lock().unwrap().fs.delete_file(destination).unwrap();
    }

    #[test]
    fn modern_wide_move_file_preserves_existing_destination() {
        type MoveFileW = unsafe extern "win64" fn(*const u16, *const u16) -> i32;
        let move_file: MoveFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileW\0") as usize) };
        let source = r"C:\modern_move_wide_conflict_source.txt";
        let destination = r"C:\modern_move_wide_conflict_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.write_file(source, b"source-data".to_vec()).unwrap();
            ctx.fs
                .write_file(destination, b"destination-data".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe { move_file(source_wide.as_ptr(), destination_wide.as_ptr()) },
            0
        );
        let error = super::native_get_last_error();
        let ctx = context.lock().unwrap();
        assert!(ctx.fs.exists(source));
        assert_eq!(ctx.fs.read_file(source).unwrap(), b"source-data");
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"destination-data");
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(source).unwrap();
        ctx.fs.delete_file(destination).unwrap();
        assert_eq!(error, 183); // ERROR_ALREADY_EXISTS
    }

    #[test]
    fn modern_wide_delete_file_removes_guest_file() {
        type DeleteFileW = unsafe extern "win64" fn(*const u16) -> i32;
        let delete_file: DeleteFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"DeleteFileW\0") as usize) };
        let path = r"C:\modern_delete_wide.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"wide-delete-me".to_vec())
            .unwrap();

        assert_eq!(unsafe { delete_file(wide.as_ptr()) }, 1);
        assert!(!context.lock().unwrap().fs.exists(path));
    }

    #[test]
    fn modern_wide_delete_file_reports_missing_path() {
        type DeleteFileW = unsafe extern "win64" fn(*const u16) -> i32;
        let delete_file: DeleteFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"DeleteFileW\0") as usize) };
        let path = r"C:\modern_delete_wide_missing.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();

        assert_eq!(unsafe { delete_file(wide.as_ptr()) }, 0);
        assert_eq!(super::native_get_last_error(), 2); // ERROR_FILE_NOT_FOUND
    }

    #[test]
    fn modern_copy_file_a_copies_data_and_honors_fail_if_exists() {
        type CopyFileA = unsafe extern "win64" fn(*const u8, *const u8, i32) -> i32;
        let copy_file: CopyFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFileA\0") as usize) };
        let source = b"C:\\modern_copy_ansi_source.txt\0";
        let destination = b"C:\\modern_copy_ansi_destination.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file("C:\\modern_copy_ansi_source.txt", b"copy-data".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { copy_file(source.as_ptr(), destination.as_ptr(), 1) },
            1
        );
        assert_eq!(
            context
                .lock()
                .unwrap()
                .fs
                .read_file("C:\\modern_copy_ansi_destination.txt")
                .unwrap(),
            b"copy-data"
        );
        assert_eq!(
            unsafe { copy_file(source.as_ptr(), destination.as_ptr(), 1) },
            0
        );
        assert_eq!(super::native_get_last_error(), 80);
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file("C:\\modern_copy_ansi_destination.txt")
            .unwrap();
        ctx.fs
            .delete_file("C:\\modern_copy_ansi_source.txt")
            .unwrap();
    }

    #[test]
    fn modern_ansi_final_path_returns_the_open_guest_path() {
        type GetFinalPathNameByHandleA = unsafe extern "win64" fn(u64, *mut u8, u32, u32) -> u32;
        let get_path: GetFinalPathNameByHandleA = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetFinalPathNameByHandleA\0") as usize)
        };
        let path = r"C:\modern_final_path_ansi.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"path-data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let mut output = [0u8; 128];
        let written = unsafe { get_path(handle, output.as_mut_ptr(), output.len() as u32, 0) };
        assert_eq!(
            &output[..written as usize],
            b"\\\\?\\C:\\modern_final_path_ansi.txt"
        );
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_temp_file_name_creates_a_unique_guest_file() {
        type GetTempPathW = unsafe extern "win64" fn(u32, *mut u16) -> u32;
        type GetTempFileNameW =
            unsafe extern "win64" fn(*const u16, *const u16, u32, *mut u16) -> u32;
        let get_temp_path: GetTempPathW =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetTempPathW\0") as usize) };
        let get_temp_file: GetTempFileNameW =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetTempFileNameW\0") as usize) };
        let mut directory = [0u16; 512];
        let length =
            unsafe { get_temp_path(directory.len() as u32, directory.as_mut_ptr()) } as usize;
        assert!(length > 0 && length < directory.len());
        assert_eq!(directory[length], 0);
        let prefix = [b'w' as u16, b'f' as u16, b's' as u16, 0];
        let mut filename = [0u16; 1024];
        assert_ne!(
            unsafe {
                get_temp_file(
                    directory.as_ptr(),
                    prefix.as_ptr(),
                    0,
                    filename.as_mut_ptr(),
                )
            },
            0
        );
        let path =
            String::from_utf16(&filename[..filename.iter().position(|unit| *unit == 0).unwrap()])
                .unwrap();
        let context = super::fs_ctx().unwrap();
        assert!(context.lock().unwrap().fs.exists(&path));
        context.lock().unwrap().fs.delete_file(&path).unwrap();
    }

    #[test]
    fn modern_create_file2_opens_existing_guest_file() {
        type CreateFile2 =
            unsafe extern "win64" fn(*const u16, u32, u32, u32, *const std::ffi::c_void) -> u64;
        let create_file2: CreateFile2 =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateFile2\0") as usize) };
        let path = r"C:\modern_create_file2.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"create-file2-data".to_vec())
            .unwrap();

        let handle = unsafe { create_file2(wide.as_ptr(), 0x8000_0000, 7, 3, std::ptr::null()) };
        assert_ne!(handle, u64::MAX);
        let mut bytes = [0u8; 17];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(handle, bytes.as_mut_ptr(), 17, &mut read, 0),
            1
        );
        assert_eq!(read, 17);
        assert_eq!(&bytes, b"create-file2-data");
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_copy_file2_copies_contents_and_preserves_source() {
        type CopyFile2 =
            unsafe extern "win64" fn(*const u16, *const u16, *const std::ffi::c_void) -> i32;
        let copy_file2: CopyFile2 =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFile2\0") as usize) };
        let source = r"C:\modern_copy_file2_source.txt";
        let destination = r"C:\modern_copy_file2_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"copy-file2-source".to_vec())
            .unwrap();

        assert_eq!(
            unsafe {
                copy_file2(
                    source_wide.as_ptr(),
                    destination_wide.as_ptr(),
                    std::ptr::null(),
                )
            },
            0 // HRESULT S_OK
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"copy-file2-source"
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(source).unwrap(),
            b"copy-file2-source"
        );
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
    }

    #[test]
    fn modern_copy_file_ex_honors_fail_if_exists_flag() {
        type CopyFileExW =
            unsafe extern "win64" fn(*const u16, *const u16, u64, u64, *mut i32, u32) -> i32;
        let copy_file_ex: CopyFileExW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFileExW\0") as usize) };
        let source = r"C:\modern_copy_file_ex_source.txt";
        let destination = r"C:\modern_copy_file_ex_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(source, b"copy-ex-source".to_vec())
                .unwrap();
            ctx.fs
                .write_file(destination, b"keep-existing".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe {
                copy_file_ex(
                    source_wide.as_ptr(),
                    destination_wide.as_ptr(),
                    0,
                    0,
                    std::ptr::null_mut(),
                    1,
                )
            },
            0
        );
        assert_eq!(super::native_get_last_error(), 80);
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"keep-existing"
        );
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
    }

    #[test]
    fn modern_find_first_stream_reports_the_default_data_stream() {
        type FindFirstStreamW =
            unsafe extern "win64" fn(*const u16, i32, *mut std::ffi::c_void, u32) -> u64;
        let find_first_stream: FindFirstStreamW =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstStreamW\0") as usize) };
        let path = r"C:\modern_stream_enumeration.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"stream-content".to_vec())
            .unwrap();

        let mut stream_data = [0u8; 600];
        let find =
            unsafe { find_first_stream(wide.as_ptr(), 0, stream_data.as_mut_ptr().cast(), 0) };
        assert_ne!(find, u64::MAX);
        assert_eq!(i64::from_le_bytes(stream_data[..8].try_into().unwrap()), 14);
        let stream_name = unsafe {
            std::slice::from_raw_parts(stream_data.as_ptr().add(8).cast::<u16>(), 296)
                .iter()
                .copied()
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>()
        };
        assert_eq!(String::from_utf16(&stream_name).unwrap(), r"::$DATA");
        assert_eq!(super::native_find_close(find), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_set_file_information_by_handle_deletes_on_last_close() {
        type SetFileInformationByHandle =
            unsafe extern "win64" fn(u64, i32, *const std::ffi::c_void, u32) -> i32;
        let set_information: SetFileInformationByHandle = unsafe {
            std::mem::transmute(require_kernel32_api(b"SetFileInformationByHandle\0") as usize)
        };
        let path = r"C:\modern_disposition_by_handle.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"delete-on-close".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x0001_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let disposition = [1u8]; // FILE_DISPOSITION_INFO.DeleteFile
        assert_eq!(
            unsafe {
                set_information(
                    handle,
                    4,
                    disposition.as_ptr().cast(),
                    disposition.len() as u32,
                )
            },
            1
        );
        assert!(context.lock().unwrap().fs.exists(path));
        assert_eq!(super::native_close_handle(handle), 1);
        assert!(!context.lock().unwrap().fs.exists(path));
    }

    #[test]
    fn modern_set_file_information_by_handle_rejects_unknown_class() {
        type SetFileInformationByHandle =
            unsafe extern "win64" fn(u64, i32, *const std::ffi::c_void, u32) -> i32;
        let set_information: SetFileInformationByHandle = unsafe {
            std::mem::transmute(require_kernel32_api(b"SetFileInformationByHandle\0") as usize)
        };
        let path = r"C:\modern_invalid_file_information_class.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"unchanged".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let information = [0u8; 16];
        let result = unsafe {
            set_information(
                handle,
                0x7fff,
                information.as_ptr().cast(),
                information.len() as u32,
            )
        };
        let error = super::native_get_last_error();
        let contents = context.lock().unwrap().fs.read_file(path).unwrap();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 0);
        assert_eq!(error, 87); // ERROR_INVALID_PARAMETER
        assert_eq!(contents, b"unchanged");
    }

    #[test]
    fn nul_device_opens_as_character_sink_and_never_creates_a_disk_entry() {
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            if !ctx.fs.is_dir(r"C:\nul_device_unit") {
                ctx.fs.mkdir(r"C:\nul_device_unit").unwrap();
            }
        }
        let payload = b"discard this output";
        for path in [
            "NUL",
            r"C:\nul_device_unit\nul.txt",
            r"\\.\NUL",
            r"\\?\C:\nul_device_unit\NUL",
        ] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
            assert_ne!(handle, u64::MAX, "failed to open {path}");
            assert_eq!(super::native_get_file_type(handle), 2, "{path}"); // FILE_TYPE_CHAR
            let mut written = 0;
            assert_eq!(
                super::native_write_file(
                    handle,
                    payload.as_ptr(),
                    payload.len() as u32,
                    &mut written,
                    0,
                ),
                1
            );
            assert_eq!(written as usize, payload.len());
            let mut read = u32::MAX;
            assert_eq!(
                super::native_read_file(handle, payload.as_ptr() as *mut u8, 8, &mut read, 0),
                1
            );
            assert_eq!(read, 0); // NUL reads as EOF.
            let mut size = -1;
            assert_eq!(super::native_get_file_size_ex(handle, &mut size), 1);
            assert_eq!(size, 0);
            assert_eq!(super::native_close_handle(handle), 1);
        }
        assert!(!context.lock().unwrap().fs.exists(r"C:\nul_device_unit\nul"));
    }

    #[test]
    fn console_devices_open_as_character_handles_and_serial_names_are_reserved() {
        for (path, access) in [
            ("CON", 0xC000_0000),
            ("CONIN$", 0x8000_0000),
            (r"\\.\CONOUT$", 0x4000_0000),
        ] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            let handle = super::native_create_file_w(wide.as_ptr(), access, 7, 0, 3, 0, 0);
            assert_ne!(handle, u64::MAX, "failed to open {path}");
            assert_eq!(super::native_get_file_type(handle), 2, "{path}"); // FILE_TYPE_CHAR
            assert_eq!(super::native_close_handle(handle), 1);
        }

        for path in ["COM1", r"C:\nul_device_unit\LPT1.txt"] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            assert_eq!(
                super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0),
                u64::MAX
            );
            assert_eq!(super::native_get_last_error(), 123); // ERROR_INVALID_NAME
        }
        assert!(!super::fs_ctx()
            .unwrap()
            .lock()
            .unwrap()
            .fs
            .exists(r"C:\nul_device_unit\LPT1.txt"));
    }

    #[test]
    fn create_file_rejects_unc_paths_with_bad_netpath() {
        for path in [r"\\server\share\x", r"\\?\UNC\server\share\x"] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            assert_eq!(
                super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0),
                u64::MAX
            );
            assert_eq!(super::native_get_last_error(), 53); // ERROR_BAD_NETPATH
        }
    }

    #[test]
    fn create_file_rejects_invalid_names_and_stream_syntax() {
        for path in [r"C:\invalid|name", r"C:\file.txt:stream"] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            assert_eq!(
                super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 2, 0, 0),
                u64::MAX
            );
            assert_eq!(super::native_get_last_error(), 123); // ERROR_INVALID_NAME
        }
    }

    #[test]
    fn modern_get_file_type_distinguishes_disk_handles_from_invalid_handles() {
        type GetFileType = unsafe extern "win64" fn(u64) -> u32;
        let get_file_type: GetFileType =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetFileType\0") as usize) };
        let file_path = r"C:\modern_get_file_type.txt";
        let directory_path = r"C:\modern_get_file_type_directory";
        let file_wide = file_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let directory_wide = directory_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.write_file(file_path, b"data".to_vec()).unwrap();
            ctx.fs.mkdir(directory_path).unwrap();
        }
        let file = super::native_create_file_w(file_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        let directory = super::native_create_file_w(
            directory_wide.as_ptr(),
            0x8000_0000,
            7,
            0,
            3,
            0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS
            0,
        );
        assert_ne!(file, u64::MAX);
        assert_ne!(directory, u64::MAX);

        let file_type = unsafe { get_file_type(file) };
        let directory_type = unsafe { get_file_type(directory) };
        let invalid_type = unsafe { get_file_type(u64::MAX) };
        let invalid_error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(directory), 1);
        assert_eq!(super::native_close_handle(file), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(file_path).unwrap();
        ctx.fs.rmdir(directory_path).unwrap();
        assert_eq!(file_type, 1); // FILE_TYPE_DISK
        assert_eq!(directory_type, 1); // directories are disk handles
        assert_eq!(invalid_type, 0); // FILE_TYPE_UNKNOWN
        assert_eq!(invalid_error, 6); // ERROR_INVALID_HANDLE
    }

    #[test]
    fn modern_get_file_size_ex_reports_null_output_and_invalid_handle() {
        type GetFileSizeEx = unsafe extern "win64" fn(u64, *mut i64) -> i32;
        let get_size: GetFileSizeEx =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetFileSizeEx\0") as usize) };
        let path = r"C:\modern_get_file_size_ex_errors.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"size-data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let mut size = -1i64;
        let valid_result = unsafe { get_size(handle, &mut size) };
        let null_result = unsafe { get_size(handle, std::ptr::null_mut()) };
        let null_error = super::native_get_last_error();
        let invalid_result = unsafe { get_size(u64::MAX, &mut size) };
        let invalid_error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(valid_result, 1);
        assert_eq!(size, 9);
        assert_eq!(null_result, 0);
        assert_eq!(null_error, 998); // ERROR_NOACCESS
        assert_eq!(invalid_result, 0);
        assert_eq!(invalid_error, 6); // ERROR_INVALID_HANDLE
    }

    #[test]
    fn modern_set_file_pointer_apis_update_position_and_extend_on_write() {
        type SetFilePointer = unsafe extern "win64" fn(u64, i32, *mut i32, u32) -> u32;
        type SetFilePointerEx = unsafe extern "win64" fn(u64, i64, *mut i64, u32) -> i32;
        let set_pointer: SetFilePointer =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFilePointer\0") as usize) };
        let set_pointer_ex: SetFilePointerEx =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFilePointerEx\0") as usize) };
        let path = r"C:\modern_set_file_pointer_apis.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"abc".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        assert_eq!(
            unsafe { set_pointer(handle, 5, std::ptr::null_mut(), 0) },
            5
        );
        let marker = b'X';
        let mut written = 0;
        assert_eq!(
            super::native_write_file(handle, &marker, 1, &mut written, 0),
            1
        );
        assert_eq!(written, 1);
        let mut position = -1i64;
        assert_eq!(unsafe { set_pointer_ex(handle, 0, &mut position, 2) }, 1);
        assert_eq!(position, 6);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"abc\0\0X"
        );
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_get_overlapped_result_reports_pending_complete_and_invalid() {
        type GetOverlappedResult = unsafe extern "win64" fn(u64, u64, *mut u32, i32) -> i32;
        let get_result: GetOverlappedResult =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetOverlappedResult\0") as usize) };
        let path = r"C:\modern_get_overlapped_result.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut overlapped = [0u64; 4];
        let pointer = overlapped.as_mut_ptr() as u64;
        let mut transferred = 0;

        super::native_set_overlapped_status(pointer, super::STATUS_PENDING, 0);
        let pending = unsafe { get_result(handle, pointer, &mut transferred, 0) };
        let pending_error = super::native_get_last_error();
        super::native_set_overlapped_status(pointer, 0, 4);
        let completed = unsafe { get_result(handle, pointer, &mut transferred, 0) };
        let invalid = unsafe { get_result(u64::MAX, pointer, &mut transferred, 0) };
        let invalid_error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(pending, 0);
        assert_eq!(pending_error, 996); // ERROR_IO_INCOMPLETE
        assert_eq!(completed, 1);
        assert_eq!(transferred, 4);
        assert_eq!(invalid, 0);
        assert_eq!(invalid_error, 6); // ERROR_INVALID_HANDLE
    }

    #[test]
    fn modern_get_overlapped_result_ex_returns_completed_byte_count() {
        type GetOverlappedResultEx = unsafe extern "win64" fn(u64, u64, *mut u32, u32, i32) -> i32;
        let get_result: GetOverlappedResultEx = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetOverlappedResultEx\0") as usize)
        };
        let path = r"C:\modern_get_overlapped_result_ex.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"completed-data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut overlapped = [0u64; 4];
        let pointer = overlapped.as_mut_ptr() as u64;
        super::native_set_overlapped_status(pointer, 0, 14);
        let mut transferred = 0;

        let result = unsafe { get_result(handle, pointer, &mut transferred, 0, 0) };
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 1);
        assert_eq!(transferred, 14);
    }

    #[test]
    fn modern_get_file_information_by_handle_reports_file_record() {
        type GetFileInformationByHandle = unsafe extern "win64" fn(u64, *mut u8) -> i32;
        let get_information: GetFileInformationByHandle = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetFileInformationByHandle\0") as usize)
        };
        let path = r"C:\modern_file_information_by_handle.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"record".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut information = [0u8; 52];

        let result = unsafe { get_information(handle, information.as_mut_ptr()) };
        let invalid = unsafe { get_information(u64::MAX, information.as_mut_ptr()) };
        let null = unsafe { get_information(handle, std::ptr::null_mut()) };
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 1);
        assert_eq!(
            u32::from_le_bytes(information[..4].try_into().unwrap()),
            0x80
        );
        assert_eq!(
            u32::from_le_bytes(information[28..32].try_into().unwrap()),
            0x5743_4C49
        );
        assert_eq!(
            u32::from_le_bytes(information[36..40].try_into().unwrap()),
            6
        );
        assert_eq!(
            u32::from_le_bytes(information[40..44].try_into().unwrap()),
            1
        );
        assert_eq!(invalid, 0);
        assert_eq!(null, 0);
    }

    #[test]
    fn modern_ansi_hard_link_shares_source_contents() {
        type CreateHardLinkA = unsafe extern "win64" fn(*const u8, *const u8, u64) -> i32;
        let create_link: CreateHardLinkA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateHardLinkA\0") as usize) };
        let source = b"C:\\modern_hard_link_ansi_source.txt\0";
        let link = b"C:\\modern_hard_link_ansi_alias.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(
                "C:\\modern_hard_link_ansi_source.txt",
                b"alias-data".to_vec(),
            )
            .unwrap();

        assert_eq!(unsafe { create_link(link.as_ptr(), source.as_ptr(), 0) }, 1);
        assert_eq!(
            context
                .lock()
                .unwrap()
                .fs
                .read_file("C:\\modern_hard_link_ansi_alias.txt")
                .unwrap(),
            b"alias-data"
        );
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file("C:\\modern_hard_link_ansi_alias.txt")
            .unwrap();
        ctx.fs
            .delete_file("C:\\modern_hard_link_ansi_source.txt")
            .unwrap();
    }

    #[test]
    fn modern_symbolic_link_resolves_to_guest_target() {
        type CreateSymbolicLinkW = unsafe extern "win64" fn(*const u16, *const u16, u32) -> i32;
        let create_link: CreateSymbolicLinkW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateSymbolicLinkW\0") as usize) };
        let target = r"C:\modern_symlink_target.txt";
        let link = r"C:\modern_symlink_alias.txt";
        let target_wide = target.encode_utf16().chain([0]).collect::<Vec<_>>();
        let link_wide = link.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(target, b"symlink-target".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { create_link(link_wide.as_ptr(), target_wide.as_ptr(), 2) },
            1
        );
        assert_ne!(
            super::native_get_file_attributes_w(link_wide.as_ptr()) & 0x400,
            0
        );
        let handle = super::native_create_file_w(link_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut bytes = [0u8; 14];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(handle, bytes.as_mut_ptr(), 14, &mut read, 0),
            1
        );
        assert_eq!(&bytes, b"symlink-target");
        assert_eq!(super::native_close_handle(handle), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(link).unwrap();
        ctx.fs.delete_file(target).unwrap();
    }

    #[test]
    fn modern_ansi_file_attributes_toggle_readonly_state() {
        type SetFileAttributesA = unsafe extern "win64" fn(*const u8, u32) -> i32;
        let set_attributes: SetFileAttributesA =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFileAttributesA\0") as usize) };
        let path = b"C:\\modern_attributes_ansi.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file("C:\\modern_attributes_ansi.txt", b"attributes".to_vec())
            .unwrap();

        assert_eq!(unsafe { set_attributes(path.as_ptr(), 1) }, 1);
        let wide = "C:\\modern_attributes_ansi.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        assert_ne!(super::native_get_file_attributes_w(wide.as_ptr()) & 1, 0);
        assert_eq!(unsafe { set_attributes(path.as_ptr(), 0x80) }, 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 1);
        assert!(!context
            .lock()
            .unwrap()
            .fs
            .exists("C:\\modern_attributes_ansi.txt"));
    }

    #[test]
    fn modern_ansi_create_and_enumerate_use_windows_1252_paths() {
        type CreateFileA = unsafe extern "win64" fn(*const u8, u32, u32, u64, u32, u32, u64) -> u64;
        let create_file: CreateFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateFileA\0") as usize) };
        let mut path = b"C:\\modern_ansi_".to_vec();
        path.push(0x80); // Windows-1252 EURO SIGN
        path.extend_from_slice(b".txt\0");
        let wide_path = r"C:\modern_ansi_€.txt";
        let wide = wide_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();

        let handle = unsafe { create_file(path.as_ptr(), 0xC000_0000, 7, 0, 1, 0, 0) };
        assert_ne!(handle, u64::MAX);
        let bytes = b"ansi-euro";
        let mut written = 0;
        assert_eq!(
            super::native_write_file(handle, bytes.as_ptr(), bytes.len() as u32, &mut written, 0),
            1
        );
        assert_eq!(written, bytes.len() as u32);
        assert_eq!(
            context.lock().unwrap().fs.read_file(wide_path).unwrap(),
            bytes
        );

        let mut find_data = [0u8; 320];
        let find = super::native_find_first_file_a(path.as_ptr(), find_data.as_mut_ptr());
        assert_ne!(find, u64::MAX);
        assert_eq!(&find_data[44..61], b"modern_ansi_\x80.txt");
        assert_eq!(super::native_find_close(find), 1);
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 1);
    }

    #[test]
    fn modern_wide_file_attributes_toggle_readonly_state() {
        type GetFileAttributesW = unsafe extern "win64" fn(*const u16) -> u32;
        type SetFileAttributesW = unsafe extern "win64" fn(*const u16, u32) -> i32;
        let get_attributes: GetFileAttributesW =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetFileAttributesW\0") as usize) };
        let set_attributes: SetFileAttributesW =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFileAttributesW\0") as usize) };
        let path = r"C:\modern_attributes_wide.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"wide-attributes".to_vec())
            .unwrap();

        assert_eq!(unsafe { set_attributes(wide.as_ptr(), 0x3) }, 1);
        assert_eq!(unsafe { get_attributes(wide.as_ptr()) }, 0x3);
        assert_eq!(unsafe { set_attributes(wide.as_ptr(), 0x80) }, 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 1);
        assert!(!context.lock().unwrap().fs.exists(path));
    }

    #[test]
    fn modern_get_file_attributes_ex_w_reports_file_and_missing_path() {
        type GetFileAttributesExW =
            unsafe extern "win64" fn(*const u16, i32, *mut std::ffi::c_void) -> i32;
        let get_attributes: GetFileAttributesExW = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetFileAttributesExW\0") as usize)
        };
        let path = r"C:\modern_attributes_ex_wide.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let missing = r"C:\modern_attributes_ex_wide_missing.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"metadata".to_vec())
            .unwrap();
        let mut data = [0u32; 9];

        assert_eq!(
            unsafe { get_attributes(wide.as_ptr(), 0, data.as_mut_ptr().cast()) },
            1
        );
        assert_eq!(data[0], 0x80);
        assert_eq!((data[7], data[8]), (0, 8));
        assert_eq!(
            unsafe { get_attributes(missing.as_ptr(), 0, data.as_mut_ptr().cast()) },
            0
        );
        assert_eq!(super::native_get_last_error(), 2); // ERROR_FILE_NOT_FOUND
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_ansi_find_first_file_returns_matching_name() {
        type FindFirstFileA = unsafe extern "win64" fn(*const u8, *mut std::ffi::c_void) -> u64;
        let find_first: FindFirstFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstFileA\0") as usize) };
        let pattern = b"C:\\modern_find_ansi\\*.txt\0";
        let directory = r"C:\modern_find_ansi";
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.mkdir(directory).unwrap();
            ctx.fs
                .write_file(r"C:\modern_find_ansi\wanted.txt", b"yes".to_vec())
                .unwrap();
            ctx.fs
                .write_file(r"C:\modern_find_ansi\ignored.bin", b"no".to_vec())
                .unwrap();
        }

        let mut data = [0u8; 320];
        let find = unsafe { find_first(pattern.as_ptr(), data.as_mut_ptr().cast()) };
        assert_ne!(find, u64::MAX);
        let name = unsafe {
            std::slice::from_raw_parts(data.as_ptr().add(44), 260)
                .iter()
                .copied()
                .take_while(|byte| *byte != 0)
                .collect::<Vec<_>>()
        };
        assert_eq!(name, b"wanted.txt");
        assert_eq!(super::native_find_close(find), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file(r"C:\modern_find_ansi\wanted.txt")
            .unwrap();
        ctx.fs
            .delete_file(r"C:\modern_find_ansi\ignored.bin")
            .unwrap();
        ctx.fs.rmdir(directory).unwrap();
    }

    #[test]
    fn modern_set_end_of_file_truncates_and_extends_at_the_current_pointer() {
        type SetEndOfFile = unsafe extern "win64" fn(u64) -> i32;
        let set_end_of_file: SetEndOfFile =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetEndOfFile\0") as usize) };
        let path = r"C:\modern_set_end_of_file.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"truncate-here".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let offset = 8i64;
        assert_eq!(
            super::native_set_file_pointer_ex(handle, offset, std::ptr::null_mut(), 0),
            1
        );

        assert_eq!(unsafe { set_end_of_file(handle) }, 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"truncate"
        );

        let extended_offset = 12i64;
        assert_eq!(
            super::native_set_file_pointer_ex(handle, extended_offset, std::ptr::null_mut(), 0),
            1
        );
        assert_eq!(unsafe { set_end_of_file(handle) }, 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"truncate\0\0\0\0"
        );
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_set_end_of_file_rejects_invalid_handle() {
        type SetEndOfFile = unsafe extern "win64" fn(u64) -> i32;
        let set_end_of_file: SetEndOfFile =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetEndOfFile\0") as usize) };

        assert_eq!(unsafe { set_end_of_file(u64::MAX) }, 0);
        assert_eq!(super::native_get_last_error(), 6); // ERROR_INVALID_HANDLE
    }

    #[test]
    fn modern_flush_file_buffers_keeps_written_guest_bytes() {
        type FlushFileBuffers = unsafe extern "win64" fn(u64) -> i32;
        let flush: FlushFileBuffers =
            unsafe { std::mem::transmute(require_kernel32_api(b"FlushFileBuffers\0") as usize) };
        let path = r"C:\modern_flush_file_buffers.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"before-flush".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let replacement = b"after-flush!";
        let mut written = 0;
        assert_eq!(
            super::native_write_file(
                handle,
                replacement.as_ptr(),
                replacement.len() as u32,
                &mut written,
                0,
            ),
            1
        );
        assert_eq!(written as usize, replacement.len());
        assert_eq!(unsafe { flush(handle) }, 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            replacement
        );
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_get_overlapped_result_ex_rejects_invalid_file_handle() {
        type GetOverlappedResultEx =
            unsafe extern "win64" fn(u64, *mut std::ffi::c_void, *mut u32, u32, i32) -> i32;
        let get_result: GetOverlappedResultEx = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetOverlappedResultEx\0") as usize)
        };
        let mut overlapped = [0u8; 32];
        let mut transferred = 0;
        assert_eq!(
            unsafe {
                get_result(
                    u64::MAX,
                    overlapped.as_mut_ptr().cast(),
                    &mut transferred,
                    0,
                    0,
                )
            },
            0
        );
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn modern_ansi_temp_file_name_creates_a_unique_guest_file() {
        type GetTempPathA = unsafe extern "win64" fn(u32, *mut u8) -> u32;
        type GetTempFileNameA = unsafe extern "win64" fn(*const u8, *const u8, u32, *mut u8) -> u32;
        let get_temp_path: GetTempPathA =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetTempPathA\0") as usize) };
        let get_temp_file: GetTempFileNameA =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetTempFileNameA\0") as usize) };
        let mut directory = [0u8; 512];
        let length =
            unsafe { get_temp_path(directory.len() as u32, directory.as_mut_ptr()) } as usize;
        assert!(length > 0 && length < directory.len());
        assert_eq!(directory[length], 0);
        let prefix = b"wfs\0";
        let mut filename = [0u8; 1024];
        assert_ne!(
            unsafe {
                get_temp_file(
                    directory.as_ptr(),
                    prefix.as_ptr(),
                    0,
                    filename.as_mut_ptr(),
                )
            },
            0
        );
        let path = String::from_utf8(
            filename[..filename.iter().position(|byte| *byte == 0).unwrap()].to_vec(),
        )
        .unwrap();
        let context = super::fs_ctx().unwrap();
        assert!(context.lock().unwrap().fs.exists(&path));
        context.lock().unwrap().fs.delete_file(&path).unwrap();
    }

    #[test]
    fn modern_ansi_find_first_file_ex_covers_reference_options() {
        type FindFirstFileExA = unsafe extern "win64" fn(
            *const u8,
            i32,
            *mut std::ffi::c_void,
            i32,
            *const std::ffi::c_void,
            u32,
        ) -> u64;
        type FindNextFileA = unsafe extern "win64" fn(u64, *mut std::ffi::c_void) -> i32;
        let find_first: FindFirstFileExA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstFileExA\0") as usize) };
        let find_next: FindNextFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindNextFileA\0") as usize) };
        let directory = r"C:\modern_find_ex_ansi";
        let pattern = b"C:\\modern_find_ex_ansi\\*\0";
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.mkdir(directory).unwrap();
            ctx.fs.mkdir(r"C:\modern_find_ex_ansi\nested").unwrap();
            ctx.fs
                .write_file(r"C:\modern_find_ex_ansi\Alpha.txt", b"a".to_vec())
                .unwrap();
            ctx.fs
                .write_file(r"C:\modern_find_ex_ansi\beta.bin", b"b".to_vec())
                .unwrap();
        }

        for (info_level, search_op, flags) in [
            (0, 0, 0),
            (0, 0, 1),
            (0, 0, 2),
            (1, 0, 0),
            (0, 1, 0),
            (0, 1, 1),
            (0, 1, 2),
            (1, 1, 0),
        ] {
            let mut data = [0u8; 320];
            let find = unsafe {
                find_first(
                    pattern.as_ptr(),
                    info_level,
                    data.as_mut_ptr().cast(),
                    search_op,
                    std::ptr::null(),
                    flags,
                )
            };
            assert_ne!(find, u64::MAX, "{info_level}/{search_op}/{flags}");
            let mut names = Vec::new();
            loop {
                let name = unsafe {
                    std::slice::from_raw_parts(data.as_ptr().add(44), 260)
                        .iter()
                        .copied()
                        .take_while(|byte| *byte != 0)
                        .collect::<Vec<_>>()
                };
                names.push(String::from_utf8(name).unwrap());
                if unsafe { find_next(find, data.as_mut_ptr().cast()) } == 0 {
                    break;
                }
            }
            names.sort();
            assert_eq!(
                names,
                ["Alpha.txt", "beta.bin", "nested"],
                "{info_level}/{search_op}/{flags}"
            );
            assert_eq!(super::native_find_close(find), 1);
        }

        context.lock().unwrap().fs.remove(directory, true).unwrap();
    }

    #[test]
    fn modern_ansi_find_first_file_ex_reports_empty_missing_and_invalid_inputs() {
        type FindFirstFileExA = unsafe extern "win64" fn(
            *const u8,
            i32,
            *mut std::ffi::c_void,
            i32,
            *const std::ffi::c_void,
            u32,
        ) -> u64;
        let find_first: FindFirstFileExA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstFileExA\0") as usize) };
        let directory = r"C:\modern_find_ex_ansi_failures";
        let empty_pattern = b"C:\\modern_find_ex_ansi_failures\\*\0";
        let missing_pattern = b"C:\\modern_find_ex_ansi_absent\\*\0";
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(directory).unwrap();
        let mut data = [0u8; 320];

        let empty = unsafe {
            find_first(
                empty_pattern.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
                0,
                std::ptr::null(),
                0,
            )
        };
        let empty_error = super::native_get_last_error();
        let missing = unsafe {
            find_first(
                missing_pattern.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
                0,
                std::ptr::null(),
                0,
            )
        };
        let missing_error = super::native_get_last_error();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(r"C:\modern_find_ex_ansi_failures\one.txt", b"x".to_vec())
            .unwrap();
        let invalid_output = unsafe {
            find_first(
                empty_pattern.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                0,
            )
        };
        let invalid_output_error = super::native_get_last_error();
        let invalid_level = unsafe {
            find_first(
                empty_pattern.as_ptr(),
                99,
                data.as_mut_ptr().cast(),
                0,
                std::ptr::null(),
                0,
            )
        };
        let invalid_level_error = super::native_get_last_error();
        context.lock().unwrap().fs.remove(directory, true).unwrap();

        assert_eq!(empty, u64::MAX);
        assert_eq!(empty_error, 2); // ERROR_FILE_NOT_FOUND
        assert_eq!(missing, u64::MAX);
        assert_eq!(missing_error, 3); // ERROR_PATH_NOT_FOUND
        assert_eq!(invalid_output, u64::MAX);
        assert_eq!(invalid_output_error, 87); // ERROR_INVALID_PARAMETER
        assert_eq!(invalid_level, u64::MAX);
        assert_eq!(invalid_level_error, 87); // ERROR_INVALID_PARAMETER
    }

    #[test]
    fn modern_ansi_find_first_file_reports_empty_and_invalid_output() {
        type FindFirstFileA = unsafe extern "win64" fn(*const u8, *mut std::ffi::c_void) -> u64;
        let find_first: FindFirstFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstFileA\0") as usize) };
        let directory = r"C:\modern_find_ansi_failures";
        let pattern = b"C:\\modern_find_ansi_failures\\*\0";
        let missing = b"C:\\modern_find_ansi_failures\\missing.txt\0";
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(directory).unwrap();
        let mut data = [0u8; 320];

        let empty = unsafe { find_first(pattern.as_ptr(), data.as_mut_ptr().cast()) };
        let empty_error = super::native_get_last_error();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(r"C:\modern_find_ansi_failures\entry.txt", b"x".to_vec())
            .unwrap();
        let invalid_output = unsafe { find_first(pattern.as_ptr(), std::ptr::null_mut()) };
        let invalid_output_error = super::native_get_last_error();
        let missing_result = unsafe { find_first(missing.as_ptr(), data.as_mut_ptr().cast()) };
        let missing_error = super::native_get_last_error();
        context.lock().unwrap().fs.remove(directory, true).unwrap();

        assert_eq!(empty, u64::MAX);
        assert_eq!(empty_error, 2); // ERROR_FILE_NOT_FOUND
        assert_eq!(invalid_output, u64::MAX);
        assert_eq!(invalid_output_error, 87); // ERROR_INVALID_PARAMETER
        assert_eq!(missing_result, u64::MAX);
        assert_eq!(missing_error, 2); // ERROR_FILE_NOT_FOUND
    }

    #[test]
    fn modern_ansi_symbolic_link_resolves_to_guest_target() {
        type CreateSymbolicLinkA = unsafe extern "win64" fn(*const u8, *const u8, u32) -> i32;
        let create_link: CreateSymbolicLinkA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateSymbolicLinkA\0") as usize) };
        let target = b"C:\\modern_symlink_ansi_target.txt\0";
        let link = b"C:\\modern_symlink_ansi_alias.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(
                "C:\\modern_symlink_ansi_target.txt",
                b"ansi-target".to_vec(),
            )
            .unwrap();

        assert_eq!(unsafe { create_link(link.as_ptr(), target.as_ptr(), 2) }, 1);
        let link_wide = "C:\\modern_symlink_ansi_alias.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        assert_ne!(
            super::native_get_file_attributes_w(link_wide.as_ptr()) & 0x400,
            0
        );
        let handle = super::native_create_file_w(link_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut bytes = [0u8; 11];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(handle, bytes.as_mut_ptr(), 11, &mut read, 0),
            1
        );
        assert_eq!(&bytes, b"ansi-target");
        assert_eq!(super::native_close_handle(handle), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file("C:\\modern_symlink_ansi_alias.txt")
            .unwrap();
        ctx.fs
            .delete_file("C:\\modern_symlink_ansi_target.txt")
            .unwrap();
    }

    #[test]
    fn modern_open_file_by_id_rejects_invalid_volume_handle() {
        type OpenFileById = unsafe extern "win64" fn(
            u64,
            *const std::ffi::c_void,
            u32,
            u32,
            *const std::ffi::c_void,
            u32,
        ) -> u64;
        let open_by_id: OpenFileById =
            unsafe { std::mem::transmute(require_kernel32_api(b"OpenFileById\0") as usize) };
        let mut descriptor = [0u8; 24];
        descriptor[..4].copy_from_slice(&24u32.to_le_bytes());

        assert_eq!(
            unsafe {
                open_by_id(
                    u64::MAX,
                    descriptor.as_ptr().cast(),
                    0x8000_0000,
                    7,
                    std::ptr::null(),
                    0,
                )
            },
            u64::MAX
        );
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn modern_set_file_valid_data_rejects_invalid_handle() {
        type SetFileValidData = unsafe extern "win64" fn(u64, i64) -> i32;
        let set_valid_data: SetFileValidData =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFileValidData\0") as usize) };
        assert_eq!(unsafe { set_valid_data(u64::MAX, 0) }, 0);
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn modern_open_file_by_id_opens_existing_file_identifier() {
        type OpenFileById = unsafe extern "win64" fn(
            u64,
            *const std::ffi::c_void,
            u32,
            u32,
            *const std::ffi::c_void,
            u32,
        ) -> u64;
        let open_by_id: OpenFileById =
            unsafe { std::mem::transmute(require_kernel32_api(b"OpenFileById\0") as usize) };
        let path = r"C:\modern_open_by_id.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"opened-by-id".to_vec())
            .unwrap();
        let volume = super::native_create_file_w(
            [b'C' as u16, b':' as u16, b'\\' as u16, 0].as_ptr(),
            0,
            7,
            0,
            3,
            0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS
            0,
        );
        let file = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(volume, u64::MAX);
        assert_ne!(file, u64::MAX);
        let mut information = [0u8; 52];
        assert_eq!(
            super::native_get_file_information_by_handle(file, information.as_mut_ptr()),
            1
        );
        let file_id = u64::from_le_bytes([
            information[48],
            information[49],
            information[50],
            information[51],
            information[44],
            information[45],
            information[46],
            information[47],
        ]);
        let mut descriptor = [0u8; 24]; // FILE_ID_DESCRIPTOR
        descriptor[..4].copy_from_slice(&24u32.to_le_bytes());
        descriptor[4..8].copy_from_slice(&0u32.to_le_bytes()); // FileIdType
        descriptor[8..16].copy_from_slice(&file_id.to_le_bytes());

        let opened = unsafe {
            open_by_id(
                volume,
                descriptor.as_ptr().cast(),
                0x8000_0000,
                7,
                std::ptr::null(),
                0,
            )
        };
        let mut contents = [0u8; 12];
        let mut read = 0;
        let read_result = if opened != u64::MAX {
            super::native_read_file(opened, contents.as_mut_ptr(), 12, &mut read, 0)
        } else {
            0
        };
        if opened != u64::MAX {
            assert_eq!(super::native_close_handle(opened), 1);
        }
        assert_eq!(super::native_close_handle(file), 1);
        assert_eq!(super::native_close_handle(volume), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_ne!(opened, u64::MAX);
        assert_eq!(read_result, 1);
        assert_eq!(read, 12);
        assert_eq!(&contents, b"opened-by-id");
    }

    #[test]
    fn modern_set_file_valid_data_reports_missing_volume_privilege() {
        type SetFileValidData = unsafe extern "win64" fn(u64, i64) -> i32;
        let set_valid_data: SetFileValidData =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFileValidData\0") as usize) };
        let path = r"C:\modern_set_valid_data_privilege.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"valid-data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x4000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let result = unsafe { set_valid_data(handle, 10) };
        let error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 0);
        assert_eq!(error, 1314); // ERROR_PRIVILEGE_NOT_HELD
    }

    #[test]
    fn modern_write_file_gather_writes_page_aligned_segment() {
        type WriteFileGather =
            unsafe extern "win64" fn(u64, *const u64, u32, *mut u32, *mut std::ffi::c_void) -> i32;
        let write_gather: WriteFileGather =
            unsafe { std::mem::transmute(require_kernel32_api(b"WriteFileGather\0") as usize) };
        let path = r"C:\modern_write_file_gather.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, vec![0; 4096])
            .unwrap();
        let handle = super::native_create_file_w(
            wide.as_ptr(),
            0xC000_0000,
            7,
            0,
            3,
            0x6000_0000, // FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED
            0,
        );
        assert_ne!(handle, u64::MAX);
        let layout = std::alloc::Layout::from_size_align(4096, 4096).unwrap();
        let page = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!page.is_null());
        unsafe { std::ptr::write_bytes(page, b'G', 4096) };
        let segments = [page as u64];
        let mut overlapped = [0u64; 4];
        let call_result = unsafe {
            write_gather(
                handle,
                segments.as_ptr(),
                4096,
                std::ptr::null_mut(),
                overlapped.as_mut_ptr().cast(),
            )
        };
        let call_error = super::native_get_last_error();
        let mut transferred = 0;
        let result = if call_result != 0 || call_error == 997 {
            super::native_get_overlapped_result(
                handle,
                overlapped.as_ptr() as u64,
                &mut transferred,
                1,
            )
        } else {
            0
        };
        let bytes = context
            .lock()
            .unwrap()
            .fs
            .read_file(path)
            .unwrap_or_default();
        unsafe { std::alloc::dealloc(page, layout) };
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert!(call_result != 0 || call_error == 997);
        assert_eq!(result, 1);
        assert_eq!(transferred, 4096);
        assert_eq!(bytes, vec![b'G'; 4096]);
    }

    #[test]
    fn modern_file_handle_completion_port_delivers_overlapped_write() {
        let path = r"C:\modern_file_handle_iocp.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, Vec::new())
            .unwrap();
        let handle = super::native_create_file_w(
            wide.as_ptr(),
            0xC000_0000,
            7,
            0,
            3,
            0x4000_0000, // FILE_FLAG_OVERLAPPED
            0,
        );
        assert_ne!(handle, u64::MAX);
        let key = 0x4f50_435f_4649_4c45;
        let port = super::native_create_io_completion_port(handle, 0, key, 0);
        assert_ne!(port, 0);

        let payload = vec![0x6du8; 64 * 1024];
        let mut overlapped = [0u64; 4];
        let pointer = overlapped.as_mut_ptr() as u64;
        let mut written = u32::MAX;
        let write_result = super::native_write_file(
            handle,
            payload.as_ptr(),
            payload.len() as u32,
            &mut written,
            pointer,
        );
        let write_error = super::native_get_last_error();
        let mut completion_bytes = 0;
        let mut completion_key = 0;
        let mut completion_overlapped = 0;
        let completion_result = super::native_get_queued_completion_status(
            port,
            &mut completion_bytes,
            &mut completion_key,
            &mut completion_overlapped,
            5000,
        );
        let mut completed_bytes = 0;
        let result_result =
            super::native_get_overlapped_result(handle, pointer, &mut completed_bytes, 0);
        unsafe { std::ptr::write_bytes(pointer as *mut u8, 0, 32) };
        let mut received = vec![0u8; payload.len()];
        let mut read = u32::MAX;
        let read_result = super::native_read_file(
            handle,
            received.as_mut_ptr(),
            received.len() as u32,
            &mut read,
            pointer,
        );
        let read_error = super::native_get_last_error();
        let mut read_completion_bytes = 0;
        let mut read_completion_key = 0;
        let mut read_completion_overlapped = 0;
        let read_completion_result = super::native_get_queued_completion_status(
            port,
            &mut read_completion_bytes,
            &mut read_completion_key,
            &mut read_completion_overlapped,
            5000,
        );
        let mut read_completed_bytes = 0;
        let read_result_result =
            super::native_get_overlapped_result(handle, pointer, &mut read_completed_bytes, 0);
        let contents = context
            .lock()
            .unwrap()
            .fs
            .read_file(path)
            .unwrap_or_default();
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(super::native_close_handle(port), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();

        assert_eq!(write_result, 0);
        assert_eq!(write_error, 997); // ERROR_IO_PENDING
        assert_eq!(completion_result, 1);
        assert_eq!(completion_bytes as usize, payload.len());
        assert_eq!(completion_key, key);
        assert_eq!(completion_overlapped, pointer);
        assert_eq!(result_result, 1);
        assert_eq!(completed_bytes as usize, payload.len());
        assert_eq!(contents, payload);
        assert_eq!(read_result, 0);
        assert_eq!(read_error, 997); // ERROR_IO_PENDING
        assert_eq!(read_completion_result, 1);
        assert_eq!(read_completion_bytes as usize, received.len());
        assert_eq!(read_completion_key, key);
        assert_eq!(read_completion_overlapped, pointer);
        assert_eq!(read_result_result, 1);
        assert_eq!(read_completed_bytes as usize, received.len());
        assert_eq!(received, payload);
    }

    #[test]
    fn modern_file_completion_modes_accept_overlapped_handle() {
        let path = r"C:\modern_file_completion_modes.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, Vec::new())
            .unwrap();
        let handle =
            super::native_create_file_w(wide.as_ptr(), 0x4000_0000, 7, 0, 3, 0x4000_0000, 0);
        assert_ne!(handle, u64::MAX);

        let result = super::native_set_file_completion_notification_modes(handle, 1);
        let error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 1, "valid overlapped file handle rejected: {error}");
    }

    #[test]
    fn modern_file_handle_cannot_be_associated_with_two_completion_ports() {
        let path = r"C:\modern_duplicate_file_iocp.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, Vec::new())
            .unwrap();
        let handle =
            super::native_create_file_w(wide.as_ptr(), 0x4000_0000, 7, 0, 3, 0x4000_0000, 0);
        assert_ne!(handle, u64::MAX);
        let first_port = super::native_create_io_completion_port(handle, 0, 0x1111, 0);
        assert_ne!(first_port, 0);

        let second_port = super::native_create_io_completion_port(handle, 0, 0x2222, 0);
        let error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(super::native_close_handle(first_port), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(second_port, 0);
        assert_eq!(error, 87); // ERROR_INVALID_PARAMETER
    }

    #[test]
    fn modern_ansi_file_mapping_view_commits_guest_file_changes() {
        type CreateFileMappingA =
            unsafe extern "win64" fn(u64, u64, u32, u32, u32, *const u8) -> u64;
        let create_mapping: CreateFileMappingA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateFileMappingA\0") as usize) };
        let path = r"C:\modern_file_mapping_ansi.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"abcdef".to_vec())
            .unwrap();
        let file = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(file, u64::MAX);

        let mapping = unsafe { create_mapping(file, 0, 0x04, 0, 6, std::ptr::null()) };
        assert_ne!(mapping, 0);
        let view = super::native_map_view_of_file(mapping, 0x2, 0, 0, 6);
        assert!(!view.is_null());
        unsafe { view.add(2).write(b'Z') };
        assert_eq!(super::native_flush_view_of_file(view.cast(), 0), 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"abZdef"
        );
        assert_eq!(super::native_unmap_view_of_file(view.cast()), 1);
        assert_eq!(super::native_close_handle(mapping), 1);
        assert_eq!(super::native_close_handle(file), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_ansi_replace_file_moves_old_data_to_backup() {
        type ReplaceFileA =
            unsafe extern "win64" fn(*const u8, *const u8, *const u8, u32, u64, u64) -> i32;
        let replace: ReplaceFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"ReplaceFileA\0") as usize) };
        let destination = b"C:\\modern_replace_ansi_destination.txt\0";
        let replacement = b"C:\\modern_replace_ansi_new.txt\0";
        let backup = b"C:\\modern_replace_ansi_backup.txt\0";
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(
                    "C:\\modern_replace_ansi_destination.txt",
                    b"old-ansi".to_vec(),
                )
                .unwrap();
            ctx.fs
                .write_file("C:\\modern_replace_ansi_new.txt", b"new-ansi".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe {
                replace(
                    destination.as_ptr(),
                    replacement.as_ptr(),
                    backup.as_ptr(),
                    0,
                    0,
                    0,
                )
            },
            1
        );
        let ctx = context.lock().unwrap();
        assert_eq!(
            ctx.fs
                .read_file("C:\\modern_replace_ansi_destination.txt")
                .unwrap(),
            b"new-ansi"
        );
        assert_eq!(
            ctx.fs
                .read_file("C:\\modern_replace_ansi_backup.txt")
                .unwrap(),
            b"old-ansi"
        );
        assert!(!ctx.fs.exists("C:\\modern_replace_ansi_new.txt"));
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file("C:\\modern_replace_ansi_backup.txt")
            .unwrap();
        ctx.fs
            .delete_file("C:\\modern_replace_ansi_destination.txt")
            .unwrap();
    }

    #[test]
    fn modern_ansi_remove_directory_removes_empty_guest_directory() {
        type RemoveDirectoryA = unsafe extern "win64" fn(*const u8) -> i32;
        let remove_directory: RemoveDirectoryA =
            unsafe { std::mem::transmute(require_kernel32_api(b"RemoveDirectoryA\0") as usize) };
        let path = b"C:\\modern_remove_directory_ansi\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .mkdir("C:\\modern_remove_directory_ansi")
            .unwrap();

        assert_eq!(unsafe { remove_directory(path.as_ptr()) }, 1);
        assert!(!context
            .lock()
            .unwrap()
            .fs
            .exists("C:\\modern_remove_directory_ansi"));
    }

    #[test]
    fn modern_write_file_gather_rejects_invalid_handle() {
        type WriteFileGather =
            unsafe extern "win64" fn(u64, *const u64, u32, *mut u32, *mut std::ffi::c_void) -> i32;
        let write_gather: WriteFileGather =
            unsafe { std::mem::transmute(require_kernel32_api(b"WriteFileGather\0") as usize) };
        let layout = std::alloc::Layout::from_size_align(4096, 4096).unwrap();
        let page = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!page.is_null());
        let segments = [page as u64];
        let mut overlapped = [0u8; 32];
        let result = unsafe {
            write_gather(
                u64::MAX,
                segments.as_ptr(),
                4096,
                std::ptr::null_mut(),
                overlapped.as_mut_ptr().cast(),
            )
        };
        unsafe { std::alloc::dealloc(page, layout) };
        assert_eq!(result, 0);
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn modern_copy_file_w_copies_guest_data_and_preserves_source() {
        type CopyFileW = unsafe extern "win64" fn(*const u16, *const u16, i32) -> i32;
        let copy_file: CopyFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFileW\0") as usize) };
        let source = r"C:\modern_copy_w_source.txt";
        let destination = r"C:\modern_copy_w_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"wide-copy-data".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { copy_file(source_wide.as_ptr(), destination_wide.as_ptr(), 1) },
            1
        );
        let ctx = context.lock().unwrap();
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"wide-copy-data");
        assert_eq!(ctx.fs.read_file(source).unwrap(), b"wide-copy-data");
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
    }

    #[test]
    fn modern_copy_file_w_preserves_existing_destination_when_fail_set() {
        type CopyFileW = unsafe extern "win64" fn(*const u16, *const u16, i32) -> i32;
        let copy_file: CopyFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFileW\0") as usize) };
        let source = r"C:\modern_copy_w_conflict_source.txt";
        let destination = r"C:\modern_copy_w_conflict_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(source, b"source-content".to_vec())
                .unwrap();
            ctx.fs
                .write_file(destination, b"keep-content".to_vec())
                .unwrap();
        }

        let result = unsafe { copy_file(source_wide.as_ptr(), destination_wide.as_ptr(), 1) };
        let source_bytes = context.lock().unwrap().fs.read_file(source).unwrap();
        let destination_bytes = context.lock().unwrap().fs.read_file(destination).unwrap();
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
        assert_eq!(result, 0);
        assert_eq!(source_bytes, b"source-content");
        assert_eq!(destination_bytes, b"keep-content");
    }

    #[test]
    fn modern_set_file_information_by_handle_renames_guest_file() {
        type SetFileInformationByHandle =
            unsafe extern "win64" fn(u64, i32, *const std::ffi::c_void, u32) -> i32;
        let set_information: SetFileInformationByHandle = unsafe {
            std::mem::transmute(require_kernel32_api(b"SetFileInformationByHandle\0") as usize)
        };
        let source = r"C:\modern_rename_by_handle_source.txt";
        let destination = r"C:\modern_rename_by_handle_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"rename-by-handle".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(source_wide.as_ptr(), 0xC001_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let encoded = destination.encode_utf16().collect::<Vec<_>>();
        let mut information = vec![0u8; 20 + encoded.len() * 2];
        information[16..20].copy_from_slice(&((encoded.len() * 2) as u32).to_le_bytes());
        for (index, unit) in encoded.iter().enumerate() {
            information[20 + index * 2..22 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            unsafe {
                set_information(
                    handle,
                    3, // FileRenameInfo
                    information.as_ptr().cast(),
                    information.len() as u32,
                )
            },
            1
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"rename-by-handle"
        );
        assert!(!context.lock().unwrap().fs.exists(source));
        assert_eq!(super::native_close_handle(handle), 1);
    }

    #[test]
    fn modern_move_file_ex_replaces_existing_guest_destination() {
        type MoveFileExW = unsafe extern "win64" fn(*const u16, *const u16, u32) -> i32;
        let move_file: MoveFileExW =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileExW\0") as usize) };
        let source = r"C:\modern_move_ex_source.txt";
        let destination = r"C:\modern_move_ex_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(source, b"new-destination".to_vec())
                .unwrap();
            ctx.fs
                .write_file(destination, b"old-destination".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe { move_file(source_wide.as_ptr(), destination_wide.as_ptr(), 1) },
            1
        );
        let ctx = context.lock().unwrap();
        assert!(!ctx.fs.exists(source));
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"new-destination");
        drop(ctx);
        context.lock().unwrap().fs.delete_file(destination).unwrap();
    }

    #[test]
    fn modern_move_file_ex_preserves_existing_paths_without_replace_flag() {
        type MoveFileExW = unsafe extern "win64" fn(*const u16, *const u16, u32) -> i32;
        let move_file: MoveFileExW =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileExW\0") as usize) };
        let source = r"C:\modern_move_ex_conflict_source.txt";
        let destination = r"C:\modern_move_ex_conflict_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(source, b"source-content".to_vec())
                .unwrap();
            ctx.fs
                .write_file(destination, b"keep-content".to_vec())
                .unwrap();
        }

        let result = unsafe { move_file(source_wide.as_ptr(), destination_wide.as_ptr(), 0) };
        let error = super::native_get_last_error();
        let ctx = context.lock().unwrap();
        assert_eq!(ctx.fs.read_file(source).unwrap(), b"source-content");
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"keep-content");
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
        assert_eq!(result, 0);
        assert_eq!(error, 183); // ERROR_ALREADY_EXISTS
    }

    #[test]
    fn modern_wide_directory_apis_create_and_remove_guest_directory() {
        type CreateDirectoryW =
            unsafe extern "win64" fn(*const u16, *const std::ffi::c_void) -> i32;
        type RemoveDirectoryW = unsafe extern "win64" fn(*const u16) -> i32;
        let create_directory: CreateDirectoryW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateDirectoryW\0") as usize) };
        let remove_directory: RemoveDirectoryW =
            unsafe { std::mem::transmute(require_kernel32_api(b"RemoveDirectoryW\0") as usize) };
        let path = r"C:\modern_directory_api";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();

        assert_eq!(
            unsafe { create_directory(wide.as_ptr(), std::ptr::null()) },
            1
        );
        assert!(context.lock().unwrap().fs.exists(path));
        assert_eq!(unsafe { remove_directory(wide.as_ptr()) }, 1);
        assert!(!context.lock().unwrap().fs.exists(path));
    }

    #[test]
    fn initializes_critical_section_with_spin_count() {
        let mut section = [0x5au8; 40];
        assert_eq!(
            native_initialize_critical_section_and_spin_count(section.as_mut_ptr(), 4000),
            1
        );
        assert_eq!(section, [0; 40]);
        assert_eq!(
            native_initialize_critical_section_and_spin_count(std::ptr::null_mut(), 0),
            0
        );
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
        assert_eq!(
            unsafe { std::slice::from_raw_parts(ptr as *const u8, 3) },
            &[0, 0, 0]
        );
        let grown = native_heap_realloc(super::PROCESS_HEAP_HANDLE, 0x8, ptr, 9);
        assert_ne!(grown, 0);
        assert_eq!(native_heap_size(super::PROCESS_HEAP_HANDLE, 0, grown), 9);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(grown as *const u8, 9) },
            &[0; 9]
        );
        assert_eq!(native_heap_free(super::PROCESS_HEAP_HANDLE, 0, grown), 1);
        assert_eq!(
            native_heap_size(super::PROCESS_HEAP_HANDLE, 0, grown),
            usize::MAX
        );
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
        assert_eq!(
            native_is_processor_feature_present(40),
            std::is_x86_feature_detected!("avx2") as i32
        );
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
        assert_eq!(
            native_sleep_condition_variable_srw(&mut condition, &mut lock, 0, 0),
            0
        );
        assert_eq!(native_try_acquire_srw_lock_shared(&mut lock), 0);
        let condition_address = (&mut condition as *mut u64) as usize;
        let worker = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            native_wake_all_condition_variable(condition_address as *mut u64);
        });
        assert_eq!(
            native_sleep_condition_variable_srw(&mut condition, &mut lock, 1000, 0),
            1
        );
        native_release_srw_lock_exclusive(&mut lock);
        worker.join().unwrap();
    }

    #[test]
    fn init_once_retries_failed_callback_and_caches_context() {
        extern "win64" fn callback(_once: *mut u64, parameter: u64, context: *mut u64) -> i32 {
            let calls = unsafe { &*(parameter as *const std::sync::atomic::AtomicU32) };
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return 0;
            }
            unsafe { context.write(0x1234) };
            1
        }
        let calls = std::sync::atomic::AtomicU32::new(0);
        let mut once = 0u64;
        let mut context = 0u64;
        let param = (&calls as *const std::sync::atomic::AtomicU32) as u64;
        let cb = callback as *const () as usize as u64;
        assert_eq!(
            native_init_once_execute_once(&mut once, cb, param, &mut context),
            0
        );
        assert_eq!(
            native_init_once_execute_once(&mut once, cb, param, &mut context),
            1
        );
        assert_eq!(context, 0x1234);
        context = 0;
        assert_eq!(
            native_init_once_execute_once(&mut once, cb, param, &mut context),
            1
        );
        assert_eq!(context, 0x1234);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn validates_native_memory_status_buffer_length() {
        assert_eq!(native_global_memory_status_ex(std::ptr::null_mut()), 0);
        let mut status = NativeMemoryStatus {
            length: 63,
            load: 0,
            total_physical: 0,
            available_physical: 0,
            total_page_file: 0,
            available_page_file: 0,
            total_virtual: 0,
            available_virtual: 0,
            available_extended_virtual: 0,
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
    fn reports_a_distinct_id_for_each_native_guest_thread() {
        assert_eq!(native_get_current_thread_id(), 1);
        let worker = std::thread::spawn(|| {
            THREAD_NATIVE_HANDLE.with(|handle| handle.set(0xface));
            native_get_current_thread_id()
        });
        assert_eq!(worker.join().unwrap(), 0xface);
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
                    arguments: vec![],
                    current_directory: r"C:\".to_string(),
                },
            )
            .unwrap_err(),
            2
        );
        fs.write_file(r"C:\bad.exe", b"not a PE".to_vec()).unwrap();
        let invalid = native_launch_spec(Some(r"C:\bad.exe".to_string()), None, None, &fs).unwrap();
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
    fn sets_reads_and_removes_a_guest_environment_variable() {
        let name: Vec<u16> = "WINCLI_TEST_NODE_ENV"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let value: Vec<u16> = "node-value"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(
            native_set_environment_variable_w(name.as_ptr(), value.as_ptr()),
            1
        );
        let mut output = [0u16; 16];
        assert_eq!(
            native_get_environment_variable_w(
                name.as_ptr(),
                output.as_mut_ptr(),
                output.len() as u32
            ),
            10
        );
        assert_eq!(String::from_utf16(&output[..10]).unwrap(), "node-value");
        assert_eq!(
            native_set_environment_variable_w(name.as_ptr(), std::ptr::null()),
            1
        );
        assert_eq!(
            native_get_environment_variable_w(
                name.as_ptr(),
                output.as_mut_ptr(),
                output.len() as u32
            ),
            0
        );
        assert_eq!(native_get_last_error(), 203);
    }

    #[test]
    fn executable_search_current_directory_policy_matches_windows() {
        let executable: Vec<u16> = "powershell.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path_executable: Vec<u16> = "tools\\powershell.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let policy_name: Vec<u16> = "NoDefaultCurrentDirectoryInExePath"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let empty_value = [0u16];

        assert_eq!(
            native_set_environment_variable_w(policy_name.as_ptr(), std::ptr::null()),
            1
        );
        assert_eq!(
            native_need_current_directory_for_exe_path_w(executable.as_ptr()),
            1
        );
        assert_eq!(
            native_set_environment_variable_w(policy_name.as_ptr(), empty_value.as_ptr()),
            1
        );
        assert_eq!(
            native_need_current_directory_for_exe_path_w(executable.as_ptr()),
            0
        );
        assert_eq!(
            native_need_current_directory_for_exe_path_w(path_executable.as_ptr()),
            1
        );
        assert_eq!(
            native_need_current_directory_for_exe_path_w(std::ptr::null()),
            0
        );
        assert_eq!(
            native_set_environment_variable_w(policy_name.as_ptr(), std::ptr::null()),
            1
        );
    }

    #[test]
    fn native_child_lookup_resolves_the_power_shell_shell_link_from_path() {
        let mut fs = WinFs::new();
        fs.mkdir(r"C:\work").unwrap();
        fs.mkdir(r"C:\bin").unwrap();
        fs.set_cwd(r"C:\work").unwrap();
        fs.write_file(
            r"C:\bin\powershell.exe",
            crate::shell::POWERSHELL_SHELL_LINK.to_vec(),
        )
        .unwrap();
        let mut launch = NativeLaunchSpec {
            application: fs.normalize("powershell.exe").unwrap().display(),
            arguments: vec![
                "powershell.exe".to_string(),
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Write-Output shell-link-ok".to_string(),
            ],
            current_directory: fs.cwd(),
        };
        super::native_resolve_launch_application(
            &mut launch,
            &fs,
            &[("PATH".to_string(), r"C:\bin".to_string())],
        );
        assert_eq!(launch.application, r"C:\bin\powershell.exe");
        assert!(crate::shell::is_powershell_shell_link(
            &fs,
            &launch.application
        ));

        let (status, stdout, stderr) =
            super::execute_powershell_shell_link(&mut fs, &launch.arguments[1..]);
        assert_eq!(status, 0);
        assert_eq!(stdout, b"shell-link-ok\n");
        assert!(stderr.is_empty());
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
            u32::from_le_bytes(output[40..44].try_into().unwrap()),
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
    fn wait_on_address_reports_changed_values_and_timeouts() {
        let value = 0u8;
        let expected = 1u8;
        assert_eq!(
            native_wait_on_address(
                (&value as *const u8).cast(),
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
        assert_eq!(native_get_last_error(), 87);
        let unchanged = 0u8;
        assert_eq!(
            native_wait_on_address(
                (&value as *const u8).cast(),
                (&unchanged as *const u8).cast(),
                1,
                0
            ),
            0
        );
        assert_eq!(native_get_last_error(), 1460);
    }

    #[test]
    fn wait_on_address_parks_until_the_guest_value_changes_and_wakes() {
        let value = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let address = std::sync::Arc::as_ptr(&value) as usize;
        let value_for_thread = std::sync::Arc::clone(&value);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let expected = 0u32;
            started_tx.send(()).unwrap();
            let result = native_wait_on_address(
                std::sync::Arc::as_ptr(&value_for_thread).cast(),
                (&expected as *const u32).cast(),
                4,
                1000,
            );
            result_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        value.store(1, std::sync::atomic::Ordering::Release);
        native_wake_by_address_all(address as *const u8);
        assert_eq!(
            result_rx.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(1)
        );
        worker.join().unwrap();
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
        assert_eq!(
            super::native_get_file_attributes_w(std::ptr::null()),
            u32::MAX
        );
        assert_eq!(super::native_get_last_error(), 87);
    }

    #[test]
    fn get_file_attributes_ex_reports_winfs_file_and_directory_metadata() {
        let context = super::fs_ctx().unwrap();
        let file_path = r"C:\attribute_ex_unit.txt";
        let directory_path = r"C:\attribute_ex_unit_dir";
        {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(file_path, b"vite".to_vec()).unwrap();
            fs.fs.mkdir(directory_path).unwrap();
        }
        let file_path_wide = file_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let directory_path_wide = directory_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let mut data = [0u32; 9];
        assert_eq!(
            super::native_get_file_attributes_ex_w(
                file_path_wide.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
            ),
            1
        );
        assert_eq!(data[0], 0x80);
        assert_eq!(data[7], 0);
        assert_eq!(data[8], 4);
        assert_eq!(
            super::native_set_file_attributes_w(file_path_wide.as_ptr(), 0x22),
            1
        );
        assert_eq!(
            super::native_get_file_attributes_w(file_path_wide.as_ptr()),
            0x22
        );
        assert_eq!(
            super::native_set_file_attributes_w(file_path_wide.as_ptr(), 0x80 | 0x2),
            0
        );
        assert_eq!(
            super::native_get_file_attributes_ex_w(
                directory_path_wide.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
            ),
            1
        );
        assert_eq!(data[0], 0x10);
        assert_eq!((data[7], data[8]), (0, 0));
        assert_eq!(
            super::native_get_file_attributes_ex_w(
                file_path_wide.as_ptr(),
                1,
                data.as_mut_ptr().cast(),
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 87);

        let missing_path = r"C:\missing_attribute_ex_unit.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        assert_eq!(
            super::native_get_file_attributes_ex_w(
                missing_path.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 2);
        let mut fs = context.lock().unwrap();
        fs.fs.delete_file(file_path).unwrap();
        fs.fs.rmdir(directory_path).unwrap();
    }

    #[test]
    fn nt_file_metadata_reports_winfs_size_type_and_id() {
        let process = super::process_ctx().unwrap();
        let handle = {
            let mut fs = process.fs.lock().unwrap();
            let handle = fs.next;
            fs.next += 1;
            let path = format!(r"C:\nt_metadata_{handle}.txt");
            fs.fs.write_file(&path, b"metadata".to_vec()).unwrap();
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path,
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };
        let mut io_status = [0u8; 16];
        let mut device = [0u8; 8];
        assert_eq!(
            super::native_nt_query_volume_information_file(
                handle,
                io_status.as_mut_ptr(),
                device.as_mut_ptr(),
                device.len() as u32,
                4,
            ),
            0
        );
        assert_eq!(u32::from_le_bytes(device[..4].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(io_status[8..16].try_into().unwrap()), 8);
        let mut info = [0u8; 104];
        assert_eq!(
            super::native_nt_query_information_file(
                handle,
                io_status.as_mut_ptr(),
                info.as_mut_ptr(),
                info.len() as u32,
                18,
            ),
            0
        );
        assert_eq!(u32::from_le_bytes(info[32..36].try_into().unwrap()), 0x80);
        assert_eq!(u64::from_le_bytes(info[48..56].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(info[56..60].try_into().unwrap()), 1);
        assert_ne!(u64::from_le_bytes(info[64..72].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(io_status[8..16].try_into().unwrap()),
            104
        );
        assert_eq!(&info[96..104], &[0; 8]);
        assert_eq!(
            super::native_nt_query_information_file(
                handle,
                io_status.as_mut_ptr(),
                info.as_mut_ptr(),
                8,
                18,
            ),
            0xC000_0004
        );
        assert_eq!(
            super::native_nt_query_volume_information_file(
                handle + 1000,
                io_status.as_mut_ptr(),
                device.as_mut_ptr(),
                device.len() as u32,
                4,
            ),
            0xC000_0008
        );
        assert_eq!(
            super::native_nt_query_information_file(
                handle,
                io_status.as_mut_ptr(),
                info.as_mut_ptr(),
                info.len() as u32,
                7,
            ),
            0xC000_0002
        );
        let mut fs = process.fs.lock().unwrap();
        let path = fs.handles.remove(&handle).unwrap().path;
        fs.fs.delete_file(&path).unwrap();
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
    fn supplies_standard_console_cursor_information() {
        let mut output = [0u8; 8];
        assert_eq!(native_get_console_cursor_info(1, output.as_mut_ptr()), 1);
        assert_eq!(u32::from_le_bytes(output[..4].try_into().unwrap()), 25);
        assert_eq!(i32::from_le_bytes(output[4..].try_into().unwrap()), 1);
        assert_eq!(native_get_console_cursor_info(99, output.as_mut_ptr()), 0);
    }

    #[test]
    fn validates_console_cursor_shape_without_resizing_host_terminal() {
        let mut information = [0u8; 8];
        information[..4].copy_from_slice(&25u32.to_le_bytes());
        information[4..].copy_from_slice(&0i32.to_le_bytes());
        assert_eq!(native_set_console_cursor_info(1, information.as_ptr()), 1);
        information[..4].copy_from_slice(&101u32.to_le_bytes());
        assert_eq!(native_set_console_cursor_info(1, information.as_ptr()), 0);
        assert_eq!(native_set_console_cursor_info(99, information.as_ptr()), 0);
    }

    #[test]
    fn validates_cursor_positions_for_terminal_dimensions() {
        assert_eq!(native_set_console_cursor_position(1, 79 | (24 << 16)), 1);
        assert_eq!(native_set_console_cursor_position(1, 80), 0);
        assert_eq!(native_set_console_cursor_position(99, 0), 0);
    }

    #[test]
    fn console_output_cell_api_is_bound_and_rejects_invalid_geometry() {
        let cell = [b' '; 4];
        let mut region = [0i16, 0, 0, 0];
        assert!(super::baseline_trampoline("WriteConsoleOutputA").is_some());
        assert_eq!(
            super::native_write_console_output_a(
                1,
                cell.as_ptr(),
                0,
                0,
                region.as_mut_ptr().cast(),
            ),
            0
        );
    }

    #[test]
    fn accepts_console_mode_changes_for_standard_handles() {
        assert_eq!(native_set_console_mode(1, 5), 1);
        assert_eq!(native_set_console_mode(99, 5), 0);
    }

    #[test]
    fn accepts_valid_console_screen_buffer_sizes_for_standard_handles() {
        let coord = u32::from(80u16) | (u32::from(25u16) << 16);
        assert_eq!(native_set_console_screen_buffer_size(1, coord), 1);
        assert_eq!(native_set_console_screen_buffer_size(99, coord), 0);
        assert_eq!(native_set_console_screen_buffer_size(1, 0), 0);
    }

    #[test]
    fn validates_console_window_rectangles_without_resizing_the_host() {
        let valid = [0i16, 0, 79, 24];
        let invalid = [4i16, 0, 3, 24];
        assert_eq!(
            native_set_console_window_info(1, 1, valid.as_ptr().cast()),
            1
        );
        assert_eq!(
            native_set_console_window_info(1, 1, invalid.as_ptr().cast()),
            0
        );
        assert_eq!(
            native_set_console_window_info(99, 1, valid.as_ptr().cast()),
            0
        );
    }

    #[test]
    fn accepts_standard_console_as_active_screen_buffer() {
        assert_eq!(native_set_console_active_screen_buffer(1), 1);
        assert_eq!(native_set_console_active_screen_buffer(99), 0);
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
        assert_eq!(
            native_format_message_a(0x1000, 0, 5, 0, short.as_mut_ptr(), 4, 0),
            0
        );
        let mut output = [0u8; 64];
        let count = native_format_message_a(0x1000, 0, 5, 0, output.as_mut_ptr(), 64, 0);
        assert_eq!(&output[..count as usize], b"WinCLI native error.\r\n");
        assert_eq!(output[count as usize], 0);
    }

    #[test]
    fn exposes_the_main_module_handle() {
        assert_eq!(
            native_get_module_handle_w(std::ptr::null()),
            0x0001_4000_0000
        );
    }

    #[test]
    fn exposes_the_main_module_through_module_handle_ex() {
        let mut handle = 0;
        assert_eq!(
            native_get_module_handle_ex_w(0, std::ptr::null(), &mut handle),
            1
        );
        assert_eq!(handle, 0x0001_4000_0000);
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
        assert_ne!(
            native_get_proc_address(API_SET_MODULE, c"FlsAlloc".as_ptr().cast()),
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
    fn critical_section_serializes_threads_and_allows_recursion() {
        let mut section = [0u8; 40];
        let section_ptr = section.as_mut_ptr();
        assert_eq!(native_initialize_critical_section_ex(section_ptr, 0, 0), 1);
        native_enter_critical_section(section_ptr);
        native_enter_critical_section(section_ptr);
        native_leave_critical_section(section_ptr);

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let section_address = section_ptr as usize;
        let worker = std::thread::spawn(move || {
            THREAD_NATIVE_HANDLE.with(|handle| handle.set(0xface));
            started_tx.send(()).unwrap();
            native_enter_critical_section(section_address as *mut u8);
            entered_tx.send(()).unwrap();
            native_leave_critical_section(section_address as *mut u8);
        });

        started_rx.recv().unwrap();
        assert!(entered_rx
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err());
        native_leave_critical_section(section_ptr);
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        worker.join().unwrap();
        native_delete_critical_section(section_ptr);
    }

    #[test]
    fn initializes_an_empty_64_bit_slist_header() {
        let mut header = [0xa5; 16];
        native_initialize_slist_head(header.as_mut_ptr());
        assert_eq!(header, [0; 16]);
    }

    #[test]
    fn ioctlsocket_and_connect_validate_handles_and_arguments() {
        let socket = 0x534f_434b_0000_0003;
        let mut argument = 1u32;
        assert_eq!(
            native_ioctlsocket(3, 0x8004_667e_u32 as i32, &mut argument),
            -1
        );
        assert_eq!(native_wsa_get_last_error(), 10038);
        assert_eq!(native_ioctlsocket(socket, 0x1234, &mut argument), -1);
        assert_eq!(native_wsa_get_last_error(), 10022);
        assert_eq!(
            native_ioctlsocket(socket, 0x8004_667e_u32 as i32, std::ptr::null_mut()),
            -1
        );
        assert_eq!(native_wsa_get_last_error(), 10014);
        assert_eq!(native_connect_socket(socket, std::ptr::null(), 16), -1);
        assert_eq!(native_wsa_get_last_error(), 10014);
        assert_eq!(native_listen_socket(3, 128), -1);
        assert_eq!(native_wsa_get_last_error(), 10038);
        assert_eq!(native_shutdown_socket(3, 2), -1);
        assert_eq!(native_wsa_get_last_error(), 10038);
    }

    #[test]
    fn inet_addr_uses_its_correct_ws2_32_ordinal() {
        assert_eq!(
            native_wsa_inet_addr(c"127.0.0.1".as_ptr().cast()),
            u32::from_ne_bytes([127, 0, 0, 1])
        );
        assert_eq!(native_wsa_inet_addr(c"invalid".as_ptr().cast()), u32::MAX);
    }

    #[test]
    fn pushes_pops_and_flushes_native_slist_entries() {
        #[repr(align(16))]
        struct Aligned([u64; 2]);
        let mut header = Aligned([0; 2]);
        let mut first = Aligned([0; 2]);
        let mut second = Aligned([0; 2]);
        let head = header.0.as_mut_ptr().cast::<u8>();
        let first = first.0.as_mut_ptr().cast::<u8>();
        let second = second.0.as_mut_ptr().cast::<u8>();
        native_initialize_slist_head(head);
        assert!(native_interlocked_push_entry_slist(head, first).is_null());
        assert_eq!(native_query_depth_slist(head), 1);
        assert_eq!(native_interlocked_push_entry_slist(head, second), first);
        assert_eq!(native_query_depth_slist(head), 2);
        assert_eq!(native_interlocked_pop_entry_slist(head), second);
        assert_eq!(native_interlocked_pop_entry_slist(head), first);
        assert!(native_interlocked_pop_entry_slist(head).is_null());
        assert_eq!(native_query_depth_slist(head), 0);
        assert!(native_interlocked_push_entry_slist(head, first).is_null());
        assert_eq!(native_interlocked_flush_slist(head), first);
        assert_eq!(native_query_depth_slist(head), 0);
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
    fn classifies_native_standard_descriptors_by_terminal_state() {
        for fd in 0..=2 {
            assert_eq!(
                native_get_file_type(fd),
                if unsafe { super::isatty(fd as i32) } != 0 {
                    2
                } else {
                    3
                }
            );
        }
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
        let kernel: Vec<u16> = "KERNEL32.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(native_get_module_handle_w(kernel.as_ptr()), API_SET_MODULE);
        let missing: Vec<u16> = "missing.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
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
        assert_eq!(native_is_valid_code_page(0), 1);
        assert_eq!(native_is_valid_code_page(1), 1);
        assert_eq!(native_is_valid_code_page(3), 1);
        assert_eq!(native_is_valid_code_page(932), 0);
        assert_eq!(native_resolve_code_page(0), native_get_acp());
        assert_eq!(native_resolve_code_page(1), native_get_oem_cp());
        assert_eq!(native_resolve_code_page(3), native_get_acp());
    }

    #[test]
    fn converts_using_the_acp_and_oem_code_page_aliases() {
        let input = [0xe9];
        let mut wide = [0u16; 1];
        for code_page in [0, 1, 3] {
            assert_eq!(
                native_multi_byte_to_wide_char(
                    code_page,
                    0,
                    input.as_ptr(),
                    input.len() as i32,
                    wide.as_mut_ptr(),
                    wide.len() as i32,
                ),
                1
            );
            assert_eq!(wide, [0xe9]);
        }
        let mut byte = [0];
        assert_eq!(
            native_wide_char_to_multi_byte(
                1,
                0,
                wide.as_ptr(),
                1,
                byte.as_mut_ptr(),
                1,
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            1
        );
        assert_eq!(byte, input);
        let euro = [0x80, 0];
        let mut euro_wide = [0u16; 2];
        assert_eq!(
            native_multi_byte_to_wide_char(0, 0, euro.as_ptr(), -1, euro_wide.as_mut_ptr(), 2),
            2
        );
        assert_eq!(euro_wide, [0x20ac, 0]);
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
        let euro = [0x20ac, 0];
        let mut euro_bytes = [0u8; 2];
        assert_eq!(
            native_wide_char_to_multi_byte(
                0,
                0,
                euro.as_ptr(),
                -1,
                euro_bytes.as_mut_ptr(),
                2,
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            2
        );
        assert_eq!(euro_bytes, [0x80, 0]);
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

pub(super) fn run_import_free(img: &PeImage) -> Result<u32, String> {
    let _run = NATIVE_RUN_LOCK
        .lock()
        .map_err(|_| "native backend execution lock is poisoned".to_string())?;
    if !img.imports.is_empty() || !img.unsupported.is_empty() {
        return Err("import-free native entry point cannot bind PE imports".to_string());
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

#[derive(Clone)]
struct NativeFile {
    path: String,
    offset: usize,
    overlapped: bool,
    completion: Option<(Arc<NativeCompletionPort>, u64)>,
}

struct NativePipeEndpoint {
    fd: i32,
    name: String,
    server: bool,
    access: u32,
}

impl Drop for NativePipeEndpoint {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

#[derive(Clone)]
struct NativePipeHandle {
    endpoint: Arc<NativePipeEndpoint>,
    pending_client: Option<Arc<NativePipeEndpoint>>,
    overlapped: bool,
    inheritable: bool,
    access: u32,
    mode: u32,
    completion: Option<(Arc<NativeCompletionPort>, u64)>,
    completion_modes: u8,
}

struct NativeNamedPipeTable {
    handles: HashMap<u64, NativePipeHandle>,
    pending_clients: HashMap<String, std::collections::VecDeque<Arc<NativePipeEndpoint>>>,
    pending_io: HashMap<(u64, u64), Arc<AtomicBool>>,
    next: u64,
}

impl NativeNamedPipeTable {
    fn new() -> Self {
        Self {
            handles: HashMap::new(),
            pending_clients: HashMap::new(),
            pending_io: HashMap::new(),
            next: 0xb000_0000,
        }
    }

    fn clone_for_child(&self, inherit_handles: bool) -> Self {
        Self {
            handles: if inherit_handles {
                self.handles
                    .iter()
                    .filter(|(_, handle)| handle.inheritable)
                    .map(|(handle, value)| (*handle, value.clone()))
                    .collect()
            } else {
                HashMap::new()
            },
            pending_clients: HashMap::new(),
            pending_io: HashMap::new(),
            next: self.next,
        }
    }
}
#[derive(Clone)]
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
fn set_teb_stack_bounds(teb: &mut [u8; 0x1000]) {
    let marker = 0u8;
    let stack_pointer = (&marker as *const u8) as usize;
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            let Some((range, _)) = line.split_once(' ') else {
                continue;
            };
            let Some((start, end)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) else {
                continue;
            };
            if start <= stack_pointer && stack_pointer < end {
                let limit = if line.contains("[stack]") {
                    end.saturating_sub(8 * 1024 * 1024)
                } else {
                    start
                };
                put64(teb, 0x08, end as u64); // NT_TIB.StackBase
                put64(teb, 0x10, limit as u64); // NT_TIB.StackLimit
                if native_diagnostic_enabled() {
                    eprintln!(
                        "native TEB stack base={end:#x} limit={limit:#x} rsp={stack_pointer:#x}"
                    );
                }
                return;
            }
        }
    }
}
fn install_thread_teb(teb: &mut [u8; 0x1000]) -> bool {
    set_teb_stack_bounds(teb);
    let base = teb.as_ptr() as u64;
    if !unsafe { set_gs(base) } {
        return false;
    }
    THREAD_TEB_BASE.set(base);
    true
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
extern "win64" fn native_wait_on_address(
    address: *const u8,
    compare: *const u8,
    size: usize,
    milliseconds: u32,
) -> i32 {
    if address.is_null()
        || compare.is_null()
        || !(1..=8).contains(&size)
        || (address as usize) % size != 0
    {
        native_set_last_error(87);
        return 0;
    }
    let expected = unsafe { native_compare_value(compare, size) };
    let equal = || unsafe { native_address_value(address, size) == expected };
    if !equal() {
        return 1;
    }
    let waiter = match NATIVE_ADDRESS_WAITERS.lock() {
        Ok(mut waiters) => {
            waiters.retain(|_, waiter| waiter.strong_count() > 0);
            if let Some(waiter) = waiters.get(&(address as usize)).and_then(Weak::upgrade) {
                waiter
            } else {
                let waiter = Arc::new(NativeAddressWaiters::new());
                waiters.insert(address as usize, Arc::downgrade(&waiter));
                waiter
            }
        }
        Err(_) => return 0,
    };
    let Ok(generation) = waiter.generation.lock() else {
        return 0;
    };
    let before = *generation;
    if !equal() {
        return 1;
    }
    let changed = if milliseconds == u32::MAX {
        waiter
            .ready
            .wait_while(generation, |current| equal() && *current == before)
            .is_ok_and(|generation| !equal() || *generation != before)
    } else {
        waiter
            .ready
            .wait_timeout_while(
                generation,
                std::time::Duration::from_millis(milliseconds as u64),
                |current| equal() && *current == before,
            )
            .map(|(generation, _)| !equal() || *generation != before)
            .unwrap_or(false)
    };
    if changed {
        1
    } else {
        native_set_last_error(1460);
        0
    }
}

unsafe fn native_address_value(address: *const u8, size: usize) -> u64 {
    match size {
        1 => (*(address as *const std::sync::atomic::AtomicU8)).load(Ordering::Acquire) as u64,
        2 => (*(address as *const std::sync::atomic::AtomicU16)).load(Ordering::Acquire) as u64,
        4 => (*(address as *const AtomicU32)).load(Ordering::Acquire) as u64,
        8 => (*(address as *const AtomicU64)).load(Ordering::Acquire),
        _ => 0,
    }
}

unsafe fn native_compare_value(address: *const u8, size: usize) -> u64 {
    match size {
        1 => address.read() as u64,
        2 => address.cast::<u16>().read_unaligned() as u64,
        4 => address.cast::<u32>().read_unaligned() as u64,
        8 => address.cast::<u64>().read_unaligned(),
        _ => 0,
    }
}

fn native_wake_address(address: *const u8, all: bool) {
    if address.is_null() {
        return;
    }
    let waiter = NATIVE_ADDRESS_WAITERS
        .lock()
        .ok()
        .and_then(|waiters| waiters.get(&(address as usize)).and_then(Weak::upgrade));
    let Some(waiter) = waiter else { return };
    if let Ok(mut generation) = waiter.generation.lock() {
        *generation = generation.wrapping_add(1);
        if all {
            waiter.ready.notify_all();
        } else {
            waiter.ready.notify_one();
        }
    };
}

extern "win64" fn native_wake_by_address_all(address: *const u8) {
    native_wake_address(address, true);
}

extern "win64" fn native_wake_by_address_single(address: *const u8) {
    native_wake_address(address, false);
}
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
    devices: HashMap<u64, NativeDevice>,
    file_access: HashMap<u64, u32>,
    file_shares: HashMap<u64, u32>,
    finds: HashMap<u64, NativeFind>,
    file_completion_modes: HashMap<u64, u8>,
    delete_on_close: std::collections::HashSet<u64>,
    file_locks: Vec<(String, u64, u64, u64)>,
    next: u64,
}

impl NativeFs {
    fn clone_for_child(&self, current_directory: &str) -> Result<Self, String> {
        let mut fs = self.fs.clone();
        fs.set_cwd(current_directory)?;
        Ok(Self {
            fs,
            handles: self.handles.clone(),
            devices: self.devices.clone(),
            file_access: self.file_access.clone(),
            file_shares: self.file_shares.clone(),
            finds: self.finds.clone(),
            file_completion_modes: self.file_completion_modes.clone(),
            delete_on_close: self.delete_on_close.clone(),
            file_locks: self.file_locks.clone(),
            next: self.next,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeDevice {
    Null,
    Console { input: u64, output: u64 },
    ConsoleIn(u64),
    ConsoleOut(u64),
}

fn native_device(handle: u64) -> Option<(NativeDevice, u32)> {
    let handle = process_ctx()
        .and_then(|process| {
            process
                .duplicate_handles
                .lock()
                .ok()
                .and_then(|values| values.get(&handle).copied())
        })
        .unwrap_or(handle);
    let context = fs_ctx()?;
    let context = context.lock().ok()?;
    let device = context.devices.get(&handle).copied()?;
    Some((
        device,
        context.file_access.get(&handle).copied().unwrap_or(0),
    ))
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
        if let Ok(mut native_fs) = fs.lock() {
            // A child process owns its working directory. Preserve the
            // parent's directory while applying the child's file journal.
            let parent_cwd = native_fs.fs.cwd();
            match crate::snapshot::apply_changes(&encoded, &mut native_fs.fs) {
                Ok(()) => {
                    let _ = native_fs.fs.set_cwd(&parent_cwd);
                }
                Err(error) => {
                    eprintln!("wincli: cannot apply child filesystem changes: {error}")
                }
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
    module_path: String,
    process_id: u32,
    process_handle: u64,
    parent_process_id: u32,
    command_line_w: Vec<u16>,
    command_line_a: Vec<u8>,
    environment: Mutex<Vec<(String, String)>>,
    environment_block: Mutex<Vec<u16>>,
    std_handles: [AtomicU64; 3],
    crt_fds: Mutex<HashMap<i32, u64>>,
    crt_fd_next: AtomicI32,
    fs: Arc<Mutex<NativeFs>>,
    named_pipes: Mutex<NativeNamedPipeTable>,
    error_mode: AtomicU32,
    pointer_cookie: u64,
    heap_allocations: Mutex<HashMap<u64, usize>>,
    virtual_allocations: Mutex<HashMap<u64, NativeVirtualAllocation>>,
    file_mappings: Mutex<HashMap<u64, NativeFileMapping>>,
    mapping_views: Mutex<HashMap<u64, NativeMappingView>>,
    mapping_next: AtomicU64,
    gs_base: AtomicU64,
    tls_template: Mutex<Option<NativeTls>>,
    dynamic_tls: Mutex<DynamicTlsSlots>,
    threads: Mutex<HashMap<u64, NativeThread>>,
    thread_next: AtomicU64,
    semaphores: Mutex<HashMap<u64, Arc<NativeSemaphore>>>,
    semaphore_next: AtomicU64,
    events: Mutex<HashMap<u64, Arc<NativeEvent>>>,
    event_names: Mutex<HashMap<String, std::sync::Weak<NativeEvent>>>,
    event_next: AtomicU64,
    job_objects: Mutex<HashMap<u64, NativeJobObject>>,
    wait_registrations: Mutex<HashMap<u64, Arc<NativeWaitRegistration>>>,
    completion_ports: Mutex<HashMap<u64, Arc<NativeCompletionPort>>>,
    socket_completion_ports: Mutex<HashMap<u64, (Arc<NativeCompletionPort>, u64)>>,
    socket_completion_modes: Mutex<HashMap<u64, u8>>,
    completion_next: AtomicU64,
    io_wait: Mutex<()>,
    io_ready: Condvar,
    pending_file_io: AtomicU64,
    pending_requests: Mutex<HashMap<(u64, u64), Arc<NativePendingIo>>>,
    file_io_queue: Mutex<Option<Arc<NativeFileIoQueue>>>,
    duplicate_handles: Mutex<HashMap<u64, u64>>,
    duplicate_next: AtomicU64,
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
    suspension: Arc<(Mutex<u32>, Condvar)>,
}

struct NativeSemaphore {
    count: Mutex<i32>,
    changed: Condvar,
    maximum: i32,
}

struct NativeJobObject {
    limit_flags: u32,
    members: std::collections::HashSet<u64>,
}

struct NativeWaitRegistration {
    callback: u64,
    context: u64,
    child: Arc<NativeChildProcess>,
    cancelled: Arc<AtomicBool>,
    execute_once: bool,
}

struct NativeEvent {
    signaled: Mutex<bool>,
    ready: Condvar,
    manual_reset: bool,
}

struct NativeFileIoQueue {
    state: Mutex<NativeFileIoQueueState>,
    ready: Condvar,
}
struct NativeFileIoQueueState {
    jobs: std::collections::VecDeque<NativeFileIoJob>,
    stop: bool,
}
struct NativeFileIoJob {
    process: Arc<NativeProcessContext>,
    request: Arc<NativePendingIo>,
    file: NativeFile,
    overlapped: u64,
    event: Option<Arc<NativeEvent>>,
    offset: usize,
    operation: NativeFileIoOperation,
}
struct NativePendingIo {
    handle: u64,
    overlapped: u64,
    cancelled: AtomicBool,
    issuer: std::thread::ThreadId,
}
enum NativeFileIoOperation {
    Read { output: u64, length: u32 },
    Write { data: Vec<u8> },
}

struct NativeVirtualAllocation {
    length: usize,
}
#[derive(Clone)]
struct NativeFileMapping {
    length: usize,
    protection: u32,
    path: Option<String>,
}
struct NativeMappingView {
    length: usize,
    view_length: usize,
    backing: Option<(String, usize)>,
    writable: bool,
}
struct NativeCompletionPort {
    queue: Mutex<std::collections::VecDeque<NativeCompletion>>,
    ready: Condvar,
}
struct NativeCompletion {
    key: u64,
    overlapped: u64,
    bytes: u32,
    status: u64,
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
        Self {
            active,
            generation: [0; 64],
            reserved_static: static_tls,
        }
    }
}
thread_local! {
    static THREAD_TLS_VALUES: std::cell::RefCell<[(u64, u64); 64]> =
        const { std::cell::RefCell::new([(0, 0); 64]) };
    static THREAD_WSA_ERROR: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
    static THREAD_NATIVE_HANDLE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static THREAD_NATIVE_PROCESS: std::cell::RefCell<Option<Arc<NativeProcessContext>>> =
        const { std::cell::RefCell::new(None) };
    static THREAD_LAST_ERROR: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static THREAD_TEB_BASE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
static NATIVE_REGISTRY_HANDLE_NEXT: AtomicU64 = AtomicU64::new(0x5500_0000);

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
        image_base: 0x0001_4000_0000,
        module_path: r"C:\wincli\wincli.exe".to_string(),
        process_id: 1,
        process_handle: u64::MAX,
        parent_process_id: 0,
        command_line_w: vec![0],
        command_line_a: vec![0],
        environment: Mutex::new(Vec::new()),
        environment_block: Mutex::new(vec![0, 0]),
        std_handles: [
            AtomicU64::new(STD_HANDLE_BASE),
            AtomicU64::new(STD_HANDLE_BASE + 1),
            AtomicU64::new(STD_HANDLE_BASE + 2),
        ],
        crt_fds: Mutex::new(HashMap::new()),
        crt_fd_next: AtomicI32::new(3),
        fs: Arc::new(Mutex::new(NativeFs {
            fs: WinFs::new(),
            handles: HashMap::new(),
            devices: HashMap::new(),
            file_access: HashMap::new(),
            file_shares: HashMap::new(),
            finds: HashMap::new(),
            file_completion_modes: HashMap::new(),
            delete_on_close: std::collections::HashSet::new(),
            file_locks: Vec::new(),
            next: 0x100,
        })),
        named_pipes: Mutex::new(NativeNamedPipeTable::new()),
        error_mode: AtomicU32::new(0),
        pointer_cookie: random_pointer_cookie(),
        heap_allocations: Mutex::new(HashMap::new()),
        virtual_allocations: Mutex::new(HashMap::new()),
        file_mappings: Mutex::new(HashMap::new()),
        mapping_views: Mutex::new(HashMap::new()),
        mapping_next: AtomicU64::new(0x9800_0000),
        gs_base: AtomicU64::new(0),
        tls_template: Mutex::new(None),
        dynamic_tls: Mutex::new(DynamicTlsSlots::new(false)),
        threads: Mutex::new(HashMap::new()),
        thread_next: AtomicU64::new(0x8000_0000),
        semaphores: Mutex::new(HashMap::new()),
        semaphore_next: AtomicU64::new(0x6000_0000),
        events: Mutex::new(HashMap::new()),
        event_names: Mutex::new(HashMap::new()),
        event_next: AtomicU64::new(0x6100_0000),
        job_objects: Mutex::new(HashMap::new()),
        wait_registrations: Mutex::new(HashMap::new()),
        completion_ports: Mutex::new(HashMap::new()),
        socket_completion_ports: Mutex::new(HashMap::new()),
        socket_completion_modes: Mutex::new(HashMap::new()),
        completion_next: AtomicU64::new(0x9000_0000),
        io_wait: Mutex::new(()),
        io_ready: Condvar::new(),
        pending_file_io: AtomicU64::new(0),
        pending_requests: Mutex::new(HashMap::new()),
        file_io_queue: Mutex::new(None),
        duplicate_handles: Mutex::new(HashMap::new()),
        duplicate_next: AtomicU64::new(0xa000_0000),
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
    if let Some(process) = THREAD_NATIVE_PROCESS.with(|active| active.borrow().clone()) {
        return Some(process);
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

extern "win64" fn native_get_module_file_name_w(
    _module: u64,
    output: *mut u16,
    output_len: u32,
) -> u32 {
    if output.is_null() || output_len == 0 {
        return 0;
    }
    let module_path = process_ctx()
        .map(|process| process.module_path.clone())
        .unwrap_or_else(|| r"C:\wincli\wincli.exe".to_string());
    let encoded: Vec<u16> = module_path.encode_utf16().collect();
    let capacity = output_len as usize;
    let copied = encoded.len().min(capacity);
    unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), output, copied) };
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
        .and_then(|process| {
            process
                .environment_block
                .lock()
                .ok()
                .map(|block| block.as_ptr())
        })
        .unwrap_or(EMPTY_ENVIRONMENT_BLOCK.as_ptr())
}

extern "win64" fn native_free_environment_strings_w(block: *const u16) -> i32 {
    process_ctx()
        .map(|process| {
            process
                .environment_block
                .lock()
                .is_ok_and(|value| block == value.as_ptr()) as i32
        })
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
extern "win64" fn native_remove_vectored_exception_handler(handle: u64) -> u32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let current = process.vectored_exception_handler.load(Ordering::Acquire);
    if current != 0 && handle == current | 1 {
        process
            .vectored_exception_handler
            .store(0, Ordering::Release);
        1
    } else {
        0
    }
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

fn native_resolve_code_page(code_page: u32) -> u32 {
    match code_page {
        0 | 3 => native_get_acp(), // CP_ACP, CP_THREAD_ACP
        1 => native_get_oem_cp(),  // CP_OEMCP
        _ => code_page,
    }
}

fn decode_windows_1252(byte: u8) -> u16 {
    const EXTENDED: [u16; 32] = [
        0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160,
        0x2039, 0x0152, 0x008d, 0x017d, 0x008f, 0x0090, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022,
        0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178,
    ];
    if (0x80..=0x9f).contains(&byte) {
        EXTENDED[(byte - 0x80) as usize]
    } else {
        byte as u16
    }
}

fn encode_windows_1252(unit: u16) -> Option<u8> {
    if unit <= 0x7f || (0xa0..=0xff).contains(&unit) {
        return Some(unit as u8);
    }
    const EXTENDED: [u16; 32] = [
        0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160,
        0x2039, 0x0152, 0x008d, 0x017d, 0x008f, 0x0090, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022,
        0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178,
    ];
    EXTENDED
        .iter()
        .position(|value| *value == unit)
        .map(|index| index as u8 + 0x80)
}

extern "win64" fn native_is_valid_code_page(code_page: u32) -> i32 {
    matches!(native_resolve_code_page(code_page), 1252 | 65001) as i32
}

extern "win64" fn native_get_cp_info(code_page: u32, info: *mut u8) -> i32 {
    if info.is_null() {
        return 0;
    }
    let max_char_size = match native_resolve_code_page(code_page) {
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
    let mut wide: Vec<u16> = match native_resolve_code_page(code_page) {
        1252 => input.into_iter().map(decode_windows_1252).collect(),
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
    let mut bytes = match native_resolve_code_page(code_page) {
        1252 => units
            .iter()
            .map(|unit| {
                encode_windows_1252(*unit).unwrap_or_else(|| {
                    used_default = true;
                    b'?'
                })
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
extern "win64" fn native_switch_to_thread() -> i32 {
    std::thread::yield_now();
    1
}
extern "win64" fn native_get_time_zone_information(output: *mut u8) -> u32 {
    if output.is_null() {
        native_set_last_error(87);
        return u32::MAX;
    }
    #[repr(C)]
    struct HostTm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        is_dst: i32,
        gmtoff: i64,
        zone: *const i8,
    }
    unsafe extern "C" {
        fn localtime_r(time: *const i64, result: *mut HostTm) -> *mut HostTm;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let mut host_tm = std::mem::MaybeUninit::<HostTm>::uninit();
    let local = unsafe { localtime_r(&now, host_tm.as_mut_ptr()) };
    if local.is_null() {
        native_set_last_error(87);
        return u32::MAX;
    }
    let host_tm = unsafe { host_tm.assume_init() };
    let bias = -((host_tm.gmtoff / 60) as i32);
    unsafe {
        std::ptr::write_bytes(output, 0, 172);
        (output as *mut i32).write_unaligned(bias);
        // GetTimeZoneInformation returns the current local offset with no
        // transition dates; the guest still formats local Date values
        // using the Linux process timezone.
        0 // TIME_ZONE_ID_UNKNOWN
    }
}
extern "win64" fn native_get_dynamic_time_zone_information(output: *mut u8) -> u32 {
    if output.is_null() {
        native_set_last_error(87);
        return u32::MAX;
    }
    #[repr(C)]
    struct HostTm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        is_dst: i32,
        gmtoff: i64,
        zone: *const i8,
    }
    unsafe extern "C" {
        fn localtime_r(time: *const i64, result: *mut HostTm) -> *mut HostTm;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let mut host_tm = std::mem::MaybeUninit::<HostTm>::uninit();
    let local = unsafe { localtime_r(&now, host_tm.as_mut_ptr()) };
    if local.is_null() {
        native_set_last_error(87);
        return u32::MAX;
    }
    let host_tm = unsafe { host_tm.assume_init() };
    let bias = -((host_tm.gmtoff / 60) as i32);
    unsafe {
        std::ptr::write_bytes(output, 0, 432);
        (output as *mut i32).write_unaligned(bias);
        (output.add(428) as *mut u32).write_unaligned(0);
    }
    let write_wide = |offset: usize, value: &str, capacity: usize| {
        let encoded: Vec<u16> = value.encode_utf16().collect();
        let count = encoded.len().min(capacity.saturating_sub(1));
        unsafe {
            let target = output.add(offset) as *mut u16;
            target.copy_from_nonoverlapping(encoded.as_ptr(), count);
            target.add(count).write(0);
        }
    };
    write_wide(4, "Local Standard Time", 32);
    write_wide(88, "Local Daylight Time", 32);
    write_wide(172, "Local", 128);
    0 // TIME_ZONE_ID_UNKNOWN
}
extern "win64" fn native_open_process_token(process: u64, _access: u32, token: *mut u64) -> i32 {
    if token.is_null() {
        native_set_last_error(87);
        return 0;
    }
    if process != u64::MAX
        && !process_ctx().is_some_and(|context| context.process_handle == process)
    {
        native_set_last_error(6);
        return 0;
    }
    unsafe { token.write(PROCESS_TOKEN_HANDLE) };
    1
}
extern "win64" fn native_get_user_name_w(name: *mut u16, size: *mut u32) -> i32 {
    if name.is_null() || size.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let value = std::env::var("USERNAME").unwrap_or_else(|_| "WinCLI".to_string());
    let encoded: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let capacity = unsafe { size.read() } as usize;
    if capacity < encoded.len() {
        unsafe { size.write(encoded.len() as u32) };
        native_set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    unsafe {
        name.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len());
        size.write(encoded.len() as u32);
    }
    1
}
fn native_monotonic_milliseconds() -> u64 {
    let mut time = NativeTimespec {
        seconds: 0,
        nanoseconds: 0,
    };
    if unsafe { clock_gettime(1, &mut time) } != 0 {
        // CLOCK_MONOTONIC
        return 0;
    }
    time.seconds as u64 * 1000 + time.nanoseconds as u64 / 1_000_000
}

extern "win64" fn native_time_get_time() -> u32 {
    native_monotonic_milliseconds() as u32
}

extern "win64" fn native_get_tick_count() -> u32 {
    native_monotonic_milliseconds() as u32
}

extern "win64" fn native_get_tick_count64() -> u64 {
    native_monotonic_milliseconds()
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
extern "win64" fn native_tls_alloc() -> u32 {
    let Some(process) = process_ctx() else {
        return u32::MAX;
    };
    let Ok(mut slots) = process.dynamic_tls.lock() else {
        return u32::MAX;
    };
    let Some(index) = slots.active.iter().position(|active| !active) else {
        native_set_last_error(8);
        return u32::MAX;
    };
    slots.active[index] = true;
    slots.generation[index] = slots.generation[index].wrapping_add(1);
    index as u32
}
extern "win64" fn native_tls_free(index: u32) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(mut slots) = process.dynamic_tls.lock() else {
        return 0;
    };
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
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(slots) = process.dynamic_tls.lock() else {
        return 0;
    };
    if !slots.active.get(index as usize).copied().unwrap_or(false) {
        native_set_last_error(87);
        return 0;
    }
    let generation = slots.generation[index as usize];
    let value = THREAD_TLS_VALUES.with(|values| {
        let (slot_generation, value) = values.borrow()[index as usize];
        if slot_generation == generation {
            value
        } else {
            0
        }
    });
    native_set_last_error(0);
    value
}
extern "win64" fn native_tls_set_value(index: u32, value: u64) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(slots) = process.dynamic_tls.lock() else {
        return 0;
    };
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
    let cookie = process_ctx()
        .map(|process| process.pointer_cookie)
        .unwrap_or(1);
    value.rotate_left(17) ^ cookie
}
extern "win64" fn native_decode_pointer(value: u64) -> u64 {
    let cookie = process_ctx()
        .map(|process| process.pointer_cookie)
        .unwrap_or(1);
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
extern "win64" fn native_get_system_time(out: *mut u16) {
    if out.is_null() {
        return;
    }
    #[repr(C)]
    struct HostTm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        isdst: i32,
        gmtoff: i64,
        zone: *const i8,
    }
    unsafe extern "C" {
        fn gmtime_r(time: *const i64, result: *mut HostTm) -> *mut HostTm;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs().min(i64::MAX as u64) as i64;
    let mut tm = std::mem::MaybeUninit::<HostTm>::uninit();
    if unsafe { gmtime_r(&seconds, tm.as_mut_ptr()) }.is_null() {
        return;
    }
    let tm = unsafe { tm.assume_init() };
    let fields = [
        (tm.year + 1900) as u16,
        (tm.mon + 1) as u16,
        tm.wday as u16,
        tm.mday as u16,
        tm.hour as u16,
        tm.min as u16,
        tm.sec as u16,
        now.subsec_millis() as u16,
    ];
    unsafe {
        std::ptr::copy_nonoverlapping(fields.as_ptr(), out, fields.len());
    }
}

extern "win64" fn native_system_time_to_file_time(system_time: *const u16, out: *mut u64) -> i32 {
    if system_time.is_null() || out.is_null() {
        native_set_last_error(87);
        return 0;
    }
    #[repr(C)]
    struct HostTm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        isdst: i32,
        gmtoff: i64,
        zone: *const i8,
    }
    unsafe extern "C" {
        fn timegm(time: *mut HostTm) -> i64;
    }
    let f = unsafe { std::slice::from_raw_parts(system_time, 8) };
    if f[0] < 1601
        || !(1..=12).contains(&f[1])
        || !(1..=31).contains(&f[3])
        || f[4] > 23
        || f[5] > 59
        || f[6] > 59
        || f[7] > 999
    {
        native_set_last_error(87);
        return 0;
    }
    let mut tm = HostTm {
        sec: f[6] as i32,
        min: f[5] as i32,
        hour: f[4] as i32,
        mday: f[3] as i32,
        mon: f[1] as i32 - 1,
        year: f[0] as i32 - 1900,
        wday: 0,
        yday: 0,
        isdst: 0,
        gmtoff: 0,
        zone: std::ptr::null(),
    };
    let seconds = unsafe { timegm(&mut tm) };
    if seconds < 0 {
        native_set_last_error(87);
        return 0;
    }
    let ticks = (seconds as u64)
        .saturating_mul(10_000_000)
        .saturating_add((f[7] as u64) * 10_000)
        .saturating_add(116_444_736_000_000_000);
    unsafe {
        out.write_unaligned(ticks);
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
    let Some(process) = process_ctx() else {
        unsafe { free(ptr as *mut c_void) };
        return 0;
    };
    let Ok(mut allocations) = process.heap_allocations.lock() else {
        unsafe { free(ptr as *mut c_void) };
        return 0;
    };
    allocations.insert(ptr, size);
    ptr
}
extern "win64" fn native_heap_realloc(heap: u64, flags: u32, ptr: u64, size: usize) -> u64 {
    if heap != PROCESS_HEAP_HANDLE || ptr == 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(mut allocations) = process.heap_allocations.lock() else {
        return 0;
    };
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
    let size = process_ctx().and_then(|process| {
        process
            .heap_allocations
            .lock()
            .ok()
            .and_then(|allocations| allocations.get(&ptr).copied())
    });
    match size {
        Some(size) => size,
        None => {
            native_set_last_error(87);
            usize::MAX
        }
    }
}
extern "win64" fn native_process_prng(out: *mut u8, len: usize) -> i32 {
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
extern "win64" fn native_crypt_acquire_context_w(
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
extern "win64" fn native_crypt_gen_random(provider: u64, len: u32, out: *mut u8) -> i32 {
    if provider != CRYPTO_PROVIDER_HANDLE || !fill_random_bytes(out, len as usize) {
        native_set_last_error(6);
        return 0;
    }
    1
}
extern "win64" fn native_crypt_release_context(provider: u64, _flags: u32) -> i32 {
    if provider != CRYPTO_PROVIDER_HANDLE {
        native_set_last_error(6);
        return 0;
    }
    1
}
extern "win64" fn native_rtl_gen_random(out: *mut u8, len: u32) -> i32 {
    fill_random_bytes(out, len as usize) as i32
}
extern "win64" fn native_event_register(
    provider_id: *const u8,
    _callback: u64,
    _context: u64,
    registration: *mut u64,
) -> u32 {
    if provider_id.is_null() || registration.is_null() {
        return 87;
    }
    unsafe { registration.write(0x4554_5700_0000_0001) };
    0
}
extern "win64" fn native_event_unregister(_registration: u64) -> u32 {
    0
}
extern "win64" fn native_event_set_information(
    _registration: u64,
    _class: u32,
    _information: *const u8,
    _length: u32,
) -> u32 {
    0
}
extern "win64" fn native_event_write_transfer(
    _registration: u64,
    _descriptor: *const u8,
    _activity: *const u8,
    _related_activity: *const u8,
    _count: u32,
    _data: *const u8,
) -> u32 {
    0
}
extern "win64" fn native_get_logical_processor_information(
    buffer: *mut u8,
    returned_length: *mut u32,
) -> i32 {
    const ENTRY_SIZE: u32 = 32;
    if returned_length.is_null() {
        native_set_last_error(87);
        return 0;
    }
    if buffer.is_null() {
        unsafe { returned_length.write(ENTRY_SIZE) };
        native_set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    // SYSTEM_LOGICAL_PROCESSOR_INFORMATION is 32 bytes on x64. Report
    // one processor core, matching the CPU affinity exposed to a guest.
    unsafe {
        std::ptr::write_bytes(buffer, 0, ENTRY_SIZE as usize);
        (buffer as *mut u64).write_unaligned(1);
        (buffer.add(8) as *mut u32).write_unaligned(0); // RelationProcessorCore
        returned_length.write(ENTRY_SIZE);
    }
    1
}
extern "win64" fn native_get_adapters_addresses(
    family: u32,
    _flags: u32,
    _reserved: u64,
    adapters: *mut u8,
    size: *mut u32,
) -> u32 {
    const REQUIRED: u32 = 240;
    const STRUCT_SIZE: u32 = 176;
    if size.is_null() || !matches!(family, 0 | 2 | 23) {
        return 87; // ERROR_INVALID_PARAMETER
    }
    if adapters.is_null() || unsafe { size.read() } < REQUIRED {
        unsafe { size.write(REQUIRED) };
        return 111; // ERROR_BUFFER_OVERFLOW
    }
    let base = adapters as usize;
    unsafe {
        std::ptr::write_bytes(adapters, 0, REQUIRED as usize);
        (adapters as *mut u32).write_unaligned(STRUCT_SIZE);
        (adapters.add(4) as *mut u32).write_unaligned(1); // IfIndex
        (adapters.add(16) as *mut *const u8).write_unaligned((base + 192) as *const u8);
        (adapters.add(72) as *mut *const u16).write_unaligned((base + 208) as *const u16);
        (adapters.add(88) as *mut u32).write_unaligned(0); // no MAC address
        (adapters.add(100) as *mut u32).write_unaligned(24); // IF_TYPE_SOFTWARE_LOOPBACK
        (adapters.add(104) as *mut u32).write_unaligned(1); // IfOperStatusUp
        (adapters.add(108) as *mut u32).write_unaligned(1); // Ipv6IfIndex
        adapters
            .add(192)
            .copy_from_nonoverlapping(b"lo\0".as_ptr(), 3);
        (adapters.add(208) as *mut u16).write_unaligned(b'l' as u16);
        (adapters.add(210) as *mut u16).write_unaligned(b'o' as u16);
        (adapters.add(212) as *mut u16).write_unaligned(0);
        size.write(REQUIRED);
    }
    0
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
        process.environment.lock().ok().and_then(|environment| {
            environment
                .iter()
                .find_map(|(key, value)| key.eq_ignore_ascii_case(&name).then(|| value.clone()))
        })
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
extern "win64" fn native_set_environment_variable_w(name: *const u16, value: *const u16) -> i32 {
    let (Some(name), value) = (wide(name), if value.is_null() { None } else { wide(value) }) else {
        native_set_last_error(87);
        return 0;
    };
    if name.is_empty() || name.contains('=') {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(mut environment) = process.environment.lock() else {
        return 0;
    };
    if let Some(index) = environment
        .iter()
        .position(|(key, _)| key.eq_ignore_ascii_case(&name))
    {
        if let Some(value) = value {
            environment[index].1 = value;
        } else {
            environment.remove(index);
        }
    } else if let Some(value) = value {
        environment.push((name, value));
    }
    if let Ok(mut block) = process.environment_block.lock() {
        *block = environment_strings(&environment);
    }
    1
}
extern "win64" fn native_need_current_directory_for_exe_path_w(exe_name: *const u16) -> i32 {
    let Some(exe_name) = wide(exe_name) else {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    };
    if exe_name.contains('\\') {
        return 1;
    }
    i32::from(!process_ctx().is_some_and(|process| {
        process.environment.lock().is_ok_and(|environment| {
            environment
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("NoDefaultCurrentDirectoryInExePath"))
        })
    }))
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
extern "win64" fn native_get_system_directory_w(output: *mut u16, capacity: u32) -> u32 {
    const SYSTEM_DIR: &str = r"C:\Windows\System32";
    let encoded: Vec<u16> = SYSTEM_DIR
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    if output.is_null() || capacity < encoded.len() as u32 {
        return encoded.len() as u32 - 1;
    }
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    encoded.len() as u32 - 1
}
extern "win64" fn native_sh_get_folder_path_w(
    _window: u64,
    csidl: i32,
    _token: u64,
    _flags: u32,
    output: *mut u16,
) -> i32 {
    let path = match csidl & 0x7fff {
        0x1a => r"C:\Users\runneradmin\AppData\Roaming",
        0x1c => r"C:\Users\runneradmin\AppData\Local",
        0x23 => r"C:\ProgramData",
        0x24 => r"C:\Windows",
        0x25 => r"C:\Windows\System32",
        0x26 => r"C:\Program Files",
        0x2b => r"C:\Program Files\Common Files",
        0x28 => r"C:\Users\runneradmin",
        _ => return 0x8007_0049u32 as i32, // E_FAIL
    };
    if output.is_null() {
        return 0x8007_0057u32 as i32; // E_INVALIDARG
    }
    let encoded: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    0 // S_OK
}
extern "win64" fn native_get_version() -> u32 {
    // Windows 10.0, build 19045, encoded using the legacy GetVersion layout.
    (19045u32 << 16) | 0x0a00
}
extern "win64" fn native_set_default_dll_directories(_flags: u32) -> i32 {
    1
}
extern "win64" fn native_set_file_apis_to_oem() {}
extern "win64" fn native_co_initialize(_reserved: *mut u8) -> i32 {
    0 // S_OK
}
extern "win64" fn native_lookup_privilege_value_w(
    _system: *const u16,
    name: *const u16,
    luid: *mut u8,
) -> i32 {
    if name.is_null() || luid.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let value = wide(name).unwrap_or_default();
    let low = value.bytes().fold(0u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(byte as u32)
    });
    unsafe {
        luid.cast::<u32>().write_unaligned(low);
        luid.add(4).cast::<i32>().write_unaligned(0);
    }
    1
}
extern "win64" fn native_adjust_token_privileges(
    _token: u64,
    _disable_all: i32,
    _new_state: *const u8,
    _buffer_len: u32,
    _previous_state: *mut u8,
    _return_len: *mut u32,
) -> i32 {
    1
}
extern "win64" fn native_lstrlen_w(input: *const u16) -> i32 {
    wide(input)
        .map(|value| value.encode_utf16().count() as i32)
        .unwrap_or(0)
}
extern "win64" fn native_lstrcpy_w(output: *mut u16, input: *const u16) -> u64 {
    if output.is_null() {
        return 0;
    }
    let Some(value) = wide(input) else {
        return 0;
    };
    let encoded: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { output.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    output as u64
}
extern "win64" fn native_lstrcat_w(output: *mut u16, input: *const u16) -> u64 {
    if output.is_null() {
        return 0;
    }
    let Some(left) = wide(output) else {
        return 0;
    };
    let Some(right) = wide(input) else {
        return 0;
    };
    let end = output.wrapping_add(left.encode_utf16().count());
    let encoded: Vec<u16> = right.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { end.copy_from_nonoverlapping(encoded.as_ptr(), encoded.len()) };
    output as u64
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
        (output.add(32) as *mut u32).write_unaligned(1);
        (output.add(36) as *mut u32).write_unaligned(8664);
        (output.add(40) as *mut u32).write_unaligned(65_536);
    }
}
extern "win64" fn native_get_process_affinity_mask(
    process: u64,
    process_mask: *mut u64,
    system_mask: *mut u64,
) -> i32 {
    let current = process_ctx()
        .is_some_and(|context| process == context.process_handle || process == u64::MAX);
    if !current || process_mask.is_null() || system_mask.is_null() {
        native_set_last_error(if current { 87 } else { 6 });
        return 0;
    }
    unsafe {
        process_mask.write(1);
        system_mask.write(1);
    }
    1
}
extern "win64" fn native_get_native_system_info(output: *mut u8) {
    native_get_system_info(output)
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
fn native_find_parts(pattern: &str) -> (String, String) {
    let path = pattern
        .strip_prefix(r"\\?\")
        .unwrap_or(pattern)
        .replace('/', "\\");
    let Some((parent, leaf)) = path.rsplit_once('\\') else {
        return (".".to_string(), path);
    };
    let parent = if parent.ends_with(':') {
        format!("{parent}\\")
    } else {
        parent.to_string()
    };
    (parent, leaf.to_string())
}
fn native_name_matches_pattern(pattern: &str, name: &str) -> bool {
    let pattern = pattern.to_lowercase().chars().collect::<Vec<_>>();
    let name = name.to_lowercase().chars().collect::<Vec<_>>();
    let mut previous = vec![false; name.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut current = vec![false; name.len() + 1];
        if token == '*' {
            current[0] = previous[0];
            for index in 1..=name.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=name.len() {
                current[index] = previous[index - 1] && (token == '?' || token == name[index - 1]);
            }
        }
        previous = current;
    }
    previous[name.len()]
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
    info_level: u32,
    output: *mut u8,
    search_op: u32,
    _filter: u64,
    flags: u32,
) -> u64 {
    let Some(pattern) = wide(pattern) else {
        native_set_last_error(87);
        return u64::MAX;
    };
    if info_level > 1 || search_op > 1 || flags > 2 || output.is_null() {
        native_set_last_error(87);
        return u64::MAX;
    }
    let context = match fs_ctx() {
        Some(value) => value,
        None => {
            native_set_last_error(6);
            return u64::MAX;
        }
    };
    let mut ctx = match context.lock() {
        Ok(value) => value,
        Err(_) => {
            native_set_last_error(6);
            return u64::MAX;
        }
    };
    let (directory, name_pattern) = native_find_parts(&pattern);
    let mut names = match ctx.fs.list_dir(&directory) {
        Ok(value) => value,
        Err(_) => {
            native_set_last_error(3);
            return u64::MAX;
        }
    };
    names.retain(|name| native_name_matches_pattern(&name_pattern, name));
    names.sort_by_key(|name| name.to_lowercase());
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
extern "win64" fn native_find_first_file_w(pattern: *const u16, output: *mut u8) -> u64 {
    native_find_first_file_ex_w(pattern, 0, output, 0, 0, 0)
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
    creation: *const u64,
    access: *const u64,
    write: *const u64,
) -> i32 {
    if host_standard_fd(handle).is_some() {
        return 1;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut context) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(path) = context.handles.get(&handle).map(|file| file.path.clone()) else {
        native_set_last_error(6);
        return 0;
    };
    let mut metadata = context.fs.file_metadata(&path);
    unsafe {
        if !creation.is_null() {
            metadata.creation_time = creation.read_unaligned();
        }
        if !access.is_null() {
            metadata.access_time = access.read_unaligned();
        }
        if !write.is_null() {
            metadata.write_time = write.read_unaligned();
        }
    }
    match context.fs.set_file_metadata(&path, metadata) {
        Ok(()) => 1,
        Err(_) => {
            native_set_last_error(5);
            0
        }
    }
}
extern "win64" fn native_heap_free(heap: u64, _flags: u32, ptr: u64) -> i32 {
    if heap != PROCESS_HEAP_HANDLE || ptr == 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(mut allocations) = process.heap_allocations.lock() else {
        return 0;
    };
    if allocations.remove(&ptr).is_none() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { free(ptr as *mut c_void) };
    1
}
fn native_critical_section(section: *mut u8) -> Option<Arc<NativeCriticalSection>> {
    if section.is_null() {
        return None;
    }
    let mut sections = NATIVE_CRITICAL_SECTIONS.lock().ok()?;
    Some(
        sections
            .entry(section as usize)
            .or_insert_with(|| Arc::new(NativeCriticalSection::new()))
            .clone(),
    )
}

fn native_critical_section_owner() -> u64 {
    THREAD_NATIVE_HANDLE.with(|handle| handle.get())
}

extern "win64" fn native_enter_critical_section(section: *mut u8) {
    let Some(section) = native_critical_section(section) else {
        return;
    };
    let owner = native_critical_section_owner();
    let Ok(mut state) = section.owner_and_recursion.lock() else {
        return;
    };
    while state.0.is_some_and(|current| current != owner) {
        state = match section.ready.wait(state) {
            Ok(state) => state,
            Err(_) => return,
        };
    }
    state.0 = Some(owner);
    state.1 = state.1.saturating_add(1);
}

extern "win64" fn native_leave_critical_section(section: *mut u8) {
    let Some(section) = native_critical_section(section) else {
        return;
    };
    let owner = native_critical_section_owner();
    let Ok(mut state) = section.owner_and_recursion.lock() else {
        return;
    };
    if state.0 != Some(owner) || state.1 == 0 {
        return;
    }
    state.1 -= 1;
    if state.1 == 0 {
        state.0 = None;
        section.ready.notify_one();
    }
}

extern "win64" fn native_delete_critical_section(section: *mut u8) {
    if !section.is_null() {
        if let Ok(mut sections) = NATIVE_CRITICAL_SECTIONS.lock() {
            sections.remove(&(section as usize));
        }
        unsafe { std::ptr::write_bytes(section, 0, 40) };
    }
}

extern "win64" fn native_initialize_slist_head(head: *mut u8) {
    if !head.is_null() {
        // SLIST_HEADER occupies 16 bytes on 64-bit Windows.
        unsafe { std::ptr::write_bytes(head, 0, 16) };
    }
}

extern "win64" fn native_interlocked_push_entry_slist(head: *mut u8, entry: *mut u8) -> *mut u8 {
    if native_diagnostic_enabled() {
        eprintln!("native InterlockedPushEntrySList head={head:p} entry={entry:p}");
    }
    if head.is_null() || entry.is_null() || (head as usize) & 15 != 0 || (entry as usize) & 15 != 0
    {
        return ptr::null_mut();
    }
    let Ok(_guard) = NATIVE_SLIST_LOCK.lock() else {
        return ptr::null_mut();
    };
    unsafe {
        let first = head as *mut u64;
        let depth = head.add(8) as *mut u16;
        let previous = first.read();
        (entry as *mut u64).write(previous);
        first.write(entry as u64);
        depth.write(depth.read().wrapping_add(1));
        previous as *mut u8
    }
}

extern "win64" fn native_interlocked_pop_entry_slist(head: *mut u8) -> *mut u8 {
    if native_diagnostic_enabled() {
        eprintln!("native InterlockedPopEntrySList head={head:p}");
    }
    if head.is_null() || (head as usize) & 15 != 0 {
        return ptr::null_mut();
    }
    let Ok(_guard) = NATIVE_SLIST_LOCK.lock() else {
        return ptr::null_mut();
    };
    unsafe {
        let first = head as *mut u64;
        let depth = head.add(8) as *mut u16;
        let entry = first.read();
        if entry == 0 {
            return ptr::null_mut();
        }
        first.write((entry as *const u64).read());
        depth.write(depth.read().wrapping_sub(1));
        entry as *mut u8
    }
}

extern "win64" fn native_interlocked_flush_slist(head: *mut u8) -> *mut u8 {
    if native_diagnostic_enabled() {
        eprintln!("native InterlockedFlushSList head={head:p}");
    }
    if head.is_null() || (head as usize) & 15 != 0 {
        return ptr::null_mut();
    }
    let Ok(_guard) = NATIVE_SLIST_LOCK.lock() else {
        return ptr::null_mut();
    };
    unsafe {
        let first = head as *mut u64;
        let depth = head.add(8) as *mut u16;
        let entries = first.read();
        first.write(0);
        depth.write(0);
        entries as *mut u8
    }
}

extern "win64" fn native_query_depth_slist(head: *const u8) -> u16 {
    if native_diagnostic_enabled() {
        eprintln!("native QueryDepthSList head={head:p}");
    }
    if head.is_null() || (head as usize) & 15 != 0 {
        return 0;
    }
    let Ok(_guard) = NATIVE_SLIST_LOCK.lock() else {
        return 0;
    };
    unsafe { head.add(8).cast::<u16>().read() }
}

fn native_submit_pipe_io(
    process: &Arc<NativeProcessContext>,
    handle: u64,
    pipe: NativePipeHandle,
    overlapped: u64,
    event: Option<Arc<NativeEvent>>,
    buffer: usize,
    data: Option<Vec<u8>>,
    length: usize,
) -> Result<(), u32> {
    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let mut pipes = process.named_pipes.lock().map_err(|_| 6u32)?;
        if !pipe.overlapped || pipes.pending_io.contains_key(&(handle, overlapped)) {
            return Err(87);
        }
        pipes
            .pending_io
            .insert((handle, overlapped), cancelled.clone());
    }
    native_set_overlapped_status(overlapped, STATUS_PENDING, 0);
    let worker_pipe = pipe.clone();
    let worker_process = Arc::clone(process);
    let spawn = std::thread::Builder::new()
        .name("wincli-named-pipe-io".into())
        .spawn(move || {
            let is_write = data.is_some();
            let events = if is_write { 0x4 } else { 0x1 };
            let (status, bytes) = loop {
                if cancelled.load(Ordering::Acquire) {
                    break (0xc000_0120, 0); // STATUS_CANCELLED
                }
                let mut descriptor = NativePollFd {
                    fd: worker_pipe.endpoint.fd,
                    events,
                    revents: 0,
                };
                let ready = unsafe { poll(&mut descriptor, 1, 25) };
                if ready < 0 {
                    break (0xc000_0001, 0); // STATUS_UNSUCCESSFUL
                }
                if ready == 0 {
                    continue;
                }
                let count = if let Some(ref payload) = data {
                    unsafe {
                        send(
                            worker_pipe.endpoint.fd,
                            payload.as_ptr().cast(),
                            payload.len(),
                            0x4000,
                        )
                    }
                } else {
                    unsafe { recv(worker_pipe.endpoint.fd, buffer as *mut c_void, length, 0) }
                };
                if count < 0 {
                    continue;
                }
                if count == 0 && !is_write && length != 0 {
                    break (0xc000_014b, 0); // STATUS_PIPE_BROKEN
                }
                break (0, count as u32);
            };
            if native_diagnostic_enabled() {
                eprintln!("native named-pipe completion handle={handle:#x} overlap={overlapped:#x} status={status:#x} bytes={bytes}");
            }
            if let Ok(mut pipes) = worker_process.named_pipes.lock() {
                pipes.pending_io.remove(&(handle, overlapped));
            }
            // Publish completion only after the old request is removed:
            // callers may immediately reuse the same OVERLAPPED address.
            native_complete_pipe_io(&worker_pipe, overlapped, bytes, status, event.as_ref());
        });
    if spawn.is_err() {
        if let Ok(mut pipes) = process.named_pipes.lock() {
            pipes.pending_io.remove(&(handle, overlapped));
        }
        return Err(8);
    }
    Ok(())
}

extern "win64" fn native_write_file(
    handle: u64,
    buf: *const u8,
    len: u32,
    written: *mut u32,
    overlapped: u64,
) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!("native WriteFile handle={handle:#x} len={len} overlap={overlapped:#x}");
    }
    if (buf.is_null() && len != 0) || len > 16 * 1024 * 1024 {
        native_set_last_error(87);
        return 0;
    }
    let pipe = process_ctx().and_then(|process| {
        process
            .named_pipes
            .lock()
            .ok()
            .and_then(|pipes| pipes.handles.get(&handle).cloned())
    });
    if let Some(pipe) = pipe {
        let can_write = if pipe.endpoint.server {
            pipe.access & 0x3 & 0x2 != 0
        } else {
            pipe.access & 0x4000_0000 != 0
        };
        if !can_write {
            native_set_last_error(5);
            return 0;
        }
        if len == 0 {
            if !written.is_null() {
                unsafe { written.write(0) };
            }
            return 1;
        }
        if pipe.overlapped && overlapped == 0 {
            native_set_last_error(87);
            return 0;
        }
        if overlapped != 0
            && (overlapped & 7 != 0 || native_overlapped_status(overlapped) == STATUS_PENDING)
        {
            native_set_last_error(87);
            return 0;
        }
        let event = match native_prepare_overlapped_event(overlapped) {
            Ok(event) => event,
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        };
        let payload = if len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(buf, len as usize).to_vec() }
        };
        if overlapped != 0 {
            let Some(process) = process_ctx() else {
                return 0;
            };
            if let Err(error) = native_submit_pipe_io(
                &process,
                handle,
                pipe,
                overlapped,
                event,
                0,
                Some(payload),
                len as usize,
            ) {
                native_set_last_error(error);
                return 0;
            }
            native_set_last_error(997); // ERROR_IO_PENDING
            return 0;
        }
        let count = unsafe {
            send(
                pipe.endpoint.fd,
                payload.as_ptr().cast(),
                payload.len(),
                0x4000,
            )
        };
        if count < 0 {
            native_set_last_error(109);
            return 0;
        }
        if !written.is_null() {
            unsafe { written.write(count as u32) };
        }
        return 1;
    }
    if let Some((device, access)) = native_device(handle) {
        if len != 0 && access & 0x4000_0000 == 0 {
            native_set_last_error(5); // ERROR_ACCESS_DENIED
            return 0;
        }
        let ok = match device {
            NativeDevice::Null => true,
            NativeDevice::Console { output, .. } | NativeDevice::ConsoleOut(output) => {
                let payload = if len == 0 {
                    &[]
                } else {
                    unsafe { std::slice::from_raw_parts(buf, len as usize) }
                };
                native_write_to_handle(output, payload)
            }
            NativeDevice::ConsoleIn(_) => {
                native_set_last_error(5); // ERROR_ACCESS_DENIED
                return 0;
            }
        };
        if !ok {
            native_set_last_error(109); // ERROR_BROKEN_PIPE
            return 0;
        }
        if !written.is_null() {
            unsafe { written.write(len) };
        }
        native_set_last_error(0);
        return 1;
    }
    if !matches!(host_standard_fd(handle), Some(1 | 2)) {
        let context = match fs_ctx() {
            Some(v) => v,
            None => return 0,
        };
        let mut ctx = match context.lock() {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let (path, offset) = match ctx.handles.get(&handle) {
            Some(v) => {
                if ctx
                    .file_access
                    .get(&handle)
                    .is_some_and(|access| access & 0xC000_0000 == 0x8000_0000)
                {
                    native_set_last_error(5);
                    return 0;
                }
                if v.overlapped && overlapped == 0 {
                    native_set_last_error(87);
                    return 0;
                }
                let offset = if overlapped == 0 {
                    Some(v.offset)
                } else {
                    native_overlapped_offset(overlapped)
                };
                let Some(offset) = offset else {
                    native_set_last_error(87);
                    return 0;
                };
                (v.path.clone(), offset)
            }
            None => {
                native_set_last_error(6);
                return 0;
            }
        };
        if overlapped != 0
            && ctx.handles.get(&handle).is_some_and(|file| file.overlapped)
            && (overlapped & 7 != 0 || native_overlapped_status(overlapped) == STATUS_PENDING)
        {
            native_set_last_error(87);
            return 0;
        }
        if overlapped != 0
            && len >= DEFERRED_FILE_IO_MIN
            && ctx.handles.get(&handle).is_some_and(|file| file.overlapped)
        {
            let Some(process) = process_ctx() else {
                return 0;
            };
            let file = ctx.handles.get(&handle).unwrap().clone();
            let data = unsafe { std::slice::from_raw_parts(buf, len as usize).to_vec() };
            if !written.is_null() {
                unsafe { written.write(0) };
            }
            drop(ctx);
            let result = native_submit_file_io(
                &process,
                handle,
                file,
                overlapped,
                offset,
                NativeFileIoOperation::Write { data },
            );
            native_set_last_error(result.err().unwrap_or(997)); // ERROR_IO_PENDING
            return 0;
        }
        let event = match native_prepare_overlapped_event(overlapped) {
            Ok(event) => event,
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        };
        let data = if len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(buf, len as usize) }
        };
        let mut content = match ctx.fs.read_file(&path) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let end = match offset.checked_add(data.len()) {
            Some(v) => v,
            None => return 0,
        };
        if content.len() < end {
            if content.try_reserve(end - content.len()).is_err() {
                native_set_last_error(8); // ERROR_NOT_ENOUGH_MEMORY
                return 0;
            }
            content.resize(end, 0);
        }
        content[offset..end].copy_from_slice(data);
        if ctx.fs.write_file(&path, content).is_err() {
            return 0;
        }
        if let Some(file) = ctx.handles.get_mut(&handle) {
            if overlapped == 0 {
                file.offset = end;
            }
            native_complete_file_io(file, overlapped, len, event.as_ref());
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
    let n = unsafe { write(host_standard_fd(handle).unwrap(), buf.cast(), len as usize) };
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
    if native_diagnostic_enabled() {
        eprintln!("native ExitProcess code={code:#x}");
    }
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
    inherit_handles: i32,
    _creation_flags: u32,
    environment: u64,
    current_directory: *const u16,
    startup_info: u64,
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
    let mut launch = match native_launch_spec(application, command_line, current_directory, &fs.fs)
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
    let Some(parent) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let search_environment = parent
        .environment
        .lock()
        .map(|environment| environment.clone())
        .unwrap_or_default();
    native_resolve_launch_application(&mut launch, &fs.fs, &search_environment);
    let parent_std_handles =
        std::array::from_fn(|index| parent.std_handles[index].load(Ordering::Acquire));
    let child_std_handles = native_startup_std_handles(startup_info, parent_std_handles);
    if crate::shell::is_powershell_shell_link(&fs.fs, &launch.application) {
        let powershell_fs = fs.fs.clone();
        drop(fs);
        return native_create_powershell_shell_child(
            parent,
            launch,
            powershell_fs,
            child_std_handles,
            process_information,
        );
    }
    let image = match load_native_child_image(&fs.fs, &launch) {
        Ok(image) => image,
        Err(error) => {
            if native_diagnostic_enabled() {
                eprintln!(
                    "native CreateProcessW could not load {} (exists={}): error={error}",
                    launch.application,
                    fs.fs.exists(&launch.application)
                );
            }
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
    let environment = explicit_environment.unwrap_or_else(|| {
        parent
            .environment
            .lock()
            .map(|environment| environment.clone())
            .unwrap_or_default()
    });
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
    let child_fs = match context.lock() {
        Ok(parent_fs) => match parent_fs.clone_for_child(&launch.current_directory) {
            Ok(child_fs) => Arc::new(Mutex::new(child_fs)),
            Err(_) => {
                native_set_last_error(267); // ERROR_DIRECTORY
                return 0;
            }
        },
        Err(_) => {
            native_set_last_error(6);
            return 0;
        }
    };
    let child_pipes = match parent.named_pipes.lock() {
        Ok(pipes) => pipes.clone_for_child(inherit_handles != 0),
        Err(_) => {
            native_set_last_error(6);
            return 0;
        }
    };
    let command_line_w = command_line_w(
        &launch.application,
        launch.arguments.get(1..).unwrap_or(&[]),
    )
    .unwrap_or_else(|_| vec![0]);
    let child_context = Arc::new(NativeProcessContext {
        image_base: image.image_base,
        module_path: launch.application.clone(),
        process_id: child.process_id,
        process_handle,
        parent_process_id: parent.process_id,
        command_line_a: command_line_a(&command_line_w),
        command_line_w,
        environment_block: Mutex::new(environment_strings(&environment)),
        environment: Mutex::new(environment),
        std_handles: [
            AtomicU64::new(child_std_handles[0]),
            AtomicU64::new(child_std_handles[1]),
            AtomicU64::new(child_std_handles[2]),
        ],
        crt_fds: Mutex::new(HashMap::new()),
        crt_fd_next: AtomicI32::new(3),
        fs: child_fs,
        named_pipes: Mutex::new(child_pipes),
        error_mode: AtomicU32::new(0),
        pointer_cookie: random_pointer_cookie(),
        heap_allocations: Mutex::new(HashMap::new()),
        virtual_allocations: Mutex::new(HashMap::new()),
        file_mappings: Mutex::new(HashMap::new()),
        mapping_views: Mutex::new(HashMap::new()),
        mapping_next: AtomicU64::new(0x9800_0000),
        gs_base: AtomicU64::new(0),
        tls_template: Mutex::new(tls.as_ref().map(NativeTls::clone_for_thread)),
        dynamic_tls: Mutex::new(DynamicTlsSlots::new(tls.is_some())),
        threads: Mutex::new(HashMap::new()),
        thread_next: AtomicU64::new(0x8000_0000),
        semaphores: Mutex::new(HashMap::new()),
        semaphore_next: AtomicU64::new(0x6000_0000),
        events: Mutex::new(HashMap::new()),
        event_names: Mutex::new(HashMap::new()),
        event_next: AtomicU64::new(0x6100_0000),
        job_objects: Mutex::new(HashMap::new()),
        wait_registrations: Mutex::new(HashMap::new()),
        completion_ports: Mutex::new(HashMap::new()),
        socket_completion_ports: Mutex::new(HashMap::new()),
        socket_completion_modes: Mutex::new(HashMap::new()),
        completion_next: AtomicU64::new(0x9000_0000),
        io_wait: Mutex::new(()),
        io_ready: Condvar::new(),
        pending_file_io: AtomicU64::new(0),
        pending_requests: Mutex::new(HashMap::new()),
        file_io_queue: Mutex::new(None),
        duplicate_handles: Mutex::new(HashMap::new()),
        duplicate_next: AtomicU64::new(0xa000_0000),
        timer_next: AtomicU64::new(0x7000_0000),
        state_fd: AtomicU32::new(state_fds[1] as u32),
        fls_value: AtomicU64::new(0),
        unhandled_exception_filter: AtomicU64::new(0),
        vectored_exception_handler: AtomicU64::new(0),
        exit_status: AtomicU32::new(259),
        exited: AtomicBool::new(false),
        children: Mutex::new(NativeProcessTable::new()),
    });
    let mut child_tls = tls;
    let mut fallback_teb = Box::new([0u8; 0x1000]);
    let child_teb = child_tls
        .as_mut()
        .map(|tls| &mut tls.teb)
        .unwrap_or(&mut fallback_teb);
    // Stack discovery reads /proc and consults diagnostics, so do it in
    // the parent before fork instead of running library code in the child.
    set_teb_stack_bounds(child_teb);
    let child_teb_base = child_teb.as_ptr() as u64;
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
        THREAD_NATIVE_PROCESS.with(|active| {
            *active.borrow_mut() = Some(child_context);
        });
        if protect_exec(&mapping).is_err() {
            unsafe { _exit(127) };
        }
        if !unsafe { set_gs(child_teb_base) } {
            unsafe { _exit(127) };
        }
        THREAD_TEB_BASE.set(child_teb_base);
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
    native_wait_file_io(&process);
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
    let Ok(encoded) = crate::snapshot::encode_changes(&ctx.fs) else {
        return;
    };
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
    let base = THREAD_TEB_BASE.get();
    if base != 0 {
        unsafe { ((base + 0x68) as *const u32).read_unaligned() }
    } else {
        THREAD_LAST_ERROR.get()
    }
}

extern "win64" fn native_set_last_error(error: u32) {
    THREAD_LAST_ERROR.set(error);
    let base = THREAD_TEB_BASE.get();
    if base != 0 {
        unsafe { ((base + 0x68) as *mut u32).write_unaligned(error) };
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

extern "win64" fn native_get_startup_info_a(startup_info: *mut u8) {
    // STARTUPINFOA and STARTUPINFOW have the same 64-bit layout; the
    // zeroed console-process baseline contains no character fields.
    native_get_startup_info_w(startup_info);
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

extern "win64" fn native_compare_string_ordinal(
    left: *const u16,
    left_len: i32,
    right: *const u16,
    right_len: i32,
    ignore_case: i32,
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
    if ignore_case != 0 {
        uppercase_ascii_utf16(&mut left);
        uppercase_ascii_utf16(&mut right);
    }
    match left.cmp(&right) {
        std::cmp::Ordering::Less => 1,
        std::cmp::Ordering::Equal => 2,
        std::cmp::Ordering::Greater => 3,
    }
}

#[cfg(test)]
mod compare_string_ordinal_tests {
    use super::*;

    #[test]
    fn compares_utf16_text_case_sensitively_or_ordinally() {
        let left: Vec<u16> = "npm".encode_utf16().chain([0]).collect();
        let right: Vec<u16> = "NPM".encode_utf16().chain([0]).collect();
        assert_eq!(
            native_compare_string_ordinal(left.as_ptr(), -1, right.as_ptr(), -1, 1),
            2
        );
        assert_eq!(
            native_compare_string_ordinal(left.as_ptr(), -1, right.as_ptr(), -1, 0),
            3
        );
    }
}

extern "win64" fn native_load_library_ex_w(path: *const u16, _file: u64, _flags: u32) -> u64 {
    (!path.is_null()).then_some(API_SET_MODULE).unwrap_or(0)
}

extern "win64" fn native_load_library_ex_a(path: *const u8, _file: u64, _flags: u32) -> u64 {
    if unsafe { ascii_z(path) }.is_some() {
        API_SET_MODULE
    } else {
        native_set_last_error(126); // ERROR_MOD_NOT_FOUND
        0
    }
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
extern "win64" fn native_nt_device_io_control_file(
    _file: u64,
    _event: u64,
    _apc_routine: u64,
    _apc_context: u64,
    io_status: *mut u8,
    _control_code: u32,
    _input: *const u8,
    _input_len: u32,
    _output: *mut u8,
    _output_len: u32,
) -> u32 {
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    if !io_status.is_null() {
        unsafe {
            (io_status as *mut u32).write_unaligned(STATUS_NOT_IMPLEMENTED);
            (io_status.add(8) as *mut u64).write_unaligned(0);
        }
    }
    STATUS_NOT_IMPLEMENTED
}

extern "win64" fn native_nt_read_file(
    file: u64,
    event: u64,
    apc_routine: u64,
    _apc_context: u64,
    io_status: *mut u8,
    buffer: *mut u8,
    length: u32,
    byte_offset: *const i64,
    _key: *const u32,
) -> u32 {
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_END_OF_FILE: u32 = 0xC000_0011;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
    let finish = |status: u32, bytes: usize| {
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(bytes as u64);
            }
        }
        status
    };
    if io_status.is_null() || (buffer.is_null() && length != 0) {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    if event != 0 || apc_routine != 0 {
        return finish(STATUS_NOT_SUPPORTED, 0);
    }
    if length == 0 {
        return finish(STATUS_SUCCESS, 0);
    }
    let requested_offset = if byte_offset.is_null() {
        None
    } else {
        let value = unsafe { byte_offset.read_unaligned() };
        if value == -2 {
            None
        } else if value < 0 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        } else {
            Some(value as u64)
        }
    };
    if let Some(fd) = host_standard_fd(file) {
        if requested_offset.is_some() {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let count = unsafe { read(fd, buffer.cast(), length as usize) };
        return if count < 0 {
            finish(0xC000_0001, 0)
        } else if count == 0 {
            finish(STATUS_END_OF_FILE, 0)
        } else {
            finish(STATUS_SUCCESS, count as usize)
        };
    }
    let Some(context) = fs_ctx() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Ok(mut fs) = context.lock() else {
        return finish(0xC000_0001, 0);
    };
    let Some((path, current_offset)) = fs
        .handles
        .get(&file)
        .map(|item| (item.path.clone(), item.offset))
    else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let offset = requested_offset.unwrap_or(current_offset as u64);
    let Ok(offset) = usize::try_from(offset) else {
        return finish(STATUS_INVALID_PARAMETER, 0);
    };
    let Ok(file_length) = fs.fs.file_len(&path) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    if offset as u64 >= file_length {
        return finish(STATUS_END_OF_FILE, 0);
    }
    let mut count = 0usize;
    while count < length as usize {
        let amount = (length as usize - count).min(64 * 1024);
        let Ok(contents) = fs
            .fs
            .read_file_range(&path, (offset + count) as u64, amount)
        else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        if contents.is_empty() {
            break;
        }
        unsafe { ptr::copy_nonoverlapping(contents.as_ptr(), buffer.add(count), contents.len()) };
        count += contents.len();
        if contents.len() < amount {
            break;
        }
    }
    if let Some(item) = fs.handles.get_mut(&file) {
        item.offset = offset + count;
    }
    finish(STATUS_SUCCESS, count)
}

extern "win64" fn native_nt_write_file(
    file: u64,
    event: u64,
    apc_routine: u64,
    _apc_context: u64,
    io_status: *mut u8,
    buffer: *const u8,
    length: u32,
    byte_offset: *const i64,
    _key: *const u32,
) -> u32 {
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
    let finish = |status: u32, bytes: usize| {
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(bytes as u64);
            }
        }
        status
    };
    if io_status.is_null() || (buffer.is_null() && length != 0) {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    if event != 0 || apc_routine != 0 {
        return finish(STATUS_NOT_SUPPORTED, 0);
    }
    if length == 0 {
        return finish(STATUS_SUCCESS, 0);
    }
    let requested_offset = if byte_offset.is_null() {
        None
    } else {
        let value = unsafe { byte_offset.read_unaligned() };
        if value == -2 {
            None
        } else if value < 0 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        } else {
            Some(value as u64)
        }
    };
    if let Some(fd) = host_standard_fd(file) {
        if requested_offset.is_some() {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let count = unsafe { write(fd, buffer.cast(), length as usize) };
        return if count < 0 {
            finish(0xC000_0001, 0)
        } else {
            finish(STATUS_SUCCESS, count as usize)
        };
    }
    let Some(context) = fs_ctx() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Ok(mut fs) = context.lock() else {
        return finish(0xC000_0001, 0);
    };
    let Some((path, current_offset)) = fs
        .handles
        .get(&file)
        .map(|item| (item.path.clone(), item.offset))
    else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let offset = requested_offset.unwrap_or(current_offset as u64);
    let Ok(offset) = usize::try_from(offset) else {
        return finish(STATUS_INVALID_PARAMETER, 0);
    };
    let Ok(mut contents) = fs.fs.read_file(&path) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let count = length as usize;
    let Some(end) = offset.checked_add(count) else {
        return finish(STATUS_INVALID_PARAMETER, 0);
    };
    if contents.len() < end {
        if contents.try_reserve(end - contents.len()).is_err() {
            return finish(0xC000_0017, 0); // STATUS_NO_MEMORY
        }
        contents.resize(end, 0);
    }
    unsafe { ptr::copy_nonoverlapping(buffer, contents.as_mut_ptr().add(offset), count) };
    if fs.fs.write_file(&path, contents).is_err() {
        return finish(0xC000_0001, 0);
    }
    if let Some(item) = fs.handles.get_mut(&file) {
        item.offset = end;
    }
    finish(STATUS_SUCCESS, count)
}

extern "win64" fn native_nt_query_information_file(
    file: u64,
    io_status: *mut u8,
    information: *mut u8,
    length: u32,
    information_class: u32,
) -> u32 {
    let original = process_ctx()
        .and_then(|process| {
            process
                .duplicate_handles
                .lock()
                .ok()
                .and_then(|values| values.get(&file).copied())
        })
        .unwrap_or(file);
    if let Some(fd) = host_standard_fd(original) {
        if !information.is_null() && length >= 4 && matches!(information_class, 8 | 16) {
            let value = match information_class {
                8 if fd == 0 => 1, // FILE_READ_DATA
                8 => 2,            // FILE_WRITE_DATA
                16 => 0x20,        // FILE_SYNCHRONOUS_IO_NONALERT
                _ => unreachable!(),
            };
            unsafe { (information as *mut u32).write_unaligned(value) };
            if !io_status.is_null() {
                unsafe {
                    (io_status as *mut u32).write_unaligned(0);
                    (io_status.add(8) as *mut u64).write_unaligned(4);
                }
            }
            return 0;
        }
    }
    if information_class == 16 && !information.is_null() && length >= 4 {
        if let Some(pipe) = process_ctx().and_then(|process| {
            process
                .named_pipes
                .lock()
                .ok()
                .and_then(|pipes| pipes.handles.get(&original).cloned())
        }) {
            let mode = if pipe.overlapped { 0 } else { 0x20 }; // FILE_SYNCHRONOUS_IO_NONALERT
            unsafe { (information as *mut u32).write_unaligned(mode) };
            if !io_status.is_null() {
                unsafe {
                    (io_status as *mut u32).write_unaligned(0);
                    (io_status.add(8) as *mut u64).write_unaligned(4);
                }
            }
            return 0; // STATUS_SUCCESS
        }
    }
    if information_class == 18 && !information.is_null() && length >= 96 {
        if let Some(context) = fs_ctx() {
            if let Ok(ctx) = context.lock() {
                if let Some(file) = ctx.handles.get(&original) {
                    let is_directory = ctx.fs.is_dir(&file.path);
                    let size = if is_directory {
                        0
                    } else {
                        ctx.fs
                            .read_file(&file.path)
                            .map_or(0, |data| data.len() as u64)
                    };
                    let file_id = ctx.fs.file_id(&file.path).unwrap_or(0);
                    let metadata = ctx.fs.file_metadata(&file.path);
                    let written = length.min(104) as usize;
                    unsafe {
                        std::ptr::write_bytes(information, 0, written);
                        (information as *mut u64).write_unaligned(metadata.creation_time);
                        (information.add(8) as *mut u64).write_unaligned(metadata.access_time);
                        (information.add(16) as *mut u64).write_unaligned(metadata.write_time);
                        (information.add(24) as *mut u64).write_unaligned(metadata.write_time);
                        (information.add(32) as *mut u32).write_unaligned(
                            native_file_attributes_at(&ctx, &file.path, is_directory),
                        );
                        (information.add(40) as *mut u64).write_unaligned(size);
                        (information.add(48) as *mut u64).write_unaligned(size);
                        (information.add(56) as *mut u32).write_unaligned(1);
                        information.add(61).write(is_directory as u8);
                        (information.add(64) as *mut u64).write_unaligned(file_id);
                    }
                    if !io_status.is_null() {
                        unsafe {
                            (io_status as *mut u32).write_unaligned(0);
                            (io_status.add(8) as *mut u64).write_unaligned(written as u64);
                        }
                    }
                    return 0;
                }
            }
        }
    }
    if information_class == 18 {
        let status = if information.is_null() || length < 96 {
            0xC000_0004 // STATUS_INFO_LENGTH_MISMATCH
        } else {
            0xC000_0008 // STATUS_INVALID_HANDLE
        };
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(0);
            }
        }
        return status;
    }
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    if !io_status.is_null() {
        unsafe {
            (io_status as *mut u32).write_unaligned(STATUS_NOT_IMPLEMENTED);
            (io_status.add(8) as *mut u64).write_unaligned(0);
        }
    }
    STATUS_NOT_IMPLEMENTED
}

extern "win64" fn native_nt_set_information_file(
    file: u64,
    io_status: *mut u8,
    information: *const u8,
    length: u32,
    information_class: u32,
) -> u32 {
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    let finish = |status: u32, information: u64| {
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(information);
            }
        }
        status
    };
    if information_class == 20 {
        if information.is_null() || length < 8 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let end = unsafe { information.cast::<i64>().read_unaligned() };
        if end < 0 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let Some(context) = fs_ctx() else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let Ok(mut context) = context.lock() else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let Some(path) = context.handles.get(&file).map(|handle| handle.path.clone()) else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let mapped = process_ctx()
            .and_then(|process| {
                process.mapping_views.lock().ok().map(|views| {
                    views.values().any(|view| {
                        view.backing.as_ref().is_some_and(|(mapped_path, _)| {
                            context.fs.normalize(mapped_path).ok()
                                == context.fs.normalize(&path).ok()
                        })
                    })
                })
            })
            .unwrap_or(false);
        let mut contents = match context.fs.read_file(&path) {
            Ok(contents) => contents,
            Err(_) => return finish(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        };
        if (end as usize) < contents.len() && mapped {
            return finish(STATUS_ACCESS_DENIED, 0);
        }
        let Ok(end) = usize::try_from(end) else {
            return finish(STATUS_INVALID_PARAMETER, 0);
        };
        contents.resize(end, 0);
        return match context.fs.write_file(&path, contents) {
            Ok(()) => finish(STATUS_SUCCESS, end as u64),
            Err(_) => finish(STATUS_ACCESS_DENIED, 0),
        };
    }
    if information_class == 10 {
        if information.is_null() || length < 20 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let replace = unsafe { information.read() != 0 };
        let name_length = unsafe { information.add(16).cast::<u32>().read_unaligned() } as usize;
        if name_length == 0 || name_length % 2 != 0 || name_length > length as usize - 20 {
            return finish(STATUS_INVALID_PARAMETER, 0);
        }
        let name = unsafe {
            std::slice::from_raw_parts(information.add(20).cast::<u16>(), name_length / 2)
        };
        let destination = String::from_utf16_lossy(name);
        let Some(context) = fs_ctx() else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let Ok(mut context) = context.lock() else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        let Some(source) = context.handles.get(&file).map(|handle| handle.path.clone()) else {
            return finish(STATUS_INVALID_HANDLE, 0);
        };
        if context.fs.exists(&destination) {
            if !replace {
                return finish(0xC000_0035, 0); // STATUS_OBJECT_NAME_COLLISION
            }
            let is_dir = context.fs.is_dir(&destination);
            let removed = if is_dir {
                context.fs.rmdir(&destination)
            } else {
                context.fs.delete_file(&destination)
            };
            if removed.is_err() {
                return finish(STATUS_ACCESS_DENIED, 0);
            }
        }
        return match context.fs.move_path(&source, &destination) {
            Ok(()) => {
                for handle in context.handles.values_mut() {
                    if handle.path.eq_ignore_ascii_case(&source) {
                        handle.path = destination.clone();
                    }
                }
                finish(STATUS_SUCCESS, 0)
            }
            Err(_) => finish(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        };
    }
    let disposition = match information_class {
        13 if !information.is_null() && length >= 1 => unsafe {
            u32::from(information.read() != 0)
        },
        // FILE_DISPOSITION_INFORMATION_EX: Flags is a ULONG; DELETE is
        // bit 0. libuv uses this class for recursive fs.rm/unlink on
        // current Windows releases.
        64 if !information.is_null() && length >= 4 => unsafe {
            information.cast::<u32>().read_unaligned()
        },
        13 | 64 => return finish(STATUS_INVALID_PARAMETER, 0),
        _ => return finish(STATUS_NOT_IMPLEMENTED, 0),
    };
    // A zero disposition cancels deletion. The in-memory filesystem only
    // removes names on a set operation, so clearing is a successful no-op.
    if disposition == 0 {
        return finish(STATUS_SUCCESS, 0);
    }
    if disposition & !0x3f != 0 {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    let Some(context) = fs_ctx() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Ok(mut context) = context.lock() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Some(path) = context.handles.get(&file).map(|handle| handle.path.clone()) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let status = if context.fs.is_dir(&path) {
        context.fs.rmdir(&path)
    } else {
        context.fs.delete_file(&path)
    };
    match status {
        Ok(()) => finish(STATUS_SUCCESS, 0),
        Err(_) if !context.fs.exists(&path) => finish(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        Err(_) => finish(STATUS_ACCESS_DENIED, 0),
    }
}

extern "win64" fn native_nt_query_volume_information_file(
    file: u64,
    io_status: *mut u8,
    information: *mut u8,
    length: u32,
    information_class: u32,
) -> u32 {
    if information_class == 4 && !information.is_null() && length >= 8 {
        if fs_ctx().is_some_and(|context| {
            context
                .lock()
                .is_ok_and(|fs| fs.handles.contains_key(&file))
        }) {
            unsafe {
                (information as *mut u32).write_unaligned(7); // FILE_DEVICE_DISK
                (information.add(4) as *mut u32).write_unaligned(0);
            }
            if !io_status.is_null() {
                unsafe {
                    (io_status as *mut u32).write_unaligned(0);
                    (io_status.add(8) as *mut u64).write_unaligned(8);
                }
            }
            return 0;
        }
    }
    if information_class == 4 {
        let status = if information.is_null() || length < 8 {
            0xC000_0004 // STATUS_INFO_LENGTH_MISMATCH
        } else {
            0xC000_0008 // STATUS_INVALID_HANDLE
        };
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(0);
            }
        }
        return status;
    }
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    if !io_status.is_null() {
        unsafe {
            (io_status as *mut u32).write_unaligned(STATUS_NOT_IMPLEMENTED);
            (io_status.add(8) as *mut u64).write_unaligned(0);
        }
    }
    STATUS_NOT_IMPLEMENTED
}

extern "win64" fn native_nt_query_directory_file(
    file: u64,
    _event: u64,
    _apc_routine: u64,
    _apc_context: u64,
    io_status: *mut u8,
    information: *mut u8,
    length: u32,
    information_class: u32,
    return_single_entry: u8,
    _file_name: *const u8,
    restart_scan: u8,
) -> u32 {
    const STATUS_SUCCESS: u32 = 0;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
    let finish = |status: u32, bytes: usize| {
        if !io_status.is_null() {
            unsafe {
                (io_status as *mut u32).write_unaligned(status);
                (io_status.add(8) as *mut u64).write_unaligned(bytes as u64);
            }
        }
        status
    };
    if io_status.is_null() || (information.is_null() && length != 0) {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    if information_class != 1 || return_single_entry > 1 || length < 64 {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    let Some(context) = fs_ctx() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Ok(mut ctx) = context.lock() else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let Some(file_info) = ctx.handles.get(&file) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let path = file_info.path.clone();
    if !ctx.fs.is_dir(&path) {
        return finish(STATUS_INVALID_PARAMETER, 0);
    }
    let Ok(names) = ctx.fs.list_dir(&path) else {
        return finish(STATUS_INVALID_HANDLE, 0);
    };
    let index = if restart_scan != 0 {
        0
    } else {
        file_info.offset
    };
    if index >= names.len() {
        if let Some(file_info) = ctx.handles.get_mut(&file) {
            file_info.offset = names.len();
        }
        return finish(STATUS_NO_MORE_FILES, 0);
    }
    let mut written = 0usize;
    let mut current = index;
    loop {
        let encoded: Vec<u16> = names[current].encode_utf16().collect();
        let entry_size = (64 + encoded.len() * 2 + 7) & !7;
        if written + entry_size > length as usize {
            if written == 0 {
                return finish(STATUS_INVALID_PARAMETER, 0);
            }
            break;
        }
        unsafe {
            let entry = information.add(written);
            std::ptr::write_bytes(entry, 0, entry_size);
            (entry.add(60) as *mut u32).write_unaligned((encoded.len() * 2) as u32);
            entry
                .add(56)
                .cast::<u32>()
                .write_unaligned(native_file_attributes(
                    ctx.fs.is_dir(&format!("{path}\\{}", names[current])),
                ));
            entry
                .add(64)
                .cast::<u16>()
                .copy_from_nonoverlapping(encoded.as_ptr(), encoded.len());
        }
        let next = current + 1;
        if return_single_entry != 0 || next == names.len() {
            written += 64 + encoded.len() * 2;
            current = next;
            break;
        }
        let next_size = (64 + names[next].encode_utf16().count() * 2 + 7) & !7;
        if written + entry_size + next_size > length as usize {
            written += 64 + encoded.len() * 2;
            current = next;
            break;
        }
        unsafe {
            (information.add(written) as *mut u32).write_unaligned(entry_size as u32);
        }
        written += entry_size;
        current = next;
    }
    if let Some(file_info) = ctx.handles.get_mut(&file) {
        file_info.offset = current;
    }
    finish(STATUS_SUCCESS, written)
}

extern "win64" fn native_nt_query_system_information(
    _information_class: u32,
    _information: *mut u8,
    _length: u32,
    return_length: *mut u32,
) -> u32 {
    if !return_length.is_null() {
        unsafe { return_length.write(0) };
    }
    0xC000_0002 // STATUS_NOT_IMPLEMENTED
}

extern "win64" fn native_nt_query_information_process(
    _process: u64,
    _information_class: u32,
    _information: *mut u8,
    _length: u32,
    return_length: *mut u32,
) -> u32 {
    if !return_length.is_null() {
        unsafe { return_length.write(0) };
    }
    0xC000_0002 // STATUS_NOT_IMPLEMENTED
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

extern "win64" fn native_virtual_alloc(
    address: *mut u8,
    size: usize,
    allocation_type: u32,
    protection: u32,
) -> *mut u8 {
    if native_diagnostic_enabled() {
        eprintln!("native VirtualAlloc address={address:p} size={size:#x} type={allocation_type:#x} protection={protection:#x}");
    }
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RESET: u32 = 0x80000;
    if allocation_type == MEM_RESET {
        let Ok(length) = page_len(size) else {
            native_set_last_error(87);
            return ptr::null_mut();
        };
        if address.is_null() || unsafe { madvise(address.cast(), length, 4) } != 0 {
            native_set_last_error(487);
            return ptr::null_mut();
        }
        return address;
    }
    if size == 0 || allocation_type & (MEM_COMMIT | MEM_RESERVE) == 0 {
        native_set_last_error(87);
        return ptr::null_mut();
    }
    let Some(host_protection) = linux_protection(protection) else {
        native_set_last_error(87);
        return ptr::null_mut();
    };
    let Ok(length) = page_len(size) else {
        native_set_last_error(8);
        return ptr::null_mut();
    };
    let Some(process) = process_ctx() else {
        return ptr::null_mut();
    };
    if allocation_type & MEM_RESERVE == 0 {
        if address.is_null() || (address as usize) & 4095 != 0 {
            native_set_last_error(487); // ERROR_INVALID_ADDRESS
            return ptr::null_mut();
        }
        let inside_reservation = process.virtual_allocations.lock().is_ok_and(|allocations| {
            allocations.iter().any(|(&base, allocation)| {
                (address as u64) >= base
                    && (address as u64)
                        .checked_add(length as u64)
                        .is_some_and(|end| end <= base + allocation.length as u64)
            })
        });
        if !inside_reservation || unsafe { mprotect(address.cast(), length, host_protection) } != 0
        {
            native_set_last_error(487);
            return ptr::null_mut();
        }
        return address;
    }
    if !address.is_null() && (address as usize) & 0xffff != 0 {
        native_set_last_error(487);
        return ptr::null_mut();
    }
    let initial_protection = if allocation_type & MEM_COMMIT != 0 {
        host_protection
    } else {
        0
    };
    let result = if address.is_null() {
        let Some(overlength) = length.checked_add(0x10000) else {
            native_set_last_error(8);
            return ptr::null_mut();
        };
        let raw = unsafe {
            mmap(
                ptr::null_mut(),
                overlength,
                initial_protection,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == MAP_FAILED {
            native_set_last_error(8);
            return ptr::null_mut();
        }
        let base = raw as usize;
        let aligned = (base + 0xffff) & !0xffff;
        let prefix = aligned - base;
        let suffix = overlength - prefix - length;
        if prefix != 0 {
            unsafe { munmap(raw, prefix) };
        }
        if suffix != 0 {
            unsafe { munmap((aligned + length) as *mut c_void, suffix) };
        }
        aligned as *mut u8
    } else {
        let raw = unsafe {
            mmap(
                address.cast(),
                length,
                initial_protection,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if raw == MAP_FAILED {
            native_set_last_error(487);
            return ptr::null_mut();
        }
        raw.cast()
    };
    if let Ok(mut allocations) = process.virtual_allocations.lock() {
        allocations.insert(result as u64, NativeVirtualAllocation { length });
    }
    result
}

extern "win64" fn native_virtual_free(address: *mut u8, size: usize, free_type: u32) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    if address.is_null() {
        native_set_last_error(87);
        return 0;
    }
    if free_type == 0x8000 {
        // MEM_RELEASE
        if size != 0 {
            native_set_last_error(87);
            return 0;
        }
        let allocation = process
            .virtual_allocations
            .lock()
            .ok()
            .and_then(|mut values| values.remove(&(address as u64)));
        let Some(allocation) = allocation else {
            native_set_last_error(487);
            return 0;
        };
        return (unsafe { munmap(address.cast(), allocation.length) } == 0) as i32;
    }
    if free_type == 0x4000 {
        // MEM_DECOMMIT
        let Ok(length) = page_len(size) else {
            native_set_last_error(87);
            return 0;
        };
        let inside_reservation = process.virtual_allocations.lock().is_ok_and(|values| {
            values.iter().any(|(&base, allocation)| {
                (address as u64) >= base
                    && (address as u64)
                        .checked_add(length as u64)
                        .is_some_and(|end| end <= base + allocation.length as u64)
            })
        });
        if !inside_reservation || unsafe { mprotect(address.cast(), length, 0) } != 0 {
            native_set_last_error(487);
            return 0;
        }
        unsafe { madvise(address.cast(), length, 4) }; // MADV_DONTNEED
        return 1;
    }
    native_set_last_error(87);
    0
}

extern "win64" fn native_network_u16(value: u16) -> u16 {
    value.swap_bytes()
}

extern "win64" fn native_network_u32(value: u32) -> u32 {
    value.swap_bytes()
}

extern "win64" fn native_get_system_metrics(_index: i32) -> i32 {
    // The native CLI guest has no Windows desktop session. The documented
    // value for absent/unsupported system metrics is zero.
    0
}

extern "win64" fn native_message_beep(_kind: u32) -> i32 {
    // The CLI guest has no Windows sound device; match the successful
    // best-effort behavior of MessageBeep without producing host audio.
    1
}

extern "win64" fn native_get_locale_info_ex(
    locale: *const u16,
    kind: u32,
    output: *mut u16,
    capacity: i32,
) -> i32 {
    if native_diagnostic_enabled() {
        eprintln!(
            "native GetLocaleInfoEx locale={:?} kind={kind:#x}",
            wide(locale)
        );
    }
    if kind == 0x5c {
        let value: Vec<u16> = "en-US\0".encode_utf16().collect();
        if capacity == 0 {
            return value.len() as i32;
        }
        if capacity > 0 && (capacity as usize) >= value.len() && !output.is_null() {
            unsafe { ptr::copy_nonoverlapping(value.as_ptr(), output, value.len()) };
            return value.len() as i32;
        }
        native_set_last_error(122);
        return 0;
    }
    native_set_last_error(87);
    0
}

extern "win64" fn native_are_file_apis_ansi() -> i32 {
    1
}
extern "win64" fn native_set_named_pipe_handle_state(
    handle: u64,
    mode: *const u32,
    _max_collection_count: *const u32,
    _collect_data_timeout: *const u32,
) -> i32 {
    if host_standard_fd(handle).is_some_and(|fd| unsafe { isatty(fd) } == 0)
        && (mode.is_null() || unsafe { mode.read() } & !0x3 == 0)
    {
        return 1;
    }
    if let Some(process) = process_ctx() {
        if let Ok(mut pipes) = process.named_pipes.lock() {
            if let Some(pipe) = pipes.handles.get_mut(&handle) {
                if mode.is_null() {
                    return 1;
                }
                let mode = unsafe { mode.read() };
                if mode & !0x3 != 0 {
                    native_set_last_error(87);
                    return 0;
                }
                pipe.mode = mode;
                return 1;
            }
        }
    }
    native_set_last_error(6);
    0
}
extern "win64" fn native_get_named_pipe_handle_state_w(
    handle: u64,
    mode: *mut u32,
    current_instances: *mut u32,
    _max_collection_count: *mut u32,
    _collect_data_timeout: *mut u32,
    _user_name: *mut u16,
    _max_user_name_size: u32,
) -> i32 {
    if host_standard_fd(handle).is_some_and(|fd| unsafe { isatty(fd) } == 0) {
        if !mode.is_null() {
            unsafe { mode.write(0) };
        }
        if !current_instances.is_null() {
            unsafe { current_instances.write(1) };
        }
        return 1;
    }
    let Some(pipe) = process_ctx().and_then(|process| {
        process
            .named_pipes
            .lock()
            .ok()
            .and_then(|pipes| pipes.handles.get(&handle).cloned())
    }) else {
        native_set_last_error(6);
        return 0;
    };
    if !mode.is_null() {
        unsafe { mode.write(pipe.mode) };
    }
    1
}
extern "win64" fn native_get_named_pipe_handle_state_a(
    handle: u64,
    mode: *mut u32,
    current_instances: *mut u32,
    max_collection_count: *mut u32,
    collect_data_timeout: *mut u32,
    user_name: *mut u8,
    max_user_name_size: u32,
) -> i32 {
    if !user_name.is_null() && max_user_name_size != 0 {
        native_set_last_error(50); // ERROR_NOT_SUPPORTED: client identity is not modeled.
        return 0;
    }
    native_get_named_pipe_handle_state_w(
        handle,
        mode,
        current_instances,
        max_collection_count,
        collect_data_timeout,
        std::ptr::null_mut(),
        0,
    )
}

#[cfg(test)]
mod named_pipe_tests {
    use super::*;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    fn server(name: &str, open_mode: u32) -> u64 {
        let path = wide(&format!(r"\\.\pipe\{name}"));
        native_create_named_pipe_w(
            path.as_ptr(),
            open_mode | 0x0004_0000, // WRITE_DAC, as used by libuv
            0,
            1,
            4096,
            4096,
            0,
            0,
        )
    }

    fn client(name: &str, access: u32, flags: u32) -> u64 {
        let path = wide(&format!(r"\\?\pipe\{name}"));
        native_create_file_w(path.as_ptr(), access, 0, 0, 3, flags, 0)
    }

    #[test]
    fn named_pipe_pair_connects_and_transfers_duplex_bytes() {
        let name = format!("uv\\wincli-unit-{}", std::process::id());
        let server = server(&name, 3);
        assert_ne!(server, u64::MAX);
        let client = client(&name, 0xc000_0000, 0);
        assert_ne!(client, u64::MAX);
        assert_eq!(native_connect_named_pipe(server, 0), 0);
        assert_eq!(native_get_last_error(), 535);

        let payload = b"duplex-pipe";
        let mut written = 0;
        assert_eq!(
            native_write_file(
                server,
                payload.as_ptr(),
                payload.len() as u32,
                &mut written,
                0
            ),
            1
        );
        assert_eq!(written, payload.len() as u32);
        let mut received = [0u8; 16];
        let mut read = 0;
        assert_eq!(
            native_read_file(
                client,
                received.as_mut_ptr(),
                received.len() as u32,
                &mut read,
                0,
            ),
            1
        );
        assert_eq!(&received[..read as usize], payload);
        assert_eq!(native_get_file_type(server), 3);
        assert_eq!(native_close_handle(client), 1);
        assert_eq!(native_close_handle(server), 1);
    }

    #[test]
    fn named_pipe_checks_client_direction_and_supports_overlapped_completion() {
        let name = format!("uv\\wincli-io-{}", std::process::id());
        let server = server(&name, 2); // Server writes; client must read.
        assert_ne!(server, u64::MAX);
        assert_eq!(client(&name, 0x4000_0000, 0), u64::MAX);
        assert_eq!(native_get_last_error(), 5);
        let client = client(&name, 0x8000_0000, 0x4000_0000);
        assert_ne!(client, u64::MAX);
        assert_eq!(native_connect_named_pipe(server, 0), 0);
        assert_eq!(native_get_last_error(), 535);

        let port_handle = native_create_io_completion_port(u64::MAX, 0, 0, 1);
        assert_ne!(port_handle, 0);
        assert_eq!(
            native_create_io_completion_port(client, port_handle, 0x1234, 1),
            port_handle
        );
        assert_eq!(
            native_set_file_completion_notification_modes(client, 0x3),
            1
        );
        let mut overlapped = [0u64; 4];
        let mut received = [0u8; 32];
        assert_eq!(
            native_read_file(
                client,
                received.as_mut_ptr(),
                received.len() as u32,
                std::ptr::null_mut(),
                overlapped.as_mut_ptr() as u64,
            ),
            0
        );
        assert_eq!(native_get_last_error(), 997);
        let payload = b"async-pipe";
        let mut written = 0;
        assert_eq!(
            native_write_file(
                server,
                payload.as_ptr(),
                payload.len() as u32,
                &mut written,
                0
            ),
            1
        );
        let process = process_ctx().unwrap();
        let port = process
            .completion_ports
            .lock()
            .unwrap()
            .get(&port_handle)
            .unwrap()
            .clone();
        let mut queue = port.queue.lock().unwrap();
        while queue.is_empty() {
            queue = port.ready.wait(queue).unwrap();
        }
        let completion = queue.pop_front().unwrap();
        assert_eq!(completion.key, 0x1234);
        assert_eq!(completion.overlapped, overlapped.as_ptr() as u64);
        assert_eq!(completion.status, 0);
        assert_eq!(completion.bytes, payload.len() as u32);
        assert_eq!(&received[..completion.bytes as usize], payload);
        assert_eq!(native_close_handle(client), 1);
        assert_eq!(native_close_handle(server), 1);
        assert_eq!(native_close_handle(port_handle), 1);
    }

    #[test]
    fn named_pipe_overlapped_connect_completes_when_client_arrives_later() {
        let name = format!("uv\\wincli-connect-{}", std::process::id());
        let server = server(&name, 0x4000_0003);
        assert_ne!(server, u64::MAX);
        let port = native_create_io_completion_port(u64::MAX, 0, 0, 1);
        assert_eq!(
            native_create_io_completion_port(server, port, 0x5678, 1),
            port
        );
        let mut overlapped = [0u64; 4];
        assert_eq!(
            native_connect_named_pipe(server, overlapped.as_mut_ptr() as u64),
            0
        );
        assert_eq!(native_get_last_error(), 997);
        let client = client(&name, 0xc000_0000, 0x4000_0000);
        assert_ne!(client, u64::MAX);

        let process = process_ctx().unwrap();
        let completion_port = process
            .completion_ports
            .lock()
            .unwrap()
            .get(&port)
            .unwrap()
            .clone();
        let mut queue = completion_port.queue.lock().unwrap();
        while queue.is_empty() {
            queue = completion_port.ready.wait(queue).unwrap();
        }
        let completion = queue.pop_front().unwrap();
        assert_eq!(completion.key, 0x5678);
        assert_eq!(completion.overlapped, overlapped.as_ptr() as u64);
        assert_eq!(completion.status, 0);
        assert_eq!(native_close_handle(client), 1);
        assert_eq!(native_close_handle(server), 1);
        assert_eq!(native_close_handle(port), 1);
    }

    #[test]
    fn process_startup_inherits_the_requested_windows_standard_handles() {
        let mut startup = [0u8; 104];
        unsafe {
            startup
                .as_mut_ptr()
                .add(60)
                .cast::<u32>()
                .write_unaligned(0x100);
            startup
                .as_mut_ptr()
                .add(80)
                .cast::<u64>()
                .write_unaligned(0xb000_0001);
            startup
                .as_mut_ptr()
                .add(88)
                .cast::<u64>()
                .write_unaligned(0xb000_0003);
            startup
                .as_mut_ptr()
                .add(96)
                .cast::<u64>()
                .write_unaligned(0xb000_0005);
        }
        assert_eq!(
            native_startup_std_handles(
                startup.as_ptr() as u64,
                [0x5000_0000, 0x5000_0001, 0x5000_0002]
            ),
            [0xb000_0001, 0xb000_0003, 0xb000_0005]
        );
        unsafe {
            startup
                .as_mut_ptr()
                .add(60)
                .cast::<u32>()
                .write_unaligned(0)
        };
        assert_eq!(
            native_startup_std_handles(
                startup.as_ptr() as u64,
                [0x5000_0000, 0x5000_0001, 0x5000_0002]
            ),
            [0x5000_0000, 0x5000_0001, 0x5000_0002]
        );
    }
}
extern "win64" fn native_reg_open_key_ex_w(
    _key: u64,
    _name: *const u16,
    _options: u32,
    _access: u32,
    out: *mut u64,
) -> u32 {
    if !out.is_null() {
        unsafe { out.write(0) };
    }
    2 // ERROR_FILE_NOT_FOUND: no registry is mounted in the guest.
}
extern "win64" fn native_reg_open_key_ex_a(
    key: u64,
    name: *const u8,
    options: u32,
    access: u32,
    out: *mut u64,
) -> u32 {
    if name.is_null() {
        native_set_last_error(87);
        return 87;
    }
    let mut units = Vec::new();
    for index in 0..32768 {
        let byte = unsafe { name.add(index).read() };
        if byte == 0 {
            units.push(0);
            return native_reg_open_key_ex_w(key, units.as_ptr(), options, access, out);
        }
        units.push(byte as u16);
    }
    native_set_last_error(87);
    87
}
extern "win64" fn native_reg_create_key_ex_w(
    _key: u64,
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
        return 87;
    }
    let handle = NATIVE_REGISTRY_HANDLE_NEXT.fetch_add(1, Ordering::Relaxed);
    unsafe {
        out.write_unaligned(handle);
        if !disposition.is_null() {
            disposition.write_unaligned(1); // REG_CREATED_NEW_KEY
        }
    }
    0
}
extern "win64" fn native_reg_set_value_ex_w(
    key: u64,
    _value_name: *const u16,
    _reserved: u32,
    _value_type: u32,
    data: *const u8,
    data_len: u32,
) -> u32 {
    if key == 0 || (data.is_null() && data_len != 0) {
        return 87;
    }
    0
}
extern "win64" fn native_reg_query_value_ex_w(
    _key: u64,
    _value_name: *const u16,
    _reserved: *mut u32,
    _value_type: *mut u32,
    _data: *mut u8,
    _data_len: *mut u32,
) -> u32 {
    2 // ERROR_FILE_NOT_FOUND
}
extern "win64" fn native_reg_close_key(_key: u64) -> u32 {
    0
}

extern "win64" fn native_local_free(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let Some(process) = process_ctx() else {
        return value;
    };
    if process
        .heap_allocations
        .lock()
        .is_ok_and(|mut values| values.remove(&value).is_some())
    {
        unsafe { free(value as *mut c_void) };
        0
    } else {
        native_set_last_error(6);
        value
    }
}
extern "win64" fn native_free_library_and_exit_thread(_module: u64, _code: u32) -> ! {
    if native_diagnostic_enabled() {
        eprintln!("native FreeLibraryAndExitThread");
    }
    let handle = THREAD_NATIVE_HANDLE.get();
    if let Some(process) = process_ctx() {
        if let Ok(mut threads) = process.threads.lock() {
            if let Some(thread) = threads.get_mut(&handle) {
                thread.exit_code = Some(_code);
            }
        }
    }
    // SYS_exit terminates only this Linux thread. pthread_exit would
    // force-unwind across PE and Rust frames and abort the guest process.
    unsafe {
        core::arch::asm!("syscall", in("rax") 60u64, in("rdi") _code as u64, options(noreturn))
    }
}

extern "win64" fn native_create_file_mapping_w(
    file: u64,
    _attributes: u64,
    protection: u32,
    size_high: u32,
    size_low: u32,
    _name: *const u16,
) -> u64 {
    let requested_size = ((size_high as u64) << 32) | size_low as u64;
    if !matches!(protection, 0x02 | 0x04) || requested_size > usize::MAX as u64 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let (path, size) = if file == u64::MAX {
        if requested_size == 0 {
            native_set_last_error(87);
            return 0;
        }
        (None, requested_size as usize)
    } else {
        let Some(context) = fs_ctx() else {
            native_set_last_error(6);
            return 0;
        };
        let Ok(mut ctx) = context.lock() else {
            native_set_last_error(6);
            return 0;
        };
        let Some(native_file) = ctx.handles.get(&file) else {
            native_set_last_error(6);
            return 0;
        };
        if ctx.fs.is_dir(&native_file.path) {
            native_set_last_error(87);
            return 0;
        }
        let path = native_file.path.clone();
        let mut contents = match ctx.fs.read_file(&path) {
            Ok(contents) => contents,
            Err(_) => {
                native_set_last_error(6);
                return 0;
            }
        };
        let size = if requested_size == 0 {
            contents.len()
        } else {
            requested_size as usize
        };
        if size == 0 {
            native_set_last_error(87);
            return 0;
        }
        if contents.len() < size {
            contents.resize(size, 0);
            if ctx.fs.write_file(&path, contents).is_err() {
                native_set_last_error(5);
                return 0;
            }
        }
        (Some(path), size)
    };
    let handle = process.mapping_next.fetch_add(1, Ordering::AcqRel);
    let result = if let Ok(mut values) = process.file_mappings.lock() {
        values.insert(
            handle,
            NativeFileMapping {
                length: size,
                protection,
                path,
            },
        );
        handle
    } else {
        0
    };
    result
}

extern "win64" fn native_create_file_mapping_a(
    file: u64,
    attributes: u64,
    protection: u32,
    size_high: u32,
    size_low: u32,
    _name: *const u8,
) -> u64 {
    native_create_file_mapping_w(
        file,
        attributes,
        protection,
        size_high,
        size_low,
        std::ptr::null(),
    )
}

extern "win64" fn native_map_view_of_file(
    mapping: u64,
    access: u32,
    offset_high: u32,
    offset_low: u32,
    bytes: usize,
) -> *mut u8 {
    let Some(process) = process_ctx() else {
        return ptr::null_mut();
    };
    let Some(mapping) = process
        .file_mappings
        .lock()
        .ok()
        .and_then(|values| values.get(&mapping).cloned())
    else {
        native_set_last_error(6);
        return ptr::null_mut();
    };
    let offset = ((offset_high as u64) << 32) | offset_low as u64;
    let Ok(offset) = usize::try_from(offset) else {
        native_set_last_error(87);
        return ptr::null_mut();
    };
    let length = if bytes == 0 {
        mapping.length.saturating_sub(offset)
    } else {
        bytes
    };
    let Some(end) = offset.checked_add(length) else {
        native_set_last_error(87);
        return ptr::null_mut();
    };
    if length == 0 || end > mapping.length || (access & 0x2 != 0 && mapping.protection != 0x04) {
        native_set_last_error(87);
        return ptr::null_mut();
    }
    let Ok(mapped_length) = page_len(length) else {
        native_set_last_error(8);
        return ptr::null_mut();
    };
    let result = unsafe {
        mmap(
            ptr::null_mut(),
            mapped_length,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if result == MAP_FAILED {
        native_set_last_error(8);
        return ptr::null_mut();
    }
    let view = result.cast::<u8>();
    if let Some(path) = mapping.path.as_deref() {
        let Some(context) = fs_ctx() else {
            unsafe { munmap(result, mapped_length) };
            native_set_last_error(6);
            return ptr::null_mut();
        };
        let Ok(ctx) = context.lock() else {
            unsafe { munmap(result, mapped_length) };
            native_set_last_error(6);
            return ptr::null_mut();
        };
        let Ok(contents) = ctx.fs.read_file(path) else {
            unsafe { munmap(result, mapped_length) };
            native_set_last_error(6);
            return ptr::null_mut();
        };
        if offset < contents.len() {
            let count = length.min(contents.len() - offset);
            unsafe { ptr::copy_nonoverlapping(contents.as_ptr().add(offset), view, count) };
        }
    }
    let writable = access & 0x2 != 0;
    let copy_on_write = access & 0x1 != 0;
    let host_protection = if writable || copy_on_write {
        PROT_READ | PROT_WRITE
    } else if access & 0x4 != 0 {
        PROT_READ
    } else {
        linux_protection(mapping.protection).unwrap_or(PROT_READ)
    };
    if unsafe { mprotect(result, mapped_length, host_protection) } != 0 {
        unsafe { munmap(result, mapped_length) };
        native_set_last_error(87);
        return ptr::null_mut();
    }
    if let Ok(mut views) = process.mapping_views.lock() {
        views.insert(
            result as u64,
            NativeMappingView {
                length: mapped_length,
                view_length: length,
                backing: mapping.path.map(|path| (path, offset)),
                writable,
            },
        );
    }
    result.cast()
}

fn native_flush_mapping_view(
    address: *const u8,
    view: &NativeMappingView,
    bytes: usize,
) -> Result<(), u32> {
    if !view.writable {
        return Ok(());
    }
    let Some((path, offset)) = view.backing.as_ref() else {
        return Ok(());
    };
    let count = if bytes == 0 { view.view_length } else { bytes };
    if count > view.view_length {
        return Err(87);
    }
    let end = offset.checked_add(count).ok_or(87u32)?;
    let Some(context) = fs_ctx() else {
        return Err(6);
    };
    let mut ctx = context.lock().map_err(|_| 6u32)?;
    let mut contents = ctx.fs.read_file(path).map_err(|_| 6u32)?;
    if contents.len() < end {
        contents.resize(end, 0);
    }
    unsafe {
        ptr::copy_nonoverlapping(address, contents.as_mut_ptr().add(*offset), count);
    }
    ctx.fs.write_file(path, contents).map_err(|_| 5u32)
}

extern "win64" fn native_flush_view_of_file(address: *const c_void, bytes: usize) -> i32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(view) = process.mapping_views.lock().ok().and_then(|values| {
        values.get(&(address as u64)).map(|view| NativeMappingView {
            length: view.length,
            view_length: view.view_length,
            backing: view.backing.clone(),
            writable: view.writable,
        })
    }) else {
        native_set_last_error(487);
        return 0;
    };
    match native_flush_mapping_view(address.cast(), &view, bytes) {
        Ok(()) => 1,
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

extern "win64" fn native_unmap_view_of_file(address: *mut c_void) -> i32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(view) = process
        .mapping_views
        .lock()
        .ok()
        .and_then(|mut values| values.remove(&(address as u64)))
    else {
        native_set_last_error(487);
        return 0;
    };
    if let Err(error) = native_flush_mapping_view(address.cast(), &view, 0) {
        unsafe { munmap(address, view.length) };
        native_set_last_error(error);
        return 0;
    }
    (unsafe { munmap(address, view.length) } == 0) as i32
}

extern "win64" fn native_ver_set_condition_mask(mask: u64, types: u32, condition: u8) -> u64 {
    let shift = if types & 0x80 != 0 {
        21
    }
    // VER_PRODUCT_TYPE
    else if types & 0x40 != 0 {
        18
    }
    // VER_SUITENAME
    else if types & 0x20 != 0 {
        15
    }
    // VER_SERVICEPACKMAJOR
    else if types & 0x10 != 0 {
        12
    }
    // VER_SERVICEPACKMINOR
    else if types & 0x08 != 0 {
        9
    }
    // VER_PLATFORMID
    else if types & 0x04 != 0 {
        6
    }
    // VER_BUILDNUMBER
    else if types & 0x02 != 0 {
        3
    }
    // VER_MAJORVERSION
    else if types & 0x01 != 0 {
        0
    }
    // VER_MINORVERSION
    else {
        return mask;
    };
    mask | (((condition & 7) as u64) << shift)
}

extern "win64" fn native_verify_version_info_w(info: *const u8, types: u32, mask: u64) -> i32 {
    if info.is_null() || types == 0 {
        native_set_last_error(87);
        return 0;
    }
    let read32 = |offset| unsafe { (info.add(offset) as *const u32).read_unaligned() };
    let read16 = |offset| unsafe { (info.add(offset) as *const u16).read_unaligned() };
    let matches = |actual: u32, expected: u32, shift: u32| match (mask >> shift) & 7 {
        1 => actual == expected,
        2 => actual > expected,
        3 => actual >= expected,
        4 => actual < expected,
        5 => actual <= expected,
        _ => false,
    };
    let checks = [
        (0x02, 10, read32(4), 3),
        (0x01, 0, read32(8), 0),
        (0x04, 19045, read32(12), 6),
        (0x08, 2, read32(16), 9),
        (0x20, 0, read16(276) as u32, 15),
        (0x10, 0, read16(278) as u32, 12),
        (0x80, 1, unsafe { *info.add(282) } as u32, 21),
    ];
    if checks.iter().any(|(bit, actual, expected, shift)| {
        types & bit != 0 && !matches(*actual, *expected, *shift)
    }) {
        native_set_last_error(1150); // ERROR_OLD_WIN_VERSION
        0
    } else {
        1
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
    strict_imports: bool,
) -> Result<Option<MissingImportStubs>, String> {
    let imports: Vec<_> = img.imports.iter().chain(&img.unsupported).collect();
    let missing = imports
        .iter()
        .filter(|import| !supports_import(&import.dll, &import.func))
        .count();
    if missing > 0 && strict_imports {
        let import = imports
            .iter()
            .find(|import| !supports_import(&import.dll, &import.func))
            .unwrap();
        return Err(format!(
            "unsupported native import: {}!{}",
            import.dll, import.func
        ));
    }
    let mut stubs = if missing == 0 {
        None
    } else {
        let size = page_len(
            missing
                .checked_mul(32)
                .ok_or("too many native import stubs")?,
        )?;
        let ptr = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == MAP_FAILED {
            return Err(format!(
                "native import stub allocation failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Some(MissingImportStubs {
            _code: Mapping {
                ptr: ptr.cast(),
                len: size,
            },
            _messages: Vec::with_capacity(missing),
        })
    };
    let mut stub_index = 0;
    for import in imports {
        let value = if supports_import(&import.dll, &import.func) {
            baseline_trampoline(&import.func).unwrap()
        } else {
            let stubs = stubs.as_mut().unwrap();
            let message = format!(
                "unsupported native import called: {}!{}\n",
                import.dll, import.func
            )
            .into_bytes();
            let message_ptr = message.as_ptr() as u64;
            let message_len = message.len() as u64;
            stubs._messages.push(message);
            let code =
                unsafe { std::slice::from_raw_parts_mut(stubs._code.ptr.add(stub_index * 32), 32) };
            code[0..2].copy_from_slice(&[0x48, 0xB9]); // mov rcx, message
            code[2..10].copy_from_slice(&message_ptr.to_le_bytes());
            code[10..12].copy_from_slice(&[0x48, 0xBA]); // mov rdx, length
            code[12..20].copy_from_slice(&message_len.to_le_bytes());
            code[20..22].copy_from_slice(&[0x48, 0xB8]); // mov rax, handler
            code[22..30].copy_from_slice(
                &(native_missing_import as *const () as usize as u64).to_le_bytes(),
            );
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
        if unsafe {
            mprotect(
                stubs._code.ptr.cast(),
                stubs._code.len,
                PROT_READ | PROT_EXEC,
            )
        } != 0
        {
            return Err(format!(
                "native import stubs could not be made executable: {}",
                std::io::Error::last_os_error()
            ));
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
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, &[], None)
        .map_err(|failure| failure.message)
}

fn write_host_stderr(bytes: &[u8]) {
    use std::io::Write;
    let _ = std::io::stderr().lock().write_all(bytes);
}

pub(super) fn run_rust_baseline_argv_with_fs_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>, WinFs), super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, &[], None)
}

pub(super) fn run_rust_baseline_argv_with_fs_environment_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
) -> Result<(u32, Vec<u8>, WinFs), super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, environment, None)
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, WinFs), String> {
    run_rust_baseline_argv_with_fs_impl(
        img,
        instance_fs,
        prog,
        args,
        &[],
        Some(&|is_stderr, chunk| {
            if is_stderr {
                write_host_stderr(chunk);
            } else {
                output(chunk);
            }
        }),
    )
    .map_err(|failure| failure.message)
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, WinFs), super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(
        img,
        instance_fs,
        prog,
        args,
        &[],
        Some(&|is_stderr, chunk| {
            if is_stderr {
                write_host_stderr(chunk);
            } else {
                output(chunk);
            }
        }),
    )
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming_channels_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(bool, &[u8]),
) -> Result<(u32, Vec<u8>, WinFs), super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, &[], Some(output))
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming_environment_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, WinFs), super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(
        img,
        instance_fs,
        prog,
        args,
        environment,
        Some(&|is_stderr, chunk| {
            if is_stderr {
                write_host_stderr(chunk);
            } else {
                output(chunk);
            }
        }),
    )
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming_channels_environment_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
    output: &dyn Fn(bool, &[u8]),
) -> Result<(u32, Vec<u8>, WinFs), super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, environment, Some(output))
}

fn run_rust_baseline_argv_with_fs_impl(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
    output: Option<&dyn Fn(bool, &[u8])>,
) -> Result<(u32, Vec<u8>, WinFs), super::NativeExecutionFailure> {
    let mut recovery_fs = Some(instance_fs);
    let mut recovery_process: Option<Arc<NativeProcessContext>> = None;
    let result = (|| -> Result<(u32, Vec<u8>, WinFs), String> {
        let total_started = std::time::Instant::now();
        // Initialize this cache before any guest fork; shims read it in
        // potentially multithreaded children.
        let _ = native_diagnostic_enabled();
        let timing = std::env::var_os("WINCLI_TIMINGS").is_some();
        let lock_started = std::time::Instant::now();
        let _run = NATIVE_RUN_LOCK
            .lock()
            .map_err(|_| "native backend execution lock is poisoned".to_string())?;
        let lock_wait_ms = lock_started.elapsed().as_secs_f64() * 1000.0;
        let entry_started = std::time::Instant::now();
        let entry = entry(img)?;
        let entry_ms = entry_started.elapsed().as_secs_f64() * 1000.0;
        let map_started = std::time::Instant::now();
        let mapping = map(img)?;
        let map_ms = map_started.elapsed().as_secs_f64() * 1000.0;
        let import_started = std::time::Instant::now();
        let strict_imports = std::env::var("WINCLI_NATIVE_STRICT_IMPORTS").as_deref() == Ok("1");
        let _import_stubs = patch_baseline_imports(&mapping, img, strict_imports)?;
        let import_ms = import_started.elapsed().as_secs_f64() * 1000.0;
        let tls_started = std::time::Instant::now();
        let tls = setup_tls(&mapping, img)?;
        let tls_ms = tls_started.elapsed().as_secs_f64() * 1000.0;
        let context_started = std::time::Instant::now();
        let mut instance_fs = recovery_fs
            .take()
            .expect("filesystem is available before launch");
        instance_fs.clear_changes();
        let fs = Arc::new(Mutex::new(NativeFs {
            fs: instance_fs,
            handles: HashMap::new(),
            devices: HashMap::new(),
            file_access: HashMap::new(),
            file_shares: HashMap::new(),
            finds: HashMap::new(),
            file_completion_modes: HashMap::new(),
            delete_on_close: std::collections::HashSet::new(),
            file_locks: Vec::new(),
            next: 0x100,
        }));
        let command_line_w = command_line_w(prog, args)?;
        let command_line_a = command_line_a(&command_line_w);
        let process = Arc::new(NativeProcessContext {
            image_base: img.image_base,
            module_path: prog.to_string(),
            process_id: 1,
            process_handle: u64::MAX,
            parent_process_id: 0,
            command_line_w,
            command_line_a,
            environment: Mutex::new(environment.to_vec()),
            environment_block: Mutex::new(environment_strings(environment)),
            std_handles: [
                AtomicU64::new(STD_HANDLE_BASE),
                AtomicU64::new(STD_HANDLE_BASE + 1),
                AtomicU64::new(STD_HANDLE_BASE + 2),
            ],
            crt_fds: Mutex::new(HashMap::new()),
            crt_fd_next: AtomicI32::new(3),
            fs,
            named_pipes: Mutex::new(NativeNamedPipeTable::new()),
            error_mode: AtomicU32::new(0),
            pointer_cookie: random_pointer_cookie(),
            heap_allocations: Mutex::new(HashMap::new()),
            virtual_allocations: Mutex::new(HashMap::new()),
            file_mappings: Mutex::new(HashMap::new()),
            mapping_views: Mutex::new(HashMap::new()),
            mapping_next: AtomicU64::new(0x9800_0000),
            gs_base: AtomicU64::new(0),
            tls_template: Mutex::new(tls.as_ref().map(NativeTls::clone_for_thread)),
            dynamic_tls: Mutex::new(DynamicTlsSlots::new(tls.is_some())),
            threads: Mutex::new(HashMap::new()),
            thread_next: AtomicU64::new(0x8000_0000),
            semaphores: Mutex::new(HashMap::new()),
            semaphore_next: AtomicU64::new(0x6000_0000),
            events: Mutex::new(HashMap::new()),
            event_names: Mutex::new(HashMap::new()),
            event_next: AtomicU64::new(0x6100_0000),
            job_objects: Mutex::new(HashMap::new()),
            wait_registrations: Mutex::new(HashMap::new()),
            completion_ports: Mutex::new(HashMap::new()),
            socket_completion_ports: Mutex::new(HashMap::new()),
            socket_completion_modes: Mutex::new(HashMap::new()),
            completion_next: AtomicU64::new(0x9000_0000),
            io_wait: Mutex::new(()),
            io_ready: Condvar::new(),
            pending_file_io: AtomicU64::new(0),
            pending_requests: Mutex::new(HashMap::new()),
            file_io_queue: Mutex::new(None),
            duplicate_handles: Mutex::new(HashMap::new()),
            duplicate_next: AtomicU64::new(0xa000_0000),
            timer_next: AtomicU64::new(0x7000_0000),
            state_fd: AtomicU32::new(u32::MAX),
            fls_value: AtomicU64::new(0),
            unhandled_exception_filter: AtomicU64::new(0),
            vectored_exception_handler: AtomicU64::new(0),
            exit_status: AtomicU32::new(259), // STILL_ACTIVE
            exited: AtomicBool::new(false),
            children: Mutex::new(NativeProcessTable::new()),
        });
        recovery_process = Some(Arc::clone(&process));
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
        let mut stderr_fds = [-1, -1];
        if unsafe { pipe(stderr_fds.as_mut_ptr()) } != 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
            }
            return Err(format!(
                "native backend could not create stderr pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut state_fds = [-1, -1];
        if unsafe { pipe(state_fds.as_mut_ptr()) } != 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
                close(stderr_fds[0]);
                close(stderr_fds[1]);
            }
            return Err(format!(
                "native backend could not create state pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let context_ms = context_started.elapsed().as_secs_f64() * 1000.0;
        let fork_started = std::time::Instant::now();
        let pid = unsafe { fork() };
        let fork_ms = fork_started.elapsed().as_secs_f64() * 1000.0;
        if pid < 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
                close(stderr_fds[0]);
                close(stderr_fds[1]);
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
                close(stderr_fds[0]);
                if dup2(fds[1], 1) < 0 {
                    _exit(127);
                }
                close(fds[1]);
                if dup2(stderr_fds[1], 2) < 0 {
                    _exit(127);
                }
                close(stderr_fds[1]);
            }
            process
                .state_fd
                .store(state_fds[1] as u32, Ordering::Release);
            if protect_exec(&mapping).is_err() {
                unsafe { _exit(127) };
            }
            // Launcher threads can have 64 KiB stacks. V8 needs a larger
            // Windows thread stack, with bounds reflected in the guest TEB.
            let guest_process = Arc::clone(&process);
            let guest_thread = std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    THREAD_NATIVE_PROCESS.with(|active| {
                        *active.borrow_mut() = Some(Arc::clone(&guest_process));
                    });
                    let mut tls = tls;
                    let mut fallback_teb = Box::new([0u8; 0x1000]);
                    let teb = tls
                        .as_mut()
                        .map(|tls| &mut tls.teb)
                        .unwrap_or(&mut fallback_teb);
                    if !install_thread_teb(teb) {
                        return 127;
                    }
                    guest_process
                        .gs_base
                        .store(teb.as_ptr() as u64, Ordering::Release);
                    // SAFETY: entry is in the child-owned RX PE mapping.
                    let guest: unsafe extern "win64" fn() -> u32 =
                        unsafe { std::mem::transmute(entry) };
                    let code = unsafe { guest() as i32 };
                    native_wait_file_io(&guest_process);
                    code
                });
            let code = guest_thread
                .ok()
                .and_then(|thread| thread.join().ok())
                .unwrap_or(127);
            unsafe { close(1) };
            native_flush_instance_state();
            unsafe { _exit(code) };
        }
        unsafe {
            close(fds[1]);
            close(stderr_fds[1]);
            close(state_fds[1]);
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let guest_started = std::time::Instant::now();
        let mut first_output_ms = None;
        let mut output_fds = [
            NativePollFd {
                fd: fds[0],
                events: 1,
                revents: 0,
            },
            NativePollFd {
                fd: stderr_fds[0],
                events: 1,
                revents: 0,
            },
        ];
        let mut open_output_fds = output_fds.len();
        while open_output_fds > 0 {
            let ready = unsafe { poll(output_fds.as_mut_ptr(), output_fds.len(), -1) };
            if ready < 0 {
                unsafe {
                    for descriptor in &output_fds {
                        if descriptor.fd >= 0 {
                            close(descriptor.fd);
                        }
                    }
                }
                return Err(format!(
                    "native backend could not poll guest output: {}",
                    std::io::Error::last_os_error()
                ));
            }
            for (index, descriptor) in output_fds.iter_mut().enumerate() {
                if descriptor.fd < 0 || descriptor.revents == 0 {
                    continue;
                }
                let n = unsafe { read(descriptor.fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n == 0 {
                    unsafe {
                        close(descriptor.fd);
                    }
                    descriptor.fd = -1;
                    open_output_fds -= 1;
                    continue;
                }
                if n < 0 {
                    unsafe {
                        for descriptor in &output_fds {
                            if descriptor.fd >= 0 {
                                close(descriptor.fd);
                            }
                        }
                    }
                    return Err(format!(
                        "native backend could not read guest {}: {}",
                        if index == 0 { "stdout" } else { "stderr" },
                        std::io::Error::last_os_error()
                    ));
                }
                if first_output_ms.is_none() {
                    first_output_ms = Some(guest_started.elapsed().as_secs_f64() * 1000.0);
                }
                let chunk = &buf[..n as usize];
                if index == 0 {
                    out.extend_from_slice(chunk);
                }
                if let Some(output) = output {
                    output(index == 1, chunk);
                } else if index == 1 {
                    write_host_stderr(chunk);
                }
            }
        }
        let guest_ms = guest_started.elapsed().as_secs_f64() * 1000.0;
        let state_started = std::time::Instant::now();
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
        let state_transfer_ms = state_started.elapsed().as_secs_f64() * 1000.0;
        process
            .exit_status
            .store((status >> 8) as u32, Ordering::Release);
        process.exited.store(true, Ordering::Release);
        if let Ok(mut context) = NATIVE_PROCESS.lock() {
            *context = None;
        }
        let decode_started = std::time::Instant::now();
        if status & 0x7f != 0 {
            return Err(format!(
                "native guest terminated by signal {}",
                status & 0x7f
            ));
        }
        let final_fs = {
            let mut native_fs = process
                .fs
                .lock()
                .map_err(|_| "native backend filesystem lock is poisoned".to_string())?;
            if !state.is_empty() {
                crate::snapshot::apply_changes(&state, &mut native_fs.fs).map_err(|e| {
                    format!("native backend returned invalid filesystem changes: {e}")
                })?;
            }
            std::mem::replace(&mut native_fs.fs, WinFs::new())
        };
        let state_decode_ms = decode_started.elapsed().as_secs_f64() * 1000.0;
        if timing {
            if !out.is_empty() && !out.ends_with(b"\n") {
                eprintln!();
            }
            let first_output = first_output_ms
                .map(|milliseconds| format!("{milliseconds:.3}ms"))
                .unwrap_or_else(|| "none".to_string());
            eprintln!(
            "wincli timing: {prog}: lock={lock_wait_ms:.3}ms entry={entry_ms:.3}ms map={map_ms:.3}ms imports={import_ms:.3}ms tls={tls_ms:.3}ms context={context_ms:.3}ms fork={fork_ms:.3}ms first_output={first_output} guest_until_output_eof={guest_ms:.3}ms state_transfer={state_transfer_ms:.3}ms state_decode={state_decode_ms:.3}ms stdout_bytes={} state_bytes={} total={:.3}ms",
            out.len(),
            state.len(),
            total_started.elapsed().as_secs_f64() * 1000.0
        );
        }
        Ok(((status >> 8) as u32, out, final_fs))
    })();
    match result {
        Ok(result) => Ok(result),
        Err(message) => {
            let fs = if let Some(process) = recovery_process {
                process
                    .fs
                    .lock()
                    .map(|native_fs| native_fs.fs.clone())
                    .unwrap_or_else(|_| WinFs::new())
            } else {
                recovery_fs.take().unwrap_or_else(WinFs::new)
            };
            Err(super::NativeExecutionFailure { message, fs })
        }
    }
}
