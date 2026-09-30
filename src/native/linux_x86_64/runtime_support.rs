//! Kernel32, ADVAPI32, OLE32, and UCRT services a managed runtime such as
//! CoreCLR queries while starting: locale identifiers, thread queries,
//! private heaps, event reporting, processor state (XState) and CONTEXT
//! helpers, module lookup by address, and fail-fast termination.

use super::*;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NOT_LOCKED: u32 = 158;
const ERROR_RESOURCE_NAME_NOT_FOUND: u32 = 1814;
const CONTEXT_SIZE: u32 = 0x4d0;
const LOCALE_EN_US: u32 = 0x0409;

// ---- locale ------------------------------------------------------------------

pub(super) extern "win64" fn native_get_default_lcid() -> u32 {
    LOCALE_EN_US
}

/// `GetUserDefaultLocaleName`: characters written including the NUL, or 0
/// when the buffer is too small.
pub(super) extern "win64" fn native_get_user_default_locale_name(output: *mut u16, capacity: i32) -> i32 {
    let name: Vec<u16> = "en-US".encode_utf16().chain(std::iter::once(0)).collect();
    if output.is_null() || (capacity as usize) < name.len() {
        native_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { output.copy_from_nonoverlapping(name.as_ptr(), name.len()) };
    name.len() as i32
}

// ---- threads -----------------------------------------------------------------

pub(super) extern "win64" fn native_get_thread_priority(_thread: u64) -> i32 {
    0 // THREAD_PRIORITY_NORMAL
}

pub(super) extern "win64" fn native_set_thread_priority(_thread: u64, _priority: i32) -> i32 {
    1
}

pub(super) extern "win64" fn native_set_thread_error_mode(_mode: u32, previous: *mut u32) -> i32 {
    if !previous.is_null() {
        unsafe { previous.write_unaligned(0) };
    }
    1
}

/// `SleepEx`: no APCs are ever queued to guest threads, so an alertable
/// sleep always runs to completion.
pub(super) extern "win64" fn native_sleep_ex(milliseconds: u32, _alertable: i32) -> u32 {
    native_sleep(milliseconds);
    0
}

pub(super) extern "win64" fn native_wait_for_single_object_ex(
    handle: u64,
    milliseconds: u32,
    _alertable: i32,
) -> u32 {
    native_wait_for_single_object(handle, milliseconds)
}

pub(super) extern "win64" fn native_create_semaphore_w(
    attributes: *const u8,
    initial: i32,
    maximum: i32,
    _name: *const u16,
) -> u64 {
    native_create_semaphore_a(attributes, initial, maximum, ptr::null())
}

pub(super) extern "win64" fn native_create_semaphore_ex_w(
    attributes: *const u8,
    initial: i32,
    maximum: i32,
    _name: *const u16,
    _flags: u32,
    _access: u32,
) -> u64 {
    native_create_semaphore_a(attributes, initial, maximum, ptr::null())
}

// ---- memory ------------------------------------------------------------------

/// Private heaps share the process heap: winrun's heap functions allocate
/// from the host allocator, and `HeapDestroy` leaves live blocks alone.
pub(super) extern "win64" fn native_heap_create(_options: u32, _initial: usize, _maximum: usize) -> u64 {
    PROCESS_HEAP_HANDLE
}

pub(super) extern "win64" fn native_heap_destroy(_heap: u64) -> i32 {
    1
}

/// `CreateMemoryResourceNotification`: an event that is never signaled,
/// since the guest never reports low (or high) memory.
pub(super) extern "win64" fn native_create_memory_resource_notification(kind: u32) -> u64 {
    if kind > 1 {
        native_set_last_error(87);
        return 0;
    }
    native_create_event_w(0, 1, 0, ptr::null())
}

pub(super) extern "win64" fn native_query_memory_resource_notification(_handle: u64, state: *mut i32) -> i32 {
    if state.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { state.write_unaligned(0) };
    1
}

pub(super) extern "win64" fn native_get_large_page_minimum() -> usize {
    0 // large pages are not available
}

/// Pages are never locked, so there is nothing to unlock.
pub(super) extern "win64" fn native_virtual_unlock(_address: u64, _size: usize) -> i32 {
    native_set_last_error(ERROR_NOT_LOCKED);
    0
}

pub(super) extern "win64" fn native_flush_process_write_buffers() {
    std::sync::atomic::fence(Ordering::SeqCst);
}

/// x86-64 keeps instruction and data caches coherent.
pub(super) extern "win64" fn native_flush_instruction_cache(_process: u64, _base: u64, _size: usize) -> i32 {
    1
}

pub(super) extern "win64" fn native_get_file_size(handle: u64, high: *mut u32) -> u32 {
    let mut size = 0i64;
    if native_get_file_size_ex(handle, &mut size) == 0 {
        return u32::MAX; // INVALID_FILE_SIZE, with the last error set
    }
    if !high.is_null() {
        unsafe { high.write_unaligned((size as u64 >> 32) as u32) };
    }
    native_set_last_error(0);
    size as u32
}

pub(super) extern "win64" fn native_is_process_in_job(_process: u64, _job: u64, result: *mut i32) -> i32 {
    if result.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { result.write_unaligned(0) };
    1
}

/// `QueryInformationJobObject`: a zeroed record (no CPU-rate, memory, or
/// process limits) of the requested class, with the basic limit flags of a
/// job winrun tracks. A process outside any job queried with a null handle
/// sees no limits either.
pub(super) extern "win64" fn native_query_information_job_object(
    job: u64,
    class: u32,
    info: *mut u8,
    length: u32,
    returned: *mut u32,
) -> i32 {
    // Sizes of the classes callers read: basic accounting (1), basic
    // limits (2), extended limits (9), and CPU rate control (15).
    let size = match class {
        1 => 48,
        2 => 64,
        9 => 144,
        15 => 8,
        _ => {
            native_set_last_error(87);
            return 0;
        }
    };
    if info.is_null() || length < size {
        native_set_last_error(24); // ERROR_BAD_LENGTH
        return 0;
    }
    let limit_flags = process_ctx()
        .and_then(|process| {
            process
                .job_objects
                .lock()
                .ok()
                .and_then(|jobs| jobs.get(&job).map(|job| job.limit_flags))
        })
        .unwrap_or(0);
    unsafe {
        ptr::write_bytes(info, 0, size as usize);
        if matches!(class, 2 | 9) {
            // JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags
            info.add(16).cast::<u32>().write_unaligned(limit_flags);
        }
        if !returned.is_null() {
            returned.write_unaligned(size);
        }
    }
    1
}

// ---- processor state -----------------------------------------------------------

/// Only the legacy x87 and SSE state components are enabled, so the
/// extended (AVX) context APIs are never needed.
pub(super) extern "win64" fn native_get_enabled_xstate_features() -> u64 {
    0b11
}

pub(super) extern "win64" fn native_locate_xstate_feature(_context: u64, _feature: u32, length: *mut u32) -> u64 {
    if !length.is_null() {
        unsafe { length.write_unaligned(0) };
    }
    0
}

pub(super) extern "win64" fn native_set_xstate_features_mask(_context: u64, _mask: u64) -> i32 {
    1
}

/// `InitializeContext`: place a `CONTEXT` (16-byte aligned) in `buffer`
/// with `flags` set; a missing or short buffer reports the size needed.
pub(super) extern "win64" fn native_initialize_context(
    buffer: *mut u8,
    flags: u32,
    context: *mut *mut u8,
    length: *mut u32,
) -> i32 {
    if length.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let needed = CONTEXT_SIZE + 15;
    let capacity = unsafe { length.read_unaligned() };
    unsafe { length.write_unaligned(needed) };
    if buffer.is_null() || capacity < needed {
        native_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    let aligned = ((buffer as usize + 15) & !15) as *mut u8;
    unsafe {
        ptr::write_bytes(aligned, 0, CONTEXT_SIZE as usize);
        aligned.add(0x30).cast::<u32>().write_unaligned(flags);
        if !context.is_null() {
            context.write_unaligned(aligned);
        }
    }
    1
}

pub(super) extern "win64" fn native_copy_context(destination: *mut u8, flags: u32, source: *const u8) -> i32 {
    if destination.is_null() || source.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe {
        destination.copy_from(source, CONTEXT_SIZE as usize);
        destination.add(0x30).cast::<u32>().write_unaligned(flags);
    }
    1
}

// ---- modules and code ----------------------------------------------------------

/// `RtlPcToFileHeader`: the base of the image containing `pc`.
pub(super) extern "win64" fn native_rtl_pc_to_file_header(pc: u64, base: *mut u64) -> u64 {
    let found = process_ctx().and_then(|process| {
        if pc >= process.image_base && pc < process.image_base + u64::from(process.image_size) {
            return Some(process.image_base);
        }
        process.loaded_modules.lock().ok().and_then(|modules| {
            modules
                .values()
                .find(|module| pc >= module.base && pc < module.base + u64::from(module.size_of_image))
                .map(|module| module.base)
        })
    });
    let found = found.unwrap_or(0);
    if !base.is_null() {
        unsafe { base.write_unaligned(found) };
    }
    found
}

/// Dynamic function tables for generated code, recorded for the unwinder:
/// (table identifier, base, length, callback, context).
pub(super) static DYNAMIC_FUNCTION_TABLES: Mutex<Vec<(u64, u64, u32, u64, u64)>> = Mutex::new(Vec::new());

pub(super) extern "win64" fn native_rtl_install_function_table_callback(
    table_identifier: u64,
    base: u64,
    length: u32,
    callback: u64,
    context: u64,
    _out_of_process_dll: *const u16,
) -> u8 {
    // The identifier's low two bits must be 3 to mark a callback table.
    if table_identifier & 3 != 3 || callback == 0 {
        return 0;
    }
    if let Ok(mut tables) = DYNAMIC_FUNCTION_TABLES.lock() {
        tables.push((table_identifier, base, length, callback, context));
    }
    1
}

// ---- security ------------------------------------------------------------------------

const ERROR_NO_TOKEN: u32 = 1008;

/// A binary SID (`S-1-<authority>-<sub>...`): revision, count, 48-bit
/// big-endian authority, then little-endian sub-authorities.
fn binary_sid(text: &str) -> Vec<u8> {
    let parts: Vec<u64> = text
        .trim_start_matches("S-")
        .split('-')
        .filter_map(|part| part.parse().ok())
        .collect();
    let (authority, subs) = (parts.get(1).copied().unwrap_or(0), parts.get(2..).unwrap_or(&[]));
    let mut sid = vec![1, subs.len() as u8];
    sid.extend_from_slice(&authority.to_be_bytes()[2..]);
    for sub in subs {
        sid.extend_from_slice(&(*sub as u32).to_le_bytes());
    }
    sid
}

/// A thread that is not impersonating has no token of its own.
pub(super) extern "win64" fn native_open_thread_token(
    _thread: u64,
    _access: u32,
    _open_as_self: i32,
    token: *mut u64,
) -> i32 {
    if !token.is_null() {
        unsafe { token.write_unaligned(0) };
    }
    native_set_last_error(ERROR_NO_TOKEN);
    0
}

pub(super) extern "win64" fn native_revert_to_self() -> i32 {
    1
}

pub(super) extern "win64" fn native_set_thread_token(_thread: *mut u64, _token: u64) -> i32 {
    1
}

/// `GetTokenInformation` for the process token: the user (runner's SID),
/// elevation (a standard, non-elevated user), and a medium integrity level.
pub(super) extern "win64" fn native_get_token_information(
    _token: u64,
    class: u32,
    info: *mut u8,
    length: u32,
    returned: *mut u32,
) -> i32 {
    let record: Vec<u8> = match class {
        // TOKEN_USER / TOKEN_MANDATORY_LABEL: SID_AND_ATTRIBUTES with the
        // SID stored right after it (at +16).
        1 | 25 => {
            let (sid, attributes) = if class == 1 {
                (binary_sid(crate::system_profile::USER_SID), 0u32)
            } else {
                (binary_sid("S-1-16-8192"), 0x20) // SE_GROUP_INTEGRITY
            };
            let mut record = vec![0u8; 16];
            record[8..12].copy_from_slice(&attributes.to_le_bytes());
            record.extend_from_slice(&sid);
            record
        }
        18 => 1u32.to_le_bytes().to_vec(), // TokenElevationTypeDefault
        20 => 0u32.to_le_bytes().to_vec(), // TOKEN_ELEVATION: not elevated
        _ => {
            native_set_last_error(87);
            return 0;
        }
    };
    if !returned.is_null() {
        unsafe { returned.write_unaligned(record.len() as u32) };
    }
    if info.is_null() || (length as usize) < record.len() {
        native_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe {
        info.copy_from_nonoverlapping(record.as_ptr(), record.len());
        if matches!(class, 1 | 25) {
            info.cast::<u64>().write_unaligned(info.add(16) as u64);
        }
    }
    1
}

pub(super) extern "win64" fn native_get_sid_sub_authority_count(sid: *mut u8) -> *mut u8 {
    if sid.is_null() {
        return ptr::null_mut();
    }
    unsafe { sid.add(1) }
}

pub(super) extern "win64" fn native_get_sid_sub_authority(sid: *mut u8, index: u32) -> *mut u32 {
    if sid.is_null() {
        return ptr::null_mut();
    }
    unsafe { sid.add(8 + 4 * index as usize).cast() }
}

// ---- reporting and termination -------------------------------------------------

/// Windows event log: events are accepted and not recorded.
pub(super) extern "win64" fn native_register_event_source_w(_server: *const u16, _source: *const u16) -> u64 {
    0x6e00_0001
}

pub(super) extern "win64" fn native_report_event_w(
    _log: u64,
    _kind: u16,
    _category: u16,
    _event: u32,
    _sid: u64,
    _strings: u16,
    _data_size: u32,
    _text: u64,
    _data: u64,
) -> i32 {
    1
}

pub(super) extern "win64" fn native_deregister_event_source(_log: u64) -> i32 {
    1
}

/// ETW: no session is listening.
pub(super) extern "win64" fn native_event_write(_registration: u64, _descriptor: u64, _count: u32, _data: u64) -> u32 {
    0
}

/// Windows Error Reporting is unavailable; registration succeeds.
pub(super) extern "win64" fn native_wer_register_runtime_exception_module(_dll: *const u16, _context: u64) -> i32 {
    0
}

/// `UnhandledExceptionFilter`: let the exception keep propagating.
pub(super) extern "win64" fn native_unhandled_exception_filter(_pointers: u64) -> i32 {
    0 // EXCEPTION_CONTINUE_SEARCH
}

/// `RaiseFailFastException`: terminate at once with the exception's code
/// (or `STATUS_FAIL_FAST_EXCEPTION`).
pub(super) extern "win64" fn native_raise_fail_fast_exception(record: *const u32, _context: u64, _flags: u32) -> ! {
    let code = if record.is_null() {
        0xc000_0602
    } else {
        unsafe { record.read_unaligned() }
    };
    native_write_to_handle(
        STD_HANDLE_BASE + 2,
        format!("winrun: fail fast exception 0x{code:08x}\r\n").as_bytes(),
    );
    native_exit_process(code)
}

/// `DebugBreak` with no debugger attached ends the process with
/// `STATUS_BREAKPOINT`.
pub(super) extern "win64" fn native_debug_break() -> ! {
    native_write_to_handle(STD_HANDLE_BASE + 2, b"winrun: DebugBreak with no debugger attached\r\n");
    native_exit_process(0x8000_0003)
}

// ---- COM basics -----------------------------------------------------------------

pub(super) extern "win64" fn native_co_initialize_ex(_reserved: u64, _model: u32) -> i32 {
    0 // S_OK
}

pub(super) extern "win64" fn native_co_uninitialize() {}

/// `CoGetContextToken(token)`: winrun has no COM object contexts, so this
/// reports COM as uninitialized (`CO_E_NOTINITIALIZED`) with a null token,
/// which callers such as CoreCLR treat as "no context".
pub(super) extern "win64" fn native_co_get_context_token(token: *mut u64) -> i32 {
    const CO_E_NOTINITIALIZED: i32 = 0x8004_01f0_u32 as i32;
    if token.is_null() {
        return E_POINTER;
    }
    unsafe { token.write(0) };
    CO_E_NOTINITIALIZED
}

const E_POINTER: i32 = 0x8000_4003_u32 as i32;

/// `GetErrorInfo(reserved, info)`: no COM error object is ever set, so
/// there is none to return (`S_FALSE`).
pub(super) extern "win64" fn native_get_error_info(_reserved: u32, info: *mut u64) -> i32 {
    if info.is_null() {
        return E_POINTER;
    }
    unsafe { info.write(0) };
    1 // S_FALSE
}

/// `SetErrorInfo(reserved, info)`: accepts (and drops) the error object;
/// winrun has no COM callers that would read it back.
pub(super) extern "win64" fn native_set_error_info(_reserved: u32, _info: u64) -> i32 {
    0 // S_OK
}

/// `IsThreadAFiber()`: winrun threads never convert to fibers.
pub(super) extern "win64" fn native_is_thread_a_fiber() -> i32 {
    0
}

/// `DisableThreadLibraryCalls(module)`: an optimization hint; modules keep
/// receiving thread notifications, which they must tolerate anyway.
pub(super) extern "win64" fn native_disable_thread_library_calls(module: u64) -> i32 {
    i32::from(module != 0)
}

/// `RoInitialize(type)`: the Windows Runtime shares COM's (no-op)
/// apartment, so initialization always succeeds.
pub(super) extern "win64" fn native_ro_initialize(_init_type: u32) -> i32 {
    0 // S_OK
}

/// `SetThreadDescription(thread, name)`: thread names are informational.
pub(super) extern "win64" fn native_set_thread_description(_thread: u64, _name: *const u16) -> i32 {
    0 // S_OK
}

pub(super) extern "win64" fn native_co_task_mem_alloc(size: usize) -> *mut c_void {
    native_crt_malloc(size)
}

pub(super) extern "win64" fn native_co_task_mem_free(block: *mut c_void) {
    if !block.is_null() {
        unsafe { free(block) };
    }
}

/// `CoCreateGuid`: a random (version 4) GUID.
pub(super) extern "win64" fn native_co_create_guid(guid: *mut u8) -> i32 {
    if guid.is_null() {
        return 0x8007_0057u32 as i32; // E_INVALIDARG
    }
    let mut bytes = [0u8; 16];
    if unsafe { getrandom(bytes.as_mut_ptr().cast(), 16, 0) } != 16 {
        return 0x8000_4005u32 as i32; // E_FAIL
    }
    bytes[7] = (bytes[7] & 0x0f) | 0x40; // Data3 version 4 (little-endian)
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant
    unsafe { guid.copy_from_nonoverlapping(bytes.as_ptr(), 16) };
    0
}

/// `LoadStringW`: guest modules' string resources are not read yet.
pub(super) extern "win64" fn native_load_string_w(_instance: u64, _id: u32, output: *mut u16, capacity: i32) -> i32 {
    if !output.is_null() && capacity > 0 {
        unsafe { output.write(0) };
    }
    native_set_last_error(ERROR_RESOURCE_NAME_NOT_FOUND);
    0
}

// ---- UCRT -------------------------------------------------------------------------

/// The x64 default floating-point control word: all exceptions masked,
/// round to nearest.
static CONTROL_WORD: AtomicU32 = AtomicU32::new(0x0008_001f);

pub(super) extern "win64" fn native_crt_controlfp_s(current: *mut u32, new: u32, mask: u32) -> i32 {
    let value = (CONTROL_WORD.load(Ordering::Acquire) & !mask) | (new & mask);
    CONTROL_WORD.store(value, Ordering::Release);
    if !current.is_null() {
        unsafe { current.write_unaligned(value) };
    }
    0
}

/// `_callnewh`: no `new` handler is installed.
pub(super) extern "win64" fn native_crt_callnewh(_size: usize) -> i32 {
    0
}

pub(super) extern "win64" fn native_crt_invalid_parameter_noinfo() -> ! {
    native_crt_invoke_watson(0, 0, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_and_context_helpers_follow_the_windows_buffer_protocol() {
        let mut name = [0u16; 8];
        assert_eq!(native_get_user_default_locale_name(name.as_mut_ptr(), 8), 6);
        assert_eq!(String::from_utf16_lossy(&name[..5]), "en-US");
        assert_eq!(native_get_user_default_locale_name(name.as_mut_ptr(), 3), 0);
        assert_eq!(native_get_default_lcid(), 0x0409);

        let mut length = 0;
        assert_eq!(
            native_initialize_context(ptr::null_mut(), 0x10_000b, ptr::null_mut(), &mut length),
            0
        );
        let mut buffer = vec![0u8; length as usize];
        let mut context = ptr::null_mut();
        assert_eq!(
            native_initialize_context(buffer.as_mut_ptr(), 0x10_000b, &mut context, &mut length),
            1
        );
        assert_eq!(context as usize % 16, 0);
        assert_eq!(unsafe { context.add(0x30).cast::<u32>().read_unaligned() }, 0x10_000b);
    }

    #[test]
    fn token_queries_report_the_profile_user_at_medium_integrity() {
        let mut needed = 0u32;
        assert_eq!(native_get_token_information(0, 1, ptr::null_mut(), 0, &mut needed), 0);
        let mut buffer = vec![0u8; needed as usize];
        assert_eq!(
            native_get_token_information(0, 1, buffer.as_mut_ptr(), needed, &mut needed),
            1
        );
        let sid = unsafe { buffer.as_ptr().cast::<u64>().read_unaligned() } as *mut u8;
        assert_eq!(sid as usize, buffer.as_ptr() as usize + 16);
        let count = unsafe { *native_get_sid_sub_authority_count(sid) };
        assert_eq!(count, 5, "S-1-5-21-a-b-c-1001");
        assert_eq!(unsafe { *native_get_sid_sub_authority(sid, 4) }, 1001);

        let mut label = [0u8; 64];
        assert_eq!(native_get_token_information(0, 25, label.as_mut_ptr(), 64, &mut needed), 1);
        let sid = unsafe { label.as_ptr().cast::<u64>().read_unaligned() } as *mut u8;
        assert_eq!(unsafe { *native_get_sid_sub_authority(sid, 0) }, 8192);
        let mut elevated = [0xffu8; 4];
        assert_eq!(native_get_token_information(0, 20, elevated.as_mut_ptr(), 4, &mut needed), 1);
        assert_eq!(elevated, [0; 4]);
        let mut token = 1u64;
        assert_eq!(native_open_thread_token(0, 8, 1, &mut token), 0);
        assert_eq!(token, 0);
    }

    #[test]
    fn guids_are_random_version_4() {
        let (mut first, mut second) = ([0u8; 16], [0u8; 16]);
        assert_eq!(native_co_create_guid(first.as_mut_ptr()), 0);
        assert_eq!(native_co_create_guid(second.as_mut_ptr()), 0);
        assert_ne!(first, second);
        assert_eq!(first[7] >> 4, 4);
        assert_eq!(first[8] & 0xc0, 0x80);
    }

    #[test]
    fn winrt_initialization_is_resolvable_and_succeeds() {
        // CoreCLR delay-loads RoInitialize from the WinRT API set; a missing
        // export raises a delay-load exception during startup.
        for name in ["RoInitialize", "RoUninitialize", "SetThreadDescription"] {
            assert!(super::super::baseline_trampoline(name).is_some(), "{name}");
        }
        assert_eq!(native_ro_initialize(1), 0);
        let mut info = 0x1234u64;
        assert_eq!(native_set_error_info(0, 0), 0);
        assert_eq!(native_get_error_info(0, &mut info), 1);
        assert_eq!(info, 0);
        assert_eq!(native_get_error_info(0, ptr::null_mut()), E_POINTER);
        let mut token = 1u64;
        assert_eq!(native_co_get_context_token(&mut token), 0x8004_01f0_u32 as i32);
        assert_eq!(token, 0);
        assert!(super::super::supports_import("ole32.dll", "CoGetContextToken"));
        // oleaut32 exports these by ordinal only.
        assert!(super::super::supports_import("OLEAUT32.dll", "#200"));
        assert!(super::super::supports_import("OLEAUT32.dll", "#201"));
        assert!(!super::super::supports_import("OLEAUT32.dll", "#202"));
        assert_eq!(native_disable_thread_library_calls(0x1_8000_0000), 1);
        assert_eq!(native_disable_thread_library_calls(0), 0);
        assert_eq!(native_is_thread_a_fiber(), 0);
        assert_eq!(native_set_thread_description(0, ptr::null()), 0);
    }

    #[test]
    fn control_word_updates_only_masked_bits() {
        let mut current = 0;
        assert_eq!(native_crt_controlfp_s(&mut current, 0, 0), 0);
        let before = current;
        native_crt_controlfp_s(&mut current, 0x0300, 0x0300);
        assert_eq!(current, (before & !0x0300) | 0x0300);
        native_crt_controlfp_s(&mut current, before, 0x0300);
        assert_eq!(current, before);
    }

    #[test]
    fn function_table_callbacks_require_a_tagged_identifier() {
        assert_eq!(native_rtl_install_function_table_callback(0x1000, 0, 0, 1, 0, ptr::null()), 0);
        assert_eq!(
            native_rtl_install_function_table_callback(0x1003, 0x1000, 0x100, 0x2000, 0, ptr::null()),
            1
        );
    }
}
