//! Kernel32, ADVAPI32, OLE32, and UCRT services a managed runtime such as
//! CoreCLR queries while starting: locale identifiers, thread queries,
//! private heaps, event reporting, processor state (XState) and CONTEXT
//! helpers, module lookup by address, and fail-fast termination.

use super::*;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NOT_LOCKED: u32 = 158;
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

pub(super) extern "win64" fn native_sleep_ex(milliseconds: u32, alertable: i32) -> u32 {
    if alertable == 0 {
        native_sleep(milliseconds);
        return 0;
    }
    let deadline = wait_deadline(milliseconds);
    loop {
        if dispatch_apcs() {
            return WAIT_IO_COMPLETION;
        }
        if wait_expired(deadline) {
            return 0;
        }
        apc_pause();
    }
}

pub(super) extern "win64" fn native_wait_for_single_object_ex(
    handle: u64,
    milliseconds: u32,
    alertable: i32,
) -> u32 {
    if alertable == 0 {
        return native_wait_for_single_object(handle, milliseconds);
    }
    let deadline = wait_deadline(milliseconds);
    loop {
        if dispatch_apcs() {
            return WAIT_IO_COMPLETION;
        }
        let result = native_wait_for_single_object(handle, 0);
        if result != 258 {
            return result;
        }
        if wait_expired(deadline) {
            return 258;
        }
        apc_pause();
    }
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
pub(super) fn binary_sid(text: &str) -> Vec<u8> {
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

/// A NUL-terminated UTF-16 string's units (without the terminator).
fn wide_units<'a>(text: *const u16) -> &'a [u16] {
    let mut length = 0;
    while unsafe { text.add(length).read() } != 0 {
        length += 1;
    }
    unsafe { std::slice::from_raw_parts(text, length) }
}

/// One UTF-16 unit folded to lower case where it maps to a single unit.
fn fold_unit(unit: u16) -> u16 {
    char::from_u32(u32::from(unit))
        .map(|c| {
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(l), None) if (l as u32) <= 0xFFFF => l as u32 as u16,
                _ => unit,
            }
        })
        .unwrap_or(unit)
}

fn str_str(text: *const u16, search: *const u16, ignore_case: bool) -> *const u16 {
    if text.is_null() || search.is_null() {
        return ptr::null();
    }
    let (haystack, needle) = (wide_units(text), wide_units(search));
    if needle.is_empty() {
        return ptr::null();
    }
    let same = |a: u16, b: u16| if ignore_case { fold_unit(a) == fold_unit(b) } else { a == b };
    haystack
        .windows(needle.len())
        .position(|window| window.iter().zip(needle).all(|(a, b)| same(*a, *b)))
        .map_or(ptr::null(), |index| unsafe { text.add(index) })
}

/// Split a command line as `CommandLineToArgvW` does: the program name
/// first (a leading quote runs to the next quote, otherwise it ends at a
/// space or tab; backslashes are literal), then the MSVC argument rules.
fn command_line_arguments(line: &str) -> Vec<String> {
    let line = line.trim_start_matches([' ', '\t']);
    let (program, rest) = if let Some(quoted) = line.strip_prefix('"') {
        match quoted.find('"') {
            Some(end) => (&quoted[..end], &quoted[end + 1..]),
            None => (quoted, ""),
        }
    } else {
        let end = line.find([' ', '\t']).unwrap_or(line.len());
        (&line[..end], &line[end..])
    };
    let mut arguments = vec![program.to_string()];
    arguments.extend(crate::cmd::split_windows_command_line(rest));
    arguments
}

/// `CommandLineToArgvW`: one `LocalAlloc` block holding the argument
/// pointers (NULL-terminated) and then the strings. An empty command line
/// gives the program's own path.
pub(super) extern "win64" fn native_command_line_to_argv_w(line: *const u16, count: *mut i32) -> u64 {
    if count.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let text = if line.is_null() { String::new() } else { wide(line).unwrap_or_default() };
    let arguments = if text.trim_matches([' ', '\t']).is_empty() {
        let mut path = [0u16; 32768];
        let length = native_get_module_file_name_w(0, path.as_mut_ptr(), path.len() as u32) as usize;
        vec![String::from_utf16_lossy(&path[..length])]
    } else {
        command_line_arguments(&text)
    };
    let encoded: Vec<Vec<u16>> = arguments.iter().map(|a| a.encode_utf16().chain(Some(0)).collect()).collect();
    let pointers = (arguments.len() + 1) * 8;
    let total = pointers + encoded.iter().map(|units| units.len() * 2).sum::<usize>();
    let block = native_heap_alloc(PROCESS_HEAP_HANDLE, 0x8, total);
    if block == 0 {
        return 0;
    }
    let mut offset = pointers;
    for (index, units) in encoded.iter().enumerate() {
        unsafe {
            ((block + index as u64 * 8) as *mut u64).write_unaligned(block + offset as u64);
            ((block + offset as u64) as *mut u16).copy_from_nonoverlapping(units.as_ptr(), units.len());
        }
        offset += units.len() * 2;
    }
    unsafe { count.write(arguments.len() as i32) };
    block
}

/// `StrStrW`: the first occurrence of `search` in `text`, or NULL.
pub(super) extern "win64" fn native_str_str_w(text: *const u16, search: *const u16) -> *const u16 {
    str_str(text, search, false)
}

/// `StrStrIW`: `StrStrW` ignoring case.
pub(super) extern "win64" fn native_str_str_i_w(text: *const u16, search: *const u16) -> *const u16 {
    str_str(text, search, true)
}

/// `UuidCreate`: a random (version 4) UUID, `RPC_S_OK`.
pub(super) extern "win64" fn native_uuid_create(uuid: *mut u8) -> i32 {
    match native_co_create_guid(uuid) {
        0 => 0,
        _ => 1775, // RPC_S_INVALID_ARG
    }
}

/// The 100 ns intervals since 1582-10-15 (the UUID epoch), never twice the
/// same within this process.
fn uuid_timestamp() -> u64 {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = (now.as_nanos() / 100) as u64 + 0x01B2_1DD2_1381_4000;
    let mut previous = LAST.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let next = ticks.max(previous + 1);
        match LAST.compare_exchange(previous, next, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed) {
            Ok(_) => return next,
            Err(current) => previous = current,
        }
    }
}

/// `UuidCreateSequential`: a time-based (version 1) UUID. The guest has no
/// network card address, so the node is random with the multicast bit set
/// (RFC 4122 4.5) and the result is `RPC_S_UUID_LOCAL_ONLY`, as Windows
/// reports without one.
pub(super) extern "win64" fn native_uuid_create_sequential(uuid: *mut u8) -> i32 {
    const RPC_S_UUID_LOCAL_ONLY: i32 = 1824;
    if uuid.is_null() {
        return 1775; // RPC_S_INVALID_ARG
    }
    static NODE_AND_SEQUENCE: std::sync::OnceLock<[u8; 8]> = std::sync::OnceLock::new();
    let random = *NODE_AND_SEQUENCE.get_or_init(|| {
        let mut bytes = [0u8; 8];
        unsafe { getrandom(bytes.as_mut_ptr().cast(), 8, 0) };
        bytes[2] |= 0x01; // multicast: not a real card address
        bytes
    });
    let ticks = uuid_timestamp();
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&(ticks as u32).to_le_bytes());
    out[4..6].copy_from_slice(&((ticks >> 32) as u16).to_le_bytes());
    out[6..8].copy_from_slice(&(((ticks >> 48) as u16 & 0x0fff) | 0x1000).to_le_bytes());
    out[8] = (random[0] & 0x3f) | 0x80; // clock sequence high, RFC 4122 variant
    out[9] = random[1];
    out[10..].copy_from_slice(&random[2..]);
    unsafe { uuid.copy_from_nonoverlapping(out.as_ptr(), 16) };
    RPC_S_UUID_LOCAL_ONLY
}

/// A GUID's 16 bytes from `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
fn parse_guid(text: &str) -> Option<[u8; 16]> {
    let body = text.strip_prefix('{')?.strip_suffix('}')?;
    let groups: Vec<&str> = body.split('-').collect();
    let lengths = [8, 4, 4, 4, 12];
    if groups.len() != 5
        || groups.iter().zip(lengths).any(|(group, length)| group.len() != length || !group.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&u32::from_str_radix(groups[0], 16).ok()?.to_le_bytes());
    out[4..6].copy_from_slice(&u16::from_str_radix(groups[1], 16).ok()?.to_le_bytes());
    out[6..8].copy_from_slice(&u16::from_str_radix(groups[2], 16).ok()?.to_le_bytes());
    let tail = format!("{}{}", groups[3], groups[4]);
    for index in 0..8 {
        out[8 + index] = u8::from_str_radix(&tail[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` for a GUID's bytes.
fn format_guid(bytes: &[u8; 16]) -> String {
    let data1 = u32::from_le_bytes(bytes[..4].try_into().unwrap_or_default());
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let tail: String = bytes[10..].iter().map(|b| format!("{b:02X}")).collect();
    format!("{{{data1:08X}-{data2:04X}-{data3:04X}-{:02X}{:02X}-{tail}}}", bytes[8], bytes[9])
}

fn guid_from_string(text: *const u16, guid: *mut u8, invalid: i32) -> i32 {
    if guid.is_null() {
        return 0x8007_0057u32 as i32; // E_INVALIDARG
    }
    // A null string is the null GUID.
    let bytes = if text.is_null() {
        [0u8; 16]
    } else {
        match wide(text).as_deref().and_then(parse_guid) {
            Some(bytes) => bytes,
            None => return invalid,
        }
    };
    unsafe { guid.copy_from_nonoverlapping(bytes.as_ptr(), 16) };
    0
}

/// `CLSIDFromString`: the brace form; anything else (a ProgID this guest
/// does not register) is `CO_E_CLASSSTRING`.
pub(super) extern "win64" fn native_clsid_from_string(text: *const u16, clsid: *mut u8) -> i32 {
    guid_from_string(text, clsid, 0x8004_01F3u32 as i32)
}

/// `IIDFromString`: the brace form only; anything else is `E_INVALIDARG`.
pub(super) extern "win64" fn native_iid_from_string(text: *const u16, iid: *mut u8) -> i32 {
    guid_from_string(text, iid, 0x8007_0057u32 as i32)
}

/// `StringFromGUID2`: the characters written with the terminator (39), or
/// 0 when the buffer is too small.
pub(super) extern "win64" fn native_string_from_guid2(guid: *const u8, output: *mut u16, capacity: i32) -> i32 {
    if guid.is_null() || output.is_null() {
        return 0;
    }
    let mut bytes = [0u8; 16];
    unsafe { bytes.as_mut_ptr().copy_from_nonoverlapping(guid, 16) };
    let text: Vec<u16> = format_guid(&bytes).encode_utf16().chain(std::iter::once(0)).collect();
    if capacity < text.len() as i32 {
        return 0;
    }
    unsafe { output.copy_from_nonoverlapping(text.as_ptr(), text.len()) };
    text.len() as i32
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

thread_local! {
    // A weak process identity prevents a host thread reused by another
    // guest process from inheriting its predecessor's CRT callback.
    static CRT_THREAD_INVALID_HANDLER: std::cell::RefCell<Option<(std::sync::Weak<NativeProcessContext>, u64)>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) extern "win64" fn native_crt_set_invalid_parameter_handler(handler: u64) -> u64 {
    process_ctx().map_or(0, |process| {
        process
            .crt_invalid_parameter_handler
            .swap(handler, Ordering::AcqRel)
    })
}

pub(super) extern "win64" fn native_crt_get_invalid_parameter_handler() -> u64 {
    process_ctx().map_or(0, |process| {
        process
            .crt_invalid_parameter_handler
            .load(Ordering::Acquire)
    })
}

pub(super) extern "win64" fn native_crt_get_thread_local_invalid_parameter_handler() -> u64 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    CRT_THREAD_INVALID_HANDLER.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|(owner, _)| {
                owner
                    .upgrade()
                    .is_some_and(|owner| Arc::ptr_eq(&owner, &process))
            })
            .map_or(0, |(_, handler)| *handler)
    })
}

pub(super) extern "win64" fn native_crt_set_thread_local_invalid_parameter_handler(
    handler: u64,
) -> u64 {
    let previous = native_crt_get_thread_local_invalid_parameter_handler();
    if let Some(process) = process_ctx() {
        CRT_THREAD_INVALID_HANDLER
            .with(|slot| *slot.borrow_mut() = Some((Arc::downgrade(&process), handler)));
    }
    previous
}

pub(super) extern "win64" fn native_crt_invalid_parameter(
    expression: u64,
    function: u64,
    file: u64,
    line: u32,
    reserved: u64,
) {
    let local = native_crt_get_thread_local_invalid_parameter_handler();
    let handler = if local != 0 {
        local
    } else {
        native_crt_get_invalid_parameter_handler()
    };
    if handler == 0 {
        native_crt_invoke_watson(expression, function, file, line, reserved);
    }
    let callback: extern "win64" fn(u64, u64, u64, u32, u64) =
        unsafe { std::mem::transmute(handler as usize) };
    callback(expression, function, file, line, reserved);
}

pub(super) extern "win64" fn native_crt_invalid_parameter_noinfo() {
    native_crt_invalid_parameter(0, 0, 0, 0, 0)
}

pub(super) extern "win64" fn native_crt_invalid_parameter_noinfo_noreturn() -> ! {
    native_crt_invalid_parameter_noinfo();
    native_crt_invoke_watson(0, 0, 0, 0, 0)
}

#[cfg(test)]
mod tests {

    #[test]
    fn command_lines_split_with_a_literal_program_name() {
        assert_eq!(
            command_line_arguments(r#""C:\Program Files\a.exe" one "two words" three\\"x"#),
            [r"C:\Program Files\a.exe", "one", "two words", r#"three\x"#]
        );
        assert_eq!(command_line_arguments(r#"C:\dir\b.exe"#), [r"C:\dir\b.exe"]);
        assert_eq!(command_line_arguments(r#"C:\a\"b.exe x"#), [r#"C:\a\"b.exe"#, "x"], "no quote handling in the name");
    }

    #[test]
    fn substring_search_with_and_without_case() {
        let w = |t: &str| t.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (text, upper, missing) = (w("Hello World"), w("WORLD"), w("planet"));
        let found = native_str_str_i_w(text.as_ptr(), upper.as_ptr());
        assert_eq!(unsafe { found.offset_from(text.as_ptr()) }, 6);
        assert!(native_str_str_w(text.as_ptr(), upper.as_ptr()).is_null(), "case matters to StrStrW");
        assert!(native_str_str_i_w(text.as_ptr(), missing.as_ptr()).is_null());
        assert!(native_str_str_i_w(ptr::null(), upper.as_ptr()).is_null());
    }

    #[test]
    fn sequential_uuids_are_version_1_and_increase() {
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        assert_eq!(native_uuid_create_sequential(a.as_mut_ptr()), 1824);
        assert_eq!(native_uuid_create_sequential(b.as_mut_ptr()), 1824);
        assert_eq!(a[7] >> 4, 1, "version 1");
        assert_eq!(a[8] & 0xc0, 0x80, "RFC 4122 variant");
        assert_eq!(a[10..], b[10..], "one node per process");
        let time = |u: &[u8; 16]| {
            (u64::from(u16::from_le_bytes([u[6], u[7]]) & 0x0fff) << 48)
                | (u64::from(u16::from_le_bytes([u[4], u[5]])) << 32)
                | u64::from(u32::from_le_bytes(u[..4].try_into().unwrap()))
        };
        assert!(time(&b) > time(&a));
        let mut random = [0u8; 16];
        assert_eq!(native_uuid_create(random.as_mut_ptr()), 0);
        assert_eq!(random[7] >> 4, 4);
    }

    #[test]
    fn guids_parse_and_format_in_registry_order() {
        let text = "{F38BF404-1D43-42F2-9305-67DE0B28FC23}";
        let bytes = parse_guid(text).unwrap();
        assert_eq!(&bytes[..4], &[0x04, 0xF4, 0x8B, 0xF3], "Data1 little-endian");
        assert_eq!(&bytes[8..10], &[0x93, 0x05], "Data4 in order");
        assert_eq!(format_guid(&bytes), text);
        assert_eq!(parse_guid("{f38bf404-1d43-42f2-9305-67de0b28fc23}"), Some(bytes), "either case");
        assert_eq!(parse_guid("F38BF404-1D43-42F2-9305-67DE0B28FC23"), None, "braces required");
        assert_eq!(parse_guid("{F38BF404-1D43-42F2-9305-67DE0B28FC2}"), None);
        let wide: Vec<u16> = "not a guid".encode_utf16().chain(Some(0)).collect();
        let mut out = [0u8; 16];
        assert_eq!(native_clsid_from_string(wide.as_ptr(), out.as_mut_ptr()), 0x8004_01F3u32 as i32);
        assert_eq!(native_clsid_from_string(std::ptr::null(), out.as_mut_ptr()), 0);
        assert_eq!(out, [0; 16]);
        let mut text_out = [0u16; 39];
        assert_eq!(native_string_from_guid2(bytes.as_ptr(), text_out.as_mut_ptr(), 39), 39);
        assert_eq!(native_string_from_guid2(bytes.as_ptr(), text_out.as_mut_ptr(), 38), 0);
    }

    use super::*;

    thread_local! { static INVALID_CALLS: std::cell::RefCell<Vec<(u32, [u64; 5])>> = const { std::cell::RefCell::new(Vec::new()) }; }
    extern "win64" fn global_invalid(
        expression: u64,
        function: u64,
        file: u64,
        line: u32,
        reserved: u64,
    ) {
        INVALID_CALLS.with(|calls| {
            calls
                .borrow_mut()
                .push((1, [expression, function, file, line as u64, reserved]))
        });
    }
    extern "win64" fn local_invalid(
        expression: u64,
        function: u64,
        file: u64,
        line: u32,
        reserved: u64,
    ) {
        INVALID_CALLS.with(|calls| {
            calls
                .borrow_mut()
                .push((2, [expression, function, file, line as u64, reserved]))
        });
    }

    #[test]
    fn invalid_parameter_handlers_roundtrip_dispatch_and_respect_thread_precedence() {
        let process = new_test_process();
        let previous = THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(Arc::clone(&process))));
        let global = global_invalid as *const () as usize as u64;
        let local = local_invalid as *const () as usize as u64;
        assert_eq!(native_crt_get_invalid_parameter_handler(), 0);
        assert_eq!(native_crt_set_invalid_parameter_handler(global), 0);
        assert_eq!(native_crt_get_invalid_parameter_handler(), global);
        native_crt_invalid_parameter(11, 12, 13, 14, 15);
        assert_eq!(
            native_crt_set_thread_local_invalid_parameter_handler(local),
            0
        );
        native_crt_invalid_parameter_noinfo();
        assert_eq!(
            native_crt_set_thread_local_invalid_parameter_handler(0),
            local
        );
        native_crt_invalid_parameter_noinfo();
        INVALID_CALLS.with(|calls| {
            assert_eq!(
                *calls.borrow(),
                vec![(1, [11, 12, 13, 14, 15]), (2, [0; 5]), (1, [0; 5])]
            )
        });
        assert_eq!(native_crt_set_invalid_parameter_handler(0), global);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(previous));
    }

    #[test]
    fn invalid_parameter_handler_state_is_isolated_between_threads_and_processes() {
        let process = new_test_process();
        let previous = THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(Arc::clone(&process))));
        let global = global_invalid as *const () as usize as u64;
        let local = local_invalid as *const () as usize as u64;
        native_crt_set_invalid_parameter_handler(global);
        native_crt_set_thread_local_invalid_parameter_handler(local);
        std::thread::spawn(move || {
            THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(process)));
            assert_eq!(native_crt_get_invalid_parameter_handler(), global);
            assert_eq!(native_crt_get_thread_local_invalid_parameter_handler(), 0);
            native_crt_set_thread_local_invalid_parameter_handler(global);
            native_crt_invalid_parameter_noinfo();
            INVALID_CALLS.with(|calls| assert_eq!(*calls.borrow(), vec![(1, [0; 5])]));
        })
        .join()
        .unwrap();
        assert_eq!(
            native_crt_get_thread_local_invalid_parameter_handler(),
            local
        );
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(new_test_process())));
        assert_eq!(native_crt_get_invalid_parameter_handler(), 0);
        assert_eq!(native_crt_get_thread_local_invalid_parameter_handler(), 0);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(previous));
    }

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
        assert!(native_set_thread_description(0, ptr::null()) < 0);
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
