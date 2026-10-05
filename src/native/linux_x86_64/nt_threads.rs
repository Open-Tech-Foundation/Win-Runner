//! Current-process NT threads over the native Windows thread objects.
use super::*;
const INVALID_PARAMETER: u32 = 0xc000000d;
const NOT_SUPPORTED: u32 = 0xc00000bb;

#[repr(C)]
#[derive(Clone, Copy)]
struct Attribute {
    kind: usize,
    size: usize,
    value: usize,
    returned_size: usize,
}
fn attributes(list: *const usize) -> Result<Vec<Attribute>, u32> {
    if list.is_null() {
        return Ok(Vec::new());
    }
    let length = unsafe { list.read_unaligned() };
    if length < 8 || (length - 8) % 32 != 0 || length > 8 + 32 * 16 {
        return Err(INVALID_PARAMETER);
    }
    let mut result = Vec::new();
    for index in 0..(length - 8) / 32 {
        let attr = unsafe {
            list.cast::<u8>()
                .add(8 + index * 32)
                .cast::<Attribute>()
                .read_unaligned()
        };
        let size = match attr.kind {
            0x10003 => 16, // PS_ATTRIBUTE_CLIENT_ID (output)
            0x10004 => 8,  // PS_ATTRIBUTE_TEB_ADDRESS (output)
            _ => return Err(NOT_SUPPORTED),
        };
        if attr.size != size
            || attr.value == 0
            || result
                .iter()
                .any(|previous: &Attribute| previous.kind == attr.kind)
        {
            return Err(INVALID_PARAMETER);
        }
        result.push(attr);
    }
    Ok(result)
}
pub(super) extern "win64" fn native_nt_create_thread_ex(
    out: *mut u64,
    desired: u32,
    object: *const u8,
    process_handle: u64,
    start: u64,
    parameter: u64,
    flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *const usize,
) -> u32 {
    if native_diagnostic_enabled() {
        eprintln!("native NtCreateThreadEx process={process_handle:#x} desired={desired:#x} flags={flags:#x} start={start:#x}");
    }
    let Some(process) = process_ctx() else {
        return 0xc0000008;
    };
    if process_handle != u64::MAX && process_handle != process.process_handle {
        return 0xc0000008;
    }
    if out.is_null() || start == 0 {
        return INVALID_PARAMETER;
    }
    if flags & !1 != 0 || zero_bits != 0 {
        return NOT_SUPPORTED;
    }
    let access = thread_access_mask(desired);
    if access & !THREAD_ALL_ACCESS != 0 {
        return 0xc0000022;
    }
    let mut inherit = false;
    if !object.is_null() {
        let length = unsafe { object.cast::<u32>().read_unaligned() };
        if length != 48 {
            return INVALID_PARAMETER;
        }
        let root = unsafe { object.add(8).cast::<u64>().read_unaligned() };
        let name = unsafe { object.add(16).cast::<u64>().read_unaligned() };
        let attrs = unsafe { object.add(24).cast::<u32>().read_unaligned() };
        let security = unsafe { object.add(32).cast::<u64>().read_unaligned() };
        let qos = unsafe { object.add(40).cast::<u64>().read_unaligned() };
        let named = name != 0 && unsafe { (name as *const u16).read_unaligned() } != 0;
        if root != 0 || named || security != 0 || qos != 0 || attrs & !(2 | 0x40) != 0 {
            return NOT_SUPPORTED;
        }
        inherit = attrs & 2 != 0;
    }
    let attrs = match attributes(attribute_list) {
        Ok(attrs) => attrs,
        Err(error) => return error,
    };
    let saved = native_get_last_error();
    // Publish outputs and desired rights before the thread can execute guest code.
    let mut id = 0;
    let handle = native_create_thread(
        0,
        stack_size.max(maximum_stack_size),
        start,
        parameter,
        4,
        &mut id,
    );
    if handle == 0 {
        let error = native_get_last_error();
        native_set_last_error(saved);
        return if error == 8 { 0xc0000017 } else { 0xc0000001 };
    }
    let teb = process
        .tls_blocks
        .lock()
        .unwrap()
        .get(&handle)
        .and_then(Weak::upgrade)
        .map(|tls| tls.lock().unwrap().teb.as_ptr() as u64)
        .unwrap_or(0);
    for attr in attrs {
        unsafe {
            let value = attr.value as *mut u64;
            if attr.kind == 0x10003 {
                value.write_unaligned(process.process_id as u64);
                value.add(1).write_unaligned(id as u64);
            } else {
                value.write_unaligned(teb)
            }
            if attr.returned_size != 0 {
                (attr.returned_size as *mut usize).write_unaligned(attr.size)
            }
        }
    }
    let queue = {
        let mut handles = process.apc_handles.lock().unwrap();
        let thread = handles.get_mut(&handle).unwrap();
        thread.access = access;
        thread.flags = inherit as u32;
        thread.queue.clone()
    };
    unsafe { out.write_unaligned(handle) }
    if flags & 1 == 0 {
        // Internal startup must not require suspend/resume access on the handle
        // requested by the caller.
        let (count, ready) = &*queue.thread.suspension;
        *count.lock().unwrap() = 0;
        ready.notify_one();
    }
    native_set_last_error(saved);
    0
}
pub(super) extern "win64" fn native_nt_resume_thread(handle: u64, previous: *mut u32) -> u32 {
    let saved = native_get_last_error();
    let count = native_resume_thread(handle);
    let status = if count == u32::MAX {
        if native_get_last_error() == 5 {
            0xc0000022
        } else {
            0xc0000008
        }
    } else {
        if !previous.is_null() {
            unsafe { previous.write_unaligned(count) }
        }
        0
    };
    native_set_last_error(saved);
    status
}
#[cfg(test)]
mod tests {
    use super::*;
    extern "win64" fn worker(parameter: u64) -> u32 {
        unsafe { (parameter as *mut u64).write(native_get_current_thread_id() as u64) }
        42
    }
    #[test]
    fn starts_without_resume_rights_and_rejects_unsupported_options_before_creation() {
        let old =
            THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(context::new_test_process())));
        let mut output = 0u64;
        let mut handle = 0;
        let empty_name = [0usize; 2];
        let object = [48usize, 0, empty_name.as_ptr() as usize, 0x40, 0, 0];
        assert_eq!(
            native_nt_create_thread_ex(
                &mut handle,
                0x100000,
                object.as_ptr().cast(),
                u64::MAX,
                worker as *const () as u64,
                &mut output as *mut _ as u64,
                0,
                0,
                0,
                0,
                std::ptr::null()
            ),
            0
        );
        assert_eq!(native_wait_for_single_object(handle, 5000), 0);
        assert_ne!(output, 0);
        assert_eq!(
            native_nt_resume_thread(handle, std::ptr::null_mut()),
            0xc0000022
        );
        native_close_handle(handle);
        let mut failed = 0x1234;
        assert_eq!(
            native_nt_create_thread_ex(
                &mut failed,
                THREAD_ALL_ACCESS,
                std::ptr::null(),
                u64::MAX,
                worker as *const () as u64,
                0,
                2,
                0,
                0,
                0,
                std::ptr::null()
            ),
            NOT_SUPPORTED
        );
        assert_eq!(failed, 0x1234);
        assert_eq!(
            native_nt_create_thread_ex(
                &mut failed,
                THREAD_ALL_ACCESS,
                std::ptr::null(),
                0,
                worker as *const () as u64,
                0,
                0,
                0,
                0,
                0,
                std::ptr::null()
            ),
            0xc0000008
        );
        assert_eq!(failed, 0x1234);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(old));
    }
    #[test]
    fn creates_suspended_thread_with_client_id_and_teb_outputs() {
        let old =
            THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(context::new_test_process())));
        let mut output = 0u64;
        let mut client = [0u64; 2];
        let mut teb = 0u64;
        let mut length = 0usize;
        let list = [
            72usize,
            0x10003,
            16,
            client.as_mut_ptr() as usize,
            0,
            0x10004,
            8,
            &mut teb as *mut _ as usize,
            &mut length as *mut _ as usize,
        ];
        let mut handle = 0;
        native_set_last_error(0x4321);
        assert_eq!(
            native_nt_create_thread_ex(
                &mut handle,
                THREAD_ALL_ACCESS,
                std::ptr::null(),
                u64::MAX,
                worker as *const () as u64,
                &mut output as *mut _ as u64,
                1,
                0,
                0,
                0,
                list.as_ptr()
            ),
            0
        );
        assert_ne!(handle, 0);
        assert_ne!(teb, 0);
        assert_eq!(length, 8);
        assert_eq!(unsafe { ((teb + 0x40) as *const u64).read() }, client[0]);
        assert_eq!(unsafe { ((teb + 0x48) as *const u64).read() }, client[1]);
        let peb = unsafe { ((teb + 0x60) as *const u64).read() };
        let process = process_ctx().unwrap();
        assert_eq!(unsafe { ((peb + 0x20) as *const u64).read() }, &process.parameters as *const NativeProcessParameters as u64);
        assert_eq!(client[1], native_get_thread_id(handle) as u64);
        assert_eq!(output, 0);
        assert_eq!(native_wait_for_single_object(handle, 0), 258);
        let mut count = 0;
        assert_eq!(native_nt_resume_thread(handle, &mut count), 0);
        assert_eq!(count, 1);
        assert_eq!(native_wait_for_single_object(handle, 5000), 0);
        assert_eq!(output, client[1]);
        assert_eq!(native_get_last_error(), 0x4321);
        assert_eq!(native_close_handle(handle), 1);
        let bad = [40usize, 0xdead, 8, &mut teb as *mut _ as usize, 0];
        assert_eq!(attributes(bad.as_ptr()).err(), Some(NOT_SUPPORTED));
        assert_eq!(native_nt_resume_thread(0, &mut count), 0xc0000008);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(old));
    }
}
