//! Windows software exception compatibility APIs for the Linux native backend.

use super::*;

#[repr(C)]
pub(super) struct NativeExceptionRecord {
    pub(super) code: u32,
    pub(super) flags: u32,
    pub(super) nested_record: u64,
    pub(super) address: u64,
    pub(super) parameter_count: u32,
    pub(super) information: [u64; 15],
}

#[repr(C, align(16))]
pub(super) struct NativeExceptionContext {
    bytes: [u8; 1232],
}

#[repr(C)]
pub(super) struct NativeExceptionPointers {
    pub(super) record: *mut NativeExceptionRecord,
    pub(super) context: *mut NativeExceptionContext,
}

impl NativeExceptionContext {
    fn software_exception() -> Self {
        // CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT
        let mut context = Self { bytes: [0; 1232] };
        context.bytes[48..52].copy_from_slice(&0x0010_001fu32.to_le_bytes());
        context
    }
}

pub(super) extern "win64" fn native_set_unhandled_exception_filter(filter: u64) -> u64 {
    process_ctx()
        .map(|process| {
            process
                .unhandled_exception_filter
                .swap(filter, Ordering::AcqRel)
        })
        .unwrap_or(0)
}

pub(super) extern "win64" fn native_add_vectored_exception_handler(
    first: u32,
    handler: u64,
) -> u64 {
    if handler == 0 {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let handle = process
        .vectored_exception_handler_next
        .fetch_add(8, Ordering::AcqRel);
    let registration = NativeVectoredExceptionHandler {
        handle,
        callback: handler,
    };
    let mut handlers = process.vectored_exception_handlers.lock().unwrap();
    if first != 0 {
        handlers.insert(0, registration);
    } else {
        handlers.push(registration);
    }
    handle
}

pub(super) extern "win64" fn native_remove_vectored_exception_handler(handle: u64) -> u32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let mut handlers = process.vectored_exception_handlers.lock().unwrap();
    if let Some(index) = handlers.iter().position(|handler| handler.handle == handle) {
        handlers.remove(index);
        1
    } else {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        0
    }
}

fn dispatch_exception(record: &mut NativeExceptionRecord) -> bool {
    let Some(process) = process_ctx() else {
        return false;
    };
    let mut context = NativeExceptionContext::software_exception();
    let mut pointers = NativeExceptionPointers {
        record,
        context: &mut context,
    };
    let callbacks: Vec<u64> = process
        .vectored_exception_handlers
        .lock()
        .unwrap()
        .iter()
        .map(|handler| handler.callback)
        .collect();
    for callback in callbacks {
        let callback: extern "win64" fn(*mut NativeExceptionPointers) -> i32 =
            unsafe { std::mem::transmute(callback as usize) };
        match callback(&mut pointers) as u32 {
            0xffff_ffff => return true, // EXCEPTION_CONTINUE_EXECUTION
            0 => {}                     // EXCEPTION_CONTINUE_SEARCH
            _ => {}                     // VEH does not accept EXECUTE_HANDLER.
        }
    }
    let filter = process.unhandled_exception_filter.load(Ordering::Acquire);
    if filter != 0 {
        let filter: extern "win64" fn(*mut NativeExceptionPointers) -> i32 =
            unsafe { std::mem::transmute(filter as usize) };
        return filter(&mut pointers) as u32 == 0xffff_ffff;
    }
    false
}

pub(super) extern "win64" fn native_raise_exception(
    code: u32,
    flags: u32,
    argument_count: u32,
    arguments: *const u64,
) {
    if argument_count > 15 || (argument_count != 0 && arguments.is_null()) {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return;
    }
    let mut record = NativeExceptionRecord {
        code,
        flags,
        nested_record: 0,
        address: 0,
        parameter_count: argument_count,
        information: [0; 15],
    };
    if argument_count != 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(
                arguments,
                record.information.as_mut_ptr(),
                argument_count as usize,
            );
        }
    }
    if !dispatch_exception(&mut record) {
        native_exit_process(code)
    }
}

pub(super) extern "win64" fn native_rtl_raise_exception(record: *mut NativeExceptionRecord) -> u32 {
    if record.is_null() {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 87;
    }
    let record = unsafe { &mut *record };
    if record.parameter_count > 15 {
        native_set_last_error(87);
        return 87;
    }
    if dispatch_exception(record) {
        0
    } else {
        native_exit_process(record.code)
    }
}

/// Find the x64 RUNTIME_FUNCTION covering ControlPc in a loaded guest image.
/// The returned pointer refers to the image's mapped exception directory.
pub(super) extern "win64" fn native_rtl_lookup_function_entry(
    control_pc: u64,
    image_base: *mut u64,
    _history_table: *mut c_void,
) -> u64 {
    if image_base.is_null() {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    unsafe { image_base.write(0) };
    let Some(process) = process_ctx() else {
        return 0;
    };
    let modules = process.loaded_modules.lock().unwrap();
    for module in modules.values() {
        let Some(relative_pc) = control_pc.checked_sub(module.base) else {
            continue;
        };
        if relative_pc >= u64::from(module.size_of_image) {
            continue;
        }
        let Some((table_rva, table_size)) = mapped_exception_directory(module) else {
            continue;
        };
        let count = table_size / 12;
        for index in 0..count {
            let entry_rva = table_rva + index * 12;
            let entry = module.base + u64::from(entry_rva);
            let begin = unsafe { (entry as *const u32).read_unaligned() };
            let end = unsafe { (entry as *const u32).add(1).read_unaligned() };
            if begin < end && relative_pc >= u64::from(begin) && relative_pc < u64::from(end) {
                unsafe { image_base.write(module.base) };
                return entry;
            }
        }
    }
    0
}

fn mapped_exception_directory(module: &NativeLoadedModule) -> Option<(u32, u32)> {
    let base = module.base as *const u8;
    let size = module.size_of_image as usize;
    let read_u16 = |offset: usize| -> Option<u16> {
        let end = offset.checked_add(2)?;
        (end <= size).then(|| unsafe { base.add(offset).cast::<u16>().read_unaligned() })
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        let end = offset.checked_add(4)?;
        (end <= size).then(|| unsafe { base.add(offset).cast::<u32>().read_unaligned() })
    };
    if read_u16(0)? != 0x5a4d {
        return None;
    }
    let nt_offset = read_u32(0x3c)? as usize;
    if read_u32(nt_offset)? != 0x0000_4550 {
        return None;
    }
    let optional_size = usize::from(read_u16(nt_offset.checked_add(20)?)?);
    let optional_offset = nt_offset.checked_add(24)?;
    if optional_size < 112 + 4 * 8
        || read_u16(optional_offset)? != 0x20b
        || read_u32(optional_offset.checked_add(108)?)? < 4
    {
        return None;
    }
    let directory_offset = optional_offset.checked_add(112 + 3 * 8)?;
    let rva = read_u32(directory_offset)?;
    let directory_size = read_u32(directory_offset.checked_add(4)?)?;
    let end = rva.checked_add(directory_size)?;
    (rva != 0 && directory_size >= 12 && directory_size % 12 == 0 && end as usize <= size)
        .then_some((rva, directory_size))
}
