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

#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub(super) struct NativeExceptionContext {
    pub(super) bytes: [u8; 1232],
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
    let dynamic_tables = process.dynamic_function_tables.lock().unwrap();
    for table in dynamic_tables.iter() {
        let Some(relative_pc) = control_pc.checked_sub(table.base) else {
            continue;
        };
        let entries = table.table as *const NativeRuntimeFunction;
        for index in 0..table.entry_count as usize {
            let entry = unsafe { entries.add(index) };
            let function = unsafe { entry.read_unaligned() };
            if function.begin_address < function.end_address
                && relative_pc >= u64::from(function.begin_address)
                && relative_pc < u64::from(function.end_address)
            {
                unsafe { image_base.write(table.base) };
                return entry as u64;
            }
        }
    }
    drop(dynamic_tables);
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

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct NativeRuntimeFunction {
    pub(super) begin_address: u32,
    pub(super) end_address: u32,
    pub(super) unwind_data: u32,
}

pub(super) extern "win64" fn native_rtl_add_function_table(
    function_table: *mut NativeRuntimeFunction,
    entry_count: u32,
    base_address: u64,
) -> u8 {
    const MAX_DYNAMIC_FUNCTION_ENTRIES: u32 = 1_000_000;
    if function_table.is_null()
        || entry_count == 0
        || entry_count > MAX_DYNAMIC_FUNCTION_ENTRIES
        || base_address == 0
        || (entry_count as usize)
            .checked_mul(std::mem::size_of::<NativeRuntimeFunction>())
            .and_then(|size| (function_table as usize).checked_add(size))
            .is_none()
    {
        return 0;
    }
    let entries = unsafe { std::slice::from_raw_parts(function_table, entry_count as usize) };
    if entries
        .iter()
        .any(|entry| entry.begin_address >= entry.end_address)
        || entries.windows(2).any(|pair| {
            pair[0].begin_address > pair[1].begin_address
                || pair[0].end_address > pair[1].begin_address
        })
    {
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let table = function_table as u64;
    let mut tables = process.dynamic_function_tables.lock().unwrap();
    if tables.iter().any(|registered| registered.table == table) {
        return 0;
    }
    tables.push(NativeDynamicFunctionTable {
        table,
        entry_count,
        base: base_address,
    });
    1
}

pub(super) extern "win64" fn native_rtl_delete_function_table(
    function_table: *mut NativeRuntimeFunction,
) -> u8 {
    if function_table.is_null() {
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let mut tables = process.dynamic_function_tables.lock().unwrap();
    let Some(index) = tables
        .iter()
        .position(|registered| registered.table == function_table as u64)
    else {
        return 0;
    };
    tables.remove(index);
    1
}

/// Apply the common x64 UNWIND_INFO operations to a Windows CONTEXT.
pub(super) extern "win64" fn native_rtl_virtual_unwind(
    handler_type: u32,
    image_base: u64,
    control_pc: u64,
    function_entry: *const NativeRuntimeFunction,
    context_record: *mut NativeExceptionContext,
    handler_data: *mut *mut c_void,
    establisher_frame: *mut u64,
    _context_pointers: *mut c_void,
) -> u64 {
    if context_record.is_null() || handler_type > 2 {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    if !handler_data.is_null() {
        unsafe { handler_data.write(std::ptr::null_mut()) };
    }
    let mut context = unsafe { context_record.read_unaligned() };
    let original_rsp = context_register(&context, 4).unwrap_or(0);
    if original_rsp == 0 {
        return 0;
    }
    if function_entry.is_null() {
        let Some(return_address) = stack_u64(original_rsp) else {
            return 0;
        };
        let Some(restored_rsp) = original_rsp.checked_add(8) else {
            return 0;
        };
        context_set_register(&mut context, 16, return_address);
        context_set_register(&mut context, 4, restored_rsp);
        if !establisher_frame.is_null() {
            unsafe { establisher_frame.write(original_rsp) };
        }
        unsafe { context_record.write_unaligned(context) };
        return 0;
    }

    let function = unsafe { function_entry.read_unaligned() };
    let Some(function_start) = image_base.checked_add(u64::from(function.begin_address)) else {
        return 0;
    };
    let Some(prologue_offset) = control_pc.checked_sub(function_start) else {
        return 0;
    };
    let Some(plan) = decode_unwind_plan(
        image_base,
        function,
        prologue_offset,
        0,
        &mut std::collections::HashSet::new(),
    ) else {
        return 0;
    };
    let operations = plan.operations;
    let frame_register = plan.frame_register;
    let frame_offset = plan.frame_offset;
    if frame_register == 0 && frame_offset != 0 {
        return 0;
    }
    let frame_register_active =
        frame_register != 0 && operations.iter().any(|operation| operation.0 == 3);
    let establisher = if frame_register_active {
        let Some(frame_value) = context_register(&context, frame_register) else {
            return 0;
        };
        let Some(frame) = frame_value.checked_sub(u64::from(frame_offset) * 16) else {
            return 0;
        };
        frame
    } else {
        original_rsp
    };
    let mut rsp = original_rsp;
    let mut machine_frame = false;
    for (op, info, operand) in operations {
        match op {
            0 => {
                if !is_nonvolatile_register(info) {
                    return 0;
                }
                let Some(value) = stack_u64(rsp) else {
                    return 0;
                };
                context_set_register(&mut context, info, value);
                let Some(next_rsp) = rsp.checked_add(8) else {
                    return 0;
                };
                rsp = next_rsp;
            }
            1 => {
                let allocation = match info {
                    0 => operand.checked_mul(8),
                    1 => Some(operand),
                    _ => None,
                };
                let Some(allocation) = allocation else {
                    return 0;
                };
                let Some(next_rsp) = rsp.checked_add(allocation) else {
                    return 0;
                };
                rsp = next_rsp;
            }
            2 => {
                let Some(next_rsp) = rsp.checked_add(u64::from(info) * 8 + 8) else {
                    return 0;
                };
                rsp = next_rsp;
            }
            3 => {
                if info != 0 || frame_register == 0 {
                    return 0;
                }
                let Some(frame_value) = context_register(&context, frame_register) else {
                    return 0;
                };
                let Some(frame) = frame_value.checked_sub(u64::from(frame_offset) * 16) else {
                    return 0;
                };
                rsp = frame;
            }
            4 | 5 => {
                if !is_nonvolatile_register(info) {
                    return 0;
                }
                let offset = if op == 4 {
                    operand.checked_mul(8)
                } else {
                    Some(operand)
                };
                let Some(offset) = offset else {
                    return 0;
                };
                let frame_base = if !frame_register_active {
                    rsp
                } else {
                    let Some(frame_value) = context_register(&context, frame_register) else {
                        return 0;
                    };
                    let Some(frame) = frame_value.checked_sub(u64::from(frame_offset) * 16) else {
                        return 0;
                    };
                    frame
                };
                let Some(address) = frame_base.checked_add(offset) else {
                    return 0;
                };
                let Some(value) = stack_u64(address) else {
                    return 0;
                };
                context_set_register(&mut context, info, value);
            }
            8 | 9 => {
                if !(6..=15).contains(&info) {
                    return 0;
                }
                let offset = if op == 8 {
                    operand.checked_mul(16)
                } else {
                    Some(operand)
                };
                let Some(offset) = offset else {
                    return 0;
                };
                let frame_base = if !frame_register_active {
                    rsp
                } else {
                    let Some(frame_value) = context_register(&context, frame_register) else {
                        return 0;
                    };
                    let Some(frame) = frame_value.checked_sub(u64::from(frame_offset) * 16) else {
                        return 0;
                    };
                    frame
                };
                let Some(address) = frame_base.checked_add(offset) else {
                    return 0;
                };
                let xmm_offset = 416 + usize::from(info) * 16;
                let saved = unsafe { std::slice::from_raw_parts(address as *const u8, 16) };
                context.bytes[xmm_offset..xmm_offset + 16].copy_from_slice(saved);
            }
            10 => {
                if info > 1 {
                    return 0;
                }
                let Some(frame) = rsp.checked_add(u64::from(info) * 8) else {
                    return 0;
                };
                let Some(rip) = stack_u64(frame) else {
                    return 0;
                };
                let Some(cs_address) = frame.checked_add(8) else {
                    return 0;
                };
                let Some(flags_address) = frame.checked_add(16) else {
                    return 0;
                };
                let Some(rsp_address) = frame.checked_add(24) else {
                    return 0;
                };
                let Some(restored_rsp) = stack_u64(rsp_address) else {
                    return 0;
                };
                let Some(ss_address) = frame.checked_add(32) else {
                    return 0;
                };
                let Some(cs) = stack_u16(cs_address) else {
                    return 0;
                };
                let Some(eflags) = stack_u32(flags_address) else {
                    return 0;
                };
                let Some(ss) = stack_u16(ss_address) else {
                    return 0;
                };
                context_set_register(&mut context, 16, rip);
                context_set_register(&mut context, 4, restored_rsp);
                context.bytes[56..58].copy_from_slice(&cs.to_le_bytes());
                context.bytes[66..68].copy_from_slice(&ss.to_le_bytes());
                context.bytes[68..72].copy_from_slice(&eflags.to_le_bytes());
                machine_frame = true;
            }
            _ => return 0,
        }
    }
    if !machine_frame {
        let Some(return_address) = stack_u64(rsp) else {
            return 0;
        };
        context_set_register(&mut context, 16, return_address);
        let Some(restored_rsp) = rsp.checked_add(8) else {
            return 0;
        };
        context_set_register(&mut context, 4, restored_rsp);
    }

    let mut handler = 0;
    let handler_flag = match handler_type {
        1 => Some(1),
        2 => Some(2),
        _ => None,
    };
    if let Some((handler_flags, handler_rva, handler_data_address)) = plan.handler {
        if handler_flag.is_some_and(|flag| handler_flags & flag != 0) {
            let Some(handler_address) = image_base.checked_add(u64::from(handler_rva)) else {
                return 0;
            };
            if !handler_data.is_null() {
                unsafe {
                    handler_data.write(handler_data_address as *mut c_void);
                }
            }
            handler = handler_address;
        }
    }
    unsafe { context_record.write_unaligned(context) };
    if !establisher_frame.is_null() {
        unsafe { establisher_frame.write(establisher) };
    }
    handler
}

fn context_register(context: &NativeExceptionContext, register: u8) -> Option<u64> {
    let offset = match register {
        0 => 120,  // RAX
        1 => 128,  // RCX
        2 => 136,  // RDX
        3 => 144,  // RBX
        4 => 152,  // RSP
        5 => 160,  // RBP
        6 => 168,  // RSI
        7 => 176,  // RDI
        8 => 184,  // R8
        9 => 192,  // R9
        10 => 200, // R10
        11 => 208, // R11
        12 => 216, // R12
        13 => 224, // R13
        14 => 232, // R14
        15 => 240, // R15
        _ => return None,
    };
    Some(u64::from_le_bytes(
        context.bytes[offset..offset + 8].try_into().ok()?,
    ))
}

fn context_set_register(context: &mut NativeExceptionContext, register: u8, value: u64) {
    let offset = match register {
        0 => 120,
        1 => 128,
        2 => 136,
        3 => 144,
        4 => 152,
        5 => 160,
        6 => 168,
        7 => 176,
        8 => 184,
        9 => 192,
        10 => 200,
        11 => 208,
        12 => 216,
        13 => 224,
        14 => 232,
        15 => 240,
        16 => 248, // RIP
        _ => return,
    };
    context.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn is_nonvolatile_register(register: u8) -> bool {
    matches!(register, 3 | 5 | 6 | 7 | 12 | 13 | 14 | 15)
}

fn stack_u64(address: u64) -> Option<u64> {
    (address != 0).then(|| unsafe { (address as *const u64).read_unaligned() })
}

fn stack_u32(address: u64) -> Option<u32> {
    (address != 0).then(|| unsafe { (address as *const u32).read_unaligned() })
}

fn stack_u16(address: u64) -> Option<u16> {
    (address != 0).then(|| unsafe { (address as *const u16).read_unaligned() })
}

struct DecodedUnwindPlan {
    operations: Vec<(u8, u8, u64)>,
    frame_register: u8,
    frame_offset: u8,
    handler: Option<(u8, u32, u64)>,
}

fn decode_unwind_plan(
    image_base: u64,
    function: NativeRuntimeFunction,
    prologue_offset: u64,
    depth: usize,
    visited: &mut std::collections::HashSet<u32>,
) -> Option<DecodedUnwindPlan> {
    const MAX_CHAIN_DEPTH: usize = 32;
    if depth >= MAX_CHAIN_DEPTH
        || function.begin_address >= function.end_address
        || (prologue_offset != u64::MAX
            && prologue_offset >= u64::from(function.end_address - function.begin_address))
        || !visited.insert(function.unwind_data)
    {
        return None;
    }
    let unwind_address = image_base.checked_add(u64::from(function.unwind_data))?;
    let header = unsafe { std::slice::from_raw_parts(unwind_address as *const u8, 4) };
    let version = header[0] & 7;
    let flags = header[0] >> 3;
    let prologue_size = header[1];
    let code_count = header[2] as usize;
    let frame_register = header[3] & 0x0f;
    let frame_offset = header[3] >> 4;
    if version != 1
        || flags & !7 != 0
        || (flags & 4 != 0 && flags & 3 != 0)
        || (frame_register == 0 && frame_offset != 0)
        || (frame_register != 0 && !is_nonvolatile_register(frame_register))
    {
        return None;
    }
    let code_bytes = code_count.checked_mul(2)?;
    let codes =
        unsafe { std::slice::from_raw_parts((unwind_address + 4) as *const u8, code_bytes) };
    let mut operations = Vec::new();
    let mut slot = 0usize;
    let mut previous_code_offset = u8::MAX;
    while slot < code_count {
        let code_offset = codes[slot * 2];
        if code_offset > previous_code_offset || code_offset > prologue_size {
            return None;
        }
        previous_code_offset = code_offset;
        let op_and_info = codes[slot * 2 + 1];
        let op = op_and_info & 0x0f;
        let info = op_and_info >> 4;
        let slots = match op {
            0 | 2 | 3 | 10 => 1,
            1 if info == 0 => 2,
            1 if info == 1 => 3,
            4 | 8 => 2,
            5 | 9 => 3,
            _ => return None,
        };
        if slot + slots > code_count {
            return None;
        }
        let operand = match slots {
            2 => u64::from(u16::from_le_bytes([
                codes[(slot + 1) * 2],
                codes[(slot + 1) * 2 + 1],
            ])),
            3 => {
                let low = u16::from_le_bytes([codes[(slot + 1) * 2], codes[(slot + 1) * 2 + 1]]);
                let high = u16::from_le_bytes([codes[(slot + 2) * 2], codes[(slot + 2) * 2 + 1]]);
                u64::from(low) | (u64::from(high) << 16)
            }
            _ => 0,
        };
        if prologue_offset == u64::MAX || u64::from(code_offset) <= prologue_offset {
            operations.push((op, info, operand));
        }
        slot += slots;
    }

    if flags & 4 != 0 {
        let padded_slots = (code_count + 1) & !1;
        let chained_entry_address = unwind_address.checked_add(4 + (padded_slots * 2) as u64)?;
        let chained_function =
            unsafe { (chained_entry_address as *const NativeRuntimeFunction).read_unaligned() };
        let mut parent =
            decode_unwind_plan(image_base, chained_function, u64::MAX, depth + 1, visited)?;
        if parent.frame_register != frame_register || parent.frame_offset != frame_offset {
            return None;
        }
        operations.append(&mut parent.operations);
        return Some(DecodedUnwindPlan {
            operations,
            frame_register,
            frame_offset,
            handler: parent.handler,
        });
    }

    let handler = if flags & 3 != 0 {
        let padded_slots = (code_count + 1) & !1;
        let handler_rva_address = unwind_address.checked_add(4 + (padded_slots * 2) as u64)?;
        let handler_rva = unsafe { (handler_rva_address as *const u32).read_unaligned() };
        let handler_data_address = handler_rva_address.checked_add(4)?;
        if handler_rva == 0 {
            return None;
        }
        Some((flags & 3, handler_rva, handler_data_address))
    } else {
        None
    };
    Some(DecodedUnwindPlan {
        operations,
        frame_register,
        frame_offset,
        handler,
    })
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
