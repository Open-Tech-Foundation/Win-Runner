//! MSVC exception handling from VCRUNTIME140: `_CxxThrowException`, the
//! C++ frame handler `__CxxFrameHandler3` (the FH3 tables MSVC and LLVM emit
//! for `try`/`catch` and destructor cleanups, which Rust's panic unwinding
//! on `*-windows-msvc` uses too), and the SEH scope handler
//! `__C_specific_handler` (`__try`/`__except`/`__finally`).
//!
//! The handlers run under winrun's exception dispatch and `RtlUnwindEx`: a
//! catch unwinds to its frame with a `STATUS_UNWIND_CONSOLIDATE` record whose
//! callback runs the catch funclet and returns where execution continues.

use super::*;

/// `EH_EXCEPTION_NUMBER`: `'msc' | 0xE0000000`.
pub(super) const CXX_EXCEPTION: u32 = 0xe06d_7363;
/// `EH_MAGIC_NUMBER1`, the first exception parameter of a C++ throw.
const EH_MAGIC: u64 = 0x1993_0520;
const STATUS_UNWIND_CONSOLIDATE: u32 = 0x8000_0029;
const EXCEPTION_UNWINDING: u32 = 0x2;
const EXCEPTION_EXIT_UNWIND: u32 = 0x4;
const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
const EXCEPTION_CONTINUE_EXECUTION: u32 = 0;
const EXCEPTION_CONTINUE_SEARCH: u32 = 1;

/// Handler adjectives (`HandlerType::adjectives`).
const HT_IS_REFERENCE: u32 = 0x8;
const HT_IS_STD_DOT_DOT: u32 = 0x40;
/// Catchable type properties.
const CT_IS_SIMPLE_TYPE: u32 = 0x1;
const CT_BY_REFERENCE_ONLY: u32 = 0x2;
const CT_HAS_VIRTUAL_BASE: u32 = 0x4;

fn read_u32(address: u64) -> u32 {
    unsafe { (address as *const u32).read_unaligned() }
}
fn read_i32(address: u64) -> i32 {
    unsafe { (address as *const i32).read_unaligned() }
}
fn read_u64(address: u64) -> u64 {
    unsafe { (address as *const u64).read_unaligned() }
}

/// The base of the loaded image containing `address`, or 0.
fn image_base_of(address: u64) -> u64 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    if address >= process.image_base
        && address < process.image_base + u64::from(process.image_size)
    {
        return process.image_base;
    }
    process
        .loaded_modules
        .lock()
        .ok()
        .and_then(|modules| {
            modules
                .values()
                .find(|m| address >= m.base && address < m.base + u64::from(m.size_of_image))
                .map(|m| m.base)
        })
        .unwrap_or(0)
}

/// A C++ exception in flight: thrown object, its ThrowInfo, and the image
/// base its ThrowInfo RVAs are relative to.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Thrown {
    object: u64,
    throw_info: u64,
    image_base: u64,
}

impl Thrown {
    fn from_record(record: &NativeExceptionRecord) -> Option<Self> {
        (record.code == CXX_EXCEPTION
            && record.parameter_count >= 3
            && record.information[0] == EH_MAGIC
            && record.information[2] != 0)
            .then(|| Thrown {
                object: record.information[1],
                throw_info: record.information[2],
                image_base: if record.parameter_count >= 4 {
                    record.information[3]
                } else {
                    0
                },
            })
    }
}

/// A catch block that is running: its exception, the frame whose catch it
/// is, and that frame's try block.
#[derive(Clone, Copy, Debug)]
struct ActiveCatch {
    thrown: Thrown,
    establisher: u64,
    try_low: i32,
    /// Stack position of the call running the catch funclet.
    stack: u64,
}

thread_local! {
    /// Catch blocks that are running, innermost last: `throw;` rethrows the
    /// last one's exception (`_CxxThrowException(NULL, NULL)`).
    static CAUGHT: std::cell::RefCell<Vec<ActiveCatch>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Destroy a C++ exception object with its ThrowInfo destructor.
fn destroy(thrown: &Thrown) {
    if thrown.throw_info == 0 || thrown.object == 0 {
        return;
    }
    let destructor = read_i32(thrown.throw_info + 4);
    if destructor != 0 {
        let destroy: extern "win64" fn(u64) = unsafe {
            std::mem::transmute((thrown.image_base + destructor as u32 as u64) as usize)
        };
        destroy(thrown.object);
    }
}

/// Unwinding to the frame at `target` abandons the running catch blocks
/// whose funclet calls were below it on the stack: destroy their exception
/// objects, except one that is being rethrown.
fn abandon_catches(target: u64, rethrown: u64) {
    let abandoned: Vec<ActiveCatch> = CAUGHT.with(|caught| {
        let mut caught = caught.borrow_mut();
        let keep = caught
            .iter()
            .position(|active| active.stack < target)
            .unwrap_or(caught.len());
        caught.split_off(keep)
    });
    for active in abandoned.iter().rev() {
        if active.thrown.object != rethrown {
            destroy(&active.thrown);
        }
    }
}

/// The running catch of the frame at `establisher`, if any.
fn active_catch(establisher: u64) -> Option<ActiveCatch> {
    CAUGHT.with(|caught| {
        caught
            .borrow()
            .iter()
            .rev()
            .find(|active| active.establisher == establisher)
            .copied()
    })
}

/// `_CxxThrowException` continued from its assembly entry with the
/// thrower's context: raise `0xE06D7363` noncontinuably from that frame.
#[no_mangle]
extern "win64" fn winrun_cxx_throw_with_context(
    object: u64,
    throw_info: u64,
    context: *mut NativeExceptionContext,
) {
    let thrown = if throw_info == 0 {
        // `throw;` rethrows the exception whose catch block is running.
        match CAUGHT.with(|caught| caught.borrow().last().copied()) {
            Some(current) => current.thrown,
            None => {
                super::super::diagnostics::report(
                    b"winrun: rethrow with no active C++ exception (std::terminate)\n",
                );
                native_exit_process(3)
            }
        }
    } else {
        Thrown {
            object,
            throw_info,
            image_base: image_base_of(throw_info),
        }
    };
    let arguments = [EH_MAGIC, thrown.object, thrown.throw_info, thrown.image_base];
    winrun_raise_exception_with_context(CXX_EXCEPTION, 1, 4, arguments.as_ptr(), context);
}

// ---- FH3 tables ------------------------------------------------------------

/// `FuncInfo` (x64): RVAs are relative to the function's image base.
struct FuncInfo {
    max_state: i32,
    unwind_map: u64,
    try_blocks: u32,
    try_block_map: u64,
    ip_entries: u32,
    ip_to_state: u64,
}

impl FuncInfo {
    fn read(address: u64, image_base: u64) -> Option<Self> {
        let magic = read_u32(address) & 0x1fff_ffff;
        if !(0x1993_0520..=0x1993_0522).contains(&magic) {
            return None;
        }
        let rva = |offset: u64| {
            let value = read_u32(address + offset);
            if value == 0 { 0 } else { image_base + u64::from(value) }
        };
        Some(FuncInfo {
            max_state: read_i32(address + 4),
            unwind_map: rva(8),
            try_blocks: read_u32(address + 12),
            try_block_map: rva(16),
            ip_entries: read_u32(address + 20),
            ip_to_state: rva(24),
        })
    }

    /// The EH state at `pc`: the last IP-to-state entry at or before it.
    fn state_at(&self, pc: u64, image_base: u64) -> i32 {
        let relative = pc.wrapping_sub(image_base);
        let mut state = -1;
        for index in 0..u64::from(self.ip_entries) {
            let entry = self.ip_to_state + index * 8;
            if u64::from(read_u32(entry)) > relative {
                break;
            }
            state = read_i32(entry + 4);
        }
        state
    }

    /// (toState, cleanup funclet address or 0) for `state`.
    fn unwind_entry(&self, state: i32, image_base: u64) -> Option<(i32, u64)> {
        if state < 0 || state >= self.max_state || self.unwind_map == 0 {
            return None;
        }
        let entry = self.unwind_map + state as u64 * 8;
        let action = read_u32(entry + 4);
        Some((
            read_i32(entry),
            if action == 0 { 0 } else { image_base + u64::from(action) },
        ))
    }
}

/// Run the cleanup funclets of a frame from `state` down to `target`.
fn unwind_frame(info: &FuncInfo, image_base: u64, establisher: u64, mut state: i32, target: i32) {
    let mut steps = 0;
    while state > target && steps <= info.max_state {
        let Some((next, action)) = info.unwind_entry(state, image_base) else {
            break;
        };
        if action != 0 {
            let funclet: extern "win64" fn(u64, u64) -> u64 =
                unsafe { std::mem::transmute(action as usize) };
            funclet(establisher, establisher);
        }
        state = next;
        steps += 1;
    }
}

/// A `HandlerType` entry of a try block.
struct Handler {
    adjectives: u32,
    type_descriptor: u64,
    catch_object: i32,
    funclet: u64,
}

/// The catchable type of `thrown` that `handler` accepts, as (properties,
/// this-displacement (mdisp, pdisp, vdisp), size, copy function).
struct Catchable {
    properties: u32,
    displacement: (i32, i32, i32),
    size: i32,
    copy: u64,
}

fn type_name(descriptor: u64) -> Option<&'static std::ffi::CStr> {
    (descriptor != 0).then(|| unsafe { std::ffi::CStr::from_ptr((descriptor + 16) as *const _) })
}

fn matching_catchable(handler: &Handler, thrown: &Thrown) -> Option<Catchable> {
    let rva = |value: i32| thrown.image_base + value as u32 as u64;
    let array = rva(read_i32(thrown.throw_info + 12));
    let count = read_i32(array).max(0) as u64;
    let wanted = type_name(handler.type_descriptor)?;
    for index in 0..count {
        let catchable = rva(read_i32(array + 4 + index * 4));
        let properties = read_u32(catchable);
        let descriptor = rva(read_i32(catchable + 4));
        let same = descriptor == handler.type_descriptor || type_name(descriptor) == Some(wanted);
        if !same {
            continue;
        }
        if properties & CT_BY_REFERENCE_ONLY != 0 && handler.adjectives & HT_IS_REFERENCE == 0 {
            continue;
        }
        let copy = read_i32(catchable + 24);
        return Some(Catchable {
            properties,
            displacement: (
                read_i32(catchable + 8),
                read_i32(catchable + 12),
                read_i32(catchable + 16),
            ),
            size: read_i32(catchable + 20),
            copy: if copy == 0 { 0 } else { rva(copy) },
        });
    }
    None
}

/// `AdjustPointer`: the address of the caught base subobject.
fn adjust_pointer(object: u64, (mdisp, pdisp, vdisp): (i32, i32, i32)) -> u64 {
    let mut address = object.wrapping_add(mdisp as i64 as u64);
    if pdisp >= 0 {
        let vbtable = read_u64(object.wrapping_add(pdisp as i64 as u64));
        let offset = read_i32(vbtable.wrapping_add(vdisp as i64 as u64));
        address = address.wrapping_add(pdisp as i64 as u64).wrapping_add(offset as i64 as u64);
    }
    address
}

/// Initialize the catch clause's parameter in the catching frame.
fn build_catch_object(handler: &Handler, catchable: Option<&Catchable>, thrown: &Thrown, establisher: u64) {
    if handler.catch_object == 0 || handler.type_descriptor == 0 {
        return;
    }
    let Some(catchable) = catchable else {
        return;
    };
    let destination = establisher.wrapping_add(handler.catch_object as i64 as u64);
    let source = adjust_pointer(thrown.object, catchable.displacement);
    unsafe {
        if handler.adjectives & HT_IS_REFERENCE != 0 {
            (destination as *mut u64).write_unaligned(source);
        } else if catchable.properties & CT_IS_SIMPLE_TYPE != 0 || catchable.copy == 0 {
            std::ptr::copy_nonoverlapping(
                source as *const u8,
                destination as *mut u8,
                catchable.size.max(0) as usize,
            );
        } else if catchable.properties & CT_HAS_VIRTUAL_BASE != 0 {
            let copy: extern "win64" fn(u64, u64, i32) =
                std::mem::transmute(catchable.copy as usize);
            copy(destination, source, 1);
        } else {
            let copy: extern "win64" fn(u64, u64) = std::mem::transmute(catchable.copy as usize);
            copy(destination, source);
        }
    }
}

/// Consolidation callback: run the catch funclet (its parent frame in rdx),
/// destroy the exception object, and return where execution continues.
extern "win64" fn call_catch_block(record: *mut NativeExceptionRecord) -> u64 {
    let record = unsafe { &*record };
    let establisher = record.information[1];
    let funclet = record.information[2];
    let thrown = Thrown {
        object: record.information[4],
        throw_info: record.information[5],
        image_base: record.information[6],
    };
    abandon_catches(record.information[7], thrown.object);
    let marker = 0u8;
    CAUGHT.with(|caught| {
        caught.borrow_mut().push(ActiveCatch {
            thrown,
            establisher,
            try_low: record.information[3] as i64 as i32,
            stack: &marker as *const u8 as u64,
        })
    });
    let catch: extern "win64" fn(u64, u64) -> u64 = unsafe { std::mem::transmute(funclet as usize) };
    let continuation = catch(establisher, establisher);
    CAUGHT.with(|caught| caught.borrow_mut().pop());
    destroy(&thrown);
    continuation
}

/// For a frame inside a catch funclet, the parent function's establisher
/// frame (saved by the funclet at `HandlerType::dispFrame`) and the high
/// state of the try block the catch belongs to, and that block's catch high
/// state; `None` for a frame of the function itself.
fn funclet_parent(info: &FuncInfo, image_base: u64, dc: &NativeDispatcherContext, establisher: u64, state: i32) -> Option<(u64, i32, i32)> {
    if dc.function_entry.is_null() {
        return None;
    }
    let begin = image_base + u64::from(unsafe { (*dc.function_entry).begin_address });
    for block in (0..u64::from(info.try_blocks)).rev() {
        let entry = info.try_block_map + block * 20;
        let (try_high, catch_high) = (read_i32(entry + 4), read_i32(entry + 8));
        if state <= try_high || state > catch_high {
            continue;
        }
        let handlers = image_base + u64::from(read_u32(entry + 16));
        for index in 0..read_i32(entry + 12).max(0) as u64 {
            let at = handlers + index * 20;
            if image_base + u64::from(read_u32(at + 12)) == begin {
                return Some((read_u64(establisher + u64::from(read_u32(at + 16))), try_high, catch_high));
            }
        }
    }
    None
}

fn is_catch_consolidation(record: &NativeExceptionRecord) -> bool {
    record.code == STATUS_UNWIND_CONSOLIDATE
        && record.parameter_count >= 8
        && record.information[0] == call_catch_block as *const () as u64
}

/// `__CxxFrameHandler3`.
pub(super) extern "win64" fn native_cxx_frame_handler3(
    record: *mut NativeExceptionRecord,
    establisher: u64,
    context: *mut NativeExceptionContext,
    dispatcher: *mut NativeDispatcherContext,
) -> u32 {
    let (record, dc) = unsafe { (&mut *record, &mut *dispatcher) };
    if dc.handler_data.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let image_base = dc.image_base;
    let info_rva = unsafe { (dc.handler_data as *const u32).read_unaligned() };
    let Some(info) = FuncInfo::read(image_base + u64::from(info_rva), image_base) else {
        return EXCEPTION_CONTINUE_SEARCH;
    };
    let mut state = info.state_at(dc.control_pc, image_base);
    // RtlUnwindEx targets the frame handling the exception (for a catch
    // funclet, the funclet's own); funclets and catch objects use the
    // parent function's frame.
    let frame = establisher;
    let parent = funclet_parent(&info, image_base, dc, establisher, state);
    let in_funclet = parent.is_some();
    let establisher = parent.map_or(establisher, |(frame, _, _)| frame);
    // The function itself while one of its catch blocks runs: what that
    // block's try enclosed is gone, and its handlers were the funclet's.
    let running = if in_funclet { None } else { active_catch(establisher) };
    if let Some(active) = running {
        state = state.min(active.try_low);
    }
    if record.flags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND) != 0 {
        // Unwinding: destroy this frame's objects. The catching frame keeps
        // the states that enclose its try block.
        let target = if record.flags & EXCEPTION_TARGET_UNWIND != 0
            && is_catch_consolidation(record)
            && record.information[7] == frame
        {
            record.information[3] as i64 as i32
        } else if let Some((_, try_high, _)) = parent {
            // A catch funclet's frame owns only the catch body's objects.
            try_high
        } else {
            -1
        };
        unwind_frame(&info, image_base, establisher, state, target);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // Searching: only C++ exceptions are caught (no /EHa asynchronous SEH).
    let Some(thrown) = Thrown::from_record(record) else {
        return EXCEPTION_CONTINUE_SEARCH;
    };
    for block in 0..u64::from(info.try_blocks) {
        let entry = info.try_block_map + block * 20;
        let (try_low, try_high) = (read_i32(entry), read_i32(entry + 4));
        if state < try_low || state > try_high {
            continue;
        }
        // A catch funclet's frame handles only the tries inside that catch;
        // while a catch runs, its function handles only the tries that
        // enclose the catch's own try.
        if let Some((_, parent_high, parent_catch_high)) = parent {
            if try_low <= parent_high || try_high > parent_catch_high {
                continue;
            }
        }
        if running.is_some_and(|active| try_low >= active.try_low) {
            continue;
        }
        let handlers = image_base + u64::from(read_u32(entry + 16));
        for index in 0..read_i32(entry + 12).max(0) as u64 {
            let at = handlers + index * 20;
            let descriptor = read_u32(at + 4);
            let handler = Handler {
                adjectives: read_u32(at),
                type_descriptor: if descriptor == 0 { 0 } else { image_base + u64::from(descriptor) },
                catch_object: read_i32(at + 8),
                funclet: image_base + u64::from(read_u32(at + 12)),
            };
            let catch_all = handler.type_descriptor == 0 || handler.adjectives & HT_IS_STD_DOT_DOT != 0;
            let catchable = if catch_all { None } else { matching_catchable(&handler, &thrown) };
            if !catch_all && catchable.is_none() {
                continue;
            }
            build_catch_object(&handler, catchable.as_ref(), &thrown, establisher);
            let mut consolidate = NativeExceptionRecord {
                code: STATUS_UNWIND_CONSOLIDATE,
                flags: 1,
                nested_record: record as *mut NativeExceptionRecord as u64,
                address: 0,
                parameter_count: 8,
                information: [0; 15],
            };
            consolidate.information[..8].copy_from_slice(&[
                call_catch_block as *const () as u64,
                establisher,
                handler.funclet,
                try_low as i64 as u64,
                thrown.object,
                thrown.throw_info,
                thrown.image_base,
                frame,
            ]);
            unsafe {
                winrun_native_rtl_unwind_ex(
                    frame,
                    dc.control_pc,
                    (&mut consolidate as *mut NativeExceptionRecord).cast(),
                    0,
                    context.cast(),
                    dc.history_table.cast(),
                );
            }
            // RtlUnwindEx continues in the catching frame and never returns.
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

// ---- SEH scope tables ------------------------------------------------------

/// `__C_specific_handler`: `__except` filters and blocks, `__finally`
/// termination handlers, from the function's SCOPE_TABLE.
pub(super) extern "win64" fn native_c_specific_handler(
    record: *mut NativeExceptionRecord,
    establisher: u64,
    context: *mut NativeExceptionContext,
    dispatcher: *mut NativeDispatcherContext,
) -> u32 {
    let (record_ref, dc) = unsafe { (&mut *record, &mut *dispatcher) };
    if dc.handler_data.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let table = dc.handler_data as u64;
    let count = u64::from(read_u32(table));
    let image_base = dc.image_base;
    let pc = dc.control_pc.wrapping_sub(image_base);
    let scope = |index: u64| {
        let entry = table + 4 + index * 16;
        (
            u64::from(read_u32(entry)),
            u64::from(read_u32(entry + 4)),
            u64::from(read_u32(entry + 8)),
            u64::from(read_u32(entry + 12)),
        )
    };
    if record_ref.flags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND) == 0 {
        for index in u64::from(dc.scope_index)..count {
            let (begin, end, filter, jump) = scope(index);
            if pc < begin || pc >= end || jump == 0 {
                continue;
            }
            let decision = if filter == 1 {
                1 // EXCEPTION_EXECUTE_HANDLER as a constant filter
            } else {
                let mut pointers = NativeExceptionPointers { record, context };
                let filter: extern "win64" fn(*mut NativeExceptionPointers, u64) -> i32 =
                    unsafe { std::mem::transmute((image_base + filter) as usize) };
                filter(&mut pointers, establisher)
            };
            if decision < 0 {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            if decision > 0 {
                unsafe {
                    winrun_native_rtl_unwind_ex(
                        establisher,
                        image_base + jump,
                        record.cast(),
                        u64::from(record_ref.code),
                        context.cast(),
                        dc.history_table.cast(),
                    );
                }
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let target = dc.target_ip.wrapping_sub(image_base);
    for index in u64::from(dc.scope_index)..count {
        let (begin, end, handler, jump) = scope(index);
        if pc < begin || pc >= end {
            continue;
        }
        if record_ref.flags & EXCEPTION_TARGET_UNWIND != 0 {
            // Stop at the scope the unwind lands in.
            if (target >= begin && target < end) || (jump != 0 && target == jump) {
                break;
            }
        }
        if jump == 0 {
            dc.scope_index = (index + 1) as u32;
            let termination: extern "win64" fn(u8, u64) =
                unsafe { std::mem::transmute((image_base + handler) as usize) };
            termination(1, establisher);
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_to_state_maps_return_addresses_into_their_region() {
        // States: [0x100, 0x120) → -1, [0x120, 0x140) → 0, then 1.
        let ip_map: [u32; 6] = [0x100, u32::MAX, 0x120, 0, 0x140, 1];
        let info = FuncInfo {
            max_state: 2,
            unwind_map: 0,
            try_blocks: 0,
            try_block_map: 0,
            ip_entries: 3,
            ip_to_state: ip_map.as_ptr() as u64,
        };
        let base = 0x1000;
        assert_eq!(info.state_at(base + 0xff, base), -1);
        assert_eq!(info.state_at(base + 0x100, base), -1);
        assert_eq!(info.state_at(base + 0x12f, base), 0);
        assert_eq!(info.state_at(base + 0x140, base), 1);
        assert_eq!(info.unwind_entry(5, base), None);
    }

    #[test]
    fn adjusted_pointers_follow_member_and_virtual_base_offsets() {
        assert_eq!(adjust_pointer(0x1000, (8, -1, 0)), 0x1008);
        // Virtual base: vbtable at object+0, entry at +4 holds 0x20.
        let vbtable: [i32; 2] = [0, 0x20];
        let object: [u64; 1] = [vbtable.as_ptr() as u64];
        let base = object.as_ptr() as u64;
        assert_eq!(adjust_pointer(base, (4, 0, 4)), base + 4 + 0x20);
    }

    #[test]
    fn catchable_types_match_by_name_and_reference_rules() {
        // A ThrowInfo with one catchable type "rust_panic" (by-reference
        // only), RVAs relative to `base`, laid out in one buffer.
        let mut image = vec![0u8; 256];
        let base = image.as_mut_ptr() as u64;
        let put = |image: &mut Vec<u8>, at: usize, value: u32| {
            image[at..at + 4].copy_from_slice(&value.to_le_bytes())
        };
        // TypeDescriptor at 0x80: vftable, spare, name.
        image[0x90..0x90 + 11].copy_from_slice(b"rust_panic\0");
        // CatchableTypeArray at 0x40: count 1, entry → 0x50.
        put(&mut image, 0x40, 1);
        put(&mut image, 0x44, 0x50);
        // CatchableType at 0x50: properties, type, mdisp, pdisp, vdisp, size, copy.
        put(&mut image, 0x50, CT_BY_REFERENCE_ONLY);
        put(&mut image, 0x54, 0x80);
        put(&mut image, 0x5c, u32::MAX); // pdisp = -1
        put(&mut image, 0x64, 8);
        // ThrowInfo at 0x20: attributes, unwind, forward compat, array.
        put(&mut image, 0x2c, 0x40);
        let thrown = Thrown { object: 0x5000, throw_info: base + 0x20, image_base: base };
        let other_name = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0rust_panic\0";
        let mut handler = Handler {
            adjectives: HT_IS_REFERENCE,
            type_descriptor: other_name.as_ptr() as u64,
            catch_object: 0,
            funclet: 0,
        };
        let catchable = matching_catchable(&handler, &thrown).expect("same name matches");
        assert_eq!((catchable.size, catchable.copy), (8, 0));
        handler.adjectives = 0;
        assert!(matching_catchable(&handler, &thrown).is_none(), "by-reference only");
        let unrelated = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0other\0";
        handler.adjectives = HT_IS_REFERENCE;
        handler.type_descriptor = unrelated.as_ptr() as u64;
        assert!(matching_catchable(&handler, &thrown).is_none());
    }

    #[test]
    fn only_msvc_throw_records_carry_cxx_exceptions() {
        let mut record: NativeExceptionRecord = unsafe { std::mem::zeroed() };
        record.code = CXX_EXCEPTION;
        record.parameter_count = 4;
        record.information[..4].copy_from_slice(&[EH_MAGIC, 1, 2, 3]);
        assert_eq!(
            Thrown::from_record(&record),
            Some(Thrown { object: 1, throw_info: 2, image_base: 3 })
        );
        record.information[0] = 0x1234;
        assert_eq!(Thrown::from_record(&record), None);
        record.information[0] = EH_MAGIC;
        record.code = 0xc000_0005;
        assert_eq!(Thrown::from_record(&record), None);
    }
}
