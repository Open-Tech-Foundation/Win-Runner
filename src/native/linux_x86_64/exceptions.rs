//! Windows software exception compatibility APIs for the Linux native backend.

use super::*;

const NATIVE_FAULT_SLOT_COUNT: usize = 64;

#[repr(align(16))]
struct NativeFaultFxState([u8; 512]);

struct NativeFaultSlot {
    thread_id: AtomicI32,
    jump_buffer: std::cell::UnsafeCell<[u64; 32]>,
    context: std::cell::UnsafeCell<std::mem::MaybeUninit<libc::ucontext_t>>,
    fxstate: std::cell::UnsafeCell<NativeFaultFxState>,
    signal: AtomicI32,
    signal_code: AtomicI32,
    fault_address: AtomicU64,
    page_fault_error: AtomicU64,
}

impl NativeFaultSlot {
    const fn new() -> Self {
        Self {
            thread_id: AtomicI32::new(0),
            jump_buffer: std::cell::UnsafeCell::new([0; 32]),
            context: std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit()),
            fxstate: std::cell::UnsafeCell::new(NativeFaultFxState([0; 512])),
            signal: AtomicI32::new(0),
            signal_code: AtomicI32::new(0),
            fault_address: AtomicU64::new(0),
            page_fault_error: AtomicU64::new(0),
        }
    }

    fn jump_buffer(&self) -> *mut std::ffi::c_void {
        self.jump_buffer.get().cast()
    }

    unsafe fn context_mut(&self) -> &mut libc::ucontext_t {
        unsafe { (&mut *self.context.get()).assume_init_mut() }
    }
}

unsafe impl Sync for NativeFaultSlot {}

static NATIVE_FAULT_SLOTS: [NativeFaultSlot; NATIVE_FAULT_SLOT_COUNT] =
    [const { NativeFaultSlot::new() }; NATIVE_FAULT_SLOT_COUNT];
static NATIVE_FAULT_HANDLERS_INSTALLED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn siglongjmp(environment: *mut std::ffi::c_void, value: libc::c_int) -> !;
}

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

#[repr(C)]
struct NativeDispatcherContext {
    control_pc: u64,
    image_base: u64,
    function_entry: *const NativeRuntimeFunction,
    establisher_frame: u64,
    target_ip: u64,
    context_record: *mut NativeExceptionContext,
    language_handler: u64,
    handler_data: *mut c_void,
    history_table: *mut c_void,
    scope_index: u32,
}

impl NativeExceptionContext {
    pub(super) fn software_exception() -> Self {
        // CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT
        let mut context = Self { bytes: [0; 1232] };
        context.bytes[48..52].copy_from_slice(&0x0010_001fu32.to_le_bytes());
        context
    }
}

/// Convert the interrupted Linux x86-64 register state into the Windows
/// CONTEXT layout consumed by the native exception APIs.
pub(super) fn context_from_linux_ucontext(source: &libc::ucontext_t) -> NativeExceptionContext {
    let registers = &source.uc_mcontext.gregs;
    let mut context = NativeExceptionContext::software_exception();
    for (windows_register, linux_register) in [
        (0, libc::REG_RAX),
        (1, libc::REG_RCX),
        (2, libc::REG_RDX),
        (3, libc::REG_RBX),
        (4, libc::REG_RSP),
        (5, libc::REG_RBP),
        (6, libc::REG_RSI),
        (7, libc::REG_RDI),
        (8, libc::REG_R8),
        (9, libc::REG_R9),
        (10, libc::REG_R10),
        (11, libc::REG_R11),
        (12, libc::REG_R12),
        (13, libc::REG_R13),
        (14, libc::REG_R14),
        (15, libc::REG_R15),
        (16, libc::REG_RIP),
    ] {
        context_set_register(
            &mut context,
            windows_register,
            registers[linux_register as usize] as u64,
        );
    }
    context.bytes[68..72]
        .copy_from_slice(&(registers[libc::REG_EFL as usize] as u32).to_le_bytes());
    let selectors = registers[libc::REG_CSGSFS as usize] as u64;
    context.bytes[56..58].copy_from_slice(&(selectors as u16).to_le_bytes());
    context.bytes[64..66].copy_from_slice(&((selectors >> 16) as u16).to_le_bytes());
    context.bytes[62..64].copy_from_slice(&((selectors >> 32) as u16).to_le_bytes());
    context.bytes[66..68].copy_from_slice(&((selectors >> 48) as u16).to_le_bytes());

    if !source.uc_mcontext.fpregs.is_null() {
        // Linux x86-64 signal frames begin with the architectural 512-byte
        // FXSAVE image, which shares the Windows CONTEXT FltSave layout.
        unsafe {
            std::ptr::copy_nonoverlapping(
                source.uc_mcontext.fpregs.cast::<u8>(),
                context.bytes.as_mut_ptr().add(256),
                512,
            );
        }
    }
    context
}

/// Apply a guest Windows CONTEXT back to the Linux signal frame so execution
/// can resume from registers changed by a Windows exception handler.
pub(super) fn apply_windows_context_to_linux_ucontext(
    source: &NativeExceptionContext,
    destination: &mut libc::ucontext_t,
) {
    let registers = &mut destination.uc_mcontext.gregs;
    for (windows_register, linux_register) in [
        (0, libc::REG_RAX),
        (1, libc::REG_RCX),
        (2, libc::REG_RDX),
        (3, libc::REG_RBX),
        (4, libc::REG_RSP),
        (5, libc::REG_RBP),
        (6, libc::REG_RSI),
        (7, libc::REG_RDI),
        (8, libc::REG_R8),
        (9, libc::REG_R9),
        (10, libc::REG_R10),
        (11, libc::REG_R11),
        (12, libc::REG_R12),
        (13, libc::REG_R13),
        (14, libc::REG_R14),
        (15, libc::REG_R15),
        (16, libc::REG_RIP),
    ] {
        registers[linux_register as usize] =
            context_register(source, windows_register).unwrap_or(0) as libc::greg_t;
    }
    registers[libc::REG_EFL as usize] =
        u32::from_le_bytes(source.bytes[68..72].try_into().unwrap()) as libc::greg_t;
    let cs = u16::from_le_bytes(source.bytes[56..58].try_into().unwrap()) as u64;
    let gs = u16::from_le_bytes(source.bytes[64..66].try_into().unwrap()) as u64;
    let fs = u16::from_le_bytes(source.bytes[62..64].try_into().unwrap()) as u64;
    let ss = u16::from_le_bytes(source.bytes[66..68].try_into().unwrap()) as u64;
    registers[libc::REG_CSGSFS as usize] = (cs | gs << 16 | fs << 32 | ss << 48) as libc::greg_t;

    if !destination.uc_mcontext.fpregs.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                source.bytes.as_ptr().add(256),
                destination.uc_mcontext.fpregs.cast::<u8>(),
                512,
            );
        }
    }
}

/// Map a synchronous Linux x86-64 fault signal into its Windows status code
/// and exception parameters. Asynchronous/user-generated signals are ignored.
pub(super) fn exception_record_from_linux_signal(
    signal: i32,
    signal_code: i32,
    fault_address: u64,
    instruction_pointer: u64,
    page_fault_error: u64,
) -> Option<NativeExceptionRecord> {
    let (code, information) = match signal {
        libc::SIGSEGV | libc::SIGBUS if signal_code > 0 => {
            let operation = if page_fault_error & (1 << 4) != 0 {
                8 // EXCEPTION_EXECUTE_FAULT
            } else if page_fault_error & (1 << 1) != 0 {
                1 // write
            } else {
                0 // read
            };
            (0xc000_0005, [operation, fault_address]) // STATUS_ACCESS_VIOLATION
        }
        libc::SIGILL if signal_code > 0 => (0xc000_001d, [0, 0]), // STATUS_ILLEGAL_INSTRUCTION
        libc::SIGFPE if signal_code > 0 => {
            const LINUX_FPE_INTDIV: i32 = 1;
            const LINUX_FPE_INTOVF: i32 = 2;
            const LINUX_FPE_FLTDIV: i32 = 3;
            const LINUX_FPE_FLTOVF: i32 = 4;
            const LINUX_FPE_FLTUND: i32 = 5;
            const LINUX_FPE_FLTRES: i32 = 6;
            const LINUX_FPE_FLTINV: i32 = 7;
            const LINUX_FPE_FLTSUB: i32 = 8;
            let status = match signal_code {
                LINUX_FPE_INTDIV => 0xc000_0094,
                LINUX_FPE_INTOVF => 0xc000_0095,
                LINUX_FPE_FLTDIV => 0xc000_008e,
                LINUX_FPE_FLTOVF => 0xc000_0091,
                LINUX_FPE_FLTUND => 0xc000_0093,
                LINUX_FPE_FLTRES => 0xc000_008f,
                LINUX_FPE_FLTINV => 0xc000_0090,
                LINUX_FPE_FLTSUB => 0xc000_008c,
                _ => return None,
            };
            (status, [0, 0])
        }
        _ => return None,
    };
    let parameter_count = if code == 0xc000_0005 { 2 } else { 0 };
    let mut record = NativeExceptionRecord {
        code,
        flags: 0,
        nested_record: 0,
        address: instruction_pointer,
        parameter_count,
        information: [0; 15],
    };
    record.information[..2].copy_from_slice(&information);
    Some(record)
}

pub(super) fn install_guest_fault_signal_handlers() -> Result<(), String> {
    if NATIVE_FAULT_HANDLERS_INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }
    for signal in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = native_guest_fault_signal_handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(format!(
                "could not install guest fault handler for signal {signal}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    NATIVE_FAULT_HANDLERS_INSTALLED.store(true, Ordering::Release);
    Ok(())
}

extern "C" fn native_guest_fault_signal_handler(
    signal: libc::c_int,
    signal_info: *mut libc::siginfo_t,
    signal_context: *mut std::ffi::c_void,
) {
    if signal_info.is_null() || signal_context.is_null() {
        unsafe { libc::_exit(128 + signal) };
    }
    let thread_id = unsafe { linux_current_thread_id() };
    let Some(slot) = NATIVE_FAULT_SLOTS
        .iter()
        .find(|slot| slot.thread_id.load(Ordering::Relaxed) == thread_id)
    else {
        unsafe { libc::_exit(128 + signal) };
    };

    let source = signal_context.cast::<libc::ucontext_t>();
    let destination = unsafe { (&mut *slot.context.get()).as_mut_ptr() };
    unsafe { std::ptr::copy_nonoverlapping(source, destination, 1) };
    let fpregs = unsafe { (*source).uc_mcontext.fpregs };
    if !fpregs.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                fpregs.cast::<u8>(),
                (*slot.fxstate.get()).0.as_mut_ptr(),
                512,
            );
            (*destination).uc_mcontext.fpregs = (*slot.fxstate.get()).0.as_mut_ptr().cast();
        }
    }
    slot.signal.store(signal, Ordering::Relaxed);
    slot.signal_code
        .store(unsafe { (*signal_info).si_code }, Ordering::Relaxed);
    slot.fault_address.store(
        unsafe { (*signal_info).si_addr() } as u64,
        Ordering::Relaxed,
    );
    slot.page_fault_error.store(
        unsafe { (*source).uc_mcontext.gregs[libc::REG_ERR as usize] as u64 },
        Ordering::Relaxed,
    );
    unsafe { siglongjmp(slot.jump_buffer(), 1) }
}

unsafe fn linux_current_thread_id() -> i32 {
    let thread_id: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") libc::SYS_gettid as i64 => thread_id,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    thread_id as i32
}

extern "C" fn dispatch_linux_guest_fault(slot_pointer: *const std::ffi::c_void) -> i32 {
    if slot_pointer.is_null() {
        return 0xc000_0005u32 as i32; // STATUS_ACCESS_VIOLATION
    }
    let slot = unsafe { &*slot_pointer.cast::<NativeFaultSlot>() };
    let signal = slot.signal.load(Ordering::Relaxed);
    let signal_code = slot.signal_code.load(Ordering::Relaxed);
    let fault_address = slot.fault_address.load(Ordering::Relaxed);
    let page_fault_error = slot.page_fault_error.load(Ordering::Relaxed);
    let linux_context = unsafe { slot.context_mut() };
    let mut windows_context = context_from_linux_ucontext(linux_context);
    let instruction_pointer = context_register(&windows_context, 16).unwrap_or(0);
    let Some(mut record) = exception_record_from_linux_signal(
        signal,
        signal_code,
        fault_address,
        instruction_pointer,
        page_fault_error,
    ) else {
        return 0xc000_001d_u32 as i32; // STATUS_ILLEGAL_INSTRUCTION fallback.
    };
    let guard_fault = matches!(signal, libc::SIGSEGV | libc::SIGBUS)
        && super::memory::consume_guard_page_fault(fault_address);
    if guard_fault {
        record.code = 0x8000_0001; // STATUS_GUARD_PAGE_VIOLATION
    }

    if dispatch_exception(&mut record, &mut windows_context) {
        apply_windows_context_to_linux_ucontext(&windows_context, linux_context);
        1 // The assembly call gate restores this context while its frame is alive.
    } else {
        record.code as i32
    }
}

pub(super) unsafe fn invoke_guest_with_fault_translation(entry: u64) -> Result<u32, u32> {
    unsafe { invoke_guest_with_arguments(entry, [0; 3]) }
}

pub(super) unsafe fn invoke_guest_with_arguments(
    entry: u64,
    arguments: [u64; 3],
) -> Result<u32, u32> {
    let thread_id = unsafe { linux_current_thread_id() };
    // Nested DLL/TLS callbacks are already inside this thread's recovery gate.
    if NATIVE_FAULT_SLOTS
        .iter()
        .any(|slot| slot.thread_id.load(Ordering::Acquire) == thread_id)
    {
        let callback: unsafe extern "win64" fn(u64, u64, u64) -> u32 =
            unsafe { std::mem::transmute(entry) };
        return Ok(unsafe { callback(arguments[0], arguments[1], arguments[2]) });
    }
    let Some(slot) = NATIVE_FAULT_SLOTS.iter().find(|slot| {
        slot.thread_id
            .compare_exchange(0, thread_id, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }) else {
        return Err(0xc000_0017); // STATUS_NO_MEMORY: no fault slot available.
    };
    let mut guest_exit_code = 0;
    let result = unsafe {
        winrun_call_guest_with_signal_recovery(
            entry,
            slot.jump_buffer(),
            &mut guest_exit_code,
            dispatch_linux_guest_fault,
            (slot as *const NativeFaultSlot).cast(),
            slot.context.get().cast(),
            arguments.as_ptr(),
        )
    };
    slot.thread_id.store(0, Ordering::Release);
    if result == 0 {
        return Ok(guest_exit_code);
    }
    Err(guest_exit_code)
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

pub(super) extern "win64" fn native_add_vectored_continue_handler(
    first: u32,
    callback: u64,
) -> u64 {
    if callback == 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let handle = process
        .vectored_exception_handler_next
        .fetch_add(8, Ordering::AcqRel);
    let registration = NativeVectoredExceptionHandler { handle, callback };
    let mut handlers = process.vectored_continue_handlers.lock().unwrap();
    if first != 0 {
        handlers.insert(0, registration);
    } else {
        handlers.push(registration);
    }
    handle
}
pub(super) extern "win64" fn native_remove_vectored_continue_handler(handle: u64) -> u32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let mut handlers = process.vectored_continue_handlers.lock().unwrap();
    if let Some(index) = handlers.iter().position(|item| item.handle == handle) {
        handlers.remove(index);
        1
    } else {
        0
    }
}
fn dispatch_continue_handlers(pointers: &mut NativeExceptionPointers) {
    let Some(process) = process_ctx() else {
        return;
    };
    let callbacks: Vec<u64> = process
        .vectored_continue_handlers
        .lock()
        .unwrap()
        .iter()
        .map(|handler| handler.callback)
        .collect();
    for callback in callbacks {
        let callback: extern "win64" fn(*mut NativeExceptionPointers) -> i32 =
            unsafe { std::mem::transmute(callback as usize) };
        if callback(pointers) == -1 {
            break;
        }
    }
}

fn dispatch_exception(
    record: &mut NativeExceptionRecord,
    context: &mut NativeExceptionContext,
) -> bool {
    let Some(process) = process_ctx() else {
        return false;
    };
    if native_diagnostic_enabled() {
        eprintln!(
            "native exception code={:#x} flags={:#x} address={:#x} info=[{:#x}, {:#x}] rsp={:#x}",
            record.code,
            record.flags,
            record.address,
            record.information[0],
            record.information[1],
            context_register(context, 4).unwrap_or(0)
        );
    }
    let mut pointers = NativeExceptionPointers { record, context };
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
            0xffff_ffff => {
                dispatch_continue_handlers(&mut pointers);
                return true;
            } // EXCEPTION_CONTINUE_EXECUTION
            0 => {} // EXCEPTION_CONTINUE_SEARCH
            _ => {} // VEH does not accept EXECUTE_HANDLER.
        }
    }
    if context_register(context, 16).is_some_and(|control_pc| control_pc != 0)
        && dispatch_frame_exception_handlers(record, context)
    {
        dispatch_continue_handlers(&mut pointers);
        return true;
    }
    let filter = process.unhandled_exception_filter.load(Ordering::Acquire);
    if filter != 0 {
        let filter: extern "win64" fn(*mut NativeExceptionPointers) -> i32 =
            unsafe { std::mem::transmute(filter as usize) };
        let continued = filter(&mut pointers) as u32 == 0xffff_ffff;
        if continued {
            dispatch_continue_handlers(&mut pointers);
        }
        return continued;
    }
    false
}

thread_local! {
    /// Where a stack walk continues when it reaches winrun's own frames,
    /// innermost last: while a language handler runs, the context of the
    /// exception being dispatched (as Windows continues through
    /// `KiUserExceptionDispatcher` to the raising frame); while a C++ catch
    /// block runs from a consolidation, the context of the frame that holds
    /// it (as Windows continues through `RcConsolidateFrames`).
    static BOUNDARY_CONTEXTS: std::cell::RefCell<Vec<NativeExceptionContext>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) fn dispatch_frame_exception_handlers(
    record: &mut NativeExceptionRecord,
    context: &mut NativeExceptionContext,
) -> bool {
    const MAX_EXCEPTION_FRAMES: usize = 128;
    let mut walk_context = *context;
    let mut boundary = BOUNDARY_CONTEXTS.with(|contexts| contexts.borrow().len());
    for _ in 0..MAX_EXCEPTION_FRAMES {
        let control_pc = context_register(&walk_context, 16).unwrap_or(0);
        let stack_pointer = context_register(&walk_context, 4).unwrap_or(0);
        if control_pc == 0 || stack_pointer == 0 {
            break;
        }

        let mut image_base = 0;
        let function_entry =
            native_rtl_lookup_function_entry(control_pc, &mut image_base, std::ptr::null_mut())
                as *const NativeRuntimeFunction;
        if function_entry.is_null() && !is_guest_image_address(control_pc) {
            // winrun's frames: continue outside them, leaving the stack of
            // boundaries as it is, since this is only a search.
            if boundary == 0 {
                break;
            }
            boundary -= 1;
            walk_context = BOUNDARY_CONTEXTS.with(|contexts| contexts.borrow()[boundary]);
            continue;
        }
        let mut frame_context = walk_context;
        let mut handler_data = std::ptr::null_mut();
        let mut establisher_frame = 0;
        let language_handler = native_rtl_virtual_unwind(
            1, // UNW_FLAG_EHANDLER
            image_base,
            control_pc,
            function_entry,
            &mut frame_context,
            &mut handler_data,
            &mut establisher_frame,
            std::ptr::null_mut(),
        );

        if language_handler != 0 {
            // As in RtlDispatchException, the dispatcher context carries the
            // caller's (unwound) context; the handler's own argument is the
            // original exception context.
            let mut dispatcher_context = NativeDispatcherContext {
                control_pc,
                image_base,
                function_entry,
                establisher_frame,
                target_ip: 0,
                context_record: &mut frame_context,
                language_handler,
                handler_data,
                history_table: std::ptr::null_mut(),
                scope_index: 0,
            };
            let handler: extern "win64" fn(
                *mut NativeExceptionRecord,
                u64,
                *mut NativeExceptionContext,
                *mut NativeDispatcherContext,
            ) -> u32 = unsafe { std::mem::transmute(language_handler as usize) };
            BOUNDARY_CONTEXTS.with(|contexts| contexts.borrow_mut().push(*context));
            let disposition = handler(record, establisher_frame, context, &mut dispatcher_context);
            BOUNDARY_CONTEXTS.with(|contexts| contexts.borrow_mut().pop());
            match disposition {
                0 if record.flags & 1 == 0 => return true, // ExceptionContinueExecution
                0 => return false, // Noncontinuable exceptions cannot resume.
                1 => {}            // ExceptionContinueSearch
                2 => record.flags |= 0x10, // EXCEPTION_NESTED_CALL
                _ => {}            // Invalid dispositions do not stop the search.
            }
        }

        let next_pc = context_register(&frame_context, 16).unwrap_or(0);
        let next_stack = context_register(&frame_context, 4).unwrap_or(0);
        if next_pc == 0 || next_stack <= stack_pointer {
            break;
        }
        walk_context = frame_context;
    }
    false
}

fn is_guest_image_address(address: u64) -> bool {
    process_ctx().is_some_and(|process| {
        (address >= process.image_base
            && address < process.image_base.saturating_add(u64::from(process.image_size)))
            || process.loaded_modules.lock().is_ok_and(|modules| {
            modules.values().any(|module| {
                address >= module.base
                    && address < module.base.saturating_add(u64::from(module.size_of_image))
            })
        })
    })
}

/// `RaiseException` continued from its assembly entry, with the caller's
/// captured context: the handler search starts at the raising function.
#[no_mangle]
extern "win64" fn winrun_raise_exception_with_context(
    code: u32,
    flags: u32,
    argument_count: u32,
    arguments: *const u64,
    context: *mut NativeExceptionContext,
) {
    if argument_count > 15 || (argument_count != 0 && arguments.is_null()) || context.is_null() {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return;
    }
    let context = unsafe { &mut *context };
    let mut record = NativeExceptionRecord {
        code,
        flags: flags & 1, // EXCEPTION_NONCONTINUABLE
        nested_record: 0,
        address: context_register(context, 16).unwrap_or(0),
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
    if !dispatch_exception(&mut record, context) {
        let program = process_ctx().map(|p| p.module_path.clone()).unwrap_or_default();
        super::super::diagnostics::report(
            format!("winrun: {program}: {}\n", unhandled_exception_message(&record)).as_bytes(),
        );
        native_exit_process(code)
    }
}

fn unhandled_exception_message(record: &NativeExceptionRecord) -> String {
    if matches!(record.code, 0xc06d007e | 0xc06d007f) && record.parameter_count == 1
        && record.information[0] != 0 {
        // The MSVC delay-load helper supplies its documented DelayLoadInfo
        // through ExceptionInformation[0] when a DLL or export cannot load.
        let info = record.information[0] as *const u8;
        unsafe {
            if info.cast::<u32>().read_unaligned() >= 64 {
                let dll = info.add(24).cast::<*const u8>().read_unaligned();
                if let Some(dll) = ascii_z(dll) {
                    let by_name = info.add(32).cast::<u32>().read_unaligned() != 0;
                    let export = if by_name {
                        ascii_z(info.add(40).cast::<*const u8>().read_unaligned())
                            .unwrap_or("<unknown>").to_owned()
                    } else {
                        format!("#{}", info.add(40).cast::<u32>().read_unaligned())
                    };
                    return format!("unhandled delay-load failure: {dll}!{export} (exception {:#010x})", record.code);
                }
            }
        }
    }
    format!("unhandled Windows exception {:#010x}", record.code)
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn fatal_delay_load_diagnostics_identify_named_and_ordinal_exports() {
        let mut info = [0usize; 8];
        info[0] = 64;
        info[3] = b"WS2_32.dll\0".as_ptr() as usize;
        info[4] = 1;
        info[5] = b"MissingExport\0".as_ptr() as usize;
        let mut record: NativeExceptionRecord = unsafe { std::mem::zeroed() };
        record.code = 0xc06d007f;
        record.parameter_count = 1;
        record.information[0] = info.as_ptr() as u64;
        assert!(unhandled_exception_message(&record).contains("WS2_32.dll!MissingExport"));
        info[4] = 0;
        info[5] = 55;
        record.information[0] = info.as_ptr() as u64;
        assert!(unhandled_exception_message(&record).contains("WS2_32.dll!#55"));
        record.parameter_count = 0;
        assert_eq!(unhandled_exception_message(&record), "unhandled Windows exception 0xc06d007f");
    }
}

const EXCEPTION_UNWINDING: u32 = 0x2;
const EXCEPTION_EXIT_UNWIND: u32 = 0x4;
const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
const EXCEPTION_COLLIDED_UNWIND: u32 = 0x40;
const STATUS_UNWIND: u32 = 0xc000_0027;
const STATUS_UNWIND_CONSOLIDATE: u32 = 0x8000_0029;

/// `RtlUnwindEx`/`RtlUnwind` continued from their assembly entry with the
/// caller's context: call each frame's unwind handler up to `target_frame`
/// (whose own handler sees `EXCEPTION_TARGET_UNWIND`), then resume in the
/// target frame at `target_ip` with `Rax = return_value`. A
/// `STATUS_UNWIND_CONSOLIDATE` record instead runs the callback in
/// `ExceptionInformation[0]` (how MSVC C++ runs a catch block) and resumes
/// where it returns.
#[no_mangle]
extern "win64" fn winrun_rtl_unwind_with_context(
    target_frame: u64,
    target_ip: u64,
    record: *mut NativeExceptionRecord,
    return_value: u64,
    original_context: *mut NativeExceptionContext,
    current: *mut NativeExceptionContext,
) {
    const MAX_UNWIND_FRAMES: usize = 1024;
    let mut context = unsafe { current.read() };
    let mut local_record = NativeExceptionRecord {
        code: STATUS_UNWIND,
        flags: 0,
        nested_record: 0,
        address: context_register(&context, 16).unwrap_or(0),
        parameter_count: 0,
        information: [0; 15],
    };
    let record = if record.is_null() {
        &mut local_record
    } else {
        unsafe { &mut *record }
    };
    let mut flags = record.flags | EXCEPTION_UNWINDING;
    if target_frame == 0 {
        flags |= EXCEPTION_EXIT_UNWIND;
    }
    let mut reached_target = false;
    for _ in 0..MAX_UNWIND_FRAMES {
        let control_pc = context_register(&context, 16).unwrap_or(0);
        let stack_pointer = context_register(&context, 4).unwrap_or(0);
        if control_pc == 0 || stack_pointer == 0 {
            break;
        }
        let mut image_base = 0;
        let function_entry =
            native_rtl_lookup_function_entry(control_pc, &mut image_base, std::ptr::null_mut())
                as *const NativeRuntimeFunction;
        if function_entry.is_null() && !is_guest_image_address(control_pc) {
            // winrun's own frames, which this unwind abandons: continue from
            // the innermost boundary context.
            match BOUNDARY_CONTEXTS.with(|contexts| contexts.borrow_mut().pop()) {
                Some(raised) => {
                    context = raised;
                    continue;
                }
                None => break,
            }
        }
        let mut previous = context;
        let mut handler_data = std::ptr::null_mut();
        let mut establisher_frame = 0;
        let handler = native_rtl_virtual_unwind(
            2, // UNW_FLAG_UHANDLER
            image_base,
            control_pc,
            function_entry,
            &mut previous,
            &mut handler_data,
            &mut establisher_frame,
            std::ptr::null_mut(),
        );
        if native_diagnostic_enabled() {
            eprintln!(
                "native unwind frame pc={control_pc:#x} sp={stack_pointer:#x} entry={} establisher={establisher_frame:#x} target={target_frame:#x} handler={handler:#x}",
                !function_entry.is_null()
            );
        }
        if target_frame != 0 && establisher_frame > target_frame {
            break; // STATUS_INVALID_UNWIND_TARGET
        }
        if handler != 0 {
            if establisher_frame == target_frame {
                flags |= EXCEPTION_TARGET_UNWIND;
            }
            record.flags = flags;
            context_set_register(&mut context, 0, return_value);
            let original = if original_context.is_null() {
                &mut context as *mut NativeExceptionContext
            } else {
                original_context
            };
            let mut dispatcher_context = NativeDispatcherContext {
                control_pc,
                image_base,
                function_entry,
                establisher_frame,
                target_ip,
                context_record: &mut context,
                language_handler: handler,
                handler_data,
                history_table: std::ptr::null_mut(),
                scope_index: 0,
            };
            let handler: extern "win64" fn(
                *mut NativeExceptionRecord,
                u64,
                *mut NativeExceptionContext,
                *mut NativeDispatcherContext,
            ) -> u32 = unsafe { std::mem::transmute(handler as usize) };
            handler(record, establisher_frame, original, &mut dispatcher_context);
            flags &= !(EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND);
        }
        if establisher_frame == target_frame {
            reached_target = true;
            break;
        }
        let next_stack = context_register(&previous, 4).unwrap_or(0);
        if next_stack <= stack_pointer {
            break;
        }
        context = previous;
    }
    record.flags = flags;
    if !reached_target {
        native_write_to_handle(
            STD_HANDLE_BASE + 2,
            format!(
                "winrun: unwind to frame 0x{target_frame:x} did not reach its target (exception 0x{:08x})\r\n",
                record.code
            )
            .as_bytes(),
        );
        native_exit_process(record.code);
    }
    context_set_register(&mut context, 0, return_value);
    if record.code != STATUS_UNWIND_CONSOLIDATE {
        context_set_register(&mut context, 16, target_ip);
    }
    native_rtl_restore_context(&mut context, record);
}

/// `RtlRestoreContext`: continue at `context`, first running a
/// `STATUS_UNWIND_CONSOLIDATE` record's callback for the resume address.
pub(super) extern "win64" fn native_rtl_restore_context(
    context: *mut NativeExceptionContext,
    record: *mut NativeExceptionRecord,
) -> ! {
    let context = unsafe { &mut *context };
    if !record.is_null() && unsafe { (*record).code } == STATUS_UNWIND_CONSOLIDATE {
        let callback: extern "win64" fn(*mut NativeExceptionRecord) -> u64 =
            unsafe { std::mem::transmute((*record).information[0] as usize) };
        BOUNDARY_CONTEXTS.with(|contexts| contexts.borrow_mut().push(*context));
        let resume = callback(record);
        BOUNDARY_CONTEXTS.with(|contexts| contexts.borrow_mut().pop());
        context_set_register(context, 16, resume);
    }
    unsafe { winrun_native_rtl_restore_context(context.bytes.as_mut_ptr()) }
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
    let mut context = NativeExceptionContext::software_exception();
    if dispatch_exception(record, &mut context) {
        0
    } else {
        native_exit_process(record.code)
    }
}

pub(super) extern "win64" fn native_rtl_dispatch_exception(
    record: *mut NativeExceptionRecord,
    context: *mut NativeExceptionContext,
) -> u8 {
    if record.is_null() || context.is_null() {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let record = unsafe { &mut *record };
    if record.parameter_count > 15 {
        native_set_last_error(87);
        return 0;
    }
    dispatch_exception(record, unsafe { &mut *context }) as u8
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

/// `RtlAddGrowableFunctionTable(handle, table, count, maximum, base, end)`:
/// a sorted table the caller fills in place and extends with
/// `RtlGrowFunctionTable`; lookups see its first `count` entries. JITs
/// (V8, CoreCLR) register generated code this way. The table address
/// doubles as the handle.
pub(super) extern "win64" fn native_rtl_add_growable_function_table(
    handle: *mut u64,
    function_table: *mut NativeRuntimeFunction,
    entry_count: u32,
    maximum_entry_count: u32,
    range_base: u64,
    range_end: u64,
) -> u32 {
    const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
    if handle.is_null()
        || function_table.is_null()
        || entry_count > maximum_entry_count
        || range_base >= range_end
    {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(process) = process_ctx() else {
        return STATUS_INVALID_PARAMETER;
    };
    let table = function_table as u64;
    let mut tables = process.dynamic_function_tables.lock().unwrap();
    if tables.iter().any(|registered| registered.table == table) {
        return STATUS_INVALID_PARAMETER;
    }
    tables.push(NativeDynamicFunctionTable {
        table,
        entry_count,
        base: range_base,
    });
    unsafe { handle.write(table) };
    0 // STATUS_SUCCESS
}

/// `RtlGrowFunctionTable(handle, count)`: more of the table is valid.
pub(super) extern "win64" fn native_rtl_grow_function_table(handle: u64, entry_count: u32) {
    if let Some(process) = process_ctx() {
        if let Some(table) = process
            .dynamic_function_tables
            .lock()
            .unwrap()
            .iter_mut()
            .find(|registered| registered.table == handle)
        {
            table.entry_count = entry_count;
        }
    }
}

pub(super) extern "win64" fn native_rtl_delete_growable_function_table(handle: u64) {
    native_rtl_delete_function_table(handle as *mut NativeRuntimeFunction);
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
    context_pointers: *mut c_void,
) -> u64 {
    if context_record.is_null() || handler_type > 2 {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    if !handler_data.is_null() {
        unsafe { handler_data.write(std::ptr::null_mut()) };
    }
    clear_context_pointers(context_pointers);
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
    let mut epilogue_context = context;
    let mut epilogue_pointers = [0u64; 32];
    if simulate_epilogue(
        image_base,
        function,
        control_pc,
        &mut epilogue_context,
        &mut epilogue_pointers,
    ) {
        unsafe { context_record.write_unaligned(epilogue_context) };
        if !establisher_frame.is_null() {
            unsafe { establisher_frame.write(original_rsp) };
        }
        if !context_pointers.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    epilogue_pointers.as_ptr(),
                    context_pointers.cast::<u64>(),
                    epilogue_pointers.len(),
                );
            }
        }
        return 0;
    }
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
                set_context_pointer(context_pointers, 16 + usize::from(info), rsp);
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
                set_context_pointer(context_pointers, 16 + usize::from(info), address);
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
                set_context_pointer(context_pointers, usize::from(info), address);
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

fn clear_context_pointers(context_pointers: *mut c_void) {
    if !context_pointers.is_null() {
        unsafe {
            std::ptr::write_bytes(context_pointers.cast::<u64>(), 0, 32);
        }
    }
}

fn set_context_pointer(context_pointers: *mut c_void, slot: usize, address: u64) {
    if !context_pointers.is_null() {
        unsafe {
            context_pointers
                .cast::<u64>()
                .add(slot)
                .write_unaligned(address);
        }
    }
}

fn simulate_epilogue(
    image_base: u64,
    function: NativeRuntimeFunction,
    control_pc: u64,
    context: &mut NativeExceptionContext,
    context_pointers: &mut [u64; 32],
) -> bool {
    let Some(control_rva) = control_pc.checked_sub(image_base) else {
        return false;
    };
    if control_rva < u64::from(function.begin_address)
        || control_rva >= u64::from(function.end_address)
    {
        return false;
    }
    let available = (u64::from(function.end_address) - control_rva).min(64) as usize;
    let bytes = unsafe { std::slice::from_raw_parts(control_pc as *const u8, available) };
    let mut cursor = 0usize;
    let mut can_adjust_stack = true;
    loop {
        let remaining = &bytes[cursor..];
        if remaining.first() == Some(&0xc3) || remaining.starts_with(&[0xf3, 0xc3]) {
            if !simulate_epilogue_return(context, 0) {
                return false;
            }
            return true;
        }
        if remaining.starts_with(&[0xc2]) && remaining.len() >= 3 {
            let extra = u16::from_le_bytes([remaining[1], remaining[2]]) as u64;
            return simulate_epilogue_return(context, extra);
        }
        if can_adjust_stack {
            if let Some((instruction_len, adjustment)) = decode_epilogue_stack_adjust(remaining) {
                let Some(rsp) =
                    context_register(context, 4).and_then(|rsp| rsp.checked_add(adjustment))
                else {
                    return false;
                };
                context_set_register(context, 4, rsp);
                cursor += instruction_len;
                can_adjust_stack = false;
                continue;
            }
            if let Some((instruction_len, base_register, displacement)) =
                decode_epilogue_lea(remaining)
            {
                let Some(base) = context_register(context, base_register) else {
                    return false;
                };
                let rsp = if displacement >= 0 {
                    base.checked_add(displacement as u64)
                } else {
                    base.checked_sub(displacement.unsigned_abs())
                };
                let Some(rsp) = rsp else {
                    return false;
                };
                context_set_register(context, 4, rsp);
                cursor += instruction_len;
                can_adjust_stack = false;
                continue;
            }
        }
        if let Some((instruction_len, register)) = decode_epilogue_pop(remaining) {
            let Some(rsp) = context_register(context, 4) else {
                return false;
            };
            let Some(value) = stack_u64(rsp) else {
                return false;
            };
            context_set_register(context, register, value);
            context_pointers[16 + usize::from(register)] = rsp;
            let Some(next_rsp) = rsp.checked_add(8) else {
                return false;
            };
            context_set_register(context, 4, next_rsp);
            cursor += instruction_len;
            can_adjust_stack = false;
            continue;
        }
        let Some(instruction_pc) = control_pc.checked_add(cursor as u64) else {
            return false;
        };
        if let Some(target) =
            decode_epilogue_jump(remaining, instruction_pc, image_base, function, context)
        {
            context_set_register(context, 16, target);
            return true;
        }
        return false;
    }
}

fn decode_epilogue_stack_adjust(bytes: &[u8]) -> Option<(usize, u64)> {
    if bytes.starts_with(&[0x48, 0x83, 0xc4]) && bytes.len() >= 4 {
        let adjustment = i8::from_le_bytes([bytes[3]]);
        return (adjustment >= 0).then_some((4, adjustment as u64));
    }
    if bytes.starts_with(&[0x48, 0x81, 0xc4]) && bytes.len() >= 7 {
        let adjustment = i32::from_le_bytes(bytes[3..7].try_into().ok()?);
        return (adjustment >= 0).then_some((7, adjustment as u64));
    }
    None
}

fn decode_epilogue_lea(bytes: &[u8]) -> Option<(usize, u8, i64)> {
    let rex = *bytes.first()?;
    if !(0x48..=0x4f).contains(&rex) || bytes.get(1) != Some(&0x8d) {
        return None;
    }
    let modrm = *bytes.get(2)?;
    let mode = modrm >> 6;
    let destination = ((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3);
    if mode == 0 || destination != 4 {
        return None;
    }
    let rm = modrm & 7;
    let mut cursor = 3;
    let base = if rm == 4 {
        let sib = *bytes.get(cursor)?;
        cursor += 1;
        if (sib >> 3) & 7 != 4 || (sib >> 6) != 0 || rex & 2 != 0 {
            return None;
        }
        (sib & 7) | ((rex & 1) << 3)
    } else {
        rm | ((rex & 1) << 3)
    };
    if !is_nonvolatile_register(base) {
        return None;
    }
    let displacement = match mode {
        1 => {
            let value = i8::from_le_bytes([*bytes.get(cursor)?]) as i64;
            cursor += 1;
            value
        }
        2 => {
            let value = i32::from_le_bytes(bytes.get(cursor..cursor + 4)?.try_into().ok()?) as i64;
            cursor += 4;
            value
        }
        _ => return None,
    };
    Some((cursor, base, displacement))
}

fn decode_epilogue_pop(bytes: &[u8]) -> Option<(usize, u8)> {
    let (instruction_len, opcode) = if bytes.first() == Some(&0x41) {
        (2, *bytes.get(1)?)
    } else {
        (1, *bytes.first()?)
    };
    let register = if instruction_len == 2 {
        match opcode {
            0x5c => 12,
            0x5d => 13,
            0x5e => 14,
            0x5f => 15,
            _ => return None,
        }
    } else {
        match opcode {
            0x5b => 3,
            0x5d => 5,
            0x5e => 6,
            0x5f => 7,
            _ => return None,
        }
    };
    Some((instruction_len, register))
}

fn decode_epilogue_jump(
    bytes: &[u8],
    instruction_pc: u64,
    image_base: u64,
    function: NativeRuntimeFunction,
    context: &NativeExceptionContext,
) -> Option<u64> {
    let target = if bytes.first() == Some(&0xeb) && bytes.len() >= 2 {
        let displacement = i8::from_le_bytes([bytes[1]]) as i64;
        instruction_pc
            .checked_add(2)?
            .checked_add_signed(displacement)?
    } else if bytes.first() == Some(&0xe9) && bytes.len() >= 5 {
        let displacement = i32::from_le_bytes(bytes[1..5].try_into().ok()?) as i64;
        instruction_pc
            .checked_add(5)?
            .checked_add_signed(displacement)?
    } else if bytes.len() >= 3 && (0x48..=0x4f).contains(&bytes[0]) && bytes[1] == 0xff {
        let rex = bytes[0];
        let modrm = bytes[2];
        if (modrm >> 3) & 7 != 4 || rex & 6 != 0 {
            return None;
        }
        if modrm >> 6 == 3 {
            let register = (modrm & 7) | ((rex & 1) << 3);
            context_register(context, register)?
        } else {
            return None;
        }
    } else if bytes.len() >= 6 && bytes[0] == 0xff && bytes[1] == 0x25
    // jmp qword ptr [rip + disp32]
    {
        let displacement = i32::from_le_bytes(bytes[2..6].try_into().ok()?) as i64;
        let pointer_address = instruction_pc
            .checked_add(6)?
            .checked_add_signed(displacement)?;
        stack_u64(pointer_address)?
    } else {
        return None;
    };

    let function_start = image_base.checked_add(u64::from(function.begin_address))?;
    let function_end = image_base.checked_add(u64::from(function.end_address))?;
    if (function_start..function_end).contains(&target) {
        return None;
    }
    Some(target)
}

fn simulate_epilogue_return(context: &mut NativeExceptionContext, extra_stack_bytes: u64) -> bool {
    let Some(rsp) = context_register(context, 4) else {
        return false;
    };
    let Some(return_address) = stack_u64(rsp) else {
        return false;
    };
    let Some(next_rsp) = rsp
        .checked_add(8)
        .and_then(|rsp| rsp.checked_add(extra_stack_bytes))
    else {
        return false;
    };
    context_set_register(context, 16, return_address);
    context_set_register(context, 4, next_rsp);
    true
}

pub(super) fn context_register(context: &NativeExceptionContext, register: u8) -> Option<u64> {
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
        16 => 248, // RIP
        _ => return None,
    };
    Some(u64::from_le_bytes(
        context.bytes[offset..offset + 8].try_into().ok()?,
    ))
}

pub(super) fn context_set_register(context: &mut NativeExceptionContext, register: u8, value: u64) {
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

#[cfg(test)]
mod continue_handler_tests {
    use super::*;
    static CALLS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    extern "win64" fn first(_: *mut NativeExceptionPointers) -> i32 {
        CALLS.lock().unwrap().push(1);
        0
    }
    extern "win64" fn last(_: *mut NativeExceptionPointers) -> i32 {
        CALLS.lock().unwrap().push(2);
        -1
    }
    #[test]
    fn continuation_handlers_run_in_order_and_can_be_removed() {
        let previous = THREAD_NATIVE_PROCESS
            .with(|slot| slot.replace(Some(super::super::context::new_test_process())));
        assert_eq!(native_add_vectored_continue_handler(0, 0), 0);
        assert_eq!(native_get_last_error(), 87);
        let tail = native_add_vectored_continue_handler(0, last as *const () as u64);
        let head = native_add_vectored_continue_handler(1, first as *const () as u64);
        let mut pointers = NativeExceptionPointers {
            record: std::ptr::null_mut(),
            context: std::ptr::null_mut(),
        };
        dispatch_continue_handlers(&mut pointers);
        assert_eq!(*CALLS.lock().unwrap(), [1, 2]);
        assert_eq!(native_remove_vectored_continue_handler(head), 1);
        assert_eq!(native_remove_vectored_continue_handler(head), 0);
        assert_eq!(native_remove_vectored_continue_handler(tail), 1);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(previous));
    }
}
