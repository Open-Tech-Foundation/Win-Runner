//! Linux host setup for Windows thread environment blocks and TLS.

use super::*;

pub(super) fn put64(dst: &mut [u8], off: usize, value: u64) {
    dst[off..off + 8].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn set_teb_stack_bounds(teb: &mut [u8; TEB_SIZE]) {
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
pub(super) fn install_thread_teb(teb: &mut [u8; TEB_SIZE]) -> bool {
    put64(teb, 0x40, native_get_current_process_id() as u64);
    put64(teb, 0x48, native_get_current_thread_id() as u64);
    if let Some(process) = process_ctx() {
        put64(teb, 0x800 + 0x20, &process.parameters as *const NativeProcessParameters as u64);
    }
    set_teb_stack_bounds(teb);
    let base = teb.as_ptr() as u64;
    if !unsafe { set_gs(base) } {
        return false;
    }
    THREAD_TEB_BASE.set(base);
    true
}
pub(super) fn setup_tls(mapping: &Mapping, img: &PeImage) -> Result<NativeTls, String> {
    let mut out = NativeTls::new(img.image_base);
    if let Some(tls) = &img.tls {
        let data = tls_template_from_mapping(mapping, tls)
            .ok_or_else(|| "native TLS template lies outside image".to_string())?;
        if !out.set_static_tls(0, data) {
            return Err("native TLS index is outside the supported slot table".to_string());
        }
        let off = tls.index_rva as usize;
        if off.checked_add(4).is_none_or(|end| end > mapping.len) {
            return Err("native TLS index lies outside image".to_string());
        }
        unsafe { (mapping.ptr.add(off) as *mut u32).write_unaligned(0) };
    }
    Ok(out)
}

pub(super) fn tls_template_from_mapping(
    mapping: &Mapping,
    tls: &crate::pe::TlsDir,
) -> Option<Vec<u8>> {
    let start = tls.raw_data_rva as usize;
    let end = start.checked_add(tls.raw_data.len())?;
    if end > mapping.len {
        return None;
    }
    let mut data =
        unsafe { std::slice::from_raw_parts(mapping.ptr.add(start), end - start) }.to_vec();
    data.resize(data.len().checked_add(tls.zero_fill as usize)?, 0);
    Some(data)
}

pub(super) fn install_module_static_tls(
    process: &NativeProcessContext,
    index: u32,
    template: &[u8],
) -> bool {
    let Ok(mut tls_template_guard) = process.tls_template.lock() else {
        return false;
    };
    let Some(tls_template) = tls_template_guard.as_mut() else {
        return false;
    };
    if !tls_template.set_static_tls(index, template.to_vec()) {
        return false;
    }
    let Ok(mut tls_blocks) = process.tls_blocks.lock() else {
        tls_template.clear_static_tls(index);
        return false;
    };
    let blocks: Vec<_> = tls_blocks
        .iter()
        .filter_map(|(id, weak)| match weak.upgrade() {
            Some(block) => Some((*id, block)),
            None => None,
        })
        .collect();
    tls_blocks.retain(|_, weak| weak.strong_count() != 0);
    drop(tls_blocks);
    drop(tls_template_guard);
    for (_, block) in blocks {
        let Ok(mut block) = block.lock() else {
            return false;
        };
        if !block.set_static_tls(index, template.to_vec()) {
            return false;
        }
    }
    true
}

pub(super) fn clear_module_static_tls(process: &NativeProcessContext, index: u32) {
    // Thread startup can hold a TLS block while reading the process template.
    // Snapshot block references under the global locks, then release them
    // before locking any block to keep the lock order acyclic.
    let blocks = {
        let Ok(mut tls_template) = process.tls_template.lock() else {
            return;
        };
        if let Some(tls_template) = tls_template.as_mut() {
            tls_template.clear_static_tls(index);
        }
        let Ok(mut tls_blocks) = process.tls_blocks.lock() else {
            return;
        };
        let blocks = tls_blocks
            .values()
            .filter_map(std::sync::Weak::upgrade)
            .collect::<Vec<_>>();
        tls_blocks.retain(|_, weak| weak.strong_count() != 0);
        blocks
    };
    for block in blocks {
        if let Ok(mut block) = block.lock() {
            block.clear_static_tls(index);
        }
    }
}
pub(super) unsafe fn set_gs(base: u64) -> bool {
    let result: u64;
    core::arch::asm!("syscall", inlateout("rax") 158u64 => result, in("rdi") 0x1001u64, in("rsi") base, lateout("rcx") _, lateout("r11") _);
    result == 0
}

pub(super) extern "win64" fn native_get_last_error() -> u32 {
    let base = THREAD_TEB_BASE.get();
    if base != 0 {
        unsafe { ((base + 0x68) as *const u32).read_unaligned() }
    } else {
        THREAD_LAST_ERROR.get()
    }
}

pub(super) extern "win64" fn native_set_last_error(error: u32) {
    THREAD_LAST_ERROR.set(error);
    let base = THREAD_TEB_BASE.get();
    if base != 0 {
        unsafe { ((base + 0x68) as *mut u32).write_unaligned(error) };
    }
}

pub(super) extern "win64" fn native_set_thread_stack_guarantee(size: *mut u32) -> i32 {
    (!size.is_null()) as i32
}

pub(super) extern "win64" fn native_get_current_thread_stack_limits(
    low: *mut usize,
    high: *mut usize,
) {
    let base = THREAD_TEB_BASE.get();
    let (limit, top) = if base != 0 {
        unsafe {
            (
                ((base + 0x10) as *const usize).read_unaligned(),
                ((base + 0x08) as *const usize).read_unaligned(),
            )
        }
    } else {
        // Also support host-side calls without an installed Windows TEB.
        let mut teb = [0u8; TEB_SIZE];
        set_teb_stack_bounds(&mut teb);
        (
            usize::from_le_bytes(teb[0x10..0x18].try_into().unwrap()),
            usize::from_le_bytes(teb[0x08..0x10].try_into().unwrap()),
        )
    };
    unsafe {
        low.write(limit);
        high.write(top);
    }
}

/// `TlsAlloc`: the lowest free index, 0-1087 as on Windows. Its value is
/// empty on every thread (slots are cleared when freed).
pub(super) extern "win64" fn native_tls_alloc() -> u32 {
    let Some(process) = process_ctx() else {
        return u32::MAX;
    };
    let Ok(mut slots) = process.dynamic_tls.lock() else {
        return u32::MAX;
    };
    let Some(index) = slots.active.iter().position(|active| !active) else {
        native_set_last_error(8);
        return u32::MAX; // TLS_OUT_OF_INDEXES
    };
    slots.active[index] = true;
    slots.reserved[index] = false;
    slots.generation[index] = slots.generation[index].wrapping_add(1);
    index as u32
}
pub(super) extern "win64" fn native_tls_free(index: u32) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    {
        let Ok(slots) = process.dynamic_tls.lock() else {
            return 0;
        };
        let reserved = slots.reserved.get(index as usize).copied().unwrap_or(false)
            || (index == 0 && slots.reserved_static);
        if !slots.active.get(index as usize).copied().unwrap_or(false) || reserved {
            native_set_last_error(87);
            return 0;
        }
    }
    // Like Windows, clear the value on every thread before the index can be
    // handed out again.
    clear_tls_index(&process, index as usize);
    let Ok(mut slots) = process.dynamic_tls.lock() else {
        return 0;
    };
    slots.active[index as usize] = false;
    slots.generation[index as usize] = slots.generation[index as usize].wrapping_add(1);
    1
}

/// The TEB cell of `TlsAlloc` index `index` for the thread whose TEB is at
/// `teb`: `TlsSlots[index]`, or `TlsExpansionSlots[index - 64]`.
fn teb_tls_cell(teb: u64, index: usize) -> Option<*mut u64> {
    if index < 64 {
        return Some((teb + (TEB_TLS_SLOTS + index * 8) as u64) as *mut u64);
    }
    if index >= TLS_INDEXES {
        return None;
    }
    let expansion =
        unsafe { ((teb + TEB_TLS_EXPANSION_SLOTS as u64) as *const u64).read_unaligned() };
    (expansion != 0).then(|| (expansion + ((index - 64) * 8) as u64) as *mut u64)
}

fn clear_tls_index(process: &NativeProcessContext, index: usize) {
    let blocks = process.tls_blocks.lock().map_or_else(
        |_| Vec::new(),
        |blocks| blocks.values().filter_map(std::sync::Weak::upgrade).collect(),
    );
    for block in blocks {
        if let Ok(mut block) = block.lock() {
            let teb = block.teb.as_mut_ptr() as u64;
            if let Some(cell) = teb_tls_cell(teb, index) {
                unsafe { cell.write_unaligned(0) };
            }
        }
    }
}

pub(super) fn reserve_module_tls_slot(process: &NativeProcessContext) -> Option<u32> {
    let mut slots = process.dynamic_tls.lock().ok()?;
    // Module static TLS indexes the 64-entry ThreadLocalStoragePointer array.
    let index = slots.active[..64].iter().position(|active| !active)?;
    slots.active[index] = true;
    slots.reserved[index] = true;
    slots.generation[index] = slots.generation[index].wrapping_add(1);
    Some(index as u32)
}

pub(super) fn release_module_tls_slot(process: &NativeProcessContext, index: u32) {
    if let Ok(mut slots) = process.dynamic_tls.lock() {
        let index = index as usize;
        if index < slots.active.len() && slots.reserved[index] {
            slots.active[index] = false;
            slots.reserved[index] = false;
            slots.generation[index] = slots.generation[index].wrapping_add(1);
        }
    }
}

/// Invoke loader callbacks whose RVAs have already been validated by the PE parser.
pub(super) fn invoke_tls_callbacks(base: u64, callbacks: &[u32], reason: u32) {
    for &callback_rva in callbacks {
        let Some(address) = base.checked_add(u64::from(callback_rva)) else {
            continue;
        };
        // SAFETY: PE parsing verifies callback RVAs point into executable image sections.
        if let Err(code) = unsafe {
            super::exceptions::invoke_guest_with_arguments(address, [base, reason as u64, 0])
        } {
            native_exit_process(code);
        }
    }
}

/// Send DLL/TLS thread notifications from a stable module snapshot. Guest code
/// runs only after releasing the module table lock, so callbacks can load DLLs.
pub(super) fn notify_guest_thread_modules(process: &NativeProcessContext, attach: bool) {
    let mut notifications = {
        let Ok(modules) = process.loaded_modules.lock() else {
            return;
        };
        let mut notifications: Vec<_> = modules
            .values()
            .map(|module| {
                (
                    module.load_order,
                    module.base,
                    module.entry_point,
                    module.tls_callbacks.clone(),
                )
            })
            .collect();
        notifications.sort_by_key(|module| module.0);
        notifications
    };
    if !attach {
        notifications.reverse();
    }
    let reason = if attach { 2 } else { 3 };
    for (_, base, entry_point, callbacks) in notifications {
        if attach {
            invoke_tls_callbacks(base, &callbacks, reason);
            if let Some(entry_point) = entry_point {
                // SAFETY: DLL entry points were validated by the PE loader.
                if let Err(code) = unsafe {
                    super::exceptions::invoke_guest_with_arguments(
                        entry_point,
                        [base, reason as u64, 0],
                    )
                } {
                    native_exit_process(code);
                }
            }
        } else {
            if let Some(entry_point) = entry_point {
                // SAFETY: DLL entry points were validated by the PE loader.
                if let Err(code) = unsafe {
                    super::exceptions::invoke_guest_with_arguments(
                        entry_point,
                        [base, reason as u64, 0],
                    )
                } {
                    native_exit_process(code);
                }
            }
            invoke_tls_callbacks(base, &callbacks, reason);
        }
    }
}

pub(super) fn initialize_module_static_tls(
    process: &NativeProcessContext,
    tls: &mut NativeTls,
) -> bool {
    let Ok(modules) = process.loaded_modules.lock() else {
        return false;
    };
    let mut templates: Vec<_> = modules
        .values()
        .filter_map(|module| {
            Some((
                module.load_order,
                module.static_tls_index?,
                module.static_tls_template.as_ref()?.clone(),
            ))
        })
        .collect();
    templates.sort_by_key(|module| module.0);
    drop(modules);
    templates
        .into_iter()
        .all(|(_, index, template)| tls.set_static_tls(index, template))
}
pub(super) extern "win64" fn native_tls_get_value(index: u32) -> u64 {
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
    let teb = THREAD_TEB_BASE.get();
    let value = if teb != 0 {
        teb_tls_cell(teb, index as usize).map_or(0, |cell| unsafe { cell.read_unaligned() })
    } else {
        let generation = slots.generation[index as usize];
        THREAD_TLS_VALUES.with(|values| match values.borrow().get(index as usize) {
            Some(&(slot_generation, value)) if slot_generation == generation => value,
            _ => 0,
        })
    };
    native_set_last_error(0);
    value
}
pub(super) extern "win64" fn native_tls_set_value(index: u32, value: u64) -> i32 {
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
    let teb = THREAD_TEB_BASE.get();
    if teb != 0 {
        let Some(cell) = teb_tls_cell(teb, index as usize) else {
            native_set_last_error(87);
            return 0;
        };
        unsafe { cell.write_unaligned(value) };
    } else {
        let generation = slots.generation[index as usize];
        THREAD_TLS_VALUES.with(|values| {
            let mut values = values.borrow_mut();
            if values.len() <= index as usize {
                values.resize(index as usize + 1, (0, 0));
            }
            values[index as usize] = (generation, value);
        });
    }
    native_set_last_error(0);
    1
}

/// FLS_MAXIMUM_AVAILABLE on current Windows.
const FLS_MAXIMUM_AVAILABLE: usize = 4080;
const FLS_OUT_OF_INDEXES: u32 = u32::MAX;

/// `FlsAlloc(callback)`: a fresh index whose value is empty on every thread.
/// Index 0 is never handed out, so a zeroed index variable is never valid.
pub(super) extern "win64" fn native_fls_alloc(callback: u64) -> u32 {
    let Some(process) = process_ctx() else {
        return FLS_OUT_OF_INDEXES;
    };
    let Ok(mut slots) = process.fls.lock() else {
        return FLS_OUT_OF_INDEXES;
    };
    if slots.callbacks.is_empty() {
        slots.callbacks.push(None);
        slots.generation.push(0);
    }
    let index = match slots.callbacks.iter().skip(1).position(Option::is_none) {
        Some(free) => free + 1,
        None if slots.callbacks.len() < FLS_MAXIMUM_AVAILABLE => {
            slots.callbacks.push(None);
            slots.generation.push(0);
            slots.callbacks.len() - 1
        }
        None => {
            native_set_last_error(259); // ERROR_NO_MORE_ITEMS
            return FLS_OUT_OF_INDEXES;
        }
    };
    slots.callbacks[index] = Some(callback);
    slots.generation[index] = slots.generation[index].wrapping_add(1);
    index as u32
}

/// The allocated index's generation and callback, or `None` (with
/// `ERROR_INVALID_PARAMETER`) for an index that is not allocated.
fn fls_slot(process: &NativeProcessContext, index: u32) -> Option<(u64, u64)> {
    let slots = process.fls.lock().ok()?;
    match slots.callbacks.get(index as usize) {
        Some(Some(callback)) if index != 0 => Some((slots.generation[index as usize], *callback)),
        _ => {
            native_set_last_error(87);
            None
        }
    }
}

/// Take this thread's live value for `index`, leaving it empty.
fn take_thread_fls_value(index: usize, generation: u64) -> u64 {
    THREAD_FLS_VALUES.with(|values| {
        let mut values = values.borrow_mut();
        match values.get_mut(index) {
            Some(slot) if slot.0 == generation => std::mem::take(slot).1,
            _ => 0,
        }
    })
}

fn call_fls_callback(callback: u64, value: u64) {
    if callback != 0 && value != 0 {
        // SAFETY: FlsAlloc's caller supplied this guest PFLS_CALLBACK_FUNCTION.
        let callback: unsafe extern "win64" fn(u64) = unsafe { std::mem::transmute(callback as usize) };
        unsafe { callback(value) };
    }
}

/// `FlsFree(index)`: runs the index's callback for the calling thread's
/// value, then releases the index. Other threads' values are dropped
/// without a callback.
pub(super) extern "win64" fn native_fls_free(index: u32) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Some((generation, callback)) = fls_slot(&process, index) else {
        return 0;
    };
    call_fls_callback(callback, take_thread_fls_value(index as usize, generation));
    let Ok(mut slots) = process.fls.lock() else {
        return 0;
    };
    slots.callbacks[index as usize] = None;
    slots.generation[index as usize] = slots.generation[index as usize].wrapping_add(1);
    1
}

pub(super) extern "win64" fn native_fls_get_value(index: u32) -> u64 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Some((generation, _)) = fls_slot(&process, index) else {
        return 0;
    };
    let value = THREAD_FLS_VALUES.with(|values| match values.borrow().get(index as usize) {
        Some(&(slot_generation, value)) if slot_generation == generation => value,
        _ => 0,
    });
    native_set_last_error(0);
    value
}

pub(super) extern "win64" fn native_fls_set_value(index: u32, value: u64) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Some((generation, _)) = fls_slot(&process, index) else {
        return 0;
    };
    THREAD_FLS_VALUES.with(|values| {
        let mut values = values.borrow_mut();
        if values.len() <= index as usize {
            values.resize(index as usize + 1, (0, 0));
        }
        values[index as usize] = (generation, value);
    });
    1
}

/// Run the FLS callbacks for the exiting thread's values, as Windows does
/// when a thread ends.
pub(super) fn run_thread_fls_callbacks(process: &NativeProcessContext) {
    let live: Vec<(usize, u64, u64)> = {
        let Ok(slots) = process.fls.lock() else {
            return;
        };
        slots
            .callbacks
            .iter()
            .enumerate()
            .filter_map(|(index, callback)| Some((index, slots.generation[index], (*callback)?)))
            .collect()
    };
    for (index, generation, callback) in live {
        call_fls_callback(callback, take_thread_fls_value(index, generation));
    }
}

#[cfg(test)]
mod tls_callback_tests {
    use super::{invoke_tls_callbacks, notify_guest_thread_modules};
    use crate::native::linux_x86_64::state::{NativeLoadedModule, NativeTls};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    static CALLBACK_REASON: AtomicU32 = AtomicU32::new(0);
    static CALLBACK_BASE: AtomicU32 = AtomicU32::new(0);
    static THREAD_EVENTS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    unsafe extern "win64" fn record_callback(base: u64, reason: u32, _reserved: u64) {
        CALLBACK_BASE.store(base as u32, Ordering::SeqCst);
        CALLBACK_REASON.store(reason, Ordering::SeqCst);
    }

    unsafe extern "win64" fn record_tls_thread_event(_base: u64, reason: u32, _reserved: u64) {
        THREAD_EVENTS.lock().unwrap().push(10 + reason);
    }

    unsafe extern "win64" fn record_dll_thread_event(
        _base: u64,
        reason: u32,
        _reserved: u64,
    ) -> i32 {
        THREAD_EVENTS.lock().unwrap().push(20 + reason);
        1
    }

    #[test]
    fn invokes_tls_callbacks_with_image_base_and_reason() {
        let callback = record_callback as *const () as usize as u64;
        CALLBACK_BASE.store(0, Ordering::SeqCst);
        CALLBACK_REASON.store(0, Ordering::SeqCst);

        invoke_tls_callbacks(callback, &[0], 1);

        assert_eq!(CALLBACK_BASE.load(Ordering::SeqCst), callback as u32);
        assert_eq!(CALLBACK_REASON.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sends_dll_thread_notifications_in_loader_order() {
        let process = &*super::TEST_PROCESS;
        let base = record_tls_thread_event as *const () as usize as u64;
        let module = NativeLoadedModule {
            path: r"C:\bin\notify.dll".to_string(),
            name: "notify.dll".to_string(),
            base,
            size_of_image: 0x1000,
            exports: Vec::new(),
            entry_point: Some(record_dll_thread_event as *const () as usize as u64),
            tls_callbacks: vec![0],
            static_tls_index: None,
            static_tls_template: None,
            load_order: 1,
            load_references: 0,
            dependencies: Vec::new(),
            mapping: None,
            initialized: true,
        };
        THREAD_EVENTS.lock().unwrap().clear();
        process.loaded_modules.lock().unwrap().insert(base, module);

        notify_guest_thread_modules(process, true);
        notify_guest_thread_modules(process, false);

        assert_eq!(*THREAD_EVENTS.lock().unwrap(), vec![12, 22, 23, 13]);
        process.loaded_modules.lock().unwrap().remove(&base);
    }

    #[test]
    fn clones_per_thread_static_tls_templates_into_independent_slots() {
        let mut template = NativeTls::new(0x1400_0000);
        assert!(template.set_static_tls(0, vec![1, 2, 3, 4]));
        assert!(template.set_static_tls(3, vec![5, 6, 0, 0]));
        let thread_tls = template.clone_for_thread();

        assert_ne!(template.slots[0], thread_tls.slots[0]);
        assert_ne!(template.slots[3], thread_tls.slots[3]);
        unsafe {
            assert_eq!(
                std::slice::from_raw_parts(thread_tls.slots[0] as *const u8, 4),
                [1, 2, 3, 4]
            );
            assert_eq!(
                std::slice::from_raw_parts(thread_tls.slots[3] as *const u8, 4),
                [5, 6, 0, 0]
            );
            (thread_tls.slots[3] as *mut u8).write(9);
            assert_eq!(
                std::slice::from_raw_parts(template.slots[3] as *const u8, 4),
                [5, 6, 0, 0]
            );
        }
    }
}

#[cfg(test)]
mod fls_tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static FREED_VALUES: Mutex<Vec<u64>> = Mutex::new(Vec::new());

    extern "win64" fn record_freed_value(value: u64) {
        FREED_VALUES.lock().unwrap().push(value);
    }

    #[test]
    fn fls_indices_are_distinct_and_values_are_per_thread() {
        let first = native_fls_alloc(0);
        let second = native_fls_alloc(0);
        assert_ne!(first, FLS_OUT_OF_INDEXES);
        assert_ne!(first, 0);
        assert_ne!(first, second);
        assert_eq!(native_fls_set_value(first, 0x1111), 1);
        assert_eq!(native_fls_set_value(second, 0x2222), 1);
        assert_eq!(native_fls_get_value(first), 0x1111);
        assert_eq!(native_fls_get_value(second), 0x2222);
        // Another thread starts with empty values for the same indices.
        let other = AtomicU64::new(u64::MAX);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                other.store(native_fls_get_value(first), Ordering::Relaxed);
                native_fls_set_value(first, 0x3333);
            });
        });
        assert_eq!(other.load(Ordering::Relaxed), 0);
        assert_eq!(native_fls_get_value(first), 0x1111);
        assert_eq!(native_fls_free(first), 1);
        assert_eq!(native_fls_free(second), 1);
        assert_eq!(native_fls_get_value(first), 0, "a freed index is invalid");
        assert_eq!(native_fls_set_value(0, 1), 0, "index 0 is never allocated");
    }

    #[test]
    fn fls_callbacks_run_on_free_and_thread_exit() {
        let callback = record_freed_value as *const () as usize as u64;
        let index = native_fls_alloc(callback);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                native_fls_set_value(index, 0xbeef);
                run_thread_fls_callbacks(&super::super::TEST_PROCESS);
                // The value was consumed; a second exit pass does nothing.
                run_thread_fls_callbacks(&super::super::TEST_PROCESS);
            });
        });
        native_fls_set_value(index, 0xcafe);
        assert_eq!(native_fls_free(index), 1);
        let freed = FREED_VALUES.lock().unwrap().clone();
        assert_eq!(freed.iter().filter(|&&value| value == 0xbeef).count(), 1);
        assert_eq!(freed.iter().filter(|&&value| value == 0xcafe).count(), 1);
    }
}

#[cfg(test)]
mod teb_tls_tests {
    use super::*;

    fn teb_u64(tls: &NativeTls, offset: usize) -> u64 {
        u64::from_le_bytes(tls.teb[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn tls_values_live_where_programs_read_the_teb() {
        // mimalloc and others read TlsSlots (gs:0x1480) and the
        // TlsExpansionSlots array (gs:0x1780) directly.
        let mut tls = NativeTls::new(0x1400_0000);
        let teb = tls.teb.as_mut_ptr() as u64;
        assert!(TEB_SIZE > TEB_TLS_EXPANSION_SLOTS + 8);
        assert_eq!(
            teb_u64(&tls, TEB_TLS_EXPANSION_SLOTS),
            tls.tls_expansion.as_ptr() as u64
        );
        let low = teb_tls_cell(teb, 5).unwrap();
        assert_eq!(low as u64, teb + 0x1480 + 5 * 8);
        let high = teb_tls_cell(teb, 64 + 1023).unwrap();
        assert_eq!(high as u64, tls.tls_expansion.as_ptr() as u64 + 1023 * 8);
        assert!(teb_tls_cell(teb, TLS_INDEXES).is_none());

        unsafe {
            low.write_unaligned(0x1111);
            high.write_unaligned(0x2222);
        }
        assert_eq!(teb_u64(&tls, 0x1480 + 5 * 8), 0x1111);
        assert_eq!(tls.tls_expansion[1023], 0x2222);

        // A new thread starts with every value empty and its own array.
        let next = tls.clone_for_thread();
        assert_eq!(teb_u64(&next, 0x1480 + 5 * 8), 0);
        assert_eq!(next.tls_expansion[1023], 0);
        assert_eq!(
            teb_u64(&next, TEB_TLS_EXPANSION_SLOTS),
            next.tls_expansion.as_ptr() as u64
        );
        assert_eq!(teb_u64(&next, 0x30), next.teb.as_ptr() as u64); // NT_TIB.Self
    }
}

pub(super) extern "win64" fn native_rtl_get_current_peb() -> u64 {
    let teb = THREAD_TEB_BASE.get();
    if teb != 0 {
        unsafe { ((teb + 0x60) as *const u64).read_unaligned() }
    } else {
        0
    }
}

#[cfg(test)]
mod stack_limit_tests {
    use super::*;

    #[test]
    fn current_host_stack_is_inside_reported_limits() {
        let mut low = 0;
        let mut high = 0;
        native_get_current_thread_stack_limits(&mut low, &mut high);
        let marker = &low as *const usize as usize;
        assert!(low != 0 && low <= marker && marker < high);
        assert!(baseline_trampoline("GetCurrentThreadStackLimits").is_some());
    }
}
