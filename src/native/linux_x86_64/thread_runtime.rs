//! Linux host setup for Windows thread environment blocks and TLS.

use super::*;

pub(super) fn put64(dst: &mut [u8], off: usize, value: u64) {
    dst[off..off + 8].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn set_teb_stack_bounds(teb: &mut [u8; 0x1000]) {
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
pub(super) fn install_thread_teb(teb: &mut [u8; 0x1000]) -> bool {
    set_teb_stack_bounds(teb);
    let base = teb.as_ptr() as u64;
    if !unsafe { set_gs(base) } {
        return false;
    }
    THREAD_TEB_BASE.set(base);
    true
}
pub(super) fn setup_tls(mapping: &Mapping, img: &PeImage) -> Result<Option<NativeTls>, String> {
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

pub(super) extern "win64" fn native_tls_alloc() -> u32 {
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
    slots.reserved[index] = false;
    slots.generation[index] = slots.generation[index].wrapping_add(1);
    index as u32
}
pub(super) extern "win64" fn native_tls_free(index: u32) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(mut slots) = process.dynamic_tls.lock() else {
        return 0;
    };
    let reserved = slots.reserved.get(index as usize).copied().unwrap_or(false)
        || (index == 0 && slots.reserved_static);
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

pub(super) fn reserve_module_tls_slot(process: &NativeProcessContext) -> Option<u32> {
    let mut slots = process.dynamic_tls.lock().ok()?;
    let index = slots.active.iter().position(|active| !active)?;
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
        let callback: unsafe extern "win64" fn(u64, u32, u64) =
            unsafe { std::mem::transmute(address as usize) };
        unsafe { callback(base, reason, 0) };
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
                let dll_main: unsafe extern "win64" fn(u64, u32, u64) -> i32 =
                    unsafe { std::mem::transmute(entry_point as usize) };
                let _ = unsafe { dll_main(base, reason, 0) };
            }
        } else {
            if let Some(entry_point) = entry_point {
                // SAFETY: DLL entry points were validated by the PE loader.
                let dll_main: unsafe extern "win64" fn(u64, u32, u64) -> i32 =
                    unsafe { std::mem::transmute(entry_point as usize) };
                let _ = unsafe { dll_main(base, reason, 0) };
            }
            invoke_tls_callbacks(base, &callbacks, reason);
        }
    }
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
    let generation = slots.generation[index as usize];
    THREAD_TLS_VALUES.with(|values| values.borrow_mut()[index as usize] = (generation, value));
    native_set_last_error(0);
    1
}

pub(super) extern "win64" fn native_fls_alloc(_callback: u64) -> u32 {
    0
}
pub(super) extern "win64" fn native_fls_free(index: u32) -> i32 {
    if index != 0 {
        return 0;
    }
    if let Some(process) = process_ctx() {
        process.fls_value.store(0, Ordering::Release);
    }
    1
}
pub(super) extern "win64" fn native_fls_get_value(index: u32) -> u64 {
    if index == 0 {
        process_ctx()
            .map(|process| process.fls_value.load(Ordering::Acquire))
            .unwrap_or(0)
    } else {
        0
    }
}
pub(super) extern "win64" fn native_fls_set_value(index: u32, value: u64) -> i32 {
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

#[cfg(test)]
mod tls_callback_tests {
    use super::{invoke_tls_callbacks, notify_guest_thread_modules};
    use crate::native::linux_x86_64::state::NativeLoadedModule;
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
            load_order: 1,
        };
        THREAD_EVENTS.lock().unwrap().clear();
        process.loaded_modules.lock().unwrap().insert(base, module);

        notify_guest_thread_modules(process, true);
        notify_guest_thread_modules(process, false);

        assert_eq!(*THREAD_EVENTS.lock().unwrap(), vec![12, 22, 23, 13]);
        process.loaded_modules.lock().unwrap().remove(&base);
    }
}
