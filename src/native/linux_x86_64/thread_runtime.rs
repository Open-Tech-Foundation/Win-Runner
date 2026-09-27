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
