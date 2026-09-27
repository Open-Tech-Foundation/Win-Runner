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
