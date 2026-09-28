//! Linux host-backed heap, virtual-memory, and file-mapping APIs.

use super::*;

pub(super) fn page_len(len: usize) -> Result<usize, String> {
    len.checked_add(4095)
        .map(|n| n & !4095)
        .ok_or_else(|| "native image size overflows page rounding".to_string())
}

pub(super) fn linux_protection(page_protection: u32) -> Option<i32> {
    // The low byte specifies the page access mode. Guard/cache modifiers
    // are intentionally not implemented by the native backend yet.
    match page_protection & 0xff {
        0x01 => Some(0),                                  // PAGE_NOACCESS
        0x02 => Some(PROT_READ),                          // PAGE_READONLY
        0x04 => Some(PROT_READ | PROT_WRITE),             // PAGE_READWRITE
        0x10 => Some(PROT_EXEC),                          // PAGE_EXECUTE
        0x20 => Some(PROT_READ | PROT_EXEC),              // PAGE_EXECUTE_READ
        0x40 => Some(PROT_READ | PROT_WRITE | PROT_EXEC), // PAGE_EXECUTE_READWRITE
        _ => None,
    }
}

#[repr(C)]
pub(super) struct NativeMemoryStatus {
    pub(super) length: u32,
    pub(super) load: u32,
    pub(super) total_physical: u64,
    pub(super) available_physical: u64,
    pub(super) total_page_file: u64,
    pub(super) available_page_file: u64,
    pub(super) total_virtual: u64,
    pub(super) available_virtual: u64,
    pub(super) available_extended_virtual: u64,
}
pub(super) extern "win64" fn native_global_memory_status_ex(
    status: *mut NativeMemoryStatus,
) -> i32 {
    if status.is_null() {
        native_set_last_error(998); // ERROR_NOACCESS
        return 0;
    }
    if unsafe { std::ptr::addr_of!((*status).length).read_unaligned() } != 64 {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    // Keep the reported budget consistent with the guest's finite WinFS
    // process model rather than exposing an arbitrary host memory size.
    let budget = 512 * 1024 * 1024u64;
    let available = budget / 2;
    let value = NativeMemoryStatus {
        length: 64,
        load: 50,
        total_physical: budget,
        available_physical: available,
        total_page_file: budget,
        available_page_file: available,
        total_virtual: budget,
        available_virtual: available,
        available_extended_virtual: 0,
    };
    unsafe { status.write_unaligned(value) };
    1
}

pub(super) extern "win64" fn native_heap_alloc(heap: u64, flags: u32, size: usize) -> u64 {
    if heap != PROCESS_HEAP_HANDLE {
        native_set_last_error(6);
        return 0;
    }
    let ptr = unsafe { malloc(size.max(1)) } as u64;
    if ptr == 0 {
        native_set_last_error(8);
        return 0;
    }
    if flags & 0x8 != 0 {
        unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, size) };
    }
    let Some(process) = process_ctx() else {
        unsafe { free(ptr as *mut c_void) };
        return 0;
    };
    let Ok(mut allocations) = process.heap_allocations.lock() else {
        unsafe { free(ptr as *mut c_void) };
        return 0;
    };
    allocations.insert(ptr, size);
    ptr
}
pub(super) extern "win64" fn native_heap_realloc(
    heap: u64,
    flags: u32,
    ptr: u64,
    size: usize,
) -> u64 {
    if heap != PROCESS_HEAP_HANDLE || ptr == 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(mut allocations) = process.heap_allocations.lock() else {
        return 0;
    };
    let Some(old_size) = allocations.get(&ptr).copied() else {
        native_set_last_error(87);
        return 0;
    };
    let new_ptr = unsafe { realloc(ptr as *mut c_void, size.max(1)) } as u64;
    if new_ptr == 0 {
        native_set_last_error(8);
        return 0;
    }
    if flags & 0x8 != 0 && size > old_size {
        unsafe { std::ptr::write_bytes((new_ptr as *mut u8).add(old_size), 0, size - old_size) };
    }
    allocations.remove(&ptr);
    allocations.insert(new_ptr, size);
    new_ptr
}
pub(super) extern "win64" fn native_heap_size(heap: u64, _flags: u32, ptr: u64) -> usize {
    if heap != PROCESS_HEAP_HANDLE || ptr == 0 {
        native_set_last_error(87);
        return usize::MAX;
    }
    let size = process_ctx().and_then(|process| {
        process
            .heap_allocations
            .lock()
            .ok()
            .and_then(|allocations| allocations.get(&ptr).copied())
    });
    match size {
        Some(size) => size,
        None => {
            native_set_last_error(87);
            usize::MAX
        }
    }
}

pub(super) extern "win64" fn native_heap_free(heap: u64, _flags: u32, ptr: u64) -> i32 {
    if heap != PROCESS_HEAP_HANDLE || ptr == 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(mut allocations) = process.heap_allocations.lock() else {
        return 0;
    };
    if allocations.remove(&ptr).is_none() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { free(ptr as *mut c_void) };
    1
}

pub(super) extern "win64" fn native_virtual_protect(
    address: *mut c_void,
    size: usize,
    page_protection: u32,
    old_page_protection: *mut u32,
) -> i32 {
    if address.is_null() || size == 0 {
        return 0;
    }
    let protection = match linux_protection(page_protection) {
        Some(value) => value,
        None => return 0,
    };
    let start = (address as usize) & !4095;
    let end = match (address as usize)
        .checked_add(size)
        .and_then(|value| value.checked_add(4095))
    {
        Some(value) => value & !4095,
        None => return 0,
    };
    if end <= start {
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Ok(mut allocations) = process.virtual_allocations.lock() else {
        return 0;
    };
    let tracked_base = allocations
        .iter()
        .find(|(&base, allocation)| {
            start as u64 >= base && (end as u64) <= base.saturating_add(allocation.length as u64)
        })
        .map(|(&base, _)| base);
    let old_protection = if let Some(base) = tracked_base {
        let Some(allocation) = allocations.get_mut(&base) else {
            native_set_last_error(487);
            return 0;
        };
        let first_page = (start as u64 - base) as usize / 4096;
        let page_count = (end - start) / 4096;
        let Some(pages) = allocation
            .pages
            .get_mut(first_page..first_page + page_count)
        else {
            native_set_last_error(487); // ERROR_INVALID_ADDRESS
            return 0;
        };
        if pages.iter().any(|page| !page.committed) {
            native_set_last_error(487);
            return 0;
        }
        let old = pages.first().map(|page| page.protection).unwrap_or(0x01);
        // SAFETY: the requested range is page-aligned, belongs to this
        // reservation, and every page is committed.
        if unsafe { mprotect(start as *mut c_void, end - start, protection) } != 0 {
            return 0;
        }
        for page in pages {
            page.protection = page_protection;
        }
        old
    } else {
        let overlaps_reservation = allocations.iter().any(|(&base, allocation)| {
            let allocation_end = base.saturating_add(allocation.length as u64);
            (start as u64) < allocation_end && (end as u64) > base
        });
        if overlaps_reservation {
            native_set_last_error(487);
            return 0;
        }
        // PE and other native mappings are not yet represented in the
        // VirtualAlloc region table; preserve their prior RWX baseline.
        // SAFETY: mprotect receives a checked, page-aligned guest range.
        if unsafe { mprotect(start as *mut c_void, end - start, protection) } != 0 {
            return 0;
        }
        0x40
    };
    if !old_page_protection.is_null() {
        unsafe { old_page_protection.write(old_protection) };
    }
    1
}

pub(super) extern "win64" fn native_virtual_alloc(
    address: *mut u8,
    size: usize,
    allocation_type: u32,
    protection: u32,
) -> *mut u8 {
    if native_diagnostic_enabled() {
        eprintln!("native VirtualAlloc address={address:p} size={size:#x} type={allocation_type:#x} protection={protection:#x}");
    }
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RESET: u32 = 0x80000;
    if allocation_type == MEM_RESET {
        let Ok(length) = page_len(size) else {
            native_set_last_error(87);
            return ptr::null_mut();
        };
        if address.is_null() || unsafe { madvise(address.cast(), length, 4) } != 0 {
            native_set_last_error(487);
            return ptr::null_mut();
        }
        return address;
    }
    if size == 0 || allocation_type & (MEM_COMMIT | MEM_RESERVE) == 0 {
        native_set_last_error(87);
        return ptr::null_mut();
    }
    let Some(host_protection) = linux_protection(protection) else {
        native_set_last_error(87);
        return ptr::null_mut();
    };
    let Ok(length) = page_len(size) else {
        native_set_last_error(8);
        return ptr::null_mut();
    };
    let Some(process) = process_ctx() else {
        return ptr::null_mut();
    };
    if allocation_type & MEM_RESERVE == 0 {
        if address.is_null() || (address as usize) & 4095 != 0 {
            native_set_last_error(487); // ERROR_INVALID_ADDRESS
            return ptr::null_mut();
        }
        let Ok(mut allocations) = process.virtual_allocations.lock() else {
            return ptr::null_mut();
        };
        let Some((&base, allocation)) = allocations.iter_mut().find(|(&base, allocation)| {
            (address as u64) >= base
                && (address as u64)
                    .checked_add(length as u64)
                    .is_some_and(|end| end <= base.saturating_add(allocation.length as u64))
        }) else {
            native_set_last_error(487);
            return ptr::null_mut();
        };
        let first_page = (address as u64 - base) as usize / 4096;
        let page_count = length / 4096;
        let Some(pages) = allocation
            .pages
            .get_mut(first_page..first_page + page_count)
        else {
            native_set_last_error(487);
            return ptr::null_mut();
        };
        if unsafe { mprotect(address.cast(), length, host_protection) } != 0 {
            native_set_last_error(487);
            return ptr::null_mut();
        }
        for page in pages {
            page.committed = true;
            page.protection = protection;
        }
        return address;
    }
    if !address.is_null() && (address as usize) & 0xffff != 0 {
        native_set_last_error(487);
        return ptr::null_mut();
    }
    let initial_protection = if allocation_type & MEM_COMMIT != 0 {
        host_protection
    } else {
        0
    };
    let result = if address.is_null() {
        let Some(overlength) = length.checked_add(0x10000) else {
            native_set_last_error(8);
            return ptr::null_mut();
        };
        let raw = unsafe {
            mmap(
                ptr::null_mut(),
                overlength,
                initial_protection,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == MAP_FAILED {
            native_set_last_error(8);
            return ptr::null_mut();
        }
        let base = raw as usize;
        let aligned = (base + 0xffff) & !0xffff;
        let prefix = aligned - base;
        let suffix = overlength - prefix - length;
        if prefix != 0 {
            unsafe { munmap(raw, prefix) };
        }
        if suffix != 0 {
            unsafe { munmap((aligned + length) as *mut c_void, suffix) };
        }
        aligned as *mut u8
    } else {
        let raw = unsafe {
            mmap(
                address.cast(),
                length,
                initial_protection,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if raw == MAP_FAILED {
            native_set_last_error(487);
            return ptr::null_mut();
        }
        raw.cast()
    };
    if let Ok(mut allocations) = process.virtual_allocations.lock() {
        let committed = allocation_type & MEM_COMMIT != 0;
        allocations.insert(
            result as u64,
            NativeVirtualAllocation {
                length,
                pages: (0..length / 4096)
                    .map(|_| NativeVirtualPage {
                        committed,
                        protection: if committed { protection } else { 0x01 },
                    })
                    .collect(),
            },
        );
    }
    result
}

pub(super) extern "win64" fn native_virtual_free(
    address: *mut u8,
    size: usize,
    free_type: u32,
) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    if address.is_null() {
        native_set_last_error(87);
        return 0;
    }
    if free_type == 0x8000 {
        // MEM_RELEASE
        if size != 0 {
            native_set_last_error(87);
            return 0;
        }
        let allocation = process
            .virtual_allocations
            .lock()
            .ok()
            .and_then(|mut values| values.remove(&(address as u64)));
        let Some(allocation) = allocation else {
            native_set_last_error(487);
            return 0;
        };
        return (unsafe { munmap(address.cast(), allocation.length) } == 0) as i32;
    }
    if free_type == 0x4000 {
        // MEM_DECOMMIT
        let Ok(length) = page_len(size) else {
            native_set_last_error(87);
            return 0;
        };
        if (address as usize) & 4095 != 0 || length == 0 {
            native_set_last_error(487);
            return 0;
        }
        let Ok(mut allocations) = process.virtual_allocations.lock() else {
            return 0;
        };
        let Some((&base, allocation)) = allocations.iter_mut().find(|(&base, allocation)| {
            (address as u64) >= base
                && (address as u64)
                    .checked_add(length as u64)
                    .is_some_and(|end| end <= base.saturating_add(allocation.length as u64))
        }) else {
            native_set_last_error(487);
            return 0;
        };
        let first_page = (address as u64 - base) as usize / 4096;
        let page_count = length / 4096;
        let Some(pages) = allocation
            .pages
            .get_mut(first_page..first_page + page_count)
        else {
            native_set_last_error(487);
            return 0;
        };
        if unsafe { mprotect(address.cast(), length, 0) } != 0 {
            native_set_last_error(487);
            return 0;
        }
        unsafe { madvise(address.cast(), length, 4) }; // MADV_DONTNEED
        for page in pages {
            page.committed = false;
            page.protection = 0x01;
        }
        return 1;
    }
    native_set_last_error(87);
    0
}

pub(super) extern "win64" fn native_create_file_mapping_w(
    file: u64,
    _attributes: u64,
    protection: u32,
    size_high: u32,
    size_low: u32,
    _name: *const u16,
) -> u64 {
    let requested_size = ((size_high as u64) << 32) | size_low as u64;
    if !matches!(protection, 0x02 | 0x04) || requested_size > usize::MAX as u64 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let (path, size) = if file == u64::MAX {
        if requested_size == 0 {
            native_set_last_error(87);
            return 0;
        }
        (None, requested_size as usize)
    } else {
        let Some(context) = fs_ctx() else {
            native_set_last_error(6);
            return 0;
        };
        let Ok(mut ctx) = context.lock() else {
            native_set_last_error(6);
            return 0;
        };
        let Some(native_file) = ctx.handles.get(&file) else {
            native_set_last_error(6);
            return 0;
        };
        if ctx.fs.is_dir(&native_file.path) {
            native_set_last_error(87);
            return 0;
        }
        let path = native_file.path.clone();
        let mut contents = match ctx.fs.read_file(&path) {
            Ok(contents) => contents,
            Err(_) => {
                native_set_last_error(6);
                return 0;
            }
        };
        let size = if requested_size == 0 {
            contents.len()
        } else {
            requested_size as usize
        };
        if size == 0 {
            native_set_last_error(87);
            return 0;
        }
        if contents.len() < size {
            contents.resize(size, 0);
            if ctx.fs.write_file(&path, contents).is_err() {
                native_set_last_error(5);
                return 0;
            }
        }
        (Some(path), size)
    };
    let handle = process.mapping_next.fetch_add(1, Ordering::AcqRel);
    let result = if let Ok(mut values) = process.file_mappings.lock() {
        values.insert(
            handle,
            NativeFileMapping {
                length: size,
                protection,
                path,
            },
        );
        handle
    } else {
        0
    };
    result
}

pub(super) extern "win64" fn native_create_file_mapping_a(
    file: u64,
    attributes: u64,
    protection: u32,
    size_high: u32,
    size_low: u32,
    _name: *const u8,
) -> u64 {
    native_create_file_mapping_w(
        file,
        attributes,
        protection,
        size_high,
        size_low,
        std::ptr::null(),
    )
}

pub(super) extern "win64" fn native_map_view_of_file(
    mapping: u64,
    access: u32,
    offset_high: u32,
    offset_low: u32,
    bytes: usize,
) -> *mut u8 {
    let Some(process) = process_ctx() else {
        return ptr::null_mut();
    };
    let Some(mapping) = process
        .file_mappings
        .lock()
        .ok()
        .and_then(|values| values.get(&mapping).cloned())
    else {
        native_set_last_error(6);
        return ptr::null_mut();
    };
    let offset = ((offset_high as u64) << 32) | offset_low as u64;
    let Ok(offset) = usize::try_from(offset) else {
        native_set_last_error(87);
        return ptr::null_mut();
    };
    let length = if bytes == 0 {
        mapping.length.saturating_sub(offset)
    } else {
        bytes
    };
    let Some(end) = offset.checked_add(length) else {
        native_set_last_error(87);
        return ptr::null_mut();
    };
    if length == 0 || end > mapping.length || (access & 0x2 != 0 && mapping.protection != 0x04) {
        native_set_last_error(87);
        return ptr::null_mut();
    }
    let Ok(mapped_length) = page_len(length) else {
        native_set_last_error(8);
        return ptr::null_mut();
    };
    let result = unsafe {
        mmap(
            ptr::null_mut(),
            mapped_length,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if result == MAP_FAILED {
        native_set_last_error(8);
        return ptr::null_mut();
    }
    let view = result.cast::<u8>();
    if let Some(path) = mapping.path.as_deref() {
        let Some(context) = fs_ctx() else {
            unsafe { munmap(result, mapped_length) };
            native_set_last_error(6);
            return ptr::null_mut();
        };
        let Ok(ctx) = context.lock() else {
            unsafe { munmap(result, mapped_length) };
            native_set_last_error(6);
            return ptr::null_mut();
        };
        let Ok(contents) = ctx.fs.read_file(path) else {
            unsafe { munmap(result, mapped_length) };
            native_set_last_error(6);
            return ptr::null_mut();
        };
        if offset < contents.len() {
            let count = length.min(contents.len() - offset);
            unsafe { ptr::copy_nonoverlapping(contents.as_ptr().add(offset), view, count) };
        }
    }
    let writable = access & 0x2 != 0;
    let copy_on_write = access & 0x1 != 0;
    let host_protection = if writable || copy_on_write {
        PROT_READ | PROT_WRITE
    } else if access & 0x4 != 0 {
        PROT_READ
    } else {
        linux_protection(mapping.protection).unwrap_or(PROT_READ)
    };
    if unsafe { mprotect(result, mapped_length, host_protection) } != 0 {
        unsafe { munmap(result, mapped_length) };
        native_set_last_error(87);
        return ptr::null_mut();
    }
    if let Ok(mut views) = process.mapping_views.lock() {
        views.insert(
            result as u64,
            NativeMappingView {
                length: mapped_length,
                view_length: length,
                backing: mapping.path.map(|path| (path, offset)),
                writable,
            },
        );
    }
    result.cast()
}

fn native_flush_mapping_view(
    address: *const u8,
    view: &NativeMappingView,
    bytes: usize,
) -> Result<(), u32> {
    if !view.writable {
        return Ok(());
    }
    let Some((path, offset)) = view.backing.as_ref() else {
        return Ok(());
    };
    let count = if bytes == 0 { view.view_length } else { bytes };
    if count > view.view_length {
        return Err(87);
    }
    let end = offset.checked_add(count).ok_or(87u32)?;
    let Some(context) = fs_ctx() else {
        return Err(6);
    };
    let mut ctx = context.lock().map_err(|_| 6u32)?;
    let mut contents = ctx.fs.read_file(path).map_err(|_| 6u32)?;
    if contents.len() < end {
        contents.resize(end, 0);
    }
    unsafe {
        ptr::copy_nonoverlapping(address, contents.as_mut_ptr().add(*offset), count);
    }
    ctx.fs.write_file(path, contents).map_err(|_| 5u32)
}

pub(super) extern "win64" fn native_flush_view_of_file(
    address: *const c_void,
    bytes: usize,
) -> i32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(view) = process.mapping_views.lock().ok().and_then(|values| {
        values.get(&(address as u64)).map(|view| NativeMappingView {
            length: view.length,
            view_length: view.view_length,
            backing: view.backing.clone(),
            writable: view.writable,
        })
    }) else {
        native_set_last_error(487);
        return 0;
    };
    match native_flush_mapping_view(address.cast(), &view, bytes) {
        Ok(()) => 1,
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

pub(super) extern "win64" fn native_unmap_view_of_file(address: *mut c_void) -> i32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Some(view) = process
        .mapping_views
        .lock()
        .ok()
        .and_then(|mut values| values.remove(&(address as u64)))
    else {
        native_set_last_error(487);
        return 0;
    };
    if let Err(error) = native_flush_mapping_view(address.cast(), &view, 0) {
        unsafe { munmap(address, view.length) };
        native_set_last_error(error);
        return 0;
    }
    (unsafe { munmap(address, view.length) } == 0) as i32
}

pub(super) extern "win64" fn native_get_process_heap() -> u64 {
    PROCESS_HEAP_HANDLE
}

#[cfg(test)]
mod virtual_memory_tests {
    use super::{native_virtual_alloc, native_virtual_free, native_virtual_protect};
    use std::ffi::c_void;

    #[test]
    fn reserve_commit_protect_and_decommit_track_page_state() {
        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const MEM_DECOMMIT: u32 = 0x4000;
        const MEM_RELEASE: u32 = 0x8000;
        const PAGE_NOACCESS: u32 = 0x01;
        const PAGE_READONLY: u32 = 0x02;
        const PAGE_READWRITE: u32 = 0x04;

        let base = native_virtual_alloc(std::ptr::null_mut(), 0x2000, MEM_RESERVE, PAGE_NOACCESS);
        assert!(!base.is_null());

        let mut old_protection = 0;
        assert_eq!(
            native_virtual_protect(
                base.cast::<c_void>(),
                0x1000,
                PAGE_READWRITE,
                &mut old_protection,
            ),
            0,
            "a reserved but uncommitted page cannot be protected"
        );
        assert_eq!(
            native_virtual_alloc(base, 0x1000, MEM_COMMIT, PAGE_READWRITE),
            base
        );
        assert_eq!(
            native_virtual_protect(
                base.cast::<c_void>(),
                0x1000,
                PAGE_READONLY,
                &mut old_protection,
            ),
            1
        );
        assert_eq!(old_protection, PAGE_READWRITE);
        let second_page = unsafe { base.add(0x1000) };
        assert_eq!(
            native_virtual_protect(
                second_page.cast::<c_void>(),
                0x1000,
                PAGE_READWRITE,
                &mut old_protection,
            ),
            0,
            "protection cannot cross into an uncommitted page"
        );
        assert_eq!(native_virtual_free(base, 0x1000, MEM_DECOMMIT), 1);
        assert_eq!(
            native_virtual_protect(
                base.cast::<c_void>(),
                0x1000,
                PAGE_READWRITE,
                &mut old_protection,
            ),
            0,
            "a decommitted page cannot be protected"
        );
        assert_eq!(native_virtual_free(base, 0, MEM_RELEASE), 1);
    }
}
