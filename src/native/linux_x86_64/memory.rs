//! Linux host-backed heap, virtual-memory, and file-mapping APIs.

use super::*;

pub(super) fn page_len(len: usize) -> Result<usize, String> {
    len.checked_add(4095)
        .map(|n| n & !4095)
        .ok_or_else(|| "native image size overflows page rounding".to_string())
}

pub(super) fn linux_protection(page_protection: u32) -> Option<i32> {
    // PAGE_GUARD is represented as inaccessible until its first fault. The
    // fault dispatcher removes the modifier and restores the underlying mode.
    let guard = page_protection & 0x100 != 0;
    let protection = match page_protection & 0xff {
        0x01 => Some(0),                                  // PAGE_NOACCESS
        0x02 => Some(PROT_READ),                          // PAGE_READONLY
        0x04 => Some(PROT_READ | PROT_WRITE),             // PAGE_READWRITE
        0x10 => Some(PROT_EXEC),                          // PAGE_EXECUTE
        0x20 => Some(PROT_READ | PROT_EXEC),              // PAGE_EXECUTE_READ
        0x40 => Some(PROT_READ | PROT_WRITE | PROT_EXEC), // PAGE_EXECUTE_READWRITE
        _ => None,
    }?;
    Some(if guard { 0 } else { protection })
}

pub(super) fn consume_guard_page_fault(address: u64) -> bool {
    let Some(process) = process_ctx() else {
        return false;
    };
    if let Ok(mut allocations) = process.virtual_allocations.lock() {
        if let Some((&base, allocation)) = allocations.iter_mut().find(|(&base, allocation)| {
            address >= base && address < base.saturating_add(allocation.length as u64)
        }) {
            let page_index = (address - base) as usize / 4096;
            let Some(page) = allocation.pages.get_mut(page_index) else {
                return false;
            };
            if !page.committed {
                return false;
            }
            return consume_guard_page(base, page_index, &mut page.protection);
        }
    }

    let module = process.loaded_modules.lock().ok().and_then(|modules| {
        modules
            .values()
            .find(|module| {
                address >= module.base
                    && address < module.base.saturating_add(u64::from(module.size_of_image))
            })
            .map(|module| (module.base, module.size_of_image))
    });
    let Some((base, image_size)) = module else {
        return false;
    };
    let Ok(page_count) = page_len(image_size as usize) else {
        return false;
    };
    let page_index = (address - base) as usize / 4096;
    let Ok(mut image_pages) = process.image_page_protections.lock() else {
        return false;
    };
    let protections = image_pages
        .entry(base)
        .or_insert_with(|| vec![0x40; page_count / 4096]);
    let Some(protection) = protections.get_mut(page_index) else {
        return false;
    };
    consume_guard_page(base, page_index, protection)
}

fn consume_guard_page(base: u64, page_index: usize, protection: &mut u32) -> bool {
    if *protection & 0x100 == 0 {
        return false;
    }
    let restored_protection = *protection & !0x100;
    let Some(host_protection) = linux_protection(restored_protection) else {
        return false;
    };
    let page_address = base + page_index as u64 * 4096;
    if unsafe { mprotect(page_address as *mut c_void, 4096, host_protection) } != 0 {
        return false;
    }
    *protection = restored_protection;
    true
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

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NativeMemoryBasicInformation {
    pub(super) base_address: u64,
    pub(super) allocation_base: u64,
    pub(super) allocation_protection: u32,
    pub(super) partition_id: u16,
    pub(super) region_size: u64,
    pub(super) state: u32,
    pub(super) protection: u32,
    pub(super) kind: u32,
}

/// `MEMORYSTATUSEX.ullTotalVirtual` on x64 Windows: the user-mode range up
/// to 0x7FFF_FFFE_FFFF.
const X64_USER_ADDRESS_SPACE: u64 = 0x7fff_fffe_0000;

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
    // Keep the reported physical budget consistent with the guest's finite
    // WinFS process model rather than exposing an arbitrary host memory
    // size. The virtual address space is the x64 user range Windows reports
    // (128 TiB): runtimes such as CoreCLR size their GC reservation from it.
    let budget = 512 * 1024 * 1024u64;
    let available = budget / 2;
    let value = NativeMemoryStatus {
        length: 64,
        load: 50,
        total_physical: budget,
        available_physical: available,
        total_page_file: budget,
        available_page_file: available,
        total_virtual: X64_USER_ADDRESS_SPACE,
        available_virtual: X64_USER_ADDRESS_SPACE - 0x1_0000_0000,
        available_extended_virtual: 0,
    };
    unsafe { status.write_unaligned(value) };
    1
}

pub(super) extern "win64" fn native_virtual_query(
    address: *const c_void,
    information: *mut NativeMemoryBasicInformation,
    information_length: usize,
) -> usize {
    let information_size = std::mem::size_of::<NativeMemoryBasicInformation>();
    if information.is_null() || information_length < information_size {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let query = address as u64;
    if let Ok(allocations) = process.virtual_allocations.lock() {
        if let Some((&allocation_base, allocation)) = allocations.iter().find(|(&base, alloc)| {
            query >= base && query < base.saturating_add(alloc.length as u64)
        }) {
            let page_index = (query - allocation_base) as usize / 4096;
            let Some(page) = allocation.pages.get(page_index) else {
                native_set_last_error(487);
                return 0;
            };
            let committed = page.committed;
            let protection = if committed { page.protection } else { 0 };
            let mut first = page_index;
            while first > 0 {
                let previous = &allocation.pages[first - 1];
                if previous.committed != committed
                    || (committed && previous.protection != protection)
                {
                    break;
                }
                first -= 1;
            }
            let mut end = page_index + 1;
            while let Some(next) = allocation.pages.get(end) {
                if next.committed != committed || (committed && next.protection != protection) {
                    break;
                }
                end += 1;
            }
            let result = NativeMemoryBasicInformation {
                base_address: allocation_base + (first as u64 * 4096),
                allocation_base,
                allocation_protection: allocation.allocation_protection,
                partition_id: 0,
                region_size: ((end - first) * 4096) as u64,
                state: if committed { 0x1000 } else { 0x2000 }, // MEM_COMMIT / MEM_RESERVE
                protection,
                kind: 0x20000, // MEM_PRIVATE
            };
            unsafe { information.write_unaligned(result) };
            return information_size;
        }
    }
    if let Ok(modules) = process.loaded_modules.lock() {
        if let Some(module) = modules.values().find(|module| {
            query >= module.base
                && query < module.base.saturating_add(u64::from(module.size_of_image))
        }) {
            let page_count = page_len(module.size_of_image as usize).unwrap_or(0) / 4096;
            let image_pages =
                process
                    .image_page_protections
                    .lock()
                    .ok()
                    .and_then(|mut protections| {
                        Some(
                            protections
                                .entry(module.base)
                                .or_insert_with(|| vec![0x40; page_count])
                                .clone(),
                        )
                    });
            let pages = image_pages.unwrap_or_else(|| vec![0x40; page_count]);
            let page_index =
                ((query - module.base) as usize / 4096).min(page_count.saturating_sub(1));
            let protection = pages.get(page_index).copied().unwrap_or(0x40);
            let mut first = page_index;
            while first > 0 && pages[first - 1] == protection {
                first -= 1;
            }
            let mut end = page_index + 1;
            while pages.get(end) == Some(&protection) {
                end += 1;
            }
            let result = NativeMemoryBasicInformation {
                base_address: module.base + first as u64 * 4096,
                allocation_base: module.base,
                allocation_protection: 0x40, // initial mapped-image protection is RWX
                partition_id: 0,
                region_size: ((end - first) * 4096) as u64,
                state: 0x1000, // MEM_COMMIT
                protection,
                kind: 0x1000000, // MEM_IMAGE
            };
            unsafe { information.write_unaligned(result) };
            return information_size;
        }
    }
    // Everything else in the user address space is either memory winrun
    // or the host mapped (reported as a reserved region) or free.
    match host_region(query) {
        Some(result) => {
            unsafe { information.write_unaligned(result) };
            information_size
        }
        None => {
            native_set_last_error(87); // above the user address space
            0
        }
    }
}

/// Lowest address Windows hands out to user mode.
const LOWEST_USER_ADDRESS: u64 = 0x1_0000;

/// Occupied host address ranges from `/proc/self/maps`, sorted.
fn host_mappings() -> Vec<(u64, u64)> {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return Vec::new();
    };
    let mut ranges: Vec<(u64, u64)> = maps
        .lines()
        .filter_map(|line| {
            let range = line.split_whitespace().next()?;
            let (start, end) = range.split_once('-')?;
            Some((
                u64::from_str_radix(start, 16).ok()?,
                u64::from_str_radix(end, 16).ok()?,
            ))
        })
        .collect();
    ranges.sort_unstable();
    ranges
}

/// `VirtualQuery` for an address winrun does not track: inside a host
/// mapping it is a reserved region (merged across adjacent mappings); in a
/// gap it is `MEM_FREE` up to the next mapping, as on Windows.
fn host_region(query: u64) -> Option<NativeMemoryBasicInformation> {
    if query >= X64_USER_ADDRESS_SPACE {
        return None;
    }
    let page = query & !4095;
    let ranges = host_mappings();
    if let Some(index) = ranges.iter().position(|&(start, end)| query >= start && query < end) {
        let (mut start, mut end) = ranges[index];
        for &(next_start, next_end) in &ranges[index + 1..] {
            if next_start != end {
                break;
            }
            end = next_end;
        }
        for &(previous_start, previous_end) in ranges[..index].iter().rev() {
            if previous_end != start {
                break;
            }
            start = previous_start;
        }
        return Some(NativeMemoryBasicInformation {
            base_address: page,
            allocation_base: start,
            allocation_protection: 0x01,
            partition_id: 0,
            region_size: end - page,
            state: 0x2000, // MEM_RESERVE: in use, not the guest's to touch
            protection: 0,
            kind: 0x20000, // MEM_PRIVATE
        });
    }
    let free_start = ranges
        .iter()
        .filter(|(_, end)| *end <= query)
        .map(|(_, end)| *end)
        .max()
        .unwrap_or(LOWEST_USER_ADDRESS)
        .max(LOWEST_USER_ADDRESS);
    let free_end = ranges
        .iter()
        .map(|(start, _)| *start)
        .filter(|start| *start > query)
        .min()
        .unwrap_or(X64_USER_ADDRESS_SPACE)
        .min(X64_USER_ADDRESS_SPACE);
    let base = page.max(free_start);
    Some(NativeMemoryBasicInformation {
        base_address: base,
        allocation_base: 0,
        allocation_protection: 0,
        partition_id: 0,
        region_size: free_end.saturating_sub(base),
        state: 0x10000, // MEM_FREE
        protection: 0x01, // PAGE_NOACCESS
        kind: 0,
    })
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
        let image = process.loaded_modules.lock().ok().and_then(|modules| {
            modules
                .values()
                .find(|module| {
                    (start as u64) >= module.base
                        && (end as u64)
                            <= module.base.saturating_add(u64::from(module.size_of_image))
                })
                .map(|module| (module.base, module.size_of_image))
        });
        if let Some((base, image_size)) = image {
            let Ok(page_count) = page_len(image_size as usize) else {
                native_set_last_error(487);
                return 0;
            };
            let mut image_pages = match process.image_page_protections.lock() {
                Ok(pages) => pages,
                Err(_) => return 0,
            };
            let pages = image_pages
                .entry(base)
                .or_insert_with(|| vec![0x40; page_count / 4096]);
            let first_page = (start as u64 - base) as usize / 4096;
            let page_len = (end - start) / 4096;
            let Some(pages) = pages.get_mut(first_page..first_page + page_len) else {
                native_set_last_error(487);
                return 0;
            };
            if unsafe { mprotect(start as *mut c_void, end - start, protection) } != 0 {
                return 0;
            }
            let old = pages.first().copied().unwrap_or(0x40);
            pages.fill(page_protection);
            old
        } else {
            // Untracked native mappings preserve the prior RWX baseline.
            // SAFETY: mprotect receives a checked, page-aligned guest range.
            if unsafe { mprotect(start as *mut c_void, end - start, protection) } != 0 {
                return 0;
            }
            0x40
        }
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
                allocation_protection: protection,
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
    use super::{
        native_virtual_alloc, native_virtual_free, native_virtual_protect, native_virtual_query,
        NativeMemoryBasicInformation,
    };
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
        assert_eq!(std::mem::size_of::<NativeMemoryBasicInformation>(), 48);

        let mut old_protection = 0;
        let mut information = NativeMemoryBasicInformation::default();
        assert_eq!(
            native_virtual_query(
                base.cast::<c_void>(),
                &mut information,
                std::mem::size_of_val(&information),
            ),
            48
        );
        assert_eq!(information.base_address, base as u64);
        assert_eq!(information.allocation_base, base as u64);
        assert_eq!(information.allocation_protection, PAGE_NOACCESS);
        assert_eq!(information.region_size, 0x2000);
        assert_eq!(information.state, 0x2000); // MEM_RESERVE
        assert_eq!(information.protection, 0);
        assert_eq!(information.kind, 0x20000); // MEM_PRIVATE
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
            native_virtual_query(
                base.cast::<c_void>(),
                &mut information,
                std::mem::size_of_val(&information),
            ),
            48
        );
        assert_eq!(information.state, 0x1000); // MEM_COMMIT
        assert_eq!(information.protection, PAGE_READONLY);
        assert_eq!(information.region_size, 0x1000);
        assert_eq!(
            native_virtual_query(
                second_page.cast::<c_void>(),
                &mut information,
                std::mem::size_of_val(&information),
            ),
            48
        );
        assert_eq!(information.state, 0x2000);
        assert_eq!(information.region_size, 0x1000);
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
            native_virtual_query(
                base.cast::<c_void>(),
                &mut information,
                std::mem::size_of_val(&information),
            ),
            48
        );
        assert_eq!(information.state, 0x2000);
        assert_eq!(information.region_size, 0x2000);
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
        assert_eq!(
            native_virtual_query(
                base.cast::<c_void>(),
                &mut information,
                std::mem::size_of_val(&information),
            ),
            std::mem::size_of_val(&information),
        );
        // Released pages are no longer a guest region: they read as free
        // (or as a host mapping if another thread reused the range).
        assert_ne!(information.state, 0x1000, "released memory is no longer committed");
        assert_eq!(
            native_virtual_query(base.cast::<c_void>(), &mut information, 47),
            0,
            "a short MEMORY_BASIC_INFORMATION buffer is rejected"
        );
    }
}
