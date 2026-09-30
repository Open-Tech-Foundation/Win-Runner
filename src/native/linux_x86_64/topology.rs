//! Processor group, affinity, and NUMA topology.
//!
//! The guest sees one processor group and one NUMA node holding
//! [`system_profile::PROCESSOR_COUNT`] logical processors, the same count
//! `GetSystemInfo` and `GetLogicalProcessorInformation` report.

use super::*;
use crate::system_profile;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

fn processor_count() -> u32 {
    system_profile::PROCESSOR_COUNT.clamp(1, 64)
}

/// The affinity mask covering every guest processor.
fn all_processors_mask() -> u64 {
    if processor_count() == 64 {
        u64::MAX
    } else {
        (1u64 << processor_count()) - 1
    }
}

/// `GROUP_AFFINITY`: Mask (8), Group (2), Reserved (6).
unsafe fn write_group_affinity(output: *mut u8, mask: u64) {
    unsafe {
        ptr::write_bytes(output, 0, 16);
        output.cast::<u64>().write_unaligned(mask);
    }
}

pub(super) extern "win64" fn native_get_active_processor_group_count() -> u16 {
    1
}

pub(super) extern "win64" fn native_get_process_group_affinity(
    _process: u64,
    count: *mut u16,
    groups: *mut u16,
) -> i32 {
    if count.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let capacity = unsafe { count.read_unaligned() };
    unsafe { count.write_unaligned(1) };
    if capacity < 1 || groups.is_null() {
        native_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { groups.write_unaligned(0) };
    1
}

pub(super) extern "win64" fn native_get_thread_group_affinity(_thread: u64, affinity: *mut u8) -> i32 {
    if affinity.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { write_group_affinity(affinity, all_processors_mask()) };
    1
}

pub(super) extern "win64" fn native_set_thread_group_affinity(
    _thread: u64,
    affinity: *const u8,
    previous: *mut u8,
) -> i32 {
    if affinity.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let (mask, group) = unsafe {
        (
            affinity.cast::<u64>().read_unaligned(),
            affinity.add(8).cast::<u16>().read_unaligned(),
        )
    };
    if group != 0 || mask & all_processors_mask() == 0 {
        native_set_last_error(87);
        return 0;
    }
    if !previous.is_null() {
        unsafe { write_group_affinity(previous, all_processors_mask()) };
    }
    1
}

/// `SetThreadAffinityMask`: the previous mask, or 0 for a mask naming no
/// guest processor.
pub(super) extern "win64" fn native_set_thread_affinity_mask(_thread: u64, mask: u64) -> u64 {
    if mask & all_processors_mask() == 0 {
        native_set_last_error(87);
        return 0;
    }
    all_processors_mask()
}

/// `PROCESSOR_NUMBER`: Group (2), Number (1), Reserved (1).
unsafe fn write_processor_number(output: *mut u8) {
    unsafe { ptr::write_bytes(output, 0, 4) };
}

pub(super) extern "win64" fn native_get_current_processor_number_ex(number: *mut u8) {
    if !number.is_null() {
        unsafe { write_processor_number(number) };
    }
}

pub(super) extern "win64" fn native_get_thread_ideal_processor_ex(_thread: u64, number: *mut u8) -> i32 {
    if number.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { write_processor_number(number) };
    1
}

pub(super) extern "win64" fn native_set_thread_ideal_processor_ex(
    _thread: u64,
    ideal: *const u8,
    previous: *mut u8,
) -> i32 {
    if ideal.is_null() {
        native_set_last_error(87);
        return 0;
    }
    if !previous.is_null() {
        unsafe { write_processor_number(previous) };
    }
    1
}

pub(super) extern "win64" fn native_get_numa_highest_node_number(node: *mut u32) -> i32 {
    if node.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { node.write_unaligned(0) };
    1
}

pub(super) extern "win64" fn native_get_numa_processor_node_ex(_processor: *const u8, node: *mut u16) -> i32 {
    if node.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { node.write_unaligned(0) };
    1
}

/// Cache levels reported to the guest: level, size in bytes, and type
/// (1 instruction, 2 data, 0 unified).
const CACHES: [(u8, u32, u32); 4] = [
    (1, 32 * 1024, 2),
    (1, 32 * 1024, 1),
    (2, 1024 * 1024, 0),
    (3, 8 * 1024 * 1024, 0),
];

/// `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` records for `relationship`
/// (`RelationAll` is 0xffff): one core per processor, one package, the
/// caches above, one NUMA node, and one group.
fn logical_processor_records(relationship: u32) -> Vec<u8> {
    let wanted = |kind: u32| relationship == 0xffff || relationship == kind;
    let mut output = Vec::new();
    let record = |output: &mut Vec<u8>, kind: u32, size: usize| -> usize {
        let start = output.len();
        output.resize(start + size, 0);
        output[start..start + 4].copy_from_slice(&kind.to_le_bytes());
        output[start + 4..start + 8].copy_from_slice(&(size as u32).to_le_bytes());
        start
    };
    let group_mask = |output: &mut Vec<u8>, at: usize, mask: u64| {
        output[at..at + 8].copy_from_slice(&mask.to_le_bytes());
    };
    if wanted(0) {
        // RelationProcessorCore: PROCESSOR_RELATIONSHIP, GroupCount at 30,
        // GroupMask at 32.
        for processor in 0..processor_count() {
            let start = record(&mut output, 0, 48);
            output[start + 30] = 1;
            group_mask(&mut output, start + 32, 1u64 << processor);
        }
    }
    if wanted(1) {
        // RelationNumaNode: NodeNumber at 8, GroupCount at 30, mask at 32.
        let start = record(&mut output, 1, 48);
        output[start + 30] = 1;
        group_mask(&mut output, start + 32, all_processors_mask());
    }
    if wanted(2) {
        // RelationCache: Level 8, Associativity 9, LineSize 10, CacheSize
        // 12, Type 16, GroupCount 38, GroupMask 40.
        for (level, size, kind) in CACHES {
            let start = record(&mut output, 2, 56);
            output[start + 8] = level;
            output[start + 9] = 8;
            output[start + 10..start + 12].copy_from_slice(&64u16.to_le_bytes());
            output[start + 12..start + 16].copy_from_slice(&size.to_le_bytes());
            output[start + 16..start + 20].copy_from_slice(&kind.to_le_bytes());
            output[start + 38] = 1;
            group_mask(&mut output, start + 40, all_processors_mask());
        }
    }
    if wanted(3) {
        // RelationProcessorPackage: same layout as a core.
        let start = record(&mut output, 3, 48);
        output[start + 30] = 1;
        group_mask(&mut output, start + 32, all_processors_mask());
    }
    if wanted(4) {
        // RelationGroup: MaximumGroupCount 8, ActiveGroupCount 10, then
        // PROCESSOR_GROUP_INFO at 32: Maximum/ActiveProcessorCount, mask
        // at +40.
        let start = record(&mut output, 4, 80);
        output[start + 8..start + 10].copy_from_slice(&1u16.to_le_bytes());
        output[start + 10..start + 12].copy_from_slice(&1u16.to_le_bytes());
        output[start + 32] = processor_count() as u8;
        output[start + 33] = processor_count() as u8;
        group_mask(&mut output, start + 72, all_processors_mask());
    }
    output
}

pub(super) extern "win64" fn native_get_logical_processor_information_ex(
    relationship: u32,
    buffer: *mut u8,
    length: *mut u32,
) -> i32 {
    if length.is_null() || !(relationship <= 7 || relationship == 0xffff) {
        native_set_last_error(87);
        return 0;
    }
    let records = logical_processor_records(relationship);
    let capacity = unsafe { length.read_unaligned() } as usize;
    unsafe { length.write_unaligned(records.len() as u32) };
    if buffer.is_null() || capacity < records.len() {
        native_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { buffer.copy_from_nonoverlapping(records.as_ptr(), records.len()) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_and_numa_queries_describe_one_group_and_node() {
        let mut count = 0u16;
        assert_eq!(native_get_process_group_affinity(0, &mut count, ptr::null_mut()), 0);
        assert_eq!(count, 1);
        let mut groups = [0xffffu16; 1];
        assert_eq!(native_get_process_group_affinity(0, &mut count, groups.as_mut_ptr()), 1);
        assert_eq!(groups[0], 0);
        let mut affinity = [0u8; 16];
        assert_eq!(native_get_thread_group_affinity(0, affinity.as_mut_ptr()), 1);
        assert_eq!(u64::from_le_bytes(affinity[..8].try_into().unwrap()), all_processors_mask());
        let mut node = 7u32;
        assert_eq!(native_get_numa_highest_node_number(&mut node), 1);
        assert_eq!(node, 0);
        assert_eq!(native_set_thread_affinity_mask(0, 0), 0);
        assert_eq!(native_set_thread_affinity_mask(0, 1), all_processors_mask());
    }

    #[test]
    fn logical_processor_information_ex_sizes_and_fills_records() {
        let mut length = 0u32;
        assert_eq!(
            native_get_logical_processor_information_ex(0xffff, ptr::null_mut(), &mut length),
            0
        );
        let expected = 48 * processor_count() as usize + 48 + 56 * CACHES.len() + 48 + 80;
        assert_eq!(length as usize, expected);
        let mut buffer = vec![0u8; length as usize];
        assert_eq!(
            native_get_logical_processor_information_ex(0xffff, buffer.as_mut_ptr(), &mut length),
            1
        );
        // Walk the variable-size records by their Size fields.
        let mut offset = 0;
        let mut kinds = Vec::new();
        while offset < buffer.len() {
            let kind = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap());
            let size = u32::from_le_bytes(buffer[offset + 4..offset + 8].try_into().unwrap());
            kinds.push(kind);
            offset += size as usize;
        }
        assert_eq!(offset, buffer.len());
        assert_eq!(kinds.iter().filter(|kind| **kind == 2).count(), CACHES.len());
        let mut caches = 0u32;
        assert_eq!(
            native_get_logical_processor_information_ex(2, ptr::null_mut(), &mut caches),
            0
        );
        assert_eq!(caches as usize, 56 * CACHES.len());
    }
}
