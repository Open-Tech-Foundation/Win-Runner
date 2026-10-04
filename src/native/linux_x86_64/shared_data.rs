//! Read-only KUSER_SHARED_DATA, read directly by Windows Go time routines.
use std::sync::OnceLock;

const ADDRESS: usize = 0x7ffe_0000;
const SIZE: usize = 4096;
static SHARED_DATA: OnceLock<Result<(), String>> = OnceLock::new();

fn update_times(page: *mut u8) {
    let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) };
    let interrupt = clock.tv_sec as u64 * 10_000_000 + clock.tv_nsec as u64 / 100;
    let system = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        / 100
        + 116_444_736_000_000_000;
    // KSYSTEM_TIME: LowPart, High1Time, High2Time. x64 reads the first
    // eight bytes in one instruction, including the unaligned SystemTime.
    unsafe {
        page.add(0x08).cast::<u64>().write_unaligned(interrupt);
        page.add(0x10)
            .cast::<u32>()
            .write_unaligned((interrupt >> 32) as u32);
        page.add(0x14).cast::<u64>().write_unaligned(system);
        page.add(0x1c)
            .cast::<u32>()
            .write_unaligned((system >> 32) as u32);
        page.cast::<u32>()
            .write_unaligned((interrupt / 10_000) as u32);
        page.add(0x320)
            .cast::<u64>()
            .write_unaligned(interrupt / 10_000);
        page.add(0x328)
            .cast::<u32>()
            .write_unaligned(((interrupt / 10_000) >> 32) as u32);
    }
}

pub(super) fn initialize() -> Result<(), String> {
    SHARED_DATA
        .get_or_init(|| {
            let fd = unsafe { libc::memfd_create(c"winrun-kuser".as_ptr(), libc::MFD_CLOEXEC) };
            if fd < 0 {
                return Err("cannot create Windows shared data backing".into());
            }
            if unsafe { libc::ftruncate(fd, SIZE as i64) } != 0 {
                unsafe { libc::close(fd) };
                return Err("cannot size Windows shared data backing".into());
            }
            let guest = unsafe {
                libc::mmap(
                    ADDRESS as *mut _,
                    SIZE,
                    libc::PROT_READ,
                    libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                    fd,
                    0,
                )
            };
            if guest == libc::MAP_FAILED {
                unsafe { libc::close(fd) };
                return Err("cannot map Windows shared data at 0x7ffe0000".into());
            }
            let writer = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            unsafe { libc::close(fd) };
            if writer == libc::MAP_FAILED {
                unsafe { libc::munmap(guest, SIZE) };
                return Err("cannot map Windows shared data writer".into());
            }
            let page = writer.cast::<u8>();
            unsafe {
                page.add(4).cast::<u32>().write_unaligned(1 << 24);
                page.add(0x260)
                    .cast::<u32>()
                    .write_unaligned(crate::system_profile::OS_BUILD_NUMBER);
                page.add(0x264).cast::<u32>().write_unaligned(1);
                page.add(0x268).write(1);
                page.add(0x26a).cast::<u16>().write_unaligned(9); // AMD64
                page.add(0x26c).cast::<u32>().write_unaligned(10);
                for (i, c) in crate::system_profile::WINDOWS
                    .encode_utf16()
                    .chain([0])
                    .enumerate()
                {
                    page.add(0x30 + i * 2).cast::<u16>().write_unaligned(c);
                }
            }
            update_times(page);
            let writer_address = writer as usize;
            if let Err(error) = std::thread::Builder::new()
                .name("winrun-shared-clock".into())
                .spawn(move || loop {
                    update_times(writer_address as *mut u8);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                })
            {
                unsafe {
                    libc::munmap(writer, SIZE);
                    libc::munmap(guest, SIZE);
                }
                return Err(format!("cannot start Windows shared clock: {error}"));
            }
            Ok(())
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_time_fields_advance_and_match_windows_epoch() {
        let mut page = [0u8; SIZE];
        update_times(page.as_mut_ptr());
        let read =
            |page: &[u8], offset| u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap());
        let first = read(&page, 0x08);
        std::thread::sleep(std::time::Duration::from_millis(5));
        update_times(page.as_mut_ptr());
        assert!(read(&page, 0x08) > first);
        assert_eq!(read(&page, 0x320), read(&page, 0x08) / 10_000);
        let system = read(&page, 0x14);
        let expected = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            / 100
            + 116_444_736_000_000_000;
        assert!(expected.abs_diff(system as u128) < 1_000_000);
        assert_eq!(&page[0x0c..0x10], &page[0x10..0x14]);
        assert_eq!(&page[0x18..0x1c], &page[0x1c..0x20]);
    }
}
