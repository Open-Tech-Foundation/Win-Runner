//! Host-backed Windows clock, time-zone, and FILETIME APIs.

use super::*;

pub(super) extern "win64" fn native_query_performance_counter(out: *mut i64) -> i32 {
    if out.is_null() {
        return 0;
    }
    let ticks = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0);
    unsafe { out.write_unaligned(ticks) };
    1
}
pub(super) extern "win64" fn native_query_performance_frequency(out: *mut i64) -> i32 {
    if out.is_null() {
        return 0;
    }
    unsafe { out.write_unaligned(1_000_000_000) };
    1
}
pub(super) extern "win64" fn native_get_time_zone_information(output: *mut u8) -> u32 {
    if output.is_null() {
        native_set_last_error(87);
        return u32::MAX;
    }
    #[repr(C)]
    struct HostTm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        is_dst: i32,
        gmtoff: i64,
        zone: *const i8,
    }
    unsafe extern "C" {
        fn localtime_r(time: *const i64, result: *mut HostTm) -> *mut HostTm;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let mut host_tm = std::mem::MaybeUninit::<HostTm>::uninit();
    let local = unsafe { localtime_r(&now, host_tm.as_mut_ptr()) };
    if local.is_null() {
        native_set_last_error(87);
        return u32::MAX;
    }
    let host_tm = unsafe { host_tm.assume_init() };
    let bias = -((host_tm.gmtoff / 60) as i32);
    unsafe {
        std::ptr::write_bytes(output, 0, 172);
        (output as *mut i32).write_unaligned(bias);
        // GetTimeZoneInformation returns the current local offset with no
        // transition dates; the guest still formats local Date values
        // using the Linux process timezone.
        0 // TIME_ZONE_ID_UNKNOWN
    }
}
pub(super) extern "win64" fn native_get_dynamic_time_zone_information(output: *mut u8) -> u32 {
    if output.is_null() {
        native_set_last_error(87);
        return u32::MAX;
    }
    #[repr(C)]
    struct HostTm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        is_dst: i32,
        gmtoff: i64,
        zone: *const i8,
    }
    unsafe extern "C" {
        fn localtime_r(time: *const i64, result: *mut HostTm) -> *mut HostTm;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let mut host_tm = std::mem::MaybeUninit::<HostTm>::uninit();
    let local = unsafe { localtime_r(&now, host_tm.as_mut_ptr()) };
    if local.is_null() {
        native_set_last_error(87);
        return u32::MAX;
    }
    let host_tm = unsafe { host_tm.assume_init() };
    let bias = -((host_tm.gmtoff / 60) as i32);
    unsafe {
        std::ptr::write_bytes(output, 0, 432);
        (output as *mut i32).write_unaligned(bias);
        (output.add(428) as *mut u32).write_unaligned(0);
    }
    let write_wide = |offset: usize, value: &str, capacity: usize| {
        let encoded: Vec<u16> = value.encode_utf16().collect();
        let count = encoded.len().min(capacity.saturating_sub(1));
        unsafe {
            let target = output.add(offset) as *mut u16;
            target.copy_from_nonoverlapping(encoded.as_ptr(), count);
            target.add(count).write(0);
        }
    };
    write_wide(4, "Local Standard Time", 32);
    write_wide(88, "Local Daylight Time", 32);
    write_wide(172, "Local", 128);
    0 // TIME_ZONE_ID_UNKNOWN
}

fn native_monotonic_milliseconds() -> u64 {
    let mut time = NativeTimespec {
        seconds: 0,
        nanoseconds: 0,
    };
    if unsafe { clock_gettime(1, &mut time) } != 0 {
        // CLOCK_MONOTONIC
        return 0;
    }
    time.seconds as u64 * 1000 + time.nanoseconds as u64 / 1_000_000
}

pub(super) extern "win64" fn native_time_get_time() -> u32 {
    native_monotonic_milliseconds() as u32
}

pub(super) extern "win64" fn native_get_tick_count() -> u32 {
    native_monotonic_milliseconds() as u32
}

pub(super) extern "win64" fn native_get_tick_count64() -> u64 {
    native_monotonic_milliseconds()
}

pub(super) extern "win64" fn native_get_system_time(out: *mut u16) {
    if out.is_null() {
        return;
    }
    #[repr(C)]
    struct HostTm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        isdst: i32,
        gmtoff: i64,
        zone: *const i8,
    }
    unsafe extern "C" {
        fn gmtime_r(time: *const i64, result: *mut HostTm) -> *mut HostTm;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs().min(i64::MAX as u64) as i64;
    let mut tm = std::mem::MaybeUninit::<HostTm>::uninit();
    if unsafe { gmtime_r(&seconds, tm.as_mut_ptr()) }.is_null() {
        return;
    }
    let tm = unsafe { tm.assume_init() };
    let fields = [
        (tm.year + 1900) as u16,
        (tm.mon + 1) as u16,
        tm.wday as u16,
        tm.mday as u16,
        tm.hour as u16,
        tm.min as u16,
        tm.sec as u16,
        now.subsec_millis() as u16,
    ];
    unsafe {
        std::ptr::copy_nonoverlapping(fields.as_ptr(), out, fields.len());
    }
}

pub(super) extern "win64" fn native_system_time_to_file_time(
    system_time: *const u16,
    out: *mut u64,
) -> i32 {
    if system_time.is_null() || out.is_null() {
        native_set_last_error(87);
        return 0;
    }
    #[repr(C)]
    struct HostTm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        isdst: i32,
        gmtoff: i64,
        zone: *const i8,
    }
    unsafe extern "C" {
        fn timegm(time: *mut HostTm) -> i64;
    }
    let f = unsafe { std::slice::from_raw_parts(system_time, 8) };
    if f[0] < 1601
        || !(1..=12).contains(&f[1])
        || !(1..=31).contains(&f[3])
        || f[4] > 23
        || f[5] > 59
        || f[6] > 59
        || f[7] > 999
    {
        native_set_last_error(87);
        return 0;
    }
    let mut tm = HostTm {
        sec: f[6] as i32,
        min: f[5] as i32,
        hour: f[4] as i32,
        mday: f[3] as i32,
        mon: f[1] as i32 - 1,
        year: f[0] as i32 - 1900,
        wday: 0,
        yday: 0,
        isdst: 0,
        gmtoff: 0,
        zone: std::ptr::null(),
    };
    let seconds = unsafe { timegm(&mut tm) };
    if seconds < 0 {
        native_set_last_error(87);
        return 0;
    }
    let ticks = (seconds as u64)
        .saturating_mul(10_000_000)
        .saturating_add((f[7] as u64) * 10_000)
        .saturating_add(116_444_736_000_000_000);
    unsafe {
        out.write_unaligned(ticks);
    }
    1
}

pub(super) extern "win64" fn native_get_system_time_as_file_time(out: *mut u64) {
    if out.is_null() {
        return;
    }
    let ticks = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().saturating_mul(10_000_000) + (d.subsec_nanos() / 100) as u64)
        .unwrap_or(0)
        .saturating_add(116_444_736_000_000_000);
    unsafe { out.write_unaligned(ticks) };
}

/// NTDLL's value-returning precise clock shares the Win32 FILETIME source.
pub(super) extern "win64" fn native_rtl_get_system_time_precise() -> u64 {
    let mut value = 0;
    native_get_system_time_as_file_time(&mut value);
    value
}
