//! UCRT time conversion and formatting.

use super::*;

const EINVAL: i32 = 22;

/// `struct tm`: nine `int` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Tm {
    second: i32,
    minute: i32,
    hour: i32,
    day: i32,
    /// 0-11.
    month: i32,
    /// Years since 1900.
    year: i32,
    /// 0 = Sunday.
    weekday: i32,
    /// 0-365.
    year_day: i32,
    daylight: i32,
}

/// UTC broken-down time for seconds since 1970, using the proleptic
/// Gregorian calendar (days-from-civil in reverse).
fn utc_from_epoch(seconds: i64) -> Tm {
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year_march = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_march = (5 * day_of_year_march + 2) / 153;
    let day = day_of_year_march - (153 * month_march + 2) / 5 + 1;
    let month = if month_march < 10 { month_march + 3 } else { month_march - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    const BEFORE_MONTH: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let year_day = BEFORE_MONTH[(month - 1) as usize] + day - 1 + i64::from(leap && month > 2);
    Tm {
        second: (second_of_day % 60) as i32,
        minute: (second_of_day / 60 % 60) as i32,
        hour: (second_of_day / 3600) as i32,
        day: day as i32,
        month: (month - 1) as i32,
        year: (year - 1900) as i32,
        weekday: (days + 4).rem_euclid(7) as i32, // 1970-01-01 was a Thursday
        year_day: year_day as i32,
        daylight: 0,
    }
}

unsafe fn write_tm(output: *mut i32, tm: Tm) {
    let fields = [
        tm.second, tm.minute, tm.hour, tm.day, tm.month, tm.year, tm.weekday, tm.year_day, tm.daylight,
    ];
    for (index, value) in fields.into_iter().enumerate() {
        unsafe { output.add(index).write_unaligned(value) };
    }
}

unsafe fn read_tm(input: *const i32) -> Tm {
    let field = |index| unsafe { input.add(index).read_unaligned() };
    Tm {
        second: field(0),
        minute: field(1),
        hour: field(2),
        day: field(3),
        month: field(4),
        year: field(5),
        weekday: field(6),
        year_day: field(7),
        daylight: field(8),
    }
}

/// `_gmtime64_s(tm, time)`: 0 on success, `EINVAL` for a null pointer or a
/// time outside years 1970-3000 (as the UCRT limits it).
pub(super) extern "win64" fn native_crt_gmtime64_s(output: *mut i32, time: *const i64) -> i32 {
    if output.is_null() || time.is_null() {
        return EINVAL;
    }
    let seconds = unsafe { time.read_unaligned() };
    if !(0..=32_535_215_999).contains(&seconds) {
        unsafe { ptr::write_bytes(output, 0xff, 9) };
        return EINVAL;
    }
    unsafe { write_tm(output, utc_from_epoch(seconds)) };
    0
}

const WEEKDAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTHS: [&str; 12] = [
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
    "November", "December",
];

/// `strftime` in the C locale for the common conversions; `%#` variants
/// drop leading zeros.
fn format_time(format: &str, tm: &Tm) -> Option<String> {
    let mut output = String::new();
    let mut chars = format.chars().peekable();
    let name = |names: &[&str], index: i32, short: bool| {
        let name = names.get(index as usize).copied().unwrap_or("?");
        if short { name[..3].to_string() } else { name.to_string() }
    };
    while let Some(character) = chars.next() {
        if character != '%' {
            output.push(character);
            continue;
        }
        let strip = chars.peek() == Some(&'#');
        if strip {
            chars.next();
        }
        let two = |value: i32| if strip { value.to_string() } else { format!("{value:02}") };
        let hour12 = if tm.hour % 12 == 0 { 12 } else { tm.hour % 12 };
        match chars.next()? {
            'a' => output.push_str(&name(&WEEKDAYS, tm.weekday, true)),
            'A' => output.push_str(&name(&WEEKDAYS, tm.weekday, false)),
            'b' | 'h' => output.push_str(&name(&MONTHS, tm.month, true)),
            'B' => output.push_str(&name(&MONTHS, tm.month, false)),
            'c' => output.push_str(&format!(
                "{:02}/{:02}/{:02} {:02}:{:02}:{:02}",
                tm.month + 1,
                tm.day,
                (tm.year + 1900) % 100,
                tm.hour,
                tm.minute,
                tm.second
            )),
            'd' => output.push_str(&two(tm.day)),
            'D' | 'x' => output.push_str(&format!("{:02}/{:02}/{:02}", tm.month + 1, tm.day, (tm.year + 1900) % 100)),
            'e' => output.push_str(&format!("{:>2}", tm.day)),
            'F' => output.push_str(&format!("{}-{:02}-{:02}", tm.year + 1900, tm.month + 1, tm.day)),
            'H' => output.push_str(&two(tm.hour)),
            'I' => output.push_str(&two(hour12)),
            'j' => output.push_str(&if strip { (tm.year_day + 1).to_string() } else { format!("{:03}", tm.year_day + 1) }),
            'm' => output.push_str(&two(tm.month + 1)),
            'M' => output.push_str(&two(tm.minute)),
            'n' => output.push('\n'),
            'p' => output.push_str(if tm.hour < 12 { "AM" } else { "PM" }),
            'S' => output.push_str(&two(tm.second)),
            't' => output.push('\t'),
            'T' | 'X' => output.push_str(&format!("{:02}:{:02}:{:02}", tm.hour, tm.minute, tm.second)),
            'u' => output.push_str(&(if tm.weekday == 0 { 7 } else { tm.weekday }).to_string()),
            'w' => output.push_str(&tm.weekday.to_string()),
            'y' => output.push_str(&two((tm.year + 1900) % 100)),
            'Y' => output.push_str(&(tm.year + 1900).to_string()),
            'z' => output.push_str("+0000"),
            'Z' => output.push_str("Coordinated Universal Time"),
            '%' => output.push('%'),
            _ => return None,
        }
    }
    Some(output)
}

/// `wcsftime(buffer, count, format, tm)`: characters written without the
/// terminator, or 0 (with the buffer emptied) when they do not fit.
pub(super) extern "win64" fn native_crt_wcsftime(
    output: *mut u16,
    count: usize,
    format: *const u16,
    tm: *const i32,
) -> usize {
    if output.is_null() || count == 0 || format.is_null() || tm.is_null() {
        THREAD_CRT_ERRNO.with(|errno| errno.set(EINVAL));
        return 0;
    }
    let Some(format) = wide(format) else {
        return 0;
    };
    let tm = unsafe { read_tm(tm) };
    let Some(text) = format_time(&format, &tm) else {
        unsafe { output.write(0) };
        THREAD_CRT_ERRNO.with(|errno| errno.set(EINVAL));
        return 0;
    };
    let units: Vec<u16> = text.encode_utf16().collect();
    if units.len() + 1 > count {
        unsafe { output.write(0) };
        return 0;
    }
    unsafe {
        output.copy_from_nonoverlapping(units.as_ptr(), units.len());
        output.add(units.len()).write(0);
    }
    units.len()
}

#[repr(C)]
struct HostTm {
    second: i32,
    minute: i32,
    hour: i32,
    day: i32,
    month: i32,
    year: i32,
    weekday: i32,
    year_day: i32,
    daylight: i32,
    offset: i64,
    zone: *const std::ffi::c_char,
}

unsafe extern "C" {
    fn localtime_r(time: *const i64, result: *mut HostTm) -> *mut HostTm;
}

/// The host's local time (the zone `GetTimeZoneInformation` also reports).
fn host_local(seconds: i64) -> Option<HostTm> {
    let mut tm = std::mem::MaybeUninit::<HostTm>::uninit();
    let result = unsafe { localtime_r(&seconds, tm.as_mut_ptr()) };
    (!result.is_null()).then(|| unsafe { tm.assume_init() })
}

/// `_localtime64_s(tm, time)`: like `_gmtime64_s`, in the local zone.
pub(super) extern "win64" fn native_crt_localtime64_s(output: *mut i32, time: *const i64) -> i32 {
    if output.is_null() || time.is_null() {
        return EINVAL;
    }
    let seconds = unsafe { time.read_unaligned() };
    let local = (0..=32_535_215_999).contains(&seconds).then(|| host_local(seconds)).flatten();
    let Some(local) = local else {
        unsafe { ptr::write_bytes(output, 0xff, 9) };
        return EINVAL;
    };
    let tm = Tm {
        second: local.second,
        minute: local.minute,
        hour: local.hour,
        day: local.day,
        month: local.month,
        year: local.year,
        weekday: local.weekday,
        year_day: local.year_day,
        daylight: i32::from(local.daylight > 0),
    };
    unsafe { write_tm(output, tm) };
    0
}

/// The UCRT's timezone globals, filled by `_tzset` from the host zone:
/// seconds west of UTC and the standard/daylight names.
struct TimeZoneGlobals {
    timezone: std::cell::UnsafeCell<i32>,
    daylight: std::cell::UnsafeCell<i32>,
    names: [std::cell::UnsafeCell<[u8; 64]>; 2],
    name_pointers: std::cell::UnsafeCell<[*const u8; 2]>,
}
unsafe impl Sync for TimeZoneGlobals {}

static TIME_ZONE: TimeZoneGlobals = TimeZoneGlobals {
    timezone: std::cell::UnsafeCell::new(0),
    daylight: std::cell::UnsafeCell::new(0),
    names: [std::cell::UnsafeCell::new([0; 64]), std::cell::UnsafeCell::new([0; 64])],
    name_pointers: std::cell::UnsafeCell::new([ptr::null(); 2]),
};
static TIME_ZONE_SET: std::sync::Once = std::sync::Once::new();

fn set_time_zone_globals() {
    TIME_ZONE_SET.call_once(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as i64);
        let local = host_local(now);
        let offset = local.as_ref().map_or(0, |local| local.offset);
        let daylight = local.as_ref().is_some_and(|local| local.daylight > 0);
        let zone = local
            .as_ref()
            .filter(|local| !local.zone.is_null())
            .map(|local| unsafe { std::ffi::CStr::from_ptr(local.zone) }.to_string_lossy().into_owned())
            .unwrap_or_else(|| "UTC".to_string());
        // The standard offset: while daylight time is in effect it is an
        // hour ahead of standard time.
        let standard = offset - if daylight { 3600 } else { 0 };
        // `_daylight`: whether the zone observes daylight time at all, seen
        // as a different offset half a year away.
        let later = host_local(now + 182 * 86400).map_or(offset, |local| local.offset);
        unsafe {
            *TIME_ZONE.daylight.get() = i32::from(later != offset);
            *TIME_ZONE.timezone.get() = -(standard as i32);
            for (index, name) in [zone.as_str(), zone.as_str()].into_iter().enumerate() {
                let buffer = &mut *TIME_ZONE.names[index].get();
                let bytes = &name.as_bytes()[..name.len().min(63)];
                buffer[..bytes.len()].copy_from_slice(bytes);
                (*TIME_ZONE.name_pointers.get())[index] = buffer.as_ptr();
            }
        }
    });
}

pub(super) extern "win64" fn native_crt_tzset() {
    set_time_zone_globals();
}

/// `__timezone()`: the address of `_timezone`.
pub(super) extern "win64" fn native_crt_timezone() -> *mut i32 {
    set_time_zone_globals();
    TIME_ZONE.timezone.get()
}

/// `__daylight()`: the address of `_daylight`.
pub(super) extern "win64" fn native_crt_daylight() -> *mut i32 {
    set_time_zone_globals();
    TIME_ZONE.daylight.get()
}

/// `__tzname()`: the address of `_tzname`, two C strings.
pub(super) extern "win64" fn native_crt_tzname() -> *mut *const u8 {
    set_time_zone_globals();
    TIME_ZONE.name_pointers.get().cast()
}

/// `_strftime_l(buffer, count, format, tm, locale)` / `strftime`: bytes
/// written without the terminator, or 0 when they do not fit.
pub(super) extern "win64" fn native_crt_strftime_l(
    output: *mut u8,
    count: usize,
    format: *const u8,
    tm: *const i32,
    _locale: *const u64,
) -> usize {
    if output.is_null() || count == 0 || format.is_null() || tm.is_null() {
        THREAD_CRT_ERRNO.with(|errno| errno.set(EINVAL));
        return 0;
    }
    let format = unsafe { std::ffi::CStr::from_ptr(format.cast()) }.to_string_lossy();
    let tm = unsafe { read_tm(tm) };
    let text = format_time(&format, &tm);
    let bytes: Vec<u8> = text
        .as_deref()
        .unwrap_or("")
        .chars()
        .map(|character| u8::try_from(u32::from(character)).unwrap_or(b'?'))
        .collect();
    if text.is_none() || bytes.len() + 1 > count {
        unsafe { output.write(0) };
        if text.is_none() {
            THREAD_CRT_ERRNO.with(|errno| errno.set(EINVAL));
        }
        return 0;
    }
    unsafe {
        output.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
        output.add(bytes.len()).write(0);
    }
    bytes.len()
}

pub(super) extern "win64" fn native_crt_strftime(
    output: *mut u8,
    count: usize,
    format: *const u8,
    tm: *const i32,
) -> usize {
    native_crt_strftime_l(output, count, format, tm, ptr::null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_time_and_strftime_use_the_host_zone() {
        let mut tm = [0i32; 9];
        assert_eq!(native_crt_localtime64_s(tm.as_mut_ptr(), &1_790_705_707), 0);
        let expected = host_local(1_790_705_707).unwrap();
        assert_eq!((tm[2], tm[3], tm[5]), (expected.hour, expected.day, expected.year));
        assert_eq!(native_crt_localtime64_s(tm.as_mut_ptr(), &-1), EINVAL);

        native_crt_gmtime64_s(tm.as_mut_ptr(), &1_790_705_707);
        let mut buffer = [0u8; 32];
        let written = native_crt_strftime(buffer.as_mut_ptr(), 32, b"%Y-%m-%d %H:%M\0".as_ptr(), tm.as_ptr());
        assert_eq!(&buffer[..written], b"2026-09-29 18:15");
        assert_eq!(native_crt_strftime(buffer.as_mut_ptr(), 4, b"%Y-%m\0".as_ptr(), tm.as_ptr()), 0);

        native_crt_tzset();
        let names = native_crt_tzname();
        let standard = unsafe { std::ffi::CStr::from_ptr((*names).cast()) };
        assert!(!standard.to_bytes().is_empty());
        assert!(unsafe { native_crt_timezone().read() }.abs() <= 14 * 3600);
    }

    #[test]
    fn gmtime_splits_epoch_seconds_into_utc_fields() {
        let mut tm = [0i32; 9];
        // 2026-09-29 18:15:07 UTC, a Tuesday, day 272 of the year.
        assert_eq!(native_crt_gmtime64_s(tm.as_mut_ptr(), &1_790_705_707), 0);
        assert_eq!(tm, [7, 15, 18, 29, 8, 126, 2, 271, 0]);
        // 2024-02-29 (leap day).
        assert_eq!(native_crt_gmtime64_s(tm.as_mut_ptr(), &1_709_164_800), 0);
        assert_eq!((tm[3], tm[4], tm[5], tm[7]), (29, 1, 124, 59));
        assert_eq!(native_crt_gmtime64_s(tm.as_mut_ptr(), &-1), EINVAL);
    }

    #[test]
    fn wcsftime_formats_c_locale_dates() {
        let mut tm = [0i32; 9];
        native_crt_gmtime64_s(tm.as_mut_ptr(), &1_790_705_707);
        let format: Vec<u16> = "%a %b %#d %Y %H:%M:%S (%j) %%".encode_utf16().chain([0]).collect();
        let mut buffer = [0u16; 64];
        let written = native_crt_wcsftime(buffer.as_mut_ptr(), 64, format.as_ptr(), tm.as_ptr());
        assert_eq!(
            String::from_utf16_lossy(&buffer[..written]),
            "Tue Sep 29 2026 18:15:07 (272) %"
        );
        let mut small = [0u16; 4];
        assert_eq!(native_crt_wcsftime(small.as_mut_ptr(), 4, format.as_ptr(), tm.as_ptr()), 0);
    }
}

unsafe extern "C" {
    fn mktime(tm: *mut HostTm) -> i64;
}

std::thread_local! {
    /// The per-thread `struct tm` msvcrt's `_gmtime64` and `_localtime64`
    /// return.
    static THREAD_TM: std::cell::UnsafeCell<[i32; 9]> = const { std::cell::UnsafeCell::new([0; 9]) };
}

/// msvcrt's `_gmtime64(time)`: the per-thread `struct tm`, or null for a
/// time outside its range, which reaches 12 hours before 1970 (the margin
/// msvcrt keeps for time zones).
pub(super) extern "win64" fn native_crt_gmtime64(time: *const i64) -> *mut i32 {
    if time.is_null() {
        return ptr::null_mut();
    }
    let seconds = unsafe { time.read_unaligned() };
    if !(-43_200..=32_535_215_999).contains(&seconds) {
        return ptr::null_mut();
    }
    THREAD_TM.with(|tm| {
        let output = tm.get().cast::<i32>();
        unsafe { write_tm(output, utc_from_epoch(seconds)) };
        output
    })
}

/// msvcrt's `_localtime64(time)`, in the local zone.
pub(super) extern "win64" fn native_crt_localtime64(time: *const i64) -> *mut i32 {
    THREAD_TM.with(|tm| {
        let output = tm.get().cast::<i32>();
        if native_crt_localtime64_s(output, time) == 0 { output } else { ptr::null_mut() }
    })
}

/// `_mktime64(tm)`: seconds since 1970 for a local broken-down time, with
/// `tm` normalized (weekday, day of the year and daylight time filled in);
/// -1 outside 1970-3000.
pub(super) extern "win64" fn native_crt_mktime64(tm: *mut i32) -> i64 {
    if tm.is_null() {
        return -1;
    }
    let given = unsafe { read_tm(tm) };
    let mut host = HostTm {
        second: given.second,
        minute: given.minute,
        hour: given.hour,
        day: given.day,
        month: given.month,
        year: given.year,
        weekday: given.weekday,
        year_day: given.year_day,
        daylight: given.daylight,
        offset: 0,
        zone: ptr::null(),
    };
    let seconds = unsafe { mktime(&mut host) };
    if !(0..=32_535_215_999).contains(&seconds) {
        return -1;
    }
    let normalized = Tm {
        second: host.second,
        minute: host.minute,
        hour: host.hour,
        day: host.day,
        month: host.month,
        year: host.year,
        weekday: host.weekday,
        year_day: host.year_day,
        daylight: i32::from(host.daylight > 0),
    };
    unsafe { write_tm(tm, normalized) };
    seconds
}
