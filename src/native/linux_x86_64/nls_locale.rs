//! NLS locale data (`GetLocaleInfoEx` and the name/LCID conversions) for the
//! locales winrun reports: the user and system locale `en-US`, its neutral
//! parent `en`, and the invariant locale. The values are those of Windows 10.

use super::*;

const LOCALE_NOUSEROVERRIDE: u32 = 0x8000_0000;
const LOCALE_USE_CP_ACP: u32 = 0x4000_0000;
const LOCALE_RETURN_NUMBER: u32 = 0x2000_0000;
const LOCALE_RETURN_GENITIVE_NAMES: u32 = 0x1000_0000;
const LOCALE_ALLOW_NEUTRAL_NAMES: u32 = 0x0800_0000;
const LCTYPE_FLAGS: u32 = LOCALE_NOUSEROVERRIDE
    | LOCALE_USE_CP_ACP
    | LOCALE_RETURN_NUMBER
    | LOCALE_RETURN_GENITIVE_NAMES
    | LOCALE_ALLOW_NEUTRAL_NAMES;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_FLAGS: u32 = 1004;

pub(super) const LCID_EN_US: u32 = 0x0409;
const LCID_EN: u32 = 0x0009;
const LCID_INVARIANT: u32 = 0x007f;
const LOCALE_USER_DEFAULT: u32 = 0x0400;
const LOCALE_SYSTEM_DEFAULT: u32 = 0x0800;
const LOCALE_CUSTOM_DEFAULT: u32 = 0x0c00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Locale {
    EnUs,
    En,
    Invariant,
}

impl Locale {
    /// A locale name as `GetLocaleInfoEx` accepts it: null or
    /// `!x-sys-default-locale` for the default, `""` for invariant.
    fn from_name(name: Option<&str>) -> Option<Self> {
        match name {
            None => Some(Self::EnUs),
            Some(name) if name.eq_ignore_ascii_case("!x-sys-default-locale") => Some(Self::EnUs),
            Some("") => Some(Self::Invariant),
            Some(name) if name.eq_ignore_ascii_case("en-US") => Some(Self::EnUs),
            Some(name) if name.eq_ignore_ascii_case("en") => Some(Self::En),
            _ => None,
        }
    }

    fn from_lcid(lcid: u32) -> Option<Self> {
        match lcid {
            0 | LOCALE_USER_DEFAULT | LOCALE_SYSTEM_DEFAULT | LOCALE_CUSTOM_DEFAULT | LCID_EN_US => {
                Some(Self::EnUs)
            }
            LCID_EN => Some(Self::En),
            LCID_INVARIANT => Some(Self::Invariant),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::EnUs => "en-US",
            Self::En => "en",
            Self::Invariant => "",
        }
    }

    fn lcid(self) -> u32 {
        match self {
            Self::EnUs => LCID_EN_US,
            Self::En => LCID_EN,
            Self::Invariant => LCID_INVARIANT,
        }
    }
}

const DAY_NAMES: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const ABBREVIATED_DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const SHORTEST_DAY_NAMES: [&str; 7] = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];
const MONTH_NAMES: [&str; 12] = [
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
    "November", "December",
];
const ABBREVIATED_MONTH_NAMES: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// A locale value: text, or a number that `LOCALE_RETURN_NUMBER` returns
/// as a `DWORD` (and that is otherwise formatted in decimal, or as four hex
/// digits for language identifiers).
enum Value {
    Text(&'static str),
    Number(u32),
    Hex(u32),
}

/// The value of `lctype` (flags removed) for `locale`, or `None` when the
/// locale has no such datum.
fn locale_value(locale: Locale, lctype: u32) -> Option<Value> {
    use Value::{Hex, Number, Text};
    let invariant = locale == Locale::Invariant;
    let neutral = locale == Locale::En;
    Some(match lctype {
        0x01 => Hex(locale.lcid()), // LOCALE_ILANGUAGE
        0x02 | 0x72 | 0x73 => Text(match locale {
            Locale::EnUs => "English (United States)",
            Locale::En => "English",
            Locale::Invariant => "Invariant Language (Invariant Country)",
        }), // SLOCALIZEDDISPLAYNAME, SENGLISHDISPLAYNAME, SNATIVEDISPLAYNAME
        0x03 => Text(if invariant { "IVL" } else { "ENU" }), // SABBREVLANGNAME
        0x04 | 0x6f | 0x1001 => Text(if invariant { "Invariant Language" } else { "English" }),
        0x05 => Number(if invariant { 0 } else { 1 }), // ICOUNTRY
        0x06 | 0x08 | 0x1002 => Text(if invariant {
            "Invariant Country"
        } else {
            "United States"
        }), // SLOCALIZEDCOUNTRYNAME, SNATIVECOUNTRYNAME, SENGLISHCOUNTRYNAME
        0x07 => Text(if invariant { "IVC" } else { "USA" }), // SABBREVCTRYNAME
        0x09 => Hex(LCID_EN_US),                              // IDEFAULTLANGUAGE
        0x0a => Number(1),                                    // IDEFAULTCOUNTRY
        0x0b => Number(437),                                  // IDEFAULTCODEPAGE
        0x1004 => Number(1252),                               // IDEFAULTANSICODEPAGE
        0x1011 => Number(10000),                              // IDEFAULTMACCODEPAGE
        0x1012 => Number(37),                                 // IDEFAULTEBCDICCODEPAGE
        0x0c => Text(","),                                    // SLIST
        0x0d => Number(if invariant { 0 } else { 1 }),        // IMEASURE: U.S.
        0x0e | 0x16 => Text("."),                             // SDECIMAL, SMONDECIMALSEP
        0x0f | 0x17 => Text(","),                             // STHOUSAND, SMONTHOUSANDSEP
        0x10 | 0x18 => Text("3;0"),                           // SGROUPING, SMONGROUPING
        0x11 | 0x19 | 0x1a => Number(2), // IDIGITS, ICURRDIGITS, IINTLCURRDIGITS
        0x12 => Number(1),               // ILZERO
        0x1010 => Number(1),             // INEGNUMBER: -1.1
        0x13 => Text("0123456789"),      // SNATIVEDIGITS
        0x14 => Text(if invariant { "\u{a4}" } else { "$" }), // SCURRENCY
        0x15 => Text(if invariant { "XDR" } else { "USD" }), // SINTLSYMBOL
        0x1007 => Text(if invariant {
            "International Monetary Fund"
        } else {
            "US Dollar"
        }), // SENGCURRNAME
        0x1008 => Text(if invariant { "International Monetary Fund" } else { "US Dollar" }),
        0x1b => Number(0),                                   // ICURRENCY: $1.1
        0x1c => Number(0),                                   // INEGCURR: ($1.1)
        0x1d => Text("/"),                                   // SDATE
        0x1e => Text(":"),                                   // STIME
        0x1f => Text(if invariant { "MM/dd/yyyy" } else { "M/d/yyyy" }), // SSHORTDATE
        0x20 => Text(if invariant { "dddd, dd MMMM yyyy" } else { "dddd, MMMM d, yyyy" }),
        0x1003 => Text(if invariant { "HH:mm:ss" } else { "h:mm:ss tt" }), // STIMEFORMAT
        0x79 => Text(if invariant { "HH:mm" } else { "h:mm tt" }),         // SSHORTTIME
        0x1006 => Text(if invariant { "yyyy MMMM" } else { "MMMM yyyy" }), // SYEARMONTH
        0x78 | 0x7c => Text("MMMM d"), // SMONTHDAY, SRELATIVELONGDATE
        0x5d => Text("hh:mm:ss"),      // SDURATION
        0x21 | 0x22 => Number(0),      // IDATE, ILDATE: month-day-year
        0x23 => Number(if invariant { 1 } else { 0 }), // ITIME: 12-hour
        0x1005 => Number(0),           // ITIMEMARKPOSN: suffix
        0x24 => Number(1),             // ICENTURY
        0x25 => Number(if invariant { 1 } else { 0 }), // ITLZERO
        0x26 | 0x27 => Number(if invariant { 1 } else { 0 }), // IDAYLZERO, IMONLZERO
        0x28 => Text("AM"),            // S1159
        0x29 => Text("PM"),            // S2359
        0x7e => Text("a"),             // SSHORTESTAM
        0x7f => Text("p"),             // SSHORTESTPM
        0x1009 => Number(1),           // ICALENDARTYPE: Gregorian
        0x100b => Number(0),           // IOPTIONALCALENDAR
        0x100c => Number(if invariant { 0 } else { 6 }), // IFIRSTDAYOFWEEK: Sunday
        0x100d => Number(0),           // IFIRSTWEEKOFYEAR
        0x2a..=0x30 => Text(DAY_NAMES[(lctype - 0x2a) as usize]),
        0x31..=0x37 => Text(ABBREVIATED_DAY_NAMES[(lctype - 0x31) as usize]),
        0x60..=0x66 => Text(SHORTEST_DAY_NAMES[(lctype - 0x60) as usize]),
        0x38..=0x43 => Text(MONTH_NAMES[(lctype - 0x38) as usize]),
        0x44..=0x4f => Text(ABBREVIATED_MONTH_NAMES[(lctype - 0x44) as usize]),
        0x100e | 0x100f => Text(""),   // 13th month names
        0x50 => Text(if invariant { "+" } else { "" }), // SPOSITIVESIGN
        0x51 => Text("-"),             // SNEGATIVESIGN
        0x52 => Number(3),             // IPOSSIGNPOSN
        0x53 => Number(0),             // INEGSIGNPOSN
        0x54 | 0x56 => Number(1),      // IPOSSYMPRECEDES, INEGSYMPRECEDES
        0x55 | 0x57 => Number(0),      // IPOSSEPBYSPACE, INEGSEPBYSPACE
        0x59 => Text(if invariant { "iv" } else { "en" }), // SISO639LANGNAME
        0x67 => Text(if invariant { "ivl" } else { "eng" }), // SISO639LANGNAME2
        0x5a => Text(if invariant { "IV" } else { "US" }), // SISO3166CTRYNAME
        0x68 => Text(if invariant { "ivc" } else { "USA" }), // SISO3166CTRYNAME2
        0x5b => Number(if invariant { 0 } else { 244 }), // IGEOID
        0x5c => Text(locale.name()),   // SNAME
        0x6c => Text("Latn;"),         // SSCRIPTS
        0x6d => Text(match locale {
            Locale::EnUs => "en",
            Locale::En | Locale::Invariant => "",
        }), // SPARENT
        0x6e => Text(if neutral { "en" } else { locale.name() }), // SCONSOLEFALLBACKNAME
        0x69 => Text("NaN"),                                     // SNAN
        0x6a => Text("\u{221e}"),                                // SPOSINFINITY
        0x6b => Text("-\u{221e}"),                               // SNEGINFINITY
        0x70 => Number(0),                                       // IREADINGLAYOUT
        0x71 => Number(u32::from(neutral)),                      // INEUTRAL
        0x74 => Number(if invariant { 0 } else { 1 }),           // INEGATIVEPERCENT
        0x75 => Number(if invariant { 0 } else { 1 }),           // IPOSITIVEPERCENT
        0x76 => Text("%"),                                       // SPERCENT
        0x77 => Text("\u{2030}"),                                // SPERMILLE
        0x7a => Text("dflt"),                                    // SOPENTYPELANGUAGETAG
        0x7b => Text(locale.name()),                             // SSORTLOCALE
        0x7d => Number(0),                                       // ICONSTRUCTEDLOCALE
        0x100a => Number(1),                                     // IPAPERSIZE: letter
        0x1013 => Text("Default"),                               // SSORTNAME
        0x1014 => Number(1),                                     // IDIGITSUBSTITUTION: none
        0x5e => Text("0409:00000409"),                           // SKEYBOARDSTOINSTALL
        0x666 | 0x999 => Number(0), // IUSEUTF8LEGACYACP, IUSEUTF8LEGACYOEMCP
        _ => return None,
    })
}

/// Copy `units` (with a terminator) to a caller buffer the Win32 way:
/// capacity 0 asks for the length; a short buffer fails with
/// `ERROR_INSUFFICIENT_BUFFER`.
fn write_counted(units: &[u16], output: *mut u16, capacity: i32) -> i32 {
    let needed = units.len() + 1;
    if capacity == 0 {
        return needed as i32;
    }
    if capacity < 0 || (capacity as usize) < needed || output.is_null() {
        native_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe {
        ptr::copy_nonoverlapping(units.as_ptr(), output, units.len());
        output.add(units.len()).write(0);
    }
    needed as i32
}

fn locale_info(locale: Locale, lctype: u32, output: *mut u16, capacity: i32) -> i32 {
    let kind = lctype & !LCTYPE_FLAGS;
    let Some(value) = locale_value(locale, kind) else {
        native_set_last_error(ERROR_INVALID_FLAGS);
        return 0;
    };
    if lctype & LOCALE_RETURN_NUMBER != 0 {
        let (Value::Number(number) | Value::Hex(number)) = value else {
            native_set_last_error(ERROR_INVALID_FLAGS);
            return 0;
        };
        // The DWORD occupies two WCHARs of the buffer.
        if capacity == 0 {
            return 2;
        }
        if capacity < 2 || output.is_null() {
            native_set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        unsafe { output.cast::<u32>().write_unaligned(number) };
        return 2;
    }
    let text = match value {
        Value::Text(text) => text.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Hex(number) => format!("{number:04x}"),
    };
    let units: Vec<u16> = text.encode_utf16().collect();
    write_counted(&units, output, capacity)
}

/// `GetLocaleInfoEx(name, lctype, buffer, capacity)`.
pub(super) extern "win64" fn native_get_locale_info_ex(
    name: *const u16,
    lctype: u32,
    output: *mut u16,
    capacity: i32,
) -> i32 {
    let name = if name.is_null() { None } else { wide(name) };
    if native_diagnostic_enabled() {
        eprintln!("native GetLocaleInfoEx locale={name:?} kind={lctype:#x}");
    }
    let Some(locale) = Locale::from_name(name.as_deref()) else {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    locale_info(locale, lctype, output, capacity)
}

/// `GetLocaleInfoW(lcid, lctype, buffer, capacity)`.
pub(super) extern "win64" fn native_get_locale_info_w(
    lcid: u32,
    lctype: u32,
    output: *mut u16,
    capacity: i32,
) -> i32 {
    let Some(locale) = Locale::from_lcid(lcid) else {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    locale_info(locale, lctype, output, capacity)
}

/// `LocaleNameToLCID(name, flags)`: 0 for an unknown name.
pub(super) extern "win64" fn native_locale_name_to_lcid(name: *const u16, _flags: u32) -> u32 {
    let name = if name.is_null() { None } else { wide(name) };
    match Locale::from_name(name.as_deref()) {
        Some(locale) => locale.lcid(),
        None => {
            native_set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
    }
}

/// `LCIDToLocaleName(lcid, buffer, capacity, flags)`.
pub(super) extern "win64" fn native_lcid_to_locale_name(
    lcid: u32,
    output: *mut u16,
    capacity: i32,
    _flags: u32,
) -> i32 {
    let Some(locale) = Locale::from_lcid(lcid) else {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let units: Vec<u16> = locale.name().encode_utf16().collect();
    write_counted(&units, output, capacity)
}

/// `IsValidLocaleName(name)`.
pub(super) extern "win64" fn native_is_valid_locale_name(name: *const u16) -> i32 {
    i32::from(!name.is_null() && Locale::from_name(wide(name).as_deref()).is_some())
}

/// `ResolveLocaleName(name, buffer, capacity)`: the closest supported
/// specific locale; any English name resolves to `en-US`.
pub(super) extern "win64" fn native_resolve_locale_name(
    name: *const u16,
    output: *mut u16,
    capacity: i32,
) -> i32 {
    let name = if name.is_null() { None } else { wide(name) };
    let resolved = match name.as_deref() {
        None => "en-US",
        Some(name) if name.is_empty() => "",
        Some(name)
            if name.eq_ignore_ascii_case("en")
                || name.get(..3).is_some_and(|prefix| prefix.eq_ignore_ascii_case("en-")) =>
        {
            "en-US"
        }
        Some(_) => "",
    };
    let units: Vec<u16> = resolved.encode_utf16().collect();
    write_counted(&units, output, capacity)
}

const MUI_LANGUAGE_ID: u32 = 0x4;

/// `Get{User,System,Thread,Process}PreferredUILanguages(flags, count,
/// buffer, length)`: the single UI language, `en-US` (or `0409` with
/// `MUI_LANGUAGE_ID`), as a double-null-terminated list.
pub(super) extern "win64" fn native_get_preferred_ui_languages(
    flags: u32,
    count: *mut u32,
    output: *mut u16,
    length: *mut u32,
) -> i32 {
    if count.is_null() || length.is_null() {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let language = if flags & MUI_LANGUAGE_ID != 0 { "0409" } else { "en-US" };
    let units: Vec<u16> = language.encode_utf16().chain([0, 0]).collect();
    let capacity = unsafe { length.read() } as usize;
    unsafe {
        count.write(1);
        length.write(units.len() as u32);
    }
    if output.is_null() {
        return 1;
    }
    if capacity < units.len() {
        native_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { ptr::copy_nonoverlapping(units.as_ptr(), output, units.len()) };
    1
}

/// `GetUserDefaultUILanguage` / `GetSystemDefaultUILanguage` and the
/// `LANGID` variants: English (United States).
pub(super) extern "win64" fn native_get_default_ui_language() -> u16 {
    LCID_EN_US as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    fn text(locale: &str, lctype: u32) -> Option<String> {
        let locale = name(locale);
        let length = native_get_locale_info_ex(locale.as_ptr(), lctype, ptr::null_mut(), 0);
        if length == 0 {
            return None;
        }
        let mut buffer = vec![0u16; length as usize];
        assert_eq!(native_get_locale_info_ex(locale.as_ptr(), lctype, buffer.as_mut_ptr(), length), length);
        Some(String::from_utf16_lossy(&buffer[..length as usize - 1]))
    }

    fn number(locale: &str, lctype: u32) -> Option<u32> {
        let locale = name(locale);
        let mut value = 0u32;
        let written = native_get_locale_info_ex(
            locale.as_ptr(),
            lctype | LOCALE_RETURN_NUMBER,
            (&mut value as *mut u32).cast(),
            2,
        );
        (written == 2).then_some(value)
    }

    #[test]
    fn describes_en_us_and_its_neutral_parent() {
        assert_eq!(text("en-us", 0x5c).as_deref(), Some("en-US"), "SNAME is canonical");
        assert_eq!(number("en-US", 0x71), Some(0), "specific");
        assert_eq!(number("en", 0x71), Some(1), "neutral");
        assert_eq!(text("en-US", 0x6d).as_deref(), Some("en"));
        assert_eq!(text("en", 0x6d).as_deref(), Some(""));
        assert_eq!(text("en-US", 0x1f).as_deref(), Some("M/d/yyyy"));
        assert_eq!(text("en-US", 0x2a).as_deref(), Some("Monday"));
        assert_eq!(text("en-US", 0x4f).as_deref(), Some("Dec"));
        assert_eq!(number("en-US", 0x100c), Some(6), "weeks start on Sunday");
        assert_eq!(number("en-US", 0x1004), Some(1252));
        assert_eq!(number("en-US", 0x01), Some(0x0409), "ILANGUAGE as a number");
        assert_eq!(text("en-US", 0x01).as_deref(), Some("0409"), "ILANGUAGE as hex text");
        // Numbers are formatted as text without LOCALE_RETURN_NUMBER.
        assert_eq!(text("en-US", 0x1004).as_deref(), Some("1252"));
        assert_eq!(text("", 0x14).as_deref(), Some("\u{a4}"), "invariant currency");
    }

    #[test]
    fn rejects_unknown_locales_types_and_short_buffers() {
        assert_eq!(text("fr-FR", 0x5c), None);
        assert_eq!(native_get_last_error(), ERROR_INVALID_PARAMETER);
        assert_eq!(text("en-US", 0xfff), None);
        assert_eq!(native_get_last_error(), ERROR_INVALID_FLAGS);
        // Text types cannot be returned as numbers.
        assert_eq!(number("en-US", 0x5c), None);
        let locale = name("en-US");
        let mut short = [0u16; 3];
        assert_eq!(native_get_locale_info_ex(locale.as_ptr(), 0x5c, short.as_mut_ptr(), 3), 0);
        assert_eq!(native_get_last_error(), ERROR_INSUFFICIENT_BUFFER);
        // The null name is the user default locale.
        assert_eq!(native_get_locale_info_ex(ptr::null(), 0x5c, ptr::null_mut(), 0), 6);
    }

    #[test]
    fn reports_en_us_as_the_preferred_ui_language() {
        let (mut count, mut length) = (0u32, 0u32);
        assert_eq!(native_get_preferred_ui_languages(0x8, &mut count, ptr::null_mut(), &mut length), 1);
        assert_eq!((count, length), (1, 7));
        let mut buffer = [0xffffu16; 7];
        assert_eq!(native_get_preferred_ui_languages(0x8, &mut count, buffer.as_mut_ptr(), &mut length), 1);
        assert_eq!(String::from_utf16_lossy(&buffer), "en-US\0\0");
        let mut short = [0u16; 3];
        length = 3;
        assert_eq!(native_get_preferred_ui_languages(0x4, &mut count, short.as_mut_ptr(), &mut length), 0);
        assert_eq!(length, 6, "0409 plus two terminators");
        assert_eq!(native_get_default_ui_language(), 0x0409);
    }

    #[test]
    fn converts_between_names_and_lcids() {
        assert_eq!(native_locale_name_to_lcid(name("en-US").as_ptr(), 0), 0x0409);
        assert_eq!(native_locale_name_to_lcid(name("xx-YY").as_ptr(), 0), 0);
        let mut buffer = [0u16; 16];
        assert_eq!(native_lcid_to_locale_name(0x0409, buffer.as_mut_ptr(), 16, 0), 6);
        assert_eq!(String::from_utf16_lossy(&buffer[..5]), "en-US");
        assert_eq!(native_lcid_to_locale_name(LOCALE_USER_DEFAULT, buffer.as_mut_ptr(), 16, 0), 6);
        assert_eq!(native_lcid_to_locale_name(0x040c, buffer.as_mut_ptr(), 16, 0), 0);
        let mut value = [0u16; 8];
        assert_eq!(native_get_locale_info_w(0x0409, 0x59, value.as_mut_ptr(), 8), 3);
        assert_eq!(String::from_utf16_lossy(&value[..2]), "en");
        assert_eq!(native_is_valid_locale_name(name("en").as_ptr()), 1);
        assert_eq!(native_is_valid_locale_name(name("de-DE").as_ptr()), 0);
        assert_eq!(native_resolve_locale_name(name("en-GB").as_ptr(), buffer.as_mut_ptr(), 16), 6);
        assert_eq!(native_resolve_locale_name(name("de-DE").as_ptr(), buffer.as_mut_ptr(), 16), 1);
    }
}
