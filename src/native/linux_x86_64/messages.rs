//! `FormatMessageA/W`: system messages for Win32, Winsock, and common
//! HRESULT codes (US English, as Windows words them), messages from a
//! string with `%1`-style inserts, and the output rules: a caller buffer
//! or a `LocalAlloc`ed one (`FORMAT_MESSAGE_ALLOCATE_BUFFER`).

use super::*;

const ALLOCATE_BUFFER: u32 = 0x100;
const IGNORE_INSERTS: u32 = 0x200;
const FROM_STRING: u32 = 0x400;
const FROM_HMODULE: u32 = 0x800;
const FROM_SYSTEM: u32 = 0x1000;
const ARGUMENT_ARRAY: u32 = 0x2000;
const MAX_WIDTH_MASK: u32 = 0xFF;

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_MR_MID_NOT_FOUND: u32 = 317;
const ERROR_RESOURCE_TYPE_NOT_FOUND: u32 = 1813;

/// The system message for a code, without its trailing line break.
fn system_message(code: u32) -> Option<&'static str> {
    // HRESULT_FROM_WIN32 values read as their Win32 code.
    let code = if code & 0xFFFF_0000 == 0x8007_0000 { code & 0xFFFF } else { code };
    Some(match code {
        0 => "The operation completed successfully.",
        1 => "Incorrect function.",
        2 => "The system cannot find the file specified.",
        3 => "The system cannot find the path specified.",
        4 => "The system cannot open the file.",
        5 => "Access is denied.",
        6 => "The handle is invalid.",
        8 => "Not enough memory resources are available to process this command.",
        13 => "The data is invalid.",
        14 => "Not enough memory resources are available to complete this operation.",
        15 => "The system cannot find the drive specified.",
        16 => "The directory cannot be removed.",
        17 => "The system cannot move the file to a different disk drive.",
        18 => "There are no more files.",
        19 => "The media is write protected.",
        21 => "The device is not ready.",
        32 => "The process cannot access the file because it is being used by another process.",
        33 => "The process cannot access the file because another process has locked a portion of the file.",
        38 => "Reached the end of the file.",
        50 => "The request is not supported.",
        53 => "The network path was not found.",
        80 => "The file exists.",
        87 => "The parameter is incorrect.",
        109 => "The pipe has been ended.",
        112 => "There is not enough space on the disk.",
        122 => "The data area passed to a system call is too small.",
        123 => "The filename, directory name, or volume label syntax is incorrect.",
        126 => "The specified module could not be found.",
        127 => "The specified procedure could not be found.",
        145 => "The directory is not empty.",
        183 => "Cannot create a file when that file already exists.",
        193 => "%1 is not a valid Win32 application.",
        203 => "The system could not find the environment option that was entered.",
        206 => "The filename or extension is too long.",
        232 => "The pipe is being closed.",
        233 => "No process is on the other end of the pipe.",
        258 => "The wait operation timed out.",
        259 => "No more data is available.",
        267 => "The directory name is invalid.",
        995 => "The I/O operation has been aborted because of either a thread exit or an application request.",
        996 => "Overlapped I/O event is not in a signaled state.",
        997 => "Overlapped I/O operation is in progress.",
        998 => "Invalid access to memory location.",
        1168 => "Element not found.",
        1223 => "The operation was canceled by the user.",
        1314 => "A required privilege is not held by the client.",
        10004 => "A blocking operation was interrupted by a call to WSACancelBlockingCall.",
        10009 => "The file handle supplied is not valid.",
        10013 => "An attempt was made to access a socket in a way forbidden by its access permissions.",
        10014 => "The system detected an invalid pointer address in attempting to use a pointer argument in a call.",
        10022 => "An invalid argument was supplied.",
        10024 => "Too many open sockets.",
        10035 => "A non-blocking socket operation could not be completed immediately.",
        10038 => "An operation was attempted on something that is not a socket.",
        10048 => "Only one usage of each socket address (protocol/network address/port) is normally permitted.",
        10049 => "The requested address is not valid in its context.",
        10051 => "A socket operation was attempted to an unreachable network.",
        10053 => "An established connection was aborted by the software in your host machine.",
        10054 => "An existing connection was forcibly closed by the remote host.",
        10060 => "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.",
        10061 => "No connection could be made because the target machine actively refused it.",
        10065 => "A socket operation was attempted to an unreachable host.",
        11001 => "No such host is known.",
        0x8009_2004 => "Cannot find object or property.",
        0x800B_0109 => "A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.",
        _ => return None,
    })
}

/// One `%n`-style insert's text: the argument read as `kind` (the text of
/// a `!kind!` suffix; strings by default).
fn insert(kind: &str, argument: u64, wide_strings: bool) -> String {
    let text = |pointer: u64, wide_chars: bool| -> String {
        if pointer == 0 {
            return "(null)".into();
        }
        if wide_chars {
            wide(pointer as *const u16).unwrap_or_default()
        } else {
            unsafe { ascii_z(pointer as *const u8) }.unwrap_or_default().to_string()
        }
    };
    match kind {
        // %s takes the caller's own width; S the other one.
        "" | "s" => text(argument, wide_strings),
        "S" => text(argument, !wide_strings),
        "ls" | "ws" => text(argument, true),
        "hs" => text(argument, false),
        "d" | "i" => (argument as i32).to_string(),
        "u" => (argument as u32).to_string(),
        "x" => format!("{:x}", argument as u32),
        "X" => format!("{:X}", argument as u32),
        "lld" | "I64d" => (argument as i64).to_string(),
        "llu" | "I64u" => argument.to_string(),
        "llx" | "I64x" => format!("{argument:x}"),
        "llX" | "I64X" => format!("{argument:X}"),
        "c" | "lc" | "wc" => char::from_u32(argument as u32).map(String::from).unwrap_or_default(),
        _ => format!("%{kind}"),
    }
}

/// Expand `%` escapes and inserts in a message. `argument(n)` reads the
/// n-th (1-based) argument; `None` leaves inserts as written.
fn expand(template: &str, argument: Option<&dyn Fn(usize) -> u64>, wide_strings: bool, max_width: u32) -> String {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        // Line breaks written in the text: kept unless a maximum width
        // (FORMAT_MESSAGE_MAX_WIDTH_MASK) asks for one line.
        if c == '\r' || c == '\n' {
            if max_width == MAX_WIDTH_MASK {
                if c == '\r' && chars.get(index + 1) == Some(&'\n') {
                    index += 1;
                }
                out.push(' ');
            } else {
                out.push(c);
            }
            index += 1;
            continue;
        }
        if c != '%' {
            out.push(c);
            index += 1;
            continue;
        }
        let Some(&next) = chars.get(index + 1) else {
            index += 1;
            continue;
        };
        if next.is_ascii_digit() && next != '0' {
            let start = index + 1;
            let mut end = start;
            while end < chars.len() && end - start < 2 && chars[end].is_ascii_digit() {
                end += 1;
            }
            let number: usize = chars[start..end].iter().collect::<String>().parse().unwrap_or(0);
            let mut kind = String::new();
            let mut after = end;
            if chars.get(end) == Some(&'!') {
                if let Some(close) = chars[end + 1..].iter().position(|c| *c == '!') {
                    kind = chars[end + 1..end + 1 + close].iter().collect();
                    after = end + 2 + close;
                }
            }
            match argument {
                Some(read) => out.push_str(&insert(&kind, read(number), wide_strings)),
                None => out.extend(&chars[index..after]),
            }
            index = after;
            continue;
        }
        match next {
            '0' => break,
            'n' => out.push_str("\r\n"),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'b' => out.push(' '),
            other => out.push(other),
        }
        index += 2;
    }
    out
}

/// The formatted message, or the error FormatMessage reports.
fn format_message(flags: u32, source: u64, message_id: u32, arguments: u64, wide_strings: bool) -> Result<String, u32> {
    let template = if flags & FROM_STRING != 0 {
        if source == 0 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        if wide_strings {
            wide(source as *const u16).ok_or(ERROR_INVALID_PARAMETER)?
        } else {
            unsafe { ascii_z(source as *const u8) }.ok_or(ERROR_INVALID_PARAMETER)?.to_string()
        }
    } else if flags & FROM_SYSTEM != 0 {
        // System messages end in a line break, as Windows' message table.
        format!("{}\r\n", system_message(message_id).ok_or(ERROR_MR_MID_NOT_FOUND)?)
    } else if flags & FROM_HMODULE != 0 {
        // Module message tables are not read.
        return Err(ERROR_RESOURCE_TYPE_NOT_FOUND);
    } else {
        return Err(ERROR_INVALID_PARAMETER);
    };
    let max_width = flags & MAX_WIDTH_MASK;
    if flags & IGNORE_INSERTS != 0 || arguments == 0 {
        return Ok(expand(&template, None, wide_strings, max_width));
    }
    // An argument array, or a va_list (a pointer to the 8-byte slots).
    let slots = if flags & ARGUMENT_ARRAY != 0 {
        arguments as *const u64
    } else {
        unsafe { (arguments as *const *const u64).read_unaligned() }
    };
    let read = move |number: usize| unsafe { slots.add(number.saturating_sub(1)).read_unaligned() };
    Ok(expand(&template, Some(&read), wide_strings, max_width))
}

/// Deliver `units` (with a terminator added) to the caller: into its
/// buffer, or a `LocalAlloc`ed one whose address goes to `output`.
fn deliver<T: Copy + Default>(units: Vec<T>, flags: u32, output: *mut T, size: u32) -> u32 {
    let length = units.len();
    if output.is_null() {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let target = if flags & ALLOCATE_BUFFER != 0 {
        let count = (length + 1).max(size as usize);
        let memory = native_heap_alloc(PROCESS_HEAP_HANDLE, 0x8, count * std::mem::size_of::<T>()) as *mut T;
        if memory.is_null() {
            return 0;
        }
        unsafe { output.cast::<*mut T>().write_unaligned(memory) };
        memory
    } else {
        if (size as usize) < length + 1 {
            native_set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        output
    };
    unsafe {
        target.copy_from_nonoverlapping(units.as_ptr(), length);
        target.add(length).write(T::default());
    }
    length as u32
}

pub(super) extern "win64" fn native_format_message_w(
    flags: u32,
    source: u64,
    message_id: u32,
    _language: u32,
    output: *mut u16,
    output_len: u32,
    arguments: u64,
) -> u32 {
    match format_message(flags, source, message_id, arguments, true) {
        Ok(text) => deliver(text.encode_utf16().collect(), flags, output, output_len),
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

pub(super) extern "win64" fn native_format_message_a(
    flags: u32,
    source: u64,
    message_id: u32,
    _language: u32,
    output: *mut u8,
    output_len: u32,
    arguments: u64,
) -> u32 {
    match format_message(flags, source, message_id, arguments, false) {
        // System messages are ASCII; other text goes out as Latin-1 bytes.
        Ok(text) => deliver(text.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect(), flags, output, output_len),
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system(code: u32, flags: u32) -> Result<String, u32> {
        format_message(FROM_SYSTEM | flags, 0, code, 0, true)
    }

    #[test]
    fn system_messages_end_in_a_line_break_and_unknown_codes_fail() {
        assert_eq!(system(2, IGNORE_INSERTS), Ok("The system cannot find the file specified.\r\n".into()));
        assert_eq!(system(0x8007_0005, IGNORE_INSERTS), Ok("Access is denied.\r\n".into()), "HRESULT_FROM_WIN32");
        assert_eq!(system(193, IGNORE_INSERTS), Ok("%1 is not a valid Win32 application.\r\n".into()));
        assert_eq!(system(0xDEAD, IGNORE_INSERTS), Err(ERROR_MR_MID_NOT_FOUND));
        assert_eq!(system(2, IGNORE_INSERTS | MAX_WIDTH_MASK), Ok("The system cannot find the file specified. ".into()));
    }

    #[test]
    fn strings_expand_inserts_from_arrays_and_escapes() {
        let template: Vec<u16> = "%1 has %2!d! items%n100%% done%0 ignored".encode_utf16().chain(Some(0)).collect();
        let name: Vec<u16> = "box".encode_utf16().chain(Some(0)).collect();
        let arguments = [name.as_ptr() as u64, 7u64];
        let text = format_message(FROM_STRING | ARGUMENT_ARRAY, template.as_ptr() as u64, 0, arguments.as_ptr() as u64, true);
        assert_eq!(text, Ok("box has 7 items\r\n100% done".into()));
        // A va_list is a pointer to the argument slots.
        let va_list = arguments.as_ptr();
        let text = format_message(FROM_STRING, template.as_ptr() as u64, 0, &va_list as *const _ as u64, true);
        assert_eq!(text, Ok("box has 7 items\r\n100% done".into()));
        let text = format_message(FROM_STRING | IGNORE_INSERTS, template.as_ptr() as u64, 0, 0, true);
        assert_eq!(text, Ok("%1 has %2!d! items\r\n100% done".into()));
    }

    #[test]
    fn output_goes_to_the_buffer_or_a_local_allocation() {
        let mut small = [0u16; 8];
        assert_eq!(native_format_message_w(FROM_SYSTEM, 0, 2, 0, small.as_mut_ptr(), 8, 0), 0);
        assert_eq!(native_get_last_error(), ERROR_INSUFFICIENT_BUFFER);
        let mut buffer = [0u16; 128];
        let length = native_format_message_w(FROM_SYSTEM | IGNORE_INSERTS, 0, 5, 0, buffer.as_mut_ptr(), 128, 0);
        assert_eq!(String::from_utf16_lossy(&buffer[..length as usize]), "Access is denied.\r\n");
        let mut ansi = [0u8; 64];
        let length = native_format_message_a(FROM_SYSTEM | IGNORE_INSERTS, 0, 87, 0, ansi.as_mut_ptr(), 64, 0);
        assert_eq!(&ansi[..length as usize], b"The parameter is incorrect.\r\n");
    }
}
