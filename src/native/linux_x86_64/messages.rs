//! Windows messages compatibility APIs for the Linux native backend.

use super::*;

pub(super) extern "win64" fn native_format_message_w(
    _flags: u32,
    _source: u64,
    _message_id: u32,
    _language: u32,
    output: *mut u16,
    output_len: u32,
    _arguments: u64,
) -> u32 {
    const MESSAGE: &[u16] = &[
        b'W' as u16,
        b'i' as u16,
        b'n' as u16,
        b'C' as u16,
        b'L' as u16,
        b'I' as u16,
        b' ' as u16,
        b'n' as u16,
        b'a' as u16,
        b't' as u16,
        b'i' as u16,
        b'v' as u16,
        b'e' as u16,
        b' ' as u16,
        b'e' as u16,
        b'r' as u16,
        b'r' as u16,
        b'o' as u16,
        b'r' as u16,
        b'.' as u16,
        b'\r' as u16,
        b'\n' as u16,
    ];
    if output.is_null() || output_len <= MESSAGE.len() as u32 {
        return 0;
    }
    unsafe {
        output.copy_from_nonoverlapping(MESSAGE.as_ptr(), MESSAGE.len());
        output.add(MESSAGE.len()).write(0)
    };
    MESSAGE.len() as u32
}
pub(super) extern "win64" fn native_format_message_a(
    flags: u32,
    _source: u64,
    _message_id: u32,
    _language: u32,
    output: *mut u8,
    output_len: u32,
    _arguments: u64,
) -> u32 {
    const MESSAGE: &[u8] = b"WinCLI native error.\r\n";
    if flags & 0x100 != 0 || output.is_null() || output_len <= MESSAGE.len() as u32 {
        native_set_last_error(122);
        return 0;
    }
    unsafe {
        output.copy_from_nonoverlapping(MESSAGE.as_ptr(), MESSAGE.len());
        output.add(MESSAGE.len()).write(0);
    }
    MESSAGE.len() as u32
}
