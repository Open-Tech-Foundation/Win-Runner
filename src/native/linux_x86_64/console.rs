//! Windows console API shims over the Win-Runner terminal and standard handles.

use super::*;

pub(super) extern "win64" fn native_get_console_mode(handle: u64, mode: *mut u32) -> i32 {
    if host_standard_fd(handle).is_none() || mode.is_null() {
        return 0;
    }
    // ENABLE_PROCESSED_OUTPUT. The native child exposes only its three
    // standard descriptors as consoles.
    unsafe { mode.write(1) };
    1
}
pub(super) extern "win64" fn native_get_console_output_cp() -> u32 {
    native_get_acp()
}
pub(super) extern "win64" fn native_get_console_cursor_info(handle: u64, output: *mut u8) -> i32 {
    if host_standard_fd(handle).is_none() || output.is_null() {
        return 0;
    }
    // CONSOLE_CURSOR_INFO is { DWORD size; BOOL visible; }.
    unsafe {
        (output as *mut u32).write_unaligned(25);
        (output.add(4) as *mut i32).write_unaligned(1);
    }
    1
}
pub(super) extern "win64" fn native_set_console_cursor_info(handle: u64, input: *const u8) -> i32 {
    if host_standard_fd(handle).is_none() || input.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let size = unsafe { (input as *const u32).read_unaligned() };
    let visible = unsafe { (input.add(4) as *const i32).read_unaligned() };
    if !(1..=100).contains(&size) || !matches!(visible, 0 | 1) {
        native_set_last_error(87);
        return 0;
    }
    // Cursor visibility and shape are owned by the host terminal.
    1
}
pub(super) extern "win64" fn native_set_console_cursor_position(handle: u64, position: u32) -> i32 {
    let Some(fd @ (1 | 2)) = host_standard_fd(handle) else {
        native_set_last_error(6);
        return 0;
    };
    let x = position as u16 as i16;
    let y = (position >> 16) as u16 as i16;
    let (columns, rows) = crate::control::terminal_size();
    if !(0..columns.min(i16::MAX as usize) as i16).contains(&x)
        || !(0..rows.min(i16::MAX as usize) as i16).contains(&y)
    {
        native_set_last_error(87);
        return 0;
    }
    let sequence = format!("\x1b[{};{}H", y + 1, x + 1);
    if unsafe { write(fd, sequence.as_ptr().cast(), sequence.len()) } == sequence.len() as isize {
        1
    } else {
        native_set_last_error(5);
        0
    }
}
pub(super) extern "win64" fn native_get_console_screen_buffer_info(
    handle: u64,
    output: *mut u8,
) -> i32 {
    if host_standard_fd(handle).is_none() || output.is_null() {
        return 0;
    }
    let (columns, rows) = crate::control::terminal_size();
    let columns = columns.min(i16::MAX as usize) as i16;
    let rows = rows.min(i16::MAX as usize) as i16;
    unsafe {
        std::ptr::write_bytes(output, 0, 22);
        (output as *mut i16).write_unaligned(columns);
        (output.add(2) as *mut i16).write_unaligned(rows);
        (output.add(8) as *mut u16).write_unaligned(7);
        (output.add(14) as *mut i16).write_unaligned(columns - 1);
        (output.add(16) as *mut i16).write_unaligned(rows - 1);
        (output.add(18) as *mut i16).write_unaligned(columns);
        (output.add(20) as *mut i16).write_unaligned(rows);
    }
    1
}
pub(super) extern "win64" fn native_set_console_mode(handle: u64, _mode: u32) -> i32 {
    host_standard_fd(handle).is_some() as i32
}
pub(super) extern "win64" fn native_set_console_screen_buffer_size(handle: u64, size: u32) -> i32 {
    let width = size as u16 as i16;
    let height = (size >> 16) as u16 as i16;
    if host_standard_fd(handle).is_none() || width <= 0 || height <= 0 {
        native_set_last_error(87);
        return 0;
    }
    // The host terminal owns the physical dimensions; accept a valid
    // guest buffer size without attempting to resize that terminal.
    1
}
pub(super) extern "win64" fn native_set_console_window_info(
    handle: u64,
    _absolute: i32,
    rect: *const u8,
) -> i32 {
    if host_standard_fd(handle).is_none() || rect.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let left = unsafe { (rect as *const i16).read_unaligned() };
    let top = unsafe { (rect.add(2) as *const i16).read_unaligned() };
    let right = unsafe { (rect.add(4) as *const i16).read_unaligned() };
    let bottom = unsafe { (rect.add(6) as *const i16).read_unaligned() };
    if right < left || bottom < top {
        native_set_last_error(87);
        return 0;
    }
    // Window geometry belongs to the host terminal; validate the guest
    // rectangle without attempting to resize the host window.
    1
}
pub(super) extern "win64" fn native_set_console_active_screen_buffer(handle: u64) -> i32 {
    if host_standard_fd(handle).is_some() {
        1
    } else {
        native_set_last_error(6);
        0
    }
}
pub(super) extern "win64" fn native_set_console_title_w(title: *const u16) -> i32 {
    if title.is_null() {
        native_set_last_error(87);
        return 0;
    }
    1
}

pub(super) extern "win64" fn native_write_console_w(
    handle: u64,
    text: *const u16,
    len: u32,
    written: *mut u32,
    _reserved: u64,
) -> i32 {
    if !matches!(host_standard_fd(handle), Some(1 | 2)) || (text.is_null() && len != 0) {
        return 0;
    }
    let units = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(text, len as usize) }
    };
    let encoded = String::from_utf16_lossy(units);
    let Some(fd) = host_standard_fd(handle) else {
        return 0;
    };
    if unsafe { write(fd, encoded.as_ptr().cast(), encoded.len()) } < 0 {
        return 0;
    }
    if !written.is_null() {
        unsafe { written.write(len) };
    }
    1
}

pub(super) extern "win64" fn native_write_console_output_a(
    handle: u64,
    cells: *const u8,
    dimensions: u32,
    source: u32,
    region: *mut u8,
) -> i32 {
    let Some(fd @ (1 | 2)) = host_standard_fd(handle) else {
        native_set_last_error(6);
        return 0;
    };
    if cells.is_null() || region.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let width = dimensions as u16 as i16;
    let height = (dimensions >> 16) as u16 as i16;
    let source_x = source as u16 as i16;
    let source_y = (source >> 16) as u16 as i16;
    let (mut left, mut top, mut right, mut bottom) = unsafe {
        (
            region.cast::<i16>().read_unaligned(),
            region.add(2).cast::<i16>().read_unaligned(),
            region.add(4).cast::<i16>().read_unaligned(),
            region.add(6).cast::<i16>().read_unaligned(),
        )
    };
    if width <= 0 || height <= 0 || source_x < 0 || source_y < 0 || right < left || bottom < top {
        native_set_last_error(87);
        return 0;
    }
    let original_left = left;
    let original_top = top;
    left = left.max(0);
    top = top.max(0);
    right = right.min(width - 1);
    bottom = bottom.min(height - 1);
    if right < left || bottom < top {
        native_set_last_error(87);
        return 0;
    }
    let output_width = (right - left + 1) as usize;
    let output_height = (bottom - top + 1) as usize;
    if output_width.saturating_mul(output_height) > 2_000_000
        || source_x as usize + (left - original_left) as usize + output_width > width as usize
        || source_y as usize + (top - original_top) as usize + output_height > height as usize
    {
        native_set_last_error(87);
        return 0;
    }
    unsafe {
        region.cast::<i16>().write_unaligned(left);
        region.add(2).cast::<i16>().write_unaligned(top);
        region.add(4).cast::<i16>().write_unaligned(right);
        region.add(6).cast::<i16>().write_unaligned(bottom);
    }
    let source_left = source_x as usize + (left - original_left) as usize;
    let source_top = source_y as usize + (top - original_top) as usize;
    let mut terminal = Vec::with_capacity(output_height * (output_width + 32));
    for row in 0..output_height {
        terminal.extend_from_slice(
            format!(
                "\x1b[{};{}H\x1b[0m",
                top as usize + row + 1,
                left as usize + 1
            )
            .as_bytes(),
        );
        let mut style = u16::MAX;
        for column in 0..output_width {
            let index = ((source_top + row) * width as usize + source_left + column) * 4;
            let character = unsafe { cells.add(index).read() };
            let attributes = unsafe { cells.add(index + 2).cast::<u16>().read_unaligned() };
            if attributes != style {
                style = attributes;
                let foreground = (attributes & 0x0f) as u8;
                let background = ((attributes >> 4) & 0x0f) as u8;
                let fg = if foreground & 8 != 0 {
                    90 + (foreground & 7)
                } else {
                    30 + foreground
                };
                let bg = if background & 8 != 0 {
                    100 + (background & 7)
                } else {
                    40 + background
                };
                terminal.extend_from_slice(format!("\x1b[{fg};{bg}m").as_bytes());
                if attributes & 0x80 != 0 {
                    terminal.extend_from_slice(b"\x1b[7m");
                }
            }
            terminal.push(if (0x20..=0x7e).contains(&character) {
                character
            } else {
                b' '
            });
        }
    }
    terminal.extend_from_slice(b"\x1b[0m");
    let mut written = 0;
    while written < terminal.len() {
        let count = unsafe {
            write(
                fd,
                terminal[written..].as_ptr().cast(),
                terminal.len() - written,
            )
        };
        if count <= 0 {
            native_set_last_error(5);
            return 0;
        }
        written += count as usize;
    }
    1
}

/// UTF-16 units of the last console line that did not fit the caller's buffer.
static CONSOLE_PENDING_INPUT: Mutex<std::collections::VecDeque<u16>> =
    Mutex::new(std::collections::VecDeque::new());

/// Read one cooked console line through `read_more` and queue it as UTF-16,
/// ending in `\r\n` like Windows line input. Returns false on end of input.
fn queue_console_line(
    pending: &mut std::collections::VecDeque<u16>,
    mut read_more: impl FnMut(&mut [u8]) -> isize,
) -> Result<bool, u32> {
    let mut line = Vec::new();
    let mut chunk = [0u8; 4096];
    while line.last() != Some(&b'\n') {
        match read_more(&mut chunk) {
            count if count > 0 => line.extend_from_slice(&chunk[..count as usize]),
            0 => break,
            _ => return Err(6), // ERROR_INVALID_HANDLE
        }
    }
    if line.is_empty() {
        return Ok(false);
    }
    if line.last() == Some(&b'\n') && line.iter().rev().nth(1) != Some(&b'\r') {
        line.pop();
        line.extend_from_slice(b"\r\n");
    }
    pending.extend(String::from_utf8_lossy(&line).encode_utf16());
    Ok(true)
}

fn read_console_units(
    output: &mut [u16],
    read_more: impl FnMut(&mut [u8]) -> isize,
) -> Result<usize, u32> {
    let Ok(mut pending) = CONSOLE_PENDING_INPUT.lock() else {
        return Err(6);
    };
    if pending.is_empty() && !output.is_empty() && !queue_console_line(&mut pending, read_more)? {
        return Ok(0);
    }
    let count = output.len().min(pending.len());
    for (slot, unit) in output.iter_mut().zip(pending.drain(..count)) {
        *slot = unit;
    }
    Ok(count)
}

/// `ReadConsoleW(handle, buffer, chars, read, control)` in line-input mode:
/// the host terminal stays cooked, so one `read` returns an edited line.
pub(super) extern "win64" fn native_read_console_w(
    handle: u64,
    buffer: *mut u16,
    chars: u32,
    read_count: *mut u32,
    _control: u64,
) -> i32 {
    let Some(fd) = host_standard_fd(handle).filter(|fd| *fd == 0) else {
        native_set_last_error(6);
        return 0;
    };
    if buffer.is_null() && chars != 0 {
        native_set_last_error(998); // ERROR_NOACCESS
        return 0;
    }
    let output: &mut [u16] = if chars == 0 {
        &mut []
    } else {
        unsafe { std::slice::from_raw_parts_mut(buffer, chars as usize) }
    };
    match read_console_units(output, |chunk| unsafe {
        read(fd, chunk.as_mut_ptr().cast(), chunk.len())
    }) {
        Ok(count) => {
            if !read_count.is_null() {
                unsafe { read_count.write(count as u32) };
            }
            1
        }
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

#[cfg(test)]
mod read_console_tests {
    use super::queue_console_line;
    use std::collections::VecDeque;

    fn feed(chunks: &[&[u8]]) -> impl FnMut(&mut [u8]) -> isize {
        let mut chunks: VecDeque<Vec<u8>> = chunks.iter().map(|c| c.to_vec()).collect();
        move |out: &mut [u8]| match chunks.pop_front() {
            Some(chunk) => {
                out[..chunk.len()].copy_from_slice(&chunk);
                chunk.len() as isize
            }
            None => 0,
        }
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn a_cooked_line_ends_in_crlf_like_windows_line_input() {
        let mut pending = VecDeque::new();
        assert_eq!(queue_console_line(&mut pending, feed(&[b"y\n"])), Ok(true));
        assert_eq!(Vec::from(pending), units("y\r\n"));
    }

    #[test]
    fn a_line_split_across_reads_and_utf8_is_joined_and_decoded() {
        let mut pending = VecDeque::new();
        let text = "h\u{e9}llo \u{1f600}\r\n".as_bytes();
        let (head, tail) = text.split_at(2); // splits the two-byte é
        assert_eq!(queue_console_line(&mut pending, feed(&[head, tail])), Ok(true));
        assert_eq!(Vec::from(pending), units("h\u{e9}llo \u{1f600}\r\n"));
    }

    #[test]
    fn end_of_input_reads_zero_and_a_partial_last_line_is_kept() {
        let mut pending = VecDeque::new();
        assert_eq!(queue_console_line(&mut pending, feed(&[])), Ok(false));
        assert_eq!(queue_console_line(&mut pending, feed(&[b"no"])), Ok(true));
        assert_eq!(Vec::from(pending), units("no"));
    }

    #[test]
    fn a_line_longer_than_the_buffer_is_returned_across_calls() {
        let mut source = feed(&[b"yes\n"]);
        let mut read = |len: usize| {
            let mut output = vec![0u16; len];
            let count = super::read_console_units(&mut output, &mut source).unwrap();
            String::from_utf16(&output[..count]).unwrap()
        };
        assert_eq!(read(2), "ye");
        assert_eq!(read(0), "");
        assert_eq!(read(2), "s\r");
        assert_eq!(read(8), "\n");
        assert_eq!(read(8), ""); // the source is at end of input
    }

    #[test]
    fn a_failed_read_reports_an_invalid_handle() {
        let mut pending = VecDeque::new();
        assert_eq!(queue_console_line(&mut pending, |_: &mut [u8]| -1), Err(6));
    }
}

pub(super) extern "win64" fn native_get_number_of_console_input_events(
    handle: u64,
    count: *mut u32,
) -> i32 {
    if count.is_null() || host_standard_fd(handle) != Some(0) {
        native_set_last_error(6);
        return 0;
    }
    unsafe { count.write(0) };
    1
}

pub(super) extern "win64" fn native_set_console_ctrl_handler(_handler: u64, _add: i32) -> i32 {
    // The CLI guest currently has no Windows console-control delivery.
    // Registration succeeds so applications can install their handler;
    // Linux signals still terminate the isolated guest process normally.
    1
}
