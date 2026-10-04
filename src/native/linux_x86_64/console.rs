//! Windows console API shims over the Win-Runner terminal and standard handles.

use super::*;
use std::collections::VecDeque;

pub(super) fn console_fd(handle: u64) -> Option<i32> {
    host_standard_fd(handle).or_else(|| match native_device(handle)?.0 {
        NativeDevice::Console { output, .. } | NativeDevice::ConsoleOut(output) => {
            host_standard_fd(output)
        }
        NativeDevice::ConsoleIn(input) => host_standard_fd(input),
        _ => None,
    })
}

pub(super) extern "win64" fn native_get_console_mode(handle: u64, mode: *mut u32) -> i32 {
    if console_fd(handle).is_none() || mode.is_null() {
        return 0;
    }
    // Console devices share modes with the corresponding standard stream.
    let value = if console_fd(handle) == Some(0) {
        console_input_mode()
    } else {
        let fd = console_fd(handle).unwrap();
        process_ctx()
            .map(|p| p.console_output_modes[(fd - 1) as usize].load(Ordering::Acquire))
            .unwrap_or(1)
    };
    unsafe { mode.write(value) };
    1
}
pub(super) extern "win64" fn native_get_console_output_cp() -> u32 {
    native_get_acp()
}
pub(super) extern "win64" fn native_get_console_cursor_info(handle: u64, output: *mut u8) -> i32 {
    if console_fd(handle).is_none() || output.is_null() {
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
    if console_fd(handle).is_none() || input.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let size = unsafe { (input as *const u32).read_unaligned() };
    let visible = unsafe { (input.add(4) as *const i32).read_unaligned() };
    if !(1..=100).contains(&size) || !matches!(visible, 0 | 1) {
        native_set_last_error(87);
        return 0;
    }
    let Some(fd @ (1 | 2)) = console_fd(handle) else {
        native_set_last_error(6);
        return 0;
    };
    let sequence = if visible == 0 {
        b"\x1b[?25l"
    } else {
        b"\x1b[?25h"
    };
    (unsafe { write(fd, sequence.as_ptr().cast(), sequence.len()) } == sequence.len() as isize)
        as i32
}
pub(super) extern "win64" fn native_set_console_cursor_position(handle: u64, position: u32) -> i32 {
    let Some(fd @ (1 | 2)) = console_fd(handle) else {
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
    if console_fd(handle).is_none() || output.is_null() {
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
pub(super) extern "win64" fn native_set_console_mode(handle: u64, mode: u32) -> i32 {
    match console_fd(handle) {
        Some(0) => {
            set_console_input_mode(mode);
            1
        }
        Some(fd @ (1 | 2)) => {
            if let Some(p) = process_ctx() {
                p.console_output_modes[(fd - 1) as usize].store(mode, Ordering::Release);
            }
            1
        }
        _ => 0,
    }
}
pub(super) extern "win64" fn native_set_console_screen_buffer_size(handle: u64, size: u32) -> i32 {
    let width = size as u16 as i16;
    let height = (size >> 16) as u16 as i16;
    if console_fd(handle).is_none() || width <= 0 || height <= 0 {
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
    if console_fd(handle).is_none() || rect.is_null() {
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
    if console_fd(handle).is_some() {
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
    if !matches!(console_fd(handle), Some(1 | 2)) || (text.is_null() && len != 0) {
        return 0;
    }
    let units = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(text, len as usize) }
    };
    let encoded = String::from_utf16_lossy(units);
    let Some(fd) = console_fd(handle) else {
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
    let Some(fd @ (1 | 2)) = console_fd(handle) else {
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

const ENABLE_PROCESSED_INPUT: u32 = 0x1;
const ENABLE_LINE_INPUT: u32 = 0x2;
const ENABLE_ECHO_INPUT: u32 = 0x4;
/// The input mode of a fresh Windows console.
const DEFAULT_CONSOLE_INPUT_MODE: u32 = 0x1f7;
const INPUT_RECORD_SIZE: usize = 20;
const KEY_EVENT: u16 = 1;

/// Console stdin shared by line reads, key-record reads, and waits.
#[derive(Clone)]
pub(super) struct ConsoleInput {
    mode: u32,
    /// UTF-16 units ready to return to a read.
    units: VecDeque<u16>,
    /// An incomplete UTF-8 sequence left at the end of a raw read.
    partial: Vec<u8>,
    /// Line-input bytes still waiting for their end of line.
    line: Vec<u8>,
    /// A read reached end of input; the next read reports it once.
    eof: bool,
    size: Option<(usize, usize)>,
    resize: Option<(usize, usize)>,
    escape_started: Option<std::time::Instant>,
}

impl ConsoleInput {
    const fn new() -> Self {
        Self {
            mode: DEFAULT_CONSOLE_INPUT_MODE,
            units: VecDeque::new(),
            partial: Vec::new(),
            line: Vec::new(),
            eof: false,
            size: None,
            resize: None,
            escape_started: None,
        }
    }

    fn line_input(&self) -> bool {
        self.mode & ENABLE_LINE_INPUT != 0
    }

    /// Queue bytes read from the terminal; empty means end of input.
    fn queue_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            if self.line.is_empty() {
                self.eof = true;
            } else {
                let line = std::mem::take(&mut self.line);
                self.units
                    .extend(String::from_utf8_lossy(&line).encode_utf16());
            }
        } else if self.line_input() {
            self.queue_line_bytes(bytes);
        } else {
            self.queue_raw_bytes(bytes);
        }
    }

    /// Complete lines become ready ending in `\r\n`, like Windows line input.
    fn queue_line_bytes(&mut self, bytes: &[u8]) {
        self.line.extend_from_slice(bytes);
        while let Some(end) = self.line.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = self.line.drain(..=end).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            line.extend_from_slice(b"\r\n");
            self.units
                .extend(String::from_utf8_lossy(&line).encode_utf16());
        }
    }

    /// Raw bytes are ready at once. An incomplete trailing UTF-8 sequence
    /// waits for the next read; DEL becomes backspace, as Windows reports it.
    fn queue_raw_bytes(&mut self, bytes: &[u8]) {
        let mut rest = std::mem::take(&mut self.partial);
        rest.extend_from_slice(bytes);
        let mut text = String::new();
        loop {
            match std::str::from_utf8(&rest) {
                Ok(valid) => {
                    text.push_str(valid);
                    rest.clear();
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    text.push_str(std::str::from_utf8(&rest[..valid]).unwrap_or_default());
                    match error.error_len() {
                        None => {
                            rest.drain(..valid);
                            break;
                        }
                        Some(length) => {
                            text.push('\u{fffd}');
                            rest.drain(..valid + length);
                        }
                    }
                }
            }
        }
        self.partial = rest;
        self.units
            .extend(text.encode_utf16().map(|unit| if unit == 0x7f { 0x08 } else { unit }));
    }

    /// A key typed through `WriteConsoleInputW`. In line-input mode Enter
    /// completes the pending line, which is how libuv cancels a line read.
    fn inject(&mut self, unit: u16) {
        if !self.line_input() {
            self.units.push_back(unit);
        } else if unit == 0x0d {
            self.queue_line_bytes(b"\n");
        } else if let Some(character) = char::from_u32(unit as u32) {
            let mut encoded = [0u8; 4];
            let encoded = character.encode_utf8(&mut encoded);
            self.line.extend_from_slice(encoded.as_bytes());
        }
    }

    /// Ready units for a `ReadConsoleW`, or None to keep waiting.
    fn take_units(&mut self, output: &mut [u16]) -> Option<usize> {
        if output.is_empty() {
            return Some(0);
        }
        if self.units.is_empty() {
            return std::mem::take(&mut self.eof).then_some(0);
        }
        let count = output.len().min(self.units.len());
        for (slot, unit) in output.iter_mut().zip(self.units.drain(..count)) {
            *slot = unit;
        }
        Some(count)
    }

    fn observe_size(&mut self, size: (usize, usize)) {
        if self.mode & 8 != 0 && self.size.is_some_and(|previous| previous != size) {
            self.resize = Some(size);
        }
        self.size = Some(size);
    }

    fn record_count(&mut self) -> usize {
        // ANSI key sequences consume several UTF-16 units but produce one
        // Windows record. Consumers use this count to issue blocking reads.
        let mut preview = self.clone();
        let count = preview
            .take_records(usize::MAX)
            .and_then(Result::ok)
            .map_or(0, |records| records.len());
        self.escape_started = preview.escape_started;
        count
    }

    /// Ready key and window records for a `ReadConsoleInputW`.
    fn take_records(&mut self, length: usize) -> Option<Result<Vec<[u8; INPUT_RECORD_SIZE]>, u32>> {
        if length == 0 {
            return Some(Ok(Vec::new()));
        }
        if let Some((columns, rows)) = self.resize.take() {
            let mut record = [0; INPUT_RECORD_SIZE];
            record[0..2].copy_from_slice(&4u16.to_le_bytes());
            record[4..6].copy_from_slice(&(columns as u16).to_le_bytes());
            record[6..8].copy_from_slice(&(rows as u16).to_le_bytes());
            return Some(Ok(vec![record]));
        }
        if self.units.is_empty() {
            return std::mem::take(&mut self.eof).then_some(Err(38)); // ERROR_HANDLE_EOF
        }
        let mut records = Vec::new();
        while records.len() < length && !self.units.is_empty() {
            if self.units[0] == 0x1b {
                let sequences: &[(&[u8], u16)] = &[
                    (b"\x1b[A", 0x26),
                    (b"\x1b[B", 0x28),
                    (b"\x1b[C", 0x27),
                    (b"\x1b[D", 0x25),
                    (b"\x1b[H", 0x24),
                    (b"\x1b[F", 0x23),
                    (b"\x1bOH", 0x24),
                    (b"\x1bOF", 0x23),
                    (b"\x1bOP", 0x70),
                    (b"\x1bOQ", 0x71),
                    (b"\x1bOR", 0x72),
                    (b"\x1bOS", 0x73),
                    (b"\x1b[2~", 0x2d),
                    (b"\x1b[3~", 0x2e),
                    (b"\x1b[5~", 0x21),
                    (b"\x1b[6~", 0x22),
                    (b"\x1b[15~", 0x74),
                    (b"\x1b[17~", 0x75),
                    (b"\x1b[18~", 0x76),
                    (b"\x1b[19~", 0x77),
                    (b"\x1b[20~", 0x78),
                    (b"\x1b[21~", 0x79),
                    (b"\x1b[23~", 0x7a),
                    (b"\x1b[24~", 0x7b),
                ];
                if let Some((sequence, key)) = sequences.iter().find(|(sequence, _)| {
                    sequence.len() <= self.units.len()
                        && sequence
                            .iter()
                            .zip(&self.units)
                            .all(|(a, b)| *a as u16 == *b)
                }) {
                    self.units.drain(..sequence.len());
                    let mut record = key_event_record(0);
                    record[10..12].copy_from_slice(&key.to_le_bytes());
                    record[12..14].copy_from_slice(&scan_code(*key).to_le_bytes());
                    records.push(record);
                    self.escape_started = None;
                    continue;
                }
                let incomplete = sequences.iter().any(|(sequence, _)| {
                    self.units.len() < sequence.len()
                        && sequence
                            .iter()
                            .zip(&self.units)
                            .all(|(a, b)| *a as u16 == *b)
                });
                if incomplete
                    && self
                        .escape_started
                        .get_or_insert_with(std::time::Instant::now)
                        .elapsed()
                        < std::time::Duration::from_millis(25)
                {
                    break;
                }
            }
            self.escape_started = None;
            records.push(key_event_record(self.units.pop_front().unwrap()));
        }
        (!records.is_empty()).then_some(Ok(records))
    }
}

static CONSOLE_INPUT: Mutex<ConsoleInput> = Mutex::new(ConsoleInput::new());
/// Terminal settings from before the guest first changed the input mode.
/// Kept apart from `CONSOLE_INPUT` so restoring never waits on a reader.
static ORIGINAL_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);
/// Readers blocked on stdin also watch this pipe, so injected input wakes them.
static CONSOLE_WAKE: LazyLock<[i32; 2]> = LazyLock::new(|| {
    let mut fds = [-1; 2];
    unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    fds
});

/// The host terminal settings for a Windows console input `mode`:
/// line input is canonical mode, echo input is echo, and processed input
/// turns Ctrl+C into a signal. Output processing stays as it was.
fn termios_for_console_mode(original: &libc::termios, mode: u32) -> libc::termios {
    let mut settings = *original;
    if mode & ENABLE_LINE_INPUT == 0 {
        settings.c_iflag &= !(libc::ICRNL
            | libc::INLCR
            | libc::IGNCR
            | libc::IXON
            | libc::ISTRIP
            | libc::BRKINT);
        settings.c_lflag &= !(libc::ICANON | libc::IEXTEN);
        settings.c_cc[libc::VMIN] = 1;
        settings.c_cc[libc::VTIME] = 0;
    }
    if mode & ENABLE_ECHO_INPUT == 0 {
        settings.c_lflag &= !libc::ECHO;
    }
    if mode & ENABLE_PROCESSED_INPUT == 0 {
        settings.c_lflag &= !libc::ISIG;
    }
    settings
}

fn set_console_input_mode(mode: u32) {
    if let Ok(mut input) = CONSOLE_INPUT.lock() {
        input.mode = mode;
        input.size = Some(crate::control::terminal_size());
    }
    if unsafe { libc::isatty(0) } != 1 {
        return;
    }
    let Ok(mut saved) = ORIGINAL_TERMIOS.lock() else {
        return;
    };
    let original = match *saved {
        Some(original) => original,
        None => {
            let mut original: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(0, &mut original) } != 0 {
                return;
            }
            *saved = Some(original);
            original
        }
    };
    let settings = termios_for_console_mode(&original, mode);
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &settings) };
}

/// Put the terminal back as it was before the guest changed the console
/// input mode, so a guest that exits in raw mode leaves a usable shell.
pub(super) fn restore_console_input_mode() {
    if let Ok(saved) = ORIGINAL_TERMIOS.try_lock() {
        if let Some(original) = saved.as_ref() {
            unsafe { libc::tcsetattr(0, libc::TCSANOW, original) };
        }
    }
}

pub(super) fn console_input_mode() -> u32 {
    CONSOLE_INPUT
        .lock()
        .map_or(DEFAULT_CONSOLE_INPUT_MODE, |input| input.mode)
}

/// US-layout scan code of a virtual key, or 0.
fn scan_code(virtual_key: u16) -> u16 {
    const LETTERS: [u8; 26] = [
        0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18,
        0x19, 0x10, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c,
    ];
    match virtual_key {
        0x41..=0x5a => LETTERS[(virtual_key - 0x41) as usize] as u16,
        0x31..=0x39 => virtual_key - 0x2f,
        0x30 => 0x0b,
        0x08 => 0x0e,
        0x09 => 0x0f,
        0x0d => 0x1c,
        0x10 => 0x2a,
        0x11 => 0x1d,
        0x12 => 0x38,
        0x1b => 0x01,
        0x20 => 0x39,
        0x25 => 0x4b,
        0x26 => 0x48,
        0x27 => 0x4d,
        0x28 => 0x50,
        0x70..=0x79 => virtual_key - 0x70 + 0x3b, // F1-F10
        0x7a => 0x57,                            // F11
        0x7b => 0x58,                            // F12
        _ => 0,
    }
}

/// `MapVirtualKeyW(code, map_type)` for the US keyboard layout.
pub(super) extern "win64" fn native_map_virtual_key_w(code: u32, map_type: u32) -> u32 {
    let Ok(code) = u16::try_from(code) else {
        return 0;
    };
    match map_type {
        0 | 4 => scan_code(code) as u32, // MAPVK_VK_TO_VSC(_EX)
        1 | 3 if code != 0 => (0..=0xff)
            .find(|virtual_key| scan_code(*virtual_key) == code)
            .unwrap_or(0) as u32, // MAPVK_VSC_TO_VK(_EX)
        2 => match code {
            0x08 | 0x09 | 0x0d | 0x1b | 0x20 | 0x30..=0x39 | 0x41..=0x5a => code as u32,
            _ => 0,
        }, // MAPVK_VK_TO_CHAR
        _ => 0,
    }
}

/// A key-down `INPUT_RECORD` for one UTF-16 unit typed at the terminal.
/// libuv turns the character back into the terminal's bytes, so escape
/// sequences such as arrow keys pass through one unit at a time.
fn key_event_record(unit: u16) -> [u8; INPUT_RECORD_SIZE] {
    const SHIFT_PRESSED: u32 = 0x10;
    const LEFT_CTRL_PRESSED: u32 = 0x08;
    let (virtual_key, control_state) = match unit {
        0x08 | 0x09 | 0x0d | 0x1b | 0x20 | 0x30..=0x39 => (unit, 0),
        0x61..=0x7a => (unit - 0x20, 0),
        0x41..=0x5a => (unit, SHIFT_PRESSED),
        0x01..=0x1a => (unit + 0x40, LEFT_CTRL_PRESSED),
        _ => (0, 0),
    };
    let mut record = [0u8; INPUT_RECORD_SIZE];
    record[0..2].copy_from_slice(&KEY_EVENT.to_le_bytes());
    record[4..8].copy_from_slice(&1u32.to_le_bytes()); // bKeyDown
    record[8..10].copy_from_slice(&1u16.to_le_bytes()); // wRepeatCount
    record[10..12].copy_from_slice(&virtual_key.to_le_bytes());
    record[12..14].copy_from_slice(&scan_code(virtual_key).to_le_bytes());
    record[14..16].copy_from_slice(&unit.to_le_bytes());
    record[16..20].copy_from_slice(&control_state.to_le_bytes());
    record
}

/// Characters of the key-down events in a `WriteConsoleInputW` buffer.
fn injected_units(records: &[u8]) -> Vec<u16> {
    let u16_at = |record: &[u8], at: usize| u16::from_le_bytes([record[at], record[at + 1]]);
    let mut units = Vec::new();
    for record in records.chunks_exact(INPUT_RECORD_SIZE) {
        let key_down = u32::from_le_bytes(record[4..8].try_into().unwrap()) != 0;
        let unit = u16_at(record, 14);
        if u16_at(record, 0) == KEY_EVENT && key_down && unit != 0 {
            let repeat = u16_at(record, 8).max(1);
            units.extend(std::iter::repeat_n(unit, repeat as usize));
        }
    }
    units
}

fn host_stdin_read(chunk: &mut [u8]) -> isize {
    loop {
        let count = unsafe { read(0, chunk.as_mut_ptr().cast(), chunk.len()) };
        if count >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return count;
        }
    }
}

fn host_stdin_readable(timeout_ms: i32) -> bool {
    let mut descriptor = NativePollFd {
        fd: 0,
        events: 1, // POLLIN
        revents: 0,
    };
    unsafe { poll(&mut descriptor, 1, timeout_ms) > 0 }
}

/// Run `take` on the console input until it returns a value. Only bytes
/// already on stdin are read under the lock, and the wait between reads
/// also watches the wake pipe, so `WriteConsoleInputW` can end it.
fn wait_for_console_input<T>(
    mut take: impl FnMut(&mut ConsoleInput) -> Option<T>,
) -> Result<T, u32> {
    loop {
        {
            let Ok(mut input) = CONSOLE_INPUT.lock() else {
                return Err(6);
            };
            input.observe_size(crate::control::terminal_size());
            if let Some(value) = take(&mut input) {
                return Ok(value);
            }
            if host_stdin_readable(0) {
                let mut chunk = [0u8; 4096];
                let count = host_stdin_read(&mut chunk);
                if count < 0 {
                    return Err(6); // ERROR_INVALID_HANDLE
                }
                input.queue_bytes(&chunk[..count as usize]);
                continue;
            }
        }
        let wake = CONSOLE_WAKE[0];
        let mut descriptors = [
            NativePollFd {
                fd: 0,
                events: 1,
                revents: 0,
            },
            NativePollFd {
                fd: wake,
                events: 1,
                revents: 0,
            },
        ];
        // The timeout only bounds a missed wake-up between two readers.
        unsafe { poll(descriptors.as_mut_ptr(), 2, 25) };
        if descriptors[1].revents != 0 {
            let mut drained = [0u8; 64];
            while unsafe { read(wake, drained.as_mut_ptr().cast(), drained.len()) } > 0 {}
        }
    }
}

/// Whether a wait on the console input handle is satisfied: input is ready
/// or the terminal has bytes (or end of input) to read.
pub(super) fn console_input_ready(timeout_ms: i32) -> bool {
    let deadline = (timeout_ms >= 0)
        .then(|| std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64));
    loop {
        if CONSOLE_INPUT.try_lock().is_ok_and(|mut input| {
            input.observe_size(crate::control::terminal_size());
            input.record_count() != 0 || input.eof
        }) || host_stdin_readable(0)
        {
            return true;
        }
        let remaining =
            deadline.map(|end| end.saturating_duration_since(std::time::Instant::now()));
        if remaining.is_some_and(|time| time.is_zero()) {
            return false;
        }
        // Window-size changes and an isolated Escape key have no fd wakeup.
        let wait = remaining.map_or(25, |time| time.as_millis().min(25) as i32);
        if host_stdin_readable(wait) {
            return true;
        }
    }
}

fn console_stdin(handle: u64) -> bool {
    console_fd(handle) == Some(0)
}

/// `ReadConsoleW(handle, buffer, chars, read, control)`. In line-input mode
/// the host terminal stays cooked and returns whole edited lines.
// Windows distinguishes a disk-file handle from an invalid console handle
// for the two console read APIs; the write/query APIs retain error 6.
fn console_read_handle_error(handle: u64) -> u32 {
    let file = fs_ctx().and_then(|ctx| ctx.lock().ok().map(|fs| fs.handles.contains_key(&handle)));
    if file == Some(true) {
        87
    } else {
        6
    }
}

pub(super) extern "win64" fn native_read_console_w(
    handle: u64,
    buffer: *mut u16,
    chars: u32,
    read_count: *mut u32,
    _control: u64,
) -> i32 {
    if !console_stdin(handle) {
        native_set_last_error(console_read_handle_error(handle));
        return 0;
    }
    if buffer.is_null() && chars != 0 {
        native_set_last_error(998); // ERROR_NOACCESS
        return 0;
    }
    let output: &mut [u16] = if chars == 0 {
        &mut []
    } else {
        unsafe { std::slice::from_raw_parts_mut(buffer, chars as usize) }
    };
    match wait_for_console_input(|input| input.take_units(output)) {
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

/// `ReadConsoleInputW(handle, records, length, read)`: blocks for at least
/// one key record. libuv's raw-mode TTY reads keys this way.
pub(super) extern "win64" fn native_read_console_input_w(
    handle: u64,
    records: *mut u8,
    length: u32,
    read_count: *mut u32,
) -> i32 {
    if !console_stdin(handle) {
        native_set_last_error(console_read_handle_error(handle));
        return 0;
    }
    if (records.is_null() && length != 0) || read_count.is_null() {
        native_set_last_error(998); // ERROR_NOACCESS
        return 0;
    }
    match wait_for_console_input(|input| input.take_records(length as usize)).and_then(|r| r) {
        Ok(read) => {
            for (index, record) in read.iter().enumerate() {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        record.as_ptr(),
                        records.add(index * INPUT_RECORD_SIZE),
                        INPUT_RECORD_SIZE,
                    )
                };
            }
            unsafe { read_count.write(read.len() as u32) };
            1
        }
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

/// `WriteConsoleInputW(handle, records, length, written)`: queue key-down
/// characters as typed input and wake any blocked console read.
pub(super) extern "win64" fn native_write_console_input_w(
    handle: u64,
    records: *const u8,
    length: u32,
    written: *mut u32,
) -> i32 {
    if !console_stdin(handle) {
        native_set_last_error(6);
        return 0;
    }
    if (records.is_null() && length != 0) || written.is_null() {
        native_set_last_error(998); // ERROR_NOACCESS
        return 0;
    }
    let bytes = if length == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(records, length as usize * INPUT_RECORD_SIZE) }
    };
    let Ok(mut input) = CONSOLE_INPUT.lock() else {
        native_set_last_error(6);
        return 0;
    };
    for unit in injected_units(bytes) {
        input.inject(unit);
    }
    drop(input);
    unsafe { write(CONSOLE_WAKE[1], [1u8].as_ptr().cast(), 1) };
    unsafe { written.write(length) };
    1
}

pub(super) extern "win64" fn native_get_number_of_console_input_events(
    handle: u64,
    count: *mut u32,
) -> i32 {
    if count.is_null() || !console_stdin(handle) {
        native_set_last_error(6);
        return 0;
    }
    let Ok(mut input) = CONSOLE_INPUT.lock() else {
        native_set_last_error(6);
        return 0;
    };
    // A raw-mode terminal's pending bytes are pending key events. A cooked
    // line stays in the terminal until a line read asks for it.
    if input.units.is_empty() && !input.line_input() && host_stdin_readable(0) {
        let mut chunk = [0u8; 4096];
        let read = host_stdin_read(&mut chunk);
        if read >= 0 {
            input.queue_bytes(&chunk[..read as usize]);
        }
    }
    input.observe_size(crate::control::terminal_size());
    unsafe { count.write(input.record_count() as u32) };
    1
}

#[cfg(test)]
mod read_console_tests {
    use super::{
        injected_units, key_event_record, native_map_virtual_key_w, termios_for_console_mode,
        ConsoleInput,
    };

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn line_input() -> ConsoleInput {
        ConsoleInput::new()
    }

    fn raw_input() -> ConsoleInput {
        let mut input = ConsoleInput::new();
        input.mode = 0x8; // ENABLE_WINDOW_INPUT, as libuv's raw mode sets
        input
    }

    fn take(input: &mut ConsoleInput, len: usize) -> Option<String> {
        let mut output = vec![0u16; len];
        let count = input.take_units(&mut output)?;
        Some(String::from_utf16(&output[..count]).unwrap())
    }

    #[test]
    fn a_cooked_line_ends_in_crlf_like_windows_line_input() {
        let mut input = line_input();
        input.queue_bytes(b"y");
        assert_eq!(take(&mut input, 8), None); // waits for the end of line
        input.queue_bytes(b"\n");
        assert_eq!(take(&mut input, 8).as_deref(), Some("y\r\n"));
        input.queue_bytes(b"ok\r\n");
        assert_eq!(take(&mut input, 8).as_deref(), Some("ok\r\n"));
    }

    #[test]
    fn a_line_split_across_reads_and_utf8_is_joined_and_decoded() {
        let mut input = line_input();
        let text = "h\u{e9}llo \u{1f600}\n".as_bytes();
        let (head, tail) = text.split_at(2); // splits the two-byte é
        input.queue_bytes(head);
        input.queue_bytes(tail);
        assert_eq!(Vec::from(input.units.clone()), units("h\u{e9}llo \u{1f600}\r\n"));
    }

    #[test]
    fn end_of_input_reads_zero_once_and_keeps_a_partial_last_line() {
        let mut input = line_input();
        input.queue_bytes(b"");
        assert_eq!(take(&mut input, 8).as_deref(), Some(""));
        assert_eq!(take(&mut input, 8), None);
        input.queue_bytes(b"no");
        input.queue_bytes(b"");
        assert_eq!(take(&mut input, 8).as_deref(), Some("no"));
        let mut input = raw_input();
        input.queue_bytes(b"");
        assert_eq!(input.take_records(1), Some(Err(38)));
        assert_eq!(input.take_records(1), None);
    }

    #[test]
    fn a_line_longer_than_the_buffer_is_returned_across_calls() {
        let mut input = line_input();
        input.queue_bytes(b"yes\n");
        assert_eq!(take(&mut input, 2).as_deref(), Some("ye"));
        assert_eq!(take(&mut input, 0).as_deref(), Some(""));
        assert_eq!(take(&mut input, 2).as_deref(), Some("s\r"));
        assert_eq!(take(&mut input, 8).as_deref(), Some("\n"));
        assert_eq!(take(&mut input, 8), None);
    }

    #[test]
    fn raw_bytes_keep_a_split_utf8_sequence_and_map_delete_to_backspace() {
        let mut input = raw_input();
        let euro = "\u{20ac}".as_bytes();
        input.queue_bytes(&[b'a', euro[0]]);
        assert_eq!(Vec::from(input.units.clone()), units("a"));
        input.queue_bytes(&[euro[1], euro[2], 0x7f, 0xff]);
        assert_eq!(Vec::from(input.units.clone()), units("a\u{20ac}\u{8}\u{fffd}"));
        assert!(input.partial.is_empty());
    }

    fn record_fields(record: &[u8; 20]) -> (u16, u32, u16, u16, u16, u16, u32) {
        let u16_at = |at: usize| u16::from_le_bytes([record[at], record[at + 1]]);
        let u32_at = |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().unwrap());
        (u16_at(0), u32_at(4), u16_at(8), u16_at(10), u16_at(12), u16_at(14), u32_at(16))
    }

    #[test]
    fn key_records_carry_the_character_virtual_key_scan_code_and_modifiers() {
        let fields = |unit: u16| record_fields(&key_event_record(unit));
        assert_eq!(fields(b'y' as u16), (1, 1, 1, 0x59, 0x15, 0x79, 0));
        assert_eq!(fields(b'Y' as u16), (1, 1, 1, 0x59, 0x15, 0x59, 0x10));
        assert_eq!(fields(0x0d), (1, 1, 1, 0x0d, 0x1c, 0x0d, 0));
        assert_eq!(fields(0x03), (1, 1, 1, 0x43, 0x2e, 0x03, 0x08));
        assert_eq!(fields(0x20ac), (1, 1, 1, 0, 0, 0x20ac, 0));
    }

    #[test]
    fn raw_reads_decode_navigation_and_split_escape_sequences() {
        let mut input = raw_input();
        input.queue_bytes(b"\x1b[");
        assert_eq!(input.take_records(2), None);
        input.queue_bytes(b"D\x1b[3~\r");
        assert_eq!(input.record_count(), 3);
        let records = input.take_records(2).unwrap().unwrap();
        assert_eq!(record_fields(&records[0]).3, 0x25); // VK_LEFT
        assert_eq!(record_fields(&records[0]).5, 0);
        assert_eq!(record_fields(&records[1]).3, 0x2e); // VK_DELETE
        assert_eq!(
            record_fields(&input.take_records(1).unwrap().unwrap()[0]).5,
            0x0d
        );
        assert_eq!(input.record_count(), 0);
        assert_eq!(input.take_records(1), None);
        input.queue_bytes(b"\x1b");
        assert_eq!(input.take_records(1), None);
        input.escape_started =
            Some(std::time::Instant::now() - std::time::Duration::from_millis(30));
        assert_eq!(
            record_fields(&input.take_records(1).unwrap().unwrap()[0]).5,
            0x1b
        );
    }

    #[test]
    fn resize_records_follow_window_input_mode_and_coalesce() {
        let mut input = raw_input();
        input.observe_size((80, 24));
        assert_eq!(input.take_records(1), None);
        input.observe_size((100, 30));
        input.observe_size((120, 40));
        assert_eq!(input.record_count(), 1);
        assert_eq!(input.take_records(0), Some(Ok(Vec::new())));
        let record = input.take_records(1).unwrap().unwrap()[0];
        assert_eq!(u16::from_le_bytes(record[0..2].try_into().unwrap()), 4);
        assert_eq!(u16::from_le_bytes(record[4..6].try_into().unwrap()), 120);
        assert_eq!(u16::from_le_bytes(record[6..8].try_into().unwrap()), 40);
        assert_eq!(input.take_records(1), None);
        input.mode = 0;
        input.observe_size((80, 24));
        assert_eq!(input.take_records(1), None);
    }

    #[test]
    fn raw_mode_read_console_returns_keys_without_waiting_for_a_line() {
        let mut input = raw_input();
        input.queue_bytes(b"y");
        assert_eq!(take(&mut input, 8).as_deref(), Some("y"));
    }

    #[test]
    fn an_injected_enter_completes_a_pending_line_read() {
        // libuv cancels its line-read thread by writing a VK_RETURN record.
        let mut enter = key_event_record(0x0d);
        enter[8..10].copy_from_slice(&1u16.to_le_bytes());
        let mut key_up = key_event_record(b'x' as u16);
        key_up[4..8].copy_from_slice(&0u32.to_le_bytes());
        let mut records = enter.to_vec();
        records.extend_from_slice(&key_up);
        assert_eq!(injected_units(&records), vec![0x0d]);

        let mut input = line_input();
        input.queue_bytes(b"ab");
        input.inject(b'c' as u16);
        assert_eq!(take(&mut input, 8), None);
        input.inject(0x0d);
        assert_eq!(take(&mut input, 8).as_deref(), Some("abc\r\n"));

        let mut input = raw_input();
        input.inject(0x0d);
        assert_eq!(take(&mut input, 8).as_deref(), Some("\r"));
    }

    #[test]
    fn map_virtual_key_translates_between_keys_scan_codes_and_characters() {
        assert_eq!(native_map_virtual_key_w(0x0d, 0), 0x1c); // VK_RETURN
        assert_eq!(native_map_virtual_key_w(0x41, 0), 0x1e); // 'A'
        assert_eq!(native_map_virtual_key_w(0x1c, 1), 0x0d);
        assert_eq!(native_map_virtual_key_w(0x30, 2), b'0' as u32);
        assert_eq!(native_map_virtual_key_w(0x70, 0), 0x3b); // F1
        assert_eq!(native_map_virtual_key_w(0x58, 1), 0x7b); // F12
        assert_eq!(native_map_virtual_key_w(0x2a3, 0), 0); // not a virtual key
        assert_eq!(native_map_virtual_key_w(0, 1), 0);
        assert_eq!(native_map_virtual_key_w(0x0d, 9), 0);
    }

    #[test]
    fn console_modes_map_to_terminal_settings() {
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        original.c_iflag = libc::ICRNL | libc::IXON;
        original.c_lflag = libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN;
        original.c_oflag = libc::OPOST;
        let cooked = termios_for_console_mode(&original, 0x7);
        assert_eq!(cooked.c_lflag, original.c_lflag);
        assert_eq!(cooked.c_iflag, original.c_iflag);
        let raw = termios_for_console_mode(&original, 0x8);
        assert_eq!(raw.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN), 0);
        assert_eq!(raw.c_iflag & (libc::ICRNL | libc::IXON), 0);
        assert_eq!(raw.c_oflag, libc::OPOST);
        assert_eq!(raw.c_cc[libc::VMIN], 1);
        let no_echo = termios_for_console_mode(&original, 0x3);
        assert_eq!(no_echo.c_lflag, libc::ICANON | libc::ISIG | libc::IEXTEN);
    }
}

pub(super) extern "win64" fn native_set_console_ctrl_handler(_handler: u64, _add: i32) -> i32 {
    // The CLI guest currently has no Windows console-control delivery.
    // Registration succeeds so applications can install their handler;
    // Linux signals still terminate the isolated guest process normally.
    1
}

// Attribute-only edits to a Windows screen buffer require a shadow screen;
// VT-based clients can operate directly without this legacy capability.
pub(super) extern "win64" fn native_fill_console_output_attribute(
    _handle: u64,
    _attribute: u16,
    _length: u32,
    _position: u32,
    written: *mut u32,
) -> i32 {
    if !written.is_null() {
        unsafe { written.write(0) };
    }
    native_set_last_error(50);
    0
}
pub(super) extern "win64" fn native_fill_console_output_character_w(
    handle: u64,
    character: u16,
    length: u32,
    position: u32,
    written: *mut u32,
) -> i32 {
    if !written.is_null() {
        unsafe { written.write(0) };
    }
    let Some(fd @ (1 | 2)) = console_fd(handle) else {
        native_set_last_error(6);
        return 0;
    };
    let (columns, rows) = crate::control::terminal_size();
    let x = position as u16 as usize;
    let y = (position >> 16) as u16 as usize;
    if x >= columns || y >= rows || columns == 0 {
        native_set_last_error(87);
        return 0;
    }
    let count = (length as usize).min(columns * rows - y * columns - x);
    // FillConsoleOutputCharacter does not change the cursor position.
    unsafe { write(fd, b"\x1b7".as_ptr().cast(), 2) };
    let mut done = 0;
    while done < count {
        let offset = y * columns + x + done;
        let take = (columns - offset % columns).min(count - done);
        if native_set_console_cursor_position(
            handle,
            (offset % columns) as u32 | ((offset / columns) as u32) << 16,
        ) == 0
        {
            unsafe { write(fd, b"\x1b8".as_ptr().cast(), 2) };
            return 0;
        }
        let text = vec![character; take];
        if native_write_console_w(handle, text.as_ptr(), take as u32, std::ptr::null_mut(), 0) == 0
        {
            unsafe { write(fd, b"\x1b8".as_ptr().cast(), 2) };
            return 0;
        }
        done += take;
    }
    unsafe { write(fd, b"\x1b8".as_ptr().cast(), 2) };
    if !written.is_null() {
        unsafe { written.write(done as u32) };
    }
    1
}

pub(super) extern "win64" fn native_set_console_text_attribute(
    handle: u64,
    attributes: u16,
) -> i32 {
    let Some(fd @ (1 | 2)) = console_fd(handle) else {
        native_set_last_error(6);
        return 0;
    };
    let ansi = |value: u16| ((value & 4) >> 2) | (value & 2) | ((value & 1) << 2);
    let fg = ansi(attributes & 7) + if attributes & 8 != 0 { 90 } else { 30 };
    let bg = ansi((attributes >> 4) & 7) + if attributes & 0x80 != 0 { 100 } else { 40 };
    let text = format!("\x1b[0;{fg};{bg}m");
    (unsafe { write(fd, text.as_ptr().cast(), text.len()) } == text.len() as isize) as i32
}
