// Shared support for the Windows-oracle probes (see tests/oracle/README.md).
//
// A probe calls Win32 APIs with fixed inputs and prints one line per
// observation: return value, output, and GetLastError. The same .exe runs on
// real Windows (producing the golden transcript) and under Win-Runner; the
// transcripts must match line for line. Probes test Windows behavior only,
// never an application.
//
// Every API except the handful needed to print and exit is looked up with
// GetProcAddress, so an API Win-Runner lacks prints `unavailable` instead of
// ending the probe. Machine-specific values are normalized before printing:
// the probe's work directory becomes `<W>` (`<W:nodrive>` without its drive),
// the directory it started in `<B>`, and their drive letter `<D>`. Lengths
// and offsets print relative to the string they describe.
// Included with `include!` (plain rustc builds, no_std, no allocator).

extern "system" {
    fn GetStdHandle(which: u32) -> usize;
    fn WriteFile(handle: usize, buffer: *const u8, length: u32, written: *mut u32, overlapped: usize) -> i32;
    fn ExitProcess(code: u32) -> !;
    fn GetModuleHandleW(name: *const u16) -> usize;
    fn GetProcAddress(module: usize, name: *const u8) -> usize;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    out_str("PANIC\n");
    flush();
    unsafe { ExitProcess(101) }
}

// C intrinsics the compiler may reference; volatile so they never lower
// into calls to themselves.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
    dst
}
#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) < (src as usize) {
        return memcpy(dst, src, n);
    }
    let mut i = n;
    while i > 0 {
        i -= 1;
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
    }
    dst
}
#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, value: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dst.add(i), value as u8);
        i += 1;
    }
    dst
}
#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let (x, y) = (core::ptr::read_volatile(a.add(i)), core::ptr::read_volatile(b.add(i)));
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}
#[no_mangle]
pub static _fltused: i32 = 0;

/// The C++ personality libcore's unwind tables name. With `panic=abort`
/// nothing unwinds, so it is never called.
#[no_mangle]
pub extern "C" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> u32 {
    1 // ExceptionContinueSearch
}

// `__chkstk` for frames over a page (normally from the CRT): touch each page
// between the caller's stack pointer and the new frame, top down, so the
// guard page is met in order. RAX holds the frame size; all registers are
// preserved.
core::arch::global_asm!(
    ".globl __chkstk",
    "__chkstk:",
    "push rcx",
    "push rax",
    "lea rcx, [rsp + 24]",
    "2:",
    "cmp rax, 0x1000",
    "jb 3f",
    "sub rcx, 0x1000",
    "test [rcx], rcx",
    "sub rax, 0x1000",
    "jmp 2b",
    "3:",
    "sub rcx, rax",
    "test [rcx], rcx",
    "pop rax",
    "pop rcx",
    "ret",
);

// ---- output ------------------------------------------------------------------

static mut OUT: [u8; 4096] = [0; 4096];
static mut OUT_LEN: usize = 0;

fn flush() {
    unsafe {
        let length = OUT_LEN;
        if length == 0 {
            return;
        }
        let mut written = 0u32;
        WriteFile(GetStdHandle(0xFFFF_FFF5), core::ptr::addr_of!(OUT) as *const u8, length as u32, &mut written, 0);
        OUT_LEN = 0;
    }
}

fn out_byte(byte: u8) {
    unsafe {
        if OUT_LEN == 4096 {
            flush();
        }
        (*core::ptr::addr_of_mut!(OUT))[OUT_LEN] = byte;
        OUT_LEN += 1;
        if byte == b'\n' {
            flush();
        }
    }
}

fn out_str(text: &str) {
    for byte in text.bytes() {
        out_byte(byte);
    }
}

fn out_dec(value: u64) {
    let mut digits = [0u8; 20];
    let mut count = 0;
    let mut rest = value;
    loop {
        digits[count] = b'0' + (rest % 10) as u8;
        count += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        out_byte(digits[count]);
    }
}

fn out_hex(value: u64) {
    out_str("0x");
    let mut started = false;
    let mut shift = 60i32;
    while shift >= 0 {
        let nibble = ((value >> shift) & 0xf) as u8;
        if nibble != 0 || started || shift == 0 {
            started = true;
            out_byte(if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 });
        }
        shift -= 4;
    }
}

/// A UTF-16 string as quoted text: ASCII as is, `"` and `\` escaped as
/// `\"` `\\`, anything else as `\u{XXXX}`.
fn out_wide_quoted(text: &[u16]) {
    out_byte(b'"');
    for &unit in text {
        match unit {
            0x22 => out_str("\\\""),
            0x5c => out_str("\\\\"),
            0x20..=0x7e => out_byte(unit as u8),
            _ => {
                out_str("\\u{");
                out_hex(unit as u64);
                out_byte(b'}');
            }
        }
    }
    out_byte(b'"');
}

// ---- wide strings -----------------------------------------------------------

/// A NUL-terminated UTF-16 copy of ASCII `text` in `buffer`.
fn wide<'a>(text: &str, buffer: &'a mut [u16]) -> &'a [u16] {
    let mut length = 0;
    for byte in text.bytes() {
        buffer[length] = byte as u16;
        length += 1;
    }
    buffer[length] = 0;
    &buffer[..=length]
}

fn wide_len(text: &[u16]) -> usize {
    text.iter().position(|&unit| unit == 0).unwrap_or(text.len())
}

fn lower(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 32 } else { unit }
}

// ---- normalization ------------------------------------------------------------

static mut WORK: [u16; 520] = [0; 520];
static mut WORK_LEN: usize = 0;
static mut BASE: [u16; 520] = [0; 520];
static mut BASE_LEN: usize = 0;

/// Record the directory the probe started in, printed as `<B>`.
fn set_base_dir(path: &[u16]) {
    unsafe {
        let length = wide_len(path);
        (&mut *core::ptr::addr_of_mut!(BASE))[..length].copy_from_slice(&path[..length]);
        BASE_LEN = length;
    }
}

/// Whether `prefix` (case-insensitively) starts `path` at `at` and ends at
/// a component boundary.
fn prefix_at(path: &[u16], at: usize, prefix: &[u16]) -> bool {
    !prefix.is_empty()
        && at + prefix.len() <= path.len()
        && (0..prefix.len()).all(|k| lower(path[at + k]) == lower(prefix[k]))
        && (at + prefix.len() == path.len() || matches!(path[at + prefix.len()], 0x5c | 0x2f))
}

/// Record the probe's work directory (an absolute DOS path, no trailing
/// separator) for normalization.
fn set_work_dir(path: &[u16]) {
    unsafe {
        let length = wide_len(path);
        (&mut *core::ptr::addr_of_mut!(WORK))[..length].copy_from_slice(&path[..length]);
        WORK_LEN = length;
    }
}

/// Print a path from Windows with the work directory shown as `<W>`, the
/// base directory as `<B>`, and a leading drive letter (plain or after
/// `\\?\`) as `<D>`.
fn out_path(path: &[u16]) {
    let length = wide_len(path);
    let path = &path[..length];
    let (work, work_len) = unsafe { (&*core::ptr::addr_of!(WORK), WORK_LEN) };
    let (base, base_len) = unsafe { (&*core::ptr::addr_of!(BASE), BASE_LEN) };
    let drive = if work_len > 0 { lower(work[0]) } else { 0 };
    let mut normalized = [0u16; 1100];
    let mut n = 0;
    let mut i = 0;
    let push = |normalized: &mut [u16; 1100], n: &mut usize, text: &str| {
        for byte in text.bytes() {
            normalized[*n] = byte as u16;
            *n += 1;
        }
    };
    // `\\?\` then a drive letter, or a drive letter at the start.
    let verbatim = length >= 6 && path[..4] == [0x5c, 0x5c, 0x3f, 0x5c];
    let drive_at = if verbatim { 4 } else { 0 };
    while i < length {
        if prefix_at(path, i, &work[..work_len]) {
            // Keep a drive letter that differs in case from the work
            // directory's visible: `<d>:` marks a lowercase one.
            if path[i] != work[0] && work_len > 2 && work[1] == 0x3a {
                push(&mut normalized, &mut n, "<d>:<W:nodrive>");
            } else {
                push(&mut normalized, &mut n, "<W>");
            }
            i += work_len;
            continue;
        }
        if base_len > 3 && prefix_at(path, i, &base[..base_len]) {
            push(&mut normalized, &mut n, "<B>");
            i += base_len;
            continue;
        }
        // The work directory without its drive (`\dir\...`), as
        // VOLUME_NAME_NONE reports it.
        if work_len > 2 && work[1] == 0x3a && prefix_at(path, i, &work[2..work_len]) {
            push(&mut normalized, &mut n, "<W:nodrive>");
            i += work_len - 2;
            continue;
        }
        if i == drive_at && i + 1 < length && path[i + 1] == 0x3a && lower(path[i]) == drive {
            push(&mut normalized, &mut n, if path[i] == work[0] { "<D>" } else { "<d>" });
            i += 1;
            continue;
        }
        normalized[n] = path[i];
        n += 1;
        i += 1;
    }
    out_wide_quoted(&normalized[..n]);
}

// ---- input paths ---------------------------------------------------------------

/// An input path: ASCII, with `{W}` standing for the work directory, `{w}`
/// for it without its drive (`\\dir\\...`), `{D}` for its drive letter, and
/// `{d}` for the drive letter in lowercase.
fn input<'a>(template: &str, buffer: &'a mut [u16; 1024]) -> &'a [u16] {
    let (work, work_len) = unsafe { (&*core::ptr::addr_of!(WORK), WORK_LEN) };
    let bytes = template.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"{W}") {
            buffer[n..n + work_len].copy_from_slice(&work[..work_len]);
            n += work_len;
            i += 3;
        } else if bytes[i..].starts_with(b"{w}") {
            buffer[n..n + work_len - 2].copy_from_slice(&work[2..work_len]);
            n += work_len - 2;
            i += 3;
        } else if bytes[i..].starts_with(b"{D}") {
            buffer[n] = work[0];
            n += 1;
            i += 3;
        } else if bytes[i..].starts_with(b"{d}") {
            buffer[n] = lower(work[0]);
            n += 1;
            i += 3;
        } else {
            buffer[n] = bytes[i] as u16;
            n += 1;
            i += 1;
        }
    }
    buffer[n] = 0;
    &buffer[..=n]
}

// ---- API lookup ---------------------------------------------------------------

/// The address of `name` (NUL-terminated) in kernel32, or 0.
fn kernel32(name: &[u8]) -> usize {
    let mut module = [0u16; 16];
    unsafe { GetProcAddress(GetModuleHandleW(wide("kernel32.dll", &mut module).as_ptr()), name.as_ptr()) }
}

type GetLastErrorFn = unsafe extern "system" fn() -> u32;
type SetLastErrorFn = unsafe extern "system" fn(u32);

fn last_error() -> u32 {
    let address = kernel32(b"GetLastError\0");
    if address == 0 {
        return u32::MAX;
    }
    unsafe { core::mem::transmute::<usize, GetLastErrorFn>(address)() }
}

/// Clear the last error before a call, so a stale code is never reported.
fn clear_error() {
    let address = kernel32(b"SetLastError\0");
    if address != 0 {
        unsafe { core::mem::transmute::<usize, SetLastErrorFn>(address)(0) };
    }
}

/// `case <name>: ` prefix of a line.
fn case(name: &str) {
    out_str(name);
    out_str(": ");
}

/// `<label>=ok` when a returned length equals `actual` (the string's
/// length), else `<label>=len<+/-delta>`: never an absolute, machine-specific
/// number.
fn out_len_relation(label: &str, returned: u32, actual: usize) {
    out_str(label);
    out_byte(b'=');
    if returned as usize == actual {
        out_str("ok");
        return;
    }
    out_str("len");
    if returned as usize > actual {
        out_byte(b'+');
        out_dec((returned as usize - actual) as u64);
    } else {
        out_byte(b'-');
        out_dec((actual - returned as usize) as u64);
    }
}

/// ` err=<n>` for a failed call.
fn out_error() {
    out_str(" err=");
    out_dec(last_error() as u64);
}

fn unavailable(name: &str) {
    case(name);
    out_str("unavailable\n");
}

/// Resolve `$name` from kernel32 as a function of type `$ty`, or print the
/// case as unavailable and `return` from the enclosing function.
macro_rules! api {
    ($case:expr, $name:literal, $ty:ty) => {{
        let address = kernel32(concat!($name, "\0").as_bytes());
        if address == 0 {
            unavailable($case);
            return;
        }
        unsafe { core::mem::transmute::<usize, $ty>(address) }
    }};
}
