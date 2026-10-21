//! The system msvcrt.dll that MinGW programs (Git for Windows) link,
//! where its contracts differ from the UCRT's, plus `PathRemoveFileSpecW`
//! and the SID and file-owner calls such programs use to decide whether a
//! directory belongs to the current user.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");

type Load = unsafe extern "system" fn(*const u16) -> usize;
type VsnPrintf = unsafe extern "C" fn(*mut u8, usize, *const u8, *const u64) -> i32;
type VscPrintf = unsafe extern "C" fn(*const u8, *const u64) -> i32;
type SwPrintf = unsafe extern "C" fn(*mut u16, *const u16, ...) -> i32;
type Srand = unsafe extern "C" fn(u32);
type Rand = unsafe extern "C" fn() -> i32;
type IsCtype = unsafe extern "C" fn(i32, i32) -> i32;
type IsClass = unsafe extern "C" fn(i32) -> i32;
type LocaleConv = unsafe extern "C" fn() -> *const usize;
type MkTime = unsafe extern "C" fn(*mut i32) -> i64;
type GmTime = unsafe extern "C" fn(*const i64) -> *const i32;
type StrToU64 = unsafe extern "C" fn(*const u8, *mut *const u8, i32) -> u64;
type WcsSpn = unsafe extern "C" fn(*const u16, *const u16) -> usize;
type RemoveSpec = unsafe extern "system" fn(*mut u16) -> i32;
type NamedSecurity = unsafe extern "system" fn(*const u16, u32, u32, *mut usize, *mut usize, *mut usize, *mut usize, *mut usize) -> u32;
type OpenToken = unsafe extern "system" fn(usize, u32, *mut usize) -> i32;
type TokenInfo = unsafe extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32;
type SidCheck = unsafe extern "system" fn(usize) -> i32;
type SidLength = unsafe extern "system" fn(usize) -> u32;
type EqualSid = unsafe extern "system" fn(usize, usize) -> i32;
type WellKnown = unsafe extern "system" fn(usize, u32) -> i32;
type Membership = unsafe extern "system" fn(usize, usize, *mut i32) -> i32;
type AllocateSid = unsafe extern "system" fn(*const u8, u8, u32, u32, u32, u32, u32, u32, u32, u32, *mut usize) -> i32;
type SidString = unsafe extern "system" fn(usize, *mut *const u8) -> i32;
type Current = unsafe extern "system" fn() -> usize;

fn module(name: &str) -> usize {
    let load = kernel32(b"LoadLibraryW\0");
    if load == 0 {
        return 0;
    }
    let mut buffer = [0u16; 32];
    unsafe { core::mem::transmute::<usize, Load>(load)(wide(name, &mut buffer).as_ptr()) }
}

macro_rules! from {
    ($module:expr, $case:expr, $name:literal, $ty:ty) => {{
        let address = unsafe { GetProcAddress($module, concat!($name, "\0").as_ptr()) };
        if address == 0 {
            unavailable($case);
            return;
        }
        unsafe { core::mem::transmute::<usize, $ty>(address) }
    }};
}

fn out_bytes_quoted(bytes: &[u8]) {
    out_byte(b'"');
    for &byte in bytes {
        if (0x20..0x7f).contains(&byte) {
            out_byte(byte);
        } else {
            out_str("\\x");
            out_hex(byte as u64);
        }
    }
    out_byte(b'"');
}

fn c_text(pointer: *const u8) -> &'static [u8] {
    let mut length = 0;
    while unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    unsafe { core::slice::from_raw_parts(pointer, length) }
}

fn probe() {
    let crt = module("msvcrt.dll");
    let vsnprintf = from!(crt, "crt.vsnprintf", "_vsnprintf", VsnPrintf);
    let vscprintf = from!(crt, "crt.vscprintf", "_vscprintf", VscPrintf);
    let swprintf = from!(crt, "crt.swprintf", "swprintf", SwPrintf);
    let srand = from!(crt, "crt.srand", "srand", Srand);
    let rand = from!(crt, "crt.rand", "rand", Rand);
    let isctype = from!(crt, "crt.isctype", "_isctype", IsCtype);
    let iscntrl = from!(crt, "crt.iscntrl", "iscntrl", IsClass);
    let isgraph = from!(crt, "crt.isgraph", "isgraph", IsClass);
    let ispunct = from!(crt, "crt.ispunct", "ispunct", IsClass);
    let localeconv = from!(crt, "crt.localeconv", "localeconv", LocaleConv);
    let mktime = from!(crt, "crt.mktime64", "_mktime64", MkTime);
    let gmtime = from!(crt, "crt.gmtime64", "_gmtime64", GmTime);
    let strtoui64 = from!(crt, "crt.strtoui64", "_strtoui64", StrToU64);
    let wcsspn = from!(crt, "crt.wcsspn", "wcsspn", WcsSpn);

    // _vsnprintf: shorter, exact and longer than the count.
    for (label, count) in [("vsnprintf.short", 8usize), ("vsnprintf.exact", 5), ("vsnprintf.long", 3)] {
        let mut buffer = [b'#'; 8];
        let arguments = [b"abcde\0".as_ptr() as u64];
        let result = unsafe { vsnprintf(buffer.as_mut_ptr(), count, b"%s\0".as_ptr(), arguments.as_ptr()) };
        case(label);
        out_str("ret=");
        out_hex(result as u32 as u64);
        out_str(" buffer=");
        out_bytes_quoted(&buffer[..6]);
        out_byte(b'\n');
    }
    let arguments = [42u64];
    case("vscprintf");
    out_dec(unsafe { vscprintf(b"n=%d\0".as_ptr(), arguments.as_ptr()) } as u64);
    out_byte(b'\n');
    let mut wide_out = [0x2au16; 16];
    let format = [b'%' as u16, b'd' as u16, b'-' as u16, b'%' as u16, b's' as u16, 0];
    let text = [b'w' as u16, 0];
    let result = unsafe { swprintf(wide_out.as_mut_ptr(), format.as_ptr(), 7i32, text.as_ptr()) };
    case("swprintf");
    out_str("ret=");
    out_dec(result as u64);
    out_str(" text=");
    out_wide_quoted(&wide_out[..wide_len(&wide_out)]);
    out_byte(b'\n');

    unsafe { srand(1) };
    case("rand.seed1");
    for _ in 0..3 {
        out_dec(unsafe { rand() } as u64);
        out_byte(b' ');
    }
    out_byte(b'\n');

    case("ctype");
    for value in [b'A' as i32, b'f' as i32, b'z' as i32, b'5' as i32, b' ' as i32, b'\t' as i32, b'\n' as i32, b'!' as i32, 0x7f, 0xe9, -1] {
        out_hex(unsafe { isctype(value, 0xffff) } as u64);
        out_byte(b' ');
    }
    out_byte(b'\n');
    case("ctype.classes");
    for value in [b'~' as i32, b' ' as i32, 0x1f] {
        out_str(if unsafe { iscntrl(value) } != 0 { "c" } else { "-" });
        out_str(if unsafe { isgraph(value) } != 0 { "g" } else { "-" });
        out_str(if unsafe { ispunct(value) } != 0 { "p " } else { "- " });
    }
    out_byte(b'\n');

    let lconv = unsafe { localeconv() };
    case("localeconv");
    unsafe {
        out_bytes_quoted(c_text(*lconv as *const u8));
        out_byte(b' ');
        out_bytes_quoted(c_text(*lconv.add(1) as *const u8));
        out_byte(b' ');
        out_bytes_quoted(c_text(*lconv.add(2) as *const u8));
        out_str(" frac=");
        out_dec(*(lconv.add(10) as *const u8) as u64);
    }
    out_byte(b'\n');

    // 32 January 2001, noon: normalized to 1 February.
    let mut tm = [0, 0, 12, 32, 0, 101, 0, 0, -1];
    let seconds = unsafe { mktime(tm.as_mut_ptr()) };
    case("mktime64.normalized");
    out_str(if seconds > 0 { "ok" } else { "fail" });
    for field in [3, 4, 5, 6, 7] {
        out_byte(b' ');
        out_dec(tm[field] as u64);
    }
    out_byte(b'\n');
    let epoch = 86_400i64 * 365 + 3_661;
    let utc = unsafe { gmtime(&epoch) };
    case("gmtime64");
    for field in 0..9 {
        out_dec(unsafe { *utc.add(field) } as u64);
        out_byte(b' ');
    }
    out_byte(b'\n');
    for (label, seconds) in [("gmtime64.negative", -1i64), ("gmtime64.half_day", -43_200), ("gmtime64.past_half_day", -43_201), ("gmtime64.year_before", -31_536_000)] {
        case(label);
        out_str(if unsafe { gmtime(&seconds) }.is_null() { "null\n" } else { "value\n" });
    }
    let mut end = core::ptr::null();
    case("strtoui64");
    out_dec(unsafe { strtoui64(b"18446744073709551615x\0".as_ptr(), &mut end, 10) });
    out_byte(b'\n');
    let span_text = [b'a' as u16, b'b' as u16, b'a' as u16, b'c' as u16, 0];
    let accept = [b'a' as u16, b'b' as u16, 0];
    case("wcsspn");
    out_dec(unsafe { wcsspn(span_text.as_ptr(), accept.as_ptr()) } as u64);
    out_byte(b'\n');

    let shell = module("shlwapi.dll");
    let remove_spec = from!(shell, "path.remove_file_spec", "PathRemoveFileSpecW", RemoveSpec);
    for input in ["C:\\dir\\file.exe", "C:\\file.exe", "C:\\", "file.exe", "\\file", "\\\\server\\share", "dir\\", "C:file"] {
        let mut buffer = [0u16; 64];
        wide(input, &mut buffer);
        let result = unsafe { remove_spec(buffer.as_mut_ptr()) };
        case("path.remove_file_spec");
        out_wide_quoted(&wide(input, &mut [0u16; 64])[..input.len()]);
        out_str(" -> ");
        out_wide_quoted(&buffer[..wide_len(&buffer)]);
        out_str(" ret=");
        out_dec(result as u64);
        out_byte(b'\n');
    }

    // Ownership of a file this process creates, as Git's safe.directory
    // check reads it.
    let advapi = module("advapi32.dll");
    let named = from!(advapi, "sid.named_security", "GetNamedSecurityInfoW", NamedSecurity);
    let open_token = from!(advapi, "sid.open_token", "OpenProcessToken", OpenToken);
    let token_info = from!(advapi, "sid.token_info", "GetTokenInformation", TokenInfo);
    let valid = from!(advapi, "sid.valid", "IsValidSid", SidCheck);
    let length = from!(advapi, "sid.length", "GetLengthSid", SidLength);
    let equal = from!(advapi, "sid.equal", "EqualSid", EqualSid);
    let well_known = from!(advapi, "sid.well_known", "IsWellKnownSid", WellKnown);
    let membership = from!(advapi, "sid.membership", "CheckTokenMembership", Membership);
    let allocate = from!(advapi, "sid.allocate", "AllocateAndInitializeSid", AllocateSid);
    let sid_string = from!(advapi, "sid.string", "ConvertSidToStringSidA", SidString);
    let current = api!("sid.process", "GetCurrentProcess", Current);
    let create: unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize =
        unsafe { core::mem::transmute(kernel32(b"CreateFileW\0")) };
    let close: unsafe extern "system" fn(usize) -> i32 = unsafe { core::mem::transmute(kernel32(b"CloseHandle\0")) };
    let mut path = [0u16; 32];
    wide("owned.txt", &mut path);
    unsafe { close(create(path.as_ptr(), 0x4000_0000, 0, 0, 2, 0x80, 0)) };
    unsafe {
        let mut token = 0;
        open_token(current(), 0x8, &mut token);
        let mut user = [0u8; 128];
        let mut needed = 0;
        token_info(token, 1, user.as_mut_ptr(), 128, &mut needed);
        let user_sid = *(user.as_ptr() as *const usize);
        let (mut owner, mut dacl, mut descriptor) = (0usize, 0usize, 0usize);
        let result = named(path.as_ptr(), 1, 0x1 | 0x4, &mut owner, core::ptr::null_mut(), &mut dacl, core::ptr::null_mut(), &mut descriptor);
        case("owner.file");
        out_str("ret=");
        out_dec(result as u64);
        if result == 0 {
            // The creator owns the file: the user, or for an elevated
            // administrator the Administrators group the token holds.
            let mut admin = 0;
            let admin_owner = well_known(owner, 26) != 0 && membership(0, owner, &mut admin) != 0 && admin != 0;
            out_str(if equal(owner, user_sid) != 0 || admin_owner { " owner=creator" } else { " owner=other" });
            out_str(if dacl != 0 { " dacl" } else { " no_dacl" });
            out_str(if valid(owner) != 0 { " valid" } else { " invalid" });
        }
        out_byte(b'\n');
        let mut missing = [0u16; 32];
        let result = named(wide("missing.txt", &mut missing).as_ptr(), 1, 0x1, &mut owner, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), &mut descriptor);
        case("owner.missing");
        out_dec(result as u64);
        out_byte(b'\n');

        let nt_authority = [0u8, 0, 0, 0, 0, 5];
        let mut administrators = 0;
        allocate(nt_authority.as_ptr(), 2, 32, 544, 0, 0, 0, 0, 0, 0, &mut administrators);
        let mut users = 0;
        allocate(nt_authority.as_ptr(), 2, 32, 545, 0, 0, 0, 0, 0, 0, &mut users);
        let mut text = core::ptr::null();
        sid_string(administrators, &mut text);
        case("sid.administrators");
        out_bytes_quoted(c_text(text));
        out_str(" length=");
        out_dec(length(administrators) as u64);
        out_str(" well_known=");
        out_dec(well_known(administrators, 26) as u64);
        out_str(" as_users=");
        out_dec(well_known(administrators, 27) as u64);
        out_byte(b'\n');
        let mut member = -1;
        case("membership.users");
        out_dec(membership(0, users, &mut member) as u64);
        out_str(" member=");
        out_dec(member as u64);
        out_byte(b'\n');
        let mut member = -1;
        case("membership.user");
        out_dec(membership(0, user_sid, &mut member) as u64);
        out_str(" member=");
        out_dec(member as u64);
        out_byte(b'\n');
    }
    out_str("END\n");
}

#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe legacy_runtime\n");
    probe();
    flush();
    unsafe { ExitProcess(0) }
}
