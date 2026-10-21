//! Security identifiers and file ownership.
//!
//! The guest has one user, the token's (`system_profile::USER_SID`), which
//! is not elevated. Every file belongs to that user, so programs that
//! check a repository's or profile's owner against the current user (Git's
//! `safe.directory`) see their own files as theirs. SIDs are the binary
//! layout: revision 1, a sub-authority count, a six-byte big-endian
//! identifier authority, and 32-bit sub-authorities.

use super::*;
use super::registry::native_local_free;
use crate::system_profile::{COMPUTER_NAME, USER_NAME, USER_SID};

const ERROR_NONE_MAPPED: u32 = 1332;

/// The SID at `sid`, if it is well formed.
fn sid_bytes<'a>(sid: *const u8) -> Option<&'a [u8]> {
    if sid.is_null() {
        return None;
    }
    let (revision, count) = unsafe { (sid.read(), sid.add(1).read()) };
    (revision == 1 && count <= 15).then(|| unsafe { std::slice::from_raw_parts(sid, 8 + 4 * usize::from(count)) })
}

/// `S-1-5-21-…` text for a binary SID.
fn sid_text(sid: &[u8]) -> String {
    let authority = sid[2..8].iter().fold(0u64, |value, byte| value << 8 | u64::from(*byte));
    let mut text = format!("S-1-{authority}");
    for chunk in sid[8..].chunks_exact(4) {
        text.push_str(&format!("-{}", u32::from_le_bytes(chunk.try_into().unwrap())));
    }
    text
}

/// The groups the token's user belongs to, besides itself: Everyone,
/// Authenticated Users and the built-in Users group (not Administrators;
/// the token is not elevated).
const MEMBER_GROUPS: [&str; 3] = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"];

pub(super) extern "win64" fn native_is_valid_sid(sid: *const u8) -> i32 {
    sid_bytes(sid).is_some() as i32
}

pub(super) extern "win64" fn native_get_length_sid(sid: *const u8) -> u32 {
    sid_bytes(sid).map_or(0, |sid| sid.len() as u32)
}

pub(super) extern "win64" fn native_equal_sid(first: *const u8, second: *const u8) -> i32 {
    native_set_last_error(0);
    match (sid_bytes(first), sid_bytes(second)) {
        (Some(first), Some(second)) => (first == second) as i32,
        _ => 0,
    }
}

pub(super) extern "win64" fn native_copy_sid(length: u32, destination: *mut u8, source: *const u8) -> i32 {
    let Some(source) = sid_bytes(source) else {
        native_set_last_error(87);
        return 0;
    };
    if (length as usize) < source.len() || destination.is_null() {
        native_set_last_error(122);
        return 0;
    }
    unsafe { ptr::copy_nonoverlapping(source.as_ptr(), destination, source.len()) };
    1
}

/// `AllocateAndInitializeSid(authority, count, s0..s7, sid)`; `FreeSid`
/// releases it.
#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_allocate_and_initialize_sid(
    authority: *const u8,
    count: u8,
    s0: u32,
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    s5: u32,
    s6: u32,
    s7: u32,
    output: *mut u64,
) -> i32 {
    if authority.is_null() || output.is_null() || count == 0 || count > 8 {
        native_set_last_error(87);
        return 0;
    }
    let mut sid = vec![1, count];
    sid.extend_from_slice(unsafe { std::slice::from_raw_parts(authority, 6) });
    for value in [s0, s1, s2, s3, s4, s5, s6, s7].into_iter().take(usize::from(count)) {
        sid.extend_from_slice(&value.to_le_bytes());
    }
    let block = native_local_alloc(0, sid.len());
    if block == 0 {
        return 0;
    }
    unsafe {
        ptr::copy_nonoverlapping(sid.as_ptr(), block as *mut u8, sid.len());
        output.write_unaligned(block);
    }
    1
}

pub(super) extern "win64" fn native_free_sid(sid: u64) -> u64 {
    native_local_free(sid);
    0
}

/// `IsWellKnownSid(sid, type)` for the `WELL_KNOWN_SID_TYPE` values with a
/// fixed SID.
pub(super) extern "win64" fn native_is_well_known_sid(sid: *const u8, kind: u32) -> i32 {
    let expected = match kind {
        0 => "S-1-0-0",       // WinNullSid
        1 => "S-1-1-0",       // WinWorldSid
        2 => "S-1-2-0",       // WinLocalSid
        3 => "S-1-3-0",       // WinCreatorOwnerSid
        11 => "S-1-5-4",      // WinInteractiveSid
        17 => "S-1-5-11",     // WinAuthenticatedUserSid
        22 => "S-1-5-18",     // WinLocalSystemSid
        23 => "S-1-5-19",     // WinLocalServiceSid
        24 => "S-1-5-20",     // WinNetworkServiceSid
        26 => "S-1-5-32-544", // WinBuiltinAdministratorsSid
        27 => "S-1-5-32-545", // WinBuiltinUsersSid
        28 => "S-1-5-32-546", // WinBuiltinGuestsSid
        _ => return 0,
    };
    sid_bytes(sid).is_some_and(|sid| sid_text(sid) == expected) as i32
}

/// `CheckTokenMembership(token, sid, is_member)` for the process's token
/// (or the thread's, which is the same).
pub(super) extern "win64" fn native_check_token_membership(_token: u64, sid: *const u8, is_member: *mut i32) -> i32 {
    let Some(sid) = sid_bytes(sid) else {
        native_set_last_error(87);
        return 0;
    };
    if is_member.is_null() {
        native_set_last_error(998);
        return 0;
    }
    let text = sid_text(sid);
    let member = text == USER_SID || MEMBER_GROUPS.contains(&text.as_str());
    unsafe { is_member.write(member as i32) };
    1
}

/// `ConvertSidToStringSidA(sid, text)`: the `S-…` form in a `LocalAlloc`
/// block.
pub(super) extern "win64" fn native_convert_sid_to_string_sid_a(sid: *const u8, output: *mut u64) -> i32 {
    let Some(sid) = sid_bytes(sid) else {
        native_set_last_error(1337); // ERROR_INVALID_SID
        return 0;
    };
    if output.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let text = sid_text(sid);
    let block = native_local_alloc(0, text.len() + 1);
    if block == 0 {
        return 0;
    }
    unsafe {
        ptr::copy_nonoverlapping(text.as_ptr(), block as *mut u8, text.len());
        (block as *mut u8).add(text.len()).write(0);
        output.write_unaligned(block);
    }
    1
}

/// `LookupAccountSidA(system, sid, name, name_size, domain, domain_size,
/// use)`: the token user's account (`SidTypeUser`, in the computer's
/// domain); other SIDs are not mapped.
pub(super) extern "win64" fn native_lookup_account_sid_a(
    _system: *const u8,
    sid: *const u8,
    name: *mut u8,
    name_size: *mut u32,
    domain: *mut u8,
    domain_size: *mut u32,
    usage: *mut u32,
) -> i32 {
    let Some(sid) = sid_bytes(sid) else {
        native_set_last_error(87);
        return 0;
    };
    if name_size.is_null() || domain_size.is_null() {
        native_set_last_error(998);
        return 0;
    }
    if sid_text(sid) != USER_SID {
        native_set_last_error(ERROR_NONE_MAPPED);
        return 0;
    }
    let (name_capacity, domain_capacity) = unsafe { (name_size.read(), domain_size.read()) };
    let fits = name_capacity as usize > USER_NAME.len() && domain_capacity as usize > COMPUTER_NAME.len();
    if !fits || name.is_null() || domain.is_null() {
        unsafe {
            name_size.write(USER_NAME.len() as u32 + 1);
            domain_size.write(COMPUTER_NAME.len() as u32 + 1);
        }
        native_set_last_error(122);
        return 0;
    }
    unsafe {
        for (text, output, size) in [(USER_NAME, name, name_size), (COMPUTER_NAME, domain, domain_size)] {
            ptr::copy_nonoverlapping(text.as_ptr(), output, text.len());
            output.add(text.len()).write(0);
            size.write(text.len() as u32);
        }
        if !usage.is_null() {
            usage.write(1); // SidTypeUser
        }
    }
    1
}

/// An ACCESS_ALLOWED_ACE granting `mask` to `sid`, inherited.
fn allowed_ace(sid: &[u8], mask: u32) -> Vec<u8> {
    let size = 8 + sid.len();
    let mut ace = vec![0, 0x10]; // ACCESS_ALLOWED_ACE_TYPE, INHERITED_ACE
    ace.extend_from_slice(&(size as u16).to_le_bytes());
    ace.extend_from_slice(&mask.to_le_bytes());
    ace.extend_from_slice(sid);
    ace
}

/// The self-relative security descriptor of a guest file: owned by the
/// token's user, with a DACL giving full control to SYSTEM,
/// Administrators and the user.
fn file_descriptor(information: u32) -> (Vec<u8>, [u32; 4]) {
    const OWNER: u32 = 0x1;
    const GROUP: u32 = 0x2;
    const DACL: u32 = 0x4;
    let user = binary_sid(USER_SID);
    let mut descriptor = vec![0u8; 20];
    let mut offsets = [0u32; 4]; // owner, group, sacl, dacl
    let mut control: u16 = 0x8000; // SE_SELF_RELATIVE
    if information & OWNER != 0 {
        offsets[0] = descriptor.len() as u32;
        descriptor.extend_from_slice(&user);
    }
    if information & GROUP != 0 {
        // The user's primary group: its domain's Users (RID 513).
        let mut group = user.clone();
        let last = group.len() - 4;
        group[last..].copy_from_slice(&513u32.to_le_bytes());
        offsets[1] = descriptor.len() as u32;
        descriptor.extend_from_slice(&group);
    }
    if information & DACL != 0 {
        control |= 0x4 | 0x400; // SE_DACL_PRESENT, SE_DACL_AUTO_INHERITED
        let aces: Vec<u8> = [binary_sid("S-1-5-18"), binary_sid("S-1-5-32-544"), user]
            .iter()
            .flat_map(|sid| allowed_ace(sid, 0x001f_01ff)) // FILE_ALL_ACCESS
            .collect();
        offsets[3] = descriptor.len() as u32;
        descriptor.extend_from_slice(&[2, 0]); // ACL_REVISION
        descriptor.extend_from_slice(&((8 + aces.len()) as u16).to_le_bytes());
        descriptor.extend_from_slice(&3u16.to_le_bytes());
        descriptor.extend_from_slice(&[0, 0]);
        descriptor.extend_from_slice(&aces);
    }
    descriptor[0] = 1;
    descriptor[2..4].copy_from_slice(&control.to_le_bytes());
    for (index, offset) in offsets.iter().enumerate() {
        descriptor[4 + index * 4..8 + index * 4].copy_from_slice(&offset.to_le_bytes());
    }
    (descriptor, offsets)
}

/// `GetNamedSecurityInfoW(name, type, information, owner, group, dacl,
/// sacl, descriptor)` for files and directories (`SE_FILE_OBJECT`); the
/// descriptor is a `LocalAlloc` block the out pointers point into.
#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_get_named_security_info_w(
    name: *const u16,
    kind: u32,
    information: u32,
    owner: *mut u64,
    group: *mut u64,
    dacl: *mut u64,
    sacl: *mut u64,
    descriptor_out: *mut u64,
) -> u32 {
    const SE_FILE_OBJECT: u32 = 1;
    if name.is_null() || kind != SE_FILE_OBJECT {
        return 87;
    }
    if information & 0x8 != 0 {
        return 1314; // ERROR_PRIVILEGE_NOT_HELD: SACLs need SeSecurityPrivilege
    }
    if native_get_file_attributes_w(name) == u32::MAX {
        return native_get_last_error();
    }
    let (bytes, offsets) = file_descriptor(information);
    let block = native_local_alloc(0, bytes.len());
    if block == 0 {
        return 8;
    }
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), block as *mut u8, bytes.len()) };
    let at = |offset: u32| if offset == 0 { 0 } else { block + u64::from(offset) };
    unsafe {
        for (output, offset) in [(owner, offsets[0]), (group, offsets[1]), (sacl, offsets[2]), (dacl, offsets[3])] {
            if !output.is_null() {
                output.write_unaligned(at(offset));
            }
        }
        if descriptor_out.is_null() {
            native_local_free(block);
        } else {
            descriptor_out.write_unaligned(block);
        }
    }
    0
}

/// `BCryptOpenAlgorithmProvider`: no CNG algorithm providers are available
/// yet (`STATUS_NOT_FOUND`); `BCryptGenRandom` takes a null provider.
pub(super) extern "win64" fn native_bcrypt_open_algorithm_provider(provider: *mut u64, _algorithm: *const u16, _implementation: *const u16, _flags: u32) -> u32 {
    if !provider.is_null() {
        unsafe { provider.write_unaligned(0) };
    }
    0xC000_0225 // STATUS_NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sids_round_trip_through_text_and_compare_by_value() {
        let user = binary_sid(USER_SID);
        assert_eq!(sid_text(&user), USER_SID);
        assert_eq!(native_get_length_sid(user.as_ptr()), 28);
        let copy = user.clone();
        assert_eq!(native_equal_sid(user.as_ptr(), copy.as_ptr()), 1);
        let admins = binary_sid("S-1-5-32-544");
        assert_eq!(native_equal_sid(user.as_ptr(), admins.as_ptr()), 0);
        assert_eq!(native_is_well_known_sid(admins.as_ptr(), 26), 1);
        assert_eq!(native_is_well_known_sid(user.as_ptr(), 26), 0);
        let mut small = [0u8; 8];
        assert_eq!(native_copy_sid(8, small.as_mut_ptr(), user.as_ptr()), 0);
        assert_eq!(native_get_last_error(), 122);
    }

    #[test]
    fn token_membership_has_the_user_but_not_administrators() {
        let mut member = -1;
        let user = binary_sid(USER_SID);
        assert_eq!(native_check_token_membership(0, user.as_ptr(), &mut member), 1);
        assert_eq!(member, 1);
        let admins = binary_sid("S-1-5-32-544");
        assert_eq!(native_check_token_membership(0, admins.as_ptr(), &mut member), 1);
        assert_eq!(member, 0);
    }

    #[test]
    fn file_descriptors_name_the_user_as_owner() {
        let (descriptor, offsets) = file_descriptor(0x1 | 0x4);
        assert_eq!(descriptor[0], 1);
        assert_eq!(u16::from_le_bytes([descriptor[2], descriptor[3]]) & 0x8004, 0x8004);
        let owner = &descriptor[offsets[0] as usize..offsets[0] as usize + 28];
        assert_eq!(sid_text(owner), USER_SID);
        assert_eq!(offsets[1], 0, "no group unless asked");
        let dacl = &descriptor[offsets[3] as usize..];
        assert_eq!(u16::from_le_bytes([dacl[4], dacl[5]]), 3, "three ACEs");
    }
}
