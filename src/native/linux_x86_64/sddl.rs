//! `ConvertStringSecurityDescriptorToSecurityDescriptorW`: SDDL text
//! (`O:BAG:SYD:P(A;OICI;FA;;;SY)`) to a self-relative `SECURITY_DESCRIPTOR`
//! in `LocalAlloc` memory. Owner, group, and a DACL of allow and deny ACEs
//! are supported; SACLs and object ACEs are reported as invalid.

use super::*;

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_UNKNOWN_REVISION: u32 = 1305;
const ERROR_NONE_MAPPED: u32 = 1332;

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_SELF_RELATIVE: u16 = 0x8000;

/// A SID's binary form from `S-1-...` text or an SDDL alias.
fn sid(text: &str) -> Result<Vec<u8>, u32> {
    let alias = match text {
        "WD" => "S-1-1-0",
        "CO" => "S-1-3-0",
        "CG" => "S-1-3-1",
        "OW" => "S-1-3-4",
        "NU" => "S-1-5-2",
        "IU" => "S-1-5-4",
        "SU" => "S-1-5-6",
        "AN" => "S-1-5-7",
        "AU" => "S-1-5-11",
        "RC" => "S-1-5-12",
        "SY" => "S-1-5-18",
        "LS" => "S-1-5-19",
        "NS" => "S-1-5-20",
        "BA" => "S-1-5-32-544",
        "BU" => "S-1-5-32-545",
        "BG" => "S-1-5-32-546",
        "AC" => "S-1-15-2-1",
        other => other,
    };
    let mut parts = alias.strip_prefix("S-").ok_or(ERROR_NONE_MAPPED)?.split('-');
    let revision: u8 = parts.next().and_then(|r| r.parse().ok()).ok_or(ERROR_INVALID_PARAMETER)?;
    let authority: u64 = parts.next().and_then(|a| a.parse().ok()).ok_or(ERROR_INVALID_PARAMETER)?;
    let subauthorities: Vec<u32> = parts
        .map(|s| s.parse().map_err(|_| ERROR_INVALID_PARAMETER))
        .collect::<Result<_, _>>()?;
    if revision != 1 || subauthorities.len() > 15 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut out = vec![1, subauthorities.len() as u8];
    out.extend_from_slice(&authority.to_be_bytes()[2..]);
    for value in subauthorities {
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(out)
}

/// An access mask: `0x...` or concatenated two-letter rights.
fn rights(text: &str) -> Result<u32, u32> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).map_err(|_| ERROR_INVALID_PARAMETER);
    }
    let mut mask = 0;
    for chunk in text.as_bytes().chunks(2) {
        mask |= match chunk {
            b"GA" => 0x1000_0000,
            b"GR" => 0x8000_0000,
            b"GW" => 0x4000_0000,
            b"GX" => 0x2000_0000,
            b"RC" => 0x0002_0000,
            b"SD" => 0x0001_0000,
            b"WD" => 0x0004_0000,
            b"WO" => 0x0008_0000,
            b"FA" => 0x001F_01FF,
            b"FR" => 0x0012_0089,
            b"FW" => 0x0012_0116,
            b"FX" => 0x0012_00A0,
            b"KA" => 0x000F_003F,
            b"KR" | b"KX" => 0x0002_0019,
            b"KW" => 0x0002_0006,
            b"CC" => 0x1,
            b"DC" => 0x2,
            b"LC" => 0x4,
            b"SW" => 0x8,
            b"RP" => 0x10,
            b"WP" => 0x20,
            b"DT" => 0x40,
            b"LO" => 0x80,
            b"CR" => 0x100,
            _ => return Err(ERROR_INVALID_PARAMETER),
        };
    }
    Ok(mask)
}

/// One `(type;flags;rights;object;inherited object;sid)` ACE.
fn ace(text: &str) -> Result<Vec<u8>, u32> {
    let fields: Vec<&str> = text.split(';').collect();
    let [kind, flags, mask, object, inherited, account] = fields.as_slice() else {
        return Err(ERROR_INVALID_PARAMETER);
    };
    let kind: u8 = match *kind {
        "A" => 0,
        "D" => 1,
        _ => return Err(ERROR_INVALID_PARAMETER),
    };
    if !object.is_empty() || !inherited.is_empty() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut ace_flags = 0u8;
    for chunk in flags.as_bytes().chunks(2) {
        ace_flags |= match chunk {
            b"OI" => 0x01,
            b"CI" => 0x02,
            b"NP" => 0x04,
            b"IO" => 0x08,
            b"ID" => 0x10,
            _ => return Err(ERROR_INVALID_PARAMETER),
        };
    }
    let account = sid(account)?;
    let size = 8 + account.len();
    let mut out = vec![kind, ace_flags];
    out.extend_from_slice(&(size as u16).to_le_bytes());
    out.extend_from_slice(&rights(mask)?.to_le_bytes());
    out.extend_from_slice(&account);
    Ok(out)
}

/// A DACL's flags and ACL bytes from the text after `D:` (`None` for
/// `NO_ACCESS_CONTROL`, a present but null DACL).
fn dacl(text: &str) -> Result<(u16, Option<Vec<u8>>), u32> {
    let (flags_text, aces_text) = text.split_at(text.find('(').unwrap_or(text.len()));
    let mut control = 0;
    let mut rest = flags_text;
    let mut null = false;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("NO_ACCESS_CONTROL") {
            null = true;
            rest = after;
        } else if let Some(after) = rest.strip_prefix("AI") {
            control |= SE_DACL_AUTO_INHERITED;
            rest = after;
        } else if let Some(after) = rest.strip_prefix("AR") {
            control |= SE_DACL_AUTO_INHERIT_REQ;
            rest = after;
        } else if let Some(after) = rest.strip_prefix('P') {
            control |= SE_DACL_PROTECTED;
            rest = after;
        } else {
            return Err(ERROR_INVALID_PARAMETER);
        }
    }
    let mut aces = Vec::new();
    let mut remaining = aces_text;
    while !remaining.is_empty() {
        let body = remaining.strip_prefix('(').ok_or(ERROR_INVALID_PARAMETER)?;
        let end = body.find(')').ok_or(ERROR_INVALID_PARAMETER)?;
        aces.push(ace(&body[..end])?);
        remaining = &body[end + 1..];
    }
    if null {
        return Ok((control, None));
    }
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut acl = vec![2, 0];
    acl.extend_from_slice(&(size as u16).to_le_bytes());
    acl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    acl.extend_from_slice(&[0, 0]);
    for entry in aces {
        acl.extend_from_slice(&entry);
    }
    Ok((control, Some(acl)))
}

/// A self-relative security descriptor for an SDDL string.
pub(super) fn security_descriptor(text: &str) -> Result<Vec<u8>, u32> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    // Split into `X:` sections; a section runs to the next `O:`/`G:`/`D:`/`S:`
    // outside parentheses.
    let mut sections: Vec<(char, String)> = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut depth = 0;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && matches!(c, 'O' | 'G' | 'D' | 'S') && chars.get(index + 1) == Some(&':') {
            sections.push((c, String::new()));
            index += 2;
            continue;
        }
        match sections.last_mut() {
            Some((_, body)) => body.push(c),
            None => return Err(ERROR_INVALID_PARAMETER),
        }
        index += 1;
    }
    let mut control = SE_SELF_RELATIVE;
    let (mut owner, mut group, mut acl) = (None, None, None);
    for (kind, body) in sections {
        match kind {
            'O' => owner = Some(sid(&body)?),
            'G' => group = Some(sid(&body)?),
            'D' => {
                let (flags, list) = dacl(&body)?;
                control |= SE_DACL_PRESENT | flags;
                acl = list;
            }
            _ => return Err(ERROR_INVALID_PARAMETER),
        }
    }
    let mut out = vec![0u8; 20];
    out[0] = 1;
    let place = |out: &mut Vec<u8>, data: Option<Vec<u8>>, offset_at: usize| {
        if let Some(data) = data {
            let offset = out.len() as u32;
            out.extend_from_slice(&data);
            out[offset_at..offset_at + 4].copy_from_slice(&offset.to_le_bytes());
        }
    };
    place(&mut out, acl, 16);
    place(&mut out, owner, 4);
    place(&mut out, group, 8);
    out[2..4].copy_from_slice(&control.to_le_bytes());
    Ok(out)
}

pub(super) extern "win64" fn native_convert_string_security_descriptor_to_security_descriptor_w(
    text: *const u16,
    revision: u32,
    descriptor: *mut u64,
    size: *mut u32,
) -> i32 {
    if text.is_null() || descriptor.is_null() {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if revision != 1 {
        native_set_last_error(ERROR_UNKNOWN_REVISION);
        return 0;
    }
    let Some(text) = wide(text) else {
        native_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let bytes = match security_descriptor(&text) {
        Ok(bytes) => bytes,
        Err(code) => {
            native_set_last_error(code);
            return 0;
        }
    };
    // LocalAlloc memory: the caller frees it with LocalFree.
    let memory = native_heap_alloc(PROCESS_HEAP_HANDLE, 0, bytes.len());
    if memory == 0 {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), memory as *mut u8, bytes.len());
        descriptor.write(memory);
        if !size.is_null() {
            size.write(bytes.len() as u32);
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_private_directory_descriptor_encodes() {
        // What CPython passes for os.mkdir(path, 0o700).
        let sd = security_descriptor("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)").unwrap();
        assert_eq!(sd[0], 1);
        let control = u16::from_le_bytes([sd[2], sd[3]]);
        assert_eq!(control, SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED);
        let dacl = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
        assert_eq!(dacl, 20);
        assert_eq!(u16::from_le_bytes([sd[dacl + 4], sd[dacl + 5]]), 3, "three ACEs");
        let first = &sd[dacl + 8..];
        assert_eq!(&first[..2], &[0, 3], "allow, object and container inherit");
        assert_eq!(u32::from_le_bytes(first[4..8].try_into().unwrap()), 0x1F01FF);
        assert_eq!(&first[8..20], &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0], "S-1-5-18");
        let acl_size = u16::from_le_bytes([sd[dacl + 2], sd[dacl + 3]]) as usize;
        assert_eq!(sd.len(), dacl + acl_size);
    }

    #[test]
    fn owners_groups_and_errors() {
        let sd = security_descriptor("O:BAG:SY").unwrap();
        let owner = u32::from_le_bytes(sd[4..8].try_into().unwrap()) as usize;
        assert_eq!(&sd[owner..owner + 16], &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]);
        assert_eq!(u16::from_le_bytes([sd[2], sd[3]]), SE_SELF_RELATIVE, "no DACL");
        assert_eq!(rights("0x1F01FF"), Ok(0x1F01FF));
        assert_eq!(rights("GRGX"), Ok(0xA000_0000));
        assert_eq!(security_descriptor("D:(X;;FA;;;SY)"), Err(ERROR_INVALID_PARAMETER));
        assert_eq!(security_descriptor("D:(A;;FA;;;ZZ)"), Err(ERROR_NONE_MAPPED));
        assert_eq!(security_descriptor("garbage"), Err(ERROR_INVALID_PARAMETER));
    }
}
