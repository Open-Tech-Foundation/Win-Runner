//! `PathCchSkipRoot`, `PathCchCombineEx`, `PathCchCanonicalizeEx` and
//! `PathCchRemoveFileSpec` (api-ms-win-core-path-l1-1-0).

const S_OK: i32 = 0;
const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
const INSUFFICIENT_BUFFER: i32 = 0x8007_007Au32 as i32;
const FILENAME_EXCED_RANGE: i32 = 0x8007_00CEu32 as i32;
const PATHCCH_ALLOW_LONG_PATHS: u32 = 1;

/// Length in UTF-16 units of the root a path starts with: `C:\`, `C:`,
/// `\`, `\\server\share\`, `\\?\C:\` and `\\?\UNC\server\share\`.
fn root_length(path: &[u16]) -> Option<usize> {
    let text = String::from_utf16_lossy(path);
    let is_sep = |c: char| c == '\\' || c == '/';
    let after_share = |rest: &str, prefix: usize| -> usize {
        // server\share, then the separator after the share if present.
        let mut parts = 0;
        let mut index = prefix;
        for (offset, c) in rest.char_indices() {
            if is_sep(c) {
                parts += 1;
                if parts == 2 {
                    return prefix + offset + 1;
                }
            }
            index = prefix + offset + c.len_utf16();
        }
        index
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return Some(after_share(rest, 8));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        let drive = rest.as_bytes();
        if drive.len() >= 2 && drive[0].is_ascii_alphabetic() && drive[1] == b':' {
            return Some(if drive.get(2).is_some_and(|c| *c == b'\\') { 7 } else { 6 });
        }
        return None;
    }
    if text.starts_with(r"\\") {
        return Some(after_share(&text[2..], 2));
    }
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Some(if bytes.get(2).is_some_and(|c| is_sep(*c as char)) { 3 } else { 2 });
    }
    if text.starts_with(is_sep) {
        return Some(1);
    }
    None
}

fn units(text: *const u16) -> Option<Vec<u16>> {
    if text.is_null() {
        return None;
    }
    let mut out = Vec::new();
    for index in 0..32768usize {
        let unit = unsafe { text.add(index).read() };
        if unit == 0 {
            return Some(out);
        }
        out.push(unit);
    }
    None
}

/// Remove `.` and `..` segments; `..` never climbs above the root.
fn canonicalize(path: &[u16]) -> Vec<u16> {
    let root = root_length(path).unwrap_or(0);
    let text = String::from_utf16_lossy(path);
    let (prefix, rest) = text.split_at(String::from_utf16_lossy(&path[..root]).len());
    let mut segments: Vec<&str> = Vec::new();
    for segment in rest.split('\\') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    let mut result = prefix.to_string();
    // A drive with no separator becomes the drive's root (`C:` → `C:\`)
    // once anything follows it.
    if !segments.is_empty() && !result.is_empty() && !result.ends_with('\\') {
        result.push('\\');
    }
    result.push_str(&segments.join("\\"));
    if text.ends_with('\\') && !segments.is_empty() {
        result.push('\\');
    }
    if result.is_empty() {
        result.push('\\');
    }
    result.encode_utf16().collect()
}

fn write_out(out: *mut u16, capacity: usize, flags: u32, value: &[u16]) -> i32 {
    if out.is_null() || capacity == 0 {
        return E_INVALIDARG;
    }
    if flags & PATHCCH_ALLOW_LONG_PATHS == 0 && value.len() + 1 > 260 {
        unsafe { out.write(0) };
        return FILENAME_EXCED_RANGE;
    }
    if value.len() + 1 > capacity {
        unsafe { out.write(0) };
        return INSUFFICIENT_BUFFER;
    }
    unsafe {
        out.copy_from_nonoverlapping(value.as_ptr(), value.len());
        out.add(value.len()).write(0);
    }
    S_OK
}

pub(super) extern "win64" fn native_path_cch_skip_root(path: *const u16, root_end: *mut *const u16) -> i32 {
    let Some(text) = units(path) else {
        return E_INVALIDARG;
    };
    if root_end.is_null() {
        return E_INVALIDARG;
    }
    match root_length(&text) {
        Some(length) => {
            unsafe { root_end.write(path.add(length)) };
            S_OK
        }
        None => E_INVALIDARG,
    }
}

pub(super) extern "win64" fn native_path_cch_canonicalize_ex(
    out: *mut u16,
    capacity: usize,
    path: *const u16,
    flags: u32,
) -> i32 {
    let Some(text) = units(path) else {
        return E_INVALIDARG;
    };
    write_out(out, capacity, flags, &canonicalize(&text))
}

pub(super) extern "win64" fn native_path_cch_combine_ex(
    out: *mut u16,
    capacity: usize,
    first: *const u16,
    second: *const u16,
    flags: u32,
) -> i32 {
    let first = units(first).unwrap_or_default();
    let second = units(second).unwrap_or_default();
    if first.is_empty() && second.is_empty() {
        return write_out(out, capacity, flags, &[b'\\' as u16]);
    }
    let combined: Vec<u16> = match root_length(&second) {
        // A path with a drive or UNC root replaces the first.
        Some(_) if second.first() != Some(&(b'\\' as u16)) || second.starts_with(&[92, 92]) => second,
        // `\x` is relative to the first path's root.
        Some(_) => {
            let root = root_length(&first).unwrap_or(0);
            let mut path = first[..root].to_vec();
            while path.last() == Some(&(b'\\' as u16)) {
                path.pop();
            }
            path.extend(&second);
            path
        }
        None if second.is_empty() => first,
        None => {
            let mut path = first;
            if !path.is_empty() && path.last() != Some(&(b'\\' as u16)) {
                path.push(b'\\' as u16);
            }
            path.extend(&second);
            path
        }
    };
    write_out(out, capacity, flags, &canonicalize(&combined))
}

/// `PathCchRemoveFileSpec(path, cch)`: drop the last element (and the
/// separator before it), never the root. `S_FALSE` when nothing is left
/// to remove.
pub(super) extern "win64" fn native_path_cch_remove_file_spec(path: *mut u16, capacity: usize) -> i32 {
    const S_FALSE: i32 = 1;
    const PATHCCH_MAX_CCH: usize = 32768;
    if path.is_null() || capacity == 0 || capacity > PATHCCH_MAX_CCH {
        return E_INVALIDARG;
    }
    let Some(text) = units(path) else {
        return E_INVALIDARG;
    };
    if text.len() >= capacity {
        return E_INVALIDARG;
    }
    let root = root_length(&text).unwrap_or(0).min(text.len());
    if text.len() == root {
        return S_FALSE;
    }
    let last_separator = text[root..]
        .iter()
        .rposition(|unit| *unit == u16::from(b'\\') || *unit == u16::from(b'/'))
        .map(|offset| root + offset);
    let end = last_separator.unwrap_or(root);
    unsafe { path.add(end).write(0) };
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn combine(a: &str, b: &str) -> String {
        let mut out = [0u16; 300];
        assert_eq!(native_path_cch_combine_ex(out.as_mut_ptr(), 300, w(a).as_ptr(), w(b).as_ptr(), 0), 0, "{a} + {b}");
        String::from_utf16_lossy(&out[..out.iter().position(|u| *u == 0).unwrap()])
    }

    #[test]
    fn roots_and_combinations() {
        for (path, root) in [(r"C:\a\b", 3), ("C:", 2), (r"\x", 1), (r"\\srv\share\x", 12), (r"\\?\C:\x", 7)] {
            let text = w(path);
            let mut end = std::ptr::null();
            assert_eq!(native_path_cch_skip_root(text.as_ptr(), &mut end), 0, "{path}");
            assert_eq!(unsafe { end.offset_from(text.as_ptr()) }, root, "{path}");
        }
        let relative = w("rel");
        let mut end = std::ptr::null();
        assert_eq!(native_path_cch_skip_root(relative.as_ptr(), &mut end), E_INVALIDARG);
        assert_eq!(combine(r"C:\a", r"b\..\c"), r"C:\a\c");
        assert_eq!(combine(r"C:\a", r"D:\x"), r"D:\x");
        assert_eq!(combine(r"C:\a\b", r"\z"), r"C:\z");
        assert_eq!(combine(r"C:\a", r"..\..\.."), r"C:\");
        assert_eq!(combine(r"C:\a\", "b"), r"C:\a\b");
        let remove = |path: &str| {
            let mut buffer = [0u16; 64];
            let text = w(path);
            buffer[..text.len()].copy_from_slice(&text);
            let result = native_path_cch_remove_file_spec(buffer.as_mut_ptr(), 64);
            (result, String::from_utf16_lossy(&buffer[..buffer.iter().position(|u| *u == 0).unwrap()]))
        };
        assert_eq!(remove(r"C:\venv\Scripts\python.exe"), (0, r"C:\venv\Scripts".to_string()));
        assert_eq!(remove(r"C:\a"), (0, r"C:\".to_string()));
        assert_eq!(remove(r"C:\"), (1, r"C:\".to_string()), "the root stays");
        assert_eq!(remove(r"C:\a\"), (0, r"C:\a".to_string()));
        assert_eq!(remove(r"\\srv\share\x"), (0, r"\\srv\share\".to_string()));
        assert_eq!(remove("name"), (0, String::new()));
        assert_eq!(native_path_cch_remove_file_spec(std::ptr::null_mut(), 10), E_INVALIDARG);
        let mut small = [0u16; 4];
        assert_eq!(
            native_path_cch_combine_ex(small.as_mut_ptr(), 4, w(r"C:\abc").as_ptr(), w("d").as_ptr(), 0),
            INSUFFICIENT_BUFFER
        );
    }
}
