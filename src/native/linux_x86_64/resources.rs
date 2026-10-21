//! PE resources: `FindResource(Ex)A/W`, `LoadResource`, `LockResource`,
//! `SizeofResource` and `FreeResource`, read from the `.rsrc` directory of
//! the mapped image. An `HRSRC` is the resource's data entry and an
//! `HGLOBAL` the resource bytes themselves, as on Windows.

use super::*;

const ERROR_RESOURCE_DATA_NOT_FOUND: u32 = 1812;
const ERROR_RESOURCE_TYPE_NOT_FOUND: u32 = 1813;
const ERROR_RESOURCE_NAME_NOT_FOUND: u32 = 1814;
const ERROR_RESOURCE_LANG_NOT_FOUND: u32 = 1815;

/// A resource type, name or language: an integer ID or a string.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    Id(u16),
    Name(String),
}

/// `MAKEINTRESOURCE` values are below 0x10000; `"#123"` also names ID 123.
fn key_from(text: Option<String>, pointer: u64) -> Option<Key> {
    if pointer < 0x1_0000 {
        return Some(Key::Id(pointer as u16));
    }
    let text = text?;
    if let Some(id) = text.strip_prefix('#').and_then(|digits| digits.parse::<u16>().ok()) {
        return Some(Key::Id(id));
    }
    Some(Key::Name(text.to_uppercase()))
}

fn ansi_key(pointer: u64) -> Option<Key> {
    let text = (pointer >= 0x1_0000)
        .then(|| unsafe { std::ffi::CStr::from_ptr(pointer as *const std::ffi::c_char) })
        .map(|text| text.to_string_lossy().into_owned());
    key_from(text, pointer)
}

fn wide_key(pointer: u64) -> Option<Key> {
    let text = (pointer >= 0x1_0000).then(|| wide(pointer as *const u16)).flatten();
    key_from(text, pointer)
}

/// Modules loaded as data (`LOAD_LIBRARY_AS_DATAFILE`): base and mapped
/// length. Their handles are the base with a low-bit tag, as on Windows.
static DATA_MODULES: std::sync::Mutex<Vec<(u64, usize)>> = std::sync::Mutex::new(Vec::new());

/// Map `bytes`' headers and sections for reading their resources; nothing
/// runs and no imports resolve. The handle is `base | 2` for
/// `LOAD_LIBRARY_AS_IMAGE_RESOURCE`, else `base | 1`.
pub(super) fn load_data_module(bytes: &[u8], image_resource: bool) -> Option<u64> {
    let read_u32 = |offset: usize| bytes.get(offset..offset + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let read_u16 = |offset: usize| bytes.get(offset..offset + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()));
    if bytes.get(..2) != Some(b"MZ") {
        return None;
    }
    let headers = read_u32(0x3c)? as usize;
    if bytes.get(headers..headers + 4) != Some(b"PE\0\0") {
        return None;
    }
    let sections = read_u16(headers + 6)? as usize;
    let optional = read_u16(headers + 20)? as usize;
    let image_size = read_u32(headers + 24 + 56)? as usize;
    let header_size = (read_u32(headers + 24 + 60)? as usize).min(bytes.len());
    let length = image_size.div_ceil(4096) * 4096;
    if length == 0 || length > 1 << 30 {
        return None;
    }
    let base = unsafe {
        libc::mmap(ptr::null_mut(), length, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    if base == libc::MAP_FAILED {
        return None;
    }
    let base = base as u64;
    let copy = |rva: usize, from: usize, count: usize| {
        if rva.saturating_add(count) <= length && from.saturating_add(count) <= bytes.len() {
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr().add(from), (base as *mut u8).add(rva), count) };
        }
    };
    copy(0, 0, header_size);
    let table = headers + 24 + optional;
    for index in 0..sections {
        let entry = table + index * 40;
        let (virtual_size, rva, raw_size, raw_offset) =
            (read_u32(entry + 8)? as usize, read_u32(entry + 12)? as usize, read_u32(entry + 16)? as usize, read_u32(entry + 20)? as usize);
        copy(rva, raw_offset, raw_size.min(virtual_size.max(raw_size)));
    }
    unsafe { libc::mprotect(base as *mut libc::c_void, length, libc::PROT_READ) };
    DATA_MODULES.lock().ok()?.push((base, length));
    Some(base | if image_resource { 2 } else { 1 })
}

/// Whether `module` is a handle `load_data_module` returned.
pub(super) fn is_data_module(module: u64) -> bool {
    module & 3 != 0 && DATA_MODULES.lock().is_ok_and(|modules| modules.iter().any(|(base, _)| *base == module & !3))
}

/// `FreeLibrary` on a data module: unmap it; `None` for other handles.
pub(super) fn free_data_module(module: u64) -> Option<i32> {
    if module & 3 == 0 {
        return None;
    }
    let mut modules = DATA_MODULES.lock().ok()?;
    let index = modules.iter().position(|(base, _)| *base == module & !3)?;
    let (base, length) = modules.remove(index);
    unsafe { libc::munmap(base as *mut libc::c_void, length) };
    Some(1)
}

/// A mapped image this process loaded (the program or one of its DLLs), or
/// a module loaded as data.
fn image_base(module: u64) -> Option<u64> {
    if module & 3 != 0 {
        let base = module & !3;
        return DATA_MODULES.lock().ok()?.iter().any(|(start, _)| *start == base).then_some(base);
    }
    let process = process_ctx()?;
    if module == 0 || module == process.image_base {
        return Some(process.image_base);
    }
    let modules = process.loaded_modules.lock().ok()?;
    modules.values().any(|loaded| loaded.base == module).then_some(module)
}

unsafe fn read_u16(address: u64) -> u16 {
    unsafe { (address as *const u16).read_unaligned() }
}

unsafe fn read_u32(address: u64) -> u32 {
    unsafe { (address as *const u32).read_unaligned() }
}

/// The resource directory's address, or 0 when the image has none.
fn resource_root(base: u64) -> u64 {
    unsafe {
        let pe = base + u64::from(read_u32(base + 0x3c));
        let optional = pe + 24;
        let magic = read_u16(optional);
        // Data directory 2 (resources) in a PE32+ or PE32 optional header.
        let directories = optional + if magic == 0x20b { 112 } else { 96 };
        let count = read_u32(optional + if magic == 0x20b { 108 } else { 92 });
        if count <= 2 {
            return 0;
        }
        let rva = read_u32(directories + 16);
        let size = read_u32(directories + 20);
        if rva == 0 || size == 0 {
            0
        } else {
            base + u64::from(rva)
        }
    }
}

/// The entries of one resource directory: (key, offset with the
/// subdirectory bit).
fn entries(root: u64, directory: u64) -> Vec<(Key, u32)> {
    unsafe {
        let named = read_u16(directory + 12) as u64;
        let ids = read_u16(directory + 14) as u64;
        (0..named + ids)
            .map(|index| {
                let entry = directory + 16 + index * 8;
                let name = read_u32(entry);
                let offset = read_u32(entry + 4);
                let key = if name & 0x8000_0000 != 0 {
                    let string = root + u64::from(name & 0x7fff_ffff);
                    let length = read_u16(string) as usize;
                    let units = std::slice::from_raw_parts((string + 2) as *const u16, length);
                    Key::Name(String::from_utf16_lossy(units).to_uppercase())
                } else {
                    Key::Id(name as u16)
                };
                (key, offset)
            })
            .collect()
    }
}

fn find(module: u64, kind: Option<Key>, name: Option<Key>, language: Option<u16>) -> u64 {
    let Some(base) = image_base(module) else {
        native_set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND);
        return 0;
    };
    let (Some(kind), Some(name)) = (kind, name) else {
        native_set_last_error(87);
        return 0;
    };
    locate(base, &kind, &name, language).unwrap_or_else(|code| {
        native_set_last_error(code);
        0
    })
}

/// The data entry of a resource in the image at `base`, or the error
/// FindResource reports.
fn locate(base: u64, kind: &Key, name: &Key, language: Option<u16>) -> Result<u64, u32> {
    let fail = Err;
    let root = resource_root(base);
    if root == 0 {
        return fail(ERROR_RESOURCE_DATA_NOT_FOUND);
    }
    let subdirectory = |directory: u64, key: &Key| {
        entries(root, directory)
            .into_iter()
            .find(|(entry, offset)| entry == key && offset & 0x8000_0000 != 0)
            .map(|(_, offset)| root + u64::from(offset & 0x7fff_ffff))
    };
    let Some(types) = subdirectory(root, kind) else {
        return fail(ERROR_RESOURCE_TYPE_NOT_FOUND);
    };
    let Some(names) = subdirectory(types, name) else {
        return fail(ERROR_RESOURCE_NAME_NOT_FOUND);
    };
    let languages = entries(root, names);
    let chosen = match language {
        Some(language) => languages.iter().find(|(key, _)| *key == Key::Id(language)),
        None => languages.first(),
    };
    match chosen {
        Some((_, offset)) if offset & 0x8000_0000 == 0 => Ok(root + u64::from(*offset)),
        _ => fail(ERROR_RESOURCE_LANG_NOT_FOUND),
    }
}

/// The main program's application manifest (`RT_MANIFEST`, ID 1), as text.
pub(super) fn main_manifest() -> Option<String> {
    const RT_MANIFEST: u16 = 24;
    let base = process_ctx()?.image_base;
    let entry = locate(base, &Key::Id(RT_MANIFEST), &Key::Id(1), None).ok()?;
    let (offset, size) = unsafe { (read_u32(entry), read_u32(entry + 4)) };
    let bytes = unsafe { std::slice::from_raw_parts((base + u64::from(offset)) as *const u8, size as usize) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

pub(super) extern "win64" fn native_find_resource_a(module: u64, name: u64, kind: u64) -> u64 {
    find(module, ansi_key(kind), ansi_key(name), None)
}

pub(super) extern "win64" fn native_find_resource_w(module: u64, name: u64, kind: u64) -> u64 {
    find(module, wide_key(kind), wide_key(name), None)
}

pub(super) extern "win64" fn native_find_resource_ex_a(module: u64, kind: u64, name: u64, language: u16) -> u64 {
    find(module, ansi_key(kind), ansi_key(name), Some(language))
}

pub(super) extern "win64" fn native_find_resource_ex_w(module: u64, kind: u64, name: u64, language: u16) -> u64 {
    find(module, wide_key(kind), wide_key(name), Some(language))
}

pub(super) extern "win64" fn native_load_resource(module: u64, resource: u64) -> u64 {
    let Some(base) = image_base(module).filter(|_| resource != 0) else {
        native_set_last_error(6);
        return 0;
    };
    base + u64::from(unsafe { read_u32(resource) })
}

pub(super) extern "win64" fn native_lock_resource(data: u64) -> u64 {
    data
}

pub(super) extern "win64" fn native_sizeof_resource(module: u64, resource: u64) -> u32 {
    if image_base(module).is_none() || resource == 0 {
        native_set_last_error(6);
        return 0;
    }
    unsafe { read_u32(resource + 4) }
}

/// `LoadStringW(module, id, buffer, size)`: string `id` from the module's
/// `RT_STRING` table (block `id / 16 + 1`, sixteen counted UTF-16 strings
/// each). It copies at most `size - 1` characters and a terminator and
/// returns the count; with `size` 0 it stores a pointer to the read-only
/// string and returns its length. A missing string returns 0.
pub(super) extern "win64" fn native_load_string_w(module: u64, id: u32, output: *mut u16, size: i32) -> i32 {
    const RT_STRING: u16 = 6;
    if output.is_null() {
        native_set_last_error(87);
        return 0;
    }
    // Ok(None): the block exists but the string is empty, which leaves the
    // last error alone (as Windows does); Err: the block's lookup failed.
    let found = image_base(module).ok_or(ERROR_RESOURCE_DATA_NOT_FOUND).and_then(|base| {
        let entry = locate(base, &Key::Id(RT_STRING), &Key::Id(((id >> 4) + 1) as u16), None)?;
        let (offset, length) = unsafe { (read_u32(entry), read_u32(entry + 4)) };
        let mut cursor = base + u64::from(offset);
        let end = cursor + u64::from(length);
        for _ in 0..(id & 15) {
            let count = unsafe { read_u16(cursor) };
            cursor += 2 + u64::from(count) * 2;
            if cursor >= end {
                return Ok(None);
            }
        }
        let count = unsafe { read_u16(cursor) } as usize;
        Ok((count > 0).then_some((cursor + 2, count)))
    });
    let Ok(Some((text, count))) = found else {
        if size > 0 {
            unsafe { output.write(0) };
        }
        if let Err(error) = found {
            native_set_last_error(error);
        }
        return 0;
    };
    if size == 0 {
        unsafe { output.cast::<u64>().write_unaligned(text) };
        return count as i32;
    }
    let copied = count.min(size as usize - 1);
    unsafe {
        output.copy_from_nonoverlapping(text as *const u16, copied);
        output.add(copied).write(0);
    }
    copied as i32
}

/// Obsolete on 32- and 64-bit Windows: resources stay mapped with the image.
pub(super) extern "win64" fn native_free_resource(_data: u64) -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resource directory with RT_RCDATA (10) → "BLOB" → language 1033 →
    /// 4 bytes, laid out as a linker writes it, at `root`.
    fn directory(root: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x100];
        let put32 = |bytes: &mut Vec<u8>, at: usize, value: u32| bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        let put16 = |bytes: &mut Vec<u8>, at: usize, value: u16| bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        // Root: one ID entry, type 10 → subdirectory at 0x18.
        put16(&mut bytes, 14, 1);
        put32(&mut bytes, 16, 10);
        put32(&mut bytes, 20, 0x8000_0018);
        // Types: one named entry, "BLOB" (string at 0x80) → 0x30.
        put16(&mut bytes, 0x18 + 12, 1);
        put32(&mut bytes, 0x18 + 16, 0x8000_0080);
        put32(&mut bytes, 0x18 + 20, 0x8000_0030);
        // Names: language 1033 → data entry at 0x48.
        put16(&mut bytes, 0x30 + 14, 1);
        put32(&mut bytes, 0x30 + 16, 1033);
        put32(&mut bytes, 0x30 + 20, 0x48);
        // Data entry: RVA (relative to the image base, here the root) and size.
        put32(&mut bytes, 0x48, (root as u32) + 0xa0);
        put32(&mut bytes, 0x4c, 4);
        put16(&mut bytes, 0x80, 4);
        for (index, unit) in "Blob".encode_utf16().enumerate() {
            put16(&mut bytes, 0x82 + index * 2, unit);
        }
        bytes[0xa0..0xa4].copy_from_slice(b"data");
        bytes
    }

    #[test]
    fn resource_directories_resolve_ids_names_and_languages() {
        let bytes = directory(0);
        let root = bytes.as_ptr() as u64;
        let types = entries(root, root);
        assert_eq!(types, vec![(Key::Id(10), 0x8000_0018)]);
        let names = entries(root, root + 0x18);
        assert_eq!(names[0].0, Key::Name("BLOB".into()), "names compare upper-cased");
        assert_eq!(key_from(Some("#10".into()), 0x1_0000), Some(Key::Id(10)));
        assert_eq!(key_from(None, 10), Some(Key::Id(10)));
        assert_eq!(key_from(Some("blob".into()), 0x1_0000), Some(Key::Name("BLOB".into())));
    }
}
