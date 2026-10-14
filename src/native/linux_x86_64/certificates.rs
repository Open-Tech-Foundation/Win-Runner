//! CryptoAPI certificate stores: the guest's system stores (read from its
//! registry), memory stores, enumeration, and adding encoded certificates.
//! This supplies data, not certificate-chain verification or private keys.
use super::*;
const NOT_FOUND: u32 = 0x8009_2004;
const ASN1_ERROR: u32 = 0x8009_310b;
const INVALID_ARGUMENT: u32 = 0x8007_0057;
#[repr(C)]
struct CertContext {
    encoding: u32,
    encoded: u64,
    size: u32,
    info: u64,
    store: u64,
}
struct Certificate {
    context: Box<CertContext>,
    _encoded: Vec<u8>,
    _buffers: Vec<Vec<u8>>,
    _info: Box<[u64; 26]>,
    _extensions: Vec<[u64; 4]>,
}
struct Lease {
    certificate: Arc<Certificate>,
    references: usize,
    index: usize,
}
#[derive(Default)]
struct Stores {
    next: u64,
    stores: HashMap<u64, Vec<Arc<Certificate>>>,
    contexts: HashMap<u64, Lease>,
}
static STORES: LazyLock<Mutex<Stores>> = LazyLock::new(|| Mutex::new(Stores::default()));
struct Der<'a> {
    tag: u8,
    all: &'a [u8],
    body: &'a [u8],
}
fn der<'a>(input: &mut &'a [u8], tag: Option<u8>) -> Result<Der<'a>, u32> {
    let bytes = *input;
    let actual = *bytes.first().ok_or(ASN1_ERROR)?;
    if tag.is_some_and(|tag| tag != actual) {
        return Err(ASN1_ERROR);
    }
    let first = *bytes.get(1).ok_or(ASN1_ERROR)?;
    let (header, length) = if first < 128 {
        (2, first as usize)
    } else {
        let count = (first & 127) as usize;
        if count == 0 || count > 4 {
            return Err(ASN1_ERROR);
        }
        let mut length = 0usize;
        for byte in bytes.get(2..2 + count).ok_or(ASN1_ERROR)? {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(*byte as usize))
                .ok_or(ASN1_ERROR)?;
        }
        (2 + count, length)
    };
    let end = header.checked_add(length).ok_or(ASN1_ERROR)?;
    let all = bytes.get(..end).ok_or(ASN1_ERROR)?;
    *input = &bytes[end..];
    Ok(Der {
        tag: actual,
        all,
        body: &all[header..],
    })
}
fn oid(bytes: &[u8]) -> Result<Vec<u8>, u32> {
    let mut components = Vec::new();
    let mut number = 0u64;
    let mut complete = false;
    for byte in bytes {
        number = number
            .checked_mul(128)
            .and_then(|n| n.checked_add((byte & 127) as u64))
            .ok_or(ASN1_ERROR)?;
        complete = byte & 128 == 0;
        if complete {
            components.push(number);
            number = 0;
        }
    }
    if !complete || components.is_empty() {
        return Err(ASN1_ERROR);
    }
    let first = components[0];
    let mut text = format!(
        "{}.{}",
        (first / 40).min(2),
        first - (first / 40).min(2) * 40
    );
    for component in &components[1..] {
        text.push_str(&format!(".{component}"));
    }
    let mut text = text.into_bytes();
    text.push(0);
    Ok(text)
}
fn keep(buffers: &mut Vec<Vec<u8>>, bytes: Vec<u8>) -> u64 {
    let pointer = bytes.as_ptr() as u64;
    buffers.push(bytes);
    pointer
}
fn blob(words: &mut [u64], offset: usize, bytes: &[u8]) {
    words[offset] = bytes.len() as u64;
    words[offset + 1] = if bytes.is_empty() {
        0
    } else {
        bytes.as_ptr() as u64
    };
}
fn algorithm(
    words: &mut [u64],
    offset: usize,
    encoded: Der<'_>,
    buffers: &mut Vec<Vec<u8>>,
) -> Result<(), u32> {
    let mut body = encoded.body;
    words[offset] = keep(buffers, oid(der(&mut body, Some(6))?.body)?);
    if !body.is_empty() {
        blob(words, offset + 1, der(&mut body, None)?.all);
    }
    if !body.is_empty() {
        return Err(ASN1_ERROR);
    }
    Ok(())
}
fn bit_blob(words: &mut [u64], offset: usize, bytes: &[u8]) -> Result<(), u32> {
    let (&unused, data) = bytes.split_first().ok_or(ASN1_ERROR)?;
    if unused > 7 {
        return Err(ASN1_ERROR);
    }
    blob(words, offset, data);
    words[offset + 2] = unused as u64;
    Ok(())
}
fn date(encoded: Der<'_>) -> Result<u64, u32> {
    let text = encoded.body;
    let digits = |start: usize, length: usize| -> Result<i32, u32> {
        let mut value = 0;
        for c in text.get(start..start + length).ok_or(ASN1_ERROR)? {
            if !c.is_ascii_digit() {
                return Err(ASN1_ERROR);
            }
            value = value * 10 + (c - b'0') as i32;
        }
        Ok(value)
    };
    let (year, offset) = match encoded.tag {
        23 if text.len() == 13 => {
            let y = digits(0, 2)?;
            (if y < 50 { 2000 + y } else { 1900 + y }, 2)
        }
        24 if text.len() == 15 => (digits(0, 4)?, 4),
        _ => return Err(ASN1_ERROR),
    };
    if text.last() != Some(&b'Z') {
        return Err(ASN1_ERROR);
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = digits(offset, 2)? - 1;
    tm.tm_mday = digits(offset + 2, 2)?;
    tm.tm_hour = digits(offset + 4, 2)?;
    tm.tm_min = digits(offset + 6, 2)?;
    tm.tm_sec = digits(offset + 8, 2)?;
    let seconds = unsafe { libc::timegm(&mut tm) };
    u64::try_from(seconds.checked_add(11_644_473_600).ok_or(ASN1_ERROR)?)
        .ok()
        .and_then(|n| n.checked_mul(10_000_000))
        .ok_or(ASN1_ERROR)
}
fn certificate(encoded: Vec<u8>, store: u64) -> Result<Arc<Certificate>, u32> {
    let mut bytes = encoded.as_slice();
    let root = der(&mut bytes, Some(48))?;
    if !bytes.is_empty() {
        return Err(ASN1_ERROR);
    }
    let mut root_body = root.body;
    let mut tbs = der(&mut root_body, Some(48))?.body;
    der(&mut root_body, Some(48))?;
    der(&mut root_body, Some(3))?;
    if !root_body.is_empty() {
        return Err(ASN1_ERROR);
    }
    let mut info = Box::new([0u64; 26]);
    let mut buffers = Vec::new();
    if tbs.first() == Some(&0xa0) {
        let mut version = der(&mut tbs, Some(0xa0))?.body;
        let number = der(&mut version, Some(2))?.body;
        if number.len() != 1 || number[0] > 2 || !version.is_empty() {
            return Err(ASN1_ERROR);
        }
        info[0] = number[0] as u64;
    }
    let serial = der(&mut tbs, Some(2))?.body;
    let serial = if serial.len() > 1 && serial[0] == 0 {
        &serial[1..]
    } else {
        serial
    };
    info[1] = serial.len() as u64;
    info[2] = keep(&mut buffers, serial.iter().rev().copied().collect());
    algorithm(&mut *info, 3, der(&mut tbs, Some(48))?, &mut buffers)?;
    blob(&mut *info, 6, der(&mut tbs, Some(48))?.all);
    let mut validity = der(&mut tbs, Some(48))?.body;
    info[8] = date(der(&mut validity, None)?)?;
    info[9] = date(der(&mut validity, None)?)?;
    if !validity.is_empty() {
        return Err(ASN1_ERROR);
    }
    blob(&mut *info, 10, der(&mut tbs, Some(48))?.all);
    let mut key = der(&mut tbs, Some(48))?.body;
    algorithm(&mut *info, 12, der(&mut key, Some(48))?, &mut buffers)?;
    bit_blob(&mut *info, 15, der(&mut key, Some(3))?.body)?;
    if !key.is_empty() {
        return Err(ASN1_ERROR);
    }
    let mut extensions = Vec::new();
    while !tbs.is_empty() {
        let field = der(&mut tbs, None)?;
        match field.tag {
            0x81 => bit_blob(&mut *info, 18, field.body)?,
            0x82 => bit_blob(&mut *info, 21, field.body)?,
            0xa3 => {
                let mut wrapper = field.body;
                let mut sequence = der(&mut wrapper, Some(48))?.body;
                if !wrapper.is_empty() {
                    return Err(ASN1_ERROR);
                }
                while !sequence.is_empty() {
                    let mut entry = der(&mut sequence, Some(48))?.body;
                    let mut extension = [0u64; 4];
                    extension[0] = keep(&mut buffers, oid(der(&mut entry, Some(6))?.body)?);
                    if entry.first() == Some(&1) {
                        let critical = der(&mut entry, Some(1))?.body;
                        if critical.len() != 1 {
                            return Err(ASN1_ERROR);
                        }
                        extension[1] = (critical[0] != 0) as u64;
                    }
                    blob(&mut extension, 2, der(&mut entry, Some(4))?.body);
                    if !entry.is_empty() {
                        return Err(ASN1_ERROR);
                    }
                    extensions.push(extension);
                }
            }
            _ => return Err(ASN1_ERROR),
        }
    }
    info[24] = extensions.len() as u64;
    info[25] = if extensions.is_empty() {
        0
    } else {
        extensions.as_ptr() as u64
    };
    let context = Box::new(CertContext {
        encoding: 1,
        encoded: encoded.as_ptr() as u64,
        size: encoded.len() as u32,
        info: info.as_ptr() as u64,
        store,
    });
    Ok(Arc::new(Certificate {
        context,
        _encoded: encoded,
        _buffers: buffers,
        _info: info,
        _extensions: extensions,
    }))
}
/// The system stores every Windows installation has.
const SYSTEM_STORES: &[&str] = &[
    "ROOT", "CA", "MY", "TRUST", "Disallowed", "AuthRoot", "TrustedPeople", "TrustedPublisher",
];

/// A system store's certificates from the guest registry: the machine's
/// `SOFTWARE\Microsoft\SystemCertificates\<name>\Certificates` then the
/// user's, each certificate a serialized `Blob` (an absent store is empty).
fn system_store(name: &str, store: u64) -> Result<Vec<Arc<Certificate>>, u32> {
    let context = fs_ctx().ok_or(6u32)?;
    let ctx = context.lock().map_err(|_| 6u32)?;
    let registry = crate::winreg::Registry::load(&ctx.fs).map_err(|_| 1015u32)?; // ERROR_REGISTRY_CORRUPT
    crate::trust_roots::store_certificates(&registry, name)
        .into_iter()
        .map(|encoded| certificate(encoded, store))
        .collect()
}

fn decode_usage(bytes: &[u8]) -> Result<Vec<Vec<u8>>, u32> {
    let mut input = bytes;
    let mut sequence = der(&mut input, Some(48))?.body;
    if !input.is_empty() {
        return Err(ASN1_ERROR);
    }
    let mut identifiers = Vec::new();
    while !sequence.is_empty() {
        identifiers.push(oid(der(&mut sequence, Some(6))?.body)?);
    }
    Ok(identifiers)
}
fn enhanced_usage(certificate: &Certificate) -> Result<Option<Vec<Vec<u8>>>, u32> {
    for extension in &certificate._extensions {
        let name = unsafe { std::ffi::CStr::from_ptr(extension[0] as *const i8) };
        if name.to_bytes() == b"2.5.29.37" {
            let bytes = unsafe {
                std::slice::from_raw_parts(extension[3] as *const u8, extension[2] as usize)
            };
            return decode_usage(bytes).map(Some);
        }
    }
    Ok(None)
}
pub(super) extern "win64" fn native_cert_get_enhanced_key_usage(
    pointer: u64,
    flags: u32,
    output: *mut u8,
    size: *mut u32,
) -> i32 {
    // CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG (2) reads the extension only,
    // CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG (4) the context property only;
    // CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG (1) changes nothing here.
    const EXT_ONLY: u32 = 2;
    const PROP_ONLY: u32 = 4;
    if size.is_null() || flags & !7 != 0 || flags & (EXT_ONLY | PROP_ONLY) == EXT_ONLY | PROP_ONLY {
        fail(INVALID_ARGUMENT);
        return 0;
    }
    let certificate = {
        let stores = STORES.lock().unwrap();
        let Some(lease) = stores.contexts.get(&pointer) else {
            fail(INVALID_ARGUMENT);
            return 0;
        };
        Arc::clone(&lease.certificate)
    };
    // No context here carries an enhanced-usage property, so a
    // property-only query finds nothing; otherwise the extension decides.
    let usage = if flags & PROP_ONLY != 0 {
        Ok(None)
    } else {
        enhanced_usage(&certificate)
    };
    let usage = match usage {
        Ok(usage) => usage,
        Err(error) => {
            fail(error);
            return 0;
        }
    };
    if usage.is_none() && flags & (EXT_ONLY | PROP_ONLY) != 0 {
        fail(NOT_FOUND);
        return 0;
    }
    let absent = usage.is_none();
    let identifiers = usage.unwrap_or_default();
    let needed = 16 + identifiers.len() * 8 + identifiers.iter().map(Vec::len).sum::<usize>();
    let capacity = unsafe { size.read_unaligned() } as usize;
    // Windows reports the size for a query or a too-small buffer, and
    // leaves the caller's size as it was after a successful read.
    if output.is_null() || capacity < needed {
        unsafe { size.write_unaligned(needed as u32) };
    }
    if !output.is_null() {
        if capacity < needed {
            fail(234);
            return 0;
        }
        unsafe {
            std::ptr::write_bytes(output, 0, needed);
            output
                .cast::<u32>()
                .write_unaligned(identifiers.len() as u32);
            output
                .add(8)
                .cast::<u64>()
                .write_unaligned(if identifiers.is_empty() {
                    0
                } else {
                    output.add(16) as u64
                });
            let mut offset = 16 + identifiers.len() * 8;
            for (index, identifier) in identifiers.iter().enumerate() {
                output
                    .add(16 + index * 8)
                    .cast::<u64>()
                    .write_unaligned(output.add(offset) as u64);
                std::ptr::copy_nonoverlapping(
                    identifier.as_ptr(),
                    output.add(offset),
                    identifier.len(),
                );
                offset += identifier.len();
            }
        }
    }
    native_set_last_error(if absent { NOT_FOUND } else { 0 });
    1
}

fn fail(error: u32) -> u64 {
    native_set_last_error(error);
    0
}
pub(super) extern "win64" fn native_cert_open_store(
    provider: u64,
    _encoding: u32,
    crypt: u64,
    flags: u32,
    parameter: *const u8,
) -> u64 {
    if crypt != 0 {
        return fail(INVALID_ARGUMENT);
    }
    // A provider is an ID, or (above 0xFFFF) a pointer to its ANSI name:
    // sz_CERT_STORE_PROV_MEMORY "Memory", _COLLECTION "Collection", and
    // _SYSTEM "System" (the Unicode system store).
    let provider = if provider > 0xFFFF {
        match unsafe { ascii_z(provider as *const u8) }.map(|name| name.to_ascii_lowercase()).as_deref() {
            Some("memory") => 2,
            Some("collection") => 11,
            Some("system") => 10,
            _ => return fail(50),
        }
    } else {
        provider
    };
    // CERT_STORE_NO_CRYPT_RELEASE (0x1), DEFER_CLOSE_UNTIL_LAST_FREE (0x4:
    // contexts here keep their certificate alive anyway), OPEN_EXISTING
    // (0x4000), READONLY (0x8000), and the current-user/local-machine
    // locations.
    if flags & !(0x0003_0000 | 0xc005) != 0 {
        return fail(50);
    }
    let mut stores = STORES.lock().unwrap();
    stores.next += 1;
    let handle = 0x4345_5254_0000_0000 | stores.next;
    let certificates = match provider {
        // Memory and collection stores start empty.
        2 | 11 if flags & 0xffff_0000 == 0 => Vec::new(),
        9 | 10 => {
            if !matches!(flags & 0xffff_0000, 0x10000 | 0x20000) {
                return fail(INVALID_ARGUMENT);
            }
            let name = if provider == 9 {
                unsafe { ascii_z(parameter) }.map(str::to_owned)
            } else {
                wide(parameter.cast())
            };
            let Some(name) = name.filter(|name| SYSTEM_STORES.iter().any(|known| known.eq_ignore_ascii_case(name))) else {
                return fail(50);
            };
            match system_store(&name, handle) {
                Ok(certificates) => certificates,
                Err(error) => return fail(error),
            }
        }
        _ => return fail(50),
    };
    stores.stores.insert(handle, certificates);
    handle
}
/// `CertAddStoreToCollection`: the collection gains the sibling's
/// certificates (the same certificates, not copies). It takes them as they
/// are when added; later changes to the sibling are not followed.
pub(super) extern "win64" fn native_cert_add_store_to_collection(
    collection: u64,
    sibling: u64,
    _flags: u32,
    _priority: u32,
) -> i32 {
    let mut stores = STORES.lock().unwrap();
    let Some(members) = stores.stores.get(&sibling).cloned() else {
        drop(stores);
        fail(INVALID_ARGUMENT);
        return 0;
    };
    let Some(certificates) = stores.stores.get_mut(&collection) else {
        drop(stores);
        fail(INVALID_ARGUMENT);
        return 0;
    };
    for certificate in members {
        if !certificates.iter().any(|known| Arc::ptr_eq(known, &certificate)) {
            certificates.push(certificate);
        }
    }
    1
}

fn release(stores: &mut Stores, pointer: u64) -> bool {
    let Some(lease) = stores.contexts.get_mut(&pointer) else {
        return false;
    };
    lease.references -= 1;
    if lease.references == 0 {
        stores.contexts.remove(&pointer);
    }
    true
}
/// `CertGetIntendedKeyUsage`: the key-usage bits (extension 2.5.29.15) of a
/// `CERT_INFO`, zero-padded to the caller's size. Without the extension it
/// returns FALSE, zeroes the buffer, and leaves the last error 0.
pub(super) extern "win64" fn native_cert_get_intended_key_usage(
    _encoding: u32,
    info: *const u64,
    usage: *mut u8,
    size: u32,
) -> i32 {
    if info.is_null() || (usage.is_null() && size != 0) {
        native_set_last_error(87);
        return 0;
    }
    if size != 0 {
        unsafe { std::ptr::write_bytes(usage, 0, size as usize) };
    }
    // CERT_INFO.cExtension and .rgExtension are its last two words; each
    // CERT_EXTENSION is { pszObjId, fCritical, Value { cbData, pbData } }.
    let (count, extensions) = unsafe {
        (
            info.add(24).read_unaligned() as u32 as usize,
            info.add(25).read_unaligned() as *const u64,
        )
    };
    native_set_last_error(0);
    if extensions.is_null() {
        return 0;
    }
    for index in 0..count {
        let extension = unsafe { extensions.add(index * 4) };
        let id = unsafe { extension.read_unaligned() } as *const u8;
        if unsafe { ascii_z(id) } != Some("2.5.29.15") {
            continue;
        }
        let (length, data) = unsafe {
            (
                extension.add(2).read_unaligned() as u32 as usize,
                extension.add(3).read_unaligned() as *const u8,
            )
        };
        if data.is_null() {
            return 0;
        }
        let mut value = unsafe { std::slice::from_raw_parts(data, length) };
        let Ok(bits) = der(&mut value, Some(3)) else {
            native_set_last_error(ASN1_ERROR);
            return 0;
        };
        // A BIT STRING body is its unused-bit count, then the bits.
        let bytes = bits.body.get(1..).unwrap_or(&[]);
        let copied = bytes.len().min(size as usize);
        unsafe { usage.copy_from_nonoverlapping(bytes.as_ptr(), copied) };
        return 1;
    }
    0
}

#[cfg(test)]
mod intended_key_usage_tests {
    use super::*;

    #[test]
    fn key_usage_bits_come_from_the_extension_or_report_none() {
        let key_usage_id = b"2.5.29.15\0";
        let other_id = b"2.5.29.19\0";
        // BIT STRING, 1 unused bit: digitalSignature | keyCertSign, 2nd byte.
        let value = [0x03u8, 0x03, 0x01, 0x84, 0x80];
        let extensions: [[u64; 4]; 2] = [
            [other_id.as_ptr() as u64, 0, 0, 0],
            [key_usage_id.as_ptr() as u64, 1, value.len() as u64, value.as_ptr() as u64],
        ];
        let mut info = [0u64; 26];
        info[24] = 2;
        info[25] = extensions.as_ptr() as u64;
        let mut usage = [0xffu8; 4];
        assert_eq!(native_cert_get_intended_key_usage(1, info.as_ptr(), usage.as_mut_ptr(), 4), 1);
        assert_eq!(usage, [0x84, 0x80, 0, 0]);
        let mut one = [0xffu8; 1];
        assert_eq!(native_cert_get_intended_key_usage(1, info.as_ptr(), one.as_mut_ptr(), 1), 1);
        assert_eq!(one, [0x84]);
        info[24] = 1;
        assert_eq!(native_cert_get_intended_key_usage(1, info.as_ptr(), usage.as_mut_ptr(), 4), 0);
        assert_eq!((usage, native_get_last_error()), ([0; 4], 0));
        assert_eq!(native_cert_get_intended_key_usage(1, std::ptr::null(), usage.as_mut_ptr(), 4), 0);
        assert_eq!(native_get_last_error(), 87);
    }
}

/// `CertOpenSystemStoreA`: the current user's system store by name.
pub(super) extern "win64" fn native_cert_open_system_store_a(_provider: u64, name: *const u8) -> u64 {
    native_cert_open_store(9, 0, 0, 0x10000, name)
}
/// `CertOpenSystemStoreW`.
pub(super) extern "win64" fn native_cert_open_system_store_w(_provider: u64, name: *const u16) -> u64 {
    native_cert_open_store(10, 0, 0, 0x10000, name.cast())
}

pub(super) extern "win64" fn native_cert_enum_certificates(store: u64, previous: u64) -> u64 {
    let mut stores = STORES.lock().unwrap();
    let index = if previous == 0 {
        0
    } else {
        // Continue after the previous context's place in this store (a
        // collection shares its members' certificates, which belong to the
        // member stores).
        let next = stores.contexts.get(&previous).and_then(|lease| {
            stores
                .stores
                .get(&store)?
                .iter()
                .position(|certificate| Arc::ptr_eq(certificate, &lease.certificate))
                .map(|index| index + 1)
        });
        release(&mut stores, previous);
        let Some(next) = next else {
            return fail(INVALID_ARGUMENT);
        };
        next
    };
    let Some(certificates) = stores.stores.get(&store) else {
        return fail(INVALID_ARGUMENT);
    };
    let Some(certificate) = certificates.get(index).cloned() else {
        return fail(NOT_FOUND);
    };
    let pointer = &*certificate.context as *const CertContext as u64;
    let lease = stores.contexts.entry(pointer).or_insert(Lease {
        certificate,
        references: 0,
        index,
    });
    lease.references += 1;
    pointer
}
/// `CertAddEncodedCertificateToStore`: add an X.509 certificate to an open
/// store by disposition (`CERT_STORE_ADD_*`). A certificate matches another
/// with identical encoded bytes. Additions stay with the open store.
pub(super) extern "win64" fn native_cert_add_encoded_certificate_to_store(
    store: u64,
    encoding: u32,
    encoded: *const u8,
    length: u32,
    disposition: u32,
    context: *mut u64,
) -> i32 {
    const CRYPT_E_EXISTS: u32 = 0x8009_2005;
    if !context.is_null() {
        unsafe { context.write(0) };
    }
    if encoded.is_null() || length == 0 || encoding & 1 == 0 || !(1..=7).contains(&disposition) {
        fail(INVALID_ARGUMENT);
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(encoded, length as usize) }.to_vec();
    let added = match certificate(bytes.clone(), store) {
        Ok(added) => added,
        Err(error) => {
            fail(error);
            return 0;
        }
    };
    let mut stores = STORES.lock().unwrap();
    let Some(certificates) = stores.stores.get_mut(&store) else {
        drop(stores);
        fail(INVALID_ARGUMENT);
        return 0;
    };
    let same = |certificate: &Arc<Certificate>| {
        let context = &certificate.context;
        let stored = unsafe { std::slice::from_raw_parts(context.encoded as *const u8, context.size as usize) };
        stored == bytes.as_slice()
    };
    let existing = certificates.iter().position(same);
    let index = match (disposition, existing) {
        (4, _) | (_, None) => {
            certificates.push(added);
            certificates.len() - 1
        }
        (2, Some(index)) => index,
        (3 | 5, Some(index)) => {
            certificates[index] = added;
            index
        }
        (_, Some(_)) => {
            drop(stores);
            fail(CRYPT_E_EXISTS);
            return 0;
        }
    };
    if !context.is_null() {
        let certificate = Arc::clone(&stores.stores[&store][index]);
        let pointer = &*certificate.context as *const CertContext as u64;
        let lease = stores.contexts.entry(pointer).or_insert(Lease { certificate, references: 0, index });
        lease.references += 1;
        unsafe { context.write(pointer) };
    }
    1
}

/// `CertCreateCertificateContext`: a context for an encoded certificate in
/// no caller-visible store (an implicit memory store, as on Windows), freed
/// with `CertFreeCertificateContext`.
pub(super) extern "win64" fn native_cert_create_certificate_context(encoding: u32, encoded: *const u8, length: u32) -> u64 {
    const CERT_STORE_PROV_MEMORY: u64 = 2;
    const CERT_STORE_ADD_ALWAYS: u32 = 4;
    let store = native_cert_open_store(CERT_STORE_PROV_MEMORY, 0, 0, 0, ptr::null());
    if store == 0 {
        return 0;
    }
    let mut context = 0u64;
    let added = native_cert_add_encoded_certificate_to_store(store, encoding, encoded, length, CERT_STORE_ADD_ALWAYS, &mut context);
    // The context keeps its certificate after the store closes.
    let error = native_get_last_error();
    native_cert_close_store(store, 0);
    if added == 0 {
        native_set_last_error(error);
        return 0;
    }
    context
}

/// The encoded certificate of a context this process holds.
pub(super) fn context_der(pointer: u64) -> Option<Vec<u8>> {
    let stores = STORES.lock().unwrap();
    let lease = stores.contexts.get(&pointer)?;
    let context = &lease.certificate.context;
    Some(unsafe { std::slice::from_raw_parts(context.encoded as *const u8, context.size as usize) }.to_vec())
}

/// The encoded certificates of an open store.
pub(super) fn store_der(store: u64) -> Option<Vec<Vec<u8>>> {
    let stores = STORES.lock().unwrap();
    let certificates = stores.stores.get(&store)?;
    Some(
        certificates
            .iter()
            .map(|certificate| {
                let context = &certificate.context;
                unsafe { std::slice::from_raw_parts(context.encoded as *const u8, context.size as usize) }.to_vec()
            })
            .collect(),
    )
}

/// The guest's machine and user ROOT stores, encoded.
pub(super) fn guest_root_der() -> Vec<Vec<u8>> {
    let Some(context) = fs_ctx() else { return Vec::new() };
    let Ok(ctx) = context.lock() else { return Vec::new() };
    crate::winreg::Registry::load(&ctx.fs)
        .map(|registry| crate::trust_roots::store_certificates(&registry, "ROOT"))
        .unwrap_or_default()
}

pub(super) extern "win64" fn native_cert_duplicate_context(pointer: u64) -> u64 {
    if pointer == 0 {
        return 0;
    }
    let mut stores = STORES.lock().unwrap();
    let Some(lease) = stores.contexts.get_mut(&pointer) else {
        return fail(INVALID_ARGUMENT);
    };
    lease.references += 1;
    pointer
}
pub(super) extern "win64" fn native_cert_free_context(pointer: u64) -> i32 {
    if pointer == 0 {
        return 1;
    }
    if release(&mut STORES.lock().unwrap(), pointer) {
        1
    } else {
        fail(INVALID_ARGUMENT);
        0
    }
}
pub(super) extern "win64" fn native_cert_close_store(store: u64, flags: u32) -> i32 {
    if flags & !3 != 0 {
        fail(INVALID_ARGUMENT);
        return 0;
    }
    if store == 0 {
        return 1;
    }
    let mut stores = STORES.lock().unwrap();
    if stores.stores.remove(&store).is_none() {
        fail(INVALID_ARGUMENT);
        return 0;
    }
    let pending = stores
        .contexts
        .values()
        .any(|lease| lease.certificate.context.store == store);
    if flags & 1 != 0 {
        stores
            .contexts
            .retain(|_, lease| lease.certificate.context.store != store);
    }
    if flags & 2 != 0 && pending {
        fail(0x8009_200f);
        return 0;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn der_rejects_truncation_indefinite_lengths_and_incomplete_oids() {
        for bytes in [&b"\x30\x80"[..], &b"\x30\x82\x01"[..], &b"\x30\x04a"[..]] {
            let mut input = bytes;
            assert!(der(&mut input, Some(48)).is_err());
        }
        assert!(oid(&[0x2a, 0x80]).is_err());
        assert_eq!(
            oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]).unwrap(),
            b"1.2.840.113549\0"
        );
        assert!(certificate(vec![0x30, 0], 0).is_err());
        assert_eq!(
            decode_usage(&[0x30, 10, 6, 8, 0x2b, 6, 1, 5, 5, 7, 3, 1]).unwrap(),
            vec![b"1.3.6.1.5.5.7.3.1\0".to_vec()]
        );
        assert!(decode_usage(&[0x30, 1, 6]).is_err());
    }
    #[test]
    fn enhanced_usage_flags_pick_extension_or_property() {
        let der = crate::trust_roots::bundled_roots()[0].clone();
        let context = native_cert_create_certificate_context(1, der.as_ptr(), der.len() as u32);
        let mut size = 0u32;
        // No context property: a property-only query finds nothing.
        assert_eq!(native_cert_get_enhanced_key_usage(context, 4, ptr::null_mut(), &mut size), 0);
        assert_eq!(native_get_last_error(), NOT_FOUND);
        // Both "only" flags at once, or an unknown flag, are invalid.
        assert_eq!(native_cert_get_enhanced_key_usage(context, 6, ptr::null_mut(), &mut size), 0);
        assert_eq!(native_get_last_error(), INVALID_ARGUMENT);
        assert_eq!(native_cert_get_enhanced_key_usage(context, 8, ptr::null_mut(), &mut size), 0);
        // The plain query always answers (empty usage: good for anything).
        assert_eq!(native_cert_get_enhanced_key_usage(context, 0, ptr::null_mut(), &mut size), 1);
        native_cert_free_context(context);
    }

    #[test]
    fn stores_open_by_provider_name() {
        let memory = native_cert_open_store(b"Memory\0".as_ptr() as u64, 0, 0, 0, ptr::null());
        assert_ne!(memory, 0, "sz_CERT_STORE_PROV_MEMORY");
        let collection = native_cert_open_store(b"COLLECTION\0".as_ptr() as u64, 0, 0, 0, ptr::null());
        assert_ne!(collection, 0, "names match without case");
        assert_eq!(native_cert_open_store(b"LDAP\0".as_ptr() as u64, 0, 0, 0, ptr::null()), 0);
        native_cert_close_store(memory, 0);
        native_cert_close_store(collection, 0);
    }

    #[test]
    fn collections_gather_their_member_stores() {
        let der = crate::trust_roots::bundled_roots()[0].clone();
        let member = native_cert_open_store(2, 0, 0, 0, ptr::null());
        assert_eq!(native_cert_add_encoded_certificate_to_store(member, 1, der.as_ptr(), der.len() as u32, 4, ptr::null_mut()), 1);
        let collection = native_cert_open_store(11, 0, 0, 0, ptr::null());
        assert_ne!(collection, 0, "CERT_STORE_PROV_COLLECTION");
        assert_eq!(native_cert_add_store_to_collection(collection, member, 1, 0), 1);
        assert_eq!(native_cert_add_store_to_collection(collection, member, 1, 0), 1, "adding twice is harmless");
        assert_eq!(native_cert_close_store(member, 0), 1);
        let first = native_cert_enum_certificates(collection, 0);
        assert_eq!(context_der(first), Some(der));
        assert_eq!(native_cert_enum_certificates(collection, first), 0, "one certificate");
        assert_eq!(native_get_last_error(), NOT_FOUND, "the end, not a bad context");
        // Enumeration walks every member's certificates.
        let roots = crate::trust_roots::bundled_roots();
        let (a, b) = (native_cert_open_store(2, 0, 0, 0, ptr::null()), native_cert_open_store(2, 0, 0, 0, ptr::null()));
        for (store, der) in [(a, &roots[0]), (a, &roots[1]), (b, &roots[2])] {
            assert_eq!(native_cert_add_encoded_certificate_to_store(store, 1, der.as_ptr(), der.len() as u32, 4, ptr::null_mut()), 1);
        }
        let both = native_cert_open_store(11, 0, 0, 0, ptr::null());
        assert_eq!(native_cert_add_store_to_collection(both, a, 1, 0), 1);
        assert_eq!(native_cert_add_store_to_collection(both, b, 1, 0), 1);
        let mut count = 0;
        let mut context = native_cert_enum_certificates(both, 0);
        while context != 0 {
            count += 1;
            context = native_cert_enum_certificates(both, context);
        }
        assert_eq!(count, 3);
        for store in [a, b, both] {
            native_cert_close_store(store, 0);
        }
        assert_eq!(native_cert_add_store_to_collection(collection, 0x1234, 1, 0), 0);
        assert_eq!(native_cert_close_store(collection, 0), 1);
    }

    #[test]
    fn created_contexts_stand_alone_until_freed() {
        let der = crate::trust_roots::bundled_roots()[0].clone();
        let context = native_cert_create_certificate_context(1, der.as_ptr(), der.len() as u32);
        assert_ne!(context, 0);
        assert_eq!(context_der(context), Some(der.clone()), "the context keeps its certificate");
        assert_eq!(native_cert_create_certificate_context(1, [0x30u8, 0].as_ptr(), 2), 0, "bad DER fails");
        assert_eq!(native_cert_create_certificate_context(2, der.as_ptr(), der.len() as u32), 0, "not X.509 encoding");
        native_cert_free_context(context);
        assert_eq!(context_der(context), None, "freed");
    }

    #[test]
    fn encoded_certificates_add_to_memory_stores_by_disposition() {
        let der = crate::trust_roots::bundled_roots()[0].clone();
        let store = native_cert_open_store(2, 0, 0, 0, ptr::null());
        assert_ne!(store, 0);
        let mut first = 0u64;
        assert_eq!(native_cert_add_encoded_certificate_to_store(store, 1, der.as_ptr(), der.len() as u32, 1, &mut first), 1);
        assert_ne!(first, 0);
        let mut again = 7u64;
        assert_eq!(native_cert_add_encoded_certificate_to_store(store, 1, der.as_ptr(), der.len() as u32, 1, &mut again), 0);
        assert_eq!((native_get_last_error(), again), (0x8009_2005, 0), "CERT_STORE_ADD_NEW: CRYPT_E_EXISTS");
        let mut existing = 0u64;
        assert_eq!(native_cert_add_encoded_certificate_to_store(store, 1, der.as_ptr(), der.len() as u32, 2, &mut existing), 1);
        assert_eq!(existing, first, "CERT_STORE_ADD_USE_EXISTING returns the stored one");
        assert_eq!(native_cert_add_encoded_certificate_to_store(store, 1, der.as_ptr(), der.len() as u32, 4, ptr::null_mut()), 1);
        let mut count = 0;
        let mut context = native_cert_enum_certificates(store, 0);
        while context != 0 {
            count += 1;
            context = native_cert_enum_certificates(store, context);
        }
        assert_eq!(count, 2, "CERT_STORE_ADD_ALWAYS adds a second copy");
        assert_eq!(native_cert_add_encoded_certificate_to_store(store, 1, [0x30u8, 0].as_ptr(), 2, 4, ptr::null_mut()), 0);
        native_cert_free_context(first);
        native_cert_free_context(existing);
        assert_eq!(native_cert_close_store(store, 0), 1);
    }
    #[test]
    fn system_root_contexts_decode_and_remain_valid_after_store_close() {
        assert_eq!(std::mem::size_of::<CertContext>(), 40);
        let root: Vec<u16> = "ROOT".encode_utf16().chain(Some(0)).collect();
        let store = native_cert_open_store(10, 0, 0, 0x2c000, root.as_ptr().cast());
        assert_ne!(store, 0, "root bundle error {:#x}", native_get_last_error());
        let first = native_cert_enum_certificates(store, 0);
        assert_ne!(first, 0);
        let context = unsafe { &*(first as *const CertContext) };
        assert_eq!(context.encoding, 1);
        assert!(context.size > 100 && context.info != 0);
        let info = unsafe { &*(context.info as *const [u64; 26]) };
        assert!(info[1] > 0 && info[6] > 0 && info[10] > 0 && info[15] > 0);
        assert!(info[8] < info[9]);
        let mut size = 0;
        assert_eq!(
            native_cert_get_enhanced_key_usage(first, 0, std::ptr::null_mut(), &mut size),
            1
        );
        assert!(size >= 16);
        let mut buffer = vec![0x55; size as usize];
        let mut small = 1;
        assert_eq!(
            native_cert_get_enhanced_key_usage(first, 0, buffer.as_mut_ptr(), &mut small),
            0
        );
        assert_eq!(native_get_last_error(), 234);
        assert_eq!(small, size);
        assert!(buffer.iter().all(|byte| *byte == 0x55));
        assert_eq!(
            native_cert_get_enhanced_key_usage(first, 0, buffer.as_mut_ptr(), &mut size),
            1
        );
        let saved = unsafe {
            std::slice::from_raw_parts(context.encoded as *const u8, context.size as usize)
        }
        .to_vec();
        assert_eq!(native_cert_duplicate_context(first), first);
        let second = native_cert_enum_certificates(store, first);
        assert_ne!(second, 0);
        assert_eq!(native_cert_close_store(store, 2), 0);
        assert_eq!(native_get_last_error(), 0x8009_200f);
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(context.encoded as *const u8, context.size as usize)
            },
            saved
        );
        assert_eq!(native_cert_free_context(first), 1);
        assert_eq!(native_cert_free_context(second), 1);
        assert_eq!(native_cert_free_context(0), 1);
        assert_eq!(native_cert_close_store(0, 0), 1);
    }
    #[test]
    fn empty_memory_store_and_unsupported_provider_return_explicit_errors() {
        let store = native_cert_open_store(2, 0, 0, 0, std::ptr::null());
        assert_ne!(store, 0);
        assert_eq!(native_cert_enum_certificates(store, 0), 0);
        assert_eq!(native_get_last_error(), NOT_FOUND);
        assert_eq!(native_cert_close_store(store, 0), 1);
        assert_eq!(native_cert_enum_certificates(store, 0), 0);
        assert_eq!(native_get_last_error(), INVALID_ARGUMENT);
        assert_eq!(native_cert_open_store(123, 0, 0, 0, std::ptr::null()), 0);
        assert_eq!(native_get_last_error(), 50);
    }
}

#[cfg(test)]
mod store_flag_tests {
    use super::*;

    #[test]
    fn memory_stores_accept_deferred_close_and_reject_unknown_flags() {
        let store = native_cert_open_store(2, 0, 0, 0x4, std::ptr::null());
        assert_ne!(store, 0, "CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG");
        assert_eq!(native_cert_enum_certificates(store, 0), 0);
        assert_eq!(native_cert_close_store(store, 0), 1);
        assert_eq!(native_cert_open_store(2, 0, 0, 0x40, std::ptr::null()), 0);
        assert_eq!(native_get_last_error(), 50);
    }
}
