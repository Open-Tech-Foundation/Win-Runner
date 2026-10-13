//! Certificate chains: `CertGetCertificateChain`,
//! `CertVerifyCertificateChainPolicy`, chain engines, and freeing. Chains
//! are built and verified by rustls-webpki against the guest's ROOT store
//! (or an engine's roots), with the caller's additional store supplying
//! intermediates, and reported in Windows' `CERT_CHAIN_CONTEXT` layout with
//! its `CERT_TRUST_*` status bits. Revocation is not checked.

use super::*;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

const CERT_TRUST_IS_NOT_TIME_VALID: u32 = 0x1;
const CERT_TRUST_IS_NOT_SIGNATURE_VALID: u32 = 0x8;
const CERT_TRUST_IS_NOT_VALID_FOR_USAGE: u32 = 0x10;
const CERT_TRUST_IS_UNTRUSTED_ROOT: u32 = 0x20;
const CERT_TRUST_INVALID_NAME_CONSTRAINTS: u32 = 0x800;
const CERT_TRUST_IS_PARTIAL_CHAIN: u32 = 0x1_0000;
const CERT_TRUST_IS_SELF_SIGNED: u32 = 0x8;

const TRUST_E_CERT_SIGNATURE: u32 = 0x8009_6004;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_CHAINING: u32 = 0x800B_010A;
const CERT_E_CN_NO_MATCH: u32 = 0x800B_010F;
const CERT_E_WRONG_USAGE: u32 = 0x800B_0110;
const CERT_E_INVALID_NAME: u32 = 0x800B_0114;

const EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

#[repr(C)]
struct ChainElement {
    size: u32,
    certificate: u64,
    error_status: u32,
    info_status: u32,
    revocation_info: u64,
    issuance_usage: u64,
    application_usage: u64,
    extended_error_info: u64,
}

#[repr(C)]
struct SimpleChain {
    size: u32,
    error_status: u32,
    info_status: u32,
    element_count: u32,
    elements: u64,
    trust_list_info: u64,
    has_revocation_freshness_time: i32,
    revocation_freshness_time: u32,
}

#[repr(C)]
struct ChainContext {
    size: u32,
    error_status: u32,
    info_status: u32,
    chain_count: u32,
    chains: u64,
    lower_quality_count: u32,
    lower_quality: u64,
    has_revocation_freshness_time: i32,
    revocation_freshness_time: u32,
    create_flags: u32,
    chain_id: [u8; 16],
}

/// A chain and everything its context points at, kept at fixed addresses.
struct Chain {
    context: ChainContext,
    simple: SimpleChain,
    simple_pointers: [u64; 1],
    elements: Vec<ChainElement>,
    element_pointers: Vec<u64>,
    /// The certificate contexts the elements hold, and the memory store
    /// that owns those not handed in by the caller.
    contexts: Vec<u64>,
    store: u64,
    /// The encoded certificates, end entity first.
    encoded: Vec<Vec<u8>>,
    references: usize,
}

// SAFETY: a chain's raw pointers only point into itself or at certificate
// contexts kept alive by its leases; it is reached through the registry lock.
unsafe impl Send for Chain {}

static CHAINS: LazyLock<Mutex<HashMap<u64, Box<Chain>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// A chain engine: the roots to trust and the extra intermediates.
struct Engine {
    roots: Vec<Vec<u8>>,
    intermediates: Vec<Vec<u8>>,
}

static ENGINES: LazyLock<Mutex<HashMap<u64, Engine>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_ENGINE: AtomicU64 = AtomicU64::new(0x4348_4e45_0000_0001);

/// One DER element: (tag, contents, rest).
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)? as usize;
    let (length, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = length << 8 | *input.get(2 + index)? as usize;
        }
        (length, 2 + count)
    };
    let contents = input.get(header..header + length)?;
    Some((tag, contents, &input[header + length..]))
}

/// Whether a certificate's issuer and subject names are the same.
fn self_issued(der: &[u8]) -> bool {
    (|| {
        let (_, certificate, _) = der_element(der)?;
        let (_, mut tbs, _) = der_element(certificate)?;
        let mut fields = Vec::new();
        while !tbs.is_empty() {
            let (tag, _, rest) = der_element(tbs)?;
            fields.push((tag, &tbs[..tbs.len() - rest.len()]));
            tbs = rest;
        }
        // [0] version, serial, signature, issuer, validity, subject.
        let skip = usize::from(fields.first()?.0 == 0xa0);
        Some(fields.get(skip + 2)?.1 == fields.get(skip + 4)?.1)
    })()
    .unwrap_or(false)
}

/// Verify `end` up to one of `roots`: the error status and the encoded
/// chain, end entity first.
fn build(end: &[u8], intermediates: &[Vec<u8>], roots: &[Vec<u8>], time: UnixTime, server_usage: bool) -> (u32, Vec<Vec<u8>>) {
    // A trusted root by itself is a complete chain.
    if roots.iter().any(|root| root.as_slice() == end) {
        return (0, vec![end.to_vec()]);
    }
    let end_der = CertificateDer::from(end);
    let Ok(certificate) = webpki::EndEntityCert::try_from(&end_der) else {
        return (CERT_TRUST_IS_PARTIAL_CHAIN, vec![end.to_vec()]);
    };
    let root_ders: Vec<CertificateDer<'_>> = roots.iter().map(|root| CertificateDer::from(root.as_slice())).collect();
    let anchors: Vec<_> = root_ders
        .iter()
        .filter_map(|root| webpki::anchor_from_trusted_cert(root).ok())
        .collect();
    let intermediate_ders: Vec<CertificateDer<'_>> =
        intermediates.iter().map(|der| CertificateDer::from(der.as_slice())).collect();
    let usage = if server_usage {
        webpki::KeyUsage::server_auth()
    } else {
        webpki::KeyUsage::required_if_present(EKU_SERVER_AUTH)
    };
    let result = certificate.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediate_ders,
        time,
        usage,
        None,
        None,
    );
    match result {
        Ok(path) => {
            let mut chain = vec![end.to_vec()];
            chain.extend(path.intermediate_certificates().map(|cert| cert.der().to_vec()));
            let anchor = path.anchor();
            if let Some(root) = root_ders.iter().find(|root| {
                webpki::anchor_from_trusted_cert(root).is_ok_and(|candidate| {
                    candidate.subject == anchor.subject && candidate.subject_public_key_info == anchor.subject_public_key_info
                })
            }) {
                chain.push(root.to_vec());
            }
            (0, chain)
        }
        Err(error) => {
            use webpki::Error as E;
            let status = match error {
                E::CertExpired { .. } | E::CertNotValidYet { .. } => CERT_TRUST_IS_NOT_TIME_VALID,
                E::UnknownIssuer | E::CaUsedAsEndEntity if self_issued(end) => CERT_TRUST_IS_UNTRUSTED_ROOT,
                E::UnknownIssuer => CERT_TRUST_IS_PARTIAL_CHAIN,
                E::InvalidSignatureForPublicKey
                | E::UnsupportedSignatureAlgorithmContext(_)
                | E::UnsupportedSignatureAlgorithmForPublicKeyContext(_)
                | E::SignatureAlgorithmMismatch => CERT_TRUST_IS_NOT_SIGNATURE_VALID,
                E::RequiredEkuNotFoundContext(_) | E::EmptyEkuExtension | E::CaUsedAsEndEntity => {
                    CERT_TRUST_IS_NOT_VALID_FOR_USAGE
                }
                E::NameConstraintViolation => CERT_TRUST_INVALID_NAME_CONSTRAINTS,
                _ => CERT_TRUST_IS_PARTIAL_CHAIN,
            };
            (status, vec![end.to_vec()])
        }
    }
}

fn unix_time(filetime: *const u64) -> UnixTime {
    if filetime.is_null() {
        return UnixTime::now();
    }
    let value = unsafe { filetime.read_unaligned() };
    let seconds = (value / 10_000_000).saturating_sub(11_644_473_600);
    UnixTime::since_unix_epoch(std::time::Duration::from_secs(seconds))
}

/// Whether CERT_CHAIN_PARA's requested usage names serverAuth.
fn requests_server_auth(parameters: *const u8) -> bool {
    if parameters.is_null() {
        return false;
    }
    unsafe {
        let count = parameters.add(16).cast::<u32>().read_unaligned() as usize;
        let identifiers = parameters.add(24).cast::<*const *const i8>().read_unaligned();
        if identifiers.is_null() {
            return false;
        }
        (0..count.min(64)).any(|index| {
            let identifier = identifiers.add(index).read_unaligned();
            !identifier.is_null() && std::ffi::CStr::from_ptr(identifier).to_bytes() == b"1.3.6.1.5.5.7.3.1"
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) extern "win64" fn native_cert_get_certificate_chain(
    engine: u64,
    certificate: u64,
    time: *const u64,
    additional_store: u64,
    parameters: *const u8,
    _flags: u32,
    _reserved: u64,
    chain_out: *mut u64,
) -> i32 {
    if chain_out.is_null() {
        native_set_last_error(87);
        return 0;
    }
    unsafe { chain_out.write(0) };
    let Some(end) = context_der(certificate) else {
        native_set_last_error(87);
        return 0;
    };
    let (roots, mut intermediates) = if engine != 0 && engine != 1 {
        match ENGINES.lock().unwrap().get(&engine) {
            Some(engine) => (engine.roots.clone(), engine.intermediates.clone()),
            None => {
                native_set_last_error(6);
                return 0;
            }
        }
    } else {
        (guest_root_der(), Vec::new())
    };
    if additional_store != 0 {
        intermediates.extend(store_der(additional_store).unwrap_or_default());
    }
    let (status, encoded) = build(&end, &intermediates, &roots, unix_time(time), requests_server_auth(parameters));

    // Element 0 is the caller's context; the rest live in a memory store.
    let store = native_cert_open_store(2, 0, 0, 0, ptr::null());
    let mut contexts = vec![native_cert_duplicate_context(certificate)];
    for der in &encoded[1..] {
        let mut context = 0u64;
        native_cert_add_encoded_certificate_to_store(store, 1, der.as_ptr(), der.len() as u32, 4, &mut context);
        contexts.push(context);
    }
    let last = encoded.len() - 1;
    let self_signed_root = status == 0 && self_issued(&encoded[last]);
    let elements: Vec<ChainElement> = contexts
        .iter()
        .enumerate()
        .map(|(index, context)| ChainElement {
            size: std::mem::size_of::<ChainElement>() as u32,
            certificate: *context,
            error_status: if index == 0 || status & (CERT_TRUST_IS_UNTRUSTED_ROOT | CERT_TRUST_IS_PARTIAL_CHAIN) != 0 { status } else { 0 },
            info_status: if index == last && (self_signed_root || status & CERT_TRUST_IS_UNTRUSTED_ROOT != 0) {
                CERT_TRUST_IS_SELF_SIGNED
            } else {
                0
            },
            revocation_info: 0,
            issuance_usage: 0,
            application_usage: 0,
            extended_error_info: 0,
        })
        .collect();
    let mut chain = Box::new(Chain {
        context: ChainContext {
            size: std::mem::size_of::<ChainContext>() as u32,
            error_status: status,
            info_status: 0,
            chain_count: 1,
            chains: 0,
            lower_quality_count: 0,
            lower_quality: 0,
            has_revocation_freshness_time: 0,
            revocation_freshness_time: 0,
            create_flags: 0,
            chain_id: [0; 16],
        },
        simple: SimpleChain {
            size: std::mem::size_of::<SimpleChain>() as u32,
            error_status: status,
            info_status: 0,
            element_count: elements.len() as u32,
            elements: 0,
            trust_list_info: 0,
            has_revocation_freshness_time: 0,
            revocation_freshness_time: 0,
        },
        simple_pointers: [0],
        elements,
        element_pointers: Vec::new(),
        contexts,
        store,
        encoded,
        references: 1,
    });
    chain.element_pointers = chain.elements.iter().map(|element| element as *const ChainElement as u64).collect();
    chain.simple.elements = chain.element_pointers.as_ptr() as u64;
    chain.simple_pointers[0] = &chain.simple as *const SimpleChain as u64;
    chain.context.chains = chain.simple_pointers.as_ptr() as u64;
    let pointer = &chain.context as *const ChainContext as u64;
    CHAINS.lock().unwrap().insert(pointer, chain);
    unsafe { chain_out.write(pointer) };
    1
}

pub(super) extern "win64" fn native_cert_free_certificate_chain(chain: u64) {
    let removed = {
        let mut chains = CHAINS.lock().unwrap();
        match chains.get_mut(&chain) {
            Some(entry) if entry.references > 1 => {
                entry.references -= 1;
                None
            }
            Some(_) => chains.remove(&chain),
            None => None,
        }
    };
    if let Some(chain) = removed {
        for context in &chain.contexts {
            native_cert_free_context(*context);
        }
        native_cert_close_store(chain.store, 0);
    }
}

pub(super) extern "win64" fn native_cert_duplicate_certificate_chain(chain: u64) -> u64 {
    match CHAINS.lock().unwrap().get_mut(&chain) {
        Some(entry) => {
            entry.references += 1;
            chain
        }
        None => 0,
    }
}

/// `CertVerifyCertificateChainPolicy` for the base, SSL and similar
/// policies: the chain's status as a `CERT_E_*` error, less what the flags
/// ignore, and for SSL the server name.
pub(super) extern "win64" fn native_cert_verify_certificate_chain_policy(
    policy: u64,
    chain: u64,
    parameters: *const u8,
    status: *mut u8,
) -> i32 {
    if status.is_null() || !(1..=7).contains(&policy) {
        native_set_last_error(87);
        return 0;
    }
    let Some((error_status, encoded)) = CHAINS
        .lock()
        .unwrap()
        .get(&chain)
        .map(|chain| (chain.context.error_status, chain.encoded.clone()))
    else {
        native_set_last_error(87);
        return 0;
    };
    let flags = if parameters.is_null() { 0 } else { unsafe { parameters.add(4).cast::<u32>().read_unaligned() } };
    let extra = if parameters.is_null() { 0 } else { unsafe { parameters.add(8).cast::<u64>().read_unaligned() } };
    let (mut checks, mut server) = (0u32, None);
    if policy == 4 && extra != 0 {
        unsafe {
            checks = (extra as *const u8).add(8).cast::<u32>().read_unaligned();
            let name = (extra as *const u8).add(16).cast::<u64>().read_unaligned();
            if name != 0 {
                server = wide(name as *const u16);
            }
        }
    }
    let last = encoded.len() as i32 - 1;
    // In the order Windows reports them, with what may ignore each.
    let failures = [
        (CERT_TRUST_IS_NOT_SIGNATURE_VALID, TRUST_E_CERT_SIGNATURE, 0, 0, 0),
        (CERT_TRUST_IS_UNTRUSTED_ROOT, CERT_E_UNTRUSTEDROOT, last, 0x10, 0x100),
        (CERT_TRUST_IS_PARTIAL_CHAIN, CERT_E_CHAINING, last, 0x10, 0x100),
        (CERT_TRUST_IS_NOT_TIME_VALID, CERT_E_EXPIRED, 0, 0x1, 0x2000),
        (CERT_TRUST_IS_NOT_VALID_FOR_USAGE, CERT_E_WRONG_USAGE, 0, 0x20, 0x200),
        (CERT_TRUST_INVALID_NAME_CONSTRAINTS, CERT_E_INVALID_NAME, 0, 0x40, 0),
    ];
    let mut result = failures.iter().find_map(|&(bit, error, element, ignore_flag, ignore_check)| {
        (error_status & bit != 0 && flags & ignore_flag == 0 && (ignore_check == 0 || checks & ignore_check == 0))
            .then_some((error, element))
    });
    if result.is_none() && checks & 0x1000 == 0 {
        if let Some(server) = server.filter(|name| !name.is_empty()) {
            let end = CertificateDer::from(encoded[0].as_slice());
            let matches = ServerName::try_from(server.as_str()).ok().is_some_and(|name| {
                webpki::EndEntityCert::try_from(&end).is_ok_and(|certificate| {
                    certificate.verify_is_valid_for_subject_name(&name).is_ok()
                })
            });
            if !matches {
                result = Some((CERT_E_CN_NO_MATCH, 0));
            }
        }
    }
    let (error, chain_index, element_index) = match result {
        Some((error, element)) => (error, 0i32, element),
        None => (0, -1, -1),
    };
    unsafe {
        status.add(4).cast::<u32>().write_unaligned(error);
        status.add(8).cast::<i32>().write_unaligned(chain_index);
        status.add(12).cast::<i32>().write_unaligned(element_index);
    }
    1
}

/// `CertCreateCertificateChainEngine`: an exclusive root store replaces the
/// system roots, a restricted one narrows them; additional stores add
/// intermediates. The stores' certificates are taken as they are now.
pub(super) extern "win64" fn native_cert_create_certificate_chain_engine(config: *const u8, engine: *mut u64) -> i32 {
    if config.is_null() || engine.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let read = |offset: usize| unsafe { config.add(offset).cast::<u64>().read_unaligned() };
    let size = unsafe { config.cast::<u32>().read_unaligned() } as usize;
    let exclusive_root = if size >= 72 { read(64) } else { 0 };
    let restricted_root = read(8);
    let system = guest_root_der();
    let roots = if exclusive_root != 0 {
        store_der(exclusive_root).unwrap_or_default()
    } else if restricted_root != 0 {
        let allowed = store_der(restricted_root).unwrap_or_default();
        system.into_iter().filter(|root| allowed.contains(root)).collect()
    } else {
        system
    };
    let count = unsafe { config.add(32).cast::<u32>().read_unaligned() } as usize;
    let stores = read(40) as *const u64;
    let mut intermediates = Vec::new();
    if !stores.is_null() {
        for index in 0..count.min(256) {
            let store = unsafe { stores.add(index).read_unaligned() };
            intermediates.extend(store_der(store).unwrap_or_default());
        }
    }
    let handle = NEXT_ENGINE.fetch_add(1, Ordering::Relaxed);
    ENGINES.lock().unwrap().insert(handle, Engine { roots, intermediates });
    unsafe { engine.write(handle) };
    1
}

pub(super) extern "win64" fn native_cert_free_certificate_chain_engine(engine: u64) {
    ENGINES.lock().unwrap().remove(&engine);
}

/// `CertSetCertificateContextProperty`: accepted; properties such as a
/// stapled OCSP response have no effect without revocation checking.
pub(super) extern "win64" fn native_cert_set_certificate_context_property(context: u64, _property: u32, _flags: u32, _data: u64) -> i32 {
    if context_der(context).is_none() {
        native_set_last_error(87);
        return 0;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trusted_root_is_a_chain_and_a_self_issued_stranger_is_untrusted() {
        let root = crate::trust_roots::bundled_roots()[0].clone();
        let roots = crate::trust_roots::bundled_roots().to_vec();
        assert!(self_issued(&root));
        assert_eq!(build(&root, &[], &roots, UnixTime::now(), false), (0, vec![root.clone()]));
        let (status, chain) = build(&root, &[], &[], UnixTime::now(), false);
        assert_eq!(status, CERT_TRUST_IS_UNTRUSTED_ROOT, "self-issued but not in the store");
        assert_eq!(chain.len(), 1);
    }
}
