//! The guest's trusted root certificates, as Windows keeps them: one key per
//! certificate under `SystemCertificates\ROOT\Certificates`, named by its
//! SHA-1 thumbprint, whose `Blob` value is the serialized certificate.
//!
//! A new disk's machine hive is seeded from the Mozilla CA bundle pinned in
//! `resources/cacert.pem` (see NOTICE), so the guest's trust never depends on
//! the host's.

use std::sync::LazyLock;

/// The machine root store, relative to `HKEY_LOCAL_MACHINE`.
pub const MACHINE_ROOT_STORE: &str = r"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates";

/// `CERT_CERT_PROP_ID`: the serialized element carrying the encoded
/// certificate.
const CERT_CERT_PROP_ID: u32 = 0x20;

static BUNDLED: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    pem_certificates(include_str!("../resources/cacert.pem"))
        .expect("the bundled CA certificates must decode")
});

/// The DER encodings of the certificates in a PEM bundle.
pub fn pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    use base64::Engine;
    pem.split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .map(|part| {
            let body = part
                .split_once("-----END CERTIFICATE-----")
                .ok_or("unterminated PEM certificate")?
                .0;
            let text: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|e| format!("invalid PEM certificate: {e}"))
        })
        .collect()
}

/// The bundled roots, DER encoded.
pub fn bundled_roots() -> &'static [Vec<u8>] {
    &BUNDLED
}

/// A certificate's thumbprint: its SHA-1, as upper-case hex.
pub fn thumbprint(der: &[u8]) -> String {
    crate::install::sha1(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

/// A certificate serialized as the registry stores it: property elements
/// of (id, 1, length, data); this one carries the encoded certificate.
pub fn serialized_blob(der: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(12 + der.len());
    blob.extend_from_slice(&CERT_CERT_PROP_ID.to_le_bytes());
    blob.extend_from_slice(&1u32.to_le_bytes());
    blob.extend_from_slice(&(der.len() as u32).to_le_bytes());
    blob.extend_from_slice(der);
    blob
}

/// The encoded certificate in a serialized blob, if it has one.
pub fn certificate_from_blob(blob: &[u8]) -> Option<&[u8]> {
    let mut rest = blob;
    while rest.len() >= 12 {
        let id = u32::from_le_bytes(rest[..4].try_into().ok()?);
        let length = u32::from_le_bytes(rest[8..12].try_into().ok()?) as usize;
        let data = rest.get(12..12 + length)?;
        if id == CERT_CERT_PROP_ID {
            return Some(data);
        }
        rest = &rest[12 + length..];
    }
    None
}

/// Put the bundled roots in the machine's ROOT store, as Windows keeps them.
pub fn add_bundled_roots(registry: &mut crate::winreg::Registry) {
    for der in bundled_roots() {
        let path = format!(r"{MACHINE_ROOT_STORE}\{}", thumbprint(der));
        registry.create_key(crate::winreg::Hive::LocalMachine, &path).0.set_value(
            "Blob",
            crate::winreg::RegValue {
                kind: crate::winreg::REG_BINARY,
                data: serialized_blob(der),
            },
        );
    }
}

/// Give a disk whose machine hive predates the ROOT store the bundled roots.
/// A store that exists is left as it is, removals included.
pub fn seed_root_store(fs: &mut crate::winfs::WinFs) -> Result<(), String> {
    let mut registry = crate::winreg::Registry::load(fs)?;
    if registry.key(crate::winreg::Hive::LocalMachine, MACHINE_ROOT_STORE).is_some() {
        return Ok(());
    }
    add_bundled_roots(&mut registry);
    registry.save(fs, crate::winreg::Hive::LocalMachine)
}

/// A system store's encoded certificates in the guest registry: the
/// machine's `SOFTWARE\Microsoft\SystemCertificates\<name>\Certificates`
/// then the user's, each a serialized `Blob` (an absent store is empty).
pub fn store_certificates(registry: &crate::winreg::Registry, name: &str) -> Vec<Vec<u8>> {
    let mut certificates = Vec::new();
    for (hive, root) in [
        (crate::winreg::Hive::LocalMachine, "SOFTWARE"),
        (crate::winreg::Hive::CurrentUser, "Software"),
    ] {
        let path = format!(r"{root}\Microsoft\SystemCertificates\{name}\Certificates");
        let Some(key) = registry.key(hive, &path) else {
            continue;
        };
        for thumbprint in key.subkey_names() {
            let encoded = key
                .subkey(thumbprint)
                .and_then(|entry| entry.value("Blob"))
                .and_then(|blob| certificate_from_blob(&blob.data));
            if let Some(encoded) = encoded {
                certificates.push(encoded.to_vec());
            }
        }
    }
    certificates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundle_decodes_to_distinct_roots() {
        let roots = bundled_roots();
        assert!(roots.len() > 100, "{}", roots.len());
        let mut prints: Vec<String> = roots.iter().map(|der| thumbprint(der)).collect();
        prints.sort();
        prints.dedup();
        assert_eq!(prints.len(), roots.len());
        assert!(roots.iter().all(|der| der.first() == Some(&0x30)), "DER sequences");
    }

    #[test]
    fn blobs_round_trip_and_skip_other_properties() {
        let der = [0x30u8, 0x03, 0x02, 0x01, 0x05];
        assert_eq!(certificate_from_blob(&serialized_blob(&der)), Some(&der[..]));
        // A preceding property (SHA-1 hash, id 3) is skipped.
        let mut blob = vec![3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0xaa, 0xbb];
        blob.extend_from_slice(&serialized_blob(&der));
        assert_eq!(certificate_from_blob(&blob), Some(&der[..]));
        assert_eq!(certificate_from_blob(&blob[..20]), None, "truncated");
        assert!(pem_certificates("-----BEGIN CERTIFICATE-----\nAAA").is_err());
    }

    #[test]
    fn disks_without_a_root_store_get_one_and_others_keep_theirs() {
        use crate::winreg::{Hive, Registry};
        let mut fs = crate::winfs::WinFs::new();
        // A machine hive saved before the ROOT store existed.
        let mut registry = Registry::defaults();
        registry.delete_key(Hive::LocalMachine, r"SOFTWARE\Microsoft\SystemCertificates", true).unwrap();
        registry.save(&mut fs, Hive::LocalMachine).unwrap();
        assert!(store_certificates(&Registry::load(&fs).unwrap(), "ROOT").is_empty());
        seed_root_store(&mut fs).unwrap();
        let mut registry = Registry::load(&fs).unwrap();
        assert_eq!(store_certificates(&registry, "ROOT").len(), bundled_roots().len());
        // A root the user removed stays removed.
        let first = format!(r"{MACHINE_ROOT_STORE}\{}", thumbprint(&bundled_roots()[0]));
        registry.delete_key(Hive::LocalMachine, &first, true).unwrap();
        registry.save(&mut fs, Hive::LocalMachine).unwrap();
        seed_root_store(&mut fs).unwrap();
        assert_eq!(store_certificates(&Registry::load(&fs).unwrap(), "ROOT").len(), bundled_roots().len() - 1);
    }

    #[test]
    fn the_default_registry_holds_the_bundled_roots() {
        let registry = crate::winreg::Registry::defaults();
        assert_eq!(store_certificates(&registry, "ROOT").len(), bundled_roots().len());
        assert!(store_certificates(&registry, "CA").is_empty());
    }
}
