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
}
