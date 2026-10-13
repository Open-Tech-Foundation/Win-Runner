//! Shared HTTPS, ZIP, and checksum helpers for guest package data and snapshots.

/// Download bytes over HTTP(S) with the built-in client, trusting the
/// bundled Mozilla roots (the guest's default ROOT store), never the host's.
pub fn fetch_url(url: &str, max_time_secs: u64) -> Result<Vec<u8>, String> {
    Ok(fetch_response(url, max_time_secs)?.body)
}

/// HTTP response after redirects, including the effective URI.
pub struct HttpResponse {
    pub body: Vec<u8>,
    pub url: String,
    pub status: u16,
}

pub fn fetch_response(url: &str, max_time_secs: u64) -> Result<HttpResponse, String> {
    fetch(url, max_time_secs, &mut |_| {})
}

/// How much of a download has arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadProgress {
    pub received: u64,
    /// The final response's `Content-Length`, when the server sends one.
    pub total: Option<u64>,
}

/// Download bytes, reporting the bytes received as they stream in (at most
/// every 100 ms, and once at the end).
pub fn fetch_url_with_progress(
    url: &str,
    max_time_secs: u64,
    mut progress: impl FnMut(DownloadProgress),
) -> Result<Vec<u8>, String> {
    let body = fetch(url, max_time_secs, &mut progress)?.body;
    progress(DownloadProgress {
        received: body.len() as u64,
        total: Some(body.len() as u64),
    });
    Ok(body)
}

/// Follow redirects and collect the final body; an HTTP error status fails.
fn fetch(
    url: &str,
    max_time_secs: u64,
    progress: &mut dyn FnMut(DownloadProgress),
) -> Result<HttpResponse, String> {
    use crate::http_client::{HttpError, ResponseHead, Sink};
    struct Collect<'a> {
        body: Vec<u8>,
        progress: &'a mut dyn FnMut(DownloadProgress),
        reported: std::time::Instant,
    }
    impl Sink for Collect<'_> {
        fn head(&mut self, _head: &ResponseHead, _last: bool) -> Result<(), HttpError> {
            Ok(())
        }
        fn data(&mut self, data: &[u8]) -> Result<(), HttpError> {
            self.body.extend_from_slice(data);
            Ok(())
        }
        fn progress(&mut self, received: u64, total: Option<u64>) {
            if self.reported.elapsed() >= std::time::Duration::from_millis(100) {
                self.reported = std::time::Instant::now();
                (self.progress)(DownloadProgress { received, total });
            }
        }
    }
    let failed = |detail: String| format!("download failed: {url}: {detail}");
    let mut request = crate::http_client::Request::get(
        crate::http_client::Url::parse(url).map_err(|e| failed(e.message()))?,
    );
    request.follow_redirects = true;
    request.timeout = Some(std::time::Duration::from_secs(max_time_secs));
    request.user_agent = "winrun/0.1.0".to_string();
    let mut sink = Collect {
        body: Vec::new(),
        progress,
        reported: std::time::Instant::now(),
    };
    let head = crate::http_client::fetch(&request, crate::trust_roots::bundled_roots(), &mut sink)
        .map_err(|e| failed(e.message()))?;
    if head.status >= 400 {
        return Err(failed(format!("HTTP {} {}", head.status, head.reason)));
    }
    Ok(HttpResponse {
        body: sink.body,
        url: head.url.as_string(),
        status: head.status,
    })
}

/// One ZIP local-header entry (directories end in `/`).
pub struct ZipEntry {
    pub name: String,
    pub is_dir: bool,
    method: u16,
    data_off: usize,
    csize: usize,
}

/// List a ZIP archive's entries (stored or deflated).
/// Scans local headers; central directory not required.
pub fn zip_entries(zip: &[u8]) -> Result<Vec<ZipEntry>, String> {
    // The central directory has every entry's sizes, including entries
    // written with trailing data descriptors (streamed archives, such as
    // Bun's releases), which local headers leave as zero.
    if let Some(entries) = central_directory_entries(zip)? {
        return Ok(entries);
    }
    local_header_entries(zip)
}

/// Entries from the end-of-central-directory record, or `None` when the
/// archive has none (local headers are scanned instead).
fn central_directory_entries(zip: &[u8]) -> Result<Option<Vec<ZipEntry>>, String> {
    const EOCD: &[u8] = b"PK\x05\x06";
    if zip.len() < 22 {
        return Ok(None);
    }
    let earliest = zip.len().saturating_sub(22 + 0xffff);
    let Some(eocd) = (earliest..=zip.len() - 22)
        .rev()
        .find(|&o| &zip[o..o + 4] == EOCD)
    else {
        return Ok(None);
    };
    let u16le = |o: usize| u16::from_le_bytes([zip[o], zip[o + 1]]) as usize;
    let u32le =
        |o: usize| u32::from_le_bytes([zip[o], zip[o + 1], zip[o + 2], zip[o + 3]]) as usize;
    let count = u16le(eocd + 10);
    let mut off = u32le(eocd + 16);
    if count == 0xffff || off == 0xffff_ffff {
        return Err("zip64 archives are not supported".to_string());
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if off + 46 > zip.len() || &zip[off..off + 4] != b"PK\x01\x02" {
            return Err("invalid zip central directory".to_string());
        }
        let method = u16le(off + 10) as u16;
        let csize = u32le(off + 20);
        let nlen = u16le(off + 28);
        let elen = u16le(off + 30);
        let clen = u16le(off + 32);
        let local = u32le(off + 42);
        if csize == 0xffff_ffff || local == 0xffff_ffff {
            return Err("zip64 archives are not supported".to_string());
        }
        let name_end = off + 46 + nlen;
        if name_end > zip.len() {
            return Err("truncated zip central directory".to_string());
        }
        let name = std::str::from_utf8(&zip[off + 46..name_end])
            .map_err(|_| "invalid zip entry name".to_string())?;
        if local + 30 > zip.len() || &zip[local..local + 4] != b"PK\x03\x04" {
            return Err(format!("invalid zip local header (entry '{name}')"));
        }
        let data_off = local + 30 + u16le(local + 26) + u16le(local + 28);
        if data_off
            .checked_add(csize)
            .is_none_or(|end| end > zip.len())
        {
            return Err(format!("truncated zip data (entry '{name}')"));
        }
        out.push(ZipEntry {
            name: name.to_string(),
            is_dir: name.ends_with('/'),
            method,
            data_off,
            csize,
        });
        off = name_end + elen + clen;
    }
    Ok(Some(out))
}

fn local_header_entries(zip: &[u8]) -> Result<Vec<ZipEntry>, String> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let u16le = |o: usize| u16::from_le_bytes([zip[o], zip[o + 1]]);
    let u32le = |o: usize| u32::from_le_bytes([zip[o], zip[o + 1], zip[o + 2], zip[o + 3]]);
    while off + 30 <= zip.len() {
        if &zip[off..off + 4] != b"PK\x03\x04" {
            break;
        }
        // local header: sig(4) ver(2) flags(2) method(2) time(2) date(2)
        // crc(4) csize(4) usize(4) nlen(2) elen(2)
        let flag = u16le(off + 6);
        let method = u16le(off + 8);
        let csize = u32le(off + 18) as usize;
        let nlen = u16le(off + 26) as usize;
        let elen = u16le(off + 28) as usize;
        let name_end = off + 30 + nlen;
        if name_end + elen > zip.len() {
            return Err("truncated zip entry header".to_string());
        }
        let name = std::str::from_utf8(&zip[off + 30..name_end])
            .map_err(|_| "invalid zip entry name".to_string())?;
        let data_off = name_end + elen;
        if flag & 0x08 != 0 {
            return Err(format!(
                "zip data descriptors not supported (entry '{name}')"
            ));
        }
        if data_off
            .checked_add(csize)
            .map(|e| e > zip.len())
            .unwrap_or(true)
        {
            return Err(format!("truncated zip data (entry '{name}')"));
        }
        out.push(ZipEntry {
            name: name.to_string(),
            is_dir: name.ends_with('/'),
            method,
            data_off,
            csize,
        });
        off = data_off + csize;
    }
    Ok(out)
}

/// Extract one listed entry's bytes (stored or deflated).
pub fn extract_bytes(zip: &[u8], entry: &ZipEntry) -> Result<Vec<u8>, String> {
    let raw = &zip[entry.data_off..entry.data_off + entry.csize];
    match entry.method {
        0 => Ok(raw.to_vec()),
        8 => crate::deflate::inflate(raw)
            .map_err(|e| format!("deflate failed for entry '{}': {e}", entry.name)),
        _ => Err(format!(
            "unsupported zip method {} for entry '{}' (only stored/deflated)",
            entry.method, entry.name
        )),
    }
}

/// Extract one entry from a ZIP archive (stored or deflated).
/// Scans local headers; central directory not required.
pub fn extract_entry(zip: &[u8], want: &str) -> Result<Vec<u8>, String> {
    let entries = zip_entries(zip)?;
    for entry in &entries {
        if entry.name == want {
            return extract_bytes(zip, entry);
        }
    }
    let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    Err(format!(
        "entry '{want}' not in archive (has: {})",
        if names.is_empty() {
            "(none)".to_string()
        } else {
            names.join(", ")
        }
    ))
}

// ---------- SHA-256 (FIPS 180-4, compact) ----------

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-1 (FIPS 180-4), for certificate thumbprints (not for security).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (slot, value) in h.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_the_fips_vectors() {
        let hex = |data: &[u8]| sha1(data).iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hex(&vec![b'a'; 1_000_000]), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    /// Minimal stored-zip writer (test + fixture use).
    fn zip_stored(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in files {
            let off = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes()); // version
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // method = stored
            out.extend_from_slice(&0u16.to_le_bytes()); // time
            out.extend_from_slice(&0u16.to_le_bytes()); // date
            let crc = crc32(data);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
            central.extend_from_slice(&off.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&central);
        let cd_len = central.len() as u32;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_len.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn downloads_follow_redirects_and_fail_on_error_statuses() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(3) {
                let mut stream = stream.unwrap();
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let reply: &[u8] = if head.starts_with(b"GET /old ") {
                    b"HTTP/1.1 301 Moved\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n"
                } else if head.starts_with(b"GET /new ") {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
                } else {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                };
                let _ = stream.write_all(reply);
            }
        });
        let base = format!("http://127.0.0.1:{port}");
        let mut reports = Vec::new();
        let body = fetch_url_with_progress(&format!("{base}/old"), 10, |p| reports.push(p)).unwrap();
        assert_eq!(body, b"body");
        assert_eq!(reports.last(), Some(&DownloadProgress { received: 4, total: Some(4) }));
        let error = fetch_url(&format!("{base}/gone"), 10).unwrap_err();
        assert!(error.contains("HTTP 404"), "{error}");
    }

    #[test]
    fn stored_zip_roundtrip() {
        let z = zip_stored(&[("a.exe", b"MZfake1"), ("sub/b.txt", b"hello")]);
        assert_eq!(extract_entry(&z, "a.exe").unwrap(), b"MZfake1");
        assert_eq!(extract_entry(&z, "sub/b.txt").unwrap(), b"hello");
        let err = extract_entry(&z, "nope.exe").unwrap_err();
        assert!(err.contains("a.exe") && err.contains("sub/b.txt"), "{err}");
    }

    #[test]
    fn deflated_entry_decodes() {
        // entry bytes: raw deflate of b"deflated-ok" (method flipped to 8)
        let mut z = zip_stored(&[("skip", b"")]);
        let raw = [
            0x4b, 0x49, 0x4d, 0xcb, 0x49, 0x2c, 0x49, 0x4d, 0xd1, 0xcd, 0xcf, 0x06, 0x00,
        ];
        // rebuild: header with method 8 + raw payload
        let mut entry = Vec::new();
        entry.extend_from_slice(b"PK\x03\x04");
        entry.extend_from_slice(&20u16.to_le_bytes());
        entry.extend_from_slice(&0u16.to_le_bytes());
        entry.extend_from_slice(&8u16.to_le_bytes()); // deflate
        entry.extend_from_slice(&0u16.to_le_bytes());
        entry.extend_from_slice(&0u16.to_le_bytes());
        entry.extend_from_slice(&0u32.to_le_bytes()); // crc (unchecked by reader)
        entry.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        entry.extend_from_slice(&11u32.to_le_bytes()); // usize
        entry.extend_from_slice(&6u16.to_le_bytes()); // "a.defl"
        entry.extend_from_slice(&0u16.to_le_bytes());
        entry.extend_from_slice(b"a.defl");
        entry.extend_from_slice(&raw);
        z.splice(0..z.len(), entry);
        assert_eq!(extract_entry(&z, "a.defl").unwrap(), b"deflated-ok");
        // unknown methods still fail clearly (method field is at header+8)
        z[8] = 99;
        let err = extract_entry(&z, "a.defl").unwrap_err();
        assert!(err.contains("unsupported zip method 99"), "{err}");
    }
}

#[cfg(test)]
mod zip_directory_tests {
    use super::*;

    /// A stored one-entry archive written the streaming way: zero sizes in
    /// the local header, a data descriptor after the data, and the real
    /// sizes only in the central directory.
    fn streamed_zip(name: &str, data: &[u8]) -> Vec<u8> {
        let mut zip = Vec::new();
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0x08u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // stored
        zip.extend_from_slice(&[0; 4]); // time, date
        zip.extend_from_slice(&[0; 12]); // crc, sizes deferred
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name.as_bytes());
        zip.extend_from_slice(data);
        zip.extend_from_slice(b"PK\x07\x08");
        zip.extend_from_slice(&[0; 4]);
        zip.extend_from_slice(&(data.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(data.len() as u32).to_le_bytes());
        let central = zip.len();
        zip.extend_from_slice(b"PK\x01\x02");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0x08u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&[0; 8]); // time, date, crc
        zip.extend_from_slice(&(data.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(data.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&[0; 12]); // extra, comment, disk, attributes
        zip.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        zip.extend_from_slice(name.as_bytes());
        let size = zip.len() - central;
        zip.extend_from_slice(b"PK\x05\x06");
        zip.extend_from_slice(&[0; 4]);
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&(size as u32).to_le_bytes());
        zip.extend_from_slice(&(central as u32).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip
    }

    #[test]
    fn streamed_entries_read_their_sizes_from_the_central_directory() {
        let zip = streamed_zip("dir/app.exe", b"MZ-payload");
        let entries = zip_entries(&zip).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "dir/app.exe");
        assert_eq!(extract_bytes(&zip, &entries[0]).unwrap(), b"MZ-payload");
        // Without the directory the local headers cannot size the entry.
        let central = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        assert!(zip_entries(&zip[..central]).err().unwrap().contains("data descriptors"));
        // A directory pointing past the data is rejected.
        let mut broken = zip.clone();
        let eocd = broken.len() - 22;
        broken[eocd + 16..eocd + 20].copy_from_slice(&9999u32.to_le_bytes());
        assert!(zip_entries(&broken).is_err());
    }
}
