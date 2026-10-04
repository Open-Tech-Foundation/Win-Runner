//! Shared HTTPS, ZIP, and checksum helpers for guest package data and snapshots.

use std::{io::Read, process::Stdio};

/// Download bytes over HTTPS via `curl`. Clear error when curl is missing.
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
    let out = std::process::Command::new("curl")
        .args([
            "-sSL",
            "--fail",
            "--max-time",
            &max_time_secs.to_string(),
            "-A",
            "winrun/0.1.0",
            "--write-out",
            "\n%{http_code}\n%{url_effective}",
            "--url",
            url,
        ])
        .output()
        .map_err(|_| "cannot run curl: install it to use remote sources".to_string())?;
    if !out.status.success() {
        let tail = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "download failed: {url} ({}){}",
            out.status,
            if tail.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", tail.trim())
            }
        ));
    }
    let mut parts = out.stdout.rsplitn(3, |byte| *byte == b'\n');
    let effective = parts.next().ok_or("missing response URI")?;
    let status = parts.next().ok_or("missing HTTP status")?;
    let body = parts.next().ok_or("missing response body")?;
    let body_len = body.len();
    let url = String::from_utf8(effective.to_vec()).map_err(|_| "invalid response URI")?;
    let status = std::str::from_utf8(status)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or("invalid HTTP status")?;
    let mut body = out.stdout;
    body.truncate(body_len);
    Ok(HttpResponse { body, url, status })
}

/// How much of a download has arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadProgress {
    pub received: u64,
    /// The final response's `Content-Length`, when the server sends one.
    pub total: Option<u64>,
}

/// Download bytes over HTTPS, reporting the bytes received as they stream
/// in (at most every 100 ms, and once at the end).
pub fn fetch_url_with_progress(
    url: &str,
    max_time_secs: u64,
    mut progress: impl FnMut(DownloadProgress),
) -> Result<Vec<u8>, String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_DOWNLOAD: AtomicU64 = AtomicU64::new(1);
    // curl writes each response's headers here before its body, so the
    // final response's length is known once body bytes arrive.
    let headers = std::env::temp_dir().join(format!(
        "winrun-download-{}-{}.tmp",
        std::process::id(),
        NEXT_DOWNLOAD.fetch_add(1, Ordering::Relaxed)
    ));
    struct RemoveOnDrop<'a>(&'a std::path::Path);
    impl Drop for RemoveOnDrop<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    let _headers_guard = RemoveOnDrop(&headers);
    let mut child = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--max-time",
            &max_time_secs.to_string(),
            "-A",
            "winrun/0.1.0",
            "--dump-header",
        ])
        .arg(&headers)
        .arg(url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "cannot run curl: install it to use remote sources".to_string())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "curl did not provide an error stream".to_string())?;
    let stderr_reader = std::thread::spawn(move || {
        let mut message = Vec::new();
        let _ = stderr.read_to_end(&mut message);
        message
    });
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "curl did not provide a download stream".to_string())?;
    let mut bytes = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut total = None;
    let mut reported = std::time::Instant::now();
    loop {
        let read = match stdout.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("cannot read curl download: {error}")),
        };
        bytes.extend_from_slice(&chunk[..read]);
        if total.is_none() {
            total = std::fs::read_to_string(&headers)
                .ok()
                .and_then(|text| final_content_length(&text));
        }
        if reported.elapsed() >= std::time::Duration::from_millis(100) {
            reported = std::time::Instant::now();
            progress(DownloadProgress {
                received: bytes.len() as u64,
                total,
            });
        }
    }
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for curl: {error}"))?;
    let stderr_message = stderr_reader.join().unwrap_or_default();
    if !status.success() {
        let tail = String::from_utf8_lossy(&stderr_message);
        return Err(format!(
            "download failed: {url} ({status}){}",
            if tail.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", tail.trim())
            }
        ));
    }
    progress(DownloadProgress {
        received: bytes.len() as u64,
        total: Some(bytes.len() as u64),
    });
    Ok(bytes)
}

/// The `Content-Length` of the last response in a `curl --dump-header`
/// file, which lists every redirect's headers before the final ones.
fn final_content_length(headers: &str) -> Option<u64> {
    let last = headers
        .split("\r\n\r\n")
        .filter(|block| block.trim_start().starts_with("HTTP/"))
        .last()?;
    last.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())?
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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn reads_the_final_responses_length_after_redirects() {
        let headers = "HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 5\r\n\r\n\
            HTTP/2 200\r\ncontent-type: application/zip\r\ncontent-length: 33554432\r\n\r\n";
        assert_eq!(final_content_length(headers), Some(33_554_432));
        // Not yet received, or no length (chunked).
        assert_eq!(final_content_length(""), None);
        assert_eq!(
            final_content_length("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
            None
        );
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
