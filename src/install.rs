//! Package install + cache.
//!
//! Layout under `$WINCLI_CACHE` (default `$XDG_CACHE_HOME/wincli` or
//! `~/.cache/wincli`):
//!
//! ```text
//! index/<name>.json     resolved metadata (version, exe, archive sha256)
//! archives/<sha256>.*   downloaded blobs, content-addressed (fetch once ever)
//! pkgs/<name>.exe       extracted runnable EXEs
//! ```
//!
//! Sources: a local directory (`$WINCLI_SOURCE` set to a path, holding
//! `<name>.json` + `<name>.zip` per package) or, by default, the remote
//! WinGet catalog (see `winget`). Archives may be stored or deflated zips,
//! or (remote portable installers) the exe itself.

use std::path::{Path, PathBuf};

/// Resolve the cache dir: `$WINCLI_CACHE`, else XDG, else `~/.cache/wincli`.
pub fn cache_dir() -> PathBuf {
    if let Ok(p) = std::env::var("WINCLI_CACHE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join("wincli");
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return PathBuf::from(h).join(".cache").join("wincli");
        }
    }
    std::env::temp_dir().join("wincli-cache")
}

/// Package source: a local directory, or the remote WinGet catalog.
#[derive(Debug, Clone)]
pub enum Source {
    Local(PathBuf),
    Winget,
}

/// Resolve the source: `$WINCLI_SOURCE` unset/`winget` → remote catalog,
/// otherwise a local package directory (must exist).
pub fn source_from_env() -> Result<Source, String> {
    match std::env::var("WINCLI_SOURCE") {
        Ok(p) if !p.is_empty() && p != "winget" => {
            let dir = PathBuf::from(&p);
            if !dir.is_dir() {
                return Err(format!("package source dir not found: {p}"));
            }
            Ok(Source::Local(dir))
        }
        Ok(_) | Err(_) => Ok(Source::Winget),
    }
}

/// Kept for explicit local-dir use (tests, fixtures).
pub fn source_dir() -> Result<PathBuf, String> {
    match source_from_env()? {
        Source::Local(p) => Ok(p),
        Source::Winget => Err("no local package source: set WINCLI_SOURCE to a package directory".to_string()),
    }
}

/// Download bytes over HTTPS via `curl`. Clear error when curl is missing.
pub fn fetch_url(url: &str, max_time_secs: u64) -> Result<Vec<u8>, String> {
    let out = std::process::Command::new("curl")
        .args([
            "-sSL",
            "--fail",
            "--max-time",
            &max_time_secs.to_string(),
            "-A",
            "wincli/0.1.0",
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
    Ok(out.stdout)
}

#[derive(Debug, Clone)]
pub struct Installed {
    pub name: String,
    pub version: String,
    /// File name of the exe inside the archive.
    pub exe_name: String,
    /// Guest-logical install location (resolved to the host cache at run time).
    pub guest_path: String,
    /// Host path of the cached runnable.
    pub host_path: PathBuf,
}

/// Install a package from a local source dir into the cache.
pub fn install(name: &str, source: &Path, cache: &Path) -> Result<Installed, String> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(format!("invalid package name: {name}"));
    }
    let manifest_path = source.join(format!("{name}.json"));
    let manifest = std::fs::read_to_string(&manifest_path)
        .map_err(|_| format!("package not found: {name} (no {} in source)", manifest_path.display()))?;
    let version = json_string(&manifest, "version")
        .ok_or_else(|| format!("package {name}: manifest missing \"version\""))?;
    let exe = json_string(&manifest, "exe")
        .ok_or_else(|| format!("package {name}: manifest missing \"exe\""))?;
    let archive_name =
        json_string(&manifest, "archive").unwrap_or_else(|| format!("{name}.zip"));
    if archive_name.contains('/') || archive_name.contains('\\') || archive_name.contains("..") {
        return Err(format!("package {name}: bad archive name"));
    }
    let blob = std::fs::read(source.join(&archive_name))
        .map_err(|_| format!("package {name}: missing archive {archive_name} in source"))?;
    let exe_bytes =
        extract_entry(&blob, &exe).map_err(|e| format!("package {name}: {e}"))?;
    if exe_bytes.len() < 2 || &exe_bytes[0..2] != b"MZ" {
        return Err(format!("package {name}: archive entry {exe} is not a PE file"));
    }
    finalize(name, &version, &exe, &blob, "zip", cache)
}

/// Install from the remote WinGet catalog: resolve → download (unless the
/// content-addressed blob is already cached) → verify SHA-256 → extract →
/// cache. Re-running never re-downloads.
pub fn install_remote(name: &str, cache: &Path) -> Result<Installed, String> {
    check_name(name)?;
    let r = crate::winget::resolve(name)?;
    let ext = match r.kind {
        crate::winget::Kind::Exe => "exe",
        crate::winget::Kind::Zip { .. } => "zip",
    };
    let blob_path = cache.join("archives").join(format!("{}.{ext}", r.sha256));
    let blob = if blob_path.is_file() {
        std::fs::read(&blob_path).map_err(|e| format!("cannot read cache: {e}"))?
    } else {
        let bytes = fetch_url(&r.url, 180)?;
        let sha = sha256_hex(&bytes);
        if sha != r.sha256 {
            return Err(format!(
                "SHA-256 mismatch for {} {} (manifest {}, got {})",
                r.id, r.version, r.sha256, sha
            ));
        }
        std::fs::create_dir_all(blob_path.parent().unwrap())
            .map_err(|e| format!("cannot create cache: {e}"))?;
        std::fs::write(&blob_path, &bytes).map_err(|e| format!("cannot write cache: {e}"))?;
        bytes
    };
    // Re-verify even on cache hit (cheap, guards against tampering).
    if sha256_hex(&blob) != r.sha256 {
        return Err(format!("cached blob failed SHA-256 for {} {}", r.id, r.version));
    }
    let (exe_bytes, exe_rel) = match &r.kind {
        crate::winget::Kind::Exe => (blob.clone(), r.exe_name.clone()),
        crate::winget::Kind::Zip { nested } => (
            extract_entry(&blob, nested)
                .map_err(|e| format!("package {}: {e}", r.id))?,
            nested.clone(),
        ),
    };
    if exe_bytes.len() < 2 || &exe_bytes[0..2] != b"MZ" {
        return Err(format!("package {}: payload is not a PE file", r.id));
    }
    finalize(name, &r.version, &exe_rel, &blob, ext, cache)
}

fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(format!("invalid package name: {name}"));
    }
    Ok(())
}

/// Shared cache-write tail for local + remote installs.
fn finalize(
    name: &str,
    version: &str,
    exe_rel: &str,
    blob: &[u8],
    blob_ext: &str,
    cache: &Path,
) -> Result<Installed, String> {
    let sha = sha256_hex(blob);
    for d in ["archives", "pkgs", "index"] {
        std::fs::create_dir_all(cache.join(d)).map_err(|e| format!("cannot create cache: {e}"))?;
    }
    // Local path already wrote the blob; remote path too. Ensure present.
    let blob_path = cache.join("archives").join(format!("{sha}.{blob_ext}"));
    if !blob_path.is_file() {
        std::fs::write(&blob_path, blob).map_err(|e| format!("cannot write cache: {e}"))?;
    }
    let exe_bytes = if blob_ext == "zip" {
        extract_entry(blob, exe_rel).map_err(|e| format!("package {name}: {e}"))?
    } else {
        blob.to_vec()
    };
    let host_path = cache.join("pkgs").join(format!("{name}.exe"));
    std::fs::write(&host_path, &exe_bytes).map_err(|e| format!("cannot write cache: {e}"))?;

    let exe_base = exe_rel
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(exe_rel)
        .to_string();
    let index = format!(
        "{{\"name\":\"{}\",\"version\":\"{}\",\"exe\":\"{}\",\"sha256\":\"{}\"}}\n",
        esc(name),
        esc(version),
        esc(exe_rel),
        sha
    );
    std::fs::write(cache.join("index").join(format!("{name}.json")), index)
        .map_err(|e| format!("cannot write cache: {e}"))?;

    Ok(Installed {
        name: name.to_string(),
        version: version.to_string(),
        exe_name: exe_base.clone(),
        guest_path: format!("C:\\bin\\{exe_base}"),
        host_path,
    })
}

/// Resolve a cached runnable by package name (`demo` or `demo.exe`).
pub fn find_cached(cache: &Path, name: &str) -> Option<PathBuf> {
    let base = name.strip_suffix(".exe").unwrap_or(name);
    if base.contains('/') || base.contains('\\') || base.contains("..") {
        return None;
    }
    let p = cache.join("pkgs").join(format!("{base}.exe"));
    p.is_file().then_some(p)
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Extract one string field from a flat JSON object. Handles \" and \\.
pub fn json_string(doc: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let mut search = doc;
    loop {
        let i = search.find(&pat)?;
        let rest = search[i + pat.len()..].trim_start();
        let rest = match rest.strip_prefix(':') {
            Some(r) => r.trim_start(),
            None => {
                search = &search[i + pat.len()..];
                continue;
            }
        };
        let mut chars = rest.strip_prefix('"')?.chars();
        let mut out = String::new();
        loop {
            match chars.next()? {
                '\\' => out.push(chars.next()?),
                '"' => return Some(out),
                c => out.push(c),
            }
        }
    }
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
    let u32le = |o: usize| {
        u32::from_le_bytes([zip[o], zip[o + 1], zip[o + 2], zip[o + 3]])
    };
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
            return Err(format!("zip data descriptors not supported (entry '{name}')"));
        }
        if data_off.checked_add(csize).map(|e| e > zip.len()).unwrap_or(true) {
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
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
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
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
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
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmpdir(tag: &str) -> PathBuf {
        static C: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "wincli-install-test-{}-{}-{tag}",
            std::process::id(),
            C.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
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

    #[test]
    fn json_string_fields() {
        let doc = r#"{"name":"demo", "version" : "0.1.0", "exe":"demo.exe"}"#;
        assert_eq!(json_string(doc, "name").as_deref(), Some("demo"));
        assert_eq!(json_string(doc, "version").as_deref(), Some("0.1.0"));
        assert_eq!(json_string(doc, "missing"), None);
    }

    #[test]
    fn install_local_roundtrip() {
        let src = tmpdir("src");
        let cache = tmpdir("cache");
        let exe = b"MZ-fake-pe-bytes";
        std::fs::write(src.join("demo.zip"), zip_stored(&[("demo.exe", exe)])).unwrap();
        std::fs::write(
            src.join("demo.json"),
            r#"{"name":"demo","version":"0.1.0","exe":"demo.exe"}"#,
        )
        .unwrap();
        let inst = install("demo", &src, &cache).unwrap();
        assert_eq!(inst.version, "0.1.0");
        assert_eq!(inst.guest_path, "C:\\bin\\demo.exe");
        assert_eq!(std::fs::read(&inst.host_path).unwrap(), exe);
        assert_eq!(
            find_cached(&cache, "demo").unwrap(),
            cache.join("pkgs").join("demo.exe")
        );
        assert!(find_cached(&cache, "demo.exe").is_some());
        // content-addressed blob present
        let sha = sha256_hex(&std::fs::read(src.join("demo.zip")).unwrap());
        assert!(cache.join("archives").join(format!("{sha}.zip")).is_file());
        // unknown package + traversal rejected
        assert!(install("nope", &src, &cache).is_err());
        assert!(install("../evil", &src, &cache).is_err());
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&cache);
    }
}
