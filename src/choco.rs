//! Chocolatey-compatible package installer (shell builtin).
//!
//! Real Chocolatey is a Windows service with a full PowerShell runtime
//! behind it; instead of executing the bootstrap script, wincli ships the
//! `choco` command natively. `choco install nodejs` downloads the official
//! `node-v<version>-win-x64.zip` from nodejs.org, verifies its SHA-256
//! against the release `SHASUMS256.txt`, caches `node.exe` as the `node`
//! package (`C:\bin\node.exe`), and extracts the bundled npm tree so bare
//! `npm` works through the shell.
//!
//! Layout under the shared cache (see [`crate::install`]):
//!
//! ```text
//! archives/<sha256>.zip   the verified Node.js distribution zip
//! pkgs/node.exe            extracted runnable node.exe
//! index/node.json          package metadata
//! nodejs/<version>/...     extracted npm tree (paths relative to npm root)
//! nodejs/current.json      {"version": ..., "npm": ...}
//! ```

use std::path::{Path, PathBuf};

/// Node.js version installed when `choco install nodejs` omits `--version`.
/// Pinned to the release validated against the native backend.
pub const DEFAULT_NODE_VERSION: &str = "24.21.0";

/// Version string reported by `choco --version` (the compatibility shim
/// itself, not an upstream Chocolatey release).
pub const SHIM_VERSION: &str = "0.1.0";

/// Override the distribution base URL (tests point this at a local
/// directory; `curl` serves `file://` URLs too).
fn dist_base() -> String {
    match std::env::var("WINCLI_NODEJS_DIST") {
        Ok(base) if !base.is_empty() => base.trim_end_matches('/').to_string(),
        _ => "https://nodejs.org/dist".to_string(),
    }
}

/// Parsed `choco` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChocoCmd {
    InstallNode { version: String },
    InstallCommunity { id: String, version: Option<String> },
    Version,
}

/// Parse shell argv after the `choco` word.
pub fn parse_args(argv: &[String]) -> Result<ChocoCmd, String> {
    const USAGE: &str = "usage: choco install <pkg> [--version=X.Y.Z] [-y] | choco --version";
    let verb = argv.first().map(|s| s.to_lowercase());
    match verb.as_deref() {
        Some("install") | Some("upgrade") => {
            let name = argv.get(1).ok_or_else(|| USAGE.to_string())?;
            let mut version: Option<String> = None;
            let mut i = 2;
            while i < argv.len() {
                let arg = &argv[i];
                if arg.eq_ignore_ascii_case("-y")
                    || arg.eq_ignore_ascii_case("--yes")
                    || arg.eq_ignore_ascii_case("--confirm")
                    || arg.eq_ignore_ascii_case("-y=true")
                    || arg.eq_ignore_ascii_case("--no-progress")
                {
                    i += 1;
                } else if let Some(v) = arg.strip_prefix("--version=") {
                    version = Some(v.to_string());
                    i += 1;
                } else if arg.eq_ignore_ascii_case("--version") {
                    version = Some(
                        argv.get(i + 1)
                            .ok_or_else(|| USAGE.to_string())?
                            .to_string(),
                    );
                    i += 2;
                } else {
                    return Err(format!("choco install: unknown option '{arg}' ({USAGE})"));
                }
            }
            let lowered = name.to_lowercase();
            let base = lowered.strip_suffix(".install").unwrap_or(&lowered);
            if base == "nodejs" {
                return Ok(ChocoCmd::InstallNode {
                    version: normalize_version(version.as_deref().unwrap_or(DEFAULT_NODE_VERSION))?,
                });
            }
            Ok(ChocoCmd::InstallCommunity {
                id: normalize_community_id(name)?,
                version: version
                    .map(|v| normalize_community_version(&v))
                    .transpose()?,
            })
        }
        Some("--version") | Some("-v") | Some("version") | Some("-version") => {
            Ok(ChocoCmd::Version)
        }
        _ => Err(USAGE.to_string()),
    }
}

/// Accept `24.21.0` or `v24.21.0`; reject anything else (keeps the
/// distribution URL and cache paths traversal-free).
fn normalize_version(raw: &str) -> Result<String, String> {
    // Tolerate quotes (`--version="24.21.0"`); the shell usually strips
    // them, but other callers may not.
    let v = raw.strip_prefix('v').unwrap_or(raw);
    let v = v
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(v);
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        Ok(v.to_string())
    } else {
        Err(format!(
            "choco: bad Node.js version '{raw}' (want X.Y.Z like 24.21.0)"
        ))
    }
}

/// What `choco install nodejs` put in the cache.
#[derive(Debug, Clone)]
pub struct NodeInstalled {
    pub version: String,
    pub npm_version: String,
    /// Host path of the cached runnable (`pkgs/node.exe`).
    pub node_exe_host: PathBuf,
    /// Host directory holding the extracted npm tree.
    pub npm_root_host: PathBuf,
}

/// Install (or reaffirm) a Node.js distribution in the cache.
pub fn install_nodejs(version: &str, cache: &Path) -> Result<NodeInstalled, String> {
    let version = normalize_version(version)?;
    if let Some(hit) = current_nodejs(cache) {
        if hit.version == version && hit.node_exe_host.is_file() && npm_cli(&hit).is_file() {
            return Ok(hit);
        }
    }
    let base = dist_base();
    let root = format!("node-v{version}-win-x64");
    let zip_name = format!("{root}.zip");
    let sums = crate::install::fetch_url(&format!("{base}/v{version}/SHASUMS256.txt"), 60)
        .map_err(|e| format!("choco: cannot fetch release checksums: {e}"))?;
    let sums = String::from_utf8(sums)
        .map_err(|_| format!("choco: non-UTF8 SHASUMS256.txt for v{version}"))?;
    let sha = parse_shasums(&sums, &zip_name).ok_or_else(|| {
        format!("choco: {zip_name} not listed in v{version} SHASUMS256.txt, refusing download")
    })?;
    let blob = crate::install::fetch_url(&format!("{base}/v{version}/{zip_name}"), 300)
        .map_err(|e| format!("choco: download failed: {e}"))?;
    if crate::install::sha256_hex(&blob) != sha {
        return Err(format!(
            "choco: SHA-256 mismatch for {zip_name} (SHASUMS256 {sha})"
        ));
    }
    // Reuse the content-addressed cache tail: archives/<sha>.zip,
    // pkgs/node.exe, index/node.json.
    crate::install::finalize(
        "node",
        &version,
        &format!("{root}/node.exe"),
        &blob,
        "zip",
        cache,
    )?;
    let node_exe_host = cache.join("pkgs").join("node.exe");
    let npm_dir = cache.join("nodejs").join(&version);
    extract_npm_tree(&blob, &root, &npm_dir)?;
    let npm_version = crate::install::json_string(
        &std::fs::read_to_string(npm_dir.join("package.json"))
            .map_err(|e| format!("choco: cannot read bundled npm metadata: {e}"))?,
        "version",
    )
    .ok_or_else(|| "choco: bundled npm package.json has no version".to_string())?;
    std::fs::write(
        cache.join("nodejs").join("current.json"),
        format!("{{\"name\":\"nodejs\",\"version\":\"{version}\",\"npm\":\"{npm_version}\"}}\n"),
    )
    .map_err(|e| format!("cannot write cache: {e}"))?;
    Ok(NodeInstalled {
        version,
        npm_version,
        node_exe_host,
        npm_root_host: npm_dir,
    })
}

/// The currently installed Node.js distribution, if any.
pub fn current_nodejs(cache: &Path) -> Option<NodeInstalled> {
    let doc = std::fs::read_to_string(cache.join("nodejs").join("current.json")).ok()?;
    let version = crate::install::json_string(&doc, "version")?;
    let npm_version = crate::install::json_string(&doc, "npm")?;
    let node_exe_host = cache.join("pkgs").join("node.exe");
    let npm_root_host = cache.join("nodejs").join(&version);
    Some(NodeInstalled {
        version,
        npm_version,
        node_exe_host,
        npm_root_host,
    })
}

/// Guest-absolute path of `npm-cli.js` once the tree is seeded at `C:\npm`.
pub fn npm_cli_guest() -> &'static str {
    r"C:\npm\bin\npm-cli.js"
}

/// Community package ids: lowercase letters, digits, `.`, `-`, `_`
/// (keeps feed URLs and cache paths traversal-free).
fn normalize_community_id(raw: &str) -> Result<String, String> {
    let id = raw.to_lowercase();
    if id.len() >= 2
        && id.len() <= 100
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && !id.contains("..")
    {
        Ok(id)
    } else {
        Err(format!("choco: bad package id '{raw}'"))
    }
}

/// Community versions (`26.3.0`, `1.2.3-beta1`): digits, letters, `.`, `-`.
fn normalize_community_version(raw: &str) -> Result<String, String> {
    let v = raw.strip_prefix('v').unwrap_or(raw);
    if v.len() >= 2
        && v.len() <= 40
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && v.chars().any(|c| c.is_ascii_digit())
    {
        Ok(v.to_string())
    } else {
        Err(format!("choco: bad package version '{raw}'"))
    }
}

/// Base64 (standard alphabet) for NuGet `PackageHash` values.
fn base64_decode(raw: &str) -> Result<Vec<u8>, String> {
    fn sextet(c: char) -> Option<u8> {
        match c {
            'A'..='Z' => Some(c as u8 - b'A'),
            'a'..='z' => Some(c as u8 - b'a' + 26),
            '0'..='9' => Some(c as u8 - b'0' + 52),
            '+' => Some(62),
            '/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<char> = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() || clean.len() % 4 != 0 {
        return Err("choco: bad base64 hash".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for quad in clean.chunks_exact(4) {
        let pad = quad.iter().rev().take_while(|c| **c == '=').count();
        if pad > 2 || quad[..4 - pad].contains(&'=') {
            return Err("choco: bad base64 hash".to_string());
        }
        let mut n = 0u32;
        for c in &quad[..4 - pad] {
            n = (n << 6)
                | u32::from(sextet(*c).ok_or_else(|| "choco: bad base64 hash".to_string())?);
        }
        n <<= 6 * pad;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// Community feed base (tests point this at a local directory).
fn community_feed_base() -> String {
    match std::env::var("WINCLI_CHOCOLATEY_FEED") {
        Ok(base) if !base.is_empty() => base.trim_end_matches('/').to_string(),
        _ => "https://community.chocolatey.org/api/v2".to_string(),
    }
}

/// A resolved community package: exact version plus verified hash.
#[derive(Debug, Clone)]
pub struct CommunityPkg {
    pub id: String,
    pub version: String,
    pub sha512: [u8; 64],
}

/// Resolve `<id>` (+ optional version) through the Chocolatey feed
/// (the OData entry carries the SHA-512 `PackageHash`).
pub fn resolve_community(id: &str, version: Option<&str>) -> Result<CommunityPkg, String> {
    let id = normalize_community_id(id)?;
    let filter = match version {
        Some(v) => {
            let v = normalize_community_version(v)?;
            format!("tolower(Id) eq '{id}' and Version eq '{v}'")
        }
        None => format!("tolower(Id) eq '{id}' and IsLatestVersion eq true"),
    };
    // Minimal OData encoding: the feed tolerates %20/%27 here.
    let query = filter.replace(' ', "%20").replace('\'', "%27");
    let url = format!("{}/Packages()?$filter={query}", community_feed_base());
    let doc = crate::install::fetch_url(&url, 60)
        .map_err(|e| format!("choco: cannot query package {id}: {e}"))?;
    let doc =
        String::from_utf8(doc).map_err(|_| format!("choco: non-UTF8 feed response for {id}"))?;
    let (version, hash_b64, algo) =
        parse_feed_entry(&doc).ok_or_else(|| format!("choco: package not found: {id}"))?;
    if algo != "SHA512" {
        return Err(format!(
            "choco: {id} has no SHA-512 PackageHash, refusing download"
        ));
    }
    let hash = base64_decode(&hash_b64)?;
    if hash.len() != 64 {
        return Err(format!("choco: bad PackageHash length for {id}"));
    }
    let mut sha512 = [0u8; 64];
    sha512.copy_from_slice(&hash);
    Ok(CommunityPkg {
        id,
        version,
        sha512,
    })
}

/// First `<entry>`'s version, package hash, and hash algorithm.
fn parse_feed_entry(xml: &str) -> Option<(String, String, String)> {
    let entry = xml.split("<entry>").nth(1)?;
    let tag = |name: &str| {
        let open = format!("<d:{name}>");
        let close = format!("</d:{name}>");
        let start = entry.find(&open)? + open.len();
        let end = entry[start..].find(&close)?;
        Some(entry[start..start + end].trim().to_string())
    };
    Some((
        tag("Version")?,
        tag("PackageHash")?,
        tag("PackageHashAlgorithm")?,
    ))
}

/// An installed community package: a tools tree plus its runnable.
#[derive(Debug, Clone)]
pub struct ChocoApp {
    pub name: String,
    pub version: String,
    /// Forward-slash path of the runnable inside the app tree.
    pub exe_rel: String,
    /// Host directory holding the extracted tree.
    pub dir_host: PathBuf,
}

/// Install a community package: verify the nupkg, extract its `tools/`
/// tree (unpacking nested archives), and pick the runnable.
pub fn install_community(
    id: &str,
    version: Option<&str>,
    cache: &Path,
) -> Result<ChocoApp, String> {
    let id = normalize_community_id(id)?;
    let sep = std::path::MAIN_SEPARATOR.to_string();
    if let Some(hit) = current_app(cache, &id) {
        if version.map_or(true, |v| v == hit.version)
            && hit.dir_host.join(hit.exe_rel.replace('/', &sep)).is_file()
        {
            return Ok(hit);
        }
    }
    let pkg = resolve_community(&id, version)?;
    let blob = crate::install::fetch_url(
        &format!(
            "{}/package/{}/{}",
            community_feed_base(),
            pkg.id,
            pkg.version
        ),
        300,
    )
    .map_err(|e| format!("choco: download failed: {e}"))?;
    if crate::install::sha512(&blob) != pkg.sha512 {
        return Err(format!(
            "choco: SHA-512 mismatch for {} {}",
            pkg.id, pkg.version
        ));
    }
    let hb = crate::install::sha256_hex(&blob);
    let archives = cache.join("archives");
    std::fs::create_dir_all(&archives).map_err(|e| format!("cannot create cache: {e}"))?;
    let blob_path = archives.join(format!("{hb}.nupkg"));
    if !blob_path.is_file() {
        std::fs::write(&blob_path, &blob).map_err(|e| format!("cannot write cache: {e}"))?;
    }
    let dest = cache.join("choco").join(&pkg.id).join(&pkg.version);
    extract_nupkg_tools(&blob, &dest)?;
    unpack_nested_archives(&dest)?;
    let (exe_rel, _) = pick_app_exe(&pkg.id, &dest)?;
    std::fs::write(
        cache.join("choco").join(format!("{}.json", pkg.id)),
        format!(
            "{{\"name\":\"{}\",\"version\":\"{}\",\"exe\":\"{}\"}}\n",
            pkg.id, pkg.version, exe_rel
        ),
    )
    .map_err(|e| format!("cannot write cache: {e}"))?;
    Ok(ChocoApp {
        name: pkg.id,
        version: pkg.version,
        exe_rel,
        dir_host: dest,
    })
}

/// The installed community app for `id`, if any.
pub fn current_app(cache: &Path, id: &str) -> Option<ChocoApp> {
    let doc = std::fs::read_to_string(cache.join("choco").join(format!("{id}.json"))).ok()?;
    let name = crate::install::json_string(&doc, "name")?;
    let version = crate::install::json_string(&doc, "version")?;
    let exe_rel = crate::install::json_string(&doc, "exe")?;
    Some(ChocoApp {
        name,
        version,
        exe_rel,
        dir_host: cache.join("choco").join(id),
    })
}

/// Match a bare shell word against installed community apps: full id,
/// id base (`7zip` for `7zip.portable`), or the runnable's stem (`7z`).
pub fn find_choco_app(cache: &Path, target: &str) -> Option<ChocoApp> {
    let dir = cache.join("choco");
    let entries = std::fs::read_dir(&dir).ok()?;
    let want = target.strip_suffix(".exe").unwrap_or(target).to_lowercase();
    if want == "nodejs" {
        return None;
    }
    let mut best: Option<ChocoApp> = None;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        if id == "nodejs" {
            continue;
        }
        let app = current_app(cache, id)?;
        let file = app.exe_rel.rsplit('/').next().unwrap_or("");
        let stem = file
            .strip_suffix(".exe")
            .or_else(|| file.strip_suffix(".EXE"))
            .unwrap_or("")
            .to_lowercase();
        let base = id
            .strip_suffix(".portable")
            .or_else(|| id.strip_suffix(".install"))
            .unwrap_or(id);
        if want == id || want == base || (!stem.is_empty() && want == stem) {
            // An exact id hit wins immediately; base/stem hits keep the
            // first candidate (one app per name in practice).
            if want == id {
                return Some(app);
            }
            best = best.or(Some(app));
        }
    }
    best
}

/// Extract a nupkg's `tools/` tree into `dest` (prefix stripped).
fn extract_nupkg_tools(blob: &[u8], dest: &Path) -> Result<(), String> {
    let entries = crate::install::zip_entries(blob)?;
    let sep = std::path::MAIN_SEPARATOR.to_string();
    let mut have_tools = false;
    for entry in &entries {
        if !entry.name.to_lowercase().starts_with("tools/") {
            continue;
        }
        let rel = entry.name["tools/".len()..].to_string();
        if rel.is_empty() {
            continue;
        }
        have_tools = true;
        let out = dest.join(rel.replace('/', &sep));
        if entry.is_dir {
            std::fs::create_dir_all(&out).map_err(|e| format!("cannot write cache: {e}"))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("cannot write cache: {e}"))?;
        }
        let bytes = crate::install::extract_bytes(blob, entry)?;
        std::fs::write(&out, bytes).map_err(|e| format!("cannot write cache: {e}"))?;
    }
    if !have_tools {
        return Err("choco: package has no tools/ payload".to_string());
    }
    Ok(())
}

/// Unpack nested archives inside an extracted tools tree: `.zip` with
/// the built-in reader, `.7z` and SFX `.exe` payloads with host `7z`.
/// `Get-ChocolateyUnzip` targets go first; other archive-looking
/// payloads follow. Unpacked payloads are removed afterwards.
fn unpack_nested_archives(dest: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    collect_tree_files(dest, &mut files);
    files.sort();
    let mut targets: Vec<PathBuf> = Vec::new();
    for file in &files {
        if file
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("chocolateyinstall.ps1"))
        {
            let ps1 = std::fs::read_to_string(file)
                .map_err(|e| format!("choco: cannot read installer script: {e}"))?;
            for target in ps1_unzip_targets(&ps1) {
                let sep = std::path::MAIN_SEPARATOR.to_string();
                let candidate = dest.join(target.replace('/', &sep));
                if candidate.is_file() && !targets.contains(&candidate) {
                    targets.push(candidate);
                }
            }
        }
    }
    for file in &files {
        if is_archive_payload(file) && !targets.contains(file) {
            targets.push(file.clone());
        }
    }
    for target in targets {
        unpack_archive_payload(&target, dest)?;
    }
    Ok(())
}

fn collect_tree_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_tree_files(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

/// Only unpack `.exe` payloads that look like self-extractors (real
/// application exes must never be unpacked).
fn is_archive_payload(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "zip" | "7z" => true,
        "exe" => {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            stem.contains("sfx")
                || stem.ends_with("_x32")
                || stem.ends_with("_x64")
                || stem.ends_with("-x32")
                || stem.ends_with("-x64")
        }
        _ => false,
    }
}

/// Unpack one payload into the app tree; the payload is removed after.
fn unpack_archive_payload(payload: &Path, dest: &Path) -> Result<(), String> {
    let ext = payload
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let sep = std::path::MAIN_SEPARATOR.to_string();
    if ext == "zip" {
        let blob =
            std::fs::read(payload).map_err(|e| format!("choco: cannot read payload: {e}"))?;
        for entry in crate::install::zip_entries(&blob).map_err(|e| format!("choco: {e}"))? {
            if entry.is_dir {
                continue;
            }
            let out = dest.join(entry.name.replace('/', &sep));
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("cannot write cache: {e}"))?;
            }
            let bytes =
                crate::install::extract_bytes(&blob, &entry).map_err(|e| format!("choco: {e}"))?;
            std::fs::write(&out, bytes).map_err(|e| format!("cannot write cache: {e}"))?;
        }
    } else {
        let status = std::process::Command::new("7z")
            .args([
                "x".to_string(),
                format!("-o{}", dest.display()),
                payload.display().to_string(),
                "-y".to_string(),
            ])
            .output()
            .map_err(|_| {
                "choco: need host 7-Zip (`7z`) to unpack this package payload".to_string()
            })?;
        if !status.status.success() {
            return Err(format!(
                "choco: cannot unpack {}: {}",
                payload.display(),
                String::from_utf8_lossy(&status.stderr).trim()
            ));
        }
    }
    std::fs::remove_file(payload).map_err(|e| format!("cannot write cache: {e}"))?;
    Ok(())
}

/// `file = ...` targets of `Get-ChocolateyUnzip` in an installer script:
/// literals plus `$toolsDir\<file>` variable assignments used by reference.
fn ps1_unzip_targets(ps1: &str) -> Vec<String> {
    use std::collections::HashMap;
    let mut vars: HashMap<String, String> = HashMap::new();
    for line in ps1.lines() {
        let t = line.trim().trim_start_matches('$');
        let Some((name, value)) = t.split_once('=') else {
            continue;
        };
        let name = name.trim().to_lowercase();
        let value = value.trim().trim_matches(['\'', '"', ';']).trim();
        if name.is_empty() || name.contains(' ') || value.contains('$') {
            continue;
        }
        if value.to_lowercase().contains("$toolsdir") {
            if let Some(file) = value.rsplit(['\\', '/']).next() {
                let file = file.trim_matches(['\'', '"', ';']);
                if !file.is_empty() {
                    vars.insert(name, file.to_string());
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut push = |file: &str| {
        let file = file.trim_matches(['\'', '"', ';', ',']);
        if !file.is_empty() && !out.contains(&file.to_string()) {
            out.push(file.to_string());
        }
    };
    for line in ps1.lines() {
        let t = line.trim();
        if !t.to_lowercase().starts_with("file") {
            continue;
        }
        let Some((_, value)) = t.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches(['\'', '"', ';', ',']);
        if value.starts_with('$') {
            if let Some(file) = vars.get(value[1..].trim().to_lowercase().as_str()) {
                push(file);
            }
        } else if !value.is_empty() && !value.contains([' ', '$']) && value.contains('.') {
            if let Some(file) = value.rsplit(['\\', '/']).next() {
                push(file);
            }
        }
    }
    out
}

/// Pick the runnable inside an extracted app tree: exact id-base stem,
/// then substring stem, then shortest stem; ties break by larger file.
fn pick_app_exe(id: &str, dest: &Path) -> Result<(String, Vec<(String, u64)>), String> {
    let mut files = Vec::new();
    collect_tree_files(dest, &mut files);
    let mut exes: Vec<(String, u64)> = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(dest)
            .map_err(|_| "choco: bad app path".to_string())?
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        if !rel.to_lowercase().ends_with(".exe") {
            continue;
        }
        if rel.to_lowercase().contains("uninstall") {
            continue;
        }
        let size = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
        exes.push((rel, size));
    }
    if exes.is_empty() {
        if id.ends_with(".install") {
            let base = id.strip_suffix(".install").unwrap_or(id);
            return Err(format!(
                "choco: {id} downloads a GUI installer at install time; try 'choco install {base}.portable'"
            ));
        }
        return Err(format!("choco: {id} embeds no runnable executable"));
    }
    let base = id
        .strip_suffix(".portable")
        .or_else(|| id.strip_suffix(".install"))
        .unwrap_or(id);
    let stem_of = |rel: &str| file_stem_lower(rel.rsplit('/').next().unwrap_or(""));
    exes.sort_by(|a, b| {
        let score = |rel: &str| {
            let stem = stem_of(rel);
            if stem == base {
                2u8
            } else if base.contains(&stem) || stem.contains(base) {
                1u8
            } else {
                0u8
            }
        };
        score(&b.0)
            .cmp(&score(&a.0))
            .then_with(|| stem_of(&a.0).len().cmp(&stem_of(&b.0).len()))
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.cmp(&b.0))
    });
    Ok((exes[0].0.clone(), exes))
}

fn file_stem_lower(file: &str) -> String {
    let lower = file.to_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

fn npm_cli(hit: &NodeInstalled) -> PathBuf {
    hit.npm_root_host.join("bin").join("npm-cli.js")
}

/// Find `<hex>  <name>` in a SHASUMS256.txt document.
fn parse_shasums(doc: &str, name: &str) -> Option<String> {
    doc.lines().find_map(|line| {
        let mut cols = line.split_whitespace();
        let sha = cols.next()?;
        let file = cols.next()?;
        if file.strip_prefix('*').unwrap_or(file) != name {
            return None;
        }
        (sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit())).then(|| sha.to_string())
    })
}

/// Extract `<root>/node_modules/npm/**` from the dist zip into `dest`
/// (paths relative to the npm root).
fn extract_npm_tree(blob: &[u8], root: &str, dest: &Path) -> Result<(), String> {
    let prefix = format!("{root}/node_modules/npm/");
    let entries = crate::install::zip_entries(blob)?;
    let mut count = 0;
    for entry in &entries {
        let Some(rel) = entry.name.strip_prefix(&prefix) else {
            continue;
        };
        if rel.is_empty() || entry.is_dir {
            continue;
        }
        if rel.contains("..") {
            return Err(format!("choco: unsafe zip entry '{}'", entry.name));
        }
        let bytes = crate::install::extract_bytes(blob, entry)?;
        let out = dest.join(rel.replace('/', &std::path::MAIN_SEPARATOR.to_string()));
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("cannot write cache: {e}"))?;
        }
        std::fs::write(&out, bytes).map_err(|e| format!("cannot write cache: {e}"))?;
        count += 1;
    }
    if count == 0 {
        return Err("choco: distribution zip has no bundled npm tree".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests mutate `WINCLI_NODEJS_DIST`; serialize them (Rust runs tests
    /// in parallel threads of one process).
    static DIST_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parses_install_with_version_forms() {
        let argv = |words: &[&str]| words.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_args(&argv(&["install", "nodejs", "--version=\"24.21.0\""])).unwrap(),
            ChocoCmd::InstallNode {
                version: "24.21.0".into()
            }
        );
        assert_eq!(
            parse_args(&argv(&[
                "install",
                "nodejs.install",
                "--version",
                "v22.1.0",
                "-y"
            ]))
            .unwrap(),
            ChocoCmd::InstallNode {
                version: "22.1.0".into()
            }
        );
        assert_eq!(
            parse_args(&argv(&["upgrade", "nodejs"])).unwrap(),
            ChocoCmd::InstallNode {
                version: DEFAULT_NODE_VERSION.into()
            }
        );
        assert_eq!(
            parse_args(&argv(&["--version"])).unwrap(),
            ChocoCmd::Version
        );
    }

    #[test]
    fn rejects_bad_packages_versions_and_options() {
        let argv = |words: &[&str]| words.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(parse_args(&argv(&["install", "python"]))
            .unwrap_err()
            .contains("no such package"));
        assert!(parse_args(&argv(&["install"]))
            .unwrap_err()
            .contains("usage"));
        assert!(parse_args(&argv(&["install", "nodejs", "--version=abc"]))
            .unwrap_err()
            .contains("bad Node.js version"));
        assert!(parse_args(&argv(&["install", "nodejs", "--version=24.21"]))
            .unwrap_err()
            .contains("bad Node.js version"));
        assert!(
            parse_args(&argv(&["install", "nodejs", "--version=24.21.0", "--evil"]))
                .unwrap_err()
                .contains("unknown option")
        );
        assert!(parse_args(&argv(&["frob"])).unwrap_err().contains("usage"));
    }

    #[test]
    fn finds_shasums_entries() {
        let doc = "aaa000\n158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541  node-v24.21.0-win-x64.zip\n";
        assert_eq!(
            parse_shasums(doc, "node-v24.21.0-win-x64.zip").as_deref(),
            Some("158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541")
        );
        assert!(parse_shasums(doc, "node-v99-win-x64.zip").is_none());
    }

    /// Minimal stored-zip writer for fixture distributions.
    fn zip_stored(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in files {
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    /// Install from a local `file://` fixture distribution (offline).
    #[test]
    fn installs_nodejs_from_a_fixture_dist() {
        let _guard = DIST_ENV_LOCK.lock().unwrap();
        let tag = format!("wincli-choco-{}", std::process::id());
        let dist = std::env::temp_dir().join(format!("{tag}-dist"));
        let cache = std::env::temp_dir().join(format!("{tag}-cache"));
        std::fs::create_dir_all(dist.join("v9.9.9")).unwrap();
        let zip = zip_stored(&[
            ("node-v9.9.9-win-x64/node.exe", b"MZ-fake-node"),
            (
                "node-v9.9.9-win-x64/node_modules/npm/bin/npm-cli.js",
                b"fake-cli",
            ),
            (
                "node-v9.9.9-win-x64/node_modules/npm/package.json",
                br#"{"name":"npm","version":"9.9.9"}"#,
            ),
        ]);
        let sha = crate::install::sha256_hex(&zip);
        std::fs::write(dist.join("v9.9.9").join("node-v9.9.9-win-x64.zip"), &zip).unwrap();
        std::fs::write(
            dist.join("v9.9.9").join("SHASUMS256.txt"),
            format!("{sha}  node-v9.9.9-win-x64.zip\n"),
        )
        .unwrap();
        std::env::set_var("WINCLI_NODEJS_DIST", format!("file://{}", dist.display()));
        let inst = install_nodejs("9.9.9", &cache).unwrap();
        assert_eq!(inst.version, "9.9.9");
        assert_eq!(inst.npm_version, "9.9.9");
        assert_eq!(std::fs::read(&inst.node_exe_host).unwrap(), b"MZ-fake-node");
        assert!(inst.npm_root_host.join("bin").join("npm-cli.js").is_file());
        // Second run is a cache hit (no network needed).
        std::fs::remove_dir_all(&dist).unwrap();
        std::env::remove_var("WINCLI_NODEJS_DIST");
        let again = install_nodejs("9.9.9", &cache).unwrap();
        assert_eq!(again.npm_version, "9.9.9");
        let _ = std::fs::remove_dir_all(&cache);
    }

    #[test]
    fn refuses_tampered_fixture_zip() {
        let _guard = DIST_ENV_LOCK.lock().unwrap();
        let tag = format!("wincli-choco-tamper-{}", std::process::id());
        let dist = std::env::temp_dir().join(format!("{tag}-dist"));
        let cache = std::env::temp_dir().join(format!("{tag}-cache"));
        std::fs::create_dir_all(dist.join("v9.9.8")).unwrap();
        std::fs::write(
            dist.join("v9.9.8").join("node-v9.9.8-win-x64.zip"),
            b"tampered",
        )
        .unwrap();
        std::fs::write(
            dist.join("v9.9.8").join("SHASUMS256.txt"),
            format!("{}  node-v9.9.8-win-x64.zip\n", "0".repeat(64)),
        )
        .unwrap();
        std::env::set_var("WINCLI_NODEJS_DIST", format!("file://{}", dist.display()));
        let err = install_nodejs("9.9.8", &cache).unwrap_err();
        assert!(err.contains("SHA-256 mismatch"), "{err}");
        std::env::remove_var("WINCLI_NODEJS_DIST");
        let _ = std::fs::remove_dir_all(&dist);
        let _ = std::fs::remove_dir_all(&cache);
    }
}
