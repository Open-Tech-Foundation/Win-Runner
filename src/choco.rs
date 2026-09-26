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
    Version,
}

/// Parse shell argv after the `choco` word.
pub fn parse_args(argv: &[String]) -> Result<ChocoCmd, String> {
    const USAGE: &str = "usage: choco install nodejs [--version=X.Y.Z] [-y] | choco --version";
    let verb = argv.first().map(|s| s.to_lowercase());
    match verb.as_deref() {
        Some("install") | Some("upgrade") => {
            let name = argv.get(1).ok_or_else(|| USAGE.to_string())?;
            let base = name.to_lowercase();
            let base = base.strip_suffix(".install").unwrap_or(&base);
            if base != "nodejs" {
                return Err(format!(
                    "choco: no such package '{name}' (try 'choco install nodejs')"
                ));
            }
            let mut version = DEFAULT_NODE_VERSION.to_string();
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
                    version = v.to_string();
                    i += 1;
                } else if arg.eq_ignore_ascii_case("--version") {
                    version = argv
                        .get(i + 1)
                        .ok_or_else(|| USAGE.to_string())?
                        .to_string();
                    i += 2;
                } else {
                    return Err(format!("choco install: unknown option '{arg}' ({USAGE})"));
                }
            }
            Ok(ChocoCmd::InstallNode {
                version: normalize_version(&version)?,
            })
        }
        Some("--version") | Some("-v") | Some("version") | Some("-version") => Ok(ChocoCmd::Version),
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
    crate::install::finalize("node", &version, &format!("{root}/node.exe"), &blob, "zip", cache)?;
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
            parse_args(&argv(&["install", "nodejs.install", "--version", "v22.1.0", "-y"])).unwrap(),
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
        assert_eq!(parse_args(&argv(&["--version"])).unwrap(), ChocoCmd::Version);
    }

    #[test]
    fn rejects_bad_packages_versions_and_options() {
        let argv = |words: &[&str]| words.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(parse_args(&argv(&["install", "python"])).unwrap_err().contains("no such package"));
        assert!(parse_args(&argv(&["install"])).unwrap_err().contains("usage"));
        assert!(parse_args(&argv(&["install", "nodejs", "--version=abc"])).unwrap_err().contains("bad Node.js version"));
        assert!(parse_args(&argv(&["install", "nodejs", "--version=24.21"])).unwrap_err().contains("bad Node.js version"));
        assert!(parse_args(&argv(&["install", "nodejs", "--version=24.21.0", "--evil"])).unwrap_err().contains("unknown option"));
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
        std::env::set_var(
            "WINCLI_NODEJS_DIST",
            format!("file://{}", dist.display()),
        );
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
        std::fs::write(dist.join("v9.9.8").join("node-v9.9.8-win-x64.zip"), b"tampered").unwrap();
        std::fs::write(
            dist.join("v9.9.8").join("SHASUMS256.txt"),
            format!("{}  node-v9.9.8-win-x64.zip\n", "0".repeat(64)),
        )
        .unwrap();
        std::env::set_var(
            "WINCLI_NODEJS_DIST",
            format!("file://{}", dist.display()),
        );
        let err = install_nodejs("9.9.8", &cache).unwrap_err();
        assert!(err.contains("SHA-256 mismatch"), "{err}");
        std::env::remove_var("WINCLI_NODEJS_DIST");
        let _ = std::fs::remove_dir_all(&dist);
        let _ = std::fs::remove_dir_all(&cache);
    }
}
