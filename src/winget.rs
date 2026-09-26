//! WinGet catalog source (P2: remote).
//!
//! No local database: manifests come straight from the winget-pkgs GitHub
//! repo (version dirs via the contents API, YAML via raw). Only portable /
//! zip installers for x64 are accepted; anything else (MSI, MSIX, setup.exe,
//! other arches) fails with a clear, actionable error.
//!
//! A tiny alias table maps short names (`rg`) to full package IDs. Full IDs
//! always work directly.

pub const RAW_BASE: &str = "https://raw.githubusercontent.com/microsoft/winget-pkgs/master";
pub const API_BASE: &str = "https://api.github.com/repos/microsoft/winget-pkgs/contents";

/// Short-name bootstrap aliases (not a package database).
pub fn alias(name: &str) -> Option<&'static str> {
    Some(match name {
        "rg" | "ripgrep" => "BurntSushi.ripgrep.MSVC",
        "fd" => "sharkdp.fd",
        "jq" => "jqlang.jq",
        "bat" => "sharkdp.bat",
        "fzf" => "junegunn.fzf",
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// URL is the exe itself.
    Exe,
    /// URL is a zip; exe lives at `nested` inside.
    Zip { nested: String },
}

#[derive(Debug, Clone)]
pub struct RemotePkg {
    pub id: String,
    pub version: String,
    pub url: String,
    /// Lowercase hex SHA-256 of the download (from the manifest).
    pub sha256: String,
    pub kind: Kind,
    /// Suggested exe file name for the guest address.
    pub exe_name: String,
}

/// Resolve `name` (alias or full ID) to a downloadable portable artifact.
pub fn resolve(name: &str) -> Result<RemotePkg, String> {
    let id = alias(name).unwrap_or(name);
    if !id.contains('.') || id.contains(['/', '\\', ' ']) || id.contains("..") {
        return Err(format!("invalid package id: {name}"));
    }
    let version = latest_version(id)?;
    let doc = fetch_text(&manifest_url(id, &version, "installer"))?;
    let man = parse_installer(&doc)?;
    if man.identifier != id {
        return Err(format!("manifest id mismatch: {}", man.identifier));
    }
    let (item, itype) = select_installer(&man)?;
    let sha256 = item
        .sha
        .clone()
        .ok_or_else(|| format!("{id}: no InstallerSha256, refusing unverified download"))?
        .to_lowercase();
    let kind = if item.url.to_lowercase().ends_with(".zip") {
        let nested = item
            .nested
            .clone()
            .ok_or_else(|| format!("{id}: zip installer without NestedInstallerFiles entry"))?;
        Kind::Zip { nested }
    } else {
        Kind::Exe
    };
    let _ = itype;
    let exe_name = match &kind {
        Kind::Exe => url_basename(&item.url),
        Kind::Zip { nested } => nested
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("app.exe")
            .to_string(),
    };
    Ok(RemotePkg {
        id: id.to_string(),
        version,
        url: item.url,
        sha256,
        kind,
        exe_name,
    })
}

fn manifest_url(id: &str, version: &str, kind: &str) -> String {
    let mut parts: Vec<&str> = id.split('.').collect();
    let publisher = parts.remove(0);
    let first = publisher.chars().next().unwrap_or('x').to_ascii_lowercase();
    let mut p = format!("{RAW_BASE}/manifests/{first}/{publisher}");
    for rest in parts {
        p.push('/');
        p.push_str(rest);
    }
    format!("{p}/{version}/{id}.{kind}.yaml")
}

fn api_dir_url(id: &str) -> String {
    let mut parts: Vec<&str> = id.split('.').collect();
    let publisher = parts.remove(0);
    let first = publisher.chars().next().unwrap_or('x').to_ascii_lowercase();
    let mut p = format!("{API_BASE}/manifests/{first}/{publisher}");
    for rest in parts {
        p.push('/');
        p.push_str(rest);
    }
    p
}

fn latest_version(id: &str) -> Result<String, String> {
    let doc = fetch_text(&api_dir_url(id))?;
    if doc.contains("API rate limit exceeded") {
        return Err("GitHub API rate limit exceeded (60/hr unauthenticated)".to_string());
    }
    let mut vers: Vec<String> = json_names(&doc)
        .into_iter()
        .filter(|n| !n.starts_with('.'))
        .collect();
    if vers.is_empty() {
        return Err(format!("no versions found for {id}"));
    }
    vers.sort_by(|a, b| version_key(a).cmp(&version_key(b)));
    Ok(vers.pop().unwrap())
}

fn version_key(v: &str) -> (Vec<u64>, String) {
    let nums = v
        .split('.')
        .map(|p| {
            p.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
        })
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect();
    (nums, v.to_string())
}

fn url_basename(url: &str) -> String {
    url.split('?')
        .next()
        .unwrap_or(url)
        .rsplit('/')
        .next()
        .unwrap_or("app.exe")
        .to_string()
}

// ---------- minimal YAML (installer manifests only) ----------

#[derive(Debug, Clone, Default)]
struct Installer {
    arch: String,
    url: String,
    sha: Option<String>,
    itype: Option<String>,
    nested: Option<String>,
}

#[derive(Debug, Clone)]
struct Manifest {
    identifier: String,
    top_type: Option<String>,
    installers: Vec<Installer>,
}

fn parse_installer(doc: &str) -> Result<Manifest, String> {
    let mut man = Manifest {
        identifier: String::new(),
        top_type: None,
        installers: Vec::new(),
    };
    let mut cur: Option<Installer> = None;
    for raw_line in doc.lines() {
        let line = raw_line.trim_end();
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("- ") {
            // new installer item (column 0)
            if let Some(prev) = cur.take() {
                man.installers.push(prev);
            }
            let mut it = Installer::default();
            if let Some((k, v)) = split_kv(rest) {
                put_field(Some(&mut it), &mut man, k, v);
            }
            cur = Some(it);
            continue;
        }
        if let Some(stripped) = line.strip_prefix("  ") {
            if stripped.starts_with("- ") {
                // nested list entry (NestedInstallerFiles)
                if let Some((k, v)) = split_kv(&stripped[2..]) {
                    if k.eq_ignore_ascii_case("RelativeFilePath") {
                        if let Some(c) = cur.as_mut() {
                            if c.nested.is_none() {
                                c.nested = Some(unquote(v));
                            }
                        }
                    }
                }
                continue;
            }
            if let Some((k, v)) = split_kv(stripped) {
                match cur.as_mut() {
                    Some(c) => put_field(Some(c), &mut man, k, v),
                    None => put_field(None, &mut man, k, v),
                }
                continue;
            }
        }
        if let Some((k, v)) = split_kv(line) {
            if let Some(prev) = cur.take() {
                man.installers.push(prev);
            }
            put_field(None, &mut man, k, v);
        }
    }
    if let Some(prev) = cur.take() {
        man.installers.push(prev);
    }
    if man.identifier.is_empty() {
        return Err("manifest missing PackageIdentifier".to_string());
    }
    if man.installers.is_empty() {
        return Err("manifest has no installers".to_string());
    }
    Ok(man)
}

fn split_kv(s: &str) -> Option<(String, String)> {
    let i = s.find(':')?;
    let k = s[..i].trim().to_string();
    let v = s[i + 1..].trim().to_string();
    if k.is_empty() || k.contains(' ') {
        return None;
    }
    Some((k, v))
}

fn unquote(s: String) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn put_field(it: Option<&mut Installer>, man: &mut Manifest, k: String, v: String) {
    let v = unquote(v);
    match k.as_str() {
        "PackageIdentifier" => man.identifier = v,
        // Item-level when inside an installer, else manifest top-level.
        "InstallerType" => match it {
            Some(i) => i.itype = Some(v),
            None => man.top_type = Some(v),
        },
        "Architecture" => {
            if let Some(i) = it {
                i.arch = v;
            }
        }
        "InstallerUrl" => {
            if let Some(i) = it {
                i.url = v;
            }
        }
        "InstallerSha256" => {
            if let Some(i) = it {
                i.sha = Some(v);
            }
        }
        _ => {}
    }
}

/// Pick the x64 portable/zip installer. Returns (installer, effective type).
fn select_installer(man: &Manifest) -> Result<(Installer, String), String> {
    let mut best: Option<(u8, Installer, String)> = None;
    for it in &man.installers {
        if !it.arch.eq_ignore_ascii_case("x64") {
            continue;
        }
        let t = it
            .itype
            .clone()
            .or_else(|| man.top_type.clone())
            .unwrap_or_default();
        let score = if t.eq_ignore_ascii_case("portable") {
            0u8
        } else if t.eq_ignore_ascii_case("zip") || it.url.to_lowercase().ends_with(".zip") {
            1u8
        } else {
            continue;
        };
        let take = match &best {
            Some((s, _, _)) => score < *s,
            None => true,
        };
        if take {
            best = Some((score, it.clone(), t));
        }
    }
    best.map(|(_, it, t)| (it, t)).ok_or_else(|| {
        let have: Vec<String> = man
            .installers
            .iter()
            .map(|i| {
                format!(
                    "{}:{}",
                    i.arch,
                    i.itype
                        .clone()
                        .or_else(|| man.top_type.clone())
                        .unwrap_or_default()
                )
            })
            .collect();
        format!(
            "no portable/zip x64 installer (has: {}); MSI/MSIX/setup are not supported",
            have.join(", ")
        )
    })
}

/// All `"name": "…"` values in a GitHub contents-API listing.
fn json_names(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut s = doc;
    while let Some(i) = s.find("\"name\"") {
        let rest = s[i + 6..].trim_start();
        let rest = match rest.strip_prefix(':') {
            Some(r) => r.trim_start(),
            None => {
                s = &s[i + 6..];
                continue;
            }
        };
        if let Some(q) = rest.strip_prefix('"') {
            if let Some(end) = q.find('"') {
                out.push(q[..end].to_string());
                s = &q[end + 1..];
                continue;
            }
        }
        s = &s[i + 6..];
    }
    out
}

fn fetch_text(url: &str) -> Result<String, String> {
    let bytes = crate::install::fetch_url(url, 30)?;
    String::from_utf8(bytes).map_err(|_| format!("non-UTF8 response from {url}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/artifacts/packages/winget-ripgrep.installer.yaml");

    #[test]
    fn parse_real_manifest() {
        let man = parse_installer(FIXTURE).unwrap();
        assert_eq!(man.identifier, "BurntSushi.ripgrep.MSVC");
        assert_eq!(man.top_type.as_deref(), Some("zip"));
        assert_eq!(man.installers.len(), 3);
    }

    #[test]
    fn select_x64_zip_with_nested_path() {
        let man = parse_installer(FIXTURE).unwrap();
        let (it, t) = select_installer(&man).unwrap();
        assert!(it.arch.eq_ignore_ascii_case("x64"));
        assert!(t.eq_ignore_ascii_case("zip") || it.url.ends_with(".zip"));
        assert_eq!(
            it.nested.as_deref(),
            Some("ripgrep-15.2.0-x86_64-pc-windows-msvc/rg.exe")
        );
        assert!(it.url.contains("x86_64-pc-windows-msvc.zip"));
        assert_eq!(it.sha.unwrap().len(), 64);
    }

    #[test]
    fn reject_msi_only() {
        let doc = "PackageIdentifier: X.Y\nInstallerType: msi\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://e/x.msi\n  InstallerSha256: abc\n";
        let man = parse_installer(doc).unwrap();
        let err = select_installer(&man).unwrap_err();
        assert!(err.contains("MSI/MSIX"), "{err}");
    }

    #[test]
    fn version_ordering() {
        let mut v = vec![
            "14.1.1".to_string(),
            "15.2.0".to_string(),
            "14.0.3".to_string(),
        ];
        v.sort_by(|a, b| version_key(a).cmp(&version_key(b)));
        assert_eq!(v.last().unwrap(), "15.2.0");
    }

    #[test]
    fn aliases() {
        assert_eq!(alias("rg"), Some("BurntSushi.ripgrep.MSVC"));
        assert_eq!(alias("BurntSushi.ripgrep.MSVC"), None); // full IDs pass through
    }

    #[test]
    fn manifest_url_shape() {
        assert_eq!(
            manifest_url("BurntSushi.ripgrep.MSVC", "15.2.0", "installer"),
            "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/b/BurntSushi/ripgrep/MSVC/15.2.0/BurntSushi.ripgrep.MSVC.installer.yaml"
        );
    }
}
