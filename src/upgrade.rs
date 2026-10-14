//! `winrun upgrade`: self-update the binary from GitHub Releases.
//!
//! This mirrors `scripts/install.sh` (same repo, same tag scheme, same
//! tarball and checksum verification) but replaces the running binary in
//! place, using only the built-in HTTPS client: no `curl`, `sha256sum`, or
//! `tar` required on the host.
//!
//! Exit-code contract: `0` = up to date / upgraded / check / dry run,
//! `1` = download, verification, or replacement failure, `2` = usage error.

use std::cmp::Ordering;
use std::io::Read;

pub const DEFAULT_REPO: &str = "Open-Tech-Foundation/Win-Runner";
pub const ARCHIVE_NAME: &str = "winrun-win-runner.tar.gz";
pub const CHECKSUMS_NAME: &str = "checksums.txt";
pub const BINARY_NAME: &str = "winrun";
/// Refuse to buffer a release file larger than this (zip-bomb guard).
pub const MAX_DOWNLOAD_BYTES: usize = 256 * 1024 * 1024;
const FETCH_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Explicit tag (`--version` or `WINRUN_VERSION`); otherwise the latest
    /// release is resolved over the network.
    pub version: Option<String>,
    pub check: bool,
    pub dry_run: bool,
}

pub fn usage_text() -> String {
    [
        "usage: winrun upgrade [--version TAG] [--check] [--dry-run]",
        "",
        "  (no flags)       install the latest release over this binary",
        "  --version TAG    install TAG instead (e.g. --version v0.2.0)",
        "  --check          print latest vs current version; change nothing",
        "  --dry-run        print what would be done; change nothing",
        "",
        "Environment: WINRUN_VERSION pins the tag, WINRUN_REPO overrides the",
        "release repo (default: Open-Tech-Foundation/Win-Runner).",
    ]
    .join("\n")
        + "\n"
}

/// Parse `argv` after the `upgrade` word.
pub fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        version: std::env::var("WINRUN_VERSION")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        check: false,
        dry_run: false,
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = arg.strip_prefix("--version=") {
            if value.trim().is_empty() {
                return Err("winrun upgrade: --version requires a tag".to_string());
            }
            options.version = Some(value.to_string());
        } else if arg == "--version" {
            index += 1;
            match args.get(index) {
                Some(tag) if !tag.trim().is_empty() => {
                    options.version = Some(tag.clone());
                }
                _ => return Err("winrun upgrade: --version requires a tag".to_string()),
            }
        } else if arg == "--check" {
            options.check = true;
        } else if arg == "--dry-run" {
            options.dry_run = true;
        } else if arg == "--help" || arg == "-h" {
            print!("{}", usage_text());
            std::process::exit(0);
        } else {
            return Err(format!("winrun upgrade: unknown option: {arg}"));
        }
        index += 1;
    }
    if options.check && options.dry_run {
        return Err("winrun upgrade: --check and --dry-run are mutually exclusive".to_string());
    }
    Ok(options)
}

/// A `v0.2.0` / `0.2.0` tag as comparable numbers.
pub fn parse_version(tag: &str) -> Result<(u64, u64, u64), String> {
    let numbers = tag.strip_prefix('v').or_else(|| tag.strip_prefix('V')).unwrap_or(tag);
    let parts: Vec<&str> = numbers.split('.').collect();
    if !(1..=3).contains(&parts.len()) || parts.iter().any(|part| part.is_empty()) {
        return Err(format!("invalid version tag: {tag}"));
    }
    let mut out = [0u64; 3];
    for (index, part) in parts.iter().enumerate() {
        out[index] = part
            .parse::<u64>()
            .map_err(|_| format!("invalid version tag: {tag}"))?;
    }
    Ok((out[0], out[1], out[2]))
}

pub fn compare_versions(a: (u64, u64, u64), b: (u64, u64, u64)) -> Ordering {
    a.cmp(&b)
}

pub fn normalize_tag(tag: &str) -> String {
    if tag.starts_with('v') || tag.starts_with('V') {
        tag.to_string()
    } else {
        format!("v{tag}")
    }
}

pub fn release_base_url(repo: &str, tag: &str) -> String {
    format!("https://github.com/{repo}/releases/download/{tag}")
}

fn api_latest_url(repo: &str) -> String {
    format!("https://api.github.com/repos/{repo}/releases/latest")
}

/// Extract `tag_name` from a GitHub `releases/latest` response body.
pub fn parse_latest_tag(body: &[u8]) -> Result<String, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("cannot parse latest release: {e}"))?;
    value
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .filter(|tag| !tag.is_empty())
        .ok_or_else(|| "latest release has no tag_name".to_string())
}

pub fn latest_tag(repo: &str) -> Result<String, String> {
    let url = api_latest_url(repo);
    let body = crate::install::fetch_url(&url, FETCH_TIMEOUT_SECS)
        .map_err(|e| format!("cannot determine latest release ({url}): {e}"))?;
    parse_latest_tag(&body)
}

/// Find the expected SHA-256 for `file` in a `sha256sum`-style listing.
/// Accepts `  ` and ` *` separators and tolerates CRLF.
pub fn parse_checksums(text: &str, file: &str) -> Result<String, String> {
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let mut fields = line.split_whitespace();
        let (Some(hash), Some(name)) = (fields.next(), fields.next()) else {
            continue;
        };
        let name = name.strip_prefix('*').unwrap_or(name);
        if name == file
            && hash.len() == 64
            && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Ok(hash.to_ascii_lowercase());
        }
    }
    Err(format!("checksums list has no entry for {file}"))
}

fn parse_octal(field: &[u8]) -> Result<usize, String> {
    let text = std::str::from_utf8(field)
        .map_err(|_| "invalid tar header".to_string())?
        .trim_matches(|c| c == '\0' || c == ' ');
    if text.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(text, 8).map_err(|_| "invalid tar size".to_string())
}

/// Extract the `winrun` entry from a `.tar.gz` release archive.
pub fn extract_binary(tar_gz: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::read::MultiGzDecoder;
    let mut tar = Vec::new();
    MultiGzDecoder::new(tar_gz)
        .read_to_end(&mut tar)
        .map_err(|e| format!("cannot decompress release archive: {e}"))?;
    if tar.len() % 512 != 0 || tar.is_empty() {
        return Err("invalid tar archive".to_string());
    }
    let mut offset = 0;
    while offset + 512 <= tar.len() {
        let header = &tar[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_end = header[..100].iter().position(|byte| *byte == 0).unwrap_or(100);
        let name = std::str::from_utf8(&header[..name_end])
            .map_err(|_| "invalid tar entry name".to_string())?;
        let size = parse_octal(&header[124..136])?;
        let data_start = offset + 512;
        let data_end = data_start
            .checked_add(size)
            .ok_or_else(|| "invalid tar entry size".to_string())?;
        if data_end > tar.len() {
            return Err("truncated tar archive".to_string());
        }
        let base = name.rsplit('/').next().unwrap_or(name);
        if base == BINARY_NAME && size > 0 {
            return Ok(tar[data_start..data_end].to_vec());
        }
        offset = data_end + (512 - data_end % 512) % 512;
    }
    Err(format!("release archive has no {BINARY_NAME} entry"))
}

fn download(repo: &str, tag: &str, file: &str) -> Result<Vec<u8>, String> {
    let url = format!("{}/{file}", release_base_url(repo, tag));
    eprintln!("Downloading {file} ({tag})...");
    let body = crate::install::fetch_url(&url, FETCH_TIMEOUT_SECS)
        .map_err(|e| format!("download failed: {url}: {e}"))?;
    if body.len() > MAX_DOWNLOAD_BYTES {
        return Err(format!(
            "download failed: {url}: file exceeds {} bytes",
            MAX_DOWNLOAD_BYTES
        ));
    }
    Ok(body)
}

/// Run the upgrade; returns the process exit code.
pub fn run(argv: &[String]) -> i32 {
    let options = match parse_args(argv) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
        eprintln!("winrun: upgrade: published releases are Linux x86-64 builds");
        return 1;
    }
    let repo = std::env::var("WINRUN_REPO")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REPO.to_string());
    let explicit = options.version.is_some();
    let tag = match options.version {
        Some(tag) => normalize_tag(&tag),
        None => match latest_tag(&repo) {
            Ok(tag) => tag,
            Err(error) => {
                eprintln!("winrun: upgrade: {error}");
                return 1;
            }
        },
    };
    let target = match parse_version(&tag) {
        Ok(version) => version,
        Err(error) => {
            eprintln!("winrun: upgrade: {error}");
            return 1;
        }
    };
    let current = match parse_version(env!("CARGO_PKG_VERSION")) {
        Ok(version) => version,
        Err(error) => {
            eprintln!("winrun: upgrade: {error}");
            return 1;
        }
    };
    let current_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    match compare_versions(target, current) {
        Ordering::Less | Ordering::Equal if !explicit => {
            println!("winrun is up to date ({current_tag})");
            return 0;
        }
        _ => {}
    }
    if options.check {
        if compare_versions(target, current) == Ordering::Greater {
            println!("update available: {current_tag} -> {tag}");
        } else {
            println!("winrun is up to date ({current_tag})");
        }
        return 0;
    }
    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("winrun: upgrade: cannot locate this binary: {error}");
            return 1;
        }
    };
    if options.dry_run {
        println!("would download {}/{ARCHIVE_NAME}", release_base_url(&repo, &tag));
        println!("would download {}/{CHECKSUMS_NAME}", release_base_url(&repo, &tag));
        println!("would verify sha256 and extract {BINARY_NAME}");
        println!("would install {}", current_exe.display());
        return 0;
    }
    let archive = match download(&repo, &tag, ARCHIVE_NAME) {
        Ok(archive) => archive,
        Err(error) => {
            eprintln!("winrun: upgrade: {error}");
            return 1;
        }
    };
    let checksums = match download(&repo, &tag, CHECKSUMS_NAME) {
        Ok(checksums) => checksums,
        Err(error) => {
            eprintln!("winrun: upgrade: {error}");
            return 1;
        }
    };
    let checksums_text = match std::str::from_utf8(&checksums) {
        Ok(text) => text,
        Err(_) => {
            eprintln!("winrun: upgrade: checksums list is not valid UTF-8");
            return 1;
        }
    };
    let expected = match parse_checksums(checksums_text, ARCHIVE_NAME) {
        Ok(expected) => expected,
        Err(error) => {
            eprintln!("winrun: upgrade: {error}");
            return 1;
        }
    };
    eprintln!("Verifying checksum...");
    let actual = crate::install::sha256_hex(&archive);
    if !actual.eq_ignore_ascii_case(&expected) {
        eprintln!("winrun: upgrade: checksum mismatch for {ARCHIVE_NAME}");
        return 1;
    }
    let binary = match extract_binary(&archive) {
        Ok(binary) => binary,
        Err(error) => {
            eprintln!("winrun: upgrade: {error}");
            return 1;
        }
    };
    let parent = match current_exe.parent() {
        Some(parent) => parent.to_path_buf(),
        None => {
            eprintln!("winrun: upgrade: cannot locate this binary's directory");
            return 1;
        }
    };
    let staging = parent.join(format!(".{}-{}.new", BINARY_NAME, std::process::id()));
    if let Err(error) = std::fs::write(&staging, &binary) {
        eprintln!(
            "winrun: upgrade: cannot write {}: {error} (rerun with sudo, or use scripts/install.sh --prefix)",
            staging.display()
        );
        return 1;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) =
            std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))
        {
            let _ = std::fs::remove_file(&staging);
            eprintln!("winrun: upgrade: cannot set permissions: {error}");
            return 1;
        }
    }
    // Smoke-check the new binary before it replaces this one.
    match std::process::Command::new(&staging).arg("--version").output() {
        Ok(output) if output.status.success() => {
            let want = tag.trim_start_matches(['v', 'V']);
            if !String::from_utf8_lossy(&output.stdout).contains(want) {
                let _ = std::fs::remove_file(&staging);
                eprintln!("winrun: upgrade: downloaded binary reports an unexpected version");
                return 1;
            }
        }
        _ => {
            let _ = std::fs::remove_file(&staging);
            eprintln!("winrun: upgrade: downloaded binary failed its smoke check");
            return 1;
        }
    }
    if let Err(error) = std::fs::rename(&staging, &current_exe) {
        let _ = std::fs::remove_file(&staging);
        eprintln!(
            "winrun: upgrade: cannot replace {}: {error} (rerun with sudo, or use scripts/install.sh --prefix)",
            current_exe.display()
        );
        return 1;
    }
    println!("Upgraded winrun {current_tag} -> {tag} at {}", current_exe.display());
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_prefixed_versions() {
        assert_eq!(parse_version("v0.2.0").unwrap(), (0, 2, 0));
        assert_eq!(parse_version("0.2.0").unwrap(), (0, 2, 0));
        assert_eq!(parse_version("v10.20.30").unwrap(), (10, 20, 30));
        assert_eq!(parse_version("1").unwrap(), (1, 0, 0));
        assert_eq!(parse_version("1.2").unwrap(), (1, 2, 0));
    }

    #[test]
    fn rejects_malformed_versions() {
        for tag in ["", "v", "v1.2.3.4", "v1.x", "v1..2", "latest", "v1.2-rc1"] {
            assert!(parse_version(tag).is_err(), "tag: {tag}");
        }
    }

    #[test]
    fn orders_versions_numerically() {
        assert_eq!(compare_versions((0, 2, 0), (0, 2, 0)), Ordering::Equal);
        assert_eq!(compare_versions((0, 1, 9), (0, 2, 0)), Ordering::Less);
        assert_eq!(compare_versions((0, 10, 0), (0, 9, 9)), Ordering::Greater);
    }

    #[test]
    fn normalizes_tags_with_leading_v() {
        assert_eq!(normalize_tag("0.2.0"), "v0.2.0");
        assert_eq!(normalize_tag("v0.2.0"), "v0.2.0");
    }

    #[test]
    fn builds_release_urls() {
        assert_eq!(
            release_base_url("o/r", "v0.2.0"),
            "https://github.com/o/r/releases/download/v0.2.0"
        );
    }

    #[test]
    fn parses_latest_tag_from_api_body() {
        let body = br#"{"tag_name":"v0.2.0","name":"0.2.0"}"#;
        assert_eq!(parse_latest_tag(body).unwrap(), "v0.2.0");
        assert!(parse_latest_tag(br#"{"name":"no tag"}"#).is_err());
        assert!(parse_latest_tag(b"not json").is_err());
    }

    #[test]
    fn parses_sha256sum_listings() {
        // Short hashes never resolve.
        let short = format!("abc123  {}\n", ARCHIVE_NAME);
        assert!(parse_checksums(&short, ARCHIVE_NAME).is_err());
        let text = format!(
            "{}  {}\n{} *{}\r\n",
            "a".repeat(64),
            ARCHIVE_NAME,
            "b".repeat(64),
            CHECKSUMS_NAME
        );
        assert_eq!(parse_checksums(&text, ARCHIVE_NAME).unwrap(), "a".repeat(64));
        assert_eq!(parse_checksums(&text, CHECKSUMS_NAME).unwrap(), "b".repeat(64));
        assert!(parse_checksums(&text, "missing.tar.gz").is_err());
    }

    fn tar_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{size:06o}\0 ", size = data.len());
        header[124..124 + size.len()].copy_from_slice(size.as_bytes());
        header[156..157].copy_from_slice(b"0");
        let mut out = header;
        out.extend_from_slice(data);
        out.resize(out.len() + (512 - data.len() % 512) % 512, 0);
        out
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn extracts_binary_from_tar_gz() {
        let mut tar = tar_entry("README.md", b"docs");
        tar.extend_from_slice(&tar_entry(BINARY_NAME, b"\x7fELFrelease"));
        tar.extend_from_slice(&[0u8; 512]);
        assert_eq!(extract_binary(&gzip(&tar)).unwrap(), b"\x7fELFrelease");
    }

    #[test]
    fn rejects_archives_without_the_binary() {
        let mut tar = tar_entry("other.txt", b"x");
        tar.extend_from_slice(&[0u8; 512]);
        assert!(extract_binary(&gzip(&tar)).is_err());
        assert!(extract_binary(b"not gzip").is_err());
        assert!(extract_binary(&gzip(b"short")).is_err());
    }

    #[test]
    fn parses_upgrade_args() {
        let args: Vec<String> = vec![];
        let options = parse_args(&args).unwrap();
        assert_eq!(options.version, std::env::var("WINRUN_VERSION").ok().filter(|v| !v.trim().is_empty()));
        assert!(!options.check && !options.dry_run);
        let args = ["--version=v0.3.0".to_string(), "--dry-run".to_string()];
        let options = parse_args(&args).unwrap();
        assert_eq!(options.version.as_deref(), Some("v0.3.0"));
        assert!(options.dry_run);
        let args = ["--version".to_string(), "v0.3.0".to_string()];
        assert_eq!(parse_args(&args).unwrap().version.as_deref(), Some("v0.3.0"));
        let args = ["--version".to_string()];
        assert!(parse_args(&args).is_err());
        let args = ["--bogus".to_string()];
        assert!(parse_args(&args).is_err());
        let args = ["--check".to_string(), "--dry-run".to_string()];
        assert!(parse_args(&args).is_err());
        let args = ["--version=".to_string()];
        assert!(parse_args(&args).is_err());
    }
}
