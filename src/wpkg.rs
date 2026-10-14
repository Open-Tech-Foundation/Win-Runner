//! Small manifest-driven installer for portable Windows ZIP, 7z, and
//! tarball (npm `.tgz`) packages.
//!
//! Package state and extracted files live only in the guest WinFS. A
//! registry provides `packages/index` and, per package, `.wpkg` files whose
//! contents decide how it installs: a pinned package lists exact versions
//! (`<version>.wpkg` with a URL and hash, plus `latest` and `versions`); an
//! upstream package has one `upstream.wpkg` naming where it is published,
//! and each install resolves the release there (see [`upstream`]). The
//! package archive is fetched separately and never executed.
//!
//! The registry is fetched once into `C:\ProgramData\wpkg\registry.zip`
//! from the project's repository and replaced only by `wpkg refresh`; the
//! copy built into winrun serves when it cannot be fetched.
//!
//! Versions install side by side as `C:\Program Files\<name>\<version>`.
//! The directory link `C:\Program Files\<name>\current` selects the default
//! version, and `C:\ProgramData\wpkg\bin` (on the system `PATH`) links each
//! command through it, so switching the default rewrites one link and never
//! leaves a command pointing at removed files.

use crate::{install, install::DownloadProgress, progress, winfs::WinFs};
#[path = "wpkg_upstream.rs"]
pub mod upstream;
use upstream::Recipe;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read},
    path::Path,
};

const STATE: &str = r"C:\ProgramData\wpkg";
const DATABASE: &str = r"C:\ProgramData\wpkg\installed.json";
const ROOT: &str = crate::system_profile::PROGRAM_FILES;
/// Verified archives, kept so reinstalling a version needs no download.
const CACHE: &str = r"C:\ProgramData\wpkg\cache";
/// Command links for every package's default version; on the system `PATH`.
pub const BIN: &str = r"C:\ProgramData\wpkg\bin";
const CURRENT: &str = "current";
/// Where Windows lists installed programs; wpkg adds one key per version.
const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const MAX_7Z_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_7Z_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

struct PackageEntry {
    name: String,
    is_dir: bool,
    bytes: Vec<u8>,
}

pub trait Repository {
    fn fetch(&self, path_or_url: &str) -> Result<Vec<u8>, String>;

    fn fetch_with_progress(
        &self,
        path_or_url: &str,
        progress: &mut dyn FnMut(DownloadProgress),
    ) -> Result<Vec<u8>, String> {
        let bytes = self.fetch(path_or_url)?;
        progress(DownloadProgress {
            received: bytes.len() as u64,
            total: Some(bytes.len() as u64),
        });
        Ok(bytes)
    }
}

/// A registry ZIP: the copy built into winrun, or the one fetched into
/// [`LOCAL_REGISTRY`]. Package archives referenced by manifests are still
/// fetched on demand.
pub struct EmbeddedRepository {
    files: HashMap<String, Vec<u8>>,
}

/// Where the published registry is fetched from.
pub const REGISTRY_URL: &str = "https://raw.githubusercontent.com/Open-Tech-Foundation/Win-CLI/main/registry.zip";
/// The guest's copy of the registry, replaced only by `wpkg refresh`.
pub const LOCAL_REGISTRY: &str = r"C:\ProgramData\wpkg\registry.zip";

/// Put `wpkg.exe` in System32 (unless the disk already has one), so
/// scripts and programs can run wpkg as the shell does.
pub fn seed_wpkg_exe(fs: &mut WinFs) {
    let path = format!(r"{}\wpkg.exe", crate::system_profile::SYSTEM32);
    if fs.is_file(&path) || fs.mkdir(crate::system_profile::SYSTEM32).is_err() {
        return;
    }
    let _ = fs.write_file(&path, crate::cmd::stub_image("WinrunWpkgMain"));
}

/// The registry URL: `WINRUN_WPKG_REGISTRY` may name another one, or
/// `embedded` to use only the copy built into winrun.
fn registry_url() -> Option<String> {
    match std::env::var("WINRUN_WPKG_REGISTRY") {
        Ok(value) if value.eq_ignore_ascii_case("embedded") => None,
        Ok(value) if !value.is_empty() => Some(value),
        _ => Some(REGISTRY_URL.to_string()),
    }
}

/// The registry wpkg works from: the guest's copy, fetched on first use
/// (the built-in copy when that fails, with a note through `progress`).
pub fn open_registry(fs: &mut WinFs, progress: &mut dyn FnMut(&str)) -> Result<EmbeddedRepository, String> {
    if fs.is_file(LOCAL_REGISTRY) {
        let bytes = fs.read_file(LOCAL_REGISTRY).map_err(|error| format!("wpkg: cannot read {LOCAL_REGISTRY}: {error}"))?;
        return EmbeddedRepository::from_zip(&bytes)
            .map_err(|error| format!("{error}; run `wpkg refresh` to fetch it again"));
    }
    let Some(url) = registry_url() else {
        return EmbeddedRepository::new();
    };
    match fetch_registry(&url) {
        Ok((bytes, repository)) => {
            fs.mkdir(STATE)
                .and_then(|_| fs.write_file(LOCAL_REGISTRY, bytes))
                .map_err(|error| format!("wpkg: cannot keep the registry: {error}"))?;
            Ok(repository)
        }
        Err(error) => {
            progress(&format!("⚠️ Using the built-in package list ({error}); run `wpkg refresh` later\n"));
            EmbeddedRepository::new()
        }
    }
}

/// Download and validate a registry ZIP.
fn fetch_registry(url: &str) -> Result<(Vec<u8>, EmbeddedRepository), String> {
    let bytes = install::fetch_url(url, 300).map_err(|error| format!("cannot fetch the registry: {error}"))?;
    let repository = EmbeddedRepository::from_zip(&bytes)?;
    repository_names(&repository)?;
    Ok((bytes, repository))
}

/// `wpkg refresh`: replace the guest's registry with the published one,
/// reporting what changed.
fn refresh_registry(fs: &mut WinFs, current: &dyn Repository) -> Result<String, String> {
    let url = registry_url().ok_or("wpkg: refresh is off (WINRUN_WPKG_REGISTRY=embedded)")?;
    let bytes = current.fetch(&url)?;
    let fresh = EmbeddedRepository::from_zip(&bytes)?;
    let summary = |repository: &dyn Repository| -> Result<HashMap<String, String>, String> {
        let mut map = HashMap::new();
        for name in repository_names(repository)? {
            let label = if repository.fetch(&format!("packages/{name}/upstream.wpkg")).is_ok() {
                "upstream".to_string()
            } else {
                registry_versions(repository, &name)?.join(", ")
            };
            map.insert(name, label);
        }
        Ok(map)
    };
    let (before, after) = (summary(current).unwrap_or_default(), summary(&fresh)?);
    fs.mkdir(STATE)
        .and_then(|_| fs.write_file(LOCAL_REGISTRY, bytes))
        .map_err(|error| format!("wpkg: cannot keep the registry: {error}"))?;
    let mut names: Vec<&String> = before.keys().chain(after.keys()).collect();
    names.sort();
    names.dedup();
    let mut changes = String::new();
    for name in names {
        match (before.get(name), after.get(name)) {
            (None, Some(now)) => changes.push_str(&format!("  + {name} ({now})\n")),
            (Some(_), None) => changes.push_str(&format!("  - {name}\n")),
            (Some(was), Some(now)) if was != now => changes.push_str(&format!("  ~ {name}: {was} -> {now}\n")),
            _ => {}
        }
    }
    Ok(if changes.is_empty() {
        "✅ Package list is up to date\n".to_string()
    } else {
        format!("✅ Package list refreshed:\n{changes}")
    })
}

impl EmbeddedRepository {
    pub fn new() -> Result<Self, String> {
        Self::from_zip(include_bytes!("../registry.zip"))
    }

    pub fn from_zip(archive: &[u8]) -> Result<Self, String> {
        let mut files = HashMap::new();
        for entry in install::zip_entries(archive)? {
            if entry.is_dir {
                continue;
            }
            let name = safe_member(&entry.name)?;
            let key = name.to_ascii_lowercase();
            if files.contains_key(&key) {
                return Err(format!("wpkg: duplicate embedded registry path: {name}"));
            }
            files.insert(key, install::extract_bytes(archive, &entry)?);
        }
        Ok(Self { files })
    }
}

impl Repository for EmbeddedRepository {
    fn fetch(&self, path_or_url: &str) -> Result<Vec<u8>, String> {
        if path_or_url.starts_with("https://") || path_or_url.starts_with("http://") {
            return install::fetch_url(path_or_url, 300).map_err(|error| format!("wpkg: {error}"));
        }
        self.files
            .get(&path_or_url.replace('\\', "/").to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| format!("wpkg: registry entry not found: {path_or_url}"))
    }

    fn fetch_with_progress(
        &self,
        path_or_url: &str,
        progress: &mut dyn FnMut(DownloadProgress),
    ) -> Result<Vec<u8>, String> {
        if path_or_url.starts_with("https://") || path_or_url.starts_with("http://") {
            return install::fetch_url_with_progress(path_or_url, 300, progress)
                .map_err(|error| format!("wpkg: {error}"));
        }
        self.fetch(path_or_url).inspect(|bytes| {
            progress(DownloadProgress {
                received: bytes.len() as u64,
                total: Some(bytes.len() as u64),
            })
        })
    }
}

pub struct HttpRepository {
    base: String,
}

impl HttpRepository {
    pub fn new(base: &str) -> Result<Self, String> {
        let base = base.trim().trim_end_matches('/');
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err("wpkg: repository URL must use HTTP or HTTPS".to_string());
        }
        Ok(Self {
            base: base.to_string(),
        })
    }
}

impl Repository for HttpRepository {
    fn fetch(&self, path_or_url: &str) -> Result<Vec<u8>, String> {
        let url = if path_or_url.starts_with("https://") || path_or_url.starts_with("http://") {
            path_or_url.to_string()
        } else {
            format!("{}/{}", self.base, path_or_url.trim_start_matches('/'))
        };
        install::fetch_url(&url, 300).map_err(|error| format!("wpkg: {error}"))
    }

    fn fetch_with_progress(
        &self,
        path_or_url: &str,
        progress: &mut dyn FnMut(DownloadProgress),
    ) -> Result<Vec<u8>, String> {
        let url = if path_or_url.starts_with("https://") || path_or_url.starts_with("http://") {
            path_or_url.to_string()
        } else {
            format!("{}/{}", self.base, path_or_url.trim_start_matches('/'))
        };
        install::fetch_url_with_progress(&url, 300, progress)
            .map_err(|error| format!("wpkg: {error}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub url: String,
    pub checksum: Checksum,
    pub bin: Vec<String>,
    /// A program that runs each command's file (`dotnet`, `node`): the
    /// command becomes a shim that runs `<run> <file> %*`.
    pub run: Option<String>,
    /// `NAME=VALUE` set for the package's commands (`{dir}` is the
    /// package's directory).
    pub env: Vec<String>,
    /// `name` or `name@version` (a version line like `10` matches its
    /// newest pinned `10.x`).
    pub dependencies: Vec<String>,
    pub description: Option<String>,
    /// Resolved from where the package is published rather than pinned.
    pub upstream: bool,
}

/// An archive's expected hash: a pinned manifest's SHA-256, or the
/// SHA-512 npm and NuGet publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    pub algorithm: &'static str,
    pub hex: String,
}

impl Checksum {
    fn new(algorithm: &'static str, hex: &str, digits: usize) -> Result<Self, String> {
        let hex = hex.to_ascii_lowercase();
        if hex.len() != digits || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("wpkg: {algorithm} must contain exactly {digits} hexadecimal digits"));
        }
        Ok(Self { algorithm, hex })
    }

    pub fn sha256(hex: &str) -> Result<Self, String> {
        Self::new("sha256", hex, 64)
    }

    pub fn sha512(hex: &str) -> Result<Self, String> {
        Self::new("sha512", hex, 128)
    }

    fn of(&self, bytes: &[u8]) -> String {
        if self.algorithm == "sha256" {
            install::sha256_hex(bytes)
        } else {
            ring::digest::digest(&ring::digest::SHA512, bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect()
        }
    }

    fn matches(&self, bytes: &[u8]) -> bool {
        self.of(bytes) == self.hex
    }

    /// The host cache's file name (SHA-256 hashes keep their old names).
    fn cache_key(&self) -> String {
        if self.algorithm == "sha256" { self.hex.clone() } else { format!("sha512-{}", self.hex) }
    }
}

/// One extracted version under `C:\Program Files\<name>\<version>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledVersion {
    pub version: String,
    pub arch: String,
    pub install_path: String,
    pub bin: Vec<String>,
    pub run: Option<String>,
    pub env: Vec<String>,
    pub dependencies: Vec<String>,
}

/// A package with side-by-side versions. `default` is the version that
/// `C:\Program Files\<name>\current` points at, and so the one [`BIN`] runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub default: String,
    pub versions: Vec<InstalledVersion>,
}

impl InstalledPackage {
    fn version(&self, version: &str) -> Option<&InstalledVersion> {
        self.versions.iter().find(|entry| entry.version == version)
    }

    fn newest(&self) -> Option<&InstalledVersion> {
        self.versions
            .iter()
            .max_by(|left, right| compare_versions(&left.version, &right.version))
    }

    /// Installed versions equal to `spec`, or else every `spec.x` match.
    fn matching(&self, spec: &str) -> Vec<&InstalledVersion> {
        if let Some(exact) = self.version(spec) {
            return vec![exact];
        }
        let mut matches: Vec<_> = self
            .versions
            .iter()
            .filter(|entry| version_matches(&entry.version, spec))
            .collect();
        matches.sort_by(|left, right| compare_versions(&right.version, &left.version));
        matches
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Search(String),
    Info(String),
    Install(String),
    List(Option<String>),
    Upgrade(Option<String>),
    Remove(String),
    Default(String, Option<String>),
    CacheList,
    CacheClean(Option<String>),
    Refresh,
}

const USAGE: &str = "usage: wpkg search <query> | info <package[@version]> | install <package[@version]> | list [package] | default <package> [version] | upgrade [package] | remove <package[@version]> | cache [clean [package]] | refresh";

fn parse_command(args: &[String]) -> Result<Command, String> {
    match args.first().map(|arg| arg.to_ascii_lowercase()).as_deref() {
        Some("search") if args.len() == 2 => Ok(Command::Search(args[1].clone())),
        Some("info") if args.len() == 2 => Ok(Command::Info(args[1].clone())),
        Some("install") if args.len() == 2 => Ok(Command::Install(args[1].clone())),
        Some("list") if args.len() <= 2 => Ok(Command::List(args.get(1).cloned())),
        Some("upgrade") if args.len() <= 2 => Ok(Command::Upgrade(args.get(1).cloned())),
        Some("remove") if args.len() == 2 => Ok(Command::Remove(args[1].clone())),
        Some("default") if matches!(args.len(), 2 | 3) => {
            Ok(Command::Default(args[1].clone(), args.get(2).cloned()))
        }
        Some("cache") if args.len() == 1 => Ok(Command::CacheList),
        Some("refresh") if args.len() == 1 => Ok(Command::Refresh),
        Some("cache") if args[1].eq_ignore_ascii_case("clean") && args.len() <= 3 => {
            Ok(Command::CacheClean(args.get(2).cloned()))
        }
        _ => Err(USAGE.to_string()),
    }
}

pub fn execute(
    fs: &mut WinFs,
    repository: &dyn Repository,
    architecture: &str,
    args: &[String],
) -> Result<Vec<u8>, String> {
    execute_with_progress(fs, repository, architecture, args, &mut |_| {})
}

pub fn execute_with_progress(
    fs: &mut WinFs,
    repository: &dyn Repository,
    architecture: &str,
    args: &[String],
    progress: &mut dyn FnMut(&str),
) -> Result<Vec<u8>, String> {
    let command = parse_command(args)?;
    let architecture = normalize_arch(architecture)?;
    let mut output = Vec::new();
    match command {
        Command::Search(query) => {
            let query = query.to_ascii_lowercase();
            let names = repository_names(repository)?;
            let matches: Vec<_> = names
                .into_iter()
                .filter(|name| name.to_ascii_lowercase().contains(&query))
                .collect();
            if matches.is_empty() {
                output.extend_from_slice(b"No matching packages.\n");
            } else {
                for name in matches {
                    let line = match package_description(repository, &name) {
                        Some(description) => format!("{name} - {description}\n"),
                        None => format!("{name}\n"),
                    };
                    output.extend_from_slice(line.as_bytes());
                }
            }
        }
        Command::Info(spec) => {
            let (name, version) = split_package_spec(&spec)?;
            let manifest = resolve_version(repository, &name, version.as_deref(), &architecture)?;
            output.extend_from_slice(
                format!(
                    "{} {} ({}){}\n{}Archive: {}\nBinaries: {}\nDependencies: {}\n",
                    manifest.name,
                    manifest.version,
                    manifest.arch,
                    if manifest.upstream { ", newest upstream release" } else { "" },
                    manifest.description.as_deref().map(|text| format!("{text}\n")).unwrap_or_default(),
                    manifest.url,
                    manifest.bin.join(", "),
                    if manifest.dependencies.is_empty() {
                        "none".to_string()
                    } else {
                        manifest.dependencies.join(", ")
                    }
                )
                .as_bytes(),
            );
            let versions = registry_versions(repository, &name)?;
            if versions.len() > 1 {
                output
                    .extend_from_slice(format!("Available: {}\n", versions.join(", ")).as_bytes());
            }
        }
        Command::Install(spec) => {
            let (name, version) = split_package_spec(&spec)?;
            let mut visiting = HashSet::new();
            let kept_default = install_recursive(
                fs,
                repository,
                &architecture,
                &name,
                version.as_deref(),
                &mut visiting,
                &mut output,
                progress,
            )?;
            if let Some((default, installed)) = kept_default {
                output.extend_from_slice(
                    format!(
                        "   Default {name} is still {default}; run `wpkg default {name} {installed}` to switch\n"
                    )
                    .as_bytes(),
                );
            }
        }
        Command::List(filter) => {
            let filter = filter.map(|name| normalize_name(&name)).transpose()?;
            let mut installed = load_database(fs)?;
            installed.retain(|package| filter.as_ref().is_none_or(|name| &package.name == name));
            installed.sort_by(|left, right| left.name.cmp(&right.name));
            if installed.is_empty() {
                match filter {
                    Some(name) => {
                        output.extend_from_slice(format!("{name} is not installed.\n").as_bytes())
                    }
                    None => output.extend_from_slice(b"No packages installed.\n"),
                }
            }
            for mut package in installed {
                package
                    .versions
                    .sort_by(|left, right| compare_versions(&left.version, &right.version));
                for entry in &package.versions {
                    let marker = if entry.version == package.default {
                        '*'
                    } else {
                        ' '
                    };
                    output.extend_from_slice(
                        format!(
                            "{marker} {} {} ({}) {}\n",
                            package.name, entry.version, entry.arch, entry.install_path
                        )
                        .as_bytes(),
                    );
                }
            }
        }
        Command::Default(name, version) => {
            let name = normalize_name(&name)?;
            let mut packages = load_database(fs)?;
            let package = packages
                .iter()
                .find(|package| package.name == name)
                .ok_or_else(|| format!("wpkg: package is not installed: {name}"))?;
            match version {
                None => output.extend_from_slice(
                    format!("{} {}\n", package.name, package.default).as_bytes(),
                ),
                Some(spec) => {
                    let spec = normalize_version(&spec)?;
                    let version = package
                        .matching(&spec)
                        .first()
                        .map(|entry| entry.version.clone())
                        .ok_or_else(|| {
                            format!(
                                "wpkg: {name} {spec} is not installed; run `wpkg install {name}@{spec}` first"
                            )
                        })?;
                    set_default(fs, &mut packages, &name, &version)?;
                    save_database(fs, &packages)?;
                    output.extend_from_slice(
                        format!("✅ {name} default is now {version}\n").as_bytes(),
                    );
                }
            }
        }
        Command::Upgrade(name) => {
            let names = if let Some(name) = name {
                vec![normalize_name(&name)?]
            } else {
                load_database(fs)?
                    .into_iter()
                    .map(|package| package.name)
                    .collect()
            };
            for name in names {
                upgrade_package(fs, repository, &architecture, &name, &mut output, progress)?;
            }
        }
        Command::Remove(spec) => {
            let (name, version) = split_package_spec(&spec)?;
            // Other packages' commands may need this one.
            let dependents: Vec<String> = load_database(fs)?
                .into_iter()
                .filter(|package| package.name != name)
                .filter(|package| {
                    package.versions.iter().any(|entry| {
                        entry.dependencies.iter().any(|dependency| dependency.split('@').next() == Some(name.as_str()))
                    })
                })
                .map(|package| package.name)
                .collect();
            let removed = remove_package(fs, &name, version.as_deref())?;
            output.extend_from_slice(format!("Removed {removed}\n").as_bytes());
            if !dependents.is_empty() {
                output.extend_from_slice(
                    format!("⚠️ {} depend on {name}\n", dependents.join(", ")).as_bytes(),
                );
            }
        }
        Command::Refresh => {
            output.extend_from_slice(refresh_registry(fs, repository)?.as_bytes());
        }
        Command::CacheList => {
            let archives = cached_archives(fs, None)?;
            if archives.is_empty() {
                output.extend_from_slice(b"Cache is empty.\n");
            }
            let mut total = 0;
            for archive in &archives {
                total += archive.bytes;
                output.extend_from_slice(
                    format!(
                        "{} {} ({}) {}\n",
                        archive.name,
                        archive.version,
                        archive.arch,
                        format_size(archive.bytes)
                    )
                    .as_bytes(),
                );
            }
            if !archives.is_empty() {
                output.extend_from_slice(
                    format!(
                        "Total: {} in {} {} at {CACHE}\n",
                        format_size(total),
                        archives.len(),
                        if archives.len() == 1 {
                            "archive"
                        } else {
                            "archives"
                        }
                    )
                    .as_bytes(),
                );
            }
        }
        Command::CacheClean(package) => {
            let package = package.map(|name| normalize_name(&name)).transpose()?;
            let archives = cached_archives(fs, package.as_deref())?;
            let mut total = 0;
            for archive in &archives {
                fs.remove(&archive.path, false)
                    .map_err(|error| format!("wpkg: cannot remove {}: {error}", archive.path))?;
                total += archive.bytes;
            }
            output.extend_from_slice(
                format!(
                    "Removed {} cached {} ({})\n",
                    archives.len(),
                    if archives.len() == 1 {
                        "archive"
                    } else {
                        "archives"
                    },
                    format_size(total)
                )
                .as_bytes(),
            );
        }
    }
    Ok(output)
}

/// Install the registry's latest version beside the installed ones. The
/// default follows only when it was the newest installed version, so a
/// deliberately pinned older default stays put.
fn upgrade_package(
    fs: &mut WinFs,
    repository: &dyn Repository,
    arch: &str,
    name: &str,
    output: &mut Vec<u8>,
    progress: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let installed = load_database(fs)?
        .into_iter()
        .find(|package| package.name == name)
        .ok_or_else(|| format!("wpkg: package is not installed: {name}"))?;
    let latest = resolve_version(repository, name, None, arch)?.version;
    if installed
        .version(&latest)
        .is_some_and(|entry| entry.arch == arch)
    {
        output.extend_from_slice(format!("✅ {name} {latest} is up to date\n").as_bytes());
        return Ok(());
    }
    let follow_default = installed
        .newest()
        .is_some_and(|newest| newest.version == installed.default);
    let mut visiting = HashSet::new();
    install_recursive(
        fs,
        repository,
        arch,
        name,
        Some(&latest),
        &mut visiting,
        output,
        progress,
    )?;
    if follow_default {
        let mut packages = load_database(fs)?;
        set_default(fs, &mut packages, name, &latest)?;
        save_database(fs, &packages)?;
        output.extend_from_slice(format!("✅ {name} default is now {latest}\n").as_bytes());
    }
    Ok(())
}

/// Returns `(default, installed)` when a new version went in beside an
/// existing default that was left unchanged.
#[allow(clippy::too_many_arguments)]
fn install_recursive(
    fs: &mut WinFs,
    repository: &dyn Repository,
    arch: &str,
    name: &str,
    requested_version: Option<&str>,
    visiting: &mut HashSet<String>,
    output: &mut Vec<u8>,
    progress: &mut dyn FnMut(&str),
) -> Result<Option<(String, String)>, String> {
    let name = normalize_name(name)?;
    if !visiting.insert(name.clone()) {
        return Err(format!("wpkg: dependency cycle at {name}"));
    }
    let manifest = resolve_version(repository, &name, requested_version, arch)?;

    // A dependency names a package, or a version (line) of it: an
    // installed match satisfies it, else the match installs beside the
    // installed versions. Installing a dependent never moves another
    // package's default.
    for dependency in &manifest.dependencies {
        let (dependency, spec) = split_package_spec(dependency)?;
        let satisfied = load_database(fs)?.iter().any(|package| {
            package.name == dependency && spec.as_deref().is_none_or(|spec| !package.matching(spec).is_empty())
        });
        if satisfied {
            continue;
        }
        install_recursive(
            fs,
            repository,
            arch,
            &dependency,
            spec.as_deref(),
            visiting,
            output,
            progress,
        )
        .map_err(|error| format!("{error} (needed by {name})"))?;
    }

    let installed = load_database(fs)?;
    let package = installed.iter().find(|package| package.name == name);
    if package
        .and_then(|package| package.version(&manifest.version))
        .is_some_and(|entry| entry.arch == arch)
    {
        output.extend_from_slice(
            format!(
                "✅ {} {} ({}) is already installed\n",
                manifest.name, manifest.version, manifest.arch
            )
            .as_bytes(),
        );
        visiting.remove(&name);
        return Ok(None);
    }

    let kept_default = install_version(fs, repository, &manifest, progress)?;
    output.extend_from_slice(
        format!(
            "✅ Installed {} {} ({})\n",
            manifest.name, manifest.version, manifest.arch
        )
        .as_bytes(),
    );
    visiting.remove(&name);
    Ok(kept_default.map(|default| (default, manifest.version)))
}

/// Download and verify a package archive, showing a progress bar.
fn download_archive(
    repository: &dyn Repository,
    manifest: &Manifest,
    progress: &mut dyn FnMut(&str),
) -> Result<Vec<u8>, String> {
    progress(&format!(
        "⬇️ Downloading {} {}\n",
        manifest.name, manifest.version
    ));
    let started = std::time::Instant::now();
    let mut finished = false;
    let archive = repository.fetch_with_progress(&manifest.url, &mut |status| {
        if finished {
            return;
        }
        let seconds = started.elapsed().as_secs_f64();
        let rate = (seconds > 0.25).then(|| status.received as f64 / seconds);
        finished = status.total == Some(status.received);
        let bar = progress::download_bar(status.received, status.total, rate);
        // A transient line until the download ends; the full bar stays.
        progress(&format!("{bar}{}", if finished { "\n" } else { "\r" }));
    })?;
    progress(&format!(
        "🔎 Verifying {} {}...\n",
        manifest.name, manifest.version
    ));
    let actual = manifest.checksum.of(&archive);
    if actual != manifest.checksum.hex {
        return Err(format!(
            "wpkg: {} mismatch for {} {} (expected {}, got {actual})",
            if manifest.checksum.algorithm == "sha256" { "SHA-256" } else { "SHA-512" },
            manifest.name,
            manifest.version,
            manifest.checksum.hex
        ));
    }
    Ok(archive)
}

/// Verified archives shared by every session on this machine, named by
/// SHA-256, so a new disk installs a package without downloading it again.
/// `WINRUN_CACHE_DIR` moves it; the default follows the XDG cache directory.
fn host_cache_dir() -> Option<std::path::PathBuf> {
    #[cfg(test)]
    {
        TEST_HOST_CACHE.with(|dir| dir.borrow().clone())
    }
    #[cfg(not(test))]
    {
        let non_empty = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
        if let Some(dir) = non_empty("WINRUN_CACHE_DIR") {
            return Some(std::path::PathBuf::from(dir).join("wpkg"));
        }
        if let Some(dir) =
            non_empty("XDG_CACHE_HOME").filter(|dir| std::path::Path::new(dir).is_absolute())
        {
            return Some(std::path::PathBuf::from(dir).join("winrun").join("wpkg"));
        }
        non_empty("HOME").map(|home| {
            std::path::PathBuf::from(home)
                .join(".cache")
                .join("winrun")
                .join("wpkg")
        })
    }
}

#[cfg(test)]
thread_local! {
    static TEST_HOST_CACHE: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// The cached archive with this hash, re-verified.
fn read_host_cache(checksum: &Checksum) -> Option<Vec<u8>> {
    let path = host_cache_dir()?.join(checksum.cache_key());
    std::fs::read(path).ok().filter(|bytes| checksum.matches(bytes))
}

/// Keep a verified archive; written to a temporary name, then renamed, so a
/// reader never sees a partial file.
fn write_host_cache(checksum: &Checksum, archive: &[u8]) -> Result<(), String> {
    let Some(dir) = host_cache_dir() else {
        return Ok(());
    };
    let key = checksum.cache_key();
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let partial = dir.join(format!(".{key}.{}.part", std::process::id()));
    std::fs::write(&partial, archive)
        .and_then(|_| std::fs::rename(&partial, dir.join(&key)))
        .map_err(|e| {
            let _ = std::fs::remove_file(&partial);
            format!("cannot write {}: {e}", dir.display())
        })
}

/// Extract one verified version into its own directory. The first version
/// of a package becomes its default; later ones leave the default alone and
/// return it so the caller can tell the user how to switch.
fn install_version(
    fs: &mut WinFs,
    repository: &dyn Repository,
    manifest: &Manifest,
    progress: &mut dyn FnMut(&str),
) -> Result<Option<String>, String> {
    let cache_path = cache_path(manifest);
    let cached = fs
        .read_file(&cache_path)
        .ok()
        .filter(|bytes| manifest.checksum.matches(bytes));
    let archive = match cached {
        Some(archive) => {
            progress(&format!(
                "📦 Using cached {} {}\n",
                manifest.name, manifest.version
            ));
            archive
        }
        None => {
            let archive = match read_host_cache(&manifest.checksum) {
                Some(archive) => {
                    progress(&format!(
                        "📦 Using downloaded {} {} from {}\n",
                        manifest.name,
                        manifest.version,
                        host_cache_dir().map_or_else(String::new, |dir| dir.display().to_string())
                    ));
                    archive
                }
                None => {
                    let archive = download_archive(repository, manifest, progress)?;
                    if let Err(error) = write_host_cache(&manifest.checksum, &archive) {
                        progress(&format!("⚠️ Not kept for later installs: {error}\n"));
                    }
                    archive
                }
            };
            // Only a verified archive is cached; a stale or damaged copy is
            // replaced.
            fs.mkdir(CACHE)
                .and_then(|_| fs.write_file(&cache_path, archive.clone()))
                .map_err(|error| format!("wpkg: cannot cache {}: {error}", manifest.name))?;
            archive
        }
    };

    progress(&format!(
        "🛠️ Installing {} {}...\n",
        manifest.name, manifest.version
    ));
    let mut packages = load_database(fs)?;
    let first_version = !packages.iter().any(|package| package.name == manifest.name);
    // Only the default version is linked into BIN, so only a first
    // install can collide with another package's commands.
    if first_version {
        check_bin_conflicts(fs, &manifest.name, &manifest.bin, manifest.run.as_deref(), &manifest.env)?;
    }

    let final_path = version_path(&manifest.name, &manifest.version);
    let package_parent = package_dir(&manifest.name);
    let staging_path = format!(r"{}\.staging-{}", package_parent, manifest.version);
    let entries = package_entries(&archive, &manifest.url)?;
    let installed_bytes: u64 = entries.iter().map(|entry| entry.bytes.len() as u64).sum();
    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(entries.len());
    for entry in entries {
        let relative = safe_member(&entry.name)?;
        if !seen.insert(relative.to_ascii_lowercase()) {
            return Err(format!("wpkg: duplicate archive path: {}", entry.name));
        }
        validated.push((entry, relative));
    }
    fs.mkdir(&package_parent)
        .map_err(|error| format!("wpkg: cannot create package directory: {error}"))?;
    if fs.exists(&staging_path) {
        fs.remove(&staging_path, true)
            .map_err(|error| format!("wpkg: cannot clear package staging area: {error}"))?;
    }
    let stage_result = (|| {
        fs.mkdir(&staging_path)
            .map_err(|error| format!("wpkg: cannot create package staging area: {error}"))?;
        for (entry, relative) in &validated {
            let guest_path = format!(r"{}\{}", staging_path, relative.replace('/', "\\"));
            if entry.is_dir {
                fs.mkdir(&guest_path)
                    .map_err(|error| format!("wpkg: cannot create {guest_path}: {error}"))?;
            } else {
                let parent = guest_path
                    .rsplit_once('\\')
                    .map(|(path, _)| path)
                    .unwrap_or(&staging_path);
                fs.mkdir(parent)
                    .map_err(|error| format!("wpkg: cannot create {parent}: {error}"))?;
                fs.write_file(&guest_path, entry.bytes.clone())
                    .map_err(|error| format!("wpkg: cannot write {guest_path}: {error}"))?;
            }
        }
        for entry in &manifest.bin {
            let (_, executable) = bin_parts(entry);
            let staged = format!(r"{}\{}", staging_path, executable.replace('/', "\\"));
            if !fs.is_file(&staged) {
                return Err(format!(
                    "wpkg: manifest binary is missing from package archive: {executable}"
                ));
            }
        }
        Ok(())
    })();
    if let Err(error) = stage_result {
        let _ = fs.remove(&staging_path, true);
        if first_version {
            let _ = fs.remove(&package_parent, true);
        }
        return Err(error);
    }

    // A same-version directory can only be a leftover or another arch.
    if fs.exists(&final_path) {
        fs.remove(&final_path, true)
            .map_err(|error| format!("wpkg: cannot replace package files: {error}"))?;
    }
    fs.move_path(&staging_path, &final_path)
        .map_err(|error| format!("wpkg: cannot finalize package files: {error}"))?;

    let entry = InstalledVersion {
        version: manifest.version.clone(),
        arch: manifest.arch.clone(),
        install_path: final_path.clone(),
        bin: manifest.bin.clone(),
        run: manifest.run.clone(),
        env: manifest.env.clone(),
        dependencies: manifest.dependencies.clone(),
    };
    let previous_default = match packages
        .iter_mut()
        .find(|package| package.name == manifest.name)
    {
        Some(package) => {
            package
                .versions
                .retain(|existing| existing.version != manifest.version);
            package.versions.push(entry);
            Some(package.default.clone())
        }
        None => {
            packages.push(InstalledPackage {
                name: manifest.name.clone(),
                default: String::new(),
                versions: vec![entry],
            });
            None
        }
    };
    match &previous_default {
        // Reinstalling the default version refreshes its links in place.
        Some(default) if default == &manifest.version => {
            set_default(fs, &mut packages, &manifest.name, &manifest.version)?
        }
        Some(_) => {}
        None => set_default(fs, &mut packages, &manifest.name, &manifest.version)?,
    }
    save_database(fs, &packages)?;
    register_uninstall(fs, manifest, &final_path, installed_bytes)?;
    Ok(previous_default.filter(|default| default != &manifest.version))
}

/// The archive format a manifest URL names by its extension: `7z`,
/// `tgz` (`.tgz`/`.tar.gz`, as npm publishes packages), or `zip`.
fn archive_kind(url: &str) -> &'static str {
    let path = url.split(['?', '#']).next().unwrap_or(url).to_ascii_lowercase();
    if path.ends_with(".7z") {
        "7z"
    } else if path.ends_with(".tgz") || path.ends_with(".tar.gz") {
        "tgz"
    } else {
        "zip"
    }
}

fn archive_is_7z(url: &str) -> bool {
    archive_kind(url) == "7z"
}

fn package_entries(archive: &[u8], url: &str) -> Result<Vec<PackageEntry>, String> {
    if archive_kind(url) == "tgz" {
        return crate::tar_tool::archive_files(archive)
            .map_err(|error| format!("wpkg: cannot unpack tarball: {error}"))
            .map(|files| {
                files
                    .into_iter()
                    .map(|(name, is_dir, bytes)| PackageEntry { name, is_dir, bytes })
                    .collect()
            });
    }
    if !archive_is_7z(url) {
        return install::zip_entries(archive)?
            .into_iter()
            .map(|entry| {
                let bytes = if entry.is_dir {
                    Vec::new()
                } else {
                    install::extract_bytes(archive, &entry)?
                };
                Ok(PackageEntry {
                    name: entry.name,
                    is_dir: entry.is_dir,
                    bytes,
                })
            })
            .collect();
    }

    let mut extracted = Vec::new();
    let mut total_bytes = 0u64;
    sevenz_rust2::decompress_with_extract_fn(
        Cursor::new(archive),
        Path::new("."),
        |entry, reader, _destination| {
            let name = safe_member(&entry.name)
                .map_err(|error| sevenz_rust2::Error::Other(std::borrow::Cow::Owned(error)))?;
            if entry.is_anti_item {
                return Err(sevenz_rust2::Error::Other(std::borrow::Cow::Owned(
                    format!("wpkg: anti-items are not supported: {name}"),
                )));
            }

            let mut bytes = Vec::new();
            if !entry.is_directory && entry.has_stream {
                if entry.size > MAX_7Z_ENTRY_BYTES {
                    return Err(sevenz_rust2::Error::Other(std::borrow::Cow::Owned(
                        format!("wpkg: 7z entry exceeds the 512 MiB limit: {name}"),
                    )));
                }
                total_bytes = total_bytes.checked_add(entry.size).ok_or_else(|| {
                    sevenz_rust2::Error::Other(std::borrow::Cow::Borrowed(
                        "wpkg: 7z uncompressed size overflow",
                    ))
                })?;
                if total_bytes > MAX_7Z_TOTAL_BYTES {
                    return Err(sevenz_rust2::Error::Other(std::borrow::Cow::Borrowed(
                        "wpkg: 7z archive exceeds the 1 GiB unpacked size limit",
                    )));
                }

                let mut limited = reader.take(MAX_7Z_ENTRY_BYTES + 1);
                limited.read_to_end(&mut bytes).map_err(|error| {
                    sevenz_rust2::Error::from(std::io::Error::new(
                        error.kind(),
                        format!("wpkg: failed reading 7z entry {name}: {error}"),
                    ))
                })?;
                if bytes.len() as u64 != entry.size {
                    return Err(sevenz_rust2::Error::Other(std::borrow::Cow::Owned(
                        format!("wpkg: 7z entry size mismatch: {name}"),
                    )));
                }
            }

            extracted.push(PackageEntry {
                name,
                is_dir: entry.is_directory,
                bytes,
            });
            Ok(true)
        },
    )
    .map_err(|error| format!("wpkg: cannot unpack 7z archive: {error}"))?;
    Ok(extracted)
}

/// Remove one version (`name@version`) or, without a version, the whole
/// package. The default version goes only when it is the last one left.
fn remove_package(fs: &mut WinFs, name: &str, spec: Option<&str>) -> Result<String, String> {
    let mut packages = load_database(fs)?;
    let package = packages
        .iter()
        .find(|package| package.name == name)
        .cloned()
        .ok_or_else(|| format!("wpkg: package is not installed: {name}"))?;

    if let Some(spec) = spec {
        let matches = package.matching(spec);
        let version = match matches.as_slice() {
            [] => return Err(format!("wpkg: {name} {spec} is not installed")),
            [entry] => entry.version.clone(),
            many => {
                let versions: Vec<_> = many.iter().map(|entry| entry.version.as_str()).collect();
                return Err(format!(
                    "wpkg: {name}@{spec} matches several installed versions ({}); name one exactly",
                    versions.join(", ")
                ));
            }
        };
        if package.versions.len() > 1 {
            if version == package.default {
                return Err(format!(
                    "wpkg: {name} {version} is the default; run `wpkg default {name} <version>` first"
                ));
            }
            let path = version_path(name, &version);
            if fs.exists(&path) {
                fs.remove(&path, true)
                    .map_err(|error| format!("wpkg: cannot remove package files: {error}"))?;
            }
            if let Some(package) = packages.iter_mut().find(|package| package.name == name) {
                package.versions.retain(|entry| entry.version != version);
            }
            save_database(fs, &packages)?;
            unregister_uninstall(fs, name, &[version.as_str()])?;
            return Ok(format!("{name} {version}"));
        }
    }

    remove_owned_links(fs, name)?;
    let current = current_link(name);
    if fs.is_symlink(&current) {
        fs.remove(&current, false)
            .map_err(|error| format!("wpkg: cannot remove {current}: {error}"))?;
    }
    // Program Files is shared: delete only the version directories wpkg
    // installed, then the package directory if nothing else is left in it.
    for entry in &package.versions {
        let path = version_path(name, &entry.version);
        if fs.exists(&path) {
            fs.remove(&path, true)
                .map_err(|error| format!("wpkg: cannot remove package files: {error}"))?;
        }
    }
    let directory = package_dir(name);
    if fs
        .list_dir(&directory)
        .is_ok_and(|entries| entries.is_empty())
    {
        fs.remove(&directory, false)
            .map_err(|error| format!("wpkg: cannot remove {directory}: {error}"))?;
    }
    packages.retain(|entry| entry.name != name);
    save_database(fs, &packages)?;
    let versions: Vec<&str> = package
        .versions
        .iter()
        .map(|entry| entry.version.as_str())
        .collect();
    unregister_uninstall(fs, name, &versions)?;
    Ok(match spec {
        Some(_) => format!("{name} {}", package.default),
        None => name.to_string(),
    })
}

/// `<package>#<version>#<arch>.<zip|7z>`: `#` cannot occur in package
/// names or versions, so a file name maps back to exactly one package.
fn cache_path(manifest: &Manifest) -> String {
    let extension = archive_kind(&manifest.url);
    format!(
        r"{CACHE}\{}#{}#{}.{extension}",
        manifest.name, manifest.version, manifest.arch
    )
}

struct CachedArchive {
    path: String,
    name: String,
    version: String,
    arch: String,
    bytes: u64,
}

/// Cached archives, optionally for one package, sorted by package then
/// version. Files wpkg did not name are left alone.
fn cached_archives(fs: &WinFs, package: Option<&str>) -> Result<Vec<CachedArchive>, String> {
    if !fs.is_dir(CACHE) {
        return Ok(Vec::new());
    }
    let mut archives = Vec::new();
    for file in fs
        .list_dir(CACHE)
        .map_err(|error| format!("wpkg: cannot list {CACHE}: {error}"))?
    {
        let Some(stem) = file
            .strip_suffix(".zip")
            .or_else(|| file.strip_suffix(".7z"))
            .or_else(|| file.strip_suffix(".tgz"))
        else {
            continue;
        };
        let mut parts = stem.split('#');
        let (Some(name), Some(version), Some(arch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if package.is_some_and(|package| !package.eq_ignore_ascii_case(name)) {
            continue;
        }
        let path = format!(r"{CACHE}\{file}");
        archives.push(CachedArchive {
            bytes: fs.file_len(&path).unwrap_or_default(),
            path,
            name: name.to_string(),
            version: version.to_string(),
            arch: arch.to_string(),
        });
    }
    archives.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| compare_versions(&left.version, &right.version))
    });
    Ok(archives)
}

fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if value >= KIB * KIB {
        format!("{:.1} MiB", value / (KIB * KIB))
    } else if value >= KIB {
        format!("{:.1} KiB", value / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn uninstall_key(name: &str, version: &str) -> String {
    format!(r"{UNINSTALL_KEY}\wpkg-{name}-{version}")
}

/// List an installed version under the registry key Windows inventory and
/// uninstall tools read for installed programs.
fn register_uninstall(
    fs: &mut WinFs,
    manifest: &Manifest,
    install_path: &str,
    installed_bytes: u64,
) -> Result<(), String> {
    use crate::winreg::{Hive, RegValue, Registry};
    let mut registry = Registry::load(fs).map_err(|error| format!("wpkg: {error}"))?;
    let key = registry
        .create_key(
            Hive::LocalMachine,
            &uninstall_key(&manifest.name, &manifest.version),
        )
        .0;
    let remove = format!("wpkg remove {}@{}", manifest.name, manifest.version);
    let estimated_kib = u32::try_from(installed_bytes.div_ceil(1024)).unwrap_or(u32::MAX);
    for (name, value) in [
        (
            "DisplayName",
            RegValue::string(&format!("{} {}", manifest.name, manifest.version)),
        ),
        ("DisplayVersion", RegValue::string(&manifest.version)),
        ("Publisher", RegValue::string("wpkg")),
        ("InstallLocation", RegValue::string(install_path)),
        ("UninstallString", RegValue::string(&remove)),
        ("QuietUninstallString", RegValue::string(&remove)),
        ("EstimatedSize", RegValue::dword(estimated_kib)),
        ("NoModify", RegValue::dword(1)),
        ("NoRepair", RegValue::dword(1)),
    ] {
        key.set_value(name, value);
    }
    registry
        .save(fs, Hive::LocalMachine)
        .map_err(|error| format!("wpkg: cannot record {}: {error}", manifest.name))
}

fn unregister_uninstall(fs: &mut WinFs, name: &str, versions: &[&str]) -> Result<(), String> {
    use crate::winreg::{Hive, Registry};
    let mut registry = Registry::load(fs).map_err(|error| format!("wpkg: {error}"))?;
    for version in versions {
        // A key someone already removed is not an error.
        let _ = registry.delete_key(Hive::LocalMachine, &uninstall_key(name, version), true);
    }
    registry
        .save(fs, Hive::LocalMachine)
        .map_err(|error| format!("wpkg: cannot update installed programs: {error}"))
}

/// Point `C:\Program Files\<name>\current` at `version` and relink its
/// commands in [`BIN`] through that directory link. Conflicts are checked before
/// anything changes.
fn set_default(
    fs: &mut WinFs,
    packages: &mut [InstalledPackage],
    name: &str,
    version: &str,
) -> Result<(), String> {
    let package = packages
        .iter_mut()
        .find(|package| package.name == name)
        .ok_or_else(|| format!("wpkg: package is not installed: {name}"))?;
    let entry = package
        .version(version)
        .cloned()
        .ok_or_else(|| format!("wpkg: {name} {version} is not installed"))?;
    check_bin_conflicts(fs, name, &entry.bin, entry.run.as_deref(), &entry.env)?;
    let current = current_link(name);
    if fs.exists(&current) && !fs.is_symlink(&current) {
        return Err(format!("wpkg: {current} exists and is not a link"));
    }

    remove_owned_links(fs, name)?;
    if fs.is_symlink(&current) {
        fs.remove(&current, false)
            .map_err(|error| format!("wpkg: cannot update {current}: {error}"))?;
    }
    fs.create_symlink(&current, &entry.install_path, true)
        .map_err(|error| format!("wpkg: cannot link {current}: {error}"))?;
    fs.mkdir(BIN)
        .map_err(|error| format!("wpkg: cannot create command directory: {error}"))?;
    for bin in &entry.bin {
        let Exposure { exposed, target, shim } = exposure(bin, entry.run.as_deref(), &entry.env)?;
        let target = format!(r"{}\{}", current, target.replace('/', "\\"));
        // A batch file finds its own files through `%~dp0`, which names the
        // link's directory, so batch commands, launched files, and commands
        // with environment settings get a forwarding shim instead.
        let exposed_result = if shim {
            let env: Vec<String> = entry.env.iter().map(|setting| setting.replace("{dir}", &current)).collect();
            fs.write_file(&exposed, shim_contents(&target, entry.run.as_deref(), &env))
        } else {
            fs.create_symlink(&exposed, &target, false)
        };
        exposed_result.map_err(|error| format!("wpkg: cannot expose {bin}: {error}"))?;
    }
    package.default = version.to_string();
    Ok(())
}

/// Command links and shims this package may replace: those that lead into
/// its own directory.
fn owns_link(fs: &WinFs, name: &str, path: &str) -> bool {
    let prefix = format!(r"{}\", package_dir(name)).to_ascii_lowercase();
    let target = if fs.is_symlink(path) {
        fs.symlink_target(path)
    } else if is_batch(path) {
        fs.read_file(path).ok().and_then(|data| shim_target(&data))
    } else {
        None
    };
    target.is_some_and(|target| target.to_ascii_lowercase().starts_with(&prefix))
}

fn is_batch(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".cmd") || lower.ends_with(".bat")
}

/// A batch file that runs `target` (through `run`, with `env` set) with
/// the same arguments. Control passes to `target` without `call`, so its
/// exit code is the shim's. A plain forward is one line; a launcher names
/// its target in a first `@rem wpkg-target` line.
fn shim_contents(target: &str, run: Option<&str>, env: &[String]) -> Vec<u8> {
    if run.is_none() && env.is_empty() {
        return format!("@\"{target}\" %*\r\n").into_bytes();
    }
    let mut text = format!("@rem wpkg-target \"{target}\"\r\n@setlocal\r\n");
    for setting in env {
        text.push_str(&format!("@set \"{setting}\"\r\n"));
    }
    match run {
        Some(run) => text.push_str(&format!("@{run} \"{target}\" %*\r\n")),
        None => text.push_str(&format!("@\"{target}\" %*\r\n")),
    }
    text.into_bytes()
}

/// The target of a shim written by [`shim_contents`].
fn shim_target(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let line = text.lines().next()?.trim_end();
    let target = match line.strip_prefix("@rem wpkg-target \"") {
        Some(rest) => rest.strip_suffix('"')?,
        None => line.strip_prefix("@\"")?.strip_suffix("\" %*")?,
    };
    (!target.contains('"') && !target.contains('\n')).then(|| target.to_string())
}

fn check_bin_conflicts(fs: &WinFs, name: &str, bins: &[String], run: Option<&str>, env: &[String]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for entry in bins {
        let exposed = exposure(entry, run, env)?.exposed;
        if !seen.insert(exposed.to_ascii_lowercase()) {
            return Err(format!("wpkg: {name} exposes {exposed} more than once"));
        }
        if (fs.exists(&exposed) || fs.is_symlink(&exposed)) && !owns_link(fs, name, &exposed) {
            return Err(format!("wpkg: binary path already exists: {exposed}"));
        }
    }
    Ok(())
}

fn remove_owned_links(fs: &mut WinFs, name: &str) -> Result<(), String> {
    let bin_prefix = format!(r"{BIN}\").to_ascii_lowercase();
    let shims = fs
        .list_dir(BIN)
        .unwrap_or_default()
        .into_iter()
        .map(|file| format!(r"{BIN}\{file}"))
        .filter(|path| is_batch(path) && !fs.is_symlink(path));
    let owned: Vec<String> = fs
        .snapshot_symlinks()
        .into_iter()
        .map(|(path, _, _)| path)
        .filter(|path| path.to_ascii_lowercase().starts_with(&bin_prefix))
        .chain(shims)
        .filter(|path| owns_link(fs, name, path))
        .collect();
    for path in owned {
        fs.remove(&path, false)
            .map_err(|error| format!("wpkg: cannot remove binary link: {error}"))?;
    }
    Ok(())
}

fn latest_version(repository: &dyn Repository, name: &str) -> Result<String, String> {
    let bytes = repository
        .fetch(&format!("packages/{name}/latest"))
        .map_err(|_| format!("wpkg: no package named {name} (see `wpkg search`)"))?;
    let version = std::str::from_utf8(&bytes)
        .map_err(|_| format!("wpkg: invalid latest version for {name}"))?
        .trim();
    normalize_version(version)
}

fn resolve_manifest(
    repository: &dyn Repository,
    name: &str,
    version: &str,
    arch: &str,
) -> Result<Manifest, String> {
    let base = format!("packages/{name}/{version}.wpkg");
    if let Ok(bytes) = repository.fetch(&base) {
        let manifest = Manifest::parse(&bytes)?;
        if manifest.name != name || manifest.version != version {
            return Err(format!(
                "wpkg: manifest identity mismatch for {name}@{version}"
            ));
        }
        if manifest.arch == arch {
            return Ok(manifest);
        }
    }
    let arch_path = format!("packages/{name}/{version}-{arch}.wpkg");
    let bytes = repository
        .fetch(&arch_path)
        .map_err(|_| format!("wpkg: no {arch} package manifest for {name}@{version}"))?;
    let manifest = Manifest::parse(&bytes)?;
    if manifest.name != name || manifest.version != version || manifest.arch != arch {
        return Err(format!(
            "wpkg: manifest identity or architecture mismatch for {name}@{version}"
        ));
    }
    Ok(manifest)
}

/// A package's one-line description, from its upstream `.wpkg` or its
/// latest pinned one.
fn package_description(repository: &dyn Repository, name: &str) -> Option<String> {
    if let Ok(bytes) = repository.fetch(&format!("packages/{name}/upstream.wpkg")) {
        return Recipe::parse(&bytes).ok()?.description;
    }
    let version = latest_version(repository, name).ok()?;
    let bytes = repository
        .fetch(&format!("packages/{name}/{version}.wpkg"))
        .or_else(|_| repository.fetch(&format!("packages/{name}/{version}-{}.wpkg", host_architecture())))
        .ok()?;
    Manifest::parse(&bytes).ok()?.description
}

fn repository_names(repository: &dyn Repository) -> Result<Vec<String>, String> {
    let bytes = repository.fetch("packages/index")?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "wpkg: invalid package index".to_string())?;
    let mut names = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        names.push(normalize_name(line)?);
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// Versions listed in `packages/<name>/versions`, oldest first. A repository
/// without the file offers only exact versions.
fn registry_versions(repository: &dyn Repository, name: &str) -> Result<Vec<String>, String> {
    let Ok(bytes) = repository.fetch(&format!("packages/{name}/versions")) else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("wpkg: invalid versions list for {name}"))?;
    let mut versions = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(normalize_version)
        .collect::<Result<Vec<_>, _>>()?;
    versions.sort_by(|left, right| compare_versions(left, right));
    versions.dedup();
    Ok(versions)
}

/// Resolve `name[@spec]`: no spec is the registry's `latest`; an exact
/// version wins; otherwise `26` means the newest `26.x` built for `arch`.
fn resolve_version(
    repository: &dyn Repository,
    name: &str,
    spec: Option<&str>,
    arch: &str,
) -> Result<Manifest, String> {
    // An upstream package resolves its release where it is published.
    if let Ok(bytes) = repository.fetch(&format!("packages/{name}/upstream.wpkg")) {
        let recipe = Recipe::parse(&bytes)?;
        if recipe.name != name {
            return Err(format!("wpkg: upstream manifest identity mismatch for {name}"));
        }
        return upstream::resolve(repository, &recipe, spec, arch);
    }
    let Some(spec) = spec else {
        let version = latest_version(repository, name)?;
        return resolve_manifest(repository, name, &version, arch);
    };
    let versions = registry_versions(repository, name)?;
    if versions.is_empty() || versions.iter().any(|version| version == spec) {
        return resolve_manifest(repository, name, spec, arch);
    }
    let mut last_error = format!("wpkg: no {name} version matches {spec}");
    for version in versions
        .iter()
        .rev()
        .filter(|version| version_matches(version, spec))
    {
        match resolve_manifest(repository, name, version, arch) {
            Ok(manifest) => return Ok(manifest),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

/// `26` matches `26`, `26.1.0`, and `26-rc1`, but not `260`.
fn version_matches(version: &str, spec: &str) -> bool {
    version == spec
        || version
            .strip_prefix(spec)
            .is_some_and(|rest| rest.starts_with(['.', '-', '+']))
}

/// Natural ordering: digit runs compare numerically, so `3.9 < 3.10`.
fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    fn chunks(version: &str) -> Vec<(bool, &str)> {
        let mut chunks = Vec::new();
        let mut start = 0;
        let bytes = version.as_bytes();
        for index in 1..=bytes.len() {
            if index == bytes.len()
                || bytes[index].is_ascii_digit() != bytes[start].is_ascii_digit()
            {
                chunks.push((bytes[start].is_ascii_digit(), &version[start..index]));
                start = index;
            }
        }
        chunks
    }
    let (left_chunks, right_chunks) = (chunks(left), chunks(right));
    for (left, right) in left_chunks.iter().zip(&right_chunks) {
        let ordering = match (left, right) {
            ((true, left), (true, right)) => {
                let (left, right) = (left.trim_start_matches('0'), right.trim_start_matches('0'));
                left.len().cmp(&right.len()).then_with(|| left.cmp(right))
            }
            ((_, left), (_, right)) => left.cmp(right),
        };
        if ordering.is_ne() {
            return ordering;
        }
    }
    left_chunks
        .len()
        .cmp(&right_chunks.len())
        .then_with(|| left.cmp(right))
}

fn load_database(fs: &WinFs) -> Result<Vec<InstalledPackage>, String> {
    if !fs.is_file(DATABASE) {
        return Ok(Vec::new());
    }
    let bytes = fs
        .read_file(DATABASE)
        .map_err(|error| format!("wpkg: cannot read installed database: {error}"))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("wpkg: installed database is invalid: {error}"))?;
    let string = |entry: &Value, key: &str| {
        entry
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("wpkg: installed database entry lacks {key}"))
    };
    let strings = |entry: &Value, key: &str| -> Result<Vec<String>, String> {
        entry
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("wpkg: installed database entry lacks {key}"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("wpkg: invalid {key} in installed database"))
            })
            .collect()
    };
    value
        .as_array()
        .ok_or_else(|| "wpkg: installed database must be a JSON array".to_string())?
        .iter()
        .map(|package| {
            let versions = package
                .get("versions")
                .and_then(Value::as_array)
                .ok_or_else(|| "wpkg: installed database entry lacks versions".to_string())?
                .iter()
                .map(|entry| {
                    Ok(InstalledVersion {
                        version: string(entry, "version")?,
                        arch: string(entry, "arch")?,
                        install_path: string(entry, "install_path")?,
                        bin: strings(entry, "bin")?,
                        run: entry.get("run").and_then(Value::as_str).map(str::to_string),
                        env: if entry.get("env").is_some() { strings(entry, "env")? } else { Vec::new() },
                        dependencies: strings(entry, "dependencies")?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(InstalledPackage {
                name: string(package, "name")?,
                default: string(package, "default")?,
                versions,
            })
        })
        .collect()
}

fn save_database(fs: &mut WinFs, packages: &[InstalledPackage]) -> Result<(), String> {
    let value = packages
        .iter()
        .map(|package| {
            json!({
                "name": package.name,
                "default": package.default,
                "versions": package.versions.iter().map(|entry| json!({
                    "version": entry.version,
                    "arch": entry.arch,
                    "install_path": entry.install_path,
                    "bin": entry.bin,
                    "run": entry.run,
                    "env": entry.env,
                    "dependencies": entry.dependencies,
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    fs.mkdir(STATE)
        .map_err(|error| format!("wpkg: cannot create package database directory: {error}"))?;
    let data = serde_json::to_vec_pretty(&value)
        .map_err(|error| format!("wpkg: cannot encode installed database: {error}"))?;
    fs.write_file(DATABASE, data)
        .map_err(|error| format!("wpkg: cannot write installed database: {error}"))
}

fn package_dir(name: &str) -> String {
    format!(r"{ROOT}\{name}")
}

fn version_path(name: &str, version: &str) -> String {
    format!(r"{ROOT}\{name}\{version}")
}

fn current_link(name: &str) -> String {
    format!(r"{ROOT}\{name}\{CURRENT}")
}

fn split_package_spec(spec: &str) -> Result<(String, Option<String>), String> {
    let (name, version) = match spec.split_once('@') {
        Some((name, version)) if !version.is_empty() => {
            (normalize_name(name)?, Some(normalize_version(version)?))
        }
        Some(_) => return Err("wpkg: package version after @ cannot be empty".to_string()),
        None => (normalize_name(spec)?, None),
    };
    Ok((name, version))
}

fn normalize_name(raw: &str) -> Result<String, String> {
    if raw.is_empty()
        || raw.len() > 100
        || raw == "."
        || raw.contains("..")
        || !raw.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(format!("wpkg: invalid package name: {raw}"));
    }
    Ok(raw.to_ascii_lowercase())
}

fn normalize_version(raw: &str) -> Result<String, String> {
    let version = raw.trim();
    if version.is_empty()
        || version.len() > 128
        || version.contains("..")
        || version.starts_with('.')
        || version.eq_ignore_ascii_case(CURRENT)
        || !version.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '+')
        })
    {
        return Err(format!("wpkg: invalid version path component: {raw}"));
    }
    Ok(version.to_string())
}

fn normalize_arch(raw: &str) -> Result<String, String> {
    match raw.to_ascii_lowercase().as_str() {
        "x64" => Ok("x64".to_string()),
        "arm64" => Ok("arm64".to_string()),
        _ => Err(format!("wpkg: unsupported architecture: {raw}")),
    }
}

pub fn host_architecture() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unsupported"
    }
}

/// A `bin` entry's command name (when given as `name=path`) and path.
fn bin_parts(entry: &str) -> (Option<&str>, &str) {
    match entry.split_once('=') {
        Some((command, path)) => (Some(command), path),
        None => (None, entry),
    }
}

/// A `bin` entry: `path` or `command=path`, the path inside the package
/// and, unless a `run` program opens it, an `.exe` or batch file.
fn validate_bin(entry: &str, launched: bool) -> Result<(), String> {
    let (command, path) = bin_parts(entry);
    if let Some(command) = command {
        if command.is_empty() || !command.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
            return Err(format!("wpkg: invalid command name in bin: {entry}"));
        }
    }
    let normalized = path.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.contains(':')
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.trim().is_empty())
        || !(launched || normalized.to_ascii_lowercase().ends_with(".exe") || is_batch(&normalized))
    {
        return Err(format!("wpkg: unsafe or non-executable bin path: {path}"));
    }
    Ok(())
}

/// How one `bin` entry appears in [`BIN`]: its file there, its path inside
/// the package, and whether it is a batch shim (launched files, packages
/// with `env`, and batch files) rather than a link.
struct Exposure {
    exposed: String,
    target: String,
    shim: bool,
}

fn exposure(entry: &str, run: Option<&str>, env: &[String]) -> Result<Exposure, String> {
    let (command, path) = bin_parts(entry);
    let file = path.rsplit('/').next().unwrap_or(path);
    let shim = run.is_some() || !env.is_empty() || is_batch(path);
    let name = match (command, shim) {
        (Some(command), true) if is_batch(command) => command.to_string(),
        (Some(command), true) => format!("{command}.cmd"),
        (None, true) if is_batch(file) => file.to_string(),
        (None, true) => format!("{}.cmd", file.rsplit_once('.').map_or(file, |(stem, _)| stem)),
        (Some(command), false) if command.to_ascii_lowercase().ends_with(".exe") => command.to_string(),
        (Some(command), false) => format!("{command}.exe"),
        (None, false) => file.to_string(),
    };
    Ok(Exposure { exposed: format!(r"{BIN}\{name}"), target: path.to_string(), shim })
}

fn safe_member(path: &str) -> Result<String, String> {
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    if trimmed.is_empty()
        || normalized.starts_with('/')
        || normalized.contains(':')
        || normalized.as_bytes().contains(&0)
        || trimmed
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.trim().is_empty())
    {
        return Err(format!("wpkg: unsafe archive path: {path}"));
    }
    Ok(trimmed.to_string())
}

/// A `.wpkg` file's `key = value` lines (values still in TOML form).
pub(crate) fn parse_fields(bytes: &[u8], allowed: &[&str]) -> Result<HashMap<String, String>, String> {
    let source = std::str::from_utf8(bytes).map_err(|_| "wpkg: manifest is not UTF-8")?;
    let mut values: HashMap<String, String> = HashMap::new();
    for (line_number, line) in source.lines().enumerate() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("wpkg: malformed manifest line {}", line_number + 1))?;
        let key = key.trim().to_ascii_lowercase();
        if !allowed.contains(&key.as_str()) {
            return Err(format!("wpkg: unsupported manifest key: {key}"));
        }
        if values.insert(key.clone(), value.trim().to_string()).is_some() {
            return Err(format!("wpkg: duplicate manifest key: {key}"));
        }
    }
    Ok(values)
}

/// The keys pinned and upstream `.wpkg` files share.
pub(crate) struct CommonFields {
    pub bin: Vec<String>,
    pub run: Option<String>,
    pub env: Vec<String>,
    pub dependencies: Vec<String>,
    pub description: Option<String>,
}

impl CommonFields {
    pub(crate) fn parse(values: &HashMap<String, String>) -> Result<Self, String> {
        let array = |key: &str| values.get(key).map(|value| parse_string_array(value)).transpose().map(Option::unwrap_or_default);
        let run = values.get("run").map(|value| parse_string(value)).transpose()?;
        if let Some(run) = &run {
            if run.is_empty() || !run.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
                return Err(format!("wpkg: run must name a command: {run}"));
            }
        }
        let bin = array("bin")?;
        if bin.is_empty() {
            return Err("wpkg: manifest bin must not be empty".to_string());
        }
        for entry in &bin {
            validate_bin(entry, run.is_some())?;
        }
        let env = array("env")?;
        for entry in &env {
            let (name, _) = entry.split_once('=').ok_or_else(|| format!("wpkg: env entries are NAME=VALUE: {entry}"))?;
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || entry.contains(['"', '\r', '\n']) {
                return Err(format!("wpkg: invalid env entry: {entry}"));
            }
        }
        let dependencies = array("dependencies")?
            .into_iter()
            .map(|dependency| {
                let (name, version) = split_package_spec(&dependency)?;
                Ok(match version {
                    Some(version) => format!("{name}@{version}"),
                    None => name,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let description = values.get("description").map(|value| parse_string(value)).transpose()?;
        Ok(Self { bin, run, env, dependencies, description })
    }
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let values = parse_fields(
            bytes,
            &["name", "version", "arch", "url", "sha256", "sha512", "bin", "run", "env", "dependencies", "description"],
        )?;
        let string = |key: &str| -> Result<String, String> {
            parse_string(values.get(key).ok_or_else(|| format!("wpkg: manifest missing {key}"))?)
        };
        let name = normalize_name(&string("name")?)?;
        let version = normalize_version(&string("version")?)?;
        let arch = normalize_arch(&string("arch")?)?;
        let url = string("url")?;
        if !url.starts_with("https://") {
            return Err("wpkg: package archive URL must use HTTPS".to_string());
        }
        let checksum = match (values.contains_key("sha256"), values.contains_key("sha512")) {
            (true, false) => Checksum::sha256(&string("sha256")?)?,
            (false, true) => Checksum::sha512(&string("sha512")?)?,
            _ => return Err("wpkg: manifest needs exactly one of sha256 and sha512".to_string()),
        };
        let common = CommonFields::parse(&values)?;
        Ok(Self {
            name,
            version,
            arch,
            url,
            checksum,
            bin: common.bin,
            run: common.run,
            env: common.env,
            dependencies: common.dependencies,
            description: common.description,
            upstream: false,
        })
    }
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quoted {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == '#' && !quoted {
            return &line[..index];
        }
    }
    line
}

fn parse_string(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if !raw.starts_with('"') || !raw.ends_with('"') || raw.len() < 2 {
        return Err("wpkg: expected a TOML basic string".to_string());
    }
    let mut output = String::new();
    let mut chars = raw[1..raw.len() - 1].chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        output.push(match chars.next() {
            Some('"') => '"',
            Some('\\') => '\\',
            Some('n') => '\n',
            Some('t') => '\t',
            _ => return Err("wpkg: unsupported TOML string escape".to_string()),
        });
    }
    Ok(output)
}

fn parse_string_array(raw: &str) -> Result<Vec<String>, String> {
    let raw = raw.trim();
    if !raw.starts_with('[') || !raw.ends_with(']') {
        return Err("wpkg: expected a TOML string array".to_string());
    }
    let body = &raw[1..raw.len() - 1];
    let mut items = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in body.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quoted {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == ',' && !quoted {
            let item = body[start..index].trim();
            if !item.is_empty() {
                items.push(parse_string(item)?);
            }
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err("wpkg: unterminated string in array".to_string());
    }
    let tail = body[start..].trim();
    if !tail.is_empty() {
        items.push(parse_string(tail)?);
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryRepo {
        files: HashMap<String, Vec<u8>>,
    }

    impl MemoryRepo {
        fn add(&mut self, path: &str, bytes: impl Into<Vec<u8>>) {
            self.files.insert(path.to_string(), bytes.into());
        }
        fn package(&mut self, name: &str, version: &str, arch: &str, bin: &[&str], deps: &[&str]) {
            self.add(
                format!("packages/{name}/latest").as_str(),
                version.as_bytes(),
            );
            let versions_path = format!("packages/{name}/versions");
            let mut versions = self
                .files
                .get(&versions_path)
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default();
            if !versions.lines().any(|line| line == version) {
                versions.push_str(&format!("{version}\n"));
            }
            self.add(&versions_path, versions);
            // Each version's binaries carry the version so tests can tell
            // which copy a command link reaches.
            let contents = format!("MZ {version}");
            let archive = zip_stored(
                bin.iter()
                    .map(|path| (*path, contents.as_bytes()))
                    .collect(),
            );
            let checksum = install::sha256_hex(&archive);
            let url = format!("https://packages.invalid/{name}-{version}-{arch}.zip");
            self.add(url.as_str(), archive);
            let bin = bin
                .iter()
                .map(|entry| format!("\"{entry}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let dependencies = deps
                .iter()
                .map(|entry| format!("\"{entry}\""))
                .collect::<Vec<_>>()
                .join(", ");
            self.add(
                format!("packages/{name}/{version}.wpkg").as_str(),
                format!(
                    "name = \"{name}\"\nversion = \"{version}\"\narch = \"{arch}\"\nurl = \"{url}\"\nsha256 = \"{checksum}\"\nbin = [{bin}]\ndependencies = [{dependencies}]\n"
                ),
            );
        }
    }

    impl Repository for MemoryRepo {
        fn fetch(&self, path: &str) -> Result<Vec<u8>, String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| format!("not found: {path}"))
        }
    }

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    fn zip_stored(entries: Vec<(&str, &[u8])>) -> Vec<u8> {
        let mut archive = Vec::new();
        for (name, data) in entries {
            archive.extend_from_slice(b"PK\x03\x04");
            archive.extend_from_slice(&20u16.to_le_bytes());
            archive.extend_from_slice(&0u16.to_le_bytes());
            archive.extend_from_slice(&0u16.to_le_bytes());
            archive.extend_from_slice(&[0; 4]);
            archive.extend_from_slice(&[0; 4]);
            archive.extend_from_slice(&(data.len() as u32).to_le_bytes());
            archive.extend_from_slice(&(data.len() as u32).to_le_bytes());
            archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
            archive.extend_from_slice(&0u16.to_le_bytes());
            archive.extend_from_slice(name.as_bytes());
            archive.extend_from_slice(data);
        }
        archive
    }

    fn run(fs: &mut WinFs, repo: &MemoryRepo, words: &[&str]) -> String {
        String::from_utf8(execute(fs, repo, "x64", &args(words)).unwrap()).unwrap()
    }

    fn package<'a>(packages: &'a [InstalledPackage], name: &str) -> &'a InstalledPackage {
        packages
            .iter()
            .find(|package| package.name == name)
            .unwrap()
    }

    fn installed_versions(fs: &WinFs, name: &str) -> Vec<String> {
        let packages = load_database(fs).unwrap();
        let mut versions: Vec<_> = package(&packages, name)
            .versions
            .iter()
            .map(|entry| entry.version.clone())
            .collect();
        versions.sort_by(|left, right| compare_versions(left, right));
        versions
    }

    fn default_version(fs: &WinFs, name: &str) -> String {
        package(&load_database(fs).unwrap(), name).default.clone()
    }

    /// A gzipped tarball with one file, laid out as npm publishes packages.
    fn npm_tarball(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(b"0000644");
        header[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        header[136..147].copy_from_slice(b"00000000000");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].copy_from_slice(b"        ");
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut tar = header.to_vec();
        tar.extend_from_slice(data);
        tar.resize(tar.len().div_ceil(512) * 512 + 1024, 0);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &tar).unwrap();
        encoder.finish().unwrap()
    }

    fn sha512_base64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(ring::digest::digest(&ring::digest::SHA512, bytes).as_ref())
    }

    /// An npm-published tool: the registry has only its upstream `.wpkg`.
    fn npm_tool(repo: &mut MemoryRepo, versions: &[&str], integrity: bool) {
        repo.add("packages/index", "tool\n");
        repo.add(
            "packages/tool/upstream.wpkg",
            "name = \"tool\"\nupstream = \"npm\"\nx64 = \"tool-windows-x64\"\nbin = [\"package/bin/tool.exe\"]\ndescription = \"A tool\"\n",
        );
        let mut documents = serde_json::Map::new();
        for version in versions {
            let archive = npm_tarball("package/bin/tool.exe", format!("MZ {version}").as_bytes());
            let url = format!("https://registry.npmjs.org/tool-windows-x64/-/tool-windows-x64-{version}.tgz");
            let mut dist = serde_json::json!({ "tarball": url });
            if integrity {
                dist["integrity"] = format!("sha512-{}", sha512_base64(&archive)).into();
            }
            documents.insert(version.to_string(), serde_json::json!({ "version": version, "dist": dist }));
            repo.add(url.as_str(), archive);
        }
        let newest = versions.last().unwrap();
        repo.add("https://registry.npmjs.org/tool-windows-x64/latest", serde_json::to_vec(&documents[*newest]).unwrap());
        repo.add(
            "https://registry.npmjs.org/tool-windows-x64",
            serde_json::to_vec(&serde_json::json!({ "versions": documents })).unwrap(),
        );
    }

    #[test]
    fn upstream_packages_install_the_newest_or_asked_release_verified_by_sha512() {
        let mut repo = MemoryRepo::default();
        npm_tool(&mut repo, &["1.0.0", "1.1.0", "2.0.0"], true);
        let mut fs = WinFs::ephemeral_runner();
        let output = run(&mut fs, &repo, &["install", "tool"]);
        assert!(output.contains("Installed tool 2.0.0"), "{output}");
        assert_eq!(fs.read_file(r"C:\ProgramData\wpkg\bin\tool.exe").unwrap(), b"MZ 2.0.0");
        let output = run(&mut fs, &repo, &["install", "tool@1"]);
        assert!(output.contains("Installed tool 1.1.0"), "a version line picks its newest: {output}");
        assert!(run(&mut fs, &repo, &["info", "tool"]).contains("2.0.0 (x64), newest upstream release\nA tool\n"));
        assert_eq!(run(&mut fs, &repo, &["search", "to"]), "tool - A tool\n");
        // A release npm publishes no SHA-512 for is refused.
        let mut repo = MemoryRepo::default();
        npm_tool(&mut repo, &["1.0.0"], false);
        let error = execute(&mut WinFs::ephemeral_runner(), &repo, "x64", &args(&["install", "tool"])).unwrap_err();
        assert!(error.contains("npm publishes no SHA-512"), "{error}");
        // A tampered archive fails verification.
        let mut repo = MemoryRepo::default();
        npm_tool(&mut repo, &["1.0.0"], true);
        repo.add("https://registry.npmjs.org/tool-windows-x64/-/tool-windows-x64-1.0.0.tgz", b"not it".to_vec());
        let error = execute(&mut WinFs::ephemeral_runner(), &repo, "x64", &args(&["install", "tool"])).unwrap_err();
        assert!(error.contains("SHA-512 mismatch"), "{error}");
    }

    #[test]
    fn nuget_and_github_upstreams_resolve_with_published_hashes() {
        let mut repo = MemoryRepo::default();
        repo.add("packages/index", "fmt\ncli\n");
        repo.add(
            "packages/fmt/upstream.wpkg",
            "name = \"fmt\"\nupstream = \"nuget\"\nx64 = \"Fmt\"\nbin = [\"fmt=tools/any/Fmt.dll\"]\nrun = \"dotnet\"\n",
        );
        let nupkg = zip_stored(vec![("tools/any/Fmt.dll", b"MZ dll")]);
        repo.add("https://api.nuget.org/v3-flatcontainer/fmt/index.json", br#"{"versions":["1.0.0","1.2.0","2.0.0-beta"]}"#.to_vec());
        repo.add(
            "https://api.nuget.org/v3/registration5-semver1/fmt/1.2.0.json",
            br#"{"catalogEntry":"https://api.nuget.org/v3/catalog0/data/fmt.1.2.0.json"}"#.to_vec(),
        );
        repo.add(
            "https://api.nuget.org/v3/catalog0/data/fmt.1.2.0.json",
            serde_json::to_vec(&serde_json::json!({"packageHash": sha512_base64(&nupkg), "packageHashAlgorithm": "SHA512"})).unwrap(),
        );
        repo.add("https://api.nuget.org/v3-flatcontainer/fmt/1.2.0/fmt.1.2.0.nupkg", nupkg);
        let mut fs = WinFs::ephemeral_runner();
        let output = run(&mut fs, &repo, &["install", "fmt"]);
        assert!(output.contains("Installed fmt 1.2.0"), "prereleases are skipped: {output}");
        // A launched file is exposed as a shim that runs it through `run`.
        let shim = String::from_utf8(fs.read_file(r"C:\ProgramData\wpkg\bin\fmt.cmd").unwrap()).unwrap();
        assert_eq!(
            shim,
            "@rem wpkg-target \"C:\\Program Files\\fmt\\current\\tools\\any\\Fmt.dll\"\r\n@setlocal\r\n@dotnet \"C:\\Program Files\\fmt\\current\\tools\\any\\Fmt.dll\" %*\r\n"
        );

        repo.add(
            "packages/cli/upstream.wpkg",
            "name = \"cli\"\nupstream = \"github\"\nrepo = \"o/cli\"\nx64 = \"cli-{version}-win64.zip\"\nbin = [\"{stem}/cli.exe\"]\nenv = [\"CLI_HOME={dir}\"]\n",
        );
        let zip = zip_stored(vec![("cli-3.1-win64/cli.exe", b"MZ cli")]);
        let release = |digest: Option<String>| {
            let mut asset = serde_json::json!({"name": "cli-3.1-win64.zip", "browser_download_url": "https://github.com/o/cli/releases/download/v3.1/cli-3.1-win64.zip"});
            if let Some(digest) = digest {
                asset["digest"] = digest.into();
            }
            serde_json::to_vec(&serde_json::json!({"tag_name": "v3.1", "assets": [asset]})).unwrap()
        };
        repo.add("https://api.github.com/repos/o/cli/releases/latest", release(None));
        let error = execute(&mut fs, &repo, "x64", &args(&["install", "cli"])).unwrap_err();
        assert!(error.contains("GitHub publishes no SHA-256"), "{error}");
        repo.add("https://api.github.com/repos/o/cli/releases/latest", release(Some(format!("sha256:{}", install::sha256_hex(&zip)))));
        repo.add("https://github.com/o/cli/releases/download/v3.1/cli-3.1-win64.zip", zip);
        let output = run(&mut fs, &repo, &["install", "cli"]);
        assert!(output.contains("Installed cli 3.1"), "{output}");
        let shim = String::from_utf8(fs.read_file(r"C:\ProgramData\wpkg\bin\cli.cmd").unwrap()).unwrap();
        assert!(shim.contains("@set \"CLI_HOME=C:\\Program Files\\cli\\current\"\r\n"), "{shim}");
        assert!(shim.ends_with("@\"C:\\Program Files\\cli\\current\\cli-3.1-win64\\cli.exe\" %*\r\n"), "{shim}");
        // Removing the package removes its shims.
        run(&mut fs, &repo, &["remove", "cli"]);
        assert!(!fs.exists(r"C:\ProgramData\wpkg\bin\cli.cmd"));
    }

    #[test]
    fn dependencies_pick_pinned_version_lines_side_by_side() {
        let mut repo = MemoryRepo::default();
        repo.package("dotnet", "8.0.5", "x64", &["dotnet.exe"], &[]);
        repo.package("dotnet", "10.0.1", "x64", &["dotnet.exe"], &[]);
        repo.package("dotnet", "10.0.3", "x64", &["dotnet.exe"], &[]);
        repo.package("app", "1.0", "x64", &["app.exe"], &["dotnet@10"]);
        repo.package("old", "1.0", "x64", &["old.exe"], &["dotnet@6"]);
        repo.add("packages/index", "app\ndotnet\nold\n");
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "dotnet@8"]);
        let output = run(&mut fs, &repo, &["install", "app"]);
        assert!(output.contains("Installed dotnet 10.0.3"), "the newest pinned 10.x: {output}");
        assert_eq!(installed_versions(&fs, "dotnet"), ["8.0.5", "10.0.3"], "beside the installed 8");
        assert_eq!(default_version(&fs, "dotnet"), "8.0.5", "a dependency never moves the default");
        let output = run(&mut fs, &repo, &["install", "app"]);
        assert!(!output.contains("Installed dotnet"), "an installed match is reused: {output}");
        let error = execute(&mut fs, &repo, "x64", &args(&["install", "nope"])).unwrap_err();
        assert_eq!(error, "wpkg: no package named nope (see `wpkg search`)");
        let error = execute(&mut fs, &repo, "x64", &args(&["install", "old"])).unwrap_err();
        assert!(error.contains("no dotnet version matches 6") && error.contains("needed by old"), "{error}");
        // Removing a package others need says so.
        let output = run(&mut fs, &repo, &["remove", "dotnet@10.0.3"]);
        assert!(output.contains("⚠️ app depend on dotnet"), "{output}");
    }

    #[test]
    fn refresh_replaces_the_registry_copy_and_reports_changes() {
        let mut published = MemoryRepo::default();
        published.add("packages/index", "tool\n");
        published.add("packages/tool/upstream.wpkg", "name = \"tool\"\nupstream = \"npm\"\nx64 = \"t\"\nbin = [\"t.exe\"]\n");
        let mut entries: Vec<(&str, &[u8])> = published.files.iter().map(|(path, bytes)| (path.as_str(), bytes.as_slice())).collect();
        entries.sort();
        let zip = zip_stored(entries);
        let mut repo = MemoryRepo::default();
        repo.package("old", "1.0", "x64", &["old.exe"], &[]);
        repo.add("packages/index", "old\n");
        repo.add(REGISTRY_URL, zip.clone());
        let mut fs = WinFs::ephemeral_runner();
        let output = run(&mut fs, &repo, &["refresh"]);
        assert_eq!(output, "✅ Package list refreshed:\n  - old\n  + tool (upstream)\n");
        assert_eq!(fs.read_file(LOCAL_REGISTRY).unwrap(), zip);
        // The guest's copy is what wpkg works from afterwards.
        let local = open_registry(&mut fs, &mut |_| {}).unwrap();
        assert_eq!(repository_names(&local).unwrap(), ["tool"]);
        // A download that is not a registry leaves the copy alone.
        repo.add(REGISTRY_URL, b"not a zip".to_vec());
        assert!(execute(&mut fs, &repo, "x64", &args(&["refresh"])).is_err());
        assert_eq!(fs.read_file(LOCAL_REGISTRY).unwrap(), zip);
    }

    #[test]
    fn npm_tarballs_install_like_zip_packages() {
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1.0", "x64", &["package/bin/tool.exe"], &[]);
        let archive = npm_tarball("package/bin/tool.exe", b"MZ npm");
        let url = "https://registry.invalid/tool/-/tool-windows-x64-1.0.tgz";
        let checksum = install::sha256_hex(&archive);
        repo.add(url, archive);
        repo.add(
            "packages/tool/1.0.wpkg",
            format!("name = \"tool\"\nversion = \"1.0\"\narch = \"x64\"\nurl = \"{url}\"\nsha256 = \"{checksum}\"\nbin = [\"package/bin/tool.exe\"]\n"),
        );
        let mut fs = WinFs::ephemeral_runner();
        let output = run(&mut fs, &repo, &["install", "tool"]);
        assert!(output.contains("Installed tool 1.0"), "{output}");
        assert_eq!(fs.read_file(r"C:\ProgramData\wpkg\bin\tool.exe").unwrap(), b"MZ npm");
        assert!(fs.is_file(r"C:\ProgramData\wpkg\cache\tool#1.0#x64.tgz"), "cached as a tarball");
        assert_eq!(archive_kind("https://x/a.tar.gz?download=1"), "tgz");
        assert_eq!(archive_kind("https://x/a.7z"), "7z");
        assert_eq!(archive_kind("https://x/a.nupkg"), "zip");
    }

    #[test]
    fn versions_install_side_by_side_and_the_first_one_is_the_default() {
        let mut repo = MemoryRepo::default();
        repo.package("python", "3.13.7", "x64", &["python.exe"], &[]);
        repo.package("python", "3.14.0", "x64", &["python.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();

        let output = run(&mut fs, &repo, &["install", "python@3.13.7"]);
        assert!(output.contains("Installed python 3.13.7"), "{output}");
        assert_eq!(
            fs.read_file(r"C:\Program Files\python\3.13.7\python.exe")
                .unwrap(),
            b"MZ 3.13.7"
        );
        assert_eq!(
            fs.read_file(r"C:\ProgramData\wpkg\bin\python.exe").unwrap(),
            b"MZ 3.13.7"
        );
        let resolved = fs
            .resolve_links(r"C:\ProgramData\wpkg\bin\python.exe")
            .unwrap();
        assert!(
            resolved.eq_ignore_ascii_case(r"C:\Program Files\python\3.13.7\python.exe"),
            "{resolved}"
        );

        let output = run(&mut fs, &repo, &["install", "python"]);
        assert!(output.contains("Installed python 3.14.0"), "{output}");
        assert!(
            output.contains("Default python is still 3.13.7; run `wpkg default python 3.14.0`"),
            "{output}"
        );
        assert_eq!(installed_versions(&fs, "python"), ["3.13.7", "3.14.0"]);
        assert_eq!(default_version(&fs, "python"), "3.13.7");
        assert_eq!(
            fs.read_file(r"C:\ProgramData\wpkg\bin\python.exe").unwrap(),
            b"MZ 3.13.7"
        );

        let list = run(&mut fs, &repo, &["list", "python"]);
        assert_eq!(
            list,
            "* python 3.13.7 (x64) C:\\Program Files\\python\\3.13.7\n  python 3.14.0 (x64) C:\\Program Files\\python\\3.14.0\n"
        );
        let output = run(&mut fs, &repo, &["install", "python@3.14.0"]);
        assert!(output.contains("is already installed"), "{output}");
    }

    #[test]
    fn batch_commands_are_exposed_as_shims_that_keep_their_own_directory() {
        let mut repo = MemoryRepo::default();
        repo.package("nodejs", "24.21.0", "x64", &["node/node.exe", "node/npm.cmd"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "nodejs"]);
        let shim = r"C:\ProgramData\wpkg\bin\npm.cmd";
        assert!(!fs.is_symlink(shim));
        // `%~dp0` inside npm.cmd must name the Node.js directory, so the shim
        // runs the batch file at its own path instead of linking to it.
        assert_eq!(
            fs.read_file(shim).unwrap(),
            b"@\"C:\\Program Files\\nodejs\\current\\node\\npm.cmd\" %*\r\n"
        );
        assert!(fs.is_symlink(r"C:\ProgramData\wpkg\bin\node.exe"));

        // Another package cannot take over the shim; removing nodejs removes it.
        repo.package("other", "1.0.0", "x64", &["npm.cmd"], &[]);
        let error = execute(&mut fs, &repo, "x64", &args(&["install", "other"])).unwrap_err();
        assert!(error.contains(r"binary path already exists"), "{error}");
        run(&mut fs, &repo, &["remove", "nodejs"]);
        assert!(!fs.exists(shim));
        run(&mut fs, &repo, &["install", "other"]);
        assert_eq!(
            fs.read_file(shim).unwrap(),
            b"@\"C:\\Program Files\\other\\current\\npm.cmd\" %*\r\n"
        );
    }

    #[test]
    fn shim_targets_round_trip_and_reject_other_batch_files() {
        let target = r"C:\Program Files\nodejs\current\npm.cmd";
        assert_eq!(super::shim_target(&super::shim_contents(target, None, &[])).as_deref(), Some(target));
        assert_eq!(super::shim_target(b"@echo off\r\nnode %*\r\n"), None);
        assert_eq!(super::shim_target(b"@\"a\" b\" %*"), None);
        assert!(super::validate_bin("bin/tool.cmd", false).is_ok());
        assert!(super::validate_bin("bin/tool.BAT", false).is_ok());
        assert!(super::validate_bin("bin/tool.ps1", false).is_err());
    }

    #[test]
    fn default_switches_the_current_link_and_every_bin_command() {
        let mut repo = MemoryRepo::default();
        repo.package("nodejs", "24.21.0", "x64", &["node.exe"], &[]);
        repo.package("nodejs", "26.1.0", "x64", &["node.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "nodejs@24"]);
        run(&mut fs, &repo, &["install", "nodejs@26"]);
        assert_eq!(
            run(&mut fs, &repo, &["default", "nodejs"]),
            "nodejs 24.21.0\n"
        );

        let output = run(&mut fs, &repo, &["default", "nodejs", "26"]);
        assert!(output.contains("nodejs default is now 26.1.0"), "{output}");
        assert_eq!(
            fs.read_file(r"C:\ProgramData\wpkg\bin\node.exe").unwrap(),
            b"MZ 26.1.0"
        );
        let current = fs
            .symlink_target(r"C:\Program Files\nodejs\current")
            .unwrap();
        assert!(
            current.eq_ignore_ascii_case(r"C:\Program Files\nodejs\26.1.0"),
            "{current}"
        );
        assert!(run(&mut fs, &repo, &["list"]).contains("* nodejs 26.1.0"));

        let error =
            execute(&mut fs, &repo, "x64", &args(&["default", "nodejs", "22"])).unwrap_err();
        assert!(error.contains("wpkg install nodejs@22"), "{error}");
        assert_eq!(default_version(&fs, "nodejs"), "26.1.0");
    }

    #[test]
    fn version_prefix_selects_the_newest_release_in_that_line() {
        let mut repo = MemoryRepo::default();
        for version in ["24.9.0", "24.10.0", "26.0.0", "260.0.0"] {
            repo.package("nodejs", version, "x64", &["node.exe"], &[]);
        }
        let mut fs = WinFs::ephemeral_runner();
        assert!(run(&mut fs, &repo, &["install", "nodejs@26"]).contains("nodejs 26.0.0"));
        assert!(run(&mut fs, &repo, &["install", "nodejs@24"]).contains("nodejs 24.10.0"));
        assert!(run(&mut fs, &repo, &["info", "nodejs@24.9"]).contains("nodejs 24.9.0 (x64)"));
        let error = execute(&mut fs, &repo, "x64", &args(&["install", "nodejs@25"])).unwrap_err();
        assert!(error.contains("no nodejs version matches 25"), "{error}");
    }

    #[test]
    fn version_prefix_skips_releases_without_a_manifest_for_the_host_arch() {
        let mut repo = MemoryRepo::default();
        repo.package("tool", "2.1", "x64", &["tool.exe"], &[]);
        repo.package("tool", "2.2", "arm64", &["tool.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        assert!(run(&mut fs, &repo, &["install", "tool@2"]).contains("Installed tool 2.1 (x64)"));
    }

    #[test]
    fn version_ordering_and_matching_are_numeric_and_component_aware() {
        let mut versions = vec!["3.10.0", "3.9.1", "3.9", "10.0", "3.10.0-rc1"];
        versions.sort_by(|left, right| compare_versions(left, right));
        assert_eq!(versions, ["3.9", "3.9.1", "3.10.0", "3.10.0-rc1", "10.0"]);
        assert!(version_matches("26.1.0", "26"));
        assert!(version_matches("26.1.0", "26.1"));
        assert!(version_matches("26-rc1", "26"));
        assert!(!version_matches("260.0.0", "26"));
        assert!(!version_matches("2.6", "26"));
    }

    #[test]
    fn version_names_cannot_collide_with_package_directory_entries() {
        for version in ["current", "CURRENT", ".staging-1", "..", "1/2", ""] {
            assert!(normalize_version(version).is_err(), "accepted {version:?}");
        }
    }

    #[test]
    fn installs_verified_7z_archives_directly_into_guest_winfs() {
        let archive = include_bytes!("../tests/artifacts/packages/wpkg-7z-fixture.7z");
        let url = "https://packages.invalid/portable-tool.7z?download=1";
        let checksum = install::sha256_hex(archive);
        let mut repo = MemoryRepo::default();
        repo.add("packages/tool/latest", "1.0");
        repo.add(url, archive.to_vec());
        repo.add(
            "packages/tool/1.0.wpkg",
            format!(
                "name = \"tool\"\nversion = \"1.0\"\narch = \"x64\"\nurl = \"{url}\"\nsha256 = \"{checksum}\"\nbin = [\"bin/tool.exe\"]\n"
            ),
        );

        let mut fs = WinFs::ephemeral_runner();
        let mut progress = Vec::new();
        let output = execute_with_progress(
            &mut fs,
            &repo,
            "x64",
            &args(&["install", "tool"]),
            &mut |message| progress.push(message.to_string()),
        )
        .unwrap();
        assert!(progress[0].contains("⬇️ Downloading tool 1.0"));
        // The finished bar is a permanent line; updates before it are
        // transient (`\r`).
        let bar = progress
            .iter()
            .find(|message| message.ends_with('\n') && message.contains('█'))
            .expect("a finished download bar");
        assert!(crate::progress::strip_ansi(bar).contains(&"█".repeat(30)), "{bar:?}");
        assert!(progress
            .iter()
            .any(|message| message.contains("🔎 Verifying")));
        assert!(progress
            .iter()
            .any(|message| message.contains("🛠️ Installing")));
        assert!(String::from_utf8_lossy(&output).contains("✅ Installed tool 1.0"));
        assert_eq!(
            fs.read_file(r"C:\Program Files\tool\1.0\bin\tool.exe")
                .unwrap(),
            b"MZ 7z fixture\n"
        );
        assert_eq!(
            fs.read_file(r"C:\ProgramData\wpkg\bin\tool.exe").unwrap(),
            b"MZ 7z fixture\n"
        );
        assert_eq!(installed_versions(&fs, "tool"), ["1.0"]);
    }

    #[test]
    fn rejects_checksum_mismatch_and_unsafe_zip_paths() {
        let mut repo = MemoryRepo::default();
        repo.package("bad", "v1+opaque", "x64", &["bad.exe"], &[]);
        let manifest_path = "packages/bad/v1+opaque.wpkg";
        let manifest = String::from_utf8(repo.files[manifest_path].clone())
            .unwrap()
            .replace(
                &install::sha256_hex(&repo.files["https://packages.invalid/bad-v1+opaque-x64.zip"]),
                &"0".repeat(64),
            );
        repo.add(manifest_path, manifest);
        let mut fs = WinFs::ephemeral_runner();
        assert!(execute(&mut fs, &repo, "x64", &args(&["install", "bad"]))
            .unwrap_err()
            .contains("SHA-256 mismatch"));

        repo.package("escape", "v1", "x64", &["ok.exe"], &[]);
        let escape = zip_stored(vec![("../../outside.exe", b"MZ")]);
        let url = "https://packages.invalid/escape-v1-x64.zip";
        let manifest_path = "packages/escape/v1.wpkg";
        let old_manifest = String::from_utf8(repo.files[manifest_path].clone()).unwrap();
        let old_hash = install::sha256_hex(&repo.files[url]);
        let new_hash = install::sha256_hex(&escape);
        repo.add(url, escape);
        repo.add(manifest_path, old_manifest.replace(&old_hash, &new_hash));
        let error = execute(&mut fs, &repo, "x64", &args(&["install", "escape"])).unwrap_err();
        assert!(error.contains("unsafe archive path"), "{error}");
        assert!(!fs.exists(r"C:\outside.exe"));
        assert!(!fs.exists(r"C:\Program Files\escape"));
        assert!(load_database(&fs).unwrap().is_empty());
    }

    #[test]
    fn failed_staging_of_a_second_version_keeps_the_installed_one() {
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1", "x64", &["tool.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "tool"]);
        repo.package("tool", "2", "x64", &["tool.exe"], &[]);
        let manifest = String::from_utf8(repo.files["packages/tool/2.wpkg"].clone())
            .unwrap()
            .replace("\"tool.exe\"", "\"missing.exe\"");
        repo.add("packages/tool/2.wpkg", manifest);
        let error = execute(&mut fs, &repo, "x64", &args(&["install", "tool@2"])).unwrap_err();
        assert!(error.contains("missing from package archive"), "{error}");
        assert!(!fs.exists(r"C:\Program Files\tool\.staging-2"));
        assert!(!fs.exists(r"C:\Program Files\tool\2"));
        assert_eq!(installed_versions(&fs, "tool"), ["1"]);
        assert_eq!(
            fs.read_file(r"C:\ProgramData\wpkg\bin\tool.exe").unwrap(),
            b"MZ 1"
        );
    }

    #[test]
    fn archive_paths_reject_host_and_windows_traversal_forms() {
        for path in [
            "../outside.exe",
            "..\\outside.exe",
            "/etc/passwd",
            "C:\\Windows\\system.ini",
            "folder/../../outside.exe",
        ] {
            assert!(safe_member(path).is_err(), "accepted unsafe path {path:?}");
        }
        assert_eq!(safe_member("bin/tool.exe").unwrap(), "bin/tool.exe");
    }

    #[test]
    fn any_installed_version_satisfies_a_dependency() {
        let mut repo = MemoryRepo::default();
        repo.package("base", "v1", "x64", &["base.exe"], &[]);
        repo.package("base", "v2", "x64", &["base.exe"], &[]);
        repo.package("tool", "nightly-build", "x64", &["tool.exe"], &["base"]);
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "base@v1"]);
        run(&mut fs, &repo, &["install", "tool"]);
        assert_eq!(installed_versions(&fs, "base"), ["v1"]);
        assert_eq!(installed_versions(&fs, "tool"), ["nightly-build"]);

        let mut fresh = WinFs::ephemeral_runner();
        run(&mut fresh, &repo, &["install", "tool"]);
        assert_eq!(installed_versions(&fresh, "base"), ["v2"]);
    }

    #[test]
    fn upgrade_installs_beside_and_moves_only_a_default_that_tracked_the_newest() {
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1", "x64", &["tool.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "tool"]);

        repo.package("tool", "2", "x64", &["tool.exe"], &[]);
        let output = run(&mut fs, &repo, &["upgrade", "tool"]);
        assert!(output.contains("tool default is now 2"), "{output}");
        assert!(!output.contains("is still"), "{output}");
        assert_eq!(installed_versions(&fs, "tool"), ["1", "2"]);
        assert_eq!(
            fs.read_file(r"C:\ProgramData\wpkg\bin\tool.exe").unwrap(),
            b"MZ 2"
        );

        run(&mut fs, &repo, &["default", "tool", "1"]);
        repo.package("tool", "3", "x64", &["tool.exe"], &[]);
        let output = run(&mut fs, &repo, &["upgrade"]);
        assert!(!output.contains("default is now"), "{output}");
        assert_eq!(installed_versions(&fs, "tool"), ["1", "2", "3"]);
        assert_eq!(default_version(&fs, "tool"), "1");
        assert!(run(&mut fs, &repo, &["upgrade", "tool"]).contains("tool 3 is up to date"));
    }

    #[test]
    fn remove_takes_one_version_or_the_whole_package() {
        let mut repo = MemoryRepo::default();
        for version in ["1.1", "1.2", "2.0"] {
            repo.package("tool", version, "x64", &["tool.exe"], &[]);
        }
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "tool@2.0"]);
        run(&mut fs, &repo, &["install", "tool@1.1"]);
        run(&mut fs, &repo, &["install", "tool@1.2"]);

        let error = execute(&mut fs, &repo, "x64", &args(&["remove", "tool@2"])).unwrap_err();
        assert!(error.contains("is the default"), "{error}");
        let error = execute(&mut fs, &repo, "x64", &args(&["remove", "tool@1"])).unwrap_err();
        assert!(
            error.contains("several installed versions (1.2, 1.1)"),
            "{error}"
        );
        let error = execute(&mut fs, &repo, "x64", &args(&["remove", "tool@3"])).unwrap_err();
        assert!(error.contains("tool 3 is not installed"), "{error}");

        assert_eq!(
            run(&mut fs, &repo, &["remove", "tool@1.1"]),
            "Removed tool 1.1\n"
        );
        assert!(!fs.exists(r"C:\Program Files\tool\1.1"));
        assert_eq!(installed_versions(&fs, "tool"), ["1.2", "2.0"]);
        assert_eq!(
            fs.read_file(r"C:\ProgramData\wpkg\bin\tool.exe").unwrap(),
            b"MZ 2.0"
        );

        assert_eq!(run(&mut fs, &repo, &["remove", "tool"]), "Removed tool\n");
        assert!(load_database(&fs).unwrap().is_empty());
        assert!(
            !fs.exists(r"C:\ProgramData\wpkg\bin\tool.exe")
                && !fs.is_symlink(r"C:\ProgramData\wpkg\bin\tool.exe")
        );
        assert!(!fs.exists(r"C:\Program Files\tool"));
        assert!(fs.snapshot_symlinks().is_empty());
    }

    #[test]
    fn remove_keeps_files_it_did_not_install_in_program_files() {
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1", "x64", &["tool.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\Program Files\tool").unwrap();
        fs.write_file(r"C:\Program Files\tool\settings.ini", b"keep".to_vec())
            .unwrap();
        run(&mut fs, &repo, &["install", "tool"]);
        run(&mut fs, &repo, &["remove", "tool"]);
        assert!(!fs.exists(r"C:\Program Files\tool\1"));
        assert!(!fs.exists(r"C:\Program Files\tool\current"));
        assert_eq!(
            fs.read_file(r"C:\Program Files\tool\settings.ini").unwrap(),
            b"keep"
        );
        assert!(fs.is_dir(r"C:\Program Files"));
    }

    #[test]
    fn installed_versions_are_listed_under_the_windows_uninstall_key() {
        use crate::winreg::{Hive, Registry};
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1.0", "x64", &["tool.exe"], &[]);
        repo.package("tool", "2.0", "x64", &["tool.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "tool@1"]);
        run(&mut fs, &repo, &["install", "tool@2"]);

        let registry = Registry::load(&fs).unwrap();
        let key = registry
            .key(Hive::LocalMachine, &uninstall_key("tool", "1.0"))
            .expect("uninstall entry");
        let text = |name: &str| key.value(name).and_then(|value| value.as_str());
        assert_eq!(text("DisplayName").as_deref(), Some("tool 1.0"));
        assert_eq!(text("DisplayVersion").as_deref(), Some("1.0"));
        assert_eq!(text("Publisher").as_deref(), Some("wpkg"));
        assert_eq!(
            text("InstallLocation").as_deref(),
            Some(r"C:\Program Files\tool\1.0")
        );
        assert_eq!(
            text("UninstallString").as_deref(),
            Some("wpkg remove tool@1.0")
        );
        // Each archive here holds one 6-byte file: rounded up to 1 KiB.
        assert_eq!(key.value("EstimatedSize").unwrap().as_dword(), Some(1));
        assert_eq!(key.value("NoModify").unwrap().as_dword(), Some(1));
        assert!(registry
            .key(Hive::LocalMachine, &uninstall_key("tool", "2.0"))
            .is_some());

        run(&mut fs, &repo, &["remove", "tool@2"]);
        let registry = Registry::load(&fs).unwrap();
        assert!(registry
            .key(Hive::LocalMachine, &uninstall_key("tool", "2.0"))
            .is_none());
        assert!(registry
            .key(Hive::LocalMachine, &uninstall_key("tool", "1.0"))
            .is_some());

        run(&mut fs, &repo, &["remove", "tool"]);
        let registry = Registry::load(&fs).unwrap();
        let uninstall = registry.key(Hive::LocalMachine, UNINSTALL_KEY).unwrap();
        assert!(uninstall.subkey_names().is_empty());
    }

    fn install_with_progress(fs: &mut WinFs, repo: &MemoryRepo, spec: &str) -> Vec<String> {
        let mut progress = Vec::new();
        execute_with_progress(fs, repo, "x64", &args(&["install", spec]), &mut |message| {
            progress.push(message.to_string())
        })
        .unwrap();
        progress
    }

    #[test]
    fn reinstalling_a_version_uses_the_verified_cache_without_downloading() {
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1.0", "x64", &["tool.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        let progress = install_with_progress(&mut fs, &repo, "tool");
        assert!(progress[0].contains("Downloading tool 1.0"), "{progress:?}");
        let cached = r"C:\ProgramData\wpkg\cache\tool#1.0#x64.zip";
        assert_eq!(
            fs.read_file(cached).unwrap(),
            repo.files["https://packages.invalid/tool-1.0-x64.zip"]
        );

        // Offline: the archive URL is gone, yet the reinstall succeeds.
        run(&mut fs, &repo, &["remove", "tool"]);
        repo.files
            .remove("https://packages.invalid/tool-1.0-x64.zip");
        let progress = install_with_progress(&mut fs, &repo, "tool");
        assert_eq!(progress[0], "📦 Using cached tool 1.0\n");
        assert!(!progress.iter().any(|line| line.contains("Downloading")));
        assert_eq!(
            fs.read_file(r"C:\ProgramData\wpkg\bin\tool.exe").unwrap(),
            b"MZ 1.0"
        );
    }

    /// Point the shared download cache at a fresh directory for this test.
    fn with_host_cache() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "wpkg-host-cache-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        super::TEST_HOST_CACHE.with(|cache| *cache.borrow_mut() = Some(dir.clone()));
        dir
    }

    #[test]
    fn a_new_disk_installs_from_the_shared_download_cache() {
        let host = with_host_cache();
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1.0", "x64", &["tool.exe"], &[]);
        let url = "https://packages.invalid/tool-1.0-x64.zip";
        let archive = repo.files[url].clone();
        let mut first = WinFs::ephemeral_runner();
        let progress = install_with_progress(&mut first, &repo, "tool");
        assert!(progress[0].contains("Downloading tool 1.0"), "{progress:?}");
        let key = install::sha256_hex(&archive).to_ascii_lowercase();
        assert_eq!(std::fs::read(host.join(&key)).unwrap(), archive);
        assert_eq!(std::fs::read_dir(&host).unwrap().count(), 1); // no partial file

        // A fresh disk (a new session) with the network gone.
        repo.files.remove(url);
        let mut second = WinFs::ephemeral_runner();
        let progress = install_with_progress(&mut second, &repo, "tool");
        assert!(progress[0].starts_with("📦 Using downloaded tool 1.0"), "{progress:?}");
        assert!(!progress.iter().any(|line| line.contains("Downloading")));
        assert_eq!(
            second.read_file(r"C:\ProgramData\wpkg\bin\tool.exe").unwrap(),
            b"MZ 1.0"
        );
        // The disk's own cache is filled too, for snapshots and offline use.
        assert_eq!(
            second.read_file(r"C:\ProgramData\wpkg\cache\tool#1.0#x64.zip").unwrap(),
            archive
        );

        // A damaged shared copy is ignored and replaced by a new download.
        std::fs::write(host.join(&key), b"damaged").unwrap();
        repo.add(url, archive.clone());
        let mut third = WinFs::ephemeral_runner();
        let progress = install_with_progress(&mut third, &repo, "tool");
        assert!(progress[0].contains("Downloading tool 1.0"), "{progress:?}");
        assert_eq!(std::fs::read(host.join(&key)).unwrap(), archive);
        std::fs::remove_dir_all(host).ok();
    }

    #[test]
    fn a_damaged_cached_archive_is_downloaded_again_and_replaced() {
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1.0", "x64", &["tool.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        let cached = r"C:\ProgramData\wpkg\cache\tool#1.0#x64.zip";
        fs.mkdir(r"C:\ProgramData\wpkg\cache").unwrap();
        fs.write_file(cached, b"tampered".to_vec()).unwrap();
        let progress = install_with_progress(&mut fs, &repo, "tool");
        assert!(progress[0].contains("Downloading"), "{progress:?}");
        assert_eq!(
            fs.read_file(cached).unwrap(),
            repo.files["https://packages.invalid/tool-1.0-x64.zip"]
        );
    }

    #[test]
    fn archives_that_fail_verification_are_not_cached() {
        let mut repo = MemoryRepo::default();
        repo.package("bad", "1", "x64", &["bad.exe"], &[]);
        repo.add(
            "https://packages.invalid/bad-1-x64.zip",
            b"not the archive".to_vec(),
        );
        let mut fs = WinFs::ephemeral_runner();
        assert!(execute(&mut fs, &repo, "x64", &args(&["install", "bad"]))
            .unwrap_err()
            .contains("SHA-256 mismatch"));
        assert!(!fs.exists(r"C:\ProgramData\wpkg\cache\bad#1#x64.zip"));
    }

    #[test]
    fn cache_lists_and_cleans_archives_per_package() {
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1.0", "x64", &["tool.exe"], &[]);
        repo.package("tool", "2.0", "x64", &["tool.exe"], &[]);
        repo.package("tool-extra", "1.0", "x64", &["extra.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        assert_eq!(run(&mut fs, &repo, &["cache"]), "Cache is empty.\n");
        run(&mut fs, &repo, &["install", "tool@1"]);
        run(&mut fs, &repo, &["install", "tool@2"]);
        run(&mut fs, &repo, &["install", "tool-extra"]);
        fs.write_file(r"C:\ProgramData\wpkg\cache\notes.txt", b"keep".to_vec())
            .unwrap();

        let listing = run(&mut fs, &repo, &["cache"]);
        let lines: Vec<_> = listing.lines().collect();
        assert!(lines[0].starts_with("tool 1.0 (x64) "), "{listing}");
        assert!(lines[1].starts_with("tool 2.0 (x64) "), "{listing}");
        assert!(lines[2].starts_with("tool-extra 1.0 (x64) "), "{listing}");
        assert!(
            lines[3].starts_with("Total: ") && lines[3].contains(" in 3 archives at "),
            "{listing}"
        );

        // `tool` does not match `tool-extra`.
        let cleaned = run(&mut fs, &repo, &["cache", "clean", "tool"]);
        assert!(
            cleaned.starts_with("Removed 2 cached archives ("),
            "{cleaned}"
        );
        assert!(run(&mut fs, &repo, &["cache"]).starts_with("tool-extra 1.0"));
        let cleaned = run(&mut fs, &repo, &["cache", "clean"]);
        assert!(
            cleaned.starts_with("Removed 1 cached archive ("),
            "{cleaned}"
        );
        assert_eq!(run(&mut fs, &repo, &["cache"]), "Cache is empty.\n");
        assert!(fs.is_file(r"C:\ProgramData\wpkg\cache\notes.txt"));
        // Installed packages are unaffected.
        assert!(fs.is_file(r"C:\ProgramData\wpkg\bin\tool.exe"));
        assert!(execute(&mut fs, &repo, "x64", &args(&["cache", "prune"])).is_err());
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn removing_the_last_version_by_name_removes_the_package() {
        let mut repo = MemoryRepo::default();
        repo.package("tool", "1", "x64", &["tool.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "tool"]);
        assert_eq!(
            run(&mut fs, &repo, &["remove", "tool@1"]),
            "Removed tool 1\n"
        );
        assert!(load_database(&fs).unwrap().is_empty());
        assert!(!fs.exists(r"C:\Program Files\tool"));
    }

    #[test]
    fn packages_cannot_take_over_each_others_commands() {
        let mut repo = MemoryRepo::default();
        repo.package("first", "1", "x64", &["tool.exe"], &[]);
        repo.package("second", "1", "x64", &["bin/tool.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        run(&mut fs, &repo, &["install", "first"]);
        let error = execute(&mut fs, &repo, "x64", &args(&["install", "second"])).unwrap_err();
        assert!(
            error.contains(r"binary path already exists: C:\ProgramData\wpkg\bin\tool.exe"),
            "{error}"
        );
        assert!(!fs.exists(r"C:\Program Files\second"));
        assert_eq!(
            fs.read_file(r"C:\ProgramData\wpkg\bin\tool.exe").unwrap(),
            b"MZ 1"
        );

        run(&mut fs, &repo, &["remove", "first"]);
        run(&mut fs, &repo, &["install", "second"]);
        assert!(fs.is_file(r"C:\ProgramData\wpkg\bin\tool.exe"));
    }

    #[test]
    fn selects_architecture_specific_manifest_when_default_arch_differs() {
        let mut repo = MemoryRepo::default();
        repo.package("portable", "1", "x64", &["portable.exe"], &[]);
        repo.package("portable", "1", "arm64", &["portable.exe"], &[]);
        let arm = repo.files.remove("packages/portable/1.wpkg").unwrap();
        repo.add("packages/portable/1-arm64.wpkg", arm);
        let mut fs = WinFs::ephemeral_runner();
        execute(&mut fs, &repo, "arm64", &args(&["install", "portable"])).unwrap();
        assert_eq!(
            package(&load_database(&fs).unwrap(), "portable").versions[0].arch,
            "arm64"
        );
    }

    #[test]
    fn lists_and_searches_registry_and_installed_packages() {
        let mut repo = MemoryRepo::default();
        repo.add("packages/index", "python\nripgrep\n");
        repo.package("ripgrep", "15.1.0", "x64", &["rg.exe"], &[]);
        let mut fs = WinFs::ephemeral_runner();
        assert_eq!(run(&mut fs, &repo, &["list"]), "No packages installed.\n");
        assert_eq!(run(&mut fs, &repo, &["search", "rip"]), "ripgrep\n");
        run(&mut fs, &repo, &["install", "ripgrep"]);
        assert!(run(&mut fs, &repo, &["list"]).contains("* ripgrep 15.1.0 (x64)"));
        assert_eq!(
            run(&mut fs, &repo, &["list", "python"]),
            "python is not installed.\n"
        );
    }

    #[test]
    fn embedded_registry_contains_metadata_only_and_resolves_seeded_packages() {
        let repo = EmbeddedRepository::new().unwrap();
        let names = repository_names(&repo).unwrap();
        assert_eq!(
            names,
            [
                "7zip", "bat", "biome", "bun", "csharpier", "curl", "deno", "dotnet", "esbuild", "fd", "fzf", "gh",
                "git", "micro", "nodejs", "opencode", "python", "ripgrep", "uv"
            ]
        );
        // Upstream packages carry recipes, resolved where they are published.
        let recipe = |name: &str| Recipe::parse(&repo.fetch(&format!("packages/{name}/upstream.wpkg")).unwrap()).unwrap();
        let opencode = recipe("opencode");
        assert_eq!((opencode.upstream, opencode.x64.as_deref()), (upstream::Upstream::Npm, Some("opencode-windows-x64")));
        assert_eq!(opencode.bin, ["package/bin/opencode.exe"]);
        let bun = recipe("bun");
        assert_eq!((bun.repo.as_deref(), bun.tag.as_str()), (Some("oven-sh/bun"), "bun-v{version}"));
        let csharpier = recipe("csharpier");
        assert_eq!((csharpier.run.as_deref(), csharpier.dependencies.as_slice()), (Some("dotnet"), &["dotnet@10".to_string()][..]));
        for name in &names {
            if repo.fetch(&format!("packages/{name}/upstream.wpkg")).is_ok() {
                assert!(recipe(name).description.is_some(), "{name} has a description");
            }
        }
        let micro = resolve_version(&repo, "micro", None, "x64").unwrap();
        assert_eq!(micro.version, "2.0.15");
        assert_eq!(micro.bin, ["micro-2.0.15/micro.exe"]);
        assert_eq!(
            micro.checksum.hex,
            "90635c53c11aa2a0d997f5e3ed43528877740725500207640b29551cef18479b"
        );
        assert!(resolve_manifest(&repo, "micro", "2.0.15", "arm64").is_err());
        let seven_zip = resolve_manifest(&repo, "7zip", "26.03", "x64").unwrap();
        assert_eq!(seven_zip.bin, ["x64/7za.exe"]);
        assert!(resolve_manifest(&repo, "7zip", "26.03", "arm64").is_err());
        let version = latest_version(&repo, "python").unwrap();
        let manifest = resolve_manifest(&repo, "python", &version, "x64").unwrap();
        assert_eq!(manifest.arch, "x64");
        assert_eq!(manifest.version, "3.14.7");
        let node = resolve_version(&repo, "nodejs", Some("24"), "x64").unwrap();
        assert_eq!(node.version, "24.21.0");
        for name in names {
            if repo.fetch(&format!("packages/{name}/upstream.wpkg")).is_ok() {
                continue;
            }
            let latest = latest_version(&repo, &name).unwrap();
            assert!(registry_versions(&repo, &name).unwrap().contains(&latest));
        }
        assert!(repo
            .files
            .values()
            .all(|bytes| std::str::from_utf8(bytes).is_ok()));
    }
}
