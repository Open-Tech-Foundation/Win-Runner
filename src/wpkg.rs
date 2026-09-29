//! Small manifest-driven installer for portable Windows ZIP and 7z packages.
//!
//! Package state and extracted files live only in the guest WinFS. Repositories
//! provide `packages/index`, per-package `latest` and `versions` files, and
//! TOML `.wpkg` manifests; the package archive is fetched separately and never
//! executed.
//!
//! Versions install side by side as `C:\Program Files\<name>\<version>`.
//! The directory link `C:\Program Files\<name>\current` selects the default
//! version, and `C:\ProgramData\wpkg\bin` (on the system `PATH`) links each
//! command through it, so switching the default rewrites one link and never
//! leaves a command pointing at removed files.

use crate::{install, winfs::WinFs};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read},
    path::Path,
};

const STATE: &str = r"C:\ProgramData\wpkg";
const DATABASE: &str = r"C:\ProgramData\wpkg\installed.json";
const ROOT: &str = crate::system_profile::PROGRAM_FILES;
/// Command links for every package's default version; on the system `PATH`.
pub const BIN: &str = r"C:\ProgramData\wpkg\bin";
const CURRENT: &str = "current";
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
        progress: &mut dyn FnMut(u8),
    ) -> Result<Vec<u8>, String> {
        let bytes = self.fetch(path_or_url)?;
        progress(100);
        Ok(bytes)
    }
}

/// Registry text files are bundled with winrun as a small ZIP resource.
/// Package archives referenced by manifests are still fetched on demand.
pub struct EmbeddedRepository {
    files: HashMap<String, Vec<u8>>,
}

impl EmbeddedRepository {
    pub fn new() -> Result<Self, String> {
        let archive = include_bytes!("../registry.zip");
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
        progress: &mut dyn FnMut(u8),
    ) -> Result<Vec<u8>, String> {
        if path_or_url.starts_with("https://") || path_or_url.starts_with("http://") {
            return install::fetch_url_with_progress(path_or_url, 300, progress)
                .map_err(|error| format!("wpkg: {error}"));
        }
        self.fetch(path_or_url).inspect(|_| progress(100))
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
        progress: &mut dyn FnMut(u8),
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
    pub sha256: String,
    pub bin: Vec<String>,
    pub dependencies: Vec<String>,
}

/// One extracted version under `C:\Program Files\<name>\<version>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledVersion {
    pub version: String,
    pub arch: String,
    pub install_path: String,
    pub bin: Vec<String>,
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
}

const USAGE: &str = "usage: wpkg search <query> | info <package[@version]> | install <package[@version]> | list [package] | default <package> [version] | upgrade [package] | remove <package[@version]>";

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
                    output.extend_from_slice(format!("{name}\n").as_bytes());
                }
            }
        }
        Command::Info(spec) => {
            let (name, version) = split_package_spec(&spec)?;
            let manifest = resolve_version(repository, &name, version.as_deref(), &architecture)?;
            output.extend_from_slice(
                format!(
                    "{} {} ({})\nArchive: {}\nBinaries: {}\nDependencies: {}\n",
                    manifest.name,
                    manifest.version,
                    manifest.arch,
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
            let removed = remove_package(fs, &name, version.as_deref())?;
            output.extend_from_slice(format!("Removed {removed}\n").as_bytes());
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
    let latest = latest_version(repository, name)?;
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

    // Any installed version satisfies a dependency; installing a dependent
    // never moves another package's default.
    for dependency in &manifest.dependencies {
        let dependency = normalize_name(dependency)?;
        if load_database(fs)?
            .iter()
            .any(|package| package.name == dependency)
        {
            continue;
        }
        install_recursive(
            fs,
            repository,
            arch,
            &dependency,
            None,
            visiting,
            output,
            progress,
        )?;
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

/// Extract one verified version into its own directory. The first version
/// of a package becomes its default; later ones leave the default alone and
/// return it so the caller can tell the user how to switch.
fn install_version(
    fs: &mut WinFs,
    repository: &dyn Repository,
    manifest: &Manifest,
    progress: &mut dyn FnMut(&str),
) -> Result<Option<String>, String> {
    progress(&format!(
        "⬇️ Downloading {} {}...\n",
        manifest.name, manifest.version
    ));
    let archive = repository.fetch_with_progress(&manifest.url, &mut |percent| {
        if percent == 100 || percent.is_multiple_of(10) {
            progress(&format!(
                "⬇️ Downloading {} {}: {percent}%\n",
                manifest.name, manifest.version
            ));
        }
    })?;
    progress(&format!(
        "🔎 Verifying {} {}...\n",
        manifest.name, manifest.version
    ));
    let actual = install::sha256_hex(&archive);
    if !actual.eq_ignore_ascii_case(&manifest.sha256) {
        return Err(format!(
            "wpkg: SHA-256 mismatch for {} {} (expected {}, got {actual})",
            manifest.name, manifest.version, manifest.sha256
        ));
    }

    progress(&format!(
        "🛠️ Installing {} {}...\n",
        manifest.name, manifest.version
    ));
    let mut packages = load_database(fs)?;
    let first_version = !packages.iter().any(|package| package.name == manifest.name);
    // Only the default version is linked into BIN, so only a first
    // install can collide with another package's commands.
    if first_version {
        check_bin_conflicts(fs, &manifest.name, &manifest.bin)?;
    }

    let final_path = version_path(&manifest.name, &manifest.version);
    let package_parent = package_dir(&manifest.name);
    let staging_path = format!(r"{}\.staging-{}", package_parent, manifest.version);
    let entries = package_entries(&archive, &manifest.url)?;
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
        for executable in &manifest.bin {
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
        install_path: final_path,
        bin: manifest.bin.clone(),
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
    Ok(previous_default.filter(|default| default != &manifest.version))
}

fn package_entries(archive: &[u8], url: &str) -> Result<Vec<PackageEntry>, String> {
    let url_path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase();
    if !url_path.ends_with(".7z") {
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
    Ok(match spec {
        Some(_) => format!("{name} {}", package.default),
        None => name.to_string(),
    })
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
    check_bin_conflicts(fs, name, &entry.bin)?;
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
    for executable in &entry.bin {
        let exposed = expose_path(executable)?;
        let target = format!(r"{}\{}", current, executable.replace('/', "\\"));
        fs.create_symlink(&exposed, &target, false)
            .map_err(|error| format!("wpkg: cannot expose {executable}: {error}"))?;
    }
    package.default = version.to_string();
    Ok(())
}

/// Command links this package may replace: links into its own directory.
fn owns_link(fs: &WinFs, name: &str, path: &str) -> bool {
    let prefix = format!(r"{}\", package_dir(name)).to_ascii_lowercase();
    fs.symlink_target(path)
        .is_some_and(|target| target.to_ascii_lowercase().starts_with(&prefix))
}

fn check_bin_conflicts(fs: &WinFs, name: &str, bins: &[String]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for executable in bins {
        let exposed = expose_path(executable)?;
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
    let owned: Vec<String> = fs
        .snapshot_symlinks()
        .into_iter()
        .map(|(path, _, _)| path)
        .filter(|path| path.to_ascii_lowercase().starts_with(&bin_prefix))
        .filter(|path| owns_link(fs, name, path))
        .collect();
    for path in owned {
        fs.remove(&path, false)
            .map_err(|error| format!("wpkg: cannot remove binary link: {error}"))?;
    }
    Ok(())
}

fn latest_version(repository: &dyn Repository, name: &str) -> Result<String, String> {
    let bytes = repository.fetch(&format!("packages/{name}/latest"))?;
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

fn expose_path(executable: &str) -> Result<String, String> {
    let basename = executable.rsplit('/').next().unwrap_or(executable);
    validate_bin(basename)?;
    Ok(format!(r"{}\{}", BIN, basename))
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

fn validate_bin(path: &str) -> Result<(), String> {
    let normalized = path.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.contains(':')
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.trim().is_empty())
        || !normalized.to_ascii_lowercase().ends_with(".exe")
    {
        return Err(format!("wpkg: unsafe or non-executable bin path: {path}"));
    }
    Ok(())
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

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
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
            if !matches!(
                key.as_str(),
                "name" | "version" | "arch" | "url" | "sha256" | "bin" | "dependencies"
            ) {
                return Err(format!("wpkg: unsupported manifest key: {key}"));
            }
            if values
                .insert(key.clone(), value.trim().to_string())
                .is_some()
            {
                return Err(format!("wpkg: duplicate manifest key: {key}"));
            }
        }
        let string = |key: &str| -> Result<String, String> {
            parse_string(
                values
                    .get(key)
                    .ok_or_else(|| format!("wpkg: manifest missing {key}"))?,
            )
        };
        let name = normalize_name(&string("name")?)?;
        let version = normalize_version(&string("version")?)?;
        let arch = normalize_arch(&string("arch")?)?;
        let url = string("url")?;
        if !url.starts_with("https://") {
            return Err("wpkg: package archive URL must use HTTPS".to_string());
        }
        let sha256 = string("sha256")?.to_ascii_lowercase();
        if sha256.len() != 64
            || !sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err("wpkg: sha256 must contain exactly 64 hexadecimal digits".to_string());
        }
        let bin = parse_string_array(
            values
                .get("bin")
                .ok_or_else(|| "wpkg: manifest missing bin".to_string())?,
        )?;
        if bin.is_empty() {
            return Err("wpkg: manifest bin must not be empty".to_string());
        }
        for executable in &bin {
            validate_bin(executable)?;
        }
        let dependencies = values
            .get("dependencies")
            .map(|value| parse_string_array(value))
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|dependency| normalize_name(&dependency))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            name,
            version,
            arch,
            url,
            sha256,
            bin,
            dependencies,
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
        assert!(progress.iter().any(|message| message.contains("100%")));
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
            ["7zip", "curl", "git", "nodejs", "python", "ripgrep"]
        );
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
            let latest = latest_version(&repo, &name).unwrap();
            assert!(registry_versions(&repo, &name).unwrap().contains(&latest));
        }
        assert!(repo
            .files
            .values()
            .all(|bytes| std::str::from_utf8(bytes).is_ok()));
    }
}
