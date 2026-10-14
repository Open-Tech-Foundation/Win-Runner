//! Upstream packages: a package whose `.wpkg` names where it is published
//! (`upstream = "npm" | "nuget" | "github"`) instead of a fixed archive.
//! At install time the newest release (or the one `@version` asks for) is
//! looked up there, and the archive is checked against the hash upstream
//! publishes with it: npm's and NuGet's SHA-512, GitHub's SHA-256 asset
//! digest. A release without a published hash is refused.

use super::*;

/// Where an upstream package is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upstream {
    Npm,
    Nuget,
    Github,
}

/// An upstream `.wpkg`: how to find a package's releases and what to
/// expose from them. `x64`/`arm64` are npm package names, NuGet ids, or
/// GitHub asset name templates; templates may use `{version}`, and `bin`
/// entries also `{stem}` (the archive's name without its extension).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    pub name: String,
    pub upstream: Upstream,
    pub x64: Option<String>,
    pub arm64: Option<String>,
    pub repo: Option<String>,
    pub tag: String,
    pub version_pattern: Option<String>,
    pub bin: Vec<String>,
    pub run: Option<String>,
    pub env: Vec<String>,
    pub dependencies: Vec<String>,
    pub description: Option<String>,
}

impl Recipe {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let values = parse_fields(
            bytes,
            &[
                "name", "upstream", "x64", "arm64", "repo", "tag", "version", "bin", "run", "env",
                "dependencies", "description",
            ],
        )?;
        let optional = |key: &str| values.get(key).map(|value| parse_string(value)).transpose();
        let name = normalize_name(&optional("name")?.ok_or("wpkg: upstream package missing name")?)?;
        let upstream = match optional("upstream")?.as_deref() {
            Some("npm") => Upstream::Npm,
            Some("nuget") => Upstream::Nuget,
            Some("github") => Upstream::Github,
            Some(other) => return Err(format!("wpkg: unsupported upstream: {other}")),
            None => return Err("wpkg: upstream package missing upstream".to_string()),
        };
        let (x64, arm64) = (optional("x64")?, optional("arm64")?);
        if x64.is_none() && arm64.is_none() {
            return Err(format!("wpkg: {name} names no x64 or arm64 build"));
        }
        let repo = optional("repo")?;
        if upstream == Upstream::Github && repo.as_deref().is_none_or(|repo| repo.split('/').count() != 2) {
            return Err(format!("wpkg: {name} needs repo = \"OWNER/REPO\""));
        }
        let common = CommonFields::parse(&values)?;
        Ok(Self {
            name,
            upstream,
            x64,
            arm64,
            repo,
            tag: optional("tag")?.unwrap_or_else(|| "v{version}".to_string()),
            version_pattern: optional("version")?,
            bin: common.bin,
            run: common.run,
            env: common.env,
            dependencies: common.dependencies,
            description: common.description,
        })
    }

    fn id(&self, arch: &str) -> Result<&str, String> {
        match arch {
            "x64" => self.x64.as_deref(),
            _ => self.arm64.as_deref(),
        }
        .ok_or_else(|| format!("wpkg: {} has no {arch} build", self.name))
    }
}

fn json(repository: &dyn Repository, url: &str) -> Result<Value, String> {
    let bytes = repository.fetch(url)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("wpkg: invalid response from {url}: {error}"))
}

/// A stable version unless prereleases are wanted.
fn stable(version: &str) -> bool {
    !version.contains(['-', '+'])
}

/// The version `spec` names among `versions`: the newest stable one
/// without a spec, the exact one, or the newest matching `spec.x`.
fn choose<'a>(versions: impl Iterator<Item = &'a str>, spec: Option<&str>) -> Option<String> {
    let versions: Vec<&str> = versions.collect();
    if let Some(spec) = spec {
        if versions.contains(&spec) {
            return Some(spec.to_string());
        }
    }
    versions
        .into_iter()
        .filter(|version| match spec {
            Some(spec) => version_matches(version, spec) && stable(version),
            None => stable(version),
        })
        .max_by(|left, right| compare_versions(left, right))
        .map(str::to_string)
}

fn base64_hex(encoded: &str) -> Result<String, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| "wpkg: upstream hash is not base64".to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The manifest of `recipe`'s release `spec` (newest without one) for
/// `arch`.
pub fn resolve(repository: &dyn Repository, recipe: &Recipe, spec: Option<&str>, arch: &str) -> Result<Manifest, String> {
    let id = recipe.id(arch)?;
    let (version, url, checksum) = match recipe.upstream {
        Upstream::Npm => resolve_npm(repository, id, spec)?,
        Upstream::Nuget => resolve_nuget(repository, id, spec)?,
        Upstream::Github => resolve_github(repository, recipe, id, spec, arch)?,
    };
    let version = normalize_version(&version)?;
    let stem = archive_stem(&url);
    let bin = recipe
        .bin
        .iter()
        .map(|entry| entry.replace("{version}", &version).replace("{stem}", &stem).replace("{arch}", arch))
        .collect();
    Ok(Manifest {
        name: recipe.name.clone(),
        version,
        arch: arch.to_string(),
        url,
        checksum,
        bin,
        run: recipe.run.clone(),
        env: recipe.env.clone(),
        dependencies: recipe.dependencies.clone(),
        description: recipe.description.clone(),
        upstream: true,
    })
}

/// An archive's file name without its extension.
fn archive_stem(url: &str) -> String {
    let file = url.split(['?', '#']).next().unwrap_or(url).rsplit('/').next().unwrap_or(url);
    for extension in [".tar.gz", ".tgz", ".zip", ".7z", ".nupkg"] {
        if let Some(stem) = file.strip_suffix(extension) {
            return stem.to_string();
        }
    }
    file.to_string()
}

fn resolve_npm(repository: &dyn Repository, package: &str, spec: Option<&str>) -> Result<(String, String, Checksum), String> {
    let escaped = package.replace('/', "%2F");
    let release = match spec {
        None => json(repository, &format!("https://registry.npmjs.org/{escaped}/latest"))?,
        Some(spec) => {
            let document = json(repository, &format!("https://registry.npmjs.org/{escaped}"))?;
            let versions = document.get("versions").and_then(Value::as_object).ok_or("wpkg: npm package lists no versions")?;
            let version = choose(versions.keys().map(String::as_str), Some(spec))
                .ok_or_else(|| format!("wpkg: no {package} version matches {spec}"))?;
            versions[&version].clone()
        }
    };
    let field = |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
    let version = field(&release, "version").ok_or("wpkg: npm release has no version")?;
    let dist = release.get("dist").ok_or("wpkg: npm release has no dist")?;
    let url = field(dist, "tarball").ok_or("wpkg: npm release has no tarball")?;
    let integrity = field(dist, "integrity").unwrap_or_default();
    let hash = integrity
        .split_whitespace()
        .find_map(|entry| entry.strip_prefix("sha512-"))
        .ok_or_else(|| format!("wpkg: npm publishes no SHA-512 for {package}@{version}"))?;
    Ok((version, url, Checksum::sha512(&base64_hex(hash)?)?))
}

fn resolve_nuget(repository: &dyn Repository, id: &str, spec: Option<&str>) -> Result<(String, String, Checksum), String> {
    let id = id.to_ascii_lowercase();
    let index = json(repository, &format!("https://api.nuget.org/v3-flatcontainer/{id}/index.json"))?;
    let versions = index.get("versions").and_then(Value::as_array).ok_or("wpkg: NuGet lists no versions")?;
    let version = choose(versions.iter().filter_map(Value::as_str), spec)
        .ok_or_else(|| format!("wpkg: no {id} version matches {}", spec.unwrap_or("a stable release")))?
        .to_ascii_lowercase();
    // The registration leaf points at the catalog entry with the hash.
    let leaf = json(repository, &format!("https://api.nuget.org/v3/registration5-semver1/{id}/{version}.json"))?;
    let catalog = leaf.get("catalogEntry").and_then(Value::as_str).ok_or("wpkg: NuGet registration has no catalog entry")?;
    let entry = json(repository, catalog)?;
    let algorithm = entry.get("packageHashAlgorithm").and_then(Value::as_str).unwrap_or_default();
    let hash = entry.get("packageHash").and_then(Value::as_str).filter(|_| algorithm.eq_ignore_ascii_case("SHA512"))
        .ok_or_else(|| format!("wpkg: NuGet publishes no SHA-512 for {id} {version}"))?;
    let url = format!("https://api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg");
    Ok((version, url, Checksum::sha512(&base64_hex(hash)?)?))
}

/// A tag's version, by the recipe's `version` pattern (one group per
/// part) or its `tag` template.
fn tag_version(recipe: &Recipe, tag: &str) -> Option<String> {
    if let Some(pattern) = &recipe.version_pattern {
        return regex_groups(pattern, tag).map(|groups| groups.join("."));
    }
    let (prefix, suffix) = recipe.tag.split_once("{version}")?;
    let version = tag.strip_prefix(prefix)?.strip_suffix(suffix)?;
    (!version.is_empty() && version.starts_with(|c: char| c.is_ascii_digit())).then(|| version.to_string())
}

/// A tiny matcher for `version` patterns: literal text with `(\d+)`
/// groups, e.g. `v(\d+)\.(\d+)\.(\d+)\.windows\.(\d+)`.
fn regex_groups(pattern: &str, text: &str) -> Option<Vec<String>> {
    let pattern = pattern.replace(r"\.", ".");
    let parts: Vec<&str> = pattern.split(r"(\d+)").collect();
    let mut rest = text.strip_prefix(parts[0])?;
    let mut groups = Vec::new();
    for literal in &parts[1..] {
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        groups.push(rest[..digits].to_string());
        rest = rest[digits..].strip_prefix(literal)?;
    }
    rest.is_empty().then_some(groups)
}

fn resolve_github(
    repository: &dyn Repository,
    recipe: &Recipe,
    asset_template: &str,
    spec: Option<&str>,
    arch: &str,
) -> Result<(String, String, Checksum), String> {
    let repo = recipe.repo.as_deref().unwrap_or_default();
    let releases = match spec {
        None => vec![json(repository, &format!("https://api.github.com/repos/{repo}/releases/latest"))?],
        Some(_) => json(repository, &format!("https://api.github.com/repos/{repo}/releases?per_page=100"))?
            .as_array()
            .cloned()
            .unwrap_or_default(),
    };
    let tagged: Vec<(String, &Value)> = releases
        .iter()
        .filter(|release| !release.get("draft").and_then(Value::as_bool).unwrap_or(false))
        .filter_map(|release| {
            let tag = release.get("tag_name").and_then(Value::as_str)?;
            Some((tag_version(recipe, tag)?, release))
        })
        .collect();
    let version = choose(tagged.iter().map(|(version, _)| version.as_str()), spec)
        .ok_or_else(|| format!("wpkg: no {} release matches {}", recipe.name, spec.unwrap_or("its tag pattern")))?;
    let release = tagged.iter().find(|(candidate, _)| *candidate == version).map(|(_, release)| *release).unwrap();
    let name = asset_template.replace("{version}", &version).replace("{arch}", arch);
    let asset = release
        .get("assets")
        .and_then(Value::as_array)
        .and_then(|assets| assets.iter().find(|asset| asset.get("name").and_then(Value::as_str) == Some(name.as_str())))
        .ok_or_else(|| format!("wpkg: {} {version} has no asset {name}", recipe.name))?;
    let url = asset.get("browser_download_url").and_then(Value::as_str).ok_or("wpkg: GitHub asset has no URL")?;
    let digest = asset
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .ok_or_else(|| format!("wpkg: GitHub publishes no SHA-256 for {name}"))?;
    Ok((version, url.to_string(), Checksum::sha256(digest)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_choose_like_package_specs() {
        let versions = ["1.2.0", "1.10.0", "2.0.0-rc1", "1.9.3"];
        assert_eq!(choose(versions.into_iter(), None).as_deref(), Some("1.10.0"), "newest stable");
        assert_eq!(choose(versions.into_iter(), Some("1.9")).as_deref(), Some("1.9.3"));
        assert_eq!(choose(versions.into_iter(), Some("2.0.0-rc1")).as_deref(), Some("2.0.0-rc1"), "an exact prerelease");
        assert_eq!(choose(versions.into_iter(), Some("3")), None);
    }

    #[test]
    fn tags_give_versions_by_template_or_pattern() {
        let mut recipe = Recipe::parse(
            b"name = \"git\"\nupstream = \"github\"\nrepo = \"a/b\"\nx64 = \"x.zip\"\nbin = [\"git.exe\"]\n",
        )
        .unwrap();
        assert_eq!(tag_version(&recipe, "v2.5.0").as_deref(), Some("2.5.0"));
        assert_eq!(tag_version(&recipe, "nightly"), None);
        recipe.version_pattern = Some(r"v(\d+)\.(\d+)\.(\d+)\.windows\.(\d+)".into());
        assert_eq!(tag_version(&recipe, "v2.55.0.windows.2").as_deref(), Some("2.55.0.2"));
        recipe.version_pattern = None;
        recipe.tag = "bun-v{version}".into();
        assert_eq!(tag_version(&recipe, "bun-v1.4.3").as_deref(), Some("1.4.3"));
        assert_eq!(archive_stem("https://x/y/bat-v1-x86_64.zip"), "bat-v1-x86_64");
        assert_eq!(archive_stem("https://x/pkg-1.0.tgz"), "pkg-1.0");
    }
}
