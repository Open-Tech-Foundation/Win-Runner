//! Immutable boot-image snapshots for ephemeral runner instances.
//!
//! A `.snap` file is a normal ZIP archive (stored or raw-deflate entries) with
//! this layout:
//!
//! ```text
//! wincli-snapshot/v1                 UTF-8: `wincli snapshot v1\n`
//! files/C/actions-runner/bin/x.exe   guest file at C:\actions-runner\bin\x.exe
//! files/C/Windows/...                more guest files
//! ```
//!
//! Directories are implicit. Entry names must use `/`, begin with `files/C/`,
//! and may not contain `.` or `..` components. Loading always starts with the
//! built-in empty runner image; the archive only adds or replaces files.

use crate::{install, winfs::WinFs};
use std::path::{Path, PathBuf};

const MARKER: &str = "wincli-snapshot/v1";
const MARKER_CONTENTS: &[u8] = b"wincli snapshot v1\n";
const FILE_PREFIX: &str = "files/C/";

/// Load a snapshot file into a newly booted ephemeral runner image.
pub fn load_file(path: &str) -> Result<WinFs, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read snapshot {path}: {e}"))?;
    load(&bytes)
}

/// Build a deterministic v1 snapshot from a host staging directory.
///
/// `input` must contain a `C/` directory. Regular files below it become
/// `files/C/...` ZIP entries; directories are implicit. Symlinks and special
/// files are rejected so the archive cannot accidentally capture host links.
pub fn build_file(input: &str, output: &str) -> Result<usize, String> {
    let root = Path::new(input).join("C");
    if !root.is_dir() {
        return Err(format!("snapshot input must contain a C directory: {}", root.display()));
    }
    let mut files = Vec::new();
    collect_files(&root, &root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut entries = vec![(MARKER.to_string(), MARKER_CONTENTS.to_vec())];
    for (relative, source) in files {
        let data = std::fs::read(&source)
            .map_err(|e| format!("cannot read snapshot input {}: {e}", source.display()))?;
        entries.push((format!("files/C/{relative}"), data));
    }
    std::fs::write(output, zip_stored(&entries))
        .map_err(|e| format!("cannot write snapshot {output}: {e}"))?;
    Ok(entries.len() - 1)
}

/// Decode an archive and overlay it on a clean runner image.
pub fn load(bytes: &[u8]) -> Result<WinFs, String> {
    let entries = install::zip_entries(bytes).map_err(|e| format!("invalid snapshot archive: {e}"))?;
    let marker = entries
        .iter()
        .find(|entry| entry.name == MARKER && !entry.is_dir)
        .ok_or_else(|| format!("snapshot missing {MARKER}"))?;
    if install::extract_bytes(bytes, marker).map_err(|e| format!("invalid snapshot marker: {e}"))?
        != MARKER_CONTENTS
    {
        return Err("unsupported snapshot format version".to_string());
    }

    let mut fs = WinFs::ephemeral_runner();
    for entry in entries.iter().filter(|entry| entry.name.starts_with(FILE_PREFIX)) {
        if entry.is_dir {
            validate_name(entry.name.trim_end_matches('/'))?;
            continue;
        }
        let guest = guest_path(&entry.name)?;
        let parent = guest.rsplit_once('\\').map(|(parent, _)| parent).unwrap_or("C:");
        fs.mkdir(parent)
            .map_err(|e| format!("snapshot cannot create {parent}: {e}"))?;
        let contents = install::extract_bytes(bytes, entry)
            .map_err(|e| format!("snapshot cannot extract {}: {e}", entry.name))?;
        fs.write_file(&guest, contents)
            .map_err(|e| format!("snapshot cannot write {guest}: {e}"))?;
    }
    Ok(fs)
}

/// Encode an in-memory instance as a bootable v1 archive. This is used by
/// the native child boundary to return its guest-side filesystem changes to
/// the host controller without mounting the host filesystem.
pub fn encode(fs: &WinFs) -> Vec<u8> {
    let mut entries = vec![(MARKER.to_string(), MARKER_CONTENTS.to_vec())];
    for (path, data) in fs.files() {
        let path = path.strip_prefix("C:\\").unwrap_or(&path).replace('\\', "/");
        entries.push((format!("files/C/{path}"), data));
    }
    zip_stored(&entries)
}

fn guest_path(name: &str) -> Result<String, String> {
    validate_name(name)?;
    let tail = name
        .strip_prefix(FILE_PREFIX)
        .ok_or_else(|| format!("snapshot entry outside guest image: {name}"))?;
    Ok(format!("C:\\{}", tail.replace('/', "\\")))
}

fn validate_name(name: &str) -> Result<(), String> {
    if !name.starts_with(FILE_PREFIX) {
        return Err(format!("snapshot entry outside guest image: {name}"));
    }
    if name.contains('\\') || name.split('/').any(|part| part.is_empty() || matches!(part, "." | "..")) {
        return Err(format!("unsafe snapshot entry: {name}"));
    }
    Ok(())
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read snapshot directory {}: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| format!("cannot read snapshot directory entry: {e}"))?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot stat snapshot input {}: {e}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("snapshot input may not contain symlinks: {}", path.display()));
        }
        if metadata.is_dir() {
            collect_files(root, &path, out)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "snapshot path escaped staging root".to_string())?
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            out.push((relative, path));
        } else {
            return Err(format!("snapshot input is not a regular file: {}", path.display()));
        }
    }
    Ok(())
}

/// Standard, stored-only ZIP writer. The loader also accepts deflated ZIPs,
/// but stored output keeps boot images deterministic without a compressor.
fn zip_stored(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let name = name.as_bytes();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
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
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let central_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn loads_files_over_a_fresh_runner_base() {
        let snap = zip_stored(&[
            (MARKER, MARKER_CONTENTS),
            ("files/C/tools/hello.txt", b"hello"),
        ]);
        let fs = load(&snap).unwrap();
        assert!(fs.is_dir(r"C:\actions-runner\_work"));
        assert_eq!(fs.read_file(r"C:\tools\hello.txt").unwrap(), b"hello");
    }

    #[test]
    fn rejects_path_escape_and_missing_marker() {
        let unsafe_snap = zip_stored(&[(MARKER, MARKER_CONTENTS), ("files/C/../bad", b"")]);
        assert!(load(&unsafe_snap).unwrap_err().contains("unsafe snapshot entry"));
        assert!(load(&zip_stored(&[("files/C/a", b"")])).is_err());
    }

    #[test]
    fn builds_deterministic_bootable_archive() {
        let root = std::env::temp_dir().join(format!("wincli-snapshot-{}", std::process::id()));
        let input = root.join("input");
        let output = root.join("os.snap");
        std::fs::create_dir_all(input.join("C/tools")).unwrap();
        std::fs::write(input.join("C/tools/tool.txt"), b"tool").unwrap();
        assert_eq!(build_file(input.to_str().unwrap(), output.to_str().unwrap()).unwrap(), 1);
        let fs = load(&std::fs::read(&output).unwrap()).unwrap();
        assert_eq!(fs.read_file(r"C:\tools\tool.txt").unwrap(), b"tool");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn encodes_a_live_instance() {
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\actions-runner\_work").unwrap();
        fs.write_file(r"C:\actions-runner\_work\result.txt", b"done".to_vec())
            .unwrap();
        let restored = load(&encode(&fs)).unwrap();
        assert_eq!(
            restored.read_file(r"C:\actions-runner\_work\result.txt").unwrap(),
            b"done"
        );
    }
}
