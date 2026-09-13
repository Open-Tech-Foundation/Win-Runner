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

const MARKER: &str = "wincli-snapshot/v1";
const MARKER_CONTENTS: &[u8] = b"wincli snapshot v1\n";
const FILE_PREFIX: &str = "files/C/";

/// Load a snapshot file into a newly booted ephemeral runner image.
pub fn load_file(path: &str) -> Result<WinFs, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read snapshot {path}: {e}"))?;
    load(&bytes)
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
}
