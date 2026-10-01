//! Seekable C-drive images for ephemeral runner instances. New `.snap` files
//! use a small path index plus file extents in one appendable disk file. Boot
//! reads the index only; guest file contents are fetched from their extents
//! when the program opens them. Legacy ZIP snapshots remain loadable.

use crate::{
    install,
    winfs::{DiskStore, SnapshotMetadata, WinFs},
};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

const MARKER: &str = "wincli-snapshot/v1";
const MARKER_CONTENTS: &[u8] = b"wincli snapshot v1\n";
const FILE_PREFIX: &str = "files/C/";
const DISK_MAGIC: &[u8; 8] = b"WFSDSK01";
const DISK_VERSION: u32 = 2;
const DISK_HEADER_LEN: u64 = 36;
const MAX_INDEX_SIZE: u64 = 256 * 1024 * 1024;
const CHANGE_MAGIC: &[u8; 8] = b"WFSCHG01";

/// Load a snapshot file into a newly booted ephemeral runner image.
pub fn load_file(path: &str) -> Result<WinFs, String> {
    let path = Path::new(path);
    let mut file =
        File::open(path).map_err(|e| format!("cannot read snapshot {}: {e}", path.display()))?;
    let mut magic = [0u8; 8];
    let read = file
        .read(&mut magic)
        .map_err(|e| format!("cannot read snapshot {}: {e}", path.display()))?;
    if read == magic.len() && &magic == DISK_MAGIC {
        return load_disk_file(path);
    }
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read legacy snapshot {}: {e}", path.display()))?;
    load(&bytes)
}

/// Save only changed file extents when updating an existing WinFS disk. The
/// index is appended and its pointer is committed last, so the previous index
/// remains active if writing new data fails.
pub fn save_file(fs: &mut WinFs, output: &str) -> Result<usize, String> {
    let output_path = Path::new(output);
    let is_existing_disk = output_path.exists() && is_disk_file(output_path)?;
    let use_temporary = !is_existing_disk;
    let write_path = if use_temporary {
        temporary_output_path(output_path)
    } else {
        output_path.to_path_buf()
    };
    let disk = if use_temporary {
        DiskStore::create_temporary(&write_path)?
    } else {
        DiskStore::open(&write_path)?
    };
    if disk.len()? == 0 {
        let mut header = vec![0u8; DISK_HEADER_LEN as usize];
        header[..8].copy_from_slice(DISK_MAGIC);
        header[8..12].copy_from_slice(&DISK_VERSION.to_le_bytes());
        disk.append(&header)?;
    }

    let files = fs.snapshot_files();
    let mut file_records = Vec::with_capacity(files.len());
    for file in &files {
        let (offset, length) = if file.is_stored_in(output_path) && is_existing_disk {
            file.disk_location()
                .map(|(_, offset, length)| (offset, length))
                .ok_or_else(|| format!("missing disk location for {}", file.path))?
        } else {
            file.append_to(&disk)?
        };
        file_records.push((file.path.clone(), offset, length));
    }

    let directories = fs.snapshot_directories();
    let metadata = fs.snapshot_metadata();
    let symlinks = fs.snapshot_symlinks();
    let entry_count = directories
        .len()
        .checked_add(file_records.len())
        .ok_or("too many snapshot entries")?;
    let index = encode_index(&directories, &file_records, &metadata, &symlinks)?;
    let index_offset = disk.append(&index)?;
    let mut header = vec![0u8; DISK_HEADER_LEN as usize];
    header[..8].copy_from_slice(DISK_MAGIC);
    header[8..12].copy_from_slice(&DISK_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&index_offset.to_le_bytes());
    header[20..28].copy_from_slice(&(index.len() as u64).to_le_bytes());
    header[28..36].copy_from_slice(&(entry_count as u64).to_le_bytes());
    disk.write_at(0, &header)?;

    let final_disk = if use_temporary {
        std::fs::rename(&write_path, output_path)
            .map_err(|e| format!("cannot commit snapshot {}: {e}", output_path.display()))?;
        DiskStore::open(output_path)?
    } else {
        disk
    };
    for (path, offset, length) in &file_records {
        fs.mark_snapshot_file(path, Arc::clone(&final_disk), *offset, *length)?;
    }
    Ok(file_records.len())
}

/// Write a small worker manifest that references existing seekable WinFS
/// extents directly. The backing stores must remain alive until the worker exits.
pub(crate) fn save_worker_manifest(fs: &WinFs, directory: &Path) -> Result<PathBuf, String> {
    use std::io::Write;
    let mut inline = File::create(directory.join("inline.bin"))
        .map_err(|error| format!("cannot create worker inline store: {error}"))?;
    let mut inline_offset = 0u64;
    let mut files = Vec::new();
    for file in fs.snapshot_files() {
        if let Some(id) = file.blob_id() {
            files.push(serde_json::json!({"path": file.path, "blob": id}));
            continue;
        }
        let (store, offset, length) = if let Some((store, offset, length)) = file.disk_location() {
            (store.path().to_string_lossy().into_owned(), offset, length)
        } else {
            let bytes = file.read_bytes()?;
            let offset = inline_offset;
            inline
                .write_all(&bytes)
                .map_err(|error| format!("cannot write worker inline store: {error}"))?;
            inline_offset = inline_offset
                .checked_add(bytes.len() as u64)
                .ok_or("worker inline store is too large")?;
            (
                directory.join("inline.bin").to_string_lossy().into_owned(),
                offset,
                bytes.len() as u64,
            )
        };
        files.push(serde_json::json!({
            "path": file.path,
            "store": store,
            "offset": offset,
            "length": length,
        }));
    }
    let metadata = fs
        .snapshot_metadata()
        .into_iter()
        .map(|entry| {
            serde_json::json!({
                "path": entry.path,
                "file_id": entry.file_id,
                "attributes": entry.metadata.attributes,
                "creation_time": entry.metadata.creation_time,
                "access_time": entry.metadata.access_time,
                "write_time": entry.metadata.write_time,
            })
        })
        .collect::<Vec<_>>();
    let links = fs.snapshot_symlinks();
    let manifest = serde_json::json!({
        "blob_dir": fs.blob_dir(),
        "directories": fs.snapshot_directories(),
        "files": files,
        "metadata": metadata,
        "symlinks": links,
    });
    let path = directory.join("winfs-manifest.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&manifest)
            .map_err(|error| format!("cannot encode worker filesystem manifest: {error}"))?,
    )
    .map_err(|error| format!("cannot write worker filesystem manifest: {error}"))?;
    Ok(path)
}

/// Reopen the extents in a worker manifest without copying file payloads.
pub(crate) fn load_worker_manifest(path: &Path) -> Result<WinFs, String> {
    use crate::winfs::{DiskStore, SnapshotMetadata, WinFileMetadata};
    use std::collections::HashMap;
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(path)
            .map_err(|error| format!("cannot read worker filesystem manifest: {error}"))?,
    )
    .map_err(|error| format!("invalid worker filesystem manifest: {error}"))?;
    // The worker writes into its starter's session and never owns storage:
    // it exits without unwinding.
    let blob_dir = manifest["blob_dir"].as_str().map(Path::new);
    let mut fs = WinFs::attached(blob_dir)?;
    for directory in manifest["directories"]
        .as_array()
        .ok_or("invalid worker directories")?
    {
        let directory = directory.as_str().ok_or("invalid worker directory entry")?;
        if !fs.is_dir(directory) {
            fs.mkdir(directory)?;
        }
    }
    let mut stores = HashMap::<String, Arc<DiskStore>>::new();
    for entry in manifest["files"].as_array().ok_or("invalid worker files")? {
        let guest = entry["path"].as_str().ok_or("invalid worker file path")?;
        if let Some(id) = entry["blob"].as_str() {
            let parent = guest
                .rsplit_once('\\')
                .map(|(parent, _)| parent)
                .unwrap_or("C:");
            fs.mkdir(parent)?;
            fs.open_blob_file(guest, id)?;
            continue;
        }
        let source = entry["store"]
            .as_str()
            .ok_or("invalid worker disk path")?
            .to_owned();
        let offset = entry["offset"]
            .as_u64()
            .ok_or("invalid worker file offset")?;
        let length = entry["length"]
            .as_u64()
            .ok_or("invalid worker file length")?;
        let store = if let Some(store) = stores.get(&source) {
            Arc::clone(store)
        } else {
            let store = DiskStore::open(Path::new(&source))?;
            stores.insert(source, Arc::clone(&store));
            store
        };
        let Some(end) = offset.checked_add(length) else {
            return Err(format!("worker file extent is out of bounds: {guest}"));
        };
        if end > store.len()? {
            return Err(format!("worker file extent is out of bounds: {guest}"));
        }
        let parent = guest
            .rsplit_once('\\')
            .map(|(parent, _)| parent)
            .unwrap_or("C:");
        fs.mkdir(parent)?;
        fs.open_snapshot_file(guest, store, offset, length)?;
    }
    let metadata = manifest["metadata"]
        .as_array()
        .ok_or("invalid worker metadata")?
        .iter()
        .map(|entry| {
            Ok(SnapshotMetadata {
                path: entry["path"]
                    .as_str()
                    .ok_or("invalid worker metadata path")?
                    .to_owned(),
                file_id: entry["file_id"].as_u64().ok_or("invalid worker file ID")?,
                metadata: WinFileMetadata {
                    attributes: entry["attributes"]
                        .as_u64()
                        .ok_or("invalid worker attributes")? as u32,
                    creation_time: entry["creation_time"]
                        .as_u64()
                        .ok_or("invalid worker creation time")?,
                    access_time: entry["access_time"]
                        .as_u64()
                        .ok_or("invalid worker access time")?,
                    write_time: entry["write_time"]
                        .as_u64()
                        .ok_or("invalid worker write time")?,
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    fs.restore_snapshot_metadata(&metadata)?;
    for entry in manifest["symlinks"]
        .as_array()
        .ok_or("invalid worker symlinks")?
    {
        let path = entry[0].as_str().ok_or("invalid worker symlink path")?;
        let target = entry[1].as_str().ok_or("invalid worker symlink target")?;
        let directory = entry[2].as_bool().ok_or("invalid worker symlink kind")?;
        fs.create_symlink(path, target, directory)?;
    }
    fs.clear_changes();
    Ok(fs)
}

fn temporary_output_path(output: &Path) -> PathBuf {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let name = output.file_name().unwrap_or_default().to_string_lossy();
    parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

fn is_disk_file(path: &Path) -> Result<bool, String> {
    let mut file =
        File::open(path).map_err(|e| format!("cannot inspect snapshot {}: {e}", path.display()))?;
    let mut magic = [0u8; 8];
    let read = file
        .read(&mut magic)
        .map_err(|e| format!("cannot inspect snapshot {}: {e}", path.display()))?;
    Ok(read == magic.len() && &magic == DISK_MAGIC)
}

fn encode_index(
    directories: &[String],
    files: &[(String, u64, u64)],
    metadata: &[SnapshotMetadata],
    symlinks: &[(String, String, bool)],
) -> Result<Vec<u8>, String> {
    let count = directories
        .len()
        .checked_add(files.len())
        .ok_or("too many snapshot entries")?;
    let count = u32::try_from(count).map_err(|_| "too many snapshot entries")?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_le_bytes());
    for directory in directories {
        encode_index_path(&mut out, 0, directory)?;
    }
    for (path, offset, length) in files {
        encode_index_path(&mut out, 1, path)?;
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
    }
    out.extend_from_slice(
        &u32::try_from(metadata.len())
            .map_err(|_| "too many metadata entries")?
            .to_le_bytes(),
    );
    for entry in metadata {
        encode_index_path(&mut out, 0, &entry.path)?;
        out.extend_from_slice(&entry.file_id.to_le_bytes());
        out.extend_from_slice(&entry.metadata.attributes.to_le_bytes());
        out.extend_from_slice(&entry.metadata.creation_time.to_le_bytes());
        out.extend_from_slice(&entry.metadata.access_time.to_le_bytes());
        out.extend_from_slice(&entry.metadata.write_time.to_le_bytes());
    }
    out.extend_from_slice(
        &u32::try_from(symlinks.len())
            .map_err(|_| "too many symbolic links")?
            .to_le_bytes(),
    );
    for (path, target, directory) in symlinks {
        encode_index_path(&mut out, 0, path)?;
        encode_index_path(&mut out, 0, target)?;
        out.push(u8::from(*directory));
    }
    Ok(out)
}

fn encode_index_path(out: &mut Vec<u8>, kind: u8, path: &str) -> Result<(), String> {
    let path = path.as_bytes();
    let len = u32::try_from(path.len()).map_err(|_| "snapshot path is too long")?;
    out.push(kind);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(path);
    Ok(())
}

fn load_disk_file(path: &Path) -> Result<WinFs, String> {
    let store = DiskStore::open(path)?;
    let header = store.read_at(0, DISK_HEADER_LEN as usize)?;
    if &header[..8] != DISK_MAGIC {
        return Err("invalid WinFS disk signature".to_string());
    }
    let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if !(1..=DISK_VERSION).contains(&version) {
        return Err(format!("unsupported WinFS disk version {version}"));
    }
    let offset = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let length = u64::from_le_bytes(header[20..28].try_into().unwrap());
    let declared_count = u64::from_le_bytes(header[28..36].try_into().unwrap());
    let disk_len = store.len()?;
    if length > MAX_INDEX_SIZE
        || offset < DISK_HEADER_LEN
        || offset
            .checked_add(length)
            .map(|end| end > disk_len)
            .unwrap_or(true)
    {
        return Err("invalid WinFS disk index bounds".to_string());
    }
    let length = usize::try_from(length).map_err(|_| "WinFS disk index is too large")?;
    let index = store.read_at(offset, length)?;
    let mut cursor = 0usize;
    let count = take_u32(&index, &mut cursor)? as u64;
    if count != declared_count {
        return Err("WinFS disk index entry count mismatch".to_string());
    }
    if count > 10_000_000 {
        return Err("WinFS disk has too many indexed entries".to_string());
    }
    let mut fs = WinFs::ephemeral_runner();
    for _ in 0..count {
        let kind = take_u8(&index, &mut cursor)?;
        let guest = take_index_path(&index, &mut cursor)?;
        validate_guest_absolute(&guest)?;
        match kind {
            0 => fs
                .mkdir(&guest)
                .map_err(|e| format!("invalid indexed directory {guest}: {e}"))?,
            1 => {
                let file_offset = take_u64(&index, &mut cursor)?;
                let file_length = take_u64(&index, &mut cursor)?;
                let end = file_offset
                    .checked_add(file_length)
                    .ok_or("indexed file extent overflow")?;
                if file_offset < DISK_HEADER_LEN || end > offset {
                    return Err(format!(
                        "indexed file extent is outside data section: {guest}"
                    ));
                }
                fs.open_snapshot_file(&guest, Arc::clone(&store), file_offset, file_length)?;
            }
            _ => return Err(format!("unknown WinFS disk index record {kind}")),
        }
    }
    if version >= 2 {
        let metadata_count = take_u32(&index, &mut cursor)? as usize;
        if metadata_count > 10_000_000 {
            return Err("WinFS disk has too many metadata entries".to_string());
        }
        let mut metadata = Vec::with_capacity(metadata_count);
        for _ in 0..metadata_count {
            let _kind = take_u8(&index, &mut cursor)?;
            let guest = take_index_path(&index, &mut cursor)?;
            validate_guest_absolute(&guest)?;
            metadata.push(SnapshotMetadata {
                path: guest,
                file_id: take_u64(&index, &mut cursor)?,
                metadata: crate::winfs::WinFileMetadata {
                    attributes: take_u32(&index, &mut cursor)?,
                    creation_time: take_u64(&index, &mut cursor)?,
                    access_time: take_u64(&index, &mut cursor)?,
                    write_time: take_u64(&index, &mut cursor)?,
                },
            });
        }
        let symlink_count = take_u32(&index, &mut cursor)? as usize;
        if symlink_count > 1_000_000 {
            return Err("WinFS disk has too many symbolic links".to_string());
        }
        for _ in 0..symlink_count {
            let _path_kind = take_u8(&index, &mut cursor)?;
            let link = take_index_path(&index, &mut cursor)?;
            let _target_kind = take_u8(&index, &mut cursor)?;
            let target = take_index_path(&index, &mut cursor)?;
            let directory = take_u8(&index, &mut cursor)? != 0;
            validate_guest_absolute(&link)?;
            validate_symlink_target(&target)?;
            fs.create_symlink(&link, &target, directory)?;
        }
        fs.restore_snapshot_metadata(&metadata)?;
    }
    if cursor != index.len() {
        return Err("trailing bytes in WinFS disk index".to_string());
    }
    fs.clear_changes();
    Ok(fs)
}

fn validate_guest_absolute(path: &str) -> Result<(), String> {
    if !path.starts_with("C:\\")
        || path[3..]
            .split('\\')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(format!("unsafe WinFS disk path: {path}"));
    }
    Ok(())
}

fn validate_symlink_target(target: &str) -> Result<(), String> {
    match crate::winfs::parse_win_path(target) {
        crate::winfs::ParsedWinPath::Dos { drive: None, .. } => Ok(()),
        crate::winfs::ParsedWinPath::Dos {
            drive: Some(drive), ..
        } if drive.eq_ignore_ascii_case(&'C') => Ok(()),
        crate::winfs::ParsedWinPath::Device(_) | crate::winfs::ParsedWinPath::Unc { .. } => {
            Err(format!("unsafe WinFS symlink target: {target}"))
        }
        crate::winfs::ParsedWinPath::Dos { .. } | crate::winfs::ParsedWinPath::Invalid(_) => {
            validate_guest_absolute(target)
        }
    }
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, String> {
    let value = *bytes.get(*cursor).ok_or("truncated WinFS disk index")?;
    *cursor += 1;
    Ok(value)
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let end = cursor.checked_add(4).ok_or("WinFS index offset overflow")?;
    let value = u32::from_le_bytes(
        bytes
            .get(*cursor..end)
            .ok_or("truncated WinFS disk index")?
            .try_into()
            .unwrap(),
    );
    *cursor = end;
    Ok(value)
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, String> {
    let end = cursor.checked_add(8).ok_or("WinFS index offset overflow")?;
    let value = u64::from_le_bytes(
        bytes
            .get(*cursor..end)
            .ok_or("truncated WinFS disk index")?
            .try_into()
            .unwrap(),
    );
    *cursor = end;
    Ok(value)
}

fn take_index_path(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    let len = take_u32(bytes, cursor)? as usize;
    let end = cursor
        .checked_add(len)
        .ok_or("WinFS path offset overflow")?;
    let value = std::str::from_utf8(bytes.get(*cursor..end).ok_or("truncated WinFS disk path")?)
        .map_err(|_| "WinFS disk path is not UTF-8")?
        .to_string();
    *cursor = end;
    Ok(value)
}

/// Encode only the guest filesystem operations performed by one process.
/// Encode the journal of a process's filesystem changes for the process that
/// started it. Written files are named by their session blob, so no file
/// contents pass through the journal.
pub(crate) fn encode_changes(fs: &WinFs) -> Result<Vec<u8>, String> {
    use crate::winfs::{FsChange, WriteData};
    let changes = fs.changes();
    let count = u32::try_from(changes.len()).map_err(|_| "too many WinFS changes")?;
    let mut out = Vec::new();
    out.extend_from_slice(CHANGE_MAGIC);
    out.extend_from_slice(&count.to_le_bytes());
    for change in changes {
        match change {
            FsChange::Mkdir(path) => {
                out.push(0);
                push_string(&mut out, path)?;
            }
            FsChange::Write { path, data } => {
                out.push(1);
                push_string(&mut out, path)?;
                match data {
                    WriteData::Bytes(bytes) => {
                        out.push(0);
                        let len = u64::try_from(bytes.len())
                            .map_err(|_| "WinFS file write is too large")?;
                        out.extend_from_slice(&len.to_le_bytes());
                        out.extend_from_slice(bytes);
                    }
                    WriteData::Blob(id) => {
                        out.push(1);
                        push_string(&mut out, id)?;
                    }
                    WriteData::Extent {
                        disk,
                        offset,
                        length,
                    } => {
                        out.push(2);
                        push_string(&mut out, &disk.to_string_lossy())?;
                        out.extend_from_slice(&offset.to_le_bytes());
                        out.extend_from_slice(&length.to_le_bytes());
                    }
                }
            }
            FsChange::Remove { path, recursive } => {
                out.push(2);
                push_string(&mut out, path)?;
                out.push(u8::from(*recursive));
            }
            FsChange::Move { source, target } => {
                out.push(3);
                push_string(&mut out, source)?;
                push_string(&mut out, target)?;
            }
            FsChange::SetCwd(path) => {
                out.push(5);
                push_string(&mut out, path)?;
            }
            FsChange::SetMetadata { path, metadata } => {
                out.push(6);
                push_string(&mut out, path)?;
                out.extend_from_slice(&metadata.attributes.to_le_bytes());
                out.extend_from_slice(&metadata.creation_time.to_le_bytes());
                out.extend_from_slice(&metadata.access_time.to_le_bytes());
                out.extend_from_slice(&metadata.write_time.to_le_bytes());
            }
            FsChange::Symlink {
                path,
                target,
                directory,
            } => {
                out.push(7);
                push_string(&mut out, path)?;
                push_string(&mut out, target)?;
                out.push(u8::from(*directory));
            }
            FsChange::HardLink { path, target } => {
                out.push(8);
                push_string(&mut out, path)?;
                push_string(&mut out, target)?;
            }
        }
    }
    Ok(out)
}

pub(crate) fn apply_changes(bytes: &[u8], fs: &mut WinFs) -> Result<(), String> {
    use crate::winfs::{FsChange, WriteData};
    if bytes.len() < 12 || &bytes[..8] != CHANGE_MAGIC {
        return Err("invalid WinFS change stream".to_string());
    }
    let mut cursor = 8usize;
    let count = take_u32(bytes, &mut cursor)? as usize;
    if count > 10_000_000 {
        return Err("too many WinFS change records".to_string());
    }
    let mut changes = Vec::with_capacity(count);
    for _ in 0..count {
        match take_u8(bytes, &mut cursor)? {
            0 => changes.push(FsChange::Mkdir(take_string(bytes, &mut cursor)?)),
            1 => {
                let path = take_string(bytes, &mut cursor)?;
                let data = match take_u8(bytes, &mut cursor)? {
                    0 => {
                        let length = take_u64(bytes, &mut cursor)?;
                        let length = usize::try_from(length)
                            .map_err(|_| "WinFS change payload is too large")?;
                        let end = cursor
                            .checked_add(length)
                            .ok_or("WinFS change payload overflow")?;
                        let payload = bytes
                            .get(cursor..end)
                            .ok_or("truncated WinFS change payload")?
                            .to_vec();
                        cursor = end;
                        WriteData::Bytes(payload)
                    }
                    1 => WriteData::Blob(take_string(bytes, &mut cursor)?),
                    2 => WriteData::Extent {
                        disk: PathBuf::from(take_string(bytes, &mut cursor)?),
                        offset: take_u64(bytes, &mut cursor)?,
                        length: take_u64(bytes, &mut cursor)?,
                    },
                    kind => return Err(format!("unknown WinFS write kind {kind}")),
                };
                changes.push(FsChange::Write { path, data });
            }
            2 => changes.push(FsChange::Remove {
                path: take_string(bytes, &mut cursor)?,
                recursive: take_u8(bytes, &mut cursor)? != 0,
            }),
            3 => changes.push(FsChange::Move {
                source: take_string(bytes, &mut cursor)?,
                target: take_string(bytes, &mut cursor)?,
            }),
            5 => changes.push(FsChange::SetCwd(take_string(bytes, &mut cursor)?)),
            6 => changes.push(FsChange::SetMetadata {
                path: take_string(bytes, &mut cursor)?,
                metadata: crate::winfs::WinFileMetadata {
                    attributes: take_u32(bytes, &mut cursor)?,
                    creation_time: take_u64(bytes, &mut cursor)?,
                    access_time: take_u64(bytes, &mut cursor)?,
                    write_time: take_u64(bytes, &mut cursor)?,
                },
            }),
            7 => changes.push(FsChange::Symlink {
                path: take_string(bytes, &mut cursor)?,
                target: take_string(bytes, &mut cursor)?,
                directory: take_u8(bytes, &mut cursor)? != 0,
            }),
            8 => changes.push(FsChange::HardLink {
                path: take_string(bytes, &mut cursor)?,
                target: take_string(bytes, &mut cursor)?,
            }),
            tag => return Err(format!("unknown WinFS change operation {tag}")),
        }
    }
    if cursor != bytes.len() {
        return Err("trailing bytes in WinFS change stream".to_string());
    }
    fs.apply_changes(&changes)
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let len = u32::try_from(value.len()).map_err(|_| "WinFS path is too long")?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn take_string(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    let len = take_u32(bytes, cursor)? as usize;
    let end = cursor
        .checked_add(len)
        .ok_or("WinFS string offset overflow")?;
    let value = std::str::from_utf8(bytes.get(*cursor..end).ok_or("truncated WinFS string")?)
        .map_err(|_| "WinFS string is not UTF-8")?
        .to_string();
    *cursor = end;
    Ok(value)
}

/// Build an indexed C: disk from a host staging directory.
///
/// `input` must contain a `C/` directory. Regular files below it are copied
/// into seekable extents and indexed by guest path. Symlinks and special files
/// are rejected so the disk cannot accidentally capture host links.
pub fn build_file(input: &str, output: &str) -> Result<usize, String> {
    let root = Path::new(input).join("C");
    if !root.is_dir() {
        return Err(format!(
            "snapshot input must contain a C directory: {}",
            root.display()
        ));
    }
    let mut files = Vec::new();
    collect_files(&root, &root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut fs = WinFs::ephemeral_runner();
    for (relative, source) in &files {
        let guest = format!("C:\\{}", relative.replace('/', "\\"));
        if let Some((parent, _)) = guest.rsplit_once('\\') {
            fs.mkdir(parent)
                .map_err(|e| format!("cannot create guest directory {parent}: {e}"))?;
        }
        let data = std::fs::read(&source)
            .map_err(|e| format!("cannot read snapshot input {}: {e}", source.display()))?;
        fs.write_file(&guest, data)
            .map_err(|e| format!("cannot write guest file {guest}: {e}"))?;
    }
    save_file(&mut fs, output)?;
    Ok(files.len())
}

/// Decode a legacy ZIP snapshot and overlay it on a clean runner image.
/// New snapshots are loaded from disk with `load_file`.
pub fn load(bytes: &[u8]) -> Result<WinFs, String> {
    let entries =
        install::zip_entries(bytes).map_err(|e| format!("invalid snapshot archive: {e}"))?;
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
    for entry in entries
        .iter()
        .filter(|entry| entry.name.starts_with(FILE_PREFIX))
    {
        if entry.is_dir {
            let name = entry.name.trim_end_matches('/');
            let guest = guest_path(name)?;
            fs.mkdir(&guest)
                .map_err(|e| format!("snapshot cannot create {guest}: {e}"))?;
            continue;
        }
        let guest = guest_path(&entry.name)?;
        let parent = guest
            .rsplit_once('\\')
            .map(|(parent, _)| parent)
            .unwrap_or("C:");
        fs.mkdir(parent)
            .map_err(|e| format!("snapshot cannot create {parent}: {e}"))?;
        let contents = install::extract_bytes(bytes, entry)
            .map_err(|e| format!("snapshot cannot extract {}: {e}", entry.name))?;
        fs.write_file(&guest, contents)
            .map_err(|e| format!("snapshot cannot write {guest}: {e}"))?;
    }
    fs.clear_changes();
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
    if name.contains('\\')
        || name
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
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
            return Err(format!(
                "snapshot input may not contain symlinks: {}",
                path.display()
            ));
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
            return Err(format!(
                "snapshot input is not a regular file: {}",
                path.display()
            ));
        }
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
        assert!(fs.is_dir(r"C:\Users\runner\AppData\Local\Temp"));
        assert_eq!(fs.cwd(), r"C:\Users\runner");
        assert_eq!(fs.read_file(r"C:\tools\hello.txt").unwrap(), b"hello");
    }

    #[test]
    fn rejects_path_escape_and_missing_marker() {
        let unsafe_snap = zip_stored(&[(MARKER, MARKER_CONTENTS), ("files/C/../bad", b"")]);
        assert!(load(&unsafe_snap)
            .unwrap_err()
            .contains("unsafe snapshot entry"));
        assert!(load(&zip_stored(&[("files/C/a", b"")])).is_err());
    }

    #[test]
    fn builds_indexed_seekable_boot_disk() {
        let root = std::env::temp_dir().join(format!("winrun-snapshot-{}", std::process::id()));
        let input = root.join("input");
        let output = root.join("os.snap");
        std::fs::create_dir_all(input.join("C/tools")).unwrap();
        std::fs::write(input.join("C/tools/tool.txt"), b"tool").unwrap();
        assert_eq!(
            build_file(input.to_str().unwrap(), output.to_str().unwrap()).unwrap(),
            1
        );
        let bytes = std::fs::read(&output).unwrap();
        assert_eq!(&bytes[..8], DISK_MAGIC);
        let fs = load_file(output.to_str().unwrap()).unwrap();
        assert_eq!(fs.read_file(r"C:\tools\tool.txt").unwrap(), b"tool");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn saving_updates_the_index_without_rewriting_existing_extents() {
        let output =
            std::env::temp_dir().join(format!("winrun-indexed-update-{}.disk", std::process::id()));
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\tools").unwrap();
        fs.write_file(r"C:\tools\node.exe", b"node-data".to_vec())
            .unwrap();
        save_file(&mut fs, output.to_str().unwrap()).unwrap();
        let first_size = std::fs::metadata(&output).unwrap().len();
        // Saved files now read from the disk; their session blobs are gone.
        let session = fs.blob_dir().unwrap().to_path_buf();
        assert_eq!(std::fs::read_dir(&session).unwrap().count(), 0);
        // Writing a saved file copies its extent into a blob again.
        fs.write_at(r"C:\tools\node.exe", 0, b"N").unwrap();
        assert_eq!(std::fs::read_dir(&session).unwrap().count(), 1);

        fs.write_file(r"C:\tools\curl.exe", b"curl-data".to_vec())
            .unwrap();
        save_file(&mut fs, output.to_str().unwrap()).unwrap();
        let second_size = std::fs::metadata(&output).unwrap().len();
        assert!(second_size > first_size);
        let loaded = load_file(output.to_str().unwrap()).unwrap();
        assert_eq!(
            loaded.read_file(r"C:\tools\node.exe").unwrap(),
            b"Node-data"
        );
        assert_eq!(
            loaded.read_file(r"C:\tools\curl.exe").unwrap(),
            b"curl-data"
        );
        std::fs::remove_file(output).ok();
    }

    #[test]
    fn c_drive_snapshot_does_not_capture_a_live_mounted_drive() {
        let root =
            std::env::temp_dir().join(format!("winrun-snapshot-mount-{}", std::process::id()));
        let output = root.with_extension("snap");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("host.txt"), b"external").unwrap();
        let mut fs = WinFs::ephemeral_runner();
        fs.mount_host_dir('Z', &root, false).unwrap();
        fs.write_file(r"C:\guest.txt", b"guest".to_vec()).unwrap();
        save_file(&mut fs, output.to_str().unwrap()).unwrap();
        let loaded = load_file(output.to_str().unwrap()).unwrap();
        assert_eq!(loaded.read_file(r"C:\guest.txt").unwrap(), b"guest");
        assert!(!loaded.exists(r"Z:\host.txt"));
        std::fs::remove_file(output).ok();
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn child_filesystem_transport_contains_only_the_change_index() {
        let mut parent = WinFs::ephemeral_runner();
        parent.mkdir(r"C:\tools").unwrap();
        parent
            .write_file(r"C:\tools\node.exe", vec![b'n'; 2 * 1024 * 1024])
            .unwrap();
        parent.clear_changes();
        let mut child = parent.clone();
        child
            .write_file(r"C:\tools\curl.exe", vec![b'c'; 2 * 1024 * 1024])
            .unwrap();
        let changes = encode_changes(&child).unwrap();
        assert!(
            changes.len() < 128,
            "change pipe carried file data: {} bytes",
            changes.len()
        );
        apply_changes(&changes, &mut parent).unwrap();
        assert_eq!(
            parent.file_len(r"C:\tools\node.exe").unwrap(),
            2 * 1024 * 1024
        );
        assert_eq!(
            parent.file_len(r"C:\tools\curl.exe").unwrap(),
            2 * 1024 * 1024
        );
        assert_eq!(
            parent.read_file_range(r"C:\tools\curl.exe", 0, 1).unwrap(),
            b"c"
        );
    }

    #[test]
    fn worker_journals_keep_changes_around_deleted_and_renamed_files() {
        // A worker process writes a temp file and deletes it, and renames a
        // file after writing it; its other changes must reach the parent.
        let mut parent = WinFs::ephemeral_runner();
        let mut child = WinFs::attached(parent.blob_dir()).unwrap();
        child.mkdir(r"C:\Users").unwrap();
        child.clear_changes();
        child.write_file(r"C:\kept.txt", b"kept".to_vec()).unwrap();
        child
            .write_file(r"C:\temp.txt", b"scratch".to_vec())
            .unwrap();
        child.delete_file(r"C:\temp.txt").unwrap();
        child
            .write_file(r"C:\draft.txt", b"final".to_vec())
            .unwrap();
        child.move_path(r"C:\draft.txt", r"C:\renamed.txt").unwrap();
        // Written files are named by blob; no contents pass through.
        assert!(child.changes().iter().all(|change| !matches!(
            change,
            crate::winfs::FsChange::Write {
                data: crate::winfs::WriteData::Bytes(_),
                ..
            }
        )));

        let journal = encode_changes(&child).unwrap();
        assert!(journal.len() < 512, "journal carries file contents");
        apply_changes(&journal, &mut parent).unwrap();
        assert_eq!(parent.read_file(r"C:\kept.txt").unwrap(), b"kept");
        assert!(!parent.exists(r"C:\temp.txt"));
        assert_eq!(parent.read_file(r"C:\renamed.txt").unwrap(), b"final");
        assert!(!parent.exists(r"C:\draft.txt"));
    }

    #[test]
    fn child_filesystem_transport_replays_metadata_and_link_operations() {
        let mut parent = WinFs::ephemeral_runner();
        parent.mkdir(r"C:\work").unwrap();
        parent
            .write_file(r"C:\work\source.txt", b"source".to_vec())
            .unwrap();
        parent.clear_changes();
        let mut child = parent.clone();
        child
            .set_file_metadata(
                r"C:\work\source.txt",
                crate::winfs::WinFileMetadata {
                    attributes: 0x21,
                    creation_time: 11,
                    access_time: 22,
                    write_time: 33,
                },
            )
            .unwrap();
        child
            .create_hard_link(r"C:\work\hard.txt", r"C:\work\source.txt")
            .unwrap();
        child
            .create_symlink(r"C:\work\sym.txt", "source.txt", false)
            .unwrap();
        child
            .write_file(r"C:\work\hard.txt", b"updated".to_vec())
            .unwrap();

        let changes = encode_changes(&child).unwrap();
        apply_changes(&changes, &mut parent).unwrap();
        assert_eq!(parent.read_file(r"C:\work\source.txt").unwrap(), b"updated");
        assert_eq!(parent.read_file(r"C:\work\sym.txt").unwrap(), b"updated");
        assert_eq!(
            parent.file_id(r"C:\work\hard.txt").unwrap(),
            parent.file_id(r"C:\work\source.txt").unwrap()
        );
        assert_eq!(parent.file_metadata(r"C:\work\hard.txt").write_time, 33);
    }

    #[test]
    fn saves_a_live_instance_as_an_indexed_disk() {
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\actions-runner\_work").unwrap();
        fs.write_file(r"C:\actions-runner\_work\result.txt", b"done".to_vec())
            .unwrap();
        let path =
            std::env::temp_dir().join(format!("winrun-live-disk-{}.snap", std::process::id()));
        save_file(&mut fs, path.to_str().unwrap()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..8], DISK_MAGIC);
        let restored = load_file(path.to_str().unwrap()).unwrap();
        assert_eq!(
            restored
                .read_file(r"C:\actions-runner\_work\result.txt")
                .unwrap(),
            b"done"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn snapshot_roundtrip_preserves_metadata_links_and_file_identity() {
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\tools").unwrap();
        fs.write_file(r"C:\tools\source.txt", b"before".to_vec())
            .unwrap();
        fs.create_hard_link(r"C:\tools\hard.txt", r"C:\tools\source.txt")
            .unwrap();
        fs.create_symlink(r"C:\tools\sym.txt", "source.txt", false)
            .unwrap();
        fs.set_file_metadata(
            r"C:\tools\source.txt",
            crate::winfs::WinFileMetadata {
                attributes: 0x21,
                creation_time: 132_537_600_000_000_001,
                access_time: 132_537_600_000_000_002,
                write_time: 132_537_600_000_000_003,
            },
        )
        .unwrap();
        let original_id = fs.file_id(r"C:\tools\source.txt").unwrap();
        let path =
            std::env::temp_dir().join(format!("winrun-metadata-links-{}.snap", std::process::id()));
        save_file(&mut fs, path.to_str().unwrap()).unwrap();

        let mut restored = load_file(path.to_str().unwrap()).unwrap();
        assert_eq!(
            restored.file_metadata(r"C:\tools\source.txt").attributes,
            0x21
        );
        assert_eq!(
            restored.file_metadata(r"C:\tools\source.txt").write_time,
            132_537_600_000_000_003
        );
        assert_eq!(restored.file_id(r"C:\tools\hard.txt").unwrap(), original_id);
        assert_eq!(restored.read_file(r"C:\tools\sym.txt").unwrap(), b"before");
        restored
            .write_file(r"C:\tools\hard.txt", b"after".to_vec())
            .unwrap();
        assert_eq!(
            restored.read_file(r"C:\tools\source.txt").unwrap(),
            b"after"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn preserves_empty_directories_across_native_child_snapshot() {
        let mut fs = WinFs::new();
        fs.mkdir(r"C:\Empty\Nested").unwrap();
        let path =
            std::env::temp_dir().join(format!("winrun-empty-disk-{}.snap", std::process::id()));
        save_file(&mut fs, path.to_str().unwrap()).unwrap();
        let restored = load_file(path.to_str().unwrap()).unwrap();
        assert!(restored.is_dir(r"C:\Empty\Nested"));
        assert_eq!(
            restored.list_dir(r"C:\Empty\Nested").unwrap(),
            Vec::<String>::new()
        );
        std::fs::remove_file(path).ok();
    }
}
