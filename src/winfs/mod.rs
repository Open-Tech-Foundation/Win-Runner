//! WinFS: indexed Windows-style filesystem with seekable disk-backed guest
//! files and optional live host-directory drives.
//!
//! - C: guest files use an append-only backing store; snapshots retain file
//!   extents and load file bytes only when opened.
//! - Optional host directories can be mounted as separate guest drives.
//! - Case-insensitive lookup, original casing preserved for listings.
//! - Supports `C:\`, `C:\test\a.txt`, relative paths, `.` and `..`.
//! - Single shared API used by native PE shims and PS1 (`ps1`).

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

static NEXT_DISK_ID: AtomicU64 = AtomicU64::new(1);

/// Seekable backing storage for WinFS file contents. Snapshot files and the
/// session's temporary write area share this interface; only file metadata
/// stays resident in the directory index.
#[derive(Debug)]
pub(crate) struct DiskStore {
    file: Mutex<File>,
    path: PathBuf,
    remove_on_drop: bool,
}

impl DiskStore {
    pub(crate) fn open(path: &Path) -> Result<Arc<Self>, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("cannot open disk {}: {e}", path.display()))?;
        Ok(Arc::new(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            remove_on_drop: false,
        }))
    }

    pub(crate) fn create_temporary(path: &Path) -> Result<Arc<Self>, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("cannot create temporary disk {}: {e}", path.display()))?;
        Ok(Arc::new(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            remove_on_drop: true,
        }))
    }

    fn temporary() -> Option<Arc<Self>> {
        let id = NEXT_DISK_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("wincli-disk-{}-{id}.tmp", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .ok()?;
        Some(Arc::new(Self {
            file: Mutex::new(file),
            path,
            remove_on_drop: true,
        }))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn len(&self) -> Result<u64, String> {
        self.file
            .lock()
            .map_err(|_| "WinFS disk lock is poisoned".to_string())?
            .metadata()
            .map(|m| m.len())
            .map_err(|e| format!("cannot stat WinFS disk: {e}"))
    }

    pub(crate) fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| "WinFS disk lock is poisoned".to_string())?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("cannot seek WinFS disk: {e}"))?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)
            .map_err(|e| format!("cannot read WinFS disk: {e}"))?;
        Ok(bytes)
    }

    pub(crate) fn append(&self, bytes: &[u8]) -> Result<u64, String> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| "WinFS disk lock is poisoned".to_string())?;
        let offset = file
            .seek(SeekFrom::End(0))
            .map_err(|e| format!("cannot seek WinFS disk: {e}"))?;
        file.write_all(bytes)
            .map_err(|e| format!("cannot write WinFS disk: {e}"))?;
        Ok(offset)
    }

    pub(crate) fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| "WinFS disk lock is poisoned".to_string())?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("cannot seek WinFS disk: {e}"))?;
        file.write_all(bytes)
            .map_err(|e| format!("cannot write WinFS disk: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("cannot flush WinFS disk: {e}"))
    }

    pub(crate) fn append_from(
        &self,
        source: &DiskStore,
        offset: u64,
        length: u64,
    ) -> Result<u64, String> {
        if std::ptr::eq(self, source) {
            let mut file = self
                .file
                .lock()
                .map_err(|_| "WinFS disk lock is poisoned".to_string())?;
            let target = file
                .seek(SeekFrom::End(0))
                .map_err(|e| format!("cannot seek WinFS disk: {e}"))?;
            let mut remaining = length;
            let mut consumed = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            while remaining != 0 {
                let amount = remaining.min(buffer.len() as u64) as usize;
                file.seek(SeekFrom::Start(offset + consumed))
                    .map_err(|e| format!("cannot seek WinFS disk: {e}"))?;
                file.read_exact(&mut buffer[..amount])
                    .map_err(|e| format!("cannot read WinFS disk: {e}"))?;
                file.seek(SeekFrom::End(0))
                    .map_err(|e| format!("cannot seek WinFS disk: {e}"))?;
                file.write_all(&buffer[..amount])
                    .map_err(|e| format!("cannot write WinFS disk: {e}"))?;
                remaining -= amount as u64;
                consumed += amount as u64;
            }
            return Ok(target);
        }
        let mut source_file = source
            .file
            .lock()
            .map_err(|_| "WinFS source disk lock is poisoned".to_string())?;
        let mut target_file = self
            .file
            .lock()
            .map_err(|_| "WinFS disk lock is poisoned".to_string())?;
        let target = target_file
            .seek(SeekFrom::End(0))
            .map_err(|e| format!("cannot seek WinFS disk: {e}"))?;
        source_file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| format!("cannot seek WinFS source disk: {e}"))?;
        let mut remaining = length;
        let mut buffer = [0u8; 64 * 1024];
        while remaining != 0 {
            let amount = remaining.min(buffer.len() as u64) as usize;
            source_file
                .read_exact(&mut buffer[..amount])
                .map_err(|e| format!("cannot read WinFS source disk: {e}"))?;
            target_file
                .write_all(&buffer[..amount])
                .map_err(|e| format!("cannot write WinFS disk: {e}"))?;
            remaining -= amount as u64;
        }
        Ok(target)
    }
}

impl Drop for DiskStore {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Clone)]
enum FileData {
    Bytes(Vec<u8>),
    Disk {
        store: Arc<DiskStore>,
        offset: u64,
        length: u64,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct SnapshotFile {
    pub path: String,
    data: FileData,
}

impl SnapshotFile {
    pub(crate) fn disk_location(&self) -> Option<(Arc<DiskStore>, u64, u64)> {
        match &self.data {
            FileData::Bytes(_) => None,
            FileData::Disk {
                store,
                offset,
                length,
            } => Some((Arc::clone(store), *offset, *length)),
        }
    }

    pub(crate) fn append_to(&self, output: &DiskStore) -> Result<(u64, u64), String> {
        match &self.data {
            FileData::Bytes(bytes) => Ok((output.append(bytes)?, bytes.len() as u64)),
            FileData::Disk {
                store,
                offset,
                length,
            } => {
                let new_offset = output.append_from(store, *offset, *length)?;
                Ok((new_offset, *length))
            }
        }
    }

    pub(crate) fn is_stored_in(&self, path: &Path) -> bool {
        match &self.data {
            FileData::Bytes(_) => false,
            FileData::Disk { store, .. } => same_file_path(store.path(), path),
        }
    }
}

fn same_file_path(left: &Path, right: &Path) -> bool {
    let left = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let right = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    left == right
}

impl FileData {
    fn len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::Disk { length, .. } => *length,
        }
    }
    fn read(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Bytes(bytes) => Ok(bytes.clone()),
            Self::Disk {
                store,
                offset,
                length,
            } => {
                let length = usize::try_from(*length)
                    .map_err(|_| "guest file is too large to read into memory".to_string())?;
                store.read_at(*offset, length)
            }
        }
    }
    fn read_range(&self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        let size = self.len();
        if offset >= size || length == 0 {
            return Ok(Vec::new());
        }
        let count = usize::try_from((size - offset).min(length as u64))
            .map_err(|_| "guest read is too large".to_string())?;
        match self {
            Self::Bytes(bytes) => Ok(bytes[offset as usize..offset as usize + count].to_vec()),
            Self::Disk {
                store,
                offset: start,
                ..
            } => store.read_at(start + offset, count),
        }
    }

    fn version(&self) -> u64 {
        match self {
            Self::Disk { offset, length, .. } => offset.rotate_left(17) ^ length,
            Self::Bytes(bytes) => bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3)
            }),
        }
    }
}

#[derive(Debug, Clone)]
enum Node {
    Dir {
        name: String,
        children: HashMap<String, Node>,
    },
    File {
        name: String,
        data: FileData,
    },
}

impl Node {
    fn name(&self) -> &str {
        match self {
            Node::Dir { name, .. } => name,
            Node::File { name, .. } => name,
        }
    }
    fn is_dir(&self) -> bool {
        matches!(self, Node::Dir { .. })
    }
    fn is_file(&self) -> bool {
        matches!(self, Node::File { .. })
    }
}

#[derive(Debug, Clone)]
pub struct WinFs {
    /// drive letter (upper) -> root dir node
    drives: HashMap<char, Node>,
    /// current drive + parts (original casing)
    cwd_drive: char,
    cwd_parts: Vec<String>,
    /// Append-only staging area for writes made after a disk image was opened.
    /// It keeps large guest files out of the host process heap.
    overlay: Option<Arc<DiskStore>>,
    /// Host directory mounts are session-only drives (for example `Z:`).
    /// Their file contents remain in the host filesystem and never enter a
    /// C-drive snapshot.
    mounts: HashMap<char, HostMount>,
    changes: Vec<FsChange>,
    record_changes: bool,
}

#[derive(Debug, Clone)]
struct HostMount {
    root: PathBuf,
    read_only: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum FsChange {
    Mkdir(String),
    Write {
        path: String,
        offset: Option<(u64, u64)>,
        bytes: Vec<u8>,
    },
    Remove {
        path: String,
        recursive: bool,
    },
    Move {
        source: String,
        target: String,
    },
    Copy {
        source: String,
        target: String,
        overwrite: bool,
    },
    SetCwd(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinPath {
    pub drive: char,
    /// path components with original casing (normalized `.`/`..` resolved)
    pub parts: Vec<String>,
}

impl WinPath {
    pub fn display(&self) -> String {
        let mut s = String::new();
        s.push(self.drive);
        s.push_str(":\\");
        s.push_str(&self.parts.join("\\"));
        s
    }
    /// lowercase key for case-insensitive lookup
    pub fn key(&self) -> String {
        let mut s = String::new();
        s.push(self.drive);
        s.push_str(":\\");
        s.push_str(
            &self
                .parts
                .iter()
                .map(|p| p.to_lowercase())
                .collect::<Vec<_>>()
                .join("\\"),
        );
        s
    }
}

fn is_drive_letter(c: char) -> bool {
    c.is_ascii_alphabetic()
}

impl Default for WinFs {
    fn default() -> Self {
        Self::new()
    }
}

impl WinFs {
    pub fn new() -> Self {
        let mut drives = HashMap::new();
        drives.insert(
            'C',
            Node::Dir {
                name: String::new(),
                children: HashMap::new(),
            },
        );
        Self {
            drives,
            cwd_drive: 'C',
            cwd_parts: Vec::new(),
            overlay: DiskStore::temporary(),
            mounts: HashMap::new(),
            changes: Vec::new(),
            record_changes: true,
        }
    }

    /// Build the empty disk for one ephemeral Windows runner instance.
    ///
    /// This deliberately creates no host mount and contains no persisted
    /// state. Callers own the returned filesystem; dropping it destroys the
    /// instance disk. The layout mirrors the writable locations a freshly
    /// provisioned Windows Actions-style runner expects before it downloads
    /// tools or checks out a repository.
    pub fn ephemeral_runner() -> Self {
        let mut fs = Self::new();
        for path in [
            r"C:\\Windows\\System32",
            r"C:\\Windows\\Temp",
            r"C:\\Program Files",
            r"C:\\Users\\runner",
            r"C:\\Users\\runner\\AppData\\Local\\Temp",
            r"C:\\actions-runner\\_work",
            r"C:\\actions-runner\\_diag",
            r"C:\\actions-runner\\externals",
        ] {
            // The paths above have no conflicting files in a fresh WinFs.
            fs.mkdir(path)
                .expect("ephemeral runner layout must be internally valid");
        }
        fs.set_cwd(r"C:\\actions-runner\\_work")
            .expect("ephemeral runner work directory must exist");
        fs
    }

    pub fn cwd(&self) -> String {
        WinPath {
            drive: self.cwd_drive,
            parts: self.cwd_parts.clone(),
        }
        .display()
    }

    /// Mount an existing host directory as a guest drive. The mount is live:
    /// guest reads and writes access files in place, and mount configuration
    /// is deliberately excluded from C-drive snapshots.
    pub fn mount_host_dir(
        &mut self,
        drive: char,
        path: &Path,
        read_only: bool,
    ) -> Result<(), String> {
        let drive = drive.to_ascii_uppercase();
        if !drive.is_ascii_alphabetic() || drive == 'C' {
            return Err("host mounts require a drive letter other than C:".to_string());
        }
        let root = path
            .canonicalize()
            .map_err(|e| format!("cannot mount {}: {e}", path.display()))?;
        if !root.is_dir() {
            return Err(format!(
                "mount source is not a directory: {}",
                path.display()
            ));
        }
        self.drives.insert(
            drive,
            Node::Dir {
                name: String::new(),
                children: HashMap::new(),
            },
        );
        self.mounts.insert(drive, HostMount { root, read_only });
        Ok(())
    }

    pub fn host_mounts(&self) -> Vec<(char, PathBuf, bool)> {
        let mut mounts: Vec<_> = self
            .mounts
            .iter()
            .map(|(drive, mount)| (*drive, mount.root.clone(), mount.read_only))
            .collect();
        mounts.sort_by_key(|entry| entry.0);
        mounts
    }

    pub(crate) fn snapshot_files(&self) -> Vec<SnapshotFile> {
        fn visit(node: &Node, path: &str, out: &mut Vec<SnapshotFile>) {
            match node {
                Node::File { data, .. } => out.push(SnapshotFile {
                    path: path.to_string(),
                    data: data.clone(),
                }),
                Node::Dir { children, .. } => {
                    for child in children.values() {
                        visit(child, &format!("{path}\\{}", child.name()), out);
                    }
                }
            }
        }
        let mut out = Vec::new();
        if let Some(root) = self.drives.get(&'C') {
            visit(root, "C:", &mut out);
        }
        out.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
        out
    }

    pub(crate) fn snapshot_directories(&self) -> Vec<String> {
        fn visit(node: &Node, path: &str, out: &mut Vec<String>) {
            if let Node::Dir { children, .. } = node {
                for child in children.values() {
                    let child_path = format!("{path}\\{}", child.name());
                    if child.is_dir() {
                        out.push(child_path.clone());
                    }
                    visit(child, &child_path, out);
                }
            }
        }
        let mut out = Vec::new();
        if let Some(root) = self.drives.get(&'C') {
            visit(root, "C:", &mut out);
        }
        out.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
        out
    }

    pub(crate) fn open_snapshot_file(
        &mut self,
        path: &str,
        store: Arc<DiskStore>,
        offset: u64,
        length: u64,
    ) -> Result<(), String> {
        let p = self.normalize(path)?;
        if p.drive != 'C' || p.parts.is_empty() {
            return Err(format!("snapshot may only contain C: files: {path}"));
        }
        let parent = self.parent_of(&p);
        self.mkdir(&parent.display())?;
        let parent_node = self
            .get_node_mut(&parent)
            .ok_or_else(|| format!("snapshot parent not found: {}", parent.display()))?;
        let Node::Dir { children, .. } = parent_node else {
            return Err(format!("snapshot parent is a file: {}", parent.display()));
        };
        let leaf = p.parts.last().unwrap().clone();
        children.insert(
            leaf.to_lowercase(),
            Node::File {
                name: leaf,
                data: FileData::Disk {
                    store,
                    offset,
                    length,
                },
            },
        );
        Ok(())
    }

    pub(crate) fn mark_snapshot_file(
        &mut self,
        path: &str,
        store: Arc<DiskStore>,
        offset: u64,
        length: u64,
    ) -> Result<(), String> {
        let p = self.normalize(path)?;
        let Some(Node::File { data, .. }) = self.get_node_mut(&p) else {
            return Err(format!(
                "snapshot file disappeared while saving: {}",
                p.display()
            ));
        };
        *data = FileData::Disk {
            store,
            offset,
            length,
        };
        Ok(())
    }

    pub(crate) fn clear_changes(&mut self) {
        self.changes.clear();
    }
    pub(crate) fn changes(&self) -> &[FsChange] {
        &self.changes
    }

    pub(crate) fn apply_changes(&mut self, changes: &[FsChange]) -> Result<(), String> {
        let result = (|| {
            for change in changes {
                match change {
                    FsChange::Mkdir(path) => self.mkdir(path)?,
                    FsChange::Write {
                        path,
                        offset: Some((offset, length)),
                        ..
                    } => {
                        let p = self.normalize(path)?;
                        if p.drive != 'C' {
                            continue;
                        }
                        let parent = self.parent_of(&p);
                        self.mkdir(&parent.display())?;
                        let store = self
                            .overlay
                            .as_ref()
                            .cloned()
                            .ok_or("WinFS disk overlay is unavailable")?;
                        let parent_node = self
                            .get_node_mut(&parent)
                            .ok_or_else(|| format!("write parent missing: {}", parent.display()))?;
                        let Node::Dir { children, .. } = parent_node else {
                            return Err(format!("write parent is a file: {}", parent.display()));
                        };
                        let leaf = p.parts.last().unwrap().clone();
                        children.insert(
                            leaf.to_lowercase(),
                            Node::File {
                                name: leaf,
                                data: FileData::Disk {
                                    store,
                                    offset: *offset,
                                    length: *length,
                                },
                            },
                        );
                        if self.record_changes {
                            self.changes.push(FsChange::Write {
                                path: p.display(),
                                offset: Some((*offset, *length)),
                                bytes: Vec::new(),
                            });
                        }
                    }
                    FsChange::Write { path, bytes, .. } => self.write_file(path, bytes.clone())?,
                    FsChange::Remove { path, recursive } => {
                        if self.exists(path) {
                            self.remove(path, *recursive)?;
                        }
                    }
                    FsChange::Move { source, target } => self.move_path(source, target)?,
                    FsChange::Copy {
                        source,
                        target,
                        overwrite,
                    } => self.copy_path(source, target, !*overwrite)?,
                    FsChange::SetCwd(path) => self.set_cwd(path)?,
                }
            }
            Ok(())
        })();
        result
    }

    fn record_write(&mut self, path: &str) -> Result<(), String> {
        if !self.record_changes {
            return Ok(());
        }
        let p = self.normalize(path)?;
        if p.drive != 'C' {
            return Ok(());
        }
        let Some(Node::File { data, .. }) = self.get_node(&p) else {
            return Ok(());
        };
        let change = match data {
            FileData::Disk {
                store,
                offset,
                length,
            } if self
                .overlay
                .as_ref()
                .is_some_and(|overlay| Arc::ptr_eq(overlay, store)) =>
            {
                FsChange::Write {
                    path: p.display(),
                    offset: Some((*offset, *length)),
                    bytes: Vec::new(),
                }
            }
            _ => FsChange::Write {
                path: p.display(),
                offset: None,
                bytes: data.read()?,
            },
        };
        self.changes.push(change);
        Ok(())
    }

    fn is_host_drive(&self, drive: char) -> bool {
        self.mounts.contains_key(&drive)
    }

    /// Resolve a guest path one component at a time. This provides Windows
    /// case-insensitive lookup while keeping host file contents demand-read.
    fn host_path(&self, p: &WinPath, allow_missing_leaf: bool) -> Result<PathBuf, String> {
        let mount = self
            .mounts
            .get(&p.drive)
            .ok_or_else(|| format!("drive {}: is not mounted", p.drive))?;
        let mut current = mount.root.clone();
        for (index, component) in p.parts.iter().enumerate() {
            let found = std::fs::read_dir(&current).ok().and_then(|entries| {
                entries.filter_map(Result::ok).find(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(component)
                })
            });
            if let Some(entry) = found {
                current = entry.path();
                let metadata = std::fs::symlink_metadata(&current).map_err(|e| {
                    format!("cannot inspect mounted path {}: {e}", current.display())
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "mounted path may not traverse symlinks: {}",
                        current.display()
                    ));
                }
                let resolved = current.canonicalize().map_err(|e| {
                    format!("cannot resolve mounted path {}: {e}", current.display())
                })?;
                if !resolved.starts_with(&mount.root) {
                    return Err(format!("mounted path escaped {}", mount.root.display()));
                }
                current = resolved;
            } else if allow_missing_leaf {
                return Ok(p.parts[index..]
                    .iter()
                    .collect::<PathBuf>()
                    .components()
                    .fold(current, |path, part| path.join(part)));
            } else {
                return Err(format!("path not found: {}", p.display()));
            }
        }
        Ok(current)
    }

    fn ensure_writable_mount(&self, drive: char) -> Result<(), String> {
        if self
            .mounts
            .get(&drive)
            .map(|mount| mount.read_only)
            .unwrap_or(false)
        {
            Err(format!("drive {drive}: is mounted read-only"))
        } else {
            Ok(())
        }
    }

    /// Stable identity for an open path within this in-memory filesystem.
    /// Case variants and repeated opens of the same path have the same ID.
    pub fn file_id(&self, path: &str) -> Result<u64, String> {
        let key = self.normalize(path)?.key();
        Ok(key.bytes().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
        }))
    }

    pub fn set_cwd(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        // must exist and be a dir
        if !self.is_dir(&p.display()) {
            return Err(format!("path not found: {path}"));
        }
        self.cwd_drive = p.drive;
        self.cwd_parts = p.parts;
        if self.record_changes {
            self.changes.push(FsChange::SetCwd(self.cwd()));
        }
        Ok(())
    }

    /// Parse + normalize a Windows path. Handles `\` and `/`, drive letters,
    /// absolute (`C:\...`, `\...`) vs relative, `.` and `..`.
    pub fn normalize(&self, raw: &str) -> Result<WinPath, String> {
        let s = raw.trim();
        if s.is_empty() {
            return Err("empty path".to_string());
        }
        // Normalize separators to backslash for parsing (but keep case).
        let mut s = s.replace('/', "\\");
        // Win32 and libuv use the extended-length DOS namespace to bypass
        // MAX_PATH handling. It has the same drive/path semantics as a DOS
        // path for this filesystem; normalize the prefix before parsing so
        // recursive mkdir/stat operations don't mistake `\\?` for a path
        // component. `\??\` is the corresponding NT object-manager prefix.
        if let Some(rest) = s.strip_prefix("\\\\?\\") {
            s = rest.to_string();
        } else if let Some(rest) = s.strip_prefix("\\??\\") {
            s = rest.to_string();
        }

        let (drive, rest): (char, &str) = if s.len() >= 2
            && is_drive_letter(s.chars().next().unwrap())
            && s.chars().nth(1) == Some(':')
        {
            let d = s.chars().next().unwrap().to_ascii_uppercase();
            if !self.drives.contains_key(&d) {
                return Err(format!(
                    "unsupported drive in path: {raw} ({d}: is not mounted)"
                ));
            }
            let rest = &s[2..];
            (d, rest)
        } else if s.starts_with('\\') {
            (self.cwd_drive, s.as_str())
        } else {
            // relative: start from cwd
            let base_parts = if self.cwd_drive == 'C' {
                self.cwd_parts.clone()
            } else {
                vec![]
            };
            let mut parts = base_parts;
            for comp in s.split('\\') {
                match comp {
                    "" | "." => continue,
                    ".." => {
                        parts.pop();
                    }
                    _ => parts.push(comp.to_string()),
                }
            }
            return Ok(WinPath {
                drive: self.cwd_drive,
                parts,
            });
        };

        // absolute on drive
        let mut parts: Vec<String> = if rest.starts_with('\\') {
            Vec::new()
        } else {
            // e.g. "C:foo" -> drive-relative; treat as cwd-relative on that drive
            if self.cwd_drive == drive {
                self.cwd_parts.clone()
            } else {
                Vec::new()
            }
        };
        // strip leading backslashes
        let rest = rest.trim_start_matches('\\');
        if rest.is_empty() {
            return Ok(WinPath { drive, parts });
        }
        for comp in rest.split('\\') {
            match comp {
                "" => continue, // collapse duplicate separators / trailing slash
                "." => continue,
                ".." => {
                    parts.pop();
                }
                _ => parts.push(comp.to_string()),
            }
        }
        Ok(WinPath { drive, parts })
    }

    fn get_node(&self, p: &WinPath) -> Option<&Node> {
        let mut node = self.drives.get(&p.drive)?;
        for part in &p.parts {
            match node {
                Node::Dir { children, .. } => {
                    node = children.get(&part.to_lowercase())?;
                }
                Node::File { .. } => return None,
            }
        }
        Some(node)
    }

    fn get_node_mut(&mut self, p: &WinPath) -> Option<&mut Node> {
        let mut node = self.drives.get_mut(&p.drive)?;
        for part in &p.parts {
            match node {
                Node::Dir { children, .. } => {
                    node = children.get_mut(&part.to_lowercase())?;
                }
                Node::File { .. } => return None,
            }
        }
        Some(node)
    }

    fn parent_of(&self, p: &WinPath) -> WinPath {
        let mut parts = p.parts.clone();
        parts.pop();
        WinPath {
            drive: p.drive,
            parts,
        }
    }

    // ---- queries (same API for EXE + PS1) ----

    pub fn exists(&self, path: &str) -> bool {
        let Ok(p) = self.normalize(path) else {
            return false;
        };
        if self.is_host_drive(p.drive) {
            return self
                .host_path(&p, false)
                .map(|path| path.exists())
                .unwrap_or(false);
        }
        self.get_node(&p).is_some()
    }

    pub fn is_file(&self, path: &str) -> bool {
        let Ok(p) = self.normalize(path) else {
            return false;
        };
        if self.is_host_drive(p.drive) {
            return self
                .host_path(&p, false)
                .and_then(|p| std::fs::metadata(p).map_err(|e| e.to_string()))
                .map(|m| m.is_file())
                .unwrap_or(false);
        }
        self.get_node(&p).map(|n| n.is_file()).unwrap_or(false)
    }

    pub fn is_dir(&self, path: &str) -> bool {
        let Ok(p) = self.normalize(path) else {
            return false;
        };
        if self.is_host_drive(p.drive) {
            return self
                .host_path(&p, false)
                .and_then(|p| std::fs::metadata(p).map_err(|e| e.to_string()))
                .map(|m| m.is_dir())
                .unwrap_or(false);
        }
        self.get_node(&p).map(|n| n.is_dir()).unwrap_or(false)
    }

    /// File length without reading the file payload into memory.
    pub fn file_len(&self, path: &str) -> Result<u64, String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            let host = self.host_path(&p, false)?;
            return std::fs::metadata(&host)
                .map(|m| m.len())
                .map_err(|e| format!("cannot stat {}: {e}", p.display()));
        }
        match self.get_node(&p) {
            Some(Node::File { data, .. }) => Ok(data.len()),
            Some(Node::Dir { .. }) => Err(format!("path is a directory: {}", p.display())),
            None => Err(format!("file not found: {}", p.display())),
        }
    }

    /// A cheap change token for directory notifications. Disk-backed files
    /// change extents on write, so this avoids reading file contents just to
    /// notice a mutation.
    pub fn file_version(&self, path: &str) -> Result<u64, String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            let host = self.host_path(&p, false)?;
            let metadata = std::fs::metadata(&host)
                .map_err(|e| format!("cannot stat {}: {e}", p.display()))?;
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos() as u64)
                .unwrap_or_default();
            return Ok(metadata.len().rotate_left(17) ^ modified);
        }
        match self.get_node(&p) {
            Some(Node::File { data, .. }) => Ok(data.version()),
            Some(Node::Dir { .. }) => Err(format!("path is a directory: {}", p.display())),
            None => Err(format!("file not found: {}", p.display())),
        }
    }

    pub fn test_path(&self, path: &str) -> bool {
        self.exists(path)
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            let host = self.host_path(&p, false)?;
            return std::fs::read(&host)
                .map_err(|e| format!("cannot read mounted file {}: {e}", p.display()));
        }
        match self.get_node(&p) {
            Some(Node::File { data, .. }) => data.read(),
            Some(Node::Dir { .. }) => Err(format!("path is a directory: {}", p.display())),
            None => Err(format!("file not found: {}", p.display())),
        }
    }

    /// Read a file range without loading the rest of its contents. Native
    /// `ReadFile` and overlapped reads use this seekable path.
    pub fn read_file_range(
        &self,
        path: &str,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            let host = self.host_path(&p, false)?;
            let mut file = File::open(&host)
                .map_err(|e| format!("cannot open mounted file {}: {e}", p.display()))?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| format!("cannot seek mounted file {}: {e}", p.display()))?;
            let mut bytes = vec![0; length];
            let count = file
                .read(&mut bytes)
                .map_err(|e| format!("cannot read mounted file {}: {e}", p.display()))?;
            bytes.truncate(count);
            return Ok(bytes);
        }
        match self.get_node(&p) {
            Some(Node::File { data, .. }) => data.read_range(offset, length),
            Some(Node::Dir { .. }) => Err(format!("path is a directory: {}", p.display())),
            None => Err(format!("file not found: {}", p.display())),
        }
    }

    pub fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            let host = self.host_path(&p, false)?;
            let mut names = std::fs::read_dir(&host)
                .map_err(|e| format!("cannot list mounted directory {}: {e}", p.display()))?
                .map(|entry| {
                    entry
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            names.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
            return Ok(names);
        }
        match self.get_node(&p) {
            Some(Node::Dir { children, .. }) => {
                let mut names: Vec<String> =
                    children.values().map(|n| n.name().to_string()).collect();
                names.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
                Ok(names)
            }
            Some(Node::File { .. }) => Err(format!("not a directory: {}", p.display())),
            None => Err(format!("path not found: {}", p.display())),
        }
    }

    /// Return every regular file as an absolute Windows path and its bytes.
    /// Snapshot code uses this to serialize an isolated instance without ever
    /// consulting the Linux filesystem.
    pub fn files(&self) -> Vec<(String, Vec<u8>)> {
        fn visit(node: &Node, path: &str, out: &mut Vec<(String, Vec<u8>)>) {
            match node {
                Node::File { data, .. } => {
                    if let Ok(bytes) = data.read() {
                        out.push((path.to_string(), bytes));
                    }
                }
                Node::Dir { children, .. } => {
                    for child in children.values() {
                        visit(child, &format!("{path}\\{}", child.name()), out);
                    }
                }
            }
        }
        let mut out = Vec::new();
        for (drive, root) in &self.drives {
            visit(root, &format!("{drive}:"), &mut out);
        }
        out.sort_by(|left, right| left.0.cmp(&right.0));
        out
    }

    /// Find a C-drive file by case-insensitive suffix without reading file
    /// contents. Useful for resolving installed tools on a large guest disk.
    pub fn find_file_path_suffix(&self, suffix: &str) -> Option<String> {
        fn visit(node: &Node, path: &str, suffix: &str) -> Option<String> {
            match node {
                Node::File { .. } => path
                    .to_lowercase()
                    .ends_with(&suffix.to_lowercase())
                    .then(|| path.to_string()),
                Node::Dir { children, .. } => children
                    .values()
                    .find_map(|child| visit(child, &format!("{path}\\{}", child.name()), suffix)),
            }
        }
        self.drives
            .get(&'C')
            .and_then(|root| visit(root, "C:", suffix))
    }

    /// Return all directories below drive roots, including empty ones.
    pub fn directories(&self) -> Vec<String> {
        fn visit(node: &Node, path: &str, out: &mut Vec<String>) {
            if let Node::Dir { children, .. } = node {
                for child in children.values() {
                    let child_path = format!("{path}\\{}", child.name());
                    if child.is_dir() {
                        out.push(child_path.clone());
                    }
                    visit(child, &child_path, out);
                }
            }
        }
        let mut out = Vec::new();
        for (drive, root) in &self.drives {
            visit(root, &format!("{drive}:"), &mut out);
        }
        out.sort();
        out
    }

    // ---- mutations ----

    /// Create all missing directories along `path` (like mkdir -p).
    pub fn mkdir(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            self.ensure_writable_mount(p.drive)?;
            let host = self.host_path(&p, true)?;
            return std::fs::create_dir_all(&host)
                .map_err(|e| format!("cannot create mounted directory {}: {e}", p.display()));
        }
        if p.parts.is_empty() {
            return Ok(()); // root exists
        }
        // walk, creating as needed (case-insensitive match, preserve first casing)
        let mut node = self
            .drives
            .get_mut(&p.drive)
            .ok_or_else(|| format!("unsupported drive: {}", p.drive))?;
        for part in &p.parts {
            let key = part.to_lowercase();
            let next = node;
            match next {
                Node::Dir { children, .. } => {
                    if let Some(existing) = children.get(&key) {
                        if existing.is_file() {
                            return Err(format!("path component is a file: {part}"));
                        }
                    } else {
                        children.insert(
                            key.clone(),
                            Node::Dir {
                                name: part.clone(),
                                children: HashMap::new(),
                            },
                        );
                    }
                    node = children.get_mut(&key).unwrap();
                }
                Node::File { .. } => return Err("parent is a file".to_string()),
            }
        }
        if self.record_changes {
            self.changes.push(FsChange::Mkdir(p.display()));
        }
        Ok(())
    }

    /// Create a single directory; fails if parent missing (Windows-like).
    /// Used by CreateDirectoryW. Use `mkdir` (recursive) for PS1 New-Item -Force.
    pub fn mkdir_one(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            self.ensure_writable_mount(p.drive)?;
            let host = self.host_path(&p, true)?;
            return std::fs::create_dir(&host)
                .map_err(|e| format!("cannot create mounted directory {}: {e}", p.display()));
        }
        if p.parts.is_empty() {
            return Err("cannot create root".to_string());
        }
        if self.get_node(&p).is_some() {
            return Err(format!("already exists: {}", p.display()));
        }
        let parent = self.parent_of(&p);
        let parent_node = self
            .get_node_mut(&parent)
            .ok_or_else(|| format!("parent not found: {}", parent.display()))?;
        match parent_node {
            Node::Dir { children, .. } => {
                let leaf = p.parts.last().unwrap().clone();
                children.insert(
                    leaf.to_lowercase(),
                    Node::Dir {
                        name: leaf,
                        children: HashMap::new(),
                    },
                );
                if self.record_changes {
                    self.changes.push(FsChange::Mkdir(p.display()));
                }
                Ok(())
            }
            Node::File { .. } => Err("parent is a file".to_string()),
        }
    }

    pub fn rmdir(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            self.ensure_writable_mount(p.drive)?;
            let host = self.host_path(&p, false)?;
            return std::fs::remove_dir(&host)
                .map_err(|e| format!("cannot remove mounted directory {}: {e}", p.display()));
        }
        if p.parts.is_empty() {
            return Err("cannot remove root".to_string());
        }
        // check empty
        match self.get_node(&p) {
            Some(Node::Dir { children, .. }) => {
                if !children.is_empty() {
                    return Err(format!("directory not empty: {}", p.display()));
                }
            }
            Some(Node::File { .. }) => return Err(format!("not a directory: {}", p.display())),
            None => return Err(format!("path not found: {}", p.display())),
        }
        let parent = self.parent_of(&p);
        let leaf_key = p.parts.last().unwrap().to_lowercase();
        let parent_node = self.get_node_mut(&parent).unwrap();
        if let Node::Dir { children, .. } = parent_node {
            children.remove(&leaf_key);
            if self.record_changes {
                self.changes.push(FsChange::Remove {
                    path: p.display(),
                    recursive: false,
                });
            }
            Ok(())
        } else {
            Err("parent is a file".to_string())
        }
    }

    pub fn write_file(&mut self, path: &str, data: Vec<u8>) -> Result<(), String> {
        let p = self.normalize(path)?;
        if p.parts.is_empty() {
            return Err("cannot write to root".to_string());
        }
        if self.is_host_drive(p.drive) {
            self.ensure_writable_mount(p.drive)?;
            let host = self.host_path(&p, true)?;
            return std::fs::write(&host, data)
                .map_err(|e| format!("cannot write mounted file {}: {e}", p.display()));
        }
        let stored = self.store_file(data)?;
        if self.get_node(&p).is_some() {
            let node = self.get_node_mut(&p).unwrap();
            match node {
                Node::File { data: d, .. } => {
                    *d = stored;
                    self.record_write(&p.display())
                }
                Node::Dir { .. } => Err(format!("path is a directory: {}", p.display())),
            }
        } else {
            // create; parent must exist
            let parent = self.parent_of(&p);
            let parent_node = self
                .get_node_mut(&parent)
                .ok_or_else(|| format!("parent not found: {}", parent.display()))?;
            match parent_node {
                Node::Dir { children, .. } => {
                    let leaf = p.parts.last().unwrap().clone();
                    children.insert(
                        leaf.to_lowercase(),
                        Node::File {
                            name: leaf,
                            data: stored,
                        },
                    );
                    self.record_write(&p.display())
                }
                Node::File { .. } => Err("parent is a file".to_string()),
            }
        }
    }

    pub fn append_file(&mut self, path: &str, data: &[u8]) -> Result<(), String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            self.ensure_writable_mount(p.drive)?;
            let host = self.host_path(&p, true)?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&host)
                .map_err(|e| format!("cannot append mounted file {}: {e}", p.display()))?;
            return file
                .write_all(data)
                .map_err(|e| format!("cannot append mounted file {}: {e}", p.display()));
        }
        if self.get_node(&p).is_some() {
            let old = match self.get_node(&p) {
                Some(Node::File { data, .. }) => data.clone(),
                Some(Node::Dir { .. }) => {
                    return Err(format!("path is a directory: {}", p.display()))
                }
                None => unreachable!(),
            };
            let stored = match (&old, &self.overlay) {
                (
                    FileData::Disk {
                        store,
                        offset,
                        length,
                    },
                    Some(overlay),
                ) => {
                    let new_offset = overlay.append_from(store, *offset, *length)?;
                    overlay.append(data)?;
                    FileData::Disk {
                        store: Arc::clone(overlay),
                        offset: new_offset,
                        length: *length + data.len() as u64,
                    }
                }
                _ => {
                    let mut contents = old.read()?;
                    contents.extend_from_slice(data);
                    self.store_file(contents)?
                }
            };
            let node = self.get_node_mut(&p).unwrap();
            match node {
                Node::File { data: d, .. } => {
                    *d = stored;
                    self.record_write(&p.display())
                }
                Node::Dir { .. } => Err(format!("path is a directory: {}", p.display())),
            }
        } else {
            self.write_file(path, data.to_vec())
        }
    }

    pub fn delete_file(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        if self.is_host_drive(p.drive) {
            self.ensure_writable_mount(p.drive)?;
            let host = self.host_path(&p, false)?;
            return std::fs::remove_file(&host)
                .map_err(|e| format!("cannot remove mounted file {}: {e}", p.display()));
        }
        match self.get_node(&p) {
            Some(Node::File { .. }) => {}
            Some(Node::Dir { .. }) => return Err(format!("is a directory: {}", p.display())),
            None => return Err(format!("file not found: {}", p.display())),
        }
        let parent = self.parent_of(&p);
        let leaf_key = p.parts.last().unwrap().to_lowercase();
        let parent_node = self.get_node_mut(&parent).unwrap();
        if let Node::Dir { children, .. } = parent_node {
            children.remove(&leaf_key);
            if self.record_changes {
                self.changes.push(FsChange::Remove {
                    path: p.display(),
                    recursive: false,
                });
            }
            Ok(())
        } else {
            Err("parent is a file".to_string())
        }
    }

    fn store_file(&self, bytes: Vec<u8>) -> Result<FileData, String> {
        if let Some(store) = &self.overlay {
            let offset = store.append(&bytes)?;
            Ok(FileData::Disk {
                store: Arc::clone(store),
                offset,
                length: bytes.len() as u64,
            })
        } else {
            Ok(FileData::Bytes(bytes))
        }
    }

    /// Remove file or (empty) dir; with `recursive` removes non-empty dirs.
    pub fn remove(&mut self, path: &str, recursive: bool) -> Result<(), String> {
        let p = self.normalize(path)?;
        if p.parts.is_empty() {
            return Err("cannot remove root".to_string());
        }
        if self.is_host_drive(p.drive) {
            self.ensure_writable_mount(p.drive)?;
            let host = self.host_path(&p, false)?;
            let metadata = std::fs::metadata(&host)
                .map_err(|e| format!("cannot inspect mounted path {}: {e}", p.display()))?;
            let result = if metadata.is_dir() {
                if recursive {
                    std::fs::remove_dir_all(&host)
                } else {
                    std::fs::remove_dir(&host)
                }
            } else {
                std::fs::remove_file(&host)
            };
            return result.map_err(|e| format!("cannot remove mounted path {}: {e}", p.display()));
        }
        let node = self
            .get_node(&p)
            .ok_or_else(|| format!("path not found: {}", p.display()))?
            .clone();
        match node {
            Node::File { .. } => self.delete_file(path),
            Node::Dir { children, .. } => {
                if !children.is_empty() && !recursive {
                    return Err(format!("directory not empty: {}", p.display()));
                }
                let parent = self.parent_of(&p);
                let leaf_key = p.parts.last().unwrap().to_lowercase();
                let parent_node = self.get_node_mut(&parent).unwrap();
                if let Node::Dir { children, .. } = parent_node {
                    children.remove(&leaf_key);
                    if self.record_changes {
                        self.changes.push(FsChange::Remove {
                            path: p.display(),
                            recursive: true,
                        });
                    }
                    Ok(())
                } else {
                    Err("parent is a file".to_string())
                }
            }
        }
    }

    pub fn move_path(&mut self, src: &str, dst: &str) -> Result<(), String> {
        let s = self.normalize(src)?;
        let d = self.normalize(dst)?;
        if s.key() == d.key() {
            return Ok(());
        }
        if self.is_host_drive(s.drive) || self.is_host_drive(d.drive) {
            if self.is_host_drive(s.drive) {
                self.ensure_writable_mount(s.drive)?;
            }
            if self.is_host_drive(d.drive) {
                self.ensure_writable_mount(d.drive)?;
            }
            let source_is_dir = self.is_dir(src);
            if s.drive == d.drive && self.is_host_drive(s.drive) {
                let source = self.host_path(&s, false)?;
                let target = self.host_path(&d, true)?;
                return std::fs::rename(&source, &target)
                    .map_err(|e| format!("cannot move {} to {}: {e}", s.display(), d.display()));
            }
            if source_is_dir {
                return Err(
                    "moving a directory across the guest disk and host mounts is not supported"
                        .to_string(),
                );
            }
            self.copy_path(src, dst, true)?;
            if self.is_host_drive(s.drive) {
                self.delete_file(src)
            } else {
                self.delete_file(src)
            }
        } else {
            let node = self
                .get_node(&s)
                .ok_or_else(|| format!("source not found: {}", s.display()))?
                .clone();
            if self.get_node(&d).is_some() {
                return Err(format!("destination exists: {}", d.display()));
            }
            if d.parts.is_empty() {
                return Err("cannot move to root".to_string());
            }
            // insert under dst leaf name (dst casing wins), then remove src
            let dparent = self.parent_of(&d);
            // cannot move a dir into itself
            if node.is_dir() {
                let sk = s.key() + "\\";
                let dk = d.key() + "\\";
                if dk.starts_with(&sk) {
                    return Err("cannot move directory into itself".to_string());
                }
            }
            let mut moved = node;
            // rename top-level to dst leaf original casing
            let leaf = d.parts.last().unwrap().clone();
            match &mut moved {
                Node::Dir { name, .. } => *name = leaf.clone(),
                Node::File { name, .. } => *name = leaf.clone(),
            }
            {
                let dp = self.get_node_mut(&dparent).ok_or_else(|| {
                    format!("destination parent not found: {}", dparent.display())
                })?;
                match dp {
                    Node::Dir { children, .. } => {
                        children.insert(leaf.to_lowercase(), moved);
                    }
                    Node::File { .. } => return Err("destination parent is a file".to_string()),
                }
            }
            // remove src
            let sparent = self.parent_of(&s);
            let skey = s.parts.last().unwrap().to_lowercase();
            let sp = self.get_node_mut(&sparent).unwrap();
            if let Node::Dir { children, .. } = sp {
                children.remove(&skey);
            }
            if self.record_changes {
                self.changes.push(FsChange::Move {
                    source: s.display(),
                    target: d.display(),
                });
            }
            Ok(())
        }
    }

    pub fn copy_path(&mut self, src: &str, dst: &str, fail_if_exists: bool) -> Result<(), String> {
        let s = self.normalize(src)?;
        let d = self.normalize(dst)?;
        if self.is_host_drive(s.drive) || self.is_host_drive(d.drive) {
            if self.is_host_drive(d.drive) {
                self.ensure_writable_mount(d.drive)?;
            }
            if self.exists(dst) {
                if fail_if_exists {
                    return Err(format!("destination exists: {}", d.display()));
                }
                if self.is_dir(dst) {
                    return Err(format!("destination is a directory: {}", d.display()));
                }
            }
            if self.is_dir(src) {
                self.mkdir(dst)?;
                for name in self.list_dir(src)? {
                    let child_src = format!("{}\\{}", s.display(), name);
                    let child_dst = format!("{}\\{}", d.display(), name);
                    self.copy_path(&child_src, &child_dst, fail_if_exists)?;
                }
                return Ok(());
            }
            let bytes = self.read_file(src)?;
            return self.write_file(dst, bytes);
        }
        let node = self
            .get_node(&s)
            .ok_or_else(|| format!("source not found: {}", s.display()))?
            .clone();
        if self.get_node(&d).is_some() {
            if fail_if_exists {
                return Err(format!("destination exists: {}", d.display()));
            } else {
                // overwrite files only (dirs merge is out of scope; require remove first)
                if node.is_file() {
                    let dst_node = self.get_node(&d).unwrap().clone();
                    if dst_node.is_dir() {
                        return Err(format!("destination is a directory: {}", d.display()));
                    }
                    // overwrite preserving dst casing? use existing name
                    let data = match node {
                        Node::File { data, .. } => data,
                        _ => unreachable!(),
                    };
                    let dst_mut = self.get_node_mut(&d).unwrap();
                    if let Node::File { data: dd, .. } = dst_mut {
                        *dd = data;
                        if self.record_changes {
                            self.changes.push(FsChange::Copy {
                                source: s.display(),
                                target: d.display(),
                                overwrite: true,
                            });
                        }
                        return Ok(());
                    }
                    return Ok(());
                }
                return Err(format!("destination exists: {}", d.display()));
            }
        }
        if d.parts.is_empty() {
            return Err("cannot copy to root".to_string());
        }
        let mut copied = node;
        let leaf = d.parts.last().unwrap().clone();
        match &mut copied {
            Node::Dir { name, .. } => *name = leaf.clone(),
            Node::File { name, .. } => *name = leaf.clone(),
        }
        let dparent = self.parent_of(&d);
        let dp = self
            .get_node_mut(&dparent)
            .ok_or_else(|| format!("destination parent not found: {}", dparent.display()))?;
        match dp {
            Node::Dir { children, .. } => {
                children.insert(leaf.to_lowercase(), copied);
                if self.record_changes {
                    self.changes.push(FsChange::Copy {
                        source: s.display(),
                        target: d.display(),
                        overwrite: false,
                    });
                }
                Ok(())
            }
            Node::File { .. } => Err("destination parent is a file".to_string()),
        }
    }

    /// Copy file bytes (helper for CopyFileW semantics).
    pub fn copy_file(&mut self, src: &str, dst: &str, fail_if_exists: bool) -> Result<(), String> {
        let s = self.normalize(src)?;
        match self.get_node(&s) {
            Some(Node::File { .. }) => {}
            Some(Node::Dir { .. }) => {
                return Err(format!("source is a directory: {}", s.display()))
            }
            None => return Err(format!("source not found: {}", s.display())),
        }
        self.copy_path(src, dst, fail_if_exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_ids_match_case_variants_and_distinguish_paths() {
        let fs = WinFs::new();
        let first = fs.file_id(r"C:\Data\one.txt").unwrap();
        assert_ne!(first, 0);
        assert_eq!(first, fs.file_id(r"c:\data\.\ONE.txt").unwrap());
        assert_ne!(first, fs.file_id(r"C:\Data\two.txt").unwrap());
        assert_ne!(first, fs.file_id(r"C:\Data").unwrap());
        assert!(fs.file_id(r"D:\Data").is_err());
    }

    #[test]
    fn case_insensitive_preserve_case() {
        let mut fs = WinFs::new();
        fs.mkdir("C:\\Test").unwrap();
        fs.write_file("C:\\TEST\\A.txt", b"hi".to_vec()).unwrap();
        assert!(fs.exists("c:\\test\\a.TXT"));
        assert_eq!(fs.read_file("C:\\test\\A.txt").unwrap(), b"hi");
        assert_eq!(fs.list_dir("c:\\TEST").unwrap(), vec!["A.txt".to_string()]);
    }

    #[test]
    fn dot_dot_normalization() {
        let mut fs = WinFs::new();
        fs.mkdir("C:\\a\\b").unwrap();
        fs.write_file("C:\\a\\b\\f.txt", b"x".to_vec()).unwrap();
        assert_eq!(fs.read_file("C:\\a\\.\\b\\f.txt").unwrap(), b"x");
        assert_eq!(fs.read_file("C:\\a\\b\\..\\b\\f.txt").unwrap(), b"x");
        assert!(fs.exists("C:\\a\\b\\..\\b"));
        // relative
        fs.set_cwd("C:\\a\\b").unwrap();
        assert_eq!(fs.read_file(".\\f.txt").unwrap(), b"x");
        assert_eq!(fs.read_file("..\\b\\f.txt").unwrap(), b"x");
    }

    #[test]
    fn reads_seeked_ranges_without_loading_the_whole_file() {
        let mut fs = WinFs::new();
        fs.write_file(r"C:\range.bin", b"0123456789".to_vec())
            .unwrap();
        assert_eq!(fs.file_len(r"C:\range.bin").unwrap(), 10);
        assert_eq!(fs.read_file_range(r"C:\range.bin", 4, 3).unwrap(), b"456");
        assert_eq!(fs.read_file_range(r"C:\range.bin", 9, 8).unwrap(), b"9");
        assert!(fs
            .read_file_range(r"C:\range.bin", 10, 2)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn modern_file_mutations_copy_move_and_delete_like_file_api_cases() {
        let mut fs = WinFs::new();
        fs.mkdir(r"C:\winfs_compat_cases").unwrap();
        let source = r"C:\winfs_compat_cases\source.bin";
        let copy = r"C:\winfs_compat_cases\copy.bin";
        let moved = r"C:\winfs_compat_cases\moved.bin";

        fs.write_file(source, b"first".to_vec()).unwrap();
        fs.append_file(source, b"-second").unwrap();
        assert_eq!(fs.read_file(source).unwrap(), b"first-second");
        assert_eq!(fs.file_len(source).unwrap(), 12);

        fs.copy_path(source, copy, true).unwrap();
        assert_eq!(fs.read_file(copy).unwrap(), b"first-second");
        assert!(fs.copy_path(source, copy, true).is_err());
        fs.copy_path(source, copy, false).unwrap();
        assert_eq!(fs.read_file(copy).unwrap(), b"first-second");

        fs.move_path(copy, moved).unwrap();
        assert!(!fs.exists(copy));
        assert_eq!(fs.read_file(moved).unwrap(), b"first-second");
        assert!(fs.move_path(source, moved).is_err());

        fs.delete_file(source).unwrap();
        fs.delete_file(moved).unwrap();
        assert!(fs.list_dir(r"C:\winfs_compat_cases").unwrap().is_empty());
        fs.rmdir(r"C:\winfs_compat_cases").unwrap();
        assert!(!fs.exists(r"C:\winfs_compat_cases"));
    }

    #[test]
    fn modern_directory_listing_and_metadata_follow_case_insensitive_paths() {
        let mut fs = WinFs::new();
        fs.mkdir(r"C:\winfs_compat_cases\nested").unwrap();
        fs.write_file(r"C:\winfs_compat_cases\Alpha.txt", b"abc".to_vec())
            .unwrap();
        fs.write_file(r"C:\winfs_compat_cases\nested\Beta.txt", b"12345".to_vec())
            .unwrap();

        let mut entries = fs.list_dir(r"c:\WINFS_COMPAT_CASES").unwrap();
        entries.sort();
        assert_eq!(entries, ["Alpha.txt", "nested"]);
        assert!(fs.is_dir(r"C:\winfs_compat_cases\NESTED"));
        assert!(fs.is_file(r"c:\winfs_compat_cases\alpha.TXT"));
        assert_eq!(fs.file_len(r"C:\WINFS_COMPAT_CASES\ALPHA.TXT").unwrap(), 3);
        assert_eq!(
            fs.read_file_range(r"C:\winfs_compat_cases\nested\beta.txt", 2, 8)
                .unwrap(),
            b"345"
        );
        assert_ne!(
            fs.file_id(r"C:\winfs_compat_cases\Alpha.txt").unwrap(),
            fs.file_id(r"C:\winfs_compat_cases\nested\Beta.txt")
                .unwrap()
        );

        assert!(fs.rmdir(r"C:\winfs_compat_cases").is_err());
        fs.remove(r"C:\winfs_compat_cases", true).unwrap();
        assert!(!fs.exists(r"C:\winfs_compat_cases"));
    }

    #[test]
    fn modern_create_always_style_write_truncates_existing_file() {
        let mut fs = WinFs::new();
        let path = r"C:\winfs_compat_cases\truncate.txt";
        fs.mkdir(r"C:\winfs_compat_cases").unwrap();
        fs.write_file(path, b"old contents with a longer tail".to_vec())
            .unwrap();
        fs.write_file(path, b"new".to_vec()).unwrap();
        assert_eq!(fs.read_file(path).unwrap(), b"new");
        assert_eq!(fs.file_len(path).unwrap(), 3);
    }

    #[test]
    fn modern_copy_and_move_directory_tree_preserve_nested_files() {
        let mut fs = WinFs::new();
        let source = r"C:\winfs_compat_cases\source";
        let copied = r"C:\winfs_compat_cases\copied";
        let moved = r"C:\winfs_compat_cases\moved";
        fs.mkdir(&format!(r"{source}\nested")).unwrap();
        fs.write_file(&format!(r"{source}\root.txt"), b"root".to_vec())
            .unwrap();
        fs.write_file(&format!(r"{source}\nested\child.txt"), b"child".to_vec())
            .unwrap();

        fs.copy_path(source, copied, true).unwrap();
        assert_eq!(
            fs.read_file(&format!(r"{copied}\nested\child.txt"))
                .unwrap(),
            b"child"
        );
        assert!(fs.copy_path(source, copied, true).is_err());
        fs.move_path(copied, moved).unwrap();
        assert!(!fs.exists(copied));
        assert_eq!(
            fs.read_file(&format!(r"{moved}\root.txt")).unwrap(),
            b"root"
        );

        fs.remove(source, true).unwrap();
        fs.remove(moved, true).unwrap();
        assert!(!fs.exists(source));
        assert!(!fs.exists(moved));
    }

    #[test]
    fn modern_directory_create_and_remove_report_invalid_states() {
        let mut fs = WinFs::new();
        let parent = r"C:\winfs_compat_cases";
        let child = r"C:\winfs_compat_cases\child";
        assert!(fs.mkdir_one(child).is_err(), "parent must exist first");
        fs.mkdir_one(parent).unwrap();
        assert!(
            fs.mkdir_one(parent).is_err(),
            "creating an existing dir fails"
        );
        fs.mkdir_one(child).unwrap();
        fs.write_file(&format!(r"{child}\entry.txt"), b"x".to_vec())
            .unwrap();
        assert!(
            fs.rmdir(child).is_err(),
            "non-empty directories cannot be removed"
        );
        fs.delete_file(&format!(r"{child}\entry.txt")).unwrap();
        fs.rmdir(child).unwrap();
        fs.rmdir(parent).unwrap();
        assert!(!fs.exists(parent));
    }

    #[test]
    fn extended_dos_and_nt_paths_resolve_like_dos_paths() {
        let mut fs = WinFs::new();
        fs.mkdir(r"C:\Users\wincli\npm-cache\_cacache\tmp").unwrap();
        for extended in [
            r"\\?\C:\Users\wincli\npm-cache\_cacache\tmp",
            r"\??\C:\Users\wincli\npm-cache\_cacache\tmp",
        ] {
            assert!(fs.is_dir(extended), "{extended}");
            assert_eq!(
                fs.normalize(extended).unwrap(),
                fs.normalize(r"C:\Users\wincli\npm-cache\_cacache\tmp")
                    .unwrap()
            );
        }
    }

    #[test]
    fn guest_c_drive_does_not_touch_host_paths_without_a_mount() {
        let mut fs = WinFs::new();
        fs.write_file("C:\\host_check_xyz.txt", b"data".to_vec())
            .unwrap();
        assert!(!std::path::Path::new("C:\\host_check_xyz.txt").exists());
        assert!(!std::path::Path::new("/tmp/host_check_xyz.txt").exists());
        assert!(!std::path::Path::new("host_check_xyz.txt").exists());
    }

    #[test]
    fn ephemeral_runner_has_fresh_windows_runner_layout() {
        let mut first = WinFs::ephemeral_runner();
        assert_eq!(first.cwd(), r"C:\actions-runner\_work");
        for path in [
            r"C:\Windows\System32",
            r"C:\Users\runner\AppData\Local\Temp",
            r"C:\actions-runner\_diag",
        ] {
            assert!(first.is_dir(path), "missing {path}");
        }
        first
            .write_file(r"C:\actions-runner\_work\checkout.txt", b"one".to_vec())
            .unwrap();

        let second = WinFs::ephemeral_runner();
        assert!(!second.exists(r"C:\actions-runner\_work\checkout.txt"));
        assert_eq!(second.cwd(), r"C:\actions-runner\_work");
    }

    #[test]
    fn files_lists_absolute_paths_in_deterministic_order() {
        let mut fs = WinFs::new();
        fs.write_file(r"C:\b.txt", b"b".to_vec()).unwrap();
        fs.mkdir(r"C:\a").unwrap();
        fs.write_file(r"C:\a\a.txt", b"a".to_vec()).unwrap();
        assert_eq!(
            fs.files(),
            vec![
                (r"C:\a\a.txt".to_string(), b"a".to_vec()),
                (r"C:\b.txt".to_string(), b"b".to_vec()),
            ]
        );
    }

    #[test]
    fn mounted_host_drive_maps_files_and_writes_through() {
        let root = std::env::temp_dir().join(format!(
            "wincli-mount-{}-{}",
            std::process::id(),
            NEXT_DISK_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("Folder")).unwrap();
        std::fs::write(root.join("Folder/Hello.txt"), b"host-data").unwrap();
        let mut fs = WinFs::ephemeral_runner();
        fs.mount_host_dir('z', &root, false).unwrap();
        assert!(fs.is_dir(r"Z:\folder"));
        assert_eq!(fs.read_file(r"z:\FOLDER\hello.TXT").unwrap(), b"host-data");
        assert_eq!(fs.list_dir(r"Z:\folder").unwrap(), vec!["Hello.txt"]);

        fs.mkdir(r"Z:\new\nested").unwrap();
        fs.write_file(r"Z:\new\nested\created.txt", b"guest-write".to_vec())
            .unwrap();
        fs.append_file(r"Z:\new\nested\created.txt", b"-through")
            .unwrap();
        assert_eq!(
            std::fs::read(root.join("new/nested/created.txt")).unwrap(),
            b"guest-write-through"
        );
        fs.delete_file(r"Z:\new\nested\created.txt").unwrap();
        assert!(!root.join("new/nested/created.txt").exists());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn mounted_host_drive_can_be_read_only() {
        let root = std::env::temp_dir().join(format!(
            "wincli-mount-ro-{}-{}",
            std::process::id(),
            NEXT_DISK_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut fs = WinFs::new();
        fs.mount_host_dir('Z', &root, true).unwrap();
        assert!(fs
            .write_file(r"Z:\no.txt", b"no".to_vec())
            .unwrap_err()
            .contains("read-only"));
        std::fs::remove_dir_all(root).ok();
    }
}
