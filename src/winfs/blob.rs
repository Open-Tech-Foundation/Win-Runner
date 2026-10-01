//! Writable storage for guest file contents: one host file (a blob) per
//! written guest file, in a session directory, like the upper layer of an
//! overlay filesystem. Snapshot files stay read-only extents until their
//! first write copies them into a blob.
//!
//! A write is a `pwrite` on the blob, truncation is `ftruncate`, and the
//! kernel reclaims a blob's space when it is deleted, so storage stays
//! proportional to the live guest data however a program writes it.
//!
//! One instance owns the session directory; the native workers that run its
//! guest processes attach to it and open blobs by id, so every process sees
//! a file's current contents, as on Windows. Only the owner deletes blobs:
//! when its last reference drops, and, for blobs a worker created but never
//! handed back, once the creating process has exited
//! ([`BlobStore::collect_garbage`]). The owner removes the directory when it
//! is dropped or the process exits (an `atexit` handler, since
//! `std::process::exit` skips destructors); directories whose owner was
//! killed are swept when a later instance starts
//! ([`sweep_stale_temporaries`]). Deletion is tied to the owner's pid, so a
//! forked child never removes its parent's files.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, Weak};

const SESSION_PREFIX: &str = "winrun-session-";
/// Blob ids are `<creating pid>-<sequence>`, unique across the processes
/// that share one session directory.
static NEXT_BLOB: AtomicU64 = AtomicU64::new(1);
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
static SWEEP: Once = Once::new();
static AT_EXIT: Once = Once::new();
/// Session directories this process owns, removed at exit.
static OWNED_SESSIONS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
const COPY_CHUNK: usize = 1024 * 1024;
/// Open host files kept per process. A session can hold any number of
/// blobs (an npm install writes thousands); descriptors stay bounded.
const OPEN_FILE_LIMIT: usize = 64;

pub(crate) struct BlobStore {
    dir: PathBuf,
    /// Set when this process created the session and may delete from it.
    owner: bool,
    owner_pid: u32,
    /// Blobs in use in this process, so each id has one `Blob` however many
    /// guest paths or lookups refer to it.
    open: Mutex<HashMap<String, Weak<Blob>>>,
    /// Recently used host files, most recent first, at most
    /// [`OPEN_FILE_LIMIT`]. A blob holds no descriptor of its own.
    files: Mutex<VecDeque<(String, Arc<File>)>>,
}

impl std::fmt::Debug for BlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobStore")
            .field("dir", &self.dir)
            .field("owner", &self.owner)
            .finish()
    }
}

pub(crate) struct Blob {
    id: String,
    store: Arc<BlobStore>,
}

impl std::fmt::Debug for Blob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Blob").field(&self.id).finish()
    }
}

impl BlobStore {
    /// A new session directory owned by this process.
    pub(crate) fn create_session() -> Result<Arc<Self>, String> {
        let temp = std::env::temp_dir();
        SWEEP.call_once(|| sweep_stale_temporaries(&temp));
        let dir = temp.join(format!(
            "{SESSION_PREFIX}{}-{}",
            std::process::id(),
            NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir)
            .map_err(|e| format!("cannot create WinFS session {}: {e}", dir.display()))?;
        AT_EXIT.call_once(|| unsafe {
            libc::atexit(remove_owned_sessions);
        });
        lock(&OWNED_SESSIONS).push(dir.clone());
        Ok(Arc::new(Self {
            dir,
            owner: true,
            owner_pid: std::process::id(),
            open: Mutex::new(HashMap::new()),
            files: Mutex::new(VecDeque::new()),
        }))
    }

    /// Attach to another process's session directory.
    pub(crate) fn attach(dir: &Path) -> Result<Arc<Self>, String> {
        if !dir.is_dir() {
            return Err(format!("WinFS session is missing: {}", dir.display()));
        }
        Ok(Arc::new(Self {
            dir: dir.to_path_buf(),
            owner: false,
            owner_pid: 0,
            open: Mutex::new(HashMap::new()),
            files: Mutex::new(VecDeque::new()),
        }))
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// A new, empty blob.
    pub(crate) fn create(self: &Arc<Self>) -> Result<Arc<Blob>, String> {
        let id = format!(
            "{}-{}",
            std::process::id(),
            NEXT_BLOB.fetch_add(1, Ordering::Relaxed)
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.dir.join(&id))
            .map_err(|e| format!("cannot create WinFS blob {id}: {e}"))?;
        self.cache_file(&id, Arc::new(file));
        Ok(self.register(id))
    }

    /// The blob `id`, which this or another process of the session created.
    pub(crate) fn open(self: &Arc<Self>, id: &str) -> Result<Arc<Blob>, String> {
        if blob_creator(id).is_none() {
            return Err(format!("invalid WinFS blob id: {id}"));
        }
        if let Some(blob) = self.lock_open().get(id).and_then(Weak::upgrade) {
            return Ok(blob);
        }
        if !self.dir.join(id).is_file() {
            return Err(format!("cannot open WinFS blob {id}: not found"));
        }
        Ok(self.register(id.to_string()))
    }

    fn register(self: &Arc<Self>, id: String) -> Arc<Blob> {
        let mut open = self.lock_open();
        // Another thread may have opened the same id meanwhile.
        if let Some(blob) = open.get(&id).and_then(Weak::upgrade) {
            return blob;
        }
        let blob = Arc::new(Blob {
            id: id.clone(),
            store: Arc::clone(self),
        });
        open.insert(id, Arc::downgrade(&blob));
        blob
    }

    fn lock_open(&self) -> std::sync::MutexGuard<'_, HashMap<String, Weak<Blob>>> {
        lock(&self.open)
    }

    /// The open host file of blob `id`, reopened if it was evicted.
    fn file(&self, id: &str) -> Result<Arc<File>, String> {
        let mut files = lock(&self.files);
        if let Some(index) = files.iter().position(|(cached, _)| cached == id) {
            let entry = files.remove(index).expect("index is in range");
            let file = Arc::clone(&entry.1);
            files.push_front(entry);
            return Ok(file);
        }
        drop(files);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join(id))
            .map_err(|e| format!("cannot open WinFS blob {id}: {e}"))?;
        let file = Arc::new(file);
        self.cache_file(id, Arc::clone(&file));
        Ok(file)
    }

    fn cache_file(&self, id: &str, file: Arc<File>) {
        let mut files = lock(&self.files);
        files.retain(|(cached, _)| cached != id);
        files.push_front((id.to_string(), file));
        // An evicted descriptor closes once no operation still uses it.
        files.truncate(OPEN_FILE_LIMIT);
    }

    fn forget_file(&self, id: &str) {
        lock(&self.files).retain(|(cached, _)| cached != id);
    }

    /// Whether this process may delete from the session.
    fn deletes(&self) -> bool {
        self.owner && self.owner_pid == std::process::id()
    }

    /// Delete blobs nothing can bind any more: not open in this (owning)
    /// process, and created by a process that has exited. The owner calls
    /// this after a worker's changes were applied; a worker's blobs that its
    /// journal never handed back, or that a later change replaced, go here.
    pub(crate) fn collect_garbage(&self) {
        if !self.deletes() {
            return;
        }
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let own = std::process::id();
        let open = self.lock_open();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(creator) = blob_creator(name) else {
                continue;
            };
            if creator == own
                || open.get(name).is_some_and(|blob| blob.strong_count() != 0)
                || process_alive(creator)
            {
                continue;
            }
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

impl Drop for BlobStore {
    fn drop(&mut self) {
        if self.deletes() {
            let _ = std::fs::remove_dir_all(&self.dir);
            lock(&OWNED_SESSIONS).retain(|dir| dir != &self.dir);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

extern "C" fn remove_owned_sessions() {
    // Registered by the creating process; a forked child inherits the list
    // but its pid differs from the sessions' `<pid>` and leaves them alone.
    let own = std::process::id();
    let sessions = std::mem::take(&mut *lock(&OWNED_SESSIONS));
    for dir in sessions {
        let owned = dir
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(temporary_owner)
            == Some(own);
        if owned {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

impl Blob {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    fn file(&self) -> Result<Arc<File>, String> {
        self.store.file(&self.id)
    }

    pub(crate) fn len(&self) -> Result<u64, String> {
        self.file()?
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|e| format!("cannot stat WinFS blob {}: {e}", self.id))
    }

    /// Up to `length` bytes from `offset`; fewer at the end of the blob.
    pub(crate) fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        let size = self.len()?;
        if offset >= size {
            return Ok(Vec::new());
        }
        let count = usize::try_from((size - offset).min(length as u64))
            .map_err(|_| "WinFS read is too large".to_string())?;
        let mut bytes = vec![0; count];
        self.file()?
            .read_exact_at(&mut bytes, offset)
            .map_err(|e| format!("cannot read WinFS blob {}: {e}", self.id))?;
        Ok(bytes)
    }

    pub(crate) fn read_all(&self) -> Result<Vec<u8>, String> {
        let size = usize::try_from(self.len()?)
            .map_err(|_| "guest file is too large to read into memory".to_string())?;
        self.read_at(0, size)
    }

    /// Write `bytes` at `offset`; a gap past the end reads as zeros.
    pub(crate) fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        self.file()?
            .write_all_at(bytes, offset)
            .map_err(|e| format!("cannot write WinFS blob {}: {e}", self.id))
    }

    pub(crate) fn set_len(&self, length: u64) -> Result<(), String> {
        self.file()?
            .set_len(length)
            .map_err(|e| format!("cannot resize WinFS blob {}: {e}", self.id))
    }

    /// Replace the whole contents.
    pub(crate) fn replace(&self, bytes: &[u8]) -> Result<(), String> {
        self.set_len(bytes.len() as u64)?;
        self.write_at(0, bytes)
    }

    /// Fill this blob with `length` bytes read in chunks from `read`.
    pub(crate) fn copy_from(
        &self,
        length: u64,
        mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<(), String> {
        self.set_len(0)?;
        let mut offset = 0u64;
        while offset < length {
            let chunk = (length - offset).min(COPY_CHUNK as u64) as usize;
            let bytes = read(offset, chunk)?;
            if bytes.len() != chunk {
                return Err(format!("short read while copying into WinFS blob {}", self.id));
            }
            self.write_at(offset, &bytes)?;
            offset += chunk as u64;
        }
        Ok(())
    }

    /// Changes whenever the contents may have, including writes by other
    /// processes of the session.
    pub(crate) fn version(&self) -> u64 {
        let Ok(file) = self.file() else {
            return 0;
        };
        file.metadata().map_or(0, |metadata| {
            let modified = (metadata.mtime() as u64)
                .wrapping_mul(1_000_000_000)
                .wrapping_add(metadata.mtime_nsec() as u64);
            metadata.len().rotate_left(17) ^ modified ^ metadata.ino().rotate_left(41)
        })
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        let mut open = self.store.lock_open();
        if open.get(&self.id).is_some_and(|blob| blob.strong_count() == 0) {
            open.remove(&self.id);
        }
        drop(open);
        self.store.forget_file(&self.id);
        if self.store.deletes() {
            let _ = std::fs::remove_file(self.store.dir.join(&self.id));
        }
    }
}

/// The creating process of blob `id` (`<pid>-<sequence>`).
fn blob_creator(id: &str) -> Option<u32> {
    let (pid, sequence) = id.split_once('-')?;
    if pid.is_empty() || sequence.is_empty() || !sequence.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

fn process_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // Signal 0 checks for existence; EPERM still means it exists.
    let exists = unsafe { libc::kill(pid, 0) } == 0;
    exists || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The owning process of a Win-Runner temporary in the temp directory:
/// session directories, worker request directories, download header files,
/// and the single-file disks of earlier versions.
fn temporary_owner(name: &str) -> Option<u32> {
    let rest = [
        SESSION_PREFIX,
        "winrun-child-worker-",
        "winrun-worker-",
        "winrun-disk-",
        "winrun-download-",
    ]
    .iter()
    .find_map(|prefix| name.strip_prefix(prefix))?;
    let rest = rest.strip_suffix(".tmp").unwrap_or(rest);
    let (pid, sequence) = rest.split_once('-')?;
    if sequence.is_empty() || !sequence.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

/// Remove Win-Runner temporaries whose owning process has exited (killed,
/// or ended without unwinding), so they never accumulate in the temp
/// directory.
pub(crate) fn sweep_stale_temporaries(temp: &Path) {
    let Ok(entries) = std::fs::read_dir(temp) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(owner) = name.to_str().and_then(temporary_owner) else {
            continue;
        };
        if owner == std::process::id() || process_alive(owner) {
            continue;
        }
        let path = entry.path();
        let _ = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blobs_write_in_place_and_keep_only_the_live_size() {
        let store = BlobStore::create_session().unwrap();
        let blob = store.create().unwrap();
        let chunk = vec![7u8; 64 * 1024];
        for index in 0..64u64 {
            blob.write_at(index * chunk.len() as u64, &chunk).unwrap();
        }
        assert_eq!(blob.len().unwrap(), 4 * 1024 * 1024);
        // The host file holds the guest file once, not once per write.
        let on_disk = std::fs::metadata(store.dir().join(blob.id())).unwrap().len();
        assert_eq!(on_disk, 4 * 1024 * 1024);
        blob.write_at(10, b"abc").unwrap();
        assert_eq!(blob.read_at(9, 5).unwrap(), [7, b'a', b'b', b'c', 7]);
        blob.set_len(2).unwrap();
        assert_eq!(blob.read_all().unwrap(), [7, 7]);
        assert_eq!(blob.read_at(5, 4).unwrap(), Vec::<u8>::new());
        blob.write_at(4, b"z").unwrap();
        assert_eq!(blob.read_all().unwrap(), [7, 7, 0, 0, b'z']);
    }

    fn open_descriptors() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    #[test]
    fn thousands_of_blobs_keep_open_descriptors_bounded() {
        // Installing Node.js writes thousands of files; a descriptor per
        // file ran past the usual limit of 1024 (EMFILE).
        let store = BlobStore::create_session().unwrap();
        let before = open_descriptors();
        let blobs: Vec<_> = (0..3000)
            .map(|index| {
                let blob = store.create().unwrap();
                blob.replace(format!("file {index}").as_bytes()).unwrap();
                blob
            })
            .collect();
        // Other tests run in parallel and open files too.
        assert!(open_descriptors() < before + OPEN_FILE_LIMIT + 200);
        assert_eq!(blobs[0].read_all().unwrap(), b"file 0");
        blobs[1].write_at(5, b"X").unwrap();
        assert_eq!(blobs[1].read_all().unwrap(), b"file X");
        assert_eq!(blobs[2999].read_all().unwrap(), b"file 2999");
    }

    #[test]
    fn an_id_has_one_open_blob_and_the_owner_deletes_it_with_the_last_reference() {
        let store = BlobStore::create_session().unwrap();
        let blob = store.create().unwrap();
        let path = store.dir().join(blob.id());
        let again = store.open(blob.id()).unwrap();
        assert!(Arc::ptr_eq(&blob, &again));
        drop(blob);
        assert!(path.exists());
        drop(again);
        assert!(!path.exists());
        let dir = store.dir().to_path_buf();
        drop(store);
        assert!(!dir.exists());
    }

    #[test]
    fn an_attached_process_shares_contents_and_never_deletes() {
        let owner = BlobStore::create_session().unwrap();
        let blob = owner.create().unwrap();
        blob.replace(b"shared").unwrap();
        let worker = BlobStore::attach(owner.dir()).unwrap();
        let seen = worker.open(blob.id()).unwrap();
        assert_eq!(seen.read_all().unwrap(), b"shared");
        seen.write_at(0, b"S").unwrap();
        assert_eq!(blob.read_all().unwrap(), b"Shared");
        let created = worker.create().unwrap();
        let created_path = owner.dir().join(created.id());
        drop(created);
        drop(seen);
        drop(worker);
        assert!(created_path.exists() && owner.dir().join(blob.id()).exists());
        assert!(BlobStore::open(&owner, "../escape").is_err());
    }

    #[test]
    fn garbage_collection_removes_unbound_blobs_of_exited_processes_only() {
        let store = BlobStore::create_session().unwrap();
        let dead = "999999999-1"; // no such process
        let alive = format!("{}-999", std::process::id());
        std::fs::write(store.dir().join(dead), b"orphan").unwrap();
        std::fs::write(store.dir().join("1-1"), b"init's").unwrap(); // pid 1 is alive
        std::fs::write(store.dir().join(&alive), b"own").unwrap();
        std::fs::write(store.dir().join("999999998-1"), b"bound").unwrap();
        let bound = store.open("999999998-1").unwrap();
        store.collect_garbage();
        assert!(!store.dir().join(dead).exists());
        assert!(store.dir().join("1-1").exists());
        assert!(store.dir().join(&alive).exists());
        assert!(store.dir().join(bound.id()).exists());
    }

    #[test]
    fn stale_temporaries_of_exited_processes_are_swept() {
        assert_eq!(temporary_owner("winrun-disk-123-4.tmp"), Some(123));
        assert_eq!(temporary_owner("winrun-session-77-1"), Some(77));
        assert_eq!(temporary_owner("winrun-worker-5-2"), Some(5));
        assert_eq!(temporary_owner("winrun-child-worker-6-3"), Some(6));
        assert_eq!(temporary_owner("winrun-download-8-1.tmp"), Some(8));
        assert_eq!(temporary_owner("winrun-disk-x"), None);
        assert_eq!(temporary_owner("other-1-2"), None);

        let root = std::env::temp_dir().join(format!("winrun-sweep-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("winrun-disk-999999999-1.tmp"), b"x").unwrap();
        std::fs::create_dir_all(root.join("winrun-session-999999999-1/inner")).unwrap();
        let live = format!("winrun-session-{}-77", std::process::id());
        std::fs::create_dir_all(root.join(&live)).unwrap();
        std::fs::write(root.join("unrelated.txt"), b"keep").unwrap();
        sweep_stale_temporaries(&root);
        assert!(!root.join("winrun-disk-999999999-1.tmp").exists());
        assert!(!root.join("winrun-session-999999999-1").exists());
        assert!(root.join(&live).exists());
        assert!(root.join("unrelated.txt").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
