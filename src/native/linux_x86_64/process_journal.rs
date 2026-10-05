//! Live child namespace publication. File contents remain in shared blobs.
use super::*;

pub(super) fn start_publisher(process: &Arc<NativeProcessContext>) -> Result<(), String> {
    let Some(path) = std::env::var_os("WINRUN_NATIVE_LIVE_STATE_PATH") else {
        return Ok(());
    };
    let path = std::path::PathBuf::from(path);
    let temporary = path.with_extension("pending");
    let weak = Arc::downgrade(process);
    std::thread::Builder::new()
        .name("winrun-child-journal".into())
        .spawn(move || {
            let mut published = 0;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(20));
                let Some(process) = weak.upgrade() else { break };
                if process.state_fd.load(Ordering::Acquire) == u32::MAX {
                    break;
                }
                let result = (|| -> Result<(), String> {
                    let fs = process
                        .fs
                        .lock()
                        .map_err(|_| "child filesystem lock poisoned")?;
                    let count = fs.fs.changes().len();
                    if count == published {
                        return Ok(());
                    }
                    let bytes = crate::snapshot::encode_changes(&fs.fs)?;
                    drop(fs);
                    // Readers see an entire generation, never a partial write.
                    std::fs::write(&temporary, bytes).map_err(|e| e.to_string())?;
                    std::fs::rename(&temporary, &path).map_err(|e| e.to_string())?;
                    published = count;
                    Ok(())
                })();
                if let Err(error) = result {
                    eprintln!("winrun: cannot publish live child filesystem changes: {error}");
                    break;
                }
            }
        })
        .map(|_| ())
        .map_err(|e| format!("cannot start child filesystem publisher: {e}"))
}

pub(super) fn receive(
    path: &std::path::Path,
    fs: &Arc<Mutex<NativeFs>>,
    applied: &mut usize,
    reported_error: &mut Option<String>,
) {
    let result = (|| -> Result<(), String> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.to_string()),
        };
        if bytes.is_empty() {
            return Ok(());
        }
        let mut fs = fs.lock().map_err(|_| "parent filesystem lock poisoned")?;
        let cwd = fs.fs.cwd();
        let result = crate::snapshot::apply_changes_since(&bytes, &mut fs.fs, *applied);
        fs.fs.set_cwd(&cwd)?;
        *applied = result?;
        Ok(())
    })();
    if let Err(error) = result {
        if reported_error.as_ref() != Some(&error) {
            eprintln!("winrun: cannot apply child filesystem changes: {error}");
            *reported_error = Some(error);
        }
    }
}
