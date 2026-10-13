//! The guest processes of one winrun session, so a guest can find and end
//! another by PID (`taskkill`): a private directory, named by
//! `WINRUN_PROCESS_TABLE` and inherited by every worker, with one entry per
//! live guest process. A guest PID is its worker's host PID; an entry also
//! keeps the worker's kernel start time, so a host PID reused by another
//! process is never mistaken for a guest.

use std::path::PathBuf;

const TABLE_VARIABLE: &str = "WINRUN_PROCESS_TABLE";

/// One guest process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProcess {
    pub pid: u32,
    pub parent: u32,
    /// The image's guest path (`C:\Windows\System32\cmd.exe`).
    pub image: String,
    start_time: u64,
}

impl GuestProcess {
    /// The image's file name (`cmd.exe`).
    pub fn image_name(&self) -> &str {
        self.image.rsplit(['\\', '/']).next().unwrap_or(&self.image)
    }
}

fn table() -> Option<PathBuf> {
    std::env::var_os(TABLE_VARIABLE).map(PathBuf::from)
}

/// Make this session's table unless an enclosing session already has one;
/// the returned guard removes a table made here.
pub fn begin_session() -> Option<SessionTable> {
    if table().is_some() {
        return None;
    }
    remove_abandoned_tables();
    let directory = std::env::temp_dir().join(format!(
        "winrun-processes-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(&directory).ok()?;
    std::env::set_var(TABLE_VARIABLE, &directory);
    Some(SessionTable(directory))
}

/// Tables left by sessions that ended without removing theirs (killed, or
/// not through winrun's exit path): their winrun process is gone.
fn remove_abandoned_tables() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(owner) = name
            .to_str()
            .and_then(|name| name.strip_prefix("winrun-processes-"))
            .and_then(|rest| rest.split('-').next())
            .and_then(|pid| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if start_time(owner).is_none() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Removes the session's table when the session ends.
pub struct SessionTable(PathBuf);

impl SessionTable {
    pub fn remove(&self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Drop for SessionTable {
    fn drop(&mut self) {
        self.remove();
    }
}

/// The kernel start time of a live, non-zombie host process.
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the parenthesized command name: state is the first,
    // starttime the twentieth.
    let after = &stat[stat.rfind(')')? + 2..];
    let fields: Vec<&str> = after.split(' ').collect();
    if matches!(fields.first(), Some(&"Z") | Some(&"X")) {
        return None;
    }
    fields.get(19)?.parse().ok()
}

/// Enter this process in the table.
pub fn register(pid: u32, parent: u32, image: &str) {
    let (Some(table), Some(started)) = (table(), start_time(std::process::id())) else {
        return;
    };
    let _ = std::fs::write(table.join(pid.to_string()), format!("{parent}\n{started}\n{image}\n"));
}

/// Leave the table.
pub fn unregister(pid: u32) {
    if let Some(table) = table() {
        let _ = std::fs::remove_file(table.join(pid.to_string()));
    }
}

/// The live guest processes; entries of processes that are gone are
/// removed on the way.
pub fn list() -> Vec<GuestProcess> {
    let Some(table) = table() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&table) else {
        return Vec::new();
    };
    let mut processes = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
        let mut lines = text.lines();
        let parent = lines.next().and_then(|line| line.parse().ok());
        let started = lines.next().and_then(|line| line.parse::<u64>().ok());
        let image = lines.next().unwrap_or_default().to_string();
        match (parent, started) {
            (Some(parent), Some(started)) if start_time(pid) == Some(started) => {
                processes.push(GuestProcess { pid, parent, image, start_time: started });
            }
            _ => {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    processes.sort_by_key(|process| process.pid);
    processes
}

/// End a guest process at once, as TerminateProcess does (its parent sees
/// exit code 1). Only a process in the table, still the same process, is
/// signalled.
pub fn terminate(process: &GuestProcess) -> Result<(), String> {
    if start_time(process.pid) != Some(process.start_time) {
        return Err("the process has already ended".to_string());
    }
    if unsafe { libc::kill(process.pid as i32, libc::SIGKILL) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_track_live_processes_only() {
        let directory = std::env::temp_dir().join(format!("winrun-process-table-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        // Run with this test's own table (tests share the environment, so
        // the variable is restored afterwards).
        let previous = std::env::var_os(TABLE_VARIABLE);
        std::env::set_var(TABLE_VARIABLE, &directory);
        let me = std::process::id();
        register(me, 7, r"C:\tools\tool.exe");
        // A stale entry: a start time this pid never had.
        std::fs::write(directory.join("1"), "0\n1\nC:\\gone.exe\n").unwrap();
        let listed = list();
        assert!(listed.iter().any(|p| p.pid == me && p.parent == 7 && p.image_name() == "tool.exe"));
        assert!(!listed.iter().any(|p| p.pid == 1), "{listed:?}");
        assert!(!directory.join("1").exists(), "stale entries are pruned");
        unregister(me);
        assert!(!list().iter().any(|p| p.pid == me));
        match previous {
            Some(value) => std::env::set_var(TABLE_VARIABLE, value),
            None => std::env::remove_var(TABLE_VARIABLE),
        }
        let _ = std::fs::remove_dir_all(&directory);
    }
}
