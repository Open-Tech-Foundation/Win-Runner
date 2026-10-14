//! `where.exe` inside a native guest process.
//!
//! The seeded `C:\Windows\System32\where.exe` is a small PE whose entry
//! point calls the private `WinrunWhereMain` export and exits with its
//! result. That runs [`crate::where_tool`] over the guest filesystem and
//! the process's environment.

use super::*;
use crate::where_tool::WhereHost;

pub(super) extern "win64" fn native_winrun_where_main() -> u32 {
    let Some(process) = process_ctx() else {
        return 1;
    };
    let end = process
        .command_line_w
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(process.command_line_w.len());
    let command_line = String::from_utf16_lossy(&process.command_line_w[..end]);
    let arguments: Vec<String> = crate::cmd::split_windows_command_line(&command_line)
        .into_iter()
        .skip(1)
        .collect();
    crate::where_tool::run(&mut NativeWhereHost, &arguments) as u32
}

struct NativeWhereHost;

impl NativeWhereHost {
    fn with_fs<R>(&self, action: impl FnOnce(&mut WinFs) -> R) -> Option<R> {
        let context = fs_ctx()?;
        let mut ctx = context.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Some(action(&mut ctx.fs))
    }
}

impl WhereHost for NativeWhereHost {
    fn variable(&mut self, name: &str) -> Option<String> {
        let process = process_ctx()?;
        let environment = process.environment.lock().ok()?;
        environment
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then(|| value.clone()))
    }

    fn current_dir(&mut self) -> String {
        self.with_fs(|fs| fs.cwd()).unwrap_or_else(|| "C:\\".to_string())
    }

    fn list_dir(&mut self, path: &str) -> Option<Vec<(String, bool)>> {
        self.with_fs(|fs| {
            if !fs.is_dir(path) {
                return None;
            }
            let names = fs.list_dir(path).ok()?;
            let base = path.trim_end_matches(['\\', '/']);
            Some(names.into_iter().map(|name| {
                let is_dir = fs.is_dir(&format!("{base}\\{name}"));
                (name, is_dir)
            }).collect())
        })
        .flatten()
    }

    fn stdout(&mut self, text: &str) {
        let _ = write_all(curl_std_handle(1), text.as_bytes());
    }

    fn stderr(&mut self, text: &str) {
        let _ = write_all(curl_std_handle(2), text.as_bytes());
    }
}
