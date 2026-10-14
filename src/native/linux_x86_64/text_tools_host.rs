//! `find.exe`, `sort.exe` and `more.com` inside a native guest process.
//!
//! The seeded System32 programs are small PEs whose entry points call the
//! private `WinrunFindMain`, `WinrunSortMain` and `WinrunMoreMain` exports,
//! which run [`crate::text_tools`] over the process's standard handles and
//! the guest filesystem.

use super::*;
use crate::text_tools::TextHost;

fn arguments() -> Vec<String> {
    let Some(process) = process_ctx() else {
        return Vec::new();
    };
    let end = process
        .command_line_w
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(process.command_line_w.len());
    let command_line = String::from_utf16_lossy(&process.command_line_w[..end]);
    crate::cmd::split_windows_command_line(&command_line).into_iter().skip(1).collect()
}

pub(super) extern "win64" fn native_winrun_find_main() -> u32 {
    crate::text_tools::find(&mut NativeTextHost, &arguments()) as u32
}

pub(super) extern "win64" fn native_winrun_sort_main() -> u32 {
    crate::text_tools::sort(&mut NativeTextHost, &arguments()) as u32
}

pub(super) extern "win64" fn native_winrun_more_main() -> u32 {
    crate::text_tools::more(&mut NativeTextHost, &arguments()) as u32
}

struct NativeTextHost;

impl NativeTextHost {
    fn with_fs<R>(&self, action: impl FnOnce(&mut WinFs) -> R) -> Option<R> {
        let context = fs_ctx()?;
        let mut ctx = context.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Some(action(&mut ctx.fs))
    }
}

impl TextHost for NativeTextHost {
    fn read_stdin(&mut self) -> Vec<u8> {
        read_all(curl_std_handle(0)).unwrap_or_default()
    }

    fn read_file(&mut self, path: &str) -> Option<Vec<u8>> {
        self.with_fs(|fs| fs.read_file(path).ok()).flatten()
    }

    fn write_file(&mut self, path: &str, bytes: &[u8]) -> bool {
        self.with_fs(|fs| fs.write_file(path, bytes.to_vec()).is_ok()).unwrap_or(false)
    }

    fn stdout(&mut self, bytes: &[u8]) {
        let _ = write_all(curl_std_handle(1), bytes);
    }

    fn stderr(&mut self, text: &str) {
        let _ = write_all(curl_std_handle(2), text.as_bytes());
    }
}
