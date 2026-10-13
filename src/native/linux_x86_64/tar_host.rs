//! `tar.exe` inside a native guest process.
//!
//! The seeded `C:\Windows\System32\tar.exe` is a small PE whose entry point
//! calls the private `WinrunTarMain` export and exits with its result. That
//! runs [`crate::tar_tool`] as a real child process over its own standard
//! handles and the guest filesystem.

use super::*;
use crate::tar_tool::TarHost;

pub(super) extern "win64" fn native_winrun_tar_main() -> u32 {
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
    crate::tar_tool::run(&mut NativeTarHost, &arguments) as u32
}

struct NativeTarHost;

impl NativeTarHost {
    fn with_fs<R>(&self, action: impl FnOnce(&mut WinFs) -> R) -> Option<R> {
        let context = fs_ctx()?;
        let mut ctx = context.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Some(action(&mut ctx.fs))
    }
}

impl TarHost for NativeTarHost {
    fn stdout(&mut self, bytes: &[u8]) -> Result<(), String> {
        write_all(curl_std_handle(1), bytes)
    }

    fn stderr(&mut self, bytes: &[u8]) {
        let _ = write_all(curl_std_handle(2), bytes);
    }

    fn read_stdin(&mut self) -> Result<Vec<u8>, String> {
        read_all(curl_std_handle(0))
    }

    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, String> {
        self.with_fs(|fs| fs.read_file(path)).unwrap_or_else(|| Err("no filesystem".into()))
    }

    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), String> {
        self.with_fs(|fs| fs.write_file(path, data.to_vec()))
            .unwrap_or_else(|| Err("no filesystem".into()))
    }

    fn create_dir(&mut self, path: &str) -> Result<(), String> {
        self.with_fs(|fs| fs.mkdir(path)).unwrap_or_else(|| Err("no filesystem".into()))
    }

    fn is_dir(&mut self, path: &str) -> bool {
        self.with_fs(|fs| fs.is_dir(path)).unwrap_or(false)
    }

    fn exists(&mut self, path: &str) -> bool {
        self.with_fs(|fs| fs.exists(path)).unwrap_or(false)
    }

    fn list_dir(&mut self, path: &str) -> Result<Vec<String>, String> {
        self.with_fs(|fs| fs.list_dir(path)).unwrap_or_else(|| Err("no filesystem".into()))
    }
}
