//! `taskkill.exe` inside a native guest process.
//!
//! The seeded `C:\Windows\System32\taskkill.exe` is a small PE whose entry
//! point calls the private `WinrunTaskkillMain` export and exits with its
//! result. That runs [`crate::taskkill_tool`] over this session's guest
//! process table.

use super::*;
use crate::native::process_table;
use crate::taskkill_tool::{Process, TaskkillHost};

pub(super) extern "win64" fn native_winrun_taskkill_main() -> u32 {
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
    crate::taskkill_tool::run(&mut NativeTaskkillHost, &arguments) as u32
}

struct NativeTaskkillHost;

impl TaskkillHost for NativeTaskkillHost {
    fn processes(&mut self) -> Vec<Process> {
        process_table::list()
            .into_iter()
            .map(|process| Process {
                pid: process.pid,
                parent: process.parent,
                image_name: process.image_name().to_string(),
            })
            .collect()
    }

    fn terminate(&mut self, pid: u32) -> Result<(), String> {
        let process = process_table::list()
            .into_iter()
            .find(|process| process.pid == pid)
            .ok_or_else(|| "The process has already ended.".to_string())?;
        process_table::terminate(&process)
    }

    fn stdout(&mut self, text: &str) {
        let _ = write_all(curl_std_handle(1), text.as_bytes());
    }

    fn stderr(&mut self, text: &str) {
        let _ = write_all(curl_std_handle(2), text.as_bytes());
    }
}
