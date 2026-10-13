//! `curl.exe` inside a native guest process.
//!
//! The seeded `C:\Windows\System32\curl.exe` is a small PE whose entry point
//! calls the private `WinrunCurlMain` export and exits with its result. That
//! runs [`crate::curl_tool`] as a real child process: its standard streams
//! are the process's handles, its files go through `CreateFileW`, and
//! servers are verified against the guest's ROOT certificate store.

use super::*;
use crate::curl_tool::CurlHost;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;

pub(super) extern "win64" fn native_winrun_curl_main() -> u32 {
    let Some(process) = process_ctx() else {
        return 2;
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
    crate::curl_tool::run(&mut NativeCurlHost, &arguments) as u32
}

struct NativeCurlHost;

fn std_handle(index: usize) -> u64 {
    process_ctx()
        .map(|process| process.parameters.std_handles[index].load(Ordering::Acquire))
        .unwrap_or(STD_HANDLE_BASE + index as u64)
}

fn last_error_text() -> String {
    match native_get_last_error() {
        2 => "The system cannot find the file specified.".to_string(),
        3 => "The system cannot find the path specified.".to_string(),
        5 => "Access is denied.".to_string(),
        32 => "The process cannot access the file because it is being used by another process.".to_string(),
        code => format!("error {code}"),
    }
}

fn write_all(handle: u64, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let chunk = bytes.len().min(1 << 20);
        let mut written = 0u32;
        if native_write_file(handle, bytes.as_ptr(), chunk as u32, &mut written, 0) == 0 || written == 0 {
            return Err(last_error_text());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn read_all(handle: u64) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let mut count = 0u32;
        if native_read_file(handle, buffer.as_mut_ptr(), buffer.len() as u32, &mut count, 0) == 0 {
            // A closed pipe ends the input (ERROR_BROKEN_PIPE).
            if native_get_last_error() == 109 {
                return Ok(data);
            }
            return Err(last_error_text());
        }
        if count == 0 {
            return Ok(data);
        }
        data.extend_from_slice(&buffer[..count as usize]);
    }
}

fn wide_z(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

impl CurlHost for NativeCurlHost {
    fn stdout(&mut self, bytes: &[u8]) -> Result<(), String> {
        write_all(std_handle(1), bytes)
    }

    fn stderr(&mut self, bytes: &[u8]) {
        let _ = write_all(std_handle(2), bytes);
    }

    fn create(&mut self, path: &str, create_dirs: bool) -> Result<u64, String> {
        if create_dirs {
            if let Some((parent, _)) = path.rsplit_once(['\\', '/']).filter(|(parent, _)| !parent.is_empty()) {
                if let Some(context) = fs_ctx() {
                    let mut ctx = context.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let _ = ctx.fs.mkdir(parent);
                }
            }
        }
        let handle = native_create_file_w(wide_z(path).as_ptr(), GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0x80, 0);
        if handle == u64::MAX || handle == 0 {
            return Err(last_error_text());
        }
        Ok(handle)
    }

    fn write(&mut self, file: u64, bytes: &[u8]) -> Result<(), String> {
        write_all(file, bytes)
    }

    fn close(&mut self, file: u64) {
        native_close_handle(file);
    }

    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, String> {
        let handle = native_create_file_w(wide_z(path).as_ptr(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0x80, 0);
        if handle == u64::MAX || handle == 0 {
            return Err(last_error_text());
        }
        let data = read_all(handle);
        native_close_handle(handle);
        data
    }

    fn read_stdin(&mut self) -> Result<Vec<u8>, String> {
        read_all(std_handle(0))
    }

    fn roots(&mut self) -> Vec<Vec<u8>> {
        let Some(context) = fs_ctx() else {
            return Vec::new();
        };
        let ctx = context.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::winreg::Registry::load(&ctx.fs)
            .map(|registry| crate::trust_roots::store_certificates(&registry, "ROOT"))
            .unwrap_or_default()
    }
}
