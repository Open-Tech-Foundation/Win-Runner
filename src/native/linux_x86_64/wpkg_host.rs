//! `wpkg.exe` inside a native guest process, so scripts, `cmd /c`, and
//! programs can run wpkg as the interactive shell does.
//!
//! The seeded `C:\Windows\System32\wpkg.exe` is a small PE whose entry point
//! calls the private `WinrunWpkgMain` export: it runs [`crate::wpkg`] over
//! the guest filesystem, writing progress and results to standard output
//! and failures to standard error (exit code 1).

use super::*;

pub(super) extern "win64" fn native_winrun_wpkg_main() -> u32 {
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
    let Some(context) = fs_ctx() else {
        return 1;
    };
    let stdout = |text: &str| {
        let _ = write_all(curl_std_handle(1), text.as_bytes());
    };
    let result = {
        let mut ctx = context.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut progress = |text: &str| {
            // Without a terminal to redraw on, only finished lines show.
            if !text.ends_with('\r') {
                stdout(text);
            }
        };
        crate::wpkg::open_registry(&mut ctx.fs, &mut progress).and_then(|repository| {
            crate::wpkg::execute_with_progress(
                &mut ctx.fs,
                &repository,
                crate::wpkg::host_architecture(),
                &arguments,
                &mut progress,
            )
        })
    };
    match result {
        Ok(output) => {
            let _ = write_all(curl_std_handle(1), &output);
            0
        }
        Err(error) => {
            let _ = write_all(curl_std_handle(2), format!("❌ wpkg failed: {error}\r\n").as_bytes());
            1
        }
    }
}
