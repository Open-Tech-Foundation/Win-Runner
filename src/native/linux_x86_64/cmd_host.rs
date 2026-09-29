//! `cmd.exe` inside a native guest process.
//!
//! The seeded `C:\Windows\System32\cmd.exe` is a small PE whose entry point
//! calls the private `WinrunCmdMain` export and exits with its result. That
//! runs [`crate::cmd`] as a real child process: it sees its own command
//! line, environment, and standard handles, and starts the programs it runs
//! through `CreateProcessW` like any Windows program.

use super::*;
use crate::cmd::{CmdHost, Output, RunRequest};

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const SHARE_ALL: u32 = 0x7;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const FILE_END: u32 = 2;
const STARTF_USESTDHANDLES: u32 = 0x100;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
const INFINITE: u32 = u32::MAX;

static NEXT_CAPTURE: AtomicU32 = AtomicU32::new(1);

pub(super) extern "win64" fn native_winrun_cmd_main() -> u32 {
    let Some(process) = process_ctx() else {
        return 1;
    };
    let end = process
        .command_line_w
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(process.command_line_w.len());
    let command_line = String::from_utf16_lossy(&process.command_line_w[..end]);
    let environment = process
        .environment
        .lock()
        .map(|environment| environment.clone())
        .unwrap_or_default();
    let cwd = fs_ctx()
        .and_then(|context| context.lock().ok().map(|ctx| ctx.fs.cwd()))
        .unwrap_or_else(|| crate::system_profile::PROFILE.to_string());
    crate::cmd::run_command_line(&mut NativeCmdHost, &command_line, environment, cwd)
}

struct NativeCmdHost;

fn wide_z(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn std_handle(index: usize) -> u64 {
    process_ctx()
        .map(|process| process.std_handles[index].load(Ordering::Acquire))
        .unwrap_or(STD_HANDLE_BASE + index as u64)
}

/// Handles opened for one child; closed once it has exited.
#[derive(Default)]
struct ChildHandles {
    owned: Vec<u64>,
    capture: Option<String>,
}

impl ChildHandles {
    fn open(&mut self, path: &str, access: u32, creation: u32) -> Result<u64, String> {
        // SECURITY_ATTRIBUTES with bInheritHandle set.
        let mut security = [0u8; 24];
        security[..4].copy_from_slice(&24u32.to_le_bytes());
        security[16..20].copy_from_slice(&1u32.to_le_bytes());
        let handle = native_create_file_w(
            wide_z(path).as_ptr(),
            access,
            SHARE_ALL,
            security.as_ptr() as u64,
            creation,
            0x80,
            0,
        );
        if handle == u64::MAX || handle == 0 {
            return Err(format!("The system cannot open {path}."));
        }
        self.owned.push(handle);
        Ok(handle)
    }

    fn output(&mut self, target: &Output) -> Result<u64, String> {
        match target {
            Output::Stdout => Ok(std_handle(1)),
            Output::Stderr => Ok(std_handle(2)),
            Output::Null => self.open("NUL", GENERIC_WRITE, OPEN_EXISTING),
            Output::File(path) => {
                let handle = self.open(path, GENERIC_WRITE, OPEN_ALWAYS)?;
                native_set_file_pointer_ex(handle, 0, ptr::null_mut(), FILE_END);
                Ok(handle)
            }
            Output::Capture => {
                // for /f waits for the command anyway, so a temporary file
                // stands in for the pipe cmd would use.
                if let Some(path) = &self.capture {
                    let path = path.clone();
                    return self
                        .open(&path, GENERIC_WRITE, OPEN_ALWAYS)
                        .inspect(|&handle| {
                            native_set_file_pointer_ex(handle, 0, ptr::null_mut(), FILE_END);
                        });
                }
                let path = format!(
                    r"{}\winrun-cmd-capture-{}-{}.tmp",
                    crate::system_profile::WINDOWS_TEMP,
                    std::process::id(),
                    NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed)
                );
                let handle = self.open(&path, GENERIC_WRITE, CREATE_ALWAYS)?;
                self.capture = Some(path);
                Ok(handle)
            }
        }
    }

    fn close(self) -> Option<String> {
        for handle in self.owned {
            native_close_handle(handle);
        }
        self.capture
    }
}

impl CmdHost for NativeCmdHost {
    fn with_fs<R>(&mut self, action: impl FnOnce(&mut WinFs) -> R) -> R {
        let context = fs_ctx().expect("cmd.exe runs inside a native process");
        let mut ctx = context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        action(&mut ctx.fs)
    }

    fn run(&mut self, request: &RunRequest) -> Result<(u32, Vec<u8>), String> {
        let mut handles = ChildHandles::default();
        let result = (|| {
            let stdin = match &request.stdin {
                Some(path) => handles.open(path, GENERIC_READ, OPEN_EXISTING)?,
                None => std_handle(0),
            };
            let stdout = handles.output(&request.stdout)?;
            let stderr = if request.stderr == request.stdout {
                stdout
            } else {
                handles.output(&request.stderr)?
            };
            let mut startup = [0u8; 104];
            startup[..4].copy_from_slice(&104u32.to_le_bytes());
            startup[60..64].copy_from_slice(&STARTF_USESTDHANDLES.to_le_bytes());
            startup[80..88].copy_from_slice(&stdin.to_le_bytes());
            startup[88..96].copy_from_slice(&stdout.to_le_bytes());
            startup[96..104].copy_from_slice(&stderr.to_le_bytes());
            let mut environment: Vec<u16> = Vec::new();
            for (name, value) in &request.environment {
                environment.extend(format!("{name}={value}").encode_utf16());
                environment.push(0);
            }
            environment.extend([0, 0]);
            let application = wide_z(&request.application);
            let mut command_line = wide_z(&request.command_line);
            let current_directory = wide_z(&request.current_directory);
            let mut information = [0u8; 24];
            let created = native_create_process_w(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                0,
                0,
                1,
                CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr() as u64,
                current_directory.as_ptr(),
                startup.as_ptr() as u64,
                information.as_mut_ptr() as u64,
            );
            if created == 0 {
                return Err(format!(
                    "{} could not be started (error {}).",
                    request.application,
                    native_get_last_error()
                ));
            }
            let process = u64::from_le_bytes(information[..8].try_into().unwrap());
            let thread = u64::from_le_bytes(information[8..16].try_into().unwrap());
            native_wait_for_single_object(process, INFINITE);
            let mut code = 1u32;
            native_get_exit_code_process(process, &mut code);
            native_close_handle(thread);
            native_close_handle(process);
            Ok(code)
        })();
        let capture = handles.close();
        let captured = match &capture {
            Some(path) => {
                let path = path.clone();
                self.with_fs(|fs| {
                    let bytes = fs.read_file(&path).unwrap_or_default();
                    let _ = fs.delete_file(&path);
                    bytes
                })
            }
            None => Vec::new(),
        };
        result.map(|code| (code, captured))
    }

    fn write(&mut self, stderr: bool, bytes: &[u8]) {
        native_write_to_handle(std_handle(if stderr { 2 } else { 1 }), bytes);
    }
}
