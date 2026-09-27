//! Windows process launch, command-line, and child-output support.

use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct NativeLaunchSpec {
    pub(super) application: String,
    pub(super) arguments: Vec<String>,
    pub(super) current_directory: String,
}

/// Parse the subset of Windows command-line syntax needed to identify an
/// executable. Backslashes are literal except when immediately before a
/// quote, following the CommandLineToArgvW/MSVC escaping rules.
pub(super) fn parse_windows_command_line(line: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        while index < chars.len() && chars[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == chars.len() {
            break;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while index < chars.len() {
            let mut slashes = 0;
            while index < chars.len() && chars[index] == '\\' {
                slashes += 1;
                index += 1;
            }
            if index < chars.len() && chars[index] == '"' {
                arg.extend(std::iter::repeat_n('\\', slashes / 2));
                if slashes % 2 == 1 {
                    arg.push('"');
                } else if quoted && index + 1 < chars.len() && chars[index + 1] == '"' {
                    arg.push('"');
                    index += 1;
                } else {
                    quoted = !quoted;
                }
                index += 1;
                continue;
            }
            arg.extend(std::iter::repeat_n('\\', slashes));
            if index == chars.len() || (!quoted && chars[index].is_ascii_whitespace()) {
                break;
            }
            arg.push(chars[index]);
            index += 1;
        }
        if quoted {
            return Err("unterminated quote in command line".to_string());
        }
        args.push(arg);
    }
    Ok(args)
}

pub(super) fn native_launch_spec(
    application: Option<String>,
    command_line: Option<String>,
    current_directory: Option<String>,
    fs: &WinFs,
) -> Result<NativeLaunchSpec, u32> {
    let command_line = command_line.unwrap_or_default();
    let arguments = parse_windows_command_line(&command_line).map_err(|_| 87u32)?;
    let application = application
        .filter(|value| !value.is_empty())
        .or_else(|| arguments.first().cloned())
        .ok_or(87u32)?;
    let application = fs.normalize(&application).map_err(|_| 3u32)?.display();
    let current_directory = match current_directory.filter(|value| !value.is_empty()) {
        Some(value) => {
            let path = fs.normalize(&value).map_err(|_| 3u32)?.display();
            if !fs.is_dir(&path) {
                return Err(267u32); // ERROR_DIRECTORY
            }
            path
        }
        None => fs.cwd(),
    };
    Ok(NativeLaunchSpec {
        application,
        arguments,
        current_directory,
    })
}

pub(super) fn native_resolve_launch_application(
    launch: &mut NativeLaunchSpec,
    fs: &WinFs,
    environment: &[(String, String)],
) {
    let Some(name) = launch.arguments.first() else {
        return;
    };
    if name.contains(['\\', '/', ':']) {
        return;
    }

    let no_current_directory = environment
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("NoDefaultCurrentDirectoryInExePath"));
    let mut directories = Vec::new();
    if !no_current_directory {
        directories.push(launch.current_directory.clone());
    }
    directories.push(r"C:\Windows\System32".to_string());
    directories.push(r"C:\Windows".to_string());
    if let Some((_, path)) = environment
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("PATH"))
    {
        directories.extend(
            path.split(';')
                .filter(|part| !part.is_empty())
                .map(str::to_string),
        );
    }

    for directory in directories {
        let candidate = format!("{}\\{}", directory.trim_end_matches(['\\', '/']), name);
        let Ok(candidate) = fs.normalize(&candidate) else {
            continue;
        };
        let candidate = candidate.display();
        if fs.is_file(&candidate) {
            launch.application = candidate;
            return;
        }
    }
}

pub(super) fn execute_powershell_shell_link(
    fs: &mut WinFs,
    arguments: &[String],
) -> (u32, Vec<u8>, Vec<u8>) {
    let cwd = fs.cwd();
    let mut stdout = Vec::new();
    let result = crate::shell::powershell_script(fs, arguments).and_then(|script| {
        crate::ps1::run_ps1(fs, &script, &mut stdout)
            .map_err(|error| format!("script error: {error}"))
    });
    let _ = fs.set_cwd(&cwd);
    match result {
        Ok(code) => (code as u32, stdout, Vec::new()),
        Err(error) => (1, stdout, format!("wincli: {error}\n").into_bytes()),
    }
}

pub(super) fn native_write_process_output(
    pipe: Option<&NativePipeHandle>,
    handle: u64,
    bytes: &[u8],
) -> bool {
    if let Some((device, _)) = native_device(handle) {
        let output = match device {
            NativeDevice::Null => return true,
            NativeDevice::Console { output, .. } | NativeDevice::ConsoleOut(output) => output,
            NativeDevice::ConsoleIn(_) => return false,
        };
        return output != handle && native_write_to_handle(output, bytes);
    }
    if let Some(pipe) = pipe {
        let can_write = if pipe.endpoint.server {
            pipe.access & 0x3 & 0x2 != 0
        } else {
            pipe.access & 0x4000_0000 != 0
        };
        if !can_write {
            return false;
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let written = unsafe {
                send(
                    pipe.endpoint.fd,
                    bytes[offset..].as_ptr().cast(),
                    bytes.len() - offset,
                    0x4000,
                )
            };
            if written <= 0 {
                return false;
            }
            offset += written as usize;
        }
        return true;
    }

    let host_fd = match handle {
        0..=2 => Some(handle as i32),
        STD_HANDLE_BASE..=0x5000_0002 => Some((handle - STD_HANDLE_BASE) as i32),
        _ => None,
    };
    let Some(host_fd @ (1 | 2)) = host_fd else {
        return bytes.is_empty();
    };
    for chunk in bytes.chunks(64 * 1024) {
        let mut offset = 0;
        while offset < chunk.len() {
            let written = unsafe {
                write(
                    host_fd,
                    chunk[offset..].as_ptr().cast(),
                    chunk.len() - offset,
                )
            };
            if written <= 0 {
                return false;
            }
            offset += written as usize;
        }
    }
    true
}

pub(super) fn native_write_to_handle(handle: u64, bytes: &[u8]) -> bool {
    let pipe = process_ctx().and_then(|process| {
        process
            .named_pipes
            .lock()
            .ok()
            .and_then(|pipes| pipes.handles.get(&handle).cloned())
    });
    native_write_process_output(pipe.as_ref(), handle, bytes)
}

pub(super) fn native_write_virtual_child_output(
    _parent: &Arc<NativeProcessContext>,
    pipe_handle: Option<(u64, NativePipeHandle)>,
    std_handle: u64,
    bytes: &[u8],
) -> bool {
    let Some((handle, pipe)) = pipe_handle else {
        return native_write_process_output(None, std_handle, bytes);
    };
    native_write_process_output(Some(&pipe), handle, bytes)
}

pub(super) fn native_create_powershell_shell_child(
    parent: Arc<NativeProcessContext>,
    launch: NativeLaunchSpec,
    mut powershell_fs: WinFs,
    std_handles: [u64; 3],
    process_information: u64,
) -> i32 {
    let (process_handle, thread_handle, child) = match parent.children.lock() {
        Ok(mut children) => children.allocate(parent.process_id),
        Err(_) => {
            native_set_last_error(6);
            return 0;
        }
    };
    let inherited_pipes = {
        let Ok(mut pipes) = parent.named_pipes.lock() else {
            native_set_last_error(6);
            return 0;
        };
        [std_handles[1], std_handles[2]].map(|handle| {
            let source = pipes.handles.get(&handle).cloned()?;
            let private_handle = pipes.next;
            pipes.next = pipes.next.saturating_add(1);
            pipes.handles.insert(private_handle, source.clone());
            Some((private_handle, source))
        })
    };
    let args = launch.arguments.into_iter().skip(1).collect::<Vec<_>>();
    let child_process_id = child.process_id;
    if !write_process_information(
        process_information,
        process_handle,
        thread_handle,
        child_process_id,
    ) {
        native_set_last_error(87);
        return 0;
    }
    let parent_fs = Arc::clone(&parent.fs);
    let worker_parent = Arc::clone(&parent);
    let worker_child = Arc::clone(&child);
    if std::thread::Builder::new()
        .name("wincli-powershell-shell-link".to_string())
        .spawn(move || {
            let _ = powershell_fs.set_cwd(&launch.current_directory);
            let (code, stdout, stderr) = execute_powershell_shell_link(&mut powershell_fs, &args);
            let state = crate::snapshot::encode_changes(&powershell_fs);
            if let Ok(mut native_fs) = parent_fs.lock() {
                let cwd = native_fs.fs.cwd();
                if let Ok(changes) = state {
                    let _ = crate::snapshot::apply_changes(&changes, &mut native_fs.fs);
                }
                let _ = native_fs.fs.set_cwd(&cwd);
            }
            let stdout_ok = native_write_virtual_child_output(
                &worker_parent,
                inherited_pipes[0].clone(),
                std_handles[1],
                &stdout,
            );
            let stderr_ok = native_write_virtual_child_output(
                &worker_parent,
                inherited_pipes[1].clone(),
                std_handles[2],
                &stderr,
            );
            if let Ok(mut pipes) = worker_parent.named_pipes.lock() {
                for (index, pipe) in inherited_pipes.into_iter().enumerate() {
                    if let Some((private_handle, _)) = pipe {
                        pipes.handles.remove(&private_handle);
                        // These are the child's inherited write ends. The
                        // parent owns the paired read ends and expects EOF
                        // after the child exits.
                        pipes.handles.remove(&std_handles[index + 1]);
                    }
                }
            }
            if let Ok(mut state) = worker_child.state.lock() {
                *state = Some(if stdout_ok && stderr_ok { code } else { 1 });
            }
            worker_child.exited.notify_all();
        })
        .is_err()
    {
        native_set_last_error(8);
        return 0;
    }
    native_set_last_error(0);
    1
}

pub(super) fn native_startup_std_handles(startup_info: u64, fallback: [u64; 3]) -> [u64; 3] {
    if startup_info == 0 {
        return fallback;
    }
    let flags = unsafe { ((startup_info + 60) as *const u32).read_unaligned() };
    if flags & 0x100 == 0 {
        return fallback;
    }
    unsafe {
        [
            (startup_info + 80) as *const u64,
            (startup_info + 88) as *const u64,
            (startup_info + 96) as *const u64,
        ]
        .map(|address| address.read_unaligned())
    }
}

pub(super) fn load_native_child_image(
    fs: &WinFs,
    launch: &NativeLaunchSpec,
) -> Result<PeImage, u32> {
    let bytes = fs.read_file(&launch.application).map_err(|_| 2u32)?; // ERROR_FILE_NOT_FOUND
    crate::pe::load_lenient(&bytes).map_err(|error| {
        if native_diagnostic_enabled() {
            eprintln!(
                "native child PE parse failed path={} len={} error={error}",
                launch.application,
                bytes.len()
            );
        }
        193u32
    }) // ERROR_BAD_EXE_FORMAT
}

pub(super) extern "win64" fn native_create_thread(
    _security: u64,
    stack_size: usize,
    start: u64,
    parameter: u64,
    flags: u32,
    thread_id: *mut u32,
) -> u64 {
    if start == 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let tls = process
        .tls_template
        .lock()
        .ok()
        .and_then(|value| value.as_ref().map(NativeTls::clone_for_thread));
    let handle = process.thread_next.fetch_add(1, Ordering::AcqRel);
    // Windows CreateThread uses the image's default stack when callers
    // pass zero. Node's libuv worker pool does this, and small host thread
    // defaults are too small for its nested module loading / async work.
    let builder = std::thread::Builder::new().stack_size(stack_size.max(4 * 1024 * 1024));
    let thread_process = Arc::clone(&process);
    let suspension = Arc::new((Mutex::new((flags & 4 != 0) as u32), Condvar::new()));
    let thread_suspension = Arc::clone(&suspension);
    let spawned = builder.spawn(move || {
        THREAD_NATIVE_HANDLE.set(handle);
        THREAD_NATIVE_PROCESS.with(|active| {
            *active.borrow_mut() = Some(Arc::clone(&thread_process));
        });
        let (count, ready) = &*thread_suspension;
        let Ok(mut count) = count.lock() else {
            return 1;
        };
        while *count != 0 {
            count = match ready.wait(count) {
                Ok(count) => count,
                Err(_) => return 1,
            };
        }
        drop(count);
        let mut _tls = tls;
        if let Some(tls) = _tls.as_mut() {
            set_teb_stack_bounds(&mut tls.teb);
            if !unsafe { set_gs(tls.teb.as_ptr() as u64) } {
                return 1;
            }
            THREAD_TEB_BASE.set(tls.teb.as_ptr() as u64);
        } else if thread_process.gs_base.load(Ordering::Acquire) != 0 {
            return 1;
        }
        let entry: unsafe extern "win64" fn(u64) -> u32 = unsafe { std::mem::transmute(start) };
        unsafe { entry(parameter) }
    });
    let Ok(join) = spawned else {
        native_set_last_error(8);
        return 0;
    };
    if !thread_id.is_null() {
        unsafe { thread_id.write(handle as u32) }
    }
    let result = match process.threads.lock() {
        Ok(mut threads) => {
            threads.insert(
                handle,
                NativeThread {
                    join: Some(join),
                    exit_code: None,
                    suspension,
                },
            );
            handle
        }
        Err(_) => {
            native_set_last_error(6);
            0
        }
    };
    if native_diagnostic_enabled() {
        eprintln!("native CreateThread start={start:#x} handle={result:#x}");
    }
    result
}
pub(super) extern "win64" fn native_resume_thread(handle: u64) -> u32 {
    let Some(suspension) = process_ctx().and_then(|process| {
        process.threads.lock().ok().and_then(|threads| {
            threads
                .get(&handle)
                .map(|thread| Arc::clone(&thread.suspension))
        })
    }) else {
        native_set_last_error(6);
        return u32::MAX;
    };
    let (count, ready) = &*suspension;
    let Ok(mut count) = count.lock() else {
        return u32::MAX;
    };
    let previous = *count;
    if *count > 0 {
        *count -= 1;
        if *count == 0 {
            ready.notify_one();
        }
    }
    previous
}

pub(super) extern "win64" fn native_create_job_object_w(_attributes: u64, name: *const u16) -> u64 {
    if !name.is_null() {
        native_set_last_error(50); // Named kernel objects are not mounted in this process.
        return 0;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    let handle = process.completion_next.fetch_add(1, Ordering::AcqRel);
    if process.job_objects.lock().is_ok_and(|mut jobs| {
        jobs.insert(
            handle,
            NativeJobObject {
                limit_flags: 0,
                members: std::collections::HashSet::new(),
            },
        );
        true
    }) {
        handle
    } else {
        0
    }
}
pub(super) extern "win64" fn native_create_job_object_a(attributes: u64, name: *const u8) -> u64 {
    if !name.is_null() {
        native_set_last_error(50);
        return 0;
    }
    native_create_job_object_w(attributes, std::ptr::null())
}
pub(super) extern "win64" fn native_set_information_job_object(
    job: u64,
    information_class: i32,
    information: *const u8,
    length: u32,
) -> i32 {
    if information.is_null() || information_class != 9 || length < 144 {
        native_set_last_error(87);
        return 0;
    }
    let flags = unsafe { ((information as usize + 24) as *const u32).read_unaligned() };
    let Some(process) = process_ctx() else {
        return 0;
    };
    let Some(_) = process.job_objects.lock().ok().and_then(|mut jobs| {
        jobs.get_mut(&job).map(|job| {
            job.limit_flags = flags;
        })
    }) else {
        native_set_last_error(6);
        return 0;
    };
    1
}
pub(super) extern "win64" fn native_assign_process_to_job_object(
    job: u64,
    process_handle: u64,
) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let is_child = process
        .children
        .lock()
        .is_ok_and(|children| children.children.contains_key(&process_handle));
    let is_current_process =
        process_handle == PROCESS_TOKEN_HANDLE || process_handle == process.process_handle;
    if !is_child && !is_current_process {
        native_set_last_error(6);
        return 0;
    }
    if process.job_objects.lock().is_ok_and(|mut jobs| {
        jobs.get_mut(&job)
            .is_some_and(|job| job.members.insert(process_handle))
    }) {
        1
    } else {
        native_set_last_error(6);
        0
    }
}
pub(super) extern "win64" fn native_terminate_job_object(job: u64, exit_code: u32) -> i32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let members = process.job_objects.lock().ok().and_then(|jobs| {
        jobs.get(&job)
            .map(|job| job.members.iter().copied().collect::<Vec<_>>())
    });
    let Some(members) = members else {
        native_set_last_error(6);
        return 0;
    };
    for member in members {
        native_terminate_process(member, exit_code);
    }
    1
}

pub(super) extern "win64" fn native_get_current_thread_id() -> u32 {
    THREAD_NATIVE_HANDLE.with(|handle| (handle.get() as u32).max(1))
}
pub(super) extern "win64" fn native_get_current_process_id() -> u32 {
    process_ctx()
        .map(|process| {
            debug_assert!(process.parent_process_id <= process.process_id);
            process.process_id
        })
        .unwrap_or(0)
}
pub(super) extern "win64" fn native_get_current_process() -> u64 {
    process_ctx()
        .map(|process| process.process_handle)
        .unwrap_or(u64::MAX)
}

pub(super) fn child_process(
    process: &NativeProcessContext,
    handle: u64,
) -> Option<Arc<NativeChildProcess>> {
    let table = process.children.lock().ok()?;
    table
        .children
        .get(&handle)
        .or_else(|| table.primary_threads.get(&handle))
        .cloned()
}

pub(super) extern "win64" fn native_get_exit_code_process(handle: u64, code: *mut u32) -> i32 {
    if code.is_null() {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    if handle == process.process_handle {
        let exit_code = if process.exited.load(Ordering::Acquire) {
            process.exit_status.load(Ordering::Acquire)
        } else {
            259 // STILL_ACTIVE
        };
        unsafe { code.write(exit_code) };
        return 1;
    }
    let Some(child) = child_process(&process, handle) else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let exit_code = child
        .state
        .lock()
        .ok()
        .and_then(|state| *state)
        .unwrap_or(259);
    unsafe { code.write(exit_code) };
    1
}
pub(super) extern "win64" fn native_terminate_process(handle: u64, code: u32) -> i32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    if handle == process.process_handle {
        process.exit_status.store(code, Ordering::Release);
        process.exited.store(true, Ordering::Release);
        native_exit_process(code)
    }
    let Some(child) = child_process(&process, handle) else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let host_pid = child.host_pid.load(Ordering::Acquire);
    if host_pid > 0 {
        // SIGTERM is the host-side equivalent of terminating a guest
        // child. The monitor reaps it and publishes completion to
        // WaitForSingleObject/GetExitCodeProcess.
        if let Ok(mut termination_code) = child.termination_code.lock() {
            *termination_code = Some(code);
        } else {
            native_set_last_error(6);
            return 0;
        }
        if unsafe { kill(host_pid, 15) } == 0 {
            return 1;
        }
        native_set_last_error(6);
        return 0;
    }
    let Ok(mut state) = child.state.lock() else {
        native_set_last_error(6);
        return 0;
    };
    if state.is_none() {
        *state = Some(code);
        child.exited.notify_all();
    }
    1
}
pub(super) extern "win64" fn native_get_current_thread() -> u64 {
    u64::MAX - 1
}

#[allow(dead_code)] // called when the child launcher returns success
pub(super) fn write_process_information(
    output: u64,
    process: u64,
    thread: u64,
    process_id: u32,
) -> bool {
    if output == 0 {
        return false;
    }
    unsafe {
        let output = output as *mut u8;
        (output as *mut u64).write_unaligned(process);
        (output.add(8) as *mut u64).write_unaligned(thread);
        (output.add(16) as *mut u32).write_unaligned(process_id);
        (output.add(20) as *mut u32).write_unaligned(1);
    }
    true
}

pub(super) fn finish_native_child(
    child: Arc<NativeChildProcess>,
    fs: Arc<Mutex<NativeFs>>,
    state_fd: i32,
    pid: i32,
) {
    let mut encoded = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read_count = unsafe { read(state_fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read_count <= 0 {
            break;
        }
        encoded.extend_from_slice(&buffer[..read_count as usize]);
    }
    unsafe { close(state_fd) };
    let mut status = 0;
    let reaped = unsafe { waitpid(pid, &mut status, 0) } == pid;
    if reaped && !encoded.is_empty() {
        if let Ok(mut native_fs) = fs.lock() {
            // A child process owns its working directory. Preserve the
            // parent's directory while applying the child's file journal.
            let parent_cwd = native_fs.fs.cwd();
            match crate::snapshot::apply_changes(&encoded, &mut native_fs.fs) {
                Ok(()) => {
                    let _ = native_fs.fs.set_cwd(&parent_cwd);
                }
                Err(error) => {
                    eprintln!("wincli: cannot apply child filesystem changes: {error}")
                }
            }
        }
    }
    if let Ok(mut state) = child.state.lock() {
        if state.is_none() {
            let terminated = child.termination_code.lock().ok().and_then(|code| *code);
            *state = Some(terminated.unwrap_or_else(|| {
                if reaped && status & 0x7f == 0 {
                    (status >> 8) as u32
                } else {
                    1
                }
            }));
        }
        child.exited.notify_all();
    }
}

struct ChildWorkerDirectory(std::path::PathBuf);

static NEXT_EXEC_CHILD_DIRECTORY: AtomicU64 = AtomicU64::new(1);

impl Drop for ChildWorkerDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn worker_stdio_for_handle(
    handle: u64,
    pipes: &NativeNamedPipeTable,
) -> Result<std::process::Stdio, u32> {
    use std::os::fd::FromRawFd;
    use std::process::Stdio;
    if let Some((device, _)) = native_device(handle) {
        return match device {
            NativeDevice::Null => Ok(Stdio::null()),
            NativeDevice::Console { .. }
            | NativeDevice::ConsoleIn(_)
            | NativeDevice::ConsoleOut(_) => Ok(Stdio::inherit()),
        };
    }
    if matches!(handle, 0..=2 | STD_HANDLE_BASE..=0x5000_0002) {
        return Ok(Stdio::inherit());
    }
    let Some(pipe) = pipes.handles.get(&handle) else {
        return Err(6); // ERROR_INVALID_HANDLE
    };
    let fd = unsafe { dup(pipe.endpoint.fd) };
    if fd < 0 {
        return Err(8); // ERROR_NOT_ENOUGH_MEMORY
    }
    // SAFETY: dup returned a new descriptor whose ownership moves into Stdio.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    Ok(Stdio::from(owned))
}

fn can_exec_worker_child(
    child_fs: &NativeFs,
    parent: &NativeProcessContext,
    std_handles: [u64; 3],
    inherit_handles: bool,
) -> bool {
    // File handles are serialized into the worker request. Handles attached
    // to completion ports still need a process-wide completion protocol.
    if child_fs
        .handles
        .values()
        .any(|file| file.completion.is_some())
    {
        return false;
    }
    if child_fs
        .devices
        .keys()
        .any(|handle| !std_handles.contains(handle))
    {
        return false;
    }
    let Ok(pipes) = parent.named_pipes.lock() else {
        return false;
    };
    for (handle, pipe) in &pipes.handles {
        if (std_handles.contains(handle) || (inherit_handles && pipe.inheritable))
            && pipe.completion.is_some()
        {
            return false;
        }
    }
    if pipes.pending_io.keys().any(|(handle, _)| {
        std_handles.contains(handle)
            || (inherit_handles
                && pipes
                    .handles
                    .get(handle)
                    .is_some_and(|pipe| pipe.inheritable))
    }) {
        return false;
    }
    std_handles.iter().all(|handle| {
        if matches!(handle, 0..=2 | STD_HANDLE_BASE..=0x5000_0002)
            || native_device(*handle).is_some()
        {
            return true;
        }
        if pipes.handles.contains_key(handle) {
            return inherit_handles;
        }
        host_standard_fd(*handle).is_some()
    })
}

fn encode_worker_native_fs(native_fs: &NativeFs) -> Result<serde_json::Value, String> {
    let files = native_fs
        .handles
        .iter()
        .map(|(handle, file)| {
            if file.completion.is_some() {
                return Err(
                    "file handle completion ports cannot cross a worker boundary".to_string(),
                );
            }
            Ok(serde_json::json!({
                "handle": handle,
                "path": file.path,
                "offset": file.offset,
                "overlapped": file.overlapped,
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let devices = native_fs
        .devices
        .iter()
        .map(|(handle, device)| {
            let value = match device {
                NativeDevice::Null => serde_json::json!({"kind": "null"}),
                NativeDevice::Console { input, output } => {
                    serde_json::json!({"kind": "console", "input": input, "output": output})
                }
                NativeDevice::ConsoleIn(input) => {
                    serde_json::json!({"kind": "console_in", "input": input})
                }
                NativeDevice::ConsoleOut(output) => {
                    serde_json::json!({"kind": "console_out", "output": output})
                }
            };
            serde_json::json!({"handle": handle, "device": value})
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "files": files,
        "devices": devices,
        "file_access": native_fs.file_access,
        "file_shares": native_fs.file_shares,
        "finds": native_fs.finds.iter().map(|(handle, find)| serde_json::json!({
            "handle": handle,
            "names": find.names,
            "index": find.index,
        })).collect::<Vec<_>>(),
        "file_completion_modes": native_fs.file_completion_modes,
        "delete_on_close": native_fs.delete_on_close,
        "file_locks": native_fs.file_locks,
        "next": native_fs.next,
    }))
}

fn send_worker_pipe_fds(
    stream: &std::os::unix::net::UnixStream,
    fds: &[i32],
) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    if fds.is_empty() {
        return Ok(());
    }
    let payload = [0x57u8];
    let control_bytes = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize };
    let mut control = vec![0usize; control_bytes.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: msghdr and cmsghdr point into the allocated control buffer.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        let mut iovec = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_bytes;
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err("cannot allocate worker pipe descriptor message".to_string());
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(header),
            std::mem::size_of_val(fds),
        );
        let sent = libc::sendmsg(stream.as_raw_fd(), &message, 0);
        if sent != payload.len() as isize {
            return Err(format!(
                "cannot transfer worker pipe descriptors: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

pub(super) fn receive_worker_pipe_fds(
    stream: &std::os::unix::net::UnixStream,
    expected: usize,
) -> Result<Vec<i32>, String> {
    use std::os::fd::AsRawFd;
    let control_bytes =
        unsafe { libc::CMSG_SPACE((expected * std::mem::size_of::<i32>()) as u32) as usize };
    let mut control = vec![0usize; control_bytes.div_ceil(std::mem::size_of::<usize>())];
    let mut payload = [0u8; 1];
    // SAFETY: msghdr and cmsghdr point into the allocated control buffer.
    let (received, fds) = unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        let mut iovec = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_bytes;
        let received = libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC);
        if received != payload.len() as isize || payload[0] != 0x57 {
            return Err(format!(
                "cannot receive worker pipe descriptors: {}",
                std::io::Error::last_os_error()
            ));
        }
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
        {
            return Err("worker did not send pipe descriptors".to_string());
        }
        let payload_bytes = (*header)
            .cmsg_len
            .saturating_sub(libc::CMSG_LEN(0) as usize);
        let count = payload_bytes / std::mem::size_of::<i32>();
        let data = libc::CMSG_DATA(header).cast::<i32>();
        let fds = std::slice::from_raw_parts(data, count).to_vec();
        (received, fds)
    };
    let _ = received;
    if fds.len() != expected {
        for fd in fds {
            unsafe { close(fd) };
        }
        return Err("worker pipe descriptor count does not match request".to_string());
    }
    Ok(fds)
}

pub(super) fn restore_worker_native_fs(
    process: &NativeProcessContext,
    request_path: &std::path::Path,
) -> Result<(), String> {
    let request: serde_json::Value = serde_json::from_slice(
        &std::fs::read(request_path)
            .map_err(|error| format!("cannot read worker request: {error}"))?,
    )
    .map_err(|error| format!("invalid worker request: {error}"))?;
    let encoded = request
        .get("native_fs")
        .ok_or_else(|| "worker request has no native filesystem state".to_string())?;
    let mut fs = process
        .fs
        .lock()
        .map_err(|_| "worker filesystem lock is poisoned".to_string())?;
    apply_worker_native_fs(&mut fs, encoded)?;
    drop(fs);
    restore_worker_pipe_handles(process, &request)
}

fn restore_worker_pipe_handles(
    process: &NativeProcessContext,
    request: &serde_json::Value,
) -> Result<(), String> {
    let Some(items) = request
        .get("inherited_pipes")
        .and_then(serde_json::Value::as_array)
        .filter(|items| !items.is_empty())
    else {
        return Ok(());
    };
    struct PipeInfo {
        handle: u64,
        name: String,
        server: bool,
        endpoint_access: u32,
        has_pending_client: bool,
        pending_client_access: u32,
        overlapped: bool,
        inheritable: bool,
        access: u32,
        mode: u32,
        completion_modes: u8,
    }
    let number = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("invalid inherited pipe field {key}"))
    };
    let infos = items
        .iter()
        .map(|item| {
            Ok::<_, String>(PipeInfo {
                handle: number(item, "handle")?,
                name: item
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("inherited pipe has invalid name")?
                    .to_owned(),
                server: item
                    .get("server")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or("inherited pipe has invalid endpoint role")?,
                endpoint_access: number(item, "endpoint_access")? as u32,
                has_pending_client: item
                    .get("has_pending_client")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or("inherited pipe has invalid pending-client state")?,
                pending_client_access: number(item, "pending_client_access")? as u32,
                overlapped: item
                    .get("overlapped")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or("inherited pipe has invalid overlapped flag")?,
                inheritable: item
                    .get("inheritable")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or("inherited pipe has invalid inheritability")?,
                access: number(item, "access")? as u32,
                mode: number(item, "mode")? as u32,
                completion_modes: number(item, "completion_modes")? as u8,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fds = std::env::var("WINCLI_NATIVE_PIPE_FDS")
        .map_err(|_| "worker did not receive inherited pipe descriptors".to_string())?
        .split(',')
        .map(|value| value.parse::<i32>().map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let expected_fds = request
        .get("pipe_transfer_fd_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or("worker request has invalid pipe descriptor count")? as usize;
    if fds.len() != expected_fds {
        for fd in fds {
            unsafe { close(fd) };
        }
        return Err("inherited pipe descriptor count does not match request".to_string());
    }
    let mut pipes = process
        .named_pipes
        .lock()
        .map_err(|_| "worker pipe table is poisoned".to_string())?;
    let mut fds = fds.into_iter();
    for info in infos {
        let fd = fds
            .next()
            .ok_or("worker is missing an inherited pipe endpoint")?;
        let endpoint = Arc::new(NativePipeEndpoint {
            fd,
            name: info.name,
            server: info.server,
            access: info.endpoint_access,
        });
        let pending_client = if info.has_pending_client {
            Some(Arc::new(NativePipeEndpoint {
                fd: fds
                    .next()
                    .ok_or("worker is missing a pending named-pipe client endpoint")?,
                name: endpoint.name.clone(),
                server: false,
                access: info.pending_client_access,
            }))
        } else {
            None
        };
        pipes.handles.insert(
            info.handle,
            NativePipeHandle {
                endpoint,
                pending_client,
                overlapped: info.overlapped,
                inheritable: info.inheritable,
                access: info.access,
                mode: info.mode,
                completion: None,
                completion_modes: info.completion_modes,
            },
        );
        pipes.next = pipes.next.max(info.handle.saturating_add(1));
    }
    Ok(())
}

fn apply_worker_native_fs(fs: &mut NativeFs, encoded: &serde_json::Value) -> Result<(), String> {
    let number = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("invalid worker filesystem field {key}"))
    };
    let files = encoded
        .get("files")
        .and_then(serde_json::Value::as_array)
        .ok_or("worker filesystem has invalid files")?;
    for item in files {
        let handle = number(item, "handle")?;
        let path = item
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or("worker file handle has invalid path")?
            .to_owned();
        let offset = number(item, "offset")? as usize;
        let overlapped = item
            .get("overlapped")
            .and_then(serde_json::Value::as_bool)
            .ok_or("worker file handle has invalid overlapped flag")?;
        fs.handles.insert(
            handle,
            NativeFile {
                path,
                offset,
                overlapped,
                completion: None,
            },
        );
    }
    let devices = encoded
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .ok_or("worker filesystem has invalid devices")?;
    for item in devices {
        let handle = number(item, "handle")?;
        let device = item
            .get("device")
            .ok_or("worker device handle has no device data")?;
        let kind = device
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or("worker device has invalid kind")?;
        let device = match kind {
            "null" => NativeDevice::Null,
            "console" => NativeDevice::Console {
                input: number(device, "input")?,
                output: number(device, "output")?,
            },
            "console_in" => NativeDevice::ConsoleIn(number(device, "input")?),
            "console_out" => NativeDevice::ConsoleOut(number(device, "output")?),
            _ => return Err(format!("unknown worker device kind {kind}")),
        };
        fs.devices.insert(handle, device);
    }
    macro_rules! restore_map {
        ($field:ident, $ty:ty) => {
            fs.$field = serde_json::from_value::<HashMap<u64, $ty>>(
                encoded
                    .get(stringify!($field))
                    .cloned()
                    .ok_or_else(|| format!("worker filesystem has no {}", stringify!($field)))?,
            )
            .map_err(|error| format!("invalid worker {}: {error}", stringify!($field)))?;
        };
    }
    restore_map!(file_access, u32);
    restore_map!(file_shares, u32);
    restore_map!(file_completion_modes, u8);
    let finds = encoded
        .get("finds")
        .and_then(serde_json::Value::as_array)
        .ok_or("worker filesystem has invalid find handles")?;
    for item in finds {
        let handle = number(item, "handle")?;
        let names = serde_json::from_value(
            item.get("names")
                .cloned()
                .ok_or("worker find handle has no names")?,
        )
        .map_err(|error| format!("invalid worker find names: {error}"))?;
        let index = number(item, "index")? as usize;
        fs.finds.insert(handle, NativeFind { names, index });
    }
    fs.delete_on_close = serde_json::from_value(
        encoded
            .get("delete_on_close")
            .cloned()
            .ok_or("worker filesystem has no delete-on-close handles")?,
    )
    .map_err(|error| format!("invalid worker delete-on-close handles: {error}"))?;
    fs.file_locks = serde_json::from_value(
        encoded
            .get("file_locks")
            .cloned()
            .ok_or("worker filesystem has no file locks")?,
    )
    .map_err(|error| format!("invalid worker file locks: {error}"))?;
    fs.next = number(encoded, "next")?;
    Ok(())
}

#[cfg(test)]
mod worker_native_fs_tests {
    use super::*;

    fn empty_fs() -> NativeFs {
        NativeFs {
            fs: WinFs::ephemeral_runner(),
            handles: HashMap::new(),
            devices: HashMap::new(),
            file_access: HashMap::new(),
            file_shares: HashMap::new(),
            finds: HashMap::new(),
            file_completion_modes: HashMap::new(),
            delete_on_close: std::collections::HashSet::new(),
            file_locks: Vec::new(),
            next: 0x100,
        }
    }

    #[test]
    fn worker_native_fs_roundtrip_preserves_open_file_state() {
        let mut original = empty_fs();
        original.handles.insert(
            0x123,
            NativeFile {
                path: r"C:\data.txt".to_string(),
                offset: 17,
                overlapped: true,
                completion: None,
            },
        );
        original.file_access.insert(0x123, 0x8000_0000);
        original.file_shares.insert(0x123, 3);
        original.file_completion_modes.insert(0x123, 1);
        original.devices.insert(0x125, NativeDevice::Null);
        original.finds.insert(
            0x124,
            NativeFind {
                names: vec!["one.txt".to_string(), "two.txt".to_string()],
                index: 1,
            },
        );
        original.delete_on_close.insert(0x123);
        original
            .file_locks
            .push((r"C:\data.txt".to_string(), 4, 8, 0x123));
        original.next = 0x125;

        let encoded = encode_worker_native_fs(&original).unwrap();
        let mut restored = empty_fs();
        apply_worker_native_fs(&mut restored, &encoded).unwrap();

        let file = restored.handles.get(&0x123).unwrap();
        assert_eq!(file.path, r"C:\data.txt");
        assert_eq!(file.offset, 17);
        assert!(file.overlapped);
        assert_eq!(restored.file_access.get(&0x123), Some(&0x8000_0000));
        assert_eq!(restored.file_shares.get(&0x123), Some(&3));
        assert_eq!(restored.file_completion_modes.get(&0x123), Some(&1));
        assert_eq!(restored.devices.get(&0x125), Some(&NativeDevice::Null));
        assert_eq!(restored.finds.get(&0x124).unwrap().index, 1);
        assert!(restored.delete_on_close.contains(&0x123));
        assert_eq!(restored.file_locks, original.file_locks);
        assert_eq!(restored.next, 0x125);
    }

    #[test]
    fn worker_native_fs_rejects_completion_port_handles() {
        let mut original = empty_fs();
        original.handles.insert(
            0x123,
            NativeFile {
                path: r"C:\data.txt".to_string(),
                offset: 0,
                overlapped: true,
                completion: Some((
                    Arc::new(NativeCompletionPort {
                        queue: Mutex::new(std::collections::VecDeque::new()),
                        ready: Condvar::new(),
                    }),
                    0,
                )),
            },
        );
        assert!(encode_worker_native_fs(&original).is_err());
    }

    #[test]
    fn worker_pipe_transfer_passes_live_file_descriptors() {
        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { pipe(pipe_fds.as_mut_ptr()) }, 0);
        let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        let sender_thread = std::thread::spawn(move || {
            send_worker_pipe_fds(&sender, &pipe_fds).unwrap();
            unsafe {
                close(pipe_fds[0]);
                close(pipe_fds[1]);
            }
        });
        let received = receive_worker_pipe_fds(&receiver, 2).unwrap();
        sender_thread.join().unwrap();
        let byte = [b'x'];
        assert_eq!(
            unsafe { write(received[1], byte.as_ptr().cast(), byte.len()) },
            1
        );
        let mut read_byte = [0u8];
        assert_eq!(
            unsafe { read(received[0], read_byte.as_mut_ptr().cast(), 1) },
            1
        );
        assert_eq!(read_byte, byte);
        unsafe {
            close(received[0]);
            close(received[1]);
        }
    }
}

fn create_exec_worker_child(
    parent: &Arc<NativeProcessContext>,
    launch: &NativeLaunchSpec,
    image: &PeImage,
    mut child_fs: NativeFs,
    child_std_handles: [u64; 3],
    inherit_handles: bool,
    environment: &[(String, String)],
    process_information: u64,
) -> Result<(), u32> {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let executable = std::env::var_os("WINCLI_NATIVE_WORKER_EXE").ok_or(120u32)?;
    let pipes = parent.named_pipes.lock().map_err(|_| 6u32)?;
    let stdio = child_std_handles
        .map(|handle| worker_stdio_for_handle(handle, &pipes))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let std_set = child_std_handles
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let transferable_pipes = if inherit_handles {
        pipes
            .handles
            .iter()
            .filter(|(handle, pipe)| pipe.inheritable && !std_set.contains(handle))
            .map(|(handle, pipe)| (*handle, pipe.clone()))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if transferable_pipes
        .iter()
        .any(|(_, pipe)| pipe.completion.is_some())
    {
        return Err(120); // ERROR_CALL_NOT_IMPLEMENTED for completion-associated pipe handles.
    }
    drop(pipes);

    let id = NEXT_EXEC_CHILD_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory =
        std::env::temp_dir().join(format!("wincli-child-worker-{}-{id}", std::process::id()));
    std::fs::create_dir(&directory).map_err(|_| 8u32)?;
    let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
    let directory_guard = ChildWorkerDirectory(directory.clone());
    let pipe_transfer_path = directory.join("inherited-pipes.sock");
    let pipe_listener = if transferable_pipes.is_empty() {
        None
    } else {
        Some(std::os::unix::net::UnixListener::bind(&pipe_transfer_path).map_err(|_| 8u32)?)
    };
    let mut inherited_pipe_metadata = Vec::new();
    let mut inherited_pipe_fds = Vec::new();
    for (handle, pipe) in &transferable_pipes {
        inherited_pipe_metadata.push(serde_json::json!({
                "handle": handle,
                "name": pipe.endpoint.name,
                "server": pipe.endpoint.server,
                "endpoint_access": pipe.endpoint.access,
                "has_pending_client": pipe.pending_client.is_some(),
                "pending_client_access": pipe.pending_client.as_ref().map_or(0, |endpoint| endpoint.access),
                "overlapped": pipe.overlapped,
                "inheritable": pipe.inheritable,
                "access": pipe.access,
                "mode": pipe.mode,
                "completion_modes": pipe.completion_modes,
            }));
        inherited_pipe_fds.push(pipe.endpoint.fd);
        if let Some(pending_client) = &pipe.pending_client {
            inherited_pipe_fds.push(pending_client.fd);
        }
    }
    let image_path = match super::super::worker::write_image(image, &directory) {
        Ok(path) => path,
        Err(_) => return Err(8),
    };
    let snapshot_path = match crate::snapshot::save_worker_manifest(&child_fs.fs, &directory) {
        Ok(path) => path,
        Err(_) => return Err(8),
    };
    let state_path = directory.join("state.bin");
    let result_path = directory.join("result.bin");
    let request_path = directory.join("request.json");
    let (process_handle, thread_handle, child) = parent
        .children
        .lock()
        .map_err(|_| 6u32)?
        .allocate(parent.process_id);
    child_fs.fs.clear_changes();
    let request = serde_json::json!({
        "image_path": image_path,
        "snapshot_path": snapshot_path,
        "state_path": state_path,
        "result_path": result_path,
        "program": launch.application,
        "args": launch.arguments.get(1..).unwrap_or(&[]),
        "environment": environment,
        "process_id": child.process_id,
        "parent_process_id": parent.process_id,
        "native_fs": encode_worker_native_fs(&child_fs).map_err(|_| 8u32)?,
        "inherited_pipes": inherited_pipe_metadata,
        "pipe_transfer_fd_count": inherited_pipe_fds.len(),
        "pipe_transfer_socket": pipe_listener.as_ref().map(|_| pipe_transfer_path),
        "mounts": child_fs.fs.host_mounts(),
        "drive_cwds": child_fs.fs.drive_current_directories(),
        "cwd": launch.current_directory,
    });
    let request_bytes = serde_json::to_vec(&request).map_err(|_| 8u32)?;
    std::fs::write(&request_path, request_bytes).map_err(|_| 8u32)?;

    let mut stdio = stdio.into_iter();
    let mut command = Command::new(executable);
    command
        .arg("__native-worker")
        .arg(&request_path)
        .env_remove("WINCLI_NATIVE_WORKER")
        .stdin(stdio.next().ok_or(8u32)?)
        .stdout(stdio.next().ok_or(8u32)?)
        .stderr(stdio.next().ok_or(8u32)?);
    let mut worker = match command.spawn() {
        Ok(worker) => worker,
        Err(_) => {
            return Err(8);
        }
    };
    if let Some(listener) = pipe_listener {
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(_) => {
                let _ = worker.kill();
                let _ = worker.wait();
                return Err(8);
            }
        };
        if send_worker_pipe_fds(&stream, &inherited_pipe_fds).is_err() {
            let _ = worker.kill();
            let _ = worker.wait();
            return Err(8);
        }
    }
    // Close this process's copies immediately; only the worker should retain
    // the inherited standard pipe endpoints after a successful spawn.
    drop(stdio);
    child.host_pid.store(worker.id() as i32, Ordering::Release);
    if !write_process_information(
        process_information,
        process_handle,
        thread_handle,
        child.process_id,
    ) {
        let _ = worker.kill();
        let _ = worker.wait();
        return Err(87);
    }
    let monitor_child = Arc::clone(&child);
    let monitor_fs = Arc::clone(&parent.fs);
    let state_path_for_monitor = state_path.clone();
    std::thread::Builder::new()
        .name("wincli-native-worker-child".to_string())
        .spawn(move || {
            let status = worker.wait();
            if let Ok(encoded) = std::fs::read(&state_path_for_monitor) {
                if !encoded.is_empty() {
                    if let Ok(mut native_fs) = monitor_fs.lock() {
                        let cwd = native_fs.fs.cwd();
                        if let Err(error) =
                            crate::snapshot::apply_changes(&encoded, &mut native_fs.fs)
                        {
                            eprintln!("wincli: cannot apply child filesystem changes: {error}");
                        }
                        let _ = native_fs.fs.set_cwd(&cwd);
                    }
                }
            }
            if let Ok(mut state) = monitor_child.state.lock() {
                if state.is_none() {
                    *state = Some(
                        status
                            .ok()
                            .and_then(|status| status.code())
                            .map(|code| code as u32)
                            .unwrap_or(1),
                    );
                }
                monitor_child.exited.notify_all();
            }
            drop(directory_guard);
        })
        .map_err(|_| 8u32)?;
    Ok(())
}

pub(super) extern "win64" fn native_exit_process(code: u32) -> ! {
    if std::env::var_os("WINCLI_NATIVE_WORKER").as_deref() == Some(std::ffi::OsStr::new("1")) {
        if process_ctx().is_some_and(|process| process.parent_process_id == 0) {
            let fd = NATIVE_WORKER_RESULT_FD.load(Ordering::Acquire);
            if fd >= 0 {
                let result = code.to_le_bytes();
                unsafe { write(fd, result.as_ptr().cast(), result.len()) };
            }
        }
    }
    if native_diagnostic_enabled() {
        eprintln!("native ExitProcess code={code:#x}");
    }
    // Closing stdout lets the parent drain console output before the
    // snapshot pipe can block on a large guest disk image.
    unsafe { close(1) };
    native_flush_instance_state();
    // SAFETY: this terminates the isolated guest worker or forked child.
    unsafe { _exit(code as i32) }
}
pub(super) extern "win64" fn native_create_process_w(
    application: *const u16,
    command_line: *mut u16,
    _process_attributes: u64,
    _thread_attributes: u64,
    inherit_handles: i32,
    _creation_flags: u32,
    environment: u64,
    current_directory: *const u16,
    startup_info: u64,
    process_information: u64,
) -> i32 {
    if process_information == 0 {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let Some(context) = fs_ctx() else {
        native_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let Ok(fs) = context.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let has_application = !application.is_null();
    let has_command_line = !command_line.is_null();
    let has_current_directory = !current_directory.is_null();
    let application = has_application.then(|| wide(application)).flatten();
    let command_line = has_command_line
        .then(|| wide(command_line.cast_const()))
        .flatten();
    let current_directory = has_current_directory
        .then(|| wide(current_directory))
        .flatten();
    if (has_application && application.is_none())
        || (has_command_line && command_line.is_none())
        || (has_current_directory && current_directory.is_none())
    {
        native_set_last_error(87);
        return 0;
    }
    let mut launch = match native_launch_spec(application, command_line, current_directory, &fs.fs)
    {
        Ok(launch) => launch,
        Err(error) => {
            native_set_last_error(error);
            return 0;
        }
    };
    let explicit_environment = if environment == 0 {
        None
    } else {
        match environment_block(environment) {
            Ok(environment) => Some(environment),
            Err(error) => {
                native_set_last_error(error);
                return 0;
            }
        }
    };
    let Some(parent) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let search_environment = parent
        .environment
        .lock()
        .map(|environment| environment.clone())
        .unwrap_or_default();
    native_resolve_launch_application(&mut launch, &fs.fs, &search_environment);
    let parent_std_handles =
        std::array::from_fn(|index| parent.std_handles[index].load(Ordering::Acquire));
    let child_std_handles = native_startup_std_handles(startup_info, parent_std_handles);
    if crate::shell::is_powershell_shell_link(&fs.fs, &launch.application) {
        let powershell_fs = fs.fs.clone();
        drop(fs);
        return native_create_powershell_shell_child(
            parent,
            launch,
            powershell_fs,
            child_std_handles,
            process_information,
        );
    }
    let image = match load_native_child_image(&fs.fs, &launch) {
        Ok(image) => image,
        Err(error) => {
            if native_diagnostic_enabled() {
                eprintln!(
                    "native CreateProcessW could not load {} (exists={}): error={error}",
                    launch.application,
                    fs.fs.exists(&launch.application)
                );
            }
            native_set_last_error(error);
            return 0;
        }
    };
    drop(fs);
    let environment = explicit_environment.unwrap_or_else(|| {
        parent
            .environment
            .lock()
            .map(|environment| environment.clone())
            .unwrap_or_default()
    });
    if std::env::var_os("WINCLI_NATIVE_WORKER_EXE").is_some() {
        let child_fs = match context.lock() {
            Ok(parent_fs) => match parent_fs.clone_for_child(&launch.current_directory) {
                Ok(child_fs) => child_fs,
                Err(_) => {
                    native_set_last_error(267); // ERROR_DIRECTORY
                    return 0;
                }
            },
            Err(_) => {
                native_set_last_error(6);
                return 0;
            }
        };
        if can_exec_worker_child(&child_fs, &parent, child_std_handles, inherit_handles != 0) {
            match create_exec_worker_child(
                &parent,
                &launch,
                &image,
                child_fs,
                child_std_handles,
                inherit_handles != 0,
                &environment,
                process_information,
            ) {
                Ok(()) => {
                    native_set_last_error(0);
                    return 1;
                }
                Err(error) => {
                    native_set_last_error(error);
                    return 0;
                }
            }
        }
    }
    let (mapping, image) = match map_relocated(&image) {
        Ok(value) => value,
        Err(_) => {
            native_set_last_error(193); // ERROR_BAD_EXE_FORMAT
            return 0;
        }
    };
    if registry::patch_baseline_imports(&mapping, &image, false).is_err() {
        native_set_last_error(193);
        return 0;
    }
    let tls = match setup_tls(&mapping, &image) {
        Ok(value) => value,
        Err(_) => {
            native_set_last_error(193);
            return 0;
        }
    };
    let entry = match entry(&image) {
        Ok(value) => value,
        Err(_) => {
            native_set_last_error(193);
            return 0;
        }
    };
    let (process_handle, thread_handle, child) = match parent.children.lock() {
        Ok(mut children) => children.allocate(parent.process_id),
        Err(_) => {
            native_set_last_error(6);
            return 0;
        }
    };
    let mut state_fds = [-1, -1];
    if unsafe { pipe(state_fds.as_mut_ptr()) } != 0 {
        native_set_last_error(8); // ERROR_NOT_ENOUGH_MEMORY
        return 0;
    }
    let child_fs = match context.lock() {
        Ok(parent_fs) => match parent_fs.clone_for_child(&launch.current_directory) {
            Ok(child_fs) => Arc::new(Mutex::new(child_fs)),
            Err(_) => {
                native_set_last_error(267); // ERROR_DIRECTORY
                return 0;
            }
        },
        Err(_) => {
            native_set_last_error(6);
            return 0;
        }
    };
    let child_pipes = match parent.named_pipes.lock() {
        Ok(pipes) => pipes.clone_for_child(inherit_handles != 0),
        Err(_) => {
            native_set_last_error(6);
            return 0;
        }
    };
    let command_line_w = command_line_w(
        &launch.application,
        launch.arguments.get(1..).unwrap_or(&[]),
    )
    .unwrap_or_else(|_| vec![0]);
    let child_context = Arc::new(NativeProcessContext {
        image_base: image.image_base,
        module_path: launch.application.clone(),
        process_id: child.process_id,
        process_handle,
        parent_process_id: parent.process_id,
        command_line_a: command_line_a(&command_line_w),
        command_line_w,
        environment_block: Mutex::new(environment_strings(&environment)),
        environment: Mutex::new(environment),
        std_handles: [
            AtomicU64::new(child_std_handles[0]),
            AtomicU64::new(child_std_handles[1]),
            AtomicU64::new(child_std_handles[2]),
        ],
        crt_fds: Mutex::new(HashMap::new()),
        crt_fd_next: AtomicI32::new(3),
        fs: child_fs,
        named_pipes: Mutex::new(child_pipes),
        error_mode: AtomicU32::new(0),
        pointer_cookie: random_pointer_cookie(),
        heap_allocations: Mutex::new(HashMap::new()),
        virtual_allocations: Mutex::new(HashMap::new()),
        file_mappings: Mutex::new(HashMap::new()),
        mapping_views: Mutex::new(HashMap::new()),
        mapping_next: AtomicU64::new(0x9800_0000),
        gs_base: AtomicU64::new(0),
        tls_template: Mutex::new(tls.as_ref().map(NativeTls::clone_for_thread)),
        dynamic_tls: Mutex::new(DynamicTlsSlots::new(tls.is_some())),
        threads: Mutex::new(HashMap::new()),
        thread_next: AtomicU64::new(0x8000_0000),
        semaphores: Mutex::new(HashMap::new()),
        semaphore_next: AtomicU64::new(0x6000_0000),
        events: Mutex::new(HashMap::new()),
        event_names: Mutex::new(HashMap::new()),
        event_next: AtomicU64::new(0x6100_0000),
        job_objects: Mutex::new(HashMap::new()),
        wait_registrations: Mutex::new(HashMap::new()),
        completion_ports: Mutex::new(HashMap::new()),
        socket_completion_ports: Mutex::new(HashMap::new()),
        socket_completion_modes: Mutex::new(HashMap::new()),
        completion_next: AtomicU64::new(0x9000_0000),
        io_wait: Mutex::new(()),
        io_ready: Condvar::new(),
        pending_file_io: AtomicU64::new(0),
        pending_requests: Mutex::new(HashMap::new()),
        file_io_queue: Mutex::new(None),
        duplicate_handles: Mutex::new(HashMap::new()),
        duplicate_next: AtomicU64::new(0xa000_0000),
        timer_next: AtomicU64::new(0x7000_0000),
        state_fd: AtomicU32::new(state_fds[1] as u32),
        fls_value: AtomicU64::new(0),
        unhandled_exception_filter: AtomicU64::new(0),
        vectored_exception_handler: AtomicU64::new(0),
        exit_status: AtomicU32::new(259),
        exited: AtomicBool::new(false),
        children: Mutex::new(NativeProcessTable::new()),
    });
    let mut child_tls = tls;
    let mut fallback_teb = Box::new([0u8; 0x1000]);
    let child_teb = child_tls
        .as_mut()
        .map(|tls| &mut tls.teb)
        .unwrap_or(&mut fallback_teb);
    // Stack discovery reads /proc and consults diagnostics, so do it in
    // the parent before fork instead of running library code in the child.
    set_teb_stack_bounds(child_teb);
    let child_teb_base = child_teb.as_ptr() as u64;
    let pid = unsafe { fork() };
    if pid < 0 {
        unsafe {
            close(state_fds[0]);
            close(state_fds[1]);
        }
        native_set_last_error(8);
        return 0;
    }
    if pid == 0 {
        #[cfg(test)]
        NATIVE_GUEST_ACTIVE.store(true, Ordering::Release);
        unsafe { close(state_fds[0]) };
        THREAD_NATIVE_PROCESS.with(|active| {
            *active.borrow_mut() = Some(child_context);
        });
        if protect_exec(&mapping).is_err() {
            unsafe { _exit(127) };
        }
        if !unsafe { set_gs(child_teb_base) } {
            unsafe { _exit(127) };
        }
        THREAD_TEB_BASE.set(child_teb_base);
        let guest: unsafe extern "win64" fn() -> u32 = unsafe { std::mem::transmute(entry) };
        let code = unsafe { guest() };
        native_flush_instance_state();
        unsafe { _exit(code as i32) };
    }
    child.host_pid.store(pid, Ordering::Release);
    unsafe { close(state_fds[1]) };
    let monitor_child = Arc::clone(&child);
    let monitor_fs = Arc::clone(&context);
    if std::thread::Builder::new()
        .name("wincli-native-child".to_string())
        .spawn(move || finish_native_child(monitor_child, monitor_fs, state_fds[0], pid))
        .is_err()
    {
        unsafe { close(state_fds[0]) };
        native_set_last_error(8);
        return 0;
    }
    if !write_process_information(
        process_information,
        process_handle,
        thread_handle,
        child.process_id,
    ) {
        native_set_last_error(87);
        return 0;
    }
    native_set_last_error(0);
    1
}

pub(super) fn native_flush_instance_state() {
    let Some(process) = process_ctx() else {
        return;
    };
    native_wait_file_io(&process);
    let fd = process.state_fd.load(Ordering::Acquire);
    if fd == u32::MAX {
        return;
    }
    let Some(context) = fs_ctx() else {
        return;
    };
    let Ok(ctx) = context.lock() else {
        return;
    };
    let encoded =
        if std::env::var_os("WINCLI_NATIVE_WORKER").as_deref() == Some(std::ffi::OsStr::new("1")) {
            crate::snapshot::encode_portable_changes(&ctx.fs)
        } else {
            crate::snapshot::encode_changes(&ctx.fs)
        };
    let Ok(encoded) = encoded else {
        return;
    };
    let mut written = 0;
    while written < encoded.len() {
        let n = unsafe {
            write(
                fd as i32,
                encoded[written..].as_ptr().cast(),
                encoded.len() - written,
            )
        };
        if n <= 0 {
            break;
        }
        written += n as usize;
    }
    unsafe { close(fd as i32) };
    process.state_fd.store(u32::MAX, Ordering::Release);
}

pub(super) extern "win64" fn native_get_command_line_w() -> u64 {
    process_ctx()
        .map(|process| process.command_line_w.as_ptr() as u64)
        .unwrap_or(0)
}
pub(super) extern "win64" fn native_get_command_line_a() -> u64 {
    process_ctx()
        .map(|process| process.command_line_a.as_ptr() as u64)
        .unwrap_or(0)
}

pub(super) extern "win64" fn native_get_module_file_name_w(
    _module: u64,
    output: *mut u16,
    output_len: u32,
) -> u32 {
    if output.is_null() || output_len == 0 {
        return 0;
    }
    let module_path = process_ctx()
        .map(|process| process.module_path.clone())
        .unwrap_or_else(|| r"C:\wincli\wincli.exe".to_string());
    let encoded: Vec<u16> = module_path.encode_utf16().collect();
    let capacity = output_len as usize;
    let copied = encoded.len().min(capacity);
    unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), output, copied) };
    if copied < capacity {
        unsafe { output.add(copied).write(0) };
    }
    copied as u32
}

pub(super) extern "win64" fn native_set_error_mode(mode: u32) -> u32 {
    process_ctx()
        .map(|process| process.error_mode.swap(mode, Ordering::AcqRel))
        .unwrap_or(0)
}
pub(super) extern "win64" fn native_get_startup_info_w(startup_info: *mut u8) {
    if startup_info.is_null() {
        return;
    }
    // STARTUPINFOW is 104 bytes on 64-bit Windows. The native runner has
    // no inherited Windows handles, so a zeroed record is the appropriate
    // console-process baseline.
    unsafe {
        std::ptr::write_bytes(startup_info, 0, 104);
        (startup_info as *mut u32).write_unaligned(104);
    }
}

pub(super) extern "win64" fn native_get_startup_info_a(startup_info: *mut u8) {
    // STARTUPINFOA and STARTUPINFOW have the same 64-bit layout; the
    // zeroed console-process baseline contains no character fields.
    native_get_startup_info_w(startup_info);
}

pub(super) extern "win64" fn native_free_library_and_exit_thread(_module: u64, _code: u32) -> ! {
    if native_diagnostic_enabled() {
        eprintln!("native FreeLibraryAndExitThread");
    }
    let handle = THREAD_NATIVE_HANDLE.get();
    if let Some(process) = process_ctx() {
        if let Ok(mut threads) = process.threads.lock() {
            if let Some(thread) = threads.get_mut(&handle) {
                thread.exit_code = Some(_code);
            }
        }
    }
    // SYS_exit terminates only this Linux thread. pthread_exit would
    // force-unwind across PE and Rust frames and abort the guest process.
    unsafe {
        core::arch::asm!("syscall", in("rax") 60u64, in("rdi") _code as u64, options(noreturn))
    }
}
