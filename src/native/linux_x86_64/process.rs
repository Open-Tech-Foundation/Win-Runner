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
            std::thread::sleep(std::time::Duration::from_millis(20));
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
