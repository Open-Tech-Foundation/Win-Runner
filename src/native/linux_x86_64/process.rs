//! Windows process launch, command-line, and child-output support.

use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct NativeLaunchSpec {
    pub(super) application: String,
    pub(super) arguments: Vec<String>,
    pub(super) current_directory: String,
    /// The caller's command line exactly as passed to `CreateProcessW`; the
    /// child's `GetCommandLineW` returns it unchanged, since programs such
    /// as cmd.exe parse it themselves.
    pub(super) command_line: Option<String>,
}

/// Parse the subset of Windows command-line syntax needed to identify an
/// executable. Backslashes are literal except when immediately before a
/// quote, following the CommandLineToArgvW/MSVC escaping rules; like them,
/// an unterminated quote runs to the end of the line rather than failing.
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
    let verbatim = command_line.clone().filter(|line| !line.trim().is_empty());
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
        command_line: verbatim,
    })
}

pub(super) fn native_resolve_launch_application(
    launch: &mut NativeLaunchSpec,
    fs: &WinFs,
    environment: &[(String, String)],
) {
    let Some(name) = launch.arguments.first().cloned() else {
        return;
    };
    // Like CreateProcess, a file name without an extension means `.exe`.
    let has_extension = name
        .rsplit(['\\', '/'])
        .next()
        .is_some_and(|file| file.contains('.'));
    if name.contains(['\\', '/', ':']) {
        let with_exe = format!("{}.exe", launch.application);
        if !has_extension && !fs.is_file(&launch.application) && fs.is_file(&with_exe) {
            launch.application = with_exe;
        }
        return;
    }

    let no_current_directory = environment
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("NoDefaultCurrentDirectoryInExePath"));
    let mut directories = Vec::new();
    if !no_current_directory {
        directories.push(launch.current_directory.clone());
    }
    directories.push(crate::system_profile::SYSTEM32.to_string());
    directories.push(crate::system_profile::WINDOWS.to_string());
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

    let file = if has_extension {
        name
    } else {
        format!("{name}.exe")
    };
    for directory in directories {
        let candidate = format!("{}\\{}", directory.trim_end_matches(['\\', '/']), file);
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

/// CreateProcess runs a `.bat` or `.cmd` file as `cmd.exe /c "<command
/// line>"`.
pub(super) fn native_batch_launch_through_cmd(launch: &mut NativeLaunchSpec) {
    let lower = launch.application.to_ascii_lowercase();
    if !(lower.ends_with(".bat") || lower.ends_with(".cmd")) {
        return;
    }
    let original = launch
        .command_line
        .clone()
        .unwrap_or_else(|| format!("\"{}\"", launch.application));
    let cmd = format!(r"{}\cmd.exe", crate::system_profile::SYSTEM32);
    let command_line = format!("{cmd} /c \"{original}\"");
    launch.arguments = vec![cmd.clone(), "/c".to_string(), original];
    launch.application = cmd;
    launch.command_line = Some(command_line);
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
        Err(error) => (1, stdout, format!("winrun: {error}\n").into_bytes()),
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
    let child_process_id = child.process_id();
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
        .name("winrun-powershell-shell-link".to_string())
        .spawn(move || {
            let mut started_usage: libc::rusage = unsafe { std::mem::zeroed() };
            unsafe {
                libc::getrusage(libc::RUSAGE_THREAD, &mut started_usage);
            }
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
                worker_child.times.finish_thread_since(&started_usage);
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
    let handle = process.thread_next.fetch_add(1, Ordering::AcqRel);
    // Serialize thread creation with DLL TLS updates. The loader takes these
    // locks in the same order, so a new block is either cloned after a DLL's
    // template is published or registered before the loader fans it out.
    let tls_block = {
        let Ok(template) = process.tls_template.lock() else {
            native_set_last_error(6);
            return 0;
        };
        let tls = template
            .as_ref()
            .map(NativeTls::clone_for_thread)
            .unwrap_or_else(|| NativeTls::new(process.image_base));
        let tls = Arc::new(Mutex::new(tls));
        let Ok(mut blocks) = process.tls_blocks.lock() else {
            native_set_last_error(6);
            return 0;
        };
        blocks.retain(|_, block| block.strong_count() != 0);
        blocks.insert(handle, Arc::downgrade(&tls));
        tls
    };
    // Windows CreateThread uses the image's default stack when callers
    // pass zero. Node's libuv worker pool does this, and small host thread
    // defaults are too small for its nested module loading / async work.
    let builder = std::thread::Builder::new().stack_size(stack_size.max(4 * 1024 * 1024));
    let thread_process = Arc::clone(&process);
    let thread_tls = Arc::clone(&tls_block);
    let suspension = Arc::new((Mutex::new((flags & 4 != 0) as u32), Condvar::new()));
    let thread_suspension = Arc::clone(&suspension);
    let apc = Arc::new(NativeApcQueue::default());
    let thread_apc = apc.clone();
    let spawned = builder.spawn(move || {
        THREAD_NATIVE_HANDLE.set(handle);
        if let Ok(mut queues) = thread_process.apc_queues.lock() {
            queues.insert(std::thread::current().id(), thread_apc.clone());
        }
        THREAD_NATIVE_PROCESS.with(|active| {
            *active.borrow_mut() = Some(Arc::clone(&thread_process));
        });
        let _apc_lifetime = NativeThreadApcGuard {
            queue: thread_apc.clone(),
            process: thread_process.clone(),
        };
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
        let Ok(mut tls) = thread_tls.lock() else {
            return 1;
        };
        if !thread_runtime::initialize_module_static_tls(&thread_process, &mut tls)
            || !install_thread_teb(&mut tls.teb)
        {
            return 1;
        }
        THREAD_TEB_BASE.set(tls.teb.as_ptr() as u64);
        drop(tls);
        thread_runtime::notify_guest_thread_modules(&thread_process, true);
        dispatch_apcs();
        let exit_code = match unsafe {
            super::exceptions::invoke_guest_with_arguments(start, [parameter, 0, 0])
        } {
            Ok(code) => code,
            Err(code) => native_exit_process(code),
        };
        thread_runtime::notify_guest_thread_modules(&thread_process, false);
        thread_runtime::run_thread_fls_callbacks(&thread_process);
        exit_code
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
                    apc,
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
/// `QueueUserWorkItem(function, context, flags)`: run `function(context)`
/// on a worker guest thread. libuv queues its console line reader this way
/// (`WT_EXECUTELONGFUNCTION`), so every item gets its own guest thread with
/// TEB/TLS set up by `CreateThread`; the caller never sees a handle.
pub(super) extern "win64" fn native_queue_user_work_item(
    function: u64,
    context: u64,
    _flags: u32,
) -> i32 {
    if function == 0 {
        native_set_last_error(87);
        return 0;
    }
    let handle = native_create_thread(0, 0, function, context, 0, std::ptr::null_mut());
    if handle == 0 {
        return 0;
    }
    native_close_handle(handle);
    1
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
        .map(|process| process.process_id)
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
    native_fs: &NativeFs,
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
    if handle & 0xffff_ffff_0000_0000 == SOCKET_HANDLE_TAG {
        let fd = unsafe { dup(handle as i32) };
        if fd < 0 {
            return Err(6);
        }
        // SAFETY: dup returned a new descriptor whose ownership moves into Stdio.
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        return Ok(Stdio::from(owned));
    }
    if matches!(handle, 0..=2 | STD_HANDLE_BASE..=0x5000_0002) {
        return Ok(Stdio::inherit());
    }
    let Some(pipe) = pipes.handles.get(&handle) else {
        if native_fs.handles.contains_key(&handle) {
            return Ok(Stdio::null());
        }
        return Ok(Stdio::null());
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
    _child_fs: &NativeFs,
    parent: &NativeProcessContext,
    _std_handles: [u64; 3],
    _inherit_handles: bool,
) -> bool {
    // All supported handle state is serialized or transferred to workers.
    // A poisoned pipe table is the only state that prevents safe setup.
    parent.named_pipes.lock().is_ok()
}

fn encode_worker_native_fs(
    native_fs: &NativeFs,
    completion_port_ids: &HashMap<usize, u64>,
) -> Result<serde_json::Value, String> {
    let files = native_fs
        .handles
        .iter()
        .map(|(handle, file)| {
            let completion = file
                .completion
                .as_ref()
                .map(|(port, key)| {
                    let id = completion_port_ids
                        .get(&(Arc::as_ptr(port) as usize))
                        .ok_or_else(|| "file completion port is not transferable".to_string())?;
                    Ok::<serde_json::Value, String>(serde_json::json!({"port": id, "key": key}))
                })
                .transpose()?;
            Ok::<serde_json::Value, String>(serde_json::json!({
                "handle": handle,
                "path": file.path,
                "offset": file.offset,
                "overlapped": file.overlapped,
                "completion": completion,
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
    let completion_ports = restore_worker_completion_ports(process, &request)?;
    let mut fs = process
        .fs
        .lock()
        .map_err(|_| "worker filesystem lock is poisoned".to_string())?;
    apply_worker_native_fs(&mut fs, encoded, &completion_ports)?;
    drop(fs);
    restore_worker_pipe_handles(process, &request, &completion_ports)?;
    restore_worker_socket_handles(process, &request, &completion_ports)
}

fn restore_worker_socket_handles(
    process: &NativeProcessContext,
    request: &serde_json::Value,
    completion_ports: &HashMap<u64, Arc<NativeCompletionPort>>,
) -> Result<(), String> {
    let Some(items) = request
        .get("inherited_sockets")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(());
    };
    let mut sockets = process
        .socket_handles
        .lock()
        .map_err(|_| "worker socket table is poisoned".to_string())?;
    let mut associations = process
        .socket_completion_ports
        .lock()
        .map_err(|_| "worker socket completion table is poisoned".to_string())?;
    let mut modes = process
        .socket_completion_modes
        .lock()
        .map_err(|_| "worker socket completion modes are poisoned".to_string())?;
    for item in items {
        let handle = item
            .get("handle")
            .and_then(serde_json::Value::as_u64)
            .ok_or("worker socket has invalid handle")?;
        if handle & 0xffff_ffff_0000_0000 != SOCKET_HANDLE_TAG
            || unsafe { fcntl(handle as i32, 1) } < 0
        {
            return Err("worker socket descriptor was not inherited".to_string());
        }
        sockets.insert(handle);
        let completion = item
            .get("completion")
            .filter(|value| !value.is_null())
            .map(|value| {
                let port_id = value
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or("worker socket has invalid completion port")?;
                let key = value
                    .get("key")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or("worker socket has invalid completion key")?;
                let port = completion_ports
                    .get(&port_id)
                    .ok_or("worker socket completion port was not restored")?;
                Ok::<_, String>((Arc::clone(port), key))
            })
            .transpose()?;
        if let Some(completion) = completion {
            associations.insert(handle, completion);
        }
        let completion_modes =
            item.get("completion_modes")
                .and_then(serde_json::Value::as_u64)
                .ok_or("worker socket has invalid completion modes")? as u8;
        modes.insert(handle, completion_modes);
    }
    Ok(())
}

fn restore_worker_pipe_handles(
    process: &NativeProcessContext,
    request: &serde_json::Value,
    completion_ports: &HashMap<u64, Arc<NativeCompletionPort>>,
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
        completion_port: Option<u64>,
        completion_key: u64,
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
                completion_port: item
                    .get("completion")
                    .and_then(|completion| completion.get("port"))
                    .and_then(serde_json::Value::as_u64),
                completion_key: item
                    .get("completion")
                    .and_then(|completion| completion.get("key"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fds = std::env::var("WINRUN_NATIVE_PIPE_FDS")
        .map_err(|_| "worker did not receive inherited pipe descriptors".to_string())?
        .split(',')
        .map(|value| value.parse::<i32>().map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let expected_fds = request
        .get("pipe_endpoint_fd_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or("worker request has invalid pipe descriptor count")? as usize;
    if fds.len() < expected_fds {
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
                completion: info
                    .completion_port
                    .map(|port_id| {
                        completion_ports
                            .get(&port_id)
                            .cloned()
                            .map(|port| (port, info.completion_key))
                            .ok_or_else(|| {
                                format!("inherited pipe completion port {port_id} is missing")
                            })
                    })
                    .transpose()?,
                completion_modes: info.completion_modes,
            },
        );
        pipes.next = pipes.next.max(info.handle.saturating_add(1));
    }
    Ok(())
}

fn restore_worker_completion_ports(
    process: &NativeProcessContext,
    request: &serde_json::Value,
) -> Result<HashMap<u64, Arc<NativeCompletionPort>>, String> {
    let Some(items) = request
        .get("completion_ports")
        .and_then(serde_json::Value::as_array)
        .filter(|items| !items.is_empty())
    else {
        return Ok(HashMap::new());
    };
    let fds = std::env::var("WINRUN_NATIVE_PIPE_FDS")
        .map_err(|_| "worker did not receive completion-port descriptors".to_string())?
        .split(',')
        .map(|value| value.parse::<i32>().map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut restored = HashMap::new();
    let mut process_ports = process
        .completion_ports
        .lock()
        .map_err(|_| "worker completion-port table is poisoned".to_string())?;
    for item in items {
        let port_id = item
            .get("handle")
            .and_then(serde_json::Value::as_u64)
            .ok_or("worker completion port has invalid handle")?;
        let fd_index =
            item.get("fd_index")
                .and_then(serde_json::Value::as_u64)
                .ok_or("worker completion port has invalid descriptor index")? as usize;
        let fd = *fds
            .get(fd_index)
            .ok_or("worker completion port descriptor is missing")?;
        let port = Arc::new(NativeCompletionPort::new());
        port.attach_worker_sender(fd)?;
        process_ports.insert(port_id, Arc::clone(&port));
        process
            .completion_next
            .fetch_max(port_id.saturating_add(1), Ordering::AcqRel);
        restored.insert(port_id, port);
    }
    Ok(restored)
}

fn apply_worker_native_fs(
    fs: &mut NativeFs,
    encoded: &serde_json::Value,
    completion_ports: &HashMap<u64, Arc<NativeCompletionPort>>,
) -> Result<(), String> {
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
        let completion = item
            .get("completion")
            .filter(|value| !value.is_null())
            .map(|value| {
                let port_id = number(value, "port")?;
                let key = number(value, "key")?;
                let port = completion_ports
                    .get(&port_id)
                    .ok_or("worker file completion port was not restored")?;
                Ok::<_, String>((Arc::clone(port), key))
            })
            .transpose()?;
        fs.handles.insert(
            handle,
            NativeFile {
                path,
                offset,
                overlapped,
                completion,
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
            .push((r"C:\data.txt".to_string(), 4, 8, 0x123, true));
        original.next = 0x125;

        let encoded = encode_worker_native_fs(&original, &HashMap::new()).unwrap();
        let mut restored = empty_fs();
        apply_worker_native_fs(&mut restored, &encoded, &HashMap::new()).unwrap();

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
    fn worker_native_fs_preserves_completion_port_associations() {
        let mut original = empty_fs();
        let port = Arc::new(NativeCompletionPort::new());
        original.handles.insert(
            0x123,
            NativeFile {
                path: r"C:\data.txt".to_string(),
                offset: 0,
                overlapped: true,
                completion: Some((Arc::clone(&port), 0x456)),
            },
        );
        let ids = HashMap::from([(Arc::as_ptr(&port) as usize, 0x789)]);
        let ports = HashMap::from([(0x789, port)]);
        let encoded = encode_worker_native_fs(&original, &ids).unwrap();
        let mut restored = empty_fs();
        apply_worker_native_fs(&mut restored, &encoded, &ports).unwrap();
        let (restored_port, key) = restored.handles[&0x123].completion.as_ref().unwrap();
        assert!(Arc::ptr_eq(restored_port, &ports[&0x789]));
        assert_eq!(*key, 0x456);
    }

    #[test]
    fn completion_port_worker_channel_forwards_packets() {
        use std::os::fd::IntoRawFd;

        let parent = Arc::new(NativeCompletionPort::new());
        let child_fd = parent.create_worker_sender().unwrap();
        let child = NativeCompletionPort::new();
        child.attach_worker_sender(child_fd.into_raw_fd()).unwrap();
        assert!(child.post(NativeCompletion {
            key: 0x1234,
            overlapped: 0x5678,
            bytes: 9,
            status: 0xc000_0001,
        }));
        let mut queue = parent.queue.lock().unwrap();
        if queue.is_empty() {
            let (ready, timeout) = parent
                .ready
                .wait_timeout(queue, std::time::Duration::from_secs(1))
                .unwrap();
            queue = ready;
            assert!(!timeout.timed_out(), "completion channel did not forward");
        }
        let completion = queue.pop_front().unwrap();
        assert_eq!(completion.key, 0x1234);
        assert_eq!(completion.overlapped, 0x5678);
        assert_eq!(completion.bytes, 9);
        assert_eq!(completion.status, 0xc000_0001);
    }

    #[test]
    fn active_overlapped_io_does_not_block_inheritable_pipe_worker_transfer() {
        use std::os::fd::IntoRawFd;

        let (endpoint, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let handle = 0xbad;
        let parent = Arc::clone(&super::TEST_PROCESS);
        {
            let mut pipes = parent.named_pipes.lock().unwrap();
            pipes.handles.insert(
                handle,
                NativePipeHandle {
                    endpoint: Arc::new(NativePipeEndpoint {
                        fd: endpoint.into_raw_fd(),
                        name: r"\\.\pipe\worker-active-io".to_string(),
                        server: false,
                        access: 3,
                    }),
                    pending_client: None,
                    overlapped: true,
                    inheritable: true,
                    access: 3,
                    mode: 0,
                    completion: None,
                    completion_modes: 0,
                },
            );
            pipes.pending_io.insert(
                (handle, 0x1234),
                NativePendingPipeIo {
                    cancelled: Arc::new(AtomicBool::new(false)),
                    issuer: std::thread::current().id(),
                },
            );
        }
        let child_fs = empty_fs();
        assert!(can_exec_worker_child(
            &child_fs,
            &parent,
            [STD_HANDLE_BASE, STD_HANDLE_BASE + 1, STD_HANDLE_BASE + 2],
            true,
        ));
        {
            let mut pipes = parent.named_pipes.lock().unwrap();
            pipes.pending_io.remove(&(handle, 0x1234));
            pipes.handles.remove(&handle);
        }
        drop(peer);
    }

    #[test]
    fn standard_pipe_with_pending_io_and_iocp_can_use_exec_worker() {
        use std::os::fd::{AsRawFd, IntoRawFd};

        let (endpoint, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let handle = STD_HANDLE_BASE + 1;
        let parent = Arc::clone(&super::TEST_PROCESS);
        let port = Arc::new(NativeCompletionPort::new());
        let pending_client_fd = unsafe { dup(peer.as_raw_fd()) };
        assert!(pending_client_fd >= 0);
        {
            let mut pipes = parent.named_pipes.lock().unwrap();
            pipes.handles.insert(
                handle,
                NativePipeHandle {
                    endpoint: Arc::new(NativePipeEndpoint {
                        fd: endpoint.into_raw_fd(),
                        name: r"\\.\pipe\worker-stdio-iocp".to_string(),
                        server: false,
                        access: 3,
                    }),
                    pending_client: Some(Arc::new(NativePipeEndpoint {
                        fd: pending_client_fd,
                        name: r"\\.\pipe\worker-stdio-iocp".to_string(),
                        server: true,
                        access: 3,
                    })),
                    overlapped: true,
                    inheritable: true,
                    access: 3,
                    mode: 0,
                    completion: Some((port, 0x5678)),
                    completion_modes: 0,
                },
            );
        }
        assert!(can_exec_worker_child(
            &empty_fs(),
            &parent,
            [STD_HANDLE_BASE, handle, STD_HANDLE_BASE + 2],
            true,
        ));
        parent.named_pipes.lock().unwrap().handles.remove(&handle);
        drop(peer);
    }

    #[test]
    fn worker_restores_inherited_socket_completion_association() {
        use std::os::fd::IntoRawFd;

        let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let handle = SOCKET_HANDLE_TAG | socket.into_raw_fd() as u64;
        let process = Arc::clone(&super::TEST_PROCESS);
        let port_id = 0x9876;
        let port = Arc::new(NativeCompletionPort::new());
        let request = serde_json::json!({
            "inherited_sockets": [{
                "handle": handle,
                "completion": {"port": port_id, "key": 0x1234},
                "completion_modes": 2,
            }],
        });
        let ports = HashMap::from([(port_id, Arc::clone(&port))]);

        restore_worker_socket_handles(&process, &request, &ports).unwrap();

        assert!(process.socket_handles.lock().unwrap().contains(&handle));
        let (associated_port, key) =
            process.socket_completion_ports.lock().unwrap()[&handle].clone();
        assert!(Arc::ptr_eq(&associated_port, &port));
        assert_eq!(key, 0x1234);
        assert_eq!(process.socket_completion_modes.lock().unwrap()[&handle], 2);

        process.socket_handles.lock().unwrap().remove(&handle);
        process
            .socket_completion_ports
            .lock()
            .unwrap()
            .remove(&handle);
        process
            .socket_completion_modes
            .lock()
            .unwrap()
            .remove(&handle);
        unsafe { close(handle as i32) };
        drop(peer);
    }

    #[test]
    fn winsock_handles_are_noninheritable_until_requested() {
        let parent = Arc::clone(&super::TEST_PROCESS);
        let handle = native_socket(2, 1, 0);
        assert_ne!(handle, u64::MAX);
        let flags = unsafe { fcntl(handle as i32, 1) };
        assert!(flags >= 0 && flags & 1 != 0, "SOCK_CLOEXEC should be set");
        assert!(parent.socket_handles.lock().unwrap().contains(&handle));
        assert_eq!(native_set_handle_information(handle, 1, 1), 1);
        assert_eq!(unsafe { fcntl(handle as i32, 1) } & 1, 0);
        assert_eq!(native_set_handle_information(handle, 1, 0), 1);
        assert_eq!(unsafe { fcntl(handle as i32, 1) } & 1, 1);
        assert_eq!(native_close_socket(handle), 0);
        assert!(!parent.socket_handles.lock().unwrap().contains(&handle));
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
    handle_list: Option<&[u64]>,
    environment: &[(String, String)],
    process_information: u64,
) -> Result<(), u32> {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    if let Some(handles) = handle_list {
        let allowed = |handle: &u64| handles.contains(handle);
        child_fs.handles.retain(|handle, _| allowed(handle));
        child_fs.devices.retain(|handle, _| allowed(handle));
        child_fs.file_access.retain(|handle, _| allowed(handle));
        child_fs.file_shares.retain(|handle, _| allowed(handle));
    }

    let executable = std::env::var_os("WINRUN_NATIVE_WORKER_EXE").ok_or(120u32)?;
    let pipes = parent.named_pipes.lock().map_err(|_| 6u32)?;
    let stdio = child_std_handles
        .map(|handle| worker_stdio_for_handle(handle, &pipes, &child_fs))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let std_set = child_std_handles
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let transferable_pipes = pipes
        .handles
        .iter()
        .filter(|(handle, pipe)| {
            (std_set.contains(handle) || (inherit_handles && pipe.inheritable))
                && handle_list.is_none_or(|handles| handles.contains(handle))
        })
        .map(|(handle, pipe)| (*handle, pipe.clone()))
        .collect::<Vec<_>>();
    drop(pipes);

    let registered_ports = parent.completion_ports.lock().map_err(|_| 6u32)?.clone();
    let all_socket_handles = parent
        .socket_handles
        .lock()
        .map_err(|_| 6u32)?
        .iter()
        .copied()
        .collect::<Vec<_>>();
    let inherited_socket_handles = all_socket_handles
        .iter()
        .copied()
        .filter(|handle| {
            let flags = unsafe { fcntl(*handle as i32, 1) };
            inherit_handles
                && flags >= 0
                && flags & 1 == 0
                && handle_list.is_none_or(|handles| handles.contains(handle))
        })
        .collect::<Vec<_>>();
    let socket_handles_to_close = all_socket_handles
        .iter()
        .copied()
        .filter(|handle| {
            let flags = unsafe { fcntl(*handle as i32, 1) };
            !inherited_socket_handles.contains(handle) && flags >= 0 && flags & 1 == 0
        })
        .map(|handle| handle as i32)
        .collect::<Vec<_>>();
    let mut completion_port_ids = HashMap::<usize, u64>::new();
    let mut completion_port_objects = HashMap::<u64, Arc<NativeCompletionPort>>::new();
    let mut register_port = |port: &Arc<NativeCompletionPort>| -> Result<(), u32> {
        let Some((handle, _)) = registered_ports
            .iter()
            .find(|(_, registered)| Arc::ptr_eq(registered, port))
        else {
            return Err(120);
        };
        completion_port_ids.insert(Arc::as_ptr(port) as usize, *handle);
        completion_port_objects.insert(*handle, Arc::clone(port));
        Ok(())
    };
    for file in child_fs.handles.values() {
        if let Some((port, _)) = &file.completion {
            register_port(port)?;
        }
    }
    for (_, pipe) in &transferable_pipes {
        if let Some((port, _)) = &pipe.completion {
            register_port(port)?;
        }
    }
    let socket_associations = parent
        .socket_completion_ports
        .lock()
        .map_err(|_| 6u32)?
        .clone();
    for handle in &inherited_socket_handles {
        if let Some((port, _)) = socket_associations.get(handle) {
            register_port(port)?;
        }
    }
    let socket_modes = parent
        .socket_completion_modes
        .lock()
        .map_err(|_| 6u32)?
        .clone();
    let inherited_socket_metadata = inherited_socket_handles
        .iter()
        .map(|handle| {
            let completion = socket_associations.get(handle).map(|(port, key)| {
                serde_json::json!({
                    "port": completion_port_ids[&(Arc::as_ptr(port) as usize)],
                    "key": key,
                })
            });
            serde_json::json!({
                "handle": handle,
                "completion": completion,
                "completion_modes": socket_modes.get(handle).copied().unwrap_or(0),
            })
        })
        .collect::<Vec<_>>();
    let worker_std_handles: [u64; 3] = std::array::from_fn(|index| {
        let handle = child_std_handles[index];
        if handle & 0xffff_ffff_0000_0000 == SOCKET_HANDLE_TAG {
            STD_HANDLE_BASE + index as u64
        } else {
            handle
        }
    });

    let id = NEXT_EXEC_CHILD_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory =
        std::env::temp_dir().join(format!("winrun-child-worker-{}-{id}", std::process::id()));
    std::fs::create_dir(&directory).map_err(|_| 8u32)?;
    let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
    let directory_guard = ChildWorkerDirectory(directory.clone());
    let pipe_transfer_path = directory.join("inherited-pipes.sock");
    let mut inherited_pipe_metadata = Vec::new();
    let mut inherited_pipe_fds = Vec::new();
    for (handle, pipe) in &transferable_pipes {
        let completion = pipe.completion.as_ref().map(|(port, key)| {
            serde_json::json!({
                "port": completion_port_ids[&(Arc::as_ptr(port) as usize)],
                "key": key,
            })
        });
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
                "completion": completion,
            }));
        inherited_pipe_fds.push(pipe.endpoint.fd);
        if let Some(pending_client) = &pipe.pending_client {
            inherited_pipe_fds.push(pending_client.fd);
        }
    }
    use std::os::fd::AsRawFd;
    let mut completion_port_fds = Vec::new();
    let mut completion_port_metadata = Vec::new();
    for (port_id, port) in &completion_port_objects {
        let fd = port.create_worker_sender().map_err(|_| 8u32)?;
        let fd_index = inherited_pipe_fds.len() + completion_port_fds.len();
        completion_port_metadata.push(serde_json::json!({
            "handle": port_id,
            "fd_index": fd_index,
        }));
        inherited_pipe_fds.push(fd.as_raw_fd());
        completion_port_fds.push(fd);
    }
    let pipe_listener = if inherited_pipe_fds.is_empty() {
        None
    } else {
        Some(std::os::unix::net::UnixListener::bind(&pipe_transfer_path).map_err(|_| 8u32)?)
    };
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
        "command_line": launch.command_line,
        "environment": environment,
        // The worker's guest process id is its own host pid.
        "parent_process_id": parent.process_id,
        "std_handles": worker_std_handles,
        "native_fs": encode_worker_native_fs(&child_fs, &completion_port_ids).map_err(|_| 8u32)?,
        "inherited_pipes": inherited_pipe_metadata,
        "inherited_sockets": inherited_socket_metadata,
        "socket_handles_to_close": socket_handles_to_close,
        "completion_ports": completion_port_metadata,
        "pipe_endpoint_fd_count": inherited_pipe_fds.len() - completion_port_fds.len(),
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
        .env_remove("WINRUN_NATIVE_WORKER")
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
    child.process_id.store(worker.id(), Ordering::Release);
    if !write_process_information(
        process_information,
        process_handle,
        thread_handle,
        child.process_id(),
    ) {
        let _ = worker.kill();
        let _ = worker.wait();
        return Err(87);
    }
    let monitor_child = Arc::clone(&child);
    let monitor_program = launch.application.clone();
    let monitor_fs = Arc::clone(&parent.fs);
    let state_path_for_monitor = state_path.clone();
    std::thread::Builder::new()
        .name("winrun-native-worker-child".to_string())
        .spawn(move || {
            let status = wait_worker_with_times(&mut worker, &monitor_child.times);
            if let Ok(encoded) = std::fs::read(&state_path_for_monitor) {
                if !encoded.is_empty() {
                    if let Ok(mut native_fs) = monitor_fs.lock() {
                        let cwd = native_fs.fs.cwd();
                        if let Err(error) =
                            crate::snapshot::apply_changes(&encoded, &mut native_fs.fs)
                        {
                            eprintln!("winrun: cannot apply child filesystem changes: {error}");
                        }
                        let _ = native_fs.fs.set_cwd(&cwd);
                    }
                }
            }
            if let Ok(native_fs) = monitor_fs.lock() {
                native_fs.fs.collect_garbage();
            }
            // Remove the request directory before publishing the exit: a
            // waiting worker may `_exit` as soon as it sees it.
            drop(directory_guard);
            if let Ok(mut state) = monitor_child.state.lock() {
                if state.is_none() {
                    *state = Some(match status {
                        Ok(status) => worker_exit_code(status, &monitor_program),
                        Err(_) => 1,
                    });
                }
                monitor_child.exited.notify_all();
            }
        })
        .map_err(|_| 8u32)?;
    Ok(())
}

/// The Windows exit code of a guest process whose worker ended with
/// `status`. A worker killed by a fault signal exits with the exception
/// code Windows reports for a crashed process (an access violation is
/// 0xC0000005), and the crash is noted on stderr, where Windows would show
/// its error report.
fn worker_exit_code(status: std::process::ExitStatus, program: &str) -> u32 {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        return code as u32;
    }
    let Some(signal) = status.signal() else {
        return 1;
    };
    let code = crash_exit_code(signal);
    if code != 1 {
        eprintln!(
            "winrun: {program} crashed ({}); exit code {code:#010X}",
            signal_name(signal)
        );
    }
    code
}

/// The exception code of a crash by host `signal`; 1 for a process that
/// was stopped (killed, terminated) rather than crashed.
fn crash_exit_code(signal: i32) -> u32 {
    match signal {
        libc::SIGSEGV | libc::SIGBUS => 0xC000_0005, // STATUS_ACCESS_VIOLATION
        libc::SIGILL => 0xC000_001D,                 // STATUS_ILLEGAL_INSTRUCTION
        libc::SIGFPE => 0xC000_0094,                 // STATUS_INTEGER_DIVIDE_BY_ZERO
        libc::SIGABRT => 3,                          // abort()
        _ => 1,
    }
}

fn signal_name(signal: i32) -> &'static str {
    match signal {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGILL => "SIGILL",
        libc::SIGFPE => "SIGFPE",
        libc::SIGABRT => "SIGABRT",
        _ => "signal",
    }
}

pub(super) extern "win64" fn native_exit_process(code: u32) -> ! {
    if std::env::var_os("WINRUN_NATIVE_WORKER").as_deref() == Some(std::ffi::OsStr::new("1")) {
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
    restore_console_input_mode();
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
    creation_flags: u32,
    environment: u64,
    current_directory: *const u16,
    startup_info: u64,
    process_information: u64,
) -> i32 {
    if process_information == 0 {
        native_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let handle_list = match startup_handle_list(startup_info, creation_flags, inherit_handles != 0) {
        Ok(handles) => handles,
        Err(error) => {
            native_set_last_error(error);
            return 0;
        }
    };
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
    native_batch_launch_through_cmd(&mut launch);
    let parent_std_handles =
        std::array::from_fn(|index| parent.std_handles[index].load(Ordering::Acquire));
    let child_std_handles = native_startup_std_handles(startup_info, parent_std_handles);
    // Callers such as libuv pass DuplicateHandle aliases of their standard
    // handles; the child inherits what the aliases refer to.
    let child_std_handles = child_std_handles.map(|handle| {
        parent
            .duplicate_handles
            .lock()
            .ok()
            .and_then(|aliases| aliases.get(&handle).copied())
            .unwrap_or(handle)
    });
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
    if !can_exec_worker_child(&child_fs, &parent, child_std_handles, inherit_handles != 0) {
        native_set_last_error(6);
        return 0;
    }
    match create_exec_worker_child(
        &parent,
        &launch,
        &image,
        child_fs,
        child_std_handles,
        inherit_handles != 0,
        handle_list.as_deref(),
        &environment,
        process_information,
    ) {
        Ok(()) => {
            native_set_last_error(0);
            1
        }
        Err(error) => {
            native_set_last_error(error);
            0
        }
    }
}

pub(super) fn native_flush_instance_state() {
    let Some(process) = process_ctx() else {
        return;
    };
    native_shutdown_file_io(&process);
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
    let encoded = crate::snapshot::encode_changes(&ctx.fs);
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

pub(super) extern "win64" fn native_get_module_file_name_a(
    module: u64,
    output: *mut u8,
    output_len: u32,
) -> u32 {
    if output.is_null() || output_len == 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let path = if module == 0 || module == process.image_base {
        process.module_path.clone()
    } else {
        match process
            .loaded_modules
            .lock()
            .ok()
            .and_then(|modules| modules.get(&module).map(|module| module.path.clone()))
        {
            Some(path) => path,
            None => {
                native_set_last_error(6);
                return 0;
            }
        }
    };
    let wide: Vec<u16> = path.encode_utf16().collect();
    let length = native_wide_char_to_multi_byte(
        0,
        0,
        wide.as_ptr(),
        wide.len() as i32,
        ptr::null_mut(),
        0,
        ptr::null(),
        ptr::null_mut(),
    );
    if length <= 0 {
        return 0;
    }
    let mut encoded = vec![0; length as usize];
    native_wide_char_to_multi_byte(
        0,
        0,
        wide.as_ptr(),
        wide.len() as i32,
        encoded.as_mut_ptr(),
        length,
        ptr::null(),
        ptr::null_mut(),
    );
    let capacity = output_len as usize;
    let copied = encoded.len().min(capacity - 1);
    unsafe {
        output.copy_from_nonoverlapping(encoded.as_ptr(), copied);
        output.add(copied).write(0);
    }
    if encoded.len() >= capacity {
        native_set_last_error(122);
        output_len
    } else {
        copied as u32
    }
}

pub(super) extern "win64" fn native_get_module_file_name_w(
    module: u64,
    output: *mut u16,
    output_len: u32,
) -> u32 {
    if output_len == 0 {
        native_set_last_error(122);
        return 0;
    }
    if output.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let path = if module == 0 || module == process.image_base {
        process.module_path.clone()
    } else {
        let path = process
            .loaded_modules
            .lock()
            .ok()
            .and_then(|modules| modules.get(&module).map(|module| module.path.clone()));
        let Some(path) = path else {
            native_set_last_error(126);
            return 0;
        };
        path
    };
    let encoded: Vec<u16> = path.encode_utf16().collect();
    let capacity = output_len as usize;
    let copied = encoded.len().min(capacity - 1);
    unsafe {
        output.copy_from_nonoverlapping(encoded.as_ptr(), copied);
        output.add(copied).write(0);
    }
    if encoded.len() >= capacity {
        native_set_last_error(122);
        output_len
    } else {
        native_set_last_error(0);
        copied as u32
    }
}

#[cfg(test)]
mod module_filename_tests {
    use super::*;
    #[test]
    fn wide_module_filename_preserves_unicode_and_terminates_small_buffers() {
        let _guard = TestProcessGuard::new();
        let mut process = new_test_process();
        Arc::get_mut(&mut process).unwrap().module_path = r"C:\café\𝄞.exe".into();
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(process.clone())));
        let expected: Vec<u16> = process.module_path.encode_utf16().chain([0]).collect();
        let mut output = vec![0xffff; expected.len() + 1];
        assert_eq!(
            native_get_module_file_name_w(0, output.as_mut_ptr(), output.len() as u32),
            expected.len() as u32 - 1
        );
        assert_eq!(&output[..expected.len()], &expected);
        assert_eq!(native_get_module_file_name_w(0, output.as_mut_ptr(), 1), 1);
        assert_eq!(output[0], 0);
        assert_eq!(native_get_last_error(), 122);
        assert_eq!(native_get_module_file_name_w(0, output.as_mut_ptr(), 3), 3);
        assert_eq!(&output[..2], &expected[..2]);
        assert_eq!(output[2], 0);
        assert_eq!(
            native_get_module_file_name_w(0xdead, output.as_mut_ptr(), 64),
            0
        );
        assert_eq!(native_get_last_error(), 126);
        assert_eq!(native_get_module_file_name_w(0, ptr::null_mut(), 0), 0);
    }
    #[test]
    fn narrow_module_filename_uses_acp_terminates_and_rejects_unknown_modules() {
        let mut process = new_test_process();
        Arc::get_mut(&mut process).unwrap().module_path = "C:\\café.exe".into();
        let previous = THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(process)));
        let mut output = [0; 64];
        assert_eq!(
            native_get_module_file_name_a(0, output.as_mut_ptr(), 64),
            11
        );
        assert_eq!(&output[..12], b"C:\\caf\xe9.exe\0");
        assert_eq!(native_get_module_file_name_a(0, output.as_mut_ptr(), 3), 3);
        assert_eq!(&output[..3], b"C:\0");
        assert_eq!(native_get_last_error(), 122);
        assert_eq!(
            native_get_module_file_name_a(0xdead, output.as_mut_ptr(), 64),
            0
        );
        assert_eq!(native_get_last_error(), 6);
        assert_eq!(native_get_module_file_name_a(0, ptr::null_mut(), 0), 0);
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(previous));
    }
}

pub(super) extern "win64" fn native_get_error_mode() -> u32 {
    process_ctx()
        .map(|process| process.error_mode.load(Ordering::Acquire))
        .unwrap_or(0)
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
    if let Some(queue) = current_apc_queue() {
        queue.close();
    }
    let handle = THREAD_NATIVE_HANDLE.get();
    if let Some(process) = process_ctx() {
        if let Ok(mut queues) = process.apc_queues.lock() {
            queues.remove(&std::thread::current().id());
        }
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

#[cfg(test)]
mod exit_code_tests {
    use super::{crash_exit_code, worker_exit_code};
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn a_crashed_worker_exits_with_the_windows_exception_code() {
        // Raw wait statuses: an exit code is in bits 8-15, a signal in 0-6.
        assert_eq!(worker_exit_code(ExitStatus::from_raw(7 << 8), "C:\\a.exe"), 7);
        assert_eq!(
            worker_exit_code(ExitStatus::from_raw(libc::SIGSEGV), "C:\\a.exe"),
            0xC000_0005
        );
        assert_eq!(crash_exit_code(libc::SIGILL), 0xC000_001D);
        assert_eq!(crash_exit_code(libc::SIGFPE), 0xC000_0094);
        assert_eq!(crash_exit_code(libc::SIGABRT), 3);
        // Killed or terminated, not crashed.
        assert_eq!(worker_exit_code(ExitStatus::from_raw(libc::SIGKILL), "C:\\a.exe"), 1);
    }
}

/// WER UI is absent on the Linux backend; retain the process reporting flags.
pub(super) extern "win64" fn native_wer_get_flags(handle: u64, flags: *mut u32) -> u32 {
    if flags.is_null() {
        return 0x8007_0057;
    }
    let Some(process) = process_ctx() else {
        return 0x8007_0006;
    };
    if handle != u64::MAX && handle != process.process_handle {
        return 0x8007_0006;
    }
    unsafe { flags.write(process.wer_flags.load(Ordering::Acquire)) };
    0
}
pub(super) extern "win64" fn native_wer_set_flags(flags: u32) -> u32 {
    let Some(process) = process_ctx() else {
        return 0x8007_0006;
    };
    process.wer_flags.store(flags, Ordering::Release);
    0
}
pub(super) extern "win64" fn native_set_process_priority_boost(handle: u64, disabled: i32) -> i32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    if handle != u64::MAX && handle != process.process_handle {
        native_set_last_error(6);
        return 0;
    }
    // Linux does not apply Windows' dynamic IO/GUI priority boosts.
    process
        .priority_boost_disabled
        .store(disabled != 0, Ordering::Release);
    1
}

/// Running host threads cannot yet be safely suspended for context injection.
/// Report the unsupported operation so Go can use cooperative preemption.
pub(super) extern "win64" fn native_suspend_thread(_handle: u64) -> u32 {
    native_set_last_error(50); // ERROR_NOT_SUPPORTED
    u32::MAX
}
