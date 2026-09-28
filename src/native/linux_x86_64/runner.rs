//! Top-level Linux native guest launch and output collection.

use super::*;

pub fn run_import_free(img: &PeImage) -> Result<u32, String> {
    let _run = NATIVE_RUN_LOCK
        .lock()
        .map_err(|_| "native backend execution lock is poisoned".to_string())?;
    if !img.imports.is_empty() || !img.unsupported.is_empty() {
        return Err("import-free native entry point cannot bind PE imports".to_string());
    }
    if img.tls.is_some() {
        return Err("import-free native entry point cannot initialize TLS".to_string());
    }
    let entry = img
        .image_base
        .checked_add(img.entry_rva as u64)
        .ok_or_else(|| "native entry address overflows".to_string())?;
    let image_end = img.image_base + img.image.len() as u64;
    if entry < img.image_base || entry >= image_end {
        return Err("native entry point lies outside the loaded image".to_string());
    }
    let mapping = map(img)?;
    protect_exec(&mapping)?;
    // SAFETY: `entry` lies in the RX mapping just created. The caller is
    // limited to bring-up PE fixtures that implement this ABI and return;
    // arbitrary Windows entry points require the planned process sandbox.
    let entry_fn: unsafe extern "win64" fn() -> u32 = unsafe { std::mem::transmute(entry) };
    Ok(unsafe { entry_fn() })
}

pub(super) fn entry(img: &PeImage) -> Result<u64, String> {
    let entry = img
        .image_base
        .checked_add(img.entry_rva as u64)
        .ok_or_else(|| "native entry address overflows".to_string())?;
    if entry < img.image_base || entry >= img.image_base + img.image.len() as u64 {
        return Err("native entry point lies outside the loaded image".to_string());
    }
    Ok(entry)
}

pub(super) fn command_line_w(prog: &str, args: &[String]) -> Result<Vec<u16>, String> {
    let mut line = quote_arg(prog);
    for arg in args {
        line.push(' ');
        line.push_str(&quote_arg(arg));
    }
    let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
    if wide.len() * 2 > COMMAND_LINE_BYTES {
        return Err("command line too long (64K guest block)".to_string());
    }
    Ok(wide)
}

pub(super) fn command_line_a(command_line: &[u16]) -> Vec<u8> {
    let end = command_line
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(command_line.len());
    let text = String::from_utf16_lossy(&command_line[..end]);
    let mut bytes = text
        .chars()
        .map(|ch| if ch.is_ascii() { ch as u8 } else { b'?' })
        .collect::<Vec<_>>();
    bytes.push(0);
    bytes
}

pub fn run_rust_baseline_argv(
    img: &PeImage,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>), String> {
    run_rust_baseline_argv_with_fs(img, WinFs::ephemeral_runner(), prog, args)
        .map(|(code, out, _)| (code, out))
}

pub fn run_rust_baseline_argv_with_fs(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>, WinFs), String> {
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, &[], None)
        .map_err(|failure| failure.message)
}

static NEXT_WORKER_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct WorkerDirectory(std::path::PathBuf);

impl Drop for WorkerDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_exec_worker(
    executable: std::path::PathBuf,
    image: &PeImage,
    mut fs: WinFs,
    program: &str,
    args: &[String],
    environment: &[(String, String)],
    output: Option<&dyn Fn(bool, &[u8])>,
) -> Result<(u32, Vec<u8>, WinFs), super::super::NativeExecutionFailure> {
    use std::process::{Command, Stdio};
    let total_started = std::time::Instant::now();
    let failed = |message: String, fs: WinFs| super::super::NativeExecutionFailure { message, fs };
    let id = NEXT_WORKER_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!("winrun-worker-{}-{id}", std::process::id()));
    if let Err(error) = std::fs::create_dir(&directory) {
        return Err(failed(
            format!("cannot create native worker directory: {error}"),
            fs,
        ));
    }
    let _directory = WorkerDirectory(directory.clone());
    let image_path = match super::super::worker::write_image(image, &directory) {
        Ok(path) => path,
        Err(error) => return Err(failed(error, fs)),
    };
    let snapshot_path = match crate::snapshot::save_worker_manifest(&fs, &directory) {
        Ok(path) => path,
        Err(error) => {
            return Err(failed(
                format!("cannot prepare native worker filesystem: {error}"),
                fs,
            ));
        }
    };
    let state_path = directory.join("state.bin");
    let result_path = directory.join("result.bin");
    let request_path = directory.join("request.json");
    let request = serde_json::json!({
        "image_path": image_path,
        "snapshot_path": snapshot_path,
        "state_path": state_path,
        "result_path": result_path,
        "program": program,
        "args": args,
        "environment": environment,
        "mounts": fs.host_mounts(),
        "drive_cwds": fs.drive_current_directories(),
        "cwd": fs.cwd(),
    });
    let request_bytes = match serde_json::to_vec(&request) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(failed(
                format!("cannot encode native worker request: {error}"),
                fs,
            ))
        }
    };
    if let Err(error) = std::fs::write(&request_path, request_bytes) {
        return Err(failed(
            format!("cannot write native worker request: {error}"),
            fs,
        ));
    }
    let worker_start = std::time::Instant::now();
    let mut child = match Command::new(executable)
        .arg("__native-worker")
        .arg(&request_path)
        .env_remove("WINRUN_NATIVE_WORKER")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return Err(failed(format!("cannot start native worker: {error}"), fs)),
    };
    let worker_start_ms = worker_start.elapsed().as_secs_f64() * 1000.0;
    let guest_started = std::time::Instant::now();
    let stdout = child.stdout.take().expect("piped worker stdout");
    let stderr = child.stderr.take().expect("piped worker stderr");
    fn forward_output<R: std::io::Read + Send + 'static>(
        is_stderr: bool,
        mut stream: R,
        sender: std::sync::mpsc::Sender<(bool, Vec<u8>)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if sender.send((is_stderr, buffer[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        })
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let readers = vec![
        forward_output(false, stdout, sender.clone()),
        forward_output(true, stderr, sender.clone()),
    ];
    drop(sender);
    let mut stdout_bytes = Vec::new();
    for (is_stderr, bytes) in receiver {
        if !is_stderr {
            stdout_bytes.extend_from_slice(&bytes);
        }
        if let Some(output) = output {
            output(is_stderr, &bytes);
        } else if is_stderr {
            write_host_stderr(&bytes);
        }
    }
    for reader in readers {
        let _ = reader.join();
    }
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            return Err(failed(
                format!("cannot wait for native worker: {error}"),
                fs,
            ))
        }
    };
    let guest_ms = guest_started.elapsed().as_secs_f64() * 1000.0;
    let guest_code = match std::fs::read(&result_path) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes(bytes.try_into().unwrap()),
        _ if !status.success() => {
            return Err(failed(
                format!(
                    "native worker exited with status {status} before reporting a guest exit code"
                ),
                fs,
            ));
        }
        _ => {
            return Err(failed(
                "native worker did not report a guest exit code".to_string(),
                fs,
            ))
        }
    };
    let state_started = std::time::Instant::now();
    match std::fs::read(&state_path) {
        Ok(state) if !state.is_empty() => {
            if let Err(error) = crate::snapshot::apply_changes(&state, &mut fs) {
                return Err(failed(
                    format!("native worker returned invalid filesystem changes: {error}"),
                    fs,
                ));
            }
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(failed(
                format!("cannot read native worker state: {error}"),
                fs,
            ))
        }
    }
    if std::env::var_os("WINRUN_TIMINGS").is_some() {
        let state_bytes = std::fs::metadata(&state_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        eprintln!(
            "winrun timing: {program}: worker_start={worker_start_ms:.3}ms guest_until_output_eof={guest_ms:.3}ms state_apply={:.3}ms state_bytes={state_bytes} total={:.3}ms",
            state_started.elapsed().as_secs_f64() * 1000.0,
            total_started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok((guest_code, stdout_bytes, fs))
}

fn write_host_stderr(bytes: &[u8]) {
    use std::io::Write;
    let _ = std::io::stderr().lock().write_all(bytes);
}

pub fn run_rust_baseline_argv_with_fs_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>, WinFs), super::super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, &[], None)
}

pub fn run_rust_baseline_argv_with_fs_environment_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
) -> Result<(u32, Vec<u8>, WinFs), super::super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, environment, None)
}

pub fn run_rust_baseline_argv_with_fs_streaming(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, WinFs), String> {
    run_rust_baseline_argv_with_fs_impl(
        img,
        instance_fs,
        prog,
        args,
        &[],
        Some(&|is_stderr, chunk| {
            if is_stderr {
                write_host_stderr(chunk);
            } else {
                output(chunk);
            }
        }),
    )
    .map_err(|failure| failure.message)
}

pub fn run_rust_baseline_argv_with_fs_streaming_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, WinFs), super::super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(
        img,
        instance_fs,
        prog,
        args,
        &[],
        Some(&|is_stderr, chunk| {
            if is_stderr {
                write_host_stderr(chunk);
            } else {
                output(chunk);
            }
        }),
    )
}

pub fn run_rust_baseline_argv_with_fs_streaming_channels_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(bool, &[u8]),
) -> Result<(u32, Vec<u8>, WinFs), super::super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, &[], Some(output))
}

pub fn run_rust_baseline_argv_with_fs_streaming_environment_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, WinFs), super::super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(
        img,
        instance_fs,
        prog,
        args,
        environment,
        Some(&|is_stderr, chunk| {
            if is_stderr {
                write_host_stderr(chunk);
            } else {
                output(chunk);
            }
        }),
    )
}

pub fn run_rust_baseline_argv_with_fs_streaming_channels_environment_recoverable(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
    output: &dyn Fn(bool, &[u8]),
) -> Result<(u32, Vec<u8>, WinFs), super::super::NativeExecutionFailure> {
    run_rust_baseline_argv_with_fs_impl(img, instance_fs, prog, args, environment, Some(output))
}

fn run_rust_baseline_argv_with_fs_impl(
    img: &PeImage,
    instance_fs: WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
    output: Option<&dyn Fn(bool, &[u8])>,
) -> Result<(u32, Vec<u8>, WinFs), super::super::NativeExecutionFailure> {
    if img.is_dotnet_framework_image() {
        return Err(super::super::NativeExecutionFailure {
            message: ".NET Framework executables are not supported yet".to_string(),
            fs: instance_fs,
        });
    }
    if std::env::var_os("WINRUN_NATIVE_WORKER").as_deref() != Some(std::ffi::OsStr::new("1")) {
        if let Some(executable) = std::env::var_os("WINRUN_NATIVE_WORKER_EXE") {
            return run_exec_worker(
                executable.into(),
                img,
                instance_fs,
                prog,
                args,
                environment,
                output,
            );
        }
    }
    let mut recovery_fs = Some(instance_fs);
    let mut recovery_process: Option<Arc<NativeProcessContext>> = None;
    let result = (|| -> Result<(u32, Vec<u8>, WinFs), String> {
        let total_started = std::time::Instant::now();
        // Initialize this cache before any guest fork; shims read it in
        // potentially multithreaded children.
        let _ = native_diagnostic_enabled();
        let timing = std::env::var_os("WINRUN_TIMINGS").is_some();
        let lock_started = std::time::Instant::now();
        let _run = NATIVE_RUN_LOCK
            .lock()
            .map_err(|_| "native backend execution lock is poisoned".to_string())?;
        let lock_wait_ms = lock_started.elapsed().as_secs_f64() * 1000.0;
        let entry_started = std::time::Instant::now();
        let entry = entry(img)?;
        let tls_callbacks = img
            .tls
            .as_ref()
            .map(|tls| tls.callbacks.clone())
            .unwrap_or_default();
        let entry_ms = entry_started.elapsed().as_secs_f64() * 1000.0;
        let map_started = std::time::Instant::now();
        let mapping = map(img)?;
        let map_ms = map_started.elapsed().as_secs_f64() * 1000.0;
        let import_started = std::time::Instant::now();
        let strict_imports = std::env::var("WINRUN_NATIVE_STRICT_IMPORTS").as_deref() == Ok("1");
        let _import_stubs = registry::patch_baseline_imports(&mapping, img, strict_imports)?;
        let import_ms = import_started.elapsed().as_secs_f64() * 1000.0;
        let tls_started = std::time::Instant::now();
        let tls = setup_tls(&mapping, img)?;
        let tls_ms = tls_started.elapsed().as_secs_f64() * 1000.0;
        let context_started = std::time::Instant::now();
        let mut instance_fs = recovery_fs
            .take()
            .expect("filesystem is available before launch");
        instance_fs.clear_changes();
        let fs = Arc::new(Mutex::new(NativeFs {
            fs: instance_fs,
            handles: HashMap::new(),
            devices: HashMap::new(),
            file_access: HashMap::new(),
            file_shares: HashMap::new(),
            finds: HashMap::new(),
            file_completion_modes: HashMap::new(),
            delete_on_close: std::collections::HashSet::new(),
            file_locks: Vec::new(),
            next: 0x100,
        }));
        let command_line_w = command_line_w(prog, args)?;
        let command_line_a = command_line_a(&command_line_w);
        let std_handles = std::env::var("WINRUN_NATIVE_STD_HANDLES")
            .ok()
            .and_then(|value| serde_json::from_str::<[u64; 3]>(&value).ok())
            .unwrap_or([STD_HANDLE_BASE, STD_HANDLE_BASE + 1, STD_HANDLE_BASE + 2]);
        let process = Arc::new(NativeProcessContext {
            image_base: img.image_base,
            image_size: img.size_of_image,
            module_path: prog.to_string(),
            process_id: std::env::var("WINRUN_NATIVE_PROCESS_ID")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1),
            process_handle: u64::MAX,
            parent_process_id: std::env::var("WINRUN_NATIVE_PARENT_PROCESS_ID")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            command_line_w,
            command_line_a,
            environment: Mutex::new(environment.to_vec()),
            environment_block: Mutex::new(environment_strings(environment)),
            std_handles: std_handles.map(AtomicU64::new),
            crt_fds: Mutex::new(HashMap::new()),
            crt_fd_next: AtomicI32::new(3),
            fs,
            named_pipes: Mutex::new(NativeNamedPipeTable::new()),
            error_mode: AtomicU32::new(0),
            pointer_cookie: random_pointer_cookie(),
            heap_allocations: Mutex::new(HashMap::new()),
            virtual_allocations: Mutex::new(HashMap::new()),
            file_mappings: Mutex::new(HashMap::new()),
            mapping_views: Mutex::new(HashMap::new()),
            mapping_next: AtomicU64::new(0x9800_0000),
            gs_base: AtomicU64::new(0),
            tls_template: Mutex::new(tls.as_ref().map(NativeTls::clone_for_thread)),
            dynamic_tls: Mutex::new(DynamicTlsSlots::new(img.tls.is_some())),
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
            socket_handles: Mutex::new(std::collections::HashSet::new()),
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
            state_fd: AtomicU32::new(u32::MAX),
            fls_value: AtomicU64::new(0),
            unhandled_exception_filter: AtomicU64::new(0),
            vectored_exception_handler: AtomicU64::new(0),
            exit_status: AtomicU32::new(259), // STILL_ACTIVE
            exited: AtomicBool::new(false),
            children: Mutex::new(NativeProcessTable::new()),
            loaded_modules: Mutex::new(HashMap::from([(
                img.image_base,
                NativeLoadedModule {
                    path: prog.to_string(),
                    name: prog.rsplit(['\\', '/']).next().unwrap_or(prog).to_string(),
                    base: img.image_base,
                    size_of_image: img.size_of_image,
                    exports: img.exports.clone(),
                    entry_point: None,
                    tls_callbacks: img
                        .tls
                        .as_ref()
                        .map(|tls| tls.callbacks.clone())
                        .unwrap_or_default(),
                    static_tls_index: img.tls.as_ref().map(|_| 0),
                    static_tls_template: img.tls.as_ref().map(|tls| {
                        let mut data = tls.raw_data.clone();
                        data.resize(data.len() + tls.zero_fill as usize, 0);
                        data
                    }),
                    load_order: 0,
                },
            )])),
            module_next: AtomicU64::new(1),
        });
        recovery_process = Some(Arc::clone(&process));
        if let Ok(mut context) = NATIVE_PROCESS.lock() {
            *context = Some(Arc::clone(&process));
        }
        let context_ms = context_started.elapsed().as_secs_f64() * 1000.0;
        if std::env::var_os("WINRUN_NATIVE_WORKER").as_deref() == Some(std::ffi::OsStr::new("1")) {
            let state_fd = std::env::var("WINRUN_NATIVE_STATE_FD")
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or("native worker has no state journal descriptor")?;
            process.state_fd.store(state_fd, Ordering::Release);
            if let Ok(request_path) = std::env::var("WINRUN_NATIVE_REQUEST_PATH") {
                super::process::restore_worker_native_fs(
                    &process,
                    std::path::Path::new(&request_path),
                )?;
            }
            protect_exec(&mapping)?;
            let guest_process = Arc::clone(&process);
            let code = std::thread::Builder::new()
                .name("winrun-native-guest".to_string())
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    THREAD_NATIVE_PROCESS.with(|active| {
                        *active.borrow_mut() = Some(Arc::clone(&guest_process));
                    });
                    let mut tls = tls;
                    let mut fallback_teb = Box::new([0u8; 0x1000]);
                    let teb = tls
                        .as_mut()
                        .map(|tls| &mut tls.teb)
                        .unwrap_or(&mut fallback_teb);
                    if !install_thread_teb(teb) {
                        return 127;
                    }
                    guest_process
                        .gs_base
                        .store(teb.as_ptr() as u64, Ordering::Release);
                    super::thread_runtime::invoke_tls_callbacks(
                        guest_process.image_base,
                        &tls_callbacks,
                        1,
                    );
                    let guest: unsafe extern "win64" fn() -> u32 =
                        unsafe { std::mem::transmute(entry) };
                    let code = unsafe { guest() as i32 };
                    native_wait_file_io(&guest_process);
                    code
                })
                .map_err(|error| format!("cannot start native guest thread: {error}"))?
                .join()
                .unwrap_or(127);
            native_flush_instance_state();
            process.exit_status.store(code as u32, Ordering::Release);
            process.exited.store(true, Ordering::Release);
            if let Ok(mut context) = NATIVE_PROCESS.lock() {
                *context = None;
            }
            let fs = process
                .fs
                .lock()
                .map_err(|_| "native backend filesystem lock is poisoned".to_string())?
                .fs
                .clone();
            return Ok((code as u32, Vec::new(), fs));
        }
        let mut fds = [-1, -1];
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            return Err(format!(
                "native backend could not create stdout pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut stderr_fds = [-1, -1];
        if unsafe { pipe(stderr_fds.as_mut_ptr()) } != 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
            }
            return Err(format!(
                "native backend could not create stderr pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut state_fds = [-1, -1];
        if unsafe { pipe(state_fds.as_mut_ptr()) } != 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
                close(stderr_fds[0]);
                close(stderr_fds[1]);
            }
            return Err(format!(
                "native backend could not create state pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fork_started = std::time::Instant::now();
        let pid = unsafe { fork() };
        let fork_ms = fork_started.elapsed().as_secs_f64() * 1000.0;
        if pid < 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
                close(stderr_fds[0]);
                close(stderr_fds[1]);
                close(state_fds[0]);
                close(state_fds[1]);
            }
            return Err(format!(
                "native backend could not fork guest: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            #[cfg(test)]
            NATIVE_GUEST_ACTIVE.store(true, Ordering::Release);
            unsafe {
                close(fds[0]);
                close(state_fds[0]);
                close(stderr_fds[0]);
                if dup2(fds[1], 1) < 0 {
                    _exit(127);
                }
                close(fds[1]);
                if dup2(stderr_fds[1], 2) < 0 {
                    _exit(127);
                }
                close(stderr_fds[1]);
            }
            process
                .state_fd
                .store(state_fds[1] as u32, Ordering::Release);
            if protect_exec(&mapping).is_err() {
                unsafe { _exit(127) };
            }
            // Launcher threads can have 64 KiB stacks. V8 needs a larger
            // Windows thread stack, with bounds reflected in the guest TEB.
            let guest_process = Arc::clone(&process);
            let tls_callbacks = tls_callbacks.clone();
            let guest_thread = std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    THREAD_NATIVE_PROCESS.with(|active| {
                        *active.borrow_mut() = Some(Arc::clone(&guest_process));
                    });
                    let mut tls = tls;
                    let mut fallback_teb = Box::new([0u8; 0x1000]);
                    let teb = tls
                        .as_mut()
                        .map(|tls| &mut tls.teb)
                        .unwrap_or(&mut fallback_teb);
                    if !install_thread_teb(teb) {
                        return 127;
                    }
                    guest_process
                        .gs_base
                        .store(teb.as_ptr() as u64, Ordering::Release);
                    super::thread_runtime::invoke_tls_callbacks(
                        guest_process.image_base,
                        &tls_callbacks,
                        1,
                    );
                    // SAFETY: entry is in the child-owned RX PE mapping.
                    let guest: unsafe extern "win64" fn() -> u32 =
                        unsafe { std::mem::transmute(entry) };
                    let code = unsafe { guest() as i32 };
                    native_wait_file_io(&guest_process);
                    code
                });
            let code = guest_thread
                .ok()
                .and_then(|thread| thread.join().ok())
                .unwrap_or(127);
            unsafe { close(1) };
            native_flush_instance_state();
            unsafe { _exit(code) };
        }
        unsafe {
            close(fds[1]);
            close(stderr_fds[1]);
            close(state_fds[1]);
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let guest_started = std::time::Instant::now();
        let mut first_output_ms = None;
        let mut output_fds = [
            NativePollFd {
                fd: fds[0],
                events: 1,
                revents: 0,
            },
            NativePollFd {
                fd: stderr_fds[0],
                events: 1,
                revents: 0,
            },
        ];
        let mut open_output_fds = output_fds.len();
        while open_output_fds > 0 {
            let ready = unsafe { poll(output_fds.as_mut_ptr(), output_fds.len(), -1) };
            if ready < 0 {
                unsafe {
                    for descriptor in &output_fds {
                        if descriptor.fd >= 0 {
                            close(descriptor.fd);
                        }
                    }
                }
                return Err(format!(
                    "native backend could not poll guest output: {}",
                    std::io::Error::last_os_error()
                ));
            }
            for (index, descriptor) in output_fds.iter_mut().enumerate() {
                if descriptor.fd < 0 || descriptor.revents == 0 {
                    continue;
                }
                let n = unsafe { read(descriptor.fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n == 0 {
                    unsafe {
                        close(descriptor.fd);
                    }
                    descriptor.fd = -1;
                    open_output_fds -= 1;
                    continue;
                }
                if n < 0 {
                    unsafe {
                        for descriptor in &output_fds {
                            if descriptor.fd >= 0 {
                                close(descriptor.fd);
                            }
                        }
                    }
                    return Err(format!(
                        "native backend could not read guest {}: {}",
                        if index == 0 { "stdout" } else { "stderr" },
                        std::io::Error::last_os_error()
                    ));
                }
                if first_output_ms.is_none() {
                    first_output_ms = Some(guest_started.elapsed().as_secs_f64() * 1000.0);
                }
                let chunk = &buf[..n as usize];
                if index == 0 {
                    out.extend_from_slice(chunk);
                }
                if let Some(output) = output {
                    output(index == 1, chunk);
                } else if index == 1 {
                    write_host_stderr(chunk);
                }
            }
        }
        let guest_ms = guest_started.elapsed().as_secs_f64() * 1000.0;
        let state_started = std::time::Instant::now();
        let mut state = Vec::new();
        loop {
            let n = unsafe { read(state_fds[0], buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                break;
            }
            if n < 0 {
                unsafe { close(state_fds[0]) };
                return Err(format!(
                    "native backend could not read guest filesystem state: {}",
                    std::io::Error::last_os_error()
                ));
            }
            state.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { close(state_fds[0]) };
        let mut status = 0;
        if unsafe { waitpid(pid, &mut status, 0) } != pid {
            return Err(format!(
                "native backend could not reap guest: {}",
                std::io::Error::last_os_error()
            ));
        }
        let state_transfer_ms = state_started.elapsed().as_secs_f64() * 1000.0;
        process
            .exit_status
            .store((status >> 8) as u32, Ordering::Release);
        process.exited.store(true, Ordering::Release);
        if let Ok(mut context) = NATIVE_PROCESS.lock() {
            *context = None;
        }
        let decode_started = std::time::Instant::now();
        if status & 0x7f != 0 {
            return Err(format!(
                "native guest terminated by signal {}",
                status & 0x7f
            ));
        }
        let final_fs = {
            let mut native_fs = process
                .fs
                .lock()
                .map_err(|_| "native backend filesystem lock is poisoned".to_string())?;
            if !state.is_empty() {
                crate::snapshot::apply_changes(&state, &mut native_fs.fs).map_err(|e| {
                    format!("native backend returned invalid filesystem changes: {e}")
                })?;
            }
            std::mem::replace(&mut native_fs.fs, WinFs::new())
        };
        let state_decode_ms = decode_started.elapsed().as_secs_f64() * 1000.0;
        if timing {
            if !out.is_empty() && !out.ends_with(b"\n") {
                eprintln!();
            }
            let first_output = first_output_ms
                .map(|milliseconds| format!("{milliseconds:.3}ms"))
                .unwrap_or_else(|| "none".to_string());
            eprintln!(
            "winrun timing: {prog}: lock={lock_wait_ms:.3}ms entry={entry_ms:.3}ms map={map_ms:.3}ms imports={import_ms:.3}ms tls={tls_ms:.3}ms context={context_ms:.3}ms fork={fork_ms:.3}ms first_output={first_output} guest_until_output_eof={guest_ms:.3}ms state_transfer={state_transfer_ms:.3}ms state_decode={state_decode_ms:.3}ms stdout_bytes={} state_bytes={} total={:.3}ms",
            out.len(),
            state.len(),
            total_started.elapsed().as_secs_f64() * 1000.0
        );
        }
        Ok(((status >> 8) as u32, out, final_fs))
    })();
    match result {
        Ok(result) => Ok(result),
        Err(message) => {
            let fs = if let Some(process) = recovery_process {
                process
                    .fs
                    .lock()
                    .map(|native_fs| native_fs.fs.clone())
                    .unwrap_or_else(|_| WinFs::new())
            } else {
                recovery_fs.take().unwrap_or_else(WinFs::new)
            };
            Err(super::super::NativeExecutionFailure { message, fs })
        }
    }
}
