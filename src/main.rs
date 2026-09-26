use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use wincli::{backend, inspect, install, instance, pe, snapshot, winfs::WinFs};

fn exit(code: i32) -> ! {
    install::cleanup_process_cache();
    std::process::exit(code)
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  wincli <app.exe> [args...]      run a Windows program from a host path");
    eprintln!("  wincli <script.ps1>             run a script (no args yet)");
    eprintln!("  wincli shell                    interactive ephemeral runner shell");
    eprintln!("  wincli runner                   run host-controlled job commands from stdin");
    eprintln!("  wincli --snapshot=os.disk shell|runner  boot an indexed C: disk image");
    eprintln!("  wincli --save-snapshot=disk.winfs shell|runner  persist C: on exit");
    eprintln!("  wincli --mount=Z:/host/folder shell  mount a writable host folder");
    eprintln!("  wincli --mount-ro=Z:/host/folder shell  mount a read-only host folder");
    eprintln!("  wincli snapshot build <dir> <os.winfs>  build image from <dir>/C");
    eprintln!("  wincli instance boot <name> [--snapshot=os.snap]");
    eprintln!("  wincli instance status|destroy <name>");
    eprintln!("  wincli instance exec <name> -- <command> [args...]");
    eprintln!("  wincli inspect <app.exe>      report PE imports vs supported APIs");
    eprintln!("env: WINCLI_SOURCE (local package dir)");
    exit(2);
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if (args.len() == 4 || args.len() == 5) && args[1] == "__instance-daemon" {
        let snapshot = args.get(4).map(String::as_str);
        if let Err(e) = instance::run_daemon(&args[2], &args[3], snapshot) {
            eprintln!("wincli: instance daemon failed: {e}");
            exit(1);
        }
        return;
    }
    install::prepare_process_cache();
    let snapshot_path = args
        .get(1)
        .and_then(|arg| arg.strip_prefix("--snapshot="))
        .map(str::to_string);
    let save_snapshot_path = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--save-snapshot="))
        .map(str::to_string);
    let mount_specs: Vec<String> = args
        .iter()
        .filter_map(|arg| arg.strip_prefix("--mount=").map(str::to_string))
        .collect();
    let read_only_mount_specs: Vec<String> = args
        .iter()
        .filter_map(|arg| arg.strip_prefix("--mount-ro=").map(str::to_string))
        .collect();
    if snapshot_path.is_some() {
        args.remove(1);
    }
    if let Some(path) = save_snapshot_path.as_deref() {
        if let Some(index) = args
            .iter()
            .position(|arg| arg == &format!("--save-snapshot={path}"))
        {
            args.remove(index);
        }
    }
    args.retain(|arg| !arg.starts_with("--mount=") && !arg.starts_with("--mount-ro="));
    if args.len() == 3 && args[1] == "inspect" {
        inspect_target(&args[2]);
    }
    if args.len() == 5 && args[1] == "snapshot" && args[2] == "build" {
        match snapshot::build_file(&args[3], &args[4]) {
            Ok(count) => println!("Built snapshot {} ({} files)", args[4], count),
            Err(e) => {
                eprintln!("wincli: cannot build snapshot: {e}");
                exit(1);
            }
        }
        return;
    }
    if args.len() >= 4 && args[1] == "instance" {
        match args[2].as_str() {
            "boot" if args.len() == 4 || args.len() == 5 => {
                let snapshot = args
                    .get(4)
                    .and_then(|value| value.strip_prefix("--snapshot="));
                if args.len() == 5 && snapshot.is_none() {
                    usage();
                }
                match instance::boot(&args[3], snapshot) {
                    Ok(()) => println!("Instance {} is running", args[3]),
                    Err(e) => {
                        eprintln!("wincli: cannot boot instance: {e}");
                        exit(1);
                    }
                }
                return;
            }
            "status" if args.len() == 4 => match instance::status(&args[3]) {
                Ok(()) => println!("Instance {} is running", args[3]),
                Err(e) => {
                    eprintln!("wincli: {e}");
                    exit(1);
                }
            },
            "destroy" if args.len() == 4 => match instance::destroy(&args[3]) {
                Ok(()) => println!("Instance {} destroyed", args[3]),
                Err(e) => {
                    eprintln!("wincli: {e}");
                    exit(1);
                }
            },
            "exec" if args.len() >= 6 && args[4] == "--" => {
                let command = match shell_command(&args[5..]) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("wincli: {e}");
                        exit(2);
                    }
                };
                match instance::exec(&args[3], &command) {
                    Ok(result) => {
                        let _ = std::io::stdout().write_all(&result.stdout);
                        exit(result.code);
                    }
                    Err(e) => {
                        eprintln!("wincli: instance execution failed: {e}");
                        exit(1);
                    }
                }
            }
            _ => usage(),
        }
        return;
    }
    if args.len() == 2 && args[1] == "shell" {
        let fs = match snapshot_path.as_deref() {
            Some(path) => load_snapshot(path),
            None => WinFs::ephemeral_runner(),
        };
        let fs = mount_host_dirs(fs, &mount_specs, &read_only_mount_specs);
        let active_snapshot = save_snapshot_path.as_deref().or(snapshot_path.as_deref());
        let (code, mut fs) = wincli::shell::run_shell_with_snapshot(fs, active_snapshot);
        save_snapshot_if_requested(save_snapshot_path.as_deref(), &mut fs);
        exit(code);
    }
    if args.len() == 2 && args[1] == "runner" {
        let fs = match snapshot_path.as_deref() {
            Some(path) => load_snapshot(path),
            None => WinFs::ephemeral_runner(),
        };
        let fs = mount_host_dirs(fs, &mount_specs, &read_only_mount_specs);
        let active_snapshot = save_snapshot_path.as_deref().or(snapshot_path.as_deref());
        let (code, mut fs) = wincli::shell::run_runner_with_snapshot(fs, active_snapshot);
        save_snapshot_if_requested(save_snapshot_path.as_deref(), &mut fs);
        exit(code);
    }
    if snapshot_path.is_some()
        || save_snapshot_path.is_some()
        || !mount_specs.is_empty()
        || !read_only_mount_specs.is_empty()
    {
        eprintln!("wincli: --snapshot/--save-snapshot/--mount are supported with shell or runner");
        exit(2);
    }
    if args.len() < 2 {
        usage();
    }
    run_target(&args[1], &args[2..]);
}

fn shell_command(args: &[String]) -> Result<String, String> {
    args.iter()
        .map(|arg| {
            if arg.contains('"') {
                return Err("instance exec arguments may not contain double quotes yet".to_string());
            }
            if arg.is_empty() || arg.chars().any(char::is_whitespace) {
                Ok(format!("\"{arg}\""))
            } else {
                Ok(arg.clone())
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join(" "))
}

fn load_snapshot(path: &str) -> WinFs {
    match snapshot::load_file(path) {
        Ok(fs) => fs,
        Err(e) => {
            eprintln!("wincli: cannot boot snapshot {path}: {e}");
            exit(1);
        }
    }
}

fn mount_host_dirs(mut fs: WinFs, writable: &[String], read_only: &[String]) -> WinFs {
    for (spec, ro) in writable
        .iter()
        .map(|value| (value, false))
        .chain(read_only.iter().map(|value| (value, true)))
    {
        let Some((drive, path)) = spec.split_once(':') else {
            eprintln!("wincli: invalid mount {spec:?}; use --mount=Z:/host/folder");
            exit(2);
        };
        let mut chars = drive.chars();
        let Some(drive) = chars.next().filter(|_| chars.next().is_none()) else {
            eprintln!("wincli: invalid mount drive in {spec:?}");
            exit(2);
        };
        if let Err(error) = fs.mount_host_dir(drive, std::path::Path::new(path), ro) {
            eprintln!("wincli: cannot mount {spec:?}: {error}");
            exit(2);
        }
    }
    fs
}

/// Write the session disk back when `--save-snapshot=<file>` was given.
fn save_snapshot_if_requested(path: Option<&str>, fs: &mut WinFs) {
    if let Some(path) = path {
        if let Err(e) = snapshot::save_file(fs, path) {
            eprintln!("wincli: cannot save snapshot {path}: {e}");
            exit(1);
        }
        eprintln!("wincli: saved C: disk snapshot {path}");
    }
}

/// Run target: host `.exe`/`.ps1` path.
fn run_target(target: &str, guest_args: &[String]) {
    // 1. host file?
    if Path::new(target).is_file() {
        let ext = Path::new(target)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        match ext.as_str() {
            "exe" => run_exe_file(target, target, guest_args),
            "ps1" => {
                if !guest_args.is_empty() {
                    eprintln!("wincli: script args not supported yet");
                    exit(2);
                }
                run_ps1_file(target);
            }
            _ => {
                eprintln!("wincli: unsupported file type (expected .exe or .ps1): {target}");
                exit(2);
            }
        }
        return;
    }
    eprintln!("wincli: nothing to run: {target} (no such host file; install packages inside `wincli shell`)");
    exit(1);
}

fn run_exe_file(path: &str, prog: &str, guest_args: &[String]) {
    // NOTE: this reads the *Linux host* file as the PE container only.
    // The Windows guest filesystem stays purely in memory (WinFs).
    let read_started = std::time::Instant::now();
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("wincli: cannot read {path}: {e}");
            exit(1);
        }
    };
    if std::env::var_os("WINCLI_TIMINGS").is_some() {
        eprintln!(
            "wincli timing: {prog}: host_read={:.3}ms",
            read_started.elapsed().as_secs_f64() * 1000.0
        );
    }
    let pe_load_started = std::time::Instant::now();
    let img = match pe::load_lenient(&data) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("wincli: failed to load {path}: {e}");
            exit(1);
        }
    };
    if std::env::var_os("WINCLI_TIMINGS").is_some() {
        eprintln!(
            "wincli timing: {prog}: pe_load={:.3}ms",
            pe_load_started.elapsed().as_secs_f64() * 1000.0
        );
    }
    run_with_runner(&img, path, prog, guest_args);
}

/// Execute a loaded image through the configured platform backend.
fn run_with_runner(img: &pe::PeImage, path: &str, prog: &str, guest_args: &[String]) {
    let backend = match backend::configured() {
        Ok(value) => value,
        Err(e) => {
            eprintln!("wincli: failed to select execution backend for {path}: {e}");
            exit(1);
        }
    };
    let sink: backend::OutputSink = Arc::new(|channel, chunk| match channel {
        backend::OutputChannel::Stdout => {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(chunk);
            let _ = stdout.flush();
        }
        backend::OutputChannel::Stderr => {
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(chunk);
            let _ = stderr.flush();
        }
    });
    match backend.execute_streaming(img, WinFs::new(), prog, guest_args, sink) {
        Ok(result) => {
            exit(result.code as i32);
        }
        Err(e) => {
            eprintln!(
                "wincli: {} execution failed for {path}: {}",
                backend.id(),
                e.message
            );
            exit(1);
        }
    }
}

fn run_ps1_file(path: &str) {
    let script = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wincli: cannot read {path}: {e}");
            exit(1);
        }
    };
    let mut fs = WinFs::new();
    let mut out = Vec::new();
    match wincli::ps1::run_ps1(&mut fs, &script, &mut out) {
        Ok(_) => {
            let _ = std::io::stdout().write_all(&out);
        }
        Err(e) => {
            // Flush partial output first (a real shell streams).
            let _ = std::io::stdout().write_all(&out);
            eprintln!("wincli: script error: {e}");
            exit(1);
        }
    }
}

/// `wincli inspect <app.exe>`: print the compatibility report for a host file.
/// Exit 0 = runnable, 1 = missing imports or invalid file.
fn inspect_target(target: &str) {
    let data = match read_inspect_target(target) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("wincli: {e}");
            exit(1);
        }
    };
    match inspect::inspect_pe(&data) {
        Ok(report) => {
            print!("{}", inspect::render(&report));
            exit(if report.runnable() { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("wincli: cannot inspect {target}: {e}");
            exit(1);
        }
    }
}

fn read_inspect_target(target: &str) -> Result<Vec<u8>, String> {
    if Path::new(target).is_file() {
        return std::fs::read(target).map_err(|e| format!("cannot read {target}: {e}"));
    }
    Err(format!(
        "nothing to inspect: {target} (expected a host .exe path)"
    ))
}
