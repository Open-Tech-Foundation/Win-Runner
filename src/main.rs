use std::io::Write;
use std::path::Path;
use winrun::{inspect, instance, snapshot, winfs::WinFs};

fn exit(code: i32) -> ! {
    std::process::exit(code)
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  winrun <app.exe> [args...]      run a Windows program from a host path");
    eprintln!("  winrun <script.ps1>             run a script (no args yet)");
    eprintln!("  winrun shell                    interactive ephemeral runner shell");
    eprintln!("  winrun runner                   run host-controlled job commands from stdin");
    eprintln!("  winrun --headless --control=127.0.0.1:0 shell  run a remotely controlled shell");
    eprintln!("  winrun --snapshot=os.disk shell|runner  boot an indexed C: disk image");
    eprintln!(
        "  winrun --snapshot=os.disk --save shell|runner|app.exe  save changes to os.disk on exit"
    );
    eprintln!(
        "  winrun --save-snapshot=disk.winfs shell|runner|app.exe  save a new C: disk on exit"
    );
    eprintln!("  winrun --snapshot=os.disk <app.exe> [args...]  run headless with streamed stdio");
    eprintln!("  winrun --mount=Z:/host/folder shell  mount a writable host folder");
    eprintln!("  winrun --mount-ro=Z:/host/folder shell  mount a read-only host folder");
    eprintln!("  winrun snapshot build <dir> <os.winfs>  build image from <dir>/C");
    eprintln!("  winrun instance boot <name> [--snapshot=os.snap]");
    eprintln!("  winrun instance status|destroy <name>");
    eprintln!("  winrun instance exec <name> -- <command> [args...]");
    eprintln!("  winrun inspect <app.exe>      report PE imports vs supported APIs");
    exit(2);
}

#[derive(Default)]
struct RuntimeOptions {
    snapshot_path: Option<String>,
    save_snapshot_path: Option<String>,
    save_on_exit: bool,
    mount_specs: Vec<String>,
    read_only_mount_specs: Vec<String>,
    control_bind: Option<String>,
    headless: bool,
}

/// Consume Win-Runner options only before the command target. Everything from the
/// target onward belongs to the guest program, even when it resembles a
/// Win-Runner option.
fn parse_runtime_options(argv: &[String]) -> (RuntimeOptions, Vec<String>) {
    let mut options = RuntimeOptions::default();
    let mut args = argv.first().cloned().into_iter().collect::<Vec<_>>();
    let mut index = 1;
    while index < argv.len() {
        let arg = &argv[index];
        if arg == "--" {
            args.extend(argv[index + 1..].iter().cloned());
            break;
        }
        if let Some(value) = arg.strip_prefix("--snapshot=") {
            options
                .snapshot_path
                .get_or_insert_with(|| value.to_string());
        } else if let Some(value) = arg.strip_prefix("--save-snapshot=") {
            options
                .save_snapshot_path
                .get_or_insert_with(|| value.to_string());
        } else if arg == "--save" {
            options.save_on_exit = true;
        } else if let Some(value) = arg.strip_prefix("--mount=") {
            options.mount_specs.push(value.to_string());
        } else if let Some(value) = arg.strip_prefix("--mount-ro=") {
            options.read_only_mount_specs.push(value.to_string());
        } else if let Some(value) = arg.strip_prefix("--control=") {
            options
                .control_bind
                .get_or_insert_with(|| value.to_string());
        } else if arg == "--headless" {
            options.headless = true;
        } else {
            args.extend(argv[index..].iter().cloned());
            break;
        }
        index += 1;
    }
    (options, args)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "__native-worker" {
        match winrun::native::execute_worker_request(Path::new(&args[2])) {
            Ok(code) => std::process::exit(code as i32),
            Err(_) => std::process::exit(127),
        }
    }
    if let Ok(executable) = std::env::current_exe() {
        std::env::set_var("WINRUN_NATIVE_WORKER_EXE", executable);
    }
    if (args.len() == 4 || args.len() == 5) && args[1] == "__instance-daemon" {
        let snapshot = args.get(4).map(String::as_str);
        if let Err(e) = instance::run_daemon(&args[2], &args[3], snapshot) {
            eprintln!("winrun: instance daemon failed: {e}");
            exit(1);
        }
        return;
    }
    let (options, args) = parse_runtime_options(&args);
    let snapshot_path = options.snapshot_path.as_deref();
    let save_snapshot_path = options.save_snapshot_path.as_deref().or_else(|| {
        if options.save_on_exit {
            snapshot_path
        } else {
            None
        }
    });
    if options.save_on_exit && save_snapshot_path.is_none() {
        eprintln!("winrun: --save requires --snapshot=<file> or --save-snapshot=<file>");
        exit(2);
    }
    let mount_specs = options.mount_specs;
    let read_only_mount_specs = options.read_only_mount_specs;
    let control_bind = options.control_bind;
    let headless = options.headless;
    if let Some(bind) = control_bind.as_deref() {
        if !headless || args.len() != 2 || args[1] != "shell" {
            eprintln!("winrun: --control requires --headless and the shell target");
            exit(2);
        }
        let mut fs = match snapshot_path.as_deref() {
            Some(path) => load_snapshot(path),
            None => WinFs::ephemeral_runner(),
        };
        fs = mount_host_dirs(fs, &mount_specs, &read_only_mount_specs);
        let active_snapshot = save_snapshot_path.as_deref().or(snapshot_path.as_deref());
        let control = match winrun::control::ControlHandle::start(bind) {
            Ok(control) => control,
            Err(error) => {
                eprintln!("winrun: cannot start control session: {error}");
                exit(1);
            }
        };
        println!(
            "{}",
            serde_json::json!({"event": "ready", "protocol": 1, "url": control.endpoint()})
        );
        let _ = std::io::stdout().flush();
        let (code, mut fs) =
            winrun::shell::run_controlled_shell_with_snapshot(fs, active_snapshot, &control);
        save_snapshot_if_requested(save_snapshot_path.as_deref(), &mut fs);
        control.finish(code);
        exit(code);
    }
    if headless {
        eprintln!("winrun: --headless requires --control=<loopback-address> shell");
        exit(2);
    }
    if args.len() == 3 && args[1] == "inspect" {
        inspect_target(&args[2]);
    }
    if args.len() == 5 && args[1] == "snapshot" && args[2] == "build" {
        match snapshot::build_file(&args[3], &args[4]) {
            Ok(count) => println!("Built snapshot {} ({} files)", args[4], count),
            Err(e) => {
                eprintln!("winrun: cannot build snapshot: {e}");
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
                        eprintln!("winrun: cannot boot instance: {e}");
                        exit(1);
                    }
                }
                return;
            }
            "status" if args.len() == 4 => match instance::status(&args[3]) {
                Ok(()) => println!("Instance {} is running", args[3]),
                Err(e) => {
                    eprintln!("winrun: {e}");
                    exit(1);
                }
            },
            "destroy" if args.len() == 4 => match instance::destroy(&args[3]) {
                Ok(()) => println!("Instance {} destroyed", args[3]),
                Err(e) => {
                    eprintln!("winrun: {e}");
                    exit(1);
                }
            },
            "exec" if args.len() >= 6 && args[4] == "--" => {
                let command = match shell_command(&args[5..]) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("winrun: {e}");
                        exit(2);
                    }
                };
                match instance::exec(&args[3], &command) {
                    Ok(result) => {
                        let _ = std::io::stdout().write_all(&result.stdout);
                        exit(result.code);
                    }
                    Err(e) => {
                        eprintln!("winrun: instance execution failed: {e}");
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
        let (code, mut fs) = winrun::shell::run_shell_with_snapshot(fs, active_snapshot);
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
        let (code, mut fs) = winrun::shell::run_runner_with_snapshot(fs, active_snapshot);
        save_snapshot_if_requested(save_snapshot_path.as_deref(), &mut fs);
        exit(code);
    }
    let configured_guest_run = snapshot_path.is_some()
        || save_snapshot_path.is_some()
        || !mount_specs.is_empty()
        || !read_only_mount_specs.is_empty();
    if configured_guest_run && args.len() >= 2 {
        let fs = match snapshot_path.as_deref() {
            Some(path) => load_snapshot(path),
            None => WinFs::ephemeral_runner(),
        };
        let fs = mount_host_dirs(fs, &mount_specs, &read_only_mount_specs);
        let (code, mut fs) = winrun::shell::run_headless_program(fs, &args[1], &args[2..]);
        save_snapshot_if_requested(save_snapshot_path.as_deref(), &mut fs);
        exit(code);
    }
    if snapshot_path.is_some()
        || save_snapshot_path.is_some()
        || !mount_specs.is_empty()
        || !read_only_mount_specs.is_empty()
    {
        eprintln!("winrun: --snapshot/--save/--save-snapshot/--mount require shell, runner, or an executable target");
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
            eprintln!("winrun: cannot boot snapshot {path}: {e}");
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
            eprintln!("winrun: invalid mount {spec:?}; use --mount=Z:/host/folder");
            exit(2);
        };
        let mut chars = drive.chars();
        let Some(drive) = chars.next().filter(|_| chars.next().is_none()) else {
            eprintln!("winrun: invalid mount drive in {spec:?}");
            exit(2);
        };
        if let Err(error) = fs.mount_host_dir(drive, std::path::Path::new(path), ro) {
            eprintln!("winrun: cannot mount {spec:?}: {error}");
            exit(2);
        }
    }
    fs
}

/// Write the session disk back when `--save-snapshot=<file>` was given.
fn save_snapshot_if_requested(path: Option<&str>, fs: &mut WinFs) {
    if let Some(path) = path {
        if let Err(e) = snapshot::save_file(fs, path) {
            eprintln!("winrun: cannot save snapshot {path}: {e}");
            exit(1);
        }
        eprintln!("winrun: saved C: disk snapshot {path}");
    }
}

#[cfg(test)]
mod tests {
    use super::parse_runtime_options;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    #[test]
    fn runtime_options_stop_at_guest_program() {
        let input = argv(&[
            "winrun",
            "--snapshot=disk.winfs",
            "--mount=Z:/host",
            "C:\\bin\\tool.exe",
            "--mount=guest-value",
            "--snapshot=guest-value",
            "--headless",
            "--control=guest-value",
        ]);
        let (options, args) = parse_runtime_options(&input);
        assert_eq!(options.snapshot_path.as_deref(), Some("disk.winfs"));
        assert_eq!(options.mount_specs, ["Z:/host"]);
        assert!(!options.headless);
        assert_eq!(
            args,
            argv(&[
                "winrun",
                "C:\\bin\\tool.exe",
                "--mount=guest-value",
                "--snapshot=guest-value",
                "--headless",
                "--control=guest-value",
            ])
        );
    }

    #[test]
    fn runtime_option_separator_passes_remaining_arguments_through() {
        let input = argv(&[
            "winrun",
            "--snapshot=disk.winfs",
            "--",
            "C:\\bin\\tool.exe",
            "--mount=guest-value",
        ]);
        let (options, args) = parse_runtime_options(&input);
        assert_eq!(options.snapshot_path.as_deref(), Some("disk.winfs"));
        assert_eq!(
            args,
            argv(&["winrun", "C:\\bin\\tool.exe", "--mount=guest-value"])
        );
    }

    #[test]
    fn runtime_save_flag_reuses_the_loaded_snapshot_path() {
        let input = argv(&["winrun", "--snapshot=disk.winfs", "--save", "shell"]);
        let (options, args) = parse_runtime_options(&input);
        assert_eq!(options.snapshot_path.as_deref(), Some("disk.winfs"));
        assert!(options.save_on_exit);
        assert_eq!(args, argv(&["winrun", "shell"]));
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
            // As a Windows process starts: on a stock runner disk (profile
            // folders, System32) with the user's logon environment.
            "exe" => {
                let (code, _) =
                    winrun::shell::run_headless_program(WinFs::ephemeral_runner(), target, guest_args);
                exit(code);
            }
            "ps1" => {
                if !guest_args.is_empty() {
                    eprintln!("winrun: script args not supported yet");
                    exit(2);
                }
                run_ps1_file(target);
            }
            _ => {
                eprintln!("winrun: unsupported file type (expected .exe or .ps1): {target}");
                exit(2);
            }
        }
        return;
    }
    eprintln!("winrun: nothing to run: {target} (no such host file; install packages inside `winrun shell`)");
    exit(1);
}

fn run_ps1_file(path: &str) {
    let script = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("winrun: cannot read {path}: {e}");
            exit(1);
        }
    };
    let mut fs = WinFs::new();
    let mut out = Vec::new();
    match winrun::ps1::run_ps1(&mut fs, &script, &mut out) {
        Ok(_) => {
            let _ = std::io::stdout().write_all(&out);
        }
        Err(e) => {
            // Flush partial output first (a real shell streams).
            let _ = std::io::stdout().write_all(&out);
            eprintln!("winrun: script error: {e}");
            exit(1);
        }
    }
}

/// `winrun inspect <app.exe>`: print the compatibility report for a host file.
/// Exit 0 = runnable, 1 = missing imports or invalid file.
fn inspect_target(target: &str) {
    let data = match read_inspect_target(target) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("winrun: {e}");
            exit(1);
        }
    };
    match inspect::inspect_pe(&data) {
        Ok(report) => {
            print!("{}", inspect::render(&report));
            exit(if report.runnable() { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("winrun: cannot inspect {target}: {e}");
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
