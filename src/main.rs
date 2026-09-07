use std::io::Write;
use std::path::Path;
use wincli::{inspect, install, pe, winapi, winfs::WinFs};

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  wincli <app.exe|pkg> [args...]  run a Windows program (host path,");
    eprintln!("                                  cached package, or C:\\bin\\<exe>)");
    eprintln!("  wincli <script.ps1>             run a script (no args yet)");
    eprintln!("  wincli inspect <app.exe|pkg>  report PE imports vs supported APIs");
    eprintln!("  wincli install <pkg>          install a package into the cache");
    eprintln!("env: WINCLI_CACHE (default ~/.cache/wincli), WINCLI_SOURCE (package dir)");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "inspect" {
        inspect_target(&args[2]);
    }
    if args.len() == 3 && args[1] == "install" {
        install_pkg(&args[2]);
        return;
    }
    if args.len() < 2 {
        usage();
    }
    run_target(&args[1], &args[2..]);
}

/// Run target: host `.exe`/`.ps1` path, cached package name, or guest
/// `C:\bin\<exe>` path. Host paths win; the rest resolve via the cache.
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
                    std::process::exit(2);
                }
                run_ps1_file(target);
            }
            _ => {
                eprintln!("wincli: unsupported file type (expected .exe or .ps1): {target}");
                std::process::exit(2);
            }
        }
        return;
    }
    // 2. cached package (`name`, `name.exe`, or `C:\bin\name.exe`)?
    let cache = install::cache_dir();
    let name = guest_bin_name(target);
    if let Some(exe_path) = install::find_cached(&cache, &name) {
        let bytes = match std::fs::read(&exe_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("wincli: cannot read {}: {e}", exe_path.display());
                std::process::exit(1);
            }
        };
        let label = exe_path.display().to_string();
        let img = match pe::load(&bytes) {
            Ok(img) => img,
            Err(e) => {
                eprintln!("wincli: failed to load {label}: {e}");
                std::process::exit(1);
            }
        };
        run_with_runner(&img, &label, target, guest_args);
        return;
    }
    eprintln!("wincli: nothing to run: {target} (no such file; try `wincli install {name}`)");
    std::process::exit(1);
}

/// Strip a guest `C:\bin\` prefix (any case, either slash) to a package name.
fn guest_bin_name(target: &str) -> String {
    let t = target.replace('/', "\\");
    if t.len() > 7 && t[..7].eq_ignore_ascii_case("c:\\bin\\") {
        t[7..].to_string()
    } else {
        target.to_string()
    }
}

fn run_exe_file(path: &str, prog: &str, guest_args: &[String]) {    // NOTE: this reads the *Linux host* file as the PE container only.
    // The Windows guest filesystem stays purely in memory (WinFs).
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("wincli: cannot read {path}: {e}");
            std::process::exit(1);
        }
    };
    let img = match pe::load(&data) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("wincli: failed to load {path}: {e}");
            std::process::exit(1);
        }
    };
    run_with_runner(&img, path, prog, guest_args);
}

/// Execute a loaded image with guest argv. Console output streams to host
/// stdout as it happens.
fn run_with_runner(img: &pe::PeImage, path: &str, prog: &str, guest_args: &[String]) {
    let fs = WinFs::new();
    let runner = match winapi::Runner::with_argv(img, fs, prog, guest_args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wincli: failed to start {path}: {e}");
            std::process::exit(1);
        }
    };
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    let runner = runner.with_console_sink(Box::new(move |chunk: &[u8]| {
        let _ = locked.write_all(chunk);
        let _ = locked.flush();
    }));
    match runner.run() {
        Ok((code, _fs, _out)) => {
            std::process::exit(code as i32);
        }
        Err(e) => {
            eprintln!("wincli: execution failed: {e}");
            std::process::exit(1);
        }
    }
}

fn run_ps1_file(path: &str) {
    let script = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wincli: cannot read {path}: {e}");
            std::process::exit(1);
        }
    };
    let mut fs = WinFs::new();
    let mut out = Vec::new();
    match wincli::ps1::run_ps1(&mut fs, &script, &mut out) {
        Ok(_) => {
            let _ = std::io::stdout().write_all(&out);
        }
        Err(e) => {
            eprintln!("wincli: script error: {e}");
            std::process::exit(1);
        }
    }
}

/// `wincli inspect <app.exe|pkg>`: print the compatibility report.
/// A host file path wins; otherwise the package cache is consulted.
/// Exit 0 = runnable, 1 = missing imports or invalid file.
fn inspect_target(target: &str) {
    let data = match read_inspect_target(target) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("wincli: {e}");
            std::process::exit(1);
        }
    };
    match inspect::inspect_pe(&data) {
        Ok(report) => {
            print!("{}", inspect::render(&report));
            std::process::exit(if report.runnable() { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("wincli: cannot inspect {target}: {e}");
            std::process::exit(1);
        }
    }
}

fn read_inspect_target(target: &str) -> Result<Vec<u8>, String> {
    if Path::new(target).is_file() {
        return std::fs::read(target).map_err(|e| format!("cannot read {target}: {e}"));
    }
    let cache = install::cache_dir();
    if let Some(p) = install::find_cached(&cache, target) {
        return std::fs::read(&p).map_err(|e| format!("cannot read {}: {e}", p.display()));
    }
    Err(format!(
        "nothing to inspect: {target} (no such file; try `wincli install {target}`)"
    ))
}

/// `wincli install <pkg>`: local `$WINCLI_SOURCE` dir, else remote catalog.
/// Guest-logical address is `C:\bin\<exe>`; bytes live in the host cache.
fn install_pkg(name: &str) {
    let cache = install::cache_dir();
    let source = match install::source_from_env() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wincli: {e}");
            std::process::exit(1);
        }
    };
    let result = match source {
        install::Source::Local(dir) => install::install(name, &dir, &cache),
        install::Source::Winget => install::install_remote(name, &cache),
    };
    match result {
        Ok(inst) => {
            println!(
                "Installed {} {} → {}",
                inst.name, inst.version, inst.guest_path
            );
        }
        Err(e) => {
            eprintln!("wincli: install failed: {e}");
            std::process::exit(1);
        }
    }
}
