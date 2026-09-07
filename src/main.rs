use std::io::Write;
use std::path::Path;
use wincli::{inspect, install, pe, winapi, winfs::WinFs};

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  wincli <app.exe|script.ps1>   run a Windows program or script");
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
    if args.len() != 2 {
        usage();
    }
    let path = &args[1];
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "exe" => run_exe_file(path),
        "ps1" => run_ps1_file(path),
        _ => {
            eprintln!("wincli: unsupported file type (expected .exe or .ps1): {path}");
            std::process::exit(2);
        }
    }
}

fn run_exe_file(path: &str) {    // NOTE: this reads the *Linux host* file as the PE container only.
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
    let fs = WinFs::new();
    let runner = match winapi::Runner::new(&img, fs) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wincli: failed to start {path}: {e}");
            std::process::exit(1);
        }
    };
    match runner.run() {
        Ok((code, _fs, out)) => {
            let _ = std::io::stdout().write_all(&out);
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

/// `wincli install <pkg>`: resolve from `$WINCLI_SOURCE` into the cache.
/// Guest-logical address is `C:\bin\<exe>`; bytes live in the host cache.
fn install_pkg(name: &str) {
    let cache = install::cache_dir();
    let source = match install::source_dir() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wincli: {e}");
            std::process::exit(1);
        }
    };
    match install::install(name, &source, &cache) {
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
