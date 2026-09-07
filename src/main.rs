use std::io::Write;
use std::path::Path;
use wincli::{pe, winapi, winfs::WinFs};

fn usage() -> ! {
    eprintln!("usage: wincli <app.exe|script.ps1>");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
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

fn run_exe_file(path: &str) {
    // NOTE: this reads the *Linux host* file as the PE container only.
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
