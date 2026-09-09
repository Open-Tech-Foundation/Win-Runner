//! `wincli shell`: interactive command shell with one WinFS per session.
//!
//! Each input line is, in order: an `exit`/`quit`, an `install`/`inspect`
//! command, a host `.exe`/`.ps1` file, a cached package
//! (`name`, `name.exe`, `C:\bin\name.exe` + args), or a PS1 statement run
//! against the session filesystem. Guest console output streams exactly
//! like the one-shot CLI paths; errors print as `wincli: ...` and the
//! shell continues. `exit [n]`/`quit`, Ctrl-D (EOF), or a closed pipe ends
//! the session (code = argument, else the last guest code).

use crate::{inspect, install, pe, ps1, winapi, winfs::WinFs};
use std::io::{BufRead, Write};

/// What the REPL does after a line.
#[derive(Debug)]
pub enum ShellFlow {
    Continue,
    Exit(i32),
}

/// One shell session: the filesystem and variables every line shares.
pub struct Shell {
    fs: WinFs,
    sess: ps1::Session,
    last_code: i32,
}

impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}

impl Shell {
    pub fn new() -> Self {
        Shell {
            fs: WinFs::new(),
            sess: ps1::Session::default(),
            last_code: 0,
        }
    }

    /// Execute one input line; guest/PS1 output is appended to `out`.
    /// `Err` is a printable error: show it and continue the session.
    pub fn exec_line(&mut self, line: &str, out: &mut Vec<u8>) -> Result<ShellFlow, String> {
        let argv = split_line(line);
        if argv.is_empty() {
            return Ok(ShellFlow::Continue);
        }
        match argv[0].to_lowercase().as_str() {
            "exit" | "quit" => {
                let code = match argv.get(1) {
                    Some(n) => n
                        .parse::<i32>()
                        .map_err(|_| format!("exit: bad code: {n}"))?,
                    None => self.last_code,
                };
                Ok(ShellFlow::Exit(code))
            }
            "install" => {
                let name = argv
                    .get(1)
                    .ok_or_else(|| "usage: install <pkg>".to_string())?;
                let inst = do_install(name)?;
                out.extend_from_slice(
                    format!("Installed {} {} → {}\n", inst.name, inst.version, inst.guest_path)
                        .as_bytes(),
                );
                Ok(ShellFlow::Continue)
            }
            "inspect" => {
                let target = argv
                    .get(1)
                    .ok_or_else(|| "usage: inspect <app.exe|pkg>".to_string())?;
                let data = read_target_bytes(target)?;
                let report =
                    inspect::inspect_pe(&data).map_err(|e| format!("cannot inspect {target}: {e}"))?;
                out.extend_from_slice(inspect::render(&report).as_bytes());
                Ok(ShellFlow::Continue)
            }
            _ => self.run_target_line(&argv, line, out),
        }
    }

    /// Host file, cached package, or PS1 statement (in that order).
    fn run_target_line(
        &mut self,
        argv: &[String],
        line: &str,
        out: &mut Vec<u8>,
    ) -> Result<ShellFlow, String> {
        let target = &argv[0];
        if std::path::Path::new(target).is_file() {
            let ext = std::path::Path::new(target)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            match ext.as_str() {
                "exe" => return self.run_exe_file(target, target, &argv[1..], out),
                "ps1" => {
                    let script = std::fs::read_to_string(target)
                        .map_err(|e| format!("cannot read {target}: {e}"))?;
                    let code = ps1::run_ps1_session(&mut self.sess, &mut self.fs, &script, out)
                        .map_err(|e| format!("script error: {e}"))?;
                    self.last_code = code;
                    return Ok(ShellFlow::Continue);
                }
                _ => {
                    return Err(format!(
                        "unsupported file type (expected .exe or .ps1): {target}"
                    ));
                }
            }
        }
        let cache = install::cache_dir();
        if let Some(exe_path) = install::find_cached(&cache, &guest_bin_name(target)) {
            return self.run_exe_file(
                &exe_path.display().to_string(),
                target,
                &argv[1..],
                out,
            );
        }
        // Otherwise a PS1 statement; an unknown first word that is not
        // installed reads as the familiar install hint.
        match ps1::run_ps1_session(&mut self.sess, &mut self.fs, line, out) {
            Ok(code) => {
                self.last_code = code;
                Ok(ShellFlow::Continue)
            }
            Err(_) => Err(format!(
                "nothing to run: {target} (no such file; try `install {target}`)"
            )),
        }
    }

    /// Run an EXE with the session filesystem; the FS comes back with the
    /// exit code. A failed run resets the session FS (it is unrecoverable
    /// from a consumed runner).
    fn run_exe_file(
        &mut self,
        path: &str,
        prog: &str,
        guest_args: &[String],
        out: &mut Vec<u8>,
    ) -> Result<ShellFlow, String> {
        let data =
            std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let img = pe::load(&data).map_err(|e| format!("failed to load {path}: {e}"))?;
        let fs = std::mem::replace(&mut self.fs, WinFs::new());
        let runner = winapi::Runner::with_argv(&img, fs, prog, guest_args)
            .map_err(|e| format!("failed to start {path}: {e}"))?;
        match runner.run() {
            Ok((code, fs_back, gout)) => {
                self.fs = fs_back;
                self.last_code = code as i32;
                out.extend_from_slice(&gout);
                Ok(ShellFlow::Continue)
            }
            Err(e) => Err(format!("execution failed: {e}")),
        }
    }
}

/// `wincli install <pkg>` shared by the CLI and the shell.
fn do_install(name: &str) -> Result<install::Installed, String> {
    let cache = install::cache_dir();
    let source = install::source_from_env()?;
    match source {
        install::Source::Local(dir) => install::install(name, &dir, &cache),
        install::Source::Winget => install::install_remote(name, &cache),
    }
    .map_err(|e| format!("install failed: {e}"))
}

/// Host file first, else the package cache (mirrors the CLI resolver).
fn read_target_bytes(target: &str) -> Result<Vec<u8>, String> {
    if std::path::Path::new(target).is_file() {
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

/// Strip a guest `C:\bin\` prefix (any case, either slash) to a package name.
fn guest_bin_name(target: &str) -> String {
    let t = target.replace('/', "\\");
    if t.len() > 7 && t[..7].eq_ignore_ascii_case("c:\\bin\\") {
        t[7..].to_string()
    } else {
        target.to_string()
    }
}

/// Split a shell line on whitespace, honoring single/double quotes.
fn split_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = None;
    let mut in_word = false;
    for c in line.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    in_word = true;
                } else if c.is_whitespace() {
                    if in_word {
                        out.push(std::mem::take(&mut cur));
                        in_word = false;
                    }
                } else {
                    cur.push(c);
                    in_word = true;
                }
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

/// Interactive loop. Returns the process exit code. The prompt goes to
/// stderr (stdout stays clean for pipes); EOF ends with the last code.
pub fn run_shell() -> i32 {
    let stdin = std::io::stdin();
    let tty = std::io::IsTerminal::is_terminal(&stdin);
    let mut shell = Shell::new();
    let prompt = || {
        if tty {
            eprint!("PS C:\\> ");
            let _ = std::io::stderr().flush();
        }
    };
    prompt();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let mut out = Vec::new();
        match shell.exec_line(&line, &mut out) {
            Ok(ShellFlow::Continue) => {
                let _ = std::io::stdout().write_all(&out);
            }
            Ok(ShellFlow::Exit(code)) => {
                let _ = std::io::stdout().write_all(&out);
                return code;
            }
            Err(e) => {
                // Flush partial output first (a real shell streams).
                let _ = std::io::stdout().write_all(&out);
                eprintln!("wincli: {e}");
            }
        }
        prompt();
    }
    shell.last_code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_lines(shell: &mut Shell, lines: &[&str]) -> (Vec<u8>, Result<ShellFlow, String>) {
        let mut out = Vec::new();
        let mut flow = Ok(ShellFlow::Continue);
        for line in lines {
            flow = shell.exec_line(line, &mut out);
            if !matches!(flow, Ok(ShellFlow::Continue)) {
                break;
            }
        }
        (out, flow)
    }

    #[test]
    fn empty_line_is_a_noop() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        assert!(matches!(
            shell.exec_line("   ", &mut out),
            Ok(ShellFlow::Continue)
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn echo_passthrough_and_session_fs() {
        let mut shell = Shell::new();
        // Files created on one line are visible on later lines: one WinFs.
        let (out, _) = run_lines(
            &mut shell,
            &["New-Item C:\\t.txt -Value hi", "Get-Content C:\\t.txt"],
        );
        assert_eq!(out, b"hi\n");
    }

    #[test]
    fn variables_persist_across_lines() {
        let mut shell = Shell::new();
        let (out, _) = run_lines(&mut shell, &["$greet = hi", "echo $greet"]);
        assert_eq!(out, b"hi\n");
    }

    #[test]
    fn unknown_word_hints_install() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        let err = shell.exec_line("frobnicate", &mut out).unwrap_err();
        assert!(err.contains("install frobnicate"), "err: {err}");
    }

    #[test]
    fn exit_flows() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        assert!(matches!(
            shell.exec_line("quit", &mut out),
            Ok(ShellFlow::Exit(0))
        ));
        assert!(matches!(
            shell.exec_line("exit 3", &mut out),
            Ok(ShellFlow::Exit(3))
        ));
        assert!(shell.exec_line("exit abc", &mut out).is_err());
    }

    #[test]
    fn install_and_inspect_need_args() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        assert!(shell.exec_line("install", &mut out).is_err());
        assert!(shell.exec_line("inspect", &mut out).is_err());
    }

    #[test]
    fn bad_exe_and_inspect_errors() {
        let p = std::env::temp_dir().join(format!("wincli-shell-{}-junk.exe", std::process::id()));
        std::fs::write(&p, b"definitely not a PE file................").unwrap();
        let path = p.to_str().unwrap().to_string();
        let mut shell = Shell::new();
        let mut out = Vec::new();
        // Bare .exe path runs it: load failure surfaces.
        let err = shell.exec_line(&path, &mut out).unwrap_err();
        assert!(err.contains("failed to load"), "err: {err}");
        // The inspect command reports it instead.
        let err = shell
            .exec_line(&format!("inspect {path}"), &mut out)
            .unwrap_err();
        std::fs::remove_file(&p).ok();
        assert!(err.contains("cannot inspect"), "err: {err}");
    }

    #[test]
    fn split_line_quotes() {
        assert_eq!(split_line("rg \"foo bar\" -i"), vec!["rg", "foo bar", "-i"]);
        assert_eq!(split_line("echo 'a b'"), vec!["echo", "a b"]);
        assert_eq!(split_line("  "), Vec::<String>::new());
    }
}
