//! Running programs from scripts: `& "C:\app.exe" args`, bare names found
//! on the guest `PATH` (`git --version`), `$LASTEXITCODE`, and the `2>&1`
//! family of stream redirections. The interpreter resolves the program
//! against the guest disk; a [`ProcessHost`] supplied by the caller runs it.
use super::*;

/// What a finished program left behind for the script.
pub struct ProcessOutput {
    /// `$LASTEXITCODE` (Windows exit codes read as signed 32-bit numbers).
    pub code: i32,
    pub stdout: Vec<u8>,
}

/// Where a program's standard error goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorStream {
    /// The console, as for an uncaptured call.
    Console,
    /// Into the output, in order (`2>&1`).
    Merge,
    /// Nowhere (`2>$null`).
    Discard,
}

/// Runs a guest program for a script. The shell provides one; without a
/// host (one-shot `run_ps1`), scripts cannot start programs.
pub trait ProcessHost {
    fn run(
        &mut self,
        fs: &mut WinFs,
        environment: &[(String, String)],
        image: &str,
        args: &[String],
        errors: ErrorStream,
    ) -> Result<ProcessOutput, String>;
}

/// Extensions tried, in order, for a name without one (`PATHEXT`'s
/// program entries).
const PROGRAM_EXTENSIONS: [&str; 4] = [".com", ".exe", ".bat", ".cmd"];

fn has_program_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PROGRAM_EXTENSIONS.iter().any(|e| lower.ends_with(e)) || lower.ends_with(".ps1")
}

/// The error-stream redirection an argument spells, if any: merging
/// (`2>&1`, `*>&1`) or discarding (`2>$null`, which expands to `2>`, and
/// `2>nul`). Other streams' merges (`3>&1`...) carry nothing here.
fn error_redirection(arg: &str) -> Option<Option<ErrorStream>> {
    match arg.to_ascii_lowercase().as_str() {
        "2>&1" | "*>&1" => Some(Some(ErrorStream::Merge)),
        "2>" | "2>nul" | "2>$null" | "*>" | "*>$null" => Some(Some(ErrorStream::Discard)),
        "3>&1" | "4>&1" | "5>&1" | "6>&1" => Some(None),
        _ => None,
    }
}

impl Interpreter<'_> {
    /// The guest file a program name runs: a path (with or without its
    /// extension) or a bare name searched on `PATH`, like PowerShell.
    pub(super) fn resolve_program(&self, name: &str) -> Option<String> {
        let candidates = |base: &str| -> Vec<String> {
            let mut list = Vec::new();
            if has_program_extension(base) {
                list.push(base.to_string());
            } else {
                list.extend(PROGRAM_EXTENSIONS.iter().map(|e| format!("{base}{e}")));
            }
            list
        };
        let found = |path: &str| -> Option<String> {
            let full = self.fs.normalize(path).ok()?.display();
            self.fs.is_file(&full).then_some(full)
        };
        if name.contains(['\\', '/', ':']) {
            return candidates(name).iter().find_map(|c| found(c));
        }
        let path = environment_get(self.environment, "PATH").unwrap_or_default();
        path.split(';')
            .map(|d| d.trim().trim_matches('"'))
            .filter(|d| !d.is_empty())
            .find_map(|dir| {
                let dir = dir.trim_end_matches('\\');
                candidates(&format!(r"{dir}\{name}"))
                    .iter()
                    .find_map(|c| found(c))
            })
    }

    /// Run a resolved program with expanded arguments: output goes to the
    /// script's output, the exit code to `$LASTEXITCODE`. Scripts run
    /// in this session; PowerShell links run their script inline.
    pub(super) fn run_program(&mut self, path: &str, args: &[String]) -> Result<Flow, String> {
        let mut errors = ErrorStream::Console;
        let mut kept = Vec::with_capacity(args.len());
        for arg in args {
            match error_redirection(arg) {
                Some(Some(stream)) => errors = stream,
                Some(None) => {}
                None => kept.push(arg.clone()),
            }
        }
        let args = kept;
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".ps1") {
            let data = self
                .fs
                .read_file(path)
                .map_err(|e| format!("cannot read {path}: {e}"))?;
            let script = String::from_utf8(data).map_err(|e| format!("cannot read {path}: {e}"))?;
            return self.run_nested_script(&script);
        }
        if crate::shell::is_powershell_shell_link(self.fs, path) {
            let script = crate::shell::powershell_script(self.fs, &args)?;
            let flow = self.run_nested_script(&script)?;
            self.vars
                .insert("lastexitcode".to_string(), Value::Str("0".to_string()));
            return Ok(flow);
        }
        if lower.ends_with(".bat") || lower.ends_with(".cmd") {
            return Err(format!(
                "batch files cannot run from PowerShell scripts yet: {path}"
            ));
        }
        let Some(host) = self.host.as_deref_mut() else {
            return Err(format!("programs cannot run from this script: {path}"));
        };
        let output = host.run(self.fs, self.environment, path, &args, errors)?;
        self.out.extend_from_slice(&output.stdout);
        if !output.stdout.is_empty() && !output.stdout.ends_with(b"\n") {
            self.out.push(b'\n');
        }
        self.vars.insert(
            "lastexitcode".to_string(),
            Value::Str(output.code.to_string()),
        );
        Ok(Flow::Next)
    }

    /// A `.ps1` started from a script: same session, its own `return`.
    fn run_nested_script(&mut self, script: &str) -> Result<Flow, String> {
        if self.depth + 1 > MAX_IEX_DEPTH {
            return Err("iex: max nesting depth exceeded".to_string());
        }
        self.depth += 1;
        let r = self.run_code(script);
        self.depth -= 1;
        Ok(match r? {
            Flow::Return => Flow::Next,
            f => f,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder(Vec<(String, Vec<String>)>);

    impl ProcessHost for Recorder {
        fn run(
            &mut self,
            _fs: &mut WinFs,
            _environment: &[(String, String)],
            image: &str,
            args: &[String],
            errors: ErrorStream,
        ) -> Result<ProcessOutput, String> {
            self.0.push((image.to_string(), args.to_vec()));
            let stream = match errors {
                ErrorStream::Console => "",
                ErrorStream::Merge => " +err",
                ErrorStream::Discard => " -err",
            };
            Ok(ProcessOutput {
                code: if args.first().is_some_and(|a| a == "fail") { 3 } else { 0 },
                stdout: format!("ran {}{stream}", args.join(",")).into_bytes(),
            })
        }
    }

    fn run_with_host(script: &str) -> (Result<i32, String>, String, Vec<(String, Vec<String>)>) {
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\tools").unwrap();
        fs.write_file(r"C:\tools\app.exe", b"MZ".to_vec()).unwrap();
        fs.write_file(r"C:\tools\other.EXE", b"MZ".to_vec()).unwrap();
        fs.write_file(r"C:\tools\job.cmd", b"@echo".to_vec()).unwrap();
        fs.write_file(r"C:\tools\inner.ps1", b"echo inner-$args0\nreturn\necho never".to_vec())
            .unwrap();
        let mut session = Session::default();
        environment_set(&mut session.environment, "PATH", r"C:\Windows;C:\tools");
        let mut host = Recorder(Vec::new());
        let mut out = Vec::new();
        let r = run_ps1_with_host(&mut session, &mut fs, script, &mut out, &mut host);
        (r, String::from_utf8(out).unwrap(), host.0)
    }

    #[test]
    fn programs_resolve_on_path_and_by_call_operator() {
        let (r, out, calls) = run_with_host(
            "app a 'b c'\n& \"C:\\tools\\other.exe\" fail 2>&1\necho \"code=$LASTEXITCODE\"\n$v = \"$(app.exe x 2>$null)\"\necho \"v=$v\"",
        );
        assert_eq!(r, Ok(0));
        assert_eq!(out, "ran a,b c\nran fail +err\ncode=3\nv=ran x -err\n");
        assert_eq!(
            calls,
            vec![
                (r"C:\tools\app.exe".to_string(), vec!["a".to_string(), "b c".to_string()]),
                (r"C:\tools\other.exe".to_string(), vec!["fail".to_string()]),
                (r"C:\tools\app.exe".to_string(), vec!["x".to_string()]),
            ]
        );
    }

    #[test]
    fn scripts_run_inline_and_missing_programs_fail() {
        let (r, out, _) = run_with_host("$args0 = 1\n& C:\\tools\\inner.ps1\necho after");
        assert_eq!(r, Ok(0));
        assert_eq!(out, "inner-1\nafter\n");
        let (r, _, _) = run_with_host("nope.exe 1");
        assert!(r.unwrap_err().contains("unknown command: nope.exe"));
        let (r, _, _) = run_with_host("job");
        assert!(r.unwrap_err().contains("batch files"));
        let mut fs = WinFs::ephemeral_runner();
        fs.write_file(r"C:\x.exe", b"MZ".to_vec()).unwrap();
        let mut out = Vec::new();
        let r = run_ps1(&mut fs, "& C:\\x.exe", &mut out);
        assert!(r.unwrap_err().contains("cannot run from this script"));
    }
}
