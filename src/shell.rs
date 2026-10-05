//! Interactive and host-controlled runner shells with one fresh WinFs image
//! per session.
//!
//! Each input line is, in order: an `exit`/`quit`, a host-only `@seed`
//! injection directive, an `install`/`inspect` command, a host or guest
//! `.exe`/`.ps1` file, a package installed into the guest session
//! (`name` or `name.exe` on `PATH`, or a full path, + args), or a PS1 statement run
//! against the session filesystem. Guest console output streams exactly
//! like the one-shot CLI paths; errors print as `winrun: ...` and the
//! shell continues. `exit [n]`/`quit`, Ctrl-D (EOF), or a closed pipe ends
//! the session (code = argument, else the last guest code).

use crate::{backend, inspect, pe, ps1, reg_command, system_profile, winfs::WinFs, winreg, wpkg};
use rustyline::{
    completion::{Completer, Pair},
    error::ReadlineError,
    highlight::Highlighter,
    hint::Hinter,
    validate::Validator,
    Context, Editor, Helper,
};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::sync::Arc;

/// Where PowerShell's PSReadLine keeps console history for the user.
const SHELL_HISTORY_PATH: &str = r"C:\Users\runner\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";
const MAX_SHELL_HISTORY_ENTRIES: usize = 1000;
pub(crate) const POWERSHELL_SHELL_LINK: &[u8] = b"WINRUN_POWERSHELL_SHELL_LINK/v1\n";

pub(crate) fn is_powershell_shell_link(fs: &WinFs, path: &str) -> bool {
    fs.read_file(path)
        .is_ok_and(|contents| contents == POWERSHELL_SHELL_LINK)
}

/// `powershell.exe` at its Windows location, which the default `PATH` lists.
fn powershell_exe_path() -> String {
    format!(r"{}\powershell.exe", system_profile::POWERSHELL_HOME)
}

fn seed_powershell_shell_link(fs: &mut WinFs) {
    let path = powershell_exe_path();
    if fs.is_file(&path) {
        return;
    }
    if fs.mkdir(system_profile::POWERSHELL_HOME).is_err() {
        return;
    }
    let _ = fs.write_file(&path, POWERSHELL_SHELL_LINK.to_vec());
}

pub(crate) fn powershell_script(fs: &WinFs, argv: &[String]) -> Result<String, String> {
    const USAGE: &str = "usage: powershell [-NoProfile] -c <script> | powershell <script.ps1>";
    let mut args = argv;
    while let Some(first) = args.first() {
        let flag = first.to_lowercase();
        if flag == "-noprofile" || flag == "-noninteractive" || flag == "-nologo" {
            args = &args[1..];
        } else if flag == "-executionpolicy" {
            if args.len() < 2 {
                return Err(USAGE.to_string());
            }
            args = &args[2..];
        } else {
            break;
        }
    }
    match args.first().map(|s| s.to_lowercase()) {
        Some(flag) if flag == "-command" || flag == "-c" || flag == "/c" => {
            if args.len() < 2 {
                return Err("usage: powershell -c <script>".to_string());
            }
            Ok(args[1..].join(" "))
        }
        Some(flag) if flag == "-file" && args.len() == 2 => {
            if fs.is_file(&args[1]) {
                let bytes = fs
                    .read_file(&args[1])
                    .map_err(|e| format!("cannot read {}: {e}", args[1]))?;
                String::from_utf8(bytes).map_err(|e| format!("cannot read {}: {e}", args[1]))
            } else {
                std::fs::read_to_string(&args[1])
                    .map_err(|e| format!("cannot read {}: {e}", args[1]))
            }
        }
        Some(_) if args.len() == 1 && args[0].to_lowercase().ends_with(".ps1") => {
            if fs.is_file(&args[0]) {
                let bytes = fs
                    .read_file(&args[0])
                    .map_err(|e| format!("cannot read {}: {e}", args[0]))?;
                String::from_utf8(bytes).map_err(|e| format!("cannot read {}: {e}", args[0]))
            } else {
                std::fs::read_to_string(&args[0])
                    .map_err(|e| format!("cannot read {}: {e}", args[0]))
            }
        }
        _ => Err(USAGE.to_string()),
    }
}

const SHELL_COMMANDS: &[&str] = &[
    "cd",
    "chdir",
    "pwd",
    "cwd",
    "dir",
    "ls",
    "type",
    "cat",
    "copy",
    "cp",
    "move",
    "mv",
    "ren",
    "rename",
    "del",
    "erase",
    "rm",
    "mkdir",
    "md",
    "rmdir",
    "rd",
    "cls",
    "clear",
    "help",
    "set",
    "setx",
    "reg",
    "path",
    "mount",
    "snapshot",
    "reload",
    "wpkg",
    "powershell",
    "inspect",
    "exit",
    "quit",
];

#[derive(Default)]
struct ShellHelper {
    cwd: String,
    directories: HashMap<String, Vec<(String, bool)>>,
    commands: Vec<String>,
}

impl ShellHelper {
    fn refresh(&mut self, fs: &WinFs, environment: &[(String, String)]) {
        self.cwd = fs.cwd();
        self.directories.clear();
        self.commands = SHELL_COMMANDS
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        self.commands
            .extend(ps1::COMMAND_NAMES.iter().map(|name| (*name).to_string()));

        let mut search_dirs = vec![self.cwd.clone(), r"C:\".to_string()];
        search_dirs.extend(
            fs.host_mounts()
                .into_iter()
                .map(|(drive, _, _)| format!("{drive}:\\")),
        );
        if let Some((_, path)) = environment
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
        {
            search_dirs.extend(
                path.split(';')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
        search_dirs.sort_by_key(|path| path.to_ascii_lowercase());
        search_dirs.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

        for directory in search_dirs {
            let Ok(normalized) = fs.normalize(&directory) else {
                continue;
            };
            let key = normalized.display().to_ascii_lowercase();
            let Ok(names) = fs.list_dir(&normalized.display()) else {
                continue;
            };
            let entries = names
                .into_iter()
                .map(|name| {
                    let child = format!(
                        "{}\\{}",
                        normalized.display().trim_end_matches(['\\', '/']),
                        name
                    );
                    let is_dir = fs.is_dir(&child);
                    if !is_dir && name.to_ascii_lowercase().ends_with(".exe") {
                        self.commands.push(name.clone());
                        self.commands.push(name[..name.len() - 4].to_string());
                    }
                    (name, is_dir)
                })
                .collect();
            self.directories.insert(key, entries);
        }
        self.commands.sort_by_key(|name| name.to_ascii_lowercase());
        self.commands.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    }

    fn complete_line(&self, line: &str, pos: usize) -> (usize, Vec<Pair>) {
        let prefix = &line[..pos.min(line.len())];
        let start = prefix
            .char_indices()
            .rev()
            .find(|(_, ch)| ch.is_whitespace())
            .map(|(index, ch)| index + ch.len_utf8())
            .unwrap_or(0);
        let partial = &prefix[start..];
        if !prefix[..start].trim().is_empty() {
            return (start, self.complete_path(partial));
        }

        let mut candidates = self
            .commands
            .iter()
            .filter(|command| {
                command
                    .to_ascii_lowercase()
                    .starts_with(&partial.to_ascii_lowercase())
            })
            .map(|command| Pair {
                display: command.clone(),
                replacement: command.clone(),
            })
            .collect::<Vec<_>>();
        if partial.contains(['\\', '/', ':']) {
            candidates.extend(self.complete_path(partial));
        }
        (start, candidates)
    }

    fn complete_path(&self, partial: &str) -> Vec<Pair> {
        let split = partial.rfind(['\\', '/']);
        let (directory_prefix, leaf_prefix) = match split {
            Some(index) => (&partial[..=index], &partial[index + 1..]),
            None => ("", partial),
        };
        let directory = if directory_prefix.is_empty() {
            self.cwd.to_ascii_lowercase()
        } else if directory_prefix.as_bytes().get(1) == Some(&b':')
            || directory_prefix.starts_with(['\\', '/'])
        {
            let mut directory = directory_prefix.trim_end_matches(['\\', '/']).to_string();
            if directory.len() == 2 && directory.as_bytes().get(1) == Some(&b':') {
                directory.push('\\');
            } else if directory.is_empty() {
                directory = format!("{}\\", &self.cwd[..2]);
            }
            directory.to_ascii_lowercase()
        } else {
            format!(
                "{}\\{}",
                self.cwd.trim_end_matches(['\\', '/']),
                directory_prefix.trim_end_matches(['\\', '/'])
            )
            .to_ascii_lowercase()
        };
        self.directories
            .get(&directory)
            .into_iter()
            .flatten()
            .filter(|(name, _)| {
                name.to_ascii_lowercase()
                    .starts_with(&leaf_prefix.to_ascii_lowercase())
            })
            .map(|(name, is_dir)| {
                let suffix = if *is_dir { "\\" } else { "" };
                let replacement = format!("{directory_prefix}{name}{suffix}");
                Pair {
                    display: replacement.clone(),
                    replacement,
                }
            })
            .collect()
    }
}

impl Completer for ShellHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        Ok(self.complete_line(line, pos))
    }
}

impl Hinter for ShellHelper {
    type Hint = String;
}

impl Highlighter for ShellHelper {}
impl Validator for ShellHelper {}
impl Helper for ShellHelper {}

/// The logon environment for this disk: stock variables plus whatever
/// `setx`, `reg add`, or `[Environment]` saved in its registry.
fn logon_environment(fs: &WinFs) -> Vec<(String, String)> {
    match winreg::Registry::load(fs) {
        Ok(registry) => winreg::login_environment(&registry),
        Err(error) => {
            eprintln!("winrun: {error}; using the default environment");
            system_profile::default_environment()
        }
    }
}

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
    backend: Result<&'static dyn backend::ExecutionBackend, String>,
    snapshot_path: Option<std::path::PathBuf>,
    node_path_entry: Option<(String, bool)>,
}

impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}

impl Shell {
    pub fn new() -> Self {
        Self::with_fs(WinFs::ephemeral_runner())
    }

    /// Start a session from a prebuilt ephemeral image, such as a decoded
    /// immutable snapshot. The image is owned by this session and discarded
    /// once it exits.
    pub fn with_fs(fs: WinFs) -> Self {
        Self::with_snapshot_path(fs, None)
    }

    /// Start a session and remember the file it was loaded from for
    /// subsequent `snapshot save` commands without a path.
    pub fn with_snapshot_path(mut fs: WinFs, snapshot_path: Option<std::path::PathBuf>) -> Self {
        seed_powershell_shell_link(&mut fs);
        crate::cmd::seed_cmd_exe(&mut fs);
        // npm's standard Windows cache and global-prefix folders; npm
        // expects the cache's temp and log directories to exist.
        for directory in [
            format!(r"{}\npm-cache\_cacache\tmp", system_profile::LOCAL_APP_DATA),
            format!(r"{}\npm-cache\_logs", system_profile::LOCAL_APP_DATA),
            format!(r"{}\npm", system_profile::APP_DATA),
        ] {
            fs.mkdir(&directory)
                .expect("npm profile directories must fit the guest filesystem");
        }
        let backend_started = std::time::Instant::now();
        let backend = backend::configured().map_err(|e| format!("failed to select backend: {e}"));
        if std::env::var_os("WINRUN_TIMINGS").is_some() {
            eprintln!(
                "winrun timing: shell backend_init={:.3}ms",
                backend_started.elapsed().as_secs_f64() * 1000.0
            );
        }
        let environment = logon_environment(&fs);
        let mut shell = Shell {
            fs,
            sess: ps1::Session::with_environment(environment),
            last_code: 0,
            backend,
            snapshot_path,
            node_path_entry: None,
        };
        shell.refresh_node_path();
        shell
    }

    /// Windows working directory visible to the shell prompt and tests.
    pub fn cwd(&self) -> String {
        self.fs.cwd()
    }

    pub fn last_code(&self) -> i32 {
        self.last_code
    }

    fn shell_history(&self) -> Vec<String> {
        self.fs
            .read_file(SHELL_HISTORY_PATH)
            .ok()
            .map(|bytes| {
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .rev()
            .take(MAX_SHELL_HISTORY_ENTRIES)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    fn persist_shell_history(&mut self, entries: &[String]) -> Result<(), String> {
        if let Some((directory, _)) = SHELL_HISTORY_PATH.rsplit_once('\\') {
            self.fs.mkdir(directory)?;
        }
        let start = entries.len().saturating_sub(MAX_SHELL_HISTORY_ENTRIES);
        let mut contents = entries[start..].join("\n");
        if !contents.is_empty() {
            contents.push('\n');
        }
        self.fs
            .write_file(SHELL_HISTORY_PATH, contents.into_bytes())
    }

    fn record_shell_command(&mut self, line: &str) -> Result<(), String> {
        if line.trim().is_empty() {
            return Ok(());
        }
        let mut entries = self.shell_history();
        if entries.last().is_some_and(|entry| entry == line) {
            return Ok(());
        }
        entries.push(line.to_owned());
        self.persist_shell_history(&entries)
    }

    fn environment_value(&self, name: &str) -> Option<&str> {
        ps1::environment_get(&self.sess.environment, name)
    }

    fn set_environment_value(&mut self, name: String, value: Option<String>) {
        ps1::environment_set(
            &mut self.sess.environment,
            &name,
            value.as_deref().unwrap_or_default(),
        );
    }

    /// The standalone Windows Node distribution installs global npm launchers
    /// beside node.exe. Keep the active distribution on PATH, including disks
    /// restored from snapshots and changes to wpkg's selected version.
    fn refresh_node_path(&mut self) {
        let node = format!(r"{}\node.exe", wpkg::BIN);
        let directory = self
            .fs
            .is_file(&node)
            .then(|| self.guest_image_path(&node))
            .and_then(|path| path.rsplit_once('\\').map(|(dir, _)| dir.to_string()));
        if directory.as_deref() == self.node_path_entry.as_ref().map(|(path, _)| path.as_str()) {
            return;
        }
        let mut entries: Vec<String> = self
            .environment_value("PATH")
            .unwrap_or("")
            .split(';')
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect();
        let matches = |entry: &str, path: &str| {
            entry
                .trim()
                .trim_matches('"')
                .trim_end_matches('\\')
                .eq_ignore_ascii_case(path.trim_end_matches('\\'))
        };
        if let Some((old, added)) = self.node_path_entry.take() {
            if added {
                entries.retain(|entry| !matches(entry, &old));
            }
        }
        if let Some(directory) = directory {
            let npm = format!(
                r"{}\npm",
                self.environment_value("APPDATA")
                    .unwrap_or(system_profile::APP_DATA)
            );
            if !entries.iter().any(|entry| matches(entry, &npm)) {
                entries.push(npm);
            }
            let added = !entries.iter().any(|entry| matches(entry, &directory));
            if added {
                entries.push(directory.clone());
            }
            self.node_path_entry = Some((directory, added));
        }
        self.set_environment_value("PATH".to_string(), Some(entries.join(";")));
    }

    fn expand_environment_references(&self, input: &str) -> String {
        let chars: Vec<char> = input.chars().collect();
        let mut output = String::with_capacity(input.len());
        let mut index = 0;
        while index < chars.len() {
            if chars[index] == '%' {
                if let Some(end) = chars[index + 1..].iter().position(|&ch| ch == '%') {
                    let end = index + 1 + end;
                    let name: String = chars[index + 1..end].iter().collect();
                    if let Some(value) = self.environment_value(&name) {
                        output.push_str(value);
                    } else {
                        output.extend(chars[index..=end].iter());
                    }
                    index = end + 1;
                    continue;
                }
            }
            output.push(chars[index]);
            index += 1;
        }
        output
    }

    fn do_set(&mut self, argv: &[String], out: &mut Vec<u8>) -> Result<(), String> {
        if argv.is_empty() {
            // Like cmd's `set`: original spelling, sorted case-insensitively.
            let vars = self
                .sess
                .environment
                .iter()
                .map(|(name, value)| (name.to_ascii_uppercase(), (name, value)))
                .collect::<BTreeMap<_, _>>();
            for (name, value) in vars.into_values() {
                out.extend_from_slice(format!("{name}={value}\n").as_bytes());
            }
            return Ok(());
        }
        let expression = argv.join(" ");
        let Some((name, value)) = expression.split_once('=') else {
            let prefix = expression.to_ascii_uppercase();
            for (name, value) in &self.sess.environment {
                if name.to_ascii_uppercase().starts_with(&prefix) {
                    out.extend_from_slice(format!("{name}={value}\n").as_bytes());
                }
            }
            return Ok(());
        };
        let name = name.trim();
        if name.is_empty() || name.chars().any(char::is_whitespace) || name.contains('%') {
            return Err("set: invalid environment variable name".to_string());
        }
        let value = self.expand_environment_references(value);
        self.set_environment_value(name.to_string(), (!value.is_empty()).then_some(value));
        Ok(())
    }

    fn do_path(&mut self, argv: &[String], out: &mut Vec<u8>) {
        if argv.is_empty() {
            let value = self.environment_value("PATH").unwrap_or("");
            out.extend_from_slice(format!("PATH={value}\n").as_bytes());
            return;
        }
        let mut value = argv.join(" ");
        if let Some(rest) = value.strip_prefix('=') {
            value = rest.to_string();
        }
        let value = self.expand_environment_references(&value);
        self.set_environment_value("PATH".to_string(), Some(value));
    }

    fn do_cd(&mut self, argv: &[String], out: &mut Vec<u8>) -> Result<(), String> {
        let path = match argv {
            [] => {
                out.extend_from_slice(format!("{}\n", self.fs.cwd()).as_bytes());
                return Ok(());
            }
            [path] => path.as_str(),
            [flag, path] if flag.eq_ignore_ascii_case("/d") => path.as_str(),
            _ => return Err("usage: cd [/d] [directory]".to_string()),
        };
        self.fs.set_cwd(path).map_err(|e| format!("cd: {e}"))
    }

    fn do_dir(&self, argv: &[String], out: &mut Vec<u8>) -> Result<(), String> {
        if argv.len() > 1 {
            return Err("usage: dir [directory]".to_string());
        }
        let path = argv.first().map(String::as_str).unwrap_or("");
        let path = if path.is_empty() {
            self.fs.cwd()
        } else {
            path.to_string()
        };
        let entries = self.fs.list_dir(&path).map_err(|e| format!("dir: {e}"))?;
        for name in entries {
            let child = format!("{}\\{}", path.trim_end_matches(['\\', '/']), name);
            if self.fs.is_dir(&child) {
                out.extend_from_slice(format!("<DIR>       {name}\n").as_bytes());
            } else {
                let size = self.fs.file_len(&child).unwrap_or(0);
                out.extend_from_slice(format!("{size:>10} {name}\n").as_bytes());
            }
        }
        Ok(())
    }

    fn do_type(&self, argv: &[String], out: &mut Vec<u8>) -> Result<(), String> {
        if argv.is_empty() {
            return Err("usage: type <file> [...]".to_string());
        }
        for path in argv {
            let bytes = self.fs.read_file(path).map_err(|e| format!("type: {e}"))?;
            out.extend_from_slice(&bytes);
            if !bytes.ends_with(b"\n") {
                out.push(b'\n');
            }
        }
        Ok(())
    }

    fn do_copy_move(&mut self, command: &str, argv: &[String], moving: bool) -> Result<(), String> {
        if argv.len() != 2 {
            return Err(format!("usage: {command} <source> <destination>"));
        }
        if moving {
            self.fs.move_path(&argv[0], &argv[1])
        } else {
            self.fs.copy_path(&argv[0], &argv[1], false)
        }
        .map_err(|e| format!("{command}: {e}"))
    }

    fn do_delete(&mut self, argv: &[String]) -> Result<(), String> {
        if argv.len() != 1 {
            return Err("usage: del <file>".to_string());
        }
        self.fs
            .remove(&argv[0], false)
            .map_err(|e| format!("del: {e}"))
    }

    fn do_mkdir(&mut self, argv: &[String]) -> Result<(), String> {
        if argv.len() != 1 {
            return Err("usage: mkdir <directory>".to_string());
        }
        self.fs.mkdir(&argv[0]).map_err(|e| format!("mkdir: {e}"))
    }

    fn do_rmdir(&mut self, argv: &[String]) -> Result<(), String> {
        let (recursive, path) = match argv {
            [path] => (false, path.as_str()),
            [flag, path] if flag.eq_ignore_ascii_case("/s") => (true, path.as_str()),
            [flag, quiet, path]
                if flag.eq_ignore_ascii_case("/s") && quiet.eq_ignore_ascii_case("/q") =>
            {
                (true, path.as_str())
            }
            _ => return Err("usage: rmdir [/s [/q]] <directory>".to_string()),
        };
        if recursive {
            self.fs.remove(path, true)
        } else {
            self.fs.rmdir(path)
        }
        .map_err(|e| format!("rmdir: {e}"))
    }

    /// Execute one input line; guest/PS1 output is appended to `out`.
    /// `Err` is a printable error: show it and continue the session.
    pub fn exec_line(&mut self, line: &str, out: &mut Vec<u8>) -> Result<ShellFlow, String> {
        self.exec_line_with_sink(line, out, None)
    }

    /// Execute with immediate console forwarding when the selected backend
    /// supports it. Buffered output is still used for PS1 statements.
    pub fn exec_line_streaming(
        &mut self,
        line: &str,
        out: &mut Vec<u8>,
        sink: backend::OutputSink,
    ) -> Result<ShellFlow, String> {
        self.exec_line_with_sink(line, out, Some(sink))
    }

    fn exec_line_with_sink(
        &mut self,
        line: &str,
        out: &mut Vec<u8>,
        sink: Option<backend::OutputSink>,
    ) -> Result<ShellFlow, String> {
        self.refresh_node_path();
        let argv = split_line(line);
        if argv.is_empty() {
            return Ok(ShellFlow::Continue);
        }
        let command = argv[0].to_ascii_lowercase();
        // PowerShell aliases with parameters or pipelines must reach the
        // interpreter instead of the shell's simpler DOS-style handlers.
        if ps1::is_builtin_command(&command)
            && (command == "ren"
                || !SHELL_COMMANDS.contains(&command.as_str())
                || argv
                    .iter()
                    .skip(1)
                    .any(|arg| arg.starts_with('-') || arg == "|"))
        {
            self.last_code = ps1::run_ps1_session(&mut self.sess, &mut self.fs, line, out)
                .map_err(|error| format!("script error: {error}"))?;
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
            "@seed" => {
                let host = argv
                    .get(1)
                    .ok_or_else(|| "usage: @seed <host-file> <guest-path>".to_string())?;
                let guest = argv
                    .get(2)
                    .ok_or_else(|| "usage: @seed <host-file> <guest-path>".to_string())?;
                if argv.len() != 3 {
                    return Err("usage: @seed <host-file> <guest-path>".to_string());
                }
                self.seed_host_file(host, guest)?;
                Ok(ShellFlow::Continue)
            }
            "reload" => {
                if argv.len() != 1 {
                    return Err("usage: reload".to_string());
                }
                let registry =
                    winreg::Registry::load(&self.fs).map_err(|error| format!("reload: {error}"))?;
                self.sess.environment = winreg::login_environment(&registry);
                self.node_path_entry = None;
                self.refresh_node_path();
                self.last_code = 0;
                out.extend_from_slice(b"Environment reloaded.\n");
                Ok(ShellFlow::Continue)
            }
            "snapshot" => {
                self.do_snapshot(&argv[1..], out)?;
                Ok(ShellFlow::Continue)
            }
            "set" => {
                self.do_set(&argv[1..], out)?;
                Ok(ShellFlow::Continue)
            }
            "path" => {
                self.do_path(&argv[1..], out);
                Ok(ShellFlow::Continue)
            }
            "setx" => {
                let message = reg_command::setx(&mut self.fs, &argv[1..])?;
                out.extend_from_slice(message.as_bytes());
                self.last_code = 0;
                Ok(ShellFlow::Continue)
            }
            "reg" => {
                let message = reg_command::reg(&mut self.fs, &argv[1..])?;
                out.extend_from_slice(message.as_bytes());
                self.last_code = 0;
                Ok(ShellFlow::Continue)
            }
            "help" => {
                out.extend_from_slice(b"Built-in commands: cd, pwd, dir, type, copy, move, del, mkdir, rmdir, cls, set, setx, reg, path, mount, wpkg, powershell, snapshot, reload, inspect, exit\n");
                Ok(ShellFlow::Continue)
            }
            "cd" | "chdir" => {
                self.do_cd(&argv[1..], out)?;
                Ok(ShellFlow::Continue)
            }
            "pwd" | "cwd" => {
                if argv.len() != 1 {
                    return Err("usage: pwd".to_string());
                }
                out.extend_from_slice(format!("{}\n", self.fs.cwd()).as_bytes());
                Ok(ShellFlow::Continue)
            }
            "dir" | "ls" => {
                self.do_dir(&argv[1..], out)?;
                Ok(ShellFlow::Continue)
            }
            "type" | "cat" => {
                self.do_type(&argv[1..], out)?;
                Ok(ShellFlow::Continue)
            }
            "copy" | "cp" => {
                self.do_copy_move("copy", &argv[1..], false)?;
                Ok(ShellFlow::Continue)
            }
            "move" | "mv" | "ren" | "rename" => {
                self.do_copy_move("move", &argv[1..], true)?;
                Ok(ShellFlow::Continue)
            }
            "del" | "erase" | "rm" => {
                self.do_delete(&argv[1..])?;
                Ok(ShellFlow::Continue)
            }
            "mkdir" | "md" => {
                self.do_mkdir(&argv[1..])?;
                Ok(ShellFlow::Continue)
            }
            "rmdir" | "rd" => {
                self.do_rmdir(&argv[1..])?;
                Ok(ShellFlow::Continue)
            }
            "cls" | "clear" => {
                if argv.len() != 1 {
                    return Err("usage: cls".to_string());
                }
                out.extend_from_slice(b"\x1b[2J\x1b[H");
                Ok(ShellFlow::Continue)
            }
            "mount" => {
                match argv.len() {
                    1 => {
                        for (drive, path, read_only) in self.fs.host_mounts() {
                            out.extend_from_slice(
                                format!(
                                    "{drive}:\\ -> {} ({})\n",
                                    path.display(),
                                    if read_only { "read-only" } else { "read/write" }
                                )
                                .as_bytes(),
                            );
                        }
                    }
                    3 | 4 => {
                        let drive = argv[1]
                            .strip_suffix(':')
                            .and_then(|s| s.chars().next())
                            .ok_or_else(|| {
                                "usage: mount <drive>: <host-directory> [ro]".to_string()
                            })?;
                        let read_only = argv
                            .get(3)
                            .map(|option| option.eq_ignore_ascii_case("ro"))
                            .unwrap_or(false);
                        if argv.len() == 4 && !read_only {
                            return Err("mount: expected optional `ro`".to_string());
                        }
                        self.fs
                            .mount_host_dir(drive, std::path::Path::new(&argv[2]), read_only)?;
                        out.extend_from_slice(
                            format!(
                                "Mounted {} as {drive}:\\ ({})\n",
                                argv[2],
                                if read_only { "read-only" } else { "read/write" }
                            )
                            .as_bytes(),
                        );
                    }
                    _ => return Err("usage: mount [<drive>: <host-directory> [ro]]".to_string()),
                }
                Ok(ShellFlow::Continue)
            }
            "wpkg" => {
                self.do_wpkg(&argv[1..], out, sink.as_ref())?;
                Ok(ShellFlow::Continue)
            }
            "powershell" => {
                self.do_powershell(&argv[1..], out)?;
                Ok(ShellFlow::Continue)
            }
            "inspect" => {
                let target = argv
                    .get(1)
                    .ok_or_else(|| "usage: inspect <app.exe|pkg>".to_string())?;
                let data = read_target_bytes(&self.fs, target)?;
                let report = inspect::inspect_pe(&data)
                    .map_err(|e| format!("cannot inspect {target}: {e}"))?;
                out.extend_from_slice(inspect::render(&report).as_bytes());
                Ok(ShellFlow::Continue)
            }
            _ => self.run_target_line(&argv, line, out, sink),
        }
    }

    /// Host file, guest executable, or PS1 statement (in that order).
    fn run_target_line(
        &mut self,
        argv: &[String],
        line: &str,
        out: &mut Vec<u8>,
        sink: Option<backend::OutputSink>,
    ) -> Result<ShellFlow, String> {
        let target = &argv[0];
        if self.fs.is_file(target) && is_powershell_shell_link(&self.fs, target) {
            self.do_powershell(&argv[1..], out)?;
            return Ok(ShellFlow::Continue);
        }
        if std::path::Path::new(target).is_file() {
            let ext = std::path::Path::new(target)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            match ext.as_str() {
                "exe" => return self.run_exe_file(target, target, &argv[1..], out, sink),
                "ps1" => {
                    let file_read_started = std::time::Instant::now();
                    let script = std::fs::read_to_string(target)
                        .map_err(|e| format!("cannot read {target}: {e}"))?;
                    report_timing(target, "host_file_read", file_read_started);
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
        if self.fs.is_file(target) && is_batch_file(target) {
            return self.run_batch(target, &argv[1..], out, sink);
        }
        if self.fs.is_file(target) && target.to_ascii_lowercase().ends_with(".ps1") {
            if argv.len() != 1 {
                return Err("script parameters are not supported for .ps1 files".into());
            }
            let data = self
                .fs
                .read_file(target)
                .map_err(|error| format!("cannot read {target}: {error}"))?;
            let script = String::from_utf8(data)
                .map_err(|error| format!("cannot read {target}: {error}"))?;
            self.last_code = ps1::run_ps1_session(&mut self.sess, &mut self.fs, &script, out)
                .map_err(|error| format!("script error: {error}"))?;
            return Ok(ShellFlow::Continue);
        }
        if self.fs.is_file(target) {
            let file_read_started = std::time::Instant::now();
            let data = self
                .fs
                .read_file(target)
                .map_err(|e| format!("cannot read guest executable {target}: {e}"))?;
            report_timing(target, "guest_file_read", file_read_started);
            let image_path = self.guest_image_path(target);
            return self.run_exe_bytes(&data, &image_path, &argv[1..], out, sink);
        }
        // Bare names resolve on the guest PATH, like a Windows terminal.
        if !target.contains(['\\', '/', ':']) {
            for directory in self
                .environment_value("PATH")
                .unwrap_or("")
                .split(';')
                .map(str::trim)
                .map(|directory| directory.trim_matches('"'))
                .filter(|directory| !directory.is_empty())
            {
                for candidate in self.path_candidates(directory, target) {
                    if self.fs.is_file(&candidate) {
                        if is_powershell_shell_link(&self.fs, &candidate) {
                            self.do_powershell(&argv[1..], out)?;
                            return Ok(ShellFlow::Continue);
                        }
                        if is_batch_file(&candidate) {
                            return self.run_batch(&candidate, &argv[1..], out, sink);
                        }
                        let file_read_started = std::time::Instant::now();
                        let data = self.fs.read_file(&candidate).map_err(|e| {
                            format!("cannot read guest executable {candidate}: {e}")
                        })?;
                        report_timing(&candidate, "guest_file_read", file_read_started);
                        let image_path = self.guest_image_path(&candidate);
                        return self.run_exe_bytes(&data, &image_path, &argv[1..], out, sink);
                    }
                }
            }
        }
        // Bare `npm` runs the Node.js distribution's npm-cli.js through the
        // node.exe installed in this guest disk (npm ships as JS).
        if target.eq_ignore_ascii_case("npm") || target.eq_ignore_ascii_case("npm.cmd") {
            return self.run_npm(&argv[1..], out, sink);
        }
        // Otherwise a PS1 statement; an unknown first word that is not
        // installed reads as the familiar install hint.
        match ps1::run_ps1_session(&mut self.sess, &mut self.fs, line, out) {
            Ok(code) => {
                self.last_code = code;
                Ok(ShellFlow::Continue)
            }
            Err(error) if error == format!("unknown command: {}", target.to_lowercase()) => Err(
                format!("nothing to run: {target} (no such file; try `wpkg install {target}`)"),
            ),
            Err(error) => Err(format!("script error: {error}")),
        }
    }

    /// `directory\target` as Windows tries it: as typed when it already has
    /// a runnable extension, otherwise with each runnable `PATHEXT`
    /// extension in order.
    fn path_candidates(&self, directory: &str, target: &str) -> Vec<String> {
        const RUNNABLE: [&str; 4] = [".com", ".exe", ".bat", ".cmd"];
        let has_extension = target
            .rfind('.')
            .is_some_and(|dot| RUNNABLE.contains(&target[dot..].to_ascii_lowercase().as_str()));
        if has_extension {
            return vec![format!(r"{directory}\{target}")];
        }
        self.environment_value("PATHEXT")
            .unwrap_or(".COM;.EXE;.BAT;.CMD")
            .split(';')
            .map(|extension| extension.trim().to_ascii_lowercase())
            .filter(|extension| RUNNABLE.contains(&extension.as_str()))
            .map(|extension| format!(r"{directory}\{target}{extension}"))
            .collect()
    }

    /// Run a `.cmd`/`.bat` file with the cmd processor inside the shell, as
    /// the shell runs `.ps1` files itself. Like a child `cmd.exe`, the
    /// script's environment changes stay with it.
    fn run_batch(
        &mut self,
        path: &str,
        arguments: &[String],
        out: &mut Vec<u8>,
        sink: Option<backend::OutputSink>,
    ) -> Result<ShellFlow, String> {
        let command_line = crate::cmd::batch_command_line(path, arguments);
        let environment = self.sess.environment.clone();
        let cwd = self.fs.cwd();
        let code = {
            let mut host = ShellCmdHost {
                shell: self,
                out,
                sink,
            };
            crate::cmd::run_command_line(&mut host, &command_line, environment, cwd)
        };
        self.last_code = code as i32;
        Ok(ShellFlow::Continue)
    }

    /// Run an EXE with the session filesystem; the FS comes back with the
    /// exit code. When native execution fails, restore the last saved snapshot
    /// when one is active; otherwise start a clean runner image.
    fn run_exe_file(
        &mut self,
        path: &str,
        prog: &str,
        guest_args: &[String],
        out: &mut Vec<u8>,
        sink: Option<backend::OutputSink>,
    ) -> Result<ShellFlow, String> {
        let file_read_started = std::time::Instant::now();
        let data = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        report_timing(prog, "host_file_read", file_read_started);
        self.run_exe_bytes(&data, prog, guest_args, out, sink)
    }

    /// Execute a PE already present in the guest image. This is intentionally
    /// separate from host-file loading so a seeded runner can execute tools
    /// without a host filesystem mount.
    fn run_exe_bytes(
        &mut self,
        data: &[u8],
        prog: &str,
        guest_args: &[String],
        out: &mut Vec<u8>,
        sink: Option<backend::OutputSink>,
    ) -> Result<ShellFlow, String> {
        let pe_load_started = std::time::Instant::now();
        let img = pe::load_lenient(data).map_err(|e| format!("failed to load {prog}: {e}"))?;
        if std::env::var_os("WINRUN_TIMINGS").is_some() {
            eprintln!(
                "winrun timing: {prog}: pe_load={:.3}ms",
                pe_load_started.elapsed().as_secs_f64() * 1000.0
            );
        }
        let backend = self.backend.as_ref().map_err(Clone::clone)?;
        let fs = std::mem::replace(&mut self.fs, WinFs::ephemeral_runner());
        let streaming = sink.is_some();
        let result = match sink {
            Some(sink) => backend.execute_streaming_with_environment(
                &img,
                fs,
                prog,
                guest_args,
                &self.sess.environment,
                sink,
            ),
            None => {
                backend.execute_with_environment(&img, fs, prog, guest_args, &self.sess.environment)
            }
        };
        let result = match result {
            Ok(result) => result,
            Err(failure) => {
                self.fs = failure.fs;
                return Err(format!(
                    "{} execution failed: {}",
                    backend.id(),
                    failure.message
                ));
            }
        };
        self.fs = result.fs;
        self.last_code = result.code as i32;
        if !streaming {
            out.extend_from_slice(&result.stdout);
        }
        Ok(ShellFlow::Continue)
    }

    /// `snapshot save [host-file]`: persist this session's disk image so
    /// a later `winrun --snapshot=<file> shell` (or `--save-snapshot`)
    /// resumes with every installation and file change intact.
    fn do_snapshot(&mut self, argv: &[String], out: &mut Vec<u8>) -> Result<(), String> {
        match argv.first().map(|s| s.to_lowercase()).as_deref() {
            Some("save") => {
                if argv.len() > 2 {
                    return Err("usage: snapshot save [file]".to_string());
                }
                let path = argv
                    .get(1)
                    .map(std::path::PathBuf::from)
                    .or_else(|| self.snapshot_path.clone())
                    .ok_or_else(|| {
                        "no snapshot path is active; use `snapshot save <file>` first".to_string()
                    })?;
                let display = path.display().to_string();
                crate::snapshot::save_file(&mut self.fs, &display)
                    .map_err(|e| format!("cannot save snapshot {display}: {e}"))?;
                self.snapshot_path = Some(path);
                self.last_code = 0;
                out.extend_from_slice(format!("Saved C: disk snapshot {}\n", display).as_bytes());
                Ok(())
            }
            _ => Err("usage: snapshot save [file]".to_string()),
        }
    }
    /// Resolve package metadata directly from the Win-Runner GitHub registry.
    /// The archive itself is fetched and verified by the wpkg engine.
    fn do_wpkg(
        &mut self,
        argv: &[String],
        out: &mut Vec<u8>,
        sink: Option<&backend::OutputSink>,
    ) -> Result<(), String> {
        let repository = wpkg::EmbeddedRepository::new()?;
        // Live output to a terminal redraws the download bar in place;
        // captured or piped output keeps only the finished lines.
        let terminal = sink.is_some() && std::io::IsTerminal::is_terminal(&std::io::stdout());
        let mut status = crate::progress::StatusWriter::new(terminal);
        let emit = |text: &str, out: &mut Vec<u8>| {
            if text.is_empty() {
                return;
            }
            if let Some(sink) = sink {
                sink(backend::OutputChannel::Stdout, text.as_bytes());
            } else {
                out.extend_from_slice(text.as_bytes());
            }
        };
        let result = {
            let mut report = |message: &str| emit(&status.render(message), out);
            wpkg::execute_with_progress(
                &mut self.fs,
                &repository,
                wpkg::host_architecture(),
                argv,
                &mut report,
            )
        };
        emit(&status.finish(), out);
        self.refresh_node_path();
        let output = result.map_err(|error| format!("❌ wpkg failed: {error}"))?;
        out.extend_from_slice(&output);
        self.last_code = 0;
        Ok(())
    }

    /// Minimal `powershell -c <script>` passthrough so Windows install
    /// one-liners (`powershell -c "irm ...|iex"`) run as PS1 in-session.
    fn do_powershell(&mut self, argv: &[String], out: &mut Vec<u8>) -> Result<(), String> {
        let script = powershell_script(&self.fs, argv)?;
        let code = ps1::run_ps1_session(&mut self.sess, &mut self.fs, &script, out)
            .map_err(|e| format!("script error: {e}"))?;
        self.last_code = code;
        Ok(())
    }

    /// Run npm from this guest disk; a fresh shell must install Node.js or
    /// boot a snapshot that already contains it.
    fn run_npm(
        &mut self,
        guest_args: &[String],
        out: &mut Vec<u8>,
        sink: Option<backend::OutputSink>,
    ) -> Result<ShellFlow, String> {
        let node_guest = format!(r"{}\node.exe", wpkg::BIN);
        let node_guest = node_guest.as_str();
        let node_path = self.guest_image_path(node_guest);
        // npm ships beside node.exe; prefer the default Node.js version's
        // copy over any other version's installed elsewhere on the disk.
        let npm_guest = node_path
            .rsplit_once('\\')
            .map(|(directory, _)| format!(r"{directory}\node_modules\npm\bin\npm-cli.js"))
            .filter(|path| self.fs.is_file(path))
            .or_else(|| {
                self.fs
                    .find_file_path_suffix(r"\node_modules\npm\bin\npm-cli.js")
            })
            .unwrap_or_else(|| r"C:\npm\bin\npm-cli.js".to_string());
        if let (Ok(node), Ok(_)) = (self.fs.read_file(node_guest), self.fs.read_file(&npm_guest)) {
            let mut args = vec![npm_guest.to_string()];
            args.extend_from_slice(guest_args);
            return self.run_exe_bytes(&node, &node_path, &args, out, sink);
        }
        let data = self.fs.read_file(node_guest).map_err(|_| {
            "nothing to run: npm (Node.js is not installed in this session; install it with `wpkg install nodejs`)"
                .to_string()
        })?;
        if self.fs.read_file(&npm_guest).is_err() {
            return Err(
                "nothing to run: npm (npm is not installed in this session; install Node.js with `wpkg install nodejs`)"
                    .to_string(),
            );
        }
        let mut args = vec![npm_guest.to_string()];
        args.extend_from_slice(guest_args);
        self.run_exe_bytes(&data, &node_path, &args, out, sink)
    }

    /// The path a guest EXE runs as. wpkg commands are links into
    /// `C:\Program Files\<name>\current`; running the real file keeps
    /// `GetModuleFileName`, DLL search, and files shipped beside the EXE
    /// inside the selected package version.
    fn guest_image_path(&self, path: &str) -> String {
        self.fs
            .resolve_links(path)
            .unwrap_or_else(|| path.to_string())
    }

    /// One-way host-to-guest copy used while booting a local runner image.
    /// The guest path is validated and written through WinFs; no guest call
    /// can recover the corresponding host path.
    fn seed_host_file(&mut self, host: &str, guest: &str) -> Result<(), String> {
        let bytes = std::fs::read(host).map_err(|e| format!("cannot seed {host}: {e}"))?;
        let normalized = self
            .fs
            .normalize(guest)
            .map_err(|e| format!("invalid guest seed path {guest}: {e}"))?;
        if normalized.parts.is_empty() {
            return Err("cannot seed the guest filesystem root".to_string());
        }
        let parent = normalized.parts[..normalized.parts.len() - 1].join("\\");
        let parent = if parent.is_empty() {
            format!("{}:\\", normalized.drive)
        } else {
            format!("{}:\\{parent}", normalized.drive)
        };
        self.fs
            .mkdir(&parent)
            .map_err(|e| format!("cannot create guest seed directory: {e}"))?;
        self.fs
            .write_file(&normalized.display(), bytes)
            .map_err(|e| format!("cannot seed {guest}: {e}"))
    }
}

fn is_batch_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".cmd") || lower.ends_with(".bat")
}

/// Runs the programs a batch file starts through the shell's own launcher,
/// streaming console output and routing redirected output where cmd asked.
struct ShellCmdHost<'s> {
    shell: &'s mut Shell,
    out: &'s mut Vec<u8>,
    sink: Option<backend::OutputSink>,
}

impl crate::cmd::CmdHost for ShellCmdHost<'_> {
    fn with_fs<R>(&mut self, action: impl FnOnce(&mut WinFs) -> R) -> R {
        action(&mut self.shell.fs)
    }

    fn run(&mut self, request: &crate::cmd::RunRequest) -> Result<(u32, Vec<u8>), String> {
        use crate::cmd::Output;
        if request.stdin.is_some() {
            return Err(
                "input redirection (<) is not supported for programs run from the shell yet."
                    .to_string(),
            );
        }
        let data = self
            .shell
            .fs
            .read_file(&request.application)
            .map_err(|error| format!("cannot read {}: {error}", request.application))?;
        let arguments: Vec<String> = crate::cmd::split_windows_command_line(&request.command_line)
            .into_iter()
            .skip(1)
            .collect();
        let image_path = self.shell.guest_image_path(&request.application);
        let saved_environment = std::mem::replace(
            &mut self.shell.sess.environment,
            request.environment.clone(),
        );
        let saved_cwd = self.shell.fs.cwd();
        let _ = self.shell.fs.set_cwd(&request.current_directory);
        let mut buffer = Vec::new();
        let result = if request.stdout == Output::Stdout {
            self.shell
                .run_exe_bytes(&data, &image_path, &arguments, self.out, self.sink.clone())
        } else {
            self.shell
                .run_exe_bytes(&data, &image_path, &arguments, &mut buffer, None)
        };
        self.shell.sess.environment = saved_environment;
        let _ = self.shell.fs.set_cwd(&saved_cwd);
        result?;
        let code = self.shell.last_code as u32;
        let captured = match &request.stdout {
            Output::Stdout | Output::Null => Vec::new(),
            Output::Stderr => {
                self.write(true, &buffer);
                Vec::new()
            }
            Output::File(path) => {
                self.shell.fs.append_file(path, &buffer)?;
                Vec::new()
            }
            Output::Capture => buffer,
        };
        Ok((code, captured))
    }

    fn write(&mut self, stderr: bool, bytes: &[u8]) {
        match (&self.sink, stderr) {
            (Some(sink), true) => sink(backend::OutputChannel::Stderr, bytes),
            (Some(sink), false) => sink(backend::OutputChannel::Stdout, bytes),
            (None, true) => {
                let _ = std::io::stderr().write_all(bytes);
            }
            (None, false) => self.out.extend_from_slice(bytes),
        }
    }
}

/// Read a host executable or a file from this session's guest disk.
fn read_target_bytes(fs: &WinFs, target: &str) -> Result<Vec<u8>, String> {
    if std::path::Path::new(target).is_file() {
        return std::fs::read(target).map_err(|e| format!("cannot read {target}: {e}"));
    }
    for candidate in [
        target.to_string(),
        format!(r"{}\{target}", wpkg::BIN),
        format!(r"{}\{target}.exe", wpkg::BIN),
    ] {
        if fs.is_file(&candidate) {
            return fs
                .read_file(&candidate)
                .map_err(|e| format!("cannot read guest executable {candidate}: {e}"));
        }
    }
    Err(format!(
        "nothing to inspect: {target} (no such file; try `wpkg install {target}` inside `winrun shell`)"
    ))
}

fn report_timing(program: &str, stage: &str, started: std::time::Instant) {
    if std::env::var_os("WINRUN_TIMINGS").is_some() {
        eprintln!(
            "winrun timing: {program}: {stage}={:.3}ms",
            started.elapsed().as_secs_f64() * 1000.0
        );
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

fn run_session(
    fs: WinFs,
    prompt_enabled: bool,
    snapshot_path: Option<std::path::PathBuf>,
) -> (i32, WinFs) {
    run_session_controlled(fs, prompt_enabled, snapshot_path, None, None)
}

fn run_session_controlled(
    fs: WinFs,
    prompt_enabled: bool,
    snapshot_path: Option<std::path::PathBuf>,
    output_sink: Option<backend::OutputSink>,
    control: Option<&crate::control::ControlHandle>,
) -> (i32, WinFs) {
    let stdin = std::io::stdin();
    let tty = prompt_enabled && std::io::IsTerminal::is_terminal(&stdin);
    let mut shell = Shell::with_snapshot_path(fs, snapshot_path);
    if let Some(control) = control {
        control.emit_prompt(&shell.cwd());
    }
    if tty {
        let mut editor = match Editor::<ShellHelper, rustyline::history::DefaultHistory>::new() {
            Ok(editor) => editor,
            Err(error) => {
                eprintln!("winrun: cannot initialize terminal input: {error}");
                return (1, shell.fs);
            }
        };
        editor.set_helper(Some(ShellHelper::default()));
        for entry in &shell.shell_history() {
            let _ = editor.add_history_entry(entry.as_str());
        }
        loop {
            if let Some(helper) = editor.helper_mut() {
                helper.refresh(&shell.fs, &shell.sess.environment);
            }
            let prompt = format!("PS {}> ", shell.cwd());
            match editor.readline(&prompt) {
                Ok(line) => {
                    let _ = editor.add_history_entry(line.as_str());
                    if let Some(code) = execute_input_line(&mut shell, &line, output_sink.clone()) {
                        return (code, shell.fs);
                    }
                    if let Some(control) = control {
                        control.emit_prompt(&shell.cwd());
                    }
                }
                Err(ReadlineError::Eof) => break,
                Err(ReadlineError::Interrupted) => eprintln!("^C"),
                Err(error) => {
                    eprintln!("winrun: terminal input failed: {error}");
                    break;
                }
            }
        }
    } else {
        if control.is_some() {
            // Read one byte at a time so commands queued behind a shell line
            // remain available to the next native program on shared stdin.
            let mut line = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                let count = unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
                match count {
                    0 => {
                        if !line.is_empty() {
                            if let Some(code) = execute_control_line(
                                &mut shell,
                                &line,
                                output_sink.clone(),
                                control,
                            ) {
                                return (code, shell.fs);
                            }
                        }
                        break;
                    }
                    1 if matches!(byte[0], b'\n' | b'\r') => {
                        if let Some(code) =
                            execute_control_line(&mut shell, &line, output_sink.clone(), control)
                        {
                            return (code, shell.fs);
                        }
                        line.clear();
                    }
                    1 if byte[0] == 3 => {
                        line.clear();
                        if let Some(sink) = &output_sink {
                            sink(backend::OutputChannel::Stderr, b"^C\n");
                        }
                        if let Some(control) = control {
                            control.emit_prompt(&shell.cwd());
                        }
                    }
                    1 => line.push(byte[0]),
                    _ => break,
                }
            }
        } else {
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                if let Some(code) = execute_input_line(&mut shell, &line, output_sink.clone()) {
                    return (code, shell.fs);
                }
            }
        }
    }
    (shell.last_code, shell.fs)
}

fn execute_input_line(
    shell: &mut Shell,
    line: &str,
    output_sink: Option<backend::OutputSink>,
) -> Option<i32> {
    let mut out = Vec::new();
    let sink = output_sink.unwrap_or_else(|| {
        Arc::new(|channel, chunk| match channel {
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
        })
    });
    // All shell input paths reach this boundary, including controlled and
    // piped sessions. Persist before parsing or starting a guest process.
    if let Err(error) = shell.record_shell_command(line) {
        sink(
            backend::OutputChannel::Stderr,
            format!("winrun: cannot save shell history to {SHELL_HISTORY_PATH}: {error}\n")
                .as_bytes(),
        );
    }
    match shell.exec_line_streaming(line, &mut out, sink.clone()) {
        Ok(ShellFlow::Continue) => {
            sink(backend::OutputChannel::Stdout, &out);
        }
        Ok(ShellFlow::Exit(code)) => {
            sink(backend::OutputChannel::Stdout, &out);
            return Some(code);
        }
        Err(error) => {
            sink(backend::OutputChannel::Stdout, &out);
            sink(
                backend::OutputChannel::Stderr,
                format!("winrun: {error}\n").as_bytes(),
            );
        }
    }
    None
}

fn execute_control_line(
    shell: &mut Shell,
    bytes: &[u8],
    output_sink: Option<backend::OutputSink>,
    control: Option<&crate::control::ControlHandle>,
) -> Option<i32> {
    let line = String::from_utf8_lossy(bytes);
    let exit = execute_input_line(shell, &line, output_sink);
    if let Some(control) = control {
        if exit.is_none() {
            control.emit_prompt(&shell.cwd());
        }
    }
    exit
}

/// Interactive loop. Returns the process exit code. EOF ends with the last
/// code; piped input remains line-oriented and does not activate the editor.
pub fn run_shell() -> (i32, WinFs) {
    run_session(WinFs::ephemeral_runner(), true, None)
}

/// Run an interactive shell from a decoded snapshot image.
pub fn run_shell_with_fs(fs: WinFs) -> (i32, WinFs) {
    run_session(fs, true, None)
}

/// Run an interactive shell and remember the snapshot file to save back to.
pub fn run_shell_with_snapshot(fs: WinFs, snapshot_path: Option<&str>) -> (i32, WinFs) {
    run_session(fs, true, snapshot_path.map(std::path::PathBuf::from))
}

/// Run the line-oriented shell under an external control transport. The
/// transport sink streams guest and builtin output while the control bridge
/// supplies input through standard input.
pub fn run_controlled_shell_with_snapshot(
    fs: WinFs,
    snapshot_path: Option<&str>,
    control: &crate::control::ControlHandle,
) -> (i32, WinFs) {
    let sink = control.output_sink();
    run_session_controlled(
        fs,
        false,
        snapshot_path.map(std::path::PathBuf::from),
        Some(sink),
        Some(control),
    )
}

/// Host-controlled runner loop. It consumes job commands from standard input
/// without a prompt, boots one fresh ephemeral WinFs image, and destroys that
/// image when the input closes. This is the local control-plane seam for a
/// future GitHub Actions protocol adapter.
pub fn run_runner() -> (i32, WinFs) {
    run_session(WinFs::ephemeral_runner(), false, None)
}

/// Run a host-controlled session from a decoded snapshot image.
pub fn run_runner_with_fs(fs: WinFs) -> (i32, WinFs) {
    run_session(fs, false, None)
}

/// Run a host-controlled session and remember the snapshot file to save back to.
pub fn run_runner_with_snapshot(fs: WinFs, snapshot_path: Option<&str>) -> (i32, WinFs) {
    run_session(fs, false, snapshot_path.map(std::path::PathBuf::from))
}

/// Run one host or guest PE without a shell prompt. Standard input stays
/// connected to the guest, and output is forwarded as it is written.
pub fn run_headless_program(fs: WinFs, target: &str, args: &[String]) -> (i32, WinFs) {
    let mut shell = Shell::with_fs(fs);
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(target.to_string());
    argv.extend_from_slice(args);
    let mut out = Vec::new();
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
    match shell.run_target_line(&argv, target, &mut out, Some(sink)) {
        Ok(ShellFlow::Continue) => {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(&out);
            let _ = stdout.flush();
            (shell.last_code, shell.fs)
        }
        Ok(ShellFlow::Exit(code)) => (code, shell.fs),
        Err(error) => {
            eprintln!("winrun: {error}");
            (1, shell.fs)
        }
    }
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
    fn shell_history_roundtrips_through_c_system_and_snapshot() {
        let mut shell = Shell::new();
        let entries = vec!["set PATH=C:\\tools".to_string(), "nano".to_string()];
        shell.persist_shell_history(&entries).unwrap();
        assert_eq!(shell.shell_history(), entries);

        let snapshot = std::env::temp_dir().join(format!(
            "winrun-history-{}-{}.winfs",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::snapshot::save_file(&mut shell.fs, snapshot.to_str().unwrap()).unwrap();
        let restored = crate::snapshot::load_file(snapshot.to_str().unwrap()).unwrap();
        std::fs::remove_file(snapshot).unwrap();
        assert_eq!(Shell::with_fs(restored).shell_history(), entries);
    }

    #[test]
    fn input_history_is_saved_before_execution_and_retains_failures() {
        let mut shell = Shell::new();
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = output.clone();
        let sink: backend::OutputSink = Arc::new(move |_, chunk| {
            captured.lock().unwrap().extend_from_slice(chunk);
        });
        execute_input_line(&mut shell, "missing-history-command", Some(sink.clone()));
        assert_eq!(shell.shell_history(), ["missing-history-command"]);
        assert!(String::from_utf8_lossy(&output.lock().unwrap()).contains("nothing to run"));
        output.lock().unwrap().clear();
        let query = format!("Get-Content {SHELL_HISTORY_PATH}");
        execute_input_line(&mut shell, &query, Some(sink.clone()));
        let contents = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(contents.lines().any(|line| line == query));
        execute_control_line(&mut shell, b"missing-control-command", Some(sink), None);
        assert_eq!(shell.shell_history().last().unwrap(), "missing-control-command");
    }

    #[test]
    fn history_save_errors_are_reported_without_blocking_execution() {
        let mut shell = Shell::new();
        shell.fs.mkdir(SHELL_HISTORY_PATH).unwrap();
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = output.clone();
        let sink: backend::OutputSink = Arc::new(move |_, chunk| {
            captured.lock().unwrap().extend_from_slice(chunk);
        });
        assert_eq!(
            execute_input_line(&mut shell, "echo still-running", Some(sink)),
            None
        );
        let contents = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(contents.contains("cannot save shell history"));
        assert!(contents.contains("still-running"));
    }

    #[test]
    fn command_history_skips_blank_and_adjacent_duplicates_and_bounds_entries() {
        let mut shell = Shell::new();
        let entries: Vec<_> = (0..MAX_SHELL_HISTORY_ENTRIES)
            .map(|index| format!("echo {index}"))
            .collect();
        shell.persist_shell_history(&entries).unwrap();
        shell.record_shell_command("  ").unwrap();
        shell.record_shell_command(entries.last().unwrap()).unwrap();
        assert_eq!(shell.shell_history(), entries);
        shell.record_shell_command("echo next").unwrap();
        let history = shell.shell_history();
        assert_eq!(history.len(), MAX_SHELL_HISTORY_ENTRIES);
        assert_eq!(history[0], entries[1]);
        assert_eq!(history.last().unwrap(), "echo next");
    }

    #[test]
    fn set_and_path_update_guest_environment_and_executable_search() {
        let mut shell = Shell::new();
        shell.fs.mkdir(r"C:\tools").unwrap();
        shell
            .fs
            .write_file(
                r"C:\tools\history-probe.exe",
                crate::pe::builder::hello("found on guest PATH"),
            )
            .unwrap();
        let mut out = Vec::new();
        shell.exec_line(r"set TOOLS=C:\tools", &mut out).unwrap();
        shell
            .exec_line("set PATH=%PATH%;%TOOLS%", &mut out)
            .unwrap();
        assert!(shell
            .environment_value("path")
            .unwrap()
            .ends_with(r";C:\tools"));
        shell.exec_line("path", &mut out).unwrap();
        assert!(String::from_utf8_lossy(&out).contains(r"C:\tools"));
        out.clear();
        shell.exec_line("history-probe", &mut out).unwrap();
        assert_eq!(out, b"found on guest PATH");

        shell.exec_line("set TOOLS=", &mut out).unwrap();
        assert_eq!(shell.environment_value("TOOLS"), None);
    }

    #[test]
    fn shell_boots_in_the_user_profile_with_the_standard_environment() {
        let shell = Shell::new();
        assert_eq!(shell.cwd(), r"C:\Users\runner");
        assert_eq!(
            shell.environment_value("userprofile"),
            Some(r"C:\Users\runner")
        );
        assert_eq!(
            shell.environment_value("localappdata"),
            Some(r"C:\Users\runner\AppData\Local")
        );
        assert_eq!(shell.environment_value("USERNAME"), Some("runner"));
        assert_eq!(
            shell.environment_value("TEMP"),
            Some(r"C:\Users\runner\AppData\Local\Temp")
        );
        let path: Vec<_> = shell
            .environment_value("PATH")
            .unwrap()
            .split(';')
            .collect();
        assert_eq!(path[0], r"C:\Windows\System32");
        assert!(path.contains(&r"C:\ProgramData\wpkg\bin"), "{path:?}");
        assert!(path.contains(&r"C:\Windows\System32\WindowsPowerShell\v1.0\"));
        // npm's own Windows defaults exist without any path redirection.
        for directory in [
            r"C:\Users\runner\AppData\Local\npm-cache\_cacache\tmp",
            r"C:\Users\runner\AppData\Local\npm-cache\_logs",
            r"C:\Users\runner\AppData\Roaming\npm",
        ] {
            assert!(shell.fs.is_dir(directory), "missing {directory}");
        }
        assert!(!shell
            .fs
            .is_symlink(r"C:\Users\runner\AppData\Local\npm-cache"));
        assert!(!shell.fs.exists(r"C:\.system"));
        assert!(SHELL_HISTORY_PATH.starts_with(system_profile::APP_DATA));
    }

    #[test]
    fn seed_copies_a_host_file_only_into_the_session_image() {
        let host = std::env::temp_dir().join(format!("winrun-seed-{}.txt", std::process::id()));
        std::fs::write(&host, b"seeded").unwrap();
        let mut shell = Shell::new();
        shell
            .seed_host_file(host.to_str().unwrap(), r"C:\actions-runner\_work\in.txt")
            .unwrap();
        assert_eq!(
            shell
                .fs
                .read_file(r"C:\actions-runner\_work\in.txt")
                .unwrap(),
            b"seeded"
        );
        std::fs::remove_file(host).ok();
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
    fn streaming_shell_execution_forwards_guest_output_to_sink() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/artifacts/exe/hello.exe");
        let mut shell = Shell::new();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_received = Arc::clone(&received);
        let sink: backend::OutputSink = Arc::new(move |channel, chunk| {
            assert_eq!(channel, backend::OutputChannel::Stdout);
            sink_received.lock().unwrap().extend_from_slice(chunk);
        });
        let mut buffered = Vec::new();
        shell
            .exec_line_streaming(path.to_str().unwrap(), &mut buffered, sink)
            .unwrap();
        assert!(buffered.is_empty());
        assert_eq!(*received.lock().unwrap(), b"Hello from Windows");
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
        assert!(err.contains("wpkg install frobnicate"), "err: {err}");
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
    fn wpkg_and_inspect_need_args() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        assert!(shell
            .exec_line("wpkg", &mut out)
            .unwrap_err()
            .contains("usage: wpkg"));
        assert!(shell.exec_line("inspect", &mut out).is_err());
    }

    #[test]
    fn wpkg_install_failure_has_failure_emoji() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        let error = shell
            .exec_line("wpkg install missing-package", &mut out)
            .unwrap_err();
        assert!(error.contains("❌ wpkg failed"), "{error}");
    }

    #[test]
    fn snapshot_save_without_a_default_path_explains_how_to_set_one() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        let error = shell.exec_line("snapshot save", &mut out).unwrap_err();
        assert!(error.contains("no snapshot path is active"), "{error}");
    }

    #[test]
    fn bad_exe_and_inspect_errors() {
        let p = std::env::temp_dir().join(format!("winrun-shell-{}-junk.exe", std::process::id()));
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
    fn common_filesystem_commands_operate_on_the_guest_c_drive() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        let initial_cwd = shell.cwd();

        shell.exec_line("mkdir work\\nested", &mut out).unwrap();
        shell
            .fs
            .write_file("work\\nested\\hello.txt", b"hello".to_vec())
            .unwrap();
        shell.exec_line("cd work\\nested", &mut out).unwrap();
        assert_eq!(shell.cwd(), format!("{initial_cwd}\\work\\nested"));
        shell.exec_line("pwd", &mut out).unwrap();
        assert!(String::from_utf8_lossy(&out).ends_with(&format!("{}\n", shell.cwd())));

        shell.exec_line("dir", &mut out).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("hello.txt"));
        out.clear();
        shell.exec_line("type hello.txt", &mut out).unwrap();
        assert_eq!(out, b"hello\n");

        shell
            .exec_line("copy hello.txt copy.txt", &mut out)
            .unwrap();
        assert_eq!(shell.fs.read_file("copy.txt").unwrap(), b"hello");
        shell
            .exec_line("move copy.txt moved.txt", &mut out)
            .unwrap();
        assert!(!shell.fs.exists("copy.txt"));
        assert!(shell.fs.exists("moved.txt"));
        shell.exec_line("del moved.txt", &mut out).unwrap();
        assert!(!shell.fs.exists("moved.txt"));

        shell.exec_line("cd /d C:\\", &mut out).unwrap();
        assert_eq!(shell.cwd(), r"C:\");
        shell
            .exec_line(&format!("rmdir /s \"{initial_cwd}\\work\""), &mut out)
            .unwrap();
        assert!(!shell.fs.exists(&format!("{initial_cwd}\\work")));
    }

    #[test]
    fn common_filesystem_commands_report_usage_and_path_errors() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        assert!(shell
            .exec_line("cd one two", &mut out)
            .unwrap_err()
            .contains("usage"));
        assert!(shell
            .exec_line("copy one", &mut out)
            .unwrap_err()
            .contains("usage"));
        assert!(shell
            .exec_line("type missing.txt", &mut out)
            .unwrap_err()
            .contains("type:"));
        assert!(shell
            .exec_line("cd missing", &mut out)
            .unwrap_err()
            .contains("cd:"));
    }

    #[test]
    fn tab_completion_offers_commands_and_current_directory_paths() {
        let mut shell = Shell::new();
        let initial_cwd = shell.cwd();
        shell.fs.mkdir("Documents").unwrap();
        shell.fs.write_file("notes.txt", b"hello".to_vec()).unwrap();
        let mut helper = ShellHelper::default();
        helper.refresh(&shell.fs, &shell.sess.environment);

        let (_, command_candidates) = helper.complete_line("wp", 2);
        assert!(command_candidates
            .iter()
            .any(|candidate| candidate.replacement == "wpkg"));
        let (_, ps_candidates) = helper.complete_line("Rename-I", 8);
        assert!(ps_candidates
            .iter()
            .any(|candidate| candidate.replacement == "rename-item"));

        let (_, path_candidates) = helper.complete_line("cd Doc", 6);
        assert!(path_candidates
            .iter()
            .any(|candidate| candidate.replacement == "Documents\\"));
        let (_, file_candidates) = helper.complete_line("type not", 8);
        assert!(file_candidates
            .iter()
            .any(|candidate| candidate.replacement == "notes.txt"));

        shell.fs.set_cwd("Documents").unwrap();
        shell
            .fs
            .write_file("inside.txt", b"inside".to_vec())
            .unwrap();
        helper.refresh(&shell.fs, &shell.sess.environment);
        let (_, nested_candidates) = helper.complete_line("type ins", 8);
        assert!(nested_candidates
            .iter()
            .any(|candidate| candidate.replacement == "inside.txt"));
        assert_eq!(shell.cwd(), format!("{initial_cwd}\\Documents"));
    }

    #[test]
    fn path_lookup_follows_pathext_order_and_keeps_typed_extensions() {
        let mut shell = Shell::new();
        shell.set_environment_value(
            "PATHEXT".to_string(),
            Some(".COM;.EXE;.JS;.CMD".to_string()),
        );
        assert_eq!(
            shell.path_candidates(r"C:\tools", "tsc"),
            [
                r"C:\tools\tsc.com",
                r"C:\tools\tsc.exe",
                r"C:\tools\tsc.cmd"
            ]
        );
        assert_eq!(
            shell.path_candidates(r"C:\tools", "tsc.CMD"),
            [r"C:\tools\tsc.CMD"]
        );
        assert!(is_batch_file(r"C:\x\run.BAT") && !is_batch_file(r"C:\x\run.exe"));
    }

    #[test]
    fn split_line_quotes() {
        assert_eq!(split_line("rg \"foo bar\" -i"), vec!["rg", "foo bar", "-i"]);
        assert_eq!(split_line("echo 'a b'"), vec!["echo", "a b"]);
        assert_eq!(split_line("  "), Vec::<String>::new());
    }

    #[test]
    fn wpkg_uses_embedded_registry_without_network_for_search_and_info() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        shell.exec_line("wpkg search node", &mut out).unwrap();
        assert_eq!(out, b"nodejs\n");
        out.clear();
        shell.exec_line("wpkg info nodejs@24", &mut out).unwrap();
        assert!(String::from_utf8_lossy(&out)
            .contains(&format!("nodejs 24.21.0 ({})", wpkg::host_architecture())));
        assert!(shell.exec_line("choco --version", &mut Vec::new()).is_err());
        assert!(shell
            .exec_line("winget --version", &mut Vec::new())
            .is_err());
    }

    #[test]
    fn active_node_global_commands_follow_version_selection_and_restore() {
        let mut fs = WinFs::ephemeral_runner();
        let bin = format!(r"{}\node.exe", wpkg::BIN);
        let old = r"C:\Program Files\nodejs\24\node.exe";
        let new = r"C:\Program Files\nodejs\26\node.exe";
        fs.mkdir(wpkg::BIN).unwrap();
        for path in [old, new] {
            fs.mkdir(path.rsplit_once('\\').unwrap().0).unwrap();
            fs.write_file(path, vec![0]).unwrap();
        }
        fs.create_symlink(&bin, old, false).unwrap();
        let mut shell = Shell::with_fs(fs);
        let path = shell.environment_value("PATH").unwrap();
        assert!(path
            .split(';')
            .any(|entry| entry == r"C:\Program Files\nodejs\24"));
        assert!(path
            .split(';')
            .any(|entry| entry == r"C:\Users\runner\AppData\Roaming\npm"));
        let mut out = Vec::new();
        shell
            .fs
            .write_file(
                r"C:\Program Files\nodejs\24\global-cli.cmd",
                b"@echo old %*\r\n".to_vec(),
            )
            .unwrap();
        shell.exec_line("global-cli works", &mut out).unwrap();
        assert_eq!(out, b"old works\r\n");
        shell.fs.delete_file(&bin).unwrap();
        shell.fs.create_symlink(&bin, new, false).unwrap();
        shell
            .fs
            .write_file(
                r"C:\Program Files\nodejs\26\global-cli.cmd",
                b"@echo new %*\r\n".to_vec(),
            )
            .unwrap();
        out.clear();
        shell.exec_line("global-cli switched", &mut out).unwrap();
        assert_eq!(out, b"new switched\r\n");
        shell.exec_line("reload", &mut out).unwrap();
        shell.exec_line("reload", &mut out).unwrap();
        let path = shell.environment_value("PATH").unwrap();
        assert!(!path.contains(r"nodejs\24"));
        assert_eq!(
            path.split(';')
                .filter(|entry| entry.ends_with(r"nodejs\26"))
                .count(),
            1
        );
        shell.exec_line(r"set PATH=C:\custom", &mut out).unwrap();
        shell.exec_line("echo unchanged", &mut out).unwrap();
        assert_eq!(shell.environment_value("PATH"), Some(r"C:\custom"));
        shell.fs.delete_file(&bin).unwrap();
        shell.refresh_node_path();
        assert_eq!(shell.environment_value("PATH"), Some(r"C:\custom"));
    }

    #[test]
    fn reload_refreshes_saved_environment_and_preserves_shell_state() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        shell.exec_line("$keep = retained", &mut out).unwrap();
        shell
            .exec_line("function Keep { echo function-retained }", &mut out)
            .unwrap();
        shell.exec_line(r"cd C:\Windows", &mut out).unwrap();
        shell
            .exec_line("set TEMPORARY_ONLY=removed", &mut out)
            .unwrap();
        shell.exec_line("setx RELOAD_TEST saved", &mut out).unwrap();
        assert_eq!(shell.environment_value("RELOAD_TEST"), None);
        out.clear();
        let before = shell.sess.environment.clone();
        assert_eq!(
            shell.exec_line("reload extra", &mut out).unwrap_err(),
            "usage: reload"
        );
        assert_eq!(shell.sess.environment, before);
        assert!(out.is_empty());
        shell.last_code = 7;
        shell.exec_line("reload", &mut out).unwrap();
        assert_eq!(out, b"Environment reloaded.\n");
        assert_eq!(shell.environment_value("RELOAD_TEST"), Some("saved"));
        assert_eq!(shell.environment_value("TEMPORARY_ONLY"), None);
        assert_eq!(shell.cwd(), r"C:\Windows");
        assert_eq!(shell.last_code(), 0);
        out.clear();
        shell.exec_line("echo $keep", &mut out).unwrap();
        shell.exec_line("Keep", &mut out).unwrap();
        assert_eq!(out, b"retained\nfunction-retained\n");
        assert!(SHELL_COMMANDS.contains(&"reload"));
    }

    #[test]
    fn npm_without_nodejs_hints_wpkg() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        let err = shell.exec_line("npm -v", &mut out).unwrap_err();
        assert!(err.contains("wpkg install nodejs"), "err: {err}");
    }

    #[test]
    fn powershell_command_passthrough_runs_ps1() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        shell
            .exec_line("powershell -NoProfile -c \"echo ps-ok\"", &mut out)
            .unwrap();
        assert_eq!(out, b"ps-ok\n");
    }

    #[test]
    fn powershell_exe_shell_link_is_seeded_and_runs_the_same_handler() {
        let mut shell = Shell::new();
        assert!(is_powershell_shell_link(
            &shell.fs,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ));
        let mut out = Vec::new();
        shell
            .exec_line(
                "powershell.exe -NoProfile -Command \"Write-Output 'linked-ok'\"",
                &mut out,
            )
            .unwrap();
        assert_eq!(out, b"linked-ok\n");
    }

    #[test]
    fn powershell_needs_a_script() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        let err = shell.exec_line("powershell", &mut out).unwrap_err();
        assert!(err.contains("usage"), "err: {err}");
    }
}
