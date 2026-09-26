//! Interactive and host-controlled runner shells with one fresh WinFs image
//! per session.
//!
//! Each input line is, in order: an `exit`/`quit`, a host-only `@seed`
//! injection directive, an `install`/`inspect` command, a host or guest
//! `.exe`/`.ps1` file, a cached package
//! (`name`, `name.exe`, `C:\bin\name.exe` + args), or a PS1 statement run
//! against the session filesystem. Guest console output streams exactly
//! like the one-shot CLI paths; errors print as `wincli: ...` and the
//! shell continues. `exit [n]`/`quit`, Ctrl-D (EOF), or a closed pipe ends
//! the session (code = argument, else the last guest code).

use crate::{backend, choco, inspect, install, pe, ps1, winfs::WinFs};
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
        Self::with_fs(WinFs::ephemeral_runner())
    }

    /// Start a session from a prebuilt ephemeral image, such as a decoded
    /// immutable snapshot. The image is owned by this session and discarded
    /// once it exits.
    pub fn with_fs(fs: WinFs) -> Self {
        Shell {
            fs,
            sess: ps1::Session::default(),
            last_code: 0,
        }
    }

    /// Windows working directory visible to the shell prompt and tests.
    pub fn cwd(&self) -> String {
        self.fs.cwd()
    }

    pub fn last_code(&self) -> i32 {
        self.last_code
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
            "install" => {
                let name = argv
                    .get(1)
                    .ok_or_else(|| "usage: install <pkg>".to_string())?;
                let inst = do_install(name)?;
                out.extend_from_slice(
                    format!(
                        "Installed {} {} → {}\n",
                        inst.name, inst.version, inst.guest_path
                    )
                    .as_bytes(),
                );
                Ok(ShellFlow::Continue)
            }
            "snapshot" => {
                self.do_snapshot(&argv[1..], out)?;
                Ok(ShellFlow::Continue)
            }
            "choco" => {
                self.do_choco(&argv[1..], out)?;
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
                let data = read_target_bytes(target)?;
                let report = inspect::inspect_pe(&data)
                    .map_err(|e| format!("cannot inspect {target}: {e}"))?;
                out.extend_from_slice(inspect::render(&report).as_bytes());
                Ok(ShellFlow::Continue)
            }
            _ => self.run_target_line(&argv, line, out, sink),
        }
    }

    /// Host file, cached package, or PS1 statement (in that order).
    fn run_target_line(
        &mut self,
        argv: &[String],
        line: &str,
        out: &mut Vec<u8>,
        sink: Option<backend::OutputSink>,
    ) -> Result<ShellFlow, String> {
        let target = &argv[0];
        if std::path::Path::new(target).is_file() {
            let ext = std::path::Path::new(target)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            match ext.as_str() {
                "exe" => return self.run_exe_file(target, target, &argv[1..], out, sink),
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
        if self.fs.is_file(target) {
            let data = self
                .fs
                .read_file(target)
                .map_err(|e| format!("cannot read guest executable {target}: {e}"))?;
            return self.run_exe_bytes(&data, target, &argv[1..], out, sink);
        }
        // Bare names resolve on the machine PATH (`C:\bin`), like a real
        // terminal: `7z` finds `C:\bin\7z.exe` installed on this disk.
        if !target.contains(['\\', '/', ':']) {
            for candidate in [format!(r"C:\bin\{target}"), format!(r"C:\bin\{target}.exe")] {
                if self.fs.is_file(&candidate) {
                    let data = self
                        .fs
                        .read_file(&candidate)
                        .map_err(|e| format!("cannot read guest executable {candidate}: {e}"))?;
                    return self.run_exe_bytes(&data, &candidate, &argv[1..], out, sink);
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
                sink,
            );
        }
        // Bare `npm` runs the cached Node.js distribution's npm-cli.js
        // through the cached node.exe (npm ships as JS, not a PE).
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
            Err(_) => Err(format!(
                "nothing to run: {target} (no such file; try `install {target}`)"
            )),
        }
    }

    /// Run an EXE with the session filesystem; the FS comes back with the
    /// exit code. A failed run resets the session to a clean runner image
    /// (the native runner has consumed its filesystem state).
    fn run_exe_file(
        &mut self,
        path: &str,
        prog: &str,
        guest_args: &[String],
        out: &mut Vec<u8>,
        sink: Option<backend::OutputSink>,
    ) -> Result<ShellFlow, String> {
        let data = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
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
        let img = pe::load_lenient(data).map_err(|e| format!("failed to load {prog}: {e}"))?;
        let fs = std::mem::replace(&mut self.fs, WinFs::ephemeral_runner());
        let backend =
            backend::configured().map_err(|e| format!("failed to select backend: {e}"))?;
        let streaming = sink.is_some();
        let result = match sink {
            Some(sink) => backend.execute_streaming(&img, fs, prog, guest_args, sink),
            None => backend.execute(&img, fs, prog, guest_args),
        }
        .map_err(|e| format!("{} execution failed: {e}", backend.id()))?;
        self.fs = result.fs;
        self.last_code = result.code as i32;
        if !streaming {
            out.extend_from_slice(&result.stdout);
        }
        Ok(ShellFlow::Continue)
    }

    /// `snapshot save <host-file>`: persist this session's disk image so
    /// a later `wincli --snapshot=<file> shell` (or `--save-snapshot`)
    /// resumes with every installation and file change intact.
    fn do_snapshot(&mut self, argv: &[String], out: &mut Vec<u8>) -> Result<(), String> {
        match argv.first().map(|s| s.to_lowercase()).as_deref() {
            Some("save") => {
                let path = argv
                    .get(1)
                    .ok_or_else(|| "usage: snapshot save <file>".to_string())?;
                if argv.len() != 2 {
                    return Err("usage: snapshot save <file>".to_string());
                }
                let bytes = crate::snapshot::encode(&self.fs);
                std::fs::write(path, &bytes)
                    .map_err(|e| format!("cannot save snapshot {path}: {e}"))?;
                self.last_code = 0;
                out.extend_from_slice(
                    format!("Saved snapshot {} ({} bytes)\n", path, bytes.len()).as_bytes(),
                );
                Ok(())
            }
            _ => Err("usage: snapshot save <file>".to_string()),
        }
    }
    /// `choco install nodejs [--version=X.Y.Z]`: fetch the official
    /// distribution, verify, and cache node.exe plus the bundled npm tree.
    /// `choco` itself is built into wincli (no bootstrap needed).
    fn do_choco(&mut self, argv: &[String], out: &mut Vec<u8>) -> Result<(), String> {
        match choco::parse_args(argv)? {
            choco::ChocoCmd::Version => {
                out.extend_from_slice(format!("wincli-choco {}\n", choco::SHIM_VERSION).as_bytes());
                Ok(())
            }
            choco::ChocoCmd::InstallNode { version } => {
                let cache = install::cache_dir();
                let inst = choco::install_nodejs(&version, &cache)?;
                self.seed_host_file(
                    &inst.node_exe_host.display().to_string(),
                    r"C:\bin\node.exe",
                )?;
                self.seed_npm_tree(&inst)?;
                self.last_code = 0;
                out.extend_from_slice(
                    format!(
                        "Installed nodejs {} → C:\\bin\\node.exe\nnpm {} ready as 'npm'\n",
                        inst.version, inst.npm_version
                    )
                    .as_bytes(),
                );
                Ok(())
            }
            choco::ChocoCmd::InstallCommunity { id, version } => {
                if id == "7zip.install" {
                    return self.install_7zip_guest(version.as_deref(), out);
                }
                let cache = install::cache_dir();
                let app = choco::install_community(&id, version.as_deref(), &cache)?;
                self.seed_choco_app(&app)?;
                self.last_code = 0;
                out.extend_from_slice(
                    format!(
                        "Installed {} {} → C:\\bin\\{}.exe\n",
                        app.name, app.version, app.name
                    )
                    .as_bytes(),
                );
                Ok(())
            }
        }
    }

    /// Install Chocolatey's `7zip.install` package by running its silent
    /// Windows installer against WinFS. The installer and resulting program
    /// files stay on the guest disk and therefore travel with snapshots.
    fn install_7zip_guest(
        &mut self,
        version: Option<&str>,
        out: &mut Vec<u8>,
    ) -> Result<(), String> {
        let (pkg, blob) = choco::download_community_nupkg("7zip.install", version)?;
        let tools = r"C:\ProgramData\chocolatey\lib\7zip.install\tools";
        let files = choco::extract_nupkg_tools_to_guest(&blob, &mut self.fs, tools)?;
        let installer = files
            .iter()
            .find(|path| {
                path.rsplit('\\')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("7zip_x64.exe"))
            })
            .ok_or_else(|| format!("choco: {} has no 64-bit 7-Zip installer", pkg.id))?;
        let bytes = self
            .fs
            .read_file(installer)
            .map_err(|e| format!("choco: cannot read guest installer: {e}"))?;
        let staged_disk = self.fs.clone();
        if let Err(error) = self.run_exe_bytes(&bytes, installer, &["/S".to_string()], out, None) {
            // A native guest crash consumes its moved WinFS. Keep the package
            // tools available so the caller can inspect or retry the install.
            self.fs = staged_disk;
            return Err(error);
        }
        if self.last_code != 0 {
            return Err(format!(
                "choco: 7-Zip guest installer exited with code {}",
                self.last_code
            ));
        }

        let (installed_path, installed) = self
            .fs
            .files()
            .into_iter()
            .find(|(path, _)| path.to_lowercase().ends_with(r"\7-zip\7z.exe"))
            .ok_or_else(|| {
                "choco: 7-Zip installer completed but did not create 7-Zip\\7z.exe".to_string()
            })?;
        let install_dir = installed_path
            .strip_suffix(r"\7z.exe")
            .unwrap_or(&installed_path);
        self.fs
            .mkdir(r"C:\bin")
            .map_err(|e| format!("choco: cannot create C:\\bin: {e}"))?;
        self.fs
            .write_file(r"C:\bin\7z.exe", installed)
            .map_err(|e| format!("choco: cannot install C:\\bin\\7z.exe: {e}"))?;
        self.last_code = 0;
        out.extend_from_slice(
            format!("Installed 7zip.install {} → {install_dir}\n", pkg.version).as_bytes(),
        );
        Ok(())
    }

    /// Copy a community app onto the guest disk. Keeping the app tree and
    /// PATH entry in WinFS makes it part of snapshots and removes runtime
    /// dependence on the host package cache.
    fn seed_choco_app(&mut self, app: &choco::ChocoApp) -> Result<(), String> {
        let mut files = Vec::new();
        collect_host_files(&app.dir_host, &mut files)
            .map_err(|e| format!("cannot seed {}: {e}", app.name))?;
        files.sort();
        for file in files {
            let rel = file
                .strip_prefix(&app.dir_host)
                .map_err(|_| "cannot seed Chocolatey app: bad path".to_string())?;
            let guest = format!(
                r"C:\apps\{}\{}",
                app.name,
                rel.to_string_lossy().replace('/', "\\")
            );
            self.seed_host_file(&file.display().to_string(), &guest)?;
        }
        let exe = app.exe_rel.rsplit('/').next().unwrap_or(&app.name);
        let exe_guest = format!(r"C:\apps\{}\{}", app.name, app.exe_rel.replace('/', "\\"));
        let bytes = self
            .fs
            .read_file(&exe_guest)
            .map_err(|e| format!("cannot seed {} executable: {e}", app.name))?;
        self.fs
            .mkdir(r"C:\bin")
            .map_err(|e| format!("cannot create command directory: {e}"))?;
        self.fs
            .write_file(&format!(r"C:\bin\{}.exe", app.name), bytes.clone())
            .map_err(|e| format!("cannot seed {} command: {e}", app.name))?;
        let stem = exe
            .strip_suffix(".exe")
            .or_else(|| exe.strip_suffix(".EXE"))
            .unwrap_or(exe);
        if !stem.eq_ignore_ascii_case(&app.name) {
            self.fs
                .write_file(&format!(r"C:\bin\{stem}.exe"), bytes)
                .map_err(|e| format!("cannot seed {} command: {e}", app.name))?;
        }
        Ok(())
    }

    /// Minimal `powershell -c <script>` passthrough so Windows install
    /// one-liners (`powershell -c "irm ...|iex"`) run as PS1 in-session.
    fn do_powershell(&mut self, argv: &[String], out: &mut Vec<u8>) -> Result<(), String> {
        let mut args = argv;
        // Swallow `-NoProfile`, `-NonInteractive`, `-NoLogo`,
        // `-ExecutionPolicy <policy>`.
        while let Some(first) = args.first() {
            let flag = first.to_lowercase();
            if flag == "-noprofile" || flag == "-noninteractive" || flag == "-nologo" {
                args = &args[1..];
            } else if flag == "-executionpolicy" {
                if args.len() < 2 {
                    return Err(
                        "usage: powershell [-NoProfile] -c <script> | powershell <script.ps1>"
                            .to_string(),
                    );
                }
                args = &args[2..];
            } else {
                break;
            }
        }
        let script = match args.first().map(|s| s.to_lowercase()) {
            Some(flag) if flag == "-command" || flag == "-c" || flag == "/c" => {
                if args.len() < 2 {
                    return Err("usage: powershell -c <script>".to_string());
                }
                args[1..].join(" ")
            }
            Some(_) if args.len() == 1 && args[0].to_lowercase().ends_with(".ps1") => {
                std::fs::read_to_string(&args[0])
                    .map_err(|e| format!("cannot read {}: {e}", args[0]))?
            }
            _ => {
                return Err(
                    "usage: powershell [-NoProfile] -c <script> | powershell <script.ps1>"
                        .to_string(),
                );
            }
        };
        let code = ps1::run_ps1_session(&mut self.sess, &mut self.fs, &script, out)
            .map_err(|e| format!("script error: {e}"))?;
        self.last_code = code;
        Ok(())
    }

    /// Run the cached npm CLI: seed the bundled npm tree into the session
    /// once, then execute it with the cached node.exe.
    fn run_npm(
        &mut self,
        guest_args: &[String],
        out: &mut Vec<u8>,
        sink: Option<backend::OutputSink>,
    ) -> Result<ShellFlow, String> {
        let node_guest = r"C:\bin\node.exe";
        let npm_guest = choco::npm_cli_guest();
        if let (Ok(node), Ok(_)) = (self.fs.read_file(node_guest), self.fs.read_file(npm_guest)) {
            let mut args = vec![npm_guest.to_string()];
            args.extend_from_slice(guest_args);
            return self.run_exe_bytes(&node, "node", &args, out, sink);
        }
        let cache = install::cache_dir();
        let inst = choco::current_nodejs(&cache).ok_or_else(|| {
            "nothing to run: npm (no nodejs; try `choco install nodejs`)".to_string()
        })?;
        if !inst.node_exe_host.is_file() {
            return Err(
                "nothing to run: npm (cached node.exe is missing; try `choco install nodejs`)"
                    .to_string(),
            );
        }
        self.seed_host_file(&inst.node_exe_host.display().to_string(), node_guest)?;
        self.seed_npm_tree(&inst)?;
        let data = self
            .fs
            .read_file(node_guest)
            .map_err(|e| format!("cannot read guest node.exe: {e}"))?;
        let mut args = vec![npm_guest.to_string()];
        args.extend_from_slice(guest_args);
        self.run_exe_bytes(&data, "node", &args, out, sink)
    }

    /// One-way host-to-guest copy of the cached npm tree (`C:\npm`),
    /// skipped when this session already seeded the same version.
    fn seed_npm_tree(&mut self, inst: &choco::NodeInstalled) -> Result<(), String> {
        const MARKER: &str = r"C:\npm\.wincli-seeded";
        if self
            .fs
            .read_file(MARKER)
            .is_ok_and(|have| have == inst.version.as_bytes())
        {
            return Ok(());
        }
        let mut files = Vec::new();
        collect_host_files(&inst.npm_root_host, &mut files)
            .map_err(|e| format!("cannot seed npm: {e}"))?;
        files.sort();
        for file in files {
            let rel = file
                .strip_prefix(&inst.npm_root_host)
                .map_err(|_| "cannot seed npm: bad path".to_string())?;
            let guest = format!(r"C:\npm\{}", rel.to_string_lossy().replace('/', "\\"));
            self.seed_host_file(&file.display().to_string(), &guest)?;
        }
        self.fs
            .write_file(MARKER, inst.version.as_bytes().to_vec())
            .map_err(|e| format!("cannot seed npm: {e}"))?;
        Ok(())
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

/// Recursively collect host files under `root` (for npm tree seeding).
fn collect_host_files(
    root: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_host_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
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

fn run_session(fs: WinFs, prompt_enabled: bool) -> (i32, WinFs) {
    let stdin = std::io::stdin();
    let tty = prompt_enabled && std::io::IsTerminal::is_terminal(&stdin);
    let mut shell = Shell::with_fs(fs);
    let prompt = |shell: &Shell| {
        if tty {
            eprint!("PS {}> ", shell.cwd());
            let _ = std::io::stderr().flush();
        }
    };
    prompt(&shell);
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
                return (code, shell.fs);
            }
            Err(e) => {
                // Flush partial output first (a real shell streams).
                let _ = std::io::stdout().write_all(&out);
                eprintln!("wincli: {e}");
            }
        }
        prompt(&shell);
    }
    (shell.last_code, shell.fs)
}

/// Interactive loop. Returns the process exit code. The prompt goes to
/// stderr (stdout stays clean for pipes); EOF ends with the last code.
pub fn run_shell() -> (i32, WinFs) {
    run_session(WinFs::ephemeral_runner(), true)
}

/// Run an interactive shell from a decoded snapshot image.
pub fn run_shell_with_fs(fs: WinFs) -> (i32, WinFs) {
    run_session(fs, true)
}

/// Host-controlled runner loop. It consumes job commands from standard input
/// without a prompt, boots one fresh ephemeral WinFs image, and destroys that
/// image when the input closes. This is the local control-plane seam for a
/// future GitHub Actions protocol adapter.
pub fn run_runner() -> (i32, WinFs) {
    run_session(WinFs::ephemeral_runner(), false)
}

/// Run a host-controlled session from a decoded snapshot image.
pub fn run_runner_with_fs(fs: WinFs) -> (i32, WinFs) {
    run_session(fs, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests below mutate `WINCLI_CACHE`; serialize them.
    static CACHE_ENV_LOCK: Mutex<()> = Mutex::new(());

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
    fn shell_boots_an_ephemeral_runner_image() {
        let shell = Shell::new();
        assert_eq!(shell.cwd(), r"C:\actions-runner\_work");
    }

    #[test]
    fn seed_copies_a_host_file_only_into_the_session_image() {
        let host = std::env::temp_dir().join(format!("wincli-seed-{}.txt", std::process::id()));
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

    #[test]
    fn choco_reports_builtin_version() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        shell.exec_line("choco --version", &mut out).unwrap();
        assert_eq!(
            out,
            format!("wincli-choco {}\n", choco::SHIM_VERSION).as_bytes()
        );
    }

    #[test]
    fn choco_rejects_unknown_packages_and_options() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        let err = shell.exec_line("choco", &mut out).unwrap_err();
        assert!(err.contains("usage"), "err: {err}");
        let err = shell
            .exec_line("choco install python", &mut out)
            .unwrap_err();
        assert!(err.contains("no such package"), "err: {err}");
    }

    #[test]
    fn npm_without_nodejs_hints_choco() {
        let _guard = CACHE_ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("wincli-npm-hint-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("WINCLI_CACHE", &dir);
        let mut shell = Shell::new();
        let mut out = Vec::new();
        let err = shell.exec_line("npm -v", &mut out).unwrap_err();
        assert!(err.contains("choco install nodejs"), "err: {err}");
        std::env::remove_var("WINCLI_CACHE");
        std::fs::remove_dir_all(&dir).ok();
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
    fn powershell_needs_a_script() {
        let mut shell = Shell::new();
        let mut out = Vec::new();
        let err = shell.exec_line("powershell", &mut out).unwrap_err();
        assert!(err.contains("usage"), "err: {err}");
    }
}
