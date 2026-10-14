//! `where.exe`, which Windows ships in System32: finds files matching
//! patterns in the current directory and the `PATH` directories (or under
//! one directory with `/R`), trying each `PATHEXT` extension for a pattern,
//! and prints their full paths.

/// What where.exe needs from the process it runs in.
pub trait WhereHost {
    fn variable(&mut self, name: &str) -> Option<String>;
    fn current_dir(&mut self) -> String;
    /// A directory's entries as `(name, is_directory)`, in listing order;
    /// `None` when it is not a directory.
    fn list_dir(&mut self, path: &str) -> Option<Vec<(String, bool)>>;
    fn stdout(&mut self, text: &str);
    fn stderr(&mut self, text: &str);
}

const USAGE_HINT: &str = "Type \"WHERE /?\" for usage.\n";
const NOT_FOUND: &str = "INFO: Could not find files for the given pattern(s).\n";

fn wildcard(pattern: &[char], text: &[char]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some('*'), _) => wildcard(&pattern[1..], text) || (!text.is_empty() && wildcard(pattern, &text[1..])),
        (Some('?'), Some(_)) => wildcard(&pattern[1..], &text[1..]),
        (Some(p), Some(t)) if p.to_lowercase().eq(t.to_lowercase()) => wildcard(&pattern[1..], &text[1..]),
        _ => false,
    }
}

/// Whether a file name matches the pattern as written or with one of the
/// executable extensions appended.
fn matches(pattern: &str, extensions: &[String], name: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    let bare: Vec<char> = pattern.chars().collect();
    wildcard(&bare, &name)
        || extensions.iter().any(|extension| {
            let with: Vec<char> = format!("{pattern}{extension}").chars().collect();
            wildcard(&with, &name)
        })
}

fn join(directory: &str, name: &str) -> String {
    format!("{}\\{name}", directory.trim_end_matches(['\\', '/']))
}

/// Run where with `arguments` (without the program name); the exit code:
/// 0 when every pattern matched, 1 when one did not, 2 on bad usage.
pub fn run(host: &mut dyn WhereHost, arguments: &[String]) -> i32 {
    let (mut quiet, mut quoted) = (false, false);
    let mut recurse: Option<String> = None;
    let mut patterns = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        index += 1;
        let Some(option) = argument.strip_prefix('/') else {
            patterns.push(argument.clone());
            continue;
        };
        match option.to_ascii_uppercase().as_str() {
            "Q" => quiet = true,
            "F" => quoted = true,
            "R" => match arguments.get(index) {
                Some(directory) => {
                    recurse = Some(directory.clone());
                    index += 1;
                }
                None => {
                    host.stderr(&format!("ERROR: Invalid syntax. Value expected for '/R'.\n{USAGE_HINT}"));
                    return 2;
                }
            },
            "?" => {
                host.stdout(
                    "\nWHERE [/R dir] [/Q] [/F] [/T] pattern...\n\nDescription:\n    Displays the location of files that match the search pattern.\n    By default, the search is done along the current directory and in\n    the paths specified by the PATH environment variable.\n",
                );
                return 0;
            }
            "T" => {
                host.stderr("ERROR: The /T option is not supported by this where.exe.\n");
                return 2;
            }
            _ => {
                host.stderr(&format!("ERROR: Invalid argument or option - '{argument}'.\n{USAGE_HINT}"));
                return 2;
            }
        }
    }
    if patterns.is_empty() {
        host.stderr(&format!("ERROR: A search pattern must be specified.\n{USAGE_HINT}"));
        return 2;
    }
    if let Some(pattern) = patterns.iter().find(|p| p.contains(':') || p.contains('\\')) {
        host.stderr(&format!("ERROR: The pattern form '{pattern}' is not supported by this where.exe.\n"));
        return 2;
    }
    let extensions: Vec<String> = host
        .variable("PATHEXT")
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .filter(|e| !e.is_empty())
        .map(str::to_string)
        .collect();
    let directories: Vec<String> = match &recurse {
        Some(root) => {
            if host.list_dir(root).is_none() {
                host.stderr("ERROR: The system cannot find the file specified.\n");
                return 2;
            }
            let mut all = Vec::new();
            let mut pending = vec![root.trim_end_matches(['\\', '/']).to_string()];
            while let Some(directory) = pending.pop() {
                let children: Vec<String> = host
                    .list_dir(&directory)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|(_, is_dir)| *is_dir)
                    .map(|(name, _)| join(&directory, &name))
                    .collect();
                all.push(directory);
                pending.extend(children.into_iter().rev());
            }
            all
        }
        None => {
            let mut directories = vec![host.current_dir()];
            for directory in host.variable("PATH").unwrap_or_default().split(';') {
                let directory = directory.trim();
                if !directory.is_empty()
                    && !directories
                        .iter()
                        .any(|d| d.trim_end_matches('\\').eq_ignore_ascii_case(directory.trim_end_matches('\\')))
                {
                    directories.push(directory.to_string());
                }
            }
            directories
        }
    };
    let mut missing = false;
    for pattern in &patterns {
        let mut found = false;
        for directory in &directories {
            for (name, is_dir) in host.list_dir(directory).unwrap_or_default() {
                if is_dir || !matches(pattern, &extensions, &name) {
                    continue;
                }
                found = true;
                if !quiet {
                    let path = join(directory, &name);
                    host.stdout(&if quoted { format!("\"{path}\"\n") } else { format!("{path}\n") });
                }
            }
        }
        missing |= !found;
    }
    if missing {
        if !quiet {
            host.stderr(NOT_FOUND);
        }
        return 1;
    }
    0
}

/// Where Windows keeps where.exe.
pub fn where_exe_path() -> String {
    format!(r"{}\where.exe", crate::system_profile::SYSTEM32)
}

/// Put `where.exe` in System32 unless the disk already has one.
pub fn seed_where_exe(fs: &mut crate::winfs::WinFs) {
    let path = where_exe_path();
    if fs.is_file(&path) || fs.mkdir(crate::system_profile::SYSTEM32).is_err() {
        return;
    }
    let _ = fs.write_file(&path, crate::cmd::stub_image("WinrunWhereMain"));
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        out: String,
        err: String,
    }

    impl WhereHost for Fake {
        fn variable(&mut self, name: &str) -> Option<String> {
            match name {
                "PATH" => Some(r"C:\Bin;C:\Tools\;C:\bin".into()),
                "PATHEXT" => Some(".COM;.EXE;.BAT".into()),
                _ => None,
            }
        }
        fn current_dir(&mut self) -> String {
            r"C:\Work".into()
        }
        fn list_dir(&mut self, path: &str) -> Option<Vec<(String, bool)>> {
            let entries: &[(&str, bool)] = match path.to_ascii_lowercase().trim_end_matches('\\') {
                r"c:\work" => &[("app.exe", false), ("notes.txt", false)],
                r"c:\bin" => &[("App.EXE", false), ("tool.bat", false), ("sub", true)],
                r"c:\bin\sub" => &[("app.exe", false)],
                r"c:\tools" => &[("tool.exe", false)],
                _ => return None,
            };
            Some(entries.iter().map(|(n, d)| (n.to_string(), *d)).collect())
        }
        fn stdout(&mut self, text: &str) {
            self.out.push_str(text);
        }
        fn stderr(&mut self, text: &str) {
            self.err.push_str(text);
        }
    }

    fn run_with(arguments: &[&str]) -> (i32, String, String) {
        let mut host = Fake { out: String::new(), err: String::new() };
        let code = run(&mut host, &arguments.iter().map(|a| a.to_string()).collect::<Vec<_>>());
        (code, host.out, host.err)
    }

    #[test]
    fn finds_by_extension_in_the_current_directory_then_path() {
        let (code, out, _) = run_with(&["app"]);
        assert_eq!(code, 0);
        assert_eq!(out, "C:\\Work\\app.exe\nC:\\Bin\\App.EXE\n", "a repeated PATH entry is searched once");
        let (_, out, _) = run_with(&["tool"]);
        assert_eq!(out, "C:\\Bin\\tool.bat\nC:\\Tools\\tool.exe\n");
        let (_, out, _) = run_with(&["*.txt", "/F"]);
        assert_eq!(out, "\"C:\\Work\\notes.txt\"\n");
    }

    #[test]
    fn missing_patterns_exit_1_and_usage_errors_exit_2() {
        assert_eq!(run_with(&["nope"]), (1, String::new(), NOT_FOUND.to_string()));
        assert_eq!(run_with(&["/Q", "nope"]), (1, String::new(), String::new()));
        assert_eq!(run_with(&["/Q", "app"]).0, 0);
        let (code, out, err) = run_with(&["app", "nope"]);
        assert_eq!((code, err.as_str()), (1, NOT_FOUND));
        assert!(out.contains("app.exe"));
        assert_eq!(run_with(&[]).0, 2);
        assert_eq!(run_with(&["/X", "a"]).0, 2);
    }

    #[test]
    fn recursion_walks_one_tree() {
        let (code, out, _) = run_with(&["/R", r"C:\Bin", "app"]);
        assert_eq!(code, 0);
        assert_eq!(out, "C:\\Bin\\App.EXE\nC:\\Bin\\sub\\app.exe\n");
    }
}
