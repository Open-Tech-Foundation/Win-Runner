//! `find.exe`, `sort.exe` and `more.com`, which Windows ships in System32:
//! line filters over files or standard input, writing CRLF lines.

/// What the tools need from the process they run in.
pub trait TextHost {
    fn read_stdin(&mut self) -> Vec<u8>;
    /// A file's bytes; `None` when it cannot be read.
    fn read_file(&mut self, path: &str) -> Option<Vec<u8>>;
    fn write_file(&mut self, path: &str, bytes: &[u8]) -> bool;
    fn stdout(&mut self, bytes: &[u8]);
    fn stderr(&mut self, text: &str);
}

/// Text lines without their line endings (a final empty line dropped).
fn lines(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines: Vec<String> = text.split('\n').map(|line| line.strip_suffix('\r').unwrap_or(line).to_string()).collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

/// `find [/V] [/C] [/N] [/I] "string" [files...]`: 0 when a line was
/// found, 1 when none (a missing file is reported and finds nothing), 2 on
/// bad usage.
pub fn find(host: &mut dyn TextHost, arguments: &[String]) -> i32 {
    let (mut invert, mut count, mut numbers, mut ignore_case) = (false, false, false, false);
    let mut needle: Option<String> = None;
    let mut files = Vec::new();
    for argument in arguments {
        if let Some(switch) = argument.strip_prefix('/') {
            match switch.to_ascii_uppercase().as_str() {
                "V" => invert = true,
                "C" => count = true,
                "N" => numbers = true,
                "I" => ignore_case = true,
                "OFF" | "OFFLINE" => {}
                _ => {
                    host.stderr("FIND: Invalid switch\r\n");
                    return 2;
                }
            }
        } else if needle.is_none() {
            // The string must be quoted; the quotes have been removed by
            // the command line, so a quoted argument arrives as itself.
            needle = Some(argument.clone());
        } else {
            files.push(argument.clone());
        }
    }
    let Some(needle) = needle else {
        host.stderr("FIND: Parameter format not correct\r\n");
        return 2;
    };
    let matches = |line: &str| {
        let found = if ignore_case { line.to_lowercase().contains(&needle.to_lowercase()) } else { line.contains(&needle) };
        found != invert
    };
    let mut any = false;
    let mut search = |host: &mut dyn TextHost, bytes: &[u8], header: Option<&str>| {
        let selected: Vec<(usize, String)> =
            lines(bytes).into_iter().enumerate().filter(|(_, line)| matches(line)).collect();
        any |= !selected.is_empty();
        let mut out = String::new();
        match (header, count) {
            (Some(name), true) => out.push_str(&format!("\r\n---------- {}: {}\r\n", name.to_uppercase(), selected.len())),
            (None, true) => out.push_str(&format!("{}\r\n", selected.len())),
            (Some(name), false) => out.push_str(&format!("\r\n---------- {}\r\n", name.to_uppercase())),
            (None, false) => {}
        }
        if !count {
            for (index, line) in selected {
                if numbers {
                    out.push_str(&format!("[{}]", index + 1));
                }
                out.push_str(&line);
                out.push_str("\r\n");
            }
        }
        host.stdout(out.as_bytes());
    };
    if files.is_empty() {
        let input = host.read_stdin();
        search(host, &input, None);
    } else {
        for file in &files {
            match host.read_file(file) {
                Some(bytes) => search(host, &bytes, Some(file)),
                None => host.stderr(&format!("File not found - {}\r\n", file.to_uppercase())),
            }
        }
    }
    if any {
        0
    } else {
        1
    }
}

/// `sort [/R] [/+n] [file] [/O output]`: lines in case-insensitive order
/// from column n.
pub fn sort(host: &mut dyn TextHost, arguments: &[String]) -> i32 {
    let mut reverse = false;
    let mut column = 1usize;
    let mut input = None;
    let mut output = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        index += 1;
        match argument.strip_prefix('/') {
            Some(switch) if switch.eq_ignore_ascii_case("R") || switch.eq_ignore_ascii_case("REVERSE") => reverse = true,
            Some(switch) if switch.starts_with('+') => match switch[1..].parse::<usize>() {
                Ok(n) if n >= 1 => column = n,
                _ => {
                    host.stderr("Invalid switch.\r\n");
                    return 1;
                }
            },
            Some(switch) if switch.eq_ignore_ascii_case("O") || switch.eq_ignore_ascii_case("OUTPUT") => {
                let Some(path) = arguments.get(index) else {
                    host.stderr("Invalid switch.\r\n");
                    return 1;
                };
                output = Some(path.clone());
                index += 1;
            }
            Some(_) => {
                host.stderr("Invalid switch.\r\n");
                return 1;
            }
            None => input = Some(argument.clone()),
        }
    }
    let bytes = match &input {
        Some(path) => match host.read_file(path) {
            Some(bytes) => bytes,
            None => {
                host.stderr("The system cannot find the file specified.\r\n");
                return 1;
            }
        },
        None => host.read_stdin(),
    };
    let mut sorted = lines(&bytes);
    let key = |line: &String| line.chars().skip(column - 1).collect::<String>().to_lowercase();
    sorted.sort_by_key(key);
    if reverse {
        sorted.reverse();
    }
    let mut text = String::new();
    for line in sorted {
        text.push_str(&line);
        text.push_str("\r\n");
    }
    match output {
        Some(path) => {
            if !host.write_file(&path, text.as_bytes()) {
                host.stderr("The system cannot find the path specified.\r\n");
                return 1;
            }
        }
        None => host.stdout(text.as_bytes()),
    }
    0
}

/// `more [file...]` with output that is not a console: the text as CRLF
/// lines, tabs expanded to eight columns, then an empty line.
pub fn more(host: &mut dyn TextHost, arguments: &[String]) -> i32 {
    let files: Vec<&String> = arguments.iter().filter(|argument| !argument.starts_with('/')).collect();
    let mut inputs = Vec::new();
    if files.is_empty() {
        inputs.push(host.read_stdin());
    } else {
        for file in files {
            match host.read_file(file) {
                Some(bytes) => inputs.push(bytes),
                None => {
                    host.stderr(&format!("Cannot access file {}\r\n", file));
                    return 1;
                }
            }
        }
    }
    for bytes in inputs {
        let mut out = String::new();
        for line in lines(&bytes) {
            let mut width = 0;
            for c in line.chars() {
                if c == '\t' {
                    let spaces = 8 - width % 8;
                    out.extend(std::iter::repeat_n(' ', spaces));
                    width += spaces;
                } else {
                    out.push(c);
                    width += 1;
                }
            }
            out.push_str("\r\n");
        }
        host.stdout(out.as_bytes());
    }
    host.stdout(b"\r\n");
    0
}

/// Where Windows keeps each tool, and the private export its stub calls.
const TOOLS: [(&str, &str); 3] = [("find.exe", "WinrunFindMain"), ("sort.exe", "WinrunSortMain"), ("more.com", "WinrunMoreMain")];

/// Put the tools in System32 unless the disk already has them.
pub fn seed_text_tools(fs: &mut crate::winfs::WinFs) {
    if fs.mkdir(crate::system_profile::SYSTEM32).is_err() {
        return;
    }
    for (name, export) in TOOLS {
        let path = format!(r"{}\{name}", crate::system_profile::SYSTEM32);
        if !fs.is_file(&path) {
            let _ = fs.write_file(&path, crate::cmd::stub_image(export));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        stdin: Vec<u8>,
        files: HashMap<String, Vec<u8>>,
        out: Vec<u8>,
        err: String,
    }

    impl TextHost for Fake {
        fn read_stdin(&mut self) -> Vec<u8> {
            self.stdin.clone()
        }
        fn read_file(&mut self, path: &str) -> Option<Vec<u8>> {
            self.files.get(path).cloned()
        }
        fn write_file(&mut self, path: &str, bytes: &[u8]) -> bool {
            self.files.insert(path.to_string(), bytes.to_vec());
            true
        }
        fn stdout(&mut self, bytes: &[u8]) {
            self.out.extend_from_slice(bytes);
        }
        fn stderr(&mut self, text: &str) {
            self.err.push_str(text);
        }
    }

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn find_filters_counts_and_numbers_lines() {
        let mut host = Fake { stdin: b"apple\nBanana\ncherry\n".to_vec(), ..Default::default() };
        assert_eq!(find(&mut host, &args(&["an"])), 0);
        assert_eq!(host.out, b"Banana\r\n");
        let mut host = Fake { stdin: b"apple\nBanana\n".to_vec(), ..Default::default() };
        assert_eq!(find(&mut host, &args(&["/I", "/N", "A"])), 0);
        assert_eq!(host.out, b"[1]apple\r\n[2]Banana\r\n");
        let mut host = Fake { stdin: b"apple\nBanana\n".to_vec(), ..Default::default() };
        assert_eq!(find(&mut host, &args(&["/V", "/C", "apple"])), 0);
        assert_eq!(host.out, b"1\r\n");
        let mut host = Fake::default();
        host.files.insert("a.txt".into(), b"one\r\ntwo\r\n".to_vec());
        assert_eq!(find(&mut host, &args(&["two", "a.txt"])), 0);
        assert_eq!(host.out, b"\r\n---------- A.TXT\r\ntwo\r\n");
        assert_eq!(find(&mut host, &args(&["zzz", "a.txt"])), 1);
        assert_eq!(find(&mut host, &args(&["two", "missing.txt"])), 1, "a missing file finds nothing");
        assert!(host.err.contains("File not found - MISSING.TXT"));
        assert_eq!(find(&mut Fake::default(), &args(&[])), 2);
    }

    #[test]
    fn sort_orders_lines_without_case_and_by_column() {
        let mut host = Fake { stdin: b"b\nA\nc\n".to_vec(), ..Default::default() };
        assert_eq!(sort(&mut host, &args(&[])), 0);
        assert_eq!(host.out, b"A\r\nb\r\nc\r\n");
        let mut host = Fake { stdin: b"x2\ny1\n".to_vec(), ..Default::default() };
        assert_eq!(sort(&mut host, &args(&["/+2", "/R"])), 0);
        assert_eq!(host.out, b"x2\r\ny1\r\n");
        let mut host = Fake { stdin: b"b\na\n".to_vec(), ..Default::default() };
        assert_eq!(sort(&mut host, &args(&["/O", "out.txt"])), 0);
        assert_eq!(host.files["out.txt"], b"a\r\nb\r\n");
    }

    #[test]
    fn more_copies_text_with_tabs_expanded() {
        let mut host = Fake { stdin: b"a\tb\nline".to_vec(), ..Default::default() };
        assert_eq!(more(&mut host, &[]), 0);
        assert_eq!(host.out, b"a       b\r\nline\r\n\r\n");
    }
}
