//! `GetFullPathNameW` as Windows computes it (`RtlGetFullPathName_U`): a
//! pure string transformation of the path against the current directory,
//! which never looks at the disk. The rules are checked against real Windows
//! by the `fs_paths` oracle probe (tests/oracle).

/// Legacy DOS device names that a bare final component maps to
/// (`nul` -> `\\.\nul`).
const DEVICES: [&str; 26] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "conin$",
    "conout$", "com0", "lpt0",
];

fn is_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

/// A full path and the byte offset of its file part (the text after the last
/// separator), or `None` when the path ends in a separator or names a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullPath {
    pub path: String,
    pub file_part: Option<usize>,
}

/// `raw` resolved the way `GetFullPathNameW` resolves it. `cwd` is the
/// current directory (`C:\dir`); `drive_cwd` gives another drive's
/// remembered directory for drive-relative paths (`D:foo`). The error is the
/// Win32 code Windows reports (`ERROR_INVALID_NAME` for an empty path).
pub fn full_path_name(raw: &str, cwd: &str, drive_cwd: impl Fn(char) -> Option<String>) -> Result<FullPath, u32> {
    const ERROR_INVALID_NAME: u32 = 123;
    if raw.is_empty() {
        return Err(ERROR_INVALID_NAME);
    }
    let chars: Vec<char> = raw.chars().collect();
    let sep = |index: usize| chars.get(index).copied().is_some_and(is_separator);

    // (root kept verbatim, remainder to normalize, whether the final
    // component may name a DOS device)
    let (root, rest, device_candidate): (String, String, bool) = if sep(0) && sep(1) {
        if matches!(chars.get(2), Some('.') | Some('?')) && (sep(3) || chars.len() == 3) {
            // Local device (`\\.\`) or root local device (`\\?\`).
            let prefix: String = ['\\', '\\', chars[2], '\\'].iter().collect();
            (prefix, chars.iter().skip(4).collect(), false)
        } else {
            // UNC: `\\server\share\` is the root.
            let body: String = chars.iter().skip(2).collect();
            let mut parts = body.splitn(3, is_separator);
            let server = parts.next().unwrap_or("");
            let share = parts.next();
            let rest = parts.next().unwrap_or("");
            let root = match share {
                Some(share) => format!("\\\\{server}\\{share}\\"),
                None => format!("\\\\{server}\\"),
            };
            (root, rest.to_string(), false)
        }
    } else if chars.len() >= 2 && chars[1] == ':' && chars[0].is_ascii_alphabetic() {
        let drive = chars[0].to_ascii_uppercase();
        let after: String = chars.iter().skip(2).collect();
        if sep(2) {
            (format!("{}:\\", chars[0]), after.chars().skip(1).collect(), true)
        } else {
            // Drive-relative: against that drive's current directory.
            let current_drive = cwd.chars().next().map(|c| c.to_ascii_uppercase());
            let base = if current_drive == Some(drive) {
                cwd.to_string()
            } else {
                drive_cwd(drive).unwrap_or_else(|| format!("{drive}:\\"))
            };
            let base_root: String = base.chars().take(3).collect();
            let base_rest: String = base.chars().skip(3).collect();
            (base_root, join(&base_rest, &after), true)
        }
    } else if sep(0) {
        // Rooted: the current drive's root.
        let root: String = cwd.chars().take(3).collect();
        (root, chars.iter().skip(1).collect(), true)
    } else {
        let root: String = cwd.chars().take(3).collect();
        let cwd_rest: String = cwd.chars().skip(3).collect();
        (root, join(&cwd_rest, raw), true)
    };

    let trailing_separator = rest.chars().last().is_some_and(is_separator);
    let mut components: Vec<String> = Vec::new();
    let segments: Vec<&str> = rest.split(is_separator).collect();
    let last_index = segments.len().saturating_sub(1);
    for (index, segment) in segments.iter().enumerate() {
        match *segment {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => {
                // Trailing dots and spaces go only from the final component.
                let segment = if index == last_index {
                    segment.trim_end_matches(['.', ' '])
                } else {
                    segment
                };
                if !segment.is_empty() {
                    components.push(segment.to_string());
                }
            }
        }
    }

    if device_candidate && !trailing_separator {
        if let Some(last) = components.last() {
            let name = last.trim_end_matches([' ', '.']);
            if DEVICES.iter().any(|device| device.eq_ignore_ascii_case(name)) {
                return Ok(FullPath { path: format!("\\\\.\\{name}"), file_part: None });
            }
        }
    }

    let mut path = root;
    path.push_str(&components.join("\\"));
    if trailing_separator && !components.is_empty() {
        path.push('\\');
    }
    let file_part = if path.ends_with('\\') {
        None
    } else {
        path.rfind('\\').map(|index| index + 1)
    };
    Ok(FullPath { path, file_part })
}

fn join(base: &str, relative: &str) -> String {
    if base.is_empty() {
        relative.to_string()
    } else {
        format!("{base}\\{relative}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: &str = r"C:\run\oracle-fs";

    fn full(raw: &str) -> (String, Option<String>) {
        let result = full_path_name(raw, W, |_| None).unwrap();
        let file = result.file_part.map(|index| result.path[index..].to_string());
        (result.path, file)
    }

    #[test]
    fn matches_the_windows_oracle_transcript() {
        // tests/oracle/golden/fs_paths.txt, recorded on windows-latest.
        assert_eq!(full("One.txt"), (format!(r"{W}\One.txt"), Some("One.txt".into())));
        assert_eq!(full(r".\One.txt").0, format!(r"{W}\One.txt"));
        assert_eq!(full(r"Sub Dir\..\One.txt").0, format!(r"{W}\One.txt"));
        assert_eq!(full("Sub Dir/two.txt").0, format!(r"{W}\Sub Dir\two.txt"));
        assert_eq!(full("Sub Dir//two.txt").0, format!(r"{W}\Sub Dir\two.txt"));
        assert_eq!(full(r"Sub Dir\.\two.txt").0, format!(r"{W}\Sub Dir\two.txt"));
        assert_eq!(full("One.txt. .").0, format!(r"{W}\One.txt"));
        assert_eq!(full("One.txt  ").0, format!(r"{W}\One.txt"));
        assert_eq!(full(r"a\...\b"), (format!(r"{W}\a\...\b"), Some("b".into())));
        assert_eq!(full(r"\One.txt"), (r"C:\One.txt".into(), Some("One.txt".into())));
        assert_eq!(full("C:One.txt").0, format!(r"{W}\One.txt"));
        assert_eq!(full("C:/x/../One.txt").0, r"C:\One.txt");
        assert_eq!(full("..").0, r"C:\run");
        assert_eq!(full(".").0, W);
        assert_eq!(full(r"Sub Dir\"), (format!(r"{W}\Sub Dir\"), None));
        assert_eq!(full(r"C:\..\..\x").0, r"C:\x");
        assert_eq!(full("One.txt:alt").0, format!(r"{W}\One.txt:alt"));
        assert_eq!(full(&format!(r"\\?\{W}\One.txt/x/..")).0, format!(r"\\?\{W}\One.txt"));
        assert_eq!(full("nul"), (r"\\.\nul".into(), None));
        assert_eq!(full("con"), (r"\\.\con".into(), None));
        assert_eq!(full("NUL.txt").0, format!(r"{W}\NUL.txt"));
        assert_eq!(full("com1.log").0, format!(r"{W}\com1.log"));
        assert_eq!(full(r"\\.\nul"), (r"\\.\nul".into(), Some("nul".into())));
        assert_eq!(full(r"\\server\share\a\..\b").0, r"\\server\share\b");
        assert_eq!(full_path_name("", W, |_| None), Err(123));
    }

    #[test]
    fn drive_relative_paths_use_that_drives_directory() {
        let other = |drive: char| (drive == 'D').then(|| r"D:\data".to_string());
        assert_eq!(full_path_name("D:x.txt", W, other).unwrap().path, r"D:\data\x.txt");
        assert_eq!(full_path_name("E:x.txt", W, other).unwrap().path, r"E:\x.txt");
        assert_eq!(full_path_name(r"\\server\share\..\..", W, other).unwrap().path, r"\\server\share\");
    }
}
