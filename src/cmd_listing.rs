//! cmd.exe's file built-ins: `dir`, `ren`/`rename`, `move`, and `path`.

use super::*;

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// The guest volume serial, as `GetVolumeInformationByHandleW` reports it.
const VOLUME_SERIAL: u32 = 0x5743_4c49;

/// A name against a `FindFirstFile` pattern with the DOS rules: a trailing
/// `.*` also matches names without an extension, and a trailing `.` matches
/// a period or the end of the name.
pub(super) fn dos_match(pattern: &str, name: &str) -> bool {
    if let Some(stem) = pattern.strip_suffix(".*") {
        if !name.contains('.') && wildcard_match(stem, name) {
            return true;
        }
    } else if let Some(stem) = pattern.strip_suffix('.').filter(|stem| !stem.is_empty() && !stem.ends_with('.')) {
        return match name.strip_suffix('.') {
            Some(before) => wildcard_match(stem, before),
            None => !name.contains('.') && wildcard_match(stem, name),
        };
    }
    wildcard_match(pattern, name)
}

/// `1,234,567`.
fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// A FILETIME as dir prints it in US English: `MM/dd/yyyy  hh:mm tt`.
fn listing_time(filetime: u64) -> String {
    let seconds = (filetime / 10_000_000).saturating_sub(11_644_473_600) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&seconds, &mut tm) };
    let hour = tm.tm_hour as u32;
    let twelve = if hour % 12 == 0 { 12 } else { hour % 12 };
    format!(
        "{:02}/{:02}/{:04}  {:02}:{:02} {}",
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_year + 1900,
        twelve,
        tm.tm_min,
        if hour < 12 { "AM" } else { "PM" }
    )
}

/// Free bytes on the host volume holding the guest's files.
fn free_bytes() -> u64 {
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    let root = std::ffi::CString::new(std::env::temp_dir().to_string_lossy().as_bytes()).unwrap_or_default();
    if unsafe { libc::statvfs(root.as_ptr(), &mut stats) } != 0 {
        return 0;
    }
    stats.f_bavail as u64 * stats.f_frsize as u64
}

#[derive(Clone)]
struct Listed {
    name: String,
    directory: bool,
    size: u64,
    time: u64,
    attributes: u32,
}

/// `/a` attribute requirements: (attribute bits, wanted set or clear).
struct AttributeFilter(Option<Vec<(u32, bool)>>);

impl AttributeFilter {
    fn parse(spec: Option<&str>) -> Result<Self, String> {
        let Some(spec) = spec else { return Ok(Self(None)) };
        let mut wanted = Vec::new();
        let mut negate = false;
        for c in spec.trim_start_matches(':').chars() {
            let bit = match c.to_ascii_uppercase() {
                '-' => {
                    negate = true;
                    continue;
                }
                'D' => 0x10,
                'R' => FILE_ATTRIBUTE_READONLY,
                'H' => FILE_ATTRIBUTE_HIDDEN,
                'S' => FILE_ATTRIBUTE_SYSTEM,
                'A' => FILE_ATTRIBUTE_ARCHIVE,
                'L' => FILE_ATTRIBUTE_REPARSE_POINT,
                'I' => 0x2000,
                'O' => 0x1000,
                _ => return Err(format!("Parameter format not correct - \"{spec}\".")),
            };
            wanted.push((bit, !negate));
            negate = false;
        }
        Ok(Self(Some(wanted)))
    }

    fn keeps(&self, entry: &Listed) -> bool {
        let attributes = entry.attributes | if entry.directory { 0x10 } else { 0 };
        match &self.0 {
            // Without /a, hidden and system entries are left out.
            None => attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) == 0,
            Some(wanted) => wanted.iter().all(|(bit, set)| (attributes & bit != 0) == *set),
        }
    }
}

/// `/o` sort keys: N name, E extension, S size, D date, G directories
/// first; `-` reverses the next key.
fn sort_entries(entries: &mut [Listed], order: &str) -> Result<(), String> {
    let order = order.trim_start_matches(':');
    let order = if order.is_empty() { "GN" } else { order };
    let mut keys = Vec::new();
    let mut reverse = false;
    for c in order.chars() {
        match c.to_ascii_uppercase() {
            '-' => reverse = true,
            key @ ('N' | 'E' | 'S' | 'D' | 'G') => {
                keys.push((key, reverse));
                reverse = false;
            }
            _ => return Err(format!("Parameter format not correct - \"{order}\".")),
        }
    }
    let extension = |name: &str| name.rsplit_once('.').map_or(String::new(), |(_, e)| e.to_lowercase());
    entries.sort_by(|a, b| {
        for (key, reverse) in &keys {
            let ordering = match key {
                'N' => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                'E' => extension(&a.name).cmp(&extension(&b.name)),
                'S' => a.size.cmp(&b.size),
                'D' => a.time.cmp(&b.time),
                _ => b.directory.cmp(&a.directory),
            };
            let ordering = if *reverse { ordering.reverse() } else { ordering };
            if ordering.is_ne() {
                return ordering;
            }
        }
        std::cmp::Ordering::Equal
    });
    Ok(())
}

struct DirOptions {
    bare: bool,
    recurse: bool,
    attributes: AttributeFilter,
    order: Option<String>,
}

#[derive(Default)]
struct Totals {
    files: u64,
    directories: u64,
    bytes: u64,
}

impl<H: CmdHost> Cmd<'_, H> {
    /// A directory's entries matching `pattern` (with `.` and `..` outside
    /// a drive root), in name order as NTFS lists them.
    fn listed_entries(&mut self, directory: &str, pattern: &str) -> Vec<Listed> {
        let root = directory.trim_end_matches('\\').len() <= 2;
        self.host.with_fs(|fs| {
            let mut names = fs.list_dir(directory).unwrap_or_default();
            names.sort_by_key(|name| name.to_lowercase());
            let base = directory.trim_end_matches('\\');
            let mut entries = Vec::new();
            let dot = |name: &str| {
                let metadata = fs.file_metadata(directory);
                Listed { name: name.to_string(), directory: true, size: 0, time: metadata.write_time, attributes: 0x10 }
            };
            if !root {
                entries.push(dot("."));
                entries.push(dot(".."));
            }
            for name in names {
                let path = format!("{base}\\{name}");
                let metadata = fs.file_metadata(&path);
                let directory = fs.is_dir(&path);
                entries.push(Listed {
                    size: if directory { 0 } else { fs.file_len(&path).unwrap_or(0) },
                    time: metadata.write_time,
                    attributes: metadata.attributes,
                    directory,
                    name,
                });
            }
            entries.retain(|entry| dos_match(pattern, &entry.name));
            entries
        })
    }

    pub(super) fn builtin_dir(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let mut options = DirOptions { bare: false, recurse: false, attributes: AttributeFilter(None), order: None };
        let mut targets = Vec::new();
        for argument in split_batch_arguments(rest) {
            let Some(switch) = argument.strip_prefix('/') else {
                targets.push(argument);
                continue;
            };
            let (letter, value) = switch.split_at(switch.chars().next().map_or(0, char::len_utf8));
            match letter.to_ascii_lowercase().as_str() {
                "b" => options.bare = true,
                "s" => options.recurse = true,
                "a" => match AttributeFilter::parse(Some(value)) {
                    Ok(filter) => options.attributes = filter,
                    Err(message) => return self.fail(io, &message, 1),
                },
                "o" => options.order = Some(value.to_string()),
                // Paging, owners, short names, and four-digit years change
                // nothing here.
                "p" | "q" | "x" | "4" | "c" | "n" | "l" => {}
                _ => return self.fail(io, &format!("Invalid switch - \"{switch}\"."), 1),
            }
        }
        if targets.is_empty() {
            targets.push(".".to_string());
        }
        let mut status = 0;
        let mut totals = Totals::default();
        let mut listed_any = false;
        for target in targets {
            let full = self.full_path(&target);
            let (directory, pattern) = if self.host.with_fs(|fs| fs.is_dir(&full)) {
                (full.clone(), "*".to_string())
            } else {
                match full.rsplit_once('\\') {
                    Some((parent, name)) => {
                        let parent = if parent.len() == 2 { format!("{parent}\\") } else { parent.to_string() };
                        (parent, name.to_string())
                    }
                    None => (self.cwd.clone(), full.clone()),
                }
            };
            if !options.bare && !listed_any {
                let drive = directory.chars().next().unwrap_or('C').to_ascii_uppercase();
                self.print(io, &format!(" Volume in drive {drive} has no label."));
                self.print(
                    io,
                    &format!(" Volume Serial Number is {:04X}-{:04X}", VOLUME_SERIAL >> 16, VOLUME_SERIAL & 0xFFFF),
                );
            }
            listed_any = true;
            if !self.list_directory(&directory, &pattern, &options, io, &mut totals) {
                if !options.bare {
                    self.print(io, "");
                    self.print(io, &format!(" Directory of {directory}"));
                    self.print(io, "");
                }
                status = self.fail(io, "File Not Found", 1).0;
            }
        }
        if !options.bare && totals.files + totals.directories > 0 {
            if options.recurse {
                self.print(io, "");
                self.print(io, "     Total Files Listed:");
                self.print(io, &format!("{:>16} File(s) {:>14} bytes", totals.files, grouped(totals.bytes)));
            }
            self.print(io, &format!("{:>16} Dir(s) {:>15} bytes free", totals.directories, grouped(free_bytes())));
        }
        if status == 0 {
            self.errorlevel = 0;
        }
        (status, Flow::Next)
    }

    /// List one directory (and with `/s` its subdirectories); whether
    /// anything matched.
    fn list_directory(&mut self, directory: &str, pattern: &str, options: &DirOptions, io: &Io, totals: &mut Totals) -> bool {
        let mut entries = self.listed_entries(directory, pattern);
        entries.retain(|entry| options.attributes.keeps(entry));
        if options.bare {
            entries.retain(|entry| entry.name != "." && entry.name != "..");
        }
        if let Some(order) = &options.order {
            if let Err(message) = sort_entries(&mut entries, order) {
                self.fail(io, &message, 1);
                return true;
            }
        }
        let base = directory.trim_end_matches('\\').to_string();
        let mut found = !entries.is_empty();
        if !entries.is_empty() {
            if options.bare {
                for entry in &entries {
                    let line = if options.recurse { format!("{base}\\{}", entry.name) } else { entry.name.clone() };
                    self.print(io, &line);
                }
            } else {
                self.print(io, "");
                self.print(io, &format!(" Directory of {}", if base.len() == 2 { format!("{base}\\") } else { base.clone() }));
                self.print(io, "");
                let (mut files, mut directories, mut bytes) = (0u64, 0u64, 0u64);
                for entry in &entries {
                    let column = if entry.directory {
                        format!("{:<14}", "<DIR>")
                    } else {
                        format!("{:>14}", grouped(entry.size))
                    };
                    self.print(io, &format!("{}    {column} {}", listing_time(entry.time), entry.name));
                    if entry.directory {
                        directories += 1;
                    } else {
                        files += 1;
                        bytes += entry.size;
                    }
                }
                self.print(io, &format!("{files:>16} File(s) {:>14} bytes", grouped(bytes)));
                totals.files += files;
                totals.directories += directories;
                totals.bytes += bytes;
            }
        }
        if options.recurse {
            let subdirectories: Vec<String> = self
                .listed_entries(directory, "*")
                .into_iter()
                .filter(|entry| entry.directory && entry.name != "." && entry.name != "..")
                .map(|entry| format!("{base}\\{}", entry.name))
                .collect();
            for subdirectory in subdirectories {
                found |= self.list_directory(&subdirectory, pattern, options, io, totals);
            }
        }
        found
    }

    /// `ren source newname`: the new name is a name, not a path; wildcards
    /// rename each match (`ren *.txt *.bak`).
    pub(super) fn builtin_rename(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let arguments = split_batch_arguments(rest);
        let [source, new_name] = &arguments[..] else {
            return self.fail(io, SYNTAX_ERROR, 1);
        };
        let new_name = new_name.trim_matches('"');
        if new_name.contains(['\\', '/', ':']) {
            return self.fail(io, SYNTAX_ERROR, 1);
        }
        let full = self.full_path(source);
        let (directory, pattern) = full.rsplit_once('\\').map_or((self.cwd.clone(), full.clone()), |(d, n)| (d.to_string(), n.to_string()));
        let matches: Vec<String> = self
            .listed_entries(&directory, &pattern)
            .into_iter()
            .map(|entry| entry.name)
            .filter(|name| name != "." && name != "..")
            .collect();
        if matches.is_empty() {
            return self.fail(io, "The system cannot find the file specified.", 1);
        }
        let mut status = 0;
        for name in matches {
            let target = rename_template(&name, new_name);
            let from = format!("{directory}\\{name}");
            let to = format!("{directory}\\{target}");
            let renamed = self.host.with_fs(|fs| {
                if !name.eq_ignore_ascii_case(&target) && fs.exists(&to) {
                    return Err(());
                }
                fs.move_path(&from, &to).map_err(|_| ())
            });
            if renamed.is_err() {
                status = self.fail(io, "A duplicate file name exists, or the file cannot be found.", 1).0;
            }
        }
        if status == 0 {
            self.errorlevel = 0;
        }
        (status, Flow::Next)
    }

    /// `move source destination`: a file into a directory or to a new name,
    /// or a directory to a new name.
    pub(super) fn builtin_move(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let arguments: Vec<String> = split_batch_arguments(rest).into_iter().filter(|a| !a.starts_with('/')).collect();
        let [source, destination] = &arguments[..] else {
            return self.fail(io, SYNTAX_ERROR, 1);
        };
        let source = self.full_path(source);
        let mut destination = self.full_path(destination);
        let directory = self.host.with_fs(|fs| fs.is_dir(&source));
        let moved = self.host.with_fs(|fs| {
            if !fs.exists(&source) {
                return Err("The system cannot find the file specified.");
            }
            if fs.is_dir(&destination) {
                let name = source.rsplit('\\').next().unwrap_or_default();
                destination = format!("{destination}\\{name}");
            }
            if fs.exists(&destination) {
                if directory || fs.is_dir(&destination) {
                    return Err("Access is denied.");
                }
                // /Y is the default for a file under cmd /c.
                fs.delete_file(&destination).map_err(|_| "Access is denied.")?;
            }
            fs.move_path(&source, &destination).map_err(|_| "The system cannot find the path specified.")
        });
        match moved {
            Ok(()) => {
                self.print(io, if directory { "        1 dir(s) moved." } else { "        1 file(s) moved." });
                self.errorlevel = 0;
                (0, Flow::Next)
            }
            Err(message) => self.fail(io, message, 1),
        }
    }

    /// `path`: show `PATH=...` (or `No Path`), `path ;` clear it, or set it.
    pub(super) fn builtin_path(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let value = rest.trim();
        let value = value.strip_prefix('=').unwrap_or(value).trim();
        if value.is_empty() {
            match self.variable("PATH") {
                Some(path) => self.print(io, &format!("PATH={path}")),
                None => self.print(io, "No Path"),
            }
        } else if value == ";" {
            self.set_variable("PATH", "");
        } else {
            self.set_variable("PATH", value.trim_matches('"'));
        }
        (0, Flow::Next)
    }
}

/// A rename template applied to a name: `*` takes the rest of the source
/// name up to the template's next character (or its last period when that
/// is `.`), `?` the source character at that place, anything else itself.
fn rename_template(name: &str, template: &str) -> String {
    let source: Vec<char> = name.chars().collect();
    let pattern: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut position = 0;
    let mut index = 0;
    while index < pattern.len() {
        match pattern[index] {
            '*' => {
                let stop = match pattern.get(index + 1) {
                    Some('.') => source.iter().rposition(|c| *c == '.').filter(|p| *p >= position).unwrap_or(source.len()),
                    Some(next) => source[position..].iter().position(|c| c.eq_ignore_ascii_case(next)).map_or(source.len(), |p| position + p),
                    None => source.len(),
                };
                out.extend(&source[position..stop]);
                position = stop;
            }
            '?' => {
                if let Some(c) = source.get(position) {
                    if *c != '.' {
                        out.push(*c);
                        position += 1;
                    }
                }
            }
            '.' => {
                out.push('.');
                // Continue after the source's next period.
                position = source[position..].iter().position(|c| *c == '.').map_or(source.len(), |p| position + p + 1);
            }
            c => {
                out.push(c);
                position += 1;
            }
        }
        index += 1;
    }
    out.trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_templates_follow_cmd() {
        assert_eq!(rename_template("a.txt", "*.bak"), "a.bak");
        assert_eq!(rename_template("report.final.txt", "*.md"), "report.final.md");
        assert_eq!(rename_template("a.txt", "b.txt"), "b.txt");
        // Each literal character takes the place of a source character.
        assert_eq!(rename_template("notes.txt", "new_*"), "new_s.txt");
        assert_eq!(rename_template("data.csv", "????.bak"), "data.bak");
    }

    #[test]
    fn listing_columns_and_patterns() {
        assert_eq!(grouped(1234567), "1,234,567");
        assert_eq!(grouped(5), "5");
        assert!(dos_match("*.*", "Makefile"));
        assert!(dos_match("*", "."));
        assert!(!dos_match("*.txt", "."));
        assert_eq!(format!("{:<14}", "<DIR>").len(), 14);
    }
}
