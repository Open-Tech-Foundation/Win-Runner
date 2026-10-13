//! `tar.exe`, which Windows ships in System32 (libarchive's bsdtar):
//! creating, listing and extracting tar archives — plain, gzip or bzip2
//! compressed — and zip archives. Reading detects the format and
//! compression by content; creating picks them from `-z`/`-j`/`--format`
//! or, with `-a`, the archive's name. The process it runs in supplies files
//! and standard streams through [`TarHost`].

use std::io::{Read, Write};

/// The bsdtar release whose command line this follows.
pub const VERSION: &str = "3.7.2";

/// What a tar process needs from its surroundings. Paths are Windows paths,
/// relative ones to the process's current directory.
pub trait TarHost {
    fn stdout(&mut self, bytes: &[u8]) -> Result<(), String>;
    fn stderr(&mut self, bytes: &[u8]);
    fn read_stdin(&mut self) -> Result<Vec<u8>, String>;
    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, String>;
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), String>;
    /// Create a directory and any missing parents.
    fn create_dir(&mut self, path: &str) -> Result<(), String>;
    fn is_dir(&mut self, path: &str) -> bool;
    fn exists(&mut self, path: &str) -> bool;
    /// A directory's entry names.
    fn list_dir(&mut self, path: &str) -> Result<Vec<String>, String>;
    /// Seconds since 1970 for new entries' times.
    fn now(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Create,
    Extract,
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compression {
    None,
    Gzip,
    Bzip2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Tar,
    Zip,
}

#[derive(Debug, Default)]
struct Options {
    mode: Option<Mode>,
    file: Option<String>,
    compression: Option<Compression>,
    format: Option<Format>,
    auto_compress: bool,
    verbose: bool,
    keep_old: bool,
    to_stdout: bool,
    strip_components: usize,
    excludes: Vec<String>,
    /// Operands, each with the `-C` directory in force where it appeared.
    operands: Vec<(Option<String>, String)>,
    directory: Option<String>,
}

/// A refusal before any archive work: text for stderr (or stdout) and the
/// exit code.
struct Stop {
    code: i32,
    text: String,
    to_stdout: bool,
}

fn usage(message: &str) -> Stop {
    Stop {
        code: 1,
        text: format!("tar: {message}\nUsage:\n  List:    tar -tf <archive-filename>\n  Extract: tar -xf <archive-filename>\n  Create:  tar -cf <archive-filename> [filenames...]\n  Help:    tar --help\n"),
        to_stdout: false,
    }
}

/// Long options taking a value.
const LONG_VALUES: &[&str] = &["file", "directory", "cd", "strip-components", "exclude", "format", "options"];

fn set_mode(options: &mut Options, mode: Mode) -> Result<(), Stop> {
    match options.mode {
        Some(existing) if existing != mode => {
            let letter = |mode| match mode {
                Mode::Create => 'c',
                Mode::Extract => 'x',
                Mode::List => 't',
            };
            Err(usage(&format!("Can't specify both -{} and -{}", letter(existing), letter(mode))))
        }
        _ => {
            options.mode = Some(mode);
            Ok(())
        }
    }
}

fn apply(options: &mut Options, name: &str, value: Option<String>) -> Result<(), Stop> {
    let value = value.unwrap_or_default();
    match name {
        "c" | "create" => set_mode(options, Mode::Create)?,
        "x" | "extract" | "get" => set_mode(options, Mode::Extract)?,
        "t" | "list" => set_mode(options, Mode::List)?,
        "f" | "file" => options.file = Some(value),
        "C" | "directory" | "cd" => options.directory = Some(value),
        "z" | "gzip" | "gunzip" => options.compression = Some(Compression::Gzip),
        "j" | "bzip2" | "bunzip2" => options.compression = Some(Compression::Bzip2),
        "a" | "auto-compress" => options.auto_compress = true,
        "v" | "verbose" => options.verbose = true,
        "k" | "keep-old-files" => options.keep_old = true,
        "O" | "to-stdout" => options.to_stdout = true,
        "strip-components" => {
            options.strip_components = value
                .parse()
                .map_err(|_| usage(&format!("Invalid --strip-components value: {value}")))?;
        }
        "exclude" => options.excludes.push(value),
        "format" => {
            options.format = Some(match value.to_ascii_lowercase().as_str() {
                "zip" => Format::Zip,
                "ustar" | "pax" | "gnutar" | "posix" | "restricted" => Format::Tar,
                other => return Err(usage(&format!("Can't use format {other}"))),
            })
        }
        // Accepted and without effect here.
        "p" | "m" | "o" | "options" | "preserve-permissions" | "no-same-owner" | "no-same-permissions"
        | "same-owner" | "modification-time" | "totals" | "no-recursion" | "numeric-owner" => {}
        "version" => {
            return Err(Stop {
                code: 0,
                text: format!("bsdtar {VERSION} - libarchive {VERSION} zlib bz2lib\n"),
                to_stdout: true,
            })
        }
        "help" | "h" => {
            return Err(Stop {
                code: 0,
                text: "tar(bsdtar): manipulate archive files\nFirst option must be a mode specifier:\n  -c Create  -r Add/Replace  -t List  -u Update  -x Extract\nCommon Options:\n  -b #  Use # 512-byte records per I/O block\n  -f <filename>  Location of archive (default \\\\.\\tape0)\n  -v    Verbose\n  -w    Interactive\nCreate: tar -c [options] [<file> | <dir> | @<archive> | -C <dir> ]\n  <file>, <dir>  add these items to archive\n  -z, -j  Compress archive with gzip/bzip2\n  --format {ustar|pax|cpio|shar}  Select archive format\n  --exclude <pattern>  Skip files that match pattern\n  -C <dir>  Change to <dir> before processing remaining files\nList: tar -t [options] [<patterns>]\n  <patterns>  If specified, list only entries that match\nExtract: tar -x [options] [<patterns>]\n  <patterns>  If specified, extract only entries that match\n  -k    Keep (don't overwrite) existing files\n  -m    Don't restore modification times\n  -O    Write entries to stdout, don't restore to disk\n  -p    Restore permissions (including ACLs, owner, file flags)\n".to_string(),
                to_stdout: true,
            })
        }
        "r" | "u" | "append" | "update" => return Err(usage("Appending to archives is not supported by this tar.exe")),
        other => {
            let shown = if other.len() == 1 { format!("-{other}") } else { format!("--{other}") };
            return Err(usage(&format!("Option {shown} is not supported")));
        }
    }
    Ok(())
}

/// Short options that take a value.
fn short_takes_value(letter: char) -> bool {
    matches!(letter, 'f' | 'C')
}

fn parse(arguments: &[String]) -> Result<Options, Stop> {
    let mut options = Options::default();
    let mut index = 0;
    // bsdtar's traditional form: a first word of bundled letters without a
    // dash (`tar xzf archive.tgz`), whose value options take the following
    // words in order.
    if let Some(first) = arguments.first().filter(|first| !first.starts_with('-') && !first.is_empty()) {
        if first.chars().all(|c| c.is_ascii_alphabetic()) {
            index = 1;
            for letter in first.chars() {
                let value = if short_takes_value(letter) {
                    index += 1;
                    Some(arguments.get(index - 1).cloned().ok_or_else(|| usage(&format!("Option -{letter} requires an argument")))?)
                } else {
                    None
                };
                apply(&mut options, &letter.to_string(), value)?;
            }
        }
    }
    while index < arguments.len() {
        let argument = &arguments[index];
        index += 1;
        if let Some(long) = argument.strip_prefix("--").filter(|long| !long.is_empty()) {
            let (name, inline) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (long, None),
            };
            let value = if LONG_VALUES.contains(&name) {
                match inline {
                    Some(value) => Some(value),
                    None => {
                        index += 1;
                        Some(arguments.get(index - 1).cloned().ok_or_else(|| usage(&format!("Option --{name} requires an argument")))?)
                    }
                }
            } else {
                None
            };
            apply(&mut options, name, value)?;
        } else if argument.len() > 1 && argument.starts_with('-') {
            let letters: Vec<char> = argument[1..].chars().collect();
            let mut at = 0;
            while at < letters.len() {
                let letter = letters[at];
                at += 1;
                if short_takes_value(letter) {
                    let value = if at < letters.len() {
                        letters[at..].iter().collect()
                    } else {
                        index += 1;
                        arguments.get(index - 1).cloned().ok_or_else(|| usage(&format!("Option -{letter} requires an argument")))?
                    };
                    apply(&mut options, &letter.to_string(), Some(value))?;
                    break;
                }
                apply(&mut options, &letter.to_string(), None)?;
            }
        } else {
            options.operands.push((options.directory.clone(), argument.clone()));
        }
    }
    if options.mode.is_none() {
        return Err(usage("Must specify one of -c, -r, -t, -u, -x"));
    }
    Ok(options)
}

// ---- archive entries ---------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    File,
    Directory,
    Symlink(String),
    Hardlink(String),
}

#[derive(Debug, Clone)]
struct Entry {
    /// Member name with `/` separators (directories without a trailing one).
    name: String,
    kind: Kind,
    data: Vec<u8>,
    mode: u32,
    mtime: u64,
}

fn octal(field: &[u8]) -> u64 {
    // GNU base-256 for large values.
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return field[1..].iter().fold(0u64, |value, byte| value << 8 | u64::from(*byte));
    }
    let text = String::from_utf8_lossy(field);
    u64::from_str_radix(text.trim_matches(|c: char| c == '\0' || c == ' '), 8).unwrap_or(0)
}

fn field_text(field: &[u8]) -> String {
    let end = field.iter().position(|byte| *byte == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// pax extended header records (`len key=value\n`).
fn pax_records(data: &[u8]) -> Vec<(String, String)> {
    let mut records = Vec::new();
    let mut rest = data;
    while let Some(space) = rest.iter().position(|byte| *byte == b' ') {
        let Some(length) = std::str::from_utf8(&rest[..space]).ok().and_then(|n| n.parse::<usize>().ok()) else {
            break;
        };
        if length <= space || length > rest.len() {
            break;
        }
        let record = String::from_utf8_lossy(&rest[space + 1..length]).trim_end_matches('\n').to_string();
        if let Some((key, value)) = record.split_once('=') {
            records.push((key.to_string(), value.to_string()));
        }
        rest = &rest[length..];
    }
    records
}

fn read_tar(data: &[u8]) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    let mut at = 0;
    let mut long_name: Option<String> = None;
    let mut long_link: Option<String> = None;
    let mut pax: Vec<(String, String)> = Vec::new();
    let mut global: Vec<(String, String)> = Vec::new();
    while at + 512 <= data.len() {
        let header = &data[at..at + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let stored: u64 = octal(&header[148..156]);
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(index, byte)| if (148..156).contains(&index) { 32 } else { u64::from(*byte) })
            .sum();
        if stored != sum {
            return Err(if entries.is_empty() { "Unrecognized archive format".into() } else { "Damaged tar archive".into() });
        }
        let pax_size = pax
            .iter()
            .chain(&global)
            .find(|(key, _)| key == "size")
            .and_then(|(_, value)| value.parse::<u64>().ok());
        let size = pax_size.unwrap_or_else(|| octal(&header[124..136])) as usize;
        let start = at + 512;
        let body = data.get(start..start + size).ok_or("Truncated tar archive")?;
        at = start + size.div_ceil(512) * 512;
        let typeflag = header[156];
        match typeflag {
            b'L' => {
                long_name = Some(field_text(body));
                continue;
            }
            b'K' => {
                long_link = Some(field_text(body));
                continue;
            }
            b'x' => {
                pax = pax_records(body);
                continue;
            }
            b'g' => {
                global = pax_records(body);
                continue;
            }
            _ => {}
        }
        let magic_ustar = &header[257..262] == b"ustar";
        let mut name = field_text(&header[..100]);
        if magic_ustar {
            let prefix = field_text(&header[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let mut link = field_text(&header[157..257]);
        let lookup = |key: &str| pax.iter().chain(&global).find(|(k, _)| k == key).map(|(_, v)| v.clone());
        if let Some(path) = lookup("path") {
            name = path;
        }
        if let Some(path) = lookup("linkpath") {
            link = path;
        }
        if let Some(path) = long_name.take() {
            name = path;
        }
        if let Some(path) = long_link.take() {
            link = path;
        }
        let mtime = lookup("mtime")
            .and_then(|value| value.split('.').next().and_then(|s| s.parse().ok()))
            .unwrap_or_else(|| octal(&header[136..148]));
        pax.clear();
        let kind = match typeflag {
            b'5' => Kind::Directory,
            b'2' => Kind::Symlink(link),
            b'1' => Kind::Hardlink(link),
            b'0' | 0 | b'7' if name.ends_with('/') => Kind::Directory,
            b'0' | 0 | b'7' => Kind::File,
            // Devices, FIFOs and vendor entries have nothing to restore.
            _ => continue,
        };
        entries.push(Entry {
            name: name.trim_end_matches('/').to_string(),
            kind,
            data: body.to_vec(),
            mode: octal(&header[100..108]) as u32,
            mtime,
        });
    }
    Ok(entries)
}

fn read_zip(data: &[u8]) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    for entry in crate::install::zip_entries(data)? {
        let body = if entry.is_dir { Vec::new() } else { crate::install::extract_bytes(data, &entry)? };
        entries.push(Entry {
            name: entry.name.replace('\\', "/").trim_end_matches('/').to_string(),
            kind: if entry.is_dir { Kind::Directory } else { Kind::File },
            data: body,
            mode: if entry.is_dir { 0o755 } else { 0o644 },
            mtime: 0,
        });
    }
    Ok(entries)
}

/// Decompress by content and parse whichever archive format it holds.
fn read_archive(data: &[u8]) -> Result<Vec<Entry>, String> {
    let decompressed;
    let data = if data.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::MultiGzDecoder::new(data)
            .read_to_end(&mut out)
            .map_err(|e| format!("gzip decompression failed: {e}"))?;
        decompressed = out;
        &decompressed[..]
    } else if data.starts_with(b"BZh") {
        let mut out = Vec::new();
        bzip2::read::MultiBzDecoder::new(data)
            .read_to_end(&mut out)
            .map_err(|e| format!("bzip2 decompression failed: {e}"))?;
        decompressed = out;
        &decompressed[..]
    } else if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        return Err("xz compression is not supported by this tar.exe".into());
    } else {
        data
    };
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return read_zip(data);
    }
    if data.len() < 512 {
        return Err(if data.is_empty() { "Empty archive".into() } else { "Unrecognized archive format".into() });
    }
    read_tar(data)
}

fn write_octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    if text.len() <= digits {
        field[..digits].copy_from_slice(text.as_bytes());
        field[digits] = 0;
    } else {
        // GNU base-256 for values that do not fit.
        field.fill(0);
        field[0] = 0x80;
        let bytes = value.to_be_bytes();
        let n = bytes.len().min(field.len() - 1);
        let len = field.len();
        field[len - n..].copy_from_slice(&bytes[bytes.len() - n..]);
    }
}

fn tar_header(name: &str, typeflag: u8, size: u64, mode: u32, mtime: u64, link: &str) -> [u8; 512] {
    let mut header = [0u8; 512];
    let bytes = name.as_bytes();
    header[..bytes.len().min(100)].copy_from_slice(&bytes[..bytes.len().min(100)]);
    write_octal(&mut header[100..108], u64::from(mode));
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size);
    write_octal(&mut header[136..148], mtime);
    header[156] = typeflag;
    let link = link.as_bytes();
    header[157..157 + link.len().min(100)].copy_from_slice(&link[..link.len().min(100)]);
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let text = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(text.as_bytes());
    header
}

fn pad(out: &mut Vec<u8>) {
    out.resize(out.len().div_ceil(512) * 512, 0);
}

fn write_tar(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        let (typeflag, link) = match &entry.kind {
            Kind::File => (b'0', ""),
            Kind::Directory => (b'5', ""),
            Kind::Symlink(target) => (b'2', target.as_str()),
            Kind::Hardlink(target) => (b'1', target.as_str()),
        };
        let name = if entry.kind == Kind::Directory { format!("{}/", entry.name) } else { entry.name.clone() };
        // Names past ustar's 100 bytes travel in a pax header, as bsdtar
        // writes them.
        if name.len() > 100 || link.len() > 100 || !name.is_ascii() {
            let mut records = Vec::new();
            for (key, value) in [("path", name.as_str()), ("linkpath", link)] {
                if value.is_empty() || (key == "linkpath" && value.len() <= 100) {
                    continue;
                }
                let body = format!(" {key}={value}\n");
                let mut length = body.len();
                while (length + body.len()).to_string().len() + body.len() != length {
                    length = (length + body.len()).to_string().len() + body.len();
                }
                records.extend_from_slice(format!("{length}{body}").as_bytes());
            }
            let pax_name: String = format!("PaxHeader/{}", name.rsplit('/').find(|s| !s.is_empty()).unwrap_or("entry"));
            out.extend_from_slice(&tar_header(&pax_name.chars().take(99).collect::<String>(), b'x', records.len() as u64, 0o644, entry.mtime, ""));
            out.extend_from_slice(&records);
            pad(&mut out);
        }
        let size = if entry.kind == Kind::File { entry.data.len() as u64 } else { 0 };
        out.extend_from_slice(&tar_header(&name, typeflag, size, entry.mode, entry.mtime, link));
        if entry.kind == Kind::File {
            out.extend_from_slice(&entry.data);
            pad(&mut out);
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    // bsdtar pads to whole 10240-byte records.
    out.resize(out.len().div_ceil(10240) * 10240, 0);
    out
}

/// A DOS date and time for a zip entry.
fn dos_time(mtime: u64) -> (u16, u16) {
    let days = (mtime / 86400) as i64;
    let seconds = mtime % 86400;
    // Civil date from days since 1970 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if year < 1980 {
        return (0, 0x21);
    }
    let time = ((seconds / 3600) << 11 | (seconds % 3600 / 60) << 5 | (seconds % 60) / 2) as u16;
    let date = (((year - 1980) as u16) << 9) | ((month as u16) << 5) | day as u16;
    (time, date)
}

fn write_zip(entries: &[Entry]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for entry in entries.iter().filter(|entry| matches!(entry.kind, Kind::File | Kind::Directory)) {
        let name = if entry.kind == Kind::Directory { format!("{}/", entry.name) } else { entry.name.clone() };
        let mut crc = flate2::Crc::new();
        crc.update(&entry.data);
        let (method, body) = if entry.data.is_empty() {
            (0u16, Vec::new())
        } else {
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&entry.data).map_err(|e| e.to_string())?;
            (8u16, encoder.finish().map_err(|e| e.to_string())?)
        };
        let (time, date) = dos_time(entry.mtime);
        let offset = out.len() as u32;
        let flags: u16 = if name.is_ascii() { 0 } else { 0x0800 };
        let mut local = Vec::new();
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&flags.to_le_bytes());
        local.extend_from_slice(&method.to_le_bytes());
        local.extend_from_slice(&time.to_le_bytes());
        local.extend_from_slice(&date.to_le_bytes());
        local.extend_from_slice(&crc.sum().to_le_bytes());
        local.extend_from_slice(&(body.len() as u32).to_le_bytes());
        local.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&local);
        out.extend_from_slice(&body);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&0x031eu16.to_le_bytes()); // made by Unix, 3.0
        // Version needed through the extra-field length, as in the local
        // header.
        central.extend_from_slice(&local[4..30]);
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        let unix_mode = if entry.kind == Kind::Directory { 0o040_000 | entry.mode } else { 0o100_000 | entry.mode };
        let external = unix_mode << 16 | u32::from(entry.kind == Kind::Directory) * 0x10;
        central.extend_from_slice(&external.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let count = entries.iter().filter(|entry| matches!(entry.kind, Kind::File | Kind::Directory)).count() as u16;
    let central_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
}

fn compress(data: Vec<u8>, compression: Compression) -> Result<Vec<u8>, String> {
    match compression {
        Compression::None => Ok(data),
        Compression::Gzip => {
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&data).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())
        }
        Compression::Bzip2 => {
            let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            encoder.write_all(&data).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())
        }
    }
}

// ---- matching and paths -------------------------------------------------------

/// bsdtar's pattern match: `*`, `?` and `[...]`-free wildcards against the
/// whole name; a pattern also matches everything under a matching directory.
fn wildcard(pattern: &[char], text: &[char]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some('*'), _) => wildcard(&pattern[1..], text) || (!text.is_empty() && wildcard(pattern, &text[1..])),
        (Some('?'), Some(_)) => wildcard(&pattern[1..], &text[1..]),
        (Some(p), Some(t)) if p == t => wildcard(&pattern[1..], &text[1..]),
        _ => false,
    }
}

fn matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.trim_end_matches('/').chars().collect();
    let name = name.trim_end_matches('/');
    let mut prefix = String::new();
    for (index, component) in name.split('/').enumerate() {
        if index > 0 {
            prefix.push('/');
        }
        prefix.push_str(component);
        if wildcard(&pattern, &prefix.chars().collect::<Vec<_>>()) {
            return true;
        }
    }
    false
}

fn excluded(options: &Options, name: &str) -> bool {
    options.excludes.iter().any(|pattern| {
        matches(pattern, name) || name.split('/').any(|component| wildcard(&pattern.chars().collect::<Vec<_>>(), &component.chars().collect::<Vec<_>>()))
    })
}

fn join(directory: Option<&str>, path: &str) -> String {
    let path = path.replace('/', "\\");
    match directory {
        Some(directory) if !(path.starts_with('\\') || path.get(1..2) == Some(":")) => {
            format!("{}\\{path}", directory.trim_end_matches(['\\', '/']))
        }
        _ => path,
    }
}

/// A member name made safe to extract, or why it is refused.
fn extraction_name(name: &str, strip: usize) -> Result<Option<String>, String> {
    let mut name = name.replace('\\', "/");
    // Drive letters and leading slashes are removed, as bsdtar does.
    if name.len() >= 2 && name.as_bytes()[1] == b':' && name.as_bytes()[0].is_ascii_alphabetic() {
        name = name[2..].to_string();
    }
    let components: Vec<&str> = name.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    if components.contains(&"..") {
        return Err("Path contains '..'".to_string());
    }
    if components.len() <= strip {
        return Ok(None);
    }
    Ok(Some(components[strip..].join("/")))
}

// ---- modes --------------------------------------------------------------------

fn read_input(host: &mut dyn TarHost, options: &Options) -> Result<Vec<u8>, String> {
    match options.file.as_deref() {
        None | Some("-") => host.read_stdin(),
        Some(path) => host.read_file(path).map_err(|_| format!("Error opening archive: Failed to open '{path}'")),
    }
}

fn list(host: &mut dyn TarHost, options: &Options) -> i32 {
    let entries = match read_input(host, options).and_then(|data| read_archive(&data)) {
        Ok(entries) => entries,
        Err(error) => {
            host.stderr(format!("tar: {error}\n").as_bytes());
            return 1;
        }
    };
    let patterns: Vec<&str> = options.operands.iter().map(|(_, pattern)| pattern.as_str()).collect();
    let mut seen = vec![false; patterns.len()];
    for entry in &entries {
        let shown = if entry.kind == Kind::Directory { format!("{}/", entry.name) } else { entry.name.clone() };
        if !patterns.is_empty() {
            let hit = patterns.iter().position(|pattern| matches(pattern, &entry.name));
            match hit {
                Some(index) => seen[index] = true,
                None => continue,
            }
        }
        if excluded(options, &entry.name) {
            continue;
        }
        let line = if options.verbose {
            let (kind, extra) = match &entry.kind {
                Kind::Directory => ('d', String::new()),
                Kind::Symlink(target) => ('l', format!(" -> {target}")),
                Kind::Hardlink(target) => ('-', format!(" link to {target}")),
                Kind::File => ('-', String::new()),
            };
            let mut permissions = String::new();
            for shift in [6, 3, 0] {
                let bits = entry.mode >> shift & 7;
                permissions.push(if bits & 4 != 0 { 'r' } else { '-' });
                permissions.push(if bits & 2 != 0 { 'w' } else { '-' });
                permissions.push(if bits & 1 != 0 { 'x' } else { '-' });
            }
            format!("{kind}{permissions}  0 0      0 {:>8} {shown}{extra}\n", entry.data.len())
        } else {
            format!("{shown}\n")
        };
        if host.stdout(line.as_bytes()).is_err() {
            return 1;
        }
    }
    let mut code = 0;
    for (index, pattern) in patterns.iter().enumerate() {
        if !seen[index] {
            host.stderr(format!("tar: {pattern}: Not found in archive\n").as_bytes());
            code = 1;
        }
    }
    if code != 0 {
        host.stderr(b"tar: Error exit delayed from previous errors.\n");
    }
    code
}

fn extract(host: &mut dyn TarHost, options: &Options) -> i32 {
    let entries = match read_input(host, options).and_then(|data| read_archive(&data)) {
        Ok(entries) => entries,
        Err(error) => {
            host.stderr(format!("tar: {error}\n").as_bytes());
            return 1;
        }
    };
    let base = options.directory.clone();
    if let Some(directory) = &base {
        if !host.is_dir(directory) {
            host.stderr(format!("tar: could not chdir to '{directory}'\n").as_bytes());
            return 1;
        }
    }
    let patterns: Vec<&str> = options.operands.iter().map(|(_, pattern)| pattern.as_str()).collect();
    let mut seen = vec![false; patterns.len()];
    let mut failed = false;
    // Where each member landed, for hard links and symlinks to members.
    let mut extracted: Vec<(String, String)> = Vec::new();
    for entry in &entries {
        if !patterns.is_empty() {
            match patterns.iter().position(|pattern| matches(pattern, &entry.name)) {
                Some(index) => seen[index] = true,
                None => continue,
            }
        }
        if excluded(options, &entry.name) {
            continue;
        }
        let name = match extraction_name(&entry.name, options.strip_components) {
            Ok(Some(name)) => name,
            Ok(None) => continue,
            Err(reason) => {
                host.stderr(format!("tar: {}: {reason}\n", entry.name).as_bytes());
                failed = true;
                continue;
            }
        };
        if options.to_stdout {
            if entry.kind == Kind::File && host.stdout(&entry.data).is_err() {
                return 1;
            }
            continue;
        }
        if options.verbose {
            host.stderr(format!("x {name}\n").as_bytes());
        }
        let path = join(base.as_deref(), &name);
        let parent = path.rsplit_once('\\').map(|(parent, _)| parent.to_string());
        if let Some(parent) = parent.filter(|parent| !parent.is_empty() && !parent.ends_with(':')) {
            if let Err(error) = host.create_dir(&parent) {
                host.stderr(format!("tar: {name}: Can't create directory: {error}\n").as_bytes());
                failed = true;
                continue;
            }
        }
        let data = match &entry.kind {
            Kind::Directory => {
                if let Err(error) = host.create_dir(&path) {
                    host.stderr(format!("tar: {name}: Can't create '{path}': {error}\n").as_bytes());
                    failed = true;
                }
                continue;
            }
            Kind::File => entry.data.clone(),
            // Links become copies of what they name, when that is a member
            // already extracted or a file beside them.
            Kind::Hardlink(target) | Kind::Symlink(target) => {
                let source = if matches!(entry.kind, Kind::Hardlink(_)) {
                    extracted.iter().find(|(member, _)| member == target.trim_end_matches('/')).map(|(_, path)| path.clone())
                } else {
                    let directory = path.rsplit_once('\\').map_or(String::new(), |(directory, _)| directory.to_string());
                    Some(join(Some(&directory), target))
                };
                match source.and_then(|source| host.read_file(&source).ok()) {
                    Some(data) => data,
                    None => {
                        host.stderr(format!("tar: {name}: Can't create link to '{target}'\n").as_bytes());
                        failed = true;
                        continue;
                    }
                }
            }
        };
        if options.keep_old && host.exists(&path) {
            host.stderr(format!("tar: {name}: Already exists\n").as_bytes());
            failed = true;
            continue;
        }
        if let Err(error) = host.write_file(&path, &data) {
            host.stderr(format!("tar: {name}: Can't create '{path}': {error}\n").as_bytes());
            failed = true;
            continue;
        }
        extracted.push((entry.name.clone(), path));
    }
    for (index, pattern) in patterns.iter().enumerate() {
        if !seen[index] {
            host.stderr(format!("tar: {pattern}: Not found in archive\n").as_bytes());
            failed = true;
        }
    }
    if failed {
        host.stderr(b"tar: Error exit delayed from previous errors.\n");
        return 1;
    }
    0
}

/// Gather `path` (and, for a directory, everything under it) as members
/// named from `name`.
fn gather(host: &mut dyn TarHost, options: &Options, path: &str, name: &str, now: u64, out: &mut Vec<Entry>) {
    if excluded(options, name) {
        return;
    }
    if host.is_dir(path) {
        if !name.is_empty() {
            out.push(Entry { name: name.to_string(), kind: Kind::Directory, data: Vec::new(), mode: 0o755, mtime: now });
        }
        let mut children = host.list_dir(path).unwrap_or_default();
        children.sort();
        for child in children {
            let child_name = if name.is_empty() { child.clone() } else { format!("{name}/{child}") };
            gather(host, options, &format!("{}\\{child}", path.trim_end_matches('\\')), &child_name, now, out);
        }
    } else if let Ok(data) = host.read_file(path) {
        out.push(Entry { name: name.to_string(), kind: Kind::File, data, mode: 0o644, mtime: now });
    }
}

fn create(host: &mut dyn TarHost, options: &Options) -> i32 {
    if options.operands.is_empty() {
        host.stderr(b"tar: no files or directories specified\n");
        return 1;
    }
    let name_hint = options.file.as_deref().unwrap_or("").to_ascii_lowercase();
    let format = options.format.unwrap_or(if options.auto_compress && name_hint.ends_with(".zip") { Format::Zip } else { Format::Tar });
    let compression = options.compression.unwrap_or(if options.auto_compress {
        if name_hint.ends_with(".gz") || name_hint.ends_with(".tgz") {
            Compression::Gzip
        } else if name_hint.ends_with(".bz2") || name_hint.ends_with(".tbz2") || name_hint.ends_with(".tbz") {
            Compression::Bzip2
        } else {
            Compression::None
        }
    } else {
        Compression::None
    });
    let now = host.now();
    let mut entries = Vec::new();
    let mut failed = false;
    let mut warned_root = false;
    for (directory, operand) in &options.operands {
        let path = join(directory.as_deref(), operand);
        if !host.exists(&path) {
            host.stderr(format!("tar: {operand}: Couldn't find file: No such file or directory\n").as_bytes());
            failed = true;
            continue;
        }
        let mut name = operand.replace('\\', "/");
        if name.len() >= 2 && name.as_bytes()[1] == b':' {
            name = name[2..].to_string();
        }
        if name.starts_with('/') {
            if !warned_root {
                host.stderr(b"tar: Removing leading '/' from member names\n");
                warned_root = true;
            }
            name = name.trim_start_matches('/').to_string();
        }
        let name = name.trim_start_matches("./").trim_end_matches('/').to_string();
        let name = if name == "." { String::new() } else { name };
        let before = entries.len();
        gather(host, options, &path, &name, now, &mut entries);
        // "." adds the directory's contents under "./" as bsdtar names them.
        if operand == "." {
            entries.insert(before, Entry { name: ".".into(), kind: Kind::Directory, data: Vec::new(), mode: 0o755, mtime: now });
            for entry in &mut entries[before + 1..] {
                entry.name = format!("./{}", entry.name);
            }
        }
    }
    if options.verbose {
        for entry in &entries {
            host.stderr(format!("a {}\n", entry.name).as_bytes());
        }
    }
    let archive = match format {
        Format::Tar => compress(write_tar(&entries), compression),
        Format::Zip => write_zip(&entries),
    };
    let archive = match archive {
        Ok(archive) => archive,
        Err(error) => {
            host.stderr(format!("tar: {error}\n").as_bytes());
            return 1;
        }
    };
    let written = match options.file.as_deref() {
        None | Some("-") => host.stdout(&archive),
        Some(path) => host.write_file(path, &archive).map_err(|_| format!("Failed to open '{path}'")),
    };
    if let Err(error) = written {
        host.stderr(format!("tar: {error}\n").as_bytes());
        return 1;
    }
    if failed {
        host.stderr(b"tar: Error exit delayed from previous errors.\n");
        return 1;
    }
    0
}

/// Run tar with `arguments` (without the program name); returns the exit
/// code.
pub fn run(host: &mut dyn TarHost, arguments: &[String]) -> i32 {
    let options = match parse(arguments) {
        Ok(options) => options,
        Err(stop) => {
            if stop.to_stdout {
                let _ = host.stdout(stop.text.as_bytes());
            } else {
                host.stderr(stop.text.as_bytes());
            }
            return stop.code;
        }
    };
    match options.mode {
        Some(Mode::Create) => create(host, &options),
        Some(Mode::Extract) => extract(host, &options),
        Some(Mode::List) => list(host, &options),
        None => 1,
    }
}

/// Where Windows keeps tar.exe.
pub fn tar_exe_path() -> String {
    format!(r"{}\tar.exe", crate::system_profile::SYSTEM32)
}

/// Put `tar.exe` in System32 unless the disk already has one.
pub fn seed_tar_exe(fs: &mut crate::winfs::WinFs) {
    let path = tar_exe_path();
    if fs.is_file(&path) || fs.mkdir(crate::system_profile::SYSTEM32).is_err() {
        return;
    }
    let _ = fs.write_file(&path, crate::cmd::stub_image("WinrunTarMain"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Files and directories by lower-cased path, with the current
    /// directory `C:\w`.
    #[derive(Default)]
    struct FakeHost {
        files: BTreeMap<String, Vec<u8>>,
        dirs: Vec<String>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        stdin: Vec<u8>,
    }

    fn full(path: &str) -> String {
        let path = path.replace('/', "\\");
        let path = if path.get(1..2) == Some(":") { path } else { format!(r"C:\w\{path}") };
        let mut parts: Vec<&str> = Vec::new();
        for part in path.split('\\') {
            match part {
                "." | "" => {}
                ".." => {
                    parts.pop();
                }
                part => parts.push(part),
            }
        }
        parts.join("\\")
    }

    impl TarHost for FakeHost {
        fn stdout(&mut self, bytes: &[u8]) -> Result<(), String> {
            self.stdout.extend_from_slice(bytes);
            Ok(())
        }
        fn stderr(&mut self, bytes: &[u8]) {
            self.stderr.extend_from_slice(bytes);
        }
        fn read_stdin(&mut self) -> Result<Vec<u8>, String> {
            Ok(std::mem::take(&mut self.stdin))
        }
        fn read_file(&mut self, path: &str) -> Result<Vec<u8>, String> {
            self.files.get(&full(path)).cloned().ok_or_else(|| "not found".into())
        }
        fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), String> {
            self.files.insert(full(path), data.to_vec());
            Ok(())
        }
        fn create_dir(&mut self, path: &str) -> Result<(), String> {
            let path = full(path);
            if !self.dirs.contains(&path) {
                self.dirs.push(path);
            }
            Ok(())
        }
        fn is_dir(&mut self, path: &str) -> bool {
            let path = full(path);
            self.dirs.contains(&path) || path == r"C:\w"
        }
        fn exists(&mut self, path: &str) -> bool {
            self.files.contains_key(&full(path)) || self.is_dir(path)
        }
        fn list_dir(&mut self, path: &str) -> Result<Vec<String>, String> {
            let prefix = format!("{}\\", full(path));
            let mut names: Vec<String> = self
                .files
                .keys()
                .chain(&self.dirs)
                .filter_map(|p| p.strip_prefix(&prefix))
                .filter(|rest| !rest.contains('\\'))
                .map(str::to_string)
                .collect();
            names.sort();
            names.dedup();
            Ok(names)
        }
        fn now(&mut self) -> u64 {
            1_700_000_000
        }
    }

    impl FakeHost {
        fn run(&mut self, arguments: &[&str]) -> i32 {
            let arguments: Vec<String> = arguments.iter().map(|a| a.to_string()).collect();
            run(self, &arguments)
        }
        fn tree() -> FakeHost {
            let mut host = FakeHost::default();
            host.create_dir("src").unwrap();
            host.create_dir("src/sub").unwrap();
            host.write_file("src/a.txt", b"alpha").unwrap();
            host.write_file("src/sub/b.bin", &[0, 1, 2, 255]).unwrap();
            host.write_file("src/skip.log", b"log").unwrap();
            host
        }
        fn out(&self) -> String {
            String::from_utf8_lossy(&self.stdout).into_owned()
        }
        fn err(&self) -> String {
            String::from_utf8_lossy(&self.stderr).into_owned()
        }
    }

    #[test]
    fn create_list_and_extract_round_trip_in_every_compression() {
        for (flags, name) in [("-cf", "out.tar"), ("-czf", "out.tgz"), ("-cjf", "out.tar.bz2"), ("-caf", "out.zip")] {
            let mut host = FakeHost::tree();
            assert_eq!(host.run(&[flags, name, "--exclude", "*.log", "src"]), 0, "{}", host.err());
            assert_eq!(host.run(&["-tf", name]), 0, "{name}: {}", host.err());
            assert_eq!(host.out(), "src/\nsrc/a.txt\nsrc/sub/\nsrc/sub/b.bin\n", "{name}");
            host.stdout.clear();
            assert_eq!(host.run(&["-xf", name, "-C", "dest", "--strip-components=1"]), 1, "dest must exist");
            host.create_dir("dest").unwrap();
            host.stderr.clear();
            assert_eq!(host.run(&["-xf", name, "-C", "dest", "--strip-components=1"]), 0, "{name}: {}", host.err());
            assert_eq!(host.files[r"C:\w\dest\a.txt"], b"alpha", "{name}");
            assert_eq!(host.files[r"C:\w\dest\sub\b.bin"], [0, 1, 2, 255], "{name}");
            assert!(!host.files.contains_key(r"C:\w\dest\skip.log"));
        }
    }

    #[test]
    fn traditional_bundled_form_and_stdin_stdout() {
        let mut host = FakeHost::tree();
        assert_eq!(host.run(&["czf", "-", "src/a.txt"]), 0);
        assert!(host.stdout.starts_with(&[0x1f, 0x8b]));
        let archive = std::mem::take(&mut host.stdout);
        host.stdin = archive;
        assert_eq!(host.run(&["xOf", "-"]), 0, "{}", host.err());
        assert_eq!(host.out(), "alpha");
    }

    #[test]
    fn selected_members_unsafe_names_and_keep_old() {
        let entries = vec![
            Entry { name: "ok/one.txt".into(), kind: Kind::File, data: b"1".to_vec(), mode: 0o644, mtime: 0 },
            Entry { name: "../evil.txt".into(), kind: Kind::File, data: b"x".to_vec(), mode: 0o644, mtime: 0 },
            Entry { name: "ok/two.txt".into(), kind: Kind::File, data: b"2".to_vec(), mode: 0o644, mtime: 0 },
            Entry { name: "ok/hard".into(), kind: Kind::Hardlink("ok/two.txt".into()), data: vec![], mode: 0o644, mtime: 0 },
        ];
        let mut host = FakeHost::default();
        host.write_file("a.tar", &write_tar(&entries)).unwrap();
        assert_eq!(host.run(&["-xf", "a.tar"]), 1);
        assert!(host.err().contains("tar: ../evil.txt: Path contains '..'\n"), "{}", host.err());
        assert!(!host.files.keys().any(|path| path.contains("evil")));
        assert_eq!(host.files[r"C:\w\ok\hard"], b"2", "hard links extract as copies");
        host.stderr.clear();
        host.write_file("ok/one.txt", b"mine").unwrap();
        assert_eq!(host.run(&["-xkf", "a.tar", "ok/one.txt"]), 1);
        assert_eq!(host.files[r"C:\w\ok\one.txt"], b"mine");
        host.stderr.clear();
        assert_eq!(host.run(&["-tf", "a.tar", "ok/t*", "missing"]), 1);
        assert_eq!(host.out(), "ok/two.txt\n");
        assert!(host.err().contains("tar: missing: Not found in archive"));
    }

    #[test]
    fn long_names_use_pax_headers_and_gnu_long_names_read() {
        let long = format!("{}/file.txt", "d".repeat(120));
        let entries = vec![Entry { name: long.clone(), kind: Kind::File, data: b"deep".to_vec(), mode: 0o644, mtime: 5 }];
        let archive = write_tar(&entries);
        assert_eq!(archive.len() % 10240, 0);
        let read = read_tar(&archive).unwrap();
        assert_eq!((read[0].name.as_str(), read[0].data.as_slice(), read[0].mtime), (long.as_str(), &b"deep"[..], 5));
        // GNU ././@LongLink form.
        let mut gnu = tar_header("././@LongLink", b'L', long.len() as u64 + 1, 0o644, 0, "").to_vec();
        gnu.extend_from_slice(long.as_bytes());
        gnu.push(0);
        pad(&mut gnu);
        gnu.extend_from_slice(&tar_header("truncated", b'0', 4, 0o644, 0, ""));
        gnu.extend_from_slice(b"deep");
        pad(&mut gnu);
        gnu.extend_from_slice(&[0; 1024]);
        assert_eq!(read_tar(&gnu).unwrap()[0].name, long);
    }

    #[test]
    fn usage_errors() {
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-f", "x.tar"]), 1);
        assert!(host.err().starts_with("tar: Must specify one of -c, -r, -t, -u, -x"));
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-cx"]), 1);
        assert!(host.err().starts_with("tar: Can't specify both -c and -x"));
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["-xf", "missing.tar"]), 1);
        assert_eq!(host.err(), "tar: Error opening archive: Failed to open 'missing.tar'\n");
        let mut host = FakeHost::default();
        host.write_file("junk.tar", &[7u8; 600]).unwrap();
        assert_eq!(host.run(&["-tf", "junk.tar"]), 1);
        assert_eq!(host.err(), "tar: Unrecognized archive format\n");
        let mut host = FakeHost::default();
        assert_eq!(host.run(&["--version"]), 0);
        assert!(host.out().starts_with("bsdtar "));
        let mut host = FakeHost::tree();
        assert_eq!(host.run(&["-cf", "o.tar", "src/a.txt", "nope"]), 1);
        assert!(host.err().contains("tar: nope: Couldn't find file"), "{}", host.err());
        assert_eq!(read_tar(&host.files[r"C:\w\o.tar"]).unwrap().len(), 1, "found members are still archived");
    }
}
