//! Lexical classification of Windows paths before WinFs applies drive cwd
//! resolution and looks up filesystem nodes.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DosDevicePath {
    Null,
    Console,
    ConsoleIn,
    ConsoleOut,
    Reserved,
    Pipe(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ParsedWinPath {
    Dos {
        drive: Option<char>,
        absolute: bool,
        components: Vec<String>,
    },
    Unc {
        server: String,
        share: String,
        components: Vec<String>,
    },
    Device(DosDevicePath),
    Invalid(String),
}

fn device_name(name: &str) -> Option<DosDevicePath> {
    let name = name
        .split(['.', ':'])
        .next()
        .unwrap_or(name)
        .trim_end_matches(' ');
    if name.eq_ignore_ascii_case("NUL") {
        Some(DosDevicePath::Null)
    } else if name.eq_ignore_ascii_case("CON") {
        Some(DosDevicePath::Console)
    } else if name.eq_ignore_ascii_case("CONIN$") {
        Some(DosDevicePath::ConsoleIn)
    } else if name.eq_ignore_ascii_case("CONOUT$") {
        Some(DosDevicePath::ConsoleOut)
    } else {
        let upper = name.to_ascii_uppercase();
        let bytes = upper.as_bytes();
        (bytes.len() == 4
            && (bytes.starts_with(b"COM") || bytes.starts_with(b"LPT"))
            && (b'1'..=b'9').contains(&bytes[3]))
        .then_some(DosDevicePath::Reserved)
    }
}

fn normalize_component(component: &str) -> String {
    if component == "." || component == ".." {
        component.to_string()
    } else {
        component.trim_end_matches(['.', ' ']).to_string()
    }
}

fn invalid_component(component: &str) -> bool {
    component.chars().any(|character| {
        character <= '\u{1f}' || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
    })
}

fn strip_prefix_case_insensitive<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn unc(value: &str) -> ParsedWinPath {
    let mut parts = value.split('\\').filter(|part| !part.is_empty());
    let Some(server) = parts.next() else {
        return ParsedWinPath::Invalid("UNC path has no server name".to_string());
    };
    let Some(share) = parts.next() else {
        return ParsedWinPath::Invalid("UNC path has no share name".to_string());
    };
    ParsedWinPath::Unc {
        server: server.to_string(),
        share: share.to_string(),
        components: parts.map(str::to_string).collect(),
    }
}

pub(crate) fn parse(raw: &str) -> ParsedWinPath {
    if raw.is_empty() {
        return ParsedWinPath::Invalid("empty path".to_string());
    }
    let mut path = raw.replace('/', "\\");

    if let Some(rest) = strip_prefix_case_insensitive(&path, r"\\.\pipe\") {
        if rest.is_empty() {
            return ParsedWinPath::Invalid("named pipe path has no name".to_string());
        }
        return ParsedWinPath::Device(DosDevicePath::Pipe(rest.to_string()));
    }

    if let Some(rest) = strip_prefix_case_insensitive(&path, r"\\?\UNC\") {
        return unc(rest);
    }
    if let Some(rest) = strip_prefix_case_insensitive(&path, r"\??\UNC\") {
        return unc(rest);
    }
    if path.starts_with(r"\\") && !path.starts_with(r"\\.\") && !path.starts_with(r"\\?\") {
        return unc(&path[2..]);
    }

    if let Some(rest) = strip_prefix_case_insensitive(&path, r"\\.\") {
        path = rest.to_string();
    } else if let Some(rest) = strip_prefix_case_insensitive(&path, r"\\?\") {
        path = rest.to_string();
    } else if let Some(rest) = strip_prefix_case_insensitive(&path, r"\??\") {
        path = rest.to_string();
    }

    let drive = if path.len() >= 2
        && path.as_bytes()[0].is_ascii_alphabetic()
        && path.as_bytes()[1] == b':'
    {
        let drive = path.as_bytes()[0] as char;
        path = path[2..].to_string();
        Some(drive)
    } else {
        None
    };
    let absolute = path.starts_with('\\');
    let body = path.trim_start_matches('\\');
    let components = body
        .split('\\')
        .filter(|part| !part.is_empty())
        .map(normalize_component)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    if let Some(component) = components.iter().find(|part| invalid_component(part)) {
        return ParsedWinPath::Invalid(format!(
            "invalid character in Windows path component: {component}"
        ));
    }

    if let Some(device) = components.last().and_then(|name| device_name(name)) {
        return ParsedWinPath::Device(device);
    }

    ParsedWinPath::Dos {
        drive,
        absolute,
        components,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, DosDevicePath, ParsedWinPath};

    #[test]
    fn parser_classifies_dos_unc_and_device_paths() {
        assert_eq!(
            parse(r"C:\work\file.txt"),
            ParsedWinPath::Dos {
                drive: Some('C'),
                absolute: true,
                components: vec!["work".to_string(), "file.txt".to_string()],
            }
        );
        assert_eq!(
            parse(r"\\server\share\folder\file"),
            ParsedWinPath::Unc {
                server: "server".to_string(),
                share: "share".to_string(),
                components: vec!["folder".to_string(), "file".to_string()],
            }
        );
        assert_eq!(parse("NUL.txt"), ParsedWinPath::Device(DosDevicePath::Null));
        assert_eq!(
            parse(r"\\.\pipe\service"),
            ParsedWinPath::Device(DosDevicePath::Pipe("service".to_string()))
        );
        assert_eq!(
            parse(r"\\?\UNC\server\share\x"),
            ParsedWinPath::Unc {
                server: "server".to_string(),
                share: "share".to_string(),
                components: vec!["x".to_string()],
            }
        );
        for path in [r"C:\bad|name", r"C:\bad<name>", r"C:\file.txt:stream"] {
            assert!(matches!(parse(path), ParsedWinPath::Invalid(_)), "{path}");
        }
    }
}
