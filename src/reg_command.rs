//! `setx` and `reg` for the shell, over the guest registry in [`winreg`].
//!
//! Output follows the Windows tools. Where those would stop and ask before
//! overwriting or deleting, these require `/f` instead, since shell lines
//! may come from scripts and control clients.

use crate::{
    winfs::WinFs,
    winreg::{self, Hive, RegValue, Registry},
};

const NOT_FOUND: &str = "ERROR: The system was unable to find the specified registry key or value.";
const SUCCESS: &str = "The operation completed successfully.\n";

/// `setx NAME VALUE [/M]`: persist a user (or, with `/M`, machine)
/// environment variable for sessions started later. Like Windows `setx`,
/// the current session's environment is unchanged.
pub fn setx(fs: &mut WinFs, argv: &[String]) -> Result<String, String> {
    let (flags, words): (Vec<&String>, Vec<&String>) =
        argv.iter().partition(|word| word.starts_with('/'));
    let machine = match flags.as_slice() {
        [] => false,
        [flag] if flag.eq_ignore_ascii_case("/m") => true,
        _ => return Err("ERROR: Invalid syntax.\nType \"SETX /?\" for usage.".to_string()),
    };
    let [name, value] = words.as_slice() else {
        return Err("ERROR: Invalid syntax.\nType \"SETX /?\" for usage.".to_string());
    };
    let hive = if machine {
        Hive::LocalMachine
    } else {
        Hive::CurrentUser
    };
    if value.is_empty() {
        // setx cannot delete; an empty value is stored as empty text.
        let mut registry = Registry::load(fs)?;
        registry.set_value(
            hive,
            winreg::environment_key(hive),
            name,
            RegValue::string(""),
        );
        registry.save(fs, hive)?;
    } else {
        winreg::set_persistent_environment(fs, hive, name, value)?;
    }
    Ok("\nSUCCESS: Specified value was saved.\n".to_string())
}

/// `reg query | add | delete` with the common switches.
pub fn reg(fs: &mut WinFs, argv: &[String]) -> Result<String, String> {
    let usage = "usage: reg query <key> [/v <name> | /ve] [/s]\n       reg add <key> [/v <name> | /ve] [/t <type>] [/d <data>] [/f]\n       reg delete <key> [/v <name> | /ve | /va] [/f]";
    let (Some(operation), Some(key_name)) = (argv.first(), argv.get(1)) else {
        return Err(usage.to_string());
    };
    let (hive, path) =
        winreg::parse_key_name(key_name).ok_or_else(|| "ERROR: Invalid key name.".to_string())?;
    let options = Options::parse(&argv[2..])?;
    match operation.to_ascii_lowercase().as_str() {
        "query" => query(fs, hive, &path, &options),
        "add" => add(fs, hive, &path, &options),
        "delete" => delete(fs, hive, &path, &options),
        _ => Err(usage.to_string()),
    }
}

#[derive(Default)]
struct Options {
    /// `/v NAME`, or `Some("")` for `/ve` (the default value).
    value: Option<String>,
    all_values: bool,
    recursive: bool,
    kind: Option<String>,
    data: Option<String>,
    force: bool,
}

impl Options {
    fn parse(words: &[String]) -> Result<Self, String> {
        let mut options = Options::default();
        let mut words = words.iter();
        while let Some(word) = words.next() {
            let mut operand = |switch: &str| {
                words
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("ERROR: {switch} needs a value."))
            };
            match word.to_ascii_lowercase().as_str() {
                "/v" => options.value = Some(operand("/v")?),
                "/ve" => options.value = Some(String::new()),
                "/va" => options.all_values = true,
                "/s" => options.recursive = true,
                "/t" => options.kind = Some(operand("/t")?),
                "/d" => options.data = Some(operand("/d")?),
                "/f" => options.force = true,
                _ => return Err(format!("ERROR: Invalid syntax: {word}")),
            }
        }
        Ok(options)
    }
}

fn full_name(hive: Hive, path: &str) -> String {
    let path = path.trim_matches('\\');
    if path.is_empty() {
        hive.root_name().to_string()
    } else {
        format!(r"{}\{path}", hive.root_name())
    }
}

fn value_line(name: &str, value: &RegValue) -> String {
    let name = if name.is_empty() { "(Default)" } else { name };
    format!(
        "    {name}    {}    {}\n",
        winreg::type_name(value.kind),
        winreg::display_data(value)
    )
}

fn query(fs: &WinFs, hive: Hive, path: &str, options: &Options) -> Result<String, String> {
    let registry = Registry::load(fs)?;
    let key = registry
        .key(hive, path)
        .ok_or_else(|| NOT_FOUND.to_string())?;
    let mut output = String::new();
    if let Some(name) = &options.value {
        let value = key.value(name).ok_or_else(|| NOT_FOUND.to_string())?;
        output.push_str(&format!("\n{}\n", full_name(hive, path)));
        output.push_str(&value_line(name, value));
        output.push('\n');
        return Ok(output);
    }
    fn walk(output: &mut String, key: &winreg::Key, name: &str, recursive: bool) {
        output.push_str(&format!("\n{name}\n"));
        for (value_name, value) in key.values() {
            output.push_str(&value_line(value_name, value));
        }
        if recursive {
            for subkey in key.subkey_names() {
                walk(
                    output,
                    key.subkey(subkey).unwrap(),
                    &format!(r"{name}\{subkey}"),
                    true,
                );
            }
        } else {
            if !key.subkey_names().is_empty() {
                output.push('\n');
            }
            for subkey in key.subkey_names() {
                output.push_str(&format!("{name}\\{subkey}\n"));
            }
        }
    }
    walk(&mut output, key, &full_name(hive, path), options.recursive);
    output.push('\n');
    Ok(output)
}

fn parse_data(kind: u32, data: &str) -> Result<RegValue, String> {
    let invalid = || {
        format!(
            "ERROR: Invalid data for {}: {data}",
            winreg::type_name(kind)
        )
    };
    let number = |text: &str| -> Option<u64> {
        match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => text.parse().ok(),
        }
    };
    Ok(match kind {
        winreg::REG_SZ => RegValue::string(data),
        winreg::REG_EXPAND_SZ => RegValue::expand_string(data),
        winreg::REG_DWORD => RegValue::dword(
            number(data)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(invalid)?,
        ),
        winreg::REG_QWORD => RegValue {
            kind,
            data: number(data).ok_or_else(invalid)?.to_le_bytes().to_vec(),
        },
        winreg::REG_MULTI_SZ => {
            let items: Vec<&str> = data.split(r"\0").filter(|item| !item.is_empty()).collect();
            RegValue::multi_string(&items)
        }
        _ => {
            if !data.len().is_multiple_of(2) {
                return Err(invalid());
            }
            RegValue {
                kind,
                data: (0..data.len())
                    .step_by(2)
                    .map(|index| u8::from_str_radix(&data[index..index + 2], 16))
                    .collect::<Result<_, _>>()
                    .map_err(|_| invalid())?,
            }
        }
    })
}

fn add(fs: &mut WinFs, hive: Hive, path: &str, options: &Options) -> Result<String, String> {
    if path.trim_matches('\\').is_empty() {
        return Err("ERROR: Invalid key name.".to_string());
    }
    let mut registry = Registry::load(fs)?;
    if let Some(name) = &options.value {
        let kind = match &options.kind {
            Some(kind) => winreg::type_from_name(kind)
                .ok_or_else(|| format!("ERROR: Invalid type: {kind}"))?,
            None => winreg::REG_SZ,
        };
        let value = parse_data(kind, options.data.as_deref().unwrap_or_default())?;
        if registry.value(hive, path, name).is_some() && !options.force {
            return Err(format!(
                "ERROR: Value {} exists; add /f to overwrite it.",
                if name.is_empty() { "(Default)" } else { name }
            ));
        }
        registry.set_value(hive, path, name, value);
    } else {
        registry.create_key(hive, path);
    }
    registry.save(fs, hive)?;
    Ok(SUCCESS.to_string())
}

fn delete(fs: &mut WinFs, hive: Hive, path: &str, options: &Options) -> Result<String, String> {
    if !options.force {
        return Err("ERROR: Add /f to delete without a confirmation prompt.".to_string());
    }
    let mut registry = Registry::load(fs)?;
    let key = registry
        .key_mut(hive, path)
        .ok_or_else(|| NOT_FOUND.to_string())?;
    if let Some(name) = &options.value {
        if !key.delete_value(name) {
            return Err(NOT_FOUND.to_string());
        }
    } else if options.all_values {
        let names: Vec<String> = key
            .values()
            .into_iter()
            .map(|(name, _)| name.to_string())
            .collect();
        for name in names {
            key.delete_value(&name);
        }
    } else {
        registry
            .delete_key(hive, path, true)
            .map_err(|error| format!("ERROR: {error}"))?;
    }
    registry.save(fs, hive)?;
    Ok(SUCCESS.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_string).collect()
    }

    #[test]
    fn setx_persists_user_and_machine_variables() {
        let mut fs = WinFs::ephemeral_runner();
        assert_eq!(
            setx(&mut fs, &words("EDITOR vim")).unwrap(),
            "\nSUCCESS: Specified value was saved.\n"
        );
        setx(&mut fs, &words(r"JAVA_HOME C:\jdk /M")).unwrap();
        setx(&mut fs, &words(r"TOOLS %USERPROFILE%\tools")).unwrap();
        let registry = Registry::load(&fs).unwrap();
        let user = registry.key(Hive::CurrentUser, "Environment").unwrap();
        assert_eq!(
            user.value("EDITOR").unwrap().as_str().as_deref(),
            Some("vim")
        );
        assert_eq!(user.value("TOOLS").unwrap().kind, winreg::REG_EXPAND_SZ);
        assert!(registry
            .value(Hive::LocalMachine, winreg::MACHINE_ENVIRONMENT, "JAVA_HOME")
            .is_some());
        let environment = winreg::login_environment(&registry);
        assert!(environment
            .iter()
            .any(|(name, value)| name == "TOOLS" && value == r"C:\Users\runner\tools"));

        for bad in ["ONLY_NAME", "A B C", "A B /X"] {
            assert!(setx(&mut fs, &words(bad))
                .unwrap_err()
                .contains("Invalid syntax"));
        }
    }

    #[test]
    fn reg_query_prints_values_then_subkeys_like_windows() {
        let mut fs = WinFs::ephemeral_runner();
        let output = reg(&mut fs, &words(r"query HKCU\Environment")).unwrap();
        assert_eq!(
            output,
            "\nHKEY_CURRENT_USER\\Environment\n    Path    REG_EXPAND_SZ    %USERPROFILE%\\AppData\\Local\\Microsoft\\WindowsApps;%APPDATA%\\npm;\n    TEMP    REG_EXPAND_SZ    %USERPROFILE%\\AppData\\Local\\Temp\n    TMP    REG_EXPAND_SZ    %USERPROFILE%\\AppData\\Local\\Temp\n\n"
        );
        let key_with_space = [
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "/v",
            "CurrentMajorVersionNumber",
        ]
        .map(str::to_string);
        let output = reg(&mut fs, &key_with_space).unwrap();
        assert_eq!(
            output,
            "\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\n    CurrentMajorVersionNumber    REG_DWORD    0xa\n\n"
        );
        let output = reg(
            &mut fs,
            &words(r"query HKCU\Software\Microsoft\Windows\CurrentVersion"),
        )
        .unwrap();
        assert!(output.ends_with(
            "\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\n\n"
        ));
        assert_eq!(
            reg(&mut fs, &words(r"query HKCU\Missing")).unwrap_err(),
            NOT_FOUND
        );
    }

    #[test]
    fn reg_add_and_delete_round_trip_typed_values() {
        let mut fs = WinFs::ephemeral_runner();
        let add = |fs: &mut WinFs, line: &str| reg(fs, &words(line));
        assert_eq!(add(&mut fs, r"add HKCU\Software\Tool").unwrap(), SUCCESS);
        add(
            &mut fs,
            r"add HKCU\Software\Tool /v Count /t REG_DWORD /d 0x10",
        )
        .unwrap();
        add(&mut fs, r"add HKCU\Software\Tool /v Big /t REG_QWORD /d 5").unwrap();
        add(
            &mut fs,
            r"add HKCU\Software\Tool /v Items /t REG_MULTI_SZ /d a\0b",
        )
        .unwrap();
        add(
            &mut fs,
            r"add HKCU\Software\Tool /v Blob /t REG_BINARY /d 00ff",
        )
        .unwrap();
        add(&mut fs, r"add HKCU\Software\Tool /ve /d default").unwrap();
        let error = add(
            &mut fs,
            r"add HKCU\Software\Tool /v Count /t REG_DWORD /d 1",
        )
        .unwrap_err();
        assert!(error.contains("/f"), "{error}");
        add(
            &mut fs,
            r"add HKCU\Software\Tool /v Count /t REG_DWORD /d 1 /f",
        )
        .unwrap();
        assert!(
            add(&mut fs, r"add HKCU\Software\Tool /v X /t REG_DWORD /d nope")
                .unwrap_err()
                .contains("Invalid data")
        );

        let output = reg(&mut fs, &words(r"query HKCU\Software\Tool")).unwrap();
        for line in [
            "    (Default)    REG_SZ    default\n",
            "    Big    REG_QWORD    0x5\n",
            "    Blob    REG_BINARY    00FF\n",
            "    Count    REG_DWORD    0x1\n",
            "    Items    REG_MULTI_SZ    a\\0b\n",
        ] {
            assert!(output.contains(line), "missing {line:?} in {output}");
        }

        assert!(reg(&mut fs, &words(r"delete HKCU\Software\Tool /v Count"))
            .unwrap_err()
            .contains("/f"));
        reg(&mut fs, &words(r"delete HKCU\Software\Tool /v Count /f")).unwrap();
        reg(&mut fs, &words(r"delete HKCU\Software\Tool /va /f")).unwrap();
        assert!(!reg(&mut fs, &words(r"query HKCU\Software\Tool"))
            .unwrap()
            .contains("REG_"));
        reg(&mut fs, &words(r"delete HKCU\Software\Tool /f")).unwrap();
        assert_eq!(
            reg(&mut fs, &words(r"query HKCU\Software\Tool")).unwrap_err(),
            NOT_FOUND
        );
        assert!(reg(&mut fs, &words(r"add HKCU /v X /d y")).is_err());
        assert!(reg(&mut fs, &words(r"query HKXX\Foo"))
            .unwrap_err()
            .contains("Invalid key name"));
    }
}
