//! The one definition of the guest Windows machine: its user, computer name,
//! and standard folders.
//!
//! The boot disk image, the default environment, and the native identity,
//! known-folder, and temp-path APIs all read from here, so every way a
//! program asks "where is my home, temp, or Program Files" gets the same
//! answer a stock Windows installation would give.

pub const USER_NAME: &str = "runner";
/// NetBIOS name: upper case and at most 15 characters, like Windows setup.
pub const COMPUTER_NAME: &str = "WINRUNNER";
/// `GetSystemInfo` and `NUMBER_OF_PROCESSORS` report the same count.
pub const PROCESSOR_COUNT: u32 = 1;

pub const SYSTEM_DRIVE: &str = "C:";
pub const WINDOWS: &str = r"C:\Windows";
pub const SYSTEM32: &str = r"C:\Windows\System32";
pub const WINDOWS_TEMP: &str = r"C:\Windows\Temp";
pub const POWERSHELL_HOME: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0";
pub const PROGRAM_FILES: &str = r"C:\Program Files";
pub const PROGRAM_FILES_X86: &str = r"C:\Program Files (x86)";
pub const COMMON_FILES: &str = r"C:\Program Files\Common Files";
pub const COMMON_FILES_X86: &str = r"C:\Program Files (x86)\Common Files";
pub const PROGRAM_DATA: &str = r"C:\ProgramData";
pub const USERS: &str = r"C:\Users";
pub const PUBLIC: &str = r"C:\Users\Public";
pub const PUBLIC_DOCUMENTS: &str = r"C:\Users\Public\Documents";
pub const DEFAULT_USER: &str = r"C:\Users\Default";

/// `%USERPROFILE%`, the user's home and the shell's starting directory.
pub const PROFILE: &str = r"C:\Users\runner";
pub const HOME_PATH: &str = r"\Users\runner";
pub const APP_DATA: &str = r"C:\Users\runner\AppData\Roaming";
pub const LOCAL_APP_DATA: &str = r"C:\Users\runner\AppData\Local";
pub const LOCAL_LOW_APP_DATA: &str = r"C:\Users\runner\AppData\LocalLow";
/// The per-user temp directory `%TEMP%` and `%TMP%` name.
pub const TEMP: &str = r"C:\Users\runner\AppData\Local\Temp";
pub const DESKTOP: &str = r"C:\Users\runner\Desktop";
pub const DOCUMENTS: &str = r"C:\Users\runner\Documents";
pub const DOWNLOADS: &str = r"C:\Users\runner\Downloads";
pub const MUSIC: &str = r"C:\Users\runner\Music";
pub const PICTURES: &str = r"C:\Users\runner\Pictures";
pub const VIDEOS: &str = r"C:\Users\runner\Videos";

/// Directories every boot image starts with.
pub const DIRECTORIES: &[&str] = &[
    SYSTEM32,
    WINDOWS_TEMP,
    POWERSHELL_HOME,
    COMMON_FILES,
    COMMON_FILES_X86,
    PROGRAM_DATA,
    PUBLIC_DOCUMENTS,
    DEFAULT_USER,
    APP_DATA,
    LOCAL_LOW_APP_DATA,
    TEMP,
    DESKTOP,
    DOCUMENTS,
    DOWNLOADS,
    MUSIC,
    PICTURES,
    VIDEOS,
];

pub fn processor_architecture() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "ARM64"
    } else {
        "AMD64"
    }
}

/// The environment a new logon session starts with. `extra_path` entries
/// follow the Windows directories on `PATH`.
pub fn default_environment(extra_path: &[&str]) -> Vec<(String, String)> {
    let mut path = vec![
        SYSTEM32.to_string(),
        WINDOWS.to_string(),
        format!(r"{SYSTEM32}\Wbem"),
        format!(r"{POWERSHELL_HOME}\"),
    ];
    path.extend(extra_path.iter().map(|entry| entry.to_string()));
    let variables: Vec<(&str, String)> = vec![
        ("ALLUSERSPROFILE", PROGRAM_DATA.into()),
        ("APPDATA", APP_DATA.into()),
        ("CommonProgramFiles", COMMON_FILES.into()),
        ("CommonProgramFiles(x86)", COMMON_FILES_X86.into()),
        ("CommonProgramW6432", COMMON_FILES.into()),
        ("COMPUTERNAME", COMPUTER_NAME.into()),
        ("ComSpec", format!(r"{SYSTEM32}\cmd.exe")),
        ("HOMEDRIVE", SYSTEM_DRIVE.into()),
        ("HOMEPATH", HOME_PATH.into()),
        ("LOCALAPPDATA", LOCAL_APP_DATA.into()),
        ("LOGONSERVER", format!(r"\\{COMPUTER_NAME}")),
        ("NUMBER_OF_PROCESSORS", PROCESSOR_COUNT.to_string()),
        ("OS", "Windows_NT".into()),
        ("Path", path.join(";")),
        (
            "PATHEXT",
            ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC".into(),
        ),
        ("PROCESSOR_ARCHITECTURE", processor_architecture().into()),
        ("ProgramData", PROGRAM_DATA.into()),
        ("ProgramFiles", PROGRAM_FILES.into()),
        ("ProgramFiles(x86)", PROGRAM_FILES_X86.into()),
        ("ProgramW6432", PROGRAM_FILES.into()),
        (
            "PSModulePath",
            format!(r"{PROGRAM_FILES}\WindowsPowerShell\Modules;{POWERSHELL_HOME}\Modules"),
        ),
        ("PUBLIC", PUBLIC.into()),
        ("SystemDrive", SYSTEM_DRIVE.into()),
        ("SystemRoot", WINDOWS.into()),
        ("TEMP", TEMP.into()),
        ("TMP", TEMP.into()),
        ("USERDOMAIN", COMPUTER_NAME.into()),
        ("USERDOMAIN_ROAMINGPROFILE", COMPUTER_NAME.into()),
        ("USERNAME", USER_NAME.into()),
        ("USERPROFILE", PROFILE.into()),
        ("windir", WINDOWS.into()),
        ("DriverData", format!(r"{SYSTEM32}\Drivers\DriverData")),
        ("PROCESSOR_LEVEL", "6".into()),
        ("SESSIONNAME", "Console".into()),
    ];
    let mut environment: Vec<(String, String)> = variables
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect();
    // Windows keeps the block sorted case-insensitively.
    environment.sort_by_key(|(name, _)| name.to_ascii_uppercase());
    environment
}

/// `SHGetFolderPath` CSIDL values (flags masked off) for the folders above.
pub fn csidl_path(csidl: i32) -> Option<&'static str> {
    Some(match csidl & 0xff {
        0x00 | 0x10 => DESKTOP,
        0x05 => DOCUMENTS,
        0x0d => MUSIC,
        0x0e => VIDEOS,
        0x1a => APP_DATA,
        0x1c => LOCAL_APP_DATA,
        0x23 => PROGRAM_DATA,
        0x24 => WINDOWS,
        0x25 => SYSTEM32,
        0x26 => PROGRAM_FILES,
        0x27 => PICTURES,
        0x28 => PROFILE,
        0x2a => PROGRAM_FILES_X86,
        0x2b => COMMON_FILES,
        0x2c => COMMON_FILES_X86,
        0x2e => PUBLIC_DOCUMENTS,
        _ => return None,
    })
}

/// `GetTempPath`'s lookup: the first of `%TMP%`, `%TEMP%`, and
/// `%USERPROFILE%` that is set, else the Windows directory; always with a
/// trailing backslash.
pub fn temp_path(environment: &[(String, String)]) -> String {
    let lookup = |key: &str| {
        environment
            .iter()
            .find(|(name, value)| name.eq_ignore_ascii_case(key) && !value.is_empty())
            .map(|(_, value)| value.clone())
    };
    let mut path = lookup("TMP")
        .or_else(|| lookup("TEMP"))
        .or_else(|| lookup("USERPROFILE"))
        .unwrap_or_else(|| WINDOWS.to_string());
    if !path.ends_with('\\') {
        path.push('\\');
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(environment: &'a [(String, String)], key: &str) -> &'a str {
        environment
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("missing {key}"))
    }

    #[test]
    fn environment_and_known_folders_describe_the_same_profile() {
        let environment = default_environment(&[]);
        assert_eq!(value(&environment, "USERPROFILE"), PROFILE);
        assert_eq!(csidl_path(0x28), Some(PROFILE));
        assert_eq!(value(&environment, "APPDATA"), csidl_path(0x1a).unwrap());
        assert_eq!(
            value(&environment, "LOCALAPPDATA"),
            csidl_path(0x1c).unwrap()
        );
        assert_eq!(
            value(&environment, "ProgramData"),
            csidl_path(0x23).unwrap()
        );
        assert_eq!(
            value(&environment, "ProgramFiles"),
            csidl_path(0x26).unwrap()
        );
        assert_eq!(value(&environment, "windir"), csidl_path(0x24).unwrap());
        assert_eq!(
            format!(
                "{}{}",
                value(&environment, "HOMEDRIVE"),
                value(&environment, "HOMEPATH")
            ),
            PROFILE
        );
        assert_eq!(PROFILE, format!(r"{USERS}\{USER_NAME}"));
        assert!(value(&environment, "TEMP").starts_with(LOCAL_APP_DATA));
        assert_eq!(temp_path(&environment), format!(r"{TEMP}\"));
        assert_eq!(value(&environment, "USERNAME"), USER_NAME);
        assert_eq!(value(&environment, "COMPUTERNAME"), COMPUTER_NAME);
        assert!(COMPUTER_NAME.len() <= 15);
    }

    #[test]
    fn path_lists_windows_directories_before_extra_entries() {
        let environment = default_environment(&[r"C:\Tools"]);
        let path: Vec<_> = value(&environment, "PATH").split(';').collect();
        assert_eq!(path[0], SYSTEM32);
        assert_eq!(path[1], WINDOWS);
        assert_eq!(path.last(), Some(&r"C:\Tools"));
        let names: Vec<_> = environment
            .iter()
            .map(|(name, _)| name.to_ascii_uppercase())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn temp_path_follows_the_windows_lookup_order() {
        let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect()
        };
        assert_eq!(
            temp_path(&env(&[("TEMP", r"C:\b"), ("TMP", r"C:\a")])),
            r"C:\a\"
        );
        assert_eq!(temp_path(&env(&[("TEMP", r"C:\b\")])), r"C:\b\");
        assert_eq!(
            temp_path(&env(&[("TMP", ""), ("USERPROFILE", PROFILE)])),
            format!(r"{PROFILE}\")
        );
        assert_eq!(temp_path(&[]), format!(r"{WINDOWS}\"));
    }
}
