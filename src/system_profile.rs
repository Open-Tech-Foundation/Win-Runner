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

/// The physical memory the guest reports when nothing configures it.
pub const DEFAULT_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
/// The least memory `--memory` accepts.
pub const MINIMUM_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// A memory size: bytes, or a number with a `K`, `M`, `G` or `T` suffix
/// (binary units, an optional trailing `B`, any case).
pub fn parse_memory_size(text: &str) -> Result<u64, String> {
    let trimmed = text.trim();
    let upper = trimmed.to_ascii_uppercase();
    let upper = upper.strip_suffix('B').unwrap_or(&upper);
    let (number, shift) = match upper.chars().last() {
        Some('K') => (&upper[..upper.len() - 1], 10),
        Some('M') => (&upper[..upper.len() - 1], 20),
        Some('G') => (&upper[..upper.len() - 1], 30),
        Some('T') => (&upper[..upper.len() - 1], 40),
        _ => (upper, 0),
    };
    let value: u64 = number
        .trim()
        .parse()
        .map_err(|_| format!("invalid memory size {trimmed:?} (use e.g. 4096M or 8G)"))?;
    let bytes = value
        .checked_mul(1u64 << shift)
        .ok_or_else(|| format!("memory size {trimmed:?} is too large"))?;
    if bytes < MINIMUM_MEMORY_BYTES {
        return Err(format!("memory size {trimmed:?} is below the 64M minimum"));
    }
    Ok(bytes)
}

/// The guest's physical memory: `WINRUN_MEMORY` (set by `--memory`), else
/// 512 MiB.
pub fn memory_bytes() -> u64 {
    static MEMORY: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
        std::env::var("WINRUN_MEMORY")
            .ok()
            .and_then(|value| parse_memory_size(&value).ok())
            .unwrap_or(DEFAULT_MEMORY_BYTES)
    });
    *MEMORY
}
/// The build `GetVersionEx`, `RtlGetVersion`, and the registry report
/// (Windows 10 22H2).
pub const OS_BUILD_NUMBER: u32 = 19045;
pub const OS_BUILD: &str = "19045";
/// `IsProcessorFeaturePresent`: the `PF_*` features of the host CPU the
/// guest runs on (baseline x86-64 features are always present).
pub fn processor_feature_present(feature: u32) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        match feature {
            2 | 3 | 6 | 8 | 9 | 10 | 12 => true,
            13 => std::is_x86_feature_detected!("sse3"),
            17 => std::is_x86_feature_detected!("xsave"),
            36 => std::is_x86_feature_detected!("ssse3"),
            37 => std::is_x86_feature_detected!("sse4.1"),
            38 => std::is_x86_feature_detected!("sse4.2"),
            39 => std::is_x86_feature_detected!("avx"),
            40 => std::is_x86_feature_detected!("avx2"),
            41 => std::is_x86_feature_detected!("avx512f"),
            60 => std::is_x86_feature_detected!("bmi2"),
            _ => false,
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        matches!(feature, 2 | 3 | 6 | 8 | 9 | 10 | 12)
    }
}

/// The local account's security identifier, as `ProfileList` and
/// `HKEY_USERS` name it.
pub const USER_SID: &str = "S-1-5-21-1000000000-1000000000-1000000000-1001";

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
pub const WINDOWS_APPS: &str = r"C:\Users\runner\AppData\Local\Microsoft\WindowsApps";

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
    WINDOWS_APPS,
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

/// The environment a new logon session starts with on a stock disk; a
/// session on an existing disk composes it from that disk's registry with
/// [`winreg::login_environment`](crate::winreg::login_environment).
pub fn default_environment() -> Vec<(String, String)> {
    crate::winreg::login_environment(&crate::winreg::Registry::defaults())
}

/// `SHGetFolderPath` CSIDL values (flags masked off) for the folders above.
/// `SHGetKnownFolderPath`'s folders by KNOWNFOLDERID, as text GUIDs.
pub fn known_folder_path(id: &str) -> Option<&'static str> {
    Some(match id.to_ascii_uppercase().as_str() {
        "B4BFCC3A-DB2C-424C-B029-7FE99A87C641" => DESKTOP,
        "FDD39AD0-238F-46AF-ADB4-6C85480369C7" => DOCUMENTS,
        "374DE290-123F-4565-9164-39C4925E467B" => DOWNLOADS,
        "4BD8D571-6D19-48D3-BE97-422220080E43" => MUSIC,
        "33E28130-4E1E-4676-835A-98395C3BC3BB" => PICTURES,
        "18989B1D-99B5-455B-841C-AB7C74E4DDFC" => VIDEOS,
        "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D" => APP_DATA,
        "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" => LOCAL_APP_DATA,
        "A520A1A4-1780-4FF6-BD18-167343C5AF16" => LOCAL_LOW_APP_DATA,
        "5E6C858F-0E22-4760-9AFE-EA3317B67173" => PROFILE,
        "0762D272-C50A-4BB0-A382-697DCD729B80" => USERS,
        "DFDF76A2-C82A-4D63-906A-5644AC457385" => PUBLIC,
        "ED4824AF-DCE4-45A8-81E2-FC7965083634" => PUBLIC_DOCUMENTS,
        "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97" => PROGRAM_DATA,
        "F38BF404-1D43-42F2-9305-67DE0B28FC23" => WINDOWS,
        "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7" => SYSTEM32,
        "905E63B6-C1BF-494E-B29C-65B732D3D21A" => PROGRAM_FILES,
        "6D809377-6AF0-444B-8957-A3773F02200E" => PROGRAM_FILES,
        "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E" => PROGRAM_FILES_X86,
        "F7F1ED05-9F6D-47A2-AAAE-29D317C6F066" => COMMON_FILES,
        "6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D" => COMMON_FILES,
        "DE974D24-D9C6-4D3E-BF91-F4455120B917" => COMMON_FILES_X86,
        _ => return None,
    })
}

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

    #[test]
    fn memory_sizes_parse_with_binary_suffixes() {
        assert_eq!(parse_memory_size("8G"), Ok(8 << 30));
        assert_eq!(parse_memory_size("4096m"), Ok(4096 << 20));
        assert_eq!(parse_memory_size("2gb"), Ok(2 << 30));
        assert_eq!(parse_memory_size("134217728"), Ok(128 << 20));
        assert!(parse_memory_size("1M").is_err(), "below the minimum");
        assert!(parse_memory_size("lots").is_err());
        assert!(parse_memory_size("99999999999T").is_err(), "overflow");
    }

    fn value<'a>(environment: &'a [(String, String)], key: &str) -> &'a str {
        environment
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("missing {key}"))
    }

    #[test]
    fn environment_and_known_folders_describe_the_same_profile() {
        let environment = default_environment();
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
