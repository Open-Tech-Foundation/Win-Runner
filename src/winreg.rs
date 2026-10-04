//! The guest Windows registry, stored in WinFS so snapshots keep it.
//!
//! Two hives back the predefined keys: `HKEY_LOCAL_MACHINE` in
//! `C:\Windows\System32\config\machine.json` and `HKEY_CURRENT_USER` in the
//! profile's `NTUSER.json`. A hive file that does not exist yet reads as the
//! stock contents from [`Registry::defaults`], so a fresh disk needs no
//! seeding and only written hives take space. The same registry supplies the
//! logon environment ([`login_environment`]) that shells and programs start
//! with.

use crate::{system_profile as profile, winfs::WinFs};
use serde_json::{json, Map, Value as Json};
use std::collections::BTreeMap;

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

pub const MACHINE_HIVE_FILE: &str = r"C:\Windows\System32\config\machine.json";
pub const USER_HIVE_FILE: &str = r"C:\Users\runner\NTUSER.json";

pub const MACHINE_ENVIRONMENT: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
pub const USER_ENVIRONMENT: &str = "Environment";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

impl Hive {
    pub fn root_name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
            Hive::CurrentUser => "HKEY_CURRENT_USER",
        }
    }

    fn file(self) -> &'static str {
        match self {
            Hive::LocalMachine => MACHINE_HIVE_FILE,
            Hive::CurrentUser => USER_HIVE_FILE,
        }
    }
}

/// Split a full key name such as `HKLM\SOFTWARE\Foo` or
/// `HKEY_CURRENT_USER\Environment` into its hive and subkey path.
/// `HKEY_CLASSES_ROOT` is the machine's `SOFTWARE\Classes`, and
/// `HKEY_USERS\<runner's SID>` is the current user.
pub fn parse_key_name(name: &str) -> Option<(Hive, String)> {
    let name = name.trim().trim_matches('\\');
    let (root, rest) = name.split_once('\\').unwrap_or((name, ""));
    let join = |prefix: &str| {
        if rest.is_empty() {
            prefix.to_string()
        } else {
            format!(r"{prefix}\{rest}")
        }
    };
    match root.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Some((Hive::LocalMachine, rest.to_string())),
        "HKCU" | "HKEY_CURRENT_USER" => Some((Hive::CurrentUser, rest.to_string())),
        "HKCR" | "HKEY_CLASSES_ROOT" => Some((Hive::LocalMachine, join(r"SOFTWARE\Classes"))),
        "HKU" | "HKEY_USERS" => {
            let (sid, rest) = rest.split_once('\\').unwrap_or((rest, ""));
            sid.eq_ignore_ascii_case(profile::USER_SID)
                .then(|| (Hive::CurrentUser, rest.to_string()))
        }
        _ => None,
    }
}

/// Key path components, dropping empty segments.
fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split('\\').filter(|part| !part.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegValue {
    pub kind: u32,
    pub data: Vec<u8>,
}

impl RegValue {
    pub fn string(text: &str) -> Self {
        Self::text(REG_SZ, text)
    }

    pub fn expand_string(text: &str) -> Self {
        Self::text(REG_EXPAND_SZ, text)
    }

    pub fn dword(value: u32) -> Self {
        RegValue {
            kind: REG_DWORD,
            data: value.to_le_bytes().to_vec(),
        }
    }

    pub fn multi_string(items: &[&str]) -> Self {
        let mut units = Vec::new();
        for item in items {
            units.extend(item.encode_utf16());
            units.push(0);
        }
        units.push(0);
        RegValue {
            kind: REG_MULTI_SZ,
            data: units.iter().flat_map(|unit| unit.to_le_bytes()).collect(),
        }
    }

    fn text(kind: u32, text: &str) -> Self {
        RegValue {
            kind,
            data: text
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(|unit| unit.to_le_bytes())
                .collect(),
        }
    }

    fn units(&self) -> Option<Vec<u16>> {
        self.data.len().is_multiple_of(2).then(|| {
            self.data
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect()
        })
    }

    /// The text of a `REG_SZ` or `REG_EXPAND_SZ` value, without its NUL.
    pub fn as_str(&self) -> Option<String> {
        if !matches!(self.kind, REG_SZ | REG_EXPAND_SZ) {
            return None;
        }
        let units = self.units()?;
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        String::from_utf16(&units[..end]).ok()
    }

    pub fn as_multi(&self) -> Option<Vec<String>> {
        if self.kind != REG_MULTI_SZ {
            return None;
        }
        let units = self.units()?;
        units
            .split(|unit| *unit == 0)
            .filter(|item| !item.is_empty())
            .map(|item| String::from_utf16(item).ok())
            .collect()
    }

    pub fn as_dword(&self) -> Option<u32> {
        (self.kind == REG_DWORD && self.data.len() == 4)
            .then(|| u32::from_le_bytes(self.data[..4].try_into().unwrap()))
    }

    pub fn as_qword(&self) -> Option<u64> {
        (self.kind == REG_QWORD && self.data.len() == 8)
            .then(|| u64::from_le_bytes(self.data[..8].try_into().unwrap()))
    }

    fn to_json(&self) -> Json {
        let lossless_text = self
            .as_str()
            .filter(|text| RegValue::text(self.kind, text).data == self.data);
        if let Some(text) = lossless_text {
            return json!({"type": self.kind, "string": text});
        }
        if let Some(items) = self.as_multi() {
            let refs: Vec<&str> = items.iter().map(String::as_str).collect();
            if RegValue::multi_string(&refs).data == self.data {
                return json!({"type": self.kind, "strings": items});
            }
        }
        if let Some(value) = self.as_dword() {
            return json!({"type": self.kind, "dword": value});
        }
        if let Some(value) = self.as_qword() {
            return json!({"type": self.kind, "qword": value});
        }
        let hex: String = self.data.iter().map(|byte| format!("{byte:02x}")).collect();
        json!({"type": self.kind, "hex": hex})
    }

    fn from_json(value: &Json) -> Result<Self, String> {
        let kind = value
            .get("type")
            .and_then(Json::as_u64)
            .and_then(|kind| u32::try_from(kind).ok())
            .ok_or("registry value lacks a type")?;
        if let Some(text) = value.get("string").and_then(Json::as_str) {
            return Ok(RegValue::text(kind, text));
        }
        if let Some(items) = value.get("strings").and_then(Json::as_array) {
            let items: Vec<&str> = items.iter().filter_map(Json::as_str).collect();
            return Ok(RegValue {
                kind,
                ..RegValue::multi_string(&items)
            });
        }
        if let Some(number) = value.get("dword").and_then(Json::as_u64) {
            let number = u32::try_from(number).map_err(|_| "registry DWORD out of range")?;
            return Ok(RegValue {
                kind,
                data: number.to_le_bytes().to_vec(),
            });
        }
        if let Some(number) = value.get("qword").and_then(Json::as_u64) {
            return Ok(RegValue {
                kind,
                data: number.to_le_bytes().to_vec(),
            });
        }
        let hex = value
            .get("hex")
            .and_then(Json::as_str)
            .ok_or("registry value lacks data")?;
        if !hex.len().is_multiple_of(2) {
            return Err("registry value has odd-length hex data".to_string());
        }
        let data = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "registry value has invalid hex data")?;
        Ok(RegValue { kind, data })
    }
}

/// A key: named values and subkeys, both matched case-insensitively while
/// keeping the spelling they were created with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Key {
    subkeys: BTreeMap<String, (String, Key)>,
    values: BTreeMap<String, (String, RegValue)>,
}

impl Key {
    pub fn subkey(&self, name: &str) -> Option<&Key> {
        self.subkeys.get(&name.to_lowercase()).map(|(_, key)| key)
    }

    fn subkey_mut(&mut self, name: &str) -> Option<&mut Key> {
        self.subkeys
            .get_mut(&name.to_lowercase())
            .map(|(_, key)| key)
    }

    fn subkey_or_create(&mut self, name: &str) -> &mut Key {
        &mut self
            .subkeys
            .entry(name.to_lowercase())
            .or_insert_with(|| (name.to_string(), Key::default()))
            .1
    }

    pub fn value(&self, name: &str) -> Option<&RegValue> {
        self.values
            .get(&name.to_lowercase())
            .map(|(_, value)| value)
    }

    pub fn set_value(&mut self, name: &str, value: RegValue) {
        let entry = self
            .values
            .entry(name.to_lowercase())
            .or_insert_with(|| (name.to_string(), value.clone()));
        entry.1 = value;
    }

    pub fn delete_value(&mut self, name: &str) -> bool {
        self.values.remove(&name.to_lowercase()).is_some()
    }

    /// Subkey names in stable (case-insensitive) order.
    pub fn subkey_names(&self) -> Vec<&str> {
        self.subkeys
            .values()
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// `(name, value)` pairs in stable (case-insensitive) order; the
    /// unnamed default value has the empty name.
    pub fn values(&self) -> Vec<(&str, &RegValue)> {
        self.values
            .values()
            .map(|(name, value)| (name.as_str(), value))
            .collect()
    }

    fn to_json(&self) -> Json {
        let mut keys = Map::new();
        for (name, key) in self.subkeys.values() {
            keys.insert(name.clone(), key.to_json());
        }
        let mut values = Map::new();
        for (name, value) in self.values.values() {
            values.insert(name.clone(), value.to_json());
        }
        json!({"keys": keys, "values": values})
    }

    fn from_json(value: &Json) -> Result<Self, String> {
        let mut key = Key::default();
        if let Some(values) = value.get("values").and_then(Json::as_object) {
            for (name, value) in values {
                key.set_value(name, RegValue::from_json(value)?);
            }
        }
        if let Some(keys) = value.get("keys").and_then(Json::as_object) {
            for (name, subkey) in keys {
                key.subkeys
                    .insert(name.to_lowercase(), (name.clone(), Key::from_json(subkey)?));
            }
        }
        Ok(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registry {
    machine: Key,
    user: Key,
}

impl Registry {
    /// The hives as saved in `fs`, or the stock contents for a hive that has
    /// never been written.
    pub fn load(fs: &WinFs) -> Result<Self, String> {
        let defaults = Registry::defaults();
        let read = |hive: Hive, default: Key| -> Result<Key, String> {
            if !fs.is_file(hive.file()) {
                return Ok(default);
            }
            let bytes = fs
                .read_file(hive.file())
                .map_err(|error| format!("cannot read registry hive {}: {error}", hive.file()))?;
            let value: Json = serde_json::from_slice(&bytes)
                .map_err(|error| format!("registry hive {} is invalid: {error}", hive.file()))?;
            Key::from_json(&value)
                .map_err(|error| format!("registry hive {} is invalid: {error}", hive.file()))
        };
        Ok(Registry {
            machine: read(Hive::LocalMachine, defaults.machine)?,
            user: read(Hive::CurrentUser, defaults.user)?,
        })
    }

    /// Write one hive back to its file.
    pub fn save(&self, fs: &mut WinFs, hive: Hive) -> Result<(), String> {
        let file = hive.file();
        if let Some((directory, _)) = file.rsplit_once('\\') {
            fs.mkdir(directory)?;
        }
        let data = serde_json::to_vec_pretty(&self.root(hive).to_json())
            .map_err(|error| format!("cannot encode registry hive: {error}"))?;
        fs.write_file(file, data)
    }

    pub fn root(&self, hive: Hive) -> &Key {
        match hive {
            Hive::LocalMachine => &self.machine,
            Hive::CurrentUser => &self.user,
        }
    }

    fn root_mut(&mut self, hive: Hive) -> &mut Key {
        match hive {
            Hive::LocalMachine => &mut self.machine,
            Hive::CurrentUser => &mut self.user,
        }
    }

    pub fn key(&self, hive: Hive, path: &str) -> Option<&Key> {
        components(path).try_fold(self.root(hive), |key, name| key.subkey(name))
    }

    pub fn key_mut(&mut self, hive: Hive, path: &str) -> Option<&mut Key> {
        components(path).try_fold(self.root_mut(hive), |key, name| key.subkey_mut(name))
    }

    /// Open or create `path`; the flag says whether it already existed.
    pub fn create_key(&mut self, hive: Hive, path: &str) -> (&mut Key, bool) {
        let existed = self.key(hive, path).is_some();
        let key =
            components(path).fold(self.root_mut(hive), |key, name| key.subkey_or_create(name));
        (key, existed)
    }

    /// Delete a key. Like `RegDeleteKey`, a key with subkeys stays unless
    /// `tree` is set; the hive roots cannot be deleted.
    pub fn delete_key(&mut self, hive: Hive, path: &str, tree: bool) -> Result<(), String> {
        let parts: Vec<&str> = components(path).collect();
        let Some((leaf, parents)) = parts.split_last() else {
            return Err("cannot delete a registry root".to_string());
        };
        let parent = parents
            .iter()
            .try_fold(self.root_mut(hive), |key, name| key.subkey_mut(name))
            .ok_or("registry key not found")?;
        match parent.subkey(leaf) {
            None => Err("registry key not found".to_string()),
            Some(key) if !tree && !key.subkeys.is_empty() => {
                Err("registry key has subkeys".to_string())
            }
            Some(_) => {
                parent.subkeys.remove(&leaf.to_lowercase());
                Ok(())
            }
        }
    }

    pub fn value(&self, hive: Hive, path: &str, name: &str) -> Option<&RegValue> {
        self.key(hive, path)?.value(name)
    }

    pub fn set_value(&mut self, hive: Hive, path: &str, name: &str, value: RegValue) {
        self.create_key(hive, path).0.set_value(name, value);
    }

    /// The registry of a stock installation for [`system_profile`](profile).
    pub fn defaults() -> Self {
        let mut registry = Registry {
            machine: Key::default(),
            user: Key::default(),
        };
        let machine = Hive::LocalMachine;
        let user = Hive::CurrentUser;
        let set = |registry: &mut Registry, hive, path: &str, values: &[(&str, RegValue)]| {
            let key = registry.create_key(hive, path).0;
            for (name, value) in values {
                key.set_value(name, value.clone());
            }
        };
        let sz = RegValue::string;
        let expand = RegValue::expand_string;

        set(
            &mut registry,
            machine,
            MACHINE_ENVIRONMENT,
            &[
                ("ComSpec", expand(r"%SystemRoot%\System32\cmd.exe")),
                ("DriverData", sz(r"C:\Windows\System32\Drivers\DriverData")),
                (
                    "NUMBER_OF_PROCESSORS",
                    sz(&profile::PROCESSOR_COUNT.to_string()),
                ),
                ("OS", sz("Windows_NT")),
                (
                    "Path",
                    expand(&format!(
                        r"%SystemRoot%\System32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SystemRoot%\System32\WindowsPowerShell\v1.0\;{}",
                        crate::wpkg::BIN
                    )),
                ),
                (
                    "PATHEXT",
                    sz(".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"),
                ),
                (
                    "PROCESSOR_ARCHITECTURE",
                    sz(profile::processor_architecture()),
                ),
                ("PROCESSOR_LEVEL", sz("6")),
                (
                    "PSModulePath",
                    expand(
                        r"%ProgramFiles%\WindowsPowerShell\Modules;%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules",
                    ),
                ),
                ("TEMP", expand(r"%SystemRoot%\TEMP")),
                ("TMP", expand(r"%SystemRoot%\TEMP")),
                ("windir", expand("%SystemRoot%")),
            ],
        );
        set(
            &mut registry,
            machine,
            r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
            &[("ComputerName", sz(profile::COMPUTER_NAME))],
        );
        set(
            &mut registry,
            machine,
            r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
            &[("ComputerName", sz(profile::COMPUTER_NAME))],
        );
        set(
            &mut registry,
            machine,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            &[
                ("CurrentBuild", sz(profile::OS_BUILD)),
                ("CurrentBuildNumber", sz(profile::OS_BUILD)),
                ("CurrentMajorVersionNumber", RegValue::dword(10)),
                ("CurrentMinorVersionNumber", RegValue::dword(0)),
                ("CurrentType", sz("Multiprocessor Free")),
                ("CurrentVersion", sz("6.3")),
                ("DisplayVersion", sz("22H2")),
                ("EditionID", sz("Professional")),
                ("InstallationType", sz("Client")),
                ("PathName", sz(profile::WINDOWS)),
                ("ProductName", sz("Windows 10 Pro")),
                ("RegisteredOwner", sz(profile::USER_NAME)),
                ("ReleaseId", sz("2009")),
                ("SystemRoot", sz(profile::WINDOWS)),
            ],
        );
        set(
            &mut registry,
            machine,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
            &[
                ("Default", expand(r"%SystemDrive%\Users\Default")),
                ("ProfilesDirectory", expand(r"%SystemDrive%\Users")),
                ("ProgramData", expand(r"%SystemDrive%\ProgramData")),
                ("Public", expand(r"%SystemDrive%\Users\Public")),
            ],
        );
        set(
            &mut registry,
            machine,
            &format!(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{}",
                profile::USER_SID
            ),
            &[("ProfileImagePath", sz(profile::PROFILE))],
        );
        set(
            &mut registry,
            machine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion",
            &[
                ("CommonFilesDir", sz(profile::COMMON_FILES)),
                ("CommonFilesDir (x86)", sz(profile::COMMON_FILES_X86)),
                ("CommonW6432Dir", sz(profile::COMMON_FILES)),
                ("ProgramFilesDir", sz(profile::PROGRAM_FILES)),
                ("ProgramFilesDir (x86)", sz(profile::PROGRAM_FILES_X86)),
                ("ProgramFilesPath", expand("%ProgramFiles%")),
                ("ProgramW6432Dir", sz(profile::PROGRAM_FILES)),
            ],
        );
        registry.create_key(
            machine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        );
        registry.create_key(machine, r"SOFTWARE\Classes");

        set(
            &mut registry,
            user,
            USER_ENVIRONMENT,
            &[
                (
                    "Path",
                    expand(r"%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;%APPDATA%\npm;"),
                ),
                ("TEMP", expand(r"%USERPROFILE%\AppData\Local\Temp")),
                ("TMP", expand(r"%USERPROFILE%\AppData\Local\Temp")),
            ],
        );
        set(
            &mut registry,
            user,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            &[
                ("AppData", expand(r"%USERPROFILE%\AppData\Roaming")),
                ("Desktop", expand(r"%USERPROFILE%\Desktop")),
                ("Local AppData", expand(r"%USERPROFILE%\AppData\Local")),
                ("My Music", expand(r"%USERPROFILE%\Music")),
                ("My Pictures", expand(r"%USERPROFILE%\Pictures")),
                ("My Video", expand(r"%USERPROFILE%\Videos")),
                ("Personal", expand(r"%USERPROFILE%\Documents")),
                (
                    "{374DE290-123F-4565-9164-39C4925E467B}",
                    expand(r"%USERPROFILE%\Downloads"),
                ),
            ],
        );
        set(
            &mut registry,
            user,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            &[
                ("AppData", sz(profile::APP_DATA)),
                ("Desktop", sz(profile::DESKTOP)),
                ("Local AppData", sz(profile::LOCAL_APP_DATA)),
                ("My Music", sz(profile::MUSIC)),
                ("My Pictures", sz(profile::PICTURES)),
                ("My Video", sz(profile::VIDEOS)),
                ("Personal", sz(profile::DOCUMENTS)),
                (
                    "{374DE290-123F-4565-9164-39C4925E467B}",
                    sz(profile::DOWNLOADS),
                ),
            ],
        );
        registry.create_key(user, "Software");
        registry
    }
}

/// Replace `%NAME%` references with values from `environment`; unknown
/// names stay as written, like `ExpandEnvironmentStrings`.
pub fn expand_environment_strings(text: &str, environment: &[(String, String)]) -> String {
    let mut output = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            output.push_str(&rest[start..]);
            return output;
        };
        let name = &after[..end];
        match environment
            .iter()
            .find(|(key, _)| !name.is_empty() && key.eq_ignore_ascii_case(name))
        {
            Some((_, value)) => {
                output.push_str(value);
                rest = &after[end + 1..];
            }
            None => {
                // Keep the first `%` literal and rescan from the second,
                // which may open a real reference.
                output.push('%');
                output.push_str(name);
                rest = &after[end..];
            }
        }
    }
    output.push_str(rest);
    output
}

fn upsert(environment: &mut Vec<(String, String)>, name: &str, value: String) {
    match environment
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
    {
        Some(entry) => entry.1 = value,
        None => environment.push((name.to_string(), value)),
    }
}

/// Apply one environment key: plain strings first, then expandable ones,
/// which may refer to the plain ones. A user `Path` extends the machine's.
fn apply_environment_key(environment: &mut Vec<(String, String)>, key: Option<&Key>, user: bool) {
    let Some(key) = key else {
        return;
    };
    for pass_kind in [REG_SZ, REG_EXPAND_SZ] {
        for (name, value) in key.values() {
            if value.kind != pass_kind || name.is_empty() {
                continue;
            }
            let Some(text) = value.as_str() else {
                continue;
            };
            let text = if pass_kind == REG_EXPAND_SZ {
                expand_environment_strings(&text, environment)
            } else {
                text
            };
            let text = if user && name.eq_ignore_ascii_case("Path") {
                match environment
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("Path"))
                    .map(|(_, value)| value.trim_end_matches(';').to_string())
                {
                    Some(machine) if !machine.is_empty() => format!("{machine};{text}"),
                    _ => text,
                }
            } else {
                text
            };
            upsert(environment, name, text);
        }
    }
}

/// The environment a logon session starts with, composed the way Windows'
/// `CreateEnvironmentBlock` does: the user's profile variables, then the
/// machine environment key, then the user environment key.
pub fn login_environment(registry: &Registry) -> Vec<(String, String)> {
    let mut environment: Vec<(String, String)> = [
        ("ALLUSERSPROFILE", profile::PROGRAM_DATA),
        ("APPDATA", profile::APP_DATA),
        ("CommonProgramFiles", profile::COMMON_FILES),
        ("CommonProgramFiles(x86)", profile::COMMON_FILES_X86),
        ("CommonProgramW6432", profile::COMMON_FILES),
        ("COMPUTERNAME", profile::COMPUTER_NAME),
        ("HOMEDRIVE", profile::SYSTEM_DRIVE),
        ("HOMEPATH", profile::HOME_PATH),
        ("LOCALAPPDATA", profile::LOCAL_APP_DATA),
        ("ProgramData", profile::PROGRAM_DATA),
        ("ProgramFiles", profile::PROGRAM_FILES),
        ("ProgramFiles(x86)", profile::PROGRAM_FILES_X86),
        ("ProgramW6432", profile::PROGRAM_FILES),
        ("PUBLIC", profile::PUBLIC),
        ("SESSIONNAME", "Console"),
        ("SystemDrive", profile::SYSTEM_DRIVE),
        ("SystemRoot", profile::WINDOWS),
        ("USERDOMAIN", profile::COMPUTER_NAME),
        ("USERDOMAIN_ROAMINGPROFILE", profile::COMPUTER_NAME),
        ("USERNAME", profile::USER_NAME),
        ("USERPROFILE", profile::PROFILE),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect();
    environment.push((
        "LOGONSERVER".to_string(),
        format!(r"\\{}", profile::COMPUTER_NAME),
    ));
    apply_environment_key(
        &mut environment,
        registry.key(Hive::LocalMachine, MACHINE_ENVIRONMENT),
        false,
    );
    apply_environment_key(
        &mut environment,
        registry.key(Hive::CurrentUser, USER_ENVIRONMENT),
        true,
    );
    environment.sort_by_key(|(name, _)| name.to_ascii_uppercase());
    environment
}

/// Where a persistent environment variable lives.
pub fn environment_key(hive: Hive) -> &'static str {
    match hive {
        Hive::LocalMachine => MACHINE_ENVIRONMENT,
        Hive::CurrentUser => USER_ENVIRONMENT,
    }
}

/// Persist (or, for an empty value, delete) a `User` or `Machine`
/// environment variable. Values that reference `%VARIABLES%` are stored as
/// `REG_EXPAND_SZ`, as `setx` does.
pub fn set_persistent_environment(
    fs: &mut WinFs,
    hive: Hive,
    name: &str,
    value: &str,
) -> Result<(), String> {
    if name.is_empty() || name.contains('=') {
        return Err(format!("invalid environment variable name: {name:?}"));
    }
    let mut registry = Registry::load(fs)?;
    let path = environment_key(hive);
    if value.is_empty() {
        if let Some(key) = registry.key_mut(hive, path) {
            key.delete_value(name);
        }
    } else if value.contains('%') {
        registry.set_value(hive, path, name, RegValue::expand_string(value));
    } else {
        registry.set_value(hive, path, name, RegValue::string(value));
    }
    registry.save(fs, hive)
}

/// A `User` or `Machine` environment variable as stored, expanded with
/// `environment` when it is `REG_EXPAND_SZ`.
pub fn persistent_environment(
    fs: &WinFs,
    hive: Hive,
    name: &str,
    environment: &[(String, String)],
) -> Result<Option<String>, String> {
    let registry = Registry::load(fs)?;
    Ok(registry
        .value(hive, environment_key(hive), name)
        .and_then(|value| {
            let text = value.as_str()?;
            Some(if value.kind == REG_EXPAND_SZ {
                expand_environment_strings(&text, environment)
            } else {
                text
            })
        }))
}

pub fn type_name(kind: u32) -> &'static str {
    match kind {
        0 => "REG_NONE",
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY => "REG_BINARY",
        REG_DWORD => "REG_DWORD",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_QWORD => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

pub fn type_from_name(name: &str) -> Option<u32> {
    Some(match name.to_ascii_uppercase().as_str() {
        "REG_NONE" => 0,
        "REG_SZ" => REG_SZ,
        "REG_EXPAND_SZ" => REG_EXPAND_SZ,
        "REG_BINARY" => REG_BINARY,
        "REG_DWORD" => REG_DWORD,
        "REG_MULTI_SZ" => REG_MULTI_SZ,
        "REG_QWORD" => REG_QWORD,
        _ => return None,
    })
}

/// A value's data as `reg query` prints it.
pub fn display_data(value: &RegValue) -> String {
    if let Some(text) = value.as_str() {
        return text;
    }
    if let Some(items) = value.as_multi() {
        return items.join(r"\0");
    }
    if let Some(number) = value.as_dword() {
        return format!("0x{number:x}");
    }
    if let Some(number) = value.as_qword() {
        return format!("0x{number:x}");
    }
    value
        .data
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(environment: &'a [(String, String)], name: &str) -> &'a str {
        environment
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    #[test]
    fn stock_logon_environment_expands_machine_then_user_keys() {
        let environment = login_environment(&Registry::defaults());
        assert_eq!(lookup(&environment, "USERPROFILE"), profile::PROFILE);
        assert_eq!(
            lookup(&environment, "ComSpec"),
            r"C:\Windows\System32\cmd.exe"
        );
        assert_eq!(lookup(&environment, "windir"), profile::WINDOWS);
        // The user's TEMP overrides the machine's %SystemRoot%\TEMP.
        assert_eq!(lookup(&environment, "TEMP"), profile::TEMP);
        let path: Vec<_> = lookup(&environment, "Path").split(';').collect();
        assert_eq!(&path[..2], [profile::SYSTEM32, profile::WINDOWS]);
        assert!(path.contains(&crate::wpkg::BIN));
        // Machine entries come before the user's.
        assert_eq!(
            path.iter()
                .position(|entry| entry.ends_with(r"Microsoft\WindowsApps")),
            Some(path.len() - 3)
        );
        assert_eq!(path[path.len() - 2], format!(r"{}\npm", profile::APP_DATA));
        let names: Vec<_> = environment
            .iter()
            .map(|(name, _)| name.to_ascii_uppercase())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn expansion_keeps_unknown_references_and_rescans() {
        let environment = vec![("A".to_string(), "1".to_string())];
        assert_eq!(expand_environment_strings("%A%-%a%", &environment), "1-1");
        assert_eq!(expand_environment_strings("%X%%A%", &environment), "%X%1");
        assert_eq!(expand_environment_strings("100%", &environment), "100%");
        assert_eq!(expand_environment_strings("50%%A%", &environment), "50%1");
    }

    #[test]
    fn hives_round_trip_through_winfs_and_absent_files_read_as_defaults() {
        let mut fs = WinFs::ephemeral_runner();
        let mut registry = Registry::load(&fs).unwrap();
        assert_eq!(registry, Registry::defaults());
        registry.set_value(
            Hive::CurrentUser,
            r"Software\Tool",
            "Mode",
            RegValue::string("fast"),
        );
        registry.set_value(
            Hive::CurrentUser,
            r"software\TOOL",
            "Count",
            RegValue::dword(7),
        );
        registry.set_value(
            Hive::CurrentUser,
            r"Software\Tool",
            "List",
            RegValue::multi_string(&["a", "b"]),
        );
        registry.set_value(
            Hive::CurrentUser,
            r"Software\Tool",
            "Blob",
            RegValue {
                kind: REG_BINARY,
                data: vec![0, 255, 1],
            },
        );
        registry.save(&mut fs, Hive::CurrentUser).unwrap();
        assert!(fs.is_file(USER_HIVE_FILE));
        assert!(!fs.is_file(MACHINE_HIVE_FILE));

        let loaded = Registry::load(&fs).unwrap();
        assert_eq!(loaded, registry);
        let key = loaded.key(Hive::CurrentUser, r"SOFTWARE\tool").unwrap();
        assert_eq!(key.value("mode").unwrap().as_str().as_deref(), Some("fast"));
        assert_eq!(key.value("COUNT").unwrap().as_dword(), Some(7));
        assert_eq!(
            key.value("list").unwrap().as_multi(),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(
            loaded.root(Hive::CurrentUser).subkey_names(),
            ["Environment", "Software"]
        );
        assert_eq!(key.values()[0].0, "Blob");
    }

    #[test]
    fn delete_key_refuses_roots_and_nonempty_keys_unless_asked_for_a_tree() {
        let mut registry = Registry::defaults();
        registry.create_key(Hive::CurrentUser, r"Software\A\B");
        assert!(registry.delete_key(Hive::CurrentUser, "", false).is_err());
        assert!(registry
            .delete_key(Hive::CurrentUser, r"Software\A", false)
            .unwrap_err()
            .contains("subkeys"));
        registry
            .delete_key(Hive::CurrentUser, r"Software\A", true)
            .unwrap();
        assert!(registry.key(Hive::CurrentUser, r"Software\A").is_none());
        assert!(registry
            .delete_key(Hive::CurrentUser, r"Software\Missing", false)
            .is_err());
    }

    #[test]
    fn persistent_variables_shape_the_next_logon_environment() {
        let mut fs = WinFs::ephemeral_runner();
        set_persistent_environment(&mut fs, Hive::CurrentUser, "EDITOR", "vim").unwrap();
        set_persistent_environment(&mut fs, Hive::CurrentUser, "Path", r"%USERPROFILE%\bin")
            .unwrap();
        set_persistent_environment(&mut fs, Hive::LocalMachine, "JAVA_HOME", r"C:\jdk").unwrap();
        let registry = Registry::load(&fs).unwrap();
        assert_eq!(
            registry
                .value(Hive::CurrentUser, USER_ENVIRONMENT, "Path")
                .unwrap()
                .kind,
            REG_EXPAND_SZ
        );
        let environment = login_environment(&registry);
        assert_eq!(lookup(&environment, "EDITOR"), "vim");
        assert_eq!(lookup(&environment, "JAVA_HOME"), r"C:\jdk");
        assert!(lookup(&environment, "Path").ends_with(r";C:\Users\runner\bin"));
        assert_eq!(
            persistent_environment(&fs, Hive::CurrentUser, "path", &environment)
                .unwrap()
                .as_deref(),
            Some(r"C:\Users\runner\bin")
        );

        set_persistent_environment(&mut fs, Hive::CurrentUser, "EDITOR", "").unwrap();
        let environment = login_environment(&Registry::load(&fs).unwrap());
        assert!(environment.iter().all(|(name, _)| name != "EDITOR"));
        assert!(set_persistent_environment(&mut fs, Hive::CurrentUser, "A=B", "x").is_err());
    }

    #[test]
    fn key_names_accept_short_long_and_alias_roots() {
        assert_eq!(
            parse_key_name(r"HKLM\SOFTWARE\Foo"),
            Some((Hive::LocalMachine, r"SOFTWARE\Foo".to_string()))
        );
        assert_eq!(
            parse_key_name(r"hkey_current_user\Environment\"),
            Some((Hive::CurrentUser, "Environment".to_string()))
        );
        assert_eq!(
            parse_key_name(r"HKCR\.txt"),
            Some((Hive::LocalMachine, r"SOFTWARE\Classes\.txt".to_string()))
        );
        assert_eq!(
            parse_key_name(&format!(r"HKU\{}\Environment", profile::USER_SID)),
            Some((Hive::CurrentUser, "Environment".to_string()))
        );
        assert_eq!(parse_key_name(r"HKU\S-1-5-18\Environment"), None);
        assert_eq!(parse_key_name(r"HKXX\Foo"), None);
    }
}
