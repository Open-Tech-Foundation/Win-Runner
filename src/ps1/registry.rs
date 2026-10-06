//! The registry provider: `HKLM:`/`HKCU:` paths for the item cmdlets and
//! `Microsoft.Win32.RegistryKey` objects, both backed by the guest hives in
//! [`winreg`](crate::winreg).
//!
//! A key object is a map whose hidden entries (names starting with NUL, so
//! no script can spell them) record the hive and subkey path; its visible
//! `Name` member is the full key name, as in PowerShell.
use super::*;
use crate::winreg::{self, Hive, RegValue, Registry};

const TYPE: &str = "\0type";
const HIVE: &str = "\0hive";
const PATH: &str = "\0path";
const REGISTRY_KEY: &str = "RegistryKey";

/// `HKCU:\Software\x`, `HKLM:`, `Registry::HKEY_CURRENT_USER\x` and the
/// provider-qualified form as a hive and subkey path. `None` for any other
/// path (file system paths included).
pub(super) fn provider_path(path: &str) -> Option<(Hive, String)> {
    let path = path.trim();
    let lower = path.to_ascii_lowercase();
    for prefix in ["microsoft.powershell.core\\registry::", "registry::"] {
        if lower.starts_with(prefix) {
            return winreg::parse_key_name(&path[prefix.len()..]);
        }
    }
    let (drive, rest) = path.split_once(':')?;
    let hive = match drive.to_ascii_uppercase().as_str() {
        "HKLM" => Hive::LocalMachine,
        "HKCU" => Hive::CurrentUser,
        _ => return None,
    };
    if !(rest.is_empty() || rest.starts_with(['\\', '/'])) {
        return None;
    }
    let sub = rest
        .split(['\\', '/'])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\\");
    Some((hive, sub))
}

fn full_name(hive: Hive, path: &str) -> String {
    if path.is_empty() {
        hive.root_name().to_string()
    } else {
        format!(r"{}\{path}", hive.root_name())
    }
}

/// A `RegistryKey` object for an existing (or just created) key.
pub(super) fn key_object(hive: Hive, path: &str) -> Value {
    let mut map = HashMap::new();
    map.insert(TYPE.to_string(), Value::Str(REGISTRY_KEY.to_string()));
    map.insert(
        HIVE.to_string(),
        Value::Str(
            match hive {
                Hive::LocalMachine => "HKLM",
                Hive::CurrentUser => "HKCU",
            }
            .to_string(),
        ),
    );
    map.insert(PATH.to_string(), Value::Str(path.to_string()));
    map.insert("Name".to_string(), Value::Str(full_name(hive, path)));
    Value::Map(map)
}

/// The hive and path of a key object.
pub(super) fn as_key(value: &Value) -> Option<(Hive, String)> {
    let Value::Map(map) = value else {
        return None;
    };
    if map.get(TYPE) != Some(&Value::Str(REGISTRY_KEY.to_string())) {
        return None;
    }
    let hive = match map.get(HIVE) {
        Some(Value::Str(h)) if h == "HKLM" => Hive::LocalMachine,
        Some(Value::Str(h)) if h == "HKCU" => Hive::CurrentUser,
        _ => return None,
    };
    match map.get(PATH) {
        Some(Value::Str(path)) => Some((hive, path.clone())),
        _ => None,
    }
}

/// A key object's full name (`HKEY_CURRENT_USER\\x`).
pub(super) fn key_name(value: &Value) -> Option<String> {
    let (hive, path) = as_key(value)?;
    Some(full_name(hive, &path))
}

/// True for hidden object entries, which display and JSON leave out.
pub(super) fn is_hidden_member(name: &str) -> bool {
    name.starts_with('\0')
}

/// A value's data as PowerShell surfaces it: strings (expanded only when
/// asked), numbers in decimal, multi-strings as arrays, bytes as numbers.
fn data_value(
    value: &RegValue,
    expand: bool,
    environment: &[(String, String)],
) -> Value {
    if let Some(text) = value.as_str() {
        if expand && value.kind == winreg::REG_EXPAND_SZ {
            return Value::Str(winreg::expand_environment_strings(&text, environment));
        }
        return Value::Str(text);
    }
    if let Some(items) = value.as_multi() {
        return Value::Arr(items.into_iter().map(Value::Str).collect());
    }
    if let Some(number) = value.as_dword() {
        return Value::Str((number as i32).to_string());
    }
    if let Some(number) = value.as_qword() {
        return Value::Str((number as i64).to_string());
    }
    Value::Arr(
        value
            .data
            .iter()
            .map(|byte| Value::Str(byte.to_string()))
            .collect(),
    )
}

/// `RegistryValueKind` names, as `GetValueKind` returns and `SetValue`
/// and `New-ItemProperty -PropertyType` accept.
fn kind_name(kind: u32) -> &'static str {
    match kind {
        winreg::REG_SZ => "String",
        winreg::REG_EXPAND_SZ => "ExpandString",
        winreg::REG_BINARY => "Binary",
        winreg::REG_DWORD => "DWord",
        winreg::REG_MULTI_SZ => "MultiString",
        winreg::REG_QWORD => "QWord",
        _ => "Unknown",
    }
}

fn kind_from_name(name: &str) -> Result<u32, String> {
    Ok(match name.trim().to_ascii_lowercase().as_str() {
        "string" | "1" => winreg::REG_SZ,
        "expandstring" | "2" => winreg::REG_EXPAND_SZ,
        "binary" | "3" => winreg::REG_BINARY,
        "dword" | "4" => winreg::REG_DWORD,
        "multistring" | "7" => winreg::REG_MULTI_SZ,
        "qword" | "11" => winreg::REG_QWORD,
        _ => return Err(format!("unsupported registry value kind: {name}")),
    })
}

/// `[Microsoft.Win32.RegistryValueKind]::X` / `[...RegistryValueOptions]::X`.
pub(super) fn enum_member(typ: &str, member: &str) -> Option<String> {
    let t = typ.to_ascii_lowercase();
    let t = t.strip_prefix("microsoft.win32.").unwrap_or(&t);
    let m = member.to_ascii_lowercase();
    let known: &[&str] = match t {
        "registryvaluekind" => &[
            "String",
            "ExpandString",
            "Binary",
            "DWord",
            "MultiString",
            "QWord",
            "Unknown",
            "None",
        ],
        "registryvalueoptions" => &["None", "DoNotExpandEnvironmentNames"],
        _ => return None,
    };
    known
        .iter()
        .find(|name| name.to_ascii_lowercase() == m)
        .map(|name| name.to_string())
}

/// Encode script data as a value of `kind`.
fn encode(kind: u32, data: &Value) -> Result<RegValue, String> {
    let text = value_string(data);
    Ok(match kind {
        winreg::REG_SZ => RegValue::string(&text),
        winreg::REG_EXPAND_SZ => RegValue::expand_string(&text),
        winreg::REG_DWORD => RegValue::dword(
            parse_integer(&text)
                .filter(|n| i32::try_from(*n).is_ok() || u32::try_from(*n).is_ok())
                .ok_or_else(|| format!("not a DWord value: {text}"))? as u32,
        ),
        winreg::REG_QWORD => RegValue {
            kind,
            data: (parse_integer(&text).ok_or_else(|| format!("not a QWord value: {text}"))?
                as u64)
                .to_le_bytes()
                .to_vec(),
        },
        winreg::REG_MULTI_SZ => {
            let items: Vec<String> = match data {
                Value::Arr(items) => items.iter().map(value_string).collect(),
                _ => vec![text],
            };
            let refs: Vec<&str> = items.iter().map(String::as_str).collect();
            RegValue::multi_string(&refs)
        }
        winreg::REG_BINARY => {
            let bytes: Result<Vec<u8>, String> = match data {
                Value::Arr(items) => items
                    .iter()
                    .map(|item| {
                        let s = value_string(item);
                        parse_integer(&s)
                            .and_then(|n| u8::try_from(n).ok())
                            .ok_or_else(|| format!("not a byte: {s}"))
                    })
                    .collect(),
                _ => Err("Binary values need a byte array".to_string()),
            };
            RegValue { kind, data: bytes? }
        }
        _ => return Err("unsupported registry value kind".to_string()),
    })
}

fn parse_integer(text: &str) -> Option<i128> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i128::from_str_radix(hex, 16).ok();
    }
    t.parse().ok()
}

/// The kind `SetValue` infers from data without an explicit kind.
fn inferred_kind(data: &Value) -> u32 {
    match data {
        Value::Arr(_) => winreg::REG_MULTI_SZ,
        _ => winreg::REG_SZ,
    }
}

/// A void method's result: outputs nothing and reads as empty.
fn void() -> Value {
    Value::Arr(Vec::new())
}

fn not_found(path: &str) -> String {
    format!("Cannot find path '{path}' because it does not exist.")
}

impl Interpreter<'_> {
    fn registry(&self) -> Result<Registry, String> {
        Registry::load(self.fs)
    }

    /// `Get-Item HKCU:\x`: the key object.
    pub(super) fn registry_get_item(&mut self, path: &str) -> Result<Value, String> {
        let (hive, sub) = provider_path(path).ok_or_else(|| not_found(path))?;
        if self.registry()?.key(hive, &sub).is_none() {
            return Err(not_found(path));
        }
        Ok(key_object(hive, &sub))
    }

    /// `Test-Path HKCU:\x`.
    pub(super) fn registry_exists(&self, path: &str) -> Result<bool, String> {
        let Some((hive, sub)) = provider_path(path) else {
            return Ok(false);
        };
        Ok(self.registry()?.key(hive, &sub).is_some())
    }

    /// `New-Item HKCU:\x [-Force]`: create the key (and, with `-Force`,
    /// missing parents). An existing key is an error without `-Force`.
    pub(super) fn registry_new_item(&mut self, path: &str, force: bool) -> Result<Value, String> {
        let (hive, sub) = provider_path(path).ok_or_else(|| not_found(path))?;
        if sub.is_empty() {
            return Err(format!("New-Item: cannot create a registry root: {path}"));
        }
        let mut registry = self.registry()?;
        if !force {
            if registry.key(hive, &sub).is_some() {
                return Err(format!("New-Item: a key at this path already exists: {path}"));
            }
            let parent = sub.rsplit_once('\\').map_or("", |(parent, _)| parent);
            if registry.key(hive, parent).is_none() {
                return Err(not_found(&full_name(hive, parent)));
            }
        }
        registry.create_key(hive, &sub);
        registry.save(self.fs, hive)?;
        Ok(key_object(hive, &sub))
    }

    /// `Remove-Item HKCU:\x [-Recurse]`. A key with subkeys needs
    /// `-Recurse`, like the real provider without confirmation.
    pub(super) fn registry_remove_item(&mut self, path: &str, recurse: bool) -> Result<(), String> {
        let (hive, sub) = provider_path(path).ok_or_else(|| not_found(path))?;
        let mut registry = self.registry()?;
        if registry.key(hive, &sub).is_none() {
            return Err(not_found(path));
        }
        registry
            .delete_key(hive, &sub, recurse)
            .map_err(|e| format!("Remove-Item: {e}"))?;
        registry.save(self.fs, hive)
    }

    /// `Get-ItemProperty <key> [-Name n]`: an object with one member per
    /// value (REG_EXPAND_SZ expanded, as PowerShell does).
    pub(super) fn registry_item_property(
        &mut self,
        path: &str,
        name: Option<&str>,
    ) -> Result<Value, String> {
        let (hive, sub) = provider_path(path).ok_or_else(|| not_found(path))?;
        let registry = self.registry()?;
        let key = registry.key(hive, &sub).ok_or_else(|| not_found(path))?;
        let mut map = HashMap::new();
        for (value_name, value) in key.values() {
            if name.is_some_and(|n| !n.eq_ignore_ascii_case(value_name)) {
                continue;
            }
            map.insert(
                value_name.to_string(),
                data_value(value, true, self.environment),
            );
        }
        if let Some(n) = name {
            if map.is_empty() {
                return Err(format!("Property {n} does not exist at path {}.", full_name(hive, &sub)));
            }
        }
        Ok(Value::Map(map))
    }

    /// `New-ItemProperty` / `Set-ItemProperty`: write one value. `create`
    /// distinguishes New (fails on an existing value unless `force`) from
    /// Set (keeps an existing value's kind unless one is given).
    pub(super) fn registry_set_property(
        &mut self,
        path: &str,
        name: &str,
        data: &Value,
        kind: Option<&str>,
        create: bool,
        force: bool,
    ) -> Result<(), String> {
        let (hive, sub) = provider_path(path).ok_or_else(|| not_found(path))?;
        let mut registry = self.registry()?;
        let existing = registry
            .key(hive, &sub)
            .ok_or_else(|| not_found(path))?
            .value(name)
            .map(|v| v.kind);
        if create && existing.is_some() && !force {
            return Err(format!("The property already exists: {name}"));
        }
        let kind = match kind {
            Some(k) => kind_from_name(k)?,
            None if !create => existing.unwrap_or_else(|| inferred_kind(data)),
            None => inferred_kind(data),
        };
        registry.set_value(hive, &sub, name, encode(kind, data)?);
        registry.save(self.fs, hive)
    }

    /// `Remove-ItemProperty <key> -Name n`.
    pub(super) fn registry_remove_property(&mut self, path: &str, name: &str) -> Result<(), String> {
        let (hive, sub) = provider_path(path).ok_or_else(|| not_found(path))?;
        let mut registry = self.registry()?;
        let key = registry.key_mut(hive, &sub).ok_or_else(|| not_found(path))?;
        if !key.delete_value(name) {
            return Err(format!("Property {name} does not exist at path {}.", full_name(hive, &sub)));
        }
        registry.save(self.fs, hive)
    }

    /// `RegistryKey` instance methods.
    pub(super) fn registry_key_method(
        &mut self,
        hive: Hive,
        sub: &str,
        method: &str,
        args: &[Value],
    ) -> Result<Value, String> {
        let arg = |i: usize| args.get(i).map(value_string).unwrap_or_default();
        let arity = |min: usize, max: usize| {
            if args.len() < min || args.len() > max {
                Err(format!("{method}: wrong number of arguments"))
            } else {
                Ok(())
            }
        };
        let child = |name: &str| {
            let name = name.trim_matches('\\');
            if sub.is_empty() {
                name.to_string()
            } else if name.is_empty() {
                sub.to_string()
            } else {
                format!(r"{sub}\{name}")
            }
        };
        match method.to_ascii_lowercase().as_str() {
            "opensubkey" => {
                arity(1, 2)?;
                let path = child(&arg(0));
                Ok(if self.registry()?.key(hive, &path).is_some() {
                    key_object(hive, &path)
                } else {
                    Value::Str(String::new())
                })
            }
            "createsubkey" => {
                arity(1, 2)?;
                let path = child(&arg(0));
                let mut registry = self.registry()?;
                registry.create_key(hive, &path);
                registry.save(self.fs, hive)?;
                Ok(key_object(hive, &path))
            }
            "getvalue" => {
                arity(1, 3)?;
                let expand = !args
                    .get(2)
                    .map(value_string)
                    .is_some_and(|o| o.eq_ignore_ascii_case("DoNotExpandEnvironmentNames"));
                let registry = self.registry()?;
                Ok(match registry.value(hive, sub, &arg(0)) {
                    Some(value) => data_value(value, expand, self.environment),
                    None => args.get(1).cloned().unwrap_or(Value::Str(String::new())),
                })
            }
            "getvaluekind" => {
                arity(1, 1)?;
                let registry = self.registry()?;
                let value = registry.value(hive, sub, &arg(0)).ok_or_else(|| {
                    format!("The specified registry key does not exist: {}", arg(0))
                })?;
                Ok(Value::Str(kind_name(value.kind).to_string()))
            }
            "getvaluenames" | "getsubkeynames" => {
                arity(0, 0)?;
                let registry = self.registry()?;
                let key = registry
                    .key(hive, sub)
                    .ok_or_else(|| not_found(&full_name(hive, sub)))?;
                let names: Vec<Value> = if method.eq_ignore_ascii_case("getvaluenames") {
                    key.values()
                        .into_iter()
                        .map(|(n, _)| Value::Str(n.to_string()))
                        .collect()
                } else {
                    key.subkey_names()
                        .into_iter()
                        .map(|n| Value::Str(n.to_string()))
                        .collect()
                };
                Ok(Value::Arr(names))
            }
            "setvalue" => {
                arity(2, 3)?;
                let data = &args[1];
                let kind = match args.get(2) {
                    Some(k) => kind_from_name(&value_string(k))?,
                    None => inferred_kind(data),
                };
                let mut registry = self.registry()?;
                registry
                    .key(hive, sub)
                    .ok_or_else(|| not_found(&full_name(hive, sub)))?;
                registry.set_value(hive, sub, &arg(0), encode(kind, data)?);
                registry.save(self.fs, hive)?;
                Ok(void())
            }
            "deletevalue" => {
                arity(1, 2)?;
                let mut registry = self.registry()?;
                let key = registry
                    .key_mut(hive, sub)
                    .ok_or_else(|| not_found(&full_name(hive, sub)))?;
                let throw = args.get(1).is_none_or(|t| is_truthy(&value_string(t)));
                if !key.delete_value(&arg(0)) && throw {
                    return Err(format!("No value exists with that name: {}", arg(0)));
                }
                registry.save(self.fs, hive)?;
                Ok(void())
            }
            "close" | "dispose" | "flush" => Ok(void()),
            "tostring" => Ok(Value::Str(full_name(hive, sub))),
            _ => Err(format!("method {method} is not supported on RegistryKey")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_paths_map_drives_and_qualified_names() {
        assert_eq!(provider_path("HKCU:"), Some((Hive::CurrentUser, String::new())));
        assert_eq!(
            provider_path(r"HKLM:\SYSTEM\x/y\"),
            Some((Hive::LocalMachine, r"SYSTEM\x\y".to_string()))
        );
        assert_eq!(
            provider_path(r"Registry::HKEY_CURRENT_USER\Environment"),
            Some((Hive::CurrentUser, "Environment".to_string()))
        );
        assert_eq!(provider_path(r"C:\Users"), None);
        assert_eq!(provider_path("HKCUx:"), None);
        assert_eq!(provider_path("HKCU:Software"), None);
    }

    #[test]
    fn value_kinds_encode_and_decode() {
        let dword = encode(winreg::REG_DWORD, &Value::Str("0x10".into())).unwrap();
        assert_eq!(data_value(&dword, true, &[]), Value::Str("16".into()));
        let multi = encode(
            winreg::REG_MULTI_SZ,
            &Value::Arr(vec![Value::Str("a".into()), Value::Str("b".into())]),
        )
        .unwrap();
        assert_eq!(
            data_value(&multi, true, &[]),
            Value::Arr(vec![Value::Str("a".into()), Value::Str("b".into())])
        );
        let expand = RegValue::expand_string("%X%\\bin");
        let env = [("X".to_string(), "C:\\x".to_string())];
        assert_eq!(data_value(&expand, true, &env), Value::Str("C:\\x\\bin".into()));
        assert_eq!(data_value(&expand, false, &env), Value::Str("%X%\\bin".into()));
        assert!(encode(winreg::REG_DWORD, &Value::Str("nope".into())).is_err());
        assert!(kind_from_name("Strange").is_err());
        assert_eq!(kind_name(kind_from_name("expandstring").unwrap()), "ExpandString");
    }

    fn run(script: &str) -> (Result<i32, String>, String) {
        let mut fs = crate::winfs::WinFs::ephemeral_runner();
        let mut out = Vec::new();
        let r = run_ps1(&mut fs, script, &mut out);
        (r, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn registry_items_and_properties_report_errors_like_the_provider() {
        let (r, _) = run("New-Item HKCU:\\Software\\A -Force\nNew-Item HKCU:\\Software\\A");
        assert!(r.unwrap_err().contains("already exists"));
        let (r, _) = run("New-Item HKCU:\\Nope\\Deeper");
        assert!(r.unwrap_err().contains("does not exist"));
        let (r, _) = run("Get-ItemProperty HKCU:\\Missing");
        assert!(r.unwrap_err().contains("does not exist"));
        let (r, _) = run("Get-ItemProperty HKCU:\\Environment -Name Nope");
        assert!(r.unwrap_err().contains("Property Nope does not exist"));
        let (r, _) = run("Get-ItemProperty C:\\Windows");
        assert!(r.unwrap_err().contains("only registry paths"));
        let (r, _) = run("New-Item HKCU:\\K -Force | Out-Null\nNew-ItemProperty HKCU:\\K -Name V -Value 1\nNew-ItemProperty HKCU:\\K -Name V -Value 2");
        assert!(r.unwrap_err().contains("already exists"));
        let (r, _) = run("$k = (Get-Item HKCU:).CreateSubKey('K')\n$k.DeleteValue('Nope')");
        assert!(r.unwrap_err().contains("No value exists"));
        let (r, _) = run("$k = Get-Item HKCU:\n$k.Explode()");
        assert!(r.unwrap_err().contains("not supported on RegistryKey"));
        let (r, _) = run("Remove-Item HKCU:\\Missing");
        assert!(r.unwrap_err().contains("does not exist"));
        let (r, _) = run("New-Item HKCU:\\P\\C -Force | Out-Null\nRemove-Item HKCU:\\P");
        assert!(r.unwrap_err().contains("subkeys"));
    }

    #[test]
    fn registry_writes_persist_in_the_guest_hive_and_list_names() {
        let mut fs = crate::winfs::WinFs::ephemeral_runner();
        let mut out = Vec::new();
        let script = "$k = (Get-Item HKCU:).CreateSubKey('Software\\T')\n$k.SetValue('S', 'x')\n$k.SetValue('E', '%A%', 'ExpandString')\n$k.GetValueNames()\n(Get-Item HKCU:\\Software).GetSubKeyNames()\nTest-Path HKCU:\\Software\\T";
        assert_eq!(run_ps1(&mut fs, script, &mut out), Ok(0));
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("S\n") && text.contains("E\n") && text.contains("T\nTrue\n"), "{text}");
        let registry = Registry::load(&fs).unwrap();
        let value = registry.value(Hive::CurrentUser, "Software\\T", "E").unwrap();
        assert_eq!(value.kind, winreg::REG_EXPAND_SZ);
        assert_eq!(value.as_str().unwrap(), "%A%");
    }
}
