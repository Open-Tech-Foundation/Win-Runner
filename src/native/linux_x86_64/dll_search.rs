//! Per-process Windows DLL search configuration and directory cookies.
use super::*;

pub(super) const DLL_SEARCH_MASK: u32 = 0x1f00;
#[derive(Clone, Default)]
pub(super) struct NativeDllSearch {
    pub(super) flags: Option<u32>,
    pub(super) directory: Option<String>,
    pub(super) added: std::collections::BTreeMap<u64, String>,
    next: u64,
}
#[derive(Clone)]
pub(super) struct DllSearchPlan {
    pub(super) flags: Option<u32>,
    pub(super) directory: Option<String>,
    pub(super) added: Vec<String>,
    pub(super) dll_directory: Option<String>,
    pub(super) altered: bool,
}
fn absolute(path: &str) -> bool {
    path.starts_with(['\\', '/'])
        || (path.as_bytes().get(1) == Some(&b':')
            && path
                .as_bytes()
                .get(2)
                .is_some_and(|c| matches!(c, b'\\' | b'/')))
}
pub(super) fn dll_search_plan(name: &str, flags: u32) -> Result<DllSearchPlan, u32> {
    if flags & !(DLL_SEARCH_MASK | 8) != 0 {
        return Err(if flags & !(DLL_SEARCH_MASK | 0xff | 0x2000) != 0 {
            87
        } else {
            50
        });
    }
    if flags & DLL_SEARCH_MASK != 0 && flags & 8 != 0 {
        return Err(87);
    }
    if flags & 0x100 != 0
        && !(name.as_bytes().get(1) == Some(&b':')
            && name
                .as_bytes()
                .get(2)
                .is_some_and(|c| matches!(c, b'\\' | b'/'))
            || name.starts_with(r"\\"))
    {
        return Err(87);
    }
    let process = process_ctx().ok_or(6u32)?;
    let policy = process.dll_search.lock().map_err(|_| 6u32)?.clone();
    let search_flags = if flags & DLL_SEARCH_MASK != 0 {
        Some(flags & DLL_SEARCH_MASK)
    } else if flags & 8 != 0 {
        None
    } else {
        policy.flags
    };
    let dll_directory = if flags & (0x100 | 8) != 0 {
        let fs = process.fs.lock().map_err(|_| 6u32)?;
        let path = fs.fs.canonical_path(name).ok_or(87u32)?;
        path.rsplit_once('\\').map(|(dir, _)| dir.to_string())
    } else {
        None
    };
    Ok(DllSearchPlan {
        flags: search_flags,
        directory: policy.directory,
        added: policy.added.into_values().collect(),
        dll_directory,
        altered: flags & 8 != 0,
    })
}

pub(super) extern "win64" fn native_set_default_dll_directories(flags: u32) -> i32 {
    if flags == 0 || flags & !(DLL_SEARCH_MASK & !0x100) != 0 {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut policy) = process.dll_search.lock() else {
        native_set_last_error(6);
        return 0;
    };
    policy.flags = Some(flags);
    1
}
pub(super) extern "win64" fn native_add_dll_directory(path: *const u16) -> u64 {
    let Some(path) = wide(path) else {
        native_set_last_error(87);
        return 0;
    };
    if path.is_empty() || !absolute(&path) {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let path = {
        let Ok(fs) = process.fs.lock() else {
            native_set_last_error(6);
            return 0;
        };
        let Some(path) = fs.fs.canonical_path(&path) else {
            native_set_last_error(87);
            return 0;
        };
        if !fs.fs.exists(&path) {
            let parent_exists = path.rsplit_once('\\').is_some_and(|(parent, _)| {
                let parent = if parent.len() == 2 {
                    format!("{parent}\\")
                } else {
                    parent.to_string()
                };
                fs.fs.is_dir(&parent)
            });
            native_set_last_error(if parent_exists { 2 } else { 3 });
            return 0;
        }
        path
    };
    let Ok(mut policy) = process.dll_search.lock() else {
        native_set_last_error(6);
        return 0;
    };
    policy.next += 1;
    let cookie = 0xdc00_0000 + policy.next;
    policy.added.insert(cookie, path);
    cookie
}
pub(super) extern "win64" fn native_remove_dll_directory(cookie: u64) -> i32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    if !process
        .dll_search
        .lock()
        .is_ok_and(|mut policy| policy.added.remove(&cookie).is_some())
    {
        native_set_last_error(87);
        return 0;
    }
    1
}
pub(super) extern "win64" fn native_set_dll_directory_w(path: *const u16) -> i32 {
    let directory = if path.is_null() {
        None
    } else {
        let Some(path) = wide(path) else {
            native_set_last_error(87);
            return 0;
        };
        Some(path)
    };
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(mut policy) = process.dll_search.lock() else {
        native_set_last_error(6);
        return 0;
    };
    policy.directory = directory;
    1
}
pub(super) extern "win64" fn native_get_dll_directory_w(size: u32, output: *mut u16) -> u32 {
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let Ok(policy) = process.dll_search.lock() else {
        native_set_last_error(6);
        return 0;
    };
    let value: Vec<u16> = policy
        .directory
        .as_deref()
        .unwrap_or("")
        .encode_utf16()
        .collect();
    if !value.is_empty() && size as usize <= value.len() {
        if size > 0 && !output.is_null() {
            unsafe {
                output.write(0);
            }
        }
        return value.len() as u32 + 1;
    }
    if size > 0 {
        if output.is_null() {
            native_set_last_error(87);
            return 0;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len());
            output.add(value.len()).write(0);
        }
    }
    value.len() as u32
}

pub(super) fn locate_dll(
    fs: &crate::winfs::WinFs,
    module_path: &str,
    name: &str,
    plan: &DllSearchPlan,
    path_env: &str,
) -> Option<String> {
    let suffixed = if name.rsplit(['\\', '/']).next()?.contains('.') {
        name.to_string()
    } else {
        format!("{name}.dll")
    };
    if absolute(&suffixed) || suffixed.as_bytes().get(1) == Some(&b':') {
        return fs
            .is_file(&suffixed)
            .then(|| fs.canonical_path(&suffixed))
            .flatten();
    }
    let mut dirs = Vec::new();
    let application = module_path
        .rsplit_once(['\\', '/'])
        .map(|(dir, _)| dir.to_string());
    if let Some(flags) = plan.flags {
        let flags = if flags & 0x1000 != 0 {
            flags | 0xe00
        } else {
            flags
        };
        if let Some(dir) = &plan.dll_directory {
            dirs.push(dir.clone());
        }
        if flags & 0x200 != 0 {
            dirs.extend(application);
        }
        if flags & 0x400 != 0 {
            dirs.extend(plan.directory.iter().filter(|dir| !dir.is_empty()).cloned());
            dirs.extend(plan.added.iter().cloned());
        }
        if flags & 0x800 != 0 {
            dirs.push(r"C:\Windows\System32".into());
        }
    } else {
        if plan.altered {
            dirs.extend(plan.dll_directory.iter().cloned());
        } else {
            dirs.extend(application);
        }
        dirs.extend(plan.directory.iter().filter(|dir| !dir.is_empty()).cloned());
        dirs.extend([
            r"C:\Windows\System32".into(),
            r"C:\Windows\System".into(),
            r"C:\Windows".into(),
        ]);
        if plan.directory.is_none() {
            dirs.push(fs.cwd());
        }
        dirs.extend(
            path_env
                .split(';')
                .filter(|dir| !dir.is_empty())
                .map(|dir| dir.trim_matches('"').to_string()),
        );
    }
    dirs.into_iter()
        .map(|dir| format!(r"{dir}\{suffixed}"))
        .find_map(|path| {
            fs.is_file(&path)
                .then(|| fs.canonical_path(&path))
                .flatten()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wide_path(path: &str) -> Vec<u16> {
        path.encode_utf16().chain([0]).collect()
    }
    #[test]
    fn directory_cookies_buffers_and_process_state() {
        let _guard = TestProcessGuard::new();
        let dir = wide_path(r"C:\dlls\café");
        process_ctx()
            .unwrap()
            .fs
            .lock()
            .unwrap()
            .fs
            .mkdir(r"C:\dlls\café")
            .unwrap();
        assert_eq!(
            native_add_dll_directory(wide_path(r"C:\dlls\missing").as_ptr()),
            0
        );
        assert_eq!(native_get_last_error(), 2);
        assert_eq!(
            native_add_dll_directory(wide_path(r"C:\absent\missing").as_ptr()),
            0
        );
        assert_eq!(native_get_last_error(), 3);
        assert_eq!(native_add_dll_directory(wide_path("relative").as_ptr()), 0);
        assert_eq!(native_get_last_error(), 87);
        let first = native_add_dll_directory(dir.as_ptr());
        let second = native_add_dll_directory(dir.as_ptr());
        assert_ne!(first, second);
        assert_ne!(first, 0);
        assert_eq!(native_remove_dll_directory(first), 1);
        assert_eq!(native_remove_dll_directory(first), 0);
        assert_eq!(native_get_last_error(), 87);
        assert_eq!(native_set_dll_directory_w(dir.as_ptr()), 1);
        assert_eq!(
            native_get_dll_directory_w(0, ptr::null_mut()),
            dir.len() as u32
        );
        let mut short = [77u16; 2];
        assert_eq!(
            native_get_dll_directory_w(2, short.as_mut_ptr()),
            dir.len() as u32
        );
        assert_eq!(short, [0, 77]);
        let mut out = [0u16; 64];
        assert_eq!(
            native_get_dll_directory_w(64, out.as_mut_ptr()),
            dir.len() as u32 - 1
        );
        assert_eq!(&out[..dir.len()], &dir);
        assert_eq!(native_set_default_dll_directories(0), 0);
        assert_eq!(native_set_default_dll_directories(0x100), 0);
        assert_eq!(native_set_default_dll_directories(0x1000), 1);
        assert_eq!(native_set_dll_directory_w(ptr::null()), 1);
        assert_eq!(native_get_dll_directory_w(64, out.as_mut_ptr()), 0);
        assert_eq!(out[0], 0);
        assert_eq!(dll_search_plan("helper.dll", 0x100).err(), Some(87));
        assert_eq!(dll_search_plan("helper.dll", 0x1008).err(), Some(87));
        assert_eq!(dll_search_plan("helper.dll", 2).err(), Some(50));
        assert_eq!(dll_search_plan("helper.dll", 0x8000).err(), Some(87));
        assert_eq!(native_load_library_ex_w(dir.as_ptr(), 1, 0), 0);
        assert_eq!(native_get_last_error(), 87);
        let previous = THREAD_NATIVE_PROCESS.with(|slot| slot.replace(Some(new_test_process())));
        assert!(process_ctx()
            .unwrap()
            .dll_search
            .lock()
            .unwrap()
            .added
            .is_empty());
        THREAD_NATIVE_PROCESS.with(|slot| slot.replace(previous));
    }
    #[test]
    fn restricted_search_ignores_cwd_path_and_unconfigured_disk_copies() {
        let _guard = TestProcessGuard::new();
        let process = process_ctx().unwrap();
        let mut fs = process.fs.lock().unwrap();
        for (dir, value) in [
            (r"C:\app", 1u8),
            (r"C:\user", 2),
            (r"C:\cwd", 3),
            (r"C:\path", 4),
            (r"C:\other", 5),
        ] {
            fs.fs.mkdir(dir).unwrap();
            fs.fs
                .write_file(&format!(r"{dir}\helper.dll"), vec![value])
                .unwrap();
        }
        fs.fs.set_cwd(r"C:\cwd").unwrap();
        let mut plan = DllSearchPlan {
            flags: Some(0x400),
            directory: None,
            added: vec![r"C:\user".into()],
            dll_directory: None,
            altered: false,
        };
        let found = locate_dll(&fs.fs, r"C:\app\tool.exe", "helper", &plan, r"C:\path").unwrap();
        assert_eq!(fs.fs.read_file(&found).unwrap(), vec![2]);
        plan.added.clear();
        assert!(locate_dll(&fs.fs, r"C:\app\tool.exe", "helper", &plan, r"C:\path").is_none());
        plan.flags = Some(0x1000);
        assert!(locate_dll(&fs.fs, r"C:\app\tool.exe", "helper", &plan, "")
            .unwrap()
            .contains("app"));
        plan.flags = None;
        assert!(locate_dll(&fs.fs, r"C:\none\tool.exe", "helper", &plan, "")
            .unwrap()
            .contains("cwd"));
        plan.directory = Some(String::new());
        assert!(locate_dll(&fs.fs, r"C:\none\tool.exe", "helper", &plan, "").is_none());
        assert!(
            locate_dll(&fs.fs, r"C:\none\tool.exe", "helper", &plan, r"C:\path")
                .unwrap()
                .contains("path")
        );
    }
}
