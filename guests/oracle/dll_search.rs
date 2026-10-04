//! DLL search flags and configuration using embedded, executable PE DLLs.
#![no_std]
#![no_main]
#![allow(dead_code)]
include!("common.rs");
fn boolean(name: &str, value: bool) {
    case(name);
    out_str(if value { "ok\n" } else { "wrong\n" });
}
fn wide_text(text: &str) -> [u16; 1024] {
    let mut out = [0; 1024];
    for (i, c) in text.encode_utf16().enumerate() {
        out[i] = c;
    }
    out
}
fn length(path: &[u16]) -> usize {
    path.iter().position(|c| *c == 0).unwrap_or(path.len())
}
fn join(path: &[u16], name: &str) -> [u16; 1024] {
    let mut out = [0; 1024];
    let n = length(path);
    out[..n].copy_from_slice(&path[..n]);
    out[n] = 92;
    for (i, c) in name.encode_utf16().enumerate() {
        out[n + 1 + i] = c;
    }
    out
}
fn value(module: usize, export: &[u8]) -> u32 {
    if module == 0 {
        return 0;
    }
    let address = unsafe { GetProcAddress(module, export.as_ptr()) };
    if address == 0 {
        return 0;
    }
    let call: unsafe extern "system" fn() -> u32 = unsafe { core::mem::transmute(address) };
    unsafe { call() }
}
fn probe() {
    type Load = unsafe extern "system" fn(*const u16, usize, u32) -> usize;
    type Add = unsafe extern "system" fn(*const u16) -> usize;
    type Remove = unsafe extern "system" fn(usize) -> i32;
    type Set = unsafe extern "system" fn(*const u16) -> i32;
    type Default = unsafe extern "system" fn(u32) -> i32;
    type Get = unsafe extern "system" fn(u32, *mut u16) -> u32;
    type ModulePath = unsafe extern "system" fn(usize, *mut u16, u32) -> u32;
    type Dir = unsafe extern "system" fn(*const u16, usize) -> i32;
    type Open = unsafe extern "system" fn(*const u16, u32, u32, usize, u32, u32, usize) -> usize;
    type Close = unsafe extern "system" fn(usize) -> i32;
    let load = api!("load.api", "LoadLibraryExW", Load);
    let add = api!("add.api", "AddDllDirectory", Add);
    let remove = api!("remove.api", "RemoveDllDirectory", Remove);
    let set = api!("set.api", "SetDllDirectoryW", Set);
    let get = api!("get.api", "GetDllDirectoryW", Get);
    let defaults = api!("defaults.api", "SetDefaultDllDirectories", Default);
    let cwd = api!("cwd.api", "GetCurrentDirectoryW", Get);
    let module_path = api!("module.api", "GetModuleFileNameW", ModulePath);
    let mkdir = api!("mkdir.api", "CreateDirectoryW", Dir);
    let open = api!("open.api", "CreateFileW", Open);
    let close = api!("close.api", "CloseHandle", Close);
    let free = api!("free.api", "FreeLibrary", Close);
    let mut root = [0u16; 1024];
    let mut app = [0u16; 1024];
    unsafe {
        cwd(1024, root.as_mut_ptr());
        module_path(0, app.as_mut_ptr(), 1024);
    }
    let end = app
        .iter()
        .take(length(&app))
        .rposition(|c| *c == 92)
        .unwrap();
    app[end] = 0;
    let user = join(&root, "dll-user");
    unsafe {
        mkdir(user.as_ptr(), 0);
    }
    let app_value = join(&app, "oracle_search_value.dll");
    let user_value = join(&user, "oracle_search_value.dll");
    let cwd_value = join(&root, "oracle_only_cwd.dll");
    let parent = join(&user, "oracle_search_parent.dll");
    let middle = join(&user, "oracle_search_middle.dll");
    for (path, bytes) in [
        (
            &app_value,
            include_bytes!("../../tests/artifacts/dll/oracle_search_app.dll").as_slice(),
        ),
        (
            &user_value,
            include_bytes!("../../tests/artifacts/dll/oracle_search_user.dll").as_slice(),
        ),
        (
            &cwd_value,
            include_bytes!("../../tests/artifacts/dll/oracle_search_user.dll").as_slice(),
        ),
        (
            &parent,
            include_bytes!("../../tests/artifacts/dll/oracle_search_parent.dll").as_slice(),
        ),
        (
            &middle,
            include_bytes!("../../tests/artifacts/dll/oracle_search_middle.dll").as_slice(),
        ),
    ] {
        let file = unsafe { open(path.as_ptr(), 0x40000000, 7, 0, 2, 0, 0) };
        let mut count = 0;
        if file == usize::MAX
            || unsafe { WriteFile(file, bytes.as_ptr(), bytes.len() as u32, &mut count, 0) } == 0
            || count != bytes.len() as u32
        {
            boolean("fixture.write", false);
            return;
        }
        unsafe {
            close(file);
        }
    }
    let name = wide_text("oracle_search_value.dll");
    let cwd_name = wide_text("oracle_only_cwd.dll");
    let export = b"OracleSearchValue\0";
    boolean(
        "directory.missing",
        unsafe { add(join(&user, "missing").as_ptr()) } == 0 && last_error() == 2,
    );
    boolean(
        "directory.parent_missing",
        unsafe { add(join(&user, "absent\\missing").as_ptr()) } == 0 && last_error() == 3,
    );
    let first = unsafe { add(user.as_ptr()) };
    let second = unsafe { add(user.as_ptr()) };
    boolean(
        "directory.cookies",
        first != 0 && second != 0 && first != second,
    );
    let h = unsafe { load(name.as_ptr(), 0, 0) };
    boolean("search.legacy_application", value(h, export) == 11);
    if h != 0 {
        unsafe {
            free(h);
        }
    }
    boolean("directory.remove_duplicate", unsafe { remove(first) } != 0);
    let h = unsafe { load(name.as_ptr(), 0, 0x400) };
    boolean("search.user", value(h, export) == 22);
    let cached = unsafe { load(name.as_ptr(), 0, 0x200) };
    boolean(
        "search.loaded_name_reused",
        cached == h && value(cached, export) == 22,
    );
    let extensionless = unsafe { load(wide_text("oracle_search_value").as_ptr(), 0, 0x800) };
    boolean(
        "search.loaded_extensionless",
        extensionless == h && extensionless != 0,
    );
    if extensionless != 0 {
        unsafe {
            free(extensionless);
        }
    }
    if cached != 0 {
        unsafe {
            free(cached);
        }
    }
    if h != 0 {
        unsafe {
            free(h);
        }
    }
    let a = unsafe { load(app_value.as_ptr(), 0, 0) };
    let b = unsafe { load(user_value.as_ptr(), 0, 0) };
    boolean(
        "search.absolute_distinct",
        a != b && value(a, export) == 11 && value(b, export) == 22,
    );
    let mut app_path = [0u16; 1024];
    let mut user_path = [0u16; 1024];
    boolean(
        "module.loaded_paths",
        unsafe { module_path(a, app_path.as_mut_ptr(), 1024) } as usize == length(&app_value)
            && unsafe { module_path(b, user_path.as_mut_ptr(), 1024) } as usize
                == length(&user_value)
            && app_path[..length(&app_value)] == app_value[..length(&app_value)]
            && user_path[..length(&user_value)] == user_value[..length(&user_value)],
    );
    let mut tiny = [99u16; 3];
    boolean(
        "module.truncated",
        unsafe { module_path(a, tiny.as_mut_ptr(), 3) } == 3 && tiny[2] == 0 && last_error() == 122,
    );
    boolean(
        "module.invalid",
        unsafe { module_path(0xdead, app_path.as_mut_ptr(), 1024) } == 0 && last_error() == 126,
    );
    if a != 0 {
        unsafe {
            free(a);
        }
    }
    if b != 0 {
        unsafe {
            free(b);
        }
    }
    boolean("directory.remove", unsafe { remove(second) } != 0);
    boolean(
        "search.removed_missing",
        unsafe { load(name.as_ptr(), 0, 0x400) } == 0 && last_error() == 126,
    );
    boolean(
        "search.system32_excludes_app",
        unsafe { load(name.as_ptr(), 0, 0x800) } == 0,
    );
    boolean("directory.set", unsafe { set(user.as_ptr()) } != 0);
    let needed = length(&user) as u32 + 1;
    boolean(
        "directory.query",
        unsafe { get(0, core::ptr::null_mut()) } == needed,
    );
    let mut buffer = [0u16; 1024];
    boolean(
        "directory.get",
        unsafe { get(1024, buffer.as_mut_ptr()) } == needed - 1
            && buffer[..needed as usize] == user[..needed as usize],
    );
    boolean(
        "directory.small",
        unsafe { get(2, buffer.as_mut_ptr()) } == needed && buffer[0] == 0,
    );
    let h = unsafe { load(name.as_ptr(), 0, 0x400) };
    boolean("search.set_directory", value(h, export) == 22);
    if h != 0 {
        unsafe {
            free(h);
        }
    }
    unsafe {
        set(wide_text("").as_ptr());
    }
    boolean(
        "search.cwd_disabled",
        unsafe { load(cwd_name.as_ptr(), 0, 0) } == 0,
    );
    unsafe {
        set(core::ptr::null());
    }
    let h = unsafe { load(cwd_name.as_ptr(), 0, 0) };
    boolean("search.cwd_restored", value(h, export) == 22);
    if h != 0 {
        unsafe {
            free(h);
        }
    }
    boolean(
        "flags.relative_load_dir",
        unsafe { load(name.as_ptr(), 0, 0x100) } == 0 && last_error() == 87,
    );
    boolean(
        "flags.incompatible",
        unsafe { load(name.as_ptr(), 0, 0x408) } == 0 && last_error() == 87,
    );
    boolean(
        "flags.default_invalid",
        unsafe { defaults(0) } == 0 && last_error() == 87,
    );
    boolean(
        "directory.relative_invalid",
        unsafe { add(wide_text("relative").as_ptr()) } == 0 && last_error() == 87,
    );
    boolean(
        "dependency.missing",
        unsafe { load(parent.as_ptr(), 0, 0x200) } == 0,
    );
    let h = unsafe { load(parent.as_ptr(), 0, 0x900) };
    boolean(
        "dependency.dll_load_dir_recursive",
        value(h, b"OracleSearchParent\0") == 22,
    );
    if h != 0 {
        unsafe {
            free(h);
        }
    }
    let h = unsafe { load(parent.as_ptr(), 0, 8) };
    boolean(
        "dependency.altered_search",
        value(h, b"OracleSearchParent\0") == 22,
    );
    if h != 0 {
        unsafe {
            free(h);
        }
    }
    let cookie = unsafe { add(user.as_ptr()) };
    let h = unsafe { load(parent.as_ptr(), 0, 0x600) };
    boolean(
        "dependency.application_before_user",
        value(h, b"OracleSearchParent\0") == 11,
    );
    if h != 0 {
        unsafe {
            free(h);
        }
    }
    boolean("defaults.set", unsafe { defaults(0x400) } != 0);
    let h = unsafe { load(name.as_ptr(), 0, 0) };
    boolean("defaults.user", value(h, export) == 22);
    if h != 0 {
        unsafe {
            free(h);
        }
    }
    let h = unsafe { load(name.as_ptr(), 0, 0x200) };
    boolean("defaults.explicit_override", value(h, export) == 11);
    if h != 0 {
        unsafe {
            free(h);
        }
    }
    unsafe {
        remove(cookie);
    }
    boolean(
        "defaults.removed_missing",
        unsafe { load(name.as_ptr(), 0, 0) } == 0,
    );
    out_str("END\n");
}
#[no_mangle]
pub extern "C" fn probe_entry() -> ! {
    out_str("probe dll_search\n");
    probe();
    flush();
    unsafe { ExitProcess(0) }
}
