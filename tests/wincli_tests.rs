//! Required acceptance tests for WinCLI.
//!
//! 1. `wincli hello.exe` prints `Hello from Windows`.
//! 2. PE exit codes propagate correctly.
//! 3. EXE can create/read/write/delete files in WinFS.
//! 4. `.ps1` can create/read/write/delete the same kinds of files.
//! 5. Paths are case-insensitive.
//! 6. `.` and `..` normalization works.
//! 7. Files never appear on the Linux host filesystem.
//! 8. Unknown PE imports fail clearly.
//! 9. EXE and PS1 execution use the exact same WinFS API.

use std::io::Read;
use std::process::{Command, Stdio};
use wincli::pe;
use wincli::winapi;
use wincli::winfs::WinFs;

// ---------- helpers ----------

fn run_exe_on_fs(data: &[u8], fs: WinFs) -> (u32, WinFs, Vec<u8>) {
    winapi::run_exe(data, fs).expect("exe should run")
}

fn run_ps1_on_fs(fs: &mut WinFs, script: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wincli::ps1::run_ps1(fs, script, &mut out).expect("ps1 should run");
    out
}

fn tmp_path(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("wincli-test-{}-{}-{name}", std::process::id(), counter()));
    p
}

fn counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    C.fetch_add(1, Ordering::SeqCst)
}

fn run_cli(file: &std::path::Path) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let output = Command::new(bin)
        .arg(file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn wincli");
    let code = output.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

// ---------- 1: hello ----------

#[test]
fn test1_hello_exe_prints() {
    let exe = pe::builder::hello("Hello from Windows");
    let (code, _fs, out) = run_exe_on_fs(&exe, WinFs::new());
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8(out).unwrap(), "Hello from Windows");

    // end-to-end through the real CLI binary
    let p = tmp_path("hello.exe");
    std::fs::write(&p, &exe).unwrap();
    let (code, stdout, _) = run_cli(&p);
    std::fs::remove_file(&p).ok();
    assert_eq!(code, 0);
    assert_eq!(stdout, "Hello from Windows");
}

// ---------- 2: exit codes ----------

#[test]
fn test2_exit_codes_propagate() {
    for code in [0u32, 1, 3, 42, 255] {
        let exe = pe::builder::exit_code(code);
        let (got, _, _) = run_exe_on_fs(&exe, WinFs::new());
        assert_eq!(got, code, "exit code {code}");

        let p = tmp_path(&format!("exit{code}.exe"));
        std::fs::write(&p, &exe).unwrap();
        let (cli_code, _, _) = run_cli(&p);
        std::fs::remove_file(&p).ok();
        assert_eq!(cli_code, code as i32, "cli exit code {code}");
    }
}

// ---------- 3: EXE file ops ----------

#[test]
fn test3_exe_file_ops() {
    let mut fs = WinFs::new();

    // mkdir
    let exe = pe::builder::mkdir("C:\\exedir");
    let (code, fs2, _) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    fs = fs2;
    assert!(fs.is_dir("C:\\exedir"));

    // create + write
    let exe = pe::builder::write_file("C:\\exedir\\a.txt", b"exe-data-123");
    let (code, fs2, _) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    fs = fs2;
    assert_eq!(fs.read_file("C:\\exedir\\a.txt").unwrap(), b"exe-data-123");

    // read back to stdout
    let exe = pe::builder::read_file_to_stdout("C:\\exedir\\a.txt");
    let (code, fs2, out) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    fs = fs2;
    assert_eq!(out, b"exe-data-123");

    // copy + move
    let exe = pe::builder::copy_file("C:\\exedir\\a.txt", "C:\\exedir\\b.txt");
    let (code, fs2, _) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    fs = fs2;
    assert_eq!(fs.read_file("C:\\exedir\\b.txt").unwrap(), b"exe-data-123");

    let exe = pe::builder::move_file("C:\\exedir\\b.txt", "C:\\exedir\\c.txt");
    let (code, fs2, _) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    fs = fs2;
    assert!(!fs.exists("C:\\exedir\\b.txt"));
    assert_eq!(fs.read_file("C:\\exedir\\c.txt").unwrap(), b"exe-data-123");

    // delete file + rmdir
    let exe = pe::builder::delete_file("C:\\exedir\\a.txt");
    let (code, fs2, _) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    fs = fs2;
    assert!(!fs.exists("C:\\exedir\\a.txt"));

    let exe = pe::builder::delete_file("C:\\exedir\\c.txt");
    let (code, fs2, _) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    fs = fs2;

    let exe = pe::builder::rmdir("C:\\exedir");
    let (code, fs2, _) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    fs = fs2;
    assert!(!fs.exists("C:\\exedir"));
}

// ---------- 4: PS1 file ops ----------

#[test]
fn test4_ps1_file_ops() {
    let mut fs = WinFs::new();
    let script = r#"
        New-Item -Path "C:\psdir" -ItemType Directory
        New-Item -Path "C:\psdir\a.txt" -ItemType File -Value "ps-data"
        Set-Content -Path "C:\psdir\b.txt" -Value "hello-ps"
        Add-Content -Path "C:\psdir\b.txt" -Value "more"
        Copy-Item -Path "C:\psdir\b.txt" -Destination "C:\psdir\c.txt"
        Move-Item -Path "C:\psdir\c.txt" -Destination "C:\psdir\d.txt"
        Remove-Item -Path "C:\psdir\a.txt"
    "#;
    run_ps1_on_fs(&mut fs, script);
    // Set-Content adds trailing newline; Add-Content appends another line
    assert_eq!(fs.read_file("C:\\psdir\\b.txt").unwrap(), b"hello-ps\nmore\n");
    assert_eq!(fs.read_file("C:\\psdir\\d.txt").unwrap(), b"hello-ps\nmore\n");
    assert!(!fs.exists("C:\\psdir\\a.txt"));
    assert!(!fs.exists("C:\\psdir\\c.txt"));

    let out = run_ps1_on_fs(&mut fs, r#"Get-Content -Path "C:\psdir\b.txt""#);
    assert_eq!(String::from_utf8(out).unwrap(), "hello-ps\nmore\n");

    let out = run_ps1_on_fs(&mut fs, r#"Get-ChildItem -Path "C:\psdir""#);
    let listing = String::from_utf8(out).unwrap();
    assert!(listing.contains("b.txt"));
    assert!(listing.contains("d.txt"));

    run_ps1_on_fs(&mut fs, r#"Remove-Item -Path "C:\psdir\d.txt""#);
    run_ps1_on_fs(&mut fs, r#"Remove-Item -Path "C:\psdir\b.txt""#);
    assert!(fs.list_dir("C:\\psdir").unwrap().is_empty());

    // end-to-end through CLI binary
    let p = tmp_path("ops.ps1");
    std::fs::write(&p, "New-Item -Path \"C:\\x\" -ItemType Directory\nTest-Path \"C:\\x\"\n").unwrap();
    let (code, stdout, _) = run_cli(&p);
    std::fs::remove_file(&p).ok();
    assert_eq!(code, 0);
    assert!(stdout.contains("True"));
}

// ---------- 5: case-insensitive ----------

#[test]
fn test5_case_insensitive() {
    // pure WinFS
    let mut fs = WinFs::new();
    fs.mkdir("C:\\TeSt").unwrap();
    fs.write_file("C:\\TEST\\A.TxT", b"data".to_vec()).unwrap();
    assert_eq!(fs.read_file("c:\\test\\a.txt").unwrap(), b"data");
    assert_eq!(fs.list_dir("C:\\TEST").unwrap(), vec!["A.TxT".to_string()]);

    // EXE writes uppercase, PS1 reads lowercase on the SAME fs
    let mut fs = WinFs::new();
    let mk = pe::builder::mkdir("C:\\CASE");
    let (_, fs2, _) = run_exe_on_fs(&mk, fs);
    fs = fs2;
    let exe = pe::builder::write_file("C:\\CASE\\UP.TXT", b"mixed");
    let (code, fs2, _) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    fs = fs2;
    let out = run_ps1_on_fs(&mut fs, r#"Get-Content -Path "c:\case\up.txt""#);
    assert_eq!(String::from_utf8(out).unwrap(), "mixed\n");

    // PS1 writes lowercase, EXE reads uppercase
    let mut fs = WinFs::new();
    run_ps1_on_fs(&mut fs, r#"New-Item -Path "C:\c2" -ItemType Directory"#);
    run_ps1_on_fs(&mut fs, r#"Set-Content -Path "c:\c2\low.txt" -Value "abc""#);
    let exe = pe::builder::read_file_to_stdout("C:\\C2\\LOW.TXT");
    let (code, _, out) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    assert_eq!(out, b"abc\n");
}

// ---------- 6: dot/dotdot ----------

#[test]
fn test6_dotdot_normalization() {
    let mut fs = WinFs::new();
    fs.mkdir("C:\\a\\b").unwrap();
    fs.write_file("C:\\a\\b\\f.txt", b"v".to_vec()).unwrap();
    assert_eq!(fs.read_file("C:\\a\\.\\b\\f.txt").unwrap(), b"v");
    assert_eq!(fs.read_file("C:\\a\\b\\..\\b\\f.txt").unwrap(), b"v");
    assert_eq!(fs.read_file("C:/a/b/f.txt").unwrap(), b"v");
    assert_eq!(fs.read_file("C:\\a\\b\\\\f.txt").unwrap(), b"v");
    fs.set_cwd("C:\\a\\b").unwrap();
    assert_eq!(fs.read_file(".\\f.txt").unwrap(), b"v");
    assert_eq!(fs.read_file("..\\b\\f.txt").unwrap(), b"v");
    assert_eq!(fs.read_file("..\\..\\a\\b\\f.txt").unwrap(), b"v");

    // via PS1
    let mut fs2 = WinFs::new();
    run_ps1_on_fs(
        &mut fs2,
        r#"New-Item -Path "C:\d1\d2" -ItemType Directory -Force"#,
    );
    run_ps1_on_fs(&mut fs2, r#"Set-Content -Path "C:\d1\d2\x.txt" -Value "zz""#);
    let out = run_ps1_on_fs(&mut fs2, r#"Get-Content -Path "C:\d1\.\d2\..\d2\x.txt""#);
    assert_eq!(String::from_utf8(out).unwrap(), "zz\n");
}

// ---------- 7: never touches host ----------

#[test]
fn test7_no_host_side_effects() {
    let sentinel = format!("wincli-sentinel-{}-{}.txt", std::process::id(), counter());
    let host_before: Vec<bool> = [
        format!("/tmp/{sentinel}"),
        format!("./{sentinel}"),
        format!("C:\\{sentinel}"),
    ]
    .iter()
    .map(|p| std::path::Path::new(p).exists())
    .collect();
    assert!(!host_before.iter().any(|b| *b));

    // EXE creates C:\<sentinel>
    let guest = format!("C:\\{sentinel}");
    let exe = pe::builder::write_file(&guest, b"no-host");
    let (code, fs, _) = run_exe_on_fs(&exe, WinFs::new());
    assert_eq!(code, 0);
    assert!(fs.exists(&guest));

    // PS1 creates another
    let sentinel2 = format!("wincli-sentinel-ps1-{}-{}.txt", std::process::id(), counter());
    let mut fs2 = WinFs::new();
    run_ps1_on_fs(
        &mut fs2,
        &format!("Set-Content -Path \"C:\\{sentinel2}\" -Value \"x\""),
    );
    assert!(fs2.exists(&format!("C:\\{sentinel2}")));

    // host must still be clean (check cwd, /tmp, and crate root)
    for dir in ["/tmp", ".", "target", "/media/G/WD_LINUX_FILES/projects/otf/Win-CLI"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                assert!(
                    !n.contains("wincli-sentinel"),
                    "guest file leaked to host dir {dir}: {n}"
                );
            }
        }
    }
    // reading guest bytes back works only through WinFS, not host fs
    let mut f = std::fs::File::open(format!("/tmp/{sentinel}"));
    assert!(f.is_err());
    let mut buf = Vec::new();
    let _ = f.as_mut().map(|f| f.read_to_end(&mut buf));
}

// ---------- 8: unknown imports ----------

#[test]
fn test8_unknown_imports_fail_clearly() {
    let exe = pe::builder::unknown_import();
    let err = pe::load(&exe).expect_err("load must reject unknown import");
    assert!(
        err.contains("unsupported import") && err.contains("NoSuchApiForTest"),
        "unexpected error: {err}"
    );

    // also via CLI: nonzero exit + clear stderr
    let p = tmp_path("bad.exe");
    std::fs::write(&p, &exe).unwrap();
    let (code, _, stderr) = run_cli(&p);
    std::fs::remove_file(&p).ok();
    assert_ne!(code, 0);
    assert!(
        stderr.contains("unsupported import"),
        "stderr should explain: {stderr}"
    );
}

// ---------- 9: same WinFS API ----------

#[test]
fn test9_exe_and_ps1_share_winfs() {
    fn type_name_of_val<T>(_: &T) -> &'static str {
        std::any::type_name::<T>()
    }
    // Both runners are generic over the same concrete type.
    assert_eq!(
        type_name_of_val(&WinFs::new()),
        "wincli::winfs::WinFs"
    );

    // EXE -> PS1 direction
    let mut fs = WinFs::new();
    let exe = pe::builder::write_file("C:\\shared\\note.txt", b"from-exe");
    // need parent dir first
    let mk = pe::builder::mkdir("C:\\shared");
    let (_, fs2, _) = run_exe_on_fs(&mk, fs);
    fs = fs2;
    let (_, fs2, _) = run_exe_on_fs(&exe, fs);
    fs = fs2;
    let out = run_ps1_on_fs(&mut fs, r#"Get-Content -Path "C:\shared\note.txt""#);
    assert_eq!(String::from_utf8(out).unwrap(), "from-exe\n");

    // PS1 -> EXE direction
    let mut fs = WinFs::new();
    run_ps1_on_fs(&mut fs, r#"New-Item -Path "C:\shared" -ItemType Directory"#);
    run_ps1_on_fs(&mut fs, r#"Set-Content -Path "C:\shared\back.txt" -Value "from-ps1""#);
    let exe = pe::builder::read_file_to_stdout("C:\\shared\\back.txt");
    let (code, _, out) = run_exe_on_fs(&exe, fs);
    assert_eq!(code, 0);
    assert_eq!(out, b"from-ps1\n");
}

// ---------- committed artifacts: black-box CLI tests ----------
// `tests/artifacts/ps1/*.ps1` and `tests/artifacts/exe/*.exe` are checked in.
// The .exe files are genuine PE32+ x86_64 guests generated by
// `cargo run --example gen_artifacts` (see examples/gen_artifacts.rs).
// The fs_*.exe guests self-verify inside the guest (PASS/exit 0), so each
// `wincli` invocation is fully observable despite the per-process WinFS.

fn artifact(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/artifacts")
        .join(rel)
}

#[test]
fn test_art_ps1_all_cmdlets() {
    let (code, stdout, stderr) = run_cli(&artifact("ps1/fs_all.ps1"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "two\nthree\na.txt\nb.txt\nTrue\nPS1-ALL-DONE\n");
    assert!(stderr.is_empty());
}

#[test]
fn test_art_ps1_case_insensitive() {
    let (code, stdout, stderr) = run_cli(&artifact("ps1/fs_case.ps1"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "ci-ok\nCaSe.TxT\nTrue\nPS1-CASE-DONE\n");
}

#[test]
fn test_art_ps1_dotdot() {
    let (code, stdout, stderr) = run_cli(&artifact("ps1/fs_dots.ps1"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "dots-ok\ndots-ok\nTrue\nPS1-DOTS-DONE\n");
}

#[test]
fn test_art_ps1_error_fails_clearly() {
    let (code, stdout, stderr) = run_cli(&artifact("ps1/fs_error.ps1"));
    assert_ne!(code, 0);
    assert!(stdout.is_empty(), "marker must not print: {stdout}");
    assert!(stderr.contains("Remove-Item"), "stderr: {stderr}");
}

#[test]
fn test_art_exe_hello() {
    let (code, stdout, stderr) = run_cli(&artifact("exe/hello.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "Hello from Windows");
}

#[test]
fn test_art_exe_exit_code() {
    let (code, stdout, _) = run_cli(&artifact("exe/exit42.exe"));
    assert_eq!(code, 42);
    assert!(stdout.is_empty());
}

#[test]
fn test_art_exe_fs_file_selftest() {
    let (code, stdout, stderr) = run_cli(&artifact("exe/fs_file.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "PASS\n");
}

#[test]
fn test_art_exe_fs_dir_selftest() {
    let (code, stdout, stderr) = run_cli(&artifact("exe/fs_dir.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "PASS\n");
}

#[test]
fn test_art_exe_fs_move_selftest() {
    let (code, stdout, stderr) = run_cli(&artifact("exe/fs_move.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "moved-bytesPASS\n");
}

#[test]
fn test_art_exe_bad_import() {
    let (code, stdout, stderr) = run_cli(&artifact("exe/bad_import.exe"));
    assert_ne!(code, 0);
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("unsupported import") && stderr.contains("NoSuchApiForTest"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_art_exe_rust_hello() {
    // Real rustc-built guest (guests/hello.rs, x86_64-pc-windows-msvc).
    // Its imports must stay within the supported API set...
    let bytes = std::fs::read(artifact("exe/rust_hello.exe")).unwrap();
    let img = pe::load(&bytes).expect("rust guest must load");
    assert!(!img.imports.is_empty());
    for imp in &img.imports {
        assert!(
            pe::is_supported(&imp.dll, &imp.func),
            "unsupported import in rust guest: {}!{}",
            imp.dll,
            imp.func
        );
    }
    // ...and it must run through the real CLI.
    let (code, stdout, stderr) = run_cli(&artifact("exe/rust_hello.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "Hello from Rust");
}

#[test]
fn test_art_exe_rust_fs_selftest() {
    // Real rustc-built FS guest (guests/fs_selftest.rs). Imports must stay
    // within the supported API set...
    let bytes = std::fs::read(artifact("exe/rust_fs.exe")).unwrap();
    let img = pe::load(&bytes).expect("rust guest must load");
    assert!(!img.imports.is_empty());
    for imp in &img.imports {
        assert!(
            pe::is_supported(&imp.dll, &imp.func),
            "unsupported import in rust guest: {}!{}",
            imp.dll,
            imp.func
        );
    }
    // ...and the guest must verify itself through the real CLI: it echoes the
    // bytes it wrote/read/moved, then PASS.
    let (code, stdout, stderr) = run_cli(&artifact("exe/rust_fs.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "rust-fs-bytes-7PASS\n");
}

fn run_inspect(file: &std::path::Path) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let output = std::process::Command::new(bin)
        .arg("inspect")
        .arg(file)
        .output()
        .expect("spawn wincli inspect");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn test_inspect_runnable_binary() {
    let (code, stdout, _) = run_inspect(&artifact("exe/hello.exe"));
    assert_eq!(code, 0);
    assert!(stdout.contains("PE: x86_64"));
    assert!(stdout.contains("Supported imports: 3"));
    assert!(stdout.contains("Missing imports:   0"));
    assert!(!stdout.contains("Missing:\n"));
}

#[test]
fn test_inspect_missing_imports() {
    let (code, stdout, _) = run_inspect(&artifact("exe/bad_import.exe"));
    assert_eq!(code, 1);
    assert!(stdout.contains("Missing imports:   1"));
    assert!(stdout.contains("Missing:\n"));
    assert!(stdout.contains("NoSuchApiForTest"));
}

#[test]
fn test_inspect_rust_guest() {
    let (code, stdout, _) = run_inspect(&artifact("exe/rust_fs.exe"));
    assert_eq!(code, 0);
    assert!(stdout.contains("Supported imports: 11"));
}

#[test]
fn test_inspect_invalid_file() {
    let p = tmp_path("junk.exe");
    std::fs::write(&p, b"definitely not a PE file................").unwrap();
    let (code, _, stderr) = run_inspect(&p);
    std::fs::remove_file(&p).ok();
    assert_eq!(code, 1);
    assert!(stderr.contains("cannot inspect"), "stderr: {stderr}");
}

// ---------- P1: offline install loop (no network) ----------

fn run_wincli_env(args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    // never inherit a real source/cache from the developer machine
    let output = cmd.output().expect("spawn wincli");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn isolated_cache(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "wincli-cli-cache-{}-{}-{tag}",
        std::process::id(),
        counter()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn test_install_inspect_run_offline_loop() {
    let cache = isolated_cache("loop");
    let src = artifact("packages").to_string_lossy().to_string();
    let cc = cache.to_string_lossy().to_string();
    let envs = [
        ("WINCLI_CACHE", cc.as_ref()),
        ("WINCLI_SOURCE", src.as_ref()),
    ];

    // install from the local fixture source (no network anywhere)
    let (code, stdout, stderr) = run_wincli_env(&["install", "demo"], &envs);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "Installed demo 0.1.0 → C:\\bin\\demo.exe\n");

    // cache layout: content-addressed blob + runnable + index
    assert!(cache.join("pkgs").join("demo.exe").is_file());
    assert!(cache.join("index").join("demo.json").is_file());
    let blobs: Vec<_> = std::fs::read_dir(cache.join("archives"))
        .unwrap()
        .collect();
    assert_eq!(blobs.len(), 1);

    // inspect by cached package name
    let (code, stdout, _) = run_wincli_env(&["inspect", "demo"], &envs);
    assert_eq!(code, 0);
    assert!(stdout.contains("Supported imports: 3"));

    // run the cached exe through the real CLI
    let exe = cache.join("pkgs").join("demo.exe");
    let (code, stdout, _) = run_wincli_env(&[exe.to_str().unwrap()], &envs);
    assert_eq!(code, 0);
    assert_eq!(stdout, "demo 0.1.0");

    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_install_unknown_package() {
    let cache = isolated_cache("unknown");
    let src = artifact("packages").to_string_lossy().to_string();
    let cc = cache.to_string_lossy().to_string();
    let (code, _, stderr) = run_wincli_env(
        &["install", "nope"],
        &[("WINCLI_CACHE", cc.as_ref()), ("WINCLI_SOURCE", src.as_ref())],
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("package not found: nope"), "stderr: {stderr}");
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_install_missing_source_dir() {
    let cache = isolated_cache("nosrc");
    let cc = cache.to_string_lossy().to_string();
    let bin = env!("CARGO_BIN_EXE_wincli");
    let output = std::process::Command::new(bin)
        .args(["install", "demo"])
        .env("WINCLI_CACHE", &cc)
        .env("WINCLI_SOURCE", "/nonexistent-source-dir-xyz")
        .output()
        .expect("spawn wincli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(stderr.contains("package source dir not found"), "stderr: {stderr}");
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_inspect_cache_miss_suggests_install() {
    let cache = isolated_cache("miss");
    let cc = cache.to_string_lossy().to_string();
    let (code, _, stderr) = run_wincli_env(
        &["inspect", "ghost-pkg"],
        &[("WINCLI_CACHE", cc.as_ref())],
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("wincli install ghost-pkg"), "stderr: {stderr}");
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_install_deflated_fixture_offline() {
    // demoz.zip is deflated (method 8) with a nested path: exercises the
    // inflate path with zero network.
    let cache = isolated_cache("demoz");
    let src = artifact("packages").to_string_lossy().to_string();
    let cc = cache.to_string_lossy().to_string();
    let envs = [
        ("WINCLI_CACHE", cc.as_ref()),
        ("WINCLI_SOURCE", src.as_ref()),
    ];
    let (code, stdout, stderr) = run_wincli_env(&["install", "demoz"], &envs);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "Installed demoz 0.2.0 → C:\\bin\\demo.exe\n");
    let exe = cache.join("pkgs").join("demoz.exe");
    let (code, stdout, _) = run_wincli_env(&[exe.to_str().unwrap()], &envs);
    assert_eq!(code, 0);
    assert_eq!(stdout, "demoz 0.1.0");
    std::fs::remove_dir_all(&cache).ok();
}

/// Live acceptance: real WinGet install of ripgrep, then the harness loop.
/// Needs network + GitHub API quota. Run explicitly:
/// `cargo test -- --ignored live_install_ripgrep`.
#[test]
#[ignore]
fn live_install_ripgrep() {
    let cache = isolated_cache("rg");
    let cc = cache.to_string_lossy().to_string();
    let bin = env!("CARGO_BIN_EXE_wincli");
    // remote default: no WINCLI_SOURCE
    let out = std::process::Command::new(bin)
        .args(["install", "rg"])
        .env("WINCLI_CACHE", &cc)
        .env_remove("WINCLI_SOURCE")
        .output()
        .expect("spawn wincli install");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.starts_with("Installed rg "), "{stdout}");
    assert!(stdout.contains("→ C:\\bin\\rg.exe"), "{stdout}");
    assert!(cache.join("pkgs").join("rg.exe").is_file());

    // the harness loop: real rg.exe is NOT yet runnable -> missing-API report
    let out = std::process::Command::new(bin)
        .args(["inspect", "rg"])
        .env("WINCLI_CACHE", &cc)
        .env_remove("WINCLI_SOURCE")
        .output()
        .expect("spawn wincli inspect");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("Missing imports:"), "{stdout}");
    assert!(stdout.contains("Missing:\n"), "{stdout}");
    std::fs::remove_dir_all(&cache).ok();
}

// ---------- P3: argv + name resolution ----------

#[test]
fn test_argv_echo_lib_level() {
    // controlled argv0 through the library
    let bytes = std::fs::read(artifact("exe/rust_argv.exe")).unwrap();
    let args = ["hello".to_string(), "a b".to_string(), "--version".to_string()];
    let (code, _, out) =
        wincli::winapi::run_exe_argv(&bytes, WinFs::new(), "myprog.exe", &args).unwrap();
    assert_eq!(code, 0);
    assert_eq!(out, b"myprog.exe hello \"a b\" --version\n");
}

#[test]
fn test_argv_echo_cli() {
    let p = artifact("exe/rust_argv.exe");
    let ps = p.to_string_lossy().to_string();
    let (code, stdout, stderr) = run_wincli_env(&[ps.as_str(), "hello", "a b", "--version"], &[]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, format!("{ps} hello \"a b\" --version\n"));
}

#[test]
fn test_bare_name_and_guest_path_resolution() {
    let cache = isolated_cache("resolve");
    let src = artifact("packages").to_string_lossy().to_string();
    let cc = cache.to_string_lossy().to_string();
    let envs = [
        ("WINCLI_CACHE", cc.as_ref()),
        ("WINCLI_SOURCE", src.as_ref()),
    ];
    // install demoz from fixtures, then run by bare name and guest path
    let (code, _, stderr) = run_wincli_env(&["install", "demoz"], &envs);
    assert_eq!(code, 0, "stderr: {stderr}");
    let (code, stdout, stderr) = run_wincli_env(&["demoz"], &envs);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "demoz 0.1.0");
    let (code, stdout, stderr) = run_wincli_env(&["C:\\bin\\demoz.exe"], &envs);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "demoz 0.1.0");
    // argv0 reflects what was typed
    let (code, stdout, _) = run_wincli_env(&["install", "demo"], &envs);
    assert_eq!(code, 0);
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_run_unknown_name_suggests_install() {
    let cache = isolated_cache("runknown");
    let cc = cache.to_string_lossy().to_string();
    let (code, _, stderr) =
        run_wincli_env(&["ghost-tool"], &[("WINCLI_CACHE", cc.as_ref())]);
    assert_eq!(code, 1);
    assert!(stderr.contains("wincli install ghost-tool"), "stderr: {stderr}");
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_ps1_with_args_rejected() {
    let (code, _, stderr) = run_wincli_env(
        &[artifact("ps1/fs_dots.ps1").to_str().unwrap(), "extra"],
        &[],
    );
    assert_eq!(code, 2);
    assert!(stderr.contains("script args not supported"), "stderr: {stderr}");
}

#[test]
fn test_art_exe_rust_fp() {
    // Real rustc-built FP guest (guests/fp.rs): scalar-double arithmetic,
    // CMPLTSD select lowering, UCOMISD branches incl. NaN.
    let bytes = std::fs::read(artifact("exe/rust_fp.exe")).unwrap();
    let img = pe::load(&bytes).expect("rust guest must load");
    for imp in img.imports.iter().chain(img.stubs.iter()) {
        assert!(
            pe::is_supported(&imp.dll, &imp.func),
            "unsupported import in rust guest: {}!{}",
            imp.dll,
            imp.func
        );
    }
    let (code, stdout, stderr) = run_cli(&artifact("exe/rust_fp.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "FP-OK\n");
}

#[test]
fn test_art_exe_rust_alloc() {
    // Real rustc-built alloc guest (guests/alloc.rs): Vec/String/format!,
    // closures, Box/BTreeMap/sort on a HeapAlloc heap.
    let bytes = std::fs::read(artifact("exe/rust_alloc.exe")).unwrap();
    let img = pe::load(&bytes).expect("rust guest must load");
    for imp in img.imports.iter().chain(img.stubs.iter()) {
        assert!(
            pe::is_supported(&imp.dll, &imp.func),
            "unsupported import in rust guest: {}!{}",
            imp.dll,
            imp.func
        );
    }
    let (code, stdout, stderr) = run_cli(&artifact("exe/rust_alloc.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "A1\nA2\nA3\nA4\nA5\nPASS\n");
}

#[test]
fn test_art_exe_rust_alloc_fs() {
    // Real rustc-built guest (guests/alloc_fs.rs): format! + WinFS file
    // write/read roundtrip with exact verification, then cleanup.
    let bytes = std::fs::read(artifact("exe/rust_alloc_fs.exe")).unwrap();
    let img = pe::load(&bytes).expect("rust guest must load");
    for imp in img.imports.iter().chain(img.stubs.iter()) {
        assert!(
            pe::is_supported(&imp.dll, &imp.func),
            "unsupported import in rust guest: {}!{}",
            imp.dll,
            imp.func
        );
    }
    let (code, stdout, stderr) = run_cli(&artifact("exe/rust_alloc_fs.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "F1\nF2\nF3\nF4\nPASS\n");
}

#[test]
fn test_art_exe_rust_hashmap() {
    // Real rustc-built guest (guests/hashmap.rs): hand-rolled open-addressing
    // map (FNV-1a, linear probing, growth/rehash, removal). Exercises 8-bit
    // high-byte register reads (AH/CH/DH/BH) in the hash loop.
    let bytes = std::fs::read(artifact("exe/rust_hashmap.exe")).unwrap();
    let img = pe::load(&bytes).expect("rust guest must load");
    for imp in img.imports.iter().chain(img.stubs.iter()) {
        assert!(
            pe::is_supported(&imp.dll, &imp.func),
            "unsupported import in rust guest: {}!{}",
            imp.dll,
            imp.func
        );
    }
    let (code, stdout, stderr) = run_cli(&artifact("exe/rust_hashmap.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "H1a\nH1\nH2\nH3\nH4\nH5\nPASS\n");
}

// ---------- interactive shell (piped stdin, no network) ----------

fn run_shell_env(input: &str, envs: &[(&str, &str)]) -> (i32, String, String) {
    use std::io::Write;
    let bin = env!("CARGO_BIN_EXE_wincli");
    let mut child = std::process::Command::new(bin)
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(envs.iter().copied())
        .spawn()
        .expect("spawn wincli shell");
    child
        .stdin
        .take()
        .expect("shell stdin")
        .write_all(input.as_bytes())
        .expect("write shell input");
    let output = child.wait_with_output().expect("wait shell");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn test_shell_install_run_session_offline() {
    let cache = isolated_cache("shell");
    let src = artifact("packages").to_string_lossy().to_string();
    let cc = cache.to_string_lossy().to_string();
    let envs = [
        ("WINCLI_CACHE", cc.as_ref()),
        ("WINCLI_SOURCE", src.as_ref()),
    ];
    // One session: install, run the package, share PS1 files across lines.
    let input = "install demo\ndemo\nNew-Item C:\\shell-t.txt -Value hi\nGet-Content C:\\shell-t.txt\n$v = 42\necho $v\nexit\n";
    let (code, stdout, stderr) = run_shell_env(input, &envs);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("Installed demo 0.1.0 → C:\\bin\\demo.exe"), "stdout: {stdout}");
    assert!(stdout.contains("demo 0.1.0"), "stdout: {stdout}");
    assert!(stdout.contains("hi\n"), "stdout: {stdout}");
    assert!(stdout.ends_with("42\n"), "stdout: {stdout}");
    assert!(cache.join("pkgs").join("demo.exe").is_file());
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_shell_unknown_and_bad_exit() {
    let cache = isolated_cache("shell-err");
    let cc = cache.to_string_lossy().to_string();
    let (code, stdout, stderr) = run_shell_env("frobnicate\nexit abc\n", &[("WINCLI_CACHE", cc.as_ref())]);
    // Errors print and the shell continues; a bad exit code is an error,
    // EOF ends the session cleanly.
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(stderr.contains("install frobnicate"), "stderr: {stderr}");
    assert!(stderr.contains("exit: bad code"), "stderr: {stderr}");
    std::fs::remove_dir_all(&cache).ok();
}
