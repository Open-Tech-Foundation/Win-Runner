//! Required acceptance tests for Win-Runner.
//!
//! 1. `winrun hello.exe` prints `Hello from Windows`.
//! 2. PE exit codes propagate correctly.
//! 3. EXE can create/read/write/delete files in WinFS.
//! 4. `.ps1` can create/read/write/delete the same kinds of files.
//! 5. Paths are case-insensitive.
//! 6. `.` and `..` normalization works.
//! 7. Files never appear on the Linux host filesystem.
//! 8. Unknown PE imports fail clearly.
//! 9. EXE and PS1 execution use the exact same WinFS API.

use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use winrun::pe;
use winrun::winfs::WinFs;

// ---------- helpers ----------

#[test]
fn renamed_cli_uses_winrun_command_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .output()
        .expect("start winrun without arguments");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("winrun <app.exe>"), "stderr: {stderr}");
}

fn run_exe_on_fs(data: &[u8], fs: WinFs) -> (u32, WinFs, Vec<u8>) {
    let image = pe::load(data).expect("PE should load with native imports");
    let (code, output, fs) =
        winrun::native::run_rust_baseline_argv_with_fs(&image, fs, "test.exe", &[])
            .expect("native PE should run");
    (code, fs, output)
}

fn run_ps1_on_fs(fs: &mut WinFs, script: &str) -> Vec<u8> {
    let mut out = Vec::new();
    winrun::ps1::run_ps1(fs, script, &mut out).expect("ps1 should run");
    out
}

fn tmp_path(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "winrun-test-{}-{}-{name}",
        std::process::id(),
        counter()
    ));
    p
}

fn counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    C.fetch_add(1, Ordering::SeqCst)
}

fn run_cli(file: &std::path::Path) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let output = Command::new(bin)
        .arg(file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn winrun");
    let code = output.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

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

#[test]
fn exec_worker_returns_guest_filesystem_changes_to_the_launcher() {
    let binary = env!("CARGO_BIN_EXE_winrun");
    let program_path = tmp_path("worker-writes.exe");
    let snapshot_path = tmp_path("worker-state.winfs");
    let image = pe::builder::write_file(r"C:\worker-result.txt", b"written in exec worker");
    std::fs::write(&program_path, image).unwrap();
    let output = Command::new(binary)
        .arg(format!("--save-snapshot={}", snapshot_path.display()))
        .arg(&program_path)
        .output()
        .expect("start winrun exec worker");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fs = winrun::snapshot::load_file(snapshot_path.to_str().unwrap()).unwrap();
    assert_eq!(
        fs.read_file(r"C:\worker-result.txt").unwrap(),
        b"written in exec worker"
    );
    std::fs::remove_file(program_path).unwrap();
    std::fs::remove_file(snapshot_path).unwrap();
}

#[test]
fn exec_worker_reads_files_from_an_existing_winfs_snapshot() {
    let binary = env!("CARGO_BIN_EXE_winrun");
    let snapshot_path = tmp_path("worker-input.winfs");
    let program_path = tmp_path("worker-read.exe");
    let mut fs = WinFs::ephemeral_runner();
    fs.write_file(r"C:\worker-input.txt", b"snapshot extent".to_vec())
        .unwrap();
    winrun::snapshot::save_file(&mut fs, snapshot_path.to_str().unwrap()).unwrap();
    std::fs::write(
        &program_path,
        pe::builder::read_file_to_stdout(r"C:\worker-input.txt"),
    )
    .unwrap();
    let output = Command::new(binary)
        .arg(format!("--snapshot={}", snapshot_path.display()))
        .arg(format!("--save-snapshot={}", snapshot_path.display()))
        .arg(&program_path)
        .output()
        .expect("start worker using an existing WinFS disk");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"snapshot extent");
    let loaded = winrun::snapshot::load_file(snapshot_path.to_str().unwrap()).unwrap();
    assert_eq!(
        loaded.read_file(r"C:\worker-input.txt").unwrap(),
        b"snapshot extent"
    );
    std::fs::remove_file(program_path).unwrap();
    std::fs::remove_file(snapshot_path).unwrap();
}

#[test]
fn create_process_child_runs_in_an_exec_worker_and_returns_output() {
    let binary = env!("CARGO_BIN_EXE_winrun");
    let snapshot_path = tmp_path("create-process-child.winfs");
    let parent_path = tmp_path("create-process-parent.exe");
    let mut fs = WinFs::ephemeral_runner();
    fs.write_file(r"C:\child.exe", pe::builder::hello("child worker\n"))
        .unwrap();
    winrun::snapshot::save_file(&mut fs, snapshot_path.to_str().unwrap()).unwrap();
    std::fs::write(
        &parent_path,
        pe::builder::create_process_wait(r"C:\child.exe", None),
    )
    .unwrap();

    let output = Command::new(binary)
        .arg(format!("--snapshot={}", snapshot_path.display()))
        .arg("--save")
        .arg(&parent_path)
        .output()
        .expect("run a parent guest that creates a child guest");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"child worker\n",
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_file(parent_path).unwrap();
    std::fs::remove_file(snapshot_path).unwrap();
}

#[test]
fn create_process_child_keeps_its_working_directory_in_winfs() {
    let binary = env!("CARGO_BIN_EXE_winrun");
    let snapshot_path = tmp_path("create-process-cwd.winfs");
    let parent_path = tmp_path("create-process-cwd-parent.exe");
    let mut fs = WinFs::ephemeral_runner();
    fs.mkdir(r"C:\work").unwrap();
    let parent_cwd = fs.cwd();
    fs.write_file(
        r"C:\child.exe",
        pe::builder::write_file("child.txt", b"cwd"),
    )
    .unwrap();
    winrun::snapshot::save_file(&mut fs, snapshot_path.to_str().unwrap()).unwrap();
    std::fs::write(
        &parent_path,
        pe::builder::create_process_wait(r"C:\child.exe", Some(r"C:\work")),
    )
    .unwrap();

    let output = Command::new(binary)
        .arg(format!("--snapshot={}", snapshot_path.display()))
        .arg("--save")
        .arg(&parent_path)
        .output()
        .expect("run a child guest with its requested working directory");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let loaded = winrun::snapshot::load_file(snapshot_path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.read_file(r"C:\work\child.txt").unwrap(), b"cwd");
    assert_eq!(loaded.cwd(), parent_cwd);

    std::fs::remove_file(parent_path).unwrap();
    std::fs::remove_file(snapshot_path).unwrap();
}

#[test]
fn save_flag_updates_the_loaded_snapshot_on_exit() {
    let binary = env!("CARGO_BIN_EXE_winrun");
    let snapshot_path = tmp_path("save-flag.winfs");
    let program_path = tmp_path("save-flag.exe");
    let mut fs = WinFs::ephemeral_runner();
    fs.write_file(r"C:\before.txt", b"before".to_vec()).unwrap();
    winrun::snapshot::save_file(&mut fs, snapshot_path.to_str().unwrap()).unwrap();
    std::fs::write(
        &program_path,
        pe::builder::write_file(r"C:\after.txt", b"saved on exit"),
    )
    .unwrap();

    let output = Command::new(binary)
        .arg(format!("--snapshot={}", snapshot_path.display()))
        .arg("--save")
        .arg(&program_path)
        .output()
        .expect("run guest and save loaded snapshot on exit");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let loaded = winrun::snapshot::load_file(snapshot_path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.read_file(r"C:\before.txt").unwrap(), b"before");
    assert_eq!(loaded.read_file(r"C:\after.txt").unwrap(), b"saved on exit");

    std::fs::remove_file(program_path).unwrap();
    std::fs::remove_file(snapshot_path).unwrap();
}

#[test]
fn exec_worker_preserves_guest_exit_codes() {
    let program_path = tmp_path("worker-exit.exe");
    std::fs::write(&program_path, pe::builder::exit_code(37)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(&program_path)
        .output()
        .expect("start winrun guest with a nonzero exit code");
    assert_eq!(
        output.status.code(),
        Some(37),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_file(program_path).unwrap();
}

#[test]
fn exec_worker_reopens_mounted_host_drives() {
    let binary = env!("CARGO_BIN_EXE_winrun");
    let host_dir = tmp_path("worker-mount");
    std::fs::create_dir(&host_dir).unwrap();
    let program_path = tmp_path("worker-mount.exe");
    let image = pe::builder::write_file(r"Z:\worker-mounted.txt", b"mounted write");
    std::fs::write(&program_path, image).unwrap();
    let mount = format!("--mount=Z:{}", host_dir.display());
    let output = Command::new(binary)
        .arg(mount)
        .arg(&program_path)
        .output()
        .expect("start winrun with mounted drive");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(host_dir.join("worker-mounted.txt")).unwrap(),
        b"mounted write"
    );
    std::fs::remove_file(program_path).unwrap();
    std::fs::remove_file(host_dir.join("worker-mounted.txt")).unwrap();
    std::fs::remove_dir(host_dir).unwrap();
}

#[test]
fn native_backend_runs_rust_hello_guest() {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_hello.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"Hello from Rust");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_argv_guest() {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_argv.exe"
    );
    let output = Command::new(bin)
        .args([exe, "hello", "a b", "--version"])
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    let expected = format!("{exe} hello \"a b\" --version\n");
    assert_eq!(output.stdout, expected.as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_fs_guest() {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_fs.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"rust-fs-bytes-7PASS\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_overlapped_iocp_guest() {
    let output = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_iocp.exe"
        ))
        .output()
        .expect("spawn native backend");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_backend_runs_rust_alloc_guest() {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_alloc.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"A1\nA2\nA3\nA4\nA5\nPASS\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_alloc_fs_guest() {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_alloc_fs.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"F1\nF2\nF3\nF4\nPASS\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_hashmap_guest() {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_hashmap.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"H1a\nH1\nH2\nH3\nH4\nH5\nPASS\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_lang_guest() {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_lang.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"P1\nP2\nP3\nP4\nP5\nP6\nP7\nP8\nP9\nP10\nP11\nP12\nP13\nP14\nP15\nP16\nPASS\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_fp_guest() {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_fp.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"FP-OK\n");
    assert!(output.stderr.is_empty());
}

// ---------- 2: exit codes ----------

#[test]
fn native_timer_imports_run_on_the_host_clock() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(5);
    a.call_import(0); // Sleep
    a.call_import(1); // timeGetTime
    a.test_eax_eax();
    a.jz(fail);
    a.mov_ecx_imm(0);
    a.call_import(2);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(2);
    let exe = build(
        a,
        &[
            ("KERNEL32.dll", "Sleep"),
            ("WINMM.dll", "timeGetTime"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    );
    let image = pe::load_lenient(&exe).unwrap();
    let (code, _, _) =
        winrun::native::run_rust_baseline_argv_with_fs(&image, WinFs::new(), "timer.exe", &[])
            .unwrap();
    assert_eq!(code, 0);
}

#[test]
fn native_guest_writes_to_nul_without_creating_a_winfs_file() {
    use pe::builder::{build, Asm};
    let mut asm = Asm::new();
    let path = asm.add_utf16("NUL");
    let payload = asm.add_data(b"discarded".to_vec());
    let written = asm.add_zeroed(4);
    let failed = asm.fresh_label();

    asm.sub_rsp(0x48);
    asm.lea_reg_rip(1, path); // RCX = lpFileName
    asm.mov_edx_imm(0xC000_0000); // GENERIC_READ | GENERIC_WRITE
    asm.mov_r8d_imm(7); // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    asm.emit(&[0x45, 0x33, 0xC9]); // xor r9d, r9d
    asm.mov_rspoff_imm32(0x20, 3); // OPEN_EXISTING
    asm.emit(&[0x48, 0x31, 0xC0]); // xor rax, rax
    asm.mov_rspoff_rax(0x28); // dwFlagsAndAttributes
    asm.mov_rspoff_rax(0x30); // hTemplateFile
    asm.call_import(0); // CreateFileW
    asm.cmp_rax_m1();
    asm.jz(failed);
    asm.mov_rspoff_reg(0x38, 0); // save handle

    asm.mov_reg_rspoff(1, 0x38); // RCX = handle
    asm.lea_reg_rip(2, payload); // RDX = buffer
    asm.mov_r8d_imm(9); // R8D = byte count
    asm.lea_reg_rip(9, written); // R9 = bytes written
    asm.emit(&[0x48, 0x31, 0xC0]); // xor rax, rax
    asm.mov_rspoff_rax(0x20); // lpOverlapped = NULL
    asm.call_import(1); // WriteFile
    asm.test_eax_eax();
    asm.jz(failed);

    asm.mov_reg_rspoff(1, 0x38);
    asm.call_import(2); // CloseHandle
    asm.mov_ecx_imm(0);
    asm.call_import(3); // ExitProcess
    asm.mark(failed);
    asm.mov_ecx_imm(1);
    asm.call_import(3); // ExitProcess

    let image = pe::load(&build(
        asm,
        &[
            ("KERNEL32.dll", "CreateFileW"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "CloseHandle"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    ))
    .unwrap();
    let (code, stdout, fs) =
        winrun::native::run_rust_baseline_argv_with_fs(&image, WinFs::new(), "nul-device.exe", &[])
            .unwrap();
    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(!fs.exists(r"C:\NUL"));
}

#[test]
fn native_guest_writes_to_conout_through_its_standard_output() {
    use pe::builder::{build, Asm};
    let mut asm = Asm::new();
    let path = asm.add_utf16("CONOUT$");
    let payload = asm.add_data(b"console-device-output".to_vec());
    let written = asm.add_zeroed(4);
    let failed = asm.fresh_label();

    asm.sub_rsp(0x48);
    asm.lea_reg_rip(1, path);
    asm.mov_edx_imm(0x4000_0000); // GENERIC_WRITE
    asm.mov_r8d_imm(7);
    asm.emit(&[0x45, 0x33, 0xC9]); // xor r9d, r9d
    asm.mov_rspoff_imm32(0x20, 3); // OPEN_EXISTING
    asm.emit(&[0x48, 0x31, 0xC0]);
    asm.mov_rspoff_rax(0x28);
    asm.mov_rspoff_rax(0x30);
    asm.call_import(0); // CreateFileW
    asm.cmp_rax_m1();
    asm.jz(failed);
    asm.mov_rspoff_reg(0x38, 0);

    asm.mov_reg_rspoff(1, 0x38);
    asm.lea_reg_rip(2, payload);
    asm.mov_r8d_imm(21);
    asm.lea_reg_rip(9, written);
    asm.emit(&[0x48, 0x31, 0xC0]);
    asm.mov_rspoff_rax(0x20);
    asm.call_import(1); // WriteFile
    asm.test_eax_eax();
    asm.jz(failed);
    asm.mov_reg_rspoff(1, 0x38);
    asm.call_import(2); // CloseHandle
    asm.mov_ecx_imm(0);
    asm.call_import(3); // ExitProcess
    asm.mark(failed);
    asm.mov_ecx_imm(1);
    asm.call_import(3);

    let image = pe::load(&build(
        asm,
        &[
            ("KERNEL32.dll", "CreateFileW"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "CloseHandle"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    ))
    .unwrap();
    let (code, stdout, _) =
        winrun::native::run_rust_baseline_argv_with_fs(&image, WinFs::new(), "conout.exe", &[])
            .unwrap();
    assert_eq!(code, 0);
    assert_eq!(stdout, b"console-device-output");
}

#[test]
fn native_global_memory_status_ex_validates_and_populates_guest_buffer() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let mut status = vec![0u8; 64];
    status[..4].copy_from_slice(&64u32.to_le_bytes());
    let status = a.add_data(status);
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, status);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.lea_reg_rip(0, status);
    a.emit(&[0x8B, 0x40, 0x08]); // total physical memory
    a.cmp_eax_imm(512 * 1024 * 1024);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    let image = pe::load(&build(
        a,
        &[
            ("KERNEL32.dll", "GlobalMemoryStatusEx"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    ))
    .unwrap();
    let (code, _, _) =
        winrun::native::run_rust_baseline_argv_with_fs(&image, WinFs::new(), "memory.exe", &[])
            .unwrap();
    assert_eq!(code, 0);
}

#[test]
fn native_allows_unused_imports_without_a_platform_shim() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(0);
    a.call_import(1);
    let exe = build(
        a,
        &[
            ("KERNEL32.dll", "NoSuchApiForTest"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    );
    let image = pe::load_lenient(&exe).unwrap();
    let (code, _, _) = winrun::native::run_rust_baseline_argv_with_fs(
        &image,
        WinFs::new(),
        "unsupported.exe",
        &[],
    )
    .expect("unused import should bind to a fail-on-call trampoline");
    assert_eq!(code, 0);
}

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
    assert_eq!(
        fs.read_file("C:\\psdir\\b.txt").unwrap(),
        b"hello-ps\nmore\n"
    );
    assert_eq!(
        fs.read_file("C:\\psdir\\d.txt").unwrap(),
        b"hello-ps\nmore\n"
    );
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
    std::fs::write(
        &p,
        "New-Item -Path \"C:\\x\" -ItemType Directory\nTest-Path \"C:\\x\"\n",
    )
    .unwrap();
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
    run_ps1_on_fs(
        &mut fs2,
        r#"Set-Content -Path "C:\d1\d2\x.txt" -Value "zz""#,
    );
    let out = run_ps1_on_fs(&mut fs2, r#"Get-Content -Path "C:\d1\.\d2\..\d2\x.txt""#);
    assert_eq!(String::from_utf8(out).unwrap(), "zz\n");
}

// ---------- 7: never touches host ----------

#[test]
fn test7_no_host_side_effects() {
    let sentinel = format!("winrun-sentinel-{}-{}.txt", std::process::id(), counter());
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
    let sentinel2 = format!(
        "winrun-sentinel-ps1-{}-{}.txt",
        std::process::id(),
        counter()
    );
    let mut fs2 = WinFs::new();
    run_ps1_on_fs(
        &mut fs2,
        &format!("Set-Content -Path \"C:\\{sentinel2}\" -Value \"x\""),
    );
    assert!(fs2.exists(&format!("C:\\{sentinel2}")));

    // host must still be clean (check cwd, /tmp, and crate root)
    for dir in [
        "/tmp",
        ".",
        "target",
        "/media/G/WD_LINUX_FILES/projects/otf/Win-CLI",
    ] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                assert!(
                    !n.contains("winrun-sentinel"),
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
        stderr.contains("unsupported native import"),
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
    assert_eq!(type_name_of_val(&WinFs::new()), "winrun::winfs::WinFs");

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
    run_ps1_on_fs(
        &mut fs,
        r#"Set-Content -Path "C:\shared\back.txt" -Value "from-ps1""#,
    );
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
// `winrun` invocation is fully observable through guest output and exit status.

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
        stderr.contains("unsupported native import") && stderr.contains("NoSuchApiForTest"),
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
    let bin = env!("CARGO_BIN_EXE_winrun");
    let output = std::process::Command::new(bin)
        .arg("inspect")
        .arg(file)
        .output()
        .expect("spawn winrun inspect");
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
fn test_inspect_large_pe_with_ordinal_import() {
    let mut exe = pe::builder::hello("hi");
    let opt = 0x80 + 4 + 20;
    exe[opt + 56..opt + 60].copy_from_slice(&(65 * 1024 * 1024u32).to_le_bytes());
    let read_u32 = |offset: usize| u32::from_le_bytes(exe[offset..offset + 4].try_into().unwrap());
    let import_rva = read_u32(opt + 120);
    let desc = pe::builder::FILE_OFF + (import_rva - pe::builder::SECTION_RVA) as usize;
    let thunk_rva = read_u32(desc);
    let thunk = pe::builder::FILE_OFF + (thunk_rva - pe::builder::SECTION_RVA) as usize;
    exe[thunk..thunk + 8].copy_from_slice(&0x8000_0000_0000_0074u64.to_le_bytes());
    let path = tmp_path("large-ordinal.exe");
    std::fs::write(&path, exe).unwrap();
    let (code, stdout, stderr) = run_inspect(&path);
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.contains("Missing imports:   1"), "{stdout}");
    assert!(stdout.contains("KERNEL32.dll!#116"), "{stdout}");
}

#[test]
fn test_movlhps_guest_copies_source_low_qword() {
    use pe::builder::{build, Asm};
    let mut asm = Asm::new();
    let src_left = asm.add_data([1u64.to_le_bytes(), 0u64.to_le_bytes()].concat());
    let src_right = asm.add_data([42u64.to_le_bytes(), 0u64.to_le_bytes()].concat());
    let output = asm.add_zeroed(16);
    let fail = asm.fresh_label();
    asm.sub_rsp(0x28);
    asm.lea_reg_rip(6, src_left);
    asm.emit(&[0x44, 0x0F, 0x10, 0x3E]); // movups xmm15,[rsi]
    asm.lea_reg_rip(7, src_right);
    asm.emit(&[0x0F, 0x10, 0x07]); // movups xmm0,[rdi]
    asm.emit(&[0x44, 0x0F, 0x16, 0xF8]); // movlhps xmm15,xmm0
    asm.lea_reg_rip(0, output);
    asm.emit(&[0x44, 0x0F, 0x11, 0x38]); // movups [rax],xmm15
    asm.emit(&[0x48, 0x8B, 0x40, 0x08]); // mov rax,[rax+8]
    asm.cmp_eax_imm(42);
    asm.jnz(fail);
    asm.mov_ecx_imm(0);
    asm.call_import(0);
    asm.mark(fail);
    asm.mov_ecx_imm(1);
    asm.call_import(0);
    let exe = build(asm, &[("KERNEL32.dll", "ExitProcess")]);
    let path = tmp_path("movlhps.exe");
    std::fs::write(&path, exe).unwrap();
    let (code, _, stderr) = run_cli(&path);
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn test_inspect_rust_guest() {
    let (code, stdout, _) = run_inspect(&artifact("exe/rust_fs.exe"));
    assert_eq!(code, 0);
    assert!(stdout.contains("Supported imports: 14"));
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

// ---------- command-line helpers ----------

fn run_winrun_env(args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_winrun");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    // Never inherit package-source configuration from the developer machine.
    let output = cmd.output().expect("spawn winrun");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn native_timing_reports_load_execution_and_state_stages() {
    let path = artifact("exe/hello.exe");
    let path = path.to_string_lossy().to_string();
    let (code, stdout, stderr) = run_winrun_env(&[&path], &[("WINRUN_TIMINGS", "1")]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "Hello from Windows");
    for stage in [
        "host_read=",
        "pe_load=",
        "worker_start=",
        "guest_until_output_eof=",
        "state_apply=",
        "total=",
    ] {
        assert!(stderr.contains(stage), "missing {stage} in {stderr}");
    }

    let (code, stdout, stderr) =
        run_shell_env(&format!("{path}\nexit\n"), &[("WINRUN_TIMINGS", "1")]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "Hello from Windows");
    assert!(stderr.contains("shell backend_init="), "stderr: {stderr}");
    assert!(stderr.contains("host_file_read="), "stderr: {stderr}");
    assert!(stderr.contains("pe_load="), "stderr: {stderr}");
    assert!(
        stderr.contains("guest_until_output_eof="),
        "stderr: {stderr}"
    );
}

// ---------- P3: argv + name resolution ----------

#[test]
fn test_argv_echo_lib_level() {
    // controlled argv0 through the library
    let bytes = std::fs::read(artifact("exe/rust_argv.exe")).unwrap();
    let args = [
        "hello".to_string(),
        "a b".to_string(),
        "--version".to_string(),
    ];
    let image = pe::load(&bytes).unwrap();
    let (code, out, _) =
        winrun::native::run_rust_baseline_argv_with_fs(&image, WinFs::new(), "myprog.exe", &args)
            .unwrap();
    assert_eq!(code, 0);
    assert_eq!(out, b"myprog.exe hello \"a b\" --version\n");
}

#[test]
fn test_argv_echo_cli() {
    let p = artifact("exe/rust_argv.exe");
    let ps = p.to_string_lossy().to_string();
    let (code, stdout, stderr) = run_winrun_env(&[ps.as_str(), "hello", "a b", "--version"], &[]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, format!("{ps} hello \"a b\" --version\n"));
}

#[test]
fn guest_arguments_that_match_winrun_options_are_preserved() {
    let snapshot = tmp_path("guest-options.winfs");
    let mut fs = WinFs::new();
    fs.mkdir(r"C:\bin").unwrap();
    fs.write_file(
        r"C:\bin\rust_argv.exe",
        std::fs::read(artifact("exe/rust_argv.exe")).unwrap(),
    )
    .unwrap();
    winrun::snapshot::save_file(&mut fs, snapshot.to_str().unwrap()).unwrap();

    let guest_args = [
        "--mount=guest-drive".to_string(),
        "--snapshot=guest-snapshot".to_string(),
        "--headless".to_string(),
        "--control=guest-address".to_string(),
    ];
    let output = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(format!("--snapshot={}", snapshot.display()))
        .arg(r"C:\bin\rust_argv.exe")
        .args(&guest_args)
        .output()
        .expect("run guest with Win-Runner-like arguments");
    let _ = std::fs::remove_file(snapshot);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"C:\\bin\\rust_argv.exe --mount=guest-drive --snapshot=guest-snapshot --headless --control=guest-address\n"
    );
}

#[test]
fn test_ps1_with_args_rejected() {
    let (code, _, stderr) = run_winrun_env(
        &[artifact("ps1/fs_dots.ps1").to_str().unwrap(), "extra"],
        &[],
    );
    assert_eq!(code, 2);
    assert!(
        stderr.contains("script args not supported"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_art_exe_rust_fp() {
    // Real rustc-built FP guest (guests/fp.rs): scalar-double arithmetic,
    // CMPLTSD select lowering, UCOMISD branches incl. NaN.
    let bytes = std::fs::read(artifact("exe/rust_fp.exe")).unwrap();
    let img = pe::load(&bytes).expect("rust guest must load");
    for imp in img.imports.iter() {
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
    for imp in img.imports.iter() {
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
    for imp in img.imports.iter() {
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
    for imp in img.imports.iter() {
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

#[test]
fn test_art_exe_rust_memcpy() {
    // Real rustc-built guest (guests/memcpy.rs): copy torture that pins
    // the F3 0F 7E movq-load direction fix — exact sizes incl. 212/213,
    // misaligned and overlapping copies, explicit movdqu loops, ~100KB
    // format!/push_str growth with verification.
    let bytes = std::fs::read(artifact("exe/rust_memcpy.exe")).unwrap();
    let img = pe::load(&bytes).expect("rust guest must load");
    for imp in img.imports.iter() {
        assert!(
            pe::is_supported(&imp.dll, &imp.func),
            "unsupported import in rust guest: {}!{}",
            imp.dll,
            imp.func
        );
    }
    let (code, stdout, stderr) = run_cli(&artifact("exe/rust_memcpy.exe"));
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "M1\nM2\nM3\nM4\nM5\nM6\nPASS\n");
}

// ---------- interactive shell (piped stdin, no network) ----------

fn run_session_env(mode: &str, input: &str, envs: &[(&str, &str)]) -> (i32, String, String) {
    run_session_args(&[mode.to_string()], input, envs)
}

fn run_session_args(args: &[String], input: &str, envs: &[(&str, &str)]) -> (i32, String, String) {
    use std::io::Write;
    let bin = env!("CARGO_BIN_EXE_winrun");
    let mut child = std::process::Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(envs.iter().copied())
        .spawn()
        .expect("spawn winrun session");
    child
        .stdin
        .take()
        .expect("session stdin")
        .write_all(input.as_bytes())
        .expect("write session input");
    let output = child.wait_with_output().expect("wait session");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn run_shell_env(input: &str, envs: &[(&str, &str)]) -> (i32, String, String) {
    run_session_env("shell", input, envs)
}

#[test]
fn shell_starts_in_the_user_profile_with_a_standard_windows_environment() {
    let (code, stdout, stderr) = run_shell_env(
        "Get-Location
$HOME
$env:LOCALAPPDATA
$env:WINRUN_E2E = from-powershell
set
powershell -c \"Write-Output via-system32\"
exit
",
        &[("WINRUN_E2E_HOST_ONLY", "leak")],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines[0], r"C:\Users\runner", "stdout: {stdout}");
    assert_eq!(lines[1], r"C:\Users\runner", "stdout: {stdout}");
    assert_eq!(
        lines[2], r"C:\Users\runner\AppData\Local",
        "stdout: {stdout}"
    );
    for expected in [
        r"USERPROFILE=C:\Users\runner",
        r"TEMP=C:\Users\runner\AppData\Local\Temp",
        r"ProgramFiles=C:\Program Files",
        r"ProgramData=C:\ProgramData",
        "USERNAME=runner",
        "COMPUTERNAME=WINRUNNER",
        r"windir=C:\Windows",
        // `$env:` and `set` share the one guest environment.
        "WINRUN_E2E=from-powershell",
        "via-system32",
    ] {
        assert!(lines.contains(&expected), "missing {expected}: {stdout}");
    }
    let path = lines
        .iter()
        .find_map(|line| line.strip_prefix("Path="))
        .unwrap();
    assert!(
        path.starts_with(r"C:\Windows\System32;C:\Windows;"),
        "{path}"
    );
    assert!(path
        .split(';')
        .any(|entry| entry == r"C:\ProgramData\wpkg\bin"));
    // Nothing from the Linux host environment reaches the guest.
    assert!(!stdout.contains("WINRUN_E2E_HOST_ONLY"), "stdout: {stdout}");
    assert!(!stdout.contains("/home/"), "stdout: {stdout}");
}

#[test]
fn wpkg_registry_metadata_is_available_in_ephemeral_shells() {
    let (code, stdout, stderr) = run_shell_env(
        "wpkg search node
wpkg info nodejs
wpkg list
exit
",
        &[],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains(
            "nodejs
"
        ),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("nodejs 24.21.0"), "stdout: {stdout}");
    assert!(
        stdout.contains("No packages installed."),
        "stdout: {stdout}"
    );
}

#[test]
fn wpkg_default_switches_which_side_by_side_version_a_bin_command_runs() {
    // The layout `wpkg install` produces for two versions, seeded offline.
    let snapshot = tmp_path("wpkg-versions.winfs");
    let exe = std::fs::read(artifact("exe/rust_argv.exe")).unwrap();
    let mut fs = WinFs::new();
    for version in ["1", "2"] {
        let directory = format!(r"C:\Program Files\argv\{version}");
        fs.mkdir(&directory).unwrap();
        fs.write_file(&format!(r"{directory}\rust_argv.exe"), exe.clone())
            .unwrap();
    }
    fs.create_symlink(
        r"C:\Program Files\argv\current",
        r"C:\Program Files\argv\1",
        true,
    )
    .unwrap();
    fs.mkdir(r"C:\ProgramData\wpkg\bin").unwrap();
    fs.create_symlink(
        r"C:\ProgramData\wpkg\bin\rust_argv.exe",
        r"C:\Program Files\argv\current\rust_argv.exe",
        false,
    )
    .unwrap();
    let versions: Vec<_> = ["1", "2"]
        .iter()
        .map(|version| {
            serde_json::json!({
                "version": version,
                "arch": winrun::wpkg::host_architecture(),
                "install_path": format!(r"C:\Program Files\argv\{version}"),
                "bin": ["rust_argv.exe"],
                "dependencies": [],
            })
        })
        .collect();
    fs.write_file(
        r"C:\ProgramData\wpkg\installed.json",
        serde_json::to_vec(&serde_json::json!([
            {"name": "argv", "default": "1", "versions": versions}
        ]))
        .unwrap(),
    )
    .unwrap();
    winrun::snapshot::save_file(&mut fs, snapshot.to_str().unwrap()).unwrap();

    let (code, stdout, stderr) = run_session_args(
        &[
            format!("--snapshot={}", snapshot.display()),
            "shell".to_string(),
        ],
        "rust_argv first
wpkg list argv
wpkg default argv 2
rust_argv second
exit
",
        &[],
    );
    let _ = std::fs::remove_file(snapshot);
    assert_eq!(code, 0, "stderr: {stderr}");
    // Commands run as the real file inside the selected version, so
    // GetModuleFileName and sibling files resolve within that version.
    assert!(
        stdout.contains(r#""C:\Program Files\argv\1\rust_argv.exe" first"#),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("* argv 1 ("), "stdout: {stdout}");
    assert!(stdout.contains("  argv 2 ("), "stdout: {stdout}");
    assert!(stdout.contains("argv default is now 2"), "stdout: {stdout}");
    assert!(
        stdout.contains(r#""C:\Program Files\argv\2\rust_argv.exe" second"#),
        "stdout: {stdout}"
    );
}

#[test]
fn shell_mounts_host_folder_as_a_live_guest_drive() {
    let root = tmp_path("mount-drive");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("existing.txt"), "from-host").unwrap();
    let mount_arg = format!("--mount=Z:{}", root.display());
    let (code, stdout, stderr) = run_session_args(
        &[mount_arg, "shell".to_string()],
        "Get-Content Z:\\existing.txt\nSet-Content Z:\\created.txt from-guest\nGet-Content z:\\created.TXT\nexit\n",
        &[],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("from-host"), "stdout: {stdout}");
    assert!(stdout.contains("from-guest"), "stdout: {stdout}");
    assert_eq!(
        std::fs::read(root.join("created.txt")).unwrap(),
        b"from-guest\n"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn failed_guest_execution_preserves_unsaved_c_drive_changes() {
    let snapshot = tmp_path("failed-run.snap");
    let snapshot_arg = format!("--snapshot={}", snapshot.display());
    let (code, _, stderr) = run_shell_env(
        &format!("snapshot save {}\nexit\n", snapshot.display()),
        &[],
    );
    assert_eq!(code, 0, "stderr: {stderr}");

    let bad_exe = artifact("exe/bad_import.exe").to_string_lossy().to_string();
    let (code, _, stderr) = run_session_args(
        &[snapshot_arg.clone(), "shell".to_string()],
        &format!("Set-Content C:\\Users\\runner\\keep.txt before-failure\n{bad_exe}\nsnapshot save\nexit\n"),
        &[("WINRUN_NATIVE_STRICT_IMPORTS", "1")],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(!stderr.contains("restored from snapshot"), "{stderr}");
    assert!(stderr.contains("unsupported native import"), "{stderr}");

    let (code, stdout, stderr) = run_session_args(
        &[snapshot_arg, "shell".to_string()],
        "Get-Content C:\\Users\\runner\\keep.txt\nexit\n",
        &[],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("before-failure"), "stdout: {stdout}");
    std::fs::remove_file(snapshot).ok();
}

#[cfg(target_os = "linux")]
#[test]
fn interactive_shell_completes_commands_and_inserts_text_at_the_cursor() {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::time::{Duration, Instant};

    let (mut master_fd, mut slave_fd) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0,
        "open pseudo-terminal"
    );
    let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
    let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
    let snapshot_path = tmp_path("interactive-shell-history.winfs");
    let host_history_canary = tmp_path("must-not-be-created-host-history");
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(format!("--save-snapshot={}", snapshot_path.display()))
        .arg("shell")
        .env("WINRUN_HISTORY_FILE", &host_history_canary)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()))
        .spawn()
        .expect("spawn interactive shell");
    drop(slave);

    let mut output = Vec::new();
    let prompt = b"PS C:\\Users\\runner> ";
    let read_until =
        |master: &mut std::fs::File, output: &mut Vec<u8>, condition: &dyn Fn(&[u8]) -> bool| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline && !condition(output) {
                let mut poll = libc::pollfd {
                    fd: master.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 100) } <= 0 {
                    continue;
                }
                let mut chunk = [0; 4096];
                match master.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => output.extend_from_slice(&chunk[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            condition(output)
        };

    assert!(
        read_until(&mut master, &mut output, &|bytes| bytes
            .windows(prompt.len())
            .any(|window| window == prompt)),
        "interactive prompt did not appear: {}",
        String::from_utf8_lossy(&output)
    );
    master.write_all(b"wp\t search node\r").unwrap();
    assert!(
        read_until(&mut master, &mut output, &|bytes| bytes
            .windows(b"node".len())
            .any(|window| window == b"node")),
        "Tab did not complete the wpkg command: {}",
        String::from_utf8_lossy(&output)
    );
    assert!(
        read_until(&mut master, &mut output, &|bytes| {
            bytes
                .windows(prompt.len())
                .filter(|window| *window == prompt)
                .count()
                >= 3
        }),
        "shell did not return to the prompt after the completed command: {}",
        String::from_utf8_lossy(&output)
    );
    let before_exit = output.len();
    master.write_all(b"exit 3\x1b[D1\r").unwrap();
    let exited = read_until(&mut master, &mut output, &|bytes| {
        bytes[before_exit..]
            .windows(8)
            .any(|window| window == b"\x1b[?2004l")
    });
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert!(
        exited,
        "shell did not exit after edited input: {}",
        String::from_utf8_lossy(&output)
    );
    let status = child.wait().expect("wait for interactive shell");
    let saved_disk = winrun::snapshot::load_file(snapshot_path.to_str().unwrap())
        .expect("load saved guest disk");
    let saved_history = String::from_utf8(
        saved_disk
            .read_file(r"C:\Users\runner\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
            .expect("read shell history from guest disk"),
    )
    .unwrap();
    assert!(
        saved_history.contains("wpkg search node"),
        "history: {saved_history}"
    );
    assert!(
        saved_history.contains("exit 13"),
        "history: {saved_history}"
    );
    std::fs::remove_file(snapshot_path).ok();
    assert!(
        !host_history_canary.exists(),
        "shell history must not be written to host state"
    );
    assert!(
        output
            .windows(b"exit 13".len())
            .any(|window| window == b"exit 13"),
        "left-arrow insertion did not produce `exit 13`: {}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(status.code(), Some(13));
}

#[test]
fn test_runner_executes_host_controlled_ephemeral_job() {
    let input = "New-Item C:\\Users\\runner\\job.txt -Value ready\nGet-Content C:\\Users\\runner\\job.txt\nexit\n";
    let (code, stdout, stderr) = run_session_env("runner", input, &[]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "ready\n");
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn test_runner_seeds_and_executes_a_guest_pe() {
    let host_exe = artifact("exe/rust_hello.exe");
    let input = format!(
        "@seed {} C:\\Users\\runner\\hello.exe\nC:\\Users\\runner\\hello.exe\nexit\n",
        host_exe.display()
    );
    let (code, stdout, stderr) = run_session_env("runner", &input, &[]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "Hello from Rust");
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn test_native_runner_commits_guest_files_to_the_session() {
    let host_exe = tmp_path("native-writer.exe");
    std::fs::write(
        &host_exe,
        pe::builder::write_file(r"C:\Users\runner\native.txt", b"persisted"),
    )
    .unwrap();
    let input = format!(
        "@seed {} C:\\Users\\runner\\writer.exe\nC:\\Users\\runner\\writer.exe\nGet-Content C:\\Users\\runner\\native.txt\nexit\n",
        host_exe.display()
    );
    let (code, stdout, stderr) = run_session_env("runner", &input, &[]);
    std::fs::remove_file(host_exe).ok();
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "persisted\n");
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn test_runner_boots_snapshot_file() {
    let input = tmp_path("snapshot-input");
    let path = tmp_path("runner.snap");
    std::fs::create_dir_all(input.join("C/Users/runner")).unwrap();
    std::fs::write(input.join("C/Users/runner/from-snapshot.txt"), b"booted").unwrap();
    let bin = env!("CARGO_BIN_EXE_winrun");
    let built = Command::new(bin)
        .args(["snapshot", "build"])
        .arg(&input)
        .arg(&path)
        .output()
        .expect("build snapshot");
    assert_eq!(built.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&built.stdout).contains("Built snapshot"));
    let output = Command::new(bin)
        .arg(format!("--snapshot={}", path.display()))
        .arg("runner")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn snapshot runner");
    let mut child = output;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"Get-Content C:\\Users\\runner\\from-snapshot.txt\nexit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    std::fs::remove_file(path).ok();
    std::fs::remove_dir_all(input).ok();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"booted\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn headless_snapshot_program_accepts_controlled_stdin_and_streams_output() {
    let snapshot = tmp_path("headless-control.winfs");
    let mut fs = WinFs::new();
    fs.mkdir(r"C:\bin").unwrap();
    fs.write_file(r"C:\bin\stdin-echo.exe", pe::builder::stdin_echo())
        .unwrap();
    winrun::snapshot::save_file(&mut fs, snapshot.to_str().unwrap()).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg(format!("--snapshot={}", snapshot.display()))
        .arg(r"C:\bin\stdin-echo.exe")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn headless guest program");
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();

    let mut ready = [0; 5];
    output
        .read_exact(&mut ready)
        .expect("read guest readiness output");
    assert_eq!(&ready, b"READY");
    input.write_all(b"ping").unwrap();
    input.flush().unwrap();

    let mut echoed = [0; 4];
    output.read_exact(&mut echoed).expect("read guest response");
    assert_eq!(&echoed, b"ping");
    drop(input);
    let status = child.wait().expect("wait for headless guest");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    std::fs::remove_file(snapshot).ok();
    assert_eq!(status.code(), Some(0), "stderr: {stderr}");
}

#[test]
fn headless_control_session_streams_shell_output_and_exits_cleanly() {
    let snapshot = tmp_path("controlled-shell.winfs");
    let mut fs = WinFs::new();
    fs.mkdir(r"C:\bin").unwrap();
    fs.write_file(
        r"C:\bin\bad_import.exe",
        std::fs::read(artifact("exe/bad_import.exe")).expect("read bad-import fixture"),
    )
    .unwrap();
    fs.write_file(r"C:\bin\stdin-echo.exe", pe::builder::stdin_echo())
        .unwrap();
    winrun::snapshot::save_file(&mut fs, snapshot.to_str().unwrap()).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .args([
            "--headless".to_string(),
            "--control=127.0.0.1:0".to_string(),
            format!("--snapshot={}", snapshot.display()),
            "shell".to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn controlled Win-Runner shell");
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut ready_line = String::new();
    stdout
        .read_line(&mut ready_line)
        .expect("read control endpoint announcement");
    let ready: serde_json::Value = serde_json::from_str(&ready_line).unwrap();
    assert_eq!(ready["event"], "ready");
    let endpoint = ready["url"].as_str().expect("WebSocket endpoint");
    let (origin, _) = endpoint.rsplit_once("/control/").unwrap();
    let address = origin.strip_prefix("ws://").unwrap();
    let mut scan = std::net::TcpStream::connect(address).expect("connect scanner socket");
    scan.write_all(b"not a websocket handshake\r\n\r\n")
        .unwrap();
    drop(scan);
    let invalid_token = format!("{origin}/control/not-the-session-token");
    assert!(tungstenite::connect(invalid_token).is_err());
    let (mut socket, _) = tungstenite::connect(endpoint).expect("connect control socket");

    let connected: serde_json::Value = match socket.read().unwrap() {
        tungstenite::Message::Text(message) => serde_json::from_str(&message).unwrap(),
        message => panic!("expected JSON control event, got {message:?}"),
    };
    assert_eq!(connected["event"], "connected");

    socket
        .send(tungstenite::Message::Text(
            r#"{"op":"write","id":1,"text":"pwd\r"}"#.to_string().into(),
        ))
        .unwrap();
    let mut saw_pwd = false;
    while !saw_pwd {
        let event: serde_json::Value = match socket.read().unwrap() {
            tungstenite::Message::Text(message) => serde_json::from_str(&message).unwrap(),
            message => panic!("expected JSON control event, got {message:?}"),
        };
        saw_pwd = event["event"] == "output"
            && event["text"]
                .as_str()
                .is_some_and(|text| text.contains("C:\\"));
    }

    socket
        .send(tungstenite::Message::Text(
            r#"{"op":"write","id":10,"text":"C:\\bin\\bad_import.exe\r"}"#
                .to_string()
                .into(),
        ))
        .unwrap();
    let mut saw_guest_stderr = false;
    while !saw_guest_stderr {
        let event: serde_json::Value = match socket.read().unwrap() {
            tungstenite::Message::Text(message) => serde_json::from_str(&message).unwrap(),
            message => panic!("expected JSON control event, got {message:?}"),
        };
        saw_guest_stderr = event["event"] == "output"
            && event["channel"] == "stderr"
            && event["text"]
                .as_str()
                .is_some_and(|text| text.contains("unsupported native import"));
    }

    socket
        .send(tungstenite::Message::Text(
            r#"{"op":"write","id":2,"text":"C:\\bin\\stdin-echo.exe\r"}"#
                .to_string()
                .into(),
        ))
        .unwrap();
    let mut saw_ready = false;
    while !saw_ready {
        let event: serde_json::Value = match socket.read().unwrap() {
            tungstenite::Message::Text(message) => serde_json::from_str(&message).unwrap(),
            message => panic!("expected JSON control event, got {message:?}"),
        };
        saw_ready = event["event"] == "output"
            && event["text"]
                .as_str()
                .is_some_and(|text| text.contains("READY"));
    }
    socket
        .send(tungstenite::Message::Text(
            r#"{"op":"write","id":3,"text":"ping"}"#.to_string().into(),
        ))
        .unwrap();
    let mut saw_echo = false;
    while !saw_echo {
        let event: serde_json::Value = match socket.read().unwrap() {
            tungstenite::Message::Text(message) => serde_json::from_str(&message).unwrap(),
            message => panic!("expected JSON control event, got {message:?}"),
        };
        saw_echo = event["event"] == "output"
            && event["text"]
                .as_str()
                .is_some_and(|text| text.contains("ping"));
    }
    socket
        .send(tungstenite::Message::Text(
            r#"{"op":"write","id":4,"text":"exit\r"}"#.to_string().into(),
        ))
        .unwrap();
    loop {
        let event: serde_json::Value = match socket.read().unwrap() {
            tungstenite::Message::Text(message) => serde_json::from_str(&message).unwrap(),
            message => panic!("expected JSON control event, got {message:?}"),
        };
        if event["event"] == "exit" {
            assert_eq!(event["code"], 0);
            break;
        }
    }
    let status = child.wait().expect("wait for controlled shell");
    assert_eq!(status.code(), Some(0));
    std::fs::remove_file(snapshot).ok();
}

#[test]
fn test_named_instance_boot_status_and_destroy() {
    let state = tmp_path("instances");
    let name = format!("test-{}", counter());
    let bin = env!("CARGO_BIN_EXE_winrun");
    let boot = Command::new(bin)
        .args(["instance", "boot", &name])
        .env("WINRUN_INSTANCE_DIR", &state)
        .output()
        .expect("boot instance");
    assert_eq!(
        boot.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&boot.stderr)
    );
    let status = Command::new(bin)
        .args(["instance", "status", &name])
        .env("WINRUN_INSTANCE_DIR", &state)
        .output()
        .expect("query instance");
    assert_eq!(status.status.code(), Some(0));
    let write = Command::new(bin)
        .args([
            "instance",
            "exec",
            &name,
            "--",
            "New-Item",
            "C:\\Users\\runner\\live.txt",
            "-Value",
            "live",
        ])
        .env("WINRUN_INSTANCE_DIR", &state)
        .output()
        .expect("write in instance");
    assert_eq!(
        write.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&write.stderr)
    );
    let read = Command::new(bin)
        .args([
            "instance",
            "exec",
            &name,
            "--",
            "Get-Content",
            "C:\\Users\\runner\\live.txt",
        ])
        .env("WINRUN_INSTANCE_DIR", &state)
        .output()
        .expect("read in instance");
    assert_eq!(
        read.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(read.stdout, b"live\n");
    let destroy = Command::new(bin)
        .args(["instance", "destroy", &name])
        .env("WINRUN_INSTANCE_DIR", &state)
        .output()
        .expect("destroy instance");
    assert_eq!(
        destroy.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&destroy.stderr)
    );
    std::fs::remove_dir_all(state).ok();
}

#[test]
fn test_shell_ps1_run_session_offline() {
    // One session: share PS1 files and variables across input lines.
    let input = "New-Item C:\\shell-t.txt -Value hi\nGet-Content C:\\shell-t.txt\n$v = 42\necho \"v=$v\"\nif ($v -eq 42) { echo if-ok }\n$langs = @('a', 'b')\nif ('a' -in $langs) { echo in-ok }\nswitch ('q') { 'q' { echo sw-ok } }\nfunction Hi($n) { echo \"hi-$n\" }\nforeach ($i in @('a', 'b')) { Hi $i }\n$ht = @{}\n$ht['k'] = 'v'\nif ($ht.ContainsKey('k')) { echo ht-ok }\ntry { echo try-ok } catch { echo bad }\n$cap = Join-Path 'C:\\x' 'y'\necho $cap\necho $cap | Out-Null\n$m = 'aBc'\necho $m.ToUpper()\n[Environment]::SetEnvironmentVariable('WINRUN_E2E_XYZ', 'e2e-ok', 'User')\necho $([Environment]::GetEnvironmentVariable('WINRUN_E2E_XYZ'))\necho '[{\"tag_name\": \"esrun@0.24.0\"}, {\"tag_name\": \"other\"}]' | ForEach-Object { $_.tag_name } | Where-Object { $_ -match \"esrun\" } | Select-Object -First 1\necho done\nexit\n";
    let (code, stdout, stderr) = run_shell_env(input, &[]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("hi\n"), "stdout: {stdout}");
    assert!(stdout.contains("v=42\n"), "stdout: {stdout}");
    assert!(stdout.contains("if-ok\n"), "stdout: {stdout}");
    assert!(stdout.contains("in-ok\n"), "stdout: {stdout}");
    assert!(stdout.contains("sw-ok\n"), "stdout: {stdout}");
    assert!(stdout.contains("hi-b\n"), "stdout: {stdout}");
    assert!(stdout.contains("ht-ok\n"), "stdout: {stdout}");
    assert!(stdout.contains("try-ok\n"), "stdout: {stdout}");
    assert!(stdout.contains("C:\\x\\y\n"), "stdout: {stdout}");
    assert!(stdout.contains("ABC\n"), "stdout: {stdout}");
    assert!(stdout.contains("e2e-ok\n"), "stdout: {stdout}");
    assert!(stdout.contains("esrun@0.24.0\n"), "stdout: {stdout}");
    assert!(stdout.ends_with("done\n"), "stdout: {stdout}");
}

#[test]
fn test_shell_unknown_and_bad_exit() {
    let (code, stdout, stderr) = run_shell_env("frobnicate\nexit abc\n", &[]);
    // Errors print and the shell continues; a bad exit code is an error,
    // EOF ends the session cleanly.
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(
        stderr.contains("wpkg install frobnicate"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("exit: bad code"), "stderr: {stderr}");
}
