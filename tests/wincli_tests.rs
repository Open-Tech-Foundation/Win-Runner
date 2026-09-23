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

use std::io::{Read, Write};
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
    p.push(format!(
        "wincli-test-{}-{}-{name}",
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

#[test]
fn probe_reports_called_unknown_import_and_skips_unused_ones() {
    use pe::builder::{build, Asm};
    let path = tmp_path("probe-import.exe");
    std::fs::write(&path, pe::builder::unknown_import()).unwrap();
    let bin = env!("CARGO_BIN_EXE_wincli");
    let output = Command::new(bin).args(["probe", path.to_str().unwrap()])
        .output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("unsupported import reached: KERNEL32.dll!NoSuchApiForTest"));

    let mut a = Asm::new();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(0);
    a.call_import(0);
    let exe = build(a, &[
        ("KERNEL32.dll", "ExitProcess"),
        ("KERNEL32.dll", "NoSuchApiForTest"),
    ]);
    assert!(pe::load(&exe).is_err());
    std::fs::write(&path, &exe).unwrap();
    let output = Command::new(bin).args(["probe", path.to_str().unwrap()])
        .output().unwrap();
    std::fs::remove_file(&path).ok();
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn probe_streams_guest_output_once_even_when_later_import_fails() {
    use pe::builder::{build, Asm};
    let path = tmp_path("probe-output.exe");
    for fail_after_write in [false, true] {
        let mut a = Asm::new();
        let message = a.add_data(b"before stop\n".to_vec());
        let written = a.add_zeroed(4);
        a.sub_rsp(0x28);
        a.mov_ecx_imm(1); // stdout
        a.lea_reg_rip(2, message);
        a.mov_r8d_imm(12);
        a.lea_reg_rip(9, written);
        a.mov_rspoff_imm32(0x20, 0);
        a.call_import(0); // WriteFile
        if fail_after_write {
            a.call_import(1); // unknown import
        } else {
            a.mov_ecx_imm(0);
            a.call_import(2); // ExitProcess
        }
        let exe = build(a, &[
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "NoSuchApiForTest"),
            ("KERNEL32.dll", "ExitProcess"),
        ]);
        std::fs::write(&path, exe).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_wincli"))
            .args(["probe", path.to_str().unwrap()]).output().unwrap();
        assert_eq!(output.status.code(), Some(if fail_after_write { 1 } else { 0 }));
        assert_eq!(String::from_utf8_lossy(&output.stdout), "before stop\n");
        if fail_after_write {
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("unsupported import reached: KERNEL32.dll!NoSuchApiForTest"));
        }
    }
    std::fs::remove_file(path).ok();
}

#[test]
fn critical_section_spin_count_variant_runs_through_cli() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let section = a.add_zeroed(40);
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, section);
    a.mov_edx_imm(123);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.lea_reg_rip(1, section);
    a.call_import(1);
    a.lea_reg_rip(1, section);
    a.call_import(2);
    a.mov_ecx_imm(0);
    a.call_import(3);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(3);
    let exe = build(a, &[
        ("KERNEL32.dll", "InitializeCriticalSectionAndSpinCount"),
        ("KERNEL32.dll", "EnterCriticalSection"),
        ("KERNEL32.dll", "LeaveCriticalSection"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
    let path = tmp_path("critical-spin.exe");
    std::fs::write(&path, exe).unwrap();
    let (code, _, stderr) = run_cli(&path);
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn srw_condition_variable_wakes_worker_and_reacquires_lock() {
    use pe::builder::{self, Asm};
    let mut a = Asm::new();
    let lock = a.add_zeroed(8);
    let cv = a.add_zeroed(8);
    let signal = a.add_zeroed(4);
    a.sub_rsp(0x68);
    a.lea_reg_rip(1, lock);
    a.call_import(0); // InitializeSRWLock
    a.lea_reg_rip(1, cv);
    a.call_import(1); // InitializeConditionVariable
    a.xor_eax();
    a.mov_rcx_rax();
    a.mov_rdx_rax();
    let worker_patch = a.code.len() + 2;
    a.emit(&[0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0]);
    a.mov_r9d_imm(0);
    a.mov_rspoff_imm32(0x20, 0);
    a.mov_rspoff_imm32(0x28, 0);
    a.call_import(2); // CreateThread; scheduler runs worker until CV wait
    a.mov_rspoff_rax(0x40);
    a.lea_reg_rip(1, cv);
    a.call_import(3); // WakeConditionVariable
    a.mov_reg_rspoff(1, 0x40);
    a.mov_edx_imm(u32::MAX);
    a.call_import(4); // WaitForSingleObject
    a.mov_eax_mem_rip(signal);
    a.mov_rcx_rax();
    a.call_import(8); // ExitProcess(signal)
    let worker_rva = builder::SECTION_RVA + a.code.len() as u32;
    a.code[worker_patch..worker_patch + 8]
        .copy_from_slice(&(builder::IMAGE_BASE + u64::from(worker_rva)).to_le_bytes());
    a.sub_rsp(0x38);
    a.lea_reg_rip(1, lock);
    a.call_import(5); // AcquireSRWLockExclusive
    a.lea_reg_rip(1, cv);
    a.lea_reg_rip(2, lock);
    a.mov_r8d_imm(u32::MAX);
    a.mov_r9d_imm(0);
    a.call_import(6); // SleepConditionVariableSRW
    a.lea_reg_rip(1, signal);
    a.emit(&[0xC7, 0x01, 1, 0, 0, 0]); // mov dword [rcx], 1
    a.lea_reg_rip(1, lock);
    a.call_import(7); // ReleaseSRWLockExclusive
    a.xor_eax();
    a.add_rsp(0x38);
    a.ret();
    let exe = builder::build(a, &[
        ("KERNEL32.dll", "InitializeSRWLock"),
        ("KERNEL32.dll", "InitializeConditionVariable"),
        ("KERNEL32.dll", "CreateThread"),
        ("KERNEL32.dll", "WakeConditionVariable"),
        ("KERNEL32.dll", "WaitForSingleObject"),
        ("KERNEL32.dll", "AcquireSRWLockExclusive"),
        ("KERNEL32.dll", "SleepConditionVariableSRW"),
        ("KERNEL32.dll", "ReleaseSRWLockExclusive"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 1);
    let path = tmp_path("srw-condition.exe");
    std::fs::write(&path, exe).unwrap();
    let (code, _, stderr) = run_cli(&path);
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 1, "stderr: {stderr}");
}

#[test]
fn dynamic_tls_slots_can_be_set_freed_and_reused() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let fail = a.fresh_label();
    a.sub_rsp(0x48);
    a.call_import(0); // TlsAlloc
    a.mov_rspoff_rax(0x30);
    a.mov_rcx_rax();
    a.mov_edx_imm(123);
    a.call_import(1); // TlsSetValue
    a.test_eax_eax();
    a.jz(fail);
    a.mov_reg_rspoff(1, 0x30);
    a.call_import(2); // TlsGetValue
    a.cmp_eax_imm(123);
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x30);
    a.call_import(3); // TlsFree
    a.test_eax_eax();
    a.jz(fail);
    a.mov_reg_rspoff(1, 0x30);
    a.call_import(2);
    a.test_eax_eax();
    a.jnz(fail);
    a.call_import(4); // GetLastError
    a.cmp_eax_imm(87); // ERROR_INVALID_PARAMETER
    a.jnz(fail);
    a.call_import(0); // TlsAlloc reuses the released index
    a.mov_reg_rspoff(1, 0x30);
    a.emit(&[0x48, 0x39, 0xC8]); // cmp rax, rcx
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(5);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(5);
    let exe = build(a, &[
        ("KERNEL32.dll", "TlsAlloc"),
        ("KERNEL32.dll", "TlsSetValue"),
        ("KERNEL32.dll", "TlsGetValue"),
        ("KERNEL32.dll", "TlsFree"),
        ("KERNEL32.dll", "GetLastError"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn init_once_callback_retries_failure_then_caches_context() {
    use pe::builder::{self, Asm};
    let mut a = Asm::new();
    let once = a.add_zeroed(8);
    let count = a.add_zeroed(4);
    let context = a.add_zeroed(8);
    let fail = a.fresh_label();
    let callback_fail = a.fresh_label();
    let mut callback_patches = Vec::new();
    a.sub_rsp(0x48);
    for call in 0..3 {
        a.lea_reg_rip(1, once);
        callback_patches.push(a.code.len() + 2);
        a.emit(&[0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0]); // mov rdx, callback VA
        a.mov_r8d_imm(7);
        a.lea_reg_rip(9, context);
        a.call_import(0);
        a.test_eax_eax();
        if call == 0 { a.jnz(fail); } else { a.jz(fail); }
    }
    a.mov_eax_mem_rip(count);
    a.cmp_eax_imm(2);
    a.jnz(fail);
    a.lea_reg_rip(0, context);
    a.emit(&[0x8B, 0x00]); // mov eax, [rax]
    a.cmp_eax_imm(0x100);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    let callback_rva = builder::SECTION_RVA + a.code.len() as u32;
    let callback_va = builder::IMAGE_BASE + u64::from(callback_rva);
    for patch in callback_patches {
        a.code[patch..patch + 8].copy_from_slice(&callback_va.to_le_bytes());
    }
    a.lea_reg_rip(0, count);
    a.emit(&[0xFF, 0x00]); // inc dword [rax]
    a.mov_eax_mem_rip(count);
    a.cmp_eax_imm(1);
    a.jz(callback_fail);
    a.emit(&[0x41, 0xC7, 0x00, 0, 1, 0, 0]); // mov dword [r8], 0x100
    a.mov_r32_imm(0, 1);
    a.ret();
    a.mark(callback_fail);
    a.xor_eax();
    a.ret();
    let exe = builder::build(a, &[
        ("KERNEL32.dll", "InitOnceExecuteOnce"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
    let path = tmp_path("init-once.exe");
    std::fs::write(&path, exe).unwrap();
    let (code, _, stderr) = run_cli(&path);
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn set_error_mode_returns_previous_process_flags() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(1);
    a.call_import(0);
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_ecx_imm(0x8002);
    a.call_import(0);
    a.cmp_eax_imm(1);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(0);
    a.cmp_eax_imm(0x8002);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    let exe = build(a, &[
        ("KERNEL32.dll", "SetErrorMode"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn system_metrics_reports_normal_boot_and_rejects_unmodeled_indices() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(67); // SM_CLEANBOOT
    a.call_import(0);
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    let exe = build(a, &[("USER32.dll", "GetSystemMetrics"), ("KERNEL32.dll", "ExitProcess")]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);

    let mut a = Asm::new();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(9999);
    a.call_import(0);
    let exe = build(a, &[("USER32.dll", "GetSystemMetrics")]);
    let error = winapi::run_exe(&exe, WinFs::new()).unwrap_err();
    assert!(error.contains("unsupported GetSystemMetrics index 9999"), "{error}");
}

#[test]
fn winsock_startup_initializes_data_and_tracks_cleanup() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let data = a.add_zeroed(408);
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.call_import(1); // WSACleanup before startup
    a.cmp_eax_imm(u32::MAX);
    a.jnz(fail);
    a.mov_ecx_imm(0x202);
    a.lea_reg_rip(2, data); // RDX = WSADATA
    a.call_import(0);
    a.test_eax_eax();
    a.jnz(fail);
    a.lea_reg_rip(0, data);
    a.emit(&[0x0f, 0xb7, 0x00]); // movzx eax, word [rax]
    a.cmp_eax_imm(0x202);
    a.jnz(fail);
    a.call_import(1);
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(2);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(2);
    let exe = build(a, &[
        ("WS2_32.dll", "#115"),
        ("WS2_32.dll", "#116"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);

    let mut a = Asm::new();
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(0x303); // unsupported Winsock version
    a.mov_edx_imm(0);
    a.call_import(0);
    a.cmp_eax_imm(10092);
    a.jnz(fail);
    a.mov_ecx_imm(0x202);
    a.call_import(0); // null WSADATA
    a.cmp_eax_imm(10014);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    let exe = build(a, &[("WS2_32.dll", "#115"), ("KERNEL32.dll", "ExitProcess")]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn winsock_socket_lifecycle_reports_errors_and_closes_on_cleanup() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let data = a.add_zeroed(408);
    let fail = a.fresh_label();
    a.sub_rsp(0x38);
    a.mov_ecx_imm(2); // AF_INET
    a.mov_edx_imm(1); // SOCK_STREAM
    a.mov_r8d_imm(0);
    a.call_import(0); // socket before WSAStartup
    a.cmp_rax_m1();
    a.jnz(fail);
    a.call_import(3); // WSAGetLastError
    a.cmp_eax_imm(10093);
    a.jnz(fail);
    a.mov_ecx_imm(0x202);
    a.lea_reg_rip(2, data);
    a.call_import(2); // WSAStartup
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_ecx_imm(2);
    a.mov_edx_imm(1);
    a.mov_r8d_imm(0);
    a.call_import(0);
    a.cmp_rax_m1();
    a.jz(fail);
    a.mov_rspoff_reg(0x20, 0);
    a.mov_rcx_rax();
    a.call_import(1); // closesocket
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x20);
    a.call_import(1); // double close
    a.cmp_eax_imm(u32::MAX);
    a.jnz(fail);
    a.call_import(3);
    a.cmp_eax_imm(10038); // WSAENOTSOCK
    a.jnz(fail);
    a.mov_ecx_imm(99); // unsupported address family
    a.mov_edx_imm(1);
    a.mov_r8d_imm(0);
    a.call_import(0);
    a.cmp_rax_m1();
    a.jnz(fail);
    a.call_import(3);
    a.cmp_eax_imm(10047); // WSAEAFNOSUPPORT
    a.jnz(fail);
    a.call_import(4); // WSACleanup
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(5);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(5);
    let exe = build(a, &[
        ("WS2_32.dll", "#23"),
        ("WS2_32.dll", "#3"),
        ("WS2_32.dll", "#115"),
        ("WS2_32.dll", "#111"),
        ("WS2_32.dll", "#116"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn winsock_protocol_info_reports_family_and_checks_buffer_size() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let data = a.add_zeroed(408);
    let info = a.add_zeroed(628);
    let len = a.add_data(628u32.to_le_bytes().to_vec());
    let fail = a.fresh_label();
    a.sub_rsp(0x48);
    a.mov_ecx_imm(0x202);
    a.lea_reg_rip(2, data);
    a.call_import(0); // WSAStartup
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_ecx_imm(23); // AF_INET6
    a.mov_edx_imm(1); // SOCK_STREAM
    a.mov_r8d_imm(0);
    a.call_import(1); // socket
    a.cmp_rax_m1();
    a.jz(fail);
    a.mov_rspoff_reg(0x30, 0);
    a.mov_rcx_rax();
    a.mov_edx_imm(0xffff); // SOL_SOCKET
    a.mov_r8d_imm(0x2005); // SO_PROTOCOL_INFOW
    a.lea_reg_rip(9, info);
    a.lea_reg_rip(0, len);
    a.mov_rspoff_reg(0x20, 0);
    a.call_import(2); // getsockopt
    a.test_eax_eax();
    a.jnz(fail);
    a.lea_reg_rip(0, info);
    a.emit(&[0x8B, 0x40, 0x4C]); // mov eax, [rax+76], iAddressFamily
    a.cmp_eax_imm(23);
    a.jnz(fail);
    a.lea_reg_rip(0, info);
    a.emit(&[0x8B, 0x40, 0x58]); // iSocketType
    a.cmp_eax_imm(1);
    a.jnz(fail);
    a.lea_reg_rip(0, len);
    a.emit(&[0xC7, 0x00, 4, 0, 0, 0]); // too-small optlen
    a.mov_reg_rspoff(1, 0x30);
    a.mov_edx_imm(0xffff);
    a.mov_r8d_imm(0x2005);
    a.lea_reg_rip(9, info);
    a.lea_reg_rip(0, len);
    a.mov_rspoff_reg(0x20, 0);
    a.call_import(2);
    a.cmp_eax_imm(u32::MAX);
    a.jnz(fail);
    a.call_import(3); // WSAGetLastError
    a.cmp_eax_imm(10014); // WSAEFAULT
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(4);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(4);
    let exe = build(a, &[
        ("WS2_32.dll", "#115"),
        ("WS2_32.dll", "#23"),
        ("WS2_32.dll", "#7"),
        ("WS2_32.dll", "#111"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn console_control_handler_registers_and_removes_guest_callback() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let callback = a.add_data(vec![0xC3]); // address is registered, never invoked
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, callback);
    a.mov_edx_imm(1);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.lea_reg_rip(1, callback);
    a.mov_edx_imm(0);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.lea_reg_rip(1, callback);
    a.call_import(0); // removing twice fails
    a.test_eax_eax();
    a.jnz(fail);
    a.call_import(1); // GetLastError
    a.cmp_eax_imm(87);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.mov_edx_imm(1);
    a.call_import(0); // ignore Ctrl+C
    a.test_eax_eax();
    a.jz(fail);
    a.mov_ecx_imm(0);
    a.mov_edx_imm(0);
    a.call_import(0); // restore Ctrl+C processing
    a.test_eax_eax();
    a.jz(fail);
    a.mov_ecx_imm(0);
    a.call_import(2);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(2);
    let exe = build(a, &[
        ("KERNEL32.dll", "SetConsoleCtrlHandler"),
        ("KERNEL32.dll", "GetLastError"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn semaphore_wait_release_count_and_invalid_creation() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let previous = a.add_zeroed(4);
    let fail = a.fresh_label();
    a.sub_rsp(0x38);
    a.mov_ecx_imm(0);
    a.mov_edx_imm(2);
    a.mov_r8d_imm(1); // initial > maximum
    a.mov_r9d_imm(0);
    a.call_import(0);
    a.test_rax_rax();
    a.jnz(fail);
    a.call_import(4); // GetLastError
    a.cmp_eax_imm(87);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.mov_edx_imm(1);
    a.mov_r8d_imm(2);
    a.mov_r9d_imm(0);
    a.call_import(0); // CreateSemaphoreA
    a.test_rax_rax();
    a.jz(fail);
    a.mov_rspoff_reg(0x20, 0);
    a.mov_rcx_rax();
    a.mov_edx_imm(0);
    a.call_import(1); // WaitForSingleObject, consumes count
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x20);
    a.mov_edx_imm(0);
    a.call_import(1); // zero timeout, count now zero
    a.cmp_eax_imm(258);
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x20);
    a.mov_edx_imm(2);
    a.lea_reg_rip(8, previous);
    a.call_import(2); // ReleaseSemaphore
    a.test_eax_eax();
    a.jz(fail);
    a.mov_eax_mem_rip(previous);
    a.test_eax_eax(); // previous count was zero
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x20);
    a.mov_edx_imm(1); // overflow maximum 2
    a.mov_r8d_imm(0);
    a.call_import(2);
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x20);
    a.call_import(3); // CloseHandle
    a.test_eax_eax();
    a.jz(fail);
    a.mov_ecx_imm(0);
    a.call_import(5);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(5);
    let exe = build(a, &[
        ("KERNEL32.dll", "CreateSemaphoreA"),
        ("KERNEL32.dll", "WaitForSingleObject"),
        ("KERNEL32.dll", "ReleaseSemaphore"),
        ("KERNEL32.dll", "CloseHandle"),
        ("KERNEL32.dll", "GetLastError"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn power_notification_registration_round_trips_handle() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let subscribe = a.add_zeroed(16);
    let handle = a.add_zeroed(8);
    let callback = a.add_data(vec![0xC3]);
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.lea_reg_rip(0, callback);
    a.lea_reg_rip(1, subscribe);
    a.emit(&[0x48, 0x89, 0x01]); // mov [rcx], rax
    a.mov_ecx_imm(2); // DEVICE_NOTIFY_CALLBACK
    a.lea_reg_rip(2, subscribe);
    a.lea_reg_rip(8, handle);
    a.call_import(0);
    a.test_eax_eax();
    a.jnz(fail);
    a.lea_reg_rip(0, handle);
    a.emit(&[0x48, 0x8B, 0x08]); // mov rcx, [rax]
    a.call_import(1);
    a.test_eax_eax();
    a.jnz(fail);
    a.lea_reg_rip(0, handle);
    a.emit(&[0x48, 0x8B, 0x08]);
    a.call_import(1); // already unregistered
    a.cmp_eax_imm(6);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(2);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(2);
    let exe = build(a, &[
        ("POWRPROF.dll", "PowerRegisterSuspendResumeNotification"),
        ("POWRPROF.dll", "PowerUnregisterSuspendResumeNotification"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn version_condition_mask_packs_comparison_fields() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(0);
    a.mov_edx_imm(2); // VER_MAJORVERSION
    a.mov_r8d_imm(3); // VER_GREATER_EQUAL
    a.call_import(0);
    a.cmp_eax_imm(0x18);
    a.jnz(fail);
    a.mov_rcx_rax();
    a.mov_edx_imm(4); // VER_BUILDNUMBER
    a.mov_r8d_imm(2); // VER_GREATER
    a.call_import(0);
    a.cmp_eax_imm(0x98);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    let exe = build(a, &[
        ("KERNEL32.dll", "VerSetConditionMask"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn split_init_once_retries_failure_and_returns_completed_context() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let once = a.add_zeroed(8);
    let pending = a.add_zeroed(4);
    let context_out = a.add_zeroed(8);
    let context = a.add_zeroed(8);
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, once);
    a.mov_edx_imm(1); // INIT_ONCE_CHECK_ONLY
    a.lea_reg_rip(8, pending);
    a.lea_reg_rip(9, context_out);
    a.call_import(0);
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_eax_mem_rip(pending);
    a.cmp_eax_imm(1);
    a.jnz(fail);
    a.lea_reg_rip(1, once);
    a.mov_edx_imm(0);
    a.lea_reg_rip(8, pending);
    a.lea_reg_rip(9, context_out);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.lea_reg_rip(1, once);
    a.mov_edx_imm(4); // INIT_ONCE_INIT_FAILED
    a.mov_r8d_imm(0);
    a.call_import(1);
    a.test_eax_eax();
    a.jz(fail);
    a.lea_reg_rip(1, once);
    a.mov_edx_imm(0);
    a.lea_reg_rip(8, pending);
    a.lea_reg_rip(9, context_out);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.lea_reg_rip(1, once);
    a.mov_edx_imm(0);
    a.lea_reg_rip(8, context);
    a.call_import(1);
    a.test_eax_eax();
    a.jz(fail);
    a.lea_reg_rip(1, once);
    a.mov_edx_imm(0);
    a.lea_reg_rip(8, pending);
    a.lea_reg_rip(9, context_out);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.mov_eax_mem_rip(pending);
    a.test_eax_eax();
    a.jnz(fail);
    a.lea_reg_rip(0, context_out);
    a.emit(&[0x48, 0x8B, 0x00]); // mov rax, [rax]
    a.lea_reg_rip(1, context);
    a.emit(&[0x48, 0x39, 0xC1]); // cmp rcx, rax
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(2);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(2);
    let exe = build(a, &[
        ("KERNEL32.dll", "InitOnceBeginInitialize"),
        ("KERNEL32.dll", "InitOnceComplete"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn verify_version_info_compares_windows_baseline_and_reports_mismatch() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let mut info = vec![0u8; 284];
    info[0..4].copy_from_slice(&284u32.to_le_bytes());
    info[4..8].copy_from_slice(&6u32.to_le_bytes());
    info[8..12].copy_from_slice(&2u32.to_le_bytes());
    let version = a.add_data(info);
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, version);
    a.mov_edx_imm(0x23); // major, minor, SP major
    a.mov_r8d_imm(0x1801b); // VER_GREATER_EQUAL in each field
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.lea_reg_rip(0, version);
    a.emit(&[0xC7, 0x40, 0x04, 11, 0, 0, 0]); // major = 11
    a.lea_reg_rip(1, version);
    a.mov_edx_imm(0x23);
    a.mov_r8d_imm(0x1801b);
    a.call_import(0);
    a.test_eax_eax();
    a.jnz(fail);
    a.call_import(1); // GetLastError
    a.cmp_eax_imm(1150);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(2);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(2);
    let exe = build(a, &[
        ("KERNEL32.dll", "VerifyVersionInfoW"),
        ("KERNEL32.dll", "GetLastError"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn nul_device_discards_writes_and_reads_eof_without_winfs_file() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let path = a.add_utf16("C:\\missing\\NUL");
    let message = a.add_data(b"hello".to_vec());
    let read_buf = a.add_zeroed(8);
    let count = a.add_zeroed(4);
    let fail = a.fresh_label();
    a.sub_rsp(0x48);
    a.lea_reg_rip(1, path);
    a.mov_edx_imm(0xC000_0000); // GENERIC_READ | GENERIC_WRITE
    a.mov_r8d_imm(0);
    a.mov_r9d_imm(0);
    a.mov_rspoff_imm32(0x20, 3); // OPEN_EXISTING
    a.mov_rspoff_imm32(0x28, 0);
    a.mov_rspoff_imm32(0x30, 0);
    a.call_import(0); // CreateFileW
    a.cmp_rax_m1();
    a.jz(fail);
    a.mov_rspoff_reg(0x38, 0);
    a.mov_rcx_rax();
    a.call_import(3); // GetFileType
    a.cmp_eax_imm(2); // FILE_TYPE_CHAR
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x38);
    a.lea_reg_rip(2, message);
    a.mov_r8d_imm(5);
    a.lea_reg_rip(9, count);
    a.mov_rspoff_imm32(0x20, 0);
    a.call_import(1); // WriteFile
    a.test_eax_eax();
    a.jz(fail);
    a.mov_eax_mem_rip(count);
    a.cmp_eax_imm(5);
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x38);
    a.lea_reg_rip(2, read_buf);
    a.mov_r8d_imm(8);
    a.lea_reg_rip(9, count);
    a.mov_rspoff_imm32(0x20, 0);
    a.call_import(2); // ReadFile
    a.test_eax_eax();
    a.jz(fail);
    a.mov_eax_mem_rip(count);
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x38);
    a.call_import(4); // CloseHandle
    a.test_eax_eax();
    a.jz(fail);
    a.mov_ecx_imm(0);
    a.call_import(5);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(5);
    let exe = build(a, &[
        ("KERNEL32.dll", "CreateFileW"),
        ("KERNEL32.dll", "WriteFile"),
        ("KERNEL32.dll", "ReadFile"),
        ("KERNEL32.dll", "GetFileType"),
        ("KERNEL32.dll", "CloseHandle"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    let (code, fs, _) = run_exe_on_fs(&exe, WinFs::new());
    assert_eq!(code, 0);
    assert!(!fs.exists("C:\\missing\\NUL"));
}

#[test]
fn handle_information_masks_flags_and_protects_close() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let path = a.add_utf16("NUL");
    let flags = a.add_zeroed(4);
    let fail = a.fresh_label();
    a.sub_rsp(0x38);
    a.lea_reg_rip(1, path);
    a.mov_edx_imm(0);
    a.mov_r8d_imm(0);
    a.mov_r9d_imm(0);
    a.mov_rspoff_imm32(0x20, 3); // OPEN_EXISTING
    a.mov_rspoff_imm32(0x28, 0);
    a.mov_rspoff_imm32(0x30, 0);
    a.call_import(0);
    a.cmp_rax_m1();
    a.jz(fail);
    a.mov_rspoff_reg(0x30, 0);
    a.mov_rcx_rax();
    a.mov_edx_imm(3); // change both known flags
    a.mov_r8d_imm(2); // protect from close only
    a.call_import(1);
    a.test_eax_eax();
    a.jz(fail);
    a.mov_reg_rspoff(1, 0x30);
    a.lea_reg_rip(2, flags);
    a.call_import(2);
    a.test_eax_eax();
    a.jz(fail);
    a.mov_eax_mem_rip(flags);
    a.cmp_eax_imm(2);
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x30);
    a.call_import(3); // protected close fails
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x30);
    a.mov_edx_imm(2);
    a.mov_r8d_imm(0);
    a.call_import(1); // remove protection
    a.test_eax_eax();
    a.jz(fail);
    a.mov_reg_rspoff(1, 0x30);
    a.call_import(3);
    a.test_eax_eax();
    a.jz(fail);
    a.mov_ecx_imm(0);
    a.call_import(4);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(4);
    let exe = build(a, &[
        ("KERNEL32.dll", "CreateFileW"),
        ("KERNEL32.dll", "SetHandleInformation"),
        ("KERNEL32.dll", "GetHandleInformation"),
        ("KERNEL32.dll", "CloseHandle"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn encoded_pointer_decodes_to_original_value() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let fail = a.fresh_label();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(0x1234_5678);
    a.call_import(0); // EncodePointer
    a.mov_rcx_rax();
    a.call_import(1); // DecodePointer
    a.cmp_eax_imm(0x1234_5678);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(2);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(2);
    let exe = build(a, &[
        ("KERNEL32.dll", "EncodePointer"),
        ("KERNEL32.dll", "DecodePointer"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn dynamic_ntdll_export_runs_and_unknown_export_fails() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let ntdll = a.add_utf16("ntdll.dll");
    let export = a.add_data(b"RtlNtStatusToDosError\0".to_vec());
    let unknown = a.add_data(b"NoSuchExportForTest\0".to_vec());
    let fail = a.fresh_label();
    a.sub_rsp(0x38);
    a.lea_reg_rip(1, ntdll);
    a.call_import(0); // GetModuleHandleW
    a.test_rax_rax();
    a.jz(fail);
    a.mov_rspoff_reg(0x20, 0);
    a.mov_rcx_rax();
    a.lea_reg_rip(2, export);
    a.call_import(1); // GetProcAddress
    a.test_rax_rax();
    a.jz(fail);
    a.mov_ecx_imm(0xC000_0005);
    a.emit(&[0xFF, 0xD0]); // call rax
    a.cmp_eax_imm(998); // ERROR_NOACCESS
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x20);
    a.lea_reg_rip(2, unknown);
    a.call_import(1);
    a.test_rax_rax();
    a.jnz(fail);
    a.call_import(2); // GetLastError
    a.cmp_eax_imm(127); // ERROR_PROC_NOT_FOUND
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(3);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(3);
    let exe = build(a, &[
        ("KERNEL32.dll", "GetModuleHandleW"),
        ("KERNEL32.dll", "GetProcAddress"),
        ("KERNEL32.dll", "GetLastError"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
}

#[test]
fn format_message_allocates_ansi_and_wide_system_text() {
    use pe::builder::{build, Asm};
    let mut a = Asm::new();
    let out_ptr = a.add_zeroed(8);
    let fail = a.fresh_label();
    a.sub_rsp(0x48);
    for import in [0, 1] { // FormatMessageA then FormatMessageW
        a.mov_ecx_imm(0x1300); // ALLOCATE_BUFFER | IGNORE_INSERTS | FROM_SYSTEM
        a.mov_edx_imm(0);
        a.mov_r8d_imm(126); // ERROR_MOD_NOT_FOUND
        a.mov_r9d_imm(0);
        a.lea_reg_rip(0, out_ptr);
        a.mov_rspoff_rax(0x20);
        a.mov_rspoff_imm32(0x28, 0);
        a.mov_rspoff_imm32(0x30, 0);
        a.call_import(import);
        a.test_eax_eax();
        a.jz(fail);
        a.lea_reg_rip(0, out_ptr);
        a.emit(&[0x48, 0x8B, 0x00]); // mov rax, [rax]
        a.mov_rcx_rax();
        a.call_import(2); // LocalFree
        a.test_eax_eax();
        a.jnz(fail);
    }
    a.mov_ecx_imm(0x1200);
    a.mov_edx_imm(0);
    a.mov_r8d_imm(9999);
    a.mov_r9d_imm(0);
    a.lea_reg_rip(0, out_ptr);
    a.mov_rspoff_rax(0x20);
    a.mov_rspoff_imm32(0x28, 0);
    a.mov_rspoff_imm32(0x30, 0);
    a.call_import(0);
    a.test_eax_eax();
    a.jnz(fail);
    a.call_import(3); // GetLastError
    a.cmp_eax_imm(317);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(4);
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(4);
    let exe = build(a, &[
        ("KERNEL32.dll", "FormatMessageA"),
        ("KERNEL32.dll", "FormatMessageW"),
        ("KERNEL32.dll", "LocalFree"),
        ("KERNEL32.dll", "GetLastError"),
        ("KERNEL32.dll", "ExitProcess"),
    ]);
    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 0);
    let path = tmp_path("format-message.exe");
    std::fs::write(&path, exe).unwrap();
    let (code, _, stderr) = run_cli(&path);
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn interpreter_guest_thread_waits_and_handle_errors() {
    use pe::builder::{self, Asm};
    let imports = [
        ("KERNEL32.DLL", "CreateThread"),
        ("KERNEL32.DLL", "WaitForSingleObject"),
        ("KERNEL32.DLL", "Sleep"),
        ("KERNEL32.DLL", "GetCurrentThreadId"),
        ("KERNEL32.DLL", "CloseHandle"),
        ("KERNEL32.DLL", "GetLastError"),
        ("KERNEL32.DLL", "ExitProcess"),
    ];
    let mut a = Asm::new();
    let shared = a.add_zeroed(8);
    let fail = a.fresh_label();
    a.sub_rsp(0x68);
    a.xor_eax();
    a.mov_rcx_rax();
    a.mov_rdx_rax();
    let start_patch = a.code.len() + 2;
    a.emit(&[0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0]); // mov r8, worker VA
    a.lea_reg_rip(9, shared);
    a.mov_rspoff_imm32(0x20, 0);
    a.mov_rspoff_imm32(0x28, 0);
    a.call_import(0);
    a.test_rax_rax();
    a.jz(fail);
    a.mov_rspoff_rax(0x40);
    a.mov_rcx_rax();
    a.mov_edx_imm(0);
    a.call_import(1);
    a.cmp_eax_imm(258); // worker sleeps, so a zero-timeout poll must time out
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x40);
    a.mov_edx_imm(u32::MAX);
    a.call_import(1);
    a.test_eax_eax();
    a.jnz(fail);
    a.mov_eax_mem_rip(shared);
    a.cmp_eax_imm(42);
    a.jnz(fail);
    a.lea_reg_rip(1, shared);
    a.emit(&[0x8B, 0x41, 0x04]); // mov eax, [rcx+4]
    a.test_eax_eax();
    a.jz(fail);
    a.cmp_eax_imm(1); // worker ID differs from the main thread's ID
    a.jz(fail);
    a.mov_reg_rspoff(1, 0x40);
    a.call_import(4);
    a.cmp_eax_imm(1);
    a.jnz(fail);
    a.mov_reg_rspoff(1, 0x40);
    a.mov_edx_imm(0);
    a.call_import(1);
    a.cmp_eax_imm(u32::MAX); // closed thread handle is invalid
    a.jnz(fail);
    a.call_import(5);
    a.cmp_eax_imm(6); // ERROR_INVALID_HANDLE
    a.jnz(fail);
    a.mov_ecx_imm(42);
    a.call_import(6);
    a.mark(fail);
    a.mov_ecx_imm(99);
    a.call_import(6);

    let worker_va = builder::IMAGE_BASE + u64::from(builder::SECTION_RVA) + a.code.len() as u64;
    a.code[start_patch..start_patch + 8].copy_from_slice(&worker_va.to_le_bytes());
    a.sub_rsp(0x38);
    a.mov_rspoff_reg(0x30, 1); // preserve lpParameter across calls
    a.mov_ecx_imm(5);
    a.call_import(2);
    a.call_import(3);
    a.mov_reg_rspoff(1, 0x30);
    a.emit(&[0x89, 0x41, 0x04]); // mov [rcx+4], eax (worker thread ID)
    a.emit(&[0xC7, 0x01, 42, 0, 0, 0]); // mov dword [rcx], 42
    a.mov_r32_imm(0, 7);
    a.add_rsp(0x38);
    a.ret();
    let exe = builder::build(a, &imports);
    let (code, _, _) = run_exe_on_fs(&exe, WinFs::new());
    assert_eq!(code, 42);

    let path = tmp_path("guest-thread.exe");
    std::fs::write(&path, exe).unwrap();
    let (code, stdout, stderr) = run_cli(&path);
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 42, "stderr: {stderr}");
    assert!(stdout.is_empty());
}

#[test]
fn interpreter_tls_callbacks_run_before_entry_and_on_worker_attach() {
    use pe::builder::{self, Asm};
    let mut a = Asm::new();
    let counter = a.add_zeroed(4);
    a.sub_rsp(0x68);
    a.xor_eax();
    a.mov_rcx_rax();
    a.mov_rdx_rax();
    let worker_patch = a.code.len() + 2;
    a.emit(&[0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0]); // mov r8, worker VA
    a.mov_r9d_imm(0);
    a.mov_rspoff_imm32(0x20, 0);
    a.mov_rspoff_imm32(0x28, 0);
    a.call_import(0); // CreateThread
    a.mov_rcx_rax();
    a.mov_edx_imm(u32::MAX);
    a.call_import(1); // WaitForSingleObject
    a.mov_eax_mem_rip(counter);
    a.mov_rcx_rax();
    a.call_import(2); // ExitProcess(counter)
    let worker_rva = builder::SECTION_RVA + a.code.len() as u32;
    a.code[worker_patch..worker_patch + 8]
        .copy_from_slice(&(builder::IMAGE_BASE + u64::from(worker_rva)).to_le_bytes());
    a.xor_eax();
    a.ret();
    let callback_rva = builder::SECTION_RVA + a.code.len() as u32;
    a.lea_reg_rip(0, counter);
    a.emit(&[0x83, 0x00, 0x01]); // add dword [rax], 1
    a.ret();
    let mut exe = builder::build(a, &[
        ("KERNEL32.DLL", "CreateThread"),
        ("KERNEL32.DLL", "WaitForSingleObject"),
        ("KERNEL32.DLL", "ExitProcess"),
    ]);

    // Add a separate .tls section to the tiny test PE.
    let opt = 0x80 + 4 + 20;
    let old_size = u32::from_le_bytes(exe[opt + 56..opt + 60].try_into().unwrap());
    let raw = exe.len();
    exe[0x80 + 6..0x80 + 8].copy_from_slice(&2u16.to_le_bytes());
    exe[opt + 56..opt + 60].copy_from_slice(&(old_size + 0x1000).to_le_bytes());
    let tls_dir = opt + 112 + 9 * 8;
    exe[tls_dir..tls_dir + 4].copy_from_slice(&old_size.to_le_bytes());
    exe[tls_dir + 4..tls_dir + 8].copy_from_slice(&40u32.to_le_bytes());
    let header = opt + 0xf0 + 40;
    exe[header..header + 8].copy_from_slice(b".tls\0\0\0\0");
    exe[header + 8..header + 12].copy_from_slice(&0x100u32.to_le_bytes());
    exe[header + 12..header + 16].copy_from_slice(&old_size.to_le_bytes());
    exe[header + 16..header + 20].copy_from_slice(&0x200u32.to_le_bytes());
    exe[header + 20..header + 24].copy_from_slice(&(raw as u32).to_le_bytes());
    exe[header + 36..header + 40].copy_from_slice(&0xc000_0040u32.to_le_bytes());
    exe.resize(raw + 0x200, 0);
    let base = builder::IMAGE_BASE + u64::from(old_size);
    exe[raw..raw + 8].copy_from_slice(&(base + 0x40).to_le_bytes());
    exe[raw + 8..raw + 16].copy_from_slice(&(base + 0x40).to_le_bytes());
    exe[raw + 16..raw + 24].copy_from_slice(&(base + 0x48).to_le_bytes());
    exe[raw + 24..raw + 32].copy_from_slice(&(base + 0x50).to_le_bytes());
    exe[raw + 0x50..raw + 0x58]
        .copy_from_slice(&(builder::IMAGE_BASE + u64::from(callback_rva)).to_le_bytes());

    assert_eq!(run_exe_on_fs(&exe, WinFs::new()).0, 2);
    let path = tmp_path("tls-thread.exe");
    std::fs::write(&path, &exe).unwrap();
    let (code, _, stderr) = run_cli(&path);
    std::fs::remove_file(&path).ok();
    assert_eq!(code, 2, "stderr: {stderr}");
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

#[test]
fn native_backend_runs_rust_hello_guest() {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_hello.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"Hello from Rust");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_argv_guest() {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_argv.exe"
    );
    let output = Command::new(bin)
        .args([exe, "hello", "a b", "--version"])
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    let expected = format!("{exe} hello \"a b\" --version\n");
    assert_eq!(output.stdout, expected.as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_fs_guest() {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_fs.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"rust-fs-bytes-7PASS\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_alloc_guest() {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_alloc.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"A1\nA2\nA3\nA4\nA5\nPASS\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_alloc_fs_guest() {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_alloc_fs.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"F1\nF2\nF3\nF4\nPASS\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_hashmap_guest() {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_hashmap.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"H1a\nH1\nH2\nH3\nH4\nH5\nPASS\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_backend_runs_rust_lang_guest() {
    let bin = env!("CARGO_BIN_EXE_wincli");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_lang.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .env("WINCLI_BACKEND", "native")
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
    let bin = env!("CARGO_BIN_EXE_wincli");
    let exe = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/artifacts/exe/rust_fp.exe"
    );
    let output = Command::new(bin)
        .arg(exe)
        .env("WINCLI_BACKEND", "native")
        .output()
        .expect("spawn native backend");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"FP-OK\n");
    assert!(output.stderr.is_empty());
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
    let sentinel2 = format!(
        "wincli-sentinel-ps1-{}-{}.txt",
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
    assert_eq!(type_name_of_val(&WinFs::new()), "wincli::winfs::WinFs");

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
    let blobs: Vec<_> = std::fs::read_dir(cache.join("archives")).unwrap().collect();
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
        &[
            ("WINCLI_CACHE", cc.as_ref()),
            ("WINCLI_SOURCE", src.as_ref()),
        ],
    );
    assert_eq!(code, 1);
    assert!(
        stderr.contains("package not found: nope"),
        "stderr: {stderr}"
    );
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
    assert!(
        stderr.contains("package source dir not found"),
        "stderr: {stderr}"
    );
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_inspect_cache_miss_suggests_install() {
    let cache = isolated_cache("miss");
    let cc = cache.to_string_lossy().to_string();
    let (code, _, stderr) =
        run_wincli_env(&["inspect", "ghost-pkg"], &[("WINCLI_CACHE", cc.as_ref())]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("wincli install ghost-pkg"),
        "stderr: {stderr}"
    );
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
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.starts_with("Installed rg "), "{stdout}");
    assert!(stdout.contains("→ C:\\bin\\rg.exe"), "{stdout}");
    assert!(cache.join("pkgs").join("rg.exe").is_file());

    // the harness loop: real rg.exe loads with no missing imports...
    let out = std::process::Command::new(bin)
        .args(["inspect", "rg"])
        .env("WINCLI_CACHE", &cc)
        .env_remove("WINCLI_SOURCE")
        .output()
        .expect("spawn wincli inspect");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("Missing imports:   0"), "{stdout}");
    // ...and searches end to end in a shell session.
    let (code, stdout, _) = run_shell_env(
        "Set-Content C:\\log.txt 'error: disk full'\nAdd-Content C:\\log.txt 'info: all good'\nrg error C:\\log.txt\nexit\n",
        &[("WINCLI_CACHE", cc.as_ref())],
    );
    assert_eq!(code, 0);
    assert_eq!(stdout, "error: disk full\n");
    // A directory walk depends on distinct BY_HANDLE_FILE_INFORMATION IDs.
    let (code, stdout, stderr) = run_shell_env(
        "New-Item C:\\data -ItemType Directory\nSet-Content C:\\data\\one.txt 'error: one'\nSet-Content C:\\data\\two.txt 'error: two'\nrg --threads 2 error C:\\data\nexit\n",
        &[("WINCLI_CACHE", cc.as_ref())],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("C:\\data\\one.txt:error: one\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("C:\\data\\two.txt:error: two\n"),
        "{stdout}"
    );
    std::fs::remove_dir_all(&cache).ok();
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
    let (code, _, _) = run_wincli_env(&["install", "demo"], &envs);
    assert_eq!(code, 0);
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_run_unknown_name_suggests_install() {
    let cache = isolated_cache("runknown");
    let cc = cache.to_string_lossy().to_string();
    let (code, _, stderr) = run_wincli_env(&["ghost-tool"], &[("WINCLI_CACHE", cc.as_ref())]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("wincli install ghost-tool"),
        "stderr: {stderr}"
    );
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_ps1_with_args_rejected() {
    let (code, _, stderr) = run_wincli_env(
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

#[test]
fn test_art_exe_rust_memcpy() {
    // Real rustc-built guest (guests/memcpy.rs): copy torture that pins
    // the F3 0F 7E movq-load direction fix — exact sizes incl. 212/213,
    // misaligned and overlapping copies, explicit movdqu loops, ~100KB
    // format!/push_str growth with verification.
    let bytes = std::fs::read(artifact("exe/rust_memcpy.exe")).unwrap();
    let img = pe::load(&bytes).expect("rust guest must load");
    for imp in img.imports.iter().chain(img.stubs.iter()) {
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
    use std::io::Write;
    let bin = env!("CARGO_BIN_EXE_wincli");
    let mut child = std::process::Command::new(bin)
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(envs.iter().copied())
        .spawn()
        .expect("spawn wincli session");
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
fn test_runner_executes_host_controlled_ephemeral_job() {
    let input = "New-Item C:\\actions-runner\\_work\\job.txt -Value ready\nGet-Content C:\\actions-runner\\_work\\job.txt\nexit\n";
    let (code, stdout, stderr) = run_session_env("runner", input, &[]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "ready\n");
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn test_runner_seeds_and_executes_a_guest_pe() {
    let host_exe = artifact("exe/rust_hello.exe");
    let input = format!(
        "@seed {} C:\\actions-runner\\_work\\hello.exe\nC:\\actions-runner\\_work\\hello.exe\nexit\n",
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
        pe::builder::write_file(r"C:\actions-runner\_work\native.txt", b"persisted"),
    )
    .unwrap();
    let input = format!(
        "@seed {} C:\\actions-runner\\_work\\writer.exe\nC:\\actions-runner\\_work\\writer.exe\nGet-Content C:\\actions-runner\\_work\\native.txt\nexit\n",
        host_exe.display()
    );
    let (code, stdout, stderr) = run_session_env("runner", &input, &[("WINCLI_BACKEND", "native")]);
    std::fs::remove_file(host_exe).ok();
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "persisted\n");
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn test_runner_boots_snapshot_file() {
    let input = tmp_path("snapshot-input");
    let path = tmp_path("runner.snap");
    std::fs::create_dir_all(input.join("C/actions-runner/_work")).unwrap();
    std::fs::write(
        input.join("C/actions-runner/_work/from-snapshot.txt"),
        b"booted",
    )
    .unwrap();
    let bin = env!("CARGO_BIN_EXE_wincli");
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
        .write_all(b"Get-Content C:\\actions-runner\\_work\\from-snapshot.txt\nexit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    std::fs::remove_file(path).ok();
    std::fs::remove_dir_all(input).ok();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"booted\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn test_named_instance_boot_status_and_destroy() {
    let state = tmp_path("instances");
    let name = format!("test-{}", counter());
    let bin = env!("CARGO_BIN_EXE_wincli");
    let boot = Command::new(bin)
        .args(["instance", "boot", &name])
        .env("WINCLI_INSTANCE_DIR", &state)
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
        .env("WINCLI_INSTANCE_DIR", &state)
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
            "C:\\actions-runner\\_work\\live.txt",
            "-Value",
            "live",
        ])
        .env("WINCLI_INSTANCE_DIR", &state)
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
            "C:\\actions-runner\\_work\\live.txt",
        ])
        .env("WINCLI_INSTANCE_DIR", &state)
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
        .env("WINCLI_INSTANCE_DIR", &state)
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
fn test_shell_install_run_session_offline() {
    let cache = isolated_cache("shell");
    let src = artifact("packages").to_string_lossy().to_string();
    let cc = cache.to_string_lossy().to_string();
    let envs = [
        ("WINCLI_CACHE", cc.as_ref()),
        ("WINCLI_SOURCE", src.as_ref()),
    ];
    // One session: install, run the package, share PS1 files across lines.
    let input = "install demo\ndemo\nNew-Item C:\\shell-t.txt -Value hi\nGet-Content C:\\shell-t.txt\n$v = 42\necho \"v=$v\"\nif ($v -eq 42) { echo if-ok }\n$langs = @('a', 'b')\nif ('a' -in $langs) { echo in-ok }\nswitch ('q') { 'q' { echo sw-ok } }\nfunction Hi($n) { echo \"hi-$n\" }\nforeach ($i in @('a', 'b')) { Hi $i }\n$ht = @{}\n$ht['k'] = 'v'\nif ($ht.ContainsKey('k')) { echo ht-ok }\ntry { echo try-ok } catch { echo bad }\n$cap = Join-Path 'C:\\x' 'y'\necho $cap\necho $cap | Out-Null\n$m = 'aBc'\necho $m.ToUpper()\n[Environment]::SetEnvironmentVariable('WINCLI_E2E_XYZ', 'e2e-ok', 'User')\necho $([Environment]::GetEnvironmentVariable('WINCLI_E2E_XYZ'))\necho '[{\"tag_name\": \"esrun@0.24.0\"}, {\"tag_name\": \"other\"}]' | ForEach-Object { $_.tag_name } | Where-Object { $_ -match \"esrun\" } | Select-Object -First 1\necho done\nexit\n";
    let (code, stdout, stderr) = run_shell_env(input, &envs);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("Installed demo 0.1.0 → C:\\bin\\demo.exe"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("demo 0.1.0"), "stdout: {stdout}");
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
    assert!(cache.join("pkgs").join("demo.exe").is_file());
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn test_shell_unknown_and_bad_exit() {
    let cache = isolated_cache("shell-err");
    let cc = cache.to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_shell_env("frobnicate\nexit abc\n", &[("WINCLI_CACHE", cc.as_ref())]);
    // Errors print and the shell continues; a bad exit code is an error,
    // EOF ends the session cleanly.
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(stderr.contains("install frobnicate"), "stderr: {stderr}");
    assert!(stderr.contains("exit: bad code"), "stderr: {stderr}");
    std::fs::remove_dir_all(&cache).ok();
}
