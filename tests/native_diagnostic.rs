use std::process::Command;
use winrun::pe::builder::{build, Asm};

fn run_guest(bytes: &[u8], diagnostic: bool, strict: bool) -> std::process::Output {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "winrun-native-diag-{}-{}.exe",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, bytes).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_winrun"));
    command.arg(&path);
    if diagnostic {
        command.env("WINRUN_NATIVE_DIAGNOSTIC", "1");
    }
    if strict {
        command.env("WINRUN_NATIVE_STRICT_IMPORTS", "1");
    }
    let output = command.output().unwrap();
    std::fs::remove_file(path).ok();
    output
}

#[test]
fn diagnostic_names_a_called_missing_import_in_native_guest() {
    let output = run_guest(&winrun::pe::builder::unknown_import(), true, false);
    assert_eq!(output.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("unsupported native import called: KERNEL32.dll!NoSuchApiForTest"));
}

#[test]
fn unused_missing_import_runs_by_default_but_strict_mode_rejects_it() {
    let mut asm = Asm::new();
    asm.sub_rsp(0x28);
    asm.mov_ecx_imm(0);
    asm.call_import(0);
    let exe = build(
        asm,
        &[
            ("KERNEL32.dll", "ExitProcess"),
            ("KERNEL32.dll", "NoSuchApiForTest"),
        ],
    );
    let strict = run_guest(&exe, false, true);
    assert_eq!(strict.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&strict.stderr).contains("NoSuchApiForTest"));
    let normal = run_guest(&exe, false, false);
    assert_eq!(normal.status.code(), Some(0));
    let diagnostic = run_guest(&exe, true, false);
    assert_eq!(diagnostic.status.code(), Some(0));
    assert!(
        !String::from_utf8_lossy(&diagnostic.stderr).contains("unsupported native import called")
    );
}

#[test]
fn native_tls_slots_clear_values_when_reused_and_report_invalid_indices() {
    let mut asm = Asm::new();
    let fail = asm.fresh_label();
    asm.sub_rsp(0x58);
    asm.call_import(0); // TlsAlloc
    asm.cmp_eax_imm(u32::MAX);
    asm.jz(fail);
    asm.mov_rspoff_rax(0x40);
    asm.mov_reg_rspoff(1, 0x40);
    asm.mov_edx_imm(0x1234);
    asm.call_import(1); // TlsSetValue
    asm.test_eax_eax();
    asm.jz(fail);
    asm.mov_reg_rspoff(1, 0x40);
    asm.call_import(2); // TlsGetValue
    asm.cmp_eax_imm(0x1234);
    asm.jnz(fail);
    asm.mov_reg_rspoff(1, 0x40);
    asm.call_import(3); // TlsFree
    asm.test_eax_eax();
    asm.jz(fail);
    asm.mov_reg_rspoff(1, 0x40);
    asm.call_import(2);
    asm.test_eax_eax();
    asm.jnz(fail);
    asm.call_import(4); // GetLastError
    asm.cmp_eax_imm(87);
    asm.jnz(fail);
    asm.call_import(0); // reused slot must start empty
    asm.emit(&[0x48, 0x3B, 0x44, 0x24, 0x40]); // cmp rax, [rsp+0x40]
    asm.jnz(fail);
    asm.mov_reg_rspoff(1, 0x40);
    asm.call_import(2);
    asm.test_eax_eax();
    asm.jnz(fail);
    asm.mov_ecx_imm(0);
    asm.call_import(5);
    asm.mark(fail);
    asm.mov_ecx_imm(1);
    asm.call_import(5);
    let exe = build(
        asm,
        &[
            ("KERNEL32.dll", "TlsAlloc"),
            ("KERNEL32.dll", "TlsSetValue"),
            ("KERNEL32.dll", "TlsGetValue"),
            ("KERNEL32.dll", "TlsFree"),
            ("KERNEL32.dll", "GetLastError"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    );
    let output = run_guest(&exe, false, false);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_error_mode_returns_previous_process_flags() {
    let mut asm = Asm::new();
    let fail = asm.fresh_label();
    asm.sub_rsp(0x28);
    asm.mov_ecx_imm(1);
    asm.call_import(0);
    asm.test_eax_eax();
    asm.jnz(fail);
    asm.mov_ecx_imm(2);
    asm.call_import(0);
    asm.cmp_eax_imm(1);
    asm.jnz(fail);
    asm.mov_ecx_imm(0);
    asm.call_import(0);
    asm.cmp_eax_imm(2);
    asm.jnz(fail);
    asm.mov_ecx_imm(0);
    asm.call_import(1);
    asm.mark(fail);
    asm.mov_ecx_imm(1);
    asm.call_import(1);
    let exe = build(
        asm,
        &[
            ("KERNEL32.dll", "SetErrorMode"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    );
    let output = run_guest(&exe, false, false);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn guest_thread_faults_reach_vectored_handlers_and_preserve_the_parameter() {
    let mut asm = Asm::new();
    // EXCEPTION_POINTERS.ContextRecord -> Rip += sizeof(ud2), CONTINUE_EXECUTION.
    let handler = asm.add_data(vec![
        0x48, 0x8b, 0x41, 0x08, 0x48, 0x83, 0x80, 0xf8, 0, 0, 0, 2, 0xb8, 0xff, 0xff, 0xff, 0xff,
        0xc3,
    ]);
    let thread = asm.add_data(vec![0x0f, 0x0b, 0xc7, 0x01, 42, 0, 0, 0, 0x31, 0xc0, 0xc3]); // ud2; *parameter = 42; return 0
    let result = asm.add_zeroed(4);
    asm.sub_rsp(0x58);
    asm.mov_ecx_imm(1);
    asm.lea_reg_rip(2, handler);
    asm.call_import(0);
    asm.mov_ecx_imm(0);
    asm.mov_edx_imm(0);
    asm.lea_reg_rip(8, thread);
    asm.lea_reg_rip(9, result);
    asm.mov_rspoff_imm32(0x20, 0);
    asm.mov_rspoff_imm32(0x28, 0);
    asm.mov_rspoff_imm32(0x2c, 0);
    asm.call_import(1);
    asm.mov_rspoff_rax(0x40);
    asm.mov_rcx_rax();
    asm.mov_edx_imm(5000);
    asm.call_import(2);
    asm.mov_eax_mem_rip(result);
    asm.mov_rcx_rax();
    asm.call_import(3);
    let output = run_guest(
        &build(
            asm,
            &[
                ("KERNEL32.dll", "AddVectoredExceptionHandler"),
                ("KERNEL32.dll", "CreateThread"),
                ("KERNEL32.dll", "WaitForSingleObject"),
                ("KERNEL32.dll", "ExitProcess"),
            ],
        ),
        true,
        false,
    );
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn image_headers_are_read_only_and_nonexecutable_sections_cannot_run() {
    let mut asm = Asm::new();
    asm.mov_rax_imm64(winrun::pe::builder::IMAGE_BASE);
    asm.emit(&[0xc6, 0x00, 0x7b]); // write to read-only DOS header
    asm.xor_eax();
    asm.ret();
    let output = run_guest(&build(asm, &[]), true, false);
    assert_eq!(
        output.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut asm = Asm::new();
    asm.xor_eax();
    asm.ret();
    let mut image = build(asm, &[]);
    let pe = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
    let section = pe + 24 + 0xf0;
    image[section + 36..section + 40].copy_from_slice(&0xc0000040u32.to_le_bytes());
    let output = run_guest(&image, true, false);
    assert_eq!(
        output.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_redirected_missing_import(strict: bool) {
    use std::io::Write;
    let path = std::env::temp_dir().join(format!(
        "winrun-hidden-shim-{}-{strict}.exe",
        std::process::id()
    ));
    std::fs::write(&path, winrun::pe::builder::unknown_import()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_winrun"));
    if strict {
        command.env("WINRUN_NATIVE_STRICT_IMPORTS", "1");
    }
    let mut child = command
        .arg("shell")
        .env_remove("WINRUN_NATIVE_DIAGNOSTIC")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let script = format!("New-Item C:\\probe -ItemType Directory\n@seed \"{}\" C:\\probe\\missing.exe\ncmd /c cmd /c C:\\probe\\missing.exe >NUL 2>&1\nexit\n", path.display());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    std::fs::remove_file(path).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("unsupported native import"), "{stdout}");
    assert!(stderr.contains("C:\\probe\\missing.exe"), "{stderr}");
    assert_eq!(
        stderr.matches("KERNEL32.dll!NoSuchApiForTest").count(),
        1,
        "{stderr}"
    );
}

#[test]
fn missing_shim_errors_survive_nested_cmd_output_redirection() {
    run_redirected_missing_import(false);
}
#[test]
fn strict_import_errors_survive_nested_cmd_output_redirection() {
    run_redirected_missing_import(true);
}
#[test]
fn worker_setup_errors_fall_back_to_stderr_without_a_valid_channel() {
    for channel in [None, Some("not-a-descriptor"), Some("-1"), Some("999999")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_winrun"));
        command
            .args(["__native-worker", "/no-such-winrun-worker-request.json"])
            .env_remove("WINRUN_NATIVE_ERROR_FD");
        if let Some(channel) = channel {
            command.env("WINRUN_NATIVE_ERROR_FD", channel);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(127));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.matches("native worker failed:").count(),
            1,
            "{stderr}"
        );
        assert!(
            stderr.contains("cannot read native worker request"),
            "{stderr}"
        );
    }
}
