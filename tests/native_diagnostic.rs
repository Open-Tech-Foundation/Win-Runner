use std::process::Command;
use wincli::pe::builder::{build, Asm};

fn run_guest(bytes: &[u8], diagnostic: bool, strict: bool) -> std::process::Output {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "wincli-native-diag-{}-{}.exe",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, bytes).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_wincli"));
    command.arg(&path);
    if diagnostic {
        command.env("WINCLI_NATIVE_DIAGNOSTIC", "1");
    }
    if strict {
        command.env("WINCLI_NATIVE_STRICT_IMPORTS", "1");
    }
    let output = command.output().unwrap();
    std::fs::remove_file(path).ok();
    output
}

#[test]
fn diagnostic_names_a_called_missing_import_in_native_guest() {
    let output = run_guest(&wincli::pe::builder::unknown_import(), true, false);
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
