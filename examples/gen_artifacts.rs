//! Test-artifact generator: builds the committed Windows guest programs in
//! `tests/artifacts/exe/` from the `pe::builder` API.
//!
//! Each `.exe` is a genuine PE32+ x86_64 binary using only the Win32 API
//! surface WinCLI implements. The `fs_*.exe` guests are self-verifying:
//! they print `PASS` + exit 0 on success, `FAIL` + exit 1 on failure, so
//! `wincli <artifact>` is a fully observable black box (fresh WinFS per run).
//!
//! Regenerate with: `cargo run --example gen_artifacts`

use std::path::PathBuf;
use wincli::pe::builder;

fn out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/artifacts/exe")
}

fn main() {
    let dir = out_dir();
    std::fs::create_dir_all(&dir).unwrap();
    // (file name, bytes)
    let artifacts: Vec<(&str, Vec<u8>)> = vec![
        ("hello.exe", builder::hello("Hello from Windows")),
        ("exit42.exe", builder::exit_code(42)),
        (
            "fs_file.exe",
            builder::fs_selftest_file("C:\\st_file.txt", b"selftest-bytes-42"),
        ),
        ("fs_dir.exe", builder::dir_selftest("C:\\st_dir")),
        (
            "fs_move.exe",
            builder::move_copy_selftest(
                "C:\\mv_a.txt",
                "C:\\mv_b.txt",
                "C:\\mv_c.txt",
                b"moved-bytes",
            ),
        ),
        ("bad_import.exe", builder::unknown_import()),
    ];
    for (name, bytes) in &artifacts {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
    }
}
