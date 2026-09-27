//! Test-artifact generator: builds the committed Windows guest programs in
//! `tests/artifacts/exe/` from the `pe::builder` API, plus the offline
//! package fixtures in `tests/artifacts/packages/` for shell installation.
//!
//! Each `.exe` is a genuine PE32+ x86_64 binary using only the Win32 API
//! surface Win-Runner implements. The `fs_*.exe` guests are self-verifying:
//! they print `PASS` + exit 0 on success, `FAIL` + exit 1 on failure, so
//! `winrun <artifact>` is a fully observable black box (fresh WinFS per run).
//!
//! Regenerate with: `cargo run --example gen_artifacts`

use std::path::PathBuf;
use winrun::pe::builder;

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
        ("demoz.exe", builder::hello("demoz 0.1.0")),
    ];
    for (name, bytes) in &artifacts {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
    }

    // Offline install fixture: package `demo` 0.1.0.
    //
    // NOTE: tests/artifacts/packages/demoz.zip is NOT generated here: it
    // must stay deflated (method 8) to exercise the inflate path, and this
    // repo has no deflate encoder. Rebuild it by hand when builder output
    // changes, e.g.:
    //   python3 -c "import zipfile; \
    //     z = zipfile.ZipFile('tests/artifacts/packages/demoz.zip', 'w', zipfile.ZIP_DEFLATED); \
    //     z.writestr('demoz/deep/demo.exe', open('tests/artifacts/exe/demoz.exe','rb').read())"
    let pkgs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/artifacts/packages");
    std::fs::create_dir_all(&pkgs).unwrap();
    let demo_exe = builder::hello("demo 0.1.0");
    std::fs::write(
        pkgs.join("demo.zip"),
        zip_stored(&[("demo.exe", &demo_exe)]),
    )
    .unwrap();
    std::fs::write(
        pkgs.join("demo.json"),
        "{\"name\":\"demo\",\"version\":\"0.1.0\",\"exe\":\"demo.exe\"}\n",
    )
    .unwrap();
    println!("wrote {} (package fixture)", pkgs.display());
}

/// Minimal stored-zip writer (single-purpose fixture use).
fn zip_stored(files: &[(&str, &[u8])]) -> Vec<u8> {
    fn u16le(v: u16, out: &mut Vec<u8>) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn u32le(v: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let off = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        u16le(20, &mut out);
        u16le(0, &mut out);
        u16le(0, &mut out); // stored
        u16le(0, &mut out);
        u16le(0, &mut out);
        u32le(crc32(data), &mut out);
        u32le(data.len() as u32, &mut out);
        u32le(data.len() as u32, &mut out);
        u16le(name.len() as u16, &mut out);
        u16le(0, &mut out);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(b"PK\x01\x02");
        u16le(20, &mut central);
        u16le(20, &mut central);
        for _ in 0..4 {
            u16le(0, &mut central); // flags, method=stored, time, date
        }
        u32le(crc32(data), &mut central);
        u32le(data.len() as u32, &mut central);
        u32le(data.len() as u32, &mut central);
        u16le(name.len() as u16, &mut central);
        for _ in 0..4 {
            u16le(0, &mut central);
        }
        u32le(0, &mut central);
        u32le(off, &mut central);
        central.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&central);
    let cd_len = central.len() as u32;
    out.extend_from_slice(b"PK\x05\x06");
    u16le(0, &mut out); // disk number
    u16le(0, &mut out); // central-dir disk
    u16le(files.len() as u16, &mut out); // disk entries
    u16le(files.len() as u16, &mut out); // total entries
    u32le(cd_len, &mut out);
    u32le(cd_off, &mut out);
    u16le(0, &mut out); // comment length
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
