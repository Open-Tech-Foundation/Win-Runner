//! Native x86-64 PE execution backend.
//!
//! This is deliberately a small first step toward a Wine-style execution
//! path.  On an x86-64 Linux host, instructions in a PE32+ image do not need
//! interpretation: they can run directly on the processor once the image is
//! mapped at its preferred base.  What still needs building is the Windows
//! personality around that code (DLL loading, import trampolines, TEB/PEB,
//! exceptions, threads, and isolation).
//!
//! CLI guests execute in a freshly exec'd worker process; the library API can
//! also run a forked child when no worker executable is configured. Neither is
//! a security sandbox: guest code can issue host syscalls with Win-Runner's
//! privileges. Windows APIs require explicit native trampolines; unsupported
//! imports fail if guest code calls them. Strict pre-entry validation is optional.

use crate::pe::PeImage;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod worker;

const COMMAND_LINE_BYTES: usize = 0x10000;

pub struct NativeExecutionFailure {
    pub message: String,
    pub fs: crate::winfs::WinFs,
}

fn quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg.chars().any(|ch| matches!(ch, ' ' | '\t' | '"' | '\n')) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat('\\').take(backslashes));
                backslashes = 0;
                out.push(ch);
            }
        }
    }
    out.extend(std::iter::repeat('\\').take(backslashes * 2));
    out.push('"');
    out
}

/// Execute the private request used by the exec-based native worker process.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn execute_worker_request(path: &std::path::Path) -> Result<u32, String> {
    worker::execute_request(path)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn execute_worker_request(_path: &std::path::Path) -> Result<u32, String> {
    Err("exec-based native workers are supported only on Linux x86-64".to_string())
}

/// Configure the result channel for the private Linux worker process.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn set_worker_result_fd(fd: i32) {
    platform_backend::set_worker_result_fd(fd);
}

/// Receive inherited Unix descriptors for a Linux native worker.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn receive_worker_pipe_descriptors(
    socket_path: &str,
    expected: usize,
) -> Result<Vec<i32>, String> {
    platform_backend::receive_worker_pipe_descriptors(socket_path, expected)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn set_worker_result_fd(_fd: i32) {}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn receive_worker_pipe_descriptors(
    _socket_path: &str,
    _expected: usize,
) -> Result<Vec<i32>, String> {
    Err("worker pipe descriptor transfer is supported only on Linux x86-64".to_string())
}

/// True when this build can execute the initial native backend.
pub const AVAILABLE: bool = cfg!(all(target_os = "linux", target_arch = "x86_64"));

/// Whether this host backend can bind a PE import without a fallback thunk.
pub fn supports_import(dll: &str, func: &str) -> bool {
    platform_backend::supports_import(dll, func)
}

/// Run an import-free PE entry point directly on the host CPU.
///
/// This is unsuitable for arbitrary or untrusted binaries: native guest code
/// runs in the current process until the planned child-process sandbox exists.
/// It is exposed now for bring-up fixtures and backend development only.
pub fn run_import_free(img: &PeImage) -> Result<u32, String> {
    platform_backend::run_import_free(img)
}

/// Run a PE guest in a child process and capture its stdout.
pub fn run_rust_baseline(img: &PeImage) -> Result<(u32, Vec<u8>), String> {
    run_rust_baseline_argv(img, "<exe>", &[])
}

/// Same as [`run_rust_baseline`], with the Windows command line supplied to
/// guests importing `GetCommandLineW`.
pub fn run_rust_baseline_argv(
    img: &PeImage,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>), String> {
    platform_backend::run_rust_baseline_argv(img, prog, args)
}

/// Run a native guest against an existing isolated instance filesystem and
/// return the child-committed filesystem with its exit status and console
/// output. The guest still executes in a forked child; state crosses that
/// boundary as a validated in-memory snapshot, never through a host mount.
pub fn run_rust_baseline_argv_with_fs(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), String> {
    run_rust_baseline_argv_with_fs_recoverable(img, fs, prog, args)
        .map_err(|failure| failure.message)
}

/// Like [`run_rust_baseline_argv_with_fs`], preserving the starting disk when
/// the child cannot commit its filesystem journal.
pub fn run_rust_baseline_argv_with_fs_recoverable(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), NativeExecutionFailure> {
    platform_backend::run_rust_baseline_argv_with_fs_recoverable(img, fs, prog, args)
}

pub fn run_rust_baseline_argv_with_fs_environment_recoverable(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), NativeExecutionFailure> {
    platform_backend::run_rust_baseline_argv_with_fs_environment_recoverable(
        img,
        fs,
        prog,
        args,
        environment,
    )
}

/// As [`run_rust_baseline_argv_with_fs`], forwarding stdout chunks while the
/// isolated native child is still running.
pub fn run_rust_baseline_argv_with_fs_streaming(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), String> {
    platform_backend::run_rust_baseline_argv_with_fs_streaming(img, fs, prog, args, output)
}

pub fn run_rust_baseline_argv_with_fs_streaming_recoverable(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), NativeExecutionFailure> {
    platform_backend::run_rust_baseline_argv_with_fs_streaming_recoverable(
        img, fs, prog, args, output,
    )
}

pub fn run_rust_baseline_argv_with_fs_streaming_channels_recoverable(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
    output: &dyn Fn(bool, &[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), NativeExecutionFailure> {
    platform_backend::run_rust_baseline_argv_with_fs_streaming_channels_recoverable(
        img, fs, prog, args, output,
    )
}

pub fn run_rust_baseline_argv_with_fs_streaming_environment_recoverable(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
    output: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), NativeExecutionFailure> {
    platform_backend::run_rust_baseline_argv_with_fs_streaming_environment_recoverable(
        img,
        fs,
        prog,
        args,
        environment,
        output,
    )
}

pub fn run_rust_baseline_argv_with_fs_streaming_channels_environment_recoverable(
    img: &PeImage,
    fs: crate::winfs::WinFs,
    prog: &str,
    args: &[String],
    environment: &[(String, String)],
    output: &dyn Fn(bool, &[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), NativeExecutionFailure> {
    platform_backend::run_rust_baseline_argv_with_fs_streaming_channels_environment_recoverable(
        img,
        fs,
        prog,
        args,
        environment,
        output,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "native/linux_x86_64.rs"]
mod linux_x86_64;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[path = "native/unsupported.rs"]
mod unsupported;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use linux_x86_64 as platform_backend;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
use unsupported as platform_backend;

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::pe::{
        builder::{build, Asm},
        load,
    };
    use crate::winfs::WinFs;

    #[test]
    fn handle_information_accepts_winsock_socket_handles() {
        assert!(super::platform_backend::test_socket_handle_inheritability());
    }

    #[test]
    fn executes_an_import_free_pe_at_native_speed() {
        let mut asm = Asm::new();
        asm.mov_r32_imm(0, 37);
        asm.ret();
        let img = load(&build(asm, &[])).expect("fixture PE loads");
        assert_eq!(run_import_free(&img).expect("native PE runs"), 37);
    }

    #[test]
    fn import_free_entry_rejects_imported_images() {
        let mut asm = Asm::new();
        asm.ret();
        let img = load(&build(asm, &[("KERNEL32.DLL", "ExitProcess")])).expect("fixture PE loads");
        let err = run_import_free(&img).expect_err("imports need shims");
        assert!(err.contains("cannot bind PE imports"));
    }

    #[test]
    fn executes_the_checked_in_rust_hello_guest_with_native_trampolines() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_hello.exe"
        );
        let bytes = std::fs::read(path).expect("checked-in guest exists");
        let img = load(&bytes).expect("rust hello loads");
        assert!(
            !img.relocations.is_empty(),
            "native child images are relocatable"
        );
        let (code, out) = run_rust_baseline(&img).expect("native rust hello runs");
        assert_eq!(code, 0);
        assert_eq!(out, b"Hello from Rust");
    }

    #[test]
    fn forwards_native_child_stdout_chunks() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_hello.exe"
        );
        let img = load(&std::fs::read(path).unwrap()).unwrap();
        let output = std::sync::Mutex::new(Vec::new());
        let (code, returned, _) = run_rust_baseline_argv_with_fs_streaming(
            &img,
            WinFs::ephemeral_runner(),
            "hello.exe",
            &[],
            &|chunk| output.lock().unwrap().extend_from_slice(chunk),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(returned, b"Hello from Rust");
        assert_eq!(*output.lock().unwrap(), b"Hello from Rust");
    }

    #[test]
    fn executes_the_checked_in_rust_argv_guest_with_native_trampolines() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_argv.exe"
        );
        let bytes = std::fs::read(path).expect("checked-in guest exists");
        let img = load(&bytes).expect("rust argv loads");
        let args = [
            "hello".to_string(),
            "a b".to_string(),
            "--version".to_string(),
        ];
        let (code, out) =
            run_rust_baseline_argv(&img, "myprog.exe", &args).expect("native rust argv runs");
        assert_eq!(code, 0);
        assert_eq!(out, b"myprog.exe hello \"a b\" --version\n");
    }

    #[test]
    fn native_guest_commits_filesystem_state_across_child_boundary() {
        let writer = load(&crate::pe::builder::write_file(
            r"C:\work\state.txt",
            b"native",
        ))
        .expect("writer loads");
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\work").unwrap();
        let (code, _, fs) = run_rust_baseline_argv_with_fs(&writer, fs, "writer.exe", &[])
            .expect("native writer runs");
        assert_eq!(code, 0);
        assert_eq!(fs.read_file(r"C:\work\state.txt").unwrap(), b"native");

        let reader = load(&crate::pe::builder::read_file_to_stdout(
            r"C:\work\state.txt",
        ))
        .expect("reader loads");
        let (code, out, _) = run_rust_baseline_argv_with_fs(&reader, fs, "reader.exe", &[])
            .expect("native reader runs");
        assert_eq!(code, 0);
        assert_eq!(out, b"native");
    }

    #[test]
    fn native_guest_reads_only_a_seeked_file_range() {
        // Exercise repeated seek/read operations, including requests that
        // reach or pass EOF.
        for (offset, length, expected) in [
            (0, 10, &b"0123456789"[..]),
            (4, 3, &b"456"[..]),
            (8, 5, &b"89"[..]),
            (10, 1, &b""[..]),
        ] {
            let reader = load(&crate::pe::builder::read_file_range_to_stdout(
                r"C:\work\range.txt",
                offset,
                length,
            ))
            .expect("seek reader loads");
            let mut fs = WinFs::ephemeral_runner();
            fs.mkdir(r"C:\work").unwrap();
            fs.write_file(r"C:\work\range.txt", b"0123456789".to_vec())
                .unwrap();
            let (code, output, _) =
                run_rust_baseline_argv_with_fs(&reader, fs, "seek-reader.exe", &[])
                    .expect("seek reader runs");
            assert_eq!(code, 0, "offset={offset}, length={length}");
            assert_eq!(output, expected, "offset={offset}, length={length}");
        }
    }
}
