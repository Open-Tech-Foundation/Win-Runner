//! Fallback API for hosts without a native PE execution backend.

use super::PeImage;

pub(super) fn supports_import(_: &str, _: &str) -> bool {
    false
}

pub(super) fn run_import_free(_: &PeImage) -> Result<u32, String> {
    Err("native backend is available only on Linux x86_64".to_string())
}

pub(super) fn run_rust_baseline_argv_with_fs_recoverable(
    _: &PeImage,
    fs: crate::winfs::WinFs,
    _: &str,
    _: &[String],
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), super::NativeExecutionFailure> {
    Err(super::NativeExecutionFailure {
        message: "native backend is available only on Linux x86_64".to_string(),
        fs,
    })
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming_channels_recoverable(
    _: &PeImage,
    fs: crate::winfs::WinFs,
    _: &str,
    _: &[String],
    _: &dyn Fn(bool, &[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), super::NativeExecutionFailure> {
    Err(super::NativeExecutionFailure {
        message: "native backend is available only on Linux x86_64".to_string(),
        fs,
    })
}

pub(super) fn run_rust_baseline_argv_with_fs_environment_recoverable(
    _: &PeImage,
    fs: crate::winfs::WinFs,
    _: &str,
    _: &[String],
    _: &[(String, String)],
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), super::NativeExecutionFailure> {
    Err(super::NativeExecutionFailure {
        message: "native backend is available only on Linux x86_64".to_string(),
        fs,
    })
}

pub(super) fn run_rust_baseline_argv(
    _: &PeImage,
    _: &str,
    _: &[String],
) -> Result<(u32, Vec<u8>), String> {
    Err("native backend is available only on Linux x86_64".to_string())
}

pub(super) fn run_rust_baseline_argv_with_fs(
    _: &PeImage,
    _: crate::winfs::WinFs,
    _: &str,
    _: &[String],
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), String> {
    Err("native backend is available only on Linux x86_64".to_string())
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming(
    _: &PeImage,
    _: crate::winfs::WinFs,
    _: &str,
    _: &[String],
    _: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), String> {
    Err("native backend is available only on Linux x86_64".to_string())
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming_recoverable(
    _: &PeImage,
    fs: crate::winfs::WinFs,
    _: &str,
    _: &[String],
    _: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), super::NativeExecutionFailure> {
    Err(super::NativeExecutionFailure {
        message: "native backend is available only on Linux x86_64".to_string(),
        fs,
    })
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming_environment_recoverable(
    _: &PeImage,
    fs: crate::winfs::WinFs,
    _: &str,
    _: &[String],
    _: &[(String, String)],
    _: &dyn Fn(&[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), super::NativeExecutionFailure> {
    Err(super::NativeExecutionFailure {
        message: "native backend is available only on Linux x86_64".to_string(),
        fs,
    })
}

pub(super) fn run_rust_baseline_argv_with_fs_streaming_channels_environment_recoverable(
    _: &PeImage,
    fs: crate::winfs::WinFs,
    _: &str,
    _: &[String],
    _: &[(String, String)],
    _: &dyn Fn(bool, &[u8]),
) -> Result<(u32, Vec<u8>, crate::winfs::WinFs), super::NativeExecutionFailure> {
    Err(super::NativeExecutionFailure {
        message: "native backend is available only on Linux x86_64".to_string(),
        fs,
    })
}
