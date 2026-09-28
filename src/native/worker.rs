//! Request protocol for clean, exec-based Linux native guest workers.

use crate::pe::{Import, PeImage, TlsDir};
use std::path::{Path, PathBuf};

pub(crate) fn write_image(image: &PeImage, directory: &Path) -> Result<PathBuf, String> {
    let image_path = directory.join("image.bin");
    std::fs::write(&image_path, &image.image)
        .map_err(|error| format!("cannot write native worker image: {error}"))?;
    let imports = |values: &[Import]| {
        values
            .iter()
            .map(|import| {
                serde_json::json!({
                    "iat_rva": import.iat_rva,
                    "dll": import.dll,
                    "func": import.func,
                })
            })
            .collect::<Vec<_>>()
    };
    let tls = image.tls.as_ref().map(|tls| {
        serde_json::json!({
            "raw_data": tls.raw_data,
            "raw_data_rva": tls.raw_data_rva,
            "zero_fill": tls.zero_fill,
            "index_rva": tls.index_rva,
            "callbacks": tls.callbacks,
        })
    });
    let metadata = serde_json::json!({
        "is_dll": image.is_dll,
        "image_base": image.image_base,
        "entry_rva": image.entry_rva,
        "size_of_image": image.size_of_image,
        "imports": imports(&image.imports),
        "unsupported": imports(&image.unsupported),
        "tls": tls,
        "code_ranges": image.code_ranges,
        "relocations": image.relocations,
    });
    let bytes = serde_json::to_vec(&metadata)
        .map_err(|error| format!("cannot encode native worker image metadata: {error}"))?;
    std::fs::write(directory.join("image.json"), bytes)
        .map_err(|error| format!("cannot write native worker image metadata: {error}"))?;
    Ok(image_path)
}

pub(crate) fn read_image(directory: &Path) -> Result<PeImage, String> {
    let metadata: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.join("image.json"))
            .map_err(|error| format!("cannot read native worker image metadata: {error}"))?,
    )
    .map_err(|error| format!("invalid native worker image metadata: {error}"))?;
    fn number(value: &serde_json::Value, key: &str) -> Result<u64, String> {
        value
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("invalid native worker image field {key}"))
    }
    let code_ranges = metadata["code_ranges"]
        .as_array()
        .ok_or("invalid native worker code ranges")?
        .iter()
        .map(|range| {
            Ok::<_, String>((
                range[0].as_u64().ok_or("invalid code range start")?,
                range[1].as_u64().ok_or("invalid code range end")?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let relocations = metadata["relocations"]
        .as_array()
        .ok_or("invalid native worker relocations")?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .map(|value| value as u32)
                .ok_or("invalid relocation RVA")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let imports = |key: &str| -> Result<Vec<Import>, String> {
        let values = metadata
            .get(key)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("native worker image is missing {key}"))?;
        values
            .iter()
            .map(|value| {
                Ok(Import {
                    iat_rva: value["iat_rva"].as_u64().ok_or("invalid import IAT RVA")? as u32,
                    dll: value["dll"]
                        .as_str()
                        .ok_or("invalid import DLL")?
                        .to_owned(),
                    func: value["func"]
                        .as_str()
                        .ok_or("invalid import function")?
                        .to_owned(),
                })
            })
            .collect()
    };
    let tls = metadata
        .get("tls")
        .filter(|value| !value.is_null())
        .map(|value| {
            Ok::<_, String>(TlsDir {
                raw_data: serde_json::from_value(value["raw_data"].clone())
                    .map_err(|error| format!("invalid native worker TLS bytes: {error}"))?,
                raw_data_rva: value["raw_data_rva"]
                    .as_u64()
                    .ok_or("invalid TLS data RVA")? as u32,
                zero_fill: value["zero_fill"].as_u64().ok_or("invalid TLS zero-fill")? as u32,
                index_rva: value["index_rva"].as_u64().ok_or("invalid TLS index RVA")? as u32,
                callbacks: serde_json::from_value(value["callbacks"].clone())
                    .map_err(|error| format!("invalid native worker TLS callbacks: {error}"))?,
            })
        })
        .transpose()?;
    Ok(PeImage {
        is_dll: metadata["is_dll"].as_bool().unwrap_or(false),
        image_base: number(&metadata, "image_base")?,
        entry_rva: number(&metadata, "entry_rva")? as u32,
        size_of_image: number(&metadata, "size_of_image")? as u32,
        image: std::fs::read(directory.join("image.bin"))
            .map_err(|error| format!("cannot read native worker image: {error}"))?,
        imports: imports("imports")?,
        exports: vec![],
        unsupported: imports("unsupported")?,
        tls,
        code_ranges,
        relocations,
    })
}

pub(crate) fn execute_request(path: &Path) -> Result<u32, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read native worker request: {error}"))?;
    let request: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid native worker request: {error}"))?;
    if let Some(handles) = request
        .get("socket_handles_to_close")
        .and_then(serde_json::Value::as_array)
    {
        for handle in handles {
            let handle = handle
                .as_i64()
                .ok_or("worker request has an invalid socket handle to close")?;
            if handle > 2 && handle <= i32::MAX as i64 {
                unsafe { libc::close(handle as i32) };
            }
        }
    }
    let descriptor_count = match request.get("pipe_transfer_fd_count") {
        None => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| "worker request has invalid descriptor count".to_string())?
            as usize,
    };
    if descriptor_count > 0 {
        let socket_path = request
            .get("pipe_transfer_socket")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "worker request has no descriptor transfer socket".to_string())?;
        let descriptors =
            crate::native::receive_worker_pipe_descriptors(socket_path, descriptor_count)?;
        std::env::set_var(
            "WINRUN_NATIVE_PIPE_FDS",
            descriptors
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    } else {
        std::env::remove_var("WINRUN_NATIVE_PIPE_FDS");
    }
    let text = |key: &str| -> Result<String, String> {
        request
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("native worker request is missing {key}"))
    };
    let directory = path
        .parent()
        .ok_or_else(|| "native worker request has no directory".to_string())?;
    let mut fs = crate::snapshot::load_worker_manifest(Path::new(&text("snapshot_path")?))?;
    let mounts: Vec<(char, PathBuf, bool)> = serde_json::from_value(
        request
            .get("mounts")
            .cloned()
            .ok_or_else(|| "native worker request is missing mounts".to_string())?,
    )
    .map_err(|error| format!("invalid native worker mounts: {error}"))?;
    for (drive, host_path, read_only) in mounts {
        fs.mount_host_dir(drive, &host_path, read_only)?;
    }
    let drive_cwds: Vec<(char, String)> = serde_json::from_value(
        request
            .get("drive_cwds")
            .cloned()
            .ok_or_else(|| "native worker request is missing drive_cwds".to_string())?,
    )
    .map_err(|error| format!("invalid native worker drive directories: {error}"))?;
    for (_, cwd) in drive_cwds {
        fs.set_cwd(&cwd)?;
    }
    fs.set_cwd(&text("cwd")?)?;
    fs.clear_changes();
    let args: Vec<String> = serde_json::from_value(
        request
            .get("args")
            .cloned()
            .ok_or_else(|| "native worker request is missing args".to_string())?,
    )
    .map_err(|error| format!("invalid native worker arguments: {error}"))?;
    let environment: Vec<(String, String)> = serde_json::from_value(
        request
            .get("environment")
            .cloned()
            .ok_or_else(|| "native worker request is missing environment".to_string())?,
    )
    .map_err(|error| format!("invalid native worker environment: {error}"))?;
    let process_id = request
        .get("process_id")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    let parent_process_id = request
        .get("parent_process_id")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let image = read_image(directory)?;
    let state_path = text("state_path")?;
    let state_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(state_path)
        .map_err(|error| format!("cannot create native worker state journal: {error}"))?;
    let result_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(text("result_path")?)
        .map_err(|error| format!("cannot create native worker result file: {error}"))?;
    use std::os::fd::IntoRawFd;
    let result_fd = result_file.into_raw_fd();
    crate::native::set_worker_result_fd(result_fd);
    std::env::set_var("WINRUN_NATIVE_WORKER", "1");
    if request.get("native_fs").is_some() {
        std::env::set_var("WINRUN_NATIVE_REQUEST_PATH", path);
    } else {
        std::env::remove_var("WINRUN_NATIVE_REQUEST_PATH");
    }
    std::env::set_var("WINRUN_NATIVE_PROCESS_ID", process_id.to_string());
    std::env::set_var(
        "WINRUN_NATIVE_PARENT_PROCESS_ID",
        parent_process_id.to_string(),
    );
    if let Some(std_handles) = request.get("std_handles") {
        let std_handles: [u64; 3] = serde_json::from_value(std_handles.clone())
            .map_err(|error| format!("invalid native worker standard handles: {error}"))?;
        std::env::set_var(
            "WINRUN_NATIVE_STD_HANDLES",
            serde_json::to_string(&std_handles)
                .map_err(|error| format!("cannot encode worker standard handles: {error}"))?,
        );
    } else {
        std::env::remove_var("WINRUN_NATIVE_STD_HANDLES");
    }
    std::env::set_var(
        "WINRUN_NATIVE_STATE_FD",
        state_file.into_raw_fd().to_string(),
    );
    let program = text("program")?;
    let (code, _, _) = crate::native::run_rust_baseline_argv_with_fs_environment_recoverable(
        &image,
        fs,
        &program,
        &args,
        &environment,
    )
    .map_err(|failure| failure.message)?;
    if result_fd >= 0 {
        let bytes = code.to_le_bytes();
        unsafe { libc::write(result_fd, bytes.as_ptr().cast(), bytes.len()) };
    }
    Ok(code)
}
