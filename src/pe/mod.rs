//! Minimal PE32+ (x86_64) loader: parse + validate, extract imports.
//! Execution lives in `emu`; Win32 shims live in `winapi`.

pub mod builder;
pub mod emu;

#[derive(Debug, Clone)]
pub struct Import {
    /// RVA of the IAT slot that will hold the resolved address
    pub iat_rva: u32,
    pub dll: String,
    pub func: String,
}

#[derive(Debug, Clone)]
pub struct PeImage {
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    /// Raw image bytes sized `size_of_image`, with sections copied to their VAs.
    /// `image[rva] == byte at image_base + rva`.
    pub image: Vec<u8>,
    pub imports: Vec<Import>,
    /// Loadable fail-stubs (`STUB_APIS`): resolved like imports, but calling
    /// one fails clearly with LastError=120. Never silently succeeds.
    pub stubs: Vec<Import>,
    /// Imports outside `SUPPORTED_APIS`. Always empty from `load` (strict);
    /// populated by `load_lenient` for `inspect`. Never executable.
    pub unsupported: Vec<Import>,
    /// Thread-local storage template (TLS directory), if present.
    pub tls: Option<TlsDir>,
    /// (iat_rva -> import index)
    pub iat_slots: Vec<u32>,
}

/// Thread-local storage directory (IMAGE_TLS_DIRECTORY64, RVAs).
#[derive(Debug, Clone)]
pub struct TlsDir {
    /// Template bytes (raw data) to copy into each thread's TLS block.
    pub raw_data: Vec<u8>,
    /// Extra zero bytes after the template.
    pub zero_fill: u32,
    /// RVA of the slot-index DWORD (loader writes the assigned index).
    pub index_rva: u32,
    /// Callback RVAs (must be empty: callbacks are not supported).
    pub callbacks: Vec<u32>,
}

/// APIs WinCLI implements. Anything else must fail clearly.
pub const SUPPORTED_APIS: &[(&str, &str)] = &[
    ("KERNEL32.DLL", "ExitProcess"),
    ("KERNEL32.DLL", "GetStdHandle"),
    ("KERNEL32.DLL", "WriteFile"),
    ("KERNEL32.DLL", "CreateFileW"),
    ("KERNEL32.DLL", "ReadFile"),
    ("KERNEL32.DLL", "CloseHandle"),
    ("KERNEL32.DLL", "CreateDirectoryW"),
    ("KERNEL32.DLL", "RemoveDirectoryW"),
    ("KERNEL32.DLL", "DeleteFileW"),
    ("KERNEL32.DLL", "MoveFileW"),
    ("KERNEL32.DLL", "CopyFileW"),
    ("KERNEL32.DLL", "GetCommandLineW"),
    ("KERNEL32.DLL", "GetCommandLineA"),
    ("KERNEL32.DLL", "GetConsoleMode"),
    ("KERNEL32.DLL", "SetConsoleMode"),
    ("KERNEL32.DLL", "WriteConsoleW"),
    ("KERNEL32.DLL", "GetConsoleOutputCP"),
    ("KERNEL32.DLL", "SetConsoleTextAttribute"),
    ("KERNEL32.DLL", "ReadConsoleW"),
    ("KERNEL32.DLL", "GetLastError"),
    ("KERNEL32.DLL", "SetLastError"),
    ("KERNEL32.DLL", "GetProcessHeap"),
    ("KERNEL32.DLL", "HeapAlloc"),
    ("KERNEL32.DLL", "HeapFree"),
    ("KERNEL32.DLL", "HeapReAlloc"),
    ("KERNEL32.DLL", "HeapSize"),
    ("KERNEL32.DLL", "VirtualAlloc"),
    ("KERNEL32.DLL", "VirtualFree"),
    ("KERNEL32.DLL", "VirtualProtect"),
    ("KERNEL32.DLL", "GetEnvironmentStringsW"),
    ("KERNEL32.DLL", "FreeEnvironmentStringsW"),
    ("KERNEL32.DLL", "GetEnvironmentVariableW"),
    ("KERNEL32.DLL", "SetEnvironmentVariableW"),
    ("KERNEL32.DLL", "GetStartupInfoW"),
    ("KERNEL32.DLL", "GetModuleHandleW"),
    ("KERNEL32.DLL", "GetModuleHandleA"),
    ("KERNEL32.DLL", "GetModuleHandleExW"),
    ("KERNEL32.DLL", "GetModuleFileNameW"),
    ("KERNEL32.DLL", "GetSystemInfo"),
    ("KERNEL32.DLL", "GetSystemTimeAsFileTime"),
    ("KERNEL32.DLL", "QueryPerformanceCounter"),
    ("KERNEL32.DLL", "QueryPerformanceFrequency"),
    ("KERNEL32.DLL", "GetCurrentProcess"),
    ("KERNEL32.DLL", "GetCurrentThread"),
    ("KERNEL32.DLL", "GetCurrentProcessId"),
    ("KERNEL32.DLL", "GetCurrentThreadId"),
    ("KERNEL32.DLL", "GetFileType"),
    ("KERNEL32.DLL", "GetCurrentDirectoryW"),
    ("KERNEL32.DLL", "GetFullPathNameW"),
    ("KERNEL32.DLL", "GetFileAttributesW"),
    ("KERNEL32.DLL", "MultiByteToWideChar"),
    ("KERNEL32.DLL", "WideCharToMultiByte"),
    ("KERNEL32.DLL", "GetACP"),
    ("KERNEL32.DLL", "GetOEMCP"),
    ("KERNEL32.DLL", "IsValidCodePage"),
    ("KERNEL32.DLL", "IsDebuggerPresent"),
    ("KERNEL32.DLL", "IsProcessorFeaturePresent"),
    ("KERNEL32.DLL", "lstrlenW"),
    ("KERNEL32.DLL", "EncodePointer"),
    ("KERNEL32.DLL", "Sleep"),
    ("KERNEL32.DLL", "SleepEx"),
    ("KERNEL32.DLL", "SwitchToThread"),
    ("KERNEL32.DLL", "TerminateProcess"),
    ("KERNEL32.DLL", "FlsAlloc"),
    ("KERNEL32.DLL", "FlsFree"),
    ("KERNEL32.DLL", "FlsGetValue"),
    ("KERNEL32.DLL", "FlsSetValue"),
    ("KERNEL32.DLL", "InitializeCriticalSectionEx"),
    ("KERNEL32.DLL", "EnterCriticalSection"),
    ("KERNEL32.DLL", "LeaveCriticalSection"),
    ("KERNEL32.DLL", "DeleteCriticalSection"),
    ("KERNEL32.DLL", "InitializeSListHead"),
    ("BCRYPTPRIMITIVES.DLL", "ProcessPrng"),
];

/// Loadable-but-unimplemented APIs: the loader resolves them so real
/// binaries start, but calling one fails clearly with
/// `LastError=ERROR_CALL_NOT_IMPLEMENTED (120)`. Never silent success.
/// Converted to real implementations on demand (execution traces decide).
pub const STUB_APIS: &[(&str, &str)] = &[
    ("API-MS-WIN-CORE-SYNCH-L1-2-0.DLL", "WaitOnAddress"),
    ("API-MS-WIN-CORE-SYNCH-L1-2-0.DLL", "WakeByAddressAll"),
    ("API-MS-WIN-CORE-SYNCH-L1-2-0.DLL", "WakeByAddressSingle"),
    ("NTDLL.DLL", "NtCreateNamedPipeFile"),
    ("NTDLL.DLL", "NtOpenFile"),
    ("NTDLL.DLL", "NtReadFile"),
    ("NTDLL.DLL", "NtWriteFile"),
    ("NTDLL.DLL", "RtlNtStatusToDosError"),
    ("USERENV.DLL", "GetUserProfileDirectoryW"),
    ("KERNEL32.DLL", "AddVectoredExceptionHandler"),
    ("KERNEL32.DLL", "CompareStringOrdinal"),
    ("KERNEL32.DLL", "CompareStringW"),
    ("KERNEL32.DLL", "CreateFileMappingW"),
    ("KERNEL32.DLL", "CreateMutexA"),
    ("KERNEL32.DLL", "CreateProcessW"),
    ("KERNEL32.DLL", "CreateThread"),
    ("KERNEL32.DLL", "CreateWaitableTimerExW"),
    ("KERNEL32.DLL", "DuplicateHandle"),
    ("KERNEL32.DLL", "FindClose"),
    ("KERNEL32.DLL", "FindFirstFileExW"),
    ("KERNEL32.DLL", "FindNextFileW"),
    ("KERNEL32.DLL", "FlushFileBuffers"),
    ("KERNEL32.DLL", "FormatMessageW"),
    ("KERNEL32.DLL", "FreeLibrary"),
    ("KERNEL32.DLL", "GetCPInfo"),
    ("KERNEL32.DLL", "GetComputerNameExW"),
    ("KERNEL32.DLL", "GetConsoleScreenBufferInfo"),
    ("KERNEL32.DLL", "GetExitCodeProcess"),
    ("KERNEL32.DLL", "GetFileInformationByHandle"),
    ("KERNEL32.DLL", "GetFileInformationByHandleEx"),
    ("KERNEL32.DLL", "GetFinalPathNameByHandleW"),
    ("KERNEL32.DLL", "GetProcAddress"),
    ("KERNEL32.DLL", "GetStringTypeW"),
    ("KERNEL32.DLL", "GetSystemDirectoryW"),
    ("KERNEL32.DLL", "GetWindowsDirectoryW"),
    ("KERNEL32.DLL", "IsThreadAFiber"),
    ("KERNEL32.DLL", "LCMapStringW"),
    ("KERNEL32.DLL", "LoadLibraryA"),
    ("KERNEL32.DLL", "LoadLibraryExW"),
    ("KERNEL32.DLL", "MapViewOfFile"),
    ("KERNEL32.DLL", "RaiseException"),
    ("KERNEL32.DLL", "ReadFileEx"),
    ("KERNEL32.DLL", "ReleaseMutex"),
    ("KERNEL32.DLL", "RtlCaptureContext"),
    ("KERNEL32.DLL", "RtlLookupFunctionEntry"),
    ("KERNEL32.DLL", "RtlPcToFileHeader"),
    ("KERNEL32.DLL", "RtlUnwindEx"),
    ("KERNEL32.DLL", "RtlVirtualUnwind"),
    ("KERNEL32.DLL", "SetFileInformationByHandle"),
    ("KERNEL32.DLL", "SetFilePointerEx"),
    ("KERNEL32.DLL", "SetFileTime"),
    ("KERNEL32.DLL", "SetStdHandle"),
    ("KERNEL32.DLL", "SetThreadStackGuarantee"),
    ("KERNEL32.DLL", "SetUnhandledExceptionFilter"),
    ("KERNEL32.DLL", "SetWaitableTimer"),
    ("KERNEL32.DLL", "UnhandledExceptionFilter"),
    ("KERNEL32.DLL", "UnmapViewOfFile"),
    ("KERNEL32.DLL", "WaitForSingleObject"),
    ("KERNEL32.DLL", "WaitForSingleObjectEx"),
    ("KERNEL32.DLL", "WriteFileEx"),
];

pub fn is_supported(dll: &str, func: &str) -> bool {
    SUPPORTED_APIS
        .iter()
        .any(|(d, f)| d.eq_ignore_ascii_case(dll) && *f == func)
}

/// True for loadable fail-stubs (see `STUB_APIS`).
pub fn is_stub(dll: &str, func: &str) -> bool {
    STUB_APIS
        .iter()
        .any(|(d, f)| d.eq_ignore_ascii_case(dll) && *f == func)
}

fn u16le(b: &[u8], off: usize) -> Result<u16, String> {
    b.get(off..off + 2)
        .ok_or_else(|| "truncated PE".to_string())
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32le(b: &[u8], off: usize) -> Result<u32, String> {
    b.get(off..off + 4)
        .ok_or_else(|| "truncated PE".to_string())
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64le(b: &[u8], off: usize) -> Result<u64, String> {
    b.get(off..off + 8)
        .ok_or_else(|| "truncated PE".to_string())
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn cstr_ascii(b: &[u8], off: usize) -> Result<String, String> {
    let mut end = off;
    while b.get(end).copied().unwrap_or(0) != 0 {
        end += 1;
        if end - off > 512 {
            return Err("import name too long".to_string());
        }
        if end >= b.len() {
            return Err("truncated import name".to_string());
        }
    }
    std::str::from_utf8(&b[off..end])
        .map(|s| s.to_string())
        .map_err(|_| "invalid import name encoding".to_string())
}

fn rva_to_file_off(sections: &[(u32, u32, u32)], rva: u32) -> Option<usize> {
    for (vaddr, vsize, foff) in sections {
        let size = (*vsize).max(1);
        if rva >= *vaddr && rva < vaddr + size {
            return Some((*foff + (rva - *vaddr)) as usize);
        }
    }
    None
}

pub fn load(data: &[u8]) -> Result<PeImage, String> {
    load_inner(data, true)
}

/// Parse without rejecting unknown imports: they land in
/// [`PeImage::unsupported`] for reporting by `inspect`.
/// The result must not be executed (`Runner::new` refuses it).
pub fn load_lenient(data: &[u8]) -> Result<PeImage, String> {
    load_inner(data, false)
}

fn load_inner(data: &[u8], strict: bool) -> Result<PeImage, String> {
    if data.len() < 0x40 {
        return Err("file too small for DOS header".to_string());
    }
    if &data[0..2] != b"MZ" {
        return Err("not a PE file (missing MZ)".to_string());
    }
    let e_lfanew = u32le(data, 0x3C)? as usize;
    if data.len() < e_lfanew + 6 {
        return Err("truncated PE header".to_string());
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("not a PE file (missing PE signature)".to_string());
    }
    let coff = e_lfanew + 4;
    let machine = u16le(data, coff)?;
    if machine != 0x8664 {
        return Err(format!("unsupported machine 0x{machine:04x}: only x86_64 (0x8664) supported"));
    }
    let num_sections = u16le(data, coff + 2)? as usize;
    let opt_size = u16le(data, coff + 16)? as usize;
    let opt = coff + 20;
    if num_sections == 0 || num_sections > 32 {
        return Err("invalid number of sections".to_string());
    }
    if data.len() < opt + opt_size {
        return Err("truncated optional header".to_string());
    }
    let magic = u16le(data, opt)?;
    if magic != 0x20b {
        return Err("only PE32+ (x86_64) supported, not PE32".to_string());
    }
    let entry_rva = u32le(data, opt + 16)?;
    let image_base = u64le(data, opt + 24)?;
    let section_align = u32le(data, opt + 32)?;
    let file_align = u32le(data, opt + 36)?;
    let size_of_image = u32le(data, opt + 56)?;
    let size_of_headers = u32le(data, opt + 60)?;
    let num_rva_sizes = u32le(data, opt + 108)? as usize;
    if num_rva_sizes < 2 {
        return Err("truncated data directories".to_string());
    }
    let import_rva = u32le(data, opt + 112 + 8)?;
    let import_size = u32le(data, opt + 112 + 12)?;
    // TLS directory is index 9 (optional).
    let (tls_rva, tls_size) = if num_rva_sizes > 9 {
        (
            u32le(data, opt + 112 + 9 * 8)?,
            u32le(data, opt + 112 + 9 * 8 + 4)?,
        )
    } else {
        (0, 0)
    };
    let _ = (section_align, file_align, size_of_headers);

    if size_of_image == 0 || size_of_image > 64 * 1024 * 1024 {
        return Err("invalid SizeOfImage".to_string());
    }

    // Section headers
    let sec_off = opt + opt_size;
    let mut sections: Vec<(u32, u32, u32, u32, u32)> = Vec::new(); // vaddr, vsize, raw_ptr, raw_size
    // (vaddr, vsize, foff, fsize, characteristics)
    struct Sec {
        vaddr: u32,
        vsize: u32,
        foff: u32,
        fsize: u32,
    }
    let mut secs: Vec<Sec> = Vec::new();
    for i in 0..num_sections {
        let o = sec_off + i * 40;
        if data.len() < o + 40 {
            return Err("truncated section headers".to_string());
        }
        let vsize = u32le(data, o + 8)?;
        let vaddr = u32le(data, o + 12)?;
        let fsize = u32le(data, o + 16)?;
        let foff = u32le(data, o + 20)?;
        secs.push(Sec {
            vaddr,
            vsize,
            foff,
            fsize,
        });
        sections.push((vaddr, vsize.max(fsize), foff, fsize, 0));
    }

    // Build loaded image
    let mut image = vec![0u8; size_of_image as usize];
    // headers
    let hdr_copy = (size_of_headers as usize).min(data.len()).min(image.len());
    image[..hdr_copy].copy_from_slice(&data[..hdr_copy]);
    for s in &secs {
        if s.fsize == 0 {
            continue;
        }
        let src_off = s.foff as usize;
        let src_end = src_off + s.fsize as usize;
        if src_end > data.len() {
            return Err("section raw data out of bounds".to_string());
        }
        let dst_off = s.vaddr as usize;
        let dst_end = dst_off + s.fsize as usize;
        if dst_end > image.len() {
            return Err("section virtual address out of bounds".to_string());
        }
        image[dst_off..dst_end].copy_from_slice(&data[src_off..src_end]);
    }

    // Parse imports (from file offsets via RVA->file mapping)
    let mut imports: Vec<Import> = Vec::new();
    let mut stubs: Vec<Import> = Vec::new();
    let mut unsupported: Vec<Import> = Vec::new();
    if import_rva != 0 {
        if import_size == 0 {
            return Err("invalid import directory".to_string());
        }
        let rva_map: Vec<(u32, u32, u32)> = secs
            .iter()
            .map(|s| (s.vaddr, s.vsize.max(s.fsize), s.foff))
            .collect();
        let to_off = |rva: u32| -> Result<usize, String> {
            rva_to_file_off(&rva_map, rva)
                .ok_or_else(|| format!("import RVA out of bounds: 0x{rva:08x}"))
        };
        let mut desc_off = to_off(import_rva)?;
        loop {
            if desc_off + 20 > data.len() {
                return Err("truncated import descriptor".to_string());
            }
            let oft = u32le(data, desc_off)?;
            let _ts = u32le(data, desc_off + 4)?;
            let _fc = u32le(data, desc_off + 8)?;
            let name_rva = u32le(data, desc_off + 12)?;
            let ft = u32le(data, desc_off + 16)?;
            if oft == 0 && name_rva == 0 && ft == 0 {
                break;
            }
            let dll = cstr_ascii(data, to_off(name_rva)?)?;
            let thunk_rva = if oft != 0 { oft } else { ft };
            // walk thunks
            let mut idx = 0u32;
            loop {
                let ent_off = to_off(thunk_rva + idx * 8)?;
                if ent_off + 8 > data.len() {
                    return Err("truncated import thunk".to_string());
                }
                let ent = u64le(data, ent_off)?;
                if ent == 0 {
                    break;
                }
                if ent & 0x8000_0000_0000_0000 != 0 {
                    return Err(format!("ordinal imports not supported: {dll} ordinal {}", ent & 0xffff));
                }
                let hn_off = to_off(ent as u32)?;
                if hn_off + 2 > data.len() {
                    return Err("truncated hint/name".to_string());
                }
                let func = cstr_ascii(data, hn_off + 2)?;
                let imp = Import {
                    iat_rva: ft + idx * 8,
                    dll: dll.clone(),
                    func,
                };
                if !is_supported(&imp.dll, &imp.func) {
                    if is_stub(&imp.dll, &imp.func) {
                        stubs.push(imp);
                    } else if strict {
                        return Err(format!(
                            "unsupported import: {}!{}",
                            imp.dll, imp.func
                        ));
                    } else {
                        unsupported.push(imp);
                    }
                } else {
                    imports.push(imp);
                }
                idx += 1;
                if idx > 256 {
                    return Err("too many imports".to_string());
                }
            }
            desc_off += 20;
            if desc_off > to_off(import_rva)? + import_size as usize {
                break;
            }
        }
    }

    let iat_slots = imports.iter().map(|i| i.iat_rva).collect();

    // TLS directory (optional): RVAs into the loaded image.
    let tls = if tls_rva != 0 {
        if tls_size < 40 {
            return Err("invalid TLS directory".to_string());
        }
        let t = tls_rva as usize;
        if t + 40 > image.len() {
            return Err("TLS directory out of bounds".to_string());
        }
        let va = |o: usize| u64::from_le_bytes(image[t + o..t + o + 8].try_into().unwrap());
        let to_rva = |a: u64| -> Result<u32, String> {
            a.checked_sub(image_base)
                .and_then(|r| u32::try_from(r).ok())
                .ok_or_else(|| "TLS address out of image".to_string())
        };
        let start = to_rva(va(0))? as usize;
        let end = to_rva(va(8))? as usize;
        if end < start || end - start > 1024 * 1024 {
            return Err("invalid TLS data range".to_string());
        }
        if end > image.len() {
            return Err("TLS data out of bounds".to_string());
        }
        let index_rva = to_rva(va(16))?;
        let cb_va = va(24);
        let zero_fill = u32::from_le_bytes(image[t + 32..t + 36].try_into().unwrap());
        if zero_fill > 1024 * 1024 {
            return Err("invalid TLS zero fill".to_string());
        }
        let mut callbacks = Vec::new();
        if cb_va != 0 {
            let cb_rva = to_rva(cb_va)? as usize;
            for i in 0..64 {
                let o = cb_rva + i * 8;
                if o + 8 > image.len() {
                    return Err("TLS callbacks out of bounds".to_string());
                }
                let f = u64::from_le_bytes(image[o..o + 8].try_into().unwrap());
                if f == 0 {
                    break;
                }
                callbacks.push(to_rva(f)?);
            }
        }
        if !callbacks.is_empty() {
            return Err(format!(
                "TLS callbacks not supported ({} found)",
                callbacks.len()
            ));
        }
        Some(TlsDir {
            raw_data: image[start..end].to_vec(),
            zero_fill,
            index_rva,
            callbacks,
        })
    } else {
        None
    };

    Ok(PeImage {
        image_base,
        entry_rva,
        size_of_image,
        image,
        imports,
        stubs,
        unsupported,
        tls,
        iat_slots,
    })
}
