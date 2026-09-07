//! Minimal Win32 API shims over [`WinFs`](crate::winfs::WinFs).
//!
//! Same `WinFs` API as `ps1` uses (requirement 9). Supported:
//! ExitProcess, GetStdHandle, WriteFile, CreateFileW, ReadFile, CloseHandle,
//! CreateDirectoryW, RemoveDirectoryW, DeleteFileW, MoveFileW, CopyFileW.
//! Anything else fails at load time (`pe::load` rejects unknown imports).

use crate::pe::emu::{Emu, StepResult};
use crate::pe::PeImage;
use crate::winfs::WinFs;
use std::collections::HashMap;

pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // -10
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // -11
pub const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // -12
pub const INVALID_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFFF;

const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;

struct FileHandle {
    path: String, // display path (original resolution; re-normalized per op)
    offset: u64,
}

pub struct Runner {
    pub emu: Emu,
    pub fs: WinFs,
    handles: HashMap<u64, FileHandle>,
    next_handle: u64,
    pub exit_code: Option<u32>,
}

impl Runner {
    pub fn new(img: &PeImage, fs: WinFs) -> Result<Self, String> {
        Ok(Self {
            emu: Emu::new(img)?,
            fs,
            handles: HashMap::new(),
            next_handle: 0x100,
            exit_code: None,
        })
    }

    fn alloc_handle(&mut self, path: String, offset: u64) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(h, FileHandle { path, offset });
        h
    }

    pub fn run(mut self) -> Result<(u32, WinFs, Vec<u8>), String> {
        loop {
            match self.emu.step()? {
                StepResult::Continue => {}
                StepResult::Halted(code) => {
                    let fs = std::mem::replace(&mut self.fs, WinFs::new());
                    return Ok((code, fs, std::mem::take(&mut self.emu.stdout)));
                }
                StepResult::CalledStub { index } => {
                    if self.do_shim(index)? {
                        // do_shim returns true when it already halted (ExitProcess)
                        let code = self.exit_code.unwrap();
                        let fs = std::mem::replace(&mut self.fs, WinFs::new());
                        return Ok((code, fs, std::mem::take(&mut self.emu.stdout)));
                    }
                }
            }
        }
    }

    /// Execute the shim for import `index`. Returns Ok(true) if halted.
    fn do_shim(&mut self, index: usize) -> Result<bool, String> {
        let imp = self.emu.imports[index].clone();
        let rcx = self.emu.regs[1];
        let rdx = self.emu.regs[2];
        let r8 = self.emu.regs[8];
        let r9 = self.emu.regs[9];
        let name = imp.func.as_str();

        // Helper to return to caller: pop return address into RIP.
        macro_rules! ret_bool {
            ($v:expr) => {{
                self.emu.regs[0] = $v;
                let ra = self.emu.pop_u64()?;
                if ra == crate::pe::emu::ENTRY_SENTINEL {
                    self.exit_code = Some((self.emu.regs[0] & 0xFFFF_FFFF) as u32);
                    return Ok(true);
                }
                self.emu.rip = ra;
                return Ok(false);
            }};
        }
        macro_rules! ret_halt {
            ($code:expr) => {{
                self.exit_code = Some($code);
                return Ok(true);
            }};
        }

        match name {
            "ExitProcess" => {
                ret_halt!((rcx & 0xFFFF_FFFF) as u32);
            }
            "GetStdHandle" => {
                let h = match rcx as u32 {
                    STD_INPUT_HANDLE => 0u64,
                    STD_OUTPUT_HANDLE => 1u64,
                    STD_ERROR_HANDLE => 2u64,
                    _ => 1u64, // unknown id -> stdout (lenient, still deterministic)
                };
                ret_bool!(h);
            }
            "WriteFile" => {
                // BOOL WriteFile(HANDLE, LPCVOID, DWORD n, LPDWORD written, LPOVERLAPPED)
                let h = rcx;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let p_written = r9;
                let overlapped = self.emu.stack_arg(4).unwrap_or(0);
                let _ = overlapped;
                if n > 16 * 1024 * 1024 {
                    ret_bool!(0);
                }
                let data = self.emu.read_bytes(buf, n)?;
                if h == 1 || h == 2 {
                    self.emu.stdout.extend_from_slice(&data);
                    if p_written != 0 {
                        self.emu.write_u32(p_written, n as u32)?;
                    }
                    ret_bool!(1);
                } else if h == 0 {
                    // writing to stdin handle fails
                    ret_bool!(0);
                } else {
                    let fh = self.handles.get_mut(&h).ok_or_else(|| {
                        format!("WriteFile: invalid handle 0x{h:016x}")
                    })?;
                    // read-modify-write at offset
                    let mut content = self
                        .fs
                        .read_file(&fh.path)
                        .map_err(|e| format!("WriteFile: {e}"))?;
                    let off = fh.offset as usize;
                    if off > content.len() {
                        content.resize(off, 0);
                    }
                    if off + n > content.len() {
                        content.resize(off + n, 0);
                    }
                    content[off..off + n].copy_from_slice(&data);
                    fh.offset += n as u64;
                    let p = fh.path.clone();
                    self.fs
                        .write_file(&p, content)
                        .map_err(|e| format!("WriteFile: {e}"))?;
                    if p_written != 0 {
                        self.emu.write_u32(p_written, n as u32)?;
                    }
                    ret_bool!(1);
                }
            }
            "CreateFileW" => {
                // HANDLE CreateFileW(path, access, share, sec, creation, flags, template)
                // Win x64: arg1-4 in rcx,rdx,r8,r9; creation is the 5th arg,
                // i.e. the first stack slot (index 4).
                let p_path = rcx;
                let creation = self.emu.stack_arg(4).unwrap_or(OPEN_EXISTING as u64) as u32;
                let path = self.emu.read_utf16(p_path)?;
                let exists = self.fs.exists(&path);
                let is_dir = self.fs.is_dir(&path);
                match creation {
                    CREATE_NEW => {
                        if exists {
                            ret_bool!(INVALID_HANDLE);
                        }
                        if is_dir {
                            ret_bool!(INVALID_HANDLE);
                        }
                        self.fs
                            .write_file(&path, Vec::new())
                            .map_err(|e| format!("CreateFileW: {e}"))?;
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    CREATE_ALWAYS => {
                        if is_dir {
                            ret_bool!(INVALID_HANDLE);
                        }
                        self.fs
                            .write_file(&path, Vec::new())
                            .map_err(|e| format!("CreateFileW: {e}"))?;
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    OPEN_EXISTING => {
                        if !exists || is_dir {
                            ret_bool!(INVALID_HANDLE);
                        }
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    OPEN_ALWAYS => {
                        if is_dir {
                            ret_bool!(INVALID_HANDLE);
                        }
                        if !exists {
                            self.fs
                                .write_file(&path, Vec::new())
                                .map_err(|e| format!("CreateFileW: {e}"))?;
                        }
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    TRUNCATE_EXISTING => {
                        if !exists || is_dir {
                            ret_bool!(INVALID_HANDLE);
                        }
                        self.fs
                            .write_file(&path, Vec::new())
                            .map_err(|e| format!("CreateFileW: {e}"))?;
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    _ => {
                        ret_bool!(INVALID_HANDLE);
                    }
                }
            }
            "ReadFile" => {
                let h = rcx;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let p_read = r9;
                if n > 16 * 1024 * 1024 {
                    ret_bool!(0);
                }
                if h == 0 {
                    // stdin: no input -> 0 bytes
                    if p_read != 0 {
                        self.emu.write_u32(p_read, 0)?;
                    }
                    ret_bool!(1);
                } else if h == 1 || h == 2 {
                    ret_bool!(0);
                } else {
                    let fh = self.handles.get_mut(&h).ok_or_else(|| {
                        format!("ReadFile: invalid handle 0x{h:016x}")
                    })?;
                    let content = self
                        .fs
                        .read_file(&fh.path)
                        .map_err(|e| format!("ReadFile: {e}"))?;
                    let off = fh.offset as usize;
                    let avail = content.len().saturating_sub(off.min(content.len()));
                    let k = avail.min(n);
                    self.emu.write_bytes(buf, &content[off..off + k])?;
                    fh.offset += k as u64;
                    if p_read != 0 {
                        self.emu.write_u32(p_read, k as u32)?;
                    }
                    ret_bool!(1);
                }
            }
            "CloseHandle" => {
                let h = rcx;
                if h <= 2 {
                    ret_bool!(1);
                }
                if self.handles.remove(&h).is_some() {
                    ret_bool!(1);
                } else {
                    ret_bool!(0);
                }
            }
            "CreateDirectoryW" => {
                let path = self.emu.read_utf16(rcx)?;
                match self.fs.mkdir_one(&path) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            "RemoveDirectoryW" => {
                let path = self.emu.read_utf16(rcx)?;
                match self.fs.rmdir(&path) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            "DeleteFileW" => {
                let path = self.emu.read_utf16(rcx)?;
                match self.fs.delete_file(&path) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            "MoveFileW" => {
                let src = self.emu.read_utf16(rcx)?;
                let dst = self.emu.read_utf16(rdx)?;
                match self.fs.move_path(&src, &dst) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            "CopyFileW" => {
                let src = self.emu.read_utf16(rcx)?;
                let dst = self.emu.read_utf16(rdx)?;
                let fail_if_exists = (r8 & 0xFFFF_FFFF) != 0;
                match self.fs.copy_file(&src, &dst, fail_if_exists) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            other => {
                return Err(format!(
                    "unsupported import at runtime: {}!{other}",
                    imp.dll
                ));
            }
        }
    }
}

/// Convenience: load bytes + run with a fresh or given FS.
pub fn run_exe(data: &[u8], fs: WinFs) -> Result<(u32, WinFs, Vec<u8>), String> {
    let img = crate::pe::load(data)?;
    Runner::new(&img, fs)?.run()
}
