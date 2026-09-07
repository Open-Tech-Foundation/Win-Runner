//! Minimal Win32 API shims over [`WinFs`](crate::winfs::WinFs).
//!
//! Same `WinFs` API as `ps1` uses (requirement 9). Supported: ExitProcess,
//! GetStdHandle, WriteFile, CreateFileW, ReadFile, CloseHandle,
//! CreateDirectoryW, RemoveDirectoryW, DeleteFileW, MoveFileW, CopyFileW,
//! GetCommandLineW/A, GetConsoleMode, SetConsoleMode, WriteConsoleW,
//! GetConsoleOutputCP, SetConsoleTextAttribute, ReadConsoleW.
//! Anything else fails at load time (`pe::load` rejects unknown imports).

use crate::pe::emu::{Emu, StepResult};
use crate::pe::PeImage;
use crate::winfs::WinFs;
use std::collections::HashMap;
use std::io::IsTerminal;

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
    /// Called with every console write as it happens (streaming). When unset
    /// (tests), output stays buffered in `emu.stdout` until `run` returns.
    console_sink: Option<Box<dyn FnMut(&[u8])>>,
    /// Whether host stdout is a TTY (drives `GetConsoleMode`).
    console_is_tty: bool,
}

impl Runner {
    pub fn new(img: &PeImage, fs: WinFs) -> Result<Self, String> {
        Self::with_argv(img, fs, "<exe>", &[])
    }

    /// `prog` is argv0 as typed; `args` are the guest arguments.
    pub fn with_argv(
        img: &PeImage,
        fs: WinFs,
        prog: &str,
        args: &[String],
    ) -> Result<Self, String> {
        if let Some(first) = img.unsupported.first() {
            return Err(format!(
                "unsupported import: {}!{} (image came from lenient load; refusing to execute)",
                first.dll, first.func
            ));
        }
        let mut emu = Emu::new(img)?;
        emu.alloc_cmdline(prog, args)?;
        Ok(Self {
            emu,
            fs,
            handles: HashMap::new(),
            next_handle: 0x100,
            exit_code: None,
            console_sink: None,
            console_is_tty: std::io::stdout().is_terminal(),
        })
    }

    pub fn with_console_sink(mut self, sink: Box<dyn FnMut(&[u8])>) -> Self {
        self.console_sink = Some(sink);
        self
    }

    /// Emit guest console bytes: buffer (returned by `run`) + stream to sink.
    fn console_out(&mut self, data: &[u8]) {
        self.emu.stdout.extend_from_slice(data);
        if let Some(sink) = self.console_sink.as_mut() {
            sink(data);
        }
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
                    self.console_out(&data);
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
            "GetCommandLineW" => {
                if self.emu.cmdline_va == 0 {
                    ret_bool!(0);
                }
                ret_bool!(self.emu.cmdline_va);
            }
            "GetCommandLineA" => {
                if self.emu.cmdline_ansi_va == 0 {
                    ret_bool!(0);
                }
                ret_bool!(self.emu.cmdline_ansi_va);
            }
            "GetConsoleMode" => {
                // Succeeds for console handles iff host stdout is a TTY,
                // mirroring Windows (pipes fail) so `--color=auto` works.
                let h = rcx;
                let p_mode = rdx;
                if (h == 1 || h == 2) && self.console_is_tty {
                    // ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT
                    if p_mode != 0 {
                        self.emu.write_u32(p_mode, 0x3)?;
                    }
                    ret_bool!(1);
                } else {
                    ret_bool!(0);
                }
            }
            "SetConsoleMode" => {
                // Modes are not tracked (byte-pipe model); succeed for
                // console handles so VT-capable guests proceed.
                let h = rcx;
                ret_bool!(u64::from(h == 1 || h == 2));
            }
            "WriteConsoleW" => {
                // BOOL WriteConsoleW(HANDLE, LPCVOID, DWORD nchars, LPDWORD, LPVOID)
                let h = rcx;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let p_written = r9;
                if h != 1 && h != 2 {
                    ret_bool!(0);
                }
                if n > 4 * 1024 * 1024 {
                    ret_bool!(0);
                }
                let mut units = Vec::with_capacity(n);
                for i in 0..n {
                    units.push(self.emu.read_u16(buf + i as u64 * 2)?);
                }
                let text = String::from_utf16_lossy(&units);
                self.console_out(text.as_bytes());
                if p_written != 0 {
                    self.emu.write_u32(p_written, n as u32)?;
                }
                ret_bool!(1);
            }
            "GetConsoleOutputCP" => {
                // UTF-8, matching our transcode behavior.
                ret_bool!(65001);
            }
            "SetConsoleTextAttribute" => {
                // Colors are passed through as bytes; nothing to store.
                let h = rcx;
                ret_bool!(u64::from(h == 1 || h == 2));
            }
            "ReadConsoleW" => {
                // Line-buffered read from host stdin, UTF-8 decoded lossily.
                let h = rcx;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let p_read = r9;
                if h != 0 || n == 0 {
                    ret_bool!(0);
                }
                let line = read_stdin_line().unwrap_or_default();
                let wide: Vec<u16> = line.encode_utf16().take(n).collect();
                for (i, u) in wide.iter().enumerate() {
                    self.emu.write_u16(buf + i as u64 * 2, *u)?;
                }
                if p_read != 0 {
                    self.emu.write_u32(p_read, wide.len() as u32)?;
                }
                ret_bool!(1);
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

/// One line from host stdin (no trailing newline), lossy UTF-8.
fn read_stdin_line() -> Option<String> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut line = String::new();
    match stdin.lock().read_line(&mut line) {
        Ok(0) => Some(String::new()), // EOF -> empty
        Ok(_) => {
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }
            Some(line)
        }
        Err(_) => None,
    }
}

/// Convenience: load bytes + run with a fresh or given FS.
pub fn run_exe(data: &[u8], fs: WinFs) -> Result<(u32, WinFs, Vec<u8>), String> {
    run_exe_argv(data, fs, "<exe>", &[])
}

/// Load bytes + run with guest argv (`prog` is argv0 as typed).
pub fn run_exe_argv(
    data: &[u8],
    fs: WinFs,
    prog: &str,
    args: &[String],
) -> Result<(u32, WinFs, Vec<u8>), String> {
    let img = crate::pe::load(data)?;
    Runner::with_argv(&img, fs, prog, args)?.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::builder::{build, Asm};

    /// Probe guest: GetConsoleOutputCP==65001, SetConsoleMode/TextAttribute ok,
    /// WriteConsoleW transcodes UTF-16 (é + lone surrogate) to UTF-8.
    /// Exit 0 = all good, 1 = any step failed.
    fn console_probe() -> Vec<u8> {
        // imports: GetStdHandle WriteConsoleW GetConsoleOutputCP
        //          SetConsoleMode SetConsoleTextAttribute ExitProcess
        const GH: usize = 0;
        const WC: usize = 1;
        const CP: usize = 2;
        const SM: usize = 3;
        const TA: usize = 4;
        const XP: usize = 5;
        let mut a = Asm::new();
        // msg = U+00E9, lone surrogate U+D800, 'B', '\n'
        let mut msg = Vec::new();
        for u in [0x00E9u16, 0xD800, 0x0042, 0x000A] {
            msg.extend_from_slice(&u.to_le_bytes());
        }
        let d_msg = a.add_data(msg);
        let d_written = a.add_zeroed(8);
        let lbl_fail = a.fresh_label();
        a.sub_rsp(0x28);
        // h = GetStdHandle(-11)
        a.mov_ecx_imm(0xFFFF_FFF5);
        a.call_import(GH);
        a.mov_rspoff_rax(0x28); // save handle
        // GetConsoleOutputCP == 65001?
        a.call_import(CP);
        a.cmp_eax_imm(65001);
        a.jnz(lbl_fail);
        // SetConsoleMode(h, 3)?
        a.mov_reg_rspoff(1, 0x28);
        a.mov_edx_imm(3);
        a.call_import(SM);
        a.test_eax_eax();
        a.jz(lbl_fail);
        // SetConsoleTextAttribute(h, 7)?
        a.mov_reg_rspoff(1, 0x28);
        a.mov_edx_imm(7);
        a.call_import(TA);
        a.test_eax_eax();
        a.jz(lbl_fail);
        // WriteConsoleW(h, msg, 4, &written, 0)?
        a.mov_reg_rspoff(1, 0x28);
        a.lea_reg_rip(2, d_msg);
        a.mov_r32_imm(8, 4);
        a.lea_reg_rip(9, d_written);
        a.xor_eax();
        a.mov_rspoff_rax(0x20);
        a.call_import(WC);
        a.test_eax_eax();
        a.jz(lbl_fail);
        a.mov_ecx_imm(0);
        a.call_import(XP);
        a.add_rsp(0x28);
        a.ret();
        a.mark(lbl_fail);
        a.mov_ecx_imm(1);
        a.call_import(XP);
        a.add_rsp(0x28);
        a.ret();
        build(
            a,
            &[
                ("KERNEL32.dll", "GetStdHandle"),
                ("KERNEL32.dll", "WriteConsoleW"),
                ("KERNEL32.dll", "GetConsoleOutputCP"),
                ("KERNEL32.dll", "SetConsoleMode"),
                ("KERNEL32.dll", "SetConsoleTextAttribute"),
                ("KERNEL32.dll", "ExitProcess"),
            ],
        )
    }

    #[test]
    fn console_shims_transcode_and_report() {
        let (code, _, out) = run_exe(&console_probe(), WinFs::new()).unwrap();
        assert_eq!(code, 0);
        // é -> C3 A9, lone surrogate -> EF BF BD (U+FFFD), then B \n
        assert_eq!(out, b"\xc3\xa9\xef\xbf\xbdB\n");
    }

    #[test]
    fn streaming_sink_sees_console_writes() {
        let exe = crate::pe::builder::hello("stream-me");
        let img = crate::pe::load(&exe).unwrap();
        let runner = Runner::new(&img, WinFs::new()).unwrap();
        // borrow dance: collect via Rc<RefCell>
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
        let seen2 = seen.clone();
        let runner = runner.with_console_sink(Box::new(move |c: &[u8]| {
            seen2.borrow_mut().extend_from_slice(c);
        }));
        let (code, _, out) = runner.run().unwrap();
        assert_eq!(code, 0);
        assert_eq!(&*seen.borrow(), b"stream-me");
        assert_eq!(out, b"stream-me");
    }

    #[test]
    fn runner_is_non_tty_under_test_harness() {
        // cargo test captures stdout -> not a TTY. Pins the deterministic half
        // of GetConsoleMode (succeeds iff TTY); the TTY-true path is trivial
        // (`mode=3`, return 1) and covered by inspection.
        let exe = crate::pe::builder::hello("x");
        let img = crate::pe::load(&exe).unwrap();
        let r = Runner::new(&img, WinFs::new()).unwrap();
        assert!(!r.console_is_tty);
    }
}
