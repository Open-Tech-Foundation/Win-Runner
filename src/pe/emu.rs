//! Minimal x86_64 interpreter.
//!
//! Supports only the instruction subset emitted by `builder` (plus common
//! straight-line integer ops). Anything else is a clear error — never silently
//! succeeding. This keeps the codebase small while running real PE32+ blobs.

use super::{Import, PeImage};
use std::collections::HashMap;

/// Fake address base for resolved imports. Outside any real mapping.
pub const STUB_BASE: u64 = 0x0000_0000_0010_0000;
pub const STACK_SIZE: usize = 2 * 1024 * 1024;
/// Default step budget (see `max_steps`).
pub const MAX_STEPS: u64 = 10_000_000;

/// Step budget, raised via `WINCLI_MAX_STEPS` for long-running guests.
pub fn max_steps() -> u64 {
    std::env::var("WINCLI_MAX_STEPS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(MAX_STEPS)
}
/// Sentinel return address placed at the bottom of the stack.
pub const ENTRY_SENTINEL: u64 = 0xDEAD_BEEF_DEAD_BEEF;

/// Minimal CPUID for feature detection. Reports the emulated subset:
/// SSE/SSE2 baseline, nothing newer. Unknown leaves read as zero.
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    match leaf {
        0 => (0x16, 0x756e_6547, 0x6c65_746e, 0x4965_6e69), // "GenuineIntel"
        1 => {
            let edx = (1 << 0)   // FPU
                | (1 << 4)       // TSC
                | (1 << 5)       // MSR
                | (1 << 6)       // PAE
                | (1 << 7)       // MCE
                | (1 << 8)       // CX8
                | (1 << 9)       // APIC
                | (1 << 11)      // SEP
                | (1 << 12)      // MTRR
                | (1 << 13)      // PGE
                | (1 << 14)      // MCA
                | (1 << 15)      // CMOV
                | (1 << 16)      // PAT
                | (1 << 17)      // PSE36
                | (1 << 19)      // CLFSH
                | (1 << 20)      // reserved (historical NT bit)
                | (1 << 23)      // MMX
                | (1 << 24)      // FXSR
                | (1 << 25)      // SSE
                | (1 << 26); // SSE2
            (0x0005_06E3, 0x0200, 0x0000_0000, edx)
        }
        7 if sub == 0 => (0, 0, 0, 0), // no AVX2/BMI/etc.
        _ => (0, 0, 0, 0),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    Continue,
    CalledStub { index: usize },
    Halted(u32),
}

/// Per-thread processor state. Guest memory and import tables stay in `Emu`
/// and are shared by every cooperatively scheduled guest thread.
#[derive(Clone)]
pub struct CpuState {
    pub regs: [u64; 16],
    pub xmm: [u128; 16],
    pub rip: u64,
    pub zf: bool,
    pub sf: bool,
    pub cf: bool,
    pub of: bool,
    pub pf: bool,
    pub df: bool,
    pub gs_base: u64,
}

pub struct Emu {
    pub base: u64,
    pub mem: Vec<u8>,
    pub regs: [u64; 16],
    /// XMM0-15 as raw 128-bit lanes. Only bitwise/packed-integer moves are
    /// supported (movaps/movups/xorps); no FP arithmetic, no MXCSR, and no
    /// alignment faulting on movaps (guests are compiler-aligned).
    pub xmm: [u128; 16],
    pub rip: u64,
    pub zf: bool,
    pub sf: bool,
    pub cf: bool,
    pub of: bool,
    /// Parity flag. Only FP compares set it (JP = unordered/NaN check);
    /// integer ops leave it alone (documented gap).
    pub pf: bool,
    /// Direction flag (STD/CLD). Only tracked, not yet consumed: string
    /// ops that need it fail clearly until implemented.
    pub df: bool,
    pub stubs: HashMap<u64, usize>,
    pub imports: Vec<Import>,
    pub stdout: Vec<u8>,
    /// Guest VA of the NUL-terminated UTF-16 command line (`GetCommandLineW`),
    /// 0 when unset. The ANSI block (`GetCommandLineA`, UTF-8 bytes) sits
    /// right after it. See `alloc_cmdline`.
    pub cmdline_va: u64,
    pub cmdline_ansi_va: u64,
    cmdline_base: u64,
    heap_base: u64,
    heap_next: u64,
    /// GS base (TEB address) for `gs:` segment accesses. 0 = unset.
    pub gs_base: u64,
    /// Set while decoding an instruction with a GS override prefix.
    seg_gs: bool,
    /// Whether the instruction currently being stepped has a REX prefix.
    /// Needed for the 8-bit high-byte rule: without REX, indices 4-7 mean
    /// AH/CH/DH/BH; with REX they address the low bytes (SPL/BPL/SIL/DIL).
    cur_rex: bool,
    steps: u64,
    /// Executable section ranges (absolute VAs): guest writes overlapping
    /// them fail loudly (W^X, like real Windows) instead of corrupting code.
    code_ranges: Vec<(u64, u64)>,
}

/// Reserved guest command-line area (UTF-16 block + ANSI block).
pub const CMDLINE_SIZE: usize = 0x10000;
/// Guest heap/virtual region served by HeapAlloc/VirtualAlloc (bump
/// allocator, no reuse; frees are no-op successes).
pub const HEAP_SIZE: usize = 64 * 1024 * 1024;
/// TEB + PEB + TLS-array page (see `Runner` TLS setup).
pub const TEB_SIZE: usize = 0x1000;
/// Minimal x64 TEB field offsets we populate.
pub const TEB_SELF_OFF: u64 = 0x30;
pub const TEB_TLS_OFF: u64 = 0x58;
pub const TEB_PEB_OFF: u64 = 0x60;
/// PEB sits 0x800 into the TEB page; ImageBaseAddress at +0x10.
pub const PEB_OFF: u64 = 0x800;
pub const PEB_IMAGEBASE_OFF: u64 = 0x10;
/// PEB_LDR_DATA pointer at +0x20 (minimal zeroed block; real SsHandle is
/// NULL for EXEs, so loader-bit checks see the genuine value).
pub const PEB_LDR_OFF: u64 = 0x20;

impl Emu {
    pub fn cpu_state(&self) -> CpuState {
        CpuState {
            regs: self.regs,
            xmm: self.xmm,
            rip: self.rip,
            zf: self.zf,
            sf: self.sf,
            cf: self.cf,
            of: self.of,
            pf: self.pf,
            df: self.df,
            gs_base: self.gs_base,
        }
    }

    pub fn restore_cpu(&mut self, state: &CpuState) {
        self.regs = state.regs;
        self.xmm = state.xmm;
        self.rip = state.rip;
        self.zf = state.zf;
        self.sf = state.sf;
        self.cf = state.cf;
        self.of = state.of;
        self.pf = state.pf;
        self.df = state.df;
        self.gs_base = state.gs_base;
    }

    pub fn thread_cpu(
        &mut self,
        start: u64,
        parameter: u64,
        stack_size: usize,
        gs_base: u64,
    ) -> Result<CpuState, String> {
        self.read_u8(start)?;
        let size = if stack_size == 0 {
            STACK_SIZE
        } else {
            stack_size.max(64 * 1024)
        };
        if size > HEAP_SIZE / 2 {
            return Err("guest thread stack is too large".to_string());
        }
        let stack = self.heap_alloc_aligned(size, 16);
        if stack == 0 {
            return Err("out of guest memory for thread stack".to_string());
        }
        let top = (stack + size as u64) & !0xf;
        self.write_u64(top - 8, ENTRY_SENTINEL)?;
        let mut cpu = self.cpu_state();
        cpu.regs = [0; 16];
        cpu.xmm = [0; 16];
        cpu.regs[1] = parameter;
        cpu.regs[4] = top - 8;
        cpu.rip = start;
        cpu.zf = false;
        cpu.sf = false;
        cpu.cf = false;
        cpu.of = false;
        cpu.pf = false;
        cpu.df = false;
        cpu.gs_base = gs_base;
        Ok(cpu)
    }

    pub fn new(img: &PeImage) -> Result<Self, String> {
        let total =
            img.size_of_image as usize + CMDLINE_SIZE + STACK_SIZE + HEAP_SIZE + TEB_SIZE + 0x1000;
        let base = img.image_base;
        let mut mem = vec![0u8; total];
        mem[..img.image.len()].copy_from_slice(&img.image);
        let heap_base = base + img.size_of_image as u64 + CMDLINE_SIZE as u64 + STACK_SIZE as u64;
        // Stack starts at the top of its dedicated region (below the heap),
        // 16-aligned. Starting at top-of-memory instead lets deep stacks
        // march down through the TEB page and heap tail (rg startup did).
        let stack_top = heap_base & !0xF;
        let mut e = Self {
            base,
            mem,
            regs: [0u64; 16],
            xmm: [0u128; 16],
            rip: base + img.entry_rva as u64,
            zf: false,
            sf: false,
            cf: false,
            of: false,
            pf: false,
            df: false,
            stubs: HashMap::new(),
            imports: img.imports.clone(),
            stdout: Vec::new(),
            cmdline_va: 0,
            cmdline_ansi_va: 0,
            cmdline_base: base + img.size_of_image as u64,
            heap_base,
            heap_next: heap_base,
            gs_base: 0,
            seg_gs: false,
            cur_rex: false,
            steps: 0,
            code_ranges: img.code_ranges.clone(),
        };
        // Reserve stub addresses and patch IAT slots (real imports first,
        // then fail-stubs; both dispatch into the shims by name). Direct
        // memory write: the loader may patch IAT slots inside executable
        // sections (old test artifacts do), like the real loader.
        let mut i = 0usize;
        for imp in img.imports.iter().chain(img.stubs.iter()) {
            let stub = STUB_BASE + i as u64 * 8;
            e.stubs.insert(stub, i);
            let va = base + imp.iat_rva as u64;
            let o = e.check_va(va, 8)?;
            e.mem[o..o + 8].copy_from_slice(&stub.to_le_bytes());
            i += 1;
        }
        e.imports = img
            .imports
            .iter()
            .chain(img.stubs.iter())
            .cloned()
            .collect();
        // Set up stack with sentinel return address.
        e.regs[4] = stack_top;
        e.push_u64(ENTRY_SENTINEL)?;
        Ok(e)
    }

    /// Bump-allocate `size` bytes (16-aligned) with an 8-byte size header.
    /// Returns 0 on exhaustion (caller maps to API failure). Frees are
    /// no-ops by design (no reuse); memory is zeroed (fresh mapping).
    pub fn heap_alloc(&mut self, size: usize) -> u64 {
        self.heap_alloc_aligned(size, 16)
    }

    /// Same with explicit power-of-two alignment.
    pub fn heap_alloc_aligned(&mut self, size: usize, align: u64) -> u64 {
        if size > HEAP_SIZE || align == 0 || align & (align - 1) != 0 {
            return 0;
        }
        let Some(payload) = self
            .heap_next
            .checked_add(8 + align - 1)
            .map(|v| v & !(align - 1))
        else {
            return 0;
        };
        let next = payload - 8;
        let end = payload.checked_add(size as u64);
        let limit = self.heap_base + HEAP_SIZE as u64;
        match end {
            Some(e) if e <= limit => {
                // header: payload size
                let off = (next - self.base) as usize;
                self.mem[off..off + 8].copy_from_slice(&(size as u64).to_le_bytes());
                self.heap_next = e;
                payload
            }
            _ => 0,
        }
    }

    /// Payload size recorded by [`Emu::heap_alloc`], 0 if untracked.
    pub fn heap_size_of(&self, va: u64) -> u64 {
        if va < self.heap_base + 8 {
            return 0;
        }
        self.read_u64(va - 8).unwrap_or(0)
    }

    /// Build the Windows command line `prog arg...` (MSVC quoting rules) and
    /// lay out UTF-16 + ANSI blocks. `prog` is argv0 as typed on the host CLI.
    pub fn alloc_cmdline(&mut self, prog: &str, args: &[String]) -> Result<(), String> {
        let mut cmd = String::new();
        cmd.push_str(&quote_arg(prog));
        for a in args {
            cmd.push(' ');
            cmd.push_str(&quote_arg(a));
        }
        let wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
        let ansi = cmd.as_bytes();
        // layout: [wide + NUL][ansi + NUL], must fit CMDLINE_SIZE
        let need = wide.len() * 2 + ansi.len() + 1;
        if need > CMDLINE_SIZE {
            return Err("command line too long (64K guest block)".to_string());
        }
        let base_va = self.cmdline_base;
        let wide_va = base_va;
        for (i, u) in wide.iter().enumerate() {
            self.write_u16(wide_va + i as u64 * 2, *u)?;
        }
        let ansi_va = wide_va + wide.len() as u64 * 2;
        self.write_bytes(ansi_va, ansi)?;
        self.write_u8(ansi_va + ansi.len() as u64, 0)?;
        self.cmdline_va = wide_va;
        self.cmdline_ansi_va = ansi_va;
        Ok(())
    }

    // ---------- memory ----------
    pub fn check_va(&self, va: u64, len: usize) -> Result<usize, String> {
        if va < self.base {
            return Err(format!("memory access below image base: 0x{va:016x}"));
        }
        let off = (va - self.base) as usize;
        if off
            .checked_add(len)
            .map(|e| e > self.mem.len())
            .unwrap_or(true)
        {
            return Err(format!("memory access out of bounds: 0x{va:016x}+{len}"));
        }
        Ok(off)
    }
    /// Reject writes overlapping executable sections (W^X).
    fn check_writable(&self, va: u64, len: usize) -> Result<(), String> {
        let end = va.saturating_add(len as u64);
        for &(s, e) in &self.code_ranges {
            if va < e && end > s {
                return Err(format!("write to executable section: 0x{va:016x}+{len}"));
            }
        }
        Ok(())
    }
    pub fn read_u8(&self, va: u64) -> Result<u8, String> {
        Ok(self.mem[self.check_va(va, 1)?])
    }
    pub fn read_u16(&self, va: u64) -> Result<u16, String> {
        let o = self.check_va(va, 2)?;
        Ok(u16::from_le_bytes([self.mem[o], self.mem[o + 1]]))
    }
    pub fn read_u32(&self, va: u64) -> Result<u32, String> {
        let o = self.check_va(va, 4)?;
        Ok(u32::from_le_bytes([
            self.mem[o],
            self.mem[o + 1],
            self.mem[o + 2],
            self.mem[o + 3],
        ]))
    }
    pub fn read_u64(&self, va: u64) -> Result<u64, String> {
        let o = self.check_va(va, 8)?;
        Ok(u64::from_le_bytes([
            self.mem[o],
            self.mem[o + 1],
            self.mem[o + 2],
            self.mem[o + 3],
            self.mem[o + 4],
            self.mem[o + 5],
            self.mem[o + 6],
            self.mem[o + 7],
        ]))
    }
    pub fn write_u8(&mut self, va: u64, v: u8) -> Result<(), String> {
        let o = self.check_va(va, 1)?;
        self.check_writable(va, 1)?;
        self.mem[o] = v;
        Ok(())
    }
    pub fn write_u16(&mut self, va: u64, v: u16) -> Result<(), String> {
        let o = self.check_va(va, 2)?;
        self.check_writable(va, 2)?;
        self.mem[o..o + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    pub fn write_u32(&mut self, va: u64, v: u32) -> Result<(), String> {
        let o = self.check_va(va, 4)?;
        self.check_writable(va, 4)?;
        self.mem[o..o + 4].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    pub fn write_u64(&mut self, va: u64, v: u64) -> Result<(), String> {
        let o = self.check_va(va, 8)?;
        self.check_writable(va, 8)?;
        self.mem[o..o + 8].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    pub fn read_u128(&self, va: u64) -> Result<u128, String> {
        let o = self.check_va(va, 16)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(&self.mem[o..o + 16]);
        Ok(u128::from_le_bytes(b))
    }
    pub fn write_u128(&mut self, va: u64, v: u128) -> Result<(), String> {
        let o = self.check_va(va, 16)?;
        self.check_writable(va, 16)?;
        self.mem[o..o + 16].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    pub fn read_bytes(&self, va: u64, len: usize) -> Result<Vec<u8>, String> {
        let o = self.check_va(va, len)?;
        Ok(self.mem[o..o + len].to_vec())
    }
    pub fn write_bytes(&mut self, va: u64, b: &[u8]) -> Result<(), String> {
        let o = self.check_va(va, b.len())?;
        self.check_writable(va, b.len())?;
        self.mem[o..o + b.len()].copy_from_slice(b);
        Ok(())
    }

    /// Read null-terminated UTF-16LE string.
    pub fn read_utf16(&self, va: u64) -> Result<String, String> {
        let mut out = Vec::new();
        for i in 0..4096 {
            let c = self.read_u16(va + i * 2)?;
            if c == 0 {
                return String::from_utf16(&out)
                    .map_err(|_| "invalid UTF-16 in guest string".to_string());
            }
            out.push(c);
        }
        Err("unterminated UTF-16 string".to_string())
    }

    // ---------- registers/stack ----------
    pub fn rsp(&self) -> u64 {
        self.regs[4]
    }
    pub fn set_rsp(&mut self, v: u64) {
        self.regs[4] = v;
    }
    pub fn push_u64(&mut self, v: u64) -> Result<(), String> {
        let rsp = self.rsp().wrapping_sub(8);
        self.set_rsp(rsp);
        self.write_u64(rsp, v)
    }
    pub fn pop_u64(&mut self) -> Result<u64, String> {
        let rsp = self.rsp();
        let v = self.read_u64(rsp)?;
        self.set_rsp(rsp.wrapping_add(8));
        Ok(v)
    }
    /// Guest VA of the TEB page (top of the carved regions).
    pub fn teb_va(&self) -> u64 {
        self.heap_base + HEAP_SIZE as u64
    }
    /// One-line register/flag summary for error context.
    pub fn regs_summary(&self) -> String {
        let r = &self.regs;
        format!(
            "rax={:x} rcx={:x} rdx={:x} rbx={:x} rsp={:x} rbp={:x} rsi={:x} rdi={:x} r8={:x} r9={:x} r10={:x} r11={:x} r12={:x} r13={:x} r14={:x} r15={:x} {}{}{}{}",
            r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10],
            r[11], r[12], r[13], r[14], r[15],
            if self.zf { "Z" } else { "-" },
            if self.sf { "S" } else { "-" },
            if self.cf { "C" } else { "-" },
            if self.of { "O" } else { "-" },
        )
    }
    /// Steps executed so far (for tracing/profiling).
    pub fn step_count(&self) -> u64 {
        self.steps
    }
    /// i-th stack arg (0-based, Win x64: 0..3 regs, 4+ on stack).
    /// Must be called after the call pushed the return address.
    pub fn stack_arg(&self, i: usize) -> Result<u64, String> {
        if i < 4 {
            return Err("stack_arg only for index >= 4".to_string());
        }
        // [rsp] = ret, [rsp+8..+40] shadow space, args at [rsp+40]+(i-4)*8
        self.read_u64(self.rsp() + 8 + 32 + (i as u64 - 4) * 8)
    }

    // ---------- flags ----------
    fn set_logic_flags(&mut self, res: u64, width: u32) {
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        let r = res & mask;
        self.zf = r == 0;
        self.sf = if width == 64 {
            (r >> 63) & 1 == 1
        } else {
            (r >> (width - 1)) & 1 == 1
        };
        self.cf = false;
        self.of = false;
    }
    fn set_add_flags(&mut self, a: u64, b: u64, res: u64, width: u32) {
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        let r = res & mask;
        self.zf = r == 0;
        self.sf = ((r >> (width - 1)) & 1) == 1;
        let a = a & mask;
        let b = b & mask;
        self.cf = r < a; // unsigned carry
        let sign = 1u64 << (width - 1);
        self.of = ((a ^ r) & (b ^ r) & sign) != 0;
    }
    fn set_sub_flags(&mut self, a: u64, b: u64, res: u64, width: u32) {
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        let r = res & mask;
        self.zf = r == 0;
        self.sf = ((r >> (width - 1)) & 1) == 1;
        let a = a & mask;
        let b = b & mask;
        self.cf = a < b; // borrow
        let sign = 1u64 << (width - 1);
        self.of = ((a ^ b) & (a ^ r) & sign) != 0;
    }

    fn jcc_taken(&self, cond: u8) -> Result<bool, String> {
        Ok(match cond {
            0 => self.of,                         // O
            1 => !self.of,                        // NO
            2 => self.cf,                         // B
            3 => !self.cf,                        // NB
            4 => self.zf,                         // Z
            5 => !self.zf,                        // NZ
            6 => self.cf || self.zf,              // BE
            7 => !self.cf && !self.zf,            // NBE
            8 => self.sf,                         // S
            9 => !self.sf,                        // NS
            10 => self.pf,                        // P (FP unordered only)
            11 => !self.pf,                       // NP
            12 => self.sf != self.of,             // L
            13 => self.sf == self.of,             // NL
            14 => self.zf || self.sf != self.of,  // LE
            15 => !self.zf && self.sf == self.of, // NLE
            _ => unreachable!(),
        })
    }

    // ---------- decode helpers ----------
    /// Decode ModR/M (+SIB+disp) at `off` (offset into mem from `ip`).
    /// Returns (reg_field, rm_is_reg, rm_reg, mem_va, total_len).
    fn decode_modrm(
        &self,
        ip: u64,
        off: usize,
        rex_r: bool,
        rex_x: bool,
        rex_b: bool,
        addr_is_rip: bool,
    ) -> Result<(usize, bool, usize, u64, usize), String> {
        let _ = addr_is_rip;
        let modrm = self.read_u8(ip + off as u64)?;
        let modf = (modrm >> 6) & 3;
        let reg = (((rex_r as u8) << 3) | ((modrm >> 3) & 7)) as usize;
        let rm = (((rex_b as u8) << 3) | (modrm & 7)) as usize;
        if modf == 3 {
            return Ok((reg, true, rm, 0, 1));
        }
        // memory
        let mut len = 1usize;
        let ea: u64;
        if (modrm & 7) == 4 {
            // SIB
            let sib = self.read_u8(ip + (off + len) as u64)?;
            len += 1;
            let scale = (sib >> 6) & 3;
            let index = (((rex_x as u8) << 3) | ((sib >> 3) & 7)) as usize;
            let base = (((rex_b as u8) << 3) | (sib & 7)) as usize;
            if (sib & 7) == 5 && modf == 0 {
                // disp32, no base
                let d = self.read_u32(ip + (off + len) as u64)? as i32 as i64 as u64;
                len += 4;
                let mut addr = d;
                if index != 4 {
                    addr = addr.wrapping_add(
                        self.regs[index]
                            .wrapping_shl(scale as u32 * 0)
                            .wrapping_mul(1 << scale),
                    );
                }
                ea = addr;
            } else {
                let mut addr = self.regs[base];
                if index != 4 {
                    addr = addr.wrapping_add(self.regs[index] << scale);
                }
                match modf {
                    0 => {}
                    1 => {
                        let d = self.read_u8(ip + (off + len) as u64)? as i8 as i64 as u64;
                        len += 1;
                        addr = addr.wrapping_add(d);
                    }
                    2 => {
                        let d = self.read_u32(ip + (off + len) as u64)? as i32 as i64 as u64;
                        len += 4;
                        addr = addr.wrapping_add(d);
                    }
                    _ => unreachable!(),
                }
                ea = addr;
            }
        } else if (modrm & 7) == 5 && modf == 0 {
            // RIP-relative
            let d = self.read_u32(ip + (off + len) as u64)? as i32 as i64;
            len += 4;
            // next_rip unknown here; caller patches: we need instruction length first.
            // Return marker: encode disp, caller adds next_rip. We stash disp in ea as raw.
            // To keep it simple, read next_rip via a second pass: caller must compute.
            // We return disp as signed; caller converts. Use u64 wrapping of disp.
            ea = d as u64; // marker
                           // flag via high bit impossible; caller knows this case by mod/rm.
                           // We'll handle RIP-relative in the caller by recomputing. For now return disp.
                           // To disambiguate, return ea = disp and len; caller checks (modrm&7)==5&&mod==0.
            return Ok((reg, false, 0x100, ea, len)); // 0x100 = RIP-rel marker
        } else {
            let mut addr = self.regs[rm];
            match modf {
                0 => {}
                1 => {
                    let d = self.read_u8(ip + (off + len) as u64)? as i8 as i64 as u64;
                    len += 1;
                    addr = addr.wrapping_add(d);
                }
                2 => {
                    let d = self.read_u32(ip + (off + len) as u64)? as i32 as i64 as u64;
                    len += 4;
                    addr = addr.wrapping_add(d);
                }
                _ => unreachable!(),
            }
            ea = addr;
        }
        // GS override (TEB/TLS access): fold the segment base in.
        let ea = if self.seg_gs {
            if self.gs_base == 0 {
                return Err("gs: segment used but no TEB is mapped (image has no TLS?)".to_string());
            }
            self.gs_base.wrapping_add(ea)
        } else {
            ea
        };
        Ok((reg, false, rm, ea, len))
    }

    /// 8-bit register read honoring the no-REX high-byte rule: without a
    /// REX prefix, indices 4-7 address AH/CH/DH/BH (bits 8-15 of regs 0-3);
    /// with REX they address the low bytes (SPL/BPL/SIL/DIL, R8B-R15B).
    fn read_r8(&self, idx: usize) -> u64 {
        if !self.cur_rex && idx >= 4 {
            (self.regs[idx - 4] >> 8) & 0xFF
        } else {
            self.regs[idx] & 0xFF
        }
    }

    /// 8-bit register write honoring the no-REX high-byte rule (see above).
    fn write_r8(&mut self, idx: usize, val: u64) {
        if !self.cur_rex && idx >= 4 {
            let b = idx - 4;
            self.regs[b] = (self.regs[b] & !0xFF00) | ((val & 0xFF) << 8);
        } else {
            self.regs[idx] = (self.regs[idx] & !0xFF) | (val & 0xFF);
        }
    }

    fn read_rm(&self, is_reg: bool, rm: usize, ea: u64, width: u32) -> Result<u64, String> {
        if is_reg {
            Ok(match width {
                8 => self.read_r8(rm),
                16 => self.regs[rm] & 0xFFFF,
                32 => self.regs[rm] & 0xFFFF_FFFF,
                64 => self.regs[rm],
                _ => return Err("bad width".to_string()),
            })
        } else {
            Ok(match width {
                8 => self.read_u8(ea)? as u64,
                16 => self.read_u16(ea)? as u64,
                32 => self.read_u32(ea)? as u64,
                64 => self.read_u64(ea)?,
                _ => return Err("bad width".to_string()),
            })
        }
    }

    fn write_rm(
        &mut self,
        is_reg: bool,
        rm: usize,
        ea: u64,
        width: u32,
        val: u64,
    ) -> Result<(), String> {
        if is_reg {
            match width {
                8 => {
                    self.write_r8(rm, val);
                }
                16 => {
                    // 16-bit writes preserve the upper bits (no zero-extension)
                    self.regs[rm] = (self.regs[rm] & !0xFFFF) | (val & 0xFFFF);
                }
                32 => {
                    self.regs[rm] = val & 0xFFFF_FFFF; // zero-extend
                }
                64 => {
                    self.regs[rm] = val;
                }
                _ => return Err("bad width".to_string()),
            }
            Ok(())
        } else {
            match width {
                8 => self.write_u8(ea, val as u8),
                16 => self.write_u16(ea, val as u16),
                32 => self.write_u32(ea, val as u32),
                64 => self.write_u64(ea, val),
                _ => Err("bad width".to_string()),
            }
        }
    }

    // ---------- single step ----------
    pub fn step(&mut self) -> Result<StepResult, String> {
        let max = max_steps();
        if self.steps >= max {
            return Err(format!(
                "execution step limit exceeded ({max} steps; raise WINCLI_MAX_STEPS?)"
            ));
        }
        self.steps += 1;
        let ip = self.rip;
        self.seg_gs = false;
        // prefixes
        let mut off = 0usize;
        let mut rex_w = false;
        let mut rex_r = false;
        let mut rex_x = false;
        let mut rex_b = false;
        let mut rex_present = false;
        let mut opsz16 = false;
        let mut rep = false;
        let mut repne = false;
        loop {
            let b = self.read_u8(ip + off as u64)?;
            if (0x40..=0x4F).contains(&b) {
                rex_present = true;
                rex_w = b & 8 != 0;
                rex_r = b & 4 != 0;
                rex_x = b & 2 != 0;
                rex_b = b & 1 != 0;
                off += 1;
                if off > 1 {
                    // only one REX expected; keep last
                }
            } else if b == 0x66 {
                opsz16 = true; // repeatable; 16-bit only for whitelisted ops below
                off += 1;
            } else if b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 {
                // CS/DS/ES/SS overrides are no-ops in the flat 64-bit model
                // (appear in rustc alignment padding)
                off += 1;
            } else if b == 0x64 {
                return Err(format!(
                    "unsupported FS segment access at 0x{ip:016x} (thread-local storage)"
                ));
            } else if b == 0x65 {
                // GS override: TEB/TLS access, folded in by decode_modrm.
                self.seg_gs = true;
                off += 1;
            } else if b == 0xF0 {
                // LOCK is a no-op in the single-threaded guest model
                off += 1;
            } else if b == 0xF2 {
                // REPNE: only PSHUFLW (F2 0F 70) is implemented; string ops
                // fail clearly below.
                repne = true;
                off += 1;
            } else if b == 0xF3 {
                // REP/REPE: string ops fail clearly below unless consumed as
                // an SSE-move alias (movdqu) or PAUSE.
                rep = true;
                off += 1;
            } else {
                break;
            }
        }
        self.cur_rex = rex_present;
        let op = self.read_u8(ip + off as u64)?;
        // REP is only meaningful on string ops (below), PAUSE (F3 90),
        // and the SSE-move aliases (F3 0F 10/11/...).
        if rep && !matches!(op, 0x90 | 0x0F | 0xA4 | 0xA5 | 0xAA | 0xAB | 0xAC | 0xAD) {
            return Err(format!(
                "unsupported REP string op 0x{op:02X} at 0x{ip:016x}"
            ));
        }
        if repne && op != 0x0F {
            return Err(format!("unsupported REPNE prefix at 0x{ip:016x}"));
        }
        let w: u32 = if rex_w {
            64
        } else if opsz16 {
            // 16-bit operand size: only TEST/MOV/NOP are implemented; the rest
            // fail clearly in the match arms via the gate below.
            16
        } else {
            32
        };
        if w == 16
            && matches!(
                op,
                0x50..=0x5F
                    | 0x63
                    | 0x68
                    | 0x6A
                    | 0x86
                    | 0x87
                    | 0x8D
                    | 0xC0
                    | 0xC1
                    | 0xC6
                    | 0xD1
                    | 0xD3
                    | 0x05
                    | 0x2D
                    | 0x35
                    | 0x3D
                    | 0x0D
                    | 0x25
            )
        {
            return Err(format!(
                "unsupported 16-bit opcode 0x{op:02X} at 0x{ip:016x}"
            ));
        }

        // two-byte opcodes
        if op == 0x0F {
            let op2 = self.read_u8(ip + off as u64 + 1)?;
            if rep
                && !matches!(
                    op2,
                    0x10 | 0x11
                        | 0x28
                        | 0x29
                        | 0x6E
                        | 0x6F
                        | 0x70
                        | 0x7E
                        | 0x7F
                        | 0xBC
                        | 0xBD
                        | 0xD6
                )
            {
                return Err(format!(
                    "unsupported REP-prefixed opcode 0F {op2:02X} at 0x{ip:016x}"
                ));
            }
            if repne
                && !matches!(
                    op2,
                    0x70 | 0x10 | 0x11 | 0x2A | 0x58 | 0x59 | 0x5C | 0x5E | 0xC2
                )
            {
                return Err(format!(
                    "unsupported REPNE/F2-prefixed opcode 0F {op2:02X} at 0x{ip:016x}"
                ));
            }
            if (0x80..=0x8F).contains(&op2) {
                let disp = self.read_u32(ip + off as u64 + 2)? as i32 as i64;
                let next = ip + off as u64 + 6;
                let cond = op2 & 0xF;
                if self.jcc_taken(cond)? {
                    self.rip = next.wrapping_add(disp as u64);
                } else {
                    self.rip = next;
                }
                return Ok(StepResult::Continue);
            }
            if op2 == 0x50 {
                // MOVMSKPS r32, xmm: collect the sign bit from each packed
                // single-precision lane.  This is commonly emitted by SIMD
                // text/search code (including ripgrep's JSON output path).
                // The source must be an XMM register; a memory form is #UD.
                let (reg, is_reg, rm, _, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                if !is_reg {
                    return Err(format!("invalid MOVMSKPS memory source at 0x{ip:016x}"));
                }
                let lanes = self.xmm[rm].to_le_bytes();
                let mut mask = 0u64;
                for lane in 0..4 {
                    mask |= (((lanes[lane * 4 + 3] >> 7) & 1) as u64) << lane;
                }
                // Like every 32-bit GPR write in long mode, clear the high
                // half of the destination register.
                self.regs[reg] = mask;
                self.rip = ip + (off + 2 + ml) as u64;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF {
                // movzx/movsx r, r/m8(16). A 0x66 prefix would narrow the
                // destination to 16 bits; refuse rather than mis-emulate.
                if opsz16 {
                    return Err(format!("unsupported 16-bit movzx at 0x{ip:016x}"));
                }
                let signed = op2 == 0xBE || op2 == 0xBF;
                let srcw = if op2 == 0xB6 || op2 == 0xBE { 8 } else { 16 };
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let ea = if rm == 0x100 {
                    let next = ip + (off + 2 + ml) as u64;
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let v = if is_reg {
                    if srcw == 8 {
                        self.read_r8(rm)
                    } else {
                        // 16-bit register read: low 16 of reg (ignore REX subtleties)
                        self.regs[rm] & 0xFFFF
                    }
                } else {
                    if srcw == 8 {
                        self.read_u8(ea)? as u64
                    } else {
                        self.read_u16(ea)? as u64
                    }
                };
                // dest width: w (32/64); zero-extend (sign-extend for movsx)
                if w == 64 {
                    self.regs[reg] = if signed {
                        if srcw == 8 {
                            (v as u8 as i8 as i64) as u64
                        } else {
                            (v as u16 as i16 as i64) as u64
                        }
                    } else {
                        v
                    };
                } else if signed {
                    let s = if srcw == 8 {
                        (v as u8 as i8 as i32) as u64
                    } else {
                        (v as u16 as i16 as i32) as u64
                    };
                    self.regs[reg] = s & 0xFFFF_FFFF;
                } else {
                    self.regs[reg] = v & 0xFFFF_FFFF;
                }
                self.rip = ip + (off + 2 + ml) as u64;
                return Ok(StepResult::Continue);
            }
            if repne && matches!(op2, 0x10 | 0x11 | 0x2A | 0x58 | 0x59 | 0x5C | 0x5E | 0xC2) {
                // Scalar-double family (F2-mandatory): MOVSD/ADDSD/SUBSD/
                // MULSD/DIVSD/CMPLTSD. Rust f64 ops lower to the same
                // instructions, so results are bit-identical. Upper lanes:
                // loads zero them, arithmetic preserves them.
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let lane = |v: u128| f64::from_bits((v & 0xFFFF_FFFF_FFFF_FFFF) as u64);
                match op2 {
                    0x10 => {
                        if is_reg {
                            let s = self.xmm[rm];
                            self.xmm[reg] = (self.xmm[reg] & !0xFFFF_FFFF_FFFF_FFFF)
                                | (s & 0xFFFF_FFFF_FFFF_FFFF);
                        } else {
                            self.xmm[reg] = self.read_u64(ea)? as u128;
                        }
                    }
                    0x11 => {
                        if is_reg {
                            return Err(format!("unsupported MOVSS reg form at 0x{ip:016x}"));
                        }
                        self.write_u64(ea, (self.xmm[reg] & 0xFFFF_FFFF_FFFF_FFFF) as u64)?;
                    }
                    0x58 | 0x59 | 0x5C | 0x5E => {
                        let a = lane(self.xmm[reg]);
                        let b = if is_reg {
                            lane(self.xmm[rm])
                        } else {
                            f64::from_bits(self.read_u64(ea)?)
                        };
                        let r = match op2 {
                            0x58 => a + b,
                            0x59 => a * b,
                            0x5C => a - b,
                            _ => a / b,
                        };
                        self.xmm[reg] =
                            (self.xmm[reg] & !0xFFFF_FFFF_FFFF_FFFF) | r.to_bits() as u128;
                    }
                    0x2A => {
                        // CVTSI2SD xmm, r/m32/64 (int64 with REX.W).
                        // Host `as` lowers to the same instruction.
                        let v: i64 = if rex_w {
                            self.read_rm(is_reg, rm, ea, 64)? as i64
                        } else {
                            self.read_rm(is_reg, rm, ea, 32)? as u32 as i32 as i64
                        };
                        let r = v as f64;
                        self.xmm[reg] =
                            (self.xmm[reg] & !0xFFFF_FFFF_FFFF_FFFF) | r.to_bits() as u128;
                    }
                    _ => {
                        // CMPLTSD-style imm8 predicate -> low-qword mask,
                        // upper lanes preserved.
                        let imm = self.read_u8(ip + (off + 2 + ml) as u64)?;
                        let next = ip + (off + 2 + ml + 1) as u64;
                        let ea = if rm == 0x100 {
                            next.wrapping_add(ea_raw)
                        } else {
                            ea_raw
                        };
                        let a = lane(self.xmm[reg]);
                        let b = if is_reg {
                            lane(self.xmm[rm])
                        } else {
                            f64::from_bits(self.read_u64(ea)?)
                        };
                        let ord = a.partial_cmp(&b);
                        let hit = match imm {
                            0 => ord == Some(std::cmp::Ordering::Equal),
                            1 => ord == Some(std::cmp::Ordering::Less),
                            2 => matches!(
                                ord,
                                Some(std::cmp::Ordering::Less) | Some(std::cmp::Ordering::Equal)
                            ),
                            3 => ord.is_none(),
                            4 => ord.is_some() && ord != Some(std::cmp::Ordering::Equal),
                            5 => ord.is_none() || ord == Some(std::cmp::Ordering::Greater),
                            6 => ord.is_none() || ord != Some(std::cmp::Ordering::Less),
                            7 => ord.is_some(),
                            _ => {
                                return Err(format!(
                                    "unsupported CMPSD predicate {imm} at 0x{ip:016x}"
                                ))
                            }
                        };
                        let mask = if hit { 0xFFFF_FFFF_FFFF_FFFFu64 } else { 0 };
                        self.xmm[reg] = (self.xmm[reg] & !0xFFFF_FFFF_FFFF_FFFF) | mask as u128;
                        self.rip = next;
                        return Ok(StepResult::Continue);
                    }
                }
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if opsz16 && matches!(op2, 0x58 | 0x59 | 0x5C | 0x5E) {
                // Packed-double family (66-mandatory): ADDPD/MULPD/SUBPD/
                // DIVPD. Per-lane host f64 ops, bit-identical under the
                // default MXCSR (same rationale as the scalar-double arm).
                // No flags. Plain (packed-single) and F3 (scalar-single)
                // spellings keep failing clearly below/above.
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.xmm[reg].to_le_bytes();
                let b: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let mut o = [0u8; 16];
                for i in 0..2 {
                    let x = f64::from_le_bytes(a[8 * i..8 * i + 8].try_into().unwrap());
                    let y = f64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
                    let r = match op2 {
                        0x58 => x + y,
                        0x59 => x * y,
                        0x5C => x - y,
                        _ => x / y,
                    };
                    o[8 * i..8 * i + 8].copy_from_slice(&r.to_le_bytes());
                }
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x2E {
                // UCOMISD xmm, xmm/m64 (66-mandatory; plain is single-prec).
                if !opsz16 {
                    return Err(format!("unsupported COMISS at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = f64::from_bits((self.xmm[reg] & 0xFFFF_FFFF_FFFF_FFFF) as u64);
                let b = if is_reg {
                    f64::from_bits((self.xmm[rm] & 0xFFFF_FFFF_FFFF_FFFF) as u64)
                } else {
                    f64::from_bits(self.read_u64(ea)?)
                };
                // ZF/PF/CF only (gt:000 lt:001 eq:100 unord:111); SF/OF/AF untouched.
                match a.partial_cmp(&b) {
                    None => {
                        self.zf = true;
                        self.pf = true;
                        self.cf = true;
                    }
                    Some(std::cmp::Ordering::Less) => {
                        self.zf = false;
                        self.pf = false;
                        self.cf = true;
                    }
                    Some(std::cmp::Ordering::Equal) => {
                        self.zf = true;
                        self.pf = false;
                        self.cf = false;
                    }
                    Some(std::cmp::Ordering::Greater) => {
                        self.zf = false;
                        self.pf = false;
                        self.cf = false;
                    }
                }
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x54 || op2 == 0x55 || op2 == 0x56 {
                // ANDPD/ANDNPD/ORPD (66-mandatory). Bitwise, no flags.
                if !opsz16 {
                    return Err(format!(
                        "unsupported MMX opcode 0F {op2:02X} at 0x{ip:016x}"
                    ));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let b = if is_reg {
                    self.xmm[rm]
                } else {
                    self.read_u128(ea)?
                };
                self.xmm[reg] = match op2 {
                    0x54 => self.xmm[reg] & b,
                    0x55 => !self.xmm[reg] & b,
                    _ => self.xmm[reg] | b,
                };
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if matches!(
                op2,
                0x10 | 0x11
                    | 0x28
                    | 0x29
                    | 0x57
                    | 0x6E
                    | 0x6F
                    | 0x7E
                    | 0x7F
                    | 0xD6
                    | 0xDB
                    | 0xDF
                    | 0xEB
                    | 0xEF
            ) {
                // Packed moves / xors. Bitwise only: no flags, no FP, no
                // MXCSR, no alignment faulting (guests are compiler-aligned).
                // A 0x66 prefix selects the unaligned/double/integer spellings
                // (movdqu/movdqa/xorpd/pxor/movd/movq), which behave
                // identically under those simplifications.
                // (Demanded by rustc memset expansion + real binaries.)
                // F2 forms are scalar-double (own arm above) or PSHUFLW;
                // anything else with F2 is undefined.
                if repne {
                    return Err(format!(
                        "unsupported F2-prefixed opcode 0F {op2:02X} at 0x{ip:016x}"
                    ));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                match op2 {
                    0x10 | 0x28 | 0x6F => {
                        // movups/movaps/movdqa xmm, xmm/m128. F3 selects
                        // scalar MOVSS (low 32 bits, high zeroed).
                        if rep && op2 == 0x10 {
                            let v: u64 = if is_reg {
                                (self.xmm[rm] & 0xFFFF_FFFF) as u64
                            } else {
                                self.read_u32(ea)? as u64
                            };
                            self.xmm[reg] = v as u128;
                        } else {
                            self.xmm[reg] = if is_reg {
                                self.xmm[rm]
                            } else {
                                self.read_u128(ea)?
                            };
                        }
                    }
                    0x11 | 0x29 | 0x7F => {
                        // movups/movaps/movdqa xmm/m128, xmm. F3 selects
                        // scalar MOVSS m32, xmm (reg-reg form is #UD).
                        if rep && op2 == 0x11 {
                            if is_reg {
                                return Err(format!("invalid MOVSS reg-reg store at 0x{ip:016x}"));
                            }
                            let v = (self.xmm[reg] & 0xFFFF_FFFF) as u32;
                            self.write_u32(ea, v)?;
                        } else if is_reg {
                            self.xmm[rm] = self.xmm[reg];
                        } else {
                            self.write_u128(ea, self.xmm[reg])?;
                        }
                    }
                    0x57 | 0xEF => {
                        // xorps/pxor xmm, xmm/m128
                        let b = if is_reg {
                            self.xmm[rm]
                        } else {
                            self.read_u128(ea)?
                        };
                        self.xmm[reg] ^= b;
                    }
                    0xDB | 0xDF | 0xEB => {
                        // PAND/PANDN/POR (66-mandatory; plain is MMX).
                        if !opsz16 {
                            return Err(format!(
                                "unsupported MMX opcode 0F {op2:02X} at 0x{ip:016x}"
                            ));
                        }
                        let b = if is_reg {
                            self.xmm[rm]
                        } else {
                            self.read_u128(ea)?
                        };
                        self.xmm[reg] = match op2 {
                            0xDB => self.xmm[reg] & b,
                            0xDF => !self.xmm[reg] & b,
                            _ => self.xmm[reg] | b,
                        };
                    }
                    0x6E => {
                        // movd xmm, r/m32 (movq with REX.W); zero-extends
                        if rex_w {
                            let v = self.read_rm(is_reg, rm, ea, 64)?;
                            self.xmm[reg] = v as u128;
                        } else {
                            let v = self.read_rm(is_reg, rm, ea, 32)?;
                            self.xmm[reg] = v as u128;
                        }
                    }
                    0x7E => {
                        if rep {
                            // F3 0F 7E: MOVQ xmm, xmm/m64 (load, low qword;
                            // high zeroed). REX.W is ignored (fixed 64-bit);
                            // REX.R/B still extend registers via decode.
                            let v: u64 = if is_reg {
                                (self.xmm[rm] & 0xFFFF_FFFF_FFFF_FFFF) as u64
                            } else {
                                self.read_u64(ea)?
                            };
                            self.xmm[reg] = v as u128;
                        } else if rex_w {
                            // movq m64, xmm (low qword)
                            let v = (self.xmm[reg] & 0xFFFF_FFFF_FFFF_FFFF) as u64;
                            if is_reg {
                                self.regs[rm] = v;
                            } else {
                                self.write_u64(ea, v)?;
                            }
                        } else {
                            // movd r/m32, xmm (low dword)
                            let v = (self.xmm[reg] & 0xFFFF_FFFF) as u64;
                            self.write_rm(is_reg, rm, ea, 32, v)?;
                        }
                    }
                    0xD6 => {
                        // movq xmm/m64, xmm (low qword; 66-mandatory).
                        // F3 form is MOVQ2DQ (different op): fail clearly.
                        if rep {
                            return Err(format!("unsupported MOVQ2DQ (F3 0F D6) at 0x{ip:016x}"));
                        }
                        if !opsz16 {
                            return Err(format!("unsupported MMX opcode 0F D6 at 0x{ip:016x}"));
                        }
                        let v = (self.xmm[reg] & 0xFFFF_FFFF_FFFF_FFFF) as u64;
                        if is_reg {
                            self.xmm[rm] = v as u128;
                        } else {
                            self.write_u64(ea, v)?;
                        }
                    }
                    _ => unreachable!(),
                }
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if (0x90..=0x9F).contains(&op2) {
                // SETcc r/m8 (demanded by rustc bool materialization, e.g. SETNZ).
                // ModRM.reg is ignored by hardware; the condition is op2 & 0xF.
                let (_, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let v = if self.jcc_taken(op2 & 0xF)? { 1 } else { 0 };
                self.write_rm(is_reg, rm, ea, 8, v)?;
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x1F {
                // Multi-byte NOP Ev (rustc alignment padding). Decode the
                // operand only to advance RIP; no other effect. /0 required.
                let (reg_field, _, _, _, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                if reg_field != 0 {
                    return Err(format!("unsupported 0F 1F /{reg_field} at 0x{ip:016x}"));
                }
                self.rip = ip + (off + 2 + ml) as u64;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xA2 {
                // CPUID: advertise exactly the emulated ISA subset so guests
                // pick scalar/SSE2 code paths (no SSE3+, no AVX).
                let leaf = self.regs[0] as u32;
                let sub = self.regs[1] as u32;
                let (a, b, c, d) = cpuid(leaf, sub);
                self.regs[0] = a as u64;
                self.regs[1] = b as u64;
                self.regs[2] = c as u64;
                self.regs[3] = d as u64;
                self.rip = ip + off as u64 + 2; // 0F A2 has no ModRM
                return Ok(StepResult::Continue);
            }
            if op2 == 0xAF {
                // IMUL r, r/m (demanded by real binaries). Truncated to
                // width; CF=OF iff the full product doesn't fit signed width.
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.read_rm(is_reg, rm, ea, w)?;
                let b = match w {
                    64 => self.regs[reg],
                    32 => self.regs[reg] & 0xFFFF_FFFF,
                    _ => self.regs[reg] & 0xFFFF,
                };
                let (trunc, of) = match w {
                    64 => {
                        let r = (a as i64 as i128) * (b as i64 as i128);
                        ((r as u64), r < i64::MIN as i128 || r > i64::MAX as i128)
                    }
                    32 => {
                        let r = (a as u32 as i32 as i64) * (b as u32 as i32 as i64);
                        (
                            (r as u32) as u64,
                            r < i32::MIN as i64 || r > i32::MAX as i64,
                        )
                    }
                    _ => {
                        let r = (a as u16 as i16 as i32) * (b as u16 as i16 as i32);
                        (
                            (r as u16) as u64,
                            r < i16::MIN as i32 || r > i16::MAX as i32,
                        )
                    }
                };
                self.cf = of;
                self.of = of;
                self.zf = false;
                self.sf = false;
                self.write_rm(true, reg, 0, w, trunc)?;
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x14 {
                // UNPCKLPS xmm, xmm/m128 (prefix-less; 66 is UNPCKLPD).
                // Interleaves low single-precision lanes, bitwise.
                if opsz16 || rep || repne {
                    return Err(format!("unsupported prefixed 0F 14 at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let d = self.xmm[reg].to_le_bytes();
                let s: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let mut o = [0u8; 16];
                o[0..4].copy_from_slice(&d[0..4]);
                o[4..8].copy_from_slice(&s[0..4]);
                o[8..12].copy_from_slice(&d[8..12]);
                o[12..16].copy_from_slice(&s[8..12]);
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x15 {
                // UNPCKHPD xmm, xmm/m128 (66-mandatory; plain is UNPCKHPS).
                // Interleaves high qwords, bitwise.
                if !opsz16 || rep || repne {
                    return Err(format!("unsupported non-HPD 0F 15 at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let d = self.xmm[reg].to_le_bytes();
                let s: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let mut o = [0u8; 16];
                o[0..8].copy_from_slice(&d[8..16]);
                o[8..16].copy_from_slice(&s[8..16]);
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x70 {
                // PSHUFD (66) / PSHUFLW (F2) / PSHUFHW (F3): shuffle
                // 32-bit lanes / low words / high words by imm8.
                if !opsz16 && !rep && !repne {
                    return Err(format!("unsupported prefix-less 0F 70 at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let imm = self.read_u8(ip + (off + 2 + ml) as u64)?;
                let next = ip + (off + 2 + ml + 1) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let s: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let lane = |i: usize| {
                    u32::from_le_bytes([s[4 * i], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3]])
                };
                let word = |i: usize| u16::from_le_bytes([s[2 * i], s[2 * i + 1]]);
                let mut o = [0u8; 16];
                if repne {
                    // PSHUFLW: shuffle low 4 words, high qword unchanged
                    for i in 0..4 {
                        let w = word(((imm >> (2 * i)) & 3) as usize);
                        o[2 * i..2 * i + 2].copy_from_slice(&w.to_le_bytes());
                    }
                    o[8..16].copy_from_slice(&s[8..16]);
                } else if rep {
                    // PSHUFHW: shuffle high 4 words, low qword unchanged
                    o[0..8].copy_from_slice(&s[0..8]);
                    for i in 0..4 {
                        let w = word(4 + ((imm >> (2 * i)) & 3) as usize);
                        o[8 + 2 * i..8 + 2 * i + 2].copy_from_slice(&w.to_le_bytes());
                    }
                } else {
                    // PSHUFD: shuffle 32-bit lanes
                    for i in 0..4 {
                        let l = lane(((imm >> (2 * i)) & 3) as usize);
                        o[4 * i..4 * i + 4].copy_from_slice(&l.to_le_bytes());
                    }
                }
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x71 {
                // 66 0F 71 /2,/4,/6 ib: PSRLW/PSRAW/PSLLW xmm, imm8.
                // These packed-word shifts are used beside MOVMSKPS by
                // vectorized formatting code. The ModRM r/m operand is the
                // destination; ModRM.reg selects the operation.
                if !opsz16 || rep || repne {
                    return Err(format!("unsupported MMX opcode 0F 71 at 0x{ip:016x}"));
                }
                let (group, is_reg, rm, _, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                if !is_reg || !matches!(group, 2 | 4 | 6) {
                    return Err(format!(
                        "unsupported packed-word shift /{group} at 0x{ip:016x}"
                    ));
                }
                let count = self.read_u8(ip + (off + 2 + ml) as u64)? as u32;
                let input = self.xmm[rm].to_le_bytes();
                let mut out = [0u8; 16];
                for lane in 0..8 {
                    let start = lane * 2;
                    let value = u16::from_le_bytes(input[start..start + 2].try_into().unwrap());
                    let shifted = match group {
                        2 => {
                            if count >= 16 {
                                0
                            } else {
                                value >> count
                            }
                        }
                        4 => {
                            if count >= 16 {
                                if value & 0x8000 != 0 {
                                    u16::MAX
                                } else {
                                    0
                                }
                            } else {
                                ((value as i16) >> count) as u16
                            }
                        }
                        _ => {
                            if count >= 16 {
                                0
                            } else {
                                value << count
                            }
                        }
                    };
                    out[start..start + 2].copy_from_slice(&shifted.to_le_bytes());
                }
                self.xmm[rm] = u128::from_le_bytes(out);
                self.rip = ip + (off + 2 + ml + 1) as u64;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x74 || op2 == 0x75 || op2 == 0x76 {
                // PCMPEQB/W/D: per-lane equality masks (plain forms are MMX).
                if !opsz16 {
                    return Err(format!(
                        "unsupported MMX opcode 0F {op2:02X} at 0x{ip:016x}"
                    ));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.xmm[reg].to_le_bytes();
                let b: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let (lanes, bits) = match op2 {
                    0x74 => (16, 8),
                    0x75 => (8, 16),
                    _ => (4, 32),
                };
                let mut o = [0u8; 16];
                for i in 0..lanes {
                    let n = bits / 8;
                    let eq = a[i * n..(i + 1) * n] == b[i * n..(i + 1) * n];
                    let fill = if eq { 0xFF } else { 0x00 };
                    for j in 0..n {
                        o[i * n + j] = fill;
                    }
                }
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xC6 {
                // SHUFPS (no prefix, 32-bit lanes) vs SHUFPD (0x66, 64-bit
                // lanes: dest[63:0] = imm0 ? src : dst, same for high half).
                // Bitwise only, no FP.
                let shufpd = opsz16;
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let imm = self.read_u8(ip + (off + 2 + ml) as u64)?;
                let next = ip + (off + 2 + ml + 1) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.xmm[reg].to_le_bytes();
                let b: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let lane_a = |i: usize| {
                    u32::from_le_bytes([a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]])
                };
                let lane_b = |i: usize| {
                    u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
                };
                let mut o = [0u8; 16];
                if shufpd {
                    if imm & 1 != 0 {
                        o[0..8].copy_from_slice(&b[0..8]);
                    } else {
                        o[0..8].copy_from_slice(&a[0..8]);
                    }
                    if imm & 2 != 0 {
                        o[8..16].copy_from_slice(&b[8..16]);
                    } else {
                        o[8..16].copy_from_slice(&a[8..16]);
                    }
                } else {
                    for i in 0..2 {
                        let l = lane_a(((imm >> (2 * i)) & 3) as usize);
                        o[4 * i..4 * i + 4].copy_from_slice(&l.to_le_bytes());
                    }
                    for i in 2..4 {
                        let l = lane_b(((imm >> (2 * i)) & 3) as usize);
                        o[4 * i..4 * i + 4].copy_from_slice(&l.to_le_bytes());
                    }
                }
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xC4 {
                // PINSRW xmm, r32/m16, imm8: dest word lane (imm & 3) =
                // src low word. Plain form is MMX (unsupported).
                if !opsz16 {
                    return Err(format!("unsupported MMX opcode 0F C4 at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let imm = self.read_u8(ip + (off + 2 + ml) as u64)?;
                let next = ip + (off + 2 + ml + 1) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let w: u16 = if is_reg {
                    (self.regs[rm] & 0xFFFF) as u16
                } else {
                    self.read_u16(ea)?
                };
                let mut o = self.xmm[reg].to_le_bytes();
                let lane = (imm & 3) as usize;
                o[2 * lane..2 * lane + 2].copy_from_slice(&w.to_le_bytes());
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xC5 {
                // PEXTRW r32, xmm, imm8: extract one 16-bit lane into a
                // zero-extended general-purpose register. Rust's vectorized
                // directory-filtering path uses this after byte compares.
                if !opsz16 || rep || repne {
                    return Err(format!("unsupported MMX opcode 0F C5 at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, _, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                if !is_reg {
                    return Err(format!("invalid PEXTRW memory source at 0x{ip:016x}"));
                }
                let lane = (self.read_u8(ip + (off + 2 + ml) as u64)? & 7) as usize;
                let bytes = self.xmm[rm].to_le_bytes();
                self.regs[reg] = u16::from_le_bytes([bytes[lane * 2], bytes[lane * 2 + 1]]) as u64;
                self.rip = ip + (off + 2 + ml + 1) as u64;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xF8 || op2 == 0xF9 || op2 == 0xFA || op2 == 0xFB {
                // PSUBB/W/D/Q xmm, xmm/m128: wrapping lane subtract.
                // Plain forms need 66 in 64-bit mode (MMX otherwise).
                if !opsz16 {
                    return Err(format!(
                        "unsupported MMX opcode 0F {op2:02X} at 0x{ip:016x}"
                    ));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.xmm[reg].to_le_bytes();
                let b: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let (lanes, n) = match op2 {
                    0xF8 => (16, 1),
                    0xF9 => (8, 2),
                    0xFA => (4, 4),
                    _ => (2, 8),
                };
                let mut o = [0u8; 16];
                for i in 0..lanes {
                    let mut av = 0u64;
                    let mut bv = 0u64;
                    for j in 0..n {
                        av |= (a[i * n + j] as u64) << (8 * j);
                        bv |= (b[i * n + j] as u64) << (8 * j);
                    }
                    let r = av.wrapping_sub(bv);
                    for j in 0..n {
                        o[i * n + j] = (r >> (8 * j)) as u8;
                    }
                }
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xD4 {
                // PADDQ xmm, xmm/m128: wrapping addition of the two packed
                // 64-bit lanes.  Rust's SIMD search/formatting paths use
                // this to advance vectorized counters.
                if !opsz16 || rep || repne {
                    return Err(format!("unsupported MMX opcode 0F D4 at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.xmm[reg].to_le_bytes();
                let b: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let mut out = [0u8; 16];
                for lane in 0..2 {
                    let start = lane * 8;
                    let left = u64::from_le_bytes(a[start..start + 8].try_into().unwrap());
                    let right = u64::from_le_bytes(b[start..start + 8].try_into().unwrap());
                    out[start..start + 8].copy_from_slice(&left.wrapping_add(right).to_le_bytes());
                }
                self.xmm[reg] = u128::from_le_bytes(out);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xFC || op2 == 0xFD || op2 == 0xFE {
                // PADDB/W/D xmm, xmm/m128: wrapping addition in byte, word,
                // or dword lanes. These are the companion operations to
                // PADDQ in compiler-generated SIMD search code.
                if !opsz16 || rep || repne {
                    return Err(format!(
                        "unsupported MMX opcode 0F {op2:02X} at 0x{ip:016x}"
                    ));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.xmm[reg].to_le_bytes();
                let b: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let lane_bytes = match op2 {
                    0xFC => 1,
                    0xFD => 2,
                    _ => 4,
                };
                let mut out = [0u8; 16];
                for lane in 0..16 / lane_bytes {
                    let start = lane * lane_bytes;
                    let mut left = 0u64;
                    let mut right = 0u64;
                    for byte in 0..lane_bytes {
                        left |= (a[start + byte] as u64) << (8 * byte);
                        right |= (b[start + byte] as u64) << (8 * byte);
                    }
                    let sum = left.wrapping_add(right);
                    for byte in 0..lane_bytes {
                        out[start + byte] = (sum >> (8 * byte)) as u8;
                    }
                }
                self.xmm[reg] = u128::from_le_bytes(out);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xF6 {
                // PSADBW xmm, xmm/m128: sum the absolute unsigned-byte
                // differences in each eight-byte half into two 64-bit lanes.
                // This is a common primitive in SIMD byte-search code.
                if !opsz16 || rep || repne {
                    return Err(format!("unsupported MMX opcode 0F F6 at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.xmm[reg].to_le_bytes();
                let b: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let mut sums = [0u64; 2];
                for i in 0..16 {
                    sums[i / 8] += (a[i] as i16 - b[i] as i16).unsigned_abs() as u64;
                }
                self.xmm[reg] = (sums[0] as u128) | ((sums[1] as u128) << 64);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if (0xC8..=0xCF).contains(&op2) {
                // BSWAP r32/r64: register is in the opcode, no ModRM.
                let r = (((rex_b as u8) << 3) | (op2 & 7)) as usize;
                if rex_w {
                    self.regs[r] = self.regs[r].swap_bytes();
                } else {
                    self.regs[r] = (self.regs[r] as u32).swap_bytes() as u64;
                }
                self.rip = ip + off as u64 + 2;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xD7 {
                // PMOVMSKB r32, xmm/m128 (plain form is MMX).
                if !opsz16 {
                    return Err(format!("unsupported MMX opcode 0F D7 at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let v: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let mut mask = 0u32;
                for i in 0..16 {
                    if v[i] & 0x80 != 0 {
                        mask |= 1 << i;
                    }
                }
                self.regs[reg] = mask as u64; // r32: zero-extended
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if matches!(op2, 0x60 | 0x61 | 0x62 | 0x68 | 0x69 | 0x6A | 0x6C) {
                // PUNPCKLBW/HBW (bytes->words), PUNPCKLWD/HWD (words->dwords),
                // PUNPCKLDQ/HDQ (dwords->qwords), and PUNPCKLQDQ (low
                // qwords). All require the 0x66 prefix (plain forms are MMX).
                if !opsz16 {
                    return Err(format!(
                        "unsupported MMX opcode 0F {op2:02X} at 0x{ip:016x}"
                    ));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.xmm[reg].to_le_bytes();
                let b: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let mut o = [0u8; 16];
                if op2 == 0x60 || op2 == 0x68 {
                    let base = if op2 == 0x60 { 0 } else { 8 };
                    for i in 0..8 {
                        o[2 * i] = a[base + i];
                        o[2 * i + 1] = b[base + i];
                    }
                } else if op2 == 0x61 || op2 == 0x69 {
                    let base = if op2 == 0x61 { 0 } else { 8 };
                    for i in 0..4 {
                        o[4 * i..4 * i + 2].copy_from_slice(&a[base + 2 * i..base + 2 * i + 2]);
                        o[4 * i + 2..4 * i + 4].copy_from_slice(&b[base + 2 * i..base + 2 * i + 2]);
                    }
                } else if op2 == 0x62 || op2 == 0x6A {
                    let base = if op2 == 0x62 { 0 } else { 8 };
                    for i in 0..2 {
                        o[8 * i..8 * i + 4].copy_from_slice(&a[base + 4 * i..base + 4 * i + 4]);
                        o[8 * i + 4..8 * i + 8].copy_from_slice(&b[base + 4 * i..base + 4 * i + 4]);
                    }
                } else {
                    o[0..8].copy_from_slice(&a[0..8]);
                    o[8..16].copy_from_slice(&b[0..8]);
                }
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x67 {
                // PACKUSWB xmm, xmm/m128: signed words saturate to bytes
                // (low 8 of each operand). Plain form is MMX.
                if !opsz16 {
                    return Err(format!("unsupported MMX opcode 0F 67 at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.xmm[reg].to_le_bytes();
                let b: [u8; 16] = if is_reg {
                    self.xmm[rm].to_le_bytes()
                } else {
                    self.read_u128(ea)?.to_le_bytes()
                };
                let sat = |lo: u8, hi: u8| {
                    let v = i16::from_le_bytes([lo, hi]);
                    v.clamp(0, 255) as u8
                };
                let mut o = [0u8; 16];
                for i in 0..8 {
                    o[i] = sat(a[2 * i], a[2 * i + 1]);
                    o[8 + i] = sat(b[2 * i], b[2 * i + 1]);
                }
                self.xmm[reg] = u128::from_le_bytes(o);
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0x12 || op2 == 0x13 || op2 == 0x16 || op2 == 0x17 {
                // MOVLPS/MOVHPS (low/high qword). Loads merge (other half
                // preserved); stores write memory. 0x13/0x17 reg-reg is #UD.
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                if op2 == 0x12 || op2 == 0x16 {
                    let dest_base = if op2 == 0x12 { 0 } else { 8 };
                    let chunk: [u8; 8] = if is_reg {
                        let s = self.xmm[rm].to_le_bytes();
                        let source_base = if op2 == 0x12 { 8 } else { 0 };
                        s[source_base..source_base + 8].try_into().unwrap()
                    } else {
                        self.read_bytes(ea, 8)?.as_slice().try_into().unwrap()
                    };
                    let mut o = self.xmm[reg].to_le_bytes();
                    o[dest_base..dest_base + 8].copy_from_slice(&chunk);
                    self.xmm[reg] = u128::from_le_bytes(o);
                } else {
                    if is_reg {
                        return Err(format!(
                            "invalid MOVLPS/MOVHPS reg-reg store 0F {op2:02X} at 0x{ip:016x}"
                        ));
                    }
                    let base = if op2 == 0x13 { 0 } else { 8 };
                    let cur = self.xmm[reg].to_le_bytes();
                    self.write_bytes(ea, &cur[base..base + 8])?;
                }
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xC0 || op2 == 0xC1 {
                // XADD r/m, r: temp=dest; dest=src+dest; src=temp. LOCK ignored.
                let width: u32 = if op2 == 0xC0 { 8 } else { w };
                if width == 16 {
                    return Err(format!("unsupported 16-bit xadd at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let mask: u64 = match width {
                    64 => u64::MAX,
                    32 => 0xFFFF_FFFF,
                    _ => 0xFF,
                };
                let dst = self.read_rm(is_reg, rm, ea, width)? & mask;
                let src = match width {
                    64 => self.regs[reg],
                    32 => self.regs[reg] & 0xFFFF_FFFF,
                    16 => self.regs[reg] & 0xFFFF,
                    _ => self.read_r8(reg),
                };
                let res = dst.wrapping_add(src) & mask;
                self.set_add_flags(dst, src, res, width);
                self.write_rm(is_reg, rm, ea, width, res)?;
                self.write_rm(true, reg, 0, width, dst)?;
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xB0 || op2 == 0xB1 {
                // CMPXCHG r/m, r: temp=dest; ZF=(dest==rax); dest=ZF?src:dest;
                // rax=temp. LOCK ignored (single thread).
                let width: u32 = if op2 == 0xB0 { 8 } else { w };
                if width == 16 {
                    return Err(format!("unsupported 16-bit cmpxchg at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let mask: u64 = match width {
                    64 => u64::MAX,
                    32 => 0xFFFF_FFFF,
                    _ => 0xFF,
                };
                let dst = self.read_rm(is_reg, rm, ea, width)? & mask;
                let acc = self.regs[0] & mask;
                let src = match width {
                    64 => self.regs[reg],
                    32 => self.regs[reg] & 0xFFFF_FFFF,
                    16 => self.regs[reg] & 0xFFFF,
                    _ => self.read_r8(reg),
                };
                let res = dst.wrapping_sub(acc) & mask;
                self.set_sub_flags(dst, acc, res, width);
                if dst == acc {
                    self.write_rm(is_reg, rm, ea, width, src & mask)?;
                } else {
                    self.write_rm(true, 0, 0, width, dst)?;
                }
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xBC || op2 == 0xBD {
                // BSF/BSR, or TZCNT/LZCNT with F3. TZCNT/LZCNT counts are
                // well-defined for zero input (== width); plain BSF/BSR leave
                // dest unchanged on zero input (matching common usage).
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let mask: u64 = match w {
                    64 => u64::MAX,
                    32 => 0xFFFF_FFFF,
                    _ => 0xFFFF,
                };
                let v = self.read_rm(is_reg, rm, ea, w)? & mask;
                if rep {
                    let n = if op2 == 0xBC {
                        v.trailing_zeros().min(w)
                    } else {
                        (v << (64 - w)).leading_zeros().min(w)
                    };
                    self.zf = v == 0;
                    self.cf = v != 0;
                    self.write_rm(true, reg, 0, w, n as u64)?;
                } else if v == 0 {
                    self.zf = true;
                } else {
                    self.zf = false;
                    // position of lowest/highest set bit within width
                    let idx = if op2 == 0xBC {
                        v.trailing_zeros()
                    } else {
                        w - 1 - (v << (64 - w)).leading_zeros()
                    };
                    self.write_rm(true, reg, 0, w, idx as u64)?;
                }
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB {
                // BT/BTS/BTR/BTC r/m, r (demanded by rg's byte-to-bitmap loop:
                // bts rax,r9). CF = old bit; only CF changes. Register dest
                // masks the index; memory dest is a bit string (signed byte
                // offset from the base, bit = index mod 8).
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let idx = self.regs[reg];
                if is_reg {
                    let mask: u64 = match w {
                        64 => u64::MAX,
                        32 => 0xFFFF_FFFF,
                        _ => 0xFFFF,
                    };
                    let b = (idx & (w as u64 - 1)) as u32;
                    let v = self.regs[rm] & mask;
                    self.cf = ((v >> b) & 1) == 1;
                    let res = match op2 {
                        0xA3 => v,
                        0xAB => v | (1 << b),
                        0xB3 => v & !(1 << b),
                        _ => v ^ (1 << b),
                    };
                    if op2 != 0xA3 {
                        self.regs[rm] = res & mask;
                    }
                } else {
                    let off = idx as i64;
                    let addr = ea.wrapping_add(off.div_euclid(8) as u64);
                    let b = off.rem_euclid(8) as u32;
                    let v = self.read_u8(addr)? as u64;
                    self.cf = ((v >> b) & 1) == 1;
                    match op2 {
                        0xA3 => {}
                        0xAB => self.write_u8(addr, (v | (1 << b)) as u8)?,
                        0xB3 => self.write_u8(addr, (v & !(1 << b)) as u8)?,
                        _ => self.write_u8(addr, (v ^ (1 << b)) as u8)?,
                    }
                }
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if op2 == 0xBA {
                // Grp8 Ev,Ib: BT/BTS/BTR/BTC. Only CF is affected.
                let (reg_field, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let imm = self.read_u8(ip + (off + 2 + ml) as u64)? as u64;
                let next = ip + (off + 2 + ml + 1) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let mask: u64 = match w {
                    64 => u64::MAX,
                    32 => 0xFFFF_FFFF,
                    _ => 0xFFFF,
                };
                let idx = (imm & (w as u64 - 1)) as u32;
                let v = self.read_rm(is_reg, rm, ea, w)? & mask;
                self.cf = ((v >> idx) & 1) == 1;
                let res = match reg_field {
                    4 => v,               // BT: test only
                    5 => v | (1 << idx),  // BTS
                    6 => v & !(1 << idx), // BTR
                    7 => v ^ (1 << idx),  // BTC
                    _ => {
                        return Err(format!(
                            "unsupported Grp8 sub-op /{reg_field} at 0x{ip:016x}"
                        ))
                    }
                };
                if reg_field != 4 {
                    self.write_rm(is_reg, rm, ea, w, res & mask)?;
                }
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            if (0x40..=0x4F).contains(&op2) {
                // CMOVcc r, r/m (demanded by rustc branchless selects).
                // Flags untouched; 32-bit dest zero-extends, 16-bit preserves.
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 2, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 2 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                if self.jcc_taken(op2 & 0xF)? {
                    let v = self.read_rm(is_reg, rm, ea, w)?;
                    self.write_rm(true, reg, 0, w, v)?;
                }
                self.rip = next;
                return Ok(StepResult::Continue);
            }
            return Err(format!(
                "unsupported 2-byte opcode 0F {op2:02X} at 0x{ip:016x}"
            ));
        }

        // jcc rel8
        if (0x70..=0x7F).contains(&op) {
            let disp = self.read_u8(ip + off as u64 + 1)? as i8 as i64;
            let next = ip + off as u64 + 2;
            if self.jcc_taken(op & 0xF)? {
                self.rip = next.wrapping_add(disp as u64);
            } else {
                self.rip = next;
            }
            return Ok(StepResult::Continue);
        }

        match op {
            0xF8 => {
                // CLC
                self.cf = false;
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0xF9 => {
                // STC
                self.cf = true;
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0xFC => {
                // CLD
                self.df = false;
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0xFD => {
                // STD
                self.df = true;
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0x98 => {
                // CWDE: EAX = sign-extend(AX)
                self.regs[0] = (self.regs[0] as u16 as i16 as i32) as u64;
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0x99 => {
                // CDQ (CQO with REX.W): sign-extend EAX into EDX / RAX into RDX
                if rex_w {
                    self.regs[2] = (self.regs[0] as i64 >> 63) as u64;
                } else {
                    self.regs[2] = ((self.regs[0] as u32 as i32 >> 31) as u32) as u64;
                }
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0xA4 | 0xA5 | 0xAA | 0xAB | 0xAC | 0xAD => {
                // String ops (demanded by memset/memcpy lowering). Repeat RCX
                // times with REP, once otherwise. DF honored. No flag effects.
                let size: u64 = match op {
                    0xA4 | 0xAA | 0xAC => 1,
                    _ => {
                        if rex_w {
                            8
                        } else {
                            4
                        }
                    }
                };
                let mut n = if rep { self.regs[1] } else { 1 };
                // bound a single instruction to 256M elements (runaway guard)
                if n > 256 * 1024 * 1024 {
                    return Err(format!("string op count too large at 0x{ip:016x}"));
                }
                let step: i64 = if self.df { -(size as i64) } else { size as i64 };
                while n > 0 {
                    match op {
                        0xA4 | 0xA5 => {
                            // MOVS: [rdi] = [rsi]
                            let v = match size {
                                1 => self.read_u8(self.regs[6])? as u64,
                                4 => self.read_u32(self.regs[6])? as u64,
                                _ => self.read_u64(self.regs[6])?,
                            };
                            match size {
                                1 => self.write_u8(self.regs[7], v as u8)?,
                                4 => self.write_u32(self.regs[7], v as u32)?,
                                _ => self.write_u64(self.regs[7], v)?,
                            }
                            self.regs[6] = self.regs[6].wrapping_add(step as u64);
                            self.regs[7] = self.regs[7].wrapping_add(step as u64);
                        }
                        0xAA | 0xAB => {
                            // STOS: [rdi] = rax
                            match size {
                                1 => self.write_u8(self.regs[7], self.regs[0] as u8)?,
                                4 => self.write_u32(self.regs[7], self.regs[0] as u32)?,
                                _ => self.write_u64(self.regs[7], self.regs[0])?,
                            }
                            self.regs[7] = self.regs[7].wrapping_add(step as u64);
                        }
                        _ => {
                            // LODS: al/eax/rax = [rsi]
                            match size {
                                1 => {
                                    let v = self.read_u8(self.regs[6])?;
                                    self.regs[0] = (self.regs[0] & !0xFF) | v as u64;
                                }
                                4 => {
                                    let v = self.read_u32(self.regs[6])?;
                                    self.regs[0] = (self.regs[0] & !0xFFFF_FFFF) | v as u64;
                                }
                                _ => {
                                    self.regs[0] = self.read_u64(self.regs[6])?;
                                }
                            }
                            self.regs[6] = self.regs[6].wrapping_add(step as u64);
                        }
                    }
                    if !rep {
                        break;
                    }
                    n -= 1;
                    self.regs[1] = n;
                }
                if rep {
                    self.regs[1] = 0;
                }
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0x90 => {
                // xchg rax,r64 with REX.B; PAUSE (F3 90); else NOP.
                if rep {
                    // PAUSE: scheduling hint, no effect
                } else if rex_b {
                    if rex_w {
                        let t = self.regs[0];
                        self.regs[0] = self.regs[8];
                        self.regs[8] = t;
                    } else {
                        let t = self.regs[0] & 0xFFFF_FFFF;
                        self.regs[0] = self.regs[8] & 0xFFFF_FFFF;
                        self.regs[8] = t;
                    }
                }
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0x50..=0x57 => {
                let r = (((rex_b as u8) << 3) | (op & 7)) as usize;
                let v = self.regs[r];
                self.push_u64(v)?;
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0x58..=0x5F => {
                let r = (((rex_b as u8) << 3) | (op & 7)) as usize;
                let v = self.pop_u64()?;
                self.regs[r] = v;
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0x69 | 0x6B => {
                // IMUL r, r/m, imm (demanded by real codegen). Truncated to
                // width; CF=OF iff the full product doesn't fit signed width.
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                let (imm, imm_len): (i64, usize) = if op == 0x6B {
                    (self.read_u8(ip + (off + 1 + ml) as u64)? as i8 as i64, 1)
                } else {
                    (self.read_u32(ip + (off + 1 + ml) as u64)? as i32 as i64, 4)
                };
                let next = ip + (off + 1 + ml + imm_len) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.read_rm(is_reg, rm, ea, w)?;
                let (trunc, of) = match w {
                    64 => {
                        let r = (a as i64 as i128) * (imm as i128);
                        ((r as u64), r < i64::MIN as i128 || r > i64::MAX as i128)
                    }
                    32 => {
                        let r = (a as u32 as i32 as i64) * imm;
                        (
                            (r as u32) as u64,
                            r < i32::MIN as i64 || r > i32::MAX as i64,
                        )
                    }
                    _ => {
                        let r = (a as u16 as i16 as i32) * (imm as i32);
                        (
                            (r as u16) as u64,
                            r < i16::MIN as i32 || r > i16::MAX as i32,
                        )
                    }
                };
                self.cf = of;
                self.of = of;
                self.zf = false;
                self.sf = false;
                self.write_rm(true, reg, 0, w, trunc)?;
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0x68 => {
                let imm = self.read_u32(ip + off as u64 + 1)? as i32 as i64 as u64;
                self.push_u64(imm)?;
                self.rip = ip + off as u64 + 5;
                Ok(StepResult::Continue)
            }
            0x6A => {
                let imm = self.read_u8(ip + off as u64 + 1)? as i8 as i64 as u64;
                self.push_u64(imm)?;
                self.rip = ip + off as u64 + 2;
                Ok(StepResult::Continue)
            }
            0xB0..=0xB7 => {
                let r = (((rex_b as u8) << 3) | (op & 7)) as usize;
                let imm = self.read_u8(ip + off as u64 + 1)?;
                self.write_r8(r, imm as u64);
                self.rip = ip + off as u64 + 2;
                Ok(StepResult::Continue)
            }
            0xB8..=0xBF => {
                let r = (((rex_b as u8) << 3) | (op & 7)) as usize;
                if rex_w {
                    let imm = self.read_u64(ip + off as u64 + 1)?;
                    self.regs[r] = imm;
                    self.rip = ip + off as u64 + 9;
                } else if w == 16 {
                    let imm = self.read_u16(ip + off as u64 + 1)?;
                    self.regs[r] = (self.regs[r] & !0xFFFF) | imm as u64;
                    self.rip = ip + off as u64 + 3;
                } else {
                    let imm = self.read_u32(ip + off as u64 + 1)?;
                    self.regs[r] = imm as u64;
                    self.rip = ip + off as u64 + 5;
                }
                Ok(StepResult::Continue)
            }
            0xC3 => {
                let ret = self.pop_u64()?;
                if ret == ENTRY_SENTINEL {
                    let code = (self.regs[0] & 0xFFFF_FFFF) as u32;
                    return Ok(StepResult::Halted(code));
                }
                self.rip = ret;
                Ok(StepResult::Continue)
            }
            0xC2 => {
                let imm = self.read_u16(ip + off as u64 + 1)? as u64;
                let ret = self.pop_u64()?;
                if ret == ENTRY_SENTINEL {
                    let code = (self.regs[0] & 0xFFFF_FFFF) as u32;
                    return Ok(StepResult::Halted(code));
                }
                self.set_rsp(self.rsp().wrapping_add(imm));
                self.rip = ret;
                Ok(StepResult::Continue)
            }
            0xC9 => {
                // leave
                self.set_rsp(self.regs[5]);
                let v = self.pop_u64()?;
                self.regs[5] = v;
                self.rip = ip + off as u64 + 1;
                Ok(StepResult::Continue)
            }
            0xE8 => {
                let disp = self.read_u32(ip + off as u64 + 1)? as i32 as i64;
                let next = ip + off as u64 + 5;
                let target = next.wrapping_add(disp as u64);
                if let Some(&idx) = self.stubs.get(&target) {
                    self.push_u64(next)?;
                    self.rip = target;
                    return Ok(StepResult::CalledStub { index: idx });
                }
                self.push_u64(next)?;
                self.rip = target;
                Ok(StepResult::Continue)
            }
            0xE9 => {
                let disp = self.read_u32(ip + off as u64 + 1)? as i32 as i64;
                let next = ip + off as u64 + 5;
                let target = next.wrapping_add(disp as u64);
                if let Some(&idx) = self.stubs.get(&target) {
                    self.rip = target;
                    return Ok(StepResult::CalledStub { index: idx });
                }
                self.rip = target;
                Ok(StepResult::Continue)
            }
            0xEB => {
                let disp = self.read_u8(ip + off as u64 + 1)? as i8 as i64;
                let next = ip + off as u64 + 2;
                self.rip = next.wrapping_add(disp as u64);
                Ok(StepResult::Continue)
            }
            0x88 | 0x89 | 0x8A | 0x8B | 0x8D | 0x01 | 0x03 | 0x29 | 0x2B | 0x31 | 0x33 | 0x39
            | 0x3B | 0x09 | 0x0B | 0x21 | 0x23 | 0x84 | 0x85 | 0x63 | 0x00 | 0x02 | 0x08 | 0x0A
            | 0x20 | 0x22 | 0x28 | 0x2A | 0x30 | 0x32 | 0x38 | 0x3A | 0x10 | 0x12 | 0x18 | 0x1A
            | 0x11 | 0x13 | 0x19 | 0x1B => {
                let is_8 = op == 0x88
                    || op == 0x8A
                    || op == 0x84
                    || matches!(
                        op,
                        0x00 | 0x02
                            | 0x08
                            | 0x0A
                            | 0x20
                            | 0x22
                            | 0x28
                            | 0x2A
                            | 0x30
                            | 0x32
                            | 0x38
                            | 0x3A
                            | 0x10
                            | 0x12
                            | 0x18
                            | 0x1A
                    );
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 1 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let width: u32 = if is_8 { 8 } else { w };
                match op {
                    0x88 => {
                        // mov r/m8, r8
                        let v = self.read_r8(reg);
                        self.write_rm(is_reg, rm, ea, 8, v)?;
                    }
                    0x8A => {
                        let v = self.read_rm(is_reg, rm, ea, 8)?;
                        self.write_r8(reg, v);
                    }
                    0x89 => {
                        let v = match width {
                            64 => self.regs[reg],
                            32 => self.regs[reg] & 0xFFFF_FFFF,
                            _ => self.regs[reg] & 0xFFFF,
                        };
                        self.write_rm(is_reg, rm, ea, width, v)?;
                    }
                    0x8B => {
                        let v = self.read_rm(is_reg, rm, ea, width)?;
                        match width {
                            64 => self.regs[reg] = v,
                            32 => self.regs[reg] = v & 0xFFFF_FFFF,
                            // 16-bit: upper bits preserved
                            _ => self.regs[reg] = (self.regs[reg] & !0xFFFF) | (v & 0xFFFF),
                        }
                    }
                    0x8D => {
                        // lea: ea (full 64-bit), no flags
                        if is_reg {
                            return Err(format!("lea with register operand at 0x{ip:016x}"));
                        }
                        if rex_w || w == 64 {
                            self.regs[reg] = ea;
                        } else {
                            self.regs[reg] = ea & 0xFFFF_FFFF;
                        }
                    }
                    0x63 => {
                        // movsxd r64, r/m32
                        let v = self.read_rm(is_reg, rm, ea, 32)? as u32 as i32 as i64 as u64;
                        self.regs[reg] = v;
                    }
                    0x84 | 0x85 => {
                        let a = match width {
                            64 => self.regs[reg],
                            32 => self.regs[reg] & 0xFFFF_FFFF,
                            16 => self.regs[reg] & 0xFFFF,
                            _ => self.read_r8(reg),
                        };
                        let b = self.read_rm(is_reg, rm, ea, width)?;
                        let mask = match width {
                            64 => u64::MAX,
                            32 => 0xFFFF_FFFF,
                            16 => 0xFFFF,
                            _ => 0xFF,
                        };
                        self.set_logic_flags((a & mask) & b, width);
                    }
                    _ => {
                        // ALU r/m,r or r,r/m
                        let to_rm = matches!(
                            op,
                            0x01 | 0x29
                                | 0x31
                                | 0x39
                                | 0x09
                                | 0x21
                                | 0x00
                                | 0x28
                                | 0x30
                                | 0x38
                                | 0x08
                                | 0x20
                                | 0x10
                                | 0x18
                                | 0x11
                                | 0x19
                        );
                        let omask: u64 = match width {
                            64 => u64::MAX,
                            32 => 0xFFFF_FFFF,
                            16 => 0xFFFF,
                            _ => 0xFF,
                        };
                        let rv = if width == 8 {
                            self.read_r8(reg)
                        } else {
                            self.regs[reg] & omask
                        };
                        let mv = self.read_rm(is_reg, rm, ea, width)? & omask;
                        // Canonical operand order: (dest, src).
                        let (dst, src) = if to_rm { (mv, rv) } else { (rv, mv) };
                        let sign = 1u64 << (width - 1);
                        if matches!(op, 0x10 | 0x12 | 0x11 | 0x13) {
                            // ADC dst, src (+CF): full carry chaining.
                            let cf = u64::from(self.cf);
                            let res = dst.wrapping_add(src).wrapping_add(cf) & omask;
                            self.cf = (dst as u128 + src as u128 + cf as u128) > omask as u128;
                            let t = src.wrapping_add(cf) & omask;
                            self.of = ((dst ^ res) & (t ^ res) & sign) != 0;
                            self.zf = res == 0;
                            self.sf = (res & sign) != 0;
                            if to_rm {
                                self.write_rm(is_reg, rm, ea, width, res)?;
                            } else {
                                self.write_rm(true, reg, 0, width, res)?;
                            }
                        } else if matches!(op, 0x18 | 0x1A | 0x19 | 0x1B) {
                            // SBB dst, src (-CF): full borrow chaining.
                            let cf = u64::from(self.cf);
                            let res = dst.wrapping_sub(src).wrapping_sub(cf) & omask;
                            self.cf = (dst as u128) < (src as u128 + cf as u128);
                            let t = src.wrapping_add(cf) & omask;
                            self.of = ((dst ^ t) & (dst ^ res) & sign) != 0;
                            self.zf = res == 0;
                            self.sf = (res & sign) != 0;
                            if to_rm {
                                self.write_rm(is_reg, rm, ea, width, res)?;
                            } else {
                                self.write_rm(true, reg, 0, width, res)?;
                            }
                        } else {
                            // add/sub/and/or/xor/cmp (no carry in)
                            let (res, is_sub, is_logic) = match op {
                                0x01 | 0x03 | 0x00 | 0x02 => {
                                    (mv.wrapping_add(rv) & omask, false, false)
                                }
                                0x29 | 0x2B | 0x28 | 0x2A => (
                                    if to_rm {
                                        mv.wrapping_sub(rv) & omask
                                    } else {
                                        rv.wrapping_sub(mv) & omask
                                    },
                                    true,
                                    false,
                                ),
                                0x31 | 0x33 | 0x30 | 0x32 => ((mv ^ rv) & omask, false, true),
                                0x09 | 0x0B | 0x08 | 0x0A => ((mv | rv) & omask, false, true),
                                0x21 | 0x23 | 0x20 | 0x22 => ((mv & rv) & omask, false, true),
                                0x39 | 0x3B | 0x38 | 0x3A => (
                                    if to_rm {
                                        mv.wrapping_sub(rv) & omask
                                    } else {
                                        rv.wrapping_sub(mv) & omask
                                    },
                                    true,
                                    false,
                                ),
                                _ => unreachable!(),
                            };
                            let is_cmp = matches!(op, 0x39 | 0x3B | 0x38 | 0x3A);
                            if is_cmp {
                                // cmp: set flags on (op1 - op2)
                                let (a, b) = if to_rm { (mv, rv) } else { (rv, mv) };
                                self.set_sub_flags(a, b, res, width);
                            } else if is_logic {
                                self.set_logic_flags(res, width);
                                if to_rm {
                                    self.write_rm(is_reg, rm, ea, width, res)?;
                                } else {
                                    self.write_rm(true, reg, 0, width, res)?;
                                }
                            } else if is_sub {
                                let (a, b) = if to_rm { (mv, rv) } else { (rv, mv) };
                                self.set_sub_flags(a, b, res, width);
                                if to_rm {
                                    self.write_rm(is_reg, rm, ea, width, res)?;
                                } else {
                                    self.write_rm(true, reg, 0, width, res)?;
                                }
                            } else {
                                // add
                                let (a, b) = if to_rm { (mv, rv) } else { (rv, mv) };
                                self.set_add_flags(a, b, res, width);
                                if to_rm {
                                    self.write_rm(is_reg, rm, ea, width, res)?;
                                } else {
                                    self.write_rm(true, reg, 0, width, res)?;
                                }
                            }
                        } // end non-carry path
                    }
                }
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => {
                // ALU AL,imm8 (ADC/SBB chain CF like their group1 siblings).
                let imm = self.read_u8(ip + off as u64 + 1)? as u64;
                let next = ip + off as u64 + 2;
                let a = self.regs[0] & 0xFF;
                match op {
                    0x04 => {
                        let r = (a + imm) & 0xFF;
                        self.set_add_flags(a, imm, r, 8);
                        self.regs[0] = (self.regs[0] & !0xFF) | r;
                    }
                    0x0C => {
                        let r = (a | imm) & 0xFF;
                        self.set_logic_flags(r, 8);
                        self.regs[0] = (self.regs[0] & !0xFF) | r;
                    }
                    0x24 => {
                        let r = (a & imm) & 0xFF;
                        self.set_logic_flags(r, 8);
                        self.regs[0] = (self.regs[0] & !0xFF) | r;
                    }
                    0x2C => {
                        let r = a.wrapping_sub(imm) & 0xFF;
                        self.set_sub_flags(a, imm, r, 8);
                        self.regs[0] = (self.regs[0] & !0xFF) | r;
                    }
                    0x34 => {
                        let r = (a ^ imm) & 0xFF;
                        self.set_logic_flags(r, 8);
                        self.regs[0] = (self.regs[0] & !0xFF) | r;
                    }
                    0x14 => {
                        let cf = u64::from(self.cf);
                        let r = a.wrapping_add(imm).wrapping_add(cf) & 0xFF;
                        self.cf = (a as u128 + imm as u128 + cf as u128) > 0xFF;
                        let t = imm.wrapping_add(cf) & 0xFF;
                        self.of = ((a ^ r) & (t ^ r) & 0x80) != 0;
                        self.zf = r == 0;
                        self.sf = (r & 0x80) != 0;
                        self.regs[0] = (self.regs[0] & !0xFF) | r;
                    }
                    0x1C => {
                        let cf = u64::from(self.cf);
                        let r = a.wrapping_sub(imm).wrapping_sub(cf) & 0xFF;
                        self.cf = (a as u128) < (imm as u128 + cf as u128);
                        let t = imm.wrapping_add(cf) & 0xFF;
                        self.of = ((a ^ t) & (a ^ r) & 0x80) != 0;
                        self.zf = r == 0;
                        self.sf = (r & 0x80) != 0;
                        self.regs[0] = (self.regs[0] & !0xFF) | r;
                    }
                    _ => {
                        // 0x3C CMP
                        let r = a.wrapping_sub(imm) & 0xFF;
                        self.set_sub_flags(a, imm, r, 8);
                    }
                }
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0xA8 => {
                // TEST AL,imm8
                let imm = self.read_u8(ip + off as u64 + 1)? as u64;
                let next = ip + off as u64 + 2;
                self.set_logic_flags((self.regs[0] & 0xFF) & imm, 8);
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0x05 | 0x2D | 0x35 | 0x3D | 0x0D | 0x25 | 0xA9 => {
                // ALU rax, imm32 (0xA9 = TEST, no writeback)
                let imm = self.read_u32(ip + off as u64 + 1)? as u64;
                let next = ip + off as u64 + 5;
                if w == 64 {
                    let a = self.regs[0];
                    match op {
                        0x05 => {
                            let r = a.wrapping_add(imm as i32 as i64 as u64);
                            self.set_add_flags(a, imm as i32 as i64 as u64, r, 64);
                            self.regs[0] = r;
                        }
                        0x2D => {
                            let b = imm as i32 as i64 as u64;
                            let r = a.wrapping_sub(b);
                            self.set_sub_flags(a, b, r, 64);
                            self.regs[0] = r;
                        }
                        0x35 => {
                            let r = a ^ (imm as i32 as i64 as u64);
                            self.set_logic_flags(r, 64);
                            self.regs[0] = r;
                        }
                        0xA9 => {
                            let r = a & (imm as i32 as i64 as u64);
                            self.set_logic_flags(r, 64);
                        }
                        0x3D => {
                            let b = imm as i32 as i64 as u64;
                            let r = a.wrapping_sub(b);
                            self.set_sub_flags(a, b, r, 64);
                        }
                        0x0D => {
                            let r = a | (imm as i32 as i64 as u64);
                            self.set_logic_flags(r, 64);
                            self.regs[0] = r;
                        }
                        0x25 => {
                            let r = a & (imm as i32 as i64 as u64);
                            self.set_logic_flags(r, 64);
                            self.regs[0] = r;
                        }
                        _ => unreachable!(),
                    }
                } else {
                    let a = self.regs[0] & 0xFFFF_FFFF;
                    let b = imm & 0xFFFF_FFFF;
                    match op {
                        0x05 => {
                            let r = a.wrapping_add(b) & 0xFFFF_FFFF;
                            self.set_add_flags(a, b, r, 32);
                            self.regs[0] = r;
                        }
                        0x2D => {
                            let r = a.wrapping_sub(b) & 0xFFFF_FFFF;
                            self.set_sub_flags(a, b, r, 32);
                            self.regs[0] = r;
                        }
                        0x35 => {
                            let r = (a ^ b) & 0xFFFF_FFFF;
                            self.set_logic_flags(r, 32);
                            self.regs[0] = r;
                        }
                        0xA9 => {
                            let r = (a & b) & 0xFFFF_FFFF;
                            self.set_logic_flags(r, 32);
                        }
                        0x3D => {
                            let r = a.wrapping_sub(b) & 0xFFFF_FFFF;
                            self.set_sub_flags(a, b, r, 32);
                        }
                        0x0D => {
                            let r = (a | b) & 0xFFFF_FFFF;
                            self.set_logic_flags(r, 32);
                            self.regs[0] = r;
                        }
                        0x25 => {
                            let r = (a & b) & 0xFFFF_FFFF;
                            self.set_logic_flags(r, 32);
                            self.regs[0] = r;
                        }
                        _ => unreachable!(),
                    }
                }
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0x81 | 0x83 => {
                let is8 = op == 0x83;
                let (reg_field, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                let imm_off = off + 1 + ml;
                // 0x83: imm8 sign-extended; 0x81: imm32 (imm16 with 0x66).
                let (imm_raw, imm_len): (u64, usize) = if is8 {
                    (self.read_u8(ip + imm_off as u64)? as i8 as i64 as u64, 1)
                } else if w == 16 {
                    (self.read_u16(ip + imm_off as u64)? as u64, 2)
                } else {
                    (self.read_u32(ip + imm_off as u64)? as i32 as i64 as u64, 4)
                };
                let next = ip + (imm_off + imm_len) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                // reg field selects op: /0 ADD /1 OR /2 ADC /3 SBB /4 AND /5 SUB /6 XOR /7 CMP
                let omask: u64 = match w {
                    64 => u64::MAX,
                    32 => 0xFFFF_FFFF,
                    _ => 0xFFFF,
                };
                let sign = 1u64 << (w - 1);
                let mv = self.read_rm(is_reg, rm, ea, w)? & omask;
                let a = mv;
                let bfull = imm_raw & omask;
                if reg_field == 2 || reg_field == 3 {
                    // ADC/SBB with immediate (+/-CF): full carry chaining.
                    let cf = u64::from(self.cf);
                    let res = if reg_field == 2 {
                        a.wrapping_add(bfull).wrapping_add(cf) & omask
                    } else {
                        a.wrapping_sub(bfull).wrapping_sub(cf) & omask
                    };
                    if reg_field == 2 {
                        self.cf = (a as u128 + bfull as u128 + cf as u128) > omask as u128;
                        let t = bfull.wrapping_add(cf) & omask;
                        self.of = ((a ^ res) & (t ^ res) & sign) != 0;
                    } else {
                        self.cf = (a as u128) < (bfull as u128 + cf as u128);
                        let t = bfull.wrapping_add(cf) & omask;
                        self.of = ((a ^ t) & (a ^ res) & sign) != 0;
                    }
                    self.zf = res == 0;
                    self.sf = (res & sign) != 0;
                    self.write_rm(is_reg, rm, ea, w, res)?;
                    self.rip = next;
                    return Ok(StepResult::Continue);
                }
                let res = match reg_field {
                    0 => a.wrapping_add(bfull),
                    1 => a | bfull,
                    4 => a & bfull,
                    5 => a.wrapping_sub(bfull),
                    6 => a ^ bfull,
                    7 => a.wrapping_sub(bfull),
                    _ => {
                        return Err(format!(
                            "unsupported group1 sub-op /{} at 0x{ip:016x} (only ADD/ADC/SBB/OR/AND/SUB/XOR/CMP)",
                            reg_field
                        ))
                    }
                };
                let res_masked = res & omask;
                match reg_field {
                    0 => self.set_add_flags(a, bfull, res, w),
                    1 | 4 | 6 => self.set_logic_flags(res, w),
                    5 | 7 => self.set_sub_flags(a, bfull, res, w),
                    _ => unreachable!(),
                }
                if reg_field != 7 {
                    self.write_rm(is_reg, rm, ea, w, res_masked)?;
                }
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0x80 => {
                // Grp1 Eb,Ib (demanded by rustc byte compares: 80 /7 ib = CMP).
                let (reg_field, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                let imm = self.read_u8(ip + (off + 1 + ml) as u64)? as u64;
                let next = ip + (off + 1 + ml + 1) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.read_rm(is_reg, rm, ea, 8)?;
                if reg_field == 2 || reg_field == 3 {
                    // ADC/SBB Eb,Ib: preserve the incoming carry while
                    // computing the result, then publish the new carry/borrow.
                    let carry = u64::from(self.cf);
                    let res = if reg_field == 2 {
                        a.wrapping_add(imm).wrapping_add(carry) & 0xff
                    } else {
                        a.wrapping_sub(imm).wrapping_sub(carry) & 0xff
                    };
                    if reg_field == 2 {
                        self.cf = a + imm + carry > 0xff;
                        let rhs = imm.wrapping_add(carry) & 0xff;
                        self.of = ((a ^ res) & (rhs ^ res) & 0x80) != 0;
                    } else {
                        self.cf = a < imm + carry;
                        let rhs = imm.wrapping_add(carry) & 0xff;
                        self.of = ((a ^ rhs) & (a ^ res) & 0x80) != 0;
                    }
                    self.zf = res == 0;
                    self.sf = res & 0x80 != 0;
                    self.write_rm(is_reg, rm, ea, 8, res)?;
                    self.rip = next;
                    return Ok(StepResult::Continue);
                }
                let res = match reg_field {
                    0 => a.wrapping_add(imm),
                    1 => a | imm,
                    4 => a & imm,
                    5 => a.wrapping_sub(imm),
                    6 => a ^ imm,
                    7 => a.wrapping_sub(imm),
                    _ => {
                        return Err(format!(
                            "unsupported group1b sub-op /{} at 0x{ip:016x} (only ADD/ADC/SBB/OR/AND/SUB/XOR/CMP)",
                            reg_field
                        ))
                    }
                };
                match reg_field {
                    0 => self.set_add_flags(a, imm, res, 8),
                    1 | 4 | 6 => self.set_logic_flags(res, 8),
                    5 | 7 => self.set_sub_flags(a, imm, res, 8),
                    _ => unreachable!(),
                }
                if reg_field != 7 {
                    self.write_rm(is_reg, rm, ea, 8, res & 0xFF)?;
                }
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0xC0 | 0xC1 | 0xD0 | 0xD1 | 0xD2 | 0xD3 => {
                // Grp2 shifts/rotates with full RCL/RCR carry chaining.
                // OF semantics below are the standard 1-bit rules;
                // count==0 leaves flags alone; rotates never touch ZF/SF.
                let width: u32 = if op == 0xC0 || op == 0xD0 { 8 } else { w };
                if width == 16 {
                    return Err(format!("unsupported 16-bit shift at 0x{ip:016x}"));
                }
                let (reg_field, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                let (count, imm_len) = match op {
                    0xC0 | 0xC1 => (self.read_u8(ip + (off + 1 + ml) as u64)? as u64, 1),
                    0xD0 | 0xD1 => (1, 0),
                    _ => (self.regs[1], 0), // 0xD2/0xD3: count in CL
                };
                let next = ip + (off + 1 + ml + imm_len) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let (mask, top) = match width {
                    64 => (u64::MAX, 63),
                    32 => (0xFFFF_FFFF, 31),
                    _ => (0xFF, 7),
                };
                let a = self.read_rm(is_reg, rm, ea, width)? & mask;
                let count = (if width == 64 { count & 63 } else { count & 31 }) as u32;
                if reg_field == 2 || reg_field == 3 {
                    // RCL/RCR with full carry chaining. ZF/SF/AF untouched.
                    let mut v = a;
                    let mut cf = self.cf;
                    for _ in 0..count {
                        if reg_field == 2 {
                            let new_cf = ((v >> top) & 1) == 1;
                            v = ((v << 1) & mask) | u64::from(cf);
                            cf = new_cf;
                        } else {
                            let new_cf = (v & 1) == 1;
                            v = (v >> 1) | ((cf as u64) << top);
                            cf = new_cf;
                        }
                    }
                    let res = v & mask;
                    self.cf = cf;
                    self.of = if count == 1 {
                        if reg_field == 2 {
                            ((res >> top) & 1 == 1) != self.cf
                        } else {
                            // documented approximation: MSB(orig) ^ MSB-1(orig)
                            ((a >> top) & 1 == 1) != ((a >> (top - 1)) & 1 == 1)
                        }
                    } else {
                        false
                    };
                    self.write_rm(is_reg, rm, ea, width, res)?;
                    self.rip = next;
                    return Ok(StepResult::Continue);
                }
                let res = match reg_field {
                    0 => {
                        // ROL
                        let r = if width == 64 {
                            a.rotate_left(count)
                        } else if width == 32 {
                            (a as u32).rotate_left(count) as u64
                        } else {
                            (a as u8).rotate_left(count) as u64
                        };
                        r & mask
                    }
                    1 => {
                        // ROR
                        let r = if width == 64 {
                            a.rotate_right(count)
                        } else if width == 32 {
                            (a as u32).rotate_right(count) as u64
                        } else {
                            (a as u8).rotate_right(count) as u64
                        };
                        r & mask
                    }
                    4 | 6 => a.wrapping_shl(count) & mask, // SHL/SAL
                    5 => a.wrapping_shr(count) & mask,     // SHR
                    7 => {
                        // SAR: arithmetic
                        let s = if width == 64 {
                            (a as i64).wrapping_shr(count) as u64
                        } else {
                            ((a as u32 as i32).wrapping_shr(count) as u32) as u64
                        };
                        s & mask
                    }
                    _ => return Err(format!(
                        "unsupported rotate /{reg_field} at 0x{ip:016x} (only ROL/ROR/SHL/SHR/SAR)"
                    )),
                };
                if count != 0 {
                    match reg_field {
                        0 => {
                            // ROL: CF = LSB(result); OF (1-bit) = MSB ^ CF.
                            // ZF/SF untouched by rotates.
                            self.cf = (res & 1) == 1;
                            self.of = if count == 1 {
                                ((res >> top) & 1 == 1) != self.cf
                            } else {
                                false
                            };
                        }
                        1 => {
                            // ROR: CF = MSB(result); OF (1-bit) = MSB ^ MSB-1.
                            self.cf = ((res >> top) & 1) == 1;
                            self.of = if count == 1 {
                                ((res >> top) & 1 == 1) != ((res >> (top - 1)) & 1 == 1)
                            } else {
                                false
                            };
                        }
                        4 | 6 => {
                            self.cf = ((a >> (width - count)) & 1) == 1;
                            self.of = if count == 1 {
                                ((res >> top) & 1 == 1) != self.cf
                            } else {
                                false
                            };
                            self.zf = (res & mask) == 0;
                            self.sf = ((res >> top) & 1) == 1;
                        }
                        5 => {
                            self.cf = ((a >> (count - 1)) & 1) == 1;
                            self.of = false;
                            self.zf = (res & mask) == 0;
                            self.sf = ((res >> top) & 1) == 1;
                        }
                        _ => {
                            self.cf = ((a >> (count - 1)) & 1) == 1;
                            self.of = false;
                            self.zf = (res & mask) == 0;
                            self.sf = ((res >> top) & 1) == 1;
                        }
                    }
                }
                self.write_rm(is_reg, rm, ea, width, res & mask)?;
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0xF6 | 0xF7 => {
                // Grp3 (demanded by real binaries). div-by-zero and quotient
                // overflow raise #DE as clear errors instead of faulting.
                let width: u32 = if op == 0xF6 { 8 } else { w };
                let (reg_field, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                let mut cursor = off + 1 + ml;
                let imm = if reg_field == 0 {
                    let v = if op == 0xF6 {
                        self.read_u8(ip + cursor as u64)? as u64
                    } else {
                        self.read_u32(ip + cursor as u64)? as u64
                    };
                    cursor += if op == 0xF6 { 1 } else { 4 };
                    Some(v)
                } else {
                    None
                };
                let next = ip + cursor as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let mask: u64 = match width {
                    64 => u64::MAX,
                    32 => 0xFFFF_FFFF,
                    16 => 0xFFFF,
                    _ => 0xFF,
                };
                let opv = self.read_rm(is_reg, rm, ea, width)? & mask;
                match reg_field {
                    0 => {
                        // TEST: imm32 sign-extended for 64-bit
                        let b = if width == 64 {
                            imm.unwrap() as i32 as i64 as u64
                        } else {
                            imm.unwrap() & mask
                        };
                        self.set_logic_flags(opv & b, width);
                    }
                    2 => {
                        // NOT: no flags
                        self.write_rm(is_reg, rm, ea, width, (!opv) & mask)?;
                    }
                    3 => {
                        // NEG: 0 - x
                        let res = (0u64.wrapping_sub(opv)) & mask;
                        self.set_sub_flags(0, opv, res, width);
                        self.write_rm(is_reg, rm, ea, width, res)?;
                    }
                    4 | 5 => {
                        // MUL / IMUL r/m (single-operand)
                        let (lo, hi, of): (u64, u64, bool) = match width {
                            64 => {
                                if reg_field == 4 {
                                    let r = self.regs[0] as u128 * opv as u128;
                                    (r as u64, (r >> 64) as u64, (r >> 64) != 0)
                                } else {
                                    let r = (self.regs[0] as i64 as i128) * (opv as i64 as i128);
                                    let (lo, hi) = (r as u64, (r >> 64) as u64);
                                    let s = (lo as i64 >> 63) as u64;
                                    (lo, hi, hi != s)
                                }
                            }
                            32 => {
                                if reg_field == 4 {
                                    let r = (self.regs[0] & mask) * opv;
                                    ((r & mask), (r >> 32) & mask, (r >> 32) != 0)
                                } else {
                                    let r = (self.regs[0] as u32 as i32 as i64)
                                        * (opv as u32 as i32 as i64);
                                    let (lo, hi) = (r as u64 & mask, ((r >> 32) as u64) & mask);
                                    let s = ((lo as i64 >> 31) as u64) & mask;
                                    (lo, hi, hi != s)
                                }
                            }
                            16 => {
                                if reg_field == 4 {
                                    let r = (self.regs[0] & mask) * opv;
                                    ((r & mask), (r >> 16) & mask, (r >> 16) != 0)
                                } else {
                                    let r = (self.regs[0] as u16 as i16 as i32)
                                        * (opv as u16 as i16 as i32);
                                    let (lo, hi) = ((r as u64) & mask, ((r >> 16) as u64) & mask);
                                    let s = ((lo as i64 >> 15) as u64) & mask;
                                    (lo, hi, hi != s)
                                }
                            }
                            _ => {
                                if reg_field == 4 {
                                    let r = (self.regs[0] & mask) * opv;
                                    ((r & mask), (r >> 8) & mask, (r >> 8) != 0)
                                } else {
                                    let r = (self.regs[0] as u8 as i8 as i16)
                                        * (opv as u8 as i8 as i16);
                                    let (lo, hi) = ((r as u64) & mask, ((r >> 8) as u64) & mask);
                                    let s = ((lo as i64 >> 7) as u64) & mask;
                                    (lo, hi, hi != s)
                                }
                            }
                        };
                        match width {
                            64 => {
                                self.regs[0] = lo;
                                self.regs[2] = hi;
                            }
                            32 => {
                                self.regs[0] = (self.regs[0] & !mask) | lo;
                                self.regs[2] = (self.regs[2] & !mask) | hi;
                            }
                            16 => {
                                self.regs[0] = (self.regs[0] & !mask) | lo;
                                self.regs[2] = (self.regs[2] & !0xFFFF) | hi;
                            }
                            _ => {
                                self.regs[0] = (self.regs[0] & !0xFFFF) | (hi << 8) | lo;
                                let _ = hi;
                            }
                        }
                        self.cf = of;
                        self.of = of;
                        self.zf = false;
                        self.sf = false;
                    }
                    6 | 7 => {
                        // DIV / IDIV
                        let signed = reg_field == 7;
                        let (q, r): (u64, u64) = match width {
                            64 => {
                                if !signed {
                                    let d = ((self.regs[2] as u128) << 64) | self.regs[0] as u128;
                                    if opv == 0 {
                                        return Err("#DE: division by zero".to_string());
                                    }
                                    let (q, r) = (d / opv as u128, d % opv as u128);
                                    if q > u64::MAX as u128 {
                                        return Err("#DE: quotient overflow".to_string());
                                    }
                                    (q as u64, r as u64)
                                } else {
                                    let d = ((self.regs[2] as i64 as i128) << 64)
                                        | self.regs[0] as u64 as i128;
                                    let o = opv as i64 as i128;
                                    if o == 0 {
                                        return Err("#DE: division by zero".to_string());
                                    }
                                    match (d.checked_div(o), d.checked_rem(o)) {
                                        (Some(q), Some(r)) => {
                                            if q < i64::MIN as i128 || q > i64::MAX as i128 {
                                                return Err("#DE: quotient overflow".to_string());
                                            }
                                            (q as u64, r as u64)
                                        }
                                        _ => return Err("#DE: quotient overflow".to_string()),
                                    }
                                }
                            }
                            32 => {
                                let dhi = self.regs[2] & mask;
                                let dlo = self.regs[0] & mask;
                                if !signed {
                                    let d = (dhi << 32) | dlo;
                                    if opv == 0 {
                                        return Err("#DE: division by zero".to_string());
                                    }
                                    let (q, r) = (d / opv, d % opv);
                                    if q > 0xFFFF_FFFF {
                                        return Err("#DE: quotient overflow".to_string());
                                    }
                                    (q, r)
                                } else {
                                    let d = (((dhi as u32 as i32 as i64) << 32) | dlo as u32 as i64)
                                        as i128;
                                    let o = opv as u32 as i32 as i128;
                                    if o == 0 {
                                        return Err("#DE: division by zero".to_string());
                                    }
                                    match (d.checked_div(o), d.checked_rem(o)) {
                                        (Some(q), Some(r)) => {
                                            if q < i32::MIN as i128 || q > i32::MAX as i128 {
                                                return Err("#DE: quotient overflow".to_string());
                                            }
                                            ((q as u32) as u64, (r as u32) as u64)
                                        }
                                        _ => return Err("#DE: quotient overflow".to_string()),
                                    }
                                }
                            }
                            _ => {
                                // 16/8-bit share the u32 path with narrower limits
                                let (dhi, dlo, bits) = match width {
                                    16 => (self.regs[2] & 0xFFFF, self.regs[0] & 0xFFFF, 16),
                                    _ => ((self.regs[0] >> 8) & 0xFF, self.regs[0] & 0xFF, 8),
                                };
                                if !signed {
                                    let d = (dhi << bits) | dlo;
                                    if opv == 0 {
                                        return Err("#DE: division by zero".to_string());
                                    }
                                    let (q, rem) = (d / opv, d % opv);
                                    let max = (1u64 << bits) - 1;
                                    if q > max {
                                        return Err("#DE: quotient overflow".to_string());
                                    }
                                    (q, rem)
                                } else {
                                    let sbits = bits as u32;
                                    let raw = (dhi << sbits) | dlo;
                                    let d = if raw >> (2 * sbits - 1) & 1 == 1 {
                                        (raw as i128) - (1i128 << (2 * sbits))
                                    } else {
                                        raw as i128
                                    };
                                    let o = if opv >> (sbits - 1) & 1 == 1 {
                                        (opv as i128) - (1i128 << sbits)
                                    } else {
                                        opv as i128
                                    };
                                    if o == 0 {
                                        return Err("#DE: division by zero".to_string());
                                    }
                                    match (d.checked_div(o), d.checked_rem(o)) {
                                        (Some(q), Some(rem)) => {
                                            let (mn, mx) = (
                                                -(1i128 << (sbits - 1)),
                                                (1i128 << (sbits - 1)) - 1,
                                            );
                                            if q < mn || q > mx {
                                                return Err("#DE: quotient overflow".to_string());
                                            }
                                            (
                                                (q as u64) & ((1 << sbits) - 1),
                                                (rem as u64) & ((1 << sbits) - 1),
                                            )
                                        }
                                        _ => return Err("#DE: quotient overflow".to_string()),
                                    }
                                }
                            }
                        };
                        match width {
                            64 => {
                                self.regs[0] = q;
                                self.regs[2] = r;
                            }
                            32 => {
                                self.regs[0] = (self.regs[0] & !mask) | q;
                                self.regs[2] = (self.regs[2] & !mask) | r;
                            }
                            16 => {
                                self.regs[0] = (self.regs[0] & !mask) | q;
                                self.regs[2] = (self.regs[2] & !0xFFFF) | r;
                            }
                            _ => {
                                self.regs[0] =
                                    (self.regs[0] & !0xFFFF) | ((r & 0xFF) << 8) | (q & 0xFF);
                            }
                        }
                    }
                    _ => {
                        return Err(format!(
                            "unsupported Grp3 sub-op /{reg_field} at 0x{ip:016x}"
                        ))
                    }
                }
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0x86 | 0x87 => {
                // XCHG r/m, r. No flags affected. LOCK ignored (one thread).
                let width: u32 = if op == 0x86 { 8 } else { w };
                if width == 16 {
                    return Err(format!("unsupported 16-bit xchg at 0x{ip:016x}"));
                }
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 1 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.read_rm(is_reg, rm, ea, width)?;
                let b = match width {
                    64 => self.regs[reg],
                    32 => self.regs[reg] & 0xFFFF_FFFF,
                    _ => self.read_r8(reg),
                };
                self.write_rm(is_reg, rm, ea, width, b)?;
                self.write_rm(true, reg, 0, width, a)?;
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0xC6 | 0xC7 => {
                let (reg_field, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                if reg_field != 0 {
                    return Err(format!("unsupported C6/C7 /{reg_field} at 0x{ip:016x}"));
                }
                if op == 0xC6 {
                    let imm = self.read_u8(ip + (off + 1 + ml) as u64)?;
                    let next = ip + (off + 1 + ml + 1) as u64;
                    let ea = if rm == 0x100 {
                        next.wrapping_add(ea_raw)
                    } else {
                        ea_raw
                    };
                    self.write_rm(is_reg, rm, ea, 8, imm as u64)?;
                    self.rip = next;
                } else {
                    // 0xC7: imm32 (imm16 with 0x66), sign-extended for 64-bit
                    let (imm, imm_len): (u64, usize) = if w == 16 {
                        (self.read_u16(ip + (off + 1 + ml) as u64)? as u64, 2)
                    } else {
                        (self.read_u32(ip + (off + 1 + ml) as u64)? as u64, 4)
                    };
                    let next = ip + (off + 1 + ml + imm_len) as u64;
                    let ea = if rm == 0x100 {
                        next.wrapping_add(ea_raw)
                    } else {
                        ea_raw
                    };
                    let v = if w == 64 {
                        imm as i32 as i64 as u64
                    } else {
                        imm
                    };
                    self.write_rm(is_reg, rm, ea, w, v)?;
                    self.rip = next;
                }
                Ok(StepResult::Continue)
            }
            0xFE => {
                // Grp4: /0 INC r/m8, /1 DEC r/m8 (CF preserved).
                let (reg_field, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                if reg_field > 1 {
                    return Err(format!(
                        "unsupported Grp4 sub-op /{reg_field} at 0x{ip:016x} (only INC/DEC)"
                    ));
                }
                let next = ip + (off + 1 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                let a = self.read_rm(is_reg, rm, ea, 8)?;
                let res = if reg_field == 0 {
                    a.wrapping_add(1)
                } else {
                    a.wrapping_sub(1)
                } & 0xFF;
                let old_cf = self.cf;
                if reg_field == 0 {
                    self.set_add_flags(a, 1, res, 8);
                } else {
                    self.set_sub_flags(a, 1, res, 8);
                }
                self.cf = old_cf;
                self.write_rm(is_reg, rm, ea, 8, res)?;
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0xFF => {
                let (reg_field, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 1 + ml) as u64;
                let ea = if rm == 0x100 {
                    next.wrapping_add(ea_raw)
                } else {
                    ea_raw
                };
                match reg_field {
                    0 => {
                        // inc
                        let omask: u64 = match w {
                            64 => u64::MAX,
                            32 => 0xFFFF_FFFF,
                            _ => 0xFFFF,
                        };
                        let mv = self.read_rm(is_reg, rm, ea, w)? & omask;
                        let a = mv;
                        let res = a.wrapping_add(1) & omask;
                        let old_cf = self.cf;
                        self.set_add_flags(a, 1, res, w);
                        self.cf = old_cf;
                        self.write_rm(is_reg, rm, ea, w, res)?;
                        self.rip = next;
                        Ok(StepResult::Continue)
                    }
                    1 => {
                        let omask: u64 = match w {
                            64 => u64::MAX,
                            32 => 0xFFFF_FFFF,
                            _ => 0xFFFF,
                        };
                        let mv = self.read_rm(is_reg, rm, ea, w)? & omask;
                        let a = mv;
                        let res = a.wrapping_sub(1) & omask;
                        let old_cf = self.cf;
                        self.set_sub_flags(a, 1, res, w);
                        self.cf = old_cf;
                        self.write_rm(is_reg, rm, ea, w, res)?;
                        self.rip = next;
                        Ok(StepResult::Continue)
                    }
                    2 => {
                        // call r/m64
                        let target = if is_reg {
                            self.regs[rm]
                        } else {
                            let ea = if rm == 0x100 {
                                next.wrapping_add(ea_raw)
                            } else {
                                ea_raw
                            };
                            self.read_u64(ea)?
                        };
                        if let Some(&idx) = self.stubs.get(&target) {
                            self.push_u64(next)?;
                            self.rip = target;
                            return Ok(StepResult::CalledStub { index: idx });
                        }
                        self.push_u64(next)?;
                        self.rip = target;
                        Ok(StepResult::Continue)
                    }
                    4 => {
                        let target = if is_reg {
                            self.regs[rm]
                        } else {
                            let ea = if rm == 0x100 {
                                next.wrapping_add(ea_raw)
                            } else {
                                ea_raw
                            };
                            self.read_u64(ea)?
                        };
                        if let Some(&idx) = self.stubs.get(&target) {
                            self.rip = target;
                            return Ok(StepResult::CalledStub { index: idx });
                        }
                        self.rip = target;
                        Ok(StepResult::Continue)
                    }
                    6 => {
                        // push r/m64
                        let v = if is_reg {
                            self.regs[rm]
                        } else {
                            let ea = if rm == 0x100 {
                                next.wrapping_add(ea_raw)
                            } else {
                                ea_raw
                            };
                            self.read_u64(ea)?
                        };
                        self.push_u64(v)?;
                        self.rip = next;
                        Ok(StepResult::Continue)
                    }
                    _ => Err(format!("unsupported FF /{reg_field} at 0x{ip:016x}")),
                }
            }
            _ => Err(format!("unsupported opcode 0x{op:02X} at 0x{ip:016x}")),
        }
    }
}

/// Quote one argv element per MSVC `CommandLineToArgvW` rules, so a guest
/// parsing `GetCommandLineW` recovers the original args.
pub fn quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg
        .chars()
        .any(|c| c == ' ' || c == '\t' || c == '"' || c == '\n')
    {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..backslashes * 2 + 1 {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // trailing backslashes are doubled before the closing quote
    for _ in 0..backslashes * 2 {
        out.push('\\');
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::PeImage;

    const BASE: u64 = 0x1400_0000_000;

    fn emu_with(code: &[u8]) -> Emu {
        let mut image = vec![0u8; 0x3000];
        image[0x1000..0x1000 + code.len()].copy_from_slice(code);
        let img = PeImage {
            image_base: BASE,
            entry_rva: 0x1000,
            size_of_image: 0x3000,
            image,
            imports: vec![],
            stubs: vec![],
            unsupported: vec![],
            tls: None,
            iat_slots: vec![],
            code_ranges: vec![],
            relocations: vec![],
        };
        Emu::new(&img).unwrap()
    }

    #[test]
    fn heap_payloads_respect_alignment_and_keep_size_headers() {
        let mut emu = emu_with(&[]);
        for (size, align) in [(0, 16), (1, 16), (17, 16), (33, 64), (7, 32)] {
            let address = emu.heap_alloc_aligned(size, align);
            assert_ne!(address, 0);
            assert_eq!(address % align, 0);
            assert_eq!(emu.heap_size_of(address), size as u64);
        }
        assert_eq!(emu.heap_alloc_aligned(8, 3), 0);
        assert_eq!(emu.heap_alloc(HEAP_SIZE + 1), 0);
    }

    /// RIP-relative disp32 for an instruction at `pos` with `len`, targeting `target_off`.
    fn rel32(pos: usize, len: usize, target_off: usize) -> [u8; 4] {
        ((target_off as i64 - (pos + len) as i64) as i32).to_le_bytes()
    }

    #[test]
    fn sse_xorps_movaps_movups_roundtrip() {
        // cell at code offset 64.
        let cell = 64usize;
        // xorps xmm0,xmm0; movaps [rip+cell],xmm0  (insn at 3, len 7)
        let mut code = vec![0x0F, 0x57, 0xC0, 0x0F, 0x29, 0x05];
        code.extend_from_slice(&rel32(3, 7, cell));
        let mut e = emu_with(&code);
        e.xmm[0] = 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00;
        // preset a nonzero sentinel next to the cell to catch off-by-one stores
        e.write_u128(
            BASE + 0x1000 + cell as u64,
            0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF,
        )
        .unwrap();
        // step xorps -> zero
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[0], 0);
        // step movaps store -> cell zeroed
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.read_u128(BASE + 0x1000 + cell as u64).unwrap(), 0);

        // movups store of preset xmm1, movaps load back into xmm2.
        let mut code = vec![];
        code.extend_from_slice(&[0x0F, 0x11, 0x0D]); // movups [rip+cell],xmm1
        code.extend_from_slice(&rel32(0, 7, cell));
        code.extend_from_slice(&[0x0F, 0x28, 0x15]); // movaps xmm2,[rip+cell]
        code.extend_from_slice(&rel32(7, 7, cell));
        let mut e = emu_with(&code);
        e.xmm[1] = 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF;
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(
            e.read_u128(BASE + 0x1000 + cell as u64).unwrap(),
            0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF
        );
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[2], 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF);
    }

    #[test]
    fn movmskps_collects_packed_single_sign_bits() {
        // MOVMSKPS r8d, xmm1. Lanes 0 and 2 have their sign bits set.
        let mut e = emu_with(&[0x44, 0x0F, 0x50, 0xC1]);
        e.xmm[1] = 0x0000_0000_8000_0000_0000_0000_8000_0000;
        e.regs[8] = u64::MAX;
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.regs[8], 0b0101);
    }

    #[test]
    fn paddq_wraps_each_qword_lane() {
        let mut e = emu_with(&[0x66, 0x0F, 0xD4, 0xC1]); // paddq xmm0,xmm1
        e.xmm[0] = 0x0000_0000_0000_0005_FFFF_FFFF_FFFF_FFFF;
        e.xmm[1] = 0x0000_0000_0000_0007_0000_0000_0000_0002;
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[0], 0x0000_0000_0000_000C_0000_0000_0000_0001);
    }

    #[test]
    fn packed_adds_wrap_within_byte_word_and_dword_lanes() {
        let mut e = emu_with(&[
            0x66, 0x0F, 0xFC, 0xC1, // paddb xmm0,xmm1
            0x66, 0x0F, 0xFD, 0xD3, // paddw xmm2,xmm3
            0x66, 0x0F, 0xFE, 0xE5, // paddd xmm4,xmm5
        ]);
        e.xmm[0] = 0xFF;
        e.xmm[1] = 2;
        e.xmm[2] = 0xFFFF;
        e.xmm[3] = 2;
        e.xmm[4] = 0xFFFF_FFFF;
        e.xmm[5] = 2;
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[0] & 0xff, 1);
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[2] & 0xffff, 1);
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[4] & 0xffff_ffff, 1);
    }

    #[test]
    fn psadbw_sums_absolute_byte_differences_per_half() {
        let mut e = emu_with(&[0x66, 0x0F, 0xF6, 0xC1]); // psadbw xmm0,xmm1
        e.xmm[0] = u128::from_le_bytes([
            0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150,
        ]);
        e.xmm[1] = u128::from_le_bytes([
            1, 8, 25, 25, 50, 40, 65, 60, 70, 100, 90, 120, 110, 135, 130, 155,
        ]);
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[0] as u64, 48);
        assert_eq!((e.xmm[0] >> 64) as u64, 70);
    }

    #[test]
    fn group1b_adc_and_sbb_use_the_incoming_carry() {
        // adc al, 1; sbb al, 1
        let mut e = emu_with(&[0x80, 0xD0, 0x01, 0x80, 0xD8, 0x01]);
        e.regs[0] = 0xff;
        e.cf = true;
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.regs[0] & 0xff, 1);
        assert!(e.cf);
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.regs[0] & 0xff, 0xff);
        assert!(e.cf);
    }

    #[test]
    fn pextrw_zero_extends_the_selected_word_lane() {
        let mut e = emu_with(&[0x66, 0x44, 0x0F, 0xC5, 0xC1, 0x06]); // pextrw r8d,xmm1,6
        e.xmm[1] = 0x8899_AABB_CCDD_EEFF_0011_2233_4455_6677;
        e.regs[8] = u64::MAX;
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.regs[8], 0xAABB);
    }

    #[test]
    fn punpckldq_and_punpckhdq_interleave_dword_lanes() {
        let mut e = emu_with(&[
            0x66, 0x0F, 0x62, 0xC1, // punpckldq xmm0,xmm1
            0x66, 0x0F, 0x6A, 0xD3, // punpckhdq xmm2,xmm3
        ]);
        e.xmm[0] = 0x0000_0004_0000_0003_0000_0002_0000_0001;
        e.xmm[1] = 0x0000_0008_0000_0007_0000_0006_0000_0005;
        e.xmm[2] = e.xmm[0];
        e.xmm[3] = e.xmm[1];
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[0], 0x0000_0006_0000_0002_0000_0005_0000_0001);
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[2], 0x0000_0008_0000_0004_0000_0007_0000_0003);
    }

    #[test]
    fn packed_word_immediate_shifts_cover_logical_and_arithmetic_forms() {
        // psrlw xmm0, 4; psraw xmm1, 20; psllw xmm2, 1
        let mut e = emu_with(&[
            0x66, 0x0F, 0x71, 0xD0, 0x04, 0x66, 0x0F, 0x71, 0xE1, 0x14, 0x66, 0x0F, 0x71, 0xF2,
            0x01,
        ]);
        e.xmm[0] = u128::from_le_bytes([0x00, 0xF0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        e.xmm[1] = u128::from_le_bytes([0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        e.xmm[2] = 1;
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[0] & 0xffff, 0x0f00);
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[1] & 0xffff, 0xffff);
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert_eq!(e.xmm[2] & 0xffff, 2);
    }

    #[test]
    fn grp1b_cmp8_flags() {
        // cmp byte [rip+cell], imm8  (80 3D disp32 ib)
        let cell = 64usize;
        let mut code = vec![0x80, 0x3D];
        code.extend_from_slice(&rel32(0, 7, cell));
        code.push(0x41);
        let mut e = emu_with(&code);
        e.write_u8(BASE + 0x1000 + cell as u64, 0x41).unwrap();
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert!(e.zf); // equal

        let mut code = vec![0x80, 0x3D];
        code.extend_from_slice(&rel32(0, 7, cell));
        code.push(0x42);
        let mut e = emu_with(&code);
        e.write_u8(BASE + 0x1000 + cell as u64, 0x41).unwrap();
        assert!(matches!(e.step().unwrap(), StepResult::Continue));
        assert!(!e.zf);
        assert!(e.cf); // 0x41 < 0x42 borrows
    }

    #[test]
    fn setcc_and_test8() {
        // xor eax,eax (ZF=1); setz al (->1); setnz bl (->0, flags untouched);
        // test al,al (->ZF=0).
        let code = vec![
            0x31, 0xC0, // xor eax,eax
            0x0F, 0x94, 0xC0, // setz al
            0x0F, 0x95, 0xC3, // setnz bl
            0x84, 0xC0, // test al,al
        ];
        let mut e = emu_with(&code);
        for _ in 0..4 {
            assert!(matches!(e.step().unwrap(), StepResult::Continue));
        }
        assert_eq!(e.regs[0] & 0xFF, 1);
        assert_eq!(e.regs[3] & 0xFF, 0);
        assert!(!e.zf);
    }

    #[test]
    fn quote_arg_rules() {
        assert_eq!(quote_arg("abc"), "abc");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg("a\tb"), "\"a\tb\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("a\\"), "a\\"); // no quoting needed
        assert_eq!(quote_arg("a\\ b"), "\"a\\ b\"");
        assert_eq!(quote_arg("a\\"), "a\\");
    }

    #[test]
    fn quote_arg_trailing_backslash_doubled() {
        // backslashes immediately before the closing quote are doubled
        assert_eq!(quote_arg("a b\\"), "\"a b\\\\\"");
        // ...but not backslashes followed by other chars
        assert_eq!(quote_arg("C:\\x\\ "), "\"C:\\x\\ \"");
    }

    #[test]
    fn cmdline_layout_roundtrip() {
        let mut e = emu_with(&[0x90]); // nop; we only need memory
        e.alloc_cmdline("prog.exe", &["a".to_string(), "b c".to_string()])
            .unwrap();
        assert_eq!(e.read_utf16(e.cmdline_va).unwrap(), "prog.exe a \"b c\"");
        // ANSI block follows the wide block + NUL
        let wide_len = "prog.exe a \"b c\"".encode_utf16().count() + 1;
        let ansi_va = e.cmdline_va + wide_len as u64 * 2;
        assert_eq!(e.cmdline_ansi_va, ansi_va);
        assert_eq!(
            e.read_bytes(ansi_va, "prog.exe a \"b c\"".len()).unwrap(),
            b"prog.exe a \"b c\""
        );
    }

    #[test]
    fn test16_sets_flags() {
        // 66 85 C0  test ax,ax  (after xor eax,eax -> ZF=1)
        let mut e = emu_with(&[0x31, 0xC0, 0x66, 0x85, 0xC0]);
        e.step().unwrap();
        assert!(e.zf);
        e.step().unwrap();
        assert!(e.zf); // ax == 0
    }

    #[test]
    fn mov16_preserves_upper() {
        // mov ecx,0x12345678 ; mov cx,0x00FF -> ecx == 0x123400FF
        let mut e = emu_with(&[0xB9, 0x78, 0x56, 0x34, 0x12, 0x66, 0xB9, 0xFF, 0x00]);
        e.step().unwrap();
        e.step().unwrap();
        assert_eq!(e.regs[1], 0x1234_00FF);
    }

    #[test]
    fn cmov_taken_and_not_taken() {
        // xor eax,eax (ZF=1); mov ecx,7; cmovz edx,ecx (->7); cmovnz ebx,ecx (stays 0)
        let mut e = emu_with(&[
            0x31, 0xC0, // xor eax,eax
            0xB9, 0x07, 0x00, 0x00, 0x00, // mov ecx,7
            0x0F, 0x44, 0xD1, // cmovz edx,ecx
            0x0F, 0x45, 0xD9, // cmovnz ebx,ecx
        ]);
        for _ in 0..4 {
            e.step().unwrap();
        }
        assert_eq!(e.regs[2], 7);
        assert_eq!(e.regs[3], 0);
    }

    #[test]
    fn multibyte_nop_skips_operand() {
        // 0F 1F 40 00 (nopl [rax]) then ret would pop sentinel; just check RIP
        let mut e = emu_with(&[0x0F, 0x1F, 0x40, 0x00, 0x90]);
        e.step().unwrap();
        assert_eq!(e.rip, e.base + 0x1000 + 4);
    }

    #[test]
    fn seg_override_skipped_but_fs_errors() {
        // 2E 90 = CS nop -> fine
        let mut e = emu_with(&[0x2E, 0x90]);
        e.step().unwrap();
        // 64 90 = FS nop -> clear TLS error
        let mut e = emu_with(&[0x64, 0x90]);
        let err = e.step().unwrap_err();
        assert!(err.contains("thread-local"), "{err}");
    }

    #[test]
    fn unsupported_16bit_push_fails_clearly() {
        // 66 50 = 16-bit push (not modeled)
        let mut e = emu_with(&[0x66, 0x50]);
        let err = e.step().unwrap_err();
        assert!(err.contains("16-bit"), "{err}");
    }

    #[test]
    fn add16_now_supported() {
        // 66 01 C0 = add ax,ax with ax=1 -> 2
        let mut e = emu_with(&[0x66, 0xB8, 0x01, 0x00, 0x66, 0x01, 0xC0]);
        e.step().unwrap();
        e.step().unwrap();
        assert_eq!(e.regs[0] & 0xFFFF, 2);
    }

    fn run(code: &[u8], steps: usize) -> Emu {
        let mut e = emu_with(code);
        for _ in 0..steps {
            e.step().unwrap();
        }
        e
    }

    #[test]
    fn shifts() {
        // mov eax,1; shl eax,3 -> 8
        let e = run(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC1, 0xE0, 0x03], 2);
        assert_eq!(e.regs[0], 8);
        assert!(!e.cf);
        // mov eax,0x80; shr eax,3 -> 0x10
        let e = run(&[0xB8, 0x80, 0x00, 0x00, 0x00, 0xC1, 0xE8, 0x03], 2);
        assert_eq!(e.regs[0], 0x10);
        // mov eax,-8; sar eax,1 -> -4, CF=0
        let e = run(&[0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0xC1, 0xF8, 0x01], 2);
        assert_eq!(e.regs[0], 0xFFFF_FFFC);
        assert!(!e.cf);
        // shl by 1 sets CF from top bit: 0x80000000 << 1 -> 0, CF=1
        let e = run(&[0xB8, 0x00, 0x00, 0x00, 0x80, 0xC1, 0xE0, 0x01], 2);
        assert_eq!(e.regs[0] & 0xFFFF_FFFF, 0);
        assert!(e.cf);
    }

    #[test]
    fn mul_div() {
        // eax=7, ebx=6; mul ebx -> eax=42, edx=0, CF=0
        let e = run(
            &[
                0xB8, 0x07, 0x00, 0x00, 0x00, 0xBB, 0x06, 0x00, 0x00, 0x00, 0xF7, 0xE3,
            ],
            3,
        );
        assert_eq!(e.regs[0] & 0xFFFF_FFFF, 42);
        assert_eq!(e.regs[2] & 0xFFFF_FFFF, 0);
        assert!(!e.cf);
        // edx=0, eax=42, ecx=5; div ecx -> eax=8, edx=2
        let e = run(
            &[
                0x31, 0xD2, // xor edx,edx
                0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax,42
                0xB9, 0x05, 0x00, 0x00, 0x00, // mov ecx,5
                0xF7, 0xF1, // div ecx
            ],
            4,
        );
        assert_eq!(e.regs[0] & 0xFFFF_FFFF, 8);
        assert_eq!(e.regs[2] & 0xFFFF_FFFF, 2);
    }

    #[test]
    fn div_by_zero_is_de_error() {
        // xor ecx,ecx; div ecx
        let mut e = emu_with(&[0x31, 0xC9, 0xF7, 0xF1]);
        e.step().unwrap();
        let err = e.step().unwrap_err();
        assert!(err.contains("#DE"), "{err}");
    }

    #[test]
    fn neg_not_test8() {
        // mov al,5; neg al -> 0xFB, CF=1
        let e = run(&[0xB0, 0x05, 0xF6, 0xD8], 2);
        assert_eq!(e.regs[0] & 0xFF, 0xFB);
        assert!(e.cf);
        // mov al,0xF0; not al -> 0x0F
        let e = run(&[0xB0, 0xF0, 0xF6, 0xD0], 2);
        assert_eq!(e.regs[0] & 0xFF, 0x0F);
    }

    fn step1(code: &[u8], e: &mut Emu) {
        e.step().unwrap();
        let _ = code;
    }

    #[test]
    fn punpcklbw_vector() {
        // movdqu xmm0,[a]; movdqu xmm1,[b]; punpcklbw xmm0,xmm1
        // (RIP-rel loads from data cells)
        let mut code = vec![];
        code.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x05]); // movdqu xmm0,[rip+da]
        let d0 = code.len();
        code.extend_from_slice(&[0u8; 4]);
        code.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x0D]); // movdqu xmm1,[rip+db]
        let d1 = code.len();
        code.extend_from_slice(&[0u8; 4]);
        code.extend_from_slice(&[0x66, 0x0F, 0x60, 0xC1]); // punpcklbw xmm0,xmm1
        let cell_a = 64usize;
        let cell_b = 80usize;
        // patch disps: disp = target - (pos + len); insn0 at 0 len 8.
        code[d0..d0 + 4].copy_from_slice(&((cell_a as i64 - 8) as i32).to_le_bytes());
        code[d1..d1 + 4].copy_from_slice(&((cell_b as i64 - 16) as i32).to_le_bytes());
        let mut e = emu_with(&code);
        let base = 0x1400_0000_000u64 + 0x1000;
        for i in 0..16u64 {
            e.write_u8(base + cell_a as u64 + i, i as u8).unwrap();
            e.write_u8(base + cell_b as u64 + i, (100 + i) as u8)
                .unwrap();
        }
        step1(&[], &mut e);
        step1(&[], &mut e);
        step1(&[], &mut e);
        let got = e.read_bytes(base + cell_a as u64, 0).unwrap();
        let _ = got;
        assert_eq!(
            e.xmm[0].to_le_bytes()[..],
            [0u8, 100, 1, 101, 2, 102, 3, 103, 4, 104, 5, 105, 6, 106, 7, 107]
        );
    }

    #[test]
    fn pcmpeqb_pmovmskb_tzcnt_chain() {
        // xmm0 = [7,0,7,5,0...]; pcmpeqb vs broadcast loaded from cell
        let mut code = vec![];
        // movdqu xmm1,[rip+cell_b] (broadcast of 7s)
        code.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x0D]);
        let d0 = code.len();
        code.extend_from_slice(&[0u8; 4]);
        // movdqu xmm0,[rip+cell_a]
        code.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x05]);
        let d1 = code.len();
        code.extend_from_slice(&[0u8; 4]);
        // pcmpeqb xmm0,xmm1
        code.extend_from_slice(&[0x66, 0x0F, 0x74, 0xC1]);
        // pmovmskb eax,xmm0
        code.extend_from_slice(&[0x66, 0x0F, 0xD7, 0xC0]);
        // tzcnt ecx,eax
        code.extend_from_slice(&[0xF3, 0x0F, 0xBC, 0xC8]);
        let cell_a = 96usize;
        let cell_b = 112usize;
        // insn0 at 0 len 8 (F3 prefix), insn1 at 8 len 8
        code[d0..d0 + 4].copy_from_slice(&((cell_b as i64 - 8) as i32).to_le_bytes());
        code[d1..d1 + 4].copy_from_slice(&((cell_a as i64 - 16) as i32).to_le_bytes());
        let mut e = emu_with(&code);
        let base = 0x1400_0000_000u64 + 0x1000;
        let mut av = [0u8; 16];
        av[0] = 7;
        av[2] = 7;
        av[3] = 5;
        for i in 0..16u64 {
            e.write_u8(base + cell_a as u64 + i, av[i as usize])
                .unwrap();
            e.write_u8(base + cell_b as u64 + i, 7).unwrap();
        }
        for _ in 0..5 {
            e.step().unwrap();
        }
        // mask bytes: ff 00 ff 00 00... -> pmovmskb = 0b0101 = 5, tzcnt = 0
        assert_eq!(e.regs[0] & 0xFFFF_FFFF, 5);
        assert_eq!(e.regs[1] & 0xFFFF_FFFF, 0);
    }

    #[test]
    fn broadcast_compare_mask_chain() {
        // Exact sequence from the stuck loop prologue:
        // movd r13d,xmm0 / punpcklbw / pshuflw 0 / pshufd 0x44 / pcmpeqb / pmovmskb
        // r13d = 0x72 -> xmm6 should become 16x 0x72; chunk with 0x72 at
        // offset 9 must yield mask bit 9.
        let mut code = vec![];
        // mov r13d, 0x72 (41 BD imm32)
        code.extend_from_slice(&[0x41, 0xBD, 0x72, 0x00, 0x00, 0x00]);
        // movd xmm0, r13d  (66 41 0F 6E C5)
        code.extend_from_slice(&[0x66, 0x41, 0x0F, 0x6E, 0xC5]);
        // punpcklbw xmm0,xmm0 (66 0F 60 C0)
        code.extend_from_slice(&[0x66, 0x0F, 0x60, 0xC0]);
        // pshuflw $0, xmm0,xmm0 (F2 0F 70 C0 00)
        code.extend_from_slice(&[0xF2, 0x0F, 0x70, 0xC0, 0x00]);
        // pshufd $0x44, xmm0,xmm6 (66 0F 70 F0 44)
        code.extend_from_slice(&[0x66, 0x0F, 0x70, 0xF0, 0x44]);
        // movdqu xmm0,[rip+cell] (F3 0F 6F 05 disp)
        let pos0 = code.len();
        code.extend_from_slice(&[0xF3, 0x0F, 0x6F, 0x05]);
        let d0 = code.len();
        code.extend_from_slice(&[0u8; 4]);
        // pcmpeqb xmm0,xmm6 (66 0F 74 C6)
        code.extend_from_slice(&[0x66, 0x0F, 0x74, 0xC6]);
        // pmovmskb eax,xmm0 (66 0F D7 C0)
        code.extend_from_slice(&[0x66, 0x0F, 0xD7, 0xC0]);
        let cell = 96usize;
        // disp = target - (pos + len); movdqu is 8 bytes with F3 prefix
        code[d0..d0 + 4].copy_from_slice(&((cell as i64 - (pos0 + 8) as i64) as i32).to_le_bytes());
        let mut e = emu_with(&code);
        let base = 0x1400_0000_000u64 + 0x1000;
        // chunk: 0x72 at offset 9, zeros elsewhere... plus junk
        let mut chunk = [0x41u8; 16];
        chunk[9] = 0x72;
        for i in 0..16u64 {
            e.write_u8(base + cell as u64 + i, chunk[i as usize])
                .unwrap();
        }
        for _ in 0..8 {
            e.step().unwrap();
        }
        assert_eq!(e.xmm[6].to_le_bytes(), [0x72u8; 16]);
        // mask: only bit 9 set -> 0x200
        assert_eq!(e.regs[0] & 0xFFFF_FFFF, 0x200);
    }

    #[test]
    fn pinsrw_inserts_word_lane() {
        // mov eax,0xBEEF; pinsrw xmm2,eax,3 -> word lane 3 = EF BE,
        // other lanes preserved (pre-set xmm2 to all 0x11).
        let mut e = emu_with(&[
            0xB8, 0xEF, 0xBE, 0x00, 0x00, // mov eax,0xBEEF
            0x66, 0x0F, 0xC4, 0xD0, 0x03, // pinsrw xmm2,eax,3
        ]);
        e.xmm[2] = u128::from_le_bytes([0x11u8; 16]);
        for _ in 0..2 {
            e.step().unwrap();
        }
        let mut expect = [0x11u8; 16];
        expect[6] = 0xEF;
        expect[7] = 0xBE;
        assert_eq!(e.xmm[2].to_le_bytes(), expect);
    }

    #[test]
    fn msvc_memcpy_tail_xmm5_rexx_sib() {
        // Exact bytes of the suspect MSVC epilogue: tail load into xmm5
        // (SIB rdx+r8, disp8 -16, REX.X) then tail store (rcx+r8, -16).
        // movdqu -0x10(%rdx,%r8,1),%xmm5
        // movdqu %xmm5,-0x10(%rcx,%r8,1)
        let mut e = emu_with(&[
            0xF3, 0x42, 0x0F, 0x6F, 0x6C, 0x02, 0xF0, 0xF3, 0x42, 0x0F, 0x7F, 0x6C, 0x01, 0xF0,
        ]);
        let base = 0x1400_0000_000u64 + 0x2000;
        let src = base;
        let dst = base + 0x500;
        let pattern = b"0123456789ABCDEF";
        for (i, b) in pattern.iter().enumerate() {
            e.write_u8(src + 196 + i as u64, *b).unwrap();
            e.write_u8(dst + 196 + i as u64, 0).unwrap();
        }
        e.regs[2] = src; // rdx
        e.regs[1] = dst; // rcx
        e.regs[8] = 212; // r8 = size
        for _ in 0..2 {
            e.step().unwrap();
        }
        assert_eq!(e.xmm[5].to_le_bytes(), *pattern);
        for (i, b) in pattern.iter().enumerate() {
            assert_eq!(e.read_u8(dst + 196 + i as u64).unwrap(), *b);
        }
    }

    #[test]
    fn msvc_jmptab_load_sib_rex_rxb() {
        // Same shape as the memcpy epilogue dispatch (REX.RXB, SIB
        // scale-4 r11-indexed, disp32) with a small displacement:
        // mov 0x10(%r10,%r11,4),%r11d
        let mut e = emu_with(&[0x47, 0x8B, 0x9C, 0x9A, 0x10, 0x00, 0x00, 0x00]);
        let base = 0x1400_0000_000u64 + 0x3000;
        e.regs[10] = base; // r10 = table base
        e.regs[11] = 6; // r11 = case index (also the dest)
        let ea = base + 6 * 4 + 0x10;
        e.write_u32(ea, 0xDEADBEEF).unwrap();
        e.step().unwrap();
        assert_eq!(e.regs[11] & 0xFFFF_FFFF, 0xDEADBEEF);
    }

    #[test]
    fn msvc_epilogue_r9_and_r9store() {
        // Exact epilogue prologue + one r9-indexed store:
        // lea r9,[r8+15] / and r9,-16 / movdqu %xmm1,-0x20(%rcx,%r9,1).
        // With r8=84: r9 must be 96 and the store must land at dst+64.
        let mut e = emu_with(&[
            0x4D, 0x8D, 0x48, 0x0F, // lea 0xf(%r8),%r9
            0x49, 0x83, 0xE1, 0xF0, // and $~0xf,%r9
            0xF3, 0x42, 0x0F, 0x7F, 0x4C, 0x09, 0xE0, // movdqu %xmm1,-0x20(%rcx,%r9,1)
        ]);
        let base = 0x1400_0000_000u64 + 0x4000;
        let dst = base + 0x500;
        e.regs[8] = 84; // r8 = remaining
        e.regs[1] = dst; // rcx
        e.xmm[1] = u128::from_le_bytes(*b"0123456789ABCDEF");
        for _ in 0..3 {
            e.step().unwrap();
        }
        assert_eq!(e.regs[9], 96);
        for (i, b) in b"0123456789ABCDEF".iter().enumerate() {
            assert_eq!(e.read_u8(dst + 64 + i as u64).unwrap(), *b);
        }
    }

    #[test]
    fn msvc_small_memcpy_case15_rex_bytes() {
        // Exact bytes of the UCRT small-memcpy 15-byte case: qword +
        // dword + REX movzwl/movzbl loads, then REX byte/word stores.
        let mut e = emu_with(&[
            0x4C, 0x8B, 0x02, // mov (%rdx),%r8
            0x8B, 0x4A, 0x08, // mov 0x8(%rdx),%ecx
            0x44, 0x0F, 0xB7, 0x4A, 0x0C, // movzwl 0xc(%rdx),%r9d
            0x44, 0x0F, 0xB6, 0x52, 0x0E, // movzbl 0xe(%rdx),%r10d
            0x4C, 0x89, 0x00, // mov %r8,(%rax)
            0x89, 0x48, 0x08, // mov %ecx,0x8(%rax)
            0x66, 0x44, 0x89, 0x48, 0x0C, // mov %r9w,0xc(%rax)
            0x44, 0x88, 0x50, 0x0E, // mov %r10b,0xe(%rax)
        ]);
        let base = 0x1400_0000_000u64 + 0x5000;
        let src = base;
        let dst = base + 0x100;
        let pattern = b"0123456789ABCDE";
        for (i, b) in pattern.iter().enumerate() {
            e.write_u8(src + i as u64, *b).unwrap();
            e.write_u8(dst + i as u64, 0).unwrap();
        }
        e.regs[2] = src; // rdx
        e.regs[0] = dst; // rax
        for _ in 0..8 {
            e.step().unwrap();
        }
        for (i, b) in pattern.iter().enumerate() {
            assert_eq!(e.read_u8(dst + i as u64).unwrap(), *b, "byte {i}");
        }
    }

    #[test]
    fn movq_load_no_rex_loads_qword() {
        // F3 0F 7E with no REX.W is still MOVQ (8 bytes), not MOVD.
        let mut e = emu_with(&[0xF3, 0x0F, 0x7E, 0x06]);
        let base = 0x1400_0000_000u64 + 0x7000;
        let pattern = b"ABCDEFGH";
        for (i, b) in pattern.iter().enumerate() {
            e.write_u8(base + i as u64, *b).unwrap();
        }
        e.regs[6] = base; // rsi; ModRM 06 = [rsi], reg xmm0
        e.step().unwrap();
        assert_eq!(
            e.xmm[0].to_le_bytes()[..8],
            *pattern,
            "low qword must hold all 8 bytes"
        );
        assert_eq!(e.xmm[0].to_le_bytes()[8..], [0u8; 8]);
    }

    #[test]
    fn movq_load_sib_index_advances() {
        // F3 0F 7E with SIB [rsi+rcx]: two consecutive 8-byte loads must
        // read successive chunks (index honored).
        let mut e = emu_with(&[
            0xF3, 0x0F, 0x7E, 0x04, 0x0E, // movq (%rsi,%rcx,1),%xmm0
            0xF3, 0x0F, 0x7E, 0x0C, 0x0E, // movq (%rsi,%rcx,1),%xmm1
        ]);
        let base = 0x1400_0000_000u64 + 0x8000;
        // Canaries: which address is actually read?
        for (i, b) in b"ABCDEFGH".iter().enumerate() {
            e.write_u8(base + i as u64, *b).unwrap();
        }
        for (i, b) in b"IJKLMNOP".iter().enumerate() {
            e.write_u8(base + 8 + i as u64, *b).unwrap();
        }
        for (i, b) in b"QRSTUVWX".iter().enumerate() {
            e.write_u8(base + 16 + i as u64, *b).unwrap();
        }
        for (i, b) in b"YZabcdef".iter().enumerate() {
            e.write_u8(base + 64 + i as u64, *b).unwrap();
        }
        e.regs[6] = base; // rsi
        e.regs[1] = 8; // rcx
        e.step().unwrap();
        eprintln!("DBG xmm0={:032x}", e.xmm[0]);
        assert_eq!(e.xmm[0].to_le_bytes()[..8], *b"IJKLMNOP", "xmm0");
        e.step().unwrap();
        assert_eq!(e.xmm[1].to_le_bytes()[..8], *b"IJKLMNOP", "xmm1");
    }

    #[test]
    fn movq_store_rex_advances_rip() {
        // 66 41 0F D6 0C 0C is 6 bytes; rip must advance past it and the
        // low qword must land at [r12+rcx].
        let mut e = emu_with(&[0x66, 0x41, 0x0F, 0xD6, 0x0C, 0x0C]);
        let base = 0x1400_0000_000u64 + 0x9000;
        e.regs[12] = base; // r12
        e.regs[1] = 0; // rcx
        e.xmm[1] = u128::from_le_bytes(*b"0123456789ABCDEF");
        let rip0 = e.rip;
        e.step().unwrap();
        assert_eq!(e.rip, rip0 + 6, "rip must advance 6");
        for (i, b) in b"01234567".iter().enumerate() {
            assert_eq!(e.read_u8(base + i as u64).unwrap(), *b, "byte {i}");
        }
    }

    #[test]
    fn movss_load_store_scalar() {
        // F3 0F 10 C8: movss xmm1,xmm0 -> low 32 bits, high zeroed.
        let mut e = emu_with(&[0xF3, 0x0F, 0x10, 0xC8]);
        e.xmm[0] = u128::from_le_bytes([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ]);
        e.xmm[1] = u128::from_le_bytes([0xFFu8; 16]);
        e.step().unwrap();
        assert_eq!(
            e.xmm[1].to_le_bytes(),
            [
                0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
        );
        // F3 0F 11 m32,xmm: covered by the masked-loop integration below.
    }

    #[test]
    fn sse_masked_copy_loop_identity_and_match() {
        // Exact bytes of the suspect masked-copy loop (rg.exe 0x140084746):
        // movq (rsi+rcx),xmm0 / movdqa xmm0,xmm1 / pcmpeqb xmm7,xmm1 /
        // movdqa xmm1,xmm2 / pandn xmm0,xmm2 / pand xmm8,xmm1 /
        // por xmm2,xmm1 / movq [r12+rcx],xmm1 / add rcx,8 / cmp rcx,rax
        // / jne top. With no needle hits it must copy exactly; hits
        // become 0xFF.
        let code = [
            0xF3, 0x0F, 0x7E, 0x04, 0x0E, // movq (%rsi,%rcx,1),%xmm0
            0x66, 0x0F, 0x6F, 0xC8, // movdqa %xmm0,%xmm1
            0x66, 0x0F, 0x74, 0xCF, // pcmpeqb %xmm7,%xmm1
            0x66, 0x0F, 0x6F, 0xD1, // movdqa %xmm1,%xmm2
            0x66, 0x0F, 0xDF, 0xD0, // pandn %xmm0,%xmm2
            0x66, 0x41, 0x0F, 0xDB, 0xC8, // pand %xmm8,%xmm1
            0x66, 0x0F, 0xEB, 0xCA, // por %xmm2,%xmm1
            0x66, 0x41, 0x0F, 0xD6, 0x0C, 0x0C, // movq %xmm1,(%r12,%rcx,1)
            0x48, 0x83, 0xC1, 0x08, // add $0x8,%rcx
            0x48, 0x39, 0xC8, // cmp %rcx,%rax
            0x75, 0xD3, // jne top (-45; body is 45 bytes)
        ];
        let mut e = emu_with(&code);
        let base = 0x1400_0000_000u64 + 0x6000;
        let src = base;
        let dst = base + 0x100;
        let input = b"ABCDEFGHAJKLMNOP";
        for (i, b) in input.iter().enumerate() {
            e.write_u8(src + i as u64, *b).unwrap();
            e.write_u8(dst + i as u64, 0).unwrap();
        }
        e.regs[6] = src; // rsi
        e.regs[12] = dst; // r12
        e.regs[1] = 0; // rcx
        e.regs[0] = 16; // rax = len
        e.xmm[7] = u128::from_le_bytes([0x41u8; 16]); // needle 'A'
        e.xmm[8] = u128::from_le_bytes([0xFFu8; 16]); // mask
        for _ in 0..22 {
            e.step().unwrap();
        }
        // 'A' at 0 and 8 become 0xFF, rest copies exactly.
        let mut expect = *input;
        expect[0] = 0xFF;
        expect[8] = 0xFF;
        for (i, b) in expect.iter().enumerate() {
            assert_eq!(e.read_u8(dst + i as u64).unwrap(), *b, "byte {i}");
        }
    }

    #[test]
    fn grp4_inc_dec_r8_preserves_cf() {
        // stc; cl=0xFF; dec cl -> 0xFE, CF stays 1; inc cl -> 0xFF
        let e = run(&[0xF9, 0xB1, 0xFF, 0xFE, 0xC9, 0xFE, 0xC1], 4);
        assert_eq!(e.regs[1] & 0xFF, 0xFF);
        assert!(e.cf);
        assert!(!e.zf);
    }

    #[test]
    fn adc_sbb_al_imm8_chain_cf() {
        // stc; al=0xFE; adc al,1 -> 0x00, CF=1 (branchless cond-decrement shape)
        let e = run(&[0xF9, 0xB0, 0xFE, 0x14, 0x01], 3);
        assert_eq!(e.regs[0] & 0xFF, 0x00);
        assert!(e.cf);
        assert!(e.zf);
        // clc; al=5; adc al,3 -> 8, CF=0
        let e = run(&[0xF8, 0xB0, 0x05, 0x14, 0x03], 3);
        assert_eq!(e.regs[0] & 0xFF, 8);
        assert!(!e.cf);
        // stc; al=5; sbb al,3 -> 1, CF=0
        let e = run(&[0xF9, 0xB0, 0x05, 0x1C, 0x03], 3);
        assert_eq!(e.regs[0] & 0xFF, 1);
        assert!(!e.cf);
        // clc; al=3; sbb al,5 -> 0xFE, CF=1
        let e = run(&[0xF8, 0xB0, 0x03, 0x1C, 0x05], 3);
        assert_eq!(e.regs[0] & 0xFF, 0xFE);
        assert!(e.cf);
    }

    #[test]
    fn adc_chains() {
        // stc; rax=-1; rbx=1; adc rax,rbx -> rax=1, CF=1
        let e = run(
            &[
                0xF9, 0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0xBB, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x11, 0xD8,
            ],
            4,
        );
        assert_eq!(e.regs[0], 1);
        assert!(e.cf);
        // clc; rax=5; rbx=3; adc rax,rbx -> 8, CF=0
        let e = run(
            &[
                0xF8, 0x48, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBB, 0x03,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x11, 0xD8,
            ],
            4,
        );
        assert_eq!(e.regs[0], 8);
        assert!(!e.cf);
    }
    #[test]
    fn sbb_chains() {
        // clc; rax=5; rbx=3; sbb rax,rbx -> 2, CF=0
        let e = run(
            &[
                0xF8, 0x48, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBB, 0x03,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x19, 0xD8,
            ],
            4,
        );
        assert_eq!(e.regs[0], 2);
        assert!(!e.cf);
        // clc; rax=3; rbx=5; sbb -> 0xFFFF...FE, CF=1
        let e = run(
            &[
                0xF8, 0x48, 0xB8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBB, 0x05,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x19, 0xD8,
            ],
            4,
        );
        assert_eq!(e.regs[0], 0xFFFF_FFFF_FFFF_FFFE);
        assert!(e.cf);
        // stc; rax=5; rbx=5; sbb -> -1, CF=1
        let e = run(
            &[
                0xF9, 0x48, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBB, 0x05,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x19, 0xD8,
            ],
            4,
        );
        assert_eq!(e.regs[0], 0xFFFF_FFFF_FFFF_FFFF);
        assert!(e.cf);
    }
    #[test]
    fn rol_semantics() {
        // mov eax,0x80000001; rol eax,1 -> 3, CF=1, OF=1, ZF/SF untouched
        let mut e = emu_with(&[0xB8, 0x01, 0x00, 0x00, 0x80, 0xC1, 0xC0, 0x01]);
        e.step().unwrap();
        e.zf = true; // sentinel: rotates must not touch ZF
        e.step().unwrap();
        assert_eq!(e.regs[0] & 0xFFFF_FFFF, 3);
        assert!(e.cf);
        assert!(e.of);
        assert!(e.zf); // untouched
    }

    fn bits(x: f64) -> u64 {
        x.to_bits()
    }
    #[test]
    fn movsd_addsd() {
        // mov rbx, <bits 1.5>; movq xmm0,rbx; mov rbx,<bits 2.25>; movq xmm1,rbx
        // addsd xmm0,xmm1 -> 3.75
        let mut code = vec![];
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&bits(1.5).to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xC3]); // movq xmm0,rbx
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&bits(2.25).to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xCB]); // movq xmm1,rbx
        code.extend_from_slice(&[0xF2, 0x0F, 0x58, 0xC1]); // addsd xmm0,xmm1
        let e = run(&code, 5);
        assert_eq!((e.xmm[0] & 0xFFFFFFFFFFFFFFFF) as u64, bits(3.75));
    }
    #[test]
    fn ucomisd_flags() {
        // ucomisd xmm0,xmm1 with 1.0 vs 2.0 -> lt: ZF=0,PF=0,CF=1
        let mut code = vec![];
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&bits(1.0).to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xC3]);
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&bits(2.0).to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xCB]);
        code.extend_from_slice(&[0x66, 0x0F, 0x2E, 0xC1]); // ucomisd xmm0,xmm1
        let e = run(&code, 5);
        assert!(!e.zf && !e.pf && e.cf);
        // eq: ZF=1,PF=0,CF=0
        let mut code = vec![];
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&bits(2.0).to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xC3]);
        code.extend_from_slice(&[0x66, 0x0F, 0x2E, 0xC0]); // ucomisd xmm0,xmm0
        let e = run(&code, 3);
        assert!(e.zf && !e.pf && !e.cf);
    }
    #[test]
    fn andpd_orpd() {
        // movq both, andpd, orpd roundtrip
        let mut code = vec![];
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&0xFF00FF00FF00FF00u64.to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xC3]); // xmm0
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&0x0FF00FF00FF00FF0u64.to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xCB]); // xmm1
        code.extend_from_slice(&[0x66, 0x0F, 0x54, 0xC1]); // andpd xmm0,xmm1
        let e = run(&code, 5);
        assert_eq!(e.xmm[0], 0x0F000F000F000F00);
        let mut code = vec![];
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&0xFF00FF00FF00FF00u64.to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xC3]);
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&0x0FF00FF00FF00FF0u64.to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xCB]);
        code.extend_from_slice(&[0x66, 0x0F, 0x56, 0xC1]); // orpd xmm0,xmm1
        let e = run(&code, 5);
        assert_eq!(e.xmm[0], 0xFFF0_FFF0_FFF0_FFF0);
    }

    fn run2(code: &[u8], steps: usize) -> Emu {
        let mut e = emu_with(code);
        for _ in 0..steps {
            e.step().unwrap();
        }
        e
    }
    #[test]
    fn rcl_carries() {
        // stc; mov eax,0x80000000; rcl eax,1 -> 1, CF=1
        let e = run2(&[0xF9, 0xB8, 0x00, 0x00, 0x00, 0x80, 0xC1, 0xD0, 0x01], 3);
        assert_eq!(e.regs[0] & 0xFFFF_FFFF, 1);
        assert!(e.cf);
    }
    #[test]
    fn imul_imm() {
        // mov eax,7; imul eax,eax,6 -> 42
        let e = run2(
            &[
                0xB8, 0x07, 0x00, 0x00, 0x00, 0x69, 0xC0, 0x06, 0x00, 0x00, 0x00,
            ],
            2,
        );
        assert_eq!(e.regs[0] & 0xFFFF_FFFF, 42);
        assert!(!e.cf);
    }
    #[test]
    fn pand_family() {
        // movdqu pattern via immediates is long; use rax/rbx + movq
        // mov rax,0xFF00FF00FF00FF00; movq xmm0,rax
        // mov rbx,0x0FF00FF00FF00FF0; movq xmm1,rbx; pand xmm0,xmm1
        let mut code = vec![];
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&0xFF00FF00FF00FF00u64.to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xC0]); // modrm C0: rm=rax
        code.extend_from_slice(&[0x48, 0xBB]);
        code.extend_from_slice(&0x0FF00FF00FF00FF0u64.to_le_bytes());
        code.extend_from_slice(&[0x66, 0x48, 0x0F, 0x6E, 0xCB]); // modrm CB: rm=rbx
        code.extend_from_slice(&[0x66, 0x0F, 0xDB, 0xC1]);
        let e = run(&code, 5);
        assert_eq!(e.xmm[0], 0x0F000F000F000F00);
    }

    #[test]
    fn div64_basic() {
        // xor edx,edx is 32-bit; build 64-bit dividend manually:
        // mov rax,42; mov rcx,5; xor edx,edx would zero rdx... use:
        // mov rax,42 (48 B8); mov rcx,5 (48 B9); mov rdx,0 (48 BA 0); div rcx (48 F7 F1)
        let mut e = emu_with(&[
            0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x05, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x48, 0xF7, 0xF1,
        ]);
        for _ in 0..4 {
            e.step().unwrap();
        }
        assert_eq!(e.regs[0], 8);
        assert_eq!(e.regs[2], 2);
    }

    #[test]
    fn high_byte_reg_read_no_rex() {
        // movzx edx,bh (0F B6 D7, no REX): rm=7 means BH, not DIL.
        // RDI low byte is 1 to catch the old mis-decode (read DIL).
        let mut e = emu_with(&[0x0F, 0xB6, 0xD7]);
        e.regs[3] = 0x1234;
        e.regs[7] = 0xFF01;
        e.step().unwrap();
        assert_eq!(e.regs[2], 0x12);
    }

    #[test]
    fn high_byte_reg_write_no_rex() {
        // mov ah,0x42 (B4 42, no REX): writes bits 8-15 of RAX.
        let mut e = emu_with(&[0xB4, 0x42]);
        e.regs[0] = 0x1234;
        e.step().unwrap();
        assert_eq!(e.regs[0], 0x4234);
    }

    #[test]
    fn low_byte_reg_read_with_rex() {
        // movzx eax,sil (40 0F B6 C6): REX present, rm=6 means SIL.
        let mut e = emu_with(&[0x40, 0x0F, 0xB6, 0xC6]);
        e.regs[6] = 0xAB00;
        e.step().unwrap();
        assert_eq!(e.regs[0], 0x00);
        let mut e = emu_with(&[0x40, 0x0F, 0xB6, 0xC6]);
        e.regs[6] = 0xCDAB;
        e.step().unwrap();
        assert_eq!(e.regs[0], 0xAB);
    }

    #[test]
    fn fnv_iter_with_high_byte() {
        // Exact guest step that exposed the high-byte bug:
        // movzx edx,bh; xor rdx,rax; imul rdx,r10 (FNV-1a byte step).
        let mut e = emu_with(&[0x0F, 0xB6, 0xD7, 0x48, 0x31, 0xC2, 0x49, 0x0F, 0xAF, 0xD2]);
        e.regs[3] = 0; // RBX=0, so BH=0
        e.regs[7] = 1; // DIL=1: old code hashed 1 instead of BH=0
        e.regs[0] = 0xaf63bd4c8601b7df;
        e.regs[10] = 0x100000001b3;
        for _ in 0..3 {
            e.step().unwrap();
        }
        assert_eq!(e.regs[2], 0x8328807b4eb6fed);
    }

    #[test]
    fn high_regs() {
        // mov r8,0x11; mov r9,0x22; mov rax,r8; add rax,r9 -> 0x33
        // mov r10,[rsp-8]? use stack slot via rbp? simpler: push/pop r12-r15
        let mut e = emu_with(&[
            0x41, 0xB8, 0x11, 0x00, 0x00, 0x00, // mov r8d,0x11
            0x41, 0xB9, 0x22, 0x00, 0x00, 0x00, // mov r9d,0x22
            0x4C, 0x89, 0xC0, // mov rax,r8
            0x4C, 0x01, 0xC8, // add rax,r9
            0x41, 0x50, // push r8
            0x41, 0x5B, // pop r11
            0x4D, 0x89, 0xD9, // mov r9,r11
            0x4D, 0x8B,
            0xC3, // mov r8,rbx?? no: REX.WRB, 8B C3 = mov r8,rbx? modrm C3: reg 000 rm 011 +REX.B -> r11? rm=8+3=11=r11, reg=0+REX.R(1<<3)=8=r8: mov r8,r11
        ]);
        for _ in 0..7 {
            e.step().unwrap();
        }
        assert_eq!(e.regs[0], 0x33);
        assert_eq!(e.regs[11], 0x11);
        assert_eq!(e.regs[9], 0x11);
        assert_eq!(e.regs[8], 0x11);
    }

    #[test]
    fn initial_rsp_in_stack_region() {
        // RSP must start at the top of the dedicated stack region (below
        // the heap and TEB), or deep stacks march down through TEB/heap
        // (real rg startup did exactly that). The sentinel push leaves the
        // standard entry invariant RSP%16==8.
        let e = emu_with(&[0x90]);
        assert_eq!(e.regs[4] % 16, 8);
        assert!(e.regs[4] < e.teb_va());
    }

    #[test]
    fn bt_family_reg() {
        // bts rax,r9 (4C 0F AB C8): CF = old bit, then set.
        let mut e = emu_with(&[0x4C, 0x0F, 0xAB, 0xC8]);
        e.regs[0] = 0;
        e.regs[9] = 5;
        e.zf = true; // BT leaves ZF alone
        e.step().unwrap();
        assert_eq!(e.regs[0], 0x20);
        assert!(!e.cf);
        assert!(e.zf);
        // bt edx,eax (0F A3 C2): test only.
        let mut e = emu_with(&[0x0F, 0xA3, 0xC2]);
        e.regs[2] = 0b1010;
        e.regs[0] = 1;
        e.step().unwrap();
        assert_eq!(e.regs[2], 0b1010);
        assert!(e.cf);
        // btr edx,eax (0F B3 C2): CF = old bit, then clear.
        let mut e = emu_with(&[0x0F, 0xB3, 0xC2]);
        e.regs[2] = 0b1010;
        e.regs[0] = 3;
        e.step().unwrap();
        assert_eq!(e.regs[2], 0b0010);
        assert!(e.cf);
        // btc edx,eax (0F BB C2): CF = old bit, then flip.
        let mut e = emu_with(&[0x0F, 0xBB, 0xC2]);
        e.regs[2] = 0b1010;
        e.regs[0] = 1;
        e.step().unwrap();
        assert_eq!(e.regs[2], 0b1000);
        assert!(e.cf);
    }

    #[test]
    fn movq_xmm_mem_reg() {
        // movq [rip+cell],xmm1 (66 0F D6 0D disp): stores low qword LE.
        let cell = 48usize;
        let mut code = vec![0x66, 0x0F, 0xD6, 0x0D];
        code.extend_from_slice(&rel32(0, 8, cell));
        let mut e = emu_with(&code);
        let base = BASE + 0x1000;
        e.xmm[1] = 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF;
        e.step().unwrap();
        assert_eq!(
            e.read_u64(base + cell as u64).unwrap(),
            0x8899_AABB_CCDD_EEFF
        );
        // movq xmm2,xmm1 (66 0F D6 CA): low qword, upper zeroed.
        let mut e = emu_with(&[0x66, 0x0F, 0xD6, 0xCA]);
        e.xmm[1] = 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF;
        e.xmm[2] = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;
        e.step().unwrap();
        assert_eq!(e.xmm[2], 0x8899_AABB_CCDD_EEFF);
        // MMX (no prefix) and MOVQ2DQ (F3) forms fail clearly.
        assert!(emu_with(&[0x0F, 0xD6, 0xCA]).step().is_err());
        assert!(emu_with(&[0xF3, 0x0F, 0xD6, 0xCA]).step().is_err());
    }

    #[test]
    fn subpd_addpd() {
        // Packed-double lanes, bit-identical via host f64 ops.
        let pack = |lo: f64, hi: f64| ((hi.to_bits() as u128) << 64) | lo.to_bits() as u128;
        let unpack = |v: u128| (f64::from_bits(v as u64), f64::from_bits((v >> 64) as u64));
        // subpd xmm0,xmm7 (66 0F 5C C7).
        let mut e = emu_with(&[0x66, 0x0F, 0x5C, 0xC7]);
        e.xmm[0] = pack(1.5, 2.5);
        e.xmm[7] = pack(0.5, 0.25);
        e.step().unwrap();
        assert_eq!(unpack(e.xmm[0]), (1.0, 2.25));
        // NaN propagates per IEEE (inf - inf).
        let mut e = emu_with(&[0x66, 0x0F, 0x5C, 0xC7]);
        e.xmm[0] = pack(f64::INFINITY, 1.0);
        e.xmm[7] = pack(f64::INFINITY, 0.0);
        e.step().unwrap();
        let (lo, hi) = unpack(e.xmm[0]);
        assert!(lo.is_nan());
        assert_eq!(hi, 1.0);
        // addpd xmm0,[rip+cell] (66 0F 58 05 disp): mem form.
        let cell = 64usize;
        let mut code = vec![0x66, 0x0F, 0x58, 0x05];
        code.extend_from_slice(&rel32(0, 8, cell));
        let mut e = emu_with(&code);
        e.write_u128(BASE + 0x1000 + cell as u64, pack(0.5, 0.25))
            .unwrap();
        e.xmm[0] = pack(1.5, 2.5);
        e.step().unwrap();
        assert_eq!(unpack(e.xmm[0]), (2.0, 2.75));
    }

    #[test]
    fn cvtsi2sd_int64_and_int32() {
        // cvtsi2sd xmm0,rax (F2 REX.W 0F 2A C0): low lane, upper kept.
        let mut e = emu_with(&[0xF2, 0x48, 0x0F, 0x2A, 0xC0]);
        e.xmm[0] = 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;
        e.regs[0] = 42;
        e.step().unwrap();
        assert_eq!(e.xmm[0], 0xFFFF_FFFF_FFFF_FFFF_4045_0000_0000_0000);
        // 64-bit negative and large values round like hardware.
        let mut e = emu_with(&[0xF2, 0x48, 0x0F, 0x2A, 0xC0]);
        e.regs[0] = (-7i64) as u64;
        e.step().unwrap();
        assert_eq!(e.xmm[0], (-7.0f64).to_bits() as u128);
        // cvtsi2sd xmm0,eax (F2 0F 2A C0): 32-bit sign-extended.
        let mut e = emu_with(&[0xF2, 0x0F, 0x2A, 0xC0]);
        e.regs[0] = 0xFFFF_FFFF;
        e.step().unwrap();
        assert_eq!(e.xmm[0], (-1.0f64).to_bits() as u128);
    }

    #[test]
    fn unpckhpd_reg() {
        // unpckhpd xmm1,xmm0 (66 0F 15 C8): high qwords [d_hi, s_hi].
        let mut e = emu_with(&[0x66, 0x0F, 0x15, 0xC8]);
        e.xmm[1] = u128::from_le_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);
        e.xmm[0] = u128::from_le_bytes([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ]);
        e.step().unwrap();
        assert_eq!(
            e.xmm[1].to_le_bytes(),
            [
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
                0x1E, 0x1F,
            ]
        );
        // Plain UNPCKHPS fails clearly.
        assert!(emu_with(&[0x0F, 0x15, 0xC8]).step().is_err());
    }

    #[test]
    fn packuswb_saturates() {
        // 66 0F 67 C6: words saturate signed to bytes (negatives to 0,
        // big to 0xFF), low 8 of each operand.
        let mut e = emu_with(&[0x66, 0x0F, 0x67, 0xC6]);
        e.xmm[0] = u128::from_le_bytes([
            0xFF, 0xFF, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x02, 0x7F, 0x00, 0x80, 0x00, 0xFF, 0x7F,
            0x00, 0x80,
        ]);
        let mut hi = [0u8; 16];
        for i in 0..8 {
            hi[2 * i] = 0x10 + i as u8;
            hi[2 * i + 1] = 0x00;
        }
        e.xmm[6] = u128::from_le_bytes(hi);
        e.step().unwrap();
        assert_eq!(
            e.xmm[0].to_le_bytes(),
            [
                0x00, 0xFF, 0xFF, 0xFF, 0x7F, 0x80, 0xFF, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17,
            ]
        );
    }

    #[test]
    fn movlps_movhps_merge_and_store() {
        let mut e = emu_with(&[
            0x0F, 0x12, 0x06, // movlps xmm0,[rsi]
            0x0F, 0x17, 0x07, // movhps [rdi],xmm0
        ]);
        let base = 0x1400_0000_000u64 + 0xA000;
        for (i, b) in b"ABCDEFGH".iter().enumerate() {
            e.write_u8(base + i as u64, *b).unwrap();
        }
        e.xmm[0] = u128::from_le_bytes(*b"0123456789ABCDEF");
        e.regs[6] = base; // rsi
        e.regs[7] = base + 0x100; // rdi
        e.step().unwrap();
        assert_eq!(
            e.xmm[0].to_le_bytes(),
            *b"ABCDEFGH89ABCDEF",
            "movlps replaces low qword, preserves high"
        );
        e.step().unwrap();
        for (i, b) in b"89ABCDEF".iter().enumerate() {
            assert_eq!(
                e.read_u8(base + 0x100 + i as u64).unwrap(),
                *b,
                "movhps store byte {i}"
            );
        }
        // MOVLHPS reg-reg copies the source low qword into the destination high qword.
        let mut e = emu_with(&[0x0F, 0x16, 0xC1]); // movlhps xmm0,xmm1
        e.xmm[0] = u128::from_le_bytes(*b"0123456789ABCDEF");
        e.xmm[1] = u128::from_le_bytes(*b"abcdefghijklmnop");
        e.step().unwrap();
        assert_eq!(
            e.xmm[0].to_le_bytes(),
            *b"01234567abcdefgh",
            "movlhps copies source low qword"
        );
        // MOVHLPS takes the source high qword into the destination low qword.
        let mut e = emu_with(&[0x0F, 0x12, 0xC1]); // movhlps xmm0,xmm1
        e.xmm[0] = u128::from_le_bytes(*b"0123456789ABCDEF");
        e.xmm[1] = u128::from_le_bytes(*b"abcdefghijklmnop");
        e.step().unwrap();
        assert_eq!(e.xmm[0].to_le_bytes(), *b"ijklmnop89ABCDEF");
    }

    #[test]
    fn punpcklwd_reg() {
        // 66 0F 61 C6: interleave low words (a0,b0,a1,b1,...).
        let mut e = emu_with(&[0x66, 0x0F, 0x61, 0xC6]);
        e.xmm[0] = u128::from_le_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);
        e.xmm[6] = u128::from_le_bytes([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ]);
        e.step().unwrap();
        assert_eq!(
            e.xmm[0].to_le_bytes(),
            [
                0x00, 0x01, 0x10, 0x11, 0x02, 0x03, 0x12, 0x13, 0x04, 0x05, 0x14, 0x15, 0x06, 0x07,
                0x16, 0x17,
            ]
        );
    }

    #[test]
    fn punpckhbw_reg() {
        // 66 0F 68 C6: xmm0 = interleave of high bytes (xmm0[8..], xmm6[8..]).
        let mut e = emu_with(&[0x66, 0x0F, 0x68, 0xC6]);
        e.xmm[0] = u128::from_le_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);
        e.xmm[6] = u128::from_le_bytes([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ]);
        e.step().unwrap();
        assert_eq!(
            e.xmm[0].to_le_bytes(),
            [
                0x08, 0x18, 0x09, 0x19, 0x0A, 0x1A, 0x0B, 0x1B, 0x0C, 0x1C, 0x0D, 0x1D, 0x0E, 0x1E,
                0x0F, 0x1F,
            ]
        );
    }

    #[test]
    fn unpcklps_reg() {
        let mut e = emu_with(&[0x0F, 0x14, 0xC6]);
        e.xmm[0] = u128::from_le_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);
        e.xmm[6] = u128::from_le_bytes([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ]);
        e.step().unwrap();
        assert_eq!(
            e.xmm[0].to_le_bytes(),
            [
                0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x08, 0x09, 0x0A, 0x0B, 0x18, 0x19,
                0x1A, 0x1B,
            ]
        );
        // Prefixed spellings (UNPCKLPD et al.) fail clearly.
        assert!(emu_with(&[0x66, 0x0F, 0x14, 0xC6]).step().is_err());
    }

    #[test]
    fn bts_mem_bitstring() {
        // bts qword [rip+cell],rax: bit 9 sets byte1 bit1 (string form).
        let cell = 32usize;
        let mut code = vec![0x48, 0x0F, 0xAB, 0x05];
        code.extend_from_slice(&rel32(0, 8, cell));
        let mut e = emu_with(&code);
        let base = BASE + 0x1000;
        e.write_u8(base + cell as u64, 0).unwrap();
        e.write_u8(base + cell as u64 + 1, 0).unwrap();
        e.regs[0] = 9;
        e.step().unwrap();
        assert_eq!(e.read_u8(base + cell as u64).unwrap(), 0);
        assert_eq!(e.read_u8(base + cell as u64 + 1).unwrap(), 0x02);
        assert!(!e.cf);
    }
}
