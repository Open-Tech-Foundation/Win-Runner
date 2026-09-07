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
pub const MAX_STEPS: u64 = 10_000_000;
/// Sentinel return address placed at the bottom of the stack.
pub const ENTRY_SENTINEL: u64 = 0xDEAD_BEEF_DEAD_BEEF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    Continue,
    CalledStub { index: usize },
    Halted(u32),
}

pub struct Emu {
    pub base: u64,
    pub mem: Vec<u8>,
    pub regs: [u64; 16],
    pub rip: u64,
    pub zf: bool,
    pub sf: bool,
    pub cf: bool,
    pub of: bool,
    pub stubs: HashMap<u64, usize>,
    pub imports: Vec<Import>,
    pub stdout: Vec<u8>,
    steps: u64,
}

impl Emu {
    pub fn new(img: &PeImage) -> Result<Self, String> {
        let total = img.size_of_image as usize + STACK_SIZE + 0x1000;
        let base = img.image_base;
        let mut mem = vec![0u8; total];
        mem[..img.image.len()].copy_from_slice(&img.image);
        let stack_top = base + total as u64 - 0x100;
        let stack_top = stack_top & !0xF;
        let mut e = Self {
            base,
            mem,
            regs: [0u64; 16],
            rip: base + img.entry_rva as u64,
            zf: false,
            sf: false,
            cf: false,
            of: false,
            stubs: HashMap::new(),
            imports: img.imports.clone(),
            stdout: Vec::new(),
            steps: 0,
        };
        // Reserve stub addresses and patch IAT slots.
        for (i, imp) in img.imports.iter().enumerate() {
            let stub = STUB_BASE + i as u64 * 8;
            e.stubs.insert(stub, i);
            e.write_u64(base + imp.iat_rva as u64, stub)?;
        }
        // Set up stack with sentinel return address.
        e.regs[4] = stack_top;
        e.push_u64(ENTRY_SENTINEL)?;
        Ok(e)
    }

    // ---------- memory ----------
    pub fn check_va(&self, va: u64, len: usize) -> Result<usize, String> {
        if va < self.base {
            return Err(format!("memory access below image base: 0x{va:016x}"));
        }
        let off = (va - self.base) as usize;
        if off.checked_add(len).map(|e| e > self.mem.len()).unwrap_or(true) {
            return Err(format!("memory access out of bounds: 0x{va:016x}+{len}"));
        }
        Ok(off)
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
        self.mem[o] = v;
        Ok(())
    }
    pub fn write_u16(&mut self, va: u64, v: u16) -> Result<(), String> {
        let o = self.check_va(va, 2)?;
        self.mem[o..o + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    pub fn write_u32(&mut self, va: u64, v: u32) -> Result<(), String> {
        let o = self.check_va(va, 4)?;
        self.mem[o..o + 4].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    pub fn write_u64(&mut self, va: u64, v: u64) -> Result<(), String> {
        let o = self.check_va(va, 8)?;
        self.mem[o..o + 8].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    pub fn read_bytes(&self, va: u64, len: usize) -> Result<Vec<u8>, String> {
        let o = self.check_va(va, len)?;
        Ok(self.mem[o..o + len].to_vec())
    }
    pub fn write_bytes(&mut self, va: u64, b: &[u8]) -> Result<(), String> {
        let o = self.check_va(va, b.len())?;
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
        let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
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
        let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
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
        let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
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
            0 => self.of,                        // O
            1 => !self.of,                       // NO
            2 => self.cf,                        // B
            3 => !self.cf,                       // NB
            4 => self.zf,                        // Z
            5 => !self.zf,                       // NZ
            6 => self.cf || self.zf,             // BE
            7 => !self.cf && !self.zf,           // NBE
            8 => self.sf,                        // S
            9 => !self.sf,                       // NS
            10 => return Err("JP not supported".to_string()),
            11 => return Err("JNP not supported".to_string()),
            12 => self.sf != self.of,            // L
            13 => self.sf == self.of,            // NL
            14 => self.zf || self.sf != self.of, // LE
            15 => !self.zf && self.sf == self.of,// NLE
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
                    addr = addr.wrapping_add(self.regs[index].wrapping_shl(scale as u32 * 0).wrapping_mul(1 << scale));
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
        Ok((reg, false, rm, ea, len))
    }

    fn read_rm(&self, is_reg: bool, rm: usize, ea: u64, width: u32) -> Result<u64, String> {
        if is_reg {
            Ok(match width {
                8 => self.regs[rm] & 0xFF,
                32 => self.regs[rm] & 0xFFFF_FFFF,
                64 => self.regs[rm],
                _ => return Err("bad width".to_string()),
            })
        } else {
            Ok(match width {
                8 => self.read_u8(ea)? as u64,
                32 => self.read_u32(ea)? as u64,
                64 => self.read_u64(ea)?,
                _ => return Err("bad width".to_string()),
            })
        }
    }

    fn write_rm(&mut self, is_reg: bool, rm: usize, ea: u64, width: u32, val: u64) -> Result<(), String> {
        if is_reg {
            match width {
                8 => {
                    self.regs[rm] = (self.regs[rm] & !0xFF) | (val & 0xFF);
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
                32 => self.write_u32(ea, val as u32),
                64 => self.write_u64(ea, val),
                _ => Err("bad width".to_string()),
            }
        }
    }

    // ---------- single step ----------
    pub fn step(&mut self) -> Result<StepResult, String> {
        if self.steps >= MAX_STEPS {
            return Err("execution step limit exceeded (possible infinite loop)".to_string());
        }
        self.steps += 1;
        let ip = self.rip;
        // prefixes
        let mut off = 0usize;
        let mut rex_w = false;
        let mut rex_r = false;
        let mut rex_x = false;
        let mut rex_b = false;
        let mut rex_present = false;
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
                return Err(format!("unsupported 0x66 operand-size prefix at 0x{ip:016x}"));
            } else if b == 0xF0 || b == 0xF2 || b == 0xF3 {
                return Err(format!("unsupported lock/rep prefix at 0x{ip:016x}"));
            } else {
                break;
            }
        }
        let _ = rex_present;
        let op = self.read_u8(ip + off as u64)?;
        let w: u32 = if rex_w { 64 } else { 32 };

        // two-byte opcodes
        if op == 0x0F {
            let op2 = self.read_u8(ip + off as u64 + 1)?;
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
            if op2 == 0xB6 || op2 == 0xB7 {
                // movzx r, r/m8(16)
                let srcw = if op2 == 0xB6 { 8 } else { 16 };
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
                        self.regs[rm] & 0xFF
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
                // dest width: w (32/64); zero-extend
                if w == 64 {
                    self.regs[reg] = v;
                } else {
                    self.regs[reg] = v & 0xFFFF_FFFF;
                }
                self.rip = ip + (off + 2 + ml) as u64;
                return Ok(StepResult::Continue);
            }
            return Err(format!("unsupported 2-byte opcode 0F {op2:02X} at 0x{ip:016x}"));
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
            0x90 => {
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
                self.regs[r] = (self.regs[r] & !0xFF) | imm as u64;
                self.rip = ip + off as u64 + 2;
                Ok(StepResult::Continue)
            }
            0xB8..=0xBF => {
                let r = (((rex_b as u8) << 3) | (op & 7)) as usize;
                if rex_w {
                    let imm = self.read_u64(ip + off as u64 + 1)?;
                    self.regs[r] = imm;
                    self.rip = ip + off as u64 + 9;
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
            0x88 | 0x89 | 0x8A | 0x8B | 0x8D | 0x01 | 0x03 | 0x29 | 0x2B | 0x31 | 0x33
            | 0x39 | 0x3B | 0x09 | 0x0B | 0x21 | 0x23 | 0x85 | 0x63 => {
                let is_8 = op == 0x88 || op == 0x8A;
                let (reg, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                let next = ip + (off + 1 + ml) as u64;
                let ea = if rm == 0x100 { next.wrapping_add(ea_raw) } else { ea_raw };
                let width: u32 = if is_8 { 8 } else { w };
                match op {
                    0x88 => {
                        // mov r/m8, r8
                        let v = self.regs[reg] & 0xFF;
                        self.write_rm(is_reg, rm, ea, 8, v)?;
                    }
                    0x8A => {
                        let v = self.read_rm(is_reg, rm, ea, 8)?;
                        self.regs[reg] = (self.regs[reg] & !0xFF) | v;
                    }
                    0x89 => {
                        let v = if width == 64 {
                            self.regs[reg]
                        } else {
                            self.regs[reg] & 0xFFFF_FFFF
                        };
                        self.write_rm(is_reg, rm, ea, width, v)?;
                    }
                    0x8B => {
                        let v = self.read_rm(is_reg, rm, ea, width)?;
                        if width == 64 {
                            self.regs[reg] = v;
                        } else {
                            self.regs[reg] = v & 0xFFFF_FFFF;
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
                    0x85 => {
                        let a = if width == 64 {
                            self.regs[reg]
                        } else {
                            self.regs[reg] & 0xFFFF_FFFF
                        };
                        let b = self.read_rm(is_reg, rm, ea, width)?;
                        let r = (a & if width == 64 { u64::MAX } else { 0xFFFF_FFFF }) & b;
                        self.set_logic_flags(r, width);
                    }
                    _ => {
                        // ALU r/m,r or r,r/m
                        let to_rm = matches!(op, 0x01 | 0x29 | 0x31 | 0x39 | 0x09 | 0x21);
                        let rv = if width == 64 {
                            self.regs[reg]
                        } else {
                            self.regs[reg] & 0xFFFF_FFFF
                        };
                        let mv = self.read_rm(is_reg, rm, ea, width)?;
                        let (res, is_sub, is_logic) = match op {
                            0x01 | 0x03 => (mv.wrapping_add(rv), false, false),
                            0x29 | 0x2B => (
                                if to_rm {
                                    mv.wrapping_sub(rv)
                                } else {
                                    rv.wrapping_sub(mv)
                                },
                                true,
                                false,
                            ),
                            0x31 | 0x33 => (mv ^ rv, false, true),
                            0x09 | 0x0B => (mv | rv, false, true),
                            0x21 | 0x23 => (mv & rv, false, true),
                            0x39 | 0x3B => (
                                if to_rm {
                                    mv.wrapping_sub(rv)
                                } else {
                                    rv.wrapping_sub(mv)
                                },
                                true,
                                false,
                            ),
                            _ => unreachable!(),
                        };
                        let is_cmp = op == 0x39 || op == 0x3B;
                        if op == 0x39 || op == 0x3B {
                            // cmp: set flags on (op1 - op2)
                            let (a, b) = if to_rm { (mv, rv) } else { (rv, mv) };
                            self.set_sub_flags(a, b, res, width);
                        } else if is_logic {
                            self.set_logic_flags(res, width);
                            if to_rm {
                                self.write_rm(is_reg, rm, ea, width, res)?;
                            } else {
                                if width == 64 {
                                    self.regs[reg] = res;
                                } else {
                                    self.regs[reg] = res & 0xFFFF_FFFF;
                                }
                            }
                        } else if is_sub {
                            let (a, b) = if to_rm { (mv, rv) } else { (rv, mv) };
                            self.set_sub_flags(a, b, res, width);
                            if to_rm {
                                self.write_rm(is_reg, rm, ea, width, res)?;
                            } else {
                                if width == 64 {
                                    self.regs[reg] = res;
                                } else {
                                    self.regs[reg] = res & 0xFFFF_FFFF;
                                }
                            }
                        } else {
                            // add
                            let (a, b) = if to_rm { (mv, rv) } else { (rv, mv) };
                            self.set_add_flags(a, b, res, width);
                            if to_rm {
                                self.write_rm(is_reg, rm, ea, width, res)?;
                            } else {
                                if width == 64 {
                                    self.regs[reg] = res;
                                } else {
                                    self.regs[reg] = res & 0xFFFF_FFFF;
                                }
                            }
                        }
                        let _ = is_cmp;
                    }
                }
                self.rip = next;
                Ok(StepResult::Continue)
            }
            0x05 | 0x2D | 0x35 | 0x3D | 0x0D | 0x25 => {
                // ALU rax, imm32
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
                let imm_raw: u64 = if is8 {
                    self.read_u8(ip + imm_off as u64)? as i8 as i64 as u64
                } else {
                    self.read_u32(ip + imm_off as u64)? as i32 as i64 as u64
                };
                let next = ip + (imm_off + if is8 { 1 } else { 4 }) as u64;
                let ea = if rm == 0x100 { next.wrapping_add(ea_raw) } else { ea_raw };
                // reg field selects op: /0 ADD /1 OR /2 ADC /3 SBB /4 AND /5 SUB /6 XOR /7 CMP
                let mv = self.read_rm(is_reg, rm, ea, w)?;
                let a = if w == 64 { mv } else { mv & 0xFFFF_FFFF };
                let bfull = if w == 64 {
                    imm_raw
                } else {
                    imm_raw & 0xFFFF_FFFF
                };
                let res = match reg_field {
                    0 => a.wrapping_add(bfull),
                    1 => a | bfull,
                    4 => a & bfull,
                    5 => a.wrapping_sub(bfull),
                    6 => a ^ bfull,
                    7 => a.wrapping_sub(bfull),
                    _ => {
                        return Err(format!(
                            "unsupported group1 sub-op /{} at 0x{ip:016x} (only ADD/OR/AND/SUB/XOR/CMP)",
                            reg_field
                        ))
                    }
                };
                let res_masked = if w == 64 { res } else { res & 0xFFFF_FFFF };
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
            0xC6 | 0xC7 => {
                let (reg_field, is_reg, rm, ea_raw, ml) =
                    self.decode_modrm(ip, off + 1, rex_r, rex_x, rex_b, true)?;
                if reg_field != 0 {
                    return Err(format!("unsupported C6/C7 /{reg_field} at 0x{ip:016x}"));
                }
                if op == 0xC6 {
                    let imm = self.read_u8(ip + (off + 1 + ml) as u64)?;
                    let next = ip + (off + 1 + ml + 1) as u64;
                    let ea = if rm == 0x100 { next.wrapping_add(ea_raw) } else { ea_raw };
                    self.write_rm(is_reg, rm, ea, 8, imm as u64)?;
                    self.rip = next;
                } else {
                    let imm = self.read_u32(ip + (off + 1 + ml) as u64)?;
                    let next = ip + (off + 1 + ml + 4) as u64;
                    let ea = if rm == 0x100 { next.wrapping_add(ea_raw) } else { ea_raw };
                    let v = if w == 64 { imm as i32 as i64 as u64 } else { imm as u64 };
                    self.write_rm(is_reg, rm, ea, w, v)?;
                    self.rip = next;
                }
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
                        let mv = self.read_rm(is_reg, rm, ea, w)?;
                        let a = if w == 64 { mv } else { mv & 0xFFFF_FFFF };
                        let res = a.wrapping_add(1);
                        let old_cf = self.cf;
                        self.set_add_flags(a, 1, res, w);
                        self.cf = old_cf;
                        let resm = if w == 64 { res } else { res & 0xFFFF_FFFF };
                        self.write_rm(is_reg, rm, ea, w, resm)?;
                        self.rip = next;
                        Ok(StepResult::Continue)
                    }
                    1 => {
                        let mv = self.read_rm(is_reg, rm, ea, w)?;
                        let a = if w == 64 { mv } else { mv & 0xFFFF_FFFF };
                        let res = a.wrapping_sub(1);
                        let old_cf = self.cf;
                        self.set_sub_flags(a, 1, res, w);
                        self.cf = old_cf;
                        let resm = if w == 64 { res } else { res & 0xFFFF_FFFF };
                        self.write_rm(is_reg, rm, ea, w, resm)?;
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
