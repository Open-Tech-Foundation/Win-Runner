//! Test-EXE builder: constructs minimal PE32+ (x86_64) binaries in-memory.
//!
//! Used by integration tests (and only tests) so `cargo test` needs no
//! external assembler. Generated code runs through the native PE backend.

use std::collections::HashMap;

pub const IMAGE_BASE: u64 = 0x0140_0000_0000;
pub const SECTION_RVA: u32 = 0x1000;
pub const FILE_OFF: usize = 0x200;

fn encode_utf16(s: &str) -> Vec<u8> {
    let mut b = Vec::new();
    for c in s.encode_utf16() {
        b.extend_from_slice(&c.to_le_bytes());
    }
    b.extend_from_slice(&[0, 0]);
    b
}

/// Tiny assembler. Code + data blobs; fixups patched at `build()`.
pub struct Asm {
    pub code: Vec<u8>,
    pub datas: Vec<Vec<u8>>,
    fix_iat: Vec<(usize, usize)>,  // (disp_pos, import_idx)
    fix_dat: Vec<(usize, usize)>,  // (disp_pos, data_idx)
    fix_jcc: Vec<(usize, usize)>,  // (disp_pos, label_id)
    fix_jmp: Vec<(usize, usize)>,  // (disp_pos, label_id)
    labels: HashMap<usize, usize>, // label_id -> code offset
    next_label: usize,
}

impl Asm {
    pub fn new() -> Self {
        Self {
            code: Vec::new(),
            datas: Vec::new(),
            fix_iat: Vec::new(),
            fix_dat: Vec::new(),
            fix_jcc: Vec::new(),
            fix_jmp: Vec::new(),
            labels: HashMap::new(),
            next_label: 0,
        }
    }
    pub fn add_data(&mut self, b: Vec<u8>) -> usize {
        self.datas.push(b);
        self.datas.len() - 1
    }
    pub fn add_utf16(&mut self, s: &str) -> usize {
        self.add_data(encode_utf16(s))
    }
    pub fn add_zeroed(&mut self, n: usize) -> usize {
        self.add_data(vec![0u8; n])
    }
    pub fn emit(&mut self, b: &[u8]) {
        self.code.extend_from_slice(b);
    }
    pub fn label(&mut self) -> usize {
        let id = self.next_label;
        self.next_label += 1;
        self.labels.insert(id, self.code.len());
        id
    }
    /// Fresh label id without marking (mark later with [`Asm::mark`]).
    pub fn fresh_label(&mut self) -> usize {
        let id = self.next_label;
        self.next_label += 1;
        id
    }
    pub fn mark(&mut self, id: usize) {
        self.labels.insert(id, self.code.len());
    }

    // ---- instruction helpers for small x86-64 PE fixtures ----
    pub fn sub_rsp(&mut self, n: u8) {
        self.emit(&[0x48, 0x83, 0xEC, n]);
    }
    pub fn add_rsp(&mut self, n: u8) {
        self.emit(&[0x48, 0x83, 0xC4, n]);
    }
    pub fn ret(&mut self) {
        self.emit(&[0xC3]);
    }
    pub fn xor_eax(&mut self) {
        self.emit(&[0x31, 0xC0]);
    }
    pub fn test_eax_eax(&mut self) {
        self.emit(&[0x85, 0xC0]);
    }
    pub fn test_rax_rax(&mut self) {
        self.emit(&[0x48, 0x85, 0xC0]);
    }
    pub fn cmp_rax_m1(&mut self) {
        // cmp rax, -1  (48 83 F8 FF)
        self.emit(&[0x48, 0x83, 0xF8, 0xFF]);
    }
    pub fn mov_ecx_imm(&mut self, v: u32) {
        let mut b = vec![0xB9];
        b.extend_from_slice(&v.to_le_bytes());
        self.emit(&b);
    }
    pub fn mov_edx_imm(&mut self, v: u32) {
        let mut b = vec![0xBA];
        b.extend_from_slice(&v.to_le_bytes());
        self.emit(&b);
    }
    pub fn mov_r8d_imm(&mut self, v: u32) {
        let mut b = vec![0x41, 0xB8];
        b.extend_from_slice(&v.to_le_bytes());
        self.emit(&b);
    }
    pub fn mov_r9d_imm(&mut self, v: u32) {
        let mut b = vec![0x41, 0xB9];
        b.extend_from_slice(&v.to_le_bytes());
        self.emit(&b);
    }
    pub fn mov_rax_imm64(&mut self, v: u64) {
        let mut b = vec![0x48, 0xB8];
        b.extend_from_slice(&v.to_le_bytes());
        self.emit(&b);
    }
    pub fn mov_rcx_imm64(&mut self, v: u64) {
        let mut b = vec![0x48, 0xB9];
        b.extend_from_slice(&v.to_le_bytes());
        self.emit(&b);
    }
    pub fn mov_rcx_rax(&mut self) {
        self.emit(&[0x48, 0x89, 0xC1]);
    }
    pub fn mov_rdx_rax(&mut self) {
        self.emit(&[0x48, 0x89, 0xC2]);
    }
    /// mov r32, imm32 (any of rax..r15)
    pub fn mov_r32_imm(&mut self, reg: usize, v: u32) {
        assert!(reg < 16);
        let mut b = Vec::new();
        if reg >= 8 {
            b.push(0x41);
        }
        b.push(0xB8 + (reg as u8 & 7));
        b.extend_from_slice(&v.to_le_bytes());
        self.emit(&b);
    }
    /// mov reg64, [rsp+off8]
    pub fn mov_reg_rspoff(&mut self, reg: usize, off: u8) {
        assert!(reg < 16);
        let rex = 0x48 | if reg >= 8 { 4 } else { 0 };
        let modrm = 0x44 | ((reg as u8 & 7) << 3); // mod=01 rm=100 (SIB)
        self.emit(&[rex, 0x8B, modrm, 0x24, off]);
    }
    /// mov dword [rsp+off8], imm32
    pub fn mov_rspoff_imm32(&mut self, off: u8, v: u32) {
        let mut b = vec![0xC7, 0x44, 0x24, off];
        b.extend_from_slice(&v.to_le_bytes());
        self.emit(&b);
    }
    /// mov eax, [rip+data_idx]
    pub fn mov_eax_mem_rip(&mut self, data_idx: usize) {
        let pos = self.code.len() + 2;
        self.emit(&[0x8B, 0x05, 0, 0, 0, 0]);
        self.fix_dat.push((pos, data_idx));
    }
    /// cmp eax, imm32
    pub fn cmp_eax_imm(&mut self, v: u32) {
        let mut b = vec![0x3D];
        b.extend_from_slice(&v.to_le_bytes());
        self.emit(&b);
    }
    /// movzx ecx, byte [rax] / movzx ebx, byte [rdx]
    pub fn movzx_ecx_byte_rax(&mut self) {
        self.emit(&[0x0F, 0xB6, 0x08]);
    }
    pub fn movzx_ebx_byte_rdx(&mut self) {
        self.emit(&[0x0F, 0xB6, 0x1A]);
    }
    /// cmp ecx, ebx
    pub fn cmp_ecx_ebx(&mut self) {
        self.emit(&[0x39, 0xD9]);
    }
    pub fn inc_rax(&mut self) {
        self.emit(&[0x48, 0xFF, 0xC0]);
    }
    pub fn inc_rdx(&mut self) {
        self.emit(&[0x48, 0xFF, 0xC2]);
    }
    pub fn dec_r10d(&mut self) {
        self.emit(&[0x41, 0xFF, 0xCA]);
    }
    /// test r10d, r10d
    pub fn test_r10d(&mut self) {
        self.emit(&[0x45, 0x85, 0xD2]);
    }
    /// lea reg32/64, [rip+data_idx]
    pub fn lea_reg_rip(&mut self, reg: usize, data_idx: usize) {
        // REX.W=1 (+ REX.R if reg>=8). opcode 8D, modrm mod=00 reg=reg&7 rm=101
        let rex = 0x48 | if reg >= 8 { 4 } else { 0 };
        let modrm = ((reg as u8 & 7) << 3) | 0x05;
        let pos = self.code.len() + 3; // disp field offset in code
        self.emit(&[rex, 0x8D, modrm, 0, 0, 0, 0]);
        self.fix_dat.push((pos, data_idx));
    }
    pub fn call_import(&mut self, import_idx: usize) {
        // call qword ptr [rip+disp]  FF 15 disp32
        let pos = self.code.len() + 2;
        self.emit(&[0xFF, 0x15, 0, 0, 0, 0]);
        self.fix_iat.push((pos, import_idx));
    }
    /// mov [rsp+off8], reg64
    pub fn mov_rspoff_reg(&mut self, off: u8, reg: usize) {
        let rex = 0x48 | if reg >= 8 { 4 } else { 0 };
        let modrm = 0x44 | ((reg as u8 & 7) << 3); // mod=01 rm=100
        self.emit(&[rex, 0x89, modrm, 0x24, off]);
    }
    /// mov [rsp+off8], rax (zeroed via xor first for NULL)
    pub fn mov_rspoff_rax(&mut self, off: u8) {
        self.emit(&[0x48, 0x89, 0x44, 0x24, off]);
    }
    /// jz/jmp rel32 to label (uses 0F 84). Caller picks cond byte.
    pub fn jcc_rel32(&mut self, cond: u8, label: usize) {
        // 0F 8x disp32 ; cond in low nibble: 4=Z,5=NZ
        let pos = self.code.len() + 2;
        self.emit(&[0x0F, 0x80 | (cond & 0xF), 0, 0, 0, 0]);
        self.fix_jcc.push((pos, label));
    }
    pub fn jz(&mut self, label: usize) {
        self.jcc_rel32(4, label)
    }
    pub fn jnz(&mut self, label: usize) {
        self.jcc_rel32(5, label)
    }
    /// jmp rel32 to label.
    pub fn jmp(&mut self, label: usize) {
        // E9 disp32
        let pos = self.code.len() + 1;
        self.emit(&[0xE9, 0, 0, 0, 0]);
        self.fix_jmp.push((pos, label));
    }
}

/// Assemble a full PE file from asm + import list.
pub fn build(mut asm: Asm, imports: &[(&str, &str)]) -> Vec<u8> {
    // Group imports by DLL preserving order.
    let mut dlls: Vec<String> = Vec::new();
    let mut dll_funcs: Vec<Vec<String>> = Vec::new();
    let mut import_slot: Vec<(usize, usize)> = Vec::new(); // global idx -> (dll_idx, func_idx)
    for (dll, func) in imports {
        let di = match dlls.iter().position(|d| d.eq_ignore_ascii_case(dll)) {
            Some(i) => i,
            None => {
                dlls.push(dll.to_string());
                dll_funcs.push(Vec::new());
                dlls.len() - 1
            }
        };
        let fi = dll_funcs[di].len();
        dll_funcs[di].push(func.to_string());
        import_slot.push((di, fi));
    }

    // Layout inside section: code | datas | import area
    let code_len = asm.code.len();
    let mut data_rvas: Vec<u32> = Vec::new();
    let mut cur = SECTION_RVA as usize + code_len;
    // align datas to 8 for u64 written counters
    for d in &asm.datas {
        let pad = (8 - (cur % 8)) % 8;
        cur += pad;
        data_rvas.push(cur as u32);
        cur += d.len();
    }
    // import area starts aligned to 8
    cur += (8 - (cur % 8)) % 8;
    let import_base = cur as u32;

    // Compute import area sizes.
    let ndesc = dlls.len() + 1;
    let desc_size = ndesc * 20;
    // INT/IAT per dll: (nfuncs+1)*8 each
    let mut int_rvas: Vec<u32> = Vec::new();
    let mut iat_rvas: Vec<u32> = Vec::new();
    let mut p = import_base as usize + desc_size;
    for funcs in &dll_funcs {
        int_rvas.push(p as u32);
        p += (funcs.len() + 1) * 8;
        iat_rvas.push(p as u32);
        p += (funcs.len() + 1) * 8;
    }
    // hint/name entries + dll names
    let mut hn_rvas: Vec<Vec<u32>> = vec![Vec::new(); dlls.len()];
    let mut dllname_rvas: Vec<u32> = Vec::new();
    for (di, funcs) in dll_funcs.iter().enumerate() {
        for f in funcs {
            hn_rvas[di].push(p as u32);
            p += 2 + f.len() + 1;
            // pad to even
            if (2 + f.len() + 1) % 2 == 1 {
                p += 1;
            }
        }
        dllname_rvas.push(p as u32);
        p += dlls[di].len() + 1;
    }
    // A loader-written IAT slot is an ideal harmless relocation target: the
    // native loader replaces it with a trampoline before execution.  Keeping
    // this tiny relocation block in generated fixtures lets CreateProcessW
    // exercise its distinct-address child mapping.
    let reloc_target = iat_rvas.first().copied();
    let reloc_rva = reloc_target.map(|target| {
        p = (p + 3) & !3;
        let rva = p as u32;
        let _ = target;
        p += 12; // IMAGE_BASE_RELOCATION header + DIR64 entry + ABSOLUTE pad
        rva
    });
    let section_len = p - SECTION_RVA as usize;

    // Global IAT rva per import index
    let mut iat_of_import: Vec<u32> = Vec::new();
    for (di, fi) in &import_slot {
        iat_of_import.push(iat_rvas[*di] + (*fi as u32) * 8);
    }

    // Patch code fixups
    let code_rva = SECTION_RVA as u64;
    for (pos, imp) in asm.fix_iat.clone() {
        let target = iat_of_import[imp] as u64;
        let next = code_rva + pos as u64 + 4;
        let disp = target.wrapping_sub(next) as u32;
        asm.code[pos..pos + 4].copy_from_slice(&disp.to_le_bytes());
    }
    // data fixups need padding-aware rvas: recompute with pads
    {
        let mut c = SECTION_RVA as usize + code_len;
        let mut rvas: Vec<u32> = Vec::new();
        for d in &asm.datas {
            let pad = (8 - (c % 8)) % 8;
            c += pad;
            rvas.push(c as u32);
            c += d.len();
        }
        for (pos, di) in asm.fix_dat.clone() {
            let target = rvas[di] as u64;
            let next = code_rva + pos as u64 + 4;
            let disp = target.wrapping_sub(next) as u32;
            asm.code[pos..pos + 4].copy_from_slice(&disp.to_le_bytes());
        }
    }
    for (pos, lab) in asm.fix_jcc.clone() {
        let target_off = *asm
            .labels
            .get(&lab)
            .unwrap_or_else(|| panic!("undefined label {lab}"));
        let target = code_rva + target_off as u64;
        let next = code_rva + pos as u64 + 4;
        let disp = target.wrapping_sub(next) as u32;
        asm.code[pos..pos + 4].copy_from_slice(&disp.to_le_bytes());
    }
    for (pos, lab) in asm.fix_jmp.clone() {
        let target_off = *asm
            .labels
            .get(&lab)
            .unwrap_or_else(|| panic!("undefined label {lab}"));
        let target = code_rva + target_off as u64;
        let next = code_rva + pos as u64 + 4;
        let disp = target.wrapping_sub(next) as u32;
        asm.code[pos..pos + 4].copy_from_slice(&disp.to_le_bytes());
    }

    // Section bytes
    let mut sec = Vec::new();
    sec.extend_from_slice(&asm.code);
    {
        let mut c = SECTION_RVA as usize + code_len;
        for d in &asm.datas {
            let pad = (8 - (c % 8)) % 8;
            sec.extend(std::iter::repeat(0u8).take(pad));
            c += pad;
            sec.extend_from_slice(d);
            c += d.len();
        }
        let pad = (8 - (c % 8)) % 8;
        sec.extend(std::iter::repeat(0u8).take(pad));
    }
    // descriptors
    for di in 0..dlls.len() {
        let mut e = Vec::new();
        e.extend_from_slice(&(int_rvas[di]).to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&(dllname_rvas[di]).to_le_bytes());
        e.extend_from_slice(&(iat_rvas[di]).to_le_bytes());
        sec.extend_from_slice(&e);
    }
    sec.extend_from_slice(&[0u8; 20]);
    // INT/IAT arrays (INT entries point to hint/name)
    for di in 0..dlls.len() {
        for fi in 0..dll_funcs[di].len() {
            sec.extend_from_slice(&(hn_rvas[di][fi] as u64).to_le_bytes());
        }
        sec.extend_from_slice(&0u64.to_le_bytes());
        for fi in 0..dll_funcs[di].len() {
            sec.extend_from_slice(&(hn_rvas[di][fi] as u64).to_le_bytes());
        }
        sec.extend_from_slice(&0u64.to_le_bytes());
    }
    for (di, funcs) in dll_funcs.iter().enumerate() {
        for (fi, f) in funcs.iter().enumerate() {
            let _ = fi;
            sec.extend_from_slice(&0u16.to_le_bytes());
            sec.extend_from_slice(f.as_bytes());
            sec.push(0);
            if (2 + f.len() + 1) % 2 == 1 {
                sec.push(0);
            }
        }
        sec.extend_from_slice(dlls[di].as_bytes());
        sec.push(0);
        let _ = di;
    }
    if let (Some(reloc_rva), Some(reloc_target)) = (reloc_rva, reloc_target) {
        while SECTION_RVA as usize + sec.len() < reloc_rva as usize {
            sec.push(0);
        }
        sec.extend_from_slice(&(reloc_target & !0xfff).to_le_bytes());
        sec.extend_from_slice(&12u32.to_le_bytes());
        sec.extend_from_slice(&(0xA000u16 | (reloc_target as u16 & 0x0fff)).to_le_bytes());
        sec.extend_from_slice(&0u16.to_le_bytes());
    }
    assert_eq!(sec.len(), section_len);

    // Headers
    let size_of_headers: u32 = 0x200;
    let vsize = section_len as u32;
    let raw_size = ((section_len + 0x1FF) / 0x200 * 0x200) as u32;
    let size_of_image = ((SECTION_RVA + vsize + 0xFFF) / 0x1000 * 0x1000) as u32;
    let import_dir_size = (ndesc * 20) as u32;

    let mut f = Vec::new();
    // DOS header (64 bytes) + padding to 0x80
    f.extend_from_slice(b"MZ");
    f.extend(std::iter::repeat(0u8).take(58));
    f.extend_from_slice(&0x80u32.to_le_bytes());
    while f.len() < 0x80 {
        f.push(0);
    }
    // PE sig + COFF
    f.extend_from_slice(b"PE\0\0");
    f.extend_from_slice(&0x8664u16.to_le_bytes()); // machine x86_64
    f.extend_from_slice(&1u16.to_le_bytes()); // sections
    f.extend_from_slice(&0u32.to_le_bytes()); // timestamp
    f.extend_from_slice(&0u32.to_le_bytes()); // symtab
    f.extend_from_slice(&0u32.to_le_bytes()); // nsyms
    f.extend_from_slice(&0xF0u16.to_le_bytes()); // opt size (240)
    f.extend_from_slice(&0x0022u16.to_le_bytes()); // characteristics (exec)
                                                   // Optional header (240 bytes)
    let mut o = Vec::new();
    o.extend_from_slice(&0x20Bu16.to_le_bytes()); // magic PE32+
    o.push(0);
    o.push(0);
    o.extend_from_slice(&raw_size.to_le_bytes()); // size of code
    o.extend_from_slice(&0u32.to_le_bytes()); // init data
    o.extend_from_slice(&0u32.to_le_bytes()); // uninit
    o.extend_from_slice(&SECTION_RVA.to_le_bytes()); // entry
    o.extend_from_slice(&SECTION_RVA.to_le_bytes()); // base of code
    o.extend_from_slice(&IMAGE_BASE.to_le_bytes()); // image base
    o.extend_from_slice(&0x1000u32.to_le_bytes()); // section align
    o.extend_from_slice(&0x200u32.to_le_bytes()); // file align
    for _ in 0..6 {
        o.extend_from_slice(&0u16.to_le_bytes());
    } // OS/image/subsys versions
    o.extend_from_slice(&0u32.to_le_bytes()); // win32 ver
    o.extend_from_slice(&size_of_image.to_le_bytes());
    o.extend_from_slice(&size_of_headers.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes()); // checksum
    o.extend_from_slice(&3u16.to_le_bytes()); // subsystem console
    o.extend_from_slice(&0u16.to_le_bytes()); // dll chars
    o.extend_from_slice(&0x100000u64.to_le_bytes()); // stack reserve
    o.extend_from_slice(&0x1000u64.to_le_bytes()); // stack commit
    o.extend_from_slice(&0x100000u64.to_le_bytes()); // heap reserve
    o.extend_from_slice(&0x1000u64.to_le_bytes()); // heap commit
    o.extend_from_slice(&0u32.to_le_bytes()); // loader flags
    o.extend_from_slice(&16u32.to_le_bytes()); // rva count
                                               // data dirs: export(0), import(1), rest 0
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&import_base.to_le_bytes());
    o.extend_from_slice(&import_dir_size.to_le_bytes());
    for index in 2..16 {
        if index == 5 {
            o.extend_from_slice(&reloc_rva.unwrap_or(0).to_le_bytes());
            o.extend_from_slice(&(if reloc_rva.is_some() { 12u32 } else { 0 }).to_le_bytes());
        } else {
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
        }
    }
    assert_eq!(o.len(), 0xF0);
    f.extend_from_slice(&o);
    // section header
    f.extend_from_slice(b".text\0\0\0");
    f.extend_from_slice(&vsize.to_le_bytes());
    f.extend_from_slice(&SECTION_RVA.to_le_bytes());
    f.extend_from_slice(&raw_size.to_le_bytes());
    f.extend_from_slice(&(FILE_OFF as u32).to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    // CODE|EXECUTE|READ|WRITE: test fixtures keep data and the IAT in the
    // single code section.
    f.extend_from_slice(&0xE000_0020u32.to_le_bytes());
    while f.len() < size_of_headers as usize {
        f.push(0);
    }
    assert_eq!(f.len(), FILE_OFF);
    f.extend_from_slice(&sec);
    while f.len() < FILE_OFF + raw_size as usize {
        f.push(0);
    }
    f
}

// ---------- convenience test EXEs ----------

/// hello.exe: prints msg via GetStdHandle+WriteFile, exit 0.
pub fn hello(msg: &str) -> Vec<u8> {
    let mut a = Asm::new();
    let d_msg = a.add_data(msg.as_bytes().to_vec());
    let d_written = a.add_zeroed(8);
    // need import indices: 0=GetStdHandle 1=WriteFile 2=ExitProcess
    a.sub_rsp(0x28);
    a.mov_ecx_imm(0xFFFF_FFF5); // -11 STD_OUTPUT
    a.call_import(0);
    a.mov_rcx_rax();
    a.lea_reg_rip(2, d_msg); // rdx = msg
    a.mov_r8d_imm(msg.len() as u32);
    a.lea_reg_rip(9, d_written); // r9 = &written
    a.xor_eax();
    a.mov_rspoff_rax(0x20); // overlapped = NULL
    a.call_import(1);
    a.mov_ecx_imm(0);
    a.call_import(2);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "GetStdHandle"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// Read exactly four bytes from standard input and write them to standard
/// output. Used to verify headless, controller-driven guest input.
pub fn stdin_echo() -> Vec<u8> {
    const GH: usize = 0;
    const RF: usize = 1;
    const WF: usize = 2;
    const XP: usize = 3;
    let mut a = Asm::new();
    let prompt = a.add_data(b"READY".to_vec());
    let buffer = a.add_zeroed(4);
    let read = a.add_zeroed(8);
    let written = a.add_zeroed(8);
    let fail = a.fresh_label();

    a.sub_rsp(0x48);
    // Emit a readiness marker before blocking for input.
    a.mov_ecx_imm(0xFFFF_FFF5);
    a.call_import(GH);
    a.mov_rcx_rax();
    a.lea_reg_rip(2, prompt);
    a.mov_r8d_imm(5);
    a.lea_reg_rip(9, written);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(WF);
    a.test_eax_eax();
    a.jz(fail);
    // GetStdHandle(STD_INPUT_HANDLE)
    a.mov_ecx_imm(0xFFFF_FFF6);
    a.call_import(GH);
    a.emit(&[0x48, 0x89, 0x44, 0x24, 0x40]);
    // ReadFile(stdin, buffer, 4, &read, NULL)
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
    a.lea_reg_rip(2, buffer);
    a.mov_r8d_imm(4);
    a.lea_reg_rip(9, read);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(RF);
    a.test_eax_eax();
    a.jz(fail);
    // WriteFile(stdout, buffer, 4, &written, NULL)
    a.mov_ecx_imm(0xFFFF_FFF5);
    a.call_import(GH);
    a.mov_rcx_rax();
    a.lea_reg_rip(2, buffer);
    a.mov_r8d_imm(4);
    a.lea_reg_rip(9, written);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(WF);
    a.test_eax_eax();
    a.jz(fail);
    a.mov_ecx_imm(0);
    a.call_import(XP);
    a.add_rsp(0x48);
    a.ret();
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(XP);
    a.add_rsp(0x48);
    a.ret();

    build(
        a,
        &[
            ("KERNEL32.dll", "GetStdHandle"),
            ("KERNEL32.dll", "ReadFile"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::hello;

    #[test]
    fn generated_images_are_relocatable_for_native_child_launches() {
        let image = crate::pe::load(&hello("child\n")).unwrap();
        assert!(!image.relocations.is_empty());
    }
}

/// exit(code): ExitProcess(code)
pub fn exit_code(code: u32) -> Vec<u8> {
    let mut a = Asm::new();
    a.sub_rsp(0x28);
    a.mov_ecx_imm(code);
    a.call_import(0);
    a.ret();
    build(a, &[("KERNEL32.dll", "ExitProcess")])
}

/// Create a child process, wait for it, then exit successfully. Used to test
/// the native process boundary without requiring an external toolchain.
pub fn create_process_wait(application: &str, current_directory: Option<&str>) -> Vec<u8> {
    // imports: 0 CreateProcessW, 1 WaitForSingleObject, 2 ExitProcess
    let mut a = Asm::new();
    let d_application = a.add_utf16(application);
    let d_current_directory = current_directory.map(|path| a.add_utf16(path));
    let d_process_information = a.add_zeroed(24);
    let fail = a.fresh_label();
    a.sub_rsp(0x58);
    a.lea_reg_rip(1, d_application);
    a.xor_eax();
    a.mov_rdx_rax();
    a.mov_r8d_imm(0);
    a.mov_r9d_imm(0);
    for offset in [0x20, 0x28, 0x30, 0x38, 0x40] {
        a.mov_rspoff_rax(offset);
    }
    if let Some(current_directory) = d_current_directory {
        a.lea_reg_rip(0, current_directory);
        a.mov_rspoff_rax(0x38);
    }
    a.lea_reg_rip(0, d_process_information);
    a.mov_rspoff_rax(0x48);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.mov_eax_mem_rip(d_process_information);
    a.mov_rcx_rax();
    a.mov_edx_imm(u32::MAX);
    a.call_import(1);
    a.cmp_eax_imm(0);
    a.jnz(fail);
    a.mov_ecx_imm(0);
    a.call_import(2);
    a.ret();
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(2);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "CreateProcessW"),
            ("KERNEL32.dll", "WaitForSingleObject"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// `CreateProcessW(NULL, command_line, ...)` with inherited handles, wait,
/// and exit with the child's exit code (99 when it cannot start). This is
/// how runtimes such as Node start `cmd.exe /d /s /c "..."`.
pub fn create_process_command_line(command_line: &str) -> Vec<u8> {
    // imports: 0 CreateProcessW, 1 WaitForSingleObject,
    //          2 GetExitCodeProcess, 3 ExitProcess
    let mut a = Asm::new();
    let d_command_line = a.add_utf16(command_line);
    let d_process_information = a.add_zeroed(24);
    let d_exit_code = a.add_zeroed(8);
    let fail = a.fresh_label();
    a.sub_rsp(0x58);
    a.xor_eax();
    a.mov_rcx_rax();
    a.lea_reg_rip(2, d_command_line);
    a.mov_r8d_imm(0);
    a.mov_r9d_imm(0);
    for offset in [0x20, 0x28, 0x30, 0x38, 0x40] {
        a.mov_rspoff_rax(offset);
    }
    a.mov_rspoff_imm32(0x20, 1); // bInheritHandles
    a.lea_reg_rip(0, d_process_information);
    a.mov_rspoff_rax(0x48);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(fail);
    a.mov_eax_mem_rip(d_process_information);
    a.mov_rcx_rax();
    a.mov_edx_imm(u32::MAX);
    a.call_import(1);
    a.mov_eax_mem_rip(d_process_information);
    a.mov_rcx_rax();
    a.lea_reg_rip(2, d_exit_code);
    a.call_import(2);
    a.mov_eax_mem_rip(d_exit_code);
    a.emit(&[0x89, 0xC1]); // mov ecx, eax
    a.call_import(3);
    a.ret();
    a.mark(fail);
    a.mov_ecx_imm(99);
    a.call_import(3);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "CreateProcessW"),
            ("KERNEL32.dll", "WaitForSingleObject"),
            ("KERNEL32.dll", "GetExitCodeProcess"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// Duplicate stdout as an inheritable handle, then start `command_line`
/// with that duplicate as the child's stdout and stderr, the way libuv
/// passes inherited stdio. Exits with the child's exit code (99 when a call
/// fails).
pub fn create_process_with_duplicated_stdout(command_line: &str) -> Vec<u8> {
    // imports: 0 GetStdHandle, 1 DuplicateHandle, 2 CreateProcessW,
    //          3 WaitForSingleObject, 4 GetExitCodeProcess, 5 ExitProcess
    let mut a = Asm::new();
    let d_command_line = a.add_utf16(command_line);
    let d_duplicate = a.add_zeroed(8);
    let mut startup = vec![0u8; 104];
    startup[..4].copy_from_slice(&104u32.to_le_bytes());
    startup[60..64].copy_from_slice(&0x100u32.to_le_bytes()); // STARTF_USESTDHANDLES
    let d_startup = a.add_data(startup);
    let d_process_information = a.add_zeroed(24);
    let d_exit_code = a.add_zeroed(8);
    let fail = a.fresh_label();
    a.sub_rsp(0x58);
    // DuplicateHandle(-1, GetStdHandle(STD_OUTPUT_HANDLE), -1, &dup, 0,
    //                 TRUE, DUPLICATE_SAME_ACCESS)
    a.mov_ecx_imm(0xFFFF_FFF5);
    a.call_import(0);
    a.mov_rdx_rax();
    a.mov_rcx_imm64(u64::MAX);
    a.emit(&[0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF]); // mov r8, -1
    a.lea_reg_rip(9, d_duplicate);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.mov_rspoff_imm32(0x28, 1);
    a.mov_rspoff_imm32(0x30, 2);
    a.call_import(1);
    a.test_eax_eax();
    a.jz(fail);
    // STARTUPINFO.hStdOutput (+88) and hStdError (+96) = dup.
    a.mov_eax_mem_rip(d_duplicate);
    a.lea_reg_rip(1, d_startup);
    a.emit(&[0x48, 0x89, 0x41, 88]); // mov [rcx+88], rax
    a.emit(&[0x48, 0x89, 0x41, 96]); // mov [rcx+96], rax
                                     // CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)
    a.xor_eax();
    a.mov_rcx_rax();
    a.lea_reg_rip(2, d_command_line);
    a.mov_r8d_imm(0);
    a.mov_r9d_imm(0);
    for offset in [0x28, 0x30, 0x38] {
        a.mov_rspoff_rax(offset);
    }
    a.mov_rspoff_imm32(0x20, 1);
    a.lea_reg_rip(0, d_startup);
    a.mov_rspoff_rax(0x40);
    a.lea_reg_rip(0, d_process_information);
    a.mov_rspoff_rax(0x48);
    a.call_import(2);
    a.test_eax_eax();
    a.jz(fail);
    a.mov_eax_mem_rip(d_process_information);
    a.mov_rcx_rax();
    a.mov_edx_imm(u32::MAX);
    a.call_import(3);
    a.mov_eax_mem_rip(d_process_information);
    a.mov_rcx_rax();
    a.lea_reg_rip(2, d_exit_code);
    a.call_import(4);
    a.mov_eax_mem_rip(d_exit_code);
    a.emit(&[0x89, 0xC1]); // mov ecx, eax
    a.call_import(5);
    a.ret();
    a.mark(fail);
    a.mov_ecx_imm(99);
    a.call_import(5);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "GetStdHandle"),
            ("KERNEL32.dll", "DuplicateHandle"),
            ("KERNEL32.dll", "CreateProcessW"),
            ("KERNEL32.dll", "WaitForSingleObject"),
            ("KERNEL32.dll", "GetExitCodeProcess"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// write file via CreateFileW + WriteFile + CloseHandle, exit 0/1.
pub fn write_file(path: &str, content: &[u8]) -> Vec<u8> {
    // imports: 0 CreateFileW, 1 WriteFile, 2 CloseHandle, 3 ExitProcess
    let mut a = Asm::new();
    let d_path = a.add_utf16(path);
    let d_data = a.add_data(content.to_vec());
    let d_written = a.add_zeroed(8);
    let lbl_fail = a.next_label;
    a.next_label += 1;
    let lbl_exit_ok = a.next_label;
    a.next_label += 1;

    a.sub_rsp(0x48);
    // CreateFileW(path, GENERIC_WRITE=0x40000000, 0, 0, CREATE_ALWAYS=2, 0x80, 0)
    a.lea_reg_rip(1, d_path); // rcx = path
    a.emit(&[0x48, 0xB8]);
    a.emit(&0x4000_0000u64.to_le_bytes()); // mov rax, GENERIC_WRITE
    a.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax
    a.mov_r8d_imm(0);
    a.mov_r9d_imm(0);
    a.xor_eax();
    a.emit(&[0xC7, 0x44, 0x24, 0x20]);
    a.emit(&2u32.to_le_bytes()); // creation = CREATE_ALWAYS at [rsp+0x20]
    a.emit(&[0xC7, 0x44, 0x24, 0x28]);
    a.emit(&0x80u32.to_le_bytes()); // flags
    a.mov_rspoff_rax(0x30); // hTemplate = NULL
    a.call_import(0);
    a.cmp_rax_m1();
    a.jz(lbl_fail);
    // save handle -> use stack slot + reload? push rax then pop to rcx later.
    // mov [rsp+0x40], rax
    a.emit(&[0x48, 0x89, 0x44, 0x24, 0x40]);
    // WriteFile(handle, data, len, &written, NULL)
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
    a.lea_reg_rip(2, d_data);
    a.mov_r8d_imm(content.len() as u32);
    a.lea_reg_rip(9, d_written);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(1);
    a.test_eax_eax();
    a.jz(lbl_fail);
    // CloseHandle(handle)
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
    a.call_import(2);
    // exit 0
    a.mov_ecx_imm(0);
    a.call_import(3);
    a.add_rsp(0x48);
    a.ret();
    // fail: exit 1
    a.mark(lbl_fail);
    a.mov_ecx_imm(1);
    a.call_import(3);
    a.mark(lbl_exit_ok);
    a.add_rsp(0x48);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "CreateFileW"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "CloseHandle"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// read file to stdout via CreateFileW(OPEN_EXISTING) + ReadFile + WriteFile stdout.
pub fn read_file_to_stdout(path: &str) -> Vec<u8> {
    // imports: 0 CreateFileW, 1 ReadFile, 2 GetStdHandle, 3 WriteFile, 4 CloseHandle, 5 ExitProcess
    let mut a = Asm::new();
    let d_path = a.add_utf16(path);
    let d_buf = a.add_zeroed(512);
    let d_read = a.add_zeroed(8);
    let d_written = a.add_zeroed(8);
    let lbl_fail = a.next_label;
    a.next_label += 1;
    a.sub_rsp(0x48);
    // handle = CreateFileW(path, GENERIC_READ=0x80000000, 0,0, OPEN_EXISTING=3, 0,0)
    a.lea_reg_rip(1, d_path);
    a.emit(&[0x48, 0xB8]);
    a.emit(&0x8000_0000u64.to_le_bytes());
    a.emit(&[0x48, 0x89, 0xC2]); // mov rdx,rax
    a.mov_r8d_imm(0);
    a.mov_r9d_imm(0);
    a.xor_eax();
    a.emit(&[0xC7, 0x44, 0x24, 0x20]);
    a.emit(&3u32.to_le_bytes()); // creation = OPEN_EXISTING at [rsp+0x20]
    a.emit(&[0xC7, 0x44, 0x24, 0x28]);
    a.emit(&0u32.to_le_bytes()); // flags
    a.mov_rspoff_rax(0x30); // hTemplate = NULL
    a.call_import(0);
    a.cmp_rax_m1();
    a.jz(lbl_fail);
    a.emit(&[0x48, 0x89, 0x44, 0x24, 0x40]); // save handle [rsp+0x40]
                                             // ReadFile(handle, buf, 512, &read, NULL)
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // rcx = handle
    a.lea_reg_rip(2, d_buf);
    a.mov_r8d_imm(512);
    a.lea_reg_rip(9, d_read);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(1);
    a.test_eax_eax();
    a.jz(lbl_fail);
    // n = *(u32*)&read -> need it in r8d for WriteFile. Load: mov r8d,[rip+...]
    // emit: 44 8B 05 disp32  (mov r8d, [rip+d_read])
    {
        let pos = a.code.len() + 3;
        a.emit(&[0x44, 0x8B, 0x05, 0, 0, 0, 0]);
        a.fix_dat.push((pos, d_read));
    }
    // stdout = GetStdHandle(-11)
    a.mov_ecx_imm(0xFFFF_FFF5);
    // Preserve r8 in the local stack frame; push would break Win64's
    // 16-byte alignment requirement before the imported call.
    a.emit(&[0x4C, 0x89, 0x44, 0x24, 0x38]); // mov [rsp+0x38], r8
    a.call_import(2);
    a.mov_rcx_rax(); // rcx = stdout
    a.emit(&[0x4C, 0x8B, 0x44, 0x24, 0x38]); // mov r8, [rsp+0x38]
                                             // rdx = buf
    a.lea_reg_rip(2, d_buf);
    // r9 = &written
    a.lea_reg_rip(9, d_written);
    // r8 already = n (low 32). upper preserved? push/pop kept full 64; n < 2^32 fine.
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(3);
    // CloseHandle
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
    a.call_import(4);
    a.mov_ecx_imm(0);
    a.call_import(5);
    a.add_rsp(0x48);
    a.ret();
    a.mark(lbl_fail);
    a.mov_ecx_imm(1);
    a.call_import(5);
    a.add_rsp(0x48);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "CreateFileW"),
            ("KERNEL32.dll", "ReadFile"),
            ("KERNEL32.dll", "GetStdHandle"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "CloseHandle"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// Seek to `offset`, read at most `length` bytes, and print them. This mirrors
/// the seek/read sequence covered by Wine's kernel32 file tests.
pub fn read_file_range_to_stdout(path: &str, offset: u32, length: u32) -> Vec<u8> {
    let mut a = Asm::new();
    let d_path = a.add_utf16(path);
    let d_buf = a.add_zeroed(length.max(1) as usize);
    let d_read = a.add_zeroed(8);
    let d_written = a.add_zeroed(8);
    let fail = a.fresh_label();
    a.sub_rsp(0x48);
    // CreateFileW(path, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, NULL)
    a.lea_reg_rip(1, d_path);
    a.emit(&[0x48, 0xB8]);
    a.emit(&0x8000_0000u64.to_le_bytes());
    a.emit(&[0x48, 0x89, 0xC2]);
    a.mov_r8d_imm(0);
    a.mov_r9d_imm(0);
    a.xor_eax();
    a.emit(&[0xC7, 0x44, 0x24, 0x20]);
    a.emit(&3u32.to_le_bytes());
    a.emit(&[0xC7, 0x44, 0x24, 0x28]);
    a.emit(&0u32.to_le_bytes());
    a.mov_rspoff_rax(0x30);
    a.call_import(0);
    a.cmp_rax_m1();
    a.jz(fail);
    a.emit(&[0x48, 0x89, 0x44, 0x24, 0x40]);
    // SetFilePointer(handle, offset, NULL, FILE_BEGIN)
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
    a.mov_r32_imm(2, offset);
    a.xor_eax();
    a.mov_r8d_imm(0);
    a.mov_r9d_imm(0);
    a.call_import(1);
    a.cmp_eax_imm(u32::MAX);
    a.jz(fail);
    // ReadFile(handle, buffer, length, &read, NULL)
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
    a.lea_reg_rip(2, d_buf);
    a.mov_r8d_imm(length);
    a.lea_reg_rip(9, d_read);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(2);
    a.test_eax_eax();
    a.jz(fail);
    {
        let pos = a.code.len() + 3;
        a.emit(&[0x44, 0x8B, 0x05, 0, 0, 0, 0]);
        a.fix_dat.push((pos, d_read));
    }
    a.emit(&[0x4C, 0x89, 0x44, 0x24, 0x38]);
    a.mov_ecx_imm(0xFFFF_FFF5);
    a.call_import(3);
    a.mov_rcx_rax();
    a.emit(&[0x4C, 0x8B, 0x44, 0x24, 0x38]);
    a.lea_reg_rip(2, d_buf);
    a.lea_reg_rip(9, d_written);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(4);
    a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
    a.call_import(5);
    a.mov_ecx_imm(0);
    a.call_import(6);
    a.add_rsp(0x48);
    a.ret();
    a.mark(fail);
    a.mov_ecx_imm(1);
    a.call_import(6);
    a.add_rsp(0x48);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "CreateFileW"),
            ("KERNEL32.dll", "SetFilePointer"),
            ("KERNEL32.dll", "ReadFile"),
            ("KERNEL32.dll", "GetStdHandle"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "CloseHandle"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// delete file + exit by BOOL.
pub fn delete_file(path: &str) -> Vec<u8> {
    let mut a = Asm::new();
    let d_path = a.add_utf16(path);
    let lbl_fail = a.next_label;
    a.next_label += 1;
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, d_path);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.add_rsp(0x28);
    a.ret();
    a.mark(lbl_fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    a.add_rsp(0x28);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "DeleteFileW"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// exe with an unsupported import (loader must fail clearly).
pub fn unknown_import() -> Vec<u8> {
    let mut a = Asm::new();
    a.sub_rsp(0x28);
    a.xor_eax();
    a.emit(&[0x48, 0x89, 0xC1]); // mov rcx,rax
    a.call_import(0);
    a.ret();
    build(a, &[("KERNEL32.dll", "NoSuchApiForTest")])
}

/// mkdir via CreateDirectoryW + exit by BOOL.
pub fn mkdir(path: &str) -> Vec<u8> {
    one_path_bool(path, "CreateDirectoryW")
}

/// rmdir via RemoveDirectoryW + exit by BOOL.
pub fn rmdir(path: &str) -> Vec<u8> {
    one_path_bool(path, "RemoveDirectoryW")
}

fn one_path_bool(path: &str, api: &str) -> Vec<u8> {
    let mut a = Asm::new();
    let d_path = a.add_utf16(path);
    let lbl_fail = a.next_label;
    a.next_label += 1;
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, d_path);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.add_rsp(0x28);
    a.ret();
    a.mark(lbl_fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    a.add_rsp(0x28);
    a.ret();
    build(a, &[("KERNEL32.dll", api), ("KERNEL32.dll", "ExitProcess")])
}

/// move via MoveFileW(src, dst) + exit by BOOL.
pub fn move_file(src: &str, dst: &str) -> Vec<u8> {
    let mut a = Asm::new();
    let d_src = a.add_utf16(src);
    let d_dst = a.add_utf16(dst);
    let lbl_fail = a.next_label;
    a.next_label += 1;
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, d_src);
    a.lea_reg_rip(2, d_dst);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.add_rsp(0x28);
    a.ret();
    a.mark(lbl_fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    a.add_rsp(0x28);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "MoveFileW"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// copy via CopyFileW(src, dst, FALSE) + exit by BOOL.
pub fn copy_file(src: &str, dst: &str) -> Vec<u8> {
    let mut a = Asm::new();
    let d_src = a.add_utf16(src);
    let d_dst = a.add_utf16(dst);
    let lbl_fail = a.next_label;
    a.next_label += 1;
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, d_src);
    a.lea_reg_rip(2, d_dst);
    a.mov_r8d_imm(0);
    a.call_import(0);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.mov_ecx_imm(0);
    a.call_import(1);
    a.add_rsp(0x28);
    a.ret();
    a.mark(lbl_fail);
    a.mov_ecx_imm(1);
    a.call_import(1);
    a.add_rsp(0x28);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "CopyFileW"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

// ---------- self-verifying guest programs (used as committed test artifacts) ----------
// Each prints `PASS\n` + exit 0 on success, `FAIL\n` + exit 1 on any failure,
// so `winrun the.exe` is fully observable black-box (fresh WinFS per process).

const CF: usize = 0; // CreateFileW
const WF: usize = 1; // WriteFile
const CH: usize = 2; // CloseHandle

/// Emit `handle = CreateFileW(path_data, access, creation)`.
/// Win x64 layout: arg1-4 in rcx,rdx,r8,r9; creation is the 5th arg at
/// [rsp+0x20], flags at [rsp+0x28], template at [rsp+0x30].
/// Frame: caller must have `sub rsp` with room; uses [rsp+0x20..0x30].
/// On return, rax = handle or INVALID_HANDLE_VALUE.
fn emit_create(a: &mut Asm, d_path: usize, access: u64, creation: u32, call_idx: usize) {
    a.lea_reg_rip(1, d_path); // rcx = path
    a.mov_rax_imm64(access);
    a.mov_rdx_rax(); // rdx = access
    a.mov_r8d_imm(0); // share
    a.mov_r9d_imm(0); // security
    a.xor_eax();
    a.mov_rspoff_imm32(0x20, creation);
    a.mov_rspoff_imm32(0x28, 0x80); // flags
    a.mov_rspoff_rax(0x30); // hTemplate = NULL
    a.call_import(call_idx);
}

/// Emit `print(msg_data, len)`: GetStdHandle(-11) + WriteFile + CloseHandle-free.
/// Uses call indices gh_idx (GetStdHandle) and wf_idx (WriteFile), plus d_written cell.
fn emit_print(a: &mut Asm, d_msg: usize, len: u32, d_written: usize, gh_idx: usize, wf_idx: usize) {
    a.mov_ecx_imm(0xFFFF_FFF5);
    a.call_import(gh_idx);
    a.mov_rcx_rax();
    a.lea_reg_rip(2, d_msg);
    a.mov_r32_imm(8, len); // r8d = len
    a.lea_reg_rip(9, d_written);
    a.xor_eax();
    a.mov_rspoff_rax(0x20); // overlapped = NULL
    a.call_import(wf_idx);
}

/// Full file selftest: write -> read back -> byte-compare -> delete ->
/// verify-open-fails. Prints PASS/FAIL.
pub fn fs_selftest_file(path: &str, content: &[u8]) -> Vec<u8> {
    assert!(!content.is_empty(), "selftest content must be non-empty");
    // imports: CreateFileW WriteFile CloseHandle ReadFile GetStdHandle DeleteFileW ExitProcess
    const RF: usize = 3;
    const GH: usize = 4;
    const DF: usize = 5;
    const XP: usize = 6;
    let mut a = Asm::new();
    let d_path = a.add_utf16(path);
    let d_data = a.add_data(content.to_vec());
    let d_buf = a.add_zeroed(content.len() + 64);
    let d_written = a.add_zeroed(8);
    let d_nread = a.add_zeroed(8);
    let d_pass = a.add_data(b"PASS\n".to_vec());
    let d_fail = a.add_data(b"FAIL\n".to_vec());
    let lbl_fail = a.next_label;
    a.next_label += 1;
    let lbl_loop = a.next_label;
    a.next_label += 1;
    let lbl_noloop = a.next_label;
    a.next_label += 1;

    a.sub_rsp(0x58);
    // -- create + write --
    emit_create(&mut a, d_path, 0x4000_0000, 2, CF);
    a.cmp_rax_m1();
    a.jz(lbl_fail);
    a.mov_rspoff_rax(0x40); // save handle
    a.mov_reg_rspoff(1, 0x40); // rcx = handle
    a.lea_reg_rip(2, d_data);
    a.mov_r32_imm(8, content.len() as u32);
    a.lea_reg_rip(9, d_written);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(WF);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.mov_reg_rspoff(1, 0x40);
    a.call_import(CH);
    // -- open + read --
    emit_create(&mut a, d_path, 0x8000_0000, 3, CF);
    a.cmp_rax_m1();
    a.jz(lbl_fail);
    a.mov_rspoff_rax(0x40);
    a.mov_reg_rspoff(1, 0x40);
    a.lea_reg_rip(2, d_buf);
    a.mov_r32_imm(8, (content.len() + 64) as u32);
    a.lea_reg_rip(9, d_nread);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(RF);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.mov_reg_rspoff(1, 0x40);
    a.call_import(CH);
    // -- verify byte count --
    a.mov_eax_mem_rip(d_nread);
    a.cmp_eax_imm(content.len() as u32);
    a.jnz(lbl_fail);
    // -- byte-compare loop --
    a.lea_reg_rip(0, d_buf); // rax = actual
    a.lea_reg_rip(2, d_data); // rdx = expected
    a.mov_r32_imm(10, content.len() as u32); // r10d = n
    a.test_r10d();
    a.jz(lbl_noloop);
    a.mark(lbl_loop);
    a.movzx_ecx_byte_rax();
    a.movzx_ebx_byte_rdx();
    a.cmp_ecx_ebx();
    a.jnz(lbl_fail);
    a.inc_rax();
    a.inc_rdx();
    a.dec_r10d();
    a.jnz(lbl_loop);
    a.mark(lbl_noloop);
    // -- delete + verify gone --
    a.lea_reg_rip(1, d_path);
    a.call_import(DF);
    a.test_eax_eax();
    a.jz(lbl_fail);
    emit_create(&mut a, d_path, 0x8000_0000, 3, CF);
    a.cmp_rax_m1();
    a.jnz(lbl_fail); // open must FAIL now
                     // -- PASS --
    emit_print(&mut a, d_pass, 5, d_written, GH, WF);
    a.mov_ecx_imm(0);
    a.call_import(XP);
    a.add_rsp(0x58);
    a.ret();
    // -- FAIL --
    a.mark(lbl_fail);
    emit_print(&mut a, d_fail, 5, d_written, GH, WF);
    a.mov_ecx_imm(1);
    a.call_import(XP);
    a.add_rsp(0x58);
    a.ret();

    build(
        a,
        &[
            ("KERNEL32.dll", "CreateFileW"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "CloseHandle"),
            ("KERNEL32.dll", "ReadFile"),
            ("KERNEL32.dll", "GetStdHandle"),
            ("KERNEL32.dll", "DeleteFileW"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// Directory selftest: mkdir -> duplicate must fail -> rmdir ->
/// duplicate must fail. Prints PASS/FAIL.
pub fn dir_selftest(path: &str) -> Vec<u8> {
    // imports: GetStdHandle WriteFile CreateDirectoryW RemoveDirectoryW ExitProcess
    const GH: usize = 0;
    const WF: usize = 1;
    const MK: usize = 2;
    const RM: usize = 3;
    const XP: usize = 4;
    let mut a = Asm::new();
    let d_path = a.add_utf16(path);
    let d_written = a.add_zeroed(8);
    let d_pass = a.add_data(b"PASS\n".to_vec());
    let d_fail = a.add_data(b"FAIL\n".to_vec());
    let lbl_fail = a.next_label;
    a.next_label += 1;
    a.sub_rsp(0x28);
    a.lea_reg_rip(1, d_path);
    a.call_import(MK);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.lea_reg_rip(1, d_path);
    a.call_import(MK);
    a.test_eax_eax();
    a.jnz(lbl_fail); // duplicate must fail
    a.lea_reg_rip(1, d_path);
    a.call_import(RM);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.lea_reg_rip(1, d_path);
    a.call_import(RM);
    a.test_eax_eax();
    a.jnz(lbl_fail); // duplicate must fail
    emit_print(&mut a, d_pass, 5, d_written, GH, WF);
    a.mov_ecx_imm(0);
    a.call_import(XP);
    a.add_rsp(0x28);
    a.ret();
    a.mark(lbl_fail);
    emit_print(&mut a, d_fail, 5, d_written, GH, WF);
    a.mov_ecx_imm(1);
    a.call_import(XP);
    a.add_rsp(0x28);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "GetStdHandle"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "CreateDirectoryW"),
            ("KERNEL32.dll", "RemoveDirectoryW"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// Move/copy selftest: write a -> copy a to b -> move b to c ->
/// read c to stdout -> delete a,c. Prints content then PASS/FAIL.
pub fn move_copy_selftest(a_path: &str, b_path: &str, c_path: &str, content: &[u8]) -> Vec<u8> {
    // imports: CreateFileW WriteFile CloseHandle ReadFile GetStdHandle
    //          CopyFileW MoveFileW DeleteFileW ExitProcess
    const RF: usize = 3;
    const GH: usize = 4;
    const CP: usize = 5;
    const MV: usize = 6;
    const DF: usize = 7;
    const XP: usize = 8;
    let mut a = Asm::new();
    let d_a = a.add_utf16(a_path);
    let d_b = a.add_utf16(b_path);
    let d_c = a.add_utf16(c_path);
    let d_data = a.add_data(content.to_vec());
    let d_buf = a.add_zeroed(content.len() + 64);
    let d_written = a.add_zeroed(8);
    let d_nread = a.add_zeroed(8);
    let d_pass = a.add_data(b"PASS\n".to_vec());
    let d_fail = a.add_data(b"FAIL\n".to_vec());
    let lbl_fail = a.next_label;
    a.next_label += 1;
    a.sub_rsp(0x58);
    // write a
    emit_create(&mut a, d_a, 0x4000_0000, 2, CF);
    a.cmp_rax_m1();
    a.jz(lbl_fail);
    a.mov_rspoff_rax(0x40);
    a.mov_reg_rspoff(1, 0x40);
    a.lea_reg_rip(2, d_data);
    a.mov_r32_imm(8, content.len() as u32);
    a.lea_reg_rip(9, d_written);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(WF);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.mov_reg_rspoff(1, 0x40);
    a.call_import(CH);
    // copy a -> b
    a.lea_reg_rip(1, d_a);
    a.lea_reg_rip(2, d_b);
    a.mov_r32_imm(8, 0);
    a.call_import(CP);
    a.test_eax_eax();
    a.jz(lbl_fail);
    // move b -> c
    a.lea_reg_rip(1, d_b);
    a.lea_reg_rip(2, d_c);
    a.call_import(MV);
    a.test_eax_eax();
    a.jz(lbl_fail);
    // read c to stdout (observable content)
    emit_create(&mut a, d_c, 0x8000_0000, 3, CF);
    a.cmp_rax_m1();
    a.jz(lbl_fail);
    a.mov_rspoff_rax(0x40);
    a.mov_reg_rspoff(1, 0x40);
    a.lea_reg_rip(2, d_buf);
    a.mov_r32_imm(8, (content.len() + 64) as u32);
    a.lea_reg_rip(9, d_nread);
    a.xor_eax();
    a.mov_rspoff_rax(0x20);
    a.call_import(RF);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.mov_reg_rspoff(1, 0x40);
    a.call_import(CH);
    a.mov_eax_mem_rip(d_nread);
    a.cmp_eax_imm(content.len() as u32);
    a.jnz(lbl_fail);
    emit_print(&mut a, d_buf, content.len() as u32, d_written, GH, WF);
    // delete a + c
    a.lea_reg_rip(1, d_a);
    a.call_import(DF);
    a.test_eax_eax();
    a.jz(lbl_fail);
    a.lea_reg_rip(1, d_c);
    a.call_import(DF);
    a.test_eax_eax();
    a.jz(lbl_fail);
    emit_print(&mut a, d_pass, 5, d_written, GH, WF);
    a.mov_ecx_imm(0);
    a.call_import(XP);
    a.add_rsp(0x58);
    a.ret();
    a.mark(lbl_fail);
    emit_print(&mut a, d_fail, 5, d_written, GH, WF);
    a.mov_ecx_imm(1);
    a.call_import(XP);
    a.add_rsp(0x58);
    a.ret();
    build(
        a,
        &[
            ("KERNEL32.dll", "CreateFileW"),
            ("KERNEL32.dll", "WriteFile"),
            ("KERNEL32.dll", "CloseHandle"),
            ("KERNEL32.dll", "ReadFile"),
            ("KERNEL32.dll", "GetStdHandle"),
            ("KERNEL32.dll", "CopyFileW"),
            ("KERNEL32.dll", "MoveFileW"),
            ("KERNEL32.dll", "DeleteFileW"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}
