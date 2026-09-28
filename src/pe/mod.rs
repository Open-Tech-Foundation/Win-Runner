//! Minimal PE32+ (x86_64) loader: parse + validate, extract imports.
//! Execution is delegated to the selected platform backend.

pub mod builder;

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Import {
    /// RVA of the IAT slot that will hold the resolved address
    pub iat_rva: u32,
    pub dll: String,
    pub func: String,
}

/// One entry from a PE export table. A function may have several names; such
/// aliases are represented as separate entries with the same ordinal/RVA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub ordinal: u32,
    pub name: Option<String>,
    pub target_rva: u32,
    /// Set when `target_rva` points back into the export directory.
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeImage {
    /// IMAGE_FILE_DLL in the PE COFF header.
    pub is_dll: bool,
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    /// Raw image bytes sized `size_of_image`, with sections copied to their VAs.
    /// `image[rva] == byte at image_base + rva`.
    pub image: Vec<u8>,
    pub imports: Vec<Import>,
    /// Parsed PE exports, including ordinal-only exports and forwarders.
    pub exports: Vec<Export>,
    /// Imports without native platform trampolines. Empty from strict `load`;
    /// populated by `load_lenient` for diagnostics and rejected before entry.
    pub unsupported: Vec<Import>,
    /// Thread-local storage template (TLS directory), if present.
    pub tls: Option<TlsDir>,
    /// Executable-but-not-writable section ranges as absolute VAs (for W^X
    /// enforcement: guest writes there fail loudly instead of corrupting
    /// code; RWX sections stay writable).
    pub code_ranges: Vec<(u64, u64)>,
    /// RVAs of 64-bit words requiring IMAGE_REL_BASED_DIR64 adjustment when
    /// the image cannot be mapped at `image_base`.
    pub relocations: Vec<u32>,
}

impl PeImage {
    /// Old .NET Framework executables enter through the CLR shim exported by
    /// mscoree.dll. Win-Runner currently runs native x86-64 code only and has
    /// no CLR host for this entry point.
    pub fn is_dotnet_framework_image(&self) -> bool {
        self.imports.iter().chain(&self.unsupported).any(|import| {
            import.dll.eq_ignore_ascii_case("mscoree.dll")
                && (import.func.eq_ignore_ascii_case("_CorExeMain")
                    || import.func.eq_ignore_ascii_case("_CorDllMain"))
        })
    }
}

/// Thread-local storage directory (IMAGE_TLS_DIRECTORY64, RVAs).
#[derive(Debug, Clone)]
pub struct TlsDir {
    /// Template bytes (raw data) to copy into each thread's TLS block.
    pub raw_data: Vec<u8>,
    /// RVA of the template in the mapped image, after base relocations.
    pub raw_data_rva: u32,
    /// Extra zero bytes after the template.
    pub zero_fill: u32,
    /// RVA of the slot-index DWORD (loader writes the assigned index).
    pub index_rva: u32,
    /// Callback RVAs invoked before the entry point and on thread attach.
    pub callbacks: Vec<u32>,
}

/// Rebase a loaded PE image before mapping it at `new_base`.
pub fn rebase(image: &mut PeImage, new_base: u64) -> Result<(), String> {
    if new_base == image.image_base {
        return Ok(());
    }
    if image.relocations.is_empty() {
        return Err("PE image has no base relocations".to_string());
    }
    apply_base_relocations(
        &mut image.image,
        &image.relocations,
        image.image_base,
        new_base,
    )?;
    let delta = new_base as i128 - image.image_base as i128;
    for (start, end) in &mut image.code_ranges {
        *start = (*start as i128 + delta)
            .try_into()
            .map_err(|_| "rebased code range overflows".to_string())?;
        *end = (*end as i128 + delta)
            .try_into()
            .map_err(|_| "rebased code range overflows".to_string())?;
    }
    image.image_base = new_base;
    Ok(())
}

fn apply_base_relocations(
    image: &mut [u8],
    relocations: &[u32],
    old_base: u64,
    new_base: u64,
) -> Result<(), String> {
    let delta = new_base as i128 - old_base as i128;
    for rva in relocations {
        let offset = *rva as usize;
        let end = offset
            .checked_add(8)
            .filter(|end| *end <= image.len())
            .ok_or_else(|| "base relocation target out of bounds".to_string())?;
        let value = u64::from_le_bytes(image[offset..end].try_into().unwrap());
        let rebased: u64 = (value as i128 + delta)
            .try_into()
            .map_err(|_| "rebased address overflows".to_string())?;
        image[offset..end].copy_from_slice(&rebased.to_le_bytes());
    }
    Ok(())
}

/// True when the selected native platform backend has an import trampoline.
pub fn is_supported(dll: &str, func: &str) -> bool {
    crate::native::supports_import(dll, func)
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

/// Parse without rejecting unknown imports. The native backend checks every
/// import before guest execution and names unsupported APIs in its error.
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
        return Err(format!(
            "unsupported machine 0x{machine:04x}: only x86_64 (0x8664) supported"
        ));
    }
    let num_sections = u16le(data, coff + 2)? as usize;
    let characteristics = u16le(data, coff + 18)?;
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
    let (export_rva, export_size) = if num_rva_sizes > 0 {
        (u32le(data, opt + 112)?, u32le(data, opt + 112 + 4)?)
    } else {
        (0, 0)
    };
    let (reloc_rva, reloc_size) = if num_rva_sizes > 5 {
        (
            u32le(data, opt + 112 + 5 * 8)?,
            u32le(data, opt + 112 + 5 * 8 + 4)?,
        )
    } else {
        (0, 0)
    };
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

    // Large self-contained CLIs (notably Node.js) exceed 64 MiB.
    // Keep a finite cap so malformed headers cannot request unbounded memory.
    if size_of_image == 0 || size_of_image > 256 * 1024 * 1024 {
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
        chars: u32,
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
        let chars = u32le(data, o + 36)?;
        secs.push(Sec {
            vaddr,
            vsize,
            foff,
            fsize,
            chars,
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

    let relocations = parse_base_relocations(&image, reloc_rva, reloc_size)?;
    let exports = parse_exports(&image, export_rva, export_size)?;

    // Parse imports (from file offsets via RVA->file mapping)
    let mut imports: Vec<Import> = Vec::new();
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
                let func = if ent & 0x8000_0000_0000_0000 != 0 {
                    if strict {
                        return Err(format!(
                            "ordinal imports not supported: {dll} ordinal {}",
                            ent & 0xffff
                        ));
                    }
                    format!("#{}", ent & 0xffff)
                } else {
                    let hn_off = to_off(ent as u32)?;
                    if hn_off + 2 > data.len() {
                        return Err("truncated hint/name".to_string());
                    }
                    cstr_ascii(data, hn_off + 2)?
                };
                let imp = Import {
                    iat_rva: ft + idx * 8,
                    dll: dll.clone(),
                    func,
                };
                if !is_supported(&imp.dll, &imp.func) {
                    if strict {
                        return Err(format!("unsupported import: {}!{}", imp.dll, imp.func));
                    } else {
                        unsupported.push(imp);
                    }
                } else {
                    imports.push(imp);
                }
                idx += 1;
                if idx > 4096 {
                    return Err("too many imports".to_string());
                }
            }
            desc_off += 20;
            if desc_off > to_off(import_rva)? + import_size as usize {
                break;
            }
        }
    }

    // Executable-but-not-writable section ranges (absolute VAs) for W^X
    // enforcement (RWX sections stay writable, like real Windows).
    let code_ranges: Vec<(u64, u64)> = secs
        .iter()
        .filter(|s| s.chars & 0x20000000 != 0 && s.chars & 0x80000000 == 0)
        .map(|s| {
            let start = image_base + s.vaddr as u64;
            (start, start + s.vsize.max(s.fsize) as u64)
        })
        .collect();

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
            let mut terminated = false;
            for i in 0..64 {
                let o = cb_rva + i * 8;
                if o + 8 > image.len() {
                    return Err("TLS callbacks out of bounds".to_string());
                }
                let f = u64::from_le_bytes(image[o..o + 8].try_into().unwrap());
                if f == 0 {
                    terminated = true;
                    break;
                }
                let callback_rva = to_rva(f)?;
                if !secs.iter().any(|s| {
                    s.chars & 0x2000_0000 != 0
                        && callback_rva >= s.vaddr
                        && callback_rva < s.vaddr.saturating_add(s.vsize.max(s.fsize))
                }) {
                    return Err(format!(
                        "TLS callback 0x{callback_rva:08x} is not executable"
                    ));
                }
                callbacks.push(callback_rva);
            }
            if !terminated {
                return Err("TLS callback list is not terminated".to_string());
            }
        }
        Some(TlsDir {
            raw_data: image[start..end].to_vec(),
            raw_data_rva: start as u32,
            zero_fill,
            index_rva,
            callbacks,
        })
    } else {
        None
    };

    Ok(PeImage {
        is_dll: characteristics & 0x2000 != 0,
        image_base,
        entry_rva,
        size_of_image,
        image,
        imports,
        exports,
        unsupported,
        tls,
        code_ranges,
        relocations,
    })
}

fn parse_base_relocations(image: &[u8], rva: u32, size: u32) -> Result<Vec<u32>, String> {
    if rva == 0 && size == 0 {
        return Ok(Vec::new());
    }
    if rva == 0 || size < 8 {
        return Err("invalid base relocation directory".to_string());
    }
    let end = (rva as usize)
        .checked_add(size as usize)
        .filter(|end| *end <= image.len())
        .ok_or_else(|| "base relocation directory out of bounds".to_string())?;
    let mut at = rva as usize;
    let mut out = Vec::new();
    while at < end {
        if end - at < 8 {
            return Err("truncated base relocation block".to_string());
        }
        let page = u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        let block = u32::from_le_bytes(image[at + 4..at + 8].try_into().unwrap()) as usize;
        if block < 8 || block % 2 != 0 || block > end - at {
            return Err("invalid base relocation block".to_string());
        }
        for entry in image[at + 8..at + block].chunks_exact(2) {
            let entry = u16::from_le_bytes(entry.try_into().unwrap());
            match entry >> 12 {
                0 => {}
                10 => {
                    let target = page
                        .checked_add((entry & 0x0fff) as u32)
                        .ok_or_else(|| "base relocation RVA overflows".to_string())?;
                    if (target as usize)
                        .checked_add(8)
                        .is_none_or(|end| end > image.len())
                    {
                        return Err("base relocation target out of bounds".to_string());
                    }
                    out.push(target);
                }
                ty => return Err(format!("unsupported base relocation type {ty}")),
            }
        }
        at += block;
    }
    Ok(out)
}

fn parse_exports(image: &[u8], rva: u32, size: u32) -> Result<Vec<Export>, String> {
    if rva == 0 && size == 0 {
        return Ok(Vec::new());
    }
    if rva == 0 || size < 40 {
        return Err("invalid export directory".to_string());
    }
    let directory_end = rva
        .checked_add(size)
        .ok_or_else(|| "export directory range overflows".to_string())?;
    let directory = rva as usize;
    if directory_end as usize > image.len() {
        return Err("export directory out of image bounds".to_string());
    }
    let ordinal_base = u32le(image, directory + 16)?;
    let function_count = u32le(image, directory + 20)? as usize;
    let name_count = u32le(image, directory + 24)? as usize;
    let functions_rva = u32le(image, directory + 28)?;
    let names_rva = u32le(image, directory + 32)?;
    let ordinals_rva = u32le(image, directory + 36)?;
    const MAX_EXPORTS: usize = 1 << 20;
    if function_count > MAX_EXPORTS || name_count > function_count || name_count > MAX_EXPORTS {
        return Err("invalid export table counts".to_string());
    }
    let table_range = |table_rva: u32, count: usize, item_size: usize| {
        if count == 0 {
            return Some(0..0);
        }
        let start = table_rva as usize;
        let length = count.checked_mul(item_size)?;
        let end = start.checked_add(length)?;
        (table_rva != 0 && end <= image.len()).then_some(start..end)
    };
    let function_table = table_range(functions_rva, function_count, 4)
        .ok_or_else(|| "export address table out of bounds".to_string())?;
    let names_table = if name_count == 0 {
        0..0
    } else {
        table_range(names_rva, name_count, 4)
            .ok_or_else(|| "export name table out of bounds".to_string())?
    };
    let ordinals_table = if name_count == 0 {
        0..0
    } else {
        table_range(ordinals_rva, name_count, 2)
            .ok_or_else(|| "export ordinal table out of bounds".to_string())?
    };

    let mut names_by_index: HashMap<usize, Vec<String>> = HashMap::new();
    for i in 0..name_count {
        let name_rva = u32le(image, names_table.start + i * 4)?;
        let function_index = u16le(image, ordinals_table.start + i * 2)? as usize;
        if function_index >= function_count {
            return Err("export name ordinal is outside address table".to_string());
        }
        let name = cstr_ascii(image, name_rva as usize)
            .map_err(|_| "invalid export name string".to_string())?;
        names_by_index.entry(function_index).or_default().push(name);
    }

    let mut exports = Vec::with_capacity(function_count.max(name_count));
    for i in 0..function_count {
        let target_rva = u32le(image, function_table.start + i * 4)?;
        if target_rva == 0 {
            continue;
        }
        let forwarder = if (rva..directory_end).contains(&target_rva) {
            Some(
                cstr_ascii(image, target_rva as usize)
                    .map_err(|_| "invalid export forwarder string".to_string())?,
            )
        } else {
            if target_rva as usize >= image.len() {
                return Err("export target is outside image".to_string());
            }
            None
        };
        let ordinal = ordinal_base
            .checked_add(i as u32)
            .ok_or_else(|| "export ordinal overflows".to_string())?;
        let names = names_by_index.remove(&i).unwrap_or_default();
        if names.is_empty() {
            exports.push(Export {
                ordinal,
                name: None,
                target_rva,
                forwarder,
            });
        } else {
            for name in names {
                exports.push(Export {
                    ordinal,
                    name: Some(name),
                    target_rva,
                    forwarder: forwarder.clone(),
                });
            }
        }
    }
    Ok(exports)
}

#[cfg(test)]
mod export_tests {
    use super::{parse_exports, Export};

    fn write_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture() -> Vec<u8> {
        let mut image = vec![0; 0x300];
        // IMAGE_EXPORT_DIRECTORY at RVA 0x100.
        write_u32(&mut image, 0x110, 10); // Ordinal base
        write_u32(&mut image, 0x114, 2); // NumberOfFunctions
        write_u32(&mut image, 0x118, 1); // NumberOfNames
        write_u32(&mut image, 0x11c, 0x150); // AddressOfFunctions
        write_u32(&mut image, 0x120, 0x158); // AddressOfNames
        write_u32(&mut image, 0x124, 0x15c); // AddressOfNameOrdinals
        write_u32(&mut image, 0x150, 0x200); // Native function RVA
        write_u32(&mut image, 0x154, 0x130); // Forwarder RVA
        write_u32(&mut image, 0x158, 0x180); // Name RVA
        write_u16(&mut image, 0x15c, 0); // Name maps to first function
        image[0x130..0x13d].copy_from_slice(b"other.Target\0");
        image[0x180..0x186].copy_from_slice(b"Entry\0");
        image
    }

    #[test]
    fn parses_named_and_ordinal_only_forwarded_exports() {
        let exports = parse_exports(&fixture(), 0x100, 0x40).unwrap();
        assert_eq!(
            exports,
            vec![
                Export {
                    ordinal: 10,
                    name: Some("Entry".to_string()),
                    target_rva: 0x200,
                    forwarder: None,
                },
                Export {
                    ordinal: 11,
                    name: None,
                    target_rva: 0x130,
                    forwarder: Some("other.Target".to_string()),
                }
            ]
        );
    }

    #[test]
    fn rejects_export_name_ordinal_outside_function_table() {
        let mut image = fixture();
        write_u16(&mut image, 0x15c, 2);
        assert!(parse_exports(&image, 0x100, 0x40)
            .unwrap_err()
            .contains("ordinal is outside"));
    }

    #[test]
    fn empty_export_table_is_valid() {
        let mut image = fixture();
        write_u32(&mut image, 0x114, 0);
        write_u32(&mut image, 0x118, 0);
        write_u32(&mut image, 0x11c, 0);
        write_u32(&mut image, 0x120, 0);
        write_u32(&mut image, 0x124, 0);
        assert!(parse_exports(&image, 0x100, 0x40).unwrap().is_empty());
    }
}

#[cfg(test)]
mod relocation_tests {
    use super::{apply_base_relocations, parse_base_relocations};

    #[test]
    fn accepts_dir64_relocations_and_rejects_bad_blocks() {
        let mut image = vec![0; 0x2000];
        image[0x1000..0x1004].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        image[0x1004..0x1008].copy_from_slice(&12u32.to_le_bytes());
        image[0x1008..0x100a].copy_from_slice(&0xa008u16.to_le_bytes());
        image[0x100a..0x100c].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            parse_base_relocations(&image, 0x1000, 12).unwrap(),
            vec![0x1008]
        );
        assert!(parse_base_relocations(&image, 0x1000, 10).is_err());
        image[0x1008..0x100a].copy_from_slice(&0x3008u16.to_le_bytes());
        assert!(parse_base_relocations(&image, 0x1000, 12).is_err());
    }

    #[test]
    fn applies_positive_and_negative_relocation_deltas() {
        let mut image = vec![0; 16];
        image[..8].copy_from_slice(&0x0001_4000_0100u64.to_le_bytes());
        apply_base_relocations(&mut image, &[0], 0x0001_4000_0000, 0x0001_5000_0000).unwrap();
        assert_eq!(
            u64::from_le_bytes(image[..8].try_into().unwrap()),
            0x0001_5000_0100
        );
        apply_base_relocations(&mut image, &[0], 0x0001_5000_0000, 0x0001_4000_0000).unwrap();
        assert_eq!(
            u64::from_le_bytes(image[..8].try_into().unwrap()),
            0x0001_4000_0100
        );
        assert!(apply_base_relocations(&mut image, &[12], 1, 2).is_err());
    }
}

#[cfg(test)]
mod large_image_tests {
    use super::*;
    use crate::pe::builder::{self, Asm, FILE_OFF, SECTION_RVA};

    const OPT: usize = 0x80 + 4 + 20;

    #[test]
    fn accepts_large_images_with_a_finite_size_limit() {
        let mut exe = builder::hello("hi");
        exe[OPT + 56..OPT + 60].copy_from_slice(&(65 * 1024 * 1024u32).to_le_bytes());
        assert_eq!(load_lenient(&exe).unwrap().size_of_image, 65 * 1024 * 1024);
        exe[OPT + 56..OPT + 60].copy_from_slice(&(257 * 1024 * 1024u32).to_le_bytes());
        assert!(load_lenient(&exe)
            .unwrap_err()
            .contains("invalid SizeOfImage"));
    }

    #[test]
    fn lenient_load_reports_ordinals_and_more_than_256_imports() {
        let imports = vec![("KERNEL32.dll", "ExitProcess"); 300];
        let exe = builder::build(Asm::new(), &imports);
        assert_eq!(load_lenient(&exe).unwrap().imports.len(), 300);

        let mut exe = builder::hello("hi");
        let import_rva = u32le(&exe, OPT + 120).unwrap();
        let desc = FILE_OFF + (import_rva - SECTION_RVA) as usize;
        let thunk_rva = u32le(&exe, desc).unwrap();
        let thunk = FILE_OFF + (thunk_rva - SECTION_RVA) as usize;
        exe[thunk..thunk + 8].copy_from_slice(&0x8000_0000_0000_0074u64.to_le_bytes());
        let image = load_lenient(&exe).unwrap();
        assert!(image.unsupported.iter().any(|item| item.func == "#116"));
        assert!(load(&exe)
            .unwrap_err()
            .contains("ordinal imports not supported"));
    }

    #[test]
    fn tls_callbacks_are_loadable_and_visible_to_inspection() {
        let mut exe = builder::hello("hi");
        let old_size = u32le(&exe, OPT + 56).unwrap();
        let tls_rva = old_size;
        let raw = exe.len() as u32;
        let base = u64le(&exe, OPT + 24).unwrap();
        exe[0x80 + 4 + 2..0x80 + 4 + 4].copy_from_slice(&2u16.to_le_bytes());
        exe[OPT + 56..OPT + 60].copy_from_slice(&(old_size + 0x1000).to_le_bytes());
        let tls_dir = OPT + 112 + 9 * 8;
        exe[tls_dir..tls_dir + 4].copy_from_slice(&tls_rva.to_le_bytes());
        exe[tls_dir + 4..tls_dir + 8].copy_from_slice(&40u32.to_le_bytes());
        let header = OPT + 0xf0 + 40;
        exe[header..header + 8].copy_from_slice(b".tls\0\0\0\0");
        exe[header + 8..header + 12].copy_from_slice(&0x100u32.to_le_bytes());
        exe[header + 12..header + 16].copy_from_slice(&tls_rva.to_le_bytes());
        exe[header + 16..header + 20].copy_from_slice(&0x200u32.to_le_bytes());
        exe[header + 20..header + 24].copy_from_slice(&raw.to_le_bytes());
        exe[header + 36..header + 40].copy_from_slice(&0xc000_0040u32.to_le_bytes());
        exe.resize(exe.len() + 0x200, 0);
        exe[raw as usize..raw as usize + 8]
            .copy_from_slice(&(base + tls_rva as u64 + 0x40).to_le_bytes());
        exe[raw as usize + 8..raw as usize + 16]
            .copy_from_slice(&(base + tls_rva as u64 + 0x40).to_le_bytes());
        exe[raw as usize + 16..raw as usize + 24]
            .copy_from_slice(&(base + tls_rva as u64 + 0x48).to_le_bytes());
        exe[raw as usize + 24..raw as usize + 32]
            .copy_from_slice(&(base + tls_rva as u64 + 0x50).to_le_bytes());
        exe[raw as usize + 0x50..raw as usize + 0x58]
            .copy_from_slice(&(base + SECTION_RVA as u64).to_le_bytes());
        assert_eq!(
            load_lenient(&exe).unwrap().tls.unwrap().callbacks,
            vec![SECTION_RVA]
        );
        assert_eq!(
            load(&exe).unwrap().tls.unwrap().callbacks,
            vec![SECTION_RVA]
        );
        let report = crate::inspect::inspect_pe(&exe).unwrap();
        assert!(report.runnable());
        assert!(report.limitations.is_empty());
        let mut invalid = exe.clone();
        invalid[raw as usize + 0x50..raw as usize + 0x58]
            .copy_from_slice(&(base + u64::from(tls_rva) + 0x40).to_le_bytes());
        assert!(load(&invalid).unwrap_err().contains("not executable"));
        invalid[raw as usize + 0x50..raw as usize + 0x58].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(load(&invalid)
            .unwrap_err()
            .contains("TLS address out of image"));
    }
}
