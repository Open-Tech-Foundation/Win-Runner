//! PE image mapping, relocation, and executable protection for Linux x86-64.

use super::*;

thread_local! {
    static GUEST_DLL_LOAD_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub(super) fn map(img: &PeImage) -> Result<Mapping, String> {
    if img.image_base & 4095 != 0 {
        return Err(format!(
            "native backend requires a page-aligned image base, got 0x{:x}",
            img.image_base
        ));
    }
    let len = page_len(img.image.len())?;
    // SAFETY: mmap is called with a page-aligned requested address and a
    // checked non-zero length. MAP_FIXED_NOREPLACE prevents clobbering a
    // host mapping if the PE preferred base is occupied.
    let raw = unsafe {
        mmap(
            img.image_base as *mut c_void,
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if raw == MAP_FAILED {
        return Err(format!(
            "native backend could not map preferred base 0x{:x}: {}",
            img.image_base,
            std::io::Error::last_os_error()
        ));
    }
    if raw as u64 != img.image_base {
        // Defensive: MAP_FIXED_NOREPLACE should guarantee this.
        unsafe { munmap(raw, len) };
        return Err("native backend mapped image at an unexpected address".to_string());
    }
    // SAFETY: `raw` names a fresh mapping at least `len` bytes long; the
    // source slice is exactly the loaded PE image and fits in that range.
    unsafe { ptr::copy_nonoverlapping(img.image.as_ptr(), raw.cast(), img.image.len()) };
    Ok(Mapping {
        ptr: raw.cast(),
        len,
    })
}

/// Windows places images on its 64 KiB allocation granularity, and
/// runtimes rely on it (CoreCLR rejects an IL image whose `ImageBase` is
/// not 64 KiB-aligned), so image mappings are carved from an oversized
/// anonymous mapping at the first aligned address.
fn mmap_image_region(len: usize) -> *mut c_void {
    const GRANULARITY: usize = 0x10000;
    let Some(reserved) = len.checked_add(GRANULARITY) else {
        return MAP_FAILED;
    };
    let raw = unsafe {
        mmap(
            ptr::null_mut(),
            reserved,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if raw == MAP_FAILED {
        return raw;
    }
    let start = raw as usize;
    let aligned = (start + GRANULARITY - 1) & !(GRANULARITY - 1);
    unsafe {
        if aligned > start {
            munmap(raw, aligned - start);
        }
        let tail = start + reserved - (aligned + len);
        if tail > 0 {
            munmap((aligned + len) as *mut c_void, tail);
        }
    }
    aligned as *mut c_void
}

/// Reserve a non-conflicting host address and rebase a child image to the
/// address actually chosen by the kernel.
#[allow(dead_code)] // attached to CreateProcessW's child launcher next
pub(super) fn map_relocated(img: &PeImage) -> Result<(Mapping, PeImage), String> {
    let len = page_len(img.image.len())?;
    let raw = mmap_image_region(len);
    if raw == MAP_FAILED {
        return Err(format!(
            "native backend could not reserve relocated image: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mapping = Mapping {
        ptr: raw.cast(),
        len,
    };
    let mut relocated = img.clone();
    if let Err(error) = crate::pe::rebase(&mut relocated, raw as u64) {
        return Err(format!("native backend could not rebase image: {error}"));
    }
    unsafe {
        ptr::copy_nonoverlapping(relocated.image.as_ptr(), mapping.ptr, relocated.image.len())
    };
    Ok((mapping, relocated))
}

/// Map an IL-only image at any free address. It holds no absolute
/// addresses, so nothing is relocated; a PE32+ header's `ImageBase` is set
/// to the actual base, as the Windows loader does for a moved image.
pub(super) fn map_il_only(img: &PeImage) -> Result<(Mapping, PeImage), String> {
    let len = page_len(img.image.len())?;
    let raw = mmap_image_region(len);
    if raw == MAP_FAILED {
        return Err(format!(
            "native backend could not map IL image: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mapping = Mapping {
        ptr: raw.cast(),
        len,
    };
    let mut mapped = img.clone();
    mapped.image_base = raw as u64;
    let header = u32::from_le_bytes(mapped.image[0x3c..0x40].try_into().unwrap()) as usize;
    let optional = header + 24;
    if mapped.image.get(optional..optional + 2) == Some(&0x20bu16.to_le_bytes()[..]) {
        mapped.image[optional + 24..optional + 32].copy_from_slice(&(raw as u64).to_le_bytes());
    }
    unsafe { ptr::copy_nonoverlapping(mapped.image.as_ptr(), mapping.ptr, mapped.image.len()) };
    Ok((mapping, mapped))
}

#[cfg(test)]
mod relocated_map_tests {
    use super::{map_relocated, PeImage};

    #[test]
    fn maps_il_images_anywhere_and_records_the_base_in_the_header() {
        let mut bytes = vec![0; 0x200];
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[0xb0..0xb8].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        let image = PeImage {
            is_dll: false,
            image_base: 0x1_4000_0000,
            entry_rva: 0,
            size_of_image: 0x200,
            image: bytes,
            imports: vec![],
            exports: vec![],
            unsupported: vec![],
            tls: None,
            code_ranges: vec![],
            relocations: vec![],
            page_protections: vec![],
        };
        let (mapping, mapped) = super::map_il_only(&image).unwrap();
        assert_eq!(mapped.image_base, mapping.ptr as u64);
        assert_eq!(mapping.ptr as u64 % 0x10000, 0, "64 KiB allocation granularity");
        let header_base = unsafe { mapping.ptr.add(0xb0).cast::<u64>().read_unaligned() };
        assert_eq!(header_base, mapping.ptr as u64);
    }

    #[test]
    fn maps_at_the_reserved_address_and_applies_dir64_delta() {
        let mut bytes = vec![0; 16];
        bytes[..8].copy_from_slice(&0x0001_4000_0100u64.to_le_bytes());
        let image = PeImage {
            is_dll: false,
            image_base: 0x0001_4000_0000,
            entry_rva: 0,
            size_of_image: 16,
            image: bytes,
            imports: vec![],
            exports: vec![],
            unsupported: vec![],
            tls: None,
            code_ranges: vec![],
            relocations: vec![0],
            page_protections: vec![],
        };
        let (mapping, relocated) = map_relocated(&image).unwrap();
        assert_eq!(relocated.image_base, mapping.ptr as u64);
        assert_eq!(mapping.ptr as u64 % 0x10000, 0, "64 KiB allocation granularity");
        let value = unsafe {
            u64::from_le_bytes(
                std::slice::from_raw_parts(mapping.ptr, 8)
                    .try_into()
                    .unwrap(),
            )
        };
        assert_eq!(value, mapping.ptr as u64 + 0x100);
    }
}

#[cfg(test)]
mod module_export_tests {
    use super::{
        native_free_library, native_get_module_handle_w, native_get_proc_address,
        native_load_library_ex_w, API_SET_MODULE,
    };
    use crate::native::linux_x86_64::state::NativeLoadedModule;
    use crate::pe::Export;
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    static DLL_PROCESS_DETACH_REASON: AtomicU32 = AtomicU32::new(u32::MAX);

    unsafe extern "win64" fn record_process_detach(_base: u64, reason: u32, _reserved: u64) -> i32 {
        DLL_PROCESS_DETACH_REASON.store(reason, Ordering::SeqCst);
        1
    }

    fn pending_module(base: u64, load_order: u64, dependencies: Vec<u64>) -> NativeLoadedModule {
        NativeLoadedModule {
            path: format!(r"C:\bin\{base:x}.dll"),
            name: format!("{base:x}.dll"),
            base,
            size_of_image: 0x1000,
            exports: Vec::new(),
            entry_point: None,
            tls_callbacks: Vec::new(),
            static_tls_index: None,
            static_tls_template: None,
            load_order,
            load_references: 0,
            dependencies,
            mapping: None,
            initialized: false,
        }
    }

    #[test]
    fn module_initialization_orders_dependencies_and_groups_cycles_by_load_order() {
        let _isolation = super::NATIVE_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _process = super::context::TestProcessGuard::new();
        let modules = std::collections::HashMap::from([
            (0x1000, pending_module(0x1000, 1, vec![0x2000])),
            (0x2000, pending_module(0x2000, 2, vec![0x1000])),
            (0x3000, pending_module(0x3000, 3, vec![0x1000])),
            (0x4000, pending_module(0x4000, 0, vec![])),
        ]);

        assert_eq!(
            super::module_initialization_order(&modules),
            vec![0x4000, 0x1000, 0x2000, 0x3000]
        );
    }

    fn dll_fixture(
        imports: &[(&str, &str)],
        export_name: Option<&str>,
        image_base: u64,
    ) -> Vec<u8> {
        let mut asm = crate::pe::builder::Asm::new();
        asm.mov_r32_imm(0, 1);
        asm.ret();
        let mut bytes = crate::pe::builder::build(asm, imports);
        let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let coff = pe + 4;
        let opt = coff + 20;
        let section = opt + 0xf0;
        let characteristics = u16::from_le_bytes(bytes[coff + 18..coff + 20].try_into().unwrap());
        bytes[coff + 18..coff + 20].copy_from_slice(&(characteristics | 0x2000).to_le_bytes());
        bytes[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        let Some(export_name) = export_name else {
            return bytes;
        };

        let old_vsize = u32::from_le_bytes(bytes[section + 8..section + 12].try_into().unwrap());
        let export_rva = crate::pe::builder::SECTION_RVA + ((old_vsize + 7) & !7);
        let function_rva_table = export_rva + 40;
        let names_rva_table = function_rva_table + 4;
        let ordinal_table = names_rva_table + 4;
        let name_rva = ordinal_table + 2;
        let data_end = name_rva + export_name.len() as u32 + 1;
        let raw_size = (data_end - crate::pe::builder::SECTION_RVA + 0x1ff) & !0x1ff;
        bytes.resize(crate::pe::builder::FILE_OFF + raw_size as usize, 0);
        let export_off =
            crate::pe::builder::FILE_OFF + (export_rva - crate::pe::builder::SECTION_RVA) as usize;
        let write32 = |bytes: &mut Vec<u8>, offset: usize, value: u32| {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };
        let write16 = |bytes: &mut Vec<u8>, offset: usize, value: u16| {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        };
        write32(&mut bytes, export_off + 16, 1);
        write32(&mut bytes, export_off + 20, 1);
        write32(&mut bytes, export_off + 24, 1);
        write32(&mut bytes, export_off + 28, function_rva_table);
        write32(&mut bytes, export_off + 32, names_rva_table);
        write32(&mut bytes, export_off + 36, ordinal_table);
        write32(
            &mut bytes,
            crate::pe::builder::FILE_OFF
                + (function_rva_table - crate::pe::builder::SECTION_RVA) as usize,
            crate::pe::builder::SECTION_RVA,
        );
        write32(
            &mut bytes,
            crate::pe::builder::FILE_OFF
                + (names_rva_table - crate::pe::builder::SECTION_RVA) as usize,
            name_rva,
        );
        write16(
            &mut bytes,
            crate::pe::builder::FILE_OFF
                + (ordinal_table - crate::pe::builder::SECTION_RVA) as usize,
            0,
        );
        let name_off =
            crate::pe::builder::FILE_OFF + (name_rva - crate::pe::builder::SECTION_RVA) as usize;
        bytes[name_off..name_off + export_name.len()].copy_from_slice(export_name.as_bytes());
        bytes[name_off + export_name.len()] = 0;
        write32(&mut bytes, opt + 112, export_rva);
        write32(&mut bytes, opt + 116, data_end - export_rva);
        let virtual_size = data_end - crate::pe::builder::SECTION_RVA;
        write32(&mut bytes, section + 8, virtual_size);
        write32(&mut bytes, section + 16, raw_size);
        write32(
            &mut bytes,
            opt + 56,
            (crate::pe::builder::SECTION_RVA + virtual_size + 0xfff) & !0xfff,
        );
        bytes
    }

    fn add_static_tls(mut bytes: Vec<u8>, initial: &[u8], zero_fill: u32) -> Vec<u8> {
        let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let coff = pe + 4;
        let opt = coff + 20;
        let section = opt + 0xf0;
        let base = u64::from_le_bytes(bytes[opt + 24..opt + 32].try_into().unwrap());
        let section_rva = u32::from_le_bytes(bytes[section + 12..section + 16].try_into().unwrap());
        let raw_size = u32::from_le_bytes(bytes[section + 16..section + 20].try_into().unwrap());
        let raw_offset = u32::from_le_bytes(bytes[section + 20..section + 24].try_into().unwrap());
        let tls_rva = section_rva + raw_size;
        let tls_file_offset = raw_offset as usize + raw_size as usize;
        let data_rva = tls_rva + 40;
        let index_rva = data_rva + initial.len() as u32;
        let needed = 40 + initial.len() + 4;
        let added_raw_size = (needed as u32 + 0x1ff) & !0x1ff;
        bytes.resize(tls_file_offset + added_raw_size as usize, 0);
        let tls = &mut bytes[tls_file_offset..tls_file_offset + 40];
        tls[0..8].copy_from_slice(&(base + data_rva as u64).to_le_bytes());
        tls[8..16].copy_from_slice(&(base + data_rva as u64 + initial.len() as u64).to_le_bytes());
        tls[16..24].copy_from_slice(&(base + index_rva as u64).to_le_bytes());
        tls[32..36].copy_from_slice(&zero_fill.to_le_bytes());
        bytes[tls_file_offset + 40..tls_file_offset + 40 + initial.len()].copy_from_slice(initial);
        let tls_dir = opt + 112 + 9 * 8;
        bytes[tls_dir..tls_dir + 4].copy_from_slice(&tls_rva.to_le_bytes());
        bytes[tls_dir + 4..tls_dir + 8].copy_from_slice(&40u32.to_le_bytes());
        let new_raw_size = raw_size + added_raw_size;
        bytes[section + 8..section + 12]
            .copy_from_slice(&(raw_size + added_raw_size).to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&new_raw_size.to_le_bytes());
        let size_of_image = (section_rva + new_raw_size + 0xfff) & !0xfff;
        bytes[opt + 56..opt + 60].copy_from_slice(&size_of_image.to_le_bytes());
        bytes
    }

    #[test]
    fn get_proc_address_resolves_named_and_ordinal_dll_exports() {
        let _isolation = super::NATIVE_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _process = super::context::TestProcessGuard::new();
        let handle = 0x7a00_0000;
        let module = NativeLoadedModule {
            path: r"C:\bin\sample.dll".to_string(),
            name: "sample.dll".to_string(),
            base: handle,
            size_of_image: 0x4000,
            exports: vec![Export {
                ordinal: 7,
                name: Some("SampleEntry".to_string()),
                target_rva: 0x1234,
                forwarder: None,
            }],
            entry_point: None,
            tls_callbacks: Vec::new(),
            static_tls_index: None,
            static_tls_template: None,
            load_order: 1,
            load_references: 0,
            dependencies: Vec::new(),
            mapping: None,
            initialized: true,
        };
        let process = &*super::process_ctx().unwrap();
        process
            .loaded_modules
            .lock()
            .unwrap()
            .insert(handle, module);
        let name = CString::new("SampleEntry").unwrap();
        assert_eq!(
            native_get_proc_address(handle, name.as_ptr().cast()),
            handle + 0x1234
        );
        assert_eq!(
            native_get_proc_address(handle, 7usize as *const u8),
            handle + 0x1234
        );
        process.loaded_modules.lock().unwrap().remove(&handle);
    }

    #[test]
    fn get_proc_address_follows_system_module_forwarder() {
        let _isolation = super::NATIVE_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _process = super::context::TestProcessGuard::new();
        let handle = 0x7a00_1000;
        let module = NativeLoadedModule {
            path: r"C:\bin\forwarder.dll".to_string(),
            name: "forwarder.dll".to_string(),
            base: handle,
            size_of_image: 0x4000,
            exports: vec![Export {
                ordinal: 1,
                name: Some("ForwardedTick".to_string()),
                target_rva: 0x200,
                forwarder: Some("kernel32.GetTickCount".to_string()),
            }],
            entry_point: None,
            tls_callbacks: Vec::new(),
            static_tls_index: None,
            static_tls_template: None,
            load_order: 1,
            load_references: 0,
            dependencies: Vec::new(),
            mapping: None,
            initialized: true,
        };
        let process = &*super::process_ctx().unwrap();
        process
            .loaded_modules
            .lock()
            .unwrap()
            .insert(handle, module);
        let name = CString::new("ForwardedTick").unwrap();
        assert_ne!(native_get_proc_address(handle, name.as_ptr().cast()), 0);
        assert_eq!(API_SET_MODULE, crate::native::linux_x86_64::API_SET_MODULE);
        process.loaded_modules.lock().unwrap().remove(&handle);
    }

    #[test]
    fn a_guest_dll_loads_when_system_imports_it_never_calls_are_missing() {
        let _isolation = super::NATIVE_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _process = super::context::TestProcessGuard::new();
        // CoreCLR and the .NET host import far more than a program uses;
        // unimplemented system functions become call-time stubs.
        let bytes = dll_fixture(
            &[
                ("user32.dll", "MessageBoxW"),
                ("KERNEL32.dll", "WinrunNoSuchFunctionForTests"),
                ("api-ms-win-crt-private-l1-1-0.dll", "_o_nothing_here"),
            ],
            None,
            0x0000_5009_0000_0000,
        );
        let process = &*super::process_ctx().unwrap();
        let path = r"C:\loader-tests\missing-system-imports.dll";
        {
            let mut native_fs = process.fs.lock().unwrap();
            native_fs.fs.mkdir(r"C:\loader-tests").unwrap();
            native_fs.fs.write_file(path, bytes).unwrap();
        }
        let name: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = native_load_library_ex_w(name.as_ptr(), 0, 0);
        assert_ne!(handle, 0, "the DLL loads with stubbed imports");
        assert_eq!(native_free_library(handle), 1);
        // A system DLL named directly loads as winrun's module, while
        // GetModuleHandle still reports it as not loaded.
        let user32: Vec<u16> = "user32.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(
            native_load_library_ex_w(user32.as_ptr(), 0, 0),
            API_SET_MODULE
        );
        assert_eq!(native_get_module_handle_w(user32.as_ptr()), 0);
    }

    #[test]
    fn load_library_maps_a_guest_dll_from_winfs() {
        let _isolation = super::NATIVE_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _process = super::context::TestProcessGuard::new();
        let bytes = dll_fixture(&[], None, 0x0000_5000_0000_0000);

        let process = &*super::process_ctx().unwrap();
        let path = r"C:\loader-tests\sample-runtime.dll";
        {
            let mut native_fs = process.fs.lock().unwrap();
            native_fs.fs.mkdir(r"C:\loader-tests").unwrap();
            native_fs.fs.write_file(path, bytes).unwrap();
        }
        let name: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = native_load_library_ex_w(name.as_ptr(), 0, 0);
        assert_ne!(handle, 0, "WinFS DLL loads");
        assert_ne!(handle, API_SET_MODULE);
        assert_eq!(handle, native_get_module_handle_w(name.as_ptr()));
        let second_handle = native_load_library_ex_w(name.as_ptr(), 0, 0);
        assert_eq!(
            second_handle, handle,
            "repeated LoadLibrary reuses the module"
        );
        assert_eq!(native_free_library(handle), 1);
        assert_eq!(
            native_get_module_handle_w(name.as_ptr()),
            handle,
            "one remaining load reference keeps the module registered"
        );
        assert_eq!(native_free_library(handle), 1);
        assert_eq!(
            native_free_library(handle),
            0,
            "unbalanced FreeLibrary fails"
        );
        assert_eq!(native_get_module_handle_w(name.as_ptr()), 0);
        process.fs.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn final_free_library_runs_process_detach_and_unmaps_the_image() {
        let _isolation = super::NATIVE_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _process = super::context::TestProcessGuard::new();
        let process = &*super::process_ctx().unwrap();
        let image =
            crate::pe::load_lenient(&dll_fixture(&[], None, 0x0000_5004_0000_0000)).unwrap();
        let mapping = super::map(&image).expect("test image maps");
        let base = mapping.ptr as u64;
        let module = NativeLoadedModule {
            path: r"C:\loader-tests\detach.dll".to_string(),
            name: "detach.dll".to_string(),
            base,
            size_of_image: image.size_of_image,
            exports: Vec::new(),
            entry_point: Some(record_process_detach as *const () as usize as u64),
            tls_callbacks: Vec::new(),
            static_tls_index: None,
            static_tls_template: None,
            load_order: 1,
            load_references: 0,
            dependencies: Vec::new(),
            mapping: Some(mapping),
            initialized: true,
        };
        DLL_PROCESS_DETACH_REASON.store(u32::MAX, Ordering::SeqCst);
        super::dispose_loaded_module(process, module);
        assert_eq!(DLL_PROCESS_DETACH_REASON.load(Ordering::SeqCst), 0);

        let remapped = super::map(&image).expect("disposed image mapping was released");
        assert_eq!(remapped.ptr as u64, base);
        drop(remapped);
    }

    #[test]
    fn load_library_resolves_recursive_guest_dll_imports() {
        let _isolation = super::NATIVE_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _process = super::context::TestProcessGuard::new();
        let process = &*super::process_ctx().unwrap();
        let dependency_path = r"C:\loader-tests\dependency.dll";
        let consumer_path = r"C:\loader-tests\consumer.dll";
        {
            let mut native_fs = process.fs.lock().unwrap();
            native_fs.fs.mkdir(r"C:\loader-tests").unwrap();
            native_fs
                .fs
                .write_file(
                    dependency_path,
                    dll_fixture(&[], Some("DependencyEntry"), 0x0000_5001_0000_0000),
                )
                .unwrap();
            native_fs
                .fs
                .write_file(
                    consumer_path,
                    dll_fixture(
                        &[("dependency.dll", "DependencyEntry")],
                        None,
                        crate::pe::builder::IMAGE_BASE,
                    ),
                )
                .unwrap();
        }
        let consumer_name: Vec<u16> = "consumer.dll".encode_utf16().chain(Some(0)).collect();
        let consumer = native_load_library_ex_w(consumer_name.as_ptr(), 0, 0);
        assert_ne!(consumer, 0, "consumer DLL resolves its guest dependency");
        let dependency_name = CString::new("dependency.dll").unwrap();
        let dependency = super::native_get_module_handle_a(dependency_name.as_ptr().cast());
        assert_ne!(dependency, 0, "dependency module is loaded");

        let consumer_image = crate::pe::load_lenient(&dll_fixture(
            &[("dependency.dll", "DependencyEntry")],
            None,
            crate::pe::builder::IMAGE_BASE,
        ))
        .unwrap();
        let import_rva = consumer_image
            .imports
            .iter()
            .chain(&consumer_image.unsupported)
            .next()
            .unwrap()
            .iat_rva;
        let imported_address =
            unsafe { std::ptr::read_unaligned((consumer + import_rva as u64) as *const u64) };
        assert_eq!(
            imported_address,
            dependency + crate::pe::builder::SECTION_RVA as u64
        );
        native_free_library(consumer);
        assert_eq!(
            super::native_get_module_handle_a(dependency_name.as_ptr().cast()),
            0,
            "releasing the consumer releases its import dependency"
        );
        let mut native_fs = process.fs.lock().unwrap();
        native_fs.fs.delete_file(consumer_path).unwrap();
        native_fs.fs.delete_file(dependency_path).unwrap();
    }

    #[test]
    fn load_library_resolves_cyclic_guest_dll_imports() {
        let _isolation = super::NATIVE_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _process = super::context::TestProcessGuard::new();
        let process = &*super::process_ctx().unwrap();
        let path_a = r"C:\loader-tests\cycle-a.dll";
        let path_b = r"C:\loader-tests\cycle-b.dll";
        let image_a = dll_fixture(
            &[("cycle-b.dll", "CycleBEntry")],
            Some("CycleAEntry"),
            crate::pe::builder::IMAGE_BASE,
        );
        let image_b = dll_fixture(
            &[("cycle-a.dll", "CycleAEntry")],
            Some("CycleBEntry"),
            0x0000_5002_0000_0000,
        );
        {
            let mut native_fs = process.fs.lock().unwrap();
            native_fs.fs.mkdir(r"C:\loader-tests").unwrap();
            native_fs.fs.write_file(path_a, image_a.clone()).unwrap();
            native_fs.fs.write_file(path_b, image_b.clone()).unwrap();
        }

        let name_a: Vec<u16> = "cycle-a.dll".encode_utf16().chain(Some(0)).collect();
        let handle_a = native_load_library_ex_w(name_a.as_ptr(), 0, 0);
        assert_ne!(handle_a, 0, "first member of import cycle loads");
        let handle_b = native_get_module_handle_w(
            "cycle-b.dll"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>()
                .as_ptr(),
        );
        assert_ne!(handle_b, 0, "second member of import cycle loads");

        for (handle, bytes, expected) in
            [(handle_a, image_a, handle_b), (handle_b, image_b, handle_a)]
        {
            let image = crate::pe::load_lenient(&bytes).unwrap();
            let import = image
                .imports
                .iter()
                .chain(&image.unsupported)
                .next()
                .unwrap();
            let target = unsafe {
                std::ptr::read_unaligned((handle + u64::from(import.iat_rva)) as *const u64)
            };
            assert_eq!(target, expected + crate::pe::builder::SECTION_RVA as u64);
            let entry: unsafe extern "win64" fn() -> u32 = unsafe { std::mem::transmute(target) };
            assert_eq!(unsafe { entry() }, 1);
        }

        native_free_library(handle_a);
        native_free_library(handle_b);
        assert!(!process
            .loaded_modules
            .lock()
            .unwrap()
            .contains_key(&handle_a));
        assert!(!process
            .loaded_modules
            .lock()
            .unwrap()
            .contains_key(&handle_b));
        let mut native_fs = process.fs.lock().unwrap();
        native_fs.fs.delete_file(path_a).unwrap();
        native_fs.fs.delete_file(path_b).unwrap();
    }

    #[test]
    fn load_library_installs_static_tls_template_and_zero_fill() {
        let _isolation = super::NATIVE_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _process = super::context::TestProcessGuard::new();
        use crate::native::linux_x86_64::state::DynamicTlsSlots;
        use crate::native::linux_x86_64::state::NativeTls;

        let process = &*super::process_ctx().unwrap();
        let path = r"C:\loader-tests\static-tls.dll";
        let bytes = add_static_tls(
            dll_fixture(&[], None, 0x0000_5003_0000_0000),
            &[0x31, 0x42, 0x53],
            2,
        );
        let image = crate::pe::load_lenient(&bytes).unwrap();
        let tls_index_rva = image.tls.as_ref().unwrap().index_rva;
        let old_template = process
            .tls_template
            .lock()
            .unwrap()
            .as_ref()
            .map(NativeTls::clone_for_thread);
        let old_slots = {
            let slots = process.dynamic_tls.lock().unwrap();
            DynamicTlsSlots {
                active: slots.active.clone(),
                generation: slots.generation.clone(),
                reserved: slots.reserved.clone(),
                reserved_static: slots.reserved_static,
            }
        };
        let old_tls_blocks = process.tls_blocks.lock().unwrap().clone();
        let current_tls = Arc::new(Mutex::new(NativeTls::new(0x1400_0000)));
        let sibling_tls = Arc::new(Mutex::new(NativeTls::new(0x1400_0000)));
        assert!(super::thread_runtime::install_thread_teb(
            &mut current_tls.lock().unwrap().teb
        ));
        *process.tls_template.lock().unwrap() =
            Some(current_tls.lock().unwrap().clone_for_thread());
        *process.tls_blocks.lock().unwrap() = std::collections::HashMap::from([
            (0, Arc::downgrade(&current_tls)),
            (1, Arc::downgrade(&sibling_tls)),
        ]);
        *process.dynamic_tls.lock().unwrap() = DynamicTlsSlots::new(false);
        {
            let mut native_fs = process.fs.lock().unwrap();
            native_fs.fs.mkdir(r"C:\loader-tests").unwrap();
            native_fs.fs.write_file(path, bytes.clone()).unwrap();
        }

        let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let handle = native_load_library_ex_w(name.as_ptr(), 0, 0);
        assert_ne!(handle, 0, "TLS DLL loads");
        let assigned_index =
            unsafe { std::ptr::read_unaligned((handle + u64::from(tls_index_rva)) as *const u32) };
        assert_eq!(assigned_index, 0);
        let address = current_tls.lock().unwrap().slots[assigned_index as usize];
        let sibling_address = sibling_tls.lock().unwrap().slots[assigned_index as usize];
        assert_ne!(address, 0);
        assert_ne!(sibling_address, 0);
        assert_ne!(address, sibling_address);
        unsafe {
            assert_eq!(
                std::slice::from_raw_parts(address as *const u8, 5),
                [0x31, 0x42, 0x53, 0, 0]
            );
            assert_eq!(
                std::slice::from_raw_parts(sibling_address as *const u8, 5),
                [0x31, 0x42, 0x53, 0, 0]
            );
        }
        let next_thread = process
            .tls_template
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone_for_thread();
        assert_ne!(address, next_thread.slots[assigned_index as usize]);
        unsafe {
            assert_eq!(
                std::slice::from_raw_parts(
                    next_thread.slots[assigned_index as usize] as *const u8,
                    5
                ),
                [0x31, 0x42, 0x53, 0, 0]
            );
        }

        super::thread_runtime::clear_module_static_tls(process, assigned_index);
        assert_eq!(
            current_tls.lock().unwrap().slots[assigned_index as usize],
            0
        );
        assert_eq!(
            sibling_tls.lock().unwrap().slots[assigned_index as usize],
            0
        );
        assert_eq!(
            process.tls_template.lock().unwrap().as_ref().unwrap().slots[assigned_index as usize],
            0
        );

        process.loaded_modules.lock().unwrap().remove(&handle);
        process
            .tls_blocks
            .lock()
            .unwrap()
            .clone_from(&old_tls_blocks);
        *process.dynamic_tls.lock().unwrap() = old_slots;
        *process.tls_template.lock().unwrap() = old_template;
        process.fs.lock().unwrap().fs.delete_file(path).unwrap();
        super::context::THREAD_TEB_BASE.set(0);
        unsafe { super::thread_runtime::set_gs(0) };
    }
}

pub(super) fn protect_exec(mapping: &Mapping, image: &PeImage) -> Result<(), String> {
    if image.page_protections.len() != mapping.len / 4096 {
        return Err("native image has an invalid page protection table".to_string());
    }
    for (page, protection) in image.page_protections.iter().enumerate() {
        let host =
            super::memory::linux_protection(*protection).ok_or("invalid image page protection")?;
        if unsafe { mprotect(mapping.ptr.add(page * 4096).cast(), 4096, host) } != 0 {
            return Err(format!(
                "cannot apply image section protection: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

pub(super) extern "win64" fn native_get_module_handle_w(name: *const u16) -> u64 {
    if name.is_null() {
        process_ctx().map(|process| process.image_base).unwrap_or(0)
    } else {
        wide(name)
            .and_then(|name| module_handle_by_name(&name))
            .unwrap_or_else(|| {
                native_set_last_error(126);
                0
            })
    }
}
fn native_module_name_supported(name: &str) -> bool {
    let module = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    module.starts_with("api-ms-win-core-")
        || module.starts_with("api-ms-win-crt-")
        || module.starts_with("api-ms-win-security-")
        || module.starts_with("ext-ms-win-kernel32-")
        || module.starts_with("ext-ms-win-advapi32-")
        || matches!(
            module.as_str(),
            "kernel32"
                | "kernel32.dll"
                | "kernelbase"
                | "kernelbase.dll"
                | "ntdll"
                | "ntdll.dll"
                | "advapi32"
                | "advapi32.dll"
                | "bcryptprimitives"
                | "bcryptprimitives.dll"
                | "userenv"
                | "userenv.dll"
                | "winmm"
                | "winmm.dll"
                | "ws2_32"
                | "ws2_32.dll"
        )
}

/// Windows system DLLs beyond [`native_module_name_supported`]: imports
/// from them get winrun's shims or call-time stubs, and `LoadLibrary`
/// succeeds, but they are never loaded from the disk. `GetModuleHandle`
/// still reports them as not loaded, as on Windows for a console process
/// that has not loaded them.
fn native_system_module_name(name: &str) -> bool {
    let module = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    native_module_name_supported(name)
        || matches!(
            module.trim_end_matches(".dll"),
            "ole32"
                | "oleaut32"
                | "combase"
                | "user32"
                | "gdi32"
                | "shell32"
                | "shlwapi"
                | "bcrypt"
                | "crypt32"
                | "ncrypt"
                | "secur32"
                | "sspicli"
                | "version"
                | "psapi"
                | "dbghelp"
                | "iphlpapi"
                | "mswsock"
                | "netapi32"
                | "wintrust"
                | "powrprof"
                | "rpcrt4"
        )
}
pub(super) extern "win64" fn native_get_module_handle_ex_w(
    flags: u32,
    name: *const u16,
    output: *mut u64,
) -> i32 {
    if output.is_null() {
        native_set_last_error(87);
        return 0;
    }
    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
    let module = if flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 {
        if name.is_null() {
            return 0;
        }
        let address = name as u64;
        let Some(process) = process_ctx() else {
            return 0;
        };
        let modules = process.loaded_modules.lock().ok();
        modules
            .and_then(|modules| {
                modules.values().find_map(|module| {
                    let end = module.base.checked_add(module.size_of_image as u64)?;
                    (address >= module.base && address < end).then_some(module.base)
                })
            })
            .or_else(|| {
                let end = process.image_base.checked_add(process.image_size as u64)?;
                (address >= process.image_base && address < end).then_some(process.image_base)
            })
            .unwrap_or(0)
    } else if name.is_null() {
        process_ctx().map(|process| process.image_base).unwrap_or(0)
    } else {
        wide(name)
            .and_then(|name| module_handle_by_name(&name))
            .unwrap_or(0)
    };
    if module == 0 {
        native_set_last_error(126);
        return 0;
    }
    unsafe { output.write(module) };
    1
}

pub(super) unsafe fn ascii_z(ptr: *const u8) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while len < 128 && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    if len == 128 {
        return None;
    }
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(ptr, len) }).ok()
}

pub(super) extern "win64" fn native_load_library_ex_w(
    path: *const u16,
    _file: u64,
    flags: u32,
) -> u64 {
    let Some(path) = wide(path) else {
        native_set_last_error(126);
        return 0;
    };
    let module = load_guest_module(&path).unwrap_or_else(|| {
        native_set_last_error(126); // ERROR_MOD_NOT_FOUND
        0
    });
    if native_diagnostic_enabled() {
        eprintln!("native LoadLibraryExW path={path} flags={flags:#x} module={module:#x}");
    }
    module
}

pub(super) extern "win64" fn native_load_library_w(path: *const u16) -> u64 {
    native_load_library_ex_w(path, 0, 0)
}

pub(super) extern "win64" fn native_load_library_a(path: *const u8) -> u64 {
    native_load_library_ex_a(path, 0, 0)
}

pub(super) extern "win64" fn native_load_library_ex_a(
    path: *const u8,
    _file: u64,
    _flags: u32,
) -> u64 {
    let Some(path) = (unsafe { ascii_z(path) }) else {
        native_set_last_error(126);
        return 0;
    };
    load_guest_module(path).unwrap_or_else(|| {
        native_set_last_error(126);
        0
    })
}

/// `GetModuleHandleExA`: the W form with the name widened. With
/// `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS`, `name` is an address, not text.
pub(super) extern "win64" fn native_get_module_handle_ex_a(
    flags: u32,
    name: *const u8,
    output: *mut u64,
) -> i32 {
    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
    if name.is_null() || flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 {
        return native_get_module_handle_ex_w(flags, name.cast(), output);
    }
    let Some(text) = (unsafe { ascii_z(name) }) else {
        native_set_last_error(126); // ERROR_MOD_NOT_FOUND
        return 0;
    };
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    native_get_module_handle_ex_w(flags, wide.as_ptr(), output)
}

pub(super) extern "win64" fn native_get_module_handle_a(name: *const u8) -> u64 {
    match unsafe { ascii_z(name) } {
        Some(value) => module_handle_by_name(value).unwrap_or(0),
        _ => {
            native_set_last_error(126);
            0
        }
    }
}

fn module_handle_by_name(name: &str) -> Option<u64> {
    if native_module_name_supported(name) {
        return Some(API_SET_MODULE);
    }
    let process = process_ctx()?;
    if process.module_path.eq_ignore_ascii_case(name)
        || module_basename(&process.module_path).eq_ignore_ascii_case(name)
    {
        return Some(process.image_base);
    }
    let modules = process.loaded_modules.lock().ok()?;
    modules
        .values()
        .find(|module| {
            module.name.eq_ignore_ascii_case(name)
                || module.name.eq_ignore_ascii_case(&module_basename(name))
                || module.path.eq_ignore_ascii_case(name)
        })
        .map(|module| module.base)
}

fn module_basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn guest_module_path(name: &str) -> Option<(String, Vec<u8>)> {
    let process = process_ctx()?;
    let fs = process.fs.lock().ok()?;
    let path = locate_guest_module(&fs.fs, &process.module_path, name)?;
    let bytes = fs.fs.read_file(&path).ok()?;
    Some((path, bytes))
}

/// Windows searches the application directory first, so a DLL shipped
/// beside the EXE wins over a same-named copy elsewhere on the disk (for
/// example another installed version of the same package).
fn locate_guest_module(fs: &crate::winfs::WinFs, module_path: &str, name: &str) -> Option<String> {
    let suffixed = if name.rsplit(['\\', '/']).next()?.contains('.') {
        name.to_string()
    } else {
        format!("{name}.dll")
    };
    if !suffixed.contains(['\\', '/', ':']) {
        if let Some((directory, _)) = module_path.rsplit_once(['\\', '/']) {
            let beside = format!(r"{directory}\{suffixed}");
            if fs.is_file(&beside) {
                return Some(beside);
            }
        }
    }
    if fs.exists(&suffixed) {
        Some(suffixed)
    } else {
        fs.find_file_path_suffix(&format!("\\{}", module_basename(&suffixed)))
    }
}

#[cfg(test)]
mod guest_module_search_tests {
    use super::locate_guest_module;
    use crate::winfs::WinFs;

    #[test]
    fn application_directory_wins_over_other_copies_on_the_disk() {
        let mut fs = WinFs::ephemeral_runner();
        for version in ["24.0.0", "26.0.0"] {
            let directory = format!(r"C:\softwares\tool\{version}");
            fs.mkdir(&directory).unwrap();
            fs.write_file(&format!(r"{directory}\helper.dll"), version.into())
                .unwrap();
        }
        let found = locate_guest_module(&fs, r"C:\softwares\tool\26.0.0\tool.exe", "HELPER");
        assert_eq!(fs.read_file(&found.unwrap()).unwrap(), b"26.0.0");
        let found = locate_guest_module(&fs, r"C:\softwares\tool\24.0.0\tool.exe", "helper.dll");
        assert_eq!(fs.read_file(&found.unwrap()).unwrap(), b"24.0.0");
    }

    #[test]
    fn falls_back_to_a_disk_search_when_the_application_directory_lacks_it() {
        let mut fs = WinFs::ephemeral_runner();
        fs.mkdir(r"C:\libs").unwrap();
        fs.write_file(r"C:\libs\only.dll", b"x".to_vec()).unwrap();
        let found = locate_guest_module(&fs, r"C:\apps\tool.exe", "only.dll").unwrap();
        assert!(found.eq_ignore_ascii_case(r"C:\libs\only.dll"), "{found}");
        assert!(locate_guest_module(&fs, r"C:\apps\tool.exe", "missing.dll").is_none());
    }
}

fn load_guest_module(name: &str) -> Option<u64> {
    let outermost = GUEST_DLL_LOAD_DEPTH.with(|depth| {
        let current = depth.get();
        depth.set(current.saturating_add(1));
        current == 0
    });
    let result = load_guest_module_inner(name, &mut std::collections::HashSet::new(), 0);
    GUEST_DLL_LOAD_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    let module = result?;
    if module != API_SET_MODULE {
        let process = process_ctx()?;
        if outermost && !initialize_pending_modules(&process) {
            collect_unreferenced_modules(&process);
            return None;
        }
        if !retain_module_load_reference(module) {
            return None;
        }
    }
    Some(module)
}

fn retain_module_load_reference(module: u64) -> bool {
    let Some(process) = process_ctx() else {
        return false;
    };
    let Ok(mut modules) = process.loaded_modules.lock() else {
        return false;
    };
    let Some(module) = modules.get_mut(&module) else {
        return false;
    };
    let Some(references) = module.load_references.checked_add(1) else {
        return false;
    };
    module.load_references = references;
    true
}

fn module_initialization_order(modules: &HashMap<u64, NativeLoadedModule>) -> Vec<u64> {
    fn finish_order(
        module: u64,
        modules: &HashMap<u64, NativeLoadedModule>,
        pending: &std::collections::HashSet<u64>,
        seen: &mut std::collections::HashSet<u64>,
        finished: &mut Vec<u64>,
    ) {
        if !seen.insert(module) {
            return;
        }
        if let Some(loaded) = modules.get(&module) {
            for dependency in &loaded.dependencies {
                if pending.contains(dependency) {
                    finish_order(*dependency, modules, pending, seen, finished);
                }
            }
        }
        finished.push(module);
    }

    fn collect_component(
        module: u64,
        reverse: &HashMap<u64, Vec<u64>>,
        seen: &mut std::collections::HashSet<u64>,
        component: &mut Vec<u64>,
    ) {
        if !seen.insert(module) {
            return;
        }
        component.push(module);
        if let Some(importers) = reverse.get(&module) {
            for importer in importers {
                collect_component(*importer, reverse, seen, component);
            }
        }
    }

    fn visit_component(
        component: usize,
        component_dependencies: &[std::collections::HashSet<usize>],
        seen: &mut std::collections::HashSet<usize>,
        order: &mut Vec<usize>,
    ) {
        if !seen.insert(component) {
            return;
        }
        let mut dependencies: Vec<_> = component_dependencies[component].iter().copied().collect();
        dependencies.sort_unstable();
        for dependency in dependencies {
            visit_component(dependency, component_dependencies, seen, order);
        }
        order.push(component);
    }

    let pending: std::collections::HashSet<_> = modules
        .values()
        .filter(|module| !module.initialized)
        .map(|module| module.base)
        .collect();
    if pending.is_empty() {
        return Vec::new();
    }
    let mut nodes: Vec<_> = pending.iter().copied().collect();
    nodes.sort_by_key(|node| modules.get(node).map(|module| module.load_order));
    let mut finished = Vec::with_capacity(nodes.len());
    let mut seen = std::collections::HashSet::new();
    for node in &nodes {
        finish_order(*node, modules, &pending, &mut seen, &mut finished);
    }

    let mut reverse: HashMap<u64, Vec<u64>> = HashMap::new();
    for node in &nodes {
        if let Some(module) = modules.get(node) {
            for dependency in &module.dependencies {
                if pending.contains(dependency) {
                    reverse.entry(*dependency).or_default().push(*node);
                }
            }
        }
    }
    for importers in reverse.values_mut() {
        importers.sort_by_key(|node| modules.get(node).map(|module| module.load_order));
    }
    let mut components = Vec::new();
    seen.clear();
    for node in finished.into_iter().rev() {
        let mut component = Vec::new();
        collect_component(node, &reverse, &mut seen, &mut component);
        if !component.is_empty() {
            component.sort_by_key(|node| modules.get(node).map(|module| module.load_order));
            components.push(component);
        }
    }
    let component_by_module: HashMap<_, _> = components
        .iter()
        .enumerate()
        .flat_map(|(index, members)| members.iter().map(move |module| (*module, index)))
        .collect();
    let mut component_dependencies = vec![std::collections::HashSet::new(); components.len()];
    for (component_index, members) in components.iter().enumerate() {
        for member in members {
            if let Some(module) = modules.get(member) {
                for dependency in &module.dependencies {
                    if let Some(dependency_component) = component_by_module.get(dependency) {
                        if *dependency_component != component_index {
                            component_dependencies[component_index].insert(*dependency_component);
                        }
                    }
                }
            }
        }
    }
    let mut component_roots: Vec<_> = (0..components.len()).collect();
    component_roots.sort_by_key(|index| {
        components[*index]
            .first()
            .and_then(|module| modules.get(module))
            .map(|module| module.load_order)
    });
    let mut component_order = Vec::new();
    let mut seen_components = std::collections::HashSet::new();
    for component in component_roots {
        visit_component(
            component,
            &component_dependencies,
            &mut seen_components,
            &mut component_order,
        );
    }
    component_order
        .into_iter()
        .flat_map(|component| components[component].iter().copied())
        .collect()
}

fn initialize_pending_modules(process: &NativeProcessContext) -> bool {
    loop {
        let order = {
            let Ok(modules) = process.loaded_modules.lock() else {
                return false;
            };
            module_initialization_order(&modules)
        };
        if order.is_empty() {
            return true;
        }
        for base in order {
            let (callbacks, entry_point) = {
                let Ok(mut modules) = process.loaded_modules.lock() else {
                    return false;
                };
                let Some(module) = modules.get_mut(&base) else {
                    continue;
                };
                if module.initialized {
                    continue;
                }
                module.initialized = true;
                (module.tls_callbacks.clone(), module.entry_point)
            };
            super::thread_runtime::invoke_tls_callbacks(base, &callbacks, 1);
            if let Some(entry_point) = entry_point {
                // SAFETY: the PE entry point was range-checked before module
                // publication and the mapping remains owned by its record.
                let dll_main: unsafe extern "win64" fn(u64, u32, u64) -> i32 =
                    unsafe { std::mem::transmute(entry_point as usize) };
                if unsafe { dll_main(base, 1, 0) } == 0 {
                    if let Ok(mut modules) = process.loaded_modules.lock() {
                        if let Some(module) = modules.get_mut(&base) {
                            module.initialized = false;
                        }
                    }
                    super::thread_runtime::invoke_tls_callbacks(base, &callbacks, 0);
                    return false;
                }
            }
        }
    }
}

fn load_guest_module_inner(
    name: &str,
    loading: &mut std::collections::HashSet<String>,
    depth: usize,
) -> Option<u64> {
    if depth >= 64 {
        return None;
    }
    if native_system_module_name(name) {
        return Some(API_SET_MODULE);
    }
    if let Some(handle) = module_handle_by_name(name) {
        return Some(handle);
    }
    let (path, bytes) = guest_module_path(name)?;
    let key = path.to_uppercase();
    if !loading.insert(key.clone()) {
        return process_ctx()?
            .loaded_modules
            .lock()
            .ok()?
            .values()
            .find(|module| {
                module.path.eq_ignore_ascii_case(&path)
                    || module.name.eq_ignore_ascii_case(&module_basename(&path))
            })
            .map(|module| module.base);
    }
    let mut provisional_module = None;
    let mut dependencies = Vec::new();
    let result = (|| {
        // IL-only assemblies load even when they are EXE images (as .NET
        // app assemblies are): they have no entry point to run.
        let (image, il_only) = match crate::pe::load_il_only(&bytes) {
            Ok(image) => (image, true),
            Err(_) => (crate::pe::load_lenient(&bytes).ok()?, false),
        };
        if !image.is_dll && !il_only {
            return None;
        }
        let tls_callbacks = image
            .tls
            .as_ref()
            .map(|tls| tls.callbacks.clone())
            .unwrap_or_default();
        let tls_index_rva = image.tls.as_ref().map(|tls| tls.index_rva);

        let (mapping, image) = if il_only {
            map_il_only(&image).ok()?
        } else {
            match map_relocated(&image) {
                Ok(mapped) => mapped,
                Err(_) if image.relocations.is_empty() => (map(&image).ok()?, image),
                Err(_) => return None,
            }
        };
        let base = mapping.ptr as u64;
        let static_tls_template = match image.tls.as_ref() {
            Some(tls) => Some(super::thread_runtime::tls_template_from_mapping(
                &mapping, tls,
            )?),
            None => None,
        };
        let process = process_ctx()?;
        let tls_index = if tls_index_rva.is_some() {
            Some(super::thread_runtime::reserve_module_tls_slot(&process)?)
        } else {
            None
        };
        if let (Some(index_rva), Some(index)) = (tls_index_rva, tls_index) {
            let offset = index_rva as usize;
            if offset.checked_add(4)? > mapping.len {
                super::thread_runtime::release_module_tls_slot(&process, index);
                return None;
            }
            // SAFETY: the parsed TLS directory supplies a checked index RVA.
            unsafe { ptr::write_unaligned(mapping.ptr.add(offset).cast::<u32>(), index) };
        }
        let module = NativeLoadedModule {
            path: path.clone(),
            name: module_basename(&path),
            base,
            size_of_image: image.size_of_image,
            exports: image.exports.clone(),
            entry_point: (image.entry_rva != 0)
                .then(|| base.checked_add(u64::from(image.entry_rva)))
                .flatten(),
            tls_callbacks: tls_callbacks.clone(),
            static_tls_index: tls_index,
            static_tls_template: static_tls_template.clone(),
            load_order: process.module_next.fetch_add(1, Ordering::AcqRel),
            load_references: 0,
            dependencies: Vec::new(),
            mapping: None,
            initialized: false,
        };
        let handle = module.base;
        if !image.page_protections.is_empty() {
            if let Ok(mut pages) = process.image_page_protections.lock() {
                pages.insert(base, image.page_protections.clone());
            }
        }
        if native_diagnostic_enabled() {
            eprintln!(
                "native LoadLibrary mapped path={} base={:#x} size={:#x}",
                module.path, module.base, module.size_of_image
            );
        }
        {
            let mut modules = process.loaded_modules.lock().ok()?;
            if let Some(existing) = modules.values().find(|loaded| {
                loaded.path.eq_ignore_ascii_case(&path)
                    || loaded.name.eq_ignore_ascii_case(&module.name)
            }) {
                if let Some(index) = tls_index {
                    super::thread_runtime::release_module_tls_slot(&process, index);
                }
                return Some(existing.base);
            }
            modules.insert(handle, module);
        }
        provisional_module = Some((handle, tls_index));

        let mut shim_imports = Vec::new();
        let mut guest_imports = Vec::new();
        for import in image.imports.iter().chain(&image.unsupported) {
            // System-module imports go to the shim table; one without a shim
            // gets a stub that reports it only if called, as for the main
            // image, so a DLL still loads when unused imports are missing.
            if super::registry::supports_import(&import.dll, &import.func)
                || native_system_module_name(&import.dll)
            {
                shim_imports.push(import.clone());
                continue;
            }
            let dependency = load_guest_module_inner(&import.dll, loading, depth + 1)?;
            if dependency == API_SET_MODULE {
                return None;
            }
            if !dependencies.contains(&dependency) {
                dependencies.push(dependency);
            }
            let target = resolve_module_export(dependency, &import.func, 0)?;
            guest_imports.push((import.iat_rva, target));
        }

        let mut shim_image = image.clone();
        shim_image.imports = shim_imports;
        shim_image.unsupported.clear();
        let stubs = super::registry::patch_baseline_imports(&mapping, &shim_image, false).ok()?;
        for (iat_rva, target) in guest_imports {
            let offset = iat_rva as usize;
            if offset.checked_add(8)? > mapping.len {
                return None;
            }
            // SAFETY: the PE import parser supplied an RVA and the range was
            // checked against this module's mapped image above.
            unsafe {
                ptr::write_unaligned(mapping.ptr.add(offset).cast::<u64>(), target);
            }
        }
        if let (Some(index), Some(template)) = (tls_index, static_tls_template.as_ref()) {
            if !super::thread_runtime::install_module_static_tls(&process, index, template) {
                return None;
            }
        }
        protect_exec(&mapping, &image).ok()?;
        {
            let mut modules = process.loaded_modules.lock().ok()?;
            let loaded = modules.get_mut(&handle)?;
            loaded.dependencies = dependencies.clone();
            loaded.mapping = Some(mapping);
        }
        if let Some(stubs) = stubs {
            std::mem::forget(stubs);
        }
        provisional_module = None;
        Some(handle)
    })();
    if let Some((handle, tls_index)) = provisional_module {
        if let Some(process) = process_ctx() {
            if let Ok(mut modules) = process.loaded_modules.lock() {
                modules.remove(&handle);
            }
            if let Some(index) = tls_index {
                super::thread_runtime::clear_module_static_tls(&process, index);
                super::thread_runtime::release_module_tls_slot(&process, index);
            }
        }
    }
    loading.remove(&key);
    result
}

pub(super) extern "win64" fn native_get_proc_address(module: u64, name: *const u8) -> u64 {
    if name.is_null() {
        native_set_last_error(127);
        return 0;
    }
    let selector = if (name as usize) <= u16::MAX as usize {
        format!("#{}", name as usize)
    } else if let Some(name) = unsafe { ascii_z(name) } {
        name.to_string()
    } else {
        native_set_last_error(127);
        return 0;
    };
    if module != API_SET_MODULE {
        return resolve_module_export(module, &selector, 0).unwrap_or_else(|| {
            native_set_last_error(127); // ERROR_PROC_NOT_FOUND
            0
        });
    }
    match selector
        .strip_prefix('#')
        .is_none()
        .then_some(selector.as_str())
    {
        Some("CompareStringEx") => native_compare_string_ex as *const () as usize as u64,
        Some("CompareStringOrdinal") => native_compare_string_ordinal as *const () as usize as u64,
        Some("GetEnvironmentVariableW") => {
            native_get_environment_variable_w as *const () as usize as u64
        }
        Some("GetEnvironmentVariableA") => {
            native_get_environment_variable_a as *const () as usize as u64
        }
        Some("GetCurrentDirectoryW") => native_get_current_directory_w as *const () as usize as u64,
        Some("NtDeviceIoControlFile") => {
            native_nt_device_io_control_file as *const () as usize as u64
        }
        Some("NtQueryInformationFile") => {
            native_nt_query_information_file as *const () as usize as u64
        }
        Some("NtSetInformationFile") => native_nt_set_information_file as *const () as usize as u64,
        Some("NtQueryVolumeInformationFile") => {
            native_nt_query_volume_information_file as *const () as usize as u64
        }
        Some("NtQueryDirectoryFile") => native_nt_query_directory_file as *const () as usize as u64,
        Some("NtQuerySystemInformation") => {
            native_nt_query_system_information as *const () as usize as u64
        }
        Some("NtQueryInformationProcess") => {
            native_nt_query_information_process as *const () as usize as u64
        }
        Some(function) => baseline_trampoline(function).unwrap_or_else(|| {
            if native_diagnostic_enabled() {
                let message = format!("unsupported native dynamic import: {function}\n");
                unsafe { write(2, message.as_ptr().cast(), message.len()) };
            }
            native_set_last_error(127); // ERROR_PROC_NOT_FOUND
            0
        }),
        None => {
            native_set_last_error(127);
            0
        }
    }
}

fn resolve_module_export(module: u64, selector: &str, depth: usize) -> Option<u64> {
    if depth >= 16 {
        return None;
    }
    let process = process_ctx()?;
    let (base, export) = {
        let modules = process.loaded_modules.lock().ok()?;
        let loaded = modules.get(&module)?;
        let export = if let Some(ordinal) = selector.strip_prefix('#') {
            let ordinal = ordinal.parse::<u32>().ok()?;
            loaded
                .exports
                .iter()
                .find(|export| export.ordinal == ordinal)?
        } else {
            loaded
                .exports
                .iter()
                .find(|export| export.name.as_deref() == Some(selector))?
        };
        (loaded.base, export.clone())
    };
    if let Some(forwarder) = export.forwarder {
        let (dll, function) = forwarder.rsplit_once('.')?;
        let forwarded_module = module_handle_by_name(dll).or_else(|| load_guest_module(dll))?;
        if forwarded_module == API_SET_MODULE {
            let function = std::ffi::CString::new(function).ok()?;
            let address = native_get_proc_address(forwarded_module, function.as_ptr().cast());
            return (address != 0).then_some(address);
        }
        return resolve_module_export(forwarded_module, function, depth + 1);
    }
    base.checked_add(export.target_rva as u64)
}

// libuv resolves this NTDLL entry during startup. Until a device-I/O
// translation exists, return a real NT failure code to callers instead
// of pretending that the operation succeeded.
pub(super) extern "win64" fn native_free_library(module: u64) -> i32 {
    if module == API_SET_MODULE {
        return 1;
    }
    let Some(process) = process_ctx() else {
        return 0;
    };
    {
        let Ok(mut modules) = process.loaded_modules.lock() else {
            return 0;
        };
        let Some(loaded) = modules.get_mut(&module) else {
            return 0;
        };
        if loaded.load_references == 0 {
            return 0;
        }
        loaded.load_references -= 1;
    }
    collect_unreferenced_modules(&process);
    1
}

fn collect_unreferenced_modules(process: &NativeProcessContext) {
    let removed = {
        let Ok(mut modules) = process.loaded_modules.lock() else {
            return;
        };
        let mut reachable: std::collections::HashSet<u64> = modules
            .values()
            .filter(|module| module.load_references != 0 || module.base == process.image_base)
            .map(|module| module.base)
            .collect();
        let mut pending: Vec<u64> = reachable.iter().copied().collect();
        while let Some(module) = pending.pop() {
            if let Some(module) = modules.get(&module) {
                for dependency in &module.dependencies {
                    if reachable.insert(*dependency) {
                        pending.push(*dependency);
                    }
                }
            }
        }
        let unreferenced: Vec<_> = modules
            .keys()
            .copied()
            .filter(|module| !reachable.contains(module))
            .collect();
        let mut unreferenced = unreferenced
            .into_iter()
            .filter_map(|module| modules.remove(&module))
            .collect::<Vec<_>>();
        unreferenced.sort_by_key(|module| module.load_order);
        unreferenced
    };
    for module in removed {
        dispose_loaded_module(process, module);
    }
}

fn dispose_loaded_module(process: &NativeProcessContext, loaded: NativeLoadedModule) {
    if loaded.initialized {
        if let Some(entry_point) = loaded.entry_point {
            // SAFETY: the entry point was validated against the mapped PE
            // image before it was published to the loader table.
            let dll_main: unsafe extern "win64" fn(u64, u32, u64) -> i32 =
                unsafe { std::mem::transmute(entry_point as usize) };
            let _ = unsafe { dll_main(loaded.base, 0, 0) };
        }
        super::thread_runtime::invoke_tls_callbacks(loaded.base, &loaded.tls_callbacks, 0);
    }
    if let Some(index) = loaded.static_tls_index {
        super::thread_runtime::clear_module_static_tls(process, index);
        super::thread_runtime::release_module_tls_slot(process, index);
    }
    if let Ok(mut image_pages) = process.image_page_protections.lock() {
        image_pages.remove(&loaded.base);
    }
    drop(loaded);
}

pub(super) struct Mapping {
    pub(super) ptr: *mut u8,
    pub(super) len: usize,
}

// A mapping is owned by one loader record and can be moved between host
// threads. Guest access uses the mapped address directly, not Rust references.
unsafe impl Send for Mapping {}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `len` come from a successful mmap in `map`.
        unsafe { munmap(self.ptr.cast(), self.len) };
    }
}
