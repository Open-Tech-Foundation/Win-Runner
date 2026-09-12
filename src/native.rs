//! Native x86-64 PE execution backend.
//!
//! This is deliberately a small first step toward a Wine-style execution
//! path.  On an x86-64 Linux host, instructions in a PE32+ image do not need
//! interpretation: they can run directly on the processor once the image is
//! mapped at its preferred base.  What still needs building is the Windows
//! personality around that code (DLL loading, import trampolines, TEB/PEB,
//! exceptions, threads, and isolation).
//!
//! The first bridge supports the three APIs used by `rust_hello.exe`:
//! `GetStdHandle`, `WriteFile`, and `ExitProcess`.  Other images deliberately
//! remain on the interpreter until their imports have real trampolines. It is
//! intentionally opt-in and is not used by the normal CLI execution path.

use crate::pe::PeImage;

/// True when this build can execute the initial native backend.
pub const AVAILABLE: bool = cfg!(all(target_os = "linux", target_arch = "x86_64"));

/// Run an import-free PE entry point directly on the host CPU.
///
/// This is unsuitable for arbitrary or untrusted binaries: native guest code
/// runs in the current process until the planned child-process sandbox exists.
/// It is exposed now for bring-up fixtures and backend development only.
pub fn run_import_free(img: &PeImage) -> Result<u32, String> {
    imp::run_import_free(img)
}

/// Run the initial native Rust-guest baseline in a child process.
///
/// The supported imports are exactly `GetStdHandle`, `WriteFile`, and
/// `ExitProcess`. Guest stdout is captured and returned. The child boundary
/// makes `ExitProcess` safe and is the beginning of the native backend's
/// isolation model.
pub fn run_rust_baseline(img: &PeImage) -> Result<(u32, Vec<u8>), String> {
    imp::run_rust_baseline(img)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use super::PeImage;
    use std::ffi::c_void;
    use std::ptr;

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const PROT_EXEC: i32 = 0x4;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANONYMOUS: i32 = 0x20;
    // Linux-specific. Unlike MAP_FIXED, this never replaces an existing map.
    const MAP_FIXED_NOREPLACE: i32 = 0x100000;
    const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;

    unsafe extern "C" {
        fn mmap(
            addr: *mut c_void,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: isize,
        ) -> *mut c_void;
        fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
        fn munmap(addr: *mut c_void, len: usize) -> i32;
        fn pipe(fds: *mut i32) -> i32;
        fn fork() -> i32;
        fn dup2(oldfd: i32, newfd: i32) -> i32;
        fn close(fd: i32) -> i32;
        fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
        fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(status: i32) -> !;
    }

    struct Mapping {
        ptr: *mut u8,
        len: usize,
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: `ptr` and `len` come from a successful mmap in `map`.
            unsafe { munmap(self.ptr.cast(), self.len) };
        }
    }

    fn page_len(len: usize) -> Result<usize, String> {
        len.checked_add(4095)
            .map(|n| n & !4095)
            .ok_or_else(|| "native image size overflows page rounding".to_string())
    }

    fn map(img: &PeImage) -> Result<Mapping, String> {
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

    fn protect_exec(mapping: &Mapping) -> Result<(), String> {
        // First native milestone uses an RX image. Writable PE sections need
        // per-section protections, which arrive with the full PE mapper.
        if unsafe { mprotect(mapping.ptr.cast(), mapping.len, PROT_READ | PROT_EXEC) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(format!(
                "native backend could not mark image executable: {e}"
            ));
        }
        Ok(())
    }

    pub(super) fn run_import_free(img: &PeImage) -> Result<u32, String> {
        if !img.imports.is_empty() || !img.stubs.is_empty() {
            return Err(
                "native backend does not yet support PE imports; use the interpreter backend"
                    .to_string(),
            );
        }
        if img.tls.is_some() {
            return Err(
                "native backend does not yet set up TLS; use the interpreter backend".to_string(),
            );
        }
        let entry = img
            .image_base
            .checked_add(img.entry_rva as u64)
            .ok_or_else(|| "native entry address overflows".to_string())?;
        let image_end = img.image_base + img.image.len() as u64;
        if entry < img.image_base || entry >= image_end {
            return Err("native entry point lies outside the loaded image".to_string());
        }
        let mapping = map(img)?;
        protect_exec(&mapping)?;
        // SAFETY: `entry` lies in the RX mapping just created. The caller is
        // limited to bring-up PE fixtures that implement this ABI and return;
        // arbitrary Windows entry points require the planned process sandbox.
        let entry_fn: unsafe extern "win64" fn() -> u32 = unsafe { std::mem::transmute(entry) };
        Ok(unsafe { entry_fn() })
    }

    const RUST_BASELINE: &[&str] = &["ExitProcess", "GetStdHandle", "WriteFile"];

    extern "win64" fn native_get_std_handle(which: u32) -> u64 {
        match which as i32 {
            -10 => 0,
            -11 => 1,
            -12 => 2,
            _ => u64::MAX,
        }
    }

    extern "win64" fn native_write_file(
        handle: u64,
        buf: *const u8,
        len: u32,
        written: *mut u32,
        _overlapped: u64,
    ) -> i32 {
        if handle != 1 && handle != 2 || buf.is_null() {
            return 0;
        }
        // SAFETY: the guest supplied `buf`/`len`; a bad pointer terminates
        // only its isolated native child, never the parent runtime.
        let n = unsafe { write(handle as i32, buf.cast(), len as usize) };
        if n < 0 {
            return 0;
        }
        if !written.is_null() {
            // SAFETY: same child-process containment as the input pointer.
            unsafe { written.write(n as u32) };
        }
        1
    }

    extern "win64" fn native_exit_process(code: u32) -> ! {
        // SAFETY: this runs only in the forked guest child.
        unsafe { _exit(code as i32) }
    }

    fn baseline_trampoline(name: &str) -> Option<u64> {
        match name {
            "GetStdHandle" => Some(native_get_std_handle as *const () as usize as u64),
            "WriteFile" => Some(native_write_file as *const () as usize as u64),
            "ExitProcess" => Some(native_exit_process as *const () as usize as u64),
            _ => None,
        }
    }

    fn patch_baseline_imports(mapping: &Mapping, img: &PeImage) -> Result<(), String> {
        for import in &img.imports {
            if !import.dll.eq_ignore_ascii_case("KERNEL32.DLL")
                || !RUST_BASELINE.contains(&import.func.as_str())
            {
                return Err(format!(
                    "native Rust baseline lacks trampoline for {}!{}",
                    import.dll, import.func
                ));
            }
            let value = baseline_trampoline(&import.func).expect("baseline name checked");
            let off = import.iat_rva as usize;
            if off.checked_add(8).is_none_or(|end| end > mapping.len) {
                return Err(format!(
                    "native IAT slot out of range: {}!{}",
                    import.dll, import.func
                ));
            }
            // SAFETY: the mapping is still RW and the checked IAT slot is in it.
            unsafe { (mapping.ptr.add(off) as *mut u64).write_unaligned(value) };
        }
        Ok(())
    }

    fn entry(img: &PeImage) -> Result<u64, String> {
        let entry = img
            .image_base
            .checked_add(img.entry_rva as u64)
            .ok_or_else(|| "native entry address overflows".to_string())?;
        if entry < img.image_base || entry >= img.image_base + img.image.len() as u64 {
            return Err("native entry point lies outside the loaded image".to_string());
        }
        Ok(entry)
    }

    pub(super) fn run_rust_baseline(img: &PeImage) -> Result<(u32, Vec<u8>), String> {
        if img.tls.is_some() || !img.stubs.is_empty() {
            return Err(
                "native Rust baseline does not yet support TLS or stub imports".to_string(),
            );
        }
        let entry = entry(img)?;
        let mapping = map(img)?;
        patch_baseline_imports(&mapping, img)?;
        let mut fds = [-1, -1];
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            return Err(format!(
                "native backend could not create stdout pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let pid = unsafe { fork() };
        if pid < 0 {
            unsafe {
                close(fds[0]);
                close(fds[1]);
            }
            return Err(format!(
                "native backend could not fork guest: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            unsafe {
                close(fds[0]);
                if dup2(fds[1], 1) < 0 {
                    _exit(127);
                }
                close(fds[1]);
            }
            if protect_exec(&mapping).is_err() {
                unsafe { _exit(127) };
            }
            // SAFETY: the entry is in the child-owned RX PE mapping. Its
            // imported ExitProcess trampoline terminates this child.
            let guest: unsafe extern "win64" fn() -> u32 = unsafe { std::mem::transmute(entry) };
            let code = unsafe { guest() };
            unsafe { _exit(code as i32) };
        }
        unsafe {
            close(fds[1]);
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                break;
            }
            if n < 0 {
                unsafe {
                    close(fds[0]);
                }
                return Err(format!(
                    "native backend could not read guest stdout: {}",
                    std::io::Error::last_os_error()
                ));
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        unsafe {
            close(fds[0]);
        }
        let mut status = 0;
        if unsafe { waitpid(pid, &mut status, 0) } != pid {
            return Err(format!(
                "native backend could not reap guest: {}",
                std::io::Error::last_os_error()
            ));
        }
        if status & 0x7f != 0 {
            return Err(format!(
                "native guest terminated by signal {}",
                status & 0x7f
            ));
        }
        Ok(((status >> 8) as u32, out))
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    use super::PeImage;

    pub(super) fn run_import_free(_: &PeImage) -> Result<u32, String> {
        Err("native backend is available only on Linux x86_64".to_string())
    }

    pub(super) fn run_rust_baseline(_: &PeImage) -> Result<(u32, Vec<u8>), String> {
        Err("native backend is available only on Linux x86_64".to_string())
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::pe::{
        builder::{build, Asm},
        load,
    };

    #[test]
    fn executes_an_import_free_pe_at_native_speed() {
        let mut asm = Asm::new();
        asm.mov_r32_imm(0, 37);
        asm.ret();
        let img = load(&build(asm, &[])).expect("fixture PE loads");
        assert_eq!(run_import_free(&img).expect("native PE runs"), 37);
    }

    #[test]
    fn imports_remain_on_the_interpreter_until_trampolines_exist() {
        let mut asm = Asm::new();
        asm.ret();
        let img = load(&build(asm, &[("KERNEL32.DLL", "ExitProcess")])).expect("fixture PE loads");
        let err = run_import_free(&img).expect_err("imports need shims");
        assert!(err.contains("does not yet support PE imports"));
    }

    #[test]
    fn executes_the_checked_in_rust_hello_guest_with_native_trampolines() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_hello.exe"
        );
        let bytes = std::fs::read(path).expect("checked-in guest exists");
        let img = load(&bytes).expect("rust hello loads");
        let (code, out) = run_rust_baseline(&img).expect("native rust hello runs");
        assert_eq!(code, 0);
        assert_eq!(out, b"Hello from Rust");
    }
}
