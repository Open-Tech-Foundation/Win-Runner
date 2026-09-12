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
    run_rust_baseline_argv(img, "<exe>", &[])
}

/// Same as [`run_rust_baseline`], with the Windows command line supplied to
/// guests importing `GetCommandLineW`.
pub fn run_rust_baseline_argv(
    img: &PeImage,
    prog: &str,
    args: &[String],
) -> Result<(u32, Vec<u8>), String> {
    imp::run_rust_baseline_argv(img, prog, args)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use super::PeImage;
    use crate::winfs::WinFs;
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const PROT_EXEC: i32 = 0x4;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANONYMOUS: i32 = 0x20;
    // Linux-specific. Unlike MAP_FIXED, this never replaces an existing map.
    const MAP_FIXED_NOREPLACE: i32 = 0x100000;
    const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;

    // Preferred-base PE mappings collide by design. Serialize native runs in
    // this process until relocations allow separate address-space layouts.
    static NATIVE_RUN_LOCK: Mutex<()> = Mutex::new(());

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
        fn malloc(size: usize) -> *mut c_void;
        fn free(ptr: *mut c_void);
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
        let _run = NATIVE_RUN_LOCK
            .lock()
            .map_err(|_| "native backend execution lock is poisoned".to_string())?;
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

    const RUST_BASELINE: &[&str] = &[
        "ExitProcess",
        "CloseHandle",
        "CopyFileW",
        "CreateDirectoryW",
        "CreateFileW",
        "DeleteFileW",
        "GetCommandLineW",
        "GetProcessHeap",
        "GetStdHandle",
        "HeapAlloc",
        "HeapFree",
        "MoveFileW",
        "ReadFile",
        "RemoveDirectoryW",
        "WriteFile",
    ];

    // The command-line buffer is owned by the parent until it reaps the
    // native guest. The child inherits it on fork, so the guest receives a
    // normal process-valid UTF-16 pointer. Native runs are CLI-process local;
    // broader concurrent execution will replace this bootstrap slot with a
    // per-process shim context.
    static COMMAND_LINE_W: AtomicU64 = AtomicU64::new(0);
    static NATIVE_FS: AtomicU64 = AtomicU64::new(0);

    struct NativeFile {
        path: String,
        offset: usize,
    }
    struct NativeFs {
        fs: WinFs,
        handles: HashMap<u64, NativeFile>,
        next: u64,
    }

    fn wide(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut units = Vec::new();
        for i in 0..32768 {
            let u = unsafe { ptr.add(i).read() };
            if u == 0 {
                return String::from_utf16(&units).ok();
            }
            units.push(u);
        }
        None
    }
    unsafe fn fs_ctx() -> Option<&'static mut NativeFs> {
        (NATIVE_FS.load(Ordering::Acquire) as *mut NativeFs).as_mut()
    }

    extern "win64" fn native_get_command_line_w() -> u64 {
        COMMAND_LINE_W.load(Ordering::Acquire)
    }

    extern "win64" fn native_get_std_handle(which: u32) -> u64 {
        match which as i32 {
            -10 => 0,
            -11 => 1,
            -12 => 2,
            _ => u64::MAX,
        }
    }

    extern "win64" fn native_get_process_heap() -> u64 {
        0x400
    }
    extern "win64" fn native_heap_alloc(_heap: u64, _flags: u32, size: u32) -> u64 {
        let size = (size as usize).max(1);
        unsafe { malloc(size).cast::<u8>() as u64 }
    }
    extern "win64" fn native_heap_free(_heap: u64, _flags: u32, ptr: u64) -> i32 {
        if ptr == 0 {
            return 0;
        }
        unsafe {
            free(ptr as *mut c_void);
        }
        1
    }

    extern "win64" fn native_write_file(
        handle: u64,
        buf: *const u8,
        len: u32,
        written: *mut u32,
        _overlapped: u64,
    ) -> i32 {
        if buf.is_null() || len > 16 * 1024 * 1024 {
            return 0;
        }
        if handle != 1 && handle != 2 {
            let ctx = match unsafe { fs_ctx() } {
                Some(v) => v,
                None => return 0,
            };
            let file = match ctx.handles.get_mut(&handle) {
                Some(v) => v,
                None => return 0,
            };
            let data = unsafe { std::slice::from_raw_parts(buf, len as usize) };
            let mut content = match ctx.fs.read_file(&file.path) {
                Ok(v) => v,
                Err(_) => return 0,
            };
            let end = match file.offset.checked_add(data.len()) {
                Some(v) => v,
                None => return 0,
            };
            if content.len() < end {
                content.resize(end, 0);
            }
            content[file.offset..end].copy_from_slice(data);
            if ctx.fs.write_file(&file.path, content).is_err() {
                return 0;
            }
            file.offset = end;
            if !written.is_null() {
                unsafe { written.write(len) };
            }
            return 1;
        }
        if buf.is_null() {
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

    extern "win64" fn native_create_file_w(
        path: *const u16,
        access: u32,
        _share: u32,
        _sec: u64,
        creation: u32,
        _flags: u32,
        _tmpl: u64,
    ) -> u64 {
        let path = match wide(path) {
            Some(v) => v,
            None => return u64::MAX,
        };
        let ctx = match unsafe { fs_ctx() } {
            Some(v) => v,
            None => return u64::MAX,
        };
        let exists = ctx.fs.exists(&path);
        let ok = match creation {
            2 => ctx.fs.write_file(&path, Vec::new()),
            3 if exists && ctx.fs.is_file(&path) => Ok(()),
            _ => Err("unsupported create".into()),
        };
        if ok.is_err() || (access & 0xC000_0000) == 0 {
            return u64::MAX;
        }
        let h = ctx.next;
        ctx.next += 1;
        ctx.handles.insert(h, NativeFile { path, offset: 0 });
        h
    }
    extern "win64" fn native_read_file(
        h: u64,
        buf: *mut u8,
        n: u32,
        read: *mut u32,
        _ov: u64,
    ) -> i32 {
        if buf.is_null() {
            return 0;
        }
        let ctx = match unsafe { fs_ctx() } {
            Some(v) => v,
            None => return 0,
        };
        let file = match ctx.handles.get_mut(&h) {
            Some(v) => v,
            None => return 0,
        };
        let data = match ctx.fs.read_file(&file.path) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let k = (data.len().saturating_sub(file.offset)).min(n as usize);
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr().add(file.offset), buf, k) };
        file.offset += k;
        if !read.is_null() {
            unsafe { read.write(k as u32) };
        }
        1
    }
    extern "win64" fn native_close_handle(h: u64) -> i32 {
        unsafe {
            fs_ctx()
                .map(|c| c.handles.remove(&h).is_some())
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_create_directory_w(p: *const u16, _s: u64) -> i32 {
        unsafe {
            fs_ctx()
                .and_then(|c| wide(p).map(|p| c.fs.mkdir_one(&p).is_ok()))
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_remove_directory_w(p: *const u16) -> i32 {
        unsafe {
            fs_ctx()
                .and_then(|c| wide(p).map(|p| c.fs.rmdir(&p).is_ok()))
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_delete_file_w(p: *const u16) -> i32 {
        unsafe {
            fs_ctx()
                .and_then(|c| wide(p).map(|p| c.fs.delete_file(&p).is_ok()))
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_move_file_w(a: *const u16, b: *const u16) -> i32 {
        let (a, b) = match (wide(a), wide(b)) {
            (Some(a), Some(b)) => (a, b),
            _ => return 0,
        };
        unsafe {
            fs_ctx()
                .map(|c| c.fs.move_path(&a, &b).is_ok())
                .unwrap_or(false) as i32
        }
    }
    extern "win64" fn native_copy_file_w(a: *const u16, b: *const u16, fail: i32) -> i32 {
        let (a, b) = match (wide(a), wide(b)) {
            (Some(a), Some(b)) => (a, b),
            _ => return 0,
        };
        unsafe {
            fs_ctx()
                .map(|c| c.fs.copy_file(&a, &b, fail != 0).is_ok())
                .unwrap_or(false) as i32
        }
    }

    fn baseline_trampoline(name: &str) -> Option<u64> {
        match name {
            "GetCommandLineW" => Some(native_get_command_line_w as *const () as usize as u64),
            "GetProcessHeap" => Some(native_get_process_heap as *const () as usize as u64),
            "GetStdHandle" => Some(native_get_std_handle as *const () as usize as u64),
            "HeapAlloc" => Some(native_heap_alloc as *const () as usize as u64),
            "HeapFree" => Some(native_heap_free as *const () as usize as u64),
            "WriteFile" => Some(native_write_file as *const () as usize as u64),
            "ExitProcess" => Some(native_exit_process as *const () as usize as u64),
            "CreateFileW" => Some(native_create_file_w as *const () as usize as u64),
            "ReadFile" => Some(native_read_file as *const () as usize as u64),
            "CloseHandle" => Some(native_close_handle as *const () as usize as u64),
            "CreateDirectoryW" => Some(native_create_directory_w as *const () as usize as u64),
            "RemoveDirectoryW" => Some(native_remove_directory_w as *const () as usize as u64),
            "DeleteFileW" => Some(native_delete_file_w as *const () as usize as u64),
            "MoveFileW" => Some(native_move_file_w as *const () as usize as u64),
            "CopyFileW" => Some(native_copy_file_w as *const () as usize as u64),
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

    fn command_line_w(prog: &str, args: &[String]) -> Result<Vec<u16>, String> {
        let mut line = crate::pe::emu::quote_arg(prog);
        for arg in args {
            line.push(' ');
            line.push_str(&crate::pe::emu::quote_arg(arg));
        }
        let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
        if wide.len() * 2 > crate::pe::emu::CMDLINE_SIZE {
            return Err("command line too long (64K guest block)".to_string());
        }
        Ok(wide)
    }

    pub(super) fn run_rust_baseline_argv(
        img: &PeImage,
        prog: &str,
        args: &[String],
    ) -> Result<(u32, Vec<u8>), String> {
        let _run = NATIVE_RUN_LOCK
            .lock()
            .map_err(|_| "native backend execution lock is poisoned".to_string())?;
        if img.tls.is_some() || !img.stubs.is_empty() {
            return Err(
                "native Rust baseline does not yet support TLS or stub imports".to_string(),
            );
        }
        let entry = entry(img)?;
        let mapping = map(img)?;
        patch_baseline_imports(&mapping, img)?;
        let cmdline = command_line_w(prog, args)?;
        let mut fs = NativeFs {
            fs: WinFs::new(),
            handles: HashMap::new(),
            next: 0x100,
        };
        COMMAND_LINE_W.store(cmdline.as_ptr() as u64, Ordering::Release);
        NATIVE_FS.store((&mut fs as *mut NativeFs) as u64, Ordering::Release);
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
        COMMAND_LINE_W.store(0, Ordering::Release);
        NATIVE_FS.store(0, Ordering::Release);
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

    pub(super) fn run_rust_baseline_argv(
        _: &PeImage,
        _: &str,
        _: &[String],
    ) -> Result<(u32, Vec<u8>), String> {
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

    #[test]
    fn executes_the_checked_in_rust_argv_guest_with_native_trampolines() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/artifacts/exe/rust_argv.exe"
        );
        let bytes = std::fs::read(path).expect("checked-in guest exists");
        let img = load(&bytes).expect("rust argv loads");
        let args = [
            "hello".to_string(),
            "a b".to_string(),
            "--version".to_string(),
        ];
        let (code, out) =
            run_rust_baseline_argv(&img, "myprog.exe", &args).expect("native rust argv runs");
        assert_eq!(code, 0);
        assert_eq!(out, b"myprog.exe hello \"a b\" --version\n");
    }
}
