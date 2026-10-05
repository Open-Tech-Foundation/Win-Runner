//! Console input/output code pages shared across native process workers.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
const CONSOLE_FD_ENV: &str = "WINRUN_NATIVE_CONSOLE_FD";
const MAP_SIZE: usize = 4096;
#[repr(C)]
struct Pages {
    input: AtomicU32,
    output: AtomicU32,
}
pub(super) struct NativeConsoleCodePages {
    mapping: *mut Pages,
    descriptor: OwnedFd,
}
// The shared mapping only contains atomics, remains mapped for this object's
// lifetime, and is never resized after it has been initialized.
unsafe impl Send for NativeConsoleCodePages {}
unsafe impl Sync for NativeConsoleCodePages {}
impl Drop for NativeConsoleCodePages {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mapping.cast(), MAP_SIZE);
        }
    }
}
impl NativeConsoleCodePages {
    fn map(descriptor: OwnedFd) -> Result<Self, String> {
        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                MAP_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                descriptor.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(format!(
                "cannot map console code pages: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            mapping: mapping.cast(),
            descriptor,
        })
    }
    pub(super) fn new() -> Result<Self, String> {
        let fd = unsafe { libc::memfd_create(c"winrun-console".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(format!(
                "cannot create console state: {}",
                std::io::Error::last_os_error()
            ));
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::ftruncate(fd, MAP_SIZE as libc::off_t) } != 0 {
            return Err(format!(
                "cannot size console state: {}",
                std::io::Error::last_os_error()
            ));
        }
        let state = Self::map(descriptor)?;
        unsafe {
            state.mapping.write(Pages {
                input: AtomicU32::new(native_get_oem_cp()),
                output: AtomicU32::new(native_get_oem_cp()),
            });
        }
        Ok(state)
    }
    pub(super) fn from_worker_environment() -> Result<Self, String> {
        if std::env::var_os("WINRUN_NATIVE_WORKER").as_deref() != Some(std::ffi::OsStr::new("1")) {
            return Self::new();
        }
        let Some(fd) = std::env::var_os(CONSOLE_FD_ENV) else {
            return Self::new();
        };
        let fd = fd
            .to_str()
            .and_then(|fd| fd.parse::<i32>().ok())
            .filter(|fd| *fd > 2)
            .ok_or("invalid inherited console descriptor")?;
        // This descriptor is private runtime state, independent of whether
        // the guest requested inheritable Windows standard handles.
        let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err("invalid inherited console descriptor".into());
        }
        let size = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
        if size != MAP_SIZE as libc::off_t {
            return Err("invalid inherited console state size".into());
        }
        Self::map(descriptor)
    }
    pub(super) fn configure_child(&self, command: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        let fd = self.descriptor.as_raw_fd();
        command.env(CONSOLE_FD_ENV, fd.to_string());
        // Only fcntl runs between fork and exec; the launcher's descriptor
        // stays close-on-exec for unrelated concurrent host launches.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    fn pages(&self) -> &Pages {
        unsafe { &*self.mapping }
    }
    fn get(&self, input: bool) -> u32 {
        if input {
            &self.pages().input
        } else {
            &self.pages().output
        }
        .load(Ordering::Acquire)
    }
    fn set(&self, input: bool, page: u32) {
        if input {
            &self.pages().input
        } else {
            &self.pages().output
        }
        .store(page, Ordering::Release);
    }
}
pub(super) extern "win64" fn native_get_console_cp() -> u32 {
    process_ctx()
        .map(|p| p.console_code_pages.get(true))
        .unwrap_or_else(|| native_get_oem_cp())
}
pub(super) extern "win64" fn native_get_console_output_cp() -> u32 {
    process_ctx()
        .map(|p| p.console_code_pages.get(false))
        .unwrap_or_else(|| native_get_oem_cp())
}
fn set_page(input: bool, page: u32) -> i32 {
    if !matches!(page, 1252 | 65001) {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    process.console_code_pages.set(input, page);
    1
}
pub(super) extern "win64" fn native_set_console_cp(page: u32) -> i32 {
    set_page(true, page)
}
pub(super) extern "win64" fn native_set_console_output_cp(page: u32) -> i32 {
    set_page(false, page)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_input_and_output_pages_roundtrip_without_changing_acp() {
        let _guard = TestProcessGuard::new();
        assert_eq!(native_get_console_cp(), 1252);
        assert_eq!(native_get_console_output_cp(), 1252);
        assert_eq!(native_set_console_cp(65001), 1);
        assert_eq!(native_get_console_cp(), 65001);
        assert_eq!(native_get_console_output_cp(), 1252);
        assert_eq!(native_set_console_output_cp(65001), 1);
        assert_eq!(native_set_console_cp(1252), 1);
        assert_eq!(native_get_console_cp(), 1252);
        assert_eq!(native_get_console_output_cp(), 65001);
        assert_eq!(native_get_acp(), 1252);
        for name in [
            "GetConsoleCP",
            "GetConsoleOutputCP",
            "SetConsoleCP",
            "SetConsoleOutputCP",
        ] {
            assert!(baseline_trampoline(name).is_some());
        }
    }
    #[test]
    fn invalid_pages_preserve_existing_console_state() {
        let _guard = TestProcessGuard::new();
        native_set_console_cp(65001);
        native_set_console_output_cp(65001);
        for page in [u32::MAX, 1234567] {
            assert_eq!(native_set_console_cp(page), 0);
            assert_eq!(native_get_last_error(), 87);
            assert_eq!(native_set_console_output_cp(page), 0);
            assert_eq!(native_get_last_error(), 87);
            assert_eq!(native_get_console_cp(), 65001);
            assert_eq!(native_get_console_output_cp(), 65001);
        }
    }
    #[test]
    fn separate_console_mappings_share_updates_but_new_consoles_are_isolated() {
        let parent = NativeConsoleCodePages::new().unwrap();
        let duplicate = parent.descriptor.try_clone().unwrap();
        let child = NativeConsoleCodePages::map(duplicate).unwrap();
        child.set(true, 65001);
        child.set(false, 65001);
        assert_eq!(parent.get(true), 65001);
        assert_eq!(parent.get(false), 65001);
        assert_eq!(NativeConsoleCodePages::new().unwrap().get(false), 1252);
        drop(parent);
        assert_eq!(child.get(false), 65001);
    }
}
