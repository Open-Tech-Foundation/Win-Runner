//! Platform execution backends for a platform-neutral WinCLI instance.
//!
//! The instance lifecycle, WinFs snapshots, and control protocol must not
//! depend on the host OS. Backends are the narrow extension point that turns
//! a loaded PE image into one guest process. New targets (macOS translation,
//! Windows-native, a VM worker) implement [`ExecutionBackend`] and register
//! alongside the built-ins here.

use crate::{native, pe::PeImage, winapi, winfs::WinFs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub direct_x86_64_pe: bool,
    pub persistent_winfs: bool,
}

pub struct Execution {
    pub code: u32,
    pub stdout: Vec<u8>,
    pub fs: WinFs,
}

pub trait ExecutionBackend: Sync {
    /// Stable backend identifier used by configuration and future protocol
    /// capability negotiation.
    fn id(&self) -> &'static str;
    fn available(&self) -> bool;
    fn capabilities(&self) -> Capabilities;
    fn execute(
        &self,
        image: &PeImage,
        fs: WinFs,
        prog: &str,
        args: &[String],
    ) -> Result<Execution, String>;
}

struct Interpreter;

impl ExecutionBackend for Interpreter {
    fn id(&self) -> &'static str {
        "interpreter"
    }

    fn available(&self) -> bool {
        true
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            direct_x86_64_pe: false,
            persistent_winfs: true,
        }
    }

    fn execute(
        &self,
        image: &PeImage,
        fs: WinFs,
        prog: &str,
        args: &[String],
    ) -> Result<Execution, String> {
        let (code, fs, stdout) = winapi::Runner::with_argv(image, fs, prog, args)?.run()?;
        Ok(Execution { code, stdout, fs })
    }
}

struct NativeLinuxX64;

impl ExecutionBackend for NativeLinuxX64 {
    fn id(&self) -> &'static str {
        "native-linux-x64"
    }

    fn available(&self) -> bool {
        native::AVAILABLE
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            direct_x86_64_pe: true,
            persistent_winfs: true,
        }
    }

    fn execute(
        &self,
        image: &PeImage,
        fs: WinFs,
        prog: &str,
        args: &[String],
    ) -> Result<Execution, String> {
        let (code, stdout, fs) = native::run_rust_baseline_argv_with_fs(image, fs, prog, args)?;
        Ok(Execution { code, stdout, fs })
    }
}

static INTERPRETER: Interpreter = Interpreter;
static NATIVE_LINUX_X64: NativeLinuxX64 = NativeLinuxX64;

/// Built-ins available to this binary. Future optional backends are added to
/// this registry without changing shell, runner, or snapshot semantics.
pub fn registered() -> [&'static dyn ExecutionBackend; 2] {
    [&INTERPRETER, &NATIVE_LINUX_X64]
}

/// Choose the configured backend. The default remains the portable
/// interpreter. `WINCLI_BACKEND=native` is retained as the existing alias;
/// `native-linux-x64` is the stable explicit identifier.
pub fn configured() -> Result<&'static dyn ExecutionBackend, String> {
    let requested = std::env::var("WINCLI_BACKEND").unwrap_or_else(|_| "interpreter".to_string());
    let requested = match requested.as_str() {
        "native" => "native-linux-x64",
        value => value,
    };
    let backend = registered()
        .into_iter()
        .find(|backend| backend.id() == requested)
        .ok_or_else(|| format!("unknown execution backend: {requested}"))?;
    if !backend.available() {
        return Err(format!("execution backend is unavailable on this host: {requested}"));
    }
    Ok(backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_have_unique_stable_ids() {
        let backends = registered();
        assert_ne!(backends[0].id(), backends[1].id());
        assert!(backends.iter().any(|backend| backend.id() == "interpreter"));
        assert!(backends.iter().any(|backend| backend.id() == "native-linux-x64"));
    }
}
