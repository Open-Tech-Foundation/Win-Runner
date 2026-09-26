//! Platform execution backends for a platform-neutral WinCLI instance.
//!
//! The instance lifecycle, WinFs snapshots, and control protocol must not
//! depend on the host OS. Backends are the narrow extension point that turns
//! a loaded PE image into one guest process. New targets (macOS translation,
//! Windows-native, a VM worker) implement [`ExecutionBackend`] and register
//! alongside the built-ins here.

use crate::{native, pe::PeImage, winfs::WinFs};
use std::sync::Arc;

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

#[derive(Debug)]
pub struct ExecutionFailure {
    pub message: String,
    /// Current guest filesystem at the failure boundary. Native child writes
    /// are committed through its filesystem journal only after clean exit.
    pub fs: WinFs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputChannel {
    Stdout,
    Stderr,
}

pub type OutputSink = Arc<dyn Fn(OutputChannel, &[u8]) + Send + Sync>;

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
    ) -> Result<Execution, ExecutionFailure>;

    /// Execute while forwarding console output. Backends without a native
    /// incremental console bridge retain the safe default and emit once on
    /// completion; platform add-ons can override this without changing the
    /// instance protocol.
    fn execute_streaming(
        &self,
        image: &PeImage,
        fs: WinFs,
        prog: &str,
        args: &[String],
        sink: OutputSink,
    ) -> Result<Execution, ExecutionFailure> {
        let result = self.execute(image, fs, prog, args)?;
        if !result.stdout.is_empty() {
            sink(OutputChannel::Stdout, &result.stdout);
        }
        Ok(result)
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
    ) -> Result<Execution, ExecutionFailure> {
        let (code, stdout, fs) = native::run_rust_baseline_argv_with_fs_recoverable(
            image, fs, prog, args,
        )
        .map_err(|failure| ExecutionFailure {
            message: failure.message,
            fs: failure.fs,
        })?;
        Ok(Execution { code, stdout, fs })
    }

    fn execute_streaming(
        &self,
        image: &PeImage,
        fs: WinFs,
        prog: &str,
        args: &[String],
        sink: OutputSink,
    ) -> Result<Execution, ExecutionFailure> {
        let forward = Arc::clone(&sink);
        let (code, stdout, fs) = native::run_rust_baseline_argv_with_fs_streaming_recoverable(
            image,
            fs,
            prog,
            args,
            &move |chunk| forward(OutputChannel::Stdout, chunk),
        )
        .map_err(|failure| ExecutionFailure {
            message: failure.message,
            fs: failure.fs,
        })?;
        Ok(Execution { code, stdout, fs })
    }
}

static NATIVE_LINUX_X64: NativeLinuxX64 = NativeLinuxX64;

/// Built-ins available to this binary. Future optional backends are added to
/// this registry without changing shell, runner, or snapshot semantics.
pub fn registered() -> [&'static dyn ExecutionBackend; 1] {
    [&NATIVE_LINUX_X64]
}

/// Choose the built-in platform backend for this host.
pub fn configured() -> Result<&'static dyn ExecutionBackend, String> {
    let backend = registered()
        .into_iter()
        .find(|backend| backend.available())
        .ok_or_else(|| "no execution backend is available on this host".to_string())?;
    Ok(backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn builtins_have_unique_stable_ids() {
        let backends = registered();
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].id(), "native-linux-x64");
        assert!(backends[0].capabilities().direct_x86_64_pe);
    }

    #[test]
    fn native_forwards_console_output_to_stream_sink() {
        let image = crate::pe::load(&crate::pe::builder::hello("streamed")).unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink_output = Arc::clone(&output);
        let sink: OutputSink = Arc::new(move |channel, chunk| {
            assert_eq!(channel, OutputChannel::Stdout);
            sink_output.lock().unwrap().extend_from_slice(chunk);
        });
        let result = NATIVE_LINUX_X64
            .execute_streaming(&image, WinFs::new(), "hello.exe", &[], sink)
            .unwrap();
        assert_eq!(result.code, 0);
        assert_eq!(*output.lock().unwrap(), b"streamed");
    }
}
