//! Linux x86-64 implementation of the native PE backend.

use super::{quote_arg, PeImage, COMMAND_LINE_BYTES};
use crate::winfs::WinFs;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, Weak};

#[path = "linux_x86_64/runtime.rs"]
mod runtime;
use runtime::*;
#[path = "linux_host.rs"]
mod host;
use host::*;

#[path = "linux_x86_64/loader.rs"]
mod loader;
use loader::*;
#[path = "linux_x86_64/process.rs"]
mod process;
use process::*;
#[path = "linux_x86_64/registry.rs"]
mod registry;
use registry::baseline_trampoline;
pub(super) use registry::supports_import;
#[path = "linux_x86_64/advapi_registry.rs"]
mod advapi_registry;
use advapi_registry::*;
#[path = "linux_x86_64/crt_time.rs"]
mod crt_time;
use crt_time::*;
#[path = "linux_x86_64/crt_math.rs"]
mod crt_math;
use crt_math::*;
#[path = "linux_x86_64/crt_text.rs"]
mod crt_text;
use crt_text::*;
#[path = "linux_x86_64/cmd_host.rs"]
mod cmd_host;
use cmd_host::*;
#[path = "linux_x86_64/sockets.rs"]
mod sockets;
use sockets::*;
#[path = "linux_x86_64/file_io/mod.rs"]
mod file_io;
use file_io::*;
#[path = "linux_x86_64/handles.rs"]
mod handles;
use handles::*;
#[path = "linux_x86_64/sync.rs"]
mod sync;
use sync::*;
#[path = "linux_x86_64/crt.rs"]
mod crt;
use crt::*;
#[path = "linux_x86_64/console.rs"]
mod console;
use console::*;
#[path = "linux_x86_64/overlapped.rs"]
mod overlapped;
use overlapped::*;
#[path = "linux_x86_64/state.rs"]
mod state;
use state::*;
#[path = "linux_x86_64/context.rs"]
mod context;
use context::*;
#[path = "linux_x86_64/locale.rs"]
mod locale;
use locale::*;
#[path = "linux_x86_64/environment.rs"]
mod environment;
use environment::*;
#[path = "linux_x86_64/thread_runtime.rs"]
mod thread_runtime;
use thread_runtime::*;
#[path = "linux_x86_64/clock.rs"]
mod clock;
use clock::*;
#[path = "linux_x86_64/ntdll.rs"]
mod ntdll;
use ntdll::*;
#[path = "linux_x86_64/memory.rs"]
mod memory;
use memory::*;
#[path = "linux_x86_64/system.rs"]
mod system;
use system::*;
#[path = "linux_x86_64/strings.rs"]
mod strings;
use strings::*;
#[path = "linux_x86_64/runner.rs"]
mod runner;
pub(super) use runner::*;
#[path = "linux_x86_64/exceptions.rs"]
mod exceptions;
use exceptions::*;
#[path = "linux_x86_64/crypto.rs"]
mod crypto;
use crypto::*;
#[path = "linux_x86_64/events.rs"]
mod events;
use events::*;
#[path = "linux_x86_64/messages.rs"]
mod messages;
use messages::*;

#[cfg(test)]
pub(super) fn test_socket_handle_inheritability() -> bool {
    let socket = native_socket(2, 1, 0);
    if socket == u64::MAX {
        return false;
    }
    let result = native_set_handle_information(socket, 1, 1) == 1
        && unsafe { fcntl(socket as i32, 1) } & 1 == 0
        && native_set_handle_information(socket, 1, 0) == 1
        && unsafe { fcntl(socket as i32, 1) } & 1 != 0;
    let _ = native_close_socket(socket);
    result
}

#[path = "linux_x86_64/arch.rs"]
mod arch;
use arch::*;

#[cfg(test)]
#[path = "linux_x86_64/tests.rs"]
mod tests;

/// Set the private result descriptor used by an exec-based guest worker.
pub(super) fn set_worker_result_fd(fd: i32) {
    NATIVE_WORKER_RESULT_FD.store(fd, Ordering::Release);
}

pub(super) fn receive_worker_pipe_descriptors(
    socket_path: &str,
    expected: usize,
) -> Result<Vec<i32>, String> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path)
        .map_err(|error| format!("cannot connect worker pipe transfer socket: {error}"))?;
    process::receive_worker_pipe_fds(&stream, expected)
}
