//! Linux backend process-wide runtime state and synthetic handle values.

use std::sync::atomic::AtomicI32;
use std::sync::{LazyLock, Mutex};

pub(super) static NATIVE_DIAGNOSTIC_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var_os("WINRUN_NATIVE_DIAGNOSTIC").is_some_and(|value| value == "1")
});

#[inline]
pub(super) fn native_diagnostic_enabled() -> bool {
    *NATIVE_DIAGNOSTIC_ENABLED
}

pub(super) const PROCESS_HEAP_HANDLE: u64 = 0x400;
pub(super) const PROCESS_TOKEN_HANDLE: u64 = 0x544f_4b45_4e00_0001;
pub(super) const STD_HANDLE_BASE: u64 = 0x5000_0000;
/// Socket handles: `SOCKET_HANDLE_BASE + 4 * fd`. Windows keeps SOCKET
/// values within 32 bits and programs rely on it (OpenSSL stores sockets as
/// `int`), so they live in an otherwise unused range below 0x4000_0000.
pub(super) const SOCKET_HANDLE_BASE: u64 = 0x2000_0000;
const SOCKET_HANDLE_END: u64 = 0x4000_0000;

/// The SOCKET for a host socket descriptor.
pub(super) fn socket_handle(fd: i32) -> u64 {
    SOCKET_HANDLE_BASE + (u64::from(fd as u32) << 2)
}

/// Whether a handle value names a socket.
pub(super) fn is_socket_handle(handle: u64) -> bool {
    (SOCKET_HANDLE_BASE..SOCKET_HANDLE_END).contains(&handle) && handle & 3 == 0
}

/// The host descriptor of a socket handle (`-1` for any other value).
pub(super) fn socket_fd(handle: u64) -> i32 {
    if is_socket_handle(handle) {
        ((handle - SOCKET_HANDLE_BASE) >> 2) as i32
    } else {
        -1
    }
}
pub(super) const CRYPTO_PROVIDER_HANDLE: u64 = 0x4352_5950_544f_0001;
// A child-local stand-in for API-set modules dynamically requested by the UCRT.
pub(super) const API_SET_MODULE: u64 = 0x5749_4e43_4c49_0001;
pub(super) const WS2_MODULE: u64 = 0x5749_4e43_4c49_0002;
pub(super) const WSOCK_MODULE: u64 = 0x5749_4e43_4c49_0003;
pub(super) static EMPTY_ENVIRONMENT_BLOCK: [u16; 2] = [0, 0];

// Preferred-base PE mappings collide by design. Serialize native runs until
// relocations allow independent address-space layouts.
pub(super) static NATIVE_RUN_LOCK: Mutex<()> = Mutex::new(());

pub(super) static NATIVE_WORKER_RESULT_FD: AtomicI32 = AtomicI32::new(-1);
