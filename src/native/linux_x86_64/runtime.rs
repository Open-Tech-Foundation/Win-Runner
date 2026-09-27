//! Linux backend process-wide runtime state and synthetic handle values.

use std::sync::atomic::AtomicI32;
use std::sync::{LazyLock, Mutex};

pub(super) static NATIVE_DIAGNOSTIC_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var_os("WINCLI_NATIVE_DIAGNOSTIC").is_some_and(|value| value == "1")
});

#[inline]
pub(super) fn native_diagnostic_enabled() -> bool {
    *NATIVE_DIAGNOSTIC_ENABLED
}

pub(super) const PROCESS_HEAP_HANDLE: u64 = 0x400;
pub(super) const PROCESS_TOKEN_HANDLE: u64 = 0x544f_4b45_4e00_0001;
pub(super) const STD_HANDLE_BASE: u64 = 0x5000_0000;
pub(super) const SOCKET_HANDLE_TAG: u64 = 0x534f_434b_0000_0000;
pub(super) const CRYPTO_PROVIDER_HANDLE: u64 = 0x4352_5950_544f_0001;
// A child-local stand-in for API-set modules dynamically requested by the UCRT.
pub(super) const API_SET_MODULE: u64 = 0x5749_4e43_4c49_0001;
pub(super) static EMPTY_ENVIRONMENT_BLOCK: [u16; 2] = [0, 0];

// Preferred-base PE mappings collide by design. Serialize native runs until
// relocations allow independent address-space layouts.
pub(super) static NATIVE_RUN_LOCK: Mutex<()> = Mutex::new(());

pub(super) static NATIVE_WORKER_RESULT_FD: AtomicI32 = AtomicI32::new(-1);
