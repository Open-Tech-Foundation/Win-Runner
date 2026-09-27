//! Windows exceptions compatibility APIs for the Linux native backend.

use super::*;

pub(super) extern "win64" fn native_set_unhandled_exception_filter(filter: u64) -> u64 {
    process_ctx()
        .map(|process| {
            process
                .unhandled_exception_filter
                .swap(filter, Ordering::AcqRel)
        })
        .unwrap_or(0)
}

pub(super) extern "win64" fn native_add_vectored_exception_handler(
    _first: u32,
    handler: u64,
) -> u64 {
    if handler == 0 {
        return 0;
    }
    if let Some(process) = process_ctx() {
        process
            .vectored_exception_handler
            .store(handler, Ordering::Release);
    }
    handler | 1
}
pub(super) extern "win64" fn native_remove_vectored_exception_handler(handle: u64) -> u32 {
    let Some(process) = process_ctx() else {
        return 0;
    };
    let current = process.vectored_exception_handler.load(Ordering::Acquire);
    if current != 0 && handle == current | 1 {
        process
            .vectored_exception_handler
            .store(0, Ordering::Release);
        1
    } else {
        0
    }
}
