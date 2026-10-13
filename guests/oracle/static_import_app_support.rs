//! A program that links oracle_search_parent.dll at load time (not through
//! LoadLibrary): its exit code is the value the parent → middle → value DLL
//! chain returns, so the loader must find and bind all three before entry.
#![no_std]
#![no_main]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
#[link(name = "oracle_search_parent")]
extern "system" {
    fn OracleSearchParent() -> u32;
}
extern "system" {
    fn ExitProcess(code: u32) -> !;
}
#[no_mangle]
pub extern "system" fn static_import_entry() -> ! {
    unsafe { ExitProcess(OracleSearchParent()) }
}
