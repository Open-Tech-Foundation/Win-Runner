#![no_std]
#![no_main]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
#[link(name = "oracle_search_middle")]
extern "system" {
    fn OracleSearchMiddle() -> u32;
}
#[no_mangle]
pub extern "system" fn OracleSearchParent() -> u32 {
    unsafe { OracleSearchMiddle() }
}
