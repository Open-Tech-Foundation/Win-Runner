#![no_std]
#![no_main]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
#[link(name = "oracle_search_value")]
extern "system" {
    fn OracleSearchValue() -> u32;
}
#[no_mangle]
pub extern "system" fn OracleSearchMiddle() -> u32 {
    unsafe { OracleSearchValue() }
}
