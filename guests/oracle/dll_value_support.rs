#![no_std]
#![no_main]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
#[no_mangle]
pub extern "system" fn OracleSearchValue() -> u32 {
    if cfg!(user_directory) {
        22
    } else {
        11
    }
}
