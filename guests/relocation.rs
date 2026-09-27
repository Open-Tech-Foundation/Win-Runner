//! Retained absolute reference that makes rust-lld emit a DIR64 base
//! relocation for every test guest. The native CreateProcessW path maps child
//! images at a distinct address, so even otherwise position-independent
//! no_std guests must carry a relocation directory.

#![no_std]

#[no_mangle]
#[used]
pub static WINRUN_RELOCATION_TARGET: u8 = 0;

#[no_mangle]
#[used]
pub static WINRUN_RELOCATION_ANCHOR: &'static u8 = &WINRUN_RELOCATION_TARGET;
