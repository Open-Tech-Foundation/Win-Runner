//! Windows events compatibility APIs for the Linux native backend.

pub(super) extern "win64" fn native_event_register(
    provider_id: *const u8,
    _callback: u64,
    _context: u64,
    registration: *mut u64,
) -> u32 {
    if provider_id.is_null() || registration.is_null() {
        return 87;
    }
    unsafe { registration.write(0x4554_5700_0000_0001) };
    0
}
pub(super) extern "win64" fn native_event_unregister(_registration: u64) -> u32 {
    0
}
pub(super) extern "win64" fn native_event_set_information(
    _registration: u64,
    _class: u32,
    _information: *const u8,
    _length: u32,
) -> u32 {
    0
}
pub(super) extern "win64" fn native_event_write_transfer(
    _registration: u64,
    _descriptor: *const u8,
    _activity: *const u8,
    _related_activity: *const u8,
    _count: u32,
    _data: *const u8,
) -> u32 {
    0
}
