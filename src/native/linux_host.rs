//! Linux host ABI declarations used by the Linux x86-64 PE backend.

use std::ffi::c_void;

pub(super) const PROT_READ: i32 = 0x1;
pub(super) const PROT_WRITE: i32 = 0x2;
pub(super) const PROT_EXEC: i32 = 0x4;
pub(super) const MAP_PRIVATE: i32 = 0x02;
pub(super) const MAP_ANONYMOUS: i32 = 0x20;
// Linux-specific. Unlike MAP_FIXED, this never replaces an existing map.
pub(super) const MAP_FIXED_NOREPLACE: i32 = 0x100000;
pub(super) const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;
unsafe extern "C" {
    pub(super) fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: isize,
    ) -> *mut c_void;
    pub(super) fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    pub(super) fn munmap(addr: *mut c_void, len: usize) -> i32;
    pub(super) fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
    pub(super) fn pipe(fds: *mut i32) -> i32;
    pub(super) fn socketpair(domain: i32, kind: i32, protocol: i32, fds: *mut i32) -> i32;
    pub(super) fn fork() -> i32;
    #[cfg(test)]
    pub(super) fn pause() -> i32;
    pub(super) fn dup2(oldfd: i32, newfd: i32) -> i32;
    pub(super) fn close(fd: i32) -> i32;
    pub(super) fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
    pub(super) fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
    pub(super) fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    pub(super) fn kill(pid: i32, signal: i32) -> i32;
    pub(super) fn _exit(status: i32) -> !;
    pub(super) fn malloc(size: usize) -> *mut c_void;
    pub(super) fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    pub(super) fn free(ptr: *mut c_void);
    pub(super) fn getrandom(buf: *mut c_void, buflen: usize, flags: u32) -> isize;
    pub(super) fn isatty(fd: i32) -> i32;
    pub(super) fn gethostname(name: *mut i8, length: usize) -> i32;
    pub(super) fn clock_gettime(clock_id: i32, time: *mut NativeTimespec) -> i32;
    pub(super) fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    pub(super) fn fcntl(fd: i32, command: i32, ...) -> i32;
    pub(super) fn ioctl(fd: i32, request: usize, argp: *mut c_void) -> i32;
    pub(super) fn bind(fd: i32, address: *const u8, length: u32) -> i32;
    pub(super) fn listen(fd: i32, backlog: i32) -> i32;
    pub(super) fn accept(fd: i32, address: *mut u8, length: *mut u32) -> i32;
    pub(super) fn connect(fd: i32, address: *const u8, length: u32) -> i32;
    pub(super) fn send(fd: i32, buffer: *const c_void, length: usize, flags: i32) -> isize;
    pub(super) fn recv(fd: i32, buffer: *mut c_void, length: usize, flags: i32) -> isize;
    pub(super) fn poll(fds: *mut NativePollFd, count: usize, timeout: i32) -> i32;
    pub(super) fn setsockopt(
        fd: i32,
        level: i32,
        option: i32,
        value: *const c_void,
        length: u32,
    ) -> i32;
    pub(super) fn getsockopt(
        fd: i32,
        level: i32,
        option: i32,
        value: *mut c_void,
        length: *mut u32,
    ) -> i32;
    pub(super) fn getsockname(fd: i32, address: *mut u8, length: *mut u32) -> i32;
    pub(super) fn getpeername(fd: i32, address: *mut u8, length: *mut u32) -> i32;
    pub(super) fn shutdown(fd: i32, how: i32) -> i32;
    pub(super) fn getaddrinfo(
        node: *const i8,
        service: *const i8,
        hints: *const HostAddrInfo,
        result: *mut *mut HostAddrInfo,
    ) -> i32;
    pub(super) fn freeaddrinfo(result: *mut HostAddrInfo);
}

#[repr(C)]
pub(super) struct NativePollFd {
    pub(super) fd: i32,
    pub(super) events: i16,
    pub(super) revents: i16,
}

#[repr(C)]
pub(super) struct NativeTimespec {
    pub(super) seconds: i64,
    pub(super) nanoseconds: i64,
}

#[repr(C)]
pub(super) struct HostAddrInfo {
    pub(super) flags: i32,
    pub(super) family: i32,
    pub(super) socktype: i32,
    pub(super) protocol: i32,
    pub(super) addrlen: u32,
    pub(super) addr: *mut u8,
    pub(super) canonname: *mut i8,
    pub(super) next: *mut HostAddrInfo,
}
