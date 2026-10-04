//! Windows process timestamps and Linux CPU accounting in FILETIME units.
use super::*;

pub(super) fn process_filetime_now() -> u64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        / 100) as u64
        + 116_444_736_000_000_000
}
pub(super) struct NativeProcessTimes {
    pub(super) creation: u64,
    pub(super) exit: AtomicU64,
    pub(super) kernel: AtomicU64,
    pub(super) user: AtomicU64,
}
impl NativeProcessTimes {
    pub(super) fn new() -> Self {
        Self {
            creation: process_filetime_now(),
            exit: AtomicU64::new(0),
            kernel: AtomicU64::new(0),
            user: AtomicU64::new(0),
        }
    }
    pub(super) fn finish(&self, usage: &libc::rusage) {
        let ticks =
            |time: libc::timeval| time.tv_sec as u64 * 10_000_000 + time.tv_usec as u64 * 10;
        self.user.store(ticks(usage.ru_utime), Ordering::Release);
        self.kernel.store(ticks(usage.ru_stime), Ordering::Release);
        self.exit.store(process_filetime_now(), Ordering::Release);
    }
    pub(super) fn finish_thread_since(&self, start: &libc::rusage) {
        let mut end: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe {
            libc::getrusage(libc::RUSAGE_THREAD, &mut end);
        }
        let ticks =
            |time: libc::timeval| time.tv_sec as u64 * 10_000_000 + time.tv_usec as u64 * 10;
        self.user.store(
            ticks(end.ru_utime).saturating_sub(ticks(start.ru_utime)),
            Ordering::Release,
        );
        self.kernel.store(
            ticks(end.ru_stime).saturating_sub(ticks(start.ru_stime)),
            Ordering::Release,
        );
        self.exit.store(process_filetime_now(), Ordering::Release);
    }
}
pub(super) fn wait_worker_with_times(
    worker: &mut std::process::Child,
    times: &NativeProcessTimes,
) -> std::io::Result<std::process::ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    let mut status = 0;
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    loop {
        if unsafe { libc::wait4(worker.id() as i32, &mut status, 0, &mut usage) } >= 0 {
            times.finish(&usage);
            return Ok(std::process::ExitStatus::from_raw(status));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
fn live_child_cpu(pid: i32) -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, fields) = stat.rsplit_once(") ")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    let user: u64 = fields.get(11)?.parse().ok()?;
    let kernel: u64 = fields.get(12)?.parse().ok()?;
    let frequency = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if frequency <= 0 {
        return None;
    }
    Some((
        kernel * 10_000_000 / frequency as u64,
        user * 10_000_000 / frequency as u64,
    ))
}
pub(super) extern "win64" fn native_get_process_times(
    handle: u64,
    creation: *mut u64,
    exit: *mut u64,
    kernel: *mut u64,
    user: *mut u64,
) -> i32 {
    if creation.is_null() || exit.is_null() || kernel.is_null() || user.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let values = if handle == u64::MAX || handle == process.process_handle {
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
            native_set_last_error(5);
            return 0;
        }
        let ticks =
            |time: libc::timeval| time.tv_sec as u64 * 10_000_000 + time.tv_usec as u64 * 10;
        (
            process.times.creation,
            process.times.exit.load(Ordering::Acquire),
            ticks(usage.ru_stime),
            ticks(usage.ru_utime),
        )
    } else if let Some(child) = child_process(&process, handle) {
        let exited = child.times.exit.load(Ordering::Acquire);
        let (kernel, user) = if exited == 0 {
            live_child_cpu(child.host_pid.load(Ordering::Acquire)).unwrap_or((
                child.times.kernel.load(Ordering::Acquire),
                child.times.user.load(Ordering::Acquire),
            ))
        } else {
            (
                child.times.kernel.load(Ordering::Acquire),
                child.times.user.load(Ordering::Acquire),
            )
        };
        (child.times.creation, exited, kernel, user)
    } else {
        native_set_last_error(6);
        return 0;
    };
    unsafe {
        creation.write_unaligned(values.0);
        exit.write_unaligned(values.1);
        kernel.write_unaligned(values.2);
        user.write_unaligned(values.3);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_times_keep_creation_and_wait4_cpu_usage_after_reaping() {
        let times = NativeProcessTimes::new();
        let creation = times.creation;
        let mut worker = std::process::Command::new("sh")
            .args(["-c", "i=0; while [ $i -lt 10000 ]; do i=$((i+1)); done"])
            .spawn()
            .unwrap();
        let status = wait_worker_with_times(&mut worker, &times).unwrap();
        assert!(status.success());
        assert!(times.exit.load(Ordering::Acquire) >= creation);
        assert!(times.user.load(Ordering::Acquire) + times.kernel.load(Ordering::Acquire) > 0);
        assert_eq!(times.creation, creation);
    }
    #[test]
    fn process_times_validate_handles_and_running_process_exit_time() {
        let mut creation = 0;
        let mut exit = 99;
        let mut kernel = 0;
        let mut user = 0;
        assert_eq!(
            native_get_process_times(u64::MAX, &mut creation, &mut exit, &mut kernel, &mut user),
            1
        );
        assert_ne!(creation, 0);
        assert_eq!(exit, 0);
        assert_eq!(
            native_get_process_times(42, &mut creation, &mut exit, &mut kernel, &mut user),
            0
        );
        assert_eq!(native_get_last_error(), 6);
        assert_eq!(
            native_get_process_times(u64::MAX, ptr::null_mut(), &mut exit, &mut kernel, &mut user),
            0
        );
        assert_eq!(native_get_last_error(), 87);
    }
}
