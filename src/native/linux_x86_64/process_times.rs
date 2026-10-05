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
    pub(super) io: Mutex<Option<[u64; 6]>>,
    memory: Mutex<ProcessMemory>,
    io_source: Mutex<Option<std::fs::File>>,
}
impl NativeProcessTimes {
    pub(super) fn new() -> Self {
        Self {
            creation: process_filetime_now(),
            exit: AtomicU64::new(0),
            kernel: AtomicU64::new(0),
            user: AtomicU64::new(0),
            io: Mutex::new(None),
            memory: Mutex::new(ProcessMemory::default()),
            io_source: Mutex::new(None),
        }
    }
    pub(super) fn prepare_worker_io(&self, pid: u32) {
        *self.io_source.lock().unwrap() = std::fs::File::open(format!("/proc/{pid}/io")).ok();
    }
    pub(super) fn finish(&self, usage: &libc::rusage) {
        let ticks =
            |time: libc::timeval| time.tv_sec as u64 * 10_000_000 + time.tv_usec as u64 * 10;
        self.user.store(ticks(usage.ru_utime), Ordering::Release);
        self.kernel.store(ticks(usage.ru_stime), Ordering::Release);
        if let Ok(mut memory) = self.memory.lock() {
            memory.faults = (usage.ru_minflt as u64).saturating_add(usage.ru_majflt as u64);
            memory.peak_rss = memory
                .peak_rss
                .max((usage.ru_maxrss as u64).saturating_mul(1024));
            memory.rss = 0;
            memory.commit = 0;
        }
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
    mut progress: impl FnMut(),
) -> std::io::Result<std::process::ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    let mut status = 0;
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // Open while the worker is alive: Linux may deny opening /proc/PID/io
    // after its credentials disappear at exit. An already-open fd retains
    // access to final counters until the zombie is reaped.
    let mut io_file = times
        .io_source
        .lock()
        .unwrap()
        .take()
        .or_else(|| std::fs::File::open(format!("/proc/{}/io", worker.id())).ok());
    // Keep the exited worker as a zombie until its final /proc I/O counters
    // have been recorded. wait4 below then reaps it and collects CPU usage.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        if unsafe {
            libc::waitid(
                libc::P_PID,
                worker.id(),
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        } == 0
        {
            progress();
            if unsafe { info.si_pid() } != 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    if let Ok(mut saved) = times.io.lock() {
        let mut contents = String::new();
        *saved = io_file.as_mut().and_then(|file| {
            std::io::Read::read_to_string(file, &mut contents).ok()?;
            parse_process_io(&contents)
        });
    }
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

fn linux_process_io(pid: u32) -> Option<[u64; 6]> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    parse_process_io(&contents)
}

fn parse_process_io(contents: &str) -> Option<[u64; 6]> {
    let values: HashMap<_, _> = contents
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name, value.trim().parse::<u64>().ok()?))
        })
        .collect();
    // Linux accounts read/write syscalls and bytes, including cached I/O.
    // It does not publish Windows' "other operation/transfer" counters.
    Some([
        *values.get("syscr")?,
        *values.get("syscw")?,
        0,
        *values.get("rchar")?,
        *values.get("wchar")?,
        0,
    ])
}

pub(super) extern "win64" fn native_get_process_io_counters(handle: u64, output: *mut u64) -> i32 {
    if output.is_null() {
        native_set_last_error(87);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let handle = process
        .duplicate_handles
        .lock()
        .ok()
        .and_then(|handles| handles.get(&handle).copied())
        .unwrap_or(handle);
    let values = if handle == u64::MAX || handle == process.process_handle {
        linux_process_io(std::process::id())
    } else if let Some(child) = child_process(&process, handle) {
        let pid = child.host_pid.load(Ordering::Acquire);
        let saved = child.times.io.lock().ok().and_then(|saved| *saved);
        saved.or_else(|| {
            if pid > 0 {
                linux_process_io(pid as u32)
            } else {
                None
            }
        })
    } else {
        native_set_last_error(6);
        return 0;
    };
    let Some(values) = values else {
        native_set_last_error(50);
        return 0;
    };
    unsafe { ptr::copy_nonoverlapping(values.as_ptr(), output, values.len()) };
    1
}
#[derive(Default, Clone, Copy)]
struct ProcessMemory {
    faults: u64,
    peak_rss: u64,
    rss: u64,
    commit: u64,
    peak_commit: u64,
}

fn linux_process_memory(pid: u32) -> Option<ProcessMemory> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let kb = |name: &str| -> Option<u64> {
        status
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key == name).then(|| value.split_whitespace().next()?.parse::<u64>().ok())?
            })
            .map(|value| value.saturating_mul(1024))
    };
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, fields) = stat.rsplit_once(") ")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    let faults = fields
        .get(7)?
        .parse::<u64>()
        .ok()?
        .saturating_add(fields.get(9)?.parse::<u64>().ok()?);
    // "ac" VMAs are charged by Linux's commit accounting. Swap usage is
    // not a substitute for Windows commit charge. Pool quotas have no Linux
    // equivalent and are reported as zero; peak commit is sampled on queries.
    let maps = std::fs::read_to_string(format!("/proc/{pid}/smaps")).ok()?;
    let mut size = 0u64;
    let mut commit = 0u64;
    for line in maps.lines() {
        if let Some(value) = line.strip_prefix("Size:") {
            size = value
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()?
                .saturating_mul(1024);
        } else if let Some(flags) = line.strip_prefix("VmFlags:") {
            if flags.split_whitespace().any(|flag| flag == "ac") {
                commit = commit.saturating_add(size);
            }
        }
    }
    Some(ProcessMemory {
        faults,
        peak_rss: kb("VmHWM")?,
        rss: kb("VmRSS")?,
        commit,
        peak_commit: commit,
    })
}

pub(super) extern "win64" fn native_get_process_memory_info(
    handle: u64,
    output: *mut u8,
    size: u32,
) -> i32 {
    if output.is_null() || size < 72 {
        native_set_last_error(87);
        return 0;
    }
    if size > 80 {
        // PROCESS_MEMORY_COUNTERS_EX2 is not implemented.
        native_set_last_error(50);
        return 0;
    }
    let Some(process) = process_ctx() else {
        native_set_last_error(6);
        return 0;
    };
    let handle = process
        .duplicate_handles
        .lock()
        .ok()
        .and_then(|handles| handles.get(&handle).copied())
        .unwrap_or(handle);
    let (pid, times) = if handle == u64::MAX || handle == process.process_handle {
        (std::process::id() as i32, &process.times)
    } else if let Some(child) = child_process(&process, handle) {
        return process_memory_result(
            child.host_pid.load(Ordering::Acquire),
            &child.times,
            output,
            size,
        );
    } else {
        native_set_last_error(6);
        return 0;
    };
    process_memory_result(pid, times, output, size)
}

fn process_memory_result(pid: i32, times: &NativeProcessTimes, output: *mut u8, size: u32) -> i32 {
    let mut saved = times.memory.lock().unwrap();
    if times.exit.load(Ordering::Acquire) == 0 {
        let Some(mut current) = (pid > 0)
            .then(|| linux_process_memory(pid as u32))
            .flatten()
        else {
            native_set_last_error(50);
            return 0;
        };
        current.peak_commit = current.commit.max(saved.peak_commit);
        *saved = current;
    }
    let mut bytes = [0u8; 80];
    let written = if size >= 80 { 80u32 } else { 72 };
    bytes[..4].copy_from_slice(&written.to_ne_bytes());
    bytes[4..8].copy_from_slice(&(saved.faults.min(u32::MAX as u64) as u32).to_ne_bytes());
    for (offset, value) in [
        (8, saved.peak_rss),
        (16, saved.rss),
        (56, saved.commit),
        (64, saved.peak_commit),
        (72, saved.commit),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output, written as usize) };
    1
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
            .args([
                "-c",
                "sleep .05; i=0; while [ $i -lt 10000 ]; do i=$((i+1)); done",
            ])
            .spawn()
            .unwrap();
        let pid = worker.id();
        let status = wait_worker_with_times(&mut worker, &times, || {}).unwrap();
        assert!(status.success());
        assert!(times.exit.load(Ordering::Acquire) >= creation);
        assert!(times.user.load(Ordering::Acquire) + times.kernel.load(Ordering::Acquire) > 0);
        assert_eq!(times.creation, creation);
        assert!(times.io.lock().unwrap().unwrap()[0] > 0);
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        let mut memory = [0u64; 10];
        assert_eq!(
            process_memory_result(pid as i32, &times, memory.as_mut_ptr().cast(), 80),
            1
        );
        assert!(memory[1] > 0);
        assert_eq!(memory[2], 0);
    }
    #[test]
    fn process_resources_validate_buffers_and_return_real_counters() {
        let _guard = TestProcessGuard::new();
        let mut io = [u64::MAX; 6];
        assert_eq!(native_get_process_io_counters(u64::MAX, io.as_mut_ptr()), 1);
        assert!(io[0] > 0);
        assert_eq!(native_get_process_io_counters(42, io.as_mut_ptr()), 0);
        assert_eq!(native_get_last_error(), 6);
        assert_eq!(native_get_process_io_counters(u64::MAX, ptr::null_mut()), 0);
        assert_eq!(native_get_last_error(), 87);
        let mut memory = [u64::MAX; 11];
        assert_eq!(
            native_get_process_memory_info(u64::MAX, memory.as_mut_ptr().cast(), 80),
            1
        );
        assert_eq!(memory[0] as u32, 80);
        assert!(memory[1] >= memory[2] && memory[2] > 0);
        assert!(memory[8] >= memory[7] && memory[9] == memory[7]);
        assert_eq!(memory[10], u64::MAX);
        let unchanged = memory;
        for (handle, size, error) in [(42, 80, 6), (u64::MAX, 71, 87), (u64::MAX, 96, 50)] {
            assert_eq!(
                native_get_process_memory_info(handle, memory.as_mut_ptr().cast(), size),
                0
            );
            assert_eq!(native_get_last_error(), error);
            assert_eq!(memory, unchanged);
        }
        assert_eq!(
            native_get_process_memory_info(u64::MAX, memory.as_mut_ptr().cast(), 72),
            1
        );
        assert_eq!(memory[9], unchanged[9]);
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
