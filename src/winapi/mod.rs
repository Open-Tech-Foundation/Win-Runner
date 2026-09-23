//! Minimal Win32 API shims over [`WinFs`](crate::winfs::WinFs).
//!
//! Same `WinFs` API as `ps1` uses (requirement 9). Supported: ExitProcess,
//! GetStdHandle, WriteFile, CreateFileW, ReadFile, CloseHandle,
//! CreateDirectoryW, RemoveDirectoryW, DeleteFileW, MoveFileW, CopyFileW,
//! GetCommandLineW/A, GetConsoleMode, SetConsoleMode, WriteConsoleW,
//! GetConsoleOutputCP, SetConsoleTextAttribute, ReadConsoleW.
//! Anything else fails at load time (`pe::load` rejects unknown imports).

use crate::pe::emu::{CpuState, Emu, StepResult};
use crate::pe::{PeImage, TlsDir};
use crate::winfs::WinFs;
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::time::{Duration, Instant};

pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // -10
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // -11
pub const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // -12
pub const INVALID_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFFF;

fn system_message(code: u32) -> Option<&'static str> {
    Some(match code {
        2 => "The system cannot find the file specified.\r\n",
        3 => "The system cannot find the path specified.\r\n",
        5 => "Access is denied.\r\n",
        6 => "The handle is invalid.\r\n",
        87 => "The parameter is incorrect.\r\n",
        120 => "This function is not supported on this system.\r\n",
        122 => "The data area passed to a system call is too small.\r\n",
        126 => "The specified module could not be found.\r\n",
        127 => "The specified procedure could not be found.\r\n",
        183 => "Cannot create a file when that file already exists.\r\n",
        _ => return None,
    })
}

fn version_compare(actual: u32, requested: u32, condition: u8) -> Option<bool> {
    Some(match condition {
        1 => actual == requested, // VER_EQUAL
        2 => actual > requested,
        3 => actual >= requested,
        4 => actual < requested,
        5 => actual <= requested,
        _ => return None,
    })
}

fn is_nul_device(path: &str) -> bool {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
        .trim_end_matches(':').eq_ignore_ascii_case("nul")
}

const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;

struct FileHandle {
    path: String, // display path (original resolution; re-normalized per op)
    offset: u64,
}

struct GuestSemaphore {
    count: i32,
    maximum: i32,
}

/// One directory-enumeration result for FindFirst/NextFileW.
struct FindEntry {
    name: String, // file name only
    attrs: u32,   // 0x10 dir, 0x80 file
    len: u64,     // 0 for dirs
}

/// Live FindFirstFileExW enumeration (entries precomputed, index into them).
struct FindSearch {
    entries: Vec<FindEntry>,
    index: usize,
}

enum ThreadState {
    Runnable,
    WaitingThread {
        handle: u64,
        deadline: Option<Instant>,
    },
    WaitingSemaphore {
        handle: u64,
        deadline: Option<Instant>,
    },
    WaitingAddress {
        address: u64,
        expected: Vec<u8>,
        deadline: Option<Instant>,
    },
    Sleeping(Instant),
    WaitingCritical(u64),
    WaitingSrw { address: u64, shared: bool },
    WaitingCondition { cv: u64, lock: u64, kind: CondLock, deadline: Option<Instant> },
    WaitingConditionLock { lock: u64, kind: CondLock },
    WaitingInitOnce { once: u64, callback: u64, parameter: u64, context_out: u64 },
    Finished,
}

#[derive(Clone, Copy)]
enum CondLock { Critical, SrwExclusive, SrwShared }

struct GuestThread {
    id: u32,
    handle: u64,
    open: bool,
    cpu: CpuState,
    last_error: u32,
    fls: Vec<Option<u64>>,
    tls_values: Vec<u64>,
    state: ThreadState,
    critical_depth: u32,
    tls_resume: Option<CpuState>,
    tls_next: usize,
    tls_reason: u32,
    once_frames: Vec<OnceFrame>,
}

struct OnceFrame {
    resume: CpuState,
    once: u64,
    context_out: u64,
    callback_context: u64,
}

enum OnceState {
    Running { owner: usize, split: bool },
    Complete { context: u64 },
}

#[derive(Default)]
struct SrwLock {
    exclusive: Option<usize>,
    shared: HashMap<usize, u32>,
}

pub struct Runner {
    pub emu: Emu,
    pub fs: WinFs,
    handles: HashMap<u64, FileHandle>,
    null_handles: HashSet<u64>,
    handle_flags: HashMap<u64, u32>,
    next_handle: u64,
    /// Live directory enumerations (separate handle space from files).
    finds: HashMap<u64, FindSearch>,
    next_find: u64,
    pub exit_code: Option<u32>,
    /// Called with every console write as it happens (streaming). When unset
    /// (tests), output stays buffered in `emu.stdout` until `run` returns.
    console_sink: Option<Box<dyn FnMut(&[u8])>>,
    /// Whether host stdout is a TTY (drives `GetConsoleMode`).
    console_is_tty: bool,
    /// Last-error code (`GetLastError`/`SetLastError`).
    last_error: u32,
    error_mode: u32,
    console_ctrl_handlers: Vec<u64>,
    ignore_ctrl_c: bool,
    /// Guest env overrides (`SetEnvironmentVariableW`); host env is never
    /// mutated, reads fall through to it.
    env_overlay: HashMap<String, Option<String>>,
    /// Fiber-local slots (`FlsAlloc` family; index+1 is the DWORD value so
    /// slot 0 stays a valid index).
    fls: Vec<Option<u64>>,
    fls_count: usize,
    tls_values: Vec<u64>,
    tls_slots: Vec<bool>,
    /// argv0 as typed (for `GetModuleFileNameW` approximation).
    prog: String,
    /// QPC epoch.
    start: std::time::Instant,
    /// Cached `GetEnvironmentStringsW` block (0 = not built yet).
    env_block: u64,
    threads: Vec<GuestThread>,
    current_thread: usize,
    next_thread_id: u32,
    switch_requested: bool,
    critical_sections: HashMap<u64, (usize, u32)>,
    srw_locks: HashMap<u64, SrwLock>,
    once_states: HashMap<u64, OnceState>,
    wsa_startups: u32,
    sockets: HashMap<u64, (u32, u32, u32)>,
    crypto_contexts: HashSet<u64>,
    semaphores: HashMap<u64, GuestSemaphore>,
    power_notifications: HashMap<u64, (u64, u64)>,
    module_handles: HashMap<String, u64>,
    tls_template: Option<TlsDir>,
    first_unsupported_index: usize,
    unsupported_end_index: usize,
    dynamic_shims: HashMap<(u64, String), u64>,
    dynamic_unsupported: HashSet<usize>,
    probe: bool,
}

impl Runner {
    pub fn new(img: &PeImage, fs: WinFs) -> Result<Self, String> {
        Self::with_argv(img, fs, "<exe>", &[])
    }

    /// `prog` is argv0 as typed; `args` are the guest arguments.
    pub fn with_argv(
        img: &PeImage,
        fs: WinFs,
        prog: &str,
        args: &[String],
    ) -> Result<Self, String> {
        Self::with_argv_inner(img, fs, prog, args, false)
    }

    /// Diagnostic-only execution: unknown imports are bound to fail-on-call
    /// thunks so a large PE can reveal its first actual startup blocker.
    pub fn with_argv_probe(
        img: &PeImage,
        fs: WinFs,
        prog: &str,
        args: &[String],
    ) -> Result<Self, String> {
        Self::with_argv_inner(img, fs, prog, args, true)
    }

    fn with_argv_inner(
        img: &PeImage,
        fs: WinFs,
        prog: &str,
        args: &[String],
        probe: bool,
    ) -> Result<Self, String> {
        if let Some(first) = img.unsupported.first().filter(|_| !probe) {
            return Err(format!(
                "unsupported import: {}!{} (image came from lenient load; refusing to execute)",
                first.dll, first.func
            ));
        }
        let mut emu = Emu::new(img)?;
        emu.alloc_cmdline(prog, args)?;
        setup_tls(&mut emu, img)?;
        let static_tls = if img.tls.is_some() {
            let array = emu.read_u64(emu.gs_base + crate::pe::emu::TEB_TLS_OFF)?;
            vec![emu.read_u64(array)?]
        } else {
            Vec::new()
        };
        let main_cpu = emu.cpu_state();
        let mut module_handles = HashMap::new();
        for dll in ["KERNEL32.DLL", "KERNELBASE.DLL", "NTDLL.DLL"].into_iter()
            .chain(img.imports.iter().chain(img.stubs.iter()).chain(img.unsupported.iter())
                .map(|imp| imp.dll.as_str())) {
            let name = dll.to_ascii_uppercase();
            let next = 0x6000_0000u64 + module_handles.len() as u64 * 0x1000;
            module_handles.entry(name).or_insert(next);
        }
        let mut runner = Self {
            emu,
            fs,
            handles: HashMap::new(),
            null_handles: HashSet::new(),
            handle_flags: HashMap::new(),
            next_handle: 0x100,
            finds: HashMap::new(),
            next_find: 0x10000,
            exit_code: None,
            console_sink: None,
            console_is_tty: std::io::stdout().is_terminal(),
            last_error: 0,
            error_mode: 0,
            console_ctrl_handlers: Vec::new(),
            ignore_ctrl_c: false,
            env_overlay: HashMap::new(),
            fls: Vec::new(),
            fls_count: 0,
            tls_values: static_tls,
            tls_slots: vec![true; usize::from(img.tls.is_some())],
            prog: prog.to_string(),
            start: std::time::Instant::now(),
            env_block: 0,
            threads: vec![GuestThread {
                id: 1,
                handle: 0,
                open: false,
                cpu: main_cpu,
                last_error: 0,
                fls: Vec::new(),
                tls_values: Vec::new(),
                state: ThreadState::Runnable,
                critical_depth: 0,
                tls_resume: None,
                tls_next: 0,
                tls_reason: 0,
                once_frames: Vec::new(),
            }],
            current_thread: 0,
            next_thread_id: 2,
            switch_requested: false,
            critical_sections: HashMap::new(),
            srw_locks: HashMap::new(),
            once_states: HashMap::new(),
            wsa_startups: 0,
            sockets: HashMap::new(),
            crypto_contexts: HashSet::new(),
            semaphores: HashMap::new(),
            power_notifications: HashMap::new(),
            module_handles,
            tls_template: img.tls.clone(),
            first_unsupported_index: img.imports.len() + img.stubs.len(),
            unsupported_end_index: img.imports.len() + img.stubs.len() + img.unsupported.len(),
            dynamic_shims: HashMap::new(),
            dynamic_unsupported: HashSet::new(),
            probe,
        };
        runner.begin_tls_callbacks(0, 1)?; // DLL_PROCESS_ATTACH
        runner.emu.restore_cpu(&runner.threads[0].cpu);
        Ok(runner)
    }

    pub fn with_console_sink(mut self, sink: Box<dyn FnMut(&[u8])>) -> Self {
        self.console_sink = Some(sink);
        self
    }

    /// Hexdump around RIP, the stack top, and likely pointer regs.
    fn post_mortem(&self) -> String {
        let mut s = String::from("\n-- post-mortem --");
        let hex = |va: u64, n: usize| {
            self.emu
                .read_bytes(va, n)
                .map(|b| {
                    b.iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<Vec<_>>()
                        .join("")
                })
                .unwrap_or_else(|_| "(unmapped)".to_string())
        };
        s.push_str(&format!(
            "\nrip-32: {}",
            hex(self.emu.rip.wrapping_sub(32), 64)
        ));
        s.push_str(&format!("\nrsp:    {}", hex(self.emu.rsp(), 64)));
        for (name, r) in [("rsi", 6), ("rdi", 7), ("r14", 14), ("r15", 15)] {
            s.push_str(&format!("\n{name}:    {}", hex(self.emu.regs[r], 64)));
        }
        s.push_str(&format!("\nr15+64: {}", hex(self.emu.regs[15] + 64, 192)));
        for (i, x) in self.emu.xmm.iter().enumerate() {
            s.push_str(&format!("\nxmm{i}:   {:032x}", x & 0xFFFF_FFFF_FFFF_FFFF));
        }
        s
    }

    /// Emit guest console bytes: buffer (returned by `run`) + stream to sink.
    fn console_out(&mut self, data: &[u8]) {
        self.emu.stdout.extend_from_slice(data);
        if let Some(sink) = self.console_sink.as_mut() {
            sink(data);
        }
    }

    fn thread_tls(&mut self) -> Result<u64, String> {
        use crate::pe::emu::{TEB_PEB_OFF, TEB_SELF_OFF, TEB_SIZE, TEB_TLS_OFF};
        let Some(tls) = &self.tls_template else {
            return Ok(0);
        };
        let data = self
            .emu
            .heap_alloc((tls.raw_data.len() + tls.zero_fill as usize).max(8));
        let array = self.emu.heap_alloc(64 * 8);
        let teb = self.emu.heap_alloc(TEB_SIZE);
        if data == 0 || array == 0 || teb == 0 {
            return Err("out of guest memory for thread TLS".to_string());
        }
        self.emu.write_bytes(data, &tls.raw_data)?;
        self.emu.write_u64(array, data)?;
        self.emu.write_u64(teb + TEB_SELF_OFF, teb)?;
        self.emu.write_u64(teb + TEB_TLS_OFF, array)?;
        let peb = self.emu.read_u64(self.emu.gs_base + TEB_PEB_OFF)?;
        self.emu.write_u64(teb + TEB_PEB_OFF, peb)?;
        Ok(teb)
    }

    fn module_handle(&self, raw: &str) -> Option<u64> {
        let name = raw.rsplit(['\\', '/']).next().unwrap_or(raw);
        let exe = self.prog.rsplit(['\\', '/']).next().unwrap_or(&self.prog);
        if name.eq_ignore_ascii_case(exe) { return Some(self.emu.base); }
        self.module_handles.get(&name.to_ascii_uppercase()).copied()
    }

    fn load_module(&mut self, raw: &str) -> Option<u64> {
        if let Some(handle) = self.module_handle(raw) { return Some(handle); }
        let name = raw.rsplit(['\\', '/']).next().unwrap_or(raw).to_ascii_uppercase();
        if !matches!(name.as_str(), "POWRPROF.DLL") { return None; }
        let handle = 0x6000_0000u64 + self.module_handles.len() as u64 * 0x1000;
        self.module_handles.insert(name, handle);
        Some(handle)
    }

    fn read_guest_ansi(&self, address: u64) -> Result<String, String> {
        let mut bytes = Vec::new();
        for offset in 0..260u64 {
            let byte = self.emu.read_u8(address + offset)?;
            if byte == 0 { return Ok(String::from_utf8_lossy(&bytes).to_string()); }
            bytes.push(byte);
        }
        Err("guest ANSI string is too long".to_string())
    }

    fn begin_tls_callbacks(&mut self, index: usize, reason: u32) -> Result<(), String> {
        if self.tls_template.as_ref().is_none_or(|tls| tls.callbacks.is_empty()) {
            return Ok(());
        }
        let thread = &mut self.threads[index];
        thread.tls_resume = Some(thread.cpu.clone());
        thread.tls_next = 0;
        thread.tls_reason = reason;
        self.advance_tls_callback(index)
    }

    fn advance_tls_callback(&mut self, index: usize) -> Result<(), String> {
        let thread = &mut self.threads[index];
        let resume = thread.tls_resume.as_ref()
            .ok_or_else(|| "TLS callback returned without pending invocation".to_string())?;
        let callbacks = &self.tls_template.as_ref().unwrap().callbacks;
        if let Some(&rva) = callbacks.get(thread.tls_next) {
            thread.tls_next += 1;
            thread.cpu = self.emu.tls_callback_cpu(
                resume, self.emu.base + u64::from(rva), self.emu.base, thread.tls_reason,
            )?;
        } else {
            thread.cpu = thread.tls_resume.take().unwrap();
        }
        Ok(())
    }

    fn start_once_callback(
        &mut self,
        index: usize,
        once: u64,
        callback: u64,
        parameter: u64,
        context_out: u64,
    ) -> Result<(), String> {
        self.emu.read_u8(callback)?;
        let resume = if index == self.current_thread {
            self.emu.cpu_state()
        } else {
            self.threads[index].cpu.clone()
        };
        let rsp = resume.regs[4].checked_sub(0x30)
            .ok_or_else(|| "one-time callback stack underflow".to_string())?;
        let callback_context = self.emu.heap_alloc(8);
        if callback_context == 0 { return Err("out of guest memory for one-time context".to_string()); }
        self.emu.write_u64(callback_context, 0)?;
        self.emu.write_u64(rsp, crate::pe::emu::INIT_ONCE_RETURN_SENTINEL)?;
        let mut cpu = resume.clone();
        cpu.regs[1] = once;
        cpu.regs[2] = parameter;
        cpu.regs[8] = callback_context;
        cpu.regs[4] = rsp;
        cpu.rip = callback;
        self.threads[index].once_frames.push(OnceFrame {
            resume, once, context_out, callback_context,
        });
        self.threads[index].cpu = cpu;
        self.threads[index].state = ThreadState::Runnable;
        self.once_states.insert(once, OnceState::Running { owner: index, split: false });
        if index == self.current_thread {
            self.emu.restore_cpu(&self.threads[index].cpu);
        }
        Ok(())
    }

    fn finish_once_callback(&mut self) -> Result<(), String> {
        let success = self.emu.regs[0] != 0;
        let index = self.current_thread;
        let frame = self.threads[index].once_frames.pop()
            .ok_or_else(|| "one-time callback returned without pending call".to_string())?;
        let context = self.emu.read_u64(frame.callback_context)?;
        let success = success && context & 3 == 0;
        if !success && context & 3 != 0 { self.last_error = 87; }
        self.emu.restore_cpu(&frame.resume);
        let return_address = self.emu.pop_u64()?;
        self.emu.rip = return_address;
        self.emu.regs[0] = u64::from(success);
        if success {
            self.emu.write_u64(frame.once, context | 2)?;
            if frame.context_out != 0 { self.emu.write_u64(frame.context_out, context)?; }
            self.once_states.insert(frame.once, OnceState::Complete { context });
            for thread in &mut self.threads {
                if let ThreadState::WaitingInitOnce { once, context_out, .. } = thread.state {
                    if once == frame.once {
                        if context_out != 0 { self.emu.write_u64(context_out, context)?; }
                        let return_address = self.emu.read_u64(thread.cpu.regs[4])?;
                        thread.cpu.regs[4] += 8;
                        thread.cpu.rip = return_address;
                        thread.cpu.regs[0] = 1;
                        thread.state = ThreadState::Runnable;
                    }
                }
            }
        } else {
            self.once_states.remove(&frame.once);
            if let Some(waiter) = self.threads.iter().position(|thread|
                matches!(thread.state, ThreadState::WaitingInitOnce { once, .. } if once == frame.once)) {
                let (callback, parameter, context_out) = match self.threads[waiter].state {
                    ThreadState::WaitingInitOnce { callback, parameter, context_out, .. } =>
                        (callback, parameter, context_out),
                    _ => unreachable!(),
                };
                self.start_once_callback(waiter, frame.once, callback, parameter, context_out)?;
            }
        }
        Ok(())
    }

    fn srw_acquire(&mut self, address: u64, shared: bool, try_only: bool) -> bool {
        let lock = self.srw_locks.entry(address).or_default();
        let waiting_writer = self.threads.iter().any(|thread| matches!(thread.state,
            ThreadState::WaitingSrw { address: at, shared: false } if at == address));
        let available = lock.exclusive.is_none()
            && (shared && !waiting_writer || !shared && lock.shared.is_empty());
        if available {
            if shared {
                *lock.shared.entry(self.current_thread).or_default() += 1;
            } else {
                lock.exclusive = Some(self.current_thread);
            }
            true
        } else {
            if !try_only {
                self.threads[self.current_thread].state = ThreadState::WaitingSrw { address, shared };
            }
            false
        }
    }

    fn srw_release(&mut self, address: u64, shared: bool) -> Result<(), String> {
        let lock = self.srw_locks.get_mut(&address)
            .ok_or_else(|| "SRW lock was not acquired".to_string())?;
        if shared {
            let depth = lock.shared.get_mut(&self.current_thread)
                .ok_or_else(|| "SRW shared lock owned by another thread".to_string())?;
            *depth -= 1;
            if *depth == 0 { lock.shared.remove(&self.current_thread); }
        } else if lock.exclusive == Some(self.current_thread) {
            lock.exclusive = None;
        } else {
            return Err("SRW exclusive lock owned by another thread".to_string());
        }
        if lock.exclusive.is_none() && lock.shared.is_empty() {
            // Give the oldest waiter its lock, or a run of shared waiters.
            for index in 0..self.threads.len() {
                if let ThreadState::WaitingSrw { address: at, shared: waiter_shared } = self.threads[index].state {
                    if at != address { continue; }
                    if waiter_shared {
                        *lock.shared.entry(index).or_default() += 1;
                        self.threads[index].state = ThreadState::Runnable;
                    } else if lock.shared.is_empty() {
                        lock.exclusive = Some(index);
                        self.threads[index].state = ThreadState::Runnable;
                        break;
                    } else {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn reacquire_condition_locks(&mut self) {
        for index in 0..self.threads.len() {
            let (address, kind) = match self.threads[index].state {
                ThreadState::WaitingConditionLock { lock, kind } => (lock, kind),
                _ => continue,
            };
            let acquired = match kind {
                CondLock::Critical => {
                    if self.critical_sections.contains_key(&address) { false }
                    else {
                        self.critical_sections.insert(address, (index, 1));
                        self.threads[index].critical_depth += 1;
                        true
                    }
                }
                CondLock::SrwExclusive => {
                    let srw = self.srw_locks.entry(address).or_default();
                    if srw.exclusive.is_some() || !srw.shared.is_empty() { false }
                    else { srw.exclusive = Some(index); true }
                }
                CondLock::SrwShared => {
                    let srw = self.srw_locks.entry(address).or_default();
                    if srw.exclusive.is_some() { false }
                    else { *srw.shared.entry(index).or_default() += 1; true }
                }
            };
            if acquired { self.threads[index].state = ThreadState::Runnable; }
        }
    }

    fn refresh_waiters(&mut self) -> Result<(), String> {
        let now = Instant::now();
        let finished: Vec<u64> = self
            .threads
            .iter()
            .filter_map(|thread| {
                if matches!(thread.state, ThreadState::Finished) {
                    Some(thread.handle)
                } else {
                    None
                }
            })
            .collect();
        for thread in &mut self.threads {
            let result = match &thread.state {
                ThreadState::WaitingThread { handle, deadline } => {
                    if finished.contains(handle) {
                        Some(0)
                    } else if deadline.is_some_and(|at| now >= at) {
                        Some(258)
                    } else {
                        None
                    }
                }
                ThreadState::WaitingSemaphore { handle, deadline } => {
                    if !self.semaphores.contains_key(handle) {
                        thread.last_error = 6;
                        Some(u32::MAX as u64)
                    } else if deadline.is_some_and(|at| now >= at) {
                        Some(258)
                    } else {
                        None
                    }
                }
                ThreadState::WaitingAddress {
                    address,
                    expected,
                    deadline,
                } => {
                    if self.emu.read_bytes(*address, expected.len())? != *expected {
                        Some(1)
                    } else if deadline.is_some_and(|at| now >= at) {
                        Some(0)
                    } else {
                        None
                    }
                }
                ThreadState::Sleeping(at) if now >= *at => Some(0),
                ThreadState::WaitingCondition { deadline, .. }
                    if deadline.is_some_and(|at| now >= at) => Some(0),
                _ => None,
            };
            if let Some(value) = result {
                if let ThreadState::WaitingCondition { lock, kind, .. } = thread.state {
                    thread.last_error = 1460;
                    thread.cpu.regs[0] = 0;
                    thread.state = ThreadState::WaitingConditionLock { lock, kind };
                    continue;
                }
                if value == 0 && matches!(thread.state, ThreadState::WaitingAddress { .. }) {
                    thread.last_error = 1460; // ERROR_TIMEOUT
                }
                thread.cpu.regs[0] = value;
                thread.state = ThreadState::Runnable;
            }
        }
        self.reacquire_condition_locks();
        Ok(())
    }

    fn schedule(&mut self) -> Result<(), String> {
        let current = self.current_thread;
        self.threads[current].cpu = self.emu.cpu_state();
        self.threads[current].last_error = self.last_error;
        self.threads[current].fls = std::mem::take(&mut self.fls);
        self.threads[current].tls_values = std::mem::take(&mut self.tls_values);
        loop {
            self.refresh_waiters()?;
            let next = (1..=self.threads.len())
                .map(|offset| (current + offset) % self.threads.len())
                .find(|&idx| matches!(self.threads[idx].state, ThreadState::Runnable));
            if let Some(next) = next {
                self.current_thread = next;
                self.emu.restore_cpu(&self.threads[next].cpu);
                self.last_error = self.threads[next].last_error;
                self.fls = std::mem::take(&mut self.threads[next].fls);
                self.tls_values = std::mem::take(&mut self.threads[next].tls_values);
                self.switch_requested = false;
                return Ok(());
            }
            let deadline = self
                .threads
                .iter()
                .filter_map(|thread| match &thread.state {
                    ThreadState::WaitingThread { deadline, .. }
                    | ThreadState::WaitingSemaphore { deadline, .. }
                    | ThreadState::WaitingAddress { deadline, .. } => *deadline,
                ThreadState::Sleeping(at) => Some(*at),
                ThreadState::WaitingCondition { deadline, .. } => *deadline,
                    _ => None,
                })
                .min();
            let Some(deadline) = deadline else {
                return Err("guest threads are deadlocked".to_string());
            };
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(1)),
            );
        }
    }

    /// Complete an NT syscall: report status + bytes through IoStatusBlock
    /// (Status u32 at +0, Information u64 at +8). Returns status for RAX.
    fn nt_finish(&mut self, iosb: u64, status: u64, written: u64) -> Result<u64, String> {
        if iosb != 0 {
            self.emu.write_u32(iosb, status as u32)?;
            self.emu.write_u64(iosb + 8, written)?;
        }
        Ok(status)
    }

    fn alloc_handle(&mut self, path: String, offset: u64) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(h, FileHandle { path, offset });
        h
    }

    fn is_open_handle(&self, handle: u64) -> bool {
        handle <= 2 || self.handles.contains_key(&handle)
            || self.null_handles.contains(&handle) || self.semaphores.contains_key(&handle)
            || self.sockets.contains_key(&handle)
            || self.threads.iter().any(|thread| thread.handle == handle && thread.open)
    }

    /// (attrs, byte length) for an open handle's path (dirs: 0x10, len 0).
    /// Std handles (0/1/2) report as character devices with no size.
    fn file_attrs_len_by_handle(&self, h: u64) -> Result<(u32, u64), String> {
        if h <= 2 {
            return Ok((0x40, 0));
        }
        let fh = self
            .handles
            .get(&h)
            .ok_or_else(|| format!("bad file handle 0x{h:016x}"))?;
        if self.fs.is_dir(&fh.path) {
            return Ok((0x10, 0));
        }
        let data = self
            .fs
            .read_file(&fh.path)
            .map_err(|e| format!("stat: {e}"))?;
        Ok((0x80, data.len() as u64))
    }

    /// Byte length for an open handle's path.
    fn file_len_by_handle(&self, h: u64) -> Result<u64, String> {
        self.file_attrs_len_by_handle(h).map(|(_, len)| len)
    }

    /// Names matching a FindFirst pattern: the exact path itself (file or
    /// dir) when the pattern has no wildcards, else the directory listing
    /// filtered by `*`/`?` (case-insensitive). Sorted (list_dir order).
    /// Missing paths yield no matches (caller reports FILE_NOT_FOUND).
    fn find_matches(&self, raw: &str, dirs_only: bool) -> Result<Vec<FindEntry>, String> {
        let cut = raw.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0);
        let (dir, mut pat) = if cut == 0 {
            (self.fs.cwd(), raw)
        } else {
            (raw[..cut - 1].to_string(), &raw[cut..])
        };
        if pat.is_empty() {
            pat = "*";
        }
        if !pat.contains(['*', '?']) {
            let full = if dir.is_empty() {
                pat.to_string()
            } else {
                format!("{}\\{pat}", dir.trim_end_matches(['\\', '/']))
            };
            if dirs_only && self.fs.is_file(&full) {
                return Ok(Vec::new());
            }
            if self.fs.is_dir(&full) {
                return Ok(vec![FindEntry {
                    name: pat.to_string(),
                    attrs: 0x10,
                    len: 0,
                }]);
            }
            if self.fs.is_file(&full) {
                let len = self
                    .fs
                    .read_file(&full)
                    .map(|v| v.len() as u64)
                    .unwrap_or(0);
                return Ok(vec![FindEntry {
                    name: pat.to_string(),
                    attrs: 0x80,
                    len,
                }]);
            }
            return Ok(Vec::new());
        }
        let names = match self.fs.list_dir(&dir) {
            Ok(n) => n,
            Err(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for name in names {
            if !wildcard_match(pat, &name) {
                continue;
            }
            let full = format!("{}\\{name}", dir.trim_end_matches(['\\', '/']));
            if self.fs.is_dir(&full) {
                out.push(FindEntry {
                    name,
                    attrs: 0x10,
                    len: 0,
                });
            } else if self.fs.is_file(&full) {
                if dirs_only {
                    continue;
                }
                let len = self
                    .fs
                    .read_file(&full)
                    .map(|v| v.len() as u64)
                    .unwrap_or(0);
                out.push(FindEntry {
                    name,
                    attrs: 0x80,
                    len,
                });
            }
        }
        Ok(out)
    }

    /// WIN32_FIND_DATAW (592 bytes) at `va`: attrs, zero times, sizes,
    /// UTF-16 name (truncated to 259 + NUL), empty alternate name.
    fn fill_find_data(&mut self, va: u64, name: &str, attrs: u32, len: u64) -> Result<(), String> {
        let mut b = vec![0u8; 592];
        b[0..4].copy_from_slice(&attrs.to_le_bytes());
        b[28..32].copy_from_slice(&((len >> 32) as u32).to_le_bytes());
        b[32..36].copy_from_slice(&(len as u32).to_le_bytes());
        let units: Vec<u16> = name.encode_utf16().take(259).collect();
        for (i, u) in units.iter().enumerate() {
            b[44 + i * 2..44 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        self.emu.write_bytes(va, &b)?;
        Ok(())
    }

    pub fn run(mut self) -> Result<(u32, WinFs, Vec<u8>), String> {
        let trace = std::env::var("WINCLI_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false);
        let dump = std::env::var("WINCLI_DUMP_ON_ERROR")
            .map(|v| v == "1")
            .unwrap_or(false);
        let mut last_steps = 0u64;
        let mut slice_steps = 0u32;
        loop {
            let rip = self.emu.rip;
            let step_res = match self.emu.step() {
                Err(e) => {
                    let mut msg = format!("{e} (rip=0x{rip:016x} {})", self.emu.regs_summary());
                    if dump {
                        msg.push_str(&self.post_mortem());
                    }
                    return Err(msg);
                }
                Ok(r) => r,
            };
            match step_res {
                StepResult::Continue => {}
                StepResult::TlsReturned => {
                    self.advance_tls_callback(self.current_thread)?;
                    self.emu.restore_cpu(&self.threads[self.current_thread].cpu);
                    continue;
                }
                StepResult::InitOnceReturned => {
                    self.finish_once_callback()?;
                    continue;
                }
                StepResult::Halted(code) => {
                    if self.current_thread != 0 {
                        self.threads[self.current_thread].state = ThreadState::Finished;
                        self.schedule()?;
                        slice_steps = 0;
                        continue;
                    }
                    if trace {
                        eprintln!("[trace] halt exit={code} steps={}", self.emu.step_count());
                    }
                    let fs = std::mem::replace(&mut self.fs, WinFs::new());
                    return Ok((code, fs, std::mem::take(&mut self.emu.stdout)));
                }
                StepResult::CalledStub { index } => {
                    if trace {
                        let imp = &self.emu.imports[index];
                        eprintln!(
                            "[trace] +{} call {}!{}",
                            self.emu.step_count() - last_steps,
                            imp.dll,
                            imp.func
                        );
                        last_steps = self.emu.step_count();
                    }
                    if self.do_shim(index)? {
                        if trace {
                            eprintln!(
                                "[trace] halt exit={} steps={}",
                                self.exit_code.unwrap(),
                                self.emu.step_count()
                            );
                        }
                        let code = self.exit_code.unwrap();
                        let fs = std::mem::replace(&mut self.fs, WinFs::new());
                        return Ok((code, fs, std::mem::take(&mut self.emu.stdout)));
                    }
                }
            }
            slice_steps += 1;
            let blocked = !matches!(
                self.threads[self.current_thread].state,
                ThreadState::Runnable
            );
            if blocked
                || self.switch_requested
                || (slice_steps >= 10_000
                    && self.threads.len() > 1
                    && self.threads[self.current_thread].critical_depth == 0)
            {
                self.schedule()?;
                slice_steps = 0;
            }
        }
    }

    /// Execute the shim for import `index`. Returns Ok(true) if halted.
    fn do_shim(&mut self, index: usize) -> Result<bool, String> {
        let imp = self.emu.imports[index].clone();
        if (index >= self.first_unsupported_index && index < self.unsupported_end_index)
            || self.dynamic_unsupported.contains(&index) {
            let detail = if imp.func == "LoadLibraryExA" && self.emu.regs[1] != 0 {
                format!(" requested={:?}", self.read_guest_ansi(self.emu.regs[1])?)
            } else { String::new() };
            return Err(format!(
                "unsupported import reached: {}!{}{} (rcx=0x{:x} rdx=0x{:x} r8=0x{:x} r9=0x{:x} stack4=0x{:x} stack5=0x{:x} stack6=0x{:x})",
                imp.dll, imp.func, detail, self.emu.regs[1], self.emu.regs[2], self.emu.regs[8],
                self.emu.regs[9], self.emu.stack_arg(4).unwrap_or(0),
                self.emu.stack_arg(5).unwrap_or(0), self.emu.stack_arg(6).unwrap_or(0),
            ));
        }
        let rcx = self.emu.regs[1];
        let rdx = self.emu.regs[2];
        let r8 = self.emu.regs[8];
        let r9 = self.emu.regs[9];
        let name = imp.func.as_str();

        // Helper to return to caller: pop return address into RIP.
        macro_rules! ret_bool {
            ($v:expr) => {{
                self.emu.regs[0] = $v;
                let ra = self.emu.pop_u64()?;
                if ra == crate::pe::emu::ENTRY_SENTINEL {
                    self.exit_code = Some((self.emu.regs[0] & 0xFFFF_FFFF) as u32);
                    return Ok(true);
                }
                self.emu.rip = ra;
                return Ok(false);
            }};
        }
        macro_rules! ret_halt {
            ($code:expr) => {{
                self.exit_code = Some($code);
                return Ok(true);
            }};
        }
        // Fail-stub: loadable but unimplemented. Sets LastError and returns
        // the failure value — explicit at the call site, never silent success.
        macro_rules! stub {
            ($v:expr) => {{
                self.last_error = 120; // ERROR_CALL_NOT_IMPLEMENTED
                ret_bool!($v);
            }};
        }

        match name {
            "CryptAcquireContextW" => {
                let flags = self.emu.stack_arg(4).unwrap_or(0) as u32;
                // An ephemeral default RSA provider is sufficient for the
                // random-byte path. Persistent key containers are not modeled.
                if rcx == 0 || rdx != 0 || r8 != 0 || r9 != 1
                    || flags & 0xF000_0000 != 0xF000_0000
                {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                let handle = self.next_handle;
                self.next_handle += 1;
                self.crypto_contexts.insert(handle);
                self.emu.write_u64(rcx, handle)?;
                ret_bool!(1);
            }
            "CryptGenRandom" => {
                if !self.crypto_contexts.contains(&rcx) {
                    self.last_error = 6; // ERROR_INVALID_HANDLE
                    ret_bool!(0);
                }
                let n = (rdx & 0xFFFF_FFFF) as usize;
                if n > 1_048_576 || (n != 0 && r8 == 0) {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                let mut bytes = vec![0u8; n];
                use std::io::Read;
                if std::fs::File::open("/dev/urandom")
                    .and_then(|mut file| file.read_exact(&mut bytes)).is_err()
                {
                    self.last_error = 31; // ERROR_GEN_FAILURE
                    ret_bool!(0);
                }
                if n != 0 { self.emu.write_bytes(r8, &bytes)?; }
                ret_bool!(1);
            }
            "CryptReleaseContext" => {
                if rdx != 0 || !self.crypto_contexts.remove(&rcx) {
                    self.last_error = if rdx != 0 { 87 } else { 6 };
                    ret_bool!(0);
                }
                ret_bool!(1);
            }
            "#8" | "#14" => ret_bool!((rcx as u32).swap_bytes() as u64),
            "#9" | "#15" => ret_bool!((rcx as u16).swap_bytes() as u64),
            "#111" => ret_bool!(self.last_error as u64), // WSAGetLastError
            "#112" => { // WSASetLastError
                self.last_error = rcx as u32;
                ret_bool!(0);
            }
            "#115" => { // WSAStartup, x64 WSADATA is 408 bytes
                let version = rcx as u16;
                if version & 0xff == 0 || version & 0xff > 2 || version >> 8 > 2 {
                    ret_bool!(10092); // WSAVERNOTSUPPORTED
                }
                if rdx == 0 { ret_bool!(10014); } // WSAEFAULT
                self.emu.write_bytes(rdx, &[0u8; 408])?;
                self.emu.write_u16(rdx, version)?;
                self.emu.write_u16(rdx + 2, 0x202)?;
                self.emu.write_bytes(rdx + 16, b"WinSock 2.0\0")?;
                self.emu.write_bytes(rdx + 273, b"Running\0")?;
                self.wsa_startups = self.wsa_startups.saturating_add(1);
                ret_bool!(0);
            }
            "#116" => { // WSACleanup
                if self.wsa_startups == 0 {
                    self.last_error = 10093; // WSANOTINITIALISED
                    ret_bool!(u32::MAX as u64); // SOCKET_ERROR
                }
                self.wsa_startups -= 1;
                if self.wsa_startups == 0 {
                    for handle in self.sockets.keys() { self.handle_flags.remove(handle); }
                    self.sockets.clear();
                }
                ret_bool!(0);
            }
            "#23" => { // socket(af, type, protocol)
                if self.wsa_startups == 0 {
                    self.last_error = 10093; // WSANOTINITIALISED
                    ret_bool!(INVALID_HANDLE);
                }
                let family = rcx as u32;
                let kind = rdx as u32;
                let protocol = r8 as u32;
                let error = if !matches!(family, 2 | 23) { // AF_INET / AF_INET6
                    Some(10047) // WSAEAFNOSUPPORT
                } else if !matches!(kind, 1 | 2) { // SOCK_STREAM / SOCK_DGRAM
                    Some(10044) // WSAESOCKTNOSUPPORT
                } else if protocol != 0 && protocol != if kind == 1 { 6 } else { 17 } {
                    Some(10043) // WSAEPROTONOSUPPORT
                } else {
                    None
                };
                if let Some(code) = error {
                    self.last_error = code;
                    ret_bool!(INVALID_HANDLE);
                }
                let handle = self.next_handle;
                self.next_handle += 1;
                self.sockets.insert(handle, (family, kind, protocol));
                ret_bool!(handle);
            }
            "#3" => { // closesocket
                if self.wsa_startups == 0 {
                    self.last_error = 10093; // WSANOTINITIALISED
                    ret_bool!(u32::MAX as u64);
                }
                if self.sockets.remove(&rcx).is_none() {
                    self.last_error = 10038; // WSAENOTSOCK
                    ret_bool!(u32::MAX as u64);
                }
                self.handle_flags.remove(&rcx);
                ret_bool!(0);
            }
            "#7" => { // getsockopt
                if self.wsa_startups == 0 {
                    self.last_error = 10093; // WSANOTINITIALISED
                    ret_bool!(u32::MAX as u64);
                }
                let Some(&(family, kind, protocol)) = self.sockets.get(&rcx) else {
                    self.last_error = 10038; // WSAENOTSOCK
                    ret_bool!(u32::MAX as u64);
                };
                let len_ptr = self.emu.stack_arg(4)?;
                if r9 == 0 || len_ptr == 0 {
                    self.last_error = 10014; // WSAEFAULT
                    ret_bool!(u32::MAX as u64);
                }
                if rdx as u32 != 0xffff { // SOL_SOCKET
                    self.last_error = 10022; // WSAEINVAL
                    ret_bool!(u32::MAX as u64);
                }
                let value = match r8 as u32 {
                    0x2005 => { // SO_PROTOCOL_INFOW: WSAPROTOCOL_INFOW
                        let mut info = vec![0u8; 628];
                        // This virtual socket does not promise IFS handles.
                        info[44..48].copy_from_slice(&1u32.to_le_bytes()); // base protocol chain
                        info[72..76].copy_from_slice(&2u32.to_le_bytes()); // iVersion
                        info[76..80].copy_from_slice(&family.to_le_bytes());
                        info[88..92].copy_from_slice(&kind.to_le_bytes());
                        let actual_protocol = if protocol == 0 {
                            if kind == 1 { 6u32 } else { 17u32 }
                        } else { protocol };
                        info[92..96].copy_from_slice(&actual_protocol.to_le_bytes());
                        info
                    }
                    0x1008 => kind.to_le_bytes().to_vec(), // SO_TYPE
                    _ => {
                        self.last_error = 10042; // WSAENOPROTOOPT
                        ret_bool!(u32::MAX as u64);
                    }
                };
                if self.emu.read_u32(len_ptr)? < value.len() as u32 {
                    self.last_error = 10014; // WSAEFAULT
                    ret_bool!(u32::MAX as u64);
                }
                self.emu.write_bytes(r9, &value)?;
                self.emu.write_u32(len_ptr, value.len() as u32)?;
                ret_bool!(0);
            }
            "PowerRegisterSuspendResumeNotification" => {
                if rcx != 2 || rdx == 0 || r8 == 0 { // DEVICE_NOTIFY_CALLBACK
                    ret_bool!(87); // ERROR_INVALID_PARAMETER
                }
                let callback = self.emu.read_u64(rdx)?;
                let context = self.emu.read_u64(rdx + 8)?;
                if callback == 0 || self.emu.read_u8(callback).is_err() {
                    ret_bool!(87);
                }
                let handle = self.next_handle;
                self.next_handle += 1;
                self.power_notifications.insert(handle, (callback, context));
                self.emu.write_u64(r8, handle)?;
                ret_bool!(0); // ERROR_SUCCESS
            }
            "PowerUnregisterSuspendResumeNotification" => {
                ret_bool!(if self.power_notifications.remove(&rcx).is_some() { 0 } else { 6 });
            }
            "ExitProcess" => {
                ret_halt!((rcx & 0xFFFF_FFFF) as u32);
            }
            "GetStdHandle" => {
                let h = match rcx as u32 {
                    STD_INPUT_HANDLE => 0u64,
                    STD_OUTPUT_HANDLE => 1u64,
                    STD_ERROR_HANDLE => 2u64,
                    _ => 1u64, // unknown id -> stdout (lenient, still deterministic)
                };
                ret_bool!(h);
            }
            "WriteFile" => {
                // BOOL WriteFile(HANDLE, LPCVOID, DWORD n, LPDWORD written, LPOVERLAPPED)
                let h = rcx;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let p_written = r9;
                let overlapped = self.emu.stack_arg(4).unwrap_or(0);
                let _ = overlapped;
                if n > 16 * 1024 * 1024 {
                    ret_bool!(0);
                }
                let data = self.emu.read_bytes(buf, n)?;
                if self.null_handles.contains(&h) {
                    if p_written != 0 { self.emu.write_u32(p_written, n as u32)?; }
                    ret_bool!(1);
                }
                if h == 1 || h == 2 {
                    self.console_out(&data);
                    if p_written != 0 {
                        self.emu.write_u32(p_written, n as u32)?;
                    }
                    ret_bool!(1);
                } else if h == 0 {
                    // writing to stdin handle fails
                    ret_bool!(0);
                } else {
                    let fh = self
                        .handles
                        .get_mut(&h)
                        .ok_or_else(|| format!("WriteFile: invalid handle 0x{h:016x}"))?;
                    // read-modify-write at offset
                    let mut content = self
                        .fs
                        .read_file(&fh.path)
                        .map_err(|e| format!("WriteFile: {e}"))?;
                    let off = fh.offset as usize;
                    if off > content.len() {
                        content.resize(off, 0);
                    }
                    if off + n > content.len() {
                        content.resize(off + n, 0);
                    }
                    content[off..off + n].copy_from_slice(&data);
                    fh.offset += n as u64;
                    let p = fh.path.clone();
                    self.fs
                        .write_file(&p, content)
                        .map_err(|e| format!("WriteFile: {e}"))?;
                    if p_written != 0 {
                        self.emu.write_u32(p_written, n as u32)?;
                    }
                    ret_bool!(1);
                }
            }
            "CreateFileW" => {
                // HANDLE CreateFileW(path, access, share, sec, creation, flags, template)
                // Win x64: arg1-4 in rcx,rdx,r8,r9; creation is the 5th arg,
                // i.e. the first stack slot (index 4).
                let p_path = rcx;
                let creation = self.emu.stack_arg(4).unwrap_or(OPEN_EXISTING as u64) as u32;
                let flags = self.emu.stack_arg(5).unwrap_or(0) as u32;
                let path = self.emu.read_utf16(p_path)?;
                if std::env::var("WINCLI_TRACE").as_deref() == Ok("1") {
                    eprintln!("[trace] CreateFileW path={path:?} creation={creation} flags=0x{flags:x}");
                }
                if is_nul_device(&path) && creation == OPEN_EXISTING {
                    let handle = self.next_handle;
                    self.next_handle += 1;
                    self.null_handles.insert(handle);
                    ret_bool!(handle);
                }
                let exists = self.fs.exists(&path);
                let is_dir = self.fs.is_dir(&path);
                // Directories open only with FILE_FLAG_BACKUP_SEMANTICS.
                let dir_handle_ok = is_dir && (flags & 0x02000000) != 0;
                match creation {
                    CREATE_NEW => {
                        if exists {
                            self.last_error = 183; // ERROR_ALREADY_EXISTS
                            ret_bool!(INVALID_HANDLE);
                        }
                        if is_dir {
                            self.last_error = 5; // ERROR_ACCESS_DENIED
                            ret_bool!(INVALID_HANDLE);
                        }
                        self.fs
                            .write_file(&path, Vec::new())
                            .map_err(|e| format!("CreateFileW: {e}"))?;
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    CREATE_ALWAYS => {
                        if is_dir {
                            self.last_error = 5; // ERROR_ACCESS_DENIED
                            ret_bool!(INVALID_HANDLE);
                        }
                        self.fs
                            .write_file(&path, Vec::new())
                            .map_err(|e| format!("CreateFileW: {e}"))?;
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    OPEN_EXISTING => {
                        if !exists || (is_dir && !dir_handle_ok) {
                            self.last_error = if !exists { 2 } else { 5 };
                            ret_bool!(INVALID_HANDLE);
                        }
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    OPEN_ALWAYS => {
                        if is_dir && !dir_handle_ok {
                            self.last_error = 5; // ERROR_ACCESS_DENIED
                            ret_bool!(INVALID_HANDLE);
                        }
                        if !exists {
                            self.fs
                                .write_file(&path, Vec::new())
                                .map_err(|e| format!("CreateFileW: {e}"))?;
                        }
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    TRUNCATE_EXISTING => {
                        if !exists || is_dir {
                            self.last_error = if !exists { 2 } else { 5 };
                            ret_bool!(INVALID_HANDLE);
                        }
                        self.fs
                            .write_file(&path, Vec::new())
                            .map_err(|e| format!("CreateFileW: {e}"))?;
                        let h = self.alloc_handle(path, 0);
                        ret_bool!(h);
                    }
                    _ => {
                        self.last_error = 87; // ERROR_INVALID_PARAMETER
                        ret_bool!(INVALID_HANDLE);
                    }
                }
            }
            "ReadFile" => {
                let h = rcx;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let p_read = r9;
                if n > 16 * 1024 * 1024 {
                    ret_bool!(0);
                }
                if self.null_handles.contains(&h) {
                    if p_read != 0 { self.emu.write_u32(p_read, 0)?; }
                    ret_bool!(1);
                }
                if h == 0 {
                    // stdin: no input -> 0 bytes
                    if p_read != 0 {
                        self.emu.write_u32(p_read, 0)?;
                    }
                    ret_bool!(1);
                } else if h == 1 || h == 2 {
                    ret_bool!(0);
                } else {
                    let fh = self
                        .handles
                        .get_mut(&h)
                        .ok_or_else(|| format!("ReadFile: invalid handle 0x{h:016x}"))?;
                    let content = self
                        .fs
                        .read_file(&fh.path)
                        .map_err(|e| format!("ReadFile: {e}"))?;
                    let off = fh.offset as usize;
                    let avail = content.len().saturating_sub(off.min(content.len()));
                    let k = avail.min(n);
                    self.emu.write_bytes(buf, &content[off..off + k])?;
                    fh.offset += k as u64;
                    if p_read != 0 {
                        self.emu.write_u32(p_read, k as u32)?;
                    }
                    ret_bool!(1);
                }
            }
            "CloseHandle" => {
                let h = rcx;
                if self.handle_flags.get(&h).is_some_and(|flags| flags & 2 != 0) {
                    self.last_error = 6;
                    ret_bool!(0);
                }
                if h <= 2 {
                    ret_bool!(1);
                }
                if self.handles.remove(&h).is_some() {
                    self.handle_flags.remove(&h);
                    ret_bool!(1);
                } else if self.null_handles.remove(&h) {
                    self.handle_flags.remove(&h);
                    ret_bool!(1);
                } else if self.semaphores.remove(&h).is_some() {
                    self.handle_flags.remove(&h);
                    ret_bool!(1);
                } else if let Some(thread) = self
                    .threads
                    .iter_mut()
                    .find(|thread| thread.handle == h && thread.open)
                {
                    thread.open = false;
                    self.handle_flags.remove(&h);
                    ret_bool!(1);
                } else {
                    self.last_error = 6;
                    ret_bool!(0);
                }
            }
            "CreateDirectoryW" => {
                let path = self.emu.read_utf16(rcx)?;
                match self.fs.mkdir_one(&path) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            "RemoveDirectoryW" => {
                let path = self.emu.read_utf16(rcx)?;
                match self.fs.rmdir(&path) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            "DeleteFileW" => {
                let path = self.emu.read_utf16(rcx)?;
                match self.fs.delete_file(&path) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            "MoveFileW" => {
                let src = self.emu.read_utf16(rcx)?;
                let dst = self.emu.read_utf16(rdx)?;
                match self.fs.move_path(&src, &dst) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            "CopyFileW" => {
                let src = self.emu.read_utf16(rcx)?;
                let dst = self.emu.read_utf16(rdx)?;
                let fail_if_exists = (r8 & 0xFFFF_FFFF) != 0;
                match self.fs.copy_file(&src, &dst, fail_if_exists) {
                    Ok(()) => ret_bool!(1),
                    Err(_) => ret_bool!(0),
                }
            }
            "GetCommandLineW" => {
                if self.emu.cmdline_va == 0 {
                    ret_bool!(0);
                }
                ret_bool!(self.emu.cmdline_va);
            }
            "GetCommandLineA" => {
                if self.emu.cmdline_ansi_va == 0 {
                    ret_bool!(0);
                }
                ret_bool!(self.emu.cmdline_ansi_va);
            }
            "GetConsoleMode" => {
                // Succeeds for console handles iff host stdout is a TTY,
                // mirroring Windows (pipes fail) so `--color=auto` works.
                let h = rcx;
                let p_mode = rdx;
                if (h == 1 || h == 2) && self.console_is_tty {
                    // ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT
                    if p_mode != 0 {
                        self.emu.write_u32(p_mode, 0x3)?;
                    }
                    ret_bool!(1);
                } else {
                    ret_bool!(0);
                }
            }
            "SetConsoleMode" => {
                // Modes are not tracked (byte-pipe model); succeed for
                // console handles so VT-capable guests proceed.
                let h = rcx;
                ret_bool!(u64::from(h == 1 || h == 2));
            }
            "WriteConsoleW" => {
                // BOOL WriteConsoleW(HANDLE, LPCVOID, DWORD nchars, LPDWORD, LPVOID)
                let h = rcx;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let p_written = r9;
                if h != 1 && h != 2 {
                    ret_bool!(0);
                }
                if n > 4 * 1024 * 1024 {
                    ret_bool!(0);
                }
                let mut units = Vec::with_capacity(n);
                for i in 0..n {
                    units.push(self.emu.read_u16(buf + i as u64 * 2)?);
                }
                let text = String::from_utf16_lossy(&units);
                self.console_out(text.as_bytes());
                if p_written != 0 {
                    self.emu.write_u32(p_written, n as u32)?;
                }
                ret_bool!(1);
            }
            "GetConsoleOutputCP" => {
                // UTF-8, matching our transcode behavior.
                ret_bool!(65001);
            }
            "SetConsoleTextAttribute" => {
                // Colors are passed through as bytes; nothing to store.
                let h = rcx;
                ret_bool!(u64::from(h == 1 || h == 2));
            }
            "ReadConsoleW" => {
                // Line-buffered read from host stdin, UTF-8 decoded lossily.
                let h = rcx;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let p_read = r9;
                if h != 0 || n == 0 {
                    ret_bool!(0);
                }
                let line = read_stdin_line().unwrap_or_default();
                let wide: Vec<u16> = line.encode_utf16().take(n).collect();
                for (i, u) in wide.iter().enumerate() {
                    self.emu.write_u16(buf + i as u64 * 2, *u)?;
                }
                if p_read != 0 {
                    self.emu.write_u32(p_read, wide.len() as u32)?;
                }
                ret_bool!(1);
            }
            "GetLastError" => {
                ret_bool!(self.last_error as u64);
            }
            "SetLastError" => {
                self.last_error = (rcx & 0xFFFF_FFFF) as u32;
                ret_bool!(0);
            }
            "GetProcessHeap" => {
                ret_bool!(0x400);
            }
            "HeapAlloc" => {
                let n = (r8 & 0xFFFF_FFFF) as usize;
                if n > 256 * 1024 * 1024 {
                    self.last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
                    ret_bool!(0);
                }
                let p = self.emu.heap_alloc(n);
                if p == 0 {
                    self.last_error = 8;
                }
                ret_bool!(p);
            }
            "HeapFree" => {
                // No-op by design (bump allocator, no reuse). NULL fails.
                ret_bool!(u64::from(r8 != 0));
            }
            "HeapReAlloc" => {
                let old = r8;
                let n = (r9 & 0xFFFF_FFFF) as usize;
                if old == 0 {
                    let p = self.emu.heap_alloc(n);
                    if p == 0 {
                        self.last_error = 8;
                    }
                    ret_bool!(p);
                }
                let have = self.emu.heap_size_of(old) as usize;
                let p = self.emu.heap_alloc(n);
                if p == 0 {
                    self.last_error = 8;
                    ret_bool!(0);
                }
                let k = have.min(n);
                if k > 0 {
                    let data = self.emu.read_bytes(old, k)?;
                    self.emu.write_bytes(p, &data)?;
                }
                ret_bool!(p);
            }
            "HeapSize" => {
                ret_bool!(self.emu.heap_size_of(r8));
            }
            "VirtualAlloc" => {
                // Only anywhere-mapping (addr NULL); protection ignored;
                // backed by the same 16-aligned bump region (rounded to pages).
                if rcx != 0 {
                    self.last_error = 487; // ERROR_INVALID_ADDRESS
                    ret_bool!(0);
                }
                let n = ((rdx + 0xFFF) & !0xFFF) as usize;
                if n == 0 || n > 256 * 1024 * 1024 {
                    self.last_error = 8;
                    ret_bool!(0);
                }
                // page-align the bump cursor, then allocate
                let p = self.emu.heap_alloc_aligned(n, 0x1000);
                if p == 0 {
                    self.last_error = 8;
                }
                ret_bool!(p);
            }
            "VirtualFree" => {
                // No-op by design (no reuse). MEM_RELEASE needs size 0.
                let ftype = (r8 & 0xFFFF_FFFF) as u32;
                if ftype == 0x8000 && rdx != 0 {
                    self.last_error = 87; // ERROR_INVALID_PARAMETER
                    ret_bool!(0);
                }
                ret_bool!(1);
            }
            "VirtualProtect" => {
                if r9 != 0 {
                    self.emu.write_u32(r9, 0x04)?; // PAGE_READWRITE
                }
                ret_bool!(1);
            }
            "GetEnvironmentStringsW" => {
                if self.env_block == 0 {
                    // Host environment passed through as UTF-16 K=V blocks.
                    let mut units: Vec<u16> = Vec::new();
                    let mut vars: Vec<(String, String)> = std::env::vars_os()
                        .filter_map(|(k, v)| {
                            Some((k.to_str()?.to_string(), v.to_str()?.to_string()))
                        })
                        .collect();
                    vars.sort();
                    for (k, v) in &vars {
                        for c in format!("{k}={v}").encode_utf16() {
                            units.push(c);
                        }
                        units.push(0);
                    }
                    units.push(0);
                    let bytes = units.len() * 2;
                    let va = self.emu.heap_alloc(bytes);
                    if va == 0 {
                        self.last_error = 8;
                        ret_bool!(0);
                    }
                    for (i, u) in units.iter().enumerate() {
                        self.emu.write_u16(va + i as u64 * 2, *u)?;
                    }
                    self.env_block = va;
                }
                ret_bool!(self.env_block);
            }
            "FreeEnvironmentStringsW" => {
                ret_bool!(1);
            }
            "GetEnvironmentVariableW" => {
                let name = self.emu.read_utf16(rcx)?;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let val = match self.env_overlay.get(&name) {
                    Some(Some(v)) => Some(v.clone()),
                    Some(None) => None,
                    None => std::env::var(&name).ok(),
                };
                let val = match val {
                    Some(v) => v,
                    None => {
                        self.last_error = 203; // ENVIRONMENT_VARIABLE_NOT_FOUND
                        ret_bool!(0);
                    }
                };
                let units: Vec<u16> = val.encode_utf16().chain(std::iter::once(0)).collect();
                if n == 0 {
                    ret_bool!(units.len() as u64);
                }
                if n < units.len() {
                    ret_bool!(units.len() as u64);
                }
                for (i, u) in units.iter().enumerate() {
                    self.emu.write_u16(buf + i as u64 * 2, *u)?;
                }
                ret_bool!((units.len() - 1) as u64);
            }
            "SetEnvironmentVariableW" => {
                let name = self.emu.read_utf16(rcx)?;
                if rdx == 0 {
                    self.env_overlay.insert(name, None);
                } else {
                    let val = self.emu.read_utf16(rdx)?;
                    self.env_overlay.insert(name, Some(val));
                }
                ret_bool!(1);
            }
            "GetStartupInfoW" => {
                // STARTUPINFOW (104 bytes): std handles + USESTDHANDLES.
                let si = rcx;
                self.emu.write_bytes(si, &[0u8; 104])?;
                self.emu.write_u32(si, 104)?; // cb
                self.emu.write_u32(si + 60, 0x100)?; // STARTF_USESTDHANDLES
                self.emu.write_u64(si + 80, 0)?; // hStdInput
                self.emu.write_u64(si + 88, 1)?; // hStdOutput
                self.emu.write_u64(si + 96, 2)?; // hStdError
                ret_bool!(0);
            }
            "GetModuleHandleW" => {
                if rcx == 0 {
                    ret_bool!(self.emu.base); // main image
                }
                let name = self.emu.read_utf16(rcx)?;
                if let Some(handle) = self.module_handle(&name) { ret_bool!(handle); }
                self.last_error = 126; // MOD_NOT_FOUND
                ret_bool!(0);
            }
            "GetModuleHandleA" => {
                if rcx == 0 {
                    ret_bool!(self.emu.base);
                }
                let name = self.read_guest_ansi(rcx)?;
                if let Some(handle) = self.module_handle(&name) { ret_bool!(handle); }
                self.last_error = 126;
                ret_bool!(0);
            }
            "GetModuleHandleExW" => {
                // (flags, name, &h): all three fit in registers.
                if rcx == 0 && rdx == 0 {
                    if r8 != 0 {
                        self.emu.write_u64(r8, self.emu.base)?;
                    }
                    ret_bool!(1);
                }
                let handle = if rcx & 4 != 0 {
                    if rdx >= self.emu.base && rdx < self.emu.base + self.emu.mem.len() as u64 {
                        Some(self.emu.base)
                    } else { None }
                } else if rdx != 0 {
                    self.module_handle(&self.emu.read_utf16(rdx)?)
                } else { Some(self.emu.base) };
                if let Some(handle) = handle {
                    if r8 != 0 { self.emu.write_u64(r8, handle)?; }
                    ret_bool!(1);
                }
                self.last_error = 126;
                ret_bool!(0);
            }
            "LoadLibraryA" | "LoadLibraryExA" | "LoadLibraryExW" => {
                let extended = name != "LoadLibraryA";
                if rcx == 0 || (extended && (rdx != 0 || r8 & !0x800 != 0)) {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                let module = if name == "LoadLibraryExW" {
                    self.emu.read_utf16(rcx)?
                } else {
                    self.read_guest_ansi(rcx)?
                };
                if let Some(handle) = self.load_module(&module) { ret_bool!(handle); }
                self.last_error = 126;
                ret_bool!(0);
            }
            "FreeLibrary" => {
                if self.module_handles.values().any(|&handle| handle == rcx) {
                    ret_bool!(1);
                }
                self.last_error = 6;
                ret_bool!(0);
            }
            "GetModuleFileNameW" => {
                // Approximation: argv0 as typed (host path), truncated to n.
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                if n == 0 {
                    ret_bool!(0);
                }
                let units: Vec<u16> = self.prog.encode_utf16().collect();
                let k = units.len().min(n);
                for (i, u) in units.iter().take(k).enumerate() {
                    self.emu.write_u16(buf + i as u64 * 2, *u)?;
                }
                ret_bool!(k as u64);
            }
            "GetSystemInfo" => {
                // SYSTEM_INFO (48 bytes, x64 layout).
                let si = rcx;
                let ncpu = std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(4);
                self.emu.write_u16(si, 9)?; // AMD64
                self.emu.write_u16(si + 2, 0)?;
                self.emu.write_u32(si + 4, 0x1000)?; // page
                self.emu.write_u64(si + 8, 0x10000)?; // min app
                self.emu.write_u64(si + 16, 0x7FFE_FFFF)?; // max app
                self.emu.write_u64(si + 24, 0xFF)?; // affinity mask
                self.emu.write_u32(si + 32, ncpu)?;
                self.emu.write_u32(si + 36, 8664)?; // PROCESSOR_AMD_X8664
                self.emu.write_u32(si + 40, 65536)?; // allocation granularity
                self.emu.write_u16(si + 44, 6)?; // level
                self.emu.write_u16(si + 46, 0)?; // revision
                ret_bool!(0);
            }
            "GetSystemTimeAsFileTime" => {
                // 100ns ticks since 1601-01-01.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let ticks = now.as_secs() * 10_000_000
                    + now.subsec_nanos() as u64 / 100
                    + 11_644_473_600 * 10_000_000;
                self.emu.write_u32(rcx, (ticks & 0xFFFF_FFFF) as u32)?;
                self.emu.write_u32(rcx + 4, (ticks >> 32) as u32)?;
                ret_bool!(0);
            }
            "QueryPerformanceFrequency" => {
                if rcx != 0 {
                    self.emu.write_u64(rcx, 10_000_000)?;
                }
                ret_bool!(1);
            }
            "QueryPerformanceCounter" => {
                let ticks = self.start.elapsed().as_nanos() as u64 / 100;
                if rcx != 0 {
                    self.emu.write_u64(rcx, ticks)?;
                }
                ret_bool!(1);
            }
            "GetCurrentProcess" => {
                ret_bool!(0xFFFF_FFFF_FFFF_FFFF);
            }
            "GetCurrentThread" => {
                ret_bool!(0xFFFF_FFFF_FFFF_FFFE);
            }
            "GetCurrentProcessId" => {
                ret_bool!(std::process::id() as u64);
            }
            "GetCurrentThreadId" => {
                ret_bool!(self.threads[self.current_thread].id as u64);
            }
            "TlsAlloc" => {
                let slot = self.tls_slots.iter().position(|&used| !used);
                let index = if let Some(index) = slot {
                    self.tls_slots[index] = true;
                    index
                } else if self.tls_slots.len() < 1088 {
                    let index = self.tls_slots.len();
                    self.tls_slots.push(true);
                    self.tls_values.push(0);
                    for (i, thread) in self.threads.iter_mut().enumerate() {
                        if i != self.current_thread { thread.tls_values.push(0); }
                    }
                    index
                } else {
                    self.last_error = 8;
                    ret_bool!(u32::MAX as u64);
                };
                ret_bool!(index as u64);
            }
            "TlsFree" => {
                let index = rcx as usize;
                if !self.tls_slots.get(index).copied().unwrap_or(false)
                    || (index == 0 && self.tls_template.is_some()) {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                self.tls_slots[index] = false;
                self.tls_values[index] = 0;
                for (i, thread) in self.threads.iter_mut().enumerate() {
                    if i != self.current_thread { thread.tls_values[index] = 0; }
                }
                ret_bool!(1);
            }
            "TlsGetValue" => {
                let index = rcx as usize;
                if !self.tls_slots.get(index).copied().unwrap_or(false) {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                self.last_error = 0;
                ret_bool!(self.tls_values[index]);
            }
            "TlsSetValue" => {
                let index = rcx as usize;
                if !self.tls_slots.get(index).copied().unwrap_or(false) {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                self.tls_values[index] = rdx;
                ret_bool!(1);
            }
            "GetFileType" => {
                if rcx <= 2 || self.null_handles.contains(&rcx) {
                    ret_bool!(2); // FILE_TYPE_CHAR
                } else if self.handles.contains_key(&rcx) {
                    ret_bool!(1); // FILE_TYPE_DISK
                } else {
                    self.last_error = 6; // INVALID_HANDLE
                    ret_bool!(0);
                }
            }
            "GetCurrentDirectoryW" => {
                // (nBufferLength, lpBuffer): length first.
                let n = (rcx & 0xFFFF_FFFF) as usize;
                let buf = rdx;
                let units: Vec<u16> = self
                    .fs
                    .cwd()
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                if n == 0 {
                    ret_bool!(units.len() as u64);
                }
                if n < units.len() {
                    ret_bool!(units.len() as u64);
                }
                for (i, u) in units.iter().enumerate() {
                    self.emu.write_u16(buf + i as u64 * 2, *u)?;
                }
                ret_bool!((units.len() - 1) as u64);
            }
            "GetFullPathNameW" => {
                // (path, n, buf, filepart): all in registers.
                let raw = self.emu.read_utf16(rcx)?;
                let n = (rdx & 0xFFFF_FFFF) as usize;
                let buf = r8;
                let p_filepart = r9;
                let disp = self
                    .fs
                    .normalize(&raw)
                    .map(|p| p.display())
                    .unwrap_or(raw.clone());
                let units: Vec<u16> = disp.encode_utf16().chain(std::iter::once(0)).collect();
                if p_filepart != 0 {
                    self.emu.write_u64(p_filepart, 0)?;
                }
                if n == 0 {
                    ret_bool!(units.len() as u64);
                }
                if n < units.len() {
                    ret_bool!(units.len() as u64);
                }
                for (i, u) in units.iter().enumerate() {
                    self.emu.write_u16(buf + i as u64 * 2, *u)?;
                }
                ret_bool!((units.len() - 1) as u64);
            }
            "GetFinalPathNameByHandleW" => {
                // (hFile, buf, n, flags): canonical path + NUL. Flags
                // ignored (no volumes; always the DOS path).
                let h = rcx;
                let buf = rdx;
                let n = (r8 & 0xFFFF_FFFF) as usize;
                let path = self
                    .handles
                    .get(&h)
                    .map(|fh| fh.path.clone())
                    .ok_or_else(|| format!("bad file handle 0x{h:016x}"))?;
                let units: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
                if n == 0 {
                    ret_bool!(units.len() as u64);
                }
                if n < units.len() {
                    ret_bool!(units.len() as u64);
                }
                for (i, u) in units.iter().enumerate() {
                    self.emu.write_u16(buf + i as u64 * 2, *u)?;
                }
                ret_bool!((units.len() - 1) as u64);
            }
            "GetFileAttributesW" => {
                let path = self.emu.read_utf16(rcx)?;
                if self.fs.is_dir(&path) {
                    ret_bool!(0x10);
                } else if self.fs.is_file(&path) {
                    ret_bool!(0x80);
                } else {
                    // INVALID_FILE_ATTRIBUTES alone is ambiguous to callers;
                    // directory walkers use the accompanying last-error value
                    // to distinguish a missing entry from other failures.
                    self.last_error = 2; // ERROR_FILE_NOT_FOUND
                    ret_bool!(0xFFFF_FFFF);
                }
            }
            "GetFileSizeEx" => {
                // (hFile, lpFileSize): u64 length at lpFileSize, nonzero on ok.
                let h = rcx;
                let p_size = rdx;
                let len = self.file_len_by_handle(h)?;
                self.emu.write_u64(p_size, len)?;
                ret_bool!(1);
            }
            "GetFileInformationByHandle" => {
                // BY_HANDLE_FILE_INFORMATION (52 bytes): attrs, 3×FILETIME,
                // volume serial, size high/low, links, index high/low.
                // Times are zero (documented simplification).
                let h = rcx;
                let info = rdx;
                let (attrs, len) = self.file_attrs_len_by_handle(h)?;
                let mut b = [0u8; 52];
                b[0..4].copy_from_slice(&attrs.to_le_bytes());
                b[28..32].copy_from_slice(&0x5743_4C49u32.to_le_bytes());
                b[32..36].copy_from_slice(&((len >> 32) as u32).to_le_bytes());
                b[36..40].copy_from_slice(&(len as u32).to_le_bytes());
                b[40..44].copy_from_slice(&1u32.to_le_bytes());
                let id = match self.handles.get(&h) {
                    Some(fh) => self.fs.file_id(&fh.path)?,
                    None => 0,
                };
                b[44..52].copy_from_slice(&id.to_le_bytes());
                self.emu.write_bytes(info, &b)?;
                ret_bool!(1);
            }
            "GetFileInformationByHandleEx" => {
                // (hFile, class, lpInfo, size): FileBasicInfo=0 (40 bytes),
                // FileStandardInfo=1 (24 bytes). Times zero (simplification).
                let h = rcx;
                let class = (rdx & 0xFFFF_FFFF) as u32;
                let info = r8;
                let n = (r9 & 0xFFFF_FFFF) as usize;
                let (attrs, len) = self.file_attrs_len_by_handle(h)?;
                let mut b = vec![0u8; if class == 0 { 40 } else { 24 }];
                if class == 0 {
                    if n < 40 {
                        self.last_error = 122; // INSUFFICIENT_BUFFER
                        ret_bool!(0);
                    }
                    b[32..36].copy_from_slice(&attrs.to_le_bytes());
                } else if class == 1 {
                    if n < 24 {
                        self.last_error = 122;
                        ret_bool!(0);
                    }
                    b[0..8].copy_from_slice(&len.to_le_bytes());
                    b[8..16].copy_from_slice(&len.to_le_bytes());
                    b[16..20].copy_from_slice(&1u32.to_le_bytes());
                    b[20] = 0;
                    b[21] = u8::from(attrs & 0x10 != 0);
                } else {
                    return Err(format!(
                        "GetFileInformationByHandleEx: info class {class} is not supported"
                    ));
                }
                self.emu.write_bytes(info, &b)?;
                ret_bool!(1);
            }
            "FindFirstFileExW" => {
                // (pattern, level, data, op, filter, flags): enumerate
                // matches into a search handle; the first flows to data.
                // Levels 0 (standard) and 1 (basic) both work (alternate
                // name stays empty); op 0 matches names, 1 dirs only.
                let raw = self.emu.read_utf16(rcx)?;
                let level = (rdx & 0xFFFF_FFFF) as u32;
                let data = r8;
                let op = (r9 & 0xFFFF_FFFF) as u32;
                let filter = self.emu.stack_arg(4).unwrap_or(0);
                if level > 1 {
                    return Err(format!(
                        "FindFirstFileExW: info level {level} is not supported"
                    ));
                }
                if op > 1 {
                    return Err(format!("FindFirstFileExW: search op {op} is not supported"));
                }
                if filter != 0 {
                    return Err("FindFirstFileExW: search filter is not supported".to_string());
                }
                let entries = self.find_matches(&raw, op == 1)?;
                if entries.is_empty() {
                    self.last_error = 2; // FILE_NOT_FOUND
                    ret_bool!(INVALID_HANDLE);
                }
                let first = &entries[0];
                let (name, attrs, len) = (first.name.clone(), first.attrs, first.len);
                self.fill_find_data(data, &name, attrs, len)?;
                let h = self.next_find;
                self.next_find += 1;
                self.finds.insert(h, FindSearch { entries, index: 1 });
                ret_bool!(h);
            }
            "FindNextFileW" => {
                // (hFind, data): next entry, or 0 + ERROR_NO_MORE_FILES.
                let h = rcx;
                let data = rdx;
                if !self.finds.contains_key(&h) {
                    self.last_error = 6; // INVALID_HANDLE
                    ret_bool!(0);
                }
                let (name, attrs, len, done) = {
                    let s = self.finds.get_mut(&h).unwrap();
                    if s.index >= s.entries.len() {
                        (String::new(), 0, 0, true)
                    } else {
                        let e = &s.entries[s.index];
                        s.index += 1;
                        (e.name.clone(), e.attrs, e.len, false)
                    }
                };
                if done {
                    self.last_error = 18; // NO_MORE_FILES
                    ret_bool!(0);
                }
                self.fill_find_data(data, &name, attrs, len)?;
                ret_bool!(1);
            }
            "FindClose" => {
                if self.finds.remove(&rcx).is_none() {
                    self.last_error = 6; // INVALID_HANDLE
                    ret_bool!(0);
                }
                ret_bool!(1);
            }
            "MultiByteToWideChar" => {
                // (codepage, flags, src, srclen, dst, dstlen).
                // UTF-8 decode regardless of code page (documented UTF-8 world).
                let src = r8;
                let srclen = r9 as i32;
                let dst = self.emu.stack_arg(4).unwrap_or(0);
                let dstlen = self.emu.stack_arg(5).unwrap_or(0) as usize;
                let bytes = if srclen < 0 {
                    let mut v = Vec::new();
                    for i in 0..1_048_576 {
                        let b = self.emu.read_u8(src + i)?;
                        if b == 0 {
                            break;
                        }
                        v.push(b);
                    }
                    (v, true)
                } else {
                    (self.emu.read_bytes(src, srclen as usize)?, false)
                };
                let text = String::from_utf8_lossy(&bytes.0);
                let mut units: Vec<u16> = text.encode_utf16().collect();
                if bytes.1 {
                    units.push(0);
                }
                if dst == 0 {
                    ret_bool!(units.len() as u64);
                }
                if dstlen < units.len() {
                    self.last_error = 122; // INSUFFICIENT_BUFFER
                    ret_bool!(0);
                }
                for (i, u) in units.iter().enumerate() {
                    self.emu.write_u16(dst + i as u64 * 2, *u)?;
                }
                ret_bool!(units.len() as u64);
            }
            "WideCharToMultiByte" => {
                // (codepage, flags, wstr, wlen, out, outlen, def, useddef).
                // Default-char args are accepted but unused (lossy '?' path
                // is U+FFFD → UTF-8); documented simplification.
                let wstr = r8;
                let wlen = r9 as i32;
                let out = self.emu.stack_arg(4).unwrap_or(0);
                let outlen = self.emu.stack_arg(5).unwrap_or(0) as usize;
                let mut units = Vec::new();
                let nul_term: bool;
                if wlen < 0 {
                    nul_term = true;
                    for i in 0..524_288 {
                        let u = self.emu.read_u16(wstr + i as u64 * 2)?;
                        if u == 0 {
                            break;
                        }
                        units.push(u);
                    }
                } else {
                    nul_term = false;
                    for i in 0..wlen as usize {
                        units.push(self.emu.read_u16(wstr + i as u64 * 2)?);
                    }
                }
                let text = String::from_utf16_lossy(&units);
                let mut bytes = text.into_bytes();
                if nul_term {
                    bytes.push(0);
                }
                if out == 0 {
                    ret_bool!(bytes.len() as u64);
                }
                if outlen < bytes.len() {
                    self.last_error = 122;
                    ret_bool!(0);
                }
                self.emu.write_bytes(out, &bytes)?;
                ret_bool!(bytes.len() as u64);
            }
            "GetACP" | "GetOEMCP" => {
                ret_bool!(65001); // UTF-8 world, matches our transcodes
            }
            "IsValidCodePage" => {
                ret_bool!(u64::from(rcx == 65001));
            }
            "IsDebuggerPresent" => {
                ret_bool!(0);
            }
            "IsProcessorFeaturePresent" => {
                ret_bool!(u64::from(rcx == 10)); // PF_XMMI64 (SSE2, always on x64)
            }
            "lstrlenW" => {
                let mut len = 0u64;
                while len < 1_048_576 {
                    if self.emu.read_u16(rcx + len * 2)? == 0 {
                        break;
                    }
                    len += 1;
                }
                ret_bool!(len);
            }
            "EncodePointer" | "DecodePointer" => {
                // Fixed-cookie XOR (documented simplification).
                ret_bool!(rcx ^ 0x9E37_79B9_7F4A_7C15);
            }
            "ProcessPrng" => {
                // Host /dev/urandom passthrough (documented): read exactly n.
                let buf = rcx;
                let n = (rdx & 0xFFFF_FFFF) as usize;
                if n > 1 * 1024 * 1024 {
                    ret_bool!(0);
                }
                let mut f = match std::fs::File::open("/dev/urandom") {
                    Ok(f) => f,
                    Err(_) => ret_bool!(0),
                };
                let mut tmp = vec![0u8; n];
                use std::io::Read;
                match f.read_exact(&mut tmp) {
                    Ok(()) => {
                        self.emu.write_bytes(buf, &tmp)?;
                        ret_bool!(1);
                    }
                    Err(_) => ret_bool!(0),
                }
            }
            "Sleep" => {
                let millis = (rcx & 0xFFFF_FFFF) as u64;
                if millis == 0 {
                    self.switch_requested = true;
                } else {
                    self.threads[self.current_thread].state =
                        ThreadState::Sleeping(Instant::now() + Duration::from_millis(millis));
                }
                ret_bool!(0);
            }
            "SleepEx" => {
                let millis = (rcx & 0xFFFF_FFFF) as u64;
                if millis == 0 {
                    self.switch_requested = true;
                } else {
                    self.threads[self.current_thread].state =
                        ThreadState::Sleeping(Instant::now() + Duration::from_millis(millis));
                }
                ret_bool!(0);
            }
            "SwitchToThread" => {
                let has_other = self.threads.iter().enumerate().any(|(index, thread)| {
                    index != self.current_thread && matches!(thread.state, ThreadState::Runnable)
                });
                self.switch_requested = has_other;
                ret_bool!(u64::from(has_other));
            }
            "CreateThread" => {
                let flags = self.emu.stack_arg(4)? as u32;
                let id_out = self.emu.stack_arg(5)?;
                // Rust's Windows thread builder uses 0x10000 to mark the
                // requested stack size as a reservation.
                if r8 == 0 || flags & !0x10000 != 0 || self.next_thread_id == u32::MAX {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                let gs_base = match self.thread_tls() {
                    Ok(value) => value,
                    Err(_) => {
                        self.last_error = 8;
                        ret_bool!(0);
                    }
                };
                let cpu = match self.emu.thread_cpu(r8, r9, rdx as usize, gs_base) {
                    Ok(value) => value,
                    Err(_) => {
                        self.last_error = 8;
                        ret_bool!(0);
                    }
                };
                let id = self.next_thread_id;
                self.next_thread_id += 1;
                let handle = 0x8000_0000u64 + u64::from(id);
                if id_out != 0 {
                    self.emu.write_u32(id_out, id)?;
                }
                self.threads.push(GuestThread {
                    id,
                    handle,
                    open: true,
                    cpu,
                    last_error: 0,
                    fls: vec![None; self.fls_count],
                    tls_values: {
                        let mut values = vec![0; self.tls_slots.len()];
                        if self.tls_template.is_some() {
                            let array = self.emu.read_u64(gs_base + crate::pe::emu::TEB_TLS_OFF)?;
                            values[0] = self.emu.read_u64(array)?;
                        }
                        values
                    },
                    state: ThreadState::Runnable,
                    critical_depth: 0,
                    tls_resume: None,
                    tls_next: 0,
                    tls_reason: 0,
                    once_frames: Vec::new(),
                });
                self.begin_tls_callbacks(self.threads.len() - 1, 2)?; // DLL_THREAD_ATTACH
                self.switch_requested = true;
                ret_bool!(handle);
            }
            "CreateSemaphoreA" | "CreateSemaphoreW" => {
                let initial = rdx as i32;
                let maximum = r8 as i32;
                if initial < 0 || maximum <= 0 || initial > maximum {
                    self.last_error = 87; // ERROR_INVALID_PARAMETER
                    ret_bool!(0);
                }
                if rcx != 0 || r9 != 0 {
                    self.last_error = 120; // security attributes / named objects not modeled
                    ret_bool!(0);
                }
                let handle = self.next_handle;
                self.next_handle += 1;
                self.semaphores.insert(handle, GuestSemaphore { count: initial, maximum });
                ret_bool!(handle);
            }
            "ReleaseSemaphore" => {
                let release = rdx as i32;
                let Some(semaphore) = self.semaphores.get_mut(&rcx) else {
                    self.last_error = 6;
                    ret_bool!(0);
                };
                if release <= 0 || release > semaphore.maximum - semaphore.count {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                let previous = semaphore.count;
                semaphore.count += release;
                if r8 != 0 { self.emu.write_u32(r8, previous as u32)?; }
                for thread in &mut self.threads {
                    if semaphore.count == 0 { break; }
                    if matches!(thread.state, ThreadState::WaitingSemaphore { handle, .. } if handle == rcx) {
                        semaphore.count -= 1;
                        thread.cpu.regs[0] = 0; // WAIT_OBJECT_0
                        thread.state = ThreadState::Runnable;
                    }
                }
                ret_bool!(1);
            }
            "WaitForSingleObject" | "WaitForSingleObjectEx" => {
                let millis = (rdx & 0xFFFF_FFFF) as u32;
                if let Some(semaphore) = self.semaphores.get_mut(&rcx) {
                    if semaphore.count > 0 {
                        semaphore.count -= 1;
                        ret_bool!(0);
                    }
                    if millis == 0 { ret_bool!(258); }
                    let deadline = if millis == u32::MAX { None } else {
                        Instant::now().checked_add(Duration::from_millis(u64::from(millis)))
                    };
                    self.threads[self.current_thread].state = ThreadState::WaitingSemaphore {
                        handle: rcx, deadline,
                    };
                    ret_bool!(0);
                }
                let target = self
                    .threads
                    .iter()
                    .find(|thread| thread.handle == rcx && thread.open);
                match target {
                    None => {
                        self.last_error = 6;
                        ret_bool!(0xFFFF_FFFF);
                    }
                    Some(thread) if matches!(thread.state, ThreadState::Finished) => ret_bool!(0),
                    Some(_) if millis == 0 => ret_bool!(258),
                    Some(_) => {
                        let deadline = if millis == u32::MAX {
                            None
                        } else {
                            Instant::now().checked_add(Duration::from_millis(u64::from(millis)))
                        };
                        self.threads[self.current_thread].state = ThreadState::WaitingThread {
                            handle: rcx,
                            deadline,
                        };
                        ret_bool!(0);
                    }
                }
            }
            "WaitOnAddress" => {
                let size = r8 as usize;
                if !matches!(size, 1 | 2 | 4 | 8) || rcx == 0 || rdx == 0 {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                let expected = self.emu.read_bytes(rdx, size)?;
                if self.emu.read_bytes(rcx, size)? != expected {
                    ret_bool!(1);
                }
                let millis = (r9 & 0xFFFF_FFFF) as u32;
                if millis == 0 {
                    self.last_error = 1460;
                    ret_bool!(0);
                }
                let deadline = if millis == u32::MAX {
                    None
                } else {
                    Instant::now().checked_add(Duration::from_millis(u64::from(millis)))
                };
                self.threads[self.current_thread].state = ThreadState::WaitingAddress {
                    address: rcx,
                    expected,
                    deadline,
                };
                ret_bool!(1);
            }
            "WakeByAddressSingle" | "WakeByAddressAll" => {
                let single = name == "WakeByAddressSingle";
                for thread in &mut self.threads {
                    if matches!(thread.state, ThreadState::WaitingAddress { address, .. } if address == rcx)
                    {
                        thread.state = ThreadState::Runnable;
                        thread.cpu.regs[0] = 1;
                        if single {
                            break;
                        }
                    }
                }
                ret_bool!(0);
            }
            "TerminateProcess" => {
                if rcx == 0xFFFF_FFFF_FFFF_FFFF {
                    ret_halt!((rdx & 0xFFFF_FFFF) as u32);
                }
                stub!(0);
            }
            "FlsAlloc" => {
                if self.fls_count >= 128 {
                    self.last_error = 8;
                    ret_bool!(0xFFFF_FFFF);
                }
                let index = self.fls_count;
                self.fls_count += 1;
                self.fls.push(None);
                for (idx, thread) in self.threads.iter_mut().enumerate() {
                    if idx != self.current_thread {
                        thread.fls.push(None);
                    }
                }
                ret_bool!(index as u64);
            }
            "FlsFree" => {
                let i = rcx as usize;
                if i < self.fls_count {
                    self.fls[i] = None;
                    for (idx, thread) in self.threads.iter_mut().enumerate() {
                        if idx != self.current_thread {
                            thread.fls[i] = None;
                        }
                    }
                    ret_bool!(1);
                } else {
                    ret_bool!(0);
                }
            }
            "FlsGetValue" => {
                let i = rcx as usize;
                ret_bool!(self.fls.get(i).and_then(|v| *v).unwrap_or(0));
            }
            "FlsSetValue" => {
                let i = rcx as usize;
                if i < self.fls.len() {
                    self.fls[i] = Some(rdx);
                    ret_bool!(1);
                } else {
                    ret_bool!(0);
                }
            }
            "InitializeCriticalSection" | "InitializeCriticalSectionEx" | "InitializeCriticalSectionAndSpinCount" => {
                let cs = rcx;
                let spin = if name == "InitializeCriticalSection" { 0 }
                    else { (rdx & 0xFFFF_FFFF) as u32 };
                self.emu.write_bytes(cs, &[0u8; 40])?;
                self.emu.write_u32(cs, 0xFFFF_FFFF)?; // LockCount = -1
                self.emu.write_u32(cs + 32, spin)?; // SpinCount
                self.critical_sections.remove(&cs);
                ret_bool!(u64::from(name != "InitializeCriticalSection"));
            }
            "InitializeSRWLock" => {
                self.emu.write_u64(rcx, 0)?;
                self.srw_locks.insert(rcx, SrwLock::default());
                ret_bool!(0);
            }
            "AcquireSRWLockExclusive" | "AcquireSRWLockShared" => {
                self.srw_acquire(rcx, name == "AcquireSRWLockShared", false);
                ret_bool!(0);
            }
            "TryAcquireSRWLockExclusive" | "TryAcquireSRWLockShared" => {
                ret_bool!(u64::from(self.srw_acquire(rcx, name == "TryAcquireSRWLockShared", true)));
            }
            "ReleaseSRWLockExclusive" | "ReleaseSRWLockShared" => {
                self.srw_release(rcx, name == "ReleaseSRWLockShared")?;
                ret_bool!(0);
            }
            "InitializeConditionVariable" => {
                self.emu.write_u64(rcx, 0)?;
                ret_bool!(0);
            }
            "InitOnceInitialize" => {
                self.emu.write_u64(rcx, 0)?;
                self.once_states.remove(&rcx);
                ret_bool!(0);
            }
            "InitOnceBeginInitialize" => {
                if rcx == 0 || r8 == 0 || rdx & !3 != 0 {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                if rdx & 2 != 0 { // async mode needs parallel-completion arbitration
                    self.last_error = 120;
                    ret_bool!(0);
                }
                self.emu.read_u64(rcx)?;
                match self.once_states.get(&rcx) {
                    Some(OnceState::Complete { context }) => {
                        self.emu.write_u32(r8, 0)?;
                        if r9 != 0 { self.emu.write_u64(r9, *context)?; }
                        ret_bool!(1);
                    }
                    Some(OnceState::Running { .. }) if rdx & 1 != 0 => {
                        self.emu.write_u32(r8, 1)?;
                        self.last_error = 997; // ERROR_IO_PENDING
                        ret_bool!(0);
                    }
                    Some(OnceState::Running { .. }) => {
                        self.last_error = 120; // synchronous contention not yet scheduled
                        ret_bool!(0);
                    }
                    None if rdx & 1 != 0 => {
                        self.emu.write_u32(r8, 1)?;
                        self.last_error = 997;
                        ret_bool!(0);
                    }
                    None => {
                        self.once_states.insert(rcx, OnceState::Running { owner: self.current_thread, split: true });
                        self.emu.write_u32(r8, 1)?;
                        ret_bool!(1);
                    }
                }
            }
            "InitOnceComplete" => {
                if rcx == 0 || rdx & !4 != 0 || (rdx & 4 != 0 && r8 != 0) || r8 & 3 != 0 {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                if !matches!(self.once_states.get(&rcx),
                    Some(OnceState::Running { owner, split: true }) if *owner == self.current_thread) {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                if rdx & 4 != 0 { // INIT_ONCE_INIT_FAILED: allow retry
                    self.once_states.remove(&rcx);
                    self.emu.write_u64(rcx, 0)?;
                } else {
                    self.once_states.insert(rcx, OnceState::Complete { context: r8 });
                    self.emu.write_u64(rcx, r8 | 2)?;
                }
                ret_bool!(1);
            }
            "SetErrorMode" => {
                let old = self.error_mode;
                self.error_mode = (rcx as u32 & 0x8007) | (old & 0x4);
                ret_bool!(old as u64);
            }
            "SetHandleInformation" => {
                if !self.is_open_handle(rcx) {
                    self.last_error = 6;
                    ret_bool!(0);
                }
                if rdx & !3 != 0 {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                let old = self.handle_flags.get(&rcx).copied().unwrap_or(0);
                self.handle_flags.insert(rcx, (old & !(rdx as u32)) | ((r8 as u32) & rdx as u32));
                ret_bool!(1);
            }
            "GetHandleInformation" => {
                if !self.is_open_handle(rcx) {
                    self.last_error = 6;
                    ret_bool!(0);
                }
                if rdx == 0 {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                self.emu.write_u32(rdx, self.handle_flags.get(&rcx).copied().unwrap_or(0))?;
                ret_bool!(1);
            }
            "VerSetConditionMask" => {
                // One three-bit comparison field per VER_* type; use the
                // highest-priority set bit as Windows does.
                let shift = match rdx as u32 {
                    mask if mask & 0x80 != 0 => Some(21), // PRODUCT_TYPE
                    mask if mask & 0x40 != 0 => Some(18), // SUITENAME
                    mask if mask & 0x20 != 0 => Some(15), // SERVICEPACKMAJOR
                    mask if mask & 0x10 != 0 => Some(12), // SERVICEPACKMINOR
                    mask if mask & 0x08 != 0 => Some(9),  // PLATFORMID
                    mask if mask & 0x04 != 0 => Some(6),  // BUILDNUMBER
                    mask if mask & 0x02 != 0 => Some(3),  // MAJORVERSION
                    mask if mask & 0x01 != 0 => Some(0),  // MINORVERSION
                    _ => None,
                };
                ret_bool!(rcx | shift.map_or(0, |bits| (r8 & 7) << bits));
            }
            "VerifyVersionInfoW" | "VerifyVersionInfoA" => {
                if rcx == 0 || rdx == 0 || r8 == 0 {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                let size = self.emu.read_u32(rcx)?;
                if size < 276 || (rdx & 0xf0 != 0 && size < 284) {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                let mut matched = true;
                for (bit, shift, actual, offset) in [
                    (0x80u64, 21, 1u32, 282u64), // VER_PRODUCT_TYPE
                    (0x08, 9, 2, 16),             // VER_PLATFORMID
                    (0x04, 6, 19045, 12),         // VER_BUILDNUMBER
                ] {
                    if rdx & bit == 0 { continue; }
                    let requested = if bit == 0x80 {
                        self.emu.read_u8(rcx + offset)? as u32
                    } else { self.emu.read_u32(rcx + offset)? };
                    let condition = ((r8 >> shift) & 7) as u8;
                    match version_compare(actual, requested, condition) {
                        Some(true) => {},
                        Some(false) => matched = false,
                        None => { self.last_error = 87; ret_bool!(0); }
                    }
                }
                if rdx & 0x40 != 0 { // VER_SUITENAME
                    let suite = self.emu.read_u16(rcx + 280)?;
                    let condition = ((r8 >> 18) & 7) as u8;
                    matched &= match condition {
                        6 => suite == 0, // VER_AND, emulated suite mask = 0
                        7 => suite == 0, // VER_OR
                        _ => { self.last_error = 87; ret_bool!(0); }
                    };
                }
                let mut last_condition = 0u8;
                let mut last_equal = true;
                for (bit, shift, actual, offset, narrow) in [
                    (0x02u64, 3, 10u32, 4u64, false),
                    (0x01, 0, 0, 8, false),
                    (0x20, 15, 0, 276, true),
                    (0x10, 12, 0, 278, true),
                ] {
                    if rdx & bit == 0 { continue; }
                    let requested = if narrow { self.emu.read_u16(rcx + offset)? as u32 }
                        else { self.emu.read_u32(rcx + offset)? };
                    let field_condition = ((r8 >> shift) & 7) as u8;
                    let condition = if field_condition == 0 { last_condition } else { field_condition };
                    if version_compare(actual, requested, condition).is_none() {
                        self.last_error = 87;
                        ret_bool!(0);
                    }
                    last_condition = condition;
                    if actual != requested {
                        matched &= version_compare(actual, requested, condition).unwrap();
                        last_equal = false;
                        break;
                    }
                }
                if last_equal && last_condition != 0 {
                    matched &= version_compare(0, 0, last_condition).unwrap();
                }
                if matched { ret_bool!(1); }
                self.last_error = 1150; // ERROR_OLD_WIN_VERSION
                ret_bool!(0);
            }
            "SetConsoleCtrlHandler" => {
                if rcx == 0 {
                    self.ignore_ctrl_c = rdx != 0;
                    ret_bool!(1);
                }
                if rdx != 0 {
                    if self.emu.read_u8(rcx).is_err() {
                        self.last_error = 87;
                        ret_bool!(0);
                    }
                    self.console_ctrl_handlers.push(rcx);
                    ret_bool!(1);
                }
                if let Some(index) = self.console_ctrl_handlers.iter().rposition(|&h| h == rcx) {
                    self.console_ctrl_handlers.remove(index);
                    ret_bool!(1);
                }
                self.last_error = 87;
                ret_bool!(0);
            }
            "GetSystemMetrics" => {
                // SM_CLEANBOOT: this emulated system starts normally. Other
                // metrics need explicit modeling before programs rely on them.
                if rcx as u32 != 67 {
                    return Err(format!("unsupported GetSystemMetrics index {}", rcx as u32));
                }
                ret_bool!(0);
            }
            "FormatMessageA" | "FormatMessageW" => {
                let flags = rcx as u32;
                let id = r8 as u32;
                let buffer = self.emu.stack_arg(4)?;
                let size = self.emu.stack_arg(5)? as usize;
                // System messages with no insert expansion are the supported
                // subset; unsupported message sources fail explicitly.
                if flags & 0x1000 == 0 || flags & (0x400 | 0x800) != 0 {
                    self.last_error = 120;
                    ret_bool!(0);
                }
                let Some(message) = system_message(id) else {
                    self.last_error = 317; // ERROR_MR_MID_NOT_FOUND
                    ret_bool!(0);
                };
                let wide = name == "FormatMessageW";
                let mut bytes = Vec::new();
                if wide {
                    for unit in message.encode_utf16().chain(std::iter::once(0)) {
                        bytes.extend_from_slice(&unit.to_le_bytes());
                    }
                } else {
                    bytes.extend_from_slice(message.as_bytes());
                    bytes.push(0);
                }
                let count = if wide { bytes.len() / 2 - 1 } else { bytes.len() - 1 };
                if size > 64 * 1024 || count + 1 > 64 * 1024 {
                    self.last_error = 122;
                    ret_bool!(0);
                }
                if flags & 0x100 != 0 { // FORMAT_MESSAGE_ALLOCATE_BUFFER
                    let alloc_size = size.max(count + 1) * if wide { 2 } else { 1 };
                    let ptr = self.emu.heap_alloc(alloc_size);
                    if ptr == 0 { self.last_error = 8; ret_bool!(0); }
                    self.emu.write_bytes(ptr, &bytes)?;
                    self.emu.write_u64(buffer, ptr)?;
                } else {
                    if size <= count { self.last_error = 122; ret_bool!(0); }
                    self.emu.write_bytes(buffer, &bytes)?;
                }
                ret_bool!(count as u64);
            }
            "LocalFree" => {
                if rcx != 0 { self.emu.read_u8(rcx)?; }
                ret_bool!(0); // bump allocator cannot reclaim the block
            }
            "GetProcAddress" => {
                if rdx <= 0xffff {
                    self.last_error = 127; // ordinal lookup not mapped
                    ret_bool!(0);
                }
                let function = self.read_guest_ansi(rdx)?;
                if std::env::var("WINCLI_TRACE").as_deref() == Ok("1") {
                    eprintln!("[trace] dynamic lookup handle=0x{rcx:x} function={function}");
                }
                let dll = self.module_handles.iter()
                    .find_map(|(dll, &handle)| (handle == rcx).then_some(dll.clone()));
                if let Some(dll) = dll.filter(|dll| crate::pe::is_supported(dll, &function) || self.probe) {
                    let key = (rcx, function.clone());
                    let address = if let Some(&address) = self.dynamic_shims.get(&key) {
                        address
                    } else {
                        let index = self.emu.imports.len();
                        let address = self.emu.register_dynamic_shim(&dll, &function);
                        if !crate::pe::is_supported(&dll, &function) {
                            self.dynamic_unsupported.insert(index);
                        }
                        self.dynamic_shims.insert(key, address);
                        address
                    };
                    ret_bool!(address);
                }
                self.last_error = 127; // ERROR_PROC_NOT_FOUND
                ret_bool!(0);
            }
            "RtlGetVersion" => {
                let size = self.emu.read_u32(rcx)?;
                if size < 276 { ret_bool!(0xC000_000D); } // STATUS_INVALID_PARAMETER
                let len = (size as usize).min(284);
                self.emu.write_bytes(rcx, &vec![0u8; len])?;
                self.emu.write_u32(rcx, size)?;
                self.emu.write_u32(rcx + 4, 10)?;
                self.emu.write_u32(rcx + 8, 0)?;
                self.emu.write_u32(rcx + 12, 19045)?; // emulated Windows 10 baseline
                self.emu.write_u32(rcx + 16, 2)?; // VER_PLATFORM_WIN32_NT
                ret_bool!(0); // STATUS_SUCCESS
            }
            "RtlNtStatusToDosError" => {
                let code = match rcx as u32 {
                    0 => 0,
                    0xC000_0005 => 998, // ERROR_NOACCESS
                    0xC000_0008 => 6,
                    0xC000_000D => 87,
                    0xC000_0017 => 8,
                    0xC000_0022 => 5,
                    0xC000_0034 => 2,
                    0xC000_003A => 3,
                    _ => 317, // ERROR_MR_MID_NOT_FOUND
                };
                ret_bool!(code);
            }
            "InitOnceExecuteOnce" => {
                if rcx == 0 || rdx == 0 {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                self.emu.read_u64(rcx)?;
                match self.once_states.get(&rcx) {
                    Some(OnceState::Complete { context }) => {
                        if r9 != 0 { self.emu.write_u64(r9, *context)?; }
                        ret_bool!(1);
                    }
                    Some(OnceState::Running { owner, .. }) if *owner == self.current_thread => {
                        return Err("recursive InitOnceExecuteOnce on the same object".to_string());
                    }
                    Some(OnceState::Running { .. }) => {
                        self.threads[self.current_thread].state = ThreadState::WaitingInitOnce {
                            once: rcx, callback: rdx, parameter: r8, context_out: r9,
                        };
                        return Ok(false); // keep the API return address on the stack
                    }
                    None => {
                        self.start_once_callback(self.current_thread, rcx, rdx, r8, r9)?;
                        return Ok(false); // resume in the guest callback
                    }
                }
            }
            "WakeConditionVariable" | "WakeAllConditionVariable" => {
                let single = name == "WakeConditionVariable";
                for thread in &mut self.threads {
                    if let ThreadState::WaitingCondition { cv, lock, kind, .. } = thread.state {
                        if cv == rcx {
                            thread.state = ThreadState::WaitingConditionLock { lock, kind };
                            thread.cpu.regs[0] = 1;
                            if single { break; }
                        }
                    }
                }
                self.reacquire_condition_locks();
                ret_bool!(0);
            }
            "SleepConditionVariableCS" | "SleepConditionVariableSRW" => {
                let is_cs = name == "SleepConditionVariableCS";
                let kind = if is_cs { CondLock::Critical }
                    else if r9 & 1 != 0 { CondLock::SrwShared }
                    else { CondLock::SrwExclusive };
                if !is_cs && r9 & !1 != 0 {
                    self.last_error = 87;
                    ret_bool!(0);
                }
                if is_cs {
                    if !matches!(self.critical_sections.get(&rdx), Some((owner, 1)) if *owner == self.current_thread) {
                        return Err("condition wait requires an owned, nonrecursive critical section".to_string());
                    }
                    self.critical_sections.remove(&rdx);
                    self.threads[self.current_thread].critical_depth -= 1;
                    if let Some(next) = self.threads.iter().position(|thread| matches!(thread.state, ThreadState::WaitingCritical(address) if address == rdx)) {
                        self.critical_sections.insert(rdx, (next, 1));
                        self.threads[next].critical_depth += 1;
                        self.threads[next].state = ThreadState::Runnable;
                    }
                } else {
                    self.srw_release(rdx, matches!(kind, CondLock::SrwShared))?;
                }
                let millis = (r8 & 0xFFFF_FFFF) as u32;
                let deadline = if millis == u32::MAX { None }
                    else { Instant::now().checked_add(Duration::from_millis(u64::from(millis))) };
                self.threads[self.current_thread].state = ThreadState::WaitingCondition {
                    cv: rcx, lock: rdx, kind, deadline,
                };
                ret_bool!(1);
            }
            "EnterCriticalSection" => {
                match self.critical_sections.get_mut(&rcx) {
                    Some((owner, depth)) if *owner == self.current_thread => *depth += 1,
                    Some(_) => {
                        self.threads[self.current_thread].state = ThreadState::WaitingCritical(rcx);
                        ret_bool!(0);
                    }
                    None => {
                        self.critical_sections.insert(rcx, (self.current_thread, 1));
                    }
                }
                self.threads[self.current_thread].critical_depth += 1;
                ret_bool!(0);
            }
            "LeaveCriticalSection" => {
                if let Some((owner, depth)) = self.critical_sections.get_mut(&rcx) {
                    if *owner == self.current_thread {
                        *depth -= 1;
                        self.threads[self.current_thread].critical_depth -= 1;
                        if *depth == 0 {
                            self.critical_sections.remove(&rcx);
                            if let Some(next) = self.threads.iter().position(|thread| matches!(thread.state, ThreadState::WaitingCritical(address) if address == rcx)) {
                                self.critical_sections.insert(rcx, (next, 1));
                                self.threads[next].critical_depth += 1;
                                self.threads[next].state = ThreadState::Runnable;
                            }
                        }
                    }
                }
                ret_bool!(0);
            }
            "DeleteCriticalSection" => {
                self.critical_sections.remove(&rcx);
                ret_bool!(0);
            }
            "InitializeSListHead" => {
                self.emu.write_bytes(rcx, &[0u8; 16])?;
                ret_bool!(0);
            }
            "NtWriteFile" => {
                // NTSTATUS NtWriteFile(handle, event, apc, ctx, iosb, buf,
                // len, byte_offset, key). Rust std writes stdout/stderr
                // through here, not WriteFile. Synchronous only.
                const STATUS_SUCCESS: u64 = 0;
                const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
                const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002;
                let h = rcx;
                let event = rdx;
                let iosb = self.emu.stack_arg(4).unwrap_or(0);
                let buf = self.emu.stack_arg(5).unwrap_or(0);
                let n = (self.emu.stack_arg(6).unwrap_or(0) & 0xFFFF_FFFF) as usize;
                let byte_off = self.emu.stack_arg(7).unwrap_or(0);
                if event != 0 || n > 16 * 1024 * 1024 {
                    let s = self.nt_finish(iosb, STATUS_NOT_IMPLEMENTED, 0)?;
                    ret_bool!(s);
                }
                let data = self.emu.read_bytes(buf, n)?;
                if h == 1 || h == 2 {
                    self.console_out(&data);
                    let s = self.nt_finish(iosb, STATUS_SUCCESS, n as u64)?;
                    ret_bool!(s);
                }
                if h == 0 {
                    let s = self.nt_finish(iosb, STATUS_INVALID_HANDLE, 0)?;
                    ret_bool!(s);
                }
                if !self.handles.contains_key(&h) {
                    let s = self.nt_finish(iosb, STATUS_INVALID_HANDLE, 0)?;
                    ret_bool!(s);
                }
                let (path, off) = {
                    let fh = self.handles.get_mut(&h).unwrap();
                    let off = if byte_off != 0 {
                        self.emu.read_u64(byte_off)? as usize
                    } else {
                        fh.offset as usize
                    };
                    (fh.path.clone(), off)
                };
                let mut content = self
                    .fs
                    .read_file(&path)
                    .map_err(|e| format!("NtWriteFile: {e}"))?;
                if off > content.len() {
                    content.resize(off, 0);
                }
                if off + n > content.len() {
                    content.resize(off + n, 0);
                }
                content[off..off + n].copy_from_slice(&data);
                if byte_off == 0 {
                    self.handles.get_mut(&h).unwrap().offset += n as u64;
                }
                self.fs
                    .write_file(&path, content)
                    .map_err(|e| format!("NtWriteFile: {e}"))?;
                let s = self.nt_finish(iosb, STATUS_SUCCESS, n as u64)?;
                ret_bool!(s);
            }
            "NtReadFile" => {
                // NTSTATUS NtReadFile(handle, event, apc, ctx, iosb, buf,
                // len, byte_offset, key). UCRT read() comes through here,
                // not ReadFile. Synchronous only; EOF reads 0 bytes ok.
                const STATUS_SUCCESS: u64 = 0;
                const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
                const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002;
                const STATUS_END_OF_FILE: u64 = 0xC000_0011;
                let h = rcx;
                let event = rdx;
                let iosb = self.emu.stack_arg(4).unwrap_or(0);
                let buf = self.emu.stack_arg(5).unwrap_or(0);
                let n = (self.emu.stack_arg(6).unwrap_or(0) & 0xFFFF_FFFF) as usize;
                let byte_off = self.emu.stack_arg(7).unwrap_or(0);
                if event != 0 || n > 16 * 1024 * 1024 {
                    let s = self.nt_finish(iosb, STATUS_NOT_IMPLEMENTED, 0)?;
                    ret_bool!(s);
                }
                if h == 0 || !self.handles.contains_key(&h) {
                    let s = self.nt_finish(iosb, STATUS_INVALID_HANDLE, 0)?;
                    ret_bool!(s);
                }
                let (path, off) = {
                    let fh = self.handles.get_mut(&h).unwrap();
                    let off = if byte_off != 0 {
                        self.emu.read_u64(byte_off)? as usize
                    } else {
                        fh.offset as usize
                    };
                    (fh.path.clone(), off)
                };
                let content = self
                    .fs
                    .read_file(&path)
                    .map_err(|e| format!("NtReadFile: {e}"))?;
                let avail = content.len().saturating_sub(off.min(content.len()));
                let k = avail.min(n);
                self.emu.write_bytes(buf, &content[off..off + k])?;
                if byte_off == 0 {
                    self.handles.get_mut(&h).unwrap().offset += k as u64;
                }
                // EOF (k == 0): STATUS_END_OF_FILE, like the real call.
                let s = if k == 0 {
                    self.nt_finish(iosb, STATUS_END_OF_FILE, 0)?
                } else {
                    self.nt_finish(iosb, STATUS_SUCCESS, k as u64)?
                };
                ret_bool!(s);
            }
            // ---- fail-stubs: loadable, fail clearly if called ----
            "NtCreateNamedPipeFile"
            | "NtOpenFile"
            | "GetUserProfileDirectoryW"
            | "AddVectoredExceptionHandler"
            | "CompareStringOrdinal"
            | "CompareStringW"
            | "CreateFileMappingW"
            | "CreateMutexA"
            | "CreateProcessW"
            | "CreateWaitableTimerExW"
            | "DuplicateHandle"
            | "FlushFileBuffers"
            | "GetCPInfo"
            | "GetComputerNameExW"
            | "GetConsoleScreenBufferInfo"
            | "GetExitCodeProcess"
            | "GetStringTypeW"
            | "GetSystemDirectoryW"
            | "GetWindowsDirectoryW"
            | "IsThreadAFiber"
            | "LCMapStringW"
            | "MapViewOfFile"
            | "RaiseException"
            | "ReadFileEx"
            | "ReleaseMutex"
            | "RtlCaptureContext"
            | "RtlLookupFunctionEntry"
            | "RtlPcToFileHeader"
            | "RtlUnwindEx"
            | "RtlVirtualUnwind"
            | "SetFileInformationByHandle"
            | "SetFilePointerEx"
            | "SetFileTime"
            | "SetStdHandle"
            | "SetThreadStackGuarantee"
            | "SetUnhandledExceptionFilter"
            | "SetWaitableTimer"
            | "UnhandledExceptionFilter"
            | "UnmapViewOfFile"
            | "WriteFileEx" => {
                stub!(0);
            }
            other => {
                return Err(format!(
                    "unsupported import at runtime: {}!{other}",
                    imp.dll
                ));
            }
        }
    }
}

/// Wildcard match for FindFirst patterns: `*` spans any run (including
/// empty), `?` is exactly one char, ASCII case-insensitive (other chars
/// compare exactly). No DOS_STAR/DOS_QM quirks.
fn wildcard_match(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ni < n.len() {
        if pi < p.len()
            && (p[pi] == '?' || p[pi].to_ascii_lowercase() == n[ni].to_ascii_lowercase())
        {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = ni;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// One line from host stdin (no trailing newline), lossy UTF-8.
fn read_stdin_line() -> Option<String> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut line = String::new();
    match stdin.lock().read_line(&mut line) {
        Ok(0) => Some(String::new()), // EOF -> empty
        Ok(_) => {
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }
            Some(line)
        }
        Err(_) => None,
    }
}

/// Map the image's TLS template (if any): allocate the per-thread block,
/// point slot 0 of a fresh TLS array at it, publish the slot index, and
/// install a minimal TEB (+PEB) as the GS base. Slot 0 is our TLS slot;
/// process-attach callbacks run before the image entry point.
fn setup_tls(emu: &mut Emu, img: &PeImage) -> Result<(), String> {
    use crate::pe::emu::{
        PEB_IMAGEBASE_OFF, PEB_LDR_OFF, PEB_OFF, TEB_PEB_OFF, TEB_SELF_OFF, TEB_TLS_OFF,
    };
    let Some(tls) = &img.tls else {
        return Ok(());
    };
    // TLS data block: template + zero fill.
    let total = tls.raw_data.len() + tls.zero_fill as usize;
    let data_va = emu.heap_alloc(total.max(8));
    if data_va == 0 {
        return Err("out of guest memory for TLS".to_string());
    }
    emu.write_bytes(data_va, &tls.raw_data)?;
    // TLS slot array (64 entries), slot 0 -> data block.
    let array_va = emu.heap_alloc(64 * 8);
    if array_va == 0 {
        return Err("out of guest memory for TLS".to_string());
    }
    emu.write_u64(array_va, data_va)?;
    emu.write_u32(img.image_base + tls.index_rva as u64, 0)?;
    // TEB + PEB.
    let teb = emu.teb_va();
    emu.write_u64(teb + TEB_SELF_OFF, teb)?;
    emu.write_u64(teb + TEB_TLS_OFF, array_va)?;
    let peb = teb + PEB_OFF;
    emu.write_u64(teb + TEB_PEB_OFF, peb)?;
    emu.write_u64(peb + PEB_IMAGEBASE_OFF, img.image_base)?;
    // Minimal zeroed PEB_LDR_DATA (real startup reads Ldr->SsHandle).
    let ldr = emu.heap_alloc(64);
    if ldr == 0 {
        return Err("out of guest memory for PEB_LDR".to_string());
    }
    emu.write_bytes(ldr, &[0u8; 64])?;
    emu.write_u64(peb + PEB_LDR_OFF, ldr)?;
    emu.gs_base = teb;
    Ok(())
}

/// Convenience: load bytes + run with a fresh or given FS.
pub fn run_exe(data: &[u8], fs: WinFs) -> Result<(u32, WinFs, Vec<u8>), String> {
    run_exe_argv(data, fs, "<exe>", &[])
}
/// Load bytes + run with guest argv (`prog` is argv0 as typed).
pub fn run_exe_argv(
    data: &[u8],
    fs: WinFs,
    prog: &str,
    args: &[String],
) -> Result<(u32, WinFs, Vec<u8>), String> {
    let img = crate::pe::load(data)?;
    Runner::with_argv(&img, fs, prog, args)?.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::builder::{build, Asm};

    /// Probe guest: GetConsoleOutputCP==65001, SetConsoleMode/TextAttribute ok,
    /// WriteConsoleW transcodes UTF-16 (é + lone surrogate) to UTF-8.
    /// Exit 0 = all good, 1 = any step failed.
    fn console_probe() -> Vec<u8> {
        // imports: GetStdHandle WriteConsoleW GetConsoleOutputCP
        //          SetConsoleMode SetConsoleTextAttribute ExitProcess
        const GH: usize = 0;
        const WC: usize = 1;
        const CP: usize = 2;
        const SM: usize = 3;
        const TA: usize = 4;
        const XP: usize = 5;
        let mut a = Asm::new();
        // msg = U+00E9, lone surrogate U+D800, 'B', '\n'
        let mut msg = Vec::new();
        for u in [0x00E9u16, 0xD800, 0x0042, 0x000A] {
            msg.extend_from_slice(&u.to_le_bytes());
        }
        let d_msg = a.add_data(msg);
        let d_written = a.add_zeroed(8);
        let lbl_fail = a.fresh_label();
        a.sub_rsp(0x28);
        // h = GetStdHandle(-11)
        a.mov_ecx_imm(0xFFFF_FFF5);
        a.call_import(GH);
        a.mov_rspoff_rax(0x28); // save handle
                                // GetConsoleOutputCP == 65001?
        a.call_import(CP);
        a.cmp_eax_imm(65001);
        a.jnz(lbl_fail);
        // SetConsoleMode(h, 3)?
        a.mov_reg_rspoff(1, 0x28);
        a.mov_edx_imm(3);
        a.call_import(SM);
        a.test_eax_eax();
        a.jz(lbl_fail);
        // SetConsoleTextAttribute(h, 7)?
        a.mov_reg_rspoff(1, 0x28);
        a.mov_edx_imm(7);
        a.call_import(TA);
        a.test_eax_eax();
        a.jz(lbl_fail);
        // WriteConsoleW(h, msg, 4, &written, 0)?
        a.mov_reg_rspoff(1, 0x28);
        a.lea_reg_rip(2, d_msg);
        a.mov_r32_imm(8, 4);
        a.lea_reg_rip(9, d_written);
        a.xor_eax();
        a.mov_rspoff_rax(0x20);
        a.call_import(WC);
        a.test_eax_eax();
        a.jz(lbl_fail);
        a.mov_ecx_imm(0);
        a.call_import(XP);
        a.add_rsp(0x28);
        a.ret();
        a.mark(lbl_fail);
        a.mov_ecx_imm(1);
        a.call_import(XP);
        a.add_rsp(0x28);
        a.ret();
        build(
            a,
            &[
                ("KERNEL32.dll", "GetStdHandle"),
                ("KERNEL32.dll", "WriteConsoleW"),
                ("KERNEL32.dll", "GetConsoleOutputCP"),
                ("KERNEL32.dll", "SetConsoleMode"),
                ("KERNEL32.dll", "SetConsoleTextAttribute"),
                ("KERNEL32.dll", "ExitProcess"),
            ],
        )
    }

    #[test]
    fn console_shims_transcode_and_report() {
        let (code, _, out) = run_exe(&console_probe(), WinFs::new()).unwrap();
        assert_eq!(code, 0);
        // é -> C3 A9, lone surrogate -> EF BF BD (U+FFFD), then B \n
        assert_eq!(out, b"\xc3\xa9\xef\xbf\xbdB\n");
    }

    #[test]
    fn streaming_sink_sees_console_writes() {
        let exe = crate::pe::builder::hello("stream-me");
        let img = crate::pe::load(&exe).unwrap();
        let runner = Runner::new(&img, WinFs::new()).unwrap();
        // borrow dance: collect via Rc<RefCell>
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
        let seen2 = seen.clone();
        let runner = runner.with_console_sink(Box::new(move |c: &[u8]| {
            seen2.borrow_mut().extend_from_slice(c);
        }));
        let (code, _, out) = runner.run().unwrap();
        assert_eq!(code, 0);
        assert_eq!(&*seen.borrow(), b"stream-me");
        assert_eq!(out, b"stream-me");
    }

    /// Probe guest: NtWriteFile to stdout reports STATUS_SUCCESS with the
    /// byte count in IoStatusBlock; a bogus handle reports
    /// STATUS_INVALID_HANDLE. Exit 0 = all good, 1 = any step failed.
    fn nt_write_probe() -> Vec<u8> {
        // imports: NtWriteFile, ExitProcess
        const NW: usize = 0;
        const XP: usize = 1;
        let mut a = Asm::new();
        let d_msg = a.add_data(b"hello".to_vec());
        let d_iosb = a.add_zeroed(16);
        let lbl_fail = a.fresh_label();
        a.sub_rsp(0x48);
        // NtWriteFile(1, 0, 0, 0, iosb, msg, 5, NULL, 0)
        a.mov_ecx_imm(1);
        a.mov_edx_imm(0);
        a.mov_r8d_imm(0);
        a.mov_r9d_imm(0);
        a.lea_reg_rip(0, d_iosb);
        a.mov_rspoff_rax(0x20);
        a.lea_reg_rip(0, d_msg);
        a.mov_rspoff_rax(0x28);
        a.mov_r32_imm(0, 5);
        a.mov_rspoff_rax(0x30);
        a.xor_eax();
        a.mov_rspoff_rax(0x38);
        a.mov_rspoff_rax(0x40);
        a.call_import(NW);
        // RAX == STATUS_SUCCESS (0)?
        a.test_eax_eax();
        a.jnz(lbl_fail);
        // IoStatusBlock.Status == 0?
        a.mov_eax_mem_rip(d_iosb);
        a.test_eax_eax();
        a.jnz(lbl_fail);
        // bogus handle -> STATUS_INVALID_HANDLE
        a.mov_ecx_imm(0x1234);
        a.call_import(NW);
        a.cmp_eax_imm(0xC000_0008);
        a.jnz(lbl_fail);
        a.mov_ecx_imm(0);
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        a.mark(lbl_fail);
        a.mov_ecx_imm(1);
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        build(
            a,
            &[
                ("NTDLL.DLL", "NtWriteFile"),
                ("KERNEL32.DLL", "ExitProcess"),
            ],
        )
    }

    #[test]
    fn nt_write_file_console_and_status() {
        let (code, _, out) = run_exe(&nt_write_probe(), WinFs::new()).unwrap();
        assert_eq!(code, 0);
        assert_eq!(out, b"hello");
    }

    fn stat_probe() -> Vec<u8> {
        // imports: CreateFileW, GetFileSizeEx, GetFileInformationByHandleEx,
        // CloseHandle, ExitProcess. Opens C:\stat.txt (pre-seeded, 5 bytes),
        // checks size and FileStandardInfo fields, exits 0/1.
        use crate::pe::builder::{build, Asm};
        const CF: usize = 0;
        const SZ: usize = 1;
        const GI: usize = 2;
        const CH: usize = 3;
        const XP: usize = 4;
        const GIC: usize = 5;
        let mut a = Asm::new();
        let d_path = a.add_utf16("C:\\stat.txt");
        let d_sz = a.add_zeroed(8);
        let d_info = a.add_zeroed(52);
        let lbl_fail = a.fresh_label();
        a.sub_rsp(0x48);
        // handle = CreateFileW(path, GENERIC_READ, 0,0, OPEN_EXISTING=3, 0,0)
        a.lea_reg_rip(1, d_path);
        a.emit(&[0x48, 0xB8]);
        a.emit(&0x8000_0000u64.to_le_bytes());
        a.emit(&[0x48, 0x89, 0xC2]); // mov rdx,rax
        a.mov_r8d_imm(0);
        a.mov_r9d_imm(0);
        a.xor_eax();
        a.emit(&[0xC7, 0x44, 0x24, 0x20]);
        a.emit(&3u32.to_le_bytes());
        a.emit(&[0xC7, 0x44, 0x24, 0x28]);
        a.emit(&0u32.to_le_bytes());
        a.mov_rspoff_rax(0x30);
        a.call_import(CF);
        a.cmp_rax_m1();
        a.jz(lbl_fail);
        a.emit(&[0x48, 0x89, 0x44, 0x24, 0x40]); // mov [rsp+0x40],rax
                                                 // GetFileSizeEx(handle, &sz): nonzero + low dword == 5
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.lea_reg_rip(2, d_sz);
        a.call_import(SZ);
        a.test_eax_eax();
        a.jz(lbl_fail);
        a.mov_eax_mem_rip(d_sz);
        a.cmp_eax_imm(5);
        a.jnz(lbl_fail);
        // GetFileInformationByHandleEx(handle, 1, &info, 24): nonzero,
        // AllocationLength low == 5, EndOfFile low == 5, IsDirectory == 0
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.mov_edx_imm(1);
        a.lea_reg_rip(8, d_info);
        a.mov_r9d_imm(24);
        a.call_import(GI);
        a.test_eax_eax();
        a.jz(lbl_fail);
        a.mov_eax_mem_rip(d_info);
        a.cmp_eax_imm(5);
        a.jnz(lbl_fail);
        a.lea_reg_rip(0, d_info);
        a.emit(&[0x48, 0x83, 0xC0, 0x08]); // add rax,8
        a.emit(&[0x8B, 0x00]); // mov eax,[rax]
        a.cmp_eax_imm(5);
        a.jnz(lbl_fail);
        a.lea_reg_rip(0, d_info);
        a.emit(&[0x48, 0x83, 0xC0, 0x15]); // add rax,21
        a.movzx_ecx_byte_rax(); // movzx ecx,byte [rax] (zero-extends)
        a.emit(&[0x83, 0xF9, 0x00]); // cmp ecx,0
        a.jnz(lbl_fail);
        // GetFileInformationByHandle(handle, &classic52): nonzero,
        // attrs dword == 0x80, size low (at +36) == 5
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.lea_reg_rip(2, d_info);
        a.call_import(GIC);
        a.test_eax_eax();
        a.jz(lbl_fail);
        a.mov_eax_mem_rip(d_info);
        a.cmp_eax_imm(0x80);
        a.jnz(lbl_fail);
        a.lea_reg_rip(0, d_info);
        a.emit(&[0x48, 0x83, 0xC0, 0x24]); // add rax,36
        a.emit(&[0x8B, 0x00]); // mov eax,[rax]
        a.cmp_eax_imm(5);
        a.jnz(lbl_fail);
        // Volume serial and file ID must identify an actual WinFS object.
        a.lea_reg_rip(0, d_info);
        a.emit(&[0x48, 0x83, 0xC0, 0x1C]); // add rax,28
        a.emit(&[0x8B, 0x00]); // mov eax,[rax]
        a.test_eax_eax();
        a.jz(lbl_fail);
        a.lea_reg_rip(0, d_info);
        a.emit(&[0x48, 0x83, 0xC0, 0x2C]); // add rax,44
        a.emit(&[0x48, 0x8B, 0x00]); // mov rax,[rax]
        a.emit(&[0x48, 0x85, 0xC0]); // test rax,rax
        a.jz(lbl_fail);
        // CloseHandle(handle); exit 0
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.call_import(CH);
        a.mov_ecx_imm(0);
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        a.mark(lbl_fail);
        a.mov_ecx_imm(1);
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        build(
            a,
            &[
                ("KERNEL32.dll", "CreateFileW"),
                ("KERNEL32.dll", "GetFileSizeEx"),
                ("KERNEL32.dll", "GetFileInformationByHandleEx"),
                ("KERNEL32.dll", "CloseHandle"),
                ("KERNEL32.dll", "ExitProcess"),
                ("KERNEL32.dll", "GetFileInformationByHandle"),
            ],
        )
    }

    #[test]
    fn file_metadata_by_handle() {
        let mut fs = WinFs::new();
        fs.write_file("C:\\stat.txt", b"hello".to_vec()).unwrap();
        let (code, _, _) = run_exe(&stat_probe(), fs).unwrap();
        assert_eq!(code, 0);
    }

    fn missing_attributes_probe() -> Vec<u8> {
        // GetFileAttributesW must pair INVALID_FILE_ATTRIBUTES with
        // ERROR_FILE_NOT_FOUND, rather than leaking an earlier last error.
        use crate::pe::builder::{build, Asm};
        const ATTRS: usize = 0;
        const LAST_ERROR: usize = 1;
        const EXIT: usize = 2;
        let mut a = Asm::new();
        let path = a.add_utf16(r"C:\missing.txt");
        let fail = a.fresh_label();
        a.sub_rsp(0x28);
        a.lea_reg_rip(1, path);
        a.call_import(ATTRS);
        a.cmp_eax_imm(u32::MAX);
        a.jnz(fail);
        a.call_import(LAST_ERROR);
        a.cmp_eax_imm(2);
        a.jnz(fail);
        a.mov_ecx_imm(0);
        a.call_import(EXIT);
        a.mark(fail);
        a.mov_ecx_imm(1);
        a.call_import(EXIT);
        build(
            a,
            &[
                ("KERNEL32.dll", "GetFileAttributesW"),
                ("KERNEL32.dll", "GetLastError"),
                ("KERNEL32.dll", "ExitProcess"),
            ],
        )
    }

    #[test]
    fn missing_file_attributes_set_not_found_error() {
        let (code, _, _) = run_exe(&missing_attributes_probe(), WinFs::new()).unwrap();
        assert_eq!(code, 0);
    }

    fn final_path_probe() -> Vec<u8> {
        // imports: CreateFileW, GetFinalPathNameByHandleW, CloseHandle,
        // ExitProcess. Opens C:\stat.txt (pre-seeded), checks the returned
        // length is 11 (chars, no NUL), the first unit is 'C', the third is
        // '\\', the unit at index 11 is NUL, and the n=0 size query returns
        // 12 (units incl. NUL). Exits 0/1.
        use crate::pe::builder::{build, Asm};
        const CF: usize = 0;
        const FP: usize = 1;
        const CH: usize = 2;
        const XP: usize = 3;
        let mut a = Asm::new();
        let d_path = a.add_utf16("C:\\stat.txt");
        let d_buf = a.add_zeroed(128);
        let lbl_fail = a.fresh_label();
        a.sub_rsp(0x48);
        // handle = CreateFileW(path, GENERIC_READ, 0,0, OPEN_EXISTING=3, 0,0)
        a.lea_reg_rip(1, d_path);
        a.emit(&[0x48, 0xB8]);
        a.emit(&0x8000_0000u64.to_le_bytes());
        a.emit(&[0x48, 0x89, 0xC2]); // mov rdx,rax
        a.mov_r8d_imm(0);
        a.mov_r9d_imm(0);
        a.xor_eax();
        a.emit(&[0xC7, 0x44, 0x24, 0x20]);
        a.emit(&3u32.to_le_bytes());
        a.emit(&[0xC7, 0x44, 0x24, 0x28]);
        a.emit(&0u32.to_le_bytes());
        a.mov_rspoff_rax(0x30);
        a.call_import(CF);
        a.cmp_rax_m1();
        a.jz(lbl_fail);
        a.emit(&[0x48, 0x89, 0x44, 0x24, 0x40]); // mov [rsp+0x40],rax
                                                 // len = GetFinalPathNameByHandleW(handle, buf, 64, 0): == 11
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.lea_reg_rip(2, d_buf);
        a.mov_r8d_imm(64);
        a.mov_r9d_imm(0);
        a.call_import(FP);
        a.cmp_eax_imm(11);
        a.jnz(lbl_fail);
        // buf[0] == 'C'
        a.lea_reg_rip(0, d_buf);
        a.emit(&[0x66, 0x8B, 0x00]); // mov ax,[rax]
        a.emit(&[0x66, 0x83, 0xF8, 0x43]); // cmp ax,'C'
        a.jnz(lbl_fail);
        // buf[2] == '\\'
        a.lea_reg_rip(0, d_buf);
        a.emit(&[0x48, 0x83, 0xC0, 0x04]); // add rax,4
        a.emit(&[0x66, 0x8B, 0x00]); // mov ax,[rax]
        a.emit(&[0x66, 0x83, 0xF8, 0x5C]); // cmp ax,'\\'
        a.jnz(lbl_fail);
        // buf[11] == NUL
        a.lea_reg_rip(0, d_buf);
        a.emit(&[0x48, 0x83, 0xC0, 0x16]); // add rax,22
        a.emit(&[0x66, 0x8B, 0x00]); // mov ax,[rax]
        a.emit(&[0x66, 0x83, 0xF8, 0x00]); // cmp ax,0
        a.jnz(lbl_fail);
        // size query: GetFinalPathNameByHandleW(handle, 0, 0, 0) == 12
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.mov_edx_imm(0);
        a.mov_r8d_imm(0);
        a.mov_r9d_imm(0);
        a.call_import(FP);
        a.cmp_eax_imm(12);
        a.jnz(lbl_fail);
        // CloseHandle(handle); exit 0
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.call_import(CH);
        a.mov_ecx_imm(0);
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        a.mark(lbl_fail);
        a.mov_ecx_imm(1);
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        build(
            a,
            &[
                ("KERNEL32.dll", "CreateFileW"),
                ("KERNEL32.dll", "GetFinalPathNameByHandleW"),
                ("KERNEL32.dll", "CloseHandle"),
                ("KERNEL32.dll", "ExitProcess"),
            ],
        )
    }

    #[test]
    fn final_path_by_handle_roundtrip() {
        let mut fs = WinFs::new();
        fs.write_file("C:\\stat.txt", b"hello".to_vec()).unwrap();
        let (code, _, _) = run_exe(&final_path_probe(), fs).unwrap();
        assert_eq!(code, 0);
    }

    fn read_probe() -> Vec<u8> {
        // imports: CreateFileW, NtReadFile, CloseHandle, ExitProcess.
        // Reads C:\stat.txt (pre-seeded "hello") via NtReadFile, checks
        // status, byte count, and first dword, exits 0/1.
        use crate::pe::builder::{build, Asm};
        const CF: usize = 0;
        const RF: usize = 1;
        const CH: usize = 2;
        const XP: usize = 3;
        let mut a = Asm::new();
        let d_path = a.add_utf16("C:\\stat.txt");
        let d_iosb = a.add_zeroed(16);
        let d_buf = a.add_zeroed(8);
        let lbl_fail = a.fresh_label();
        a.sub_rsp(0x48);
        // handle = CreateFileW(path, GENERIC_READ, 0,0, OPEN_EXISTING=3, 0,0)
        a.lea_reg_rip(1, d_path);
        a.emit(&[0x48, 0xB8]);
        a.emit(&0x8000_0000u64.to_le_bytes());
        a.emit(&[0x48, 0x89, 0xC2]); // mov rdx,rax
        a.mov_r8d_imm(0);
        a.mov_r9d_imm(0);
        a.xor_eax();
        a.emit(&[0xC7, 0x44, 0x24, 0x20]);
        a.emit(&3u32.to_le_bytes());
        a.emit(&[0xC7, 0x44, 0x24, 0x28]);
        a.emit(&0u32.to_le_bytes());
        a.mov_rspoff_rax(0x30);
        a.call_import(CF);
        a.cmp_rax_m1();
        a.jz(lbl_fail);
        a.emit(&[0x48, 0x89, 0x44, 0x24, 0x40]); // mov [rsp+0x40],rax
                                                 // NtReadFile(handle, 0,0,0, iosb, buf, 5, NULL, 0)
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.mov_edx_imm(0);
        a.mov_r8d_imm(0);
        a.mov_r9d_imm(0);
        a.lea_reg_rip(0, d_iosb);
        a.mov_rspoff_rax(0x20);
        a.lea_reg_rip(0, d_buf);
        a.mov_rspoff_rax(0x28);
        a.mov_r32_imm(0, 5);
        a.mov_rspoff_rax(0x30);
        a.xor_eax();
        a.mov_rspoff_rax(0x38);
        a.mov_rspoff_rax(0x40);
        a.call_import(RF);
        // status == 0?
        a.test_eax_eax();
        a.jnz(lbl_fail);
        // iosb.Information (at +8) == 5?
        a.lea_reg_rip(0, d_iosb);
        a.emit(&[0x48, 0x83, 0xC0, 0x08]); // add rax,8
        a.emit(&[0x8B, 0x00]); // mov eax,[rax]
        a.cmp_eax_imm(5);
        a.jnz(lbl_fail);
        // buf first dword == "hell"?
        a.mov_eax_mem_rip(d_buf);
        a.cmp_eax_imm(0x6C6C6568);
        a.jnz(lbl_fail);
        // CloseHandle(handle); exit 0
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.call_import(CH);
        a.mov_ecx_imm(0);
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        a.mark(lbl_fail);
        a.mov_ecx_imm(1);
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        build(
            a,
            &[
                ("KERNEL32.dll", "CreateFileW"),
                ("NTDLL.dll", "NtReadFile"),
                ("KERNEL32.dll", "CloseHandle"),
                ("KERNEL32.dll", "ExitProcess"),
            ],
        )
    }

    #[test]
    fn nt_read_file_roundtrip() {
        let mut fs = WinFs::new();
        fs.write_file("C:\\stat.txt", b"hello".to_vec()).unwrap();
        let (code, _, _) = run_exe(&read_probe(), fs).unwrap();
        assert_eq!(code, 0);
    }

    fn sysinfo_probe() -> Vec<u8> {
        // imports: GetSystemInfo, ExitProcess. Exits with
        // dwAllocationGranularity (must be nonzero, real value 65536).
        use crate::pe::builder::{build, Asm};
        const SI: usize = 0;
        const XP: usize = 1;
        let mut a = Asm::new();
        let d_si = a.add_zeroed(48);
        a.sub_rsp(0x28);
        a.lea_reg_rip(1, d_si);
        a.call_import(SI);
        a.lea_reg_rip(0, d_si);
        a.emit(&[0x48, 0x83, 0xC0, 0x28]); // add rax,40
        a.emit(&[0x8B, 0x08]); // mov ecx,[rax]
        a.call_import(XP);
        a.add_rsp(0x28);
        a.ret();
        build(
            a,
            &[
                ("KERNEL32.dll", "GetSystemInfo"),
                ("KERNEL32.dll", "ExitProcess"),
            ],
        )
    }

    #[test]
    fn system_info_granularity_nonzero() {
        // memmap2 divides file offsets by dwAllocationGranularity; zero
        // panics the guest (divide by zero). Regression test.
        let (code, _, _) = run_exe(&sysinfo_probe(), WinFs::new()).unwrap();
        assert_eq!(code, 65536);
    }

    #[test]
    fn wildcard_match_basics() {
        use super::wildcard_match;
        assert!(wildcard_match("*", "anything.txt"));
        assert!(wildcard_match("*.txt", "a.txt"));
        assert!(wildcard_match("*.txt", "A.TXT"));
        assert!(!wildcard_match("*.txt", "a.log"));
        assert!(wildcard_match("a?.txt", "a1.txt"));
        assert!(!wildcard_match("a?.txt", "a12.txt"));
        assert!(wildcard_match("a*", "abc"));
        assert!(wildcard_match("*b*", "abc"));
        assert!(!wildcard_match("a*c", "ab"));
        assert!(wildcard_match("a*c", "ac"));
        assert!(wildcard_match("a*c", "axyzc"));
        assert!(wildcard_match("exact", "exact"));
        assert!(wildcard_match("exact", "EXACT"));
        assert!(!wildcard_match("exact", "exact!"));
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "x"));
    }

    fn find_probe() -> Vec<u8> {
        // imports: FindFirstFileExW, FindNextFileW, FindClose,
        // GetLastError, ExitProcess. Enumerates C:\d\* (pre-seeded with
        // a.txt, b.log), checks the first name is a.txt, counts entries,
        // checks GetLastError is NO_MORE_FILES (18), exits with the count.
        use crate::pe::builder::{build, Asm};
        const FF: usize = 0;
        const FN: usize = 1;
        const FC: usize = 2;
        const GE: usize = 3;
        const XP: usize = 4;
        let mut a = Asm::new();
        let d_pat = a.add_utf16("C:\\d\\*");
        let d_buf = a.add_zeroed(592);
        let lbl_fail = a.fresh_label();
        let lbl_next = a.fresh_label();
        let lbl_done = a.fresh_label();
        a.sub_rsp(0x48);
        // h = FindFirstFileExW(pat, 0, buf, 0, 0, 0); fail if -1
        a.lea_reg_rip(1, d_pat);
        a.mov_edx_imm(0);
        a.lea_reg_rip(8, d_buf);
        a.mov_r9d_imm(0);
        a.xor_eax();
        a.mov_rspoff_rax(0x20);
        a.mov_rspoff_rax(0x28);
        a.call_import(FF);
        a.cmp_rax_m1();
        a.jz(lbl_fail);
        a.emit(&[0x48, 0x89, 0x44, 0x24, 0x40]); // mov [rsp+0x40],rax
                                                 // first name must be a.txt: check buf+44 UTF-16 'a' (0x61)
        a.lea_reg_rip(0, d_buf);
        a.emit(&[0x48, 0x83, 0xC0, 0x2C]); // add rax,44
        a.emit(&[0x66, 0x8B, 0x00]); // mov ax,[rax]
        a.emit(&[0x66, 0x83, 0xF8, 0x61]); // cmp ax,'a'
        a.jnz(lbl_fail);
        a.mov_eax_mem_rip(d_buf);
        a.cmp_eax_imm(0x80);
        a.jnz(lbl_fail);
        a.emit(&[0x48, 0x31, 0xDB]); // xor rbx,rbx
        a.emit(&[0x48, 0xFF, 0xC3]); // inc rbx (first entry)
        a.mark(lbl_next);
        // FindNextFileW(h, buf): 0 ends the loop
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.lea_reg_rip(2, d_buf);
        a.call_import(FN);
        a.test_eax_eax();
        a.jz(lbl_done);
        a.emit(&[0x48, 0xFF, 0xC3]); // inc rbx
        a.jmp(lbl_next);
        a.mark(lbl_done);
        // GetLastError() == 18 (NO_MORE_FILES)?
        a.call_import(GE);
        a.cmp_eax_imm(18);
        a.jnz(lbl_fail);
        // FindClose(h); exit(count)
        a.emit(&[0x48, 0x8B, 0x4C, 0x24, 0x40]); // mov rcx,[rsp+0x40]
        a.call_import(FC);
        a.emit(&[0x48, 0x89, 0xD9]); // mov rcx,rbx
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        a.mark(lbl_fail);
        a.mov_ecx_imm(1);
        a.call_import(XP);
        a.add_rsp(0x48);
        a.ret();
        build(
            a,
            &[
                ("KERNEL32.dll", "FindFirstFileExW"),
                ("KERNEL32.dll", "FindNextFileW"),
                ("KERNEL32.dll", "FindClose"),
                ("KERNEL32.dll", "GetLastError"),
                ("KERNEL32.dll", "ExitProcess"),
            ],
        )
    }

    #[test]
    fn find_enumerates_names_counts_and_ends() {
        // C:\d holds a.txt + b.log: enumeration yields both (sorted),
        // exhaustion reports NO_MORE_FILES, close succeeds; exit == count.
        let mut fs = WinFs::new();
        fs.mkdir("C:\\d").unwrap();
        fs.write_file("C:\\d\\b.log", b"2".to_vec()).unwrap();
        fs.write_file("C:\\d\\a.txt", b"1".to_vec()).unwrap();
        let (code, _, _) = run_exe(&find_probe(), fs).unwrap();
        assert_eq!(code, 2);
    }

    #[test]
    fn runner_is_non_tty_under_test_harness() {
        // cargo test captures stdout -> not a TTY. Pins the deterministic half
        // of GetConsoleMode (succeeds iff TTY); the TTY-true path is trivial
        // (`mode=3`, return 1) and covered by inspection.
        let exe = crate::pe::builder::hello("x");
        let img = crate::pe::load(&exe).unwrap();
        let r = Runner::new(&img, WinFs::new()).unwrap();
        assert!(!r.console_is_tty);
    }

    #[test]
    fn guest_waiters_wake_on_memory_change_and_timeout() {
        let exe = crate::pe::builder::hello("x");
        let img = crate::pe::load(&exe).unwrap();
        let mut runner = Runner::new(&img, WinFs::new()).unwrap();
        let address = runner.emu.heap_alloc(8);
        runner.emu.write_u32(address, 0).unwrap();
        let cpu = runner
            .emu
            .thread_cpu(img.image_base + u64::from(img.entry_rva), address, 0, 0)
            .unwrap();
        let stack = cpu.regs[4];
        assert_eq!(
            runner.emu.read_u64(stack).unwrap(),
            crate::pe::emu::ENTRY_SENTINEL
        );
        assert_ne!(stack, runner.emu.rsp());
        runner.threads.push(GuestThread {
            id: 2,
            handle: 0x8000_0002,
            open: true,
            cpu,
            last_error: 0,
            fls: Vec::new(),
            tls_values: Vec::new(),
            state: ThreadState::WaitingAddress {
                address,
                expected: vec![0, 0, 0, 0],
                deadline: None,
            },
            critical_depth: 0,
            tls_resume: None,
            tls_next: 0,
            tls_reason: 0,
            once_frames: Vec::new(),
        });
        runner.refresh_waiters().unwrap();
        assert!(matches!(
            runner.threads[1].state,
            ThreadState::WaitingAddress { .. }
        ));
        runner.emu.write_u32(address, 1).unwrap();
        runner.refresh_waiters().unwrap();
        assert!(matches!(runner.threads[1].state, ThreadState::Runnable));
        assert_eq!(runner.threads[1].cpu.regs[0], 1);

        runner.threads[1].state = ThreadState::WaitingAddress {
            address,
            expected: vec![1, 0, 0, 0],
            deadline: Some(Instant::now() - Duration::from_millis(1)),
        };
        runner.refresh_waiters().unwrap();
        assert!(matches!(runner.threads[1].state, ThreadState::Runnable));
        assert_eq!(runner.threads[1].cpu.regs[0], 0);
        assert_eq!(runner.threads[1].last_error, 1460);
    }

    #[test]
    fn semaphore_release_wakes_waiter_and_consumes_token() {
        use crate::pe::builder::{build, Asm};
        let mut a = Asm::new();
        a.sub_rsp(0x28);
        a.call_import(0);
        let exe = build(a, &[("KERNEL32.dll", "ReleaseSemaphore")]);
        let img = crate::pe::load(&exe).unwrap();
        let mut runner = Runner::new(&img, WinFs::new()).unwrap();
        let handle = 0x1234;
        runner.semaphores.insert(handle, GuestSemaphore { count: 0, maximum: 2 });
        runner.threads.push(GuestThread {
            id: 2, handle: 0x8000_0002, open: true,
            cpu: runner.emu.cpu_state(), last_error: 0, fls: Vec::new(),
            tls_values: Vec::new(),
            state: ThreadState::WaitingSemaphore { handle, deadline: None },
            critical_depth: 0, tls_resume: None, tls_next: 0,
            tls_reason: 0, once_frames: Vec::new(),
        });
        runner.emu.regs[1] = handle;
        runner.emu.regs[2] = 1;
        runner.emu.regs[8] = 0;
        runner.do_shim(0).unwrap();
        assert!(matches!(runner.threads[1].state, ThreadState::Runnable));
        assert_eq!(runner.threads[1].cpu.regs[0], 0);
        assert_eq!(runner.semaphores[&handle].count, 0);

        runner.threads[1].state = ThreadState::WaitingSemaphore {
            handle, deadline: Some(Instant::now() - Duration::from_millis(1)),
        };
        runner.refresh_waiters().unwrap();
        assert!(matches!(runner.threads[1].state, ThreadState::Runnable));
        assert_eq!(runner.threads[1].cpu.regs[0], 258);
    }

    #[test]
    fn srw_exclusive_waiter_wakes_after_release() {
        let exe = crate::pe::builder::hello("x");
        let img = crate::pe::load(&exe).unwrap();
        let mut runner = Runner::new(&img, WinFs::new()).unwrap();
        let address = runner.emu.heap_alloc(8);
        let cpu = runner.emu.cpu_state();
        runner.threads.push(GuestThread {
            id: 2, handle: 0x8000_0002, open: true, cpu, last_error: 0,
            fls: Vec::new(), tls_values: Vec::new(), state: ThreadState::Runnable,
            critical_depth: 0, tls_resume: None, tls_next: 0, tls_reason: 0,
            once_frames: Vec::new(),
        });
        assert!(runner.srw_acquire(address, false, false));
        runner.current_thread = 1;
        assert!(!runner.srw_acquire(address, false, true));
        assert!(matches!(runner.threads[1].state, ThreadState::Runnable));
        assert!(!runner.srw_acquire(address, false, false));
        assert!(matches!(runner.threads[1].state, ThreadState::WaitingSrw { .. }));
        runner.current_thread = 0;
        runner.srw_release(address, false).unwrap();
        assert!(matches!(runner.threads[1].state, ThreadState::Runnable));
        assert_eq!(runner.srw_locks[&address].exclusive, Some(1));
    }

    #[test]
    fn condition_timeout_reacquires_lock_before_returning() {
        let exe = crate::pe::builder::hello("x");
        let img = crate::pe::load(&exe).unwrap();
        let mut runner = Runner::new(&img, WinFs::new()).unwrap();
        let lock = runner.emu.heap_alloc(8);
        runner.threads[0].state = ThreadState::WaitingCondition {
            cv: lock + 8, lock, kind: CondLock::SrwExclusive,
            deadline: Some(Instant::now() - Duration::from_millis(1)),
        };
        runner.refresh_waiters().unwrap();
        assert!(matches!(runner.threads[0].state, ThreadState::Runnable));
        assert_eq!(runner.threads[0].cpu.regs[0], 0);
        assert_eq!(runner.threads[0].last_error, 1460);
        assert_eq!(runner.srw_locks[&lock].exclusive, Some(0));
        let critical = runner.emu.heap_alloc(40);
        runner.threads[0].state = ThreadState::WaitingCondition {
            cv: critical + 40, lock: critical, kind: CondLock::Critical,
            deadline: Some(Instant::now() - Duration::from_millis(1)),
        };
        runner.refresh_waiters().unwrap();
        assert!(matches!(runner.threads[0].state, ThreadState::Runnable));
        assert_eq!(runner.critical_sections[&critical], (0, 1));
        assert_eq!(runner.threads[0].critical_depth, 1);
    }

    #[test]
    fn init_once_success_wakes_waiter_with_context() {
        let exe = crate::pe::builder::hello("x");
        let img = crate::pe::load(&exe).unwrap();
        let mut runner = Runner::new(&img, WinFs::new()).unwrap();
        let once = runner.emu.heap_alloc(8);
        let callback_context = runner.emu.heap_alloc(8);
        let waiter_context = runner.emu.heap_alloc(8);
        let waiter_stack = runner.emu.heap_alloc(8);
        let waiter_return = img.image_base + u64::from(img.entry_rva);
        runner.emu.write_u64(callback_context, 0x100).unwrap();
        runner.emu.write_u64(waiter_stack, waiter_return).unwrap();
        let mut waiter_cpu = runner.emu.cpu_state();
        waiter_cpu.regs[4] = waiter_stack;
        runner.threads.push(GuestThread {
            id: 2, handle: 0x8000_0002, open: true, cpu: waiter_cpu,
            last_error: 0, fls: Vec::new(), tls_values: Vec::new(),
            state: ThreadState::WaitingInitOnce {
                once, callback: waiter_return, parameter: 0, context_out: waiter_context,
            }, critical_depth: 0, tls_resume: None, tls_next: 0, tls_reason: 0,
            once_frames: Vec::new(),
        });
        runner.once_states.insert(once, OnceState::Running { owner: 0, split: false });
        runner.threads[0].once_frames.push(OnceFrame {
            resume: runner.emu.cpu_state(), once, context_out: 0, callback_context,
        });
        runner.emu.regs[0] = 1;
        runner.finish_once_callback().unwrap();
        assert!(matches!(runner.once_states[&once], OnceState::Complete { context: 0x100 }));
        assert!(matches!(runner.threads[1].state, ThreadState::Runnable));
        assert_eq!(runner.threads[1].cpu.rip, waiter_return);
        assert_eq!(runner.threads[1].cpu.regs[0], 1);
        assert_eq!(runner.emu.read_u64(waiter_context).unwrap(), 0x100);
    }
}
