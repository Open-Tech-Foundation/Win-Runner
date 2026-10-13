//! `taskkill.exe`, which Windows ships in System32: ends guest processes by
//! PID (`/PID`) or image name (`/IM`, with `*` wildcards), with their
//! descendants (`/T`). Guest processes have no windows to close, so ending
//! one needs `/F`, as on Windows for a windowless process.

/// What taskkill needs from the process it runs in.
pub trait TaskkillHost {
    fn processes(&mut self) -> Vec<Process>;
    fn terminate(&mut self, pid: u32) -> Result<(), String>;
    fn stdout(&mut self, text: &str);
    fn stderr(&mut self, text: &str);
}

/// One guest process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub parent: u32,
    pub image_name: String,
}

const USAGE_HINT: &str = "Type \"TASKKILL /?\" for usage.\n";

fn wildcard(pattern: &[char], text: &[char]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some('*'), _) => wildcard(&pattern[1..], text) || (!text.is_empty() && wildcard(pattern, &text[1..])),
        (Some(p), Some(t)) if p.eq_ignore_ascii_case(t) => wildcard(&pattern[1..], &text[1..]),
        _ => false,
    }
}

/// A process and its descendants, deepest first, each with its parent.
fn tree(processes: &[Process], root: u32, out: &mut Vec<(u32, Option<u32>)>, parent: Option<u32>) {
    for child in processes.iter().filter(|process| process.parent == root && process.pid != root) {
        if !out.iter().any(|(pid, _)| *pid == child.pid) {
            tree(processes, child.pid, out, Some(root));
        }
    }
    out.push((root, parent));
}

/// Run taskkill with `arguments` (without the program name); the exit code.
pub fn run(host: &mut dyn TaskkillHost, arguments: &[String]) -> i32 {
    let (mut pids, mut images) = (Vec::new(), Vec::new());
    let (mut force, mut whole_tree) = (false, false);
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        index += 1;
        let Some(option) = argument.strip_prefix('/').or_else(|| argument.strip_prefix('-')) else {
            host.stderr(&format!("ERROR: Invalid argument/option - '{argument}'.\n{USAGE_HINT}"));
            return 1;
        };
        let mut value = || {
            index += 1;
            arguments.get(index - 1).cloned()
        };
        match option.to_ascii_uppercase().as_str() {
            "F" => force = true,
            "T" => whole_tree = true,
            "PID" => match value() {
                Some(pid) => pids.push(pid),
                None => {
                    host.stderr(&format!("ERROR: Invalid syntax. Value expected for '/PID'.\n{USAGE_HINT}"));
                    return 1;
                }
            },
            "IM" => match value() {
                Some(image) => images.push(image),
                None => {
                    host.stderr(&format!("ERROR: Invalid syntax. Value expected for '/IM'.\n{USAGE_HINT}"));
                    return 1;
                }
            },
            "?" => {
                host.stdout(
                    "\nTASKKILL [/S system [/U username [/P [password]]]]\n         { [/FI filter] [/PID processid | /IM imagename] } [/T] [/F]\n\nDescription:\n    This tool is used to terminate tasks by process id (PID) or image name.\n",
                );
                return 0;
            }
            "FI" | "S" | "U" | "P" => {
                host.stderr(&format!("ERROR: The /{} option is not supported by this taskkill.exe.\n", option.to_ascii_uppercase()));
                return 1;
            }
            _ => {
                host.stderr(&format!("ERROR: Invalid argument/option - '{argument}'.\n{USAGE_HINT}"));
                return 1;
            }
        }
    }
    if pids.is_empty() && images.is_empty() {
        host.stderr(&format!("ERROR: Invalid syntax. Neither /FI nor /PID nor /IM were specified.\n{USAGE_HINT}"));
        return 1;
    }
    let processes = host.processes();
    let (mut not_found, mut failed) = (false, false);
    // (target as typed, pids it names, whether named by image)
    let mut targets: Vec<(String, Vec<u32>, bool)> = Vec::new();
    for pid in &pids {
        let found: Vec<u32> = pid
            .parse::<u32>()
            .ok()
            .filter(|pid| processes.iter().any(|process| process.pid == *pid))
            .into_iter()
            .collect();
        targets.push((pid.clone(), found, false));
    }
    for image in &images {
        let pattern: Vec<char> = image.chars().collect();
        let found: Vec<u32> = processes
            .iter()
            .filter(|process| wildcard(&pattern, &process.image_name.chars().collect::<Vec<_>>()))
            .map(|process| process.pid)
            .collect();
        targets.push((image.clone(), found, true));
    }
    let mut ended: Vec<u32> = Vec::new();
    for (target, found, by_image) in targets {
        if found.is_empty() {
            host.stderr(&format!("ERROR: The process \"{target}\" not found.\n"));
            not_found = true;
            continue;
        }
        for pid in found {
            let mut order = Vec::new();
            if whole_tree {
                tree(&processes, pid, &mut order, None);
            } else {
                order.push((pid, None));
            }
            for (victim, parent) in order {
                if ended.contains(&victim) {
                    continue;
                }
                let described = match (parent, by_image && victim == pid) {
                    (Some(parent), _) => format!("with PID {victim} (child process of PID {parent})"),
                    (None, true) => format!("\"{target}\" with PID {victim}"),
                    (None, false) => format!("with PID {victim}"),
                };
                if !force {
                    host.stderr(&format!(
                        "ERROR: The process {described} could not be terminated.\nReason: This process can only be terminated forcefully (with /F option).\n"
                    ));
                    failed = true;
                    continue;
                }
                match host.terminate(victim) {
                    Ok(()) => {
                        host.stdout(&format!("SUCCESS: The process {described} has been terminated.\n"));
                        ended.push(victim);
                    }
                    Err(reason) => {
                        host.stderr(&format!("ERROR: The process {described} could not be terminated.\nReason: {reason}\n"));
                        failed = true;
                    }
                }
            }
        }
    }
    if not_found {
        128
    } else if failed {
        1
    } else {
        0
    }
}

/// Where Windows keeps taskkill.exe.
pub fn taskkill_exe_path() -> String {
    format!(r"{}\taskkill.exe", crate::system_profile::SYSTEM32)
}

/// Put `taskkill.exe` in System32 unless the disk already has one.
pub fn seed_taskkill_exe(fs: &mut crate::winfs::WinFs) {
    let path = taskkill_exe_path();
    if fs.is_file(&path) || fs.mkdir(crate::system_profile::SYSTEM32).is_err() {
        return;
    }
    let _ = fs.write_file(&path, crate::cmd::stub_image("WinrunTaskkillMain"));
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        processes: Vec<Process>,
        ended: Vec<u32>,
        out: String,
        err: String,
    }

    impl TaskkillHost for Fake {
        fn processes(&mut self) -> Vec<Process> {
            self.processes.clone()
        }
        fn terminate(&mut self, pid: u32) -> Result<(), String> {
            self.ended.push(pid);
            Ok(())
        }
        fn stdout(&mut self, text: &str) {
            self.out.push_str(text);
        }
        fn stderr(&mut self, text: &str) {
            self.err.push_str(text);
        }
    }

    fn fake() -> Fake {
        let process = |pid, parent, name: &str| Process { pid, parent, image_name: name.into() };
        Fake {
            processes: vec![
                process(10, 1, "esdev.exe"),
                process(20, 10, "esrun.exe"),
                process(30, 20, "node.exe"),
                process(40, 1, "other.exe"),
            ],
            ended: Vec::new(),
            out: String::new(),
            err: String::new(),
        }
    }

    fn run_with(host: &mut Fake, arguments: &[&str]) -> i32 {
        run(host, &arguments.iter().map(|a| a.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn a_forced_tree_kill_ends_descendants_first() {
        let mut host = fake();
        assert_eq!(run_with(&mut host, &["/PID", "20", "/F", "/T"]), 0);
        assert_eq!(host.ended, vec![30, 20]);
        assert_eq!(
            host.out,
            "SUCCESS: The process with PID 30 (child process of PID 20) has been terminated.\n\
             SUCCESS: The process with PID 20 has been terminated.\n"
        );
    }

    #[test]
    fn images_match_with_wildcards_and_missing_targets_exit_128() {
        let mut host = fake();
        assert_eq!(run_with(&mut host, &["-im", "ES*.EXE", "/f"]), 0);
        assert_eq!(host.ended, vec![10, 20]);
        assert!(host.out.contains("SUCCESS: The process \"ES*.EXE\" with PID 10 has been terminated."));
        let mut host = fake();
        assert_eq!(run_with(&mut host, &["/PID", "99", "/F"]), 128);
        assert_eq!(host.err, "ERROR: The process \"99\" not found.\n");
    }

    #[test]
    fn without_force_nothing_is_ended_and_usage_errors_exit_1() {
        let mut host = fake();
        assert_eq!(run_with(&mut host, &["/PID", "40"]), 1);
        assert!(host.ended.is_empty());
        assert!(host.err.contains("can only be terminated forcefully (with /F option)"));
        let mut host = fake();
        assert_eq!(run_with(&mut host, &["/F"]), 1);
        assert!(host.err.starts_with("ERROR: Invalid syntax. Neither /FI nor /PID nor /IM were specified."));
        let mut host = fake();
        assert_eq!(run_with(&mut host, &["/PID"]), 1);
    }
}
