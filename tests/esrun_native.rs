//! ES-Runtime (`esrun.exe`, a V8-based JavaScript runtime) on the native
//! backend, exercising Windows path handling through its `runtime:fs`
//! module. Set WINRUN_ESRUN_EXE to a Windows x64 esrun.exe to enable.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn esrun_path() -> Option<PathBuf> {
    std::env::var_os("WINRUN_ESRUN_EXE").map(PathBuf::from)
}

const SCRIPT: &str = r#"
import { file, write, readDir, mkdir, remove, realPath } from "runtime:fs";
const step = async (name, fn) => {
  try { console.log(`ok ${name}: ${JSON.stringify(await fn())}`); }
  catch (e) { console.log(`FAIL ${name}: ${e?.message}`); }
};
await step("mkdir", () => mkdir("data\\sub dir", { recursive: true }));
await step("write", () => write("data\\sub dir\\one.txt", "hello"));
await step("forward", async () => await file("data/sub dir/one.txt").text());
await step("absolute", async () => await file("C:/proj/data/sub dir/one.txt").text());
await step("dotdot", async () => await file("data\\sub dir\\..\\sub dir\\one.txt").text());
await step("case", async () => await file("DATA\\SUB DIR\\ONE.TXT").text());
await step("realPath", () => realPath("data/sub dir/../sub dir/one.txt"));
await step("readDir", async () => (await readDir("data")).map((e) => e.name));
await step("remove", () => remove("data", { recursive: true }));
await step("gone", async () => (await readDir(".")).map((e) => e.name).includes("data"));
"#;

#[test]
fn esrun_handles_windows_paths_in_its_sandbox() {
    let Some(esrun) = esrun_path() else {
        return;
    };
    let esrun = esrun.canonicalize().expect("WINRUN_ESRUN_EXE exists");
    let script = std::env::temp_dir().join(format!("winrun-esrun-{}.js", std::process::id()));
    std::fs::write(&script, SCRIPT).unwrap();
    let commands = format!(
        "New-Item C:\\proj -ItemType Directory\n@seed {} C:\\proj\\paths.js\ncd C:\\proj\n\"{}\" --allow-read --allow-write paths.js\nexit\n",
        script.display(),
        esrun.display()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_winrun"))
        .arg("shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the winrun shell");
    child.stdin.take().unwrap().write_all(commands.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    let _ = std::fs::remove_file(&script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = [
        "ok write: 5",
        "ok forward: \"hello\"",
        "ok absolute: \"hello\"",
        "ok dotdot: \"hello\"",
        "ok case: \"hello\"",
        r#"ok realPath: "C:\\proj\\data\\sub dir\\one.txt""#,
        "ok readDir: [\"sub dir\"]",
        "ok remove: undefined",
        "ok gone: false",
    ];
    for line in expected {
        assert!(
            stdout.lines().any(|output| output == line),
            "missing {line:?} in:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!stdout.contains("FAIL"), "{stdout}");
}
