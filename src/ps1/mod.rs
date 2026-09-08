//! Minimal PowerShell-like interpreter for filesystem tests.
//!
//! Implements only: New-Item, Set-Content, Add-Content, Get-Content,
//! Get-ChildItem, Remove-Item, Copy-Item, Move-Item, Test-Path
//! (+ Write-Host/Write-Output/echo as pass-through for scripts),
//! text pipelines (`a | b`, fed as text), Invoke-RestMethod (`irm`,
//! HTTPS GET via host curl), and Invoke-Expression (`iex`, runs text
//! as code in the same session).
//! All operations go through the exact same [`WinFs`](crate::winfs::WinFs) API
//! that the EXE shims use.

use crate::winfs::WinFs;
use std::collections::HashMap;

/// Max nested Invoke-Expression depth (a script executing itself would
/// otherwise recurse until the host stack overflows).
const MAX_IEX_DEPTH: usize = 32;

/// Run a `.ps1` script. Returns exit code (0 ok). Output is appended to `out`.
pub fn run_ps1(fs: &mut WinFs, script: &str, out: &mut Vec<u8>) -> Result<i32, String> {
    let interp = Interpreter { fs, out, depth: 0 };
    interp.run(script)
}

struct Interpreter<'a> {
    fs: &'a mut WinFs,
    out: &'a mut Vec<u8>,
    depth: usize,
}

impl<'a> Interpreter<'a> {
    fn run(mut self, script: &str) -> Result<i32, String> {
        self.run_code(script)?;
        Ok(0)
    }

    fn run_code(&mut self, script: &str) -> Result<(), String> {
        // Split into statements on newlines and top-level ';'
        let mut code = String::new();
        for line in script.lines() {
            let stripped = strip_comment(line);
            code.push_str(&stripped);
            code.push('\n');
        }
        for stmt in split_statements(&code) {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            self.run_pipeline(stmt)?;
        }
        Ok(())
    }

    /// Run `a | b | c`: each segment's captured output feeds the next as
    /// text; only the last segment's output reaches the session. Only
    /// Invoke-Expression consumes piped input for now; other commands run
    /// normally and ignore it.
    fn run_pipeline(&mut self, stmt: &str) -> Result<(), String> {
        let segments = split_pipeline(stmt)?;
        if segments.len() == 1 {
            return self.exec_statement(stmt, None);
        }
        let mut input: Option<String> = None;
        for (i, seg) in segments.iter().enumerate() {
            let mut buf = Vec::new();
            {
                let mut sub = Interpreter {
                    fs: &mut *self.fs,
                    out: &mut buf,
                    depth: self.depth,
                };
                sub.exec_statement(seg, input.as_deref())?;
            }
            if i + 1 == segments.len() {
                self.out.extend_from_slice(&buf);
            } else {
                input = Some(String::from_utf8_lossy(&buf).into_owned());
            }
        }
        Ok(())
    }

    fn emit(&mut self, s: &str) {
        self.out.extend_from_slice(s.as_bytes());
        self.out.push(b'\n');
    }

    fn exec_statement(&mut self, stmt: &str, pipe_in: Option<&str>) -> Result<(), String> {
        let args = tokenize(stmt)?;
        if args.is_empty() {
            return Ok(());
        }
        let cmd = args[0].to_lowercase();
        let rest = &args[1..];
        match cmd.as_str() {
            "new-item" => self.cmd_new_item(rest),
            "set-content" => self.cmd_set_content(rest),
            "add-content" => self.cmd_add_content(rest),
            "get-content" => self.cmd_get_content(rest),
            "get-childitem" | "dir" | "ls" | "gci" => self.cmd_get_childitem(rest),
            "remove-item" | "rm" | "del" | "ri" => self.cmd_remove_item(rest),
            "copy-item" | "copy" | "cp" | "ci" => self.cmd_copy_item(rest),
            "move-item" | "move" | "mv" | "mi" => self.cmd_move_item(rest),
            "test-path" => self.cmd_test_path(rest),
            "write-host" | "write-output" | "echo" => {
                let (_, positional) = parse_params(rest, &[])?;
                self.emit(&positional.join(" "));
                Ok(())
            }
            "irm" | "invoke-restmethod" => self.cmd_irm(rest),
            "iex" | "invoke-expression" => self.cmd_iex(rest, pipe_in),
            _ => Err(format!("unknown command: {}", args[0])),
        }
    }

    /// Invoke-RestMethod: HTTPS GET via host curl, response text to output.
    fn cmd_irm(&mut self, args: &[String]) -> Result<(), String> {
        let (named, positional) = parse_params(args, &["uri"])?;
        let url = named
            .get("uri")
            .cloned()
            .or_else(|| positional.first().cloned())
            .ok_or_else(|| "usage: irm <url>".to_string())?;
        let text = crate::install::fetch_url(&url, 120)
            .map_err(|e| format!("irm: {e}"))?;
        self.out.extend_from_slice(&text);
        Ok(())
    }

    /// Invoke-Expression: run text as code in this session (same filesystem).
    /// Prefers an argument; otherwise consumes piped input.
    fn cmd_iex(&mut self, args: &[String], pipe_in: Option<&str>) -> Result<(), String> {
        let (_, positional) = parse_params(args, &[])?;
        let code = positional
            .first()
            .cloned()
            .or_else(|| pipe_in.map(str::to_string))
            .ok_or_else(|| "usage: iex <script>".to_string())?;
        if self.depth + 1 > MAX_IEX_DEPTH {
            return Err("iex: max nesting depth exceeded".to_string());
        }
        self.depth += 1;
        let r = self.run_code(&code);
        self.depth -= 1;
        r
    }

    fn cmd_new_item(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(
            args,
            &["path", "itemtype", "value", "force", "name"],
        )?;
        let path = named
            .get("path")
            .cloned()
            .or_else(|| pos.first().cloned())
            .ok_or_else(|| "New-Item: missing -Path".to_string())?;
        let item_type = named
            .get("itemtype")
            .cloned()
            .or_else(|| {
                // second positional could be item type if it matches
                pos.get(1).cloned().filter(|p| {
                    p.eq_ignore_ascii_case("file") || p.eq_ignore_ascii_case("directory")
                })
            })
            .unwrap_or_else(|| "file".to_string());
        let value = named.get("value").cloned().or_else(|| {
            // value = last positional that isn't the type
            if pos.len() >= 2
                && (pos[1].eq_ignore_ascii_case("file")
                    || pos[1].eq_ignore_ascii_case("directory"))
            {
                pos.get(2).cloned()
            } else {
                pos.get(1).cloned()
            }
        });
        let force = named.contains_key("force");
        if item_type.eq_ignore_ascii_case("directory") {
            if force {
                self.fs.mkdir(&path).map_err(|e| format!("New-Item: {e}"))?;
            } else {
                self.fs
                    .mkdir_one(&path)
                    .map_err(|e| format!("New-Item: {e}"))?;
            }
        } else {
            // file
            if self.fs.is_dir(&path) {
                return Err(format!("New-Item: path is a directory: {path}"));
            }
            if self.fs.exists(&path) && !force {
                return Err(format!("New-Item: already exists: {path}"));
            }
            // ensure parent exists (mkdir -p style for -Force, else require parent)
            let data = value.unwrap_or_default().into_bytes();
            if force {
                // create parents
                if let Some(parent) = parent_of(&path) {
                    if !parent.is_empty() {
                        self.fs.mkdir(&parent).map_err(|e| format!("New-Item: {e}"))?;
                    }
                }
                self.fs
                    .write_file(&path, data)
                    .map_err(|e| format!("New-Item: {e}"))?;
            } else {
                self.fs
                    .write_file(&path, data)
                    .map_err(|e| format!("New-Item: {e}"))?;
            }
        }
        Ok(())
    }

    fn cmd_set_content(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path", "value"])?;
        let path = named
            .get("path")
            .cloned()
            .or_else(|| pos.first().cloned())
            .ok_or_else(|| "Set-Content: missing -Path".to_string())?;
        let value = named
            .get("value")
            .cloned()
            .or_else(|| pos.get(1).cloned())
            .unwrap_or_default();
        // Set-Content creates parent dirs? PowerShell requires parent; keep strict-ish:
        // create file (parent must exist) — but be lenient and create parents like -Force.
        if let Some(parent) = parent_of(&path) {
            if !parent.is_empty() && !self.fs.is_dir(&parent) && !self.fs.exists(&parent) {
                // auto-create parents to keep scripts simple
                self.fs.mkdir(&parent).map_err(|e| format!("Set-Content: {e}"))?;
            }
        }
        let mut data = value.into_bytes();
        data.push(b'\n');
        self.fs
            .write_file(&path, data)
            .map_err(|e| format!("Set-Content: {e}"))?;
        Ok(())
    }

    fn cmd_add_content(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path", "value"])?;
        let path = named
            .get("path")
            .cloned()
            .or_else(|| pos.first().cloned())
            .ok_or_else(|| "Add-Content: missing -Path".to_string())?;
        let value = named
            .get("value")
            .cloned()
            .or_else(|| pos.get(1).cloned())
            .unwrap_or_default();
        let mut data = value.into_bytes();
        data.push(b'\n');
        self.fs
            .append_file(&path, &data)
            .map_err(|e| format!("Add-Content: {e}"))?;
        Ok(())
    }

    fn cmd_get_content(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path"])?;
        let path = named
            .get("path")
            .cloned()
            .or_else(|| pos.first().cloned())
            .ok_or_else(|| "Get-Content: missing -Path".to_string())?;
        let data = self.fs.read_file(&path).map_err(|e| format!("Get-Content: {e}"))?;
        let text = String::from_utf8_lossy(&data);
        // print without adding extra newline if content already ends with one
        let s = text.strip_suffix('\n').unwrap_or(&text);
        for line in s.split('\n') {
            self.emit(line);
        }
        Ok(())
    }

    fn cmd_get_childitem(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path"])?;
        let path = named
            .get("path")
            .cloned()
            .or_else(|| pos.first().cloned())
            .unwrap_or_else(|| String::from("C:\\"));
        let names = self
            .fs
            .list_dir(&path)
            .map_err(|e| format!("Get-ChildItem: {e}"))?;
        for n in names {
            self.emit(&n);
        }
        Ok(())
    }

    fn cmd_remove_item(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path", "recurse", "force"])?;
        let path = named
            .get("path")
            .cloned()
            .or_else(|| pos.first().cloned())
            .ok_or_else(|| "Remove-Item: missing -Path".to_string())?;
        let recurse = named.contains_key("recurse");
        // -Force also implies recursive-ish leniency? keep: recurse only via -Recurse.
        self.fs
            .remove(&path, recurse || named.contains_key("force") && self.fs.is_dir(&path) && recurse)
            .map_err(|e| format!("Remove-Item: {e}"))?;
        Ok(())
    }

    fn cmd_copy_item(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path", "destination", "force"])?;
        let src = named
            .get("path")
            .cloned()
            .or_else(|| pos.first().cloned())
            .ok_or_else(|| "Copy-Item: missing -Path".to_string())?;
        let dst = named
            .get("destination")
            .cloned()
            .or_else(|| pos.get(1).cloned())
            .ok_or_else(|| "Copy-Item: missing -Destination".to_string())?;
        let force = named.contains_key("force");
        // auto-create dst parents for convenience
        if let Some(parent) = parent_of(&dst) {
            if !parent.is_empty() && !self.fs.exists(&parent) {
                self.fs.mkdir(&parent).map_err(|e| format!("Copy-Item: {e}"))?;
            }
        }
        self.fs
            .copy_path(&src, &dst, !force)
            .map_err(|e| format!("Copy-Item: {e}"))?;
        Ok(())
    }

    fn cmd_move_item(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path", "destination", "force"])?;
        let src = named
            .get("path")
            .cloned()
            .or_else(|| pos.first().cloned())
            .ok_or_else(|| "Move-Item: missing -Path".to_string())?;
        let dst = named
            .get("destination")
            .cloned()
            .or_else(|| pos.get(1).cloned())
            .ok_or_else(|| "Move-Item: missing -Destination".to_string())?;
        if let Some(parent) = parent_of(&dst) {
            if !parent.is_empty() && !self.fs.exists(&parent) {
                self.fs.mkdir(&parent).map_err(|e| format!("Move-Item: {e}"))?;
            }
        }
        self.fs
            .move_path(&src, &dst)
            .map_err(|e| format!("Move-Item: {e}"))?;
        Ok(())
    }

    fn cmd_test_path(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path"])?;
        let path = named
            .get("path")
            .cloned()
            .or_else(|| pos.first().cloned())
            .ok_or_else(|| "Test-Path: missing -Path".to_string())?;
        self.emit(if self.fs.test_path(&path) { "True" } else { "False" });
        Ok(())
    }
}

/// Strip `#` comments (outside quotes).
fn strip_comment(line: &str) -> String {
    let mut out = String::new();
    let mut sq = false;
    let mut dq = false;
    for c in line.chars() {
        match c {
            '\'' if !dq => {
                sq = !sq;
                out.push(c);
            }
            '"' if !sq => {
                dq = !dq;
                out.push(c);
            }
            '#' if !sq && !dq => break,
            _ => out.push(c),
        }
    }
    out
}

/// Split statements on newlines and top-level `;` (outside quotes).
fn split_statements(code: &str) -> Vec<String> {
    let mut stmts = Vec::new();
    let mut cur = String::new();
    let mut sq = false;
    let mut dq = false;
    for c in code.chars() {
        match c {
            '\'' if !dq => {
                sq = !sq;
                cur.push(c);
            }
            '"' if !sq => {
                dq = !dq;
                cur.push(c);
            }
            ';' if !sq && !dq => {
                stmts.push(std::mem::take(&mut cur));
            }
            '\n' if !sq && !dq => {
                stmts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        stmts.push(cur);
    }
    stmts
}

/// Split one statement into top-level `|` pipeline segments (quote-aware).
/// Errors on empty segments so `| foo` / `foo |` fail clearly.
fn split_pipeline(stmt: &str) -> Result<Vec<String>, String> {
    let mut segs = Vec::new();
    let mut cur = String::new();
    let mut sq = false;
    let mut dq = false;
    for c in stmt.chars() {
        match c {
            '\'' if !dq => {
                sq = !sq;
                cur.push(c);
            }
            '"' if !sq => {
                dq = !dq;
                cur.push(c);
            }
            '|' if !sq && !dq => {
                if cur.trim().is_empty() {
                    return Err("empty command in pipeline".to_string());
                }
                segs.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if cur.trim().is_empty() {
        return Err("empty command in pipeline".to_string());
    }
    segs.push(cur);
    Ok(segs)
}

/// Tokenize respecting single/double quotes (quotes removed).
fn tokenize(s: &str) -> Result<Vec<String>, String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut sq = false;
    let mut dq = false;
    let mut in_tok = false;
    for c in s.chars() {
        match c {
            '\'' if !dq => {
                sq = !sq;
                in_tok = true;
            }
            '"' if !sq => {
                dq = !dq;
                in_tok = true;
            }
            c if c.is_whitespace() && !sq && !dq => {
                if in_tok {
                    toks.push(std::mem::take(&mut cur));
                    in_tok = false;
                }
            }
            _ => {
                cur.push(c);
                in_tok = true;
            }
        }
    }
    if sq || dq {
        return Err("unterminated quote".to_string());
    }
    if in_tok {
        toks.push(cur);
    }
    Ok(toks)
}

/// Parse `-Name value` / `-Flag` params. Returns (named lower->value, positional).
fn parse_params(
    args: &[String],
    known: &[&str],
) -> Result<(HashMap<String, String>, Vec<String>), String> {
    let known_set: Vec<String> = known.iter().map(|s| s.to_lowercase()).collect();
    let mut named: HashMap<String, String> = HashMap::new();
    let mut pos: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') && a.len() > 1 {
            let key = a.trim_start_matches('-').to_lowercase();
            // normalize: destination|dest -> destination; itemtype ok
            let key = match key.as_str() {
                "dest" => "destination".to_string(),
                _ => key,
            };
            if known_set.contains(&key) || known.is_empty() {
                // value-taking unless boolean flag (force/recurse)
                if key == "force" || key == "recurse" {
                    named.insert(key, "true".to_string());
                    i += 1;
                } else if i + 1 < args.len() {
                    named.insert(key, args[i + 1].clone());
                    i += 2;
                } else {
                    return Err(format!("missing value for -{key}"));
                }
            } else {
                return Err(format!("unknown parameter -{key}"));
            }
        } else {
            pos.push(a.clone());
            i += 1;
        }
    }
    Ok((named, pos))
}

fn parent_of(path: &str) -> Option<String> {
    let p = path.replace('/', "\\");
    match p.rfind('\\') {
        Some(0) => None,
        Some(i) => {
            // handle drive root "C:\" -> no parent
            let head = &p[..i];
            if head.len() == 2 && head.chars().nth(1) == Some(':') {
                Some(head.to_string() + "\\")
            } else {
                Some(head.to_string())
            }
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::winfs::WinFs;

    fn run(script: &str) -> (i32, Vec<u8>, Result<i32, String>) {
        let mut fs = WinFs::new();
        let mut out = Vec::new();
        let r = run_ps1(&mut fs, script, &mut out);
        let code = match &r {
            Ok(c) => *c,
            Err(_) => -1,
        };
        (code, out, r)
    }

    #[test]
    fn pipe_into_iex_executes_text() {
        let (_, out, r) = run("echo 'Write-Host piped-hi' | iex");
        assert!(r.is_ok());
        assert_eq!(out, b"piped-hi\n");
    }

    #[test]
    fn iex_arg_executes() {
        let (_, out, r) = run("iex 'echo from-arg'");
        assert!(r.is_ok());
        assert_eq!(out, b"from-arg\n");
    }

    #[test]
    fn iex_needs_code() {
        let (_, _, r) = run("iex");
        assert!(r.unwrap_err().contains("usage"));
    }

    #[test]
    fn empty_pipeline_segment_fails() {
        assert!(run("| echo hi").2.is_err());
        assert!(run("echo hi |").2.is_err());
    }

    #[test]
    fn iex_nesting_ok_and_capped() {
        // Two levels nest with alternating quotes.
        let (_, out, r) = run("iex 'iex \"echo L2\"'");
        assert!(r.is_ok());
        assert_eq!(out, b"L2\n");
        // The depth cap itself, driven directly (textual nesting past
        // two levels needs escape syntax the tokenizer lacks).
        fn try_at_depth(depth: usize) -> Result<(), String> {
            let mut fs = WinFs::new();
            let mut out = Vec::new();
            let mut interp = Interpreter {
                fs: &mut fs,
                out: &mut out,
                depth,
            };
            interp.cmd_iex(&["echo hi".to_string()], None).map(|_| ())
        }
        assert!(try_at_depth(31).is_ok());
        assert!(try_at_depth(32).unwrap_err().contains("depth"));
    }

    #[test]
    fn irm_needs_url() {
        let (_, _, r) = run("irm");
        assert!(r.unwrap_err().contains("usage"));
    }

    #[test]
    fn irm_failed_fetch_is_an_error() {
        // Discard port on loopback: refused fast, no DNS, no network.
        let (_, _, r) = run("irm http://127.0.0.1:9/nope");
        assert!(r.is_err());
    }
}
