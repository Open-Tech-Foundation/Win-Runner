//! Minimal PowerShell-like interpreter for filesystem tests.
//!
//! Implements only: New-Item, Set-Content, Add-Content, Get-Content,
//! Get-ChildItem, Remove-Item, Copy-Item, Move-Item, Test-Path
//! (+ Write-Host/Write-Output/echo as pass-through for scripts),
//! text pipelines (`a | b`, fed as text), Invoke-RestMethod (`irm`,
//! HTTPS GET via host curl), Invoke-Expression (`iex`, runs text
//! as code in the same session), and `$name = value` variables
//! (`$env:`/`$HOME`/`$null` read from the host, session-persisted).
//! Double-quoted strings interpolate (`$x`, `${x}`, `$(...)`);
//! single-quoted strings stay verbatim. Multi-line `if`/`elseif`/`else`
//! blocks work with truthiness, `-not`, and `-eq`/`-ne` conditions
//! (`throw` surfaces a message); anything else fails clearly. Variables
//! hold strings or `@(...)` arrays (`+=` appends, `.Count`/`.Length`
//! work, `-in`/`-notin`/`-contains`/`-notcontains` test membership).
//! `switch` matches literal patterns (plus `default`) as a statement or
//! an assignment value; bare quoted/`$` strings output their value.
//! `foreach` iterates arrays/literals/scalars with `break`/`continue`;
//! `function` defines named params with child-scope calls (output
//! capturable by assignment). `@{}` maps string keys to values with
//! `.ContainsKey()` and `[key]`/`[index]` reads (arrays/strings index
//! too); other methods fail clearly. `try`/`catch`/`finally` run the
//! first error handler with `finally` always executing (its own signal
//! wins). Console/script output flushes before errors report.
//! All operations go through the exact same [`WinFs`](crate::winfs::WinFs) API
//! that the EXE shims use.

use crate::winfs::WinFs;
use std::collections::HashMap;

/// Max nested Invoke-Expression depth (a script executing itself would
/// otherwise recurse until the host stack overflows).
const MAX_IEX_DEPTH: usize = 32;

/// Session variables (`$name = value`). Held by the caller (e.g. the
/// interactive shell) so assignments persist across lines; one-shot
/// `run_ps1` uses a throwaway session.
#[derive(Default)]
pub struct Session {
    pub vars: HashMap<String, Value>,
    pub funcs: HashMap<String, FuncDef>,
}

/// A defined function: parameter names (lowercased, no `$`) and body text.
#[derive(Clone)]
pub struct FuncDef {
    pub params: Vec<String>,
    pub body: String,
}

/// Statement flow: straight-line runs return `Next`; `break`/`continue`
/// propagate dynamically to the innermost enclosing loop (`if`/`switch`
/// bodies are transparent, except `switch` absorbs `break`). `$()`
/// boundaries absorb both.
enum Flow {
    Next,
    Break,
    Continue,
}

/// A variable value: plain string, string array, or string-keyed map.
/// Maps and arrays render space-joined/empty in string context.
#[derive(Clone)]
pub enum Value {
    Str(String),
    Arr(Vec<String>),
    Map(HashMap<String, Value>),
}

/// Run a `.ps1` script. Returns exit code (0 ok). Output is appended to `out`.
pub fn run_ps1(fs: &mut WinFs, script: &str, out: &mut Vec<u8>) -> Result<i32, String> {
    run_ps1_session(&mut Session::default(), fs, script, out)
}

/// Run a script with a caller-held [`Session`] (variables persist).
pub fn run_ps1_session(
    sess: &mut Session,
    fs: &mut WinFs,
    script: &str,
    out: &mut Vec<u8>,
) -> Result<i32, String> {
    let interp = Interpreter {
        fs,
        out,
        depth: 0,
        vars: &mut sess.vars,
        funcs: &mut sess.funcs,
    };
    interp.run(script)
}

struct Interpreter<'a> {
    fs: &'a mut WinFs,
    out: &'a mut Vec<u8>,
    depth: usize,
    vars: &'a mut HashMap<String, Value>,
    funcs: &'a mut HashMap<String, FuncDef>,
}

impl<'a> Interpreter<'a> {
    fn run(mut self, script: &str) -> Result<i32, String> {
        // Stray top-level break/continue is ignored, like the real shell.
        match self.run_code(script)? {
            Flow::Next | Flow::Break | Flow::Continue => Ok(0),
        }
    }

    fn run_code(&mut self, script: &str) -> Result<Flow, String> {
        // Split into statements on newlines and top-level ';'. A line
        // ending in `=`, `|`, `,`, or backtick continues on the next line.
        let mut code = String::new();
        for line in script.lines() {
            let stripped = strip_comment(line);
            let t = stripped.trim_end();
            if t.ends_with('=') || t.ends_with('|') || t.ends_with(',') || t.ends_with('`') {
                code.push_str(t);
                code.push(' ');
                continue;
            }
            code.push_str(&stripped);
            code.push('\n');
        }
        let chunks = split_chunks(&code);
        let mut i = 0;
        while i < chunks.len() {
            let t = chunks[i].trim();
            if t.is_empty() {
                i += 1;
                continue;
            }
            if starts_kw(t, "if") {
                let (next, flow) = self.run_if_chain(&chunks, i)?;
                i = next;
                match flow {
                    Flow::Next => {}
                    Flow::Break | Flow::Continue => return Ok(flow),
                }
            } else if starts_kw(t, "try") {
                let (next, flow) = self.run_try_chain(&chunks, i)?;
                i = next;
                match flow {
                    Flow::Next => {}
                    Flow::Break | Flow::Continue => return Ok(flow),
                }
            } else if let Some((name, op, first)) = split_assign_if_head(&chunks[i]) {
                // `$v = if ...` / `$v += if ...`: gather the chain,
                // evaluate capturing output lines into the value.
                let (text, next) = gather_blocks(&chunks, i, first, &["elseif", "else"]);
                let key = check_assign_target(&name)?;
                let mut buf = Vec::new();
                let flow = {
                    let mut sub = self.sub(&mut buf);
                    sub.eval_if_chain(&text)
                };
                match flow? {
                    Flow::Next => {}
                    f => return Ok(f),
                }
                let text = String::from_utf8_lossy(&buf);
                let lines: Vec<String> = text.lines().map(str::to_string).collect();
                match op {
                    AssignOp::Set => {
                        self.vars.insert(key, lines_value(lines));
                    }
                    AssignOp::Append => {
                        let elems = match lines_value(lines) {
                            Value::Str(s) if s.is_empty() => Vec::new(),
                            Value::Str(s) => vec![s],
                            Value::Arr(a) => a,
                            Value::Map(_) => {
                                return Err("cannot append a hashtable".to_string());
                            }
                        };
                        let merged = append_values(self.vars.get(&key), elems);
                        self.vars.insert(key, merged);
                    }
                }
                i = next;
            } else {
                for stmt in split_statements(&chunks[i]) {
                    let stmt = stmt.trim();
                    if stmt.is_empty() {
                        continue;
                    }
                    match self.run_pipeline(stmt)? {
                        Flow::Next => {}
                        f => return Ok(f),
                    }
                }
                i += 1;
            }
        }
        Ok(Flow::Next)
    }

    /// Run `if (c) {...} [elseif (c) {...}]* [else {...}]?` starting at
    /// chunk `i` (same-chunk `} else {` plus following elseif/else chunks).
    /// Returns the next chunk index plus any loop signal from a body.
    fn run_if_chain(&mut self, chunks: &[String], i: usize) -> Result<(usize, Flow), String> {
        let (text, j) = gather_blocks(&chunks, i, chunks[i].clone(), &["elseif", "else"]);
        let flow = self.eval_if_chain(&text)?;
        Ok((j, flow))
    }

    /// Run `try {...} [catch {...}]* [finally {...}]?` starting at chunk
    /// `i`. Returns the next chunk index plus any loop signal.
    fn run_try_chain(&mut self, chunks: &[String], i: usize) -> Result<(usize, Flow), String> {
        let (text, j) = gather_blocks(&chunks, i, chunks[i].clone(), &["catch", "finally"]);
        let flow = self.eval_try(&text)?;
        Ok((j, flow))
    }

    /// Evaluate a complete try text: try body, first catch on error (typed
    /// catches are accepted but not distinguished), optional finally which
    /// always runs. A finally of its own overrides any in-flight signal.
    fn eval_try(&mut self, text: &str) -> Result<Flow, String> {
        let rest = text.trim_start()["try".len()..].trim_start();
        if !rest.starts_with('{') {
            return Err("try needs {body}".to_string());
        }
        let (trybody, mut rest) = take_wrapped(rest, '{', '}')?;
        // Collect catches then at most one finally, in order.
        let mut catches = Vec::new();
        let mut finally: Option<String> = None;
        loop {
            rest = rest.trim_start().to_string();
            if starts_kw(&rest, "catch") {
                let after_raw = rest["catch".len()..].trim_start();
                // Optional `[Type]` (accepted, not distinguished).
                let after = if after_raw.starts_with('[') {
                    let (_, rest2) = take_wrapped(after_raw, '[', ']')?;
                    rest2.trim_start().to_string()
                } else {
                    after_raw.to_string()
                };
                if !after.starts_with('{') {
                    return Err("catch needs {body}".to_string());
                }
                let (body, rest2) = take_wrapped(&after, '{', '}')?;
                catches.push(body);
                rest = rest2;
            } else if starts_kw(&rest, "finally") {
                if finally.is_some() {
                    return Err("duplicate finally".to_string());
                }
                let after = rest["finally".len()..].trim_start();
                if !after.starts_with('{') {
                    return Err("finally needs {body}".to_string());
                }
                let (body, rest2) = take_wrapped(after, '{', '}')?;
                finally = Some(body);
                rest = rest2;
            } else {
                break;
            }
        }
        if catches.len() > 1 {
            // Without typed matching every catch would fire in turn;
            // running just the first keeps it predictable.
        }
        let run_finally = |me: &mut Self| -> Result<Flow, String> {
            match &finally {
                Some(b) => {
                    let b = b.clone();
                    me.run_code(&b)
                }
                None => Ok(Flow::Next),
            }
        };
        match self.run_code(&trybody) {
            Err(e) => {
                let cf = if let Some(cb) = catches.first() {
                    let cb = cb.clone();
                    match self.run_code(&cb) {
                        Err(e2) => {
                            run_finally(self)?;
                            return Err(e2);
                        }
                        Ok(f) => f,
                    }
                } else {
                    if let Some(b) = finally.clone() {
                        self.run_code(&b)?;
                    }
                    return Err(e);
                };
                let ff = run_finally(self)?;
                Ok(match ff {
                    Flow::Next => cf,
                    _ => ff,
                })
            }
            Ok(f) => {
                let ff = run_finally(self)?;
                Ok(match ff {
                    Flow::Next => f,
                    _ => ff,
                })
            }
        }
    }

    /// Evaluate a complete if/elseif/else text: first true branch runs.
    /// A `break`/`continue` inside a body propagates to the caller's loop.
    fn eval_if_chain(&mut self, text: &str) -> Result<Flow, String> {
        let (cond, body, mut rest) = parse_if_block(text, "if")?;
        if self.eval_cond(&cond)? {
            let flow = self.run_code(&body)?;
            if !matches!(flow, Flow::Next) {
                return Ok(flow);
            }
            return self.run_remainder(&skip_if_tail(&rest)?);
        }
        loop {
            rest = rest.trim_start().to_string();
            if starts_kw(&rest, "elseif") {
                let (cond, body, rest2) = parse_if_block(&rest, "elseif")?;
                if self.eval_cond(&cond)? {
                    let flow = self.run_code(&body)?;
                    if !matches!(flow, Flow::Next) {
                        return Ok(flow);
                    }
                    return self.run_remainder(&skip_if_tail(&rest2)?);
                }
                rest = rest2;
            } else if starts_kw(&rest, "else") {
                let after = rest["else".len()..].trim_start();
                if after.starts_with('(') {
                    return Err("else takes no condition".to_string());
                }
                let (body, rest2) = take_wrapped(after, '{', '}')?;
                let flow = self.run_code(&body)?;
                if !matches!(flow, Flow::Next) {
                    return Ok(flow);
                }
                return self.run_remainder(&rest2);
            } else {
                return self.run_remainder(&rest);
            }
        }
    }

    /// Run leftover text after an if-chain (same-line trailing statements).
    fn run_remainder(&mut self, rest: &str) -> Result<Flow, String> {
        if rest.trim().is_empty() {
            Ok(Flow::Next)
        } else {
            self.run_code(rest)
        }
    }

    /// Evaluate an if/elseif condition: truthy value, `-not`, `-eq`/`-ne`,
    /// `-in`/`-notin`/`-contains`/`-notcontains` (arrays welcome on the
    /// collection side). Method calls, other properties, and other
    /// operators fail clearly.
    fn eval_cond(&mut self, cond: &str) -> Result<bool, String> {
        let toks = tokenize(cond)?;
        if toks.is_empty() {
            return Err("empty condition".to_string());
        }
        if toks.len() == 1 {
            let t = toks[0].text();
            if t.eq_ignore_ascii_case("$true") {
                return Ok(true);
            }
            if t.eq_ignore_ascii_case("$false") {
                return Ok(false);
            }
            // Single value: expand it (method calls like
            // `$m.ContainsKey($k)` evaluate here) and test truthiness.
            let v = self.expand_token(&toks[0])?;
            return Ok(is_truthy(&v));
        }
        // Membership form first: `$x -in $coll` / `$coll -contains $x`
        // (negated variants too). The collection side may be an array
        // literal, which the shape guard below would otherwise reject.
        if toks.len() >= 3 {
            let op = toks[1].text().to_lowercase();
            if ["-in", "-notin", "-contains", "-notcontains"].contains(&op.as_str()) {
                return self.eval_membership(&toks, &op);
            }
        }
        // Code-shaped tokens need the object model (later); quoted
        // literals and `$arr.Count` probes pass through untouched.
        for tok in &toks {
            let t = tok.text();
            if tok.verbatim() || is_count_probe(&t) {
                continue;
            }
            if t.contains(['.', '(', ')', '{', '}', '[', ']', '@']) {
                return Err(format!("not supported in conditions: {t}"));
            }
        }
        let mut args = Vec::with_capacity(toks.len());
        for tok in &toks {
            args.push(self.expand_token(tok)?);
        }
        if args[0].eq_ignore_ascii_case("-not") {
            if args.len() == 2 {
                return Ok(!is_truthy(&args[1]));
            }
            return Err("only `-not <value>` is supported".to_string());
        }
        if args.len() == 3 {
            let op = args[1].to_lowercase();
            if op == "-eq" {
                return Ok(args[0].to_lowercase() == args[2].to_lowercase());
            }
            if op == "-ne" {
                return Ok(args[0].to_lowercase() != args[2].to_lowercase());
            }
            return Err(format!("{} is not supported in conditions", args[1]));
        }
        Err(format!("cannot evaluate condition: {}", args.join(" ")))
    }

    /// Membership: `$item -in $coll` / `$coll -contains $item` (and
    /// negations). The collection side is an array variable, an `@(...)`
    /// literal, or a scalar (single-element); an array item is an error.
    /// Case-insensitive, like the real operators.
    fn eval_membership(&mut self, toks: &[Token], op: &str) -> Result<bool, String> {
        let (item, coll): (&Token, &[Token]) = if op == "-in" || op == "-notin" {
            if toks.len() < 3 {
                return Err(format!("{op} needs a collection"));
            }
            (&toks[0], &toks[2..])
        } else if toks.len() == 3 {
            (&toks[2], &toks[..1])
        } else {
            return Err("cannot evaluate condition: trailing tokens".to_string());
        };
        if item.text().trim_start().starts_with("@(") {
            return Err("arrays cannot be membership items".to_string());
        }
        if matches!(self.var_value(&item.text()), Some(Value::Arr(_))) {
            return Err("arrays cannot be membership items".to_string());
        }
        let item_val = self.expand_token(item)?;
        let coll_vals = if coll.len() == 1 && !coll[0].text().trim_start().starts_with("@(") {
            self.resolve_operand_values(&coll[0])?
        } else {
            let joined: String = coll.iter().map(Token::text).collect::<Vec<_>>().join(" ");
            if !joined.trim_start().starts_with("@(") {
                return Err(format!("cannot evaluate condition: {op} needs a collection"));
            }
            self.eval_array(&joined)?
        };
        let hit = coll_vals
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&item_val));
        Ok(if op == "-in" || op == "-contains" {
            hit
        } else {
            !hit
        })
    }

    /// One operand's values: array variable elements, else the expanded
    /// scalar. (Callers route `@(...)` to eval_array first.)
    fn resolve_operand_values(&mut self, tok: &Token) -> Result<Vec<String>, String> {
        if let Some(Value::Arr(a)) = self.var_value(&tok.text()).cloned() {
            return Ok(a);
        }
        Ok(vec![self.expand_token(tok)?])
    }

    /// Variable value for plain `$name` text (dotted/coded shapes excluded).
    fn var_value(&self, text: &str) -> Option<&Value> {
        if !text.starts_with('$') {
            return None;
        }
        let name = &text[1..];
        if !is_var_name(name) {
            return None;
        }
        self.vars.get(&name.to_lowercase())
    }

    /// Run `a | b | c`: each segment's captured output feeds the next as
    /// text; only the last segment's output reaches the session. Only
    /// Invoke-Expression consumes piped input for now; other commands run
    /// normally and ignore it. Loop signals propagate (abandoning the rest).
    fn run_pipeline(&mut self, stmt: &str) -> Result<Flow, String> {
        let segments = split_pipeline(stmt)?;
        if segments.len() == 1 {
            return self.exec_statement(stmt, None);
        }
        let mut input: Option<String> = None;
        for (i, seg) in segments.iter().enumerate() {
            let mut buf = Vec::new();
            let flow = {
                let mut sub = self.sub(&mut buf);
                sub.exec_statement(seg, input.as_deref())
            };
            match flow? {
                Flow::Next => {}
                f => return Ok(f),
            }
            if i + 1 == segments.len() {
                self.out.extend_from_slice(&buf);
            } else {
                input = Some(String::from_utf8_lossy(&buf).into_owned());
            }
        }
        Ok(Flow::Next)
    }

    fn emit(&mut self, s: &str) {
        self.out.extend_from_slice(s.as_bytes());
        self.out.push(b'\n');
    }

    fn exec_statement(&mut self, stmt: &str, pipe_in: Option<&str>) -> Result<Flow, String> {
        let toks = tokenize(stmt)?;
        if toks.is_empty() {
            return Ok(Flow::Next);
        }
        // Block constructs run from raw text (braces don't tokenize).
        if !toks[0].verbatim() {
            let kw = toks[0].text().to_lowercase();
            if kw == "switch" {
                return self.cmd_switch(stmt);
            }
            if kw == "foreach" {
                return self.cmd_foreach(stmt);
            }
            if kw == "function" {
                return self.cmd_function_def(stmt);
            }
        }
        // `$x = switch ... {...}` assigns the switch output.
        if let Some(sw) = split_switch_assign(stmt)? {
            return self.cmd_assign_switch(sw.0, sw.1, sw.2);
        }
        // `$m[$k] = v` assigns into a map.
        if let Some(ix) = split_index_assign(stmt) {
            return self.cmd_assign_index(ix.0, ix.1, ix.2, ix.3);
        }
        if !toks[0].verbatim() {
            if let Some(asg) = split_assignment(&toks)? {
                return self.cmd_assign(asg.0, asg.1, asg.2);
            }
        }
        // Bare quoted strings and `$` expressions output their value
        // (what switch bodies and subexpressions produce).
        if toks.len() == 1 && (toks[0].quoted || toks[0].text().len() > 1 && toks[0].text().starts_with('$')) {
            let v = self.expand_token(&toks[0])?;
            self.emit(&v);
            return Ok(Flow::Next);
        }
        // Expand variables per token; single-quoted spans stay verbatim.
        let mut args = Vec::with_capacity(toks.len());
        for tok in &toks {
            args.push(self.expand_token(tok)?);
        }
        let cmd = args[0].to_lowercase();
        let rest = &args[1..];
        // Loop signals and code execution (flow-aware) precede the
        // plain builtins below.
        if cmd == "break" {
            return Ok(Flow::Break);
        }
        if cmd == "continue" {
            return Ok(Flow::Continue);
        }
        if cmd == "iex" || cmd == "invoke-expression" {
            return self.cmd_iex(rest, pipe_in);
        }
        if let Some((params, body)) = self
            .funcs
            .get(&cmd)
            .map(|f| (f.params.clone(), f.body.clone()))
        {
            return self.call_function(&cmd, &params, &body, rest);
        }
        self.exec_builtin(&cmd, rest, pipe_in)
    }

    /// Plain builtins shared by statement position and value capture
    /// (`$x = Join-Path ...`). `break`/`continue`/`iex` flow through.
    /// `out-null` sinks its input (pipeline or argument position).
    fn exec_builtin(
        &mut self,
        cmd: &str,
        rest: &[String],
        pipe_in: Option<&str>,
    ) -> Result<Flow, String> {
        if cmd == "break" {
            return Ok(Flow::Break);
        }
        if cmd == "continue" {
            return Ok(Flow::Continue);
        }
        if cmd == "iex" || cmd == "invoke-expression" {
            return self.cmd_iex(rest, pipe_in);
        }
        match cmd {
            "new-item" => self.cmd_new_item(rest),
            "set-content" => self.cmd_set_content(rest),
            "add-content" => self.cmd_add_content(rest),
            "get-content" => self.cmd_get_content(rest),
            "get-childitem" | "dir" | "ls" | "gci" => self.cmd_get_childitem(rest),
            "remove-item" | "rm" | "del" | "ri" => self.cmd_remove_item(rest),
            "copy-item" | "copy" | "cp" | "ci" => self.cmd_copy_item(rest),
            "move-item" | "move" | "mv" | "mi" => self.cmd_move_item(rest),
            "test-path" => self.cmd_test_path(rest),
            "join-path" => self.cmd_join_path(rest),
            "write-host" | "write-output" | "echo" => {
                let (_, positional) = parse_params(rest, &[])?;
                self.emit(&positional.join(" "));
                Ok(())
            }
            "throw" => {
                let (_, positional) = parse_params(rest, &[])?;
                let msg = positional.join(" ");
                if msg.is_empty() {
                    return Err("usage: throw <message>".to_string());
                }
                Err(msg)
            }
            "irm" | "invoke-restmethod" => self.cmd_irm(rest),
            "out-null" => Ok(()),
            _ => Err(format!("unknown command: {cmd}")),
        }?;
        Ok(Flow::Next)
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
    /// Prefers an argument; otherwise consumes piped input. Loop signals
    /// propagate (dynamic scope).
    fn cmd_iex(&mut self, args: &[String], pipe_in: Option<&str>) -> Result<Flow, String> {
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

    /// `$name = value` / `$name += value` assignment. Values are
    /// `@(...)` arrays, `@{}` (empty map), defined-function calls, or
    /// scalars; `+=` follows PowerShell add semantics. Only plain names
    /// are storable; `$env:`/`$HOME`/`$null` targets fail clearly.
    fn cmd_assign(&mut self, name: String, op: AssignOp, vals: Vec<Token>) -> Result<Flow, String> {
        let key = check_assign_target(&name)?;
        let (v, flow) = self.eval_value(&vals)?;
        match flow {
            Flow::Next => {}
            f => return Ok(f),
        }
        match op {
            AssignOp::Set => {
                self.vars.insert(key, v);
            }
            AssignOp::Append => {
                let elems = match &v {
                    Value::Str(s) if s.is_empty() => Vec::new(),
                    Value::Str(s) => vec![s.clone()],
                    Value::Arr(a) => a.clone(),
                    Value::Map(_) => {
                        return Err("cannot append a hashtable".to_string());
                    }
                };
                let merged = append_values(self.vars.get(&key), elems);
                self.vars.insert(key, merged);
            }
        }
        Ok(Flow::Next)
    }

    /// Evaluate assignment value tokens: `@(...)` array, `@{}` empty map,
    /// defined-function call capture, builtin capture, or scalar. Returns
    /// the value plus any loop signal from a captured call (abandon on it).
    fn eval_value(&mut self, vals: &[Token]) -> Result<(Value, Flow), String> {
        let joined: String = vals
            .iter()
            .map(Token::text)
            .collect::<Vec<_>>()
            .join(" ");
        let t = joined.trim_start();
        if t.starts_with("@(") {
            return Ok((Value::Arr(self.eval_array(&joined)?), Flow::Next));
        }
        let nospace: String = t.chars().filter(|c| !c.is_whitespace()).collect();
        if nospace == "@{}" {
            return Ok((Value::Map(HashMap::new()), Flow::Next));
        }
        if nospace.starts_with("@{") {
            return Err("hashtable literals with entries are not supported".to_string());
        }
        // `$t = Command [$args...]`: defined function or builtin, run
        // capturing output (0 lines → `""`, 1 → string, N → array).
        if !vals.is_empty() && !vals[0].verbatim() {
            let fname = vals[0].text().to_lowercase();
            if let Some((params, body)) =
                self.funcs.get(&fname).map(|f| (f.params.clone(), f.body.clone()))
            {
                let mut argvals = Vec::with_capacity(vals.len().saturating_sub(1));
                for tok in vals.iter().skip(1) {
                    argvals.push(self.expand_token(tok)?);
                }
                let mut buf = Vec::new();
                let flow = {
                    let mut sub = self.sub(&mut buf);
                    sub.call_function(&fname, &params, &body, &argvals)
                };
                match flow? {
                    Flow::Next => {}
                    f => return Ok((Value::Str(String::new()), f)),
                }
                let text = String::from_utf8_lossy(&buf);
                let lines: Vec<String> = text.lines().map(str::to_string).collect();
                return Ok((lines_value(lines), Flow::Next));
            }
            if is_builtin_command(&fname) {
                let mut argvals = Vec::with_capacity(vals.len().saturating_sub(1));
                for tok in vals.iter().skip(1) {
                    argvals.push(self.expand_token(tok)?);
                }
                let mut buf = Vec::new();
                let flow = {
                    let mut sub = self.sub(&mut buf);
                    sub.exec_builtin(&fname, &argvals, None)
                };
                match flow? {
                    Flow::Next => {}
                    f => return Ok((Value::Str(String::new()), f)),
                }
                let text = String::from_utf8_lossy(&buf);
                let lines: Vec<String> = text.lines().map(str::to_string).collect();
                return Ok((lines_value(lines), Flow::Next));
            }
        }
        if vals.len() != 1 {
            return Err("unexpected tokens after assignment value".to_string());
        }
        Ok((Value::Str(self.expand_token(&vals[0])?), Flow::Next))
    }

    /// `$map[$key] = value` / `$map[$key] += value`: index assignment
    /// into an existing map (plain `$name` only). Keys and values expand;
    /// `+=` merges with the same rules as variable append.
    fn cmd_assign_index(
        &mut self,
        map: String,
        keytext: String,
        op: AssignOp,
        valtext: String,
    ) -> Result<Flow, String> {
        let key = check_assign_target(&map)?;
        if !matches!(self.vars.get(&key), Some(Value::Map(_))) {
            return Err(format!("{map} is not a hashtable"));
        }
        let ktoks = tokenize(&keytext)?;
        if ktoks.len() != 1 {
            return Err("index must be a single value".to_string());
        }
        let k = self.expand_token(&ktoks[0])?.to_lowercase();
        let vtoks = tokenize(&valtext)?;
        if vtoks.is_empty() {
            return Err("missing value in assignment".to_string());
        }
        let (v, flow) = self.eval_value(&vtoks)?;
        match flow {
            Flow::Next => {}
            f => return Ok(f),
        }
        let entry = match self.vars.get_mut(&key) {
            Some(Value::Map(m)) => m,
            _ => return Err(format!("{map} is not a hashtable")),
        };
        match op {
            AssignOp::Set => {
                entry.insert(k, v);
            }
            AssignOp::Append => {
                let elems = match &v {
                    Value::Str(s) if s.is_empty() => Vec::new(),
                    Value::Str(s) => vec![s.clone()],
                    Value::Arr(a) => a.clone(),
                    Value::Map(_) => {
                        return Err("cannot append a hashtable".to_string());
                    }
                };
                let merged = append_values(entry.get(&k), elems);
                entry.insert(k, merged);
            }
        }
        Ok(Flow::Next)
    }

    /// Evaluate `@(...)` text into element strings (each expanded).
    fn eval_array(&mut self, text: &str) -> Result<Vec<String>, String> {
        let t = text.trim_start();
        let (inner, rest) = take_wrapped(&t[1..], '(', ')')?;
        if !rest.trim().is_empty() {
            return Err("unexpected text after array".to_string());
        }
        if inner.trim().is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for el in split_top_commas(&inner) {
            let el = el.trim();
            if el.is_empty() {
                return Err("empty array element".to_string());
            }
            let toks = tokenize(el)?;
            if toks.len() != 1 {
                return Err("array elements must be single values".to_string());
            }
            out.push(self.expand_token(&toks[0])?);
        }
        Ok(out)
    }

    /// `switch (value) { pattern { body } ... default { body } }` as a
    /// statement: every matching branch runs, `default` runs iff nothing
    /// matched. Patterns are literal (case-insensitive); `{...}` patterns
    /// and flags fail clearly. A `break` inside a body exits the switch;
    /// `continue` propagates to the enclosing loop.
    fn cmd_switch(&mut self, stmt: &str) -> Result<Flow, String> {
        let (expr, clauses, rest) = parse_switch(stmt)?;
        if !rest.trim().is_empty() {
            return Err("unexpected text after switch".to_string());
        }
        let mut buf = Vec::new();
        let flow = {
            let mut sub = self.sub(&mut buf);
            sub.run_switch_bodies(&expr, &clauses)
        };
        self.out.extend_from_slice(&buf);
        match flow? {
            Flow::Break => Ok(Flow::Next),
            f => Ok(f),
        }
    }

    /// `$name = switch ...` / `$name += switch ...`: the switch output
    /// lines become the value (0 lines → `""`, 1 → string, N → array).
    /// A loop signal abandons the capture and propagates.
    fn cmd_assign_switch(
        &mut self,
        name: String,
        op: AssignOp,
        rhs: String,
    ) -> Result<Flow, String> {
        let key = check_assign_target(&name)?;
        let (expr, clauses, rest) = parse_switch(&rhs)?;
        if !rest.trim().is_empty() {
            return Err("unexpected text after switch".to_string());
        }
        let mut buf = Vec::new();
        let flow = {
            let mut sub = self.sub(&mut buf);
            sub.run_switch_bodies(&expr, &clauses)
        };
        // A loop signal abandons the capture and propagates.
        match flow? {
            Flow::Next => {}
            f => return Ok(f),
        }
        let text = String::from_utf8_lossy(&buf);
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        match op {
            AssignOp::Set => {
                self.vars.insert(key, lines_value(lines));
            }
            AssignOp::Append => {
                let merged = append_values(self.vars.get(&key), lines);
                self.vars.insert(key, merged);
            }
        }
        Ok(Flow::Next)
    }

    /// Evaluate the switch expression, run matching clause bodies into `out`.
    /// Loop signals from bodies propagate (the `switch` statement itself
    /// absorbs `break`; see cmd_switch).
    fn run_switch_bodies(&mut self, expr: &str, clauses: &str) -> Result<Flow, String> {
        let value = self.eval_switch_value(expr)?;
        let mut rest = clauses.trim_start().to_string();
        let mut matched = false;
        while !rest.trim().is_empty() {
            // Clause pattern: text to the first top-level `{`.
            let (pat, after) = split_clause_head(&rest)?;
            let after = after.trim_start();
            if !after.starts_with('{') {
                return Err("expected {body} in switch clause".to_string());
            }
            let (body, rest2) = take_wrapped(after, '{', '}')?;
            let pat = pat.trim();
            if pat.is_empty() {
                // `{ cond } { body }` scriptblock form.
                return Err("scriptblock switch patterns are not supported".to_string());
            }
            let ptoks = tokenize(pat)?;
            if ptoks.len() != 1 {
                return Err("switch patterns must be single values".to_string());
            }
            let pat_val = self.expand_token(&ptoks[0])?;
            if pat_val.eq_ignore_ascii_case("default") {
                if !matched {
                    match self.run_code(&body)? {
                        Flow::Next => {}
                        f => return Ok(f),
                    }
                    matched = true;
                }
            } else if pat_val.eq_ignore_ascii_case(&value) {
                match self.run_code(&body)? {
                    Flow::Next => {}
                    f => return Ok(f),
                }
                matched = true;
            }
            rest = rest2.trim_start().to_string();
        }
        Ok(Flow::Next)
    }

    /// `foreach ($v in EXPR) { body }`: array variable, `@(...)` literal,
    /// or scalar (single iteration). `break` stops, `continue` skips.
    fn cmd_foreach(&mut self, stmt: &str) -> Result<Flow, String> {
        let rest = stmt.trim_start()["foreach".len()..].trim_start();
        if !rest.starts_with('(') {
            return Err("foreach needs ($var in ...)".to_string());
        }
        let (header, rest2) = take_wrapped(rest, '(', ')').map_err(|_| "foreach needs ($var in ...)".to_string())?;
        let rest2 = rest2.trim_start();
        if !rest2.starts_with('{') {
            return Err("foreach needs {body}".to_string());
        }
        let (body, rest3) = take_wrapped(rest2, '{', '}')?;
        if !rest3.trim().is_empty() {
            return Err("unexpected text after foreach".to_string());
        }
        let htoks = tokenize(&header)?;
        if htoks.len() < 3 || !htoks[1].text().eq_ignore_ascii_case("in") {
            return Err("foreach needs ($var in ...)".to_string());
        }
        let var_name = htoks[0].text();
        let var_name = var_name
            .strip_prefix('$')
            .ok_or_else(|| "invalid loop variable".to_string())?;
        if !is_var_name(var_name) {
            return Err("invalid loop variable".to_string());
        }
        let key = var_name.to_lowercase();
        let items = self.eval_collection(&htoks[2..])?;
        for item in items {
            self.vars.insert(key.clone(), Value::Str(item));
            match self.run_code(&body)? {
                Flow::Next => {}
                Flow::Break => break,
                Flow::Continue => continue,
            }
        }
        Ok(Flow::Next)
    }

    /// One collection's elements: array variable, `@(...)` literal, or a
    /// single scalar (single iteration).
    fn eval_collection(&mut self, toks: &[Token]) -> Result<Vec<String>, String> {
        if toks.is_empty() {
            return Err("foreach needs a collection".to_string());
        }
        if toks.len() == 1 && !toks[0].text().trim_start().starts_with("@(") {
            return self.resolve_operand_values(&toks[0]);
        }
        let joined: String = toks.iter().map(Token::text).collect::<Vec<_>>().join(" ");
        if !joined.trim_start().starts_with("@(") {
            return Err("foreach needs a collection".to_string());
        }
        self.eval_array(&joined)
    }

    /// `function Name($a, $b) { body }` (params optional): stores the
    /// definition; nothing runs. Redefinition overwrites.
    fn cmd_function_def(&mut self, stmt: &str) -> Result<Flow, String> {
        let rest = stmt.trim_start()["function".len()..].trim_start();
        // Name runs to whitespace, `(`, or `{`.
        let mut name_end = rest.len();
        for (idx, c) in rest.char_indices() {
            if c.is_whitespace() || c == '(' || c == '{' {
                name_end = idx;
                break;
            }
        }
        let name = &rest[..name_end];
        if name.is_empty()
            || !name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("invalid function name".to_string());
        }
        let mut rest = rest[name_end..].trim_start().to_string();
        let mut params = Vec::new();
        if rest.starts_with('(') {
            let (inner, rest2) = take_wrapped(&rest, '(', ')')?;
            rest = rest2.trim_start().to_string();
            for p in split_top_commas(&inner) {
                let p = p.trim().strip_prefix('$').unwrap_or(p.trim());
                if p.is_empty() || !is_var_name(p) {
                    return Err(format!("invalid function parameter: {p}"));
                }
                params.push(p.to_lowercase());
            }
        }
        if !rest.starts_with('{') {
            return Err("function needs {body}".to_string());
        }
        let (body, rest2) = take_wrapped(&rest, '{', '}')?;
        if !rest2.trim().is_empty() {
            return Err("unexpected text after function".to_string());
        }
        self.funcs.insert(
            name.to_lowercase(),
            FuncDef {
                params,
                body,
            },
        );
        Ok(Flow::Next)
    }

    /// Call a defined function: bind positionals (missing → `""`, extra is
    /// an error), run the body in a child scope (writes are local).
    fn call_function(
        &mut self,
        name: &str,
        params: &[String],
        body: &str,
        args: &[String],
    ) -> Result<Flow, String> {
        if args.len() > params.len() {
            return Err(format!("too many arguments to {name}"));
        }
        let saved = self.vars.clone();
        for (i, p) in params.iter().enumerate() {
            self.vars.insert(
                p.clone(),
                Value::Str(args.get(i).cloned().unwrap_or_default()),
            );
        }
        let body = body.to_string();
        let r = self.run_code(&body);
        *self.vars = saved;
        r
    }

    /// The switch value: single expanded token in `(...)` (parens required).
    fn eval_switch_value(&mut self, expr: &str) -> Result<String, String> {
        let toks = tokenize(expr)?;
        if toks.len() != 1 {
            return Err("switch value must be a single value".to_string());
        }
        self.expand_token(&toks[0])
    }

    /// Expand one token: `$name` / `${name}` / `$(...)` in expandable spans,
    /// single-quoted spans verbatim. Member access (`$bin.exe`) expands the
    /// variable part only.
    fn expand_token(&mut self, tok: &Token) -> Result<String, String> {
        let cs = &tok.chars;
        let mut out = String::new();
        let mut i = 0;
        while i < cs.len() {
            let (c, ex) = cs[i];
            if c != '$' || !ex {
                out.push(c);
                i += 1;
                continue;
            }
            if i + 1 < cs.len() && cs[i + 1].0 == '(' {
                let (code, used) = take_balanced(&cs[i + 2..])?;
                out.push_str(&self.eval_sub(&code)?);
                i += 2 + used;
                continue;
            }
            if i + 1 < cs.len() && cs[i + 1].0 == '{' {
                let mut j = i + 2;
                while j < cs.len() && cs[j].0 != '}' {
                    j += 1;
                }
                if j >= cs.len() {
                    return Err("unbalanced ${}".to_string());
                }
                let name: String = cs[i + 2..j].iter().map(|(c, _)| *c).collect();
                out.push_str(&self.lookup_var(&name));
                i = j + 1;
                continue;
            }
            let mut j = i + 1;
            while j < cs.len()
                && (cs[j].0.is_ascii_alphanumeric()
                    || cs[j].0 == '_'
                    || cs[j].0 == ':'
                    || cs[j].0 == '.')
            {
                j += 1;
            }
            if j == i + 1 {
                out.push('$');
                i += 1;
            } else {
                let name: String = cs[i + 1..j].iter().map(|(c, _)| *c).collect();
                // Method call `$recv.Method(args)` / bare `(` after `$name`.
                if j < cs.len() && cs[j].0 == '(' {
                    if !name.contains('.') {
                        return Err(format!("unexpected ( after ${name}"));
                    }
                    let dot = name.rfind('.').unwrap();
                    let (recv, method) = (&name[..dot], &name[dot + 1..]);
                    if !is_var_name(recv) {
                        return Err("nested method receivers are not supported".to_string());
                    }
                    let tail: String = cs[j..].iter().map(|(c, _)| *c).collect();
                    let (inner, rest2) = take_wrapped(&tail, '(', ')')?;
                    let mut argvals = Vec::new();
                    if !inner.trim().is_empty() {
                        for a in split_top_commas(&inner) {
                            let atoks = tokenize(a.trim())?;
                            if atoks.len() != 1 {
                                return Err("method arguments must be single values".to_string());
                            }
                            argvals.push(self.expand_token(&atoks[0])?);
                        }
                    }
                    out.push_str(&self.eval_method(recv, method, &argvals)?);
                    i = cs.len() - rest2.chars().count();
                    continue;
                }
                // Index `$v[...]` on plain variables (maps, arrays,
                // strings, or unset/null). Other bases keep the legacy
                // value-plus-literal behavior.
                if j < cs.len() && cs[j].0 == '[' && is_var_name(&name) {
                    let tail: String =
                        cs[j..].iter().map(|(c, _)| *c).collect();
                    let (inner, rest2) = take_wrapped(&tail, '[', ']')?;
                    let itoks = tokenize(inner.trim())?;
                    if itoks.len() != 1 {
                        return Err("index must be a single value".to_string());
                    }
                    let key = self.expand_token(&itoks[0])?;
                    let base = self.vars.get(&name.to_lowercase());
                    out.push_str(&self.eval_index(base, &key)?);
                    i = cs.len() - rest2.chars().count();
                    continue;
                }
                out.push_str(&self.lookup_var(&name));
                i = j;
            }
        }
        Ok(out)
    }

    /// Run subexpression code, capturing output (trailing newlines trimmed).
    /// Loop signals are absorbed here (`$(...)` is a value boundary).
    fn eval_sub(&mut self, code: &str) -> Result<String, String> {
        if self.depth + 1 > MAX_IEX_DEPTH {
            return Err("iex: max nesting depth exceeded".to_string());
        }
        self.depth += 1;
        let mut buf = Vec::new();
        let flow = {
            let mut sub = self.sub(&mut buf);
            sub.run_code(code)
        };
        self.depth -= 1;
        if let Err(e) = flow {
            return Err(e);
        }
        let s = String::from_utf8_lossy(&buf);
        Ok(s.trim_end_matches(['\n', '\r']).to_string())
    }

    /// Child interpreter sharing filesystem, variables, and functions.
    fn sub<'b>(&'b mut self, out: &'b mut Vec<u8>) -> Interpreter<'b> {
        Interpreter {
            fs: &mut *self.fs,
            out,
            depth: self.depth,
            vars: &mut *self.vars,
            funcs: &mut *self.funcs,
        }
    }

    fn lookup_var(&self, name: &str) -> String {
        // `name` is ASCII-only ([A-Za-z0-9_.:] run), so byte slicing is safe.
        if let Some(dot) = name.find('.') {
            let (head, tail) = (&name[..dot], &name[dot + 1..]);
            // `$arr.Count` / `$arr.Length` (string vars keep the legacy
            // head-plus-literal behavior; other members come later).
            if tail.eq_ignore_ascii_case("count") || tail.eq_ignore_ascii_case("length") {
                if let Some(Value::Arr(a)) = self.vars.get(&head.to_lowercase()) {
                    return a.len().to_string();
                }
            }
            return self.lookup_scalar(head) + "." + tail;
        }
        self.lookup_scalar(name)
    }

    fn lookup_scalar(&self, name: &str) -> String {
        if name.eq_ignore_ascii_case("null") || name == "_" {
            return String::new();
        }
        if name.eq_ignore_ascii_case("home") {
            return std::env::var("HOME").unwrap_or_default();
        }
        if name.len() > 4 && name[..4].eq_ignore_ascii_case("env:") {
            return std::env::var(&name[4..]).unwrap_or_default();
        }
        if name.contains(':') {
            return format!("${name}");
        }
        match self.vars.get(&name.to_lowercase()) {
            Some(v) => value_string(v),
            None => String::new(),
        }
    }

    /// `$recv.Method(args)`: only `ContainsKey` on maps for now (True/False,
    /// PowerShell-capitalized). Anything else fails clearly.
    fn eval_method(&self, recv: &str, method: &str, args: &[String]) -> Result<String, String> {
        if !method.eq_ignore_ascii_case("containskey") {
            return Err(format!("method {method} is not supported"));
        }
        let Some(Value::Map(m)) = self.vars.get(&recv.to_lowercase()) else {
            return Err(format!("ContainsKey needs a hashtable"));
        };
        if args.len() != 1 {
            return Err("ContainsKey takes one argument".to_string());
        }
        Ok(if m.contains_key(&args[0].to_lowercase()) {
            "True".to_string()
        } else {
            "False".to_string()
        })
    }

    /// `$v[key]`: map lookup (case-insensitive, missing → empty), array
    /// or string index (negative counts from the end, out-of-range →
    /// empty), unset (`$null`) → empty.
    fn eval_index(&self, base: Option<&Value>, key: &str) -> Result<String, String> {
        match base {
            None => Ok(String::new()),
            Some(Value::Map(m)) => Ok(m
                .get(&key.to_lowercase())
                .map(value_string)
                .unwrap_or_default()),
            Some(Value::Arr(a)) => array_index(a, key),
            Some(Value::Str(s)) => {
                let chars: Vec<char> = s.chars().collect();
                array_index(&chars, key)
            }
        }
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

    fn cmd_join_path(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path", "childpath", "resolve"])?;
        let mut parts: Vec<String> = Vec::new();
        if let Some(p) = named.get("path") {
            parts.push(p.clone());
        }
        if let Some(c) = named.get("childpath") {
            parts.push(c.clone());
        }
        parts.extend(pos.iter().cloned());
        if parts.len() < 2 {
            return Err("usage: Join-Path <path> <child> [...]".to_string());
        }
        let mut out = parts[0].replace('/', "\\");
        for part in &parts[1..] {
            let child = part.replace('/', "\\");
            let child = child.trim_start_matches('\\');
            let base = out.trim_end_matches('\\');
            // `C:\` trims to `C:`; re-adding the separator restores it.
            out = if base.is_empty() {
                format!("\\{child}")
            } else {
                format!("{base}\\{child}")
            };
        }
        if named.contains_key("resolve") && !self.fs.test_path(&out) {
            return Err(format!("Join-Path: path not found: {out}"));
        }
        self.emit(&out);
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

/// Split code into chunks: newlines/semicolons at brace depth 0 end a
/// chunk (quote-aware); `{...}` groups stay whole, including same-line
/// `} else {` tails.
fn split_chunks(code: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut cur = String::new();
    let mut sq = false;
    let mut dq = false;
    let mut depth = 0usize;
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
            '{' if !sq && !dq => {
                depth += 1;
                cur.push(c);
            }
            '}' if !sq && !dq => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            ';' | '\n' if !sq && !dq && depth == 0 => {
                if !cur.trim().is_empty() {
                    chunks.push(std::mem::take(&mut cur));
                } else {
                    cur.clear();
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        chunks.push(cur);
    }
    chunks
}

/// True when `s` starts with keyword `kw` on a word boundary
/// (case-insensitive; `elsewhere` is not `else`).
fn starts_kw(s: &str, kw: &str) -> bool {
    let t = s.trim_start();
    match t.get(..kw.len()) {
        Some(head) if head.eq_ignore_ascii_case(kw) => {}
        _ => return false,
    }
    match t[kw.len()..].chars().next() {
        None => true,
        Some(c) => c.is_whitespace() || c == '(' || c == '{',
    }
}

/// Skip unexecuted trailing elseif/else blocks after a taken branch.
/// A trailing elseif past `else` is invalid and stays for the caller to
/// reject (it surfaces as an unknown command, clearly).
fn skip_if_tail(rest: &str) -> Result<String, String> {
    let mut rest = rest.trim_start().to_string();
    loop {
        if starts_kw(&rest, "elseif") {
            let (_, _, rest2) = parse_if_block(&rest, "elseif")?;
            rest = rest2.trim_start().to_string();
        } else if starts_kw(&rest, "else") {
            let after = rest["else".len()..].trim_start();
            if after.starts_with('(') {
                return Err("else takes no condition".to_string());
            }
            let (_, rest2) = take_wrapped(after, '{', '}')?;
            rest = rest2;
        } else {
            return Ok(rest);
        }
    }
}

/// Gather a block chain's full text: first text plus following chunks
/// starting with any of `kws` (e.g. elseif/else, catch/finally), plus
/// continuation chunks while the last block is unclosed (so newline-brace
/// style works). Returns (text, next index).
fn gather_blocks(chunks: &[String], i: usize, first: String, kws: &[&str]) -> (String, usize) {
    let mut text = first;
    let mut j = i + 1;
    loop {
        let t = text.trim_end();
        let need_more = !t.ends_with('}');
        let chain_next = t.ends_with('}')
            && j < chunks.len()
            && kws.iter().any(|k| starts_kw(chunks[j].trim_start(), k));
        if (!need_more && !chain_next) || j >= chunks.len() {
            break;
        }
        text.push('\n');
        text.push_str(&chunks[j]);
        j += 1;
    }
    (text, j)
}

/// Parse `KW (cond) { body }rest` (KW = if/elseif). Returns (cond, body, rest).
fn parse_if_block(s: &str, kw: &str) -> Result<(String, String, String), String> {
    let after_kw = s.trim_start()[kw.len()..].trim_start();
    if !after_kw.starts_with('(') {
        return Err(format!("expected (condition) after {kw}"));
    }
    let (cond, rest) = take_wrapped(after_kw, '(', ')')?;
    let rest = rest.trim_start();
    if !rest.starts_with('{') {
        return Err(format!("expected {{body}} after {kw} (...)"));
    }
    let (body, rest2) = take_wrapped(rest, '{', '}')?;
    Ok((cond, body, rest2))
}

/// Split a leading `(...)`/`{...}` (quote-aware): returns (inner, rest).
fn take_wrapped(s: &str, open: char, close: char) -> Result<(String, String), String> {
    let mut depth = 0usize;
    let mut sq = false;
    let mut dq = false;
    for (idx, c) in s.char_indices() {
        if c == '\'' && !dq {
            sq = !sq;
            continue;
        }
        if c == '"' && !sq {
            dq = !dq;
            continue;
        }
        if sq || dq {
            continue;
        }
        if c == open {
            depth += 1;
        }
        if c == close {
            depth -= 1;
            if depth == 0 {
                let inner = s[open.len_utf8()..idx].to_string();
                let rest = s[idx + close.len_utf8()..].to_string();
                return Ok((inner, rest));
            }
        }
    }
    Err(format!("unbalanced {open}"))
}

/// PowerShell truthiness lite: empty, `$false`/`false`, and numeric zero
/// are false (arrays and other types don't exist here yet).
fn is_truthy(s: &str) -> bool {
    !(s.is_empty() || s.eq_ignore_ascii_case("false") || s == "0")
}

/// Split statements on newlines and top-level `;` (outside quotes).
fn split_statements(code: &str) -> Vec<String> {
    let mut stmts = Vec::new();
    let mut cur = String::new();
    let mut sq = false;
    let mut dq = false;
    let mut depth = 0usize;
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
            '{' if !sq && !dq => {
                depth += 1;
                cur.push(c);
            }
            '}' if !sq && !dq => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            ';' if !sq && !dq && depth == 0 => {
                stmts.push(std::mem::take(&mut cur));
            }
            '\n' if !sq && !dq && depth == 0 => {
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

/// Split one statement into top-level `|` pipeline segments (quote-aware,
/// brace/paren-depth-aware so pipes inside `{...}` / `$(...)` stay whole).
/// Errors on empty segments so `| foo` / `foo |` fail clearly.
fn split_pipeline(stmt: &str) -> Result<Vec<String>, String> {
    let mut segs = Vec::new();
    let mut cur = String::new();
    let mut sq = false;
    let mut dq = false;
    let mut depth = 0usize;
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
            '{' | '(' if !sq && !dq => {
                depth += 1;
                cur.push(c);
            }
            '}' | ')' if !sq && !dq => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            '|' if !sq && !dq && depth == 0 => {
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

/// Assignment operator: `=` replaces, `+=` appends (PowerShell array-add
/// semantics: null+scalar is scalar, anything else grows an array).
#[derive(PartialEq, Eq)]
enum AssignOp {
    Set,
    Append,
}

/// Output lines to a value: 0 lines → `""`, 1 → string, N → array.
fn lines_value(lines: Vec<String>) -> Value {
    if lines.len() == 1 {
        Value::Str(lines.into_iter().next().unwrap())
    } else if lines.is_empty() {
        Value::Str(String::new())
    } else {
        Value::Arr(lines)
    }
}

/// A value in string context: strings as-is, arrays space-joined, empty
/// maps stringify empty (Out-String behavior for `@{}`).
fn value_string(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Arr(a) => a.join(" "),
        Value::Map(_) => String::new(),
    }
}

/// Index into a slice by integer text (negative counts from the end,
/// out-of-range → empty). Used for arrays and string characters.
fn array_index<T>(items: &[T], key: &str) -> Result<String, String>
where
    T: Clone + Into<String>,
{
    let idx: i64 = key
        .trim()
        .parse()
        .map_err(|_| "index must be an integer".to_string())?;
    let idx = if idx < 0 {
        items.len() as i64 + idx
    } else {
        idx
    };
    Ok(items
        .get(idx as usize)
        .cloned()
        .map(Into::into)
        .unwrap_or_default())
}

/// PowerShell `+=` merge: null+scalar stays scalar, anything else grows
/// an array (`"a" + "b"` becomes `@("a", "b")`, like the real thing).
/// An array base stays an array even when the result has one element
/// (`@() + "x"` has `.Count` 1).
fn append_values(existing: Option<&Value>, new: Vec<String>) -> Value {
    let was_array = matches!(existing, Some(Value::Arr(_)));
    let mut base: Vec<String> = match existing {
        Some(Value::Arr(a)) => a.clone(),
        Some(Value::Str(s)) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    };
    base.extend(new);
    if base.len() == 1 && !was_array {
        Value::Str(base.into_iter().next().unwrap())
    } else {
        Value::Arr(base)
    }
}

/// Split on top-level commas (quote-aware, paren-depth-aware for `$(...)`).
fn split_top_commas(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut sq = false;
    let mut dq = false;
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '\'' if !dq => {
                sq = !sq;
                cur.push(c);
            }
            '"' if !sq => {
                dq = !dq;
                cur.push(c);
            }
            '(' if !sq && !dq => {
                depth += 1;
                cur.push(c);
            }
            ')' if !sq && !dq => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            ',' if !sq && !dq && depth == 0 => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts
}

/// Detect `$name = if ...` / `$name += if ...` on raw chunk text.
/// Returns (name, op, text starting at `if`).
fn split_assign_if_head(chunk: &str) -> Option<(String, AssignOp, String)> {
    let t = chunk.trim_start();
    if !t.starts_with('$') {
        return None;
    }
    let mut name_end = 1;
    for c in t[1..].chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            name_end += c.len_utf8();
        } else {
            break;
        }
    }
    if name_end < 2 {
        return None;
    }
    let name = t[..name_end].to_string();
    let rest = t[name_end..].trim_start();
    let (op, after) = if rest.starts_with("+=") {
        (AssignOp::Append, rest[2..].trim_start())
    } else if rest.starts_with('=') && !rest[1..].starts_with('=') {
        (AssignOp::Set, rest[1..].trim_start())
    } else {
        return None;
    };
    if !starts_kw(after, "if") {
        return None;
    }
    Some((name, op, after.to_string()))
}

/// Validate an assignment target (`$name`), returning the key.
fn check_assign_target(name: &str) -> Result<String, String> {
    let bare = name
        .strip_prefix('$')
        .ok_or_else(|| "invalid variable name".to_string())?;
    if bare.eq_ignore_ascii_case("null") {
        return Err("cannot assign to $null".to_string());
    }
    if bare.eq_ignore_ascii_case("home") {
        return Err("assigning $HOME is not supported".to_string());
    }
    if bare.len() > 4 && bare[..4].eq_ignore_ascii_case("env:") {
        return Err("assigning $env: is not supported".to_string());
    }
    if !is_var_name(bare) {
        return Err(format!("invalid variable name: {name}"));
    }
    Ok(bare.to_lowercase())
}

/// Detect `$map[$key] = value` / `$map[$key] += value` on raw statement
/// text (tokenizing would shred the brackets). Returns (map, key, op, value).
fn split_index_assign(stmt: &str) -> Option<(String, String, AssignOp, String)> {
    let t = stmt.trim_start();
    if !t.starts_with('$') {
        return None;
    }
    let mut ni = 1;
    for c in t[1..].chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            ni += c.len_utf8();
        } else {
            break;
        }
    }
    if ni < 2 {
        return None;
    }
    let name = t[..ni].to_string();
    let rest = t[ni..].trim_start();
    if !rest.starts_with('[') {
        return None;
    }
    // Balanced `[...]` over the raw text (quotes intact here).
    let mut sq = false;
    let mut dq = false;
    let mut depth = 0usize;
    let mut end = None;
    for (idx, c) in rest.char_indices() {
        if c == '\'' && !dq {
            sq = !sq;
        } else if c == '"' && !sq {
            dq = !dq;
        } else if c == '[' && !sq && !dq {
            depth += 1;
        } else if c == ']' && !sq && !dq {
            depth -= 1;
            if depth == 0 {
                end = Some(idx);
                break;
            }
        }
    }
    let end = end?;
    let keytext = rest[1..end].to_string();
    let after = rest[end + 1..].trim_start();
    let (op, valtext) = if after.starts_with("+=") {
        (AssignOp::Append, after[2..].trim_start().to_string())
    } else if after.starts_with('=') && !after[1..].starts_with('=') {
        (AssignOp::Set, after[1..].trim_start().to_string())
    } else {
        return None;
    };
    if valtext.is_empty() {
        return None;
    }
    Some((name, keytext, op, valtext))
}

/// Detect `$name = switch ...` / `$name += switch ...` on raw statement
/// text (tokenizing would shred the braces). Returns (name, op, rhs text).
fn split_switch_assign(stmt: &str) -> Result<Option<(String, AssignOp, String)>, String> {
    let t = stmt.trim_start();
    if !t.starts_with('$') {
        return Ok(None);
    }
    let eq = match t.find('=') {
        Some(i) => i,
        None => return Ok(None),
    };
    if t[eq + 1..].starts_with('=') {
        return Ok(None); // `==` etc: normal path errors clearly
    }
    let mut name = t[..eq].trim_end().to_string();
    let op = if name.ends_with('+') {
        name.pop();
        AssignOp::Append
    } else {
        AssignOp::Set
    };
    let rhs = t[eq + 1..].trim_start();
    if !starts_kw(rhs, "switch") {
        return Ok(None);
    }
    Ok(Some((name, op, rhs.to_string())))
}

/// Parse `switch [-flag] (value) { clauses }rest`. Flags fail clearly;
/// the value parens are required. Returns (value, clauses, rest).
fn parse_switch(s: &str) -> Result<(String, String, String), String> {
    let mut rest = s.trim_start()["switch".len()..].trim_start();
    if rest.starts_with('-') {
        return Err("switch flags are not supported".to_string());
    }
    if !rest.starts_with('(') {
        return Err("switch needs (value)".to_string());
    }
    let (expr, rest2) = take_wrapped(rest, '(', ')')?;
    rest = rest2.trim_start();
    if !rest.starts_with('{') {
        return Err("switch needs {clauses}".to_string());
    }
    let (clauses, rest3) = take_wrapped(rest, '{', '}')?;
    Ok((expr, clauses, rest3))
}

/// Split `pattern { ... }rest` at the first top-level `{`.
/// Returns (pattern text, text from `{`).
fn split_clause_head(s: &str) -> Result<(String, String), String> {
    let mut sq = false;
    let mut dq = false;
    for (idx, c) in s.char_indices() {
        if c == '\'' && !dq {
            sq = !sq;
        } else if c == '"' && !sq {
            dq = !dq;
        } else if c == '{' && !sq && !dq {
            return Ok((s[..idx].to_string(), s[idx..].to_string()));
        }
    }
    Err("expected {body} in switch clause".to_string())
}

/// Plain builtins runnable as statements and capturable in value
/// position (`$x = Join-Path ...`). Keep in sync with `exec_builtin`.
fn is_builtin_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "new-item"
            | "set-content"
            | "add-content"
            | "get-content"
            | "get-childitem"
            | "dir"
            | "ls"
            | "gci"
            | "remove-item"
            | "rm"
            | "del"
            | "ri"
            | "copy-item"
            | "copy"
            | "cp"
            | "ci"
            | "move-item"
            | "move"
            | "mv"
            | "mi"
            | "test-path"
            | "join-path"
            | "write-host"
            | "write-output"
            | "echo"
            | "throw"
            | "irm"
            | "invoke-restmethod"
            | "iex"
            | "invoke-expression"
            | "break"
            | "continue"
            | "out-null"
    )
}

/// Split `$name = value` / `$name += value` (spaced or joined) off
/// tokenized args. Ok(None) = not an assignment; Err = malformed.
/// Value tokens are returned raw (array values legitimately span tokens).
fn split_assignment(args: &[Token]) -> Result<Option<(String, AssignOp, Vec<Token>)>, String> {
    let first_text = args[0].text();
    if !first_text.starts_with('$') {
        return Ok(None);
    }
    if let Some(eq) = first_text.find('=') {
        // Joined form: `$name=value`, `$name+=value` (also `$x= 1`).
        // Text and flag indices line up (quotes stripped, never stored).
        let mut name = first_text[..eq].to_string();
        let tail = &args[0].chars[eq + 1..];
        if tail.first().is_some_and(|(c, _)| *c == '=') {
            return Err("comparison operators are not supported".to_string());
        }
        let op = if name.ends_with('+') {
            name.pop();
            AssignOp::Append
        } else {
            AssignOp::Set
        };
        if name.len() < 2 {
            return Err("invalid variable name".to_string());
        }
        let mut vals = Vec::new();
        if !tail.is_empty() {
            vals.push(Token {
                chars: tail.to_vec(),
                quoted: false,
            });
        }
        vals.extend_from_slice(&args[1..]);
        if vals.is_empty() {
            return Err("missing value in assignment".to_string());
        }
        return Ok(Some((name, op, vals)));
    }
    // Spaced form: `$name = value ...` / `$name += value ...`.
    let texts: Vec<String> = args.iter().map(Token::text).collect();
    if texts.len() < 2 || (texts[1] != "=" && texts[1] != "+=") {
        if texts.len() > 1 && texts[1].starts_with('=') {
            return Err("comparison operators are not supported".to_string());
        }
        return Ok(None);
    }
    if texts.len() < 3 {
        return Err("missing value in assignment".to_string());
    }
    if first_text.len() < 2 {
        return Err("invalid variable name".to_string());
    }
    let op = if texts[1] == "+=" {
        AssignOp::Append
    } else {
        AssignOp::Set
    };
    Ok(Some((first_text, op, args[2..].to_vec())))
}

/// Split `code...)` at the balancing `)` (quote-aware over the stripped
/// text). Returns (inner code, chars consumed including `)`).
fn take_balanced(cs: &[(char, bool)]) -> Result<(String, usize), String> {
    let mut depth = 1usize;
    let mut sq = false;
    let mut dq = false;
    let mut inner = String::new();
    let mut i = 0;
    while i < cs.len() {
        let (c, _) = cs[i];
        match c {
            '\'' if !dq => {
                sq = !sq;
                inner.push(c);
            }
            '"' if !sq => {
                dq = !dq;
                inner.push(c);
            }
            '(' if !sq && !dq => {
                depth += 1;
                inner.push(c);
            }
            ')' if !sq && !dq => {
                depth -= 1;
                if depth == 0 {
                    return Ok((inner, i + 1));
                }
                inner.push(c);
            }
            _ => inner.push(c),
        }
        i += 1;
    }
    Err("unbalanced $(...)".to_string())
}

/// True for plain variable names (case-insensitive, ASCII).
fn is_var_name(s: &str) -> bool {
    let mut it = s.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    it.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// True for `$Name.Count` / `$Name.Length` probes (allowed in conditions;
/// expansion resolves them against array variables).
fn is_count_probe(text: &str) -> bool {
    if !text.starts_with('$') {
        return false;
    }
    match text[1..].find('.') {
        Some(dot) => {
            let (head, tail) = (&text[1..dot + 1], &text[dot + 2..]);
            (tail.eq_ignore_ascii_case("count") || tail.eq_ignore_ascii_case("length"))
                && is_var_name(head)
                && !tail.contains('.')
        }
        None => false,
    }
}

/// One whitespace-separated token: chars with a per-char expand flag
/// (false inside single quotes). `text()` drops the flags; indices of
/// `text()` line up with `chars` (quotes stripped, never stored).
/// `quoted` records whether any quotes surrounded part of it.
#[derive(Clone)]
struct Token {
    chars: Vec<(char, bool)>,
    quoted: bool,
}

impl Token {
    fn text(&self) -> String {
        self.chars.iter().map(|(c, _)| *c).collect()
    }
    /// True when every char came from single quotes (verbatim literal).
    fn verbatim(&self) -> bool {
        !self.chars.is_empty() && self.chars.iter().all(|(_, ex)| !ex)
    }
}

/// Tokenize respecting single/double quotes (quotes removed).
fn tokenize(s: &str) -> Result<Vec<Token>, String> {
    let mut toks = Vec::new();
    let mut cur: Vec<(char, bool)> = Vec::new();
    let mut sq = false;
    let mut dq = false;
    let mut in_tok = false;
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '\'' if !dq => {
                sq = !sq;
                in_tok = true;
                quoted = true;
            }
            '"' if !sq => {
                dq = !dq;
                in_tok = true;
                quoted = true;
            }
            c if c.is_whitespace() && !sq && !dq => {
                if in_tok {
                    toks.push(Token {
                        chars: std::mem::take(&mut cur),
                        quoted: std::mem::replace(&mut quoted, false),
                    });
                    in_tok = false;
                }
            }
            _ => {
                cur.push((c, !sq));
                in_tok = true;
            }
        }
    }
    if sq || dq {
        return Err("unterminated quote".to_string());
    }
    if in_tok {
        toks.push(Token { chars: cur, quoted });
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
            let mut vars = HashMap::new();
            let mut funcs = HashMap::new();
            let mut interp = Interpreter {
                fs: &mut fs,
                out: &mut out,
                depth,
                vars: &mut vars,
                funcs: &mut funcs,
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

    fn run_session(script: &str) -> (Vec<u8>, Result<i32, String>) {
        let mut sess = Session::default();
        let mut fs = WinFs::new();
        let mut out = Vec::new();
        let r = run_ps1_session(&mut sess, &mut fs, script, &mut out);
        (out, r)
    }

    #[test]
    fn variables_assign_read_case_insensitive() {
        let (out, r) = run_session("$Repo = Open-Tech-Foundation/ES-Runtime\necho $Repo\necho $repo");
        assert!(r.is_ok());
        assert_eq!(out, b"Open-Tech-Foundation/ES-Runtime\nOpen-Tech-Foundation/ES-Runtime\n");
    }

    #[test]
    fn undefined_var_expands_empty() {
        let (out, r) = run_session("echo a$Nope_XYZ_123 b");
        assert!(r.is_ok());
        assert_eq!(out, b"a b\n");
    }

    #[test]
    fn null_and_home() {
        let (out, r) = run_session("echo x$null y");
        assert!(r.is_ok());
        assert_eq!(out, b"x y\n");
        let home = std::env::var("HOME").unwrap_or_default();
        let (out, r) = run_session("echo $HOME");
        assert!(r.is_ok());
        assert_eq!(out, format!("{home}\n").as_bytes());
    }

    #[test]
    fn env_var_reads_host() {
        std::env::set_var("WINCLI_TEST_VAR_XYZ", "env-ok");
        let (out, r) = run_session("echo $env:WINCLI_TEST_VAR_XYZ");
        std::env::remove_var("WINCLI_TEST_VAR_XYZ");
        assert!(r.is_ok());
        assert_eq!(out, b"env-ok\n");
        let (_, r) = run_session("echo $env:WINCLI_DEFINITELY_NOT_SET_XYZ");
        assert!(r.is_ok());
    }

    #[test]
    fn assignment_shape_errors() {
        assert!(run_session("$x =").1.is_err());
        assert!(run_session("$x = a b").1.is_err());
        assert!(run_session("$x == 1").1.unwrap_err().contains("comparison"));
        assert!(run_session("$env:A = b").1.unwrap_err().contains("$env:"));
        assert!(run_session("$HOME = b").1.unwrap_err().contains("$HOME"));
        assert!(run_session("$null = b").1.unwrap_err().contains("$null"));
    }

    #[test]
    fn double_quoted_interpolation() {
        let (out, r) = run_session("$name = World\necho \"Hello $name\"");
        assert!(r.is_ok());
        assert_eq!(out, b"Hello World\n");
    }

    #[test]
    fn single_quoted_stays_verbatim() {
        let (out, r) = run_session("$name = World\necho '$name'");
        assert!(r.is_ok());
        assert_eq!(out, b"$name\n");
    }

    #[test]
    fn braced_and_adjacent_names() {
        let (out, r) = run_session("$name = World\necho \"a${name}b\"");
        assert!(r.is_ok());
        assert_eq!(out, b"aWorldb\n");
    }

    #[test]
    fn subexpression_runs_and_trims() {
        let (out, r) = run_session("echo \"v$(echo 42)\"");
        assert!(r.is_ok());
        assert_eq!(out, b"v42\n");
        // Empty subexpression.
        let (out, r) = run_session("echo \"a$()b\"");
        assert!(r.is_ok());
        assert_eq!(out, b"ab\n");
        // (Nested same-shape strings are unreliable without escapes;
        // see the iex nesting test.)
    }

    #[test]
    fn unbalanced_delimiters_fail() {
        assert!(run_session("echo \"a$(echo b\"").1.is_err());
        assert!(run_session("echo \"a${b\"").1.is_err());
    }

    #[test]
    fn if_branches_on_truthiness() {
        let (out, r) = run_session("$x = 1\nif ($x) { echo yes }");
        assert!(r.is_ok());
        assert_eq!(out, b"yes\n");
        let (out, r) = run_session("if ($Nope_X) { echo bad } else { echo fallback }");
        assert!(r.is_ok());
        assert_eq!(out, b"fallback\n");
    }

    #[test]
    fn if_eq_ne_case_insensitive() {
        let (out, r) = run_session("if (A -eq a) { echo ci }");
        assert!(r.is_ok());
        assert_eq!(out, b"ci\n");
        let (out, r) = run_session("if (A -ne b) { echo ne }");
        assert!(r.is_ok());
        assert_eq!(out, b"ne\n");
        let (out, r) = run_session("if ($Nope_X -eq 1) { echo bad } else { echo els }");
        assert!(r.is_ok());
        assert_eq!(out, b"els\n");
    }

    #[test]
    fn if_not_and_literals() {
        let (out, r) = run_session("if (-not $Nope_X) { echo not-ok }");
        assert!(r.is_ok());
        assert_eq!(out, b"not-ok\n");
        let (out, r) = run_session("if ($true) { echo t }");
        assert!(r.is_ok());
        assert_eq!(out, b"t\n");
        let (out, r) = run_session("if ($false) { echo bad } else { echo f }");
        assert!(r.is_ok());
        assert_eq!(out, b"f\n");
    }

    #[test]
    fn if_elseif_else_chain_and_nesting() {
        let script = "$x = 2\nif ($x -eq 1) { echo one } elseif ($x -eq 2) { echo two } else { echo other }";
        let (out, r) = run_session(script);
        assert!(r.is_ok());
        assert_eq!(out, b"two\n");
        // Multi-line shape with next-line elseif.
        let script = "if ($Nope_X) {\n echo bad\n}\nelseif ($Nope_Y) {\n echo bad2\n}\nelse {\n echo els\n}";
        let (out, r) = run_session(script);
        assert!(r.is_ok());
        assert_eq!(out, b"els\n");
        // Taken branch skips the rest; nesting works.
        let (out, r) = run_session("if (1 -eq 1) { if (2 -eq 2) { echo nest } } else { echo bad }");
        assert!(r.is_ok());
        assert_eq!(out, b"nest\n");
    }

    #[test]
    fn if_unsupported_conditions_fail_clearly() {
        assert!(run_session("if ($x -match y) { echo bad }").1.unwrap_err().contains("-match"));
        assert!(run_session("if ($x.Split('y') -eq 'a') { echo bad }").1.unwrap_err().contains("not supported"));
        assert!(run_session("if (($a -eq $b)) { echo bad }").1.is_err());
        assert!(run_session("if ($x) { echo bad } else ($y) { echo bad }").1.unwrap_err().contains("no condition"));
    }

    #[test]
    fn throw_surfaces_message() {
        assert_eq!(
            run_session("throw boom-message").1.unwrap_err(),
            "boom-message"
        );
        assert!(run_session("throw").1.is_err());
    }

    #[test]
    fn builtin_capture_in_assignment() {
        // `$x = Join-Path ...` runs the builtin capturing its output.
        let (out, r) = run_session("$d = Join-Path \"C:\\base\" sub\necho $d");
        assert!(r.is_ok());
        assert_eq!(out, b"C:\\base\\sub\n");
        // Trailing/leading separators collapse; roots survive.
        let (out, r) = run_session("$r = Join-Path 'C:\\' 'bin'\necho $r");
        assert!(r.is_ok());
        assert_eq!(out, b"C:\\bin\n");
        // Any builtin captures, including echo itself.
        let (out, r) = run_session("$t = echo captured\necho $t");
        assert!(r.is_ok());
        assert_eq!(out, b"captured\n");
        // Out-Null sinks pipeline output.
        let (out, r) = run_session("echo hi | Out-Null");
        assert!(r.is_ok());
        assert_eq!(out, b"");
    }

    #[test]
    fn try_catch_finally_paths() {
        // Clean run: try + finally.
        let (out, r) = run_session("try { echo t } catch { echo c } finally { echo f }");
        assert!(r.is_ok());
        assert_eq!(out, b"t\nf\n");
        // Error: catch runs, error swallowed, finally runs.
        let (out, r) = run_session("try { throw boom } catch { echo caught } finally { echo fin }");
        assert!(r.is_ok());
        assert_eq!(out, b"caught\nfin\n");
        // No catch: finally runs, error propagates (with partial output).
        let (out, r) = run_session("try { echo t } catch { echo c } finally { echo f2 }");
        assert!(r.is_ok());
        assert_eq!(out, b"t\nf2\n");
        let (out, r) = run_session("try { throw x } finally { echo f2 }");
        assert_eq!(r.unwrap_err(), "x");
        assert_eq!(out, b"f2\n");
        // Catch error replaces; no try output survives it silently.
        let (out, r) = run_session("try { throw a } catch { throw b } finally { echo f }");
        assert_eq!(r.unwrap_err(), "b");
        assert_eq!(out, b"f\n");
    }

    #[test]
    fn try_finally_break_propagates() {
        // Break in try runs finally, then leaves the loop.
        let script = "foreach ($i in @('a', 'b', 'c')) { try { if ($i -eq 'b') { break } echo \"kept-$i\" } finally { echo fin } }";
        let (out, r) = run_session(script);
        assert!(r.is_ok());
        assert_eq!(out, b"kept-a\nfin\nfin\n");
    }

    #[test]
    fn try_shape_errors() {
        assert!(run_session("try echo hi").1.unwrap_err().contains("needs {body}"));
        assert!(run_session("try { echo hi } catch echo").1.unwrap_err().contains("needs {body}"));
        assert!(run_session("try { echo hi } finally").1.unwrap_err().contains("needs {body}"));
        assert!(run_session("try { echo hi } finally { echo f } finally { echo g }").1.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn hashtable_containskey_and_index() {
        let script = "$u = @{}\nif ($u.ContainsKey('esrun')) { echo bad } else { echo miss }\n$u['esrun'] = 'no asset'\nif ($u.ContainsKey('esrun')) { echo hit }\necho $u['esrun']";
        let (out, r) = run_session(script);
        assert!(r.is_ok());
        assert_eq!(out, b"miss\nhit\nno asset\n");
        // Missing keys read empty; other-method and entry literals fail.
        let (out, r) = run_session("$u = @{}\necho \"x$u['nope']y\"");
        assert!(r.is_ok());
        assert_eq!(out, b"xy\n");
        assert!(run_session("$u = @{a=1}").1.unwrap_err().contains("entries"));
        assert!(run_session("echo $u.Length('x')").1.unwrap_err().contains("method"));
        assert!(run_session("$s = 'ab'\necho $s.Foo()").1.unwrap_err().contains("method"));
    }

    #[test]
    fn array_index_reads() {
        let (out, r) = run_session("$a = @('x', 'y')\necho $a[1]");
        assert!(r.is_ok());
        assert_eq!(out, b"y\n");
        let (out, r) = run_session("$a = @('x', 'y')\necho $a[-1]");
        assert!(r.is_ok());
        assert_eq!(out, b"y\n");
        let (out, r) = run_session("$a = @('x')\necho \"a$b[5]c\"");
        assert!(r.is_ok());
        assert_eq!(out, b"ac\n");
        assert!(run_session("$a = @('x')\necho $a[nope]").1.unwrap_err().contains("integer"));
        assert!(run_session("$nosuch[0] = 1").1.unwrap_err().contains("hashtable"));
    }

    #[test]
    fn foreach_iterates_arrays_literals_scalars() {
        let (out, r) = run_session("$c = @('a', 'b')\nforeach ($i in $c) { echo \"got-$i\" }");
        assert!(r.is_ok());
        assert_eq!(out, b"got-a\ngot-b\n");
        let (out, r) = run_session("foreach ($i in @('x', 'y')) { echo $i }");
        assert!(r.is_ok());
        assert_eq!(out, b"x\ny\n");
        let (out, r) = run_session("foreach ($i in solo) { echo $i }");
        assert!(r.is_ok());
        assert_eq!(out, b"solo\n");
    }

    #[test]
    fn foreach_break_continue() {
        let script = "foreach ($i in @('a', 'b', 'c', 'd')) { if ($i -eq 'b') { continue } if ($i -eq 'd') { break } echo \"kept-$i\" }";
        let (out, r) = run_session(script);
        assert!(r.is_ok());
        assert_eq!(out, b"kept-a\nkept-c\n");
        // Nested loops: inner break stays inner.
        let script = "foreach ($o in @('1', '2')) { foreach ($i in @('a', 'b')) { if ($i -eq 'b') { break } echo \"$o$i\" } }";
        let (out, r) = run_session(script);
        assert!(r.is_ok());
        assert_eq!(out, b"1a\n2a\n");
        // Stray top-level break/continue are ignored.
        assert!(run_session("break").1.is_ok());
        assert!(run_session("continue").1.is_ok());
    }

    #[test]
    fn foreach_shape_errors() {
        assert!(run_session("foreach $x in $y { echo $x }").1.unwrap_err().contains("($var"));
        assert!(run_session("foreach ($x in $y)").1.unwrap_err().contains("{body}"));
        assert!(run_session("foreach ($1 in $y) { echo $1 }").1.unwrap_err().contains("loop variable"));
        assert!(run_session("foreach ($x in $y) { echo $x } extra").1.unwrap_err().contains("unexpected text"));
    }

    #[test]
    fn function_define_call_params() {
        let (out, r) = run_session("function Hi($who) { echo \"hi-$who\" }\nHi world");
        assert!(r.is_ok());
        assert_eq!(out, b"hi-world\n");
        // Missing args become "", extra args fail.
        let (out, r) = run_session("function F($a, $b) { echo \"$a-$b\" }\nF only");
        assert!(r.is_ok());
        assert_eq!(out, b"only-\n");
        assert!(run_session("function F($a) { echo $a }\nF 1 2").1.unwrap_err().contains("too many"));
        // Unknown commands still fail.
        assert!(run_session("NoSuchFn 1").1.unwrap_err().contains("unknown command"));
        // Param-less form and redefinition.
        let (out, r) = run_session("function P { echo one }\nP\nfunction P { echo two }\nP");
        assert!(r.is_ok());
        assert_eq!(out, b"one\ntwo\n");
        // Names are case-insensitive, dashes allowed.
        let (out, r) = run_session("function Install-One($b) { echo \"got-$b\" }\ninstall-one X");
        assert!(r.is_ok());
        assert_eq!(out, b"got-X\n");
        assert!(run_session("function 1bad { echo x }").1.unwrap_err().contains("function name"));
    }

    #[test]
    fn function_output_captures_and_scopes() {
        // Call output captured by assignment (1 line → string).
        let (out, r) = run_session("function GetIt($x) { echo \"got-$x\" }\n$t = GetIt world\necho $t");
        assert!(r.is_ok());
        assert_eq!(out, b"got-world\n");
        // Writes are local to the call (child scope).
        let (out, r) = run_session("$v = outer\nfunction Sc($v) { echo \"in-$v\" }\nSc inner\necho $v");
        assert!(r.is_ok());
        assert_eq!(out, b"in-inner\nouter\n");
    }

    #[test]
    fn switch_assigns_matched_value() {
        let script = "$arch = switch (\"AMD64\") { \"AMD64\" { \"x86-64\" } \"ARM64\" { \"arm64\" } default { throw \"unsupported\" } }\necho $arch";
        let (out, r) = run_session(script);
        assert!(r.is_ok());
        assert_eq!(out, b"x86-64\n");
    }

    #[test]
    fn switch_statement_default_and_case() {
        let (out, r) = run_session("switch (\"b\") { \"a\" { echo A } \"b\" { echo B } }");
        assert!(r.is_ok());
        assert_eq!(out, b"B\n");
        let (out, r) = run_session("switch (\"z\") { \"a\" { echo A } default { echo D } }");
        assert!(r.is_ok());
        assert_eq!(out, b"D\n");
        // Case-insensitive, no match no default is silent.
        let (out, r) = run_session("switch (\"amd64\") { \"AMD64\" { echo y } }");
        assert!(r.is_ok());
        assert_eq!(out, b"y\n");
        let (out, r) = run_session("switch (\"z\") { \"a\" { echo A } }");
        assert!(r.is_ok());
        assert!(out.is_empty());
    }

    #[test]
    fn switch_multi_output_is_array() {
        let (out, r) = run_session("$v = switch ('x') { 'x' { echo a; echo b } }\necho $v");
        assert!(r.is_ok());
        assert_eq!(out, b"a b\n");
    }

    #[test]
    fn switch_nested_pipe_in_branch() {
        let (out, r) = run_session("switch ('x') { 'x' { echo 'echo deep' | iex } }");
        assert!(r.is_ok());
        assert_eq!(out, b"deep\n");
    }

    #[test]
    fn switch_shape_errors() {
        assert!(run_session("switch -regex ('a') { 'a' { echo y } }").1.unwrap_err().contains("flags"));
        assert!(run_session("switch $x { 'a' { echo y } }").1.unwrap_err().contains("needs (value)"));
        assert!(run_session("switch ('a') { { $_ } { echo y } }").1.unwrap_err().contains("scriptblock"));
        assert!(run_session("switch ('a') { 'a' 'b' }").1.is_err());
    }

    #[test]
    fn bare_quoted_and_dollar_emit() {
        let (out, r) = run_session("\"hi\"");
        assert!(r.is_ok());
        assert_eq!(out, b"hi\n");
        let (out, r) = run_session("$v = 7\necho \"$v\"");
        assert!(r.is_ok());
        assert_eq!(out, b"7\n");
    }

    #[test]
    fn arrays_literal_count_and_join() {
        let (out, r) = run_session("$Bins = @('esrun', 'esdev')\necho $Bins");
        assert!(r.is_ok());
        assert_eq!(out, b"esrun esdev\n");
        let (out, r) = run_session("$Bins = @('esrun', 'esdev')\nif ($Bins.Count -eq 2) { echo c }");
        assert!(r.is_ok());
        assert_eq!(out, b"c\n");
        let (out, r) = run_session("$Bins = @('esrun')\nif ($Bins.Length -eq 1) { echo len }");
        assert!(r.is_ok());
        assert_eq!(out, b"len\n");
        let (out, r) = run_session("$e = @()\nif ($e.Count -eq 0) { echo empty }");
        assert!(r.is_ok());
        assert_eq!(out, b"empty\n");
    }

    #[test]
    fn in_contains_family() {
        let pre = "$Bins = @('esrun', 'esdev')\n";
        for (cond, want) in [
            ("if (esrun -in $Bins) { echo y }", "y\n"),
            ("if (foo -in $Bins) { echo y } else { echo n }", "n\n"),
            ("if (foo -notin $Bins) { echo y }", "y\n"),
            ("if ($Bins -contains esdev) { echo y }", "y\n"),
            ("if ($Bins -notcontains foo) { echo y }", "y\n"),
            ("if (ESRUN -in $Bins) { echo y }", "y\n"),
            ("if ('x' -in @('a', 'x')) { echo y }", "y\n"),
            ("if ('x' -in 'x') { echo y }", "y\n"),
        ] {
            let (out, r) = run_session(&format!("{pre}{cond}"));
            assert!(r.is_ok(), "{cond}");
            assert_eq!(out, want.as_bytes(), "{cond}");
        }
    }

    #[test]
    fn append_grows_arrays() {
        // null + scalar stays scalar.
        let (out, r) = run_session("$u += \"b\"\necho $u");
        assert!(r.is_ok());
        assert_eq!(out, b"b\n");
        // scalar + scalar becomes an array.
        let (out, r) = run_session("$s = \"a\"\n$s += \"b\"\necho $s");
        assert!(r.is_ok());
        assert_eq!(out, b"a b\n");
        // empty array stays an array (Count works).
        let (out, r) = run_session("$e = @()\n$e += \"x\"\nif ($e.Count -eq 1) { echo y }");
        assert!(r.is_ok());
        assert_eq!(out, b"y\n");
        // array extends.
        let (out, r) = run_session("$a = @('x')\n$a += 'y'\necho $a");
        assert!(r.is_ok());
        assert_eq!(out, b"x y\n");
    }

    #[test]
    fn array_and_membership_shape_errors() {
        assert!(run_session("$a = @('x',,'y')").1.is_err());
        assert!(run_session("$a = @('x'").1.is_err());
        assert!(run_session("$a = @('x') extra").1.unwrap_err().contains("after array"));
        // No-space `@(...)` on the collection side works.
        let (out, r) = run_session("if (@('a') -contains 'a') { echo y }");
        assert!(r.is_ok());
        assert_eq!(out, b"y\n");
        // Arrays as items and method calls fail clearly.
        assert!(run_session("if (@('a') -in $Bins) { echo y }").1.unwrap_err().contains("items"));
        assert!(run_session("if ($x -match y) { echo y }").1.unwrap_err().contains("-match"));
        assert!(run_session("if ($x.Split('@') -eq 'a') { echo y }").1.unwrap_err().contains("not supported"));
    }

    #[test]
    fn interpolated_assignment_value() {
        let (out, r) = run_session("$name = World\n$t = \"$name!\"\necho $t");
        assert!(r.is_ok());
        assert_eq!(out, b"World!\n");
        // Single-quoted values stay literal.
        let (out, r) = run_session("$name = World\n$t = '$name'\necho $t");
        assert!(r.is_ok());
        assert_eq!(out, b"$name\n");
    }
}
