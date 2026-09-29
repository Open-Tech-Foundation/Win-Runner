//! A narrow `cmd.exe`: enough of the command processor for programs that
//! shell out through `%ComSpec% /d /s /c "..."` and for the `.cmd`/`.bat`
//! launchers that npm, pip, and similar tools generate.
//!
//! Supported: `/c` and `/k` with cmd's quote-stripping rules; `&`, `&&`,
//! `||`, `( )` blocks, and `>`, `>>`, `2>&1`, `<`, `nul` redirection;
//! `%VAR%` (with `:a=b` substitution and `:~n,m` substrings), `%*`, `%0`-`%9`
//! and `%~dp0`-style modifiers, expanded a whole line at a time as cmd does;
//! batch files with labels, `goto`, `call`, `exit /b`, `setlocal`, `shift`;
//! `if` and `for` (including `for /f` over command output); and the common
//! internal commands, `set /a` arithmetic, `set /p`, pipes (run one side
//! after the other through a temporary file), and delayed `!var!`
//! expansion under `setlocal enabledelayedexpansion` or `cmd /v:on`. Not
//! supported: an interactive prompt.
//!
//! The processor is platform-neutral: a [`CmdHost`] supplies the guest
//! filesystem, runs programs, and receives cmd's own output.

use crate::winfs::WinFs;
use std::collections::HashMap;
use std::rc::Rc;

/// Batch calls nest at most this deep, like cmd's recursion guard.
const MAX_CALL_DEPTH: usize = 64;

/// Where a command's output goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// cmd's own standard output.
    Stdout,
    /// cmd's own standard error.
    Stderr,
    /// `nul`.
    Null,
    /// Append to this guest file (redirection truncates it once, up front).
    File(String),
    /// Collected for `for /f` over a command's output.
    Capture,
}

/// A program for the host to start and wait for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    pub application: String,
    /// The full Windows command line, including the program as typed.
    pub command_line: String,
    pub current_directory: String,
    pub environment: Vec<(String, String)>,
    /// Guest file for standard input, from `<`.
    pub stdin: Option<String>,
    pub stdout: Output,
    pub stderr: Output,
}

pub trait CmdHost {
    fn with_fs<R>(&mut self, action: impl FnOnce(&mut WinFs) -> R) -> R;
    /// Start a program and wait for it. Returns its exit code and, when
    /// either stream is [`Output::Capture`], what it wrote there.
    fn run(&mut self, request: &RunRequest) -> Result<(u32, Vec<u8>), String>;
    /// cmd's own output: `false` for standard output, `true` for error.
    fn write(&mut self, stderr: bool, bytes: &[u8]);
    /// One line from cmd's standard input for `set /p`, without its line
    /// ending; `None` at end of input.
    fn read_line(&mut self) -> Option<String> {
        None
    }
}

/// Run `cmd.exe` with its full command line (program name first), starting
/// in `current_directory` with `environment`. Returns the exit code.
pub fn run_command_line<H: CmdHost>(
    host: &mut H,
    command_line: &str,
    environment: Vec<(String, String)>,
    current_directory: String,
) -> u32 {
    let executable = |host: &mut H, path: &str| {
        let full = collapse_path(&if path.contains(':') {
            path.to_string()
        } else {
            format!(r"{}\{path}", current_directory.trim_end_matches('\\'))
        });
        host.with_fs(|fs| fs.is_file(&full) || fs.is_file(&format!("{full}.exe")))
    };
    let (command, delayed) =
        match command_after_switches(command_line, |path| executable(host, path)) {
            Ok(command) => command,
            Err(message) => {
                host.write(true, message.as_bytes());
                return 1;
            }
        };
    let mut cmd = Cmd {
        host,
        environment,
        cwd: current_directory,
        errorlevel: 0,
        echo: true,
        delayed,
        locals: Vec::new(),
        directories: Vec::new(),
        frames: Vec::new(),
        capture: Vec::new(),
        command_line: command_line.to_string(),
        random: 0x2545_f491,
    };
    cmd.run_line(&command)
}

/// The command after `/c` or `/k`, and whether `/v:on` enabled delayed
/// expansion. Quotes follow cmd's rules: a leading quote and the last quote
/// are removed, unless (without `/s`) the text has exactly two quotes
/// enclosing an existing executable's name that contains whitespace and no
/// special characters.
fn command_after_switches(
    command_line: &str,
    is_executable: impl FnMut(&str) -> bool,
) -> Result<(String, bool), String> {
    let mut rest = skip_program_name(command_line);
    let mut strip = false;
    let mut delayed = false;
    loop {
        rest = rest.trim_start();
        if !rest.starts_with('/') {
            return Err(
                "winrun's cmd.exe runs commands with /c; the interactive prompt is not supported.\r\n"
                    .to_string(),
            );
        }
        let end = rest[1..]
            .find(|character: char| character.is_whitespace() || character == '/')
            .map_or(rest.len(), |index| index + 1);
        let switch = rest[..end].to_ascii_lowercase();
        rest = &rest[end..];
        match switch.as_str() {
            "/c" | "/k" => break,
            "/s" => strip = true,
            "/v" | "/v:on" => delayed = true,
            "/v:off" => delayed = false,
            _ => {}
        }
    }
    let command = rest.strip_prefix(' ').unwrap_or(rest).trim_start();
    Ok((strip_command_quotes(command, strip, is_executable), delayed))
}

fn strip_command_quotes(
    command: &str,
    strip: bool,
    mut is_executable: impl FnMut(&str) -> bool,
) -> String {
    if !command.starts_with('"') {
        return command.to_string();
    }
    // The run between the first two quotes; what follows the second quote
    // (arguments) does not matter.
    let quoted = command[1..].find('"').map(|end| &command[1..end + 1]);
    let keep = !strip
        && command.matches('"').count() == 2
        && quoted.is_some_and(|quoted| {
            quoted.chars().any(char::is_whitespace)
                && !quoted.contains(['&', '<', '>', '(', ')', '@', '^', '|'])
                && is_executable(quoted)
        });
    if keep {
        return command.to_string();
    }
    let without_first = &command[1..];
    match without_first.rfind('"') {
        Some(last) => format!("{}{}", &without_first[..last], &without_first[last + 1..]),
        None => without_first.to_string(),
    }
}

fn skip_program_name(command_line: &str) -> &str {
    let text = command_line.trim_start();
    if let Some(quoted) = text.strip_prefix('"') {
        return quoted.find('"').map_or("", |end| &quoted[end + 1..]);
    }
    text.find(char::is_whitespace)
        .map_or("", |end| &text[end..])
}

/// Where Windows keeps `cmd.exe`, and where `%ComSpec%` points.
pub fn cmd_exe_path() -> String {
    format!(r"{}\cmd.exe", crate::system_profile::SYSTEM32)
}

/// A minimal PE whose entry point runs this processor through the private
/// `WinrunCmdMain` native export and exits with its result, so cmd.exe runs
/// as a real child process with its own command line and handles.
pub fn cmd_exe_image() -> Vec<u8> {
    use crate::pe::builder::{build, Asm};
    let mut asm = Asm::new();
    asm.sub_rsp(0x28);
    asm.call_import(0);
    asm.emit(&[0x89, 0xC1]); // mov ecx, eax
    asm.call_import(1);
    asm.add_rsp(0x28);
    asm.ret();
    build(
        asm,
        &[
            ("KERNEL32.dll", "WinrunCmdMain"),
            ("KERNEL32.dll", "ExitProcess"),
        ],
    )
}

/// Split a Windows command line into arguments with the MSVC/
/// `CommandLineToArgvW` rules: backslashes are literal unless they precede
/// a quote, `""` inside quotes is a quote, and an unterminated quote runs
/// to the end.
pub fn split_windows_command_line(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut arguments = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index == chars.len() {
            break;
        }
        let mut argument = String::new();
        let mut quoted = false;
        while index < chars.len() {
            let mut slashes = 0;
            while index < chars.len() && chars[index] == '\\' {
                slashes += 1;
                index += 1;
            }
            if index < chars.len() && chars[index] == '"' {
                argument.extend(std::iter::repeat_n('\\', slashes / 2));
                if slashes % 2 == 1 {
                    argument.push('"');
                } else if quoted && chars.get(index + 1) == Some(&'"') {
                    argument.push('"');
                    index += 1;
                } else {
                    quoted = !quoted;
                }
                index += 1;
                continue;
            }
            argument.extend(std::iter::repeat_n('\\', slashes));
            if index == chars.len() || (!quoted && chars[index].is_whitespace()) {
                break;
            }
            argument.push(chars[index]);
            index += 1;
        }
        arguments.push(argument);
    }
    arguments
}

/// The `cmd.exe` command line that runs `path` with `arguments`, quoting
/// words with spaces the way cmd reads them back.
pub fn batch_command_line(path: &str, arguments: &[String]) -> String {
    let quote = |word: &str| {
        if word.is_empty() || word.contains([' ', '\t']) {
            format!("\"{word}\"")
        } else {
            word.to_string()
        }
    };
    let mut command = quote(path);
    for argument in arguments {
        command.push(' ');
        command.push_str(&quote(argument));
    }
    format!("{} /d /s /c \"{command}\"", cmd_exe_path())
}

/// Put `cmd.exe` in System32 unless the disk already has one.
pub fn seed_cmd_exe(fs: &mut WinFs) {
    let path = cmd_exe_path();
    if fs.is_file(&path) || fs.mkdir(crate::system_profile::SYSTEM32).is_err() {
        return;
    }
    let _ = fs.write_file(&path, cmd_exe_image());
}

// ---- parsing ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Empty,
    Command {
        text: String,
        redirects: Vec<Redirect>,
    },
    Block {
        body: Box<Node>,
        redirects: Vec<Redirect>,
    },
    If {
        case_insensitive: bool,
        negate: bool,
        condition: Condition,
        then: Box<Node>,
        otherwise: Option<Box<Node>>,
    },
    For {
        variable: char,
        kind: ForKind,
        set: String,
        body: String,
    },
    Seq(Box<Node>, Box<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Pipe(Box<Node>, Box<Node>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Condition {
    Exist(String),
    Defined(String),
    ErrorLevel(u32),
    Compare {
        left: String,
        op: CompareOp,
        right: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompareOp {
    Equal,
    Equ,
    Neq,
    Lss,
    Leq,
    Gtr,
    Geq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ForKind {
    List,
    Lines(String),
    Range,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Redirect {
    fd: u8,
    kind: RedirectKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RedirectKind {
    Write { path: String, append: bool },
    Duplicate(u8),
    Read(String),
}

const SYNTAX_ERROR: &str = "The syntax of the command is incorrect.";

struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
}

fn parse(text: &str) -> Result<Node, String> {
    let mut parser = Parser {
        chars: text.chars().collect(),
        pos: 0,
        depth: 0,
    };
    let node = parser.seq(false)?;
    parser.skip_blank();
    if parser.pos < parser.chars.len() {
        return Err(SYNTAX_ERROR.to_string());
    }
    Ok(node)
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn starts_with(&self, text: &str) -> bool {
        text.chars()
            .enumerate()
            .all(|(index, expected)| self.peek_at(index) == Some(expected))
    }

    /// `word` (ASCII, any case) followed by whitespace, `(`, a quote, or
    /// the end.
    fn at_word(&self, word: &str) -> bool {
        let matches = word.chars().enumerate().all(|(index, expected)| {
            self.peek_at(index)
                .is_some_and(|actual| actual.eq_ignore_ascii_case(&expected))
        });
        matches
            && self
                .peek_at(word.len())
                .is_none_or(|next| next.is_whitespace() || next == '(' || next == '"')
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\r')) {
            self.pos += 1;
        }
    }

    fn skip_blank(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.pos += 1;
        }
    }

    fn at_sequence_end(&self) -> bool {
        match self.peek() {
            None => true,
            Some(')') => self.depth > 0,
            _ => false,
        }
    }

    /// Commands joined by `&`. With `line`, the sequence ends at the end
    /// of the line (the command of an `if` or `for`); otherwise newlines,
    /// which only occur inside blocks, also separate commands.
    fn seq(&mut self, line: bool) -> Result<Node, String> {
        let mut left = self.and_or()?;
        loop {
            self.skip_ws();
            match self.peek() {
                Some('&') if self.peek_at(1) != Some('&') => self.pos += 1,
                Some('\n') if !line => self.pos += 1,
                _ => break,
            }
            self.skip_ws();
            if !line {
                self.skip_blank();
            }
            if self.at_sequence_end() || (line && self.peek() == Some('\n')) {
                break;
            }
            let right = self.and_or()?;
            left = Node::Seq(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and_or(&mut self) -> Result<Node, String> {
        let mut left = self.pipe()?;
        loop {
            self.skip_ws();
            let and = if self.starts_with("&&") {
                true
            } else if self.starts_with("||") {
                false
            } else {
                break;
            };
            self.pos += 2;
            self.skip_blank();
            let right = self.pipe()?;
            left = if and {
                Node::And(Box::new(left), Box::new(right))
            } else {
                Node::Or(Box::new(left), Box::new(right))
            };
        }
        Ok(left)
    }

    fn pipe(&mut self) -> Result<Node, String> {
        let mut left = self.unit()?;
        loop {
            self.skip_ws();
            if self.peek() == Some('|') && self.peek_at(1) != Some('|') {
                self.pos += 1;
                let right = self.unit()?;
                left = Node::Pipe(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn unit(&mut self) -> Result<Node, String> {
        self.skip_ws();
        while self.peek() == Some('@') {
            self.pos += 1;
            self.skip_ws();
        }
        if self.at_sequence_end() || self.peek() == Some('\n') {
            return Ok(Node::Empty);
        }
        if self.peek() == Some('(') {
            self.pos += 1;
            self.depth += 1;
            self.skip_blank();
            let body = if self.peek() == Some(')') {
                Node::Empty
            } else {
                self.seq(false)?
            };
            self.skip_blank();
            if self.peek() != Some(')') {
                return Err(SYNTAX_ERROR.to_string());
            }
            self.pos += 1;
            self.depth -= 1;
            let redirects = self.trailing_redirects()?;
            return Ok(Node::Block {
                body: Box::new(body),
                redirects,
            });
        }
        if self.at_word("if") {
            return self.if_statement();
        }
        if self.at_word("for") {
            return self.for_statement();
        }
        if self.at_word("rem") || self.starts_with("::") {
            while self.peek().is_some_and(|character| character != '\n') {
                self.pos += 1;
            }
            return Ok(Node::Empty);
        }
        self.command()
    }

    fn command(&mut self) -> Result<Node, String> {
        let mut text = String::new();
        let mut redirects = Vec::new();
        let mut quoted = false;
        while let Some(character) = self.peek() {
            if quoted {
                if character == '\n' {
                    break;
                }
                text.push(character);
                self.pos += 1;
                quoted = character != '"';
                continue;
            }
            match character {
                '"' => {
                    quoted = true;
                    text.push(character);
                    self.pos += 1;
                }
                '^' => {
                    self.pos += 1;
                    match self.peek() {
                        Some('\n') => self.pos += 1,
                        Some(escaped) => {
                            text.push(escaped);
                            self.pos += 1;
                        }
                        None => {}
                    }
                }
                '&' | '|' | '\n' => break,
                ')' if self.depth > 0 => break,
                '<' | '>' => {
                    let fd = if character == '<' {
                        0
                    } else {
                        take_fd_prefix(&mut text)
                    };
                    redirects.push(self.redirect(fd)?);
                }
                _ => {
                    text.push(character);
                    self.pos += 1;
                }
            }
        }
        Ok(Node::Command { text, redirects })
    }

    fn redirect(&mut self, fd: u8) -> Result<Redirect, String> {
        let operator = self.peek();
        self.pos += 1;
        if operator == Some('<') {
            self.skip_ws();
            let path = self.word();
            if path.is_empty() {
                return Err(SYNTAX_ERROR.to_string());
            }
            return Ok(Redirect {
                fd: 0,
                kind: RedirectKind::Read(path),
            });
        }
        let append = self.peek() == Some('>');
        if append {
            self.pos += 1;
        }
        if self.peek() == Some('&') {
            if let Some(target @ ('0'..='9')) = self.peek_at(1) {
                self.pos += 2;
                return Ok(Redirect {
                    fd,
                    kind: RedirectKind::Duplicate(target as u8 - b'0'),
                });
            }
        }
        self.skip_ws();
        let path = self.word();
        if path.is_empty() {
            return Err(SYNTAX_ERROR.to_string());
        }
        Ok(Redirect {
            fd,
            kind: RedirectKind::Write { path, append },
        })
    }

    /// A redirection target or similar word, quotes removed.
    fn word(&mut self) -> String {
        let mut word = String::new();
        let mut quoted = false;
        while let Some(character) = self.peek() {
            if character == '"' {
                quoted = !quoted;
                self.pos += 1;
                continue;
            }
            if !quoted
                && (character.is_whitespace()
                    || matches!(character, '&' | '|' | '<' | '>' | '(')
                    || (character == ')' && self.depth > 0))
            {
                break;
            }
            word.push(character);
            self.pos += 1;
        }
        word
    }

    fn trailing_redirects(&mut self) -> Result<Vec<Redirect>, String> {
        let mut redirects = Vec::new();
        loop {
            self.skip_ws();
            match (self.peek(), self.peek_at(1)) {
                (Some('<' | '>'), _) => {
                    let fd = if self.peek() == Some('<') { 0 } else { 1 };
                    redirects.push(self.redirect(fd)?);
                }
                (Some(digit @ ('1' | '2')), Some('>')) => {
                    self.pos += 1;
                    redirects.push(self.redirect(digit as u8 - b'0')?);
                }
                _ => return Ok(redirects),
            }
        }
    }

    /// An `if` operand: a quoted run (quotes kept) or text up to
    /// whitespace or `==`.
    fn operand(&mut self) -> String {
        self.skip_ws();
        let mut operand = String::new();
        if self.peek() == Some('"') {
            operand.push('"');
            self.pos += 1;
            while let Some(character) = self.peek() {
                self.pos += 1;
                operand.push(character);
                if character == '"' {
                    break;
                }
            }
            return operand;
        }
        while let Some(character) = self.peek() {
            if character.is_whitespace()
                || self.starts_with("==")
                || matches!(character, '&' | '|' | '<' | '>' | '(')
                || (character == ')' && self.depth > 0)
            {
                break;
            }
            operand.push(character);
            self.pos += 1;
        }
        operand
    }

    fn if_statement(&mut self) -> Result<Node, String> {
        self.pos += 2;
        self.skip_ws();
        let (mut case_insensitive, mut negate) = (false, false);
        loop {
            if self.at_word("/i") {
                self.pos += 2;
                case_insensitive = true;
            } else if self.at_word("not") {
                self.pos += 3;
                negate = true;
            } else {
                break;
            }
            self.skip_ws();
        }
        let condition = if self.at_word("exist") {
            self.pos += 5;
            Condition::Exist(self.operand())
        } else if self.at_word("defined") {
            self.pos += 7;
            Condition::Defined(self.operand())
        } else if self.at_word("errorlevel") {
            self.pos += 10;
            let level = self
                .operand()
                .parse()
                .map_err(|_| SYNTAX_ERROR.to_string())?;
            Condition::ErrorLevel(level)
        } else {
            let left = self.operand();
            self.skip_ws();
            let op = if self.starts_with("==") {
                self.pos += 2;
                CompareOp::Equal
            } else {
                match self.operand().to_ascii_uppercase().as_str() {
                    "EQU" => CompareOp::Equ,
                    "NEQ" => CompareOp::Neq,
                    "LSS" => CompareOp::Lss,
                    "LEQ" => CompareOp::Leq,
                    "GTR" => CompareOp::Gtr,
                    "GEQ" => CompareOp::Geq,
                    _ => return Err(SYNTAX_ERROR.to_string()),
                }
            };
            let right = self.operand();
            if left.is_empty() || right.is_empty() {
                return Err(SYNTAX_ERROR.to_string());
            }
            Condition::Compare { left, op, right }
        };
        self.skip_ws();
        if self.at_sequence_end() || self.peek() == Some('\n') {
            return Err(SYNTAX_ERROR.to_string());
        }
        let block = self.peek() == Some('(');
        let then = if block { self.unit()? } else { self.seq(true)? };
        let mut otherwise = None;
        if block {
            self.skip_ws();
            if self.at_word("else") {
                self.pos += 4;
                self.skip_ws();
                otherwise = Some(Box::new(if self.peek() == Some('(') {
                    self.unit()?
                } else {
                    self.seq(true)?
                }));
            }
        }
        Ok(Node::If {
            case_insensitive,
            negate,
            condition,
            then: Box::new(then),
            otherwise,
        })
    }

    fn for_statement(&mut self) -> Result<Node, String> {
        self.pos += 3;
        self.skip_ws();
        let kind = if self.at_word("/f") {
            self.pos += 2;
            self.skip_ws();
            let mut options = String::new();
            if self.peek() == Some('"') {
                self.pos += 1;
                while let Some(character) = self.peek() {
                    self.pos += 1;
                    if character == '"' {
                        break;
                    }
                    options.push(character);
                }
            }
            ForKind::Lines(options)
        } else if self.at_word("/l") {
            self.pos += 2;
            ForKind::Range
        } else if self.peek() == Some('/') {
            return Err("winrun's cmd.exe supports for, for /f, and for /l only.".to_string());
        } else {
            ForKind::List
        };
        self.skip_ws();
        if self.peek() != Some('%') {
            return Err(SYNTAX_ERROR.to_string());
        }
        self.pos += 1;
        let variable = self.peek().ok_or_else(|| SYNTAX_ERROR.to_string())?;
        self.pos += 1;
        self.skip_ws();
        if !self.at_word("in") {
            return Err(SYNTAX_ERROR.to_string());
        }
        self.pos += 2;
        self.skip_ws();
        if self.peek() != Some('(') {
            return Err(SYNTAX_ERROR.to_string());
        }
        self.pos += 1;
        let mut set = String::new();
        let (mut depth, mut quoted) = (1usize, false);
        loop {
            let character = self.peek().ok_or_else(|| SYNTAX_ERROR.to_string())?;
            self.pos += 1;
            match character {
                '"' => quoted = !quoted,
                '(' if !quoted => depth += 1,
                ')' if !quoted => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            set.push(character);
        }
        self.skip_ws();
        if !self.at_word("do") {
            return Err(SYNTAX_ERROR.to_string());
        }
        self.pos += 2;
        self.skip_ws();
        let start = self.pos;
        if self.peek() == Some('(') {
            self.unit()?;
        } else {
            self.seq(true)?;
        }
        let body = self.chars[start..self.pos].iter().collect();
        Ok(Node::For {
            variable,
            kind,
            set,
            body,
        })
    }
}

/// A `1` or `2` typed directly before `>` names the stream (`2>nul`), but
/// only as its own word (`echo a2>x` writes `a2`).
fn take_fd_prefix(text: &mut String) -> u8 {
    let mut chars = text.chars().rev();
    match (chars.next(), chars.next()) {
        (Some(digit @ ('1' | '2')), previous) if previous.is_none_or(char::is_whitespace) => {
            text.pop();
            digit as u8 - b'0'
        }
        _ => 1,
    }
}

/// Net `(`/`)` count on a batch line, outside quotes and `^` escapes; used
/// to join a block's lines before parsing.
fn paren_delta(line: &str) -> isize {
    let trimmed = line.trim_start().trim_start_matches('@').trim_start();
    if trimmed.starts_with("::") || trimmed.to_ascii_lowercase().starts_with("rem ") {
        return 0;
    }
    let (mut delta, mut quoted, mut escaped) = (0isize, false, false);
    for character in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '^' if !quoted => escaped = true,
            '"' => quoted = !quoted,
            '(' if !quoted => delta += 1,
            ')' if !quoted => delta -= 1,
            _ => {}
        }
    }
    delta
}

/// Batch arguments: split on whitespace, `,`, `;`, and `=` outside quotes;
/// quotes stay part of the argument.
fn split_batch_arguments(raw: &str) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in raw.chars() {
        if character == '"' {
            quoted = !quoted;
            current.push(character);
        } else if !quoted && (character.is_whitespace() || matches!(character, ',' | ';' | '=')) {
            if !current.is_empty() {
                arguments.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if !current.is_empty() {
        arguments.push(current);
    }
    arguments
}

// ---- execution -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Io {
    stdin: Option<String>,
    stdout: Output,
    stderr: Output,
}

impl Io {
    fn console() -> Self {
        Io {
            stdin: None,
            stdout: Output::Stdout,
            stderr: Output::Stderr,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Next,
    /// Continue the current batch file at this line.
    Goto(usize),
    /// Leave the current batch file or subroutine.
    ExitBatch,
    /// Leave cmd.
    Exit,
}

struct Frame {
    /// The batch file's full path, for `%~dp0` and friends.
    path: String,
    /// `%0` as it was invoked.
    invoked: String,
    arguments: Vec<String>,
    /// `%*`.
    raw_arguments: String,
    lines: Rc<[String]>,
    labels: Rc<HashMap<String, usize>>,
    /// `setlocal` depth when the frame started; its end restores to it.
    locals: usize,
    /// A failed `goto` finishes the current line, then the batch file.
    stop_after_line: bool,
}

/// What `setlocal` saves: environment, directory, delayed expansion.
type LocalScope = (Vec<(String, String)>, String, bool);

struct Cmd<'h, H: CmdHost> {
    host: &'h mut H,
    environment: Vec<(String, String)>,
    cwd: String,
    errorlevel: u32,
    echo: bool,
    /// `!var!` expansion at execution time.
    delayed: bool,
    /// `setlocal` saves the environment, directory, and delayed expansion.
    locals: Vec<LocalScope>,
    directories: Vec<String>,
    frames: Vec<Frame>,
    capture: Vec<u8>,
    command_line: String,
    random: u32,
}

impl<H: CmdHost> Cmd<'_, H> {
    fn run_line(&mut self, line: &str) -> u32 {
        let expanded = self.expand(line, false);
        match parse(&expanded) {
            Ok(node) => {
                self.exec(&node, &Io::console());
            }
            Err(message) => {
                self.host.write(true, format!("{message}\r\n").as_bytes());
                self.errorlevel = 1;
            }
        }
        self.errorlevel
    }

    // -- output ---------------------------------------------------------------

    fn emit(&mut self, target: &Output, bytes: &[u8]) {
        match target {
            Output::Stdout => self.host.write(false, bytes),
            Output::Stderr => self.host.write(true, bytes),
            Output::Null => {}
            Output::File(path) => {
                let path = path.clone();
                let bytes = bytes.to_vec();
                let _ = self.host.with_fs(|fs| fs.append_file(&path, &bytes));
            }
            Output::Capture => self.capture.extend_from_slice(bytes),
        }
    }

    fn print(&mut self, io: &Io, text: &str) {
        self.emit(&io.stdout.clone(), format!("{text}\r\n").as_bytes());
    }

    /// Report a failed command on its error stream and set `errorlevel`.
    fn fail(&mut self, io: &Io, message: &str, level: u32) -> (u32, Flow) {
        self.emit(&io.stderr.clone(), format!("{message}\r\n").as_bytes());
        self.errorlevel = level;
        (level, Flow::Next)
    }

    // -- variables ------------------------------------------------------------

    fn variable(&mut self, name: &str) -> Option<String> {
        if let Some((_, value)) = self
            .environment
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            return Some(value.clone());
        }
        match name.to_ascii_lowercase().as_str() {
            "cd" => Some(self.cwd.clone()),
            "errorlevel" => Some(self.errorlevel.to_string()),
            "cmdextversion" => Some("2".to_string()),
            "cmdcmdline" => Some(self.command_line.clone()),
            "random" => {
                // xorshift: stable per process, like cmd's per-session seed.
                self.random ^= self.random << 13;
                self.random ^= self.random >> 17;
                self.random ^= self.random << 5;
                Some((self.random % 32768).to_string())
            }
            _ => None,
        }
    }

    fn set_variable(&mut self, name: &str, value: &str) {
        match self
            .environment
            .iter()
            .position(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            Some(index) if value.is_empty() => {
                self.environment.remove(index);
            }
            Some(index) => self.environment[index].1 = value.to_string(),
            None if value.is_empty() => {}
            None => self.environment.push((name.to_string(), value.to_string())),
        }
    }

    /// cmd's first expansion pass over a whole line (or block). In a batch
    /// file `%%` is a literal `%` and undefined variables become empty; on
    /// a command line they stay as typed.
    fn expand(&mut self, text: &str, batch: bool) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut output = String::new();
        let mut index = 0;
        while index < chars.len() {
            let character = chars[index];
            if character != '%' {
                output.push(character);
                index += 1;
                continue;
            }
            let next = chars.get(index + 1).copied();
            if batch && next == Some('%') {
                output.push('%');
                index += 2;
                continue;
            }
            if batch && !self.frames.is_empty() {
                if let Some(digit @ ('0'..='9')) = next {
                    output.push_str(&self.argument(digit as usize - '0' as usize, ""));
                    index += 2;
                    continue;
                }
                if next == Some('*') {
                    let raw = self.frames.last().unwrap().raw_arguments.clone();
                    output.push_str(raw.trim());
                    index += 2;
                    continue;
                }
                if next == Some('~') {
                    let mut end = index + 2;
                    while end < chars.len() && "fdpnxsatz".contains(chars[end].to_ascii_lowercase())
                    {
                        end += 1;
                    }
                    if let Some(digit @ ('0'..='9')) = chars.get(end).copied() {
                        let modifiers: String = chars[index + 2..end].iter().collect();
                        output.push_str(
                            &self.argument(digit as usize - '0' as usize, &format!("~{modifiers}")),
                        );
                        index = end + 1;
                        continue;
                    }
                }
            }
            let Some(close) = chars[index + 1..].iter().position(|c| *c == '%') else {
                if !batch {
                    output.push('%');
                }
                index += 1;
                continue;
            };
            let reference: String = chars[index + 1..index + 1 + close].iter().collect();
            let (name, spec) = match reference.split_once(':') {
                Some((name, spec)) => (name.to_string(), Some(spec.to_string())),
                None => (reference.clone(), None),
            };
            match (name.is_empty(), self.variable(&name)) {
                (false, Some(value)) => {
                    output.push_str(&apply_variable_spec(&value, spec.as_deref()));
                    index += close + 2;
                }
                _ if batch => index += close + 2,
                _ => {
                    // Keep the literal `%name`; the closing `%` may open
                    // the next reference.
                    output.push('%');
                    output.push_str(&reference);
                    index += close + 1;
                }
            }
        }
        output
    }

    /// `%N` or `%~<modifiers>N` in the current batch frame.
    fn argument(&self, number: usize, modifiers: &str) -> String {
        let frame = self.frames.last().unwrap();
        let value = if number == 0 {
            frame.invoked.clone()
        } else {
            frame.arguments.get(number - 1).cloned().unwrap_or_default()
        };
        let Some(modifiers) = modifiers.strip_prefix('~') else {
            return value;
        };
        let path = if number == 0 {
            frame.path.clone()
        } else {
            value.trim_matches('"').to_string()
        };
        if modifiers.is_empty() {
            return value.trim_matches('"').to_string();
        }
        self.path_modifiers(&path, modifiers)
    }

    fn path_modifiers(&self, path: &str, modifiers: &str) -> String {
        let full = self.full_path(path);
        let modifiers = modifiers.to_ascii_lowercase();
        if modifiers.contains('f') && !modifiers.contains(['d', 'p', 'n', 'x']) {
            return full;
        }
        let (directory, file) = full.rsplit_once('\\').unwrap_or(("", &full));
        let (stem, extension) = match file.rfind('.') {
            Some(dot) if dot > 0 => (&file[..dot], &file[dot..]),
            _ => (file, ""),
        };
        let (drive, rest) = if directory.len() >= 2 && directory.as_bytes()[1] == b':' {
            (&directory[..2], &directory[2..])
        } else {
            ("", directory)
        };
        let mut output = String::new();
        if modifiers.contains('d') {
            output.push_str(drive);
        }
        if modifiers.contains('p') {
            output.push_str(rest);
            output.push('\\');
        }
        if modifiers.contains('n') {
            output.push_str(stem);
        }
        if modifiers.contains('x') {
            output.push_str(extension);
        }
        output
    }

    // -- paths ----------------------------------------------------------------

    fn full_path(&self, path: &str) -> String {
        let path = path.trim_matches('"');
        let bytes = path.as_bytes();
        let absolute = if bytes.len() >= 2 && bytes[1] == b':' {
            if bytes.len() == 2 {
                format!("{path}\\")
            } else {
                path.to_string()
            }
        } else if path.starts_with("\\\\") {
            path.to_string()
        } else if path.starts_with('\\') || path.starts_with('/') {
            format!("{}{path}", &self.cwd[..2.min(self.cwd.len())])
        } else if path.is_empty() {
            self.cwd.clone()
        } else {
            format!("{}\\{path}", self.cwd.trim_end_matches('\\'))
        };
        collapse_path(&absolute.replace('/', "\\"))
    }

    fn resolve_program(&mut self, name: &str) -> Option<String> {
        const RUNNABLE: [&str; 4] = [".com", ".exe", ".bat", ".cmd"];
        let extensions: Vec<String> = self
            .variable("PATHEXT")
            .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string())
            .split(';')
            .map(|extension| extension.trim().to_ascii_lowercase())
            .filter(|extension| RUNNABLE.contains(&extension.as_str()))
            .collect();
        let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
        let has_extension = file
            .rfind('.')
            .is_some_and(|dot| RUNNABLE.contains(&file[dot..].to_ascii_lowercase().as_str()));
        let directories: Vec<String> = if name.contains(['\\', '/', ':']) {
            vec![String::new()]
        } else {
            let mut directories = vec![self.cwd.clone()];
            if let Some(path) = self.variable("PATH") {
                directories.extend(
                    path.split(';')
                        .map(|entry| entry.trim().trim_matches('"').to_string())
                        .filter(|entry| !entry.is_empty()),
                );
            }
            directories
        };
        for directory in directories {
            let base = if directory.is_empty() {
                self.full_path(name)
            } else {
                format!("{}\\{name}", directory.trim_end_matches('\\'))
            };
            let candidates: Vec<String> = if has_extension {
                vec![base]
            } else {
                extensions
                    .iter()
                    .map(|extension| format!("{base}{extension}"))
                    .collect()
            };
            for candidate in candidates {
                if self.host.with_fs(|fs| fs.is_file(&candidate)) {
                    return Some(candidate);
                }
            }
        }
        None
    }

    // -- redirection ----------------------------------------------------------

    fn apply_redirects(&mut self, redirects: &[Redirect], io: &Io) -> Result<Io, String> {
        let mut io = io.clone();
        for redirect in redirects {
            match &redirect.kind {
                RedirectKind::Read(path) => {
                    let full = self.full_path(path);
                    if !self.host.with_fs(|fs| fs.is_file(&full)) {
                        return Err("The system cannot find the file specified.".to_string());
                    }
                    io.stdin = Some(full);
                }
                RedirectKind::Duplicate(source) => {
                    let value = if *source == 2 {
                        io.stderr.clone()
                    } else {
                        io.stdout.clone()
                    };
                    if redirect.fd == 2 {
                        io.stderr = value;
                    } else {
                        io.stdout = value;
                    }
                }
                RedirectKind::Write { path, append } => {
                    let target = if path.eq_ignore_ascii_case("nul") {
                        Output::Null
                    } else {
                        let full = self.full_path(path);
                        let append = *append;
                        let prepared = self.host.with_fs(|fs| {
                            if append && fs.is_file(&full) {
                                Ok(())
                            } else {
                                fs.write_file(&full, Vec::new())
                            }
                        });
                        prepared.map_err(|_| {
                            "The system cannot find the path specified.".to_string()
                        })?;
                        Output::File(full)
                    };
                    if redirect.fd == 2 {
                        io.stderr = target;
                    } else {
                        io.stdout = target;
                    }
                }
            }
        }
        Ok(io)
    }

    // -- execution --------------------------------------------------------------

    fn exec(&mut self, node: &Node, io: &Io) -> (u32, Flow) {
        match node {
            Node::Empty => (0, Flow::Next),
            Node::Seq(left, right) => {
                let (_, flow) = self.exec(left, io);
                if flow != Flow::Next {
                    return (self.errorlevel, flow);
                }
                self.exec(right, io)
            }
            Node::And(left, right) => {
                let (status, flow) = self.exec(left, io);
                if flow != Flow::Next || status != 0 {
                    return (status, flow);
                }
                self.exec(right, io)
            }
            Node::Or(left, right) => {
                let (status, flow) = self.exec(left, io);
                if flow != Flow::Next || status == 0 {
                    return (status, flow);
                }
                self.exec(right, io)
            }
            Node::Pipe(left, right) => self.run_pipe(left, right, io),
            Node::Block { body, redirects } => match self.apply_redirects(redirects, io) {
                Ok(inner) => self.exec(body, &inner),
                Err(message) => self.fail(io, &message, 1),
            },
            Node::If {
                case_insensitive,
                negate,
                condition,
                then,
                otherwise,
            } => {
                let holds = self.condition(condition, *case_insensitive) != *negate;
                match (holds, otherwise) {
                    (true, _) => self.exec(then, io),
                    (false, Some(otherwise)) => self.exec(otherwise, io),
                    (false, None) => (0, Flow::Next),
                }
            }
            Node::For {
                variable,
                kind,
                set,
                body,
            } => self.run_for(*variable, kind, set, body, io),
            Node::Command { text, redirects } => {
                let text = self.delayed_expand(text);
                let redirects: Vec<Redirect> = redirects
                    .iter()
                    .map(|redirect| self.delayed_redirect(redirect))
                    .collect();
                match self.apply_redirects(&redirects, io) {
                    Ok(inner) => self.run_command(&text, &inner, false),
                    Err(message) => self.fail(io, &message, 1),
                }
            }
        }
    }

    fn condition(&mut self, condition: &Condition, case_insensitive: bool) -> bool {
        let condition = match condition {
            Condition::Exist(path) => Condition::Exist(self.delayed_expand(path)),
            Condition::Compare { left, op, right } => Condition::Compare {
                left: self.delayed_expand(left),
                op: *op,
                right: self.delayed_expand(right),
            },
            other => other.clone(),
        };
        match &condition {
            Condition::Exist(path) => {
                let full = self.full_path(path);
                self.host.with_fs(|fs| fs.exists(&full))
            }
            Condition::Defined(name) => self
                .environment
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case(name)),
            Condition::ErrorLevel(level) => self.errorlevel >= *level,
            Condition::Compare { left, op, right } => {
                let ordering = match (left.parse::<i64>(), right.parse::<i64>()) {
                    (Ok(left), Ok(right)) if *op != CompareOp::Equal => left.cmp(&right),
                    _ if case_insensitive => left.to_lowercase().cmp(&right.to_lowercase()),
                    _ => left.cmp(right),
                };
                match *op {
                    CompareOp::Equal | CompareOp::Equ => ordering.is_eq(),
                    CompareOp::Neq => ordering.is_ne(),
                    CompareOp::Lss => ordering.is_lt(),
                    CompareOp::Leq => ordering.is_le(),
                    CompareOp::Gtr => ordering.is_gt(),
                    CompareOp::Geq => ordering.is_ge(),
                }
            }
        }
    }

    fn run_command(&mut self, text: &str, io: &Io, called: bool) -> (u32, Flow) {
        let text = text.trim_start();
        if text.trim().is_empty() {
            return (0, Flow::Next);
        }
        let (name, rest) = split_command_name(text);
        match name.to_ascii_lowercase().as_str() {
            "echo" => self.builtin_echo(rest, io),
            "set" => self.builtin_set(rest, io),
            "cd" | "chdir" => self.builtin_cd(rest, io),
            "pushd" => {
                let previous = self.cwd.clone();
                let result = self.builtin_cd(rest, io);
                if result.0 == 0 {
                    self.directories.push(previous);
                }
                result
            }
            "popd" => {
                if let Some(directory) = self.directories.pop() {
                    self.cwd = directory;
                }
                (0, Flow::Next)
            }
            "exit" => self.builtin_exit(rest),
            "goto" => self.builtin_goto(rest, io),
            "call" => self.builtin_call(rest, io),
            "setlocal" => {
                self.locals
                    .push((self.environment.clone(), self.cwd.clone(), self.delayed));
                for option in rest.split_whitespace() {
                    match option.to_ascii_lowercase().as_str() {
                        "enabledelayedexpansion" => self.delayed = true,
                        "disabledelayedexpansion" => self.delayed = false,
                        _ => {}
                    }
                }
                (0, Flow::Next)
            }
            "endlocal" => {
                let floor = self.frames.last().map_or(0, |frame| frame.locals);
                if self.locals.len() > floor {
                    let (environment, cwd, delayed) = self.locals.pop().unwrap();
                    self.environment = environment;
                    self.cwd = cwd;
                    self.delayed = delayed;
                }
                (0, Flow::Next)
            }
            "shift" => {
                if let Some(frame) = self.frames.last_mut() {
                    if !frame.arguments.is_empty() {
                        frame.arguments.remove(0);
                    }
                }
                (0, Flow::Next)
            }
            "rem" | "title" | "cls" | "pause" | "verify" | "color" => (0, Flow::Next),
            "chcp" => {
                self.print(io, "Active code page: 65001");
                (0, Flow::Next)
            }
            "ver" => {
                self.print(
                    io,
                    &format!(
                        "\r\nMicrosoft Windows [Version 10.0.{}]",
                        crate::system_profile::OS_BUILD
                    ),
                );
                (0, Flow::Next)
            }
            "type" => self.builtin_type(rest, io),
            "mkdir" | "md" => self.builtin_mkdir(rest, io),
            "rmdir" | "rd" => self.builtin_rmdir(rest, io),
            "del" | "erase" => self.builtin_del(rest, io),
            "copy" => self.builtin_copy(rest, io),
            _ => self.run_external(&name, text, io, called),
        }
    }

    fn run_external(&mut self, name: &str, text: &str, io: &Io, called: bool) -> (u32, Flow) {
        let Some(path) = self.resolve_program(name) else {
            return self.fail(
                io,
                &format!(
                    "'{name}' is not recognized as an internal or external command,\r\noperable program or batch file."
                ),
                9009,
            );
        };
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".cmd") || lower.ends_with(".bat") {
            let (typed, arguments) = split_first_token(text);
            let flow = self.run_batch(&path, typed, arguments, io);
            if flow == Flow::Exit {
                return (self.errorlevel, Flow::Exit);
            }
            // A batch file started without `call` from another one does not
            // return to it.
            let flow = if !called && !self.frames.is_empty() {
                Flow::ExitBatch
            } else {
                Flow::Next
            };
            return (self.errorlevel, flow);
        }
        let request = RunRequest {
            application: path,
            command_line: text.trim_end().to_string(),
            current_directory: self.cwd.clone(),
            environment: self.environment.clone(),
            stdin: io.stdin.clone(),
            stdout: io.stdout.clone(),
            stderr: io.stderr.clone(),
        };
        match self.host.run(&request) {
            Ok((code, captured)) => {
                self.capture.extend_from_slice(&captured);
                self.errorlevel = code;
                (code, Flow::Next)
            }
            Err(message) => self.fail(io, &message, 1),
        }
    }

    // -- batch files ------------------------------------------------------------

    fn run_batch(&mut self, path: &str, invoked: &str, raw_arguments: &str, io: &Io) -> Flow {
        if self.frames.len() >= MAX_CALL_DEPTH {
            self.fail(io, "Batch recursion exceeds stack limits.", 1);
            return Flow::Exit;
        }
        let owned = path.to_string();
        let bytes = match self.host.with_fs(|fs| fs.read_file(&owned)) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.fail(io, "The system cannot find the file specified.", 1);
                return Flow::Next;
            }
        };
        let lines: Rc<[String]> = String::from_utf8_lossy(&bytes)
            .split('\n')
            .map(|line| line.trim_end_matches('\r').to_string())
            .collect();
        let mut labels = HashMap::new();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if let Some(label) = trimmed.strip_prefix(':') {
                if !label.starts_with(':') {
                    let name: String = label
                        .chars()
                        .take_while(|c| !c.is_whitespace() && !matches!(c, ':' | '+' | '&'))
                        .collect();
                    labels.entry(name.to_lowercase()).or_insert(index);
                }
            }
        }
        self.frames.push(Frame {
            path: path.to_string(),
            invoked: invoked.to_string(),
            arguments: split_batch_arguments(raw_arguments),
            raw_arguments: raw_arguments.to_string(),
            lines,
            labels: Rc::new(labels),
            locals: self.locals.len(),
            stop_after_line: false,
        });
        let flow = self.run_frame(0, io);
        self.pop_frame();
        flow
    }

    fn pop_frame(&mut self) {
        if let Some(frame) = self.frames.pop() {
            while self.locals.len() > frame.locals {
                let (environment, cwd, delayed) = self.locals.pop().unwrap();
                self.environment = environment;
                self.cwd = cwd;
                self.delayed = delayed;
            }
        }
    }

    /// Run the top frame's lines from `pc`. Returns [`Flow::Exit`] when cmd
    /// itself must end, otherwise [`Flow::Next`].
    fn run_frame(&mut self, mut pc: usize, io: &Io) -> Flow {
        let lines = Rc::clone(&self.frames.last().unwrap().lines);
        while pc < lines.len() {
            let trimmed = lines[pc].trim_start();
            if trimmed.is_empty() || trimmed.starts_with(':') {
                pc += 1;
                continue;
            }
            let mut logical = lines[pc].clone();
            let mut depth = paren_delta(&logical);
            pc += 1;
            while depth > 0 && pc < lines.len() {
                logical.push('\n');
                logical.push_str(&lines[pc]);
                depth += paren_delta(&lines[pc]);
                pc += 1;
            }
            let quiet = logical.trim_start().starts_with('@');
            let expanded = self.expand(&logical, true);
            if self.echo && !quiet {
                let echoed = format!("\r\n{}>{}\r\n", self.cwd, expanded.trim());
                self.emit(&io.stdout.clone(), echoed.as_bytes());
            }
            let node = match parse(&expanded) {
                Ok(node) => node,
                Err(message) => {
                    self.fail(io, &message, 1);
                    return Flow::Next;
                }
            };
            let (_, flow) = self.exec(&node, io);
            match flow {
                Flow::Next => {}
                Flow::Goto(target) => pc = target,
                Flow::ExitBatch => return Flow::Next,
                Flow::Exit => return Flow::Exit,
            }
            if self.frames.last().unwrap().stop_after_line {
                return Flow::Next;
            }
        }
        Flow::Next
    }

    fn builtin_goto(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let label: String = rest
            .trim_start()
            .trim_start_matches(':')
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        let Some(frame) = self.frames.last_mut() else {
            return self.fail(
                io,
                "Invalid attempt to call batch label outside of batch script.",
                1,
            );
        };
        if label.eq_ignore_ascii_case("eof") {
            return (self.errorlevel, Flow::ExitBatch);
        }
        match frame.labels.get(&label.to_lowercase()) {
            Some(index) => (0, Flow::Goto(index + 1)),
            None => {
                frame.stop_after_line = true;
                self.fail(
                    io,
                    &format!("The system cannot find the batch label specified - {label}"),
                    1,
                )
            }
        }
    }

    fn builtin_call(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let rest = rest.trim_start();
        let Some(label_text) = rest.strip_prefix(':') else {
            return self.run_command(rest, io, true);
        };
        let (label, arguments) = split_first_token(label_text);
        let Some(frame) = self.frames.last() else {
            return self.fail(
                io,
                "Invalid attempt to call batch label outside of batch script.",
                1,
            );
        };
        let Some(&index) = frame.labels.get(&label.to_lowercase()) else {
            return self.fail(
                io,
                &format!("The system cannot find the batch label specified - {label}"),
                1,
            );
        };
        if self.frames.len() >= MAX_CALL_DEPTH {
            self.fail(io, "Batch recursion exceeds stack limits.", 1);
            return (1, Flow::Exit);
        }
        let subroutine = Frame {
            path: frame.path.clone(),
            invoked: format!(":{label}"),
            arguments: split_batch_arguments(arguments),
            raw_arguments: arguments.to_string(),
            lines: Rc::clone(&frame.lines),
            labels: Rc::clone(&frame.labels),
            locals: self.locals.len(),
            stop_after_line: false,
        };
        self.frames.push(subroutine);
        let flow = self.run_frame(index + 1, io);
        self.pop_frame();
        (
            self.errorlevel,
            if flow == Flow::Exit {
                Flow::Exit
            } else {
                Flow::Next
            },
        )
    }

    fn builtin_exit(&mut self, rest: &str) -> (u32, Flow) {
        let mut words = rest.split_whitespace();
        let mut batch_only = false;
        let mut code = None;
        for word in words.by_ref() {
            if word.eq_ignore_ascii_case("/b") {
                batch_only = true;
            } else {
                code = word.parse::<i64>().ok();
                break;
            }
        }
        if let Some(code) = code {
            self.errorlevel = code as u32;
        }
        let flow = if batch_only && !self.frames.is_empty() {
            Flow::ExitBatch
        } else {
            Flow::Exit
        };
        (self.errorlevel, flow)
    }

    // -- for --------------------------------------------------------------------

    fn run_for(
        &mut self,
        variable: char,
        kind: &ForKind,
        set: &str,
        body: &str,
        io: &Io,
    ) -> (u32, Flow) {
        let iterations: Vec<Vec<String>> = match kind {
            ForKind::List => split_batch_arguments(set)
                .into_iter()
                .map(|item| vec![item])
                .collect(),
            ForKind::Range => {
                let numbers: Vec<i64> = set
                    .split([',', ' '])
                    .filter(|part| !part.is_empty())
                    .filter_map(|part| part.trim().parse().ok())
                    .collect();
                let &[start, step, end] = numbers.as_slice() else {
                    return self.fail(io, SYNTAX_ERROR, 1);
                };
                let mut values = Vec::new();
                let mut value = start;
                while step != 0 && ((step > 0 && value <= end) || (step < 0 && value >= end)) {
                    values.push(vec![value.to_string()]);
                    value += step;
                    if values.len() > 1_000_000 {
                        break;
                    }
                }
                values
            }
            ForKind::Lines(options) => match self.for_lines(options, set, io) {
                Ok(lines) => lines,
                Err(message) => return self.fail(io, &message, 1),
            },
        };
        let mut status = 0;
        for values in iterations {
            let text = substitute_for_variables(body, variable, &values, |path, modifiers| {
                self.path_modifiers(path, modifiers)
            });
            let node = match parse(&text) {
                Ok(node) => node,
                Err(message) => return self.fail(io, &message, 1),
            };
            let (result, flow) = self.exec(&node, io);
            status = result;
            if flow != Flow::Next {
                return (status, flow);
            }
        }
        (status, Flow::Next)
    }

    /// The token rows `for /f` iterates over.
    fn for_lines(&mut self, options: &str, set: &str, io: &Io) -> Result<Vec<Vec<String>>, String> {
        let options = ForOptions::parse(options)?;
        let set = set.trim();
        let (command_quote, string_quote) = if options.usebackq {
            ('`', '\'')
        } else {
            ('\'', '"')
        };
        let text =
            if set.len() >= 2 && set.starts_with(command_quote) && set.ends_with(command_quote) {
                let command = &set[1..set.len() - 1];
                self.capture_command(command, io)
            } else if set.len() >= 2 && set.starts_with(string_quote) && set.ends_with(string_quote)
            {
                set[1..set.len() - 1].to_string()
            } else {
                let mut text = String::new();
                for file in split_batch_arguments(set) {
                    let full = self.full_path(&file);
                    let bytes = self
                        .host
                        .with_fs(|fs| fs.read_file(&full))
                        .map_err(|_| format!("The system cannot find the file {file}."))?;
                    text.push_str(&String::from_utf8_lossy(&bytes));
                    text.push('\n');
                }
                text
            };
        Ok(text
            .split('\n')
            .map(|line| line.trim_end_matches('\r'))
            .filter(|line| !line.is_empty())
            .skip(options.skip)
            .filter(|line| options.eol.is_none_or(|eol| !line.starts_with(eol)))
            .map(|line| options.tokens(line))
            .filter(|tokens| tokens.first().is_some_and(|first| !first.is_empty()))
            .collect())
    }

    /// Run a command as cmd would in a child `cmd /c`, collecting its
    /// standard output. Environment and directory changes stay inside.
    fn capture_command(&mut self, command: &str, io: &Io) -> String {
        let saved_capture = std::mem::take(&mut self.capture);
        let saved_environment = self.environment.clone();
        let saved_cwd = self.cwd.clone();
        let saved_errorlevel = self.errorlevel;
        let inner = Io {
            stdin: None,
            stdout: Output::Capture,
            stderr: io.stderr.clone(),
        };
        match parse(command) {
            Ok(node) => {
                self.exec(&node, &inner);
            }
            Err(message) => {
                self.fail(io, &message, 1);
            }
        }
        let captured = std::mem::replace(&mut self.capture, saved_capture);
        self.environment = saved_environment;
        self.cwd = saved_cwd;
        self.errorlevel = saved_errorlevel;
        String::from_utf8_lossy(&captured).into_owned()
    }

    // -- internal commands -----------------------------------------------------

    fn builtin_echo(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        if rest.trim().is_empty()
            && !rest.starts_with(['.', ':', '(', '/', '\\', '[', ']', '+', ','])
        {
            let state = if self.echo { "on" } else { "off" };
            self.print(io, &format!("ECHO is {state}."));
            return (0, Flow::Next);
        }
        let text = rest.get(1..).unwrap_or_default();
        match text.trim().to_ascii_lowercase().as_str() {
            "on" if !rest.starts_with('.') => self.echo = true,
            "off" if !rest.starts_with('.') => self.echo = false,
            _ => self.print(io, text),
        }
        (0, Flow::Next)
    }

    /// `set /a`: evaluate comma-separated integer expressions. Outside a
    /// batch file the last result is printed, without a newline, as cmd does.
    fn set_arithmetic(&mut self, expression: &str, io: &Io) -> (u32, Flow) {
        let expression = expression.replace('"', "");
        let parsed = match ArithmeticParser::new(&expression).parse() {
            Ok(parsed) => parsed,
            Err(message) => return self.fail(io, &message, 1_073_750_988),
        };
        match self.evaluate(&parsed) {
            Ok(value) => {
                if self.frames.is_empty() {
                    self.emit(&io.stdout.clone(), value.to_string().as_bytes());
                }
                (0, Flow::Next)
            }
            Err(message) => self.fail(io, &message, 1_073_750_993),
        }
    }

    fn evaluate(&mut self, expression: &Arithmetic) -> Result<i32, String> {
        Ok(match expression {
            Arithmetic::Number(value) => *value,
            Arithmetic::Variable(name) => self
                .environment
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .and_then(|(_, value)| parse_arithmetic_number(value.trim()))
                .unwrap_or(0),
            Arithmetic::Unary(operator, operand) => {
                let value = self.evaluate(operand)?;
                match operator {
                    '-' => value.wrapping_neg(),
                    '~' => !value,
                    _ => i32::from(value == 0),
                }
            }
            Arithmetic::Binary(operator, left, right) => {
                let left = self.evaluate(left)?;
                let right = self.evaluate(right)?;
                apply_arithmetic(operator, left, right)?
            }
            Arithmetic::Assign(name, operator, value) => {
                let value = self.evaluate(value)?;
                let value = match operator {
                    Some(operator) => {
                        let current = self.evaluate(&Arithmetic::Variable(name.clone()))?;
                        apply_arithmetic(operator, current, value)?
                    }
                    None => value,
                };
                self.set_variable(name, &value.to_string());
                value
            }
            Arithmetic::Sequence(first, second) => {
                self.evaluate(first)?;
                self.evaluate(second)?
            }
        })
    }

    /// `set /p NAME=prompt`: print the prompt, then read one line from
    /// standard input (a redirected or piped file, or the console). Empty
    /// input leaves the variable unchanged and sets errorlevel 1.
    fn set_prompt(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let text = rest.trim_start();
        let text = text
            .strip_prefix('"')
            .and_then(|quoted| quoted.rfind('"').map(|end| &quoted[..end]))
            .unwrap_or(text);
        let Some((name, prompt)) = text.split_once('=') else {
            return self.fail(io, SYNTAX_ERROR, 1);
        };
        if name.is_empty() {
            return self.fail(io, SYNTAX_ERROR, 1);
        }
        self.emit(&io.stdout.clone(), prompt.as_bytes());
        let line = match &io.stdin {
            Some(path) => {
                let path = path.clone();
                self.host
                    .with_fs(|fs| fs.read_file(&path))
                    .ok()
                    .and_then(|bytes| {
                        String::from_utf8_lossy(&bytes)
                            .split('\n')
                            .next()
                            .map(|line| line.trim_end_matches('\r').to_string())
                    })
            }
            None => self.host.read_line(),
        };
        match line.filter(|line| !line.is_empty()) {
            Some(line) => {
                self.set_variable(name, &line);
                (0, Flow::Next)
            }
            None => {
                self.errorlevel = 1;
                (1, Flow::Next)
            }
        }
    }

    /// Run `left | right`: the left side's output, collected first, is the
    /// right side's standard input.
    fn run_pipe(&mut self, left: &Node, right: &Node, io: &Io) -> (u32, Flow) {
        let saved = std::mem::take(&mut self.capture);
        let producer = Io {
            stdin: io.stdin.clone(),
            stdout: Output::Capture,
            stderr: io.stderr.clone(),
        };
        let (_, flow) = self.exec(left, &producer);
        let output = std::mem::replace(&mut self.capture, saved);
        if flow == Flow::Exit {
            return (self.errorlevel, flow);
        }
        let directory = self
            .variable("TEMP")
            .unwrap_or_else(|| crate::system_profile::WINDOWS_TEMP.to_string());
        self.random = self.random.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let path = format!(
            r"{}\winrun-pipe-{:08x}.tmp",
            directory.trim_end_matches('\\'),
            self.random
        );
        let written = self.host.with_fs(|fs| {
            fs.mkdir(&directory)?;
            fs.write_file(&path, output)
        });
        if let Err(message) = written {
            return self.fail(io, &format!("The pipe cannot be created: {message}"), 1);
        }
        let consumer = Io {
            stdin: Some(path.clone()),
            stdout: io.stdout.clone(),
            stderr: io.stderr.clone(),
        };
        let result = self.exec(right, &consumer);
        let _ = self.host.with_fs(|fs| fs.delete_file(&path));
        result
    }

    // -- delayed expansion -------------------------------------------------------

    fn delayed_expand(&mut self, text: &str) -> String {
        if !self.delayed || !text.contains('!') {
            return text.to_string();
        }
        let batch = !self.frames.is_empty();
        let mut output = String::new();
        let mut rest = text;
        while let Some(start) = rest.find('!') {
            output.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let Some(end) = after.find('!') else {
                // A lone `!` disappears, as in cmd.
                rest = after;
                continue;
            };
            let reference = &after[..end];
            let (name, spec) = match reference.split_once(':') {
                Some((name, spec)) => (name, Some(spec)),
                None => (reference, None),
            };
            match self.variable(name).filter(|_| !name.is_empty()) {
                Some(value) => output.push_str(&apply_variable_spec(&value, spec)),
                None if batch => {}
                None => {
                    output.push('!');
                    output.push_str(reference);
                    output.push('!');
                }
            }
            rest = &after[end + 1..];
        }
        output.push_str(rest);
        output
    }

    fn delayed_redirect(&mut self, redirect: &Redirect) -> Redirect {
        let kind = match &redirect.kind {
            RedirectKind::Write { path, append } => RedirectKind::Write {
                path: self.delayed_expand(path),
                append: *append,
            },
            RedirectKind::Read(path) => RedirectKind::Read(self.delayed_expand(path)),
            other => other.clone(),
        };
        Redirect {
            fd: redirect.fd,
            kind,
        }
    }

    fn builtin_set(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let argument = rest.trim_start();
        let lower = argument.to_ascii_lowercase();
        if lower.starts_with("/a") {
            return self.set_arithmetic(&argument[2..], io);
        }
        if lower.starts_with("/p") {
            return self.set_prompt(&argument[2..], io);
        }
        let assignment = match argument.strip_prefix('"') {
            Some(quoted) => match quoted.rfind('"') {
                Some(end) => &quoted[..end],
                None => quoted,
            },
            None => argument,
        };
        if assignment.trim().is_empty() {
            let mut variables = self.environment.clone();
            variables.sort_by_key(|(name, _)| name.to_ascii_uppercase());
            for (name, value) in variables {
                self.print(io, &format!("{name}={value}"));
            }
            return (0, Flow::Next);
        }
        match assignment.split_once('=') {
            Some(("", _)) => self.fail(io, SYNTAX_ERROR, 1),
            Some((name, value)) => {
                self.set_variable(name, value);
                (0, Flow::Next)
            }
            None => {
                let prefix = assignment.trim().to_ascii_lowercase();
                let mut matches: Vec<(String, String)> = self
                    .environment
                    .iter()
                    .filter(|(name, _)| name.to_ascii_lowercase().starts_with(&prefix))
                    .cloned()
                    .collect();
                if matches.is_empty() {
                    return self.fail(
                        io,
                        &format!("Environment variable {} not defined", assignment.trim()),
                        1,
                    );
                }
                matches.sort_by_key(|(name, _)| name.to_ascii_uppercase());
                for (name, value) in matches {
                    self.print(io, &format!("{name}={value}"));
                }
                (0, Flow::Next)
            }
        }
    }

    fn builtin_cd(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let mut argument = rest.trim();
        if argument.len() >= 2 && argument[..2].eq_ignore_ascii_case("/d") {
            argument = argument[2..].trim_start();
        }
        if argument.is_empty() {
            let cwd = self.cwd.clone();
            self.print(io, &cwd);
            return (0, Flow::Next);
        }
        let target = self.full_path(argument.trim_matches('"'));
        let resolved = self.host.with_fs(|fs| {
            fs.is_dir(&target)
                .then(|| fs.normalize(&target).ok().map(|path| path.display()))
                .flatten()
        });
        match resolved {
            Some(directory) => {
                self.cwd = directory;
                (0, Flow::Next)
            }
            None => self.fail(io, "The system cannot find the path specified.", 1),
        }
    }

    fn builtin_type(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let mut status = 0;
        for file in split_batch_arguments(rest) {
            let full = self.full_path(&file);
            match self.host.with_fs(|fs| fs.read_file(&full)) {
                Ok(bytes) => self.emit(&io.stdout.clone(), &bytes),
                Err(_) => {
                    status = self
                        .fail(io, "The system cannot find the file specified.", 1)
                        .0;
                }
            }
        }
        (status, Flow::Next)
    }

    fn builtin_mkdir(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let mut status = 0;
        for directory in split_batch_arguments(rest) {
            let full = self.full_path(&directory);
            if self.host.with_fs(|fs| fs.exists(&full)) {
                status = self
                    .fail(
                        io,
                        &format!(
                            "A subdirectory or file {} already exists.",
                            directory.trim_matches('"')
                        ),
                        1,
                    )
                    .0;
                continue;
            }
            if self.host.with_fs(|fs| fs.mkdir(&full)).is_err() {
                status = self
                    .fail(io, "The system cannot find the path specified.", 1)
                    .0;
            }
        }
        (status, Flow::Next)
    }

    fn builtin_rmdir(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let arguments = split_batch_arguments(rest);
        let recursive = arguments.iter().any(|a| a.eq_ignore_ascii_case("/s"));
        let mut status = 0;
        for directory in arguments.iter().filter(|a| !a.starts_with('/')) {
            let full = self.full_path(directory);
            if !self.host.with_fs(|fs| fs.is_dir(&full)) {
                status = self
                    .fail(io, "The system cannot find the file specified.", 2)
                    .0;
                continue;
            }
            if self.host.with_fs(|fs| fs.remove(&full, recursive)).is_err() {
                status = self.fail(io, "The directory is not empty.", 145).0;
            }
        }
        (status, Flow::Next)
    }

    fn builtin_del(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        for pattern in split_batch_arguments(rest)
            .into_iter()
            .filter(|argument| !argument.starts_with('/'))
        {
            let full = self.full_path(&pattern);
            let (directory, file_pattern) = full.rsplit_once('\\').unwrap_or((&self.cwd, &full));
            let (directory, file_pattern) = (directory.to_string(), file_pattern.to_string());
            let matches: Vec<String> = if file_pattern.contains(['*', '?']) {
                self.host.with_fs(|fs| {
                    fs.list_dir(&directory)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|name| wildcard_match(&file_pattern, name))
                        .map(|name| format!("{directory}\\{name}"))
                        .filter(|path| fs.is_file(path))
                        .collect()
                })
            } else if self.host.with_fs(|fs| fs.is_file(&full)) {
                vec![full.clone()]
            } else {
                Vec::new()
            };
            if matches.is_empty() {
                // del reports but still succeeds, as on Windows.
                self.emit(
                    &io.stderr.clone(),
                    format!("Could Not Find {full}\r\n").as_bytes(),
                );
            }
            for path in matches {
                let _ = self.host.with_fs(|fs| fs.delete_file(&path));
            }
        }
        (0, Flow::Next)
    }

    fn builtin_copy(&mut self, rest: &str, io: &Io) -> (u32, Flow) {
        let arguments: Vec<String> = split_batch_arguments(rest)
            .into_iter()
            .filter(|argument| !argument.starts_with('/'))
            .collect();
        let [source, destination] = &arguments[..] else {
            return self.fail(io, SYNTAX_ERROR, 1);
        };
        let source = self.full_path(source);
        let mut destination = self.full_path(destination);
        let copied = self.host.with_fs(|fs| {
            if !fs.is_file(&source) {
                return Err(());
            }
            if fs.is_dir(&destination) {
                let name = source.rsplit('\\').next().unwrap_or_default();
                destination = format!("{destination}\\{name}");
            }
            let bytes = fs.read_file(&source).map_err(|_| ())?;
            fs.write_file(&destination, bytes).map_err(|_| ())
        });
        match copied {
            Ok(()) => {
                self.print(io, "        1 file(s) copied.");
                (0, Flow::Next)
            }
            Err(()) => self.fail(io, "The system cannot find the file specified.", 1),
        }
    }
}

/// A `set /a` expression.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Arithmetic {
    Number(i32),
    Variable(String),
    Unary(char, Box<Arithmetic>),
    Binary(&'static str, Box<Arithmetic>, Box<Arithmetic>),
    /// `name = value` or a compound `name op= value`.
    Assign(String, Option<&'static str>, Box<Arithmetic>),
    Sequence(Box<Arithmetic>, Box<Arithmetic>),
}

/// Numbers as `set /a` reads them: `0x` hex, leading-zero octal, decimal,
/// wrapping to 32 bits.
fn parse_arithmetic_number(text: &str) -> Option<i32> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let value = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else if digits.len() > 1 && digits.starts_with('0') {
        i64::from_str_radix(&digits[1..], 8).ok()?
    } else {
        digits.parse::<i64>().ok()?
    };
    let value = value as i32;
    Some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

fn apply_arithmetic(operator: &str, left: i32, right: i32) -> Result<i32, String> {
    Ok(match operator {
        "+" => left.wrapping_add(right),
        "-" => left.wrapping_sub(right),
        "*" => left.wrapping_mul(right),
        "/" | "%" if right == 0 => return Err("Divide by zero error.".to_string()),
        "/" => left.wrapping_div(right),
        "%" => left.wrapping_rem(right),
        "<<" => left.wrapping_shl(right as u32),
        ">>" => left.wrapping_shr(right as u32),
        "&" => left & right,
        "^" => left ^ right,
        _ => left | right,
    })
}

/// Precedence climbing over cmd's operators, lowest first: `,`, the
/// assignments, `|`, `^`, `&`, shifts, `+ -`, `* / %`, then unary `! ~ -`.
struct ArithmeticParser {
    chars: Vec<char>,
    pos: usize,
}

impl ArithmeticParser {
    fn new(text: &str) -> Self {
        ArithmeticParser {
            chars: text.chars().collect(),
            pos: 0,
        }
    }

    fn parse(mut self) -> Result<Arithmetic, String> {
        let expression = self.sequence()?;
        self.skip_ws();
        if self.pos < self.chars.len() {
            return Err("Missing operator.".to_string());
        }
        Ok(expression)
    }

    fn skip_ws(&mut self) {
        while self.chars.get(self.pos).is_some_and(|c| c.is_whitespace()) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, token: &str) -> bool {
        self.skip_ws();
        let matches = token
            .chars()
            .enumerate()
            .all(|(index, expected)| self.chars.get(self.pos + index) == Some(&expected));
        if matches {
            self.pos += token.chars().count();
        }
        matches
    }

    /// An operator that is not the start of a longer one (`<` of `<<=`).
    fn eat_operator(&mut self, token: &str, not_followed_by: &[char]) -> bool {
        let start = self.pos;
        if self.eat(token) {
            if self
                .chars
                .get(self.pos)
                .is_some_and(|next| not_followed_by.contains(next))
            {
                self.pos = start;
                return false;
            }
            return true;
        }
        false
    }

    fn sequence(&mut self) -> Result<Arithmetic, String> {
        let mut left = self.assignment()?;
        while self.eat(",") {
            let right = self.assignment()?;
            left = Arithmetic::Sequence(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn assignment(&mut self) -> Result<Arithmetic, String> {
        self.skip_ws();
        let start = self.pos;
        let name: String = self.chars[self.pos..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '#' | '@'))
            .collect();
        if !name.is_empty() && !name.starts_with(|c: char| c.is_ascii_digit()) {
            self.pos += name.chars().count();
            const COMPOUND: [&str; 10] =
                ["<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "&=", "^=", "|="];
            for operator in COMPOUND {
                if self.eat(operator) {
                    let value = self.assignment()?;
                    let binary = &operator[..operator.len() - 1];
                    let binary: &'static str = match binary {
                        "<<" => "<<",
                        ">>" => ">>",
                        "+" => "+",
                        "-" => "-",
                        "*" => "*",
                        "/" => "/",
                        "%" => "%",
                        "&" => "&",
                        "^" => "^",
                        _ => "|",
                    };
                    return Ok(Arithmetic::Assign(name, Some(binary), Box::new(value)));
                }
            }
            if self.eat_operator("=", &['=']) {
                let value = self.assignment()?;
                return Ok(Arithmetic::Assign(name, None, Box::new(value)));
            }
            self.pos = start;
        }
        self.binary(0)
    }

    fn binary(&mut self, level: usize) -> Result<Arithmetic, String> {
        const LEVELS: [&[&str]; 6] = [
            &["|"],
            &["^"],
            &["&"],
            &["<<", ">>"],
            &["+", "-"],
            &["*", "/", "%"],
        ];
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        'operators: loop {
            for operator in LEVELS[level] {
                // `a << = b` is not an operator here; `a <<= b` is an
                // assignment, handled above.
                if self.eat_operator(operator, &['=']) {
                    let right = self.binary(level + 1)?;
                    left = Arithmetic::Binary(operator, Box::new(left), Box::new(right));
                    continue 'operators;
                }
            }
            return Ok(left);
        }
    }

    fn unary(&mut self) -> Result<Arithmetic, String> {
        for operator in ['!', '~', '-', '+'] {
            if self.eat(&operator.to_string()) {
                let operand = self.unary()?;
                return Ok(if operator == '+' {
                    operand
                } else {
                    Arithmetic::Unary(operator, Box::new(operand))
                });
            }
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Arithmetic, String> {
        self.skip_ws();
        if self.eat("(") {
            let inner = self.sequence()?;
            if !self.eat(")") {
                return Err("Unbalanced parenthesis.".to_string());
            }
            return Ok(inner);
        }
        let word: String = self.chars[self.pos..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '#' | '@'))
            .collect();
        if word.is_empty() {
            return Err("Missing operand.".to_string());
        }
        self.pos += word.chars().count();
        if word.starts_with(|c: char| c.is_ascii_digit()) {
            return parse_arithmetic_number(&word)
                .map(Arithmetic::Number)
                .ok_or_else(|| "Invalid number.  Numeric constants are either decimal (17),\r\nhexadecimal (0x11), or octal (021).".to_string());
        }
        Ok(Arithmetic::Variable(word))
    }
}

/// `for /f` options: `delims=`, `tokens=`, `skip=`, `eol=`, `usebackq`.
struct ForOptions {
    delims: Vec<char>,
    tokens: Vec<usize>,
    rest: bool,
    skip: usize,
    eol: Option<char>,
    usebackq: bool,
}

impl ForOptions {
    fn parse(text: &str) -> Result<Self, String> {
        let mut options = ForOptions {
            delims: vec![' ', '\t'],
            tokens: vec![1],
            rest: false,
            skip: 0,
            eol: Some(';'),
            usebackq: false,
        };
        let mut remaining = text;
        while !remaining.trim_start().is_empty() {
            remaining = remaining.trim_start();
            let lower = remaining.to_ascii_lowercase();
            if let Some(value) = lower.strip_prefix("delims=") {
                // `delims=` runs to the end or up to the next option;
                // everything after `=` counts, including spaces.
                let value_start = remaining.len() - value.len();
                let end = [" tokens=", " skip=", " eol=", " usebackq"]
                    .iter()
                    .filter_map(|option| lower[value_start..].find(option))
                    .min()
                    .map_or(remaining.len(), |offset| value_start + offset);
                options.delims = remaining[value_start..end].chars().collect();
                remaining = &remaining[end..];
            } else if let Some(value) = lower.strip_prefix("tokens=") {
                let spec: String = value.chars().take_while(|c| !c.is_whitespace()).collect();
                remaining = &remaining["tokens=".len() + spec.len()..];
                options.rest = spec.ends_with('*');
                options.tokens.clear();
                for part in spec
                    .trim_end_matches('*')
                    .split(',')
                    .filter(|p| !p.is_empty())
                {
                    match part.split_once('-') {
                        Some((start, end)) => {
                            let (start, end): (usize, usize) = (
                                start.parse().map_err(|_| SYNTAX_ERROR.to_string())?,
                                end.parse().map_err(|_| SYNTAX_ERROR.to_string())?,
                            );
                            options.tokens.extend(start..=end);
                        }
                        None => options
                            .tokens
                            .push(part.parse().map_err(|_| SYNTAX_ERROR.to_string())?),
                    }
                }
            } else if let Some(value) = lower.strip_prefix("skip=") {
                let number: String = value.chars().take_while(char::is_ascii_digit).collect();
                options.skip = number.parse().map_err(|_| SYNTAX_ERROR.to_string())?;
                remaining = &remaining["skip=".len() + number.len()..];
            } else if lower.starts_with("eol=") {
                options.eol = remaining[4..].chars().next();
                remaining = &remaining[4 + options.eol.map_or(0, char::len_utf8)..];
            } else if lower.starts_with("usebackq") {
                options.usebackq = true;
                remaining = &remaining["usebackq".len()..];
            } else {
                return Err(SYNTAX_ERROR.to_string());
            }
        }
        Ok(options)
    }

    /// The selected tokens of `line`; with a trailing `*`, one more value
    /// holds the rest of the line.
    fn tokens(&self, line: &str) -> Vec<String> {
        if self.delims.is_empty() {
            return vec![line.to_string()];
        }
        let mut spans = Vec::new();
        let mut start = None;
        for (index, character) in line.char_indices() {
            if self.delims.contains(&character) {
                if let Some(begin) = start.take() {
                    spans.push((begin, index));
                }
            } else if start.is_none() {
                start = Some(index);
            }
        }
        if let Some(begin) = start {
            spans.push((begin, line.len()));
        }
        let mut values: Vec<String> = self
            .tokens
            .iter()
            .map(|number| {
                spans
                    .get(number.saturating_sub(1))
                    .map(|(begin, end)| line[*begin..*end].to_string())
                    .unwrap_or_default()
            })
            .collect();
        if self.rest {
            let last = self.tokens.iter().copied().max().unwrap_or(0);
            values.push(
                spans
                    .get(last)
                    .map(|(begin, _)| line[*begin..].to_string())
                    .unwrap_or_default(),
            );
        }
        values
    }
}

/// Replace `%X` (and `%~X`, `%~dpX`, ...) for the loop variable and the
/// letters after it, which hold further `tokens=` values.
fn substitute_for_variables(
    body: &str,
    variable: char,
    values: &[String],
    mut modifiers: impl FnMut(&str, &str) -> String,
) -> String {
    let chars: Vec<char> = body.chars().collect();
    let value_for = |name: char| -> Option<&String> {
        let offset = (name as u32).checked_sub(variable as u32)? as usize;
        values.get(offset)
    };
    let mut output = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '%' {
            if let Some(value) = chars.get(index + 1).and_then(|c| value_for(*c)) {
                output.push_str(value);
                index += 2;
                continue;
            }
            if chars.get(index + 1) == Some(&'~') {
                let mut end = index + 2;
                while end < chars.len()
                    && "fdpnxsatz".contains(chars[end].to_ascii_lowercase())
                    && value_for(chars[end]).is_none()
                {
                    end += 1;
                }
                if let Some(value) = chars.get(end).and_then(|c| value_for(*c)) {
                    let mods: String = chars[index + 2..end].iter().collect();
                    let unquoted = value.trim_matches('"');
                    output.push_str(&if mods.is_empty() {
                        unquoted.to_string()
                    } else {
                        modifiers(unquoted, &mods)
                    });
                    index = end + 1;
                    continue;
                }
            }
        }
        output.push(chars[index]);
        index += 1;
    }
    output
}

/// `:~start[,length]` substrings and `:find=replace` substitution
/// (`*find=` replaces through the first match).
fn apply_variable_spec(value: &str, spec: Option<&str>) -> String {
    let Some(spec) = spec else {
        return value.to_string();
    };
    if let Some(range) = spec.strip_prefix('~') {
        let chars: Vec<char> = value.chars().collect();
        let length = chars.len() as i64;
        let (start, count) = match range.split_once(',') {
            Some((start, count)) => (
                start.trim().parse::<i64>().unwrap_or(0),
                count.trim().parse::<i64>().ok(),
            ),
            None => (range.trim().parse::<i64>().unwrap_or(0), None),
        };
        let start: i64 = if start < 0 {
            (length + start).max(0)
        } else {
            start.min(length)
        };
        let end = match count {
            None => length,
            Some(count) if count < 0 => (length + count).max(start),
            Some(count) => (start + count).min(length),
        };
        return chars[start as usize..end as usize].iter().collect();
    }
    let Some((find, replace)) = spec.split_once('=') else {
        return value.to_string();
    };
    if find.is_empty() {
        return value.to_string();
    }
    if let Some(find) = find.strip_prefix('*') {
        return match value.to_ascii_lowercase().find(&find.to_ascii_lowercase()) {
            Some(position) => format!("{replace}{}", &value[position + find.len()..]),
            None => value.to_string(),
        };
    }
    let lower_value = value.to_ascii_lowercase();
    let lower_find = find.to_ascii_lowercase();
    let mut output = String::new();
    let mut position = 0;
    while let Some(offset) = lower_value[position..].find(&lower_find) {
        output.push_str(&value[position..position + offset]);
        output.push_str(replace);
        position += offset + find.len();
    }
    output.push_str(&value[position..]);
    output
}

/// The command word and the text after it. A quoted word loses its quotes;
/// `echo.`, `echo(`, and `cd..` split before the punctuation, as cmd does.
fn split_command_name(text: &str) -> (String, &str) {
    if let Some(quoted) = text.strip_prefix('"') {
        return match quoted.find('"') {
            Some(end) => (quoted[..end].to_string(), &quoted[end + 1..]),
            None => (quoted.to_string(), ""),
        };
    }
    let lower = text.to_ascii_lowercase();
    for (word, punctuation) in [("echo", ".:(/\\[]+,"), ("cd", ".\\"), ("chdir", ".\\")] {
        if lower.starts_with(word)
            && text[word.len()..]
                .chars()
                .next()
                .is_some_and(|next| punctuation.contains(next))
        {
            return (text[..word.len()].to_string(), &text[word.len()..]);
        }
    }
    let end = text
        .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '='))
        .unwrap_or(text.len());
    (text[..end].to_string(), &text[end..])
}

/// The first whitespace-separated token (quotes kept) and the rest.
fn split_first_token(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    let mut quoted = false;
    for (index, character) in text.char_indices() {
        if character == '"' {
            quoted = !quoted;
        } else if !quoted && character.is_whitespace() {
            return (&text[..index], &text[index..]);
        }
    }
    (text, "")
}

fn collapse_path(path: &str) -> String {
    let (prefix, rest) = if path.len() >= 2 && path.as_bytes()[1] == b':' {
        (&path[..2], &path[2..])
    } else {
        ("", path)
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    format!("{prefix}\\{}", parts.join("\\"))
}

fn wildcard_match(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let name: Vec<char> = name.to_lowercase().chars().collect();
    fn matches(pattern: &[char], name: &[char]) -> bool {
        match pattern.split_first() {
            None => name.is_empty(),
            Some(('*', rest)) => (0..=name.len()).any(|skip| matches(rest, &name[skip..])),
            Some(('?', rest)) => !name.is_empty() && matches(rest, &name[1..]),
            Some((expected, rest)) => name.first() == Some(expected) && matches(rest, &name[1..]),
        }
    }
    matches(&pattern, &name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs nothing: records each request and answers with a scripted exit
    /// code and standard output per program path.
    struct FakeHost {
        fs: WinFs,
        out: Vec<u8>,
        err: Vec<u8>,
        runs: Vec<RunRequest>,
        programs: HashMap<String, (u32, Vec<u8>)>,
    }

    impl FakeHost {
        fn new() -> Self {
            let mut fs = WinFs::ephemeral_runner();
            fs.mkdir(r"C:\tools").unwrap();
            let mut host = FakeHost {
                fs,
                out: Vec::new(),
                err: Vec::new(),
                runs: Vec::new(),
                programs: HashMap::new(),
            };
            host.program(r"C:\tools\ok.exe", 0, b"");
            host.program(r"C:\tools\fail.exe", 3, b"");
            host
        }

        fn program(&mut self, path: &str, code: u32, stdout: &[u8]) {
            self.fs.write_file(path, b"MZ".to_vec()).unwrap();
            self.programs
                .insert(path.to_ascii_lowercase(), (code, stdout.to_vec()));
        }

        fn file(&mut self, path: &str, text: &str) {
            let directory = path.rsplit_once('\\').unwrap().0;
            self.fs.mkdir(directory).unwrap();
            self.fs.write_file(path, text.as_bytes().to_vec()).unwrap();
        }

        fn cmd(&mut self, command: &str) -> u32 {
            self.out.clear();
            self.err.clear();
            let environment = vec![
                (
                    "ComSpec".to_string(),
                    r"C:\Windows\System32\cmd.exe".to_string(),
                ),
                (
                    "PATH".to_string(),
                    r"C:\Windows\System32;C:\tools".to_string(),
                ),
                (
                    "PATHEXT".to_string(),
                    ".COM;.EXE;.BAT;.CMD;.VBS;.JS".to_string(),
                ),
                ("USERPROFILE".to_string(), r"C:\Users\runner".to_string()),
            ];
            let cwd = r"C:\Users\runner".to_string();
            run_command_line(
                self,
                &format!(r"C:\Windows\System32\cmd.exe /d /s /c {command}"),
                environment,
                cwd,
            )
        }

        fn out(&self) -> String {
            String::from_utf8_lossy(&self.out).into_owned()
        }

        fn err(&self) -> String {
            String::from_utf8_lossy(&self.err).into_owned()
        }
    }

    impl CmdHost for FakeHost {
        fn with_fs<R>(&mut self, action: impl FnOnce(&mut WinFs) -> R) -> R {
            action(&mut self.fs)
        }

        fn run(&mut self, request: &RunRequest) -> Result<(u32, Vec<u8>), String> {
            self.runs.push(request.clone());
            let (code, stdout) = self
                .programs
                .get(&request.application.to_ascii_lowercase())
                .cloned()
                .unwrap_or((0, Vec::new()));
            match &request.stdout {
                Output::Stdout => self.out.extend_from_slice(&stdout),
                Output::Stderr => self.err.extend_from_slice(&stdout),
                Output::File(path) => self.fs.append_file(path, &stdout).unwrap(),
                Output::Null => {}
                Output::Capture => return Ok((code, stdout)),
            }
            Ok((code, Vec::new()))
        }

        fn write(&mut self, stderr: bool, bytes: &[u8]) {
            if stderr {
                self.err.extend_from_slice(bytes);
            } else {
                self.out.extend_from_slice(bytes);
            }
        }
    }

    #[test]
    fn switches_and_quote_rules_select_the_command_text() {
        let command = |line: &str| {
            command_after_switches(line, |path| path == r"C:\Program Files\x.exe")
                .unwrap()
                .0
        };
        assert_eq!(
            command(r#"C:\Windows\System32\cmd.exe /d /s /c "echo a && echo b""#),
            "echo a && echo b"
        );
        // Without /s, one quoted path with a space stays quoted.
        assert_eq!(
            command(r#"cmd /c "C:\Program Files\x.exe""#),
            r#""C:\Program Files\x.exe""#
        );
        assert_eq!(
            command(r#"cmd /c ""C:\Program Files\x.exe" arg""#),
            r#""C:\Program Files\x.exe" arg"#
        );
        // Arguments may follow the quoted executable.
        assert_eq!(
            command(r#"cmd /c "C:\Program Files\x.exe" -v"#),
            r#""C:\Program Files\x.exe" -v"#
        );
        // A quoted command that is not an executable loses its quotes.
        assert_eq!(command(r#"cmd /c "exit 3""#), "exit 3");
        assert_eq!(command(r#"cmd /c "exit 3" & ver"#), "exit 3 & ver");
        assert_eq!(command(r#""C:\Windows\System32\cmd.exe" /q/c ver"#), "ver");
        assert!(command_after_switches("cmd.exe", |_| false).is_err());
        assert!(command_after_switches("cmd.exe /d", |_| false).is_err());
    }

    #[test]
    fn operators_follow_exit_codes_and_the_last_errorlevel_is_the_result() {
        let mut host = FakeHost::new();
        assert_eq!(host.cmd(r#""ok && echo yes""#), 0);
        assert_eq!(host.out(), "yes\r\n");
        assert_eq!(
            host.cmd(r#""fail && echo no || echo recovered""#),
            3,
            "echo does not reset ERRORLEVEL"
        );
        assert_eq!(host.out(), "recovered\r\n");
        assert_eq!(host.cmd("fail"), 3);
        assert_eq!(host.cmd(r#""exit 7""#), 7);
        assert_eq!(host.cmd(r#""ok && exit /b 4""#), 4);
        // `echo a && ...` keeps the space before `&&`, as cmd does.
        host.cmd(r#""echo a && echo b""#);
        assert_eq!(host.out(), "a \r\nb\r\n");
        host.cmd(r#""echo.&echo(x""#);
        assert_eq!(host.out(), "\r\nx\r\n");
    }

    #[test]
    fn unknown_commands_report_9009() {
        let mut host = FakeHost::new();
        assert_eq!(host.cmd("nosuch arg"), 9009);
        assert_eq!(
            host.err(),
            "'nosuch' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"
        );
        assert_eq!(host.cmd(r#""nosuch 2>nul""#), 9009);
        assert_eq!(host.err(), "");
    }

    #[test]
    fn a_command_line_is_expanded_once_before_it_runs() {
        let mut host = FakeHost::new();
        host.cmd(r#""echo %USERPROFILE% %NOT_DEFINED_X%""#);
        assert_eq!(host.out(), "C:\\Users\\runner %NOT_DEFINED_X%\r\n");
        // The whole line is expanded before `set` runs.
        host.cmd(r#""set A=1& echo %A%""#);
        assert_eq!(host.out(), "%A%\r\n");
    }

    #[test]
    fn variable_substitution_and_substrings() {
        assert_eq!(
            apply_variable_spec(".COM;.EXE;.JS;.CMD", Some(";.JS;=;")),
            ".COM;.EXE;.CMD"
        );
        assert_eq!(apply_variable_spec("abcdef", Some("~1,2")), "bc");
        assert_eq!(apply_variable_spec("abcdef", Some("~-3")), "def");
        assert_eq!(apply_variable_spec("abcdef", Some("~0,-2")), "abcd");
        assert_eq!(apply_variable_spec("a=b;c", Some("*;=X")), "Xc");
        assert_eq!(apply_variable_spec("AbAb", Some("ab=z")), "zz");
    }

    #[test]
    fn redirection_targets_files_nul_and_the_other_stream_in_order() {
        let mut host = FakeHost::new();
        // Only the redirection is removed: the space before `&` stays, as
        // in cmd.
        host.cmd(r#""echo hi> C:\out.txt & echo more>>C:\out.txt""#);
        assert_eq!(
            host.fs.read_file(r"C:\out.txt").unwrap(),
            b"hi \r\nmore\r\n"
        );
        host.cmd(r#""ok > C:\log.txt 2>&1""#);
        let run = host.runs.last().unwrap();
        assert_eq!(run.stdout, Output::File(r"C:\log.txt".to_string()));
        assert_eq!(run.stderr, Output::File(r"C:\log.txt".to_string()));
        host.cmd(r#""ok 2>&1 >C:\log2.txt""#);
        let run = host.runs.last().unwrap();
        assert_eq!(run.stdout, Output::File(r"C:\log2.txt".to_string()));
        assert_eq!(run.stderr, Output::Stdout);
        host.cmd(r#""ok >nul < C:\out.txt""#);
        let run = host.runs.last().unwrap();
        assert_eq!(run.stdout, Output::Null);
        assert_eq!(run.stdin.as_deref(), Some(r"C:\out.txt"));
        // A digit that is part of a word is text, not a stream number.
        host.cmd(r#""echo a2>C:\a.txt""#);
        assert_eq!(host.fs.read_file(r"C:\a.txt").unwrap(), b"a2\r\n");
        assert_eq!(host.cmd(r#""(echo one & echo two) > C:\b.txt""#), 0);
        assert_eq!(host.fs.read_file(r"C:\b.txt").unwrap(), b"one \r\ntwo\r\n");
    }

    #[test]
    fn programs_resolve_through_cwd_then_path_with_pathext() {
        let mut host = FakeHost::new();
        host.cmd("ok --flag");
        let run = host.runs.last().unwrap();
        assert_eq!(run.application, r"C:\tools\ok.exe");
        assert_eq!(run.command_line, "ok --flag");
        assert_eq!(run.current_directory, r"C:\Users\runner");
        host.program(r"C:\Users\runner\ok.exe", 0, b"");
        host.cmd("ok");
        assert_eq!(
            host.runs.last().unwrap().application,
            r"C:\Users\runner\ok.exe"
        );
        host.cmd(r"C:\tools\fail");
        assert_eq!(host.runs.last().unwrap().application, r"C:\tools\fail.exe");
        // Script extensions cmd cannot run natively are skipped.
        host.file(r"C:\Users\runner\ok.js", "");
        host.fs.delete_file(r"C:\Users\runner\ok.exe").unwrap();
        host.cmd("ok");
        assert_eq!(host.runs.last().unwrap().application, r"C:\tools\ok.exe");
    }

    const NPM_BIN_SHIM: &str = "@ECHO off\r
GOTO start\r
:find_dp0\r
SET dp0=%~dp0\r
EXIT /b\r
:start\r
SETLOCAL\r
CALL :find_dp0\r
\r
IF EXIST \"%dp0%\\node.exe\" (\r
  SET \"_prog=%dp0%\\node.exe\"\r
) ELSE (\r
  SET \"_prog=node\"\r
  SET PATHEXT=%PATHEXT:;.JS;=;%\r
)\r
\r
endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\"  \"%dp0%\\node_modules\\typescript\\bin\\tsc\" %*\r
";

    #[test]
    fn npm_bin_shims_run_node_with_the_script_and_arguments() {
        let mut host = FakeHost::new();
        host.file(r"C:\tools\tsc.cmd", NPM_BIN_SHIM);
        host.program(r"C:\tools\node.exe", 2, b"Version 5.0\r\n");
        assert_eq!(host.cmd(r#""tsc --version "a b"""#), 2);
        let run = host.runs.last().unwrap();
        assert_eq!(run.application, r"C:\tools\node.exe");
        assert_eq!(
            run.command_line,
            // `%dp0%` ends in `\` and the template adds another; Windows
            // passes the text through unchanged.
            r#""C:\tools\\node.exe"  "C:\tools\\node_modules\typescript\bin\tsc" --version "a b""#
        );
        assert_eq!(host.out(), "Version 5.0\r\n");
        assert_eq!(host.err(), "", "the deliberate failed goto is silenced");
        // endLocal restored the caller's environment.
        let environment = &run.environment;
        assert!(!environment.iter().any(|(name, _)| name == "_prog"));

        // Without node.exe beside the shim, `node` comes from PATH, with
        // .JS removed from PATHEXT so a node.js file cannot shadow it.
        host.fs.delete_file(r"C:\tools\node.exe").unwrap();
        host.fs.mkdir(r"C:\nodejs").unwrap();
        host.program(r"C:\nodejs\node.exe", 0, b"");
        host.file(r"C:\Users\runner\node.js", "");
        let mut environment_host = host;
        environment_host.out.clear();
        let code = run_command_line(
            &mut environment_host,
            r"cmd /d /s /c tsc",
            vec![
                ("PATH".to_string(), r"C:\tools;C:\nodejs".to_string()),
                ("PATHEXT".to_string(), ".COM;.EXE;.BAT;.CMD;.JS".to_string()),
            ],
            r"C:\Users\runner".to_string(),
        );
        assert_eq!(code, 0);
        let run = environment_host.runs.last().unwrap();
        assert_eq!(run.application, r"C:\nodejs\node.exe");
        assert!(run.command_line.starts_with("\"node\"  "));
    }

    const NPM_CMD: &str = ":: Created by npm, please don't edit manually.\r
@ECHO OFF\r
\r
SETLOCAL\r
\r
SET \"NODE_EXE=%~dp0\\node.exe\"\r
IF NOT EXIST \"%NODE_EXE%\" (\r
  SET \"NODE_EXE=node\"\r
)\r
\r
SET \"NPM_PREFIX_JS=%~dp0\\node_modules\\npm\\bin\\npm-prefix.js\"\r
SET \"NPM_CLI_JS=%~dp0\\node_modules\\npm\\bin\\npm-cli.js\"\r
FOR /F \"delims=\" %%F IN ('CALL \"%NODE_EXE%\" \"%NPM_PREFIX_JS%\"') DO (\r
  SET \"NPM_PREFIX_NPM_CLI_JS=%%F\\node_modules\\npm\\bin\\npm-cli.js\"\r
)\r
IF EXIST \"%NPM_PREFIX_NPM_CLI_JS%\" (\r
  SET \"NPM_CLI_JS=%NPM_PREFIX_NPM_CLI_JS%\"\r
)\r
\r
\"%NODE_EXE%\" \"%NPM_CLI_JS%\" %*\r
";

    #[test]
    fn npm_cmd_captures_the_prefix_with_for_f_and_prefers_its_cli() {
        let mut host = FakeHost::new();
        host.file(r"C:\nodejs\npm.cmd", NPM_CMD);
        host.program(
            r"C:\nodejs\node.exe",
            0,
            b"C:\\Users\\runner\\AppData\\Roaming\\npm\r\n",
        );
        host.file(
            r"C:\Users\runner\AppData\Roaming\npm\node_modules\npm\bin\npm-cli.js",
            "",
        );
        assert_eq!(host.cmd(r#""C:\nodejs\npm.cmd install left-pad""#), 0);
        assert_eq!(host.runs.len(), 2);
        assert_eq!(host.runs[0].stdout, Output::Capture);
        assert_eq!(
            host.runs[0].command_line,
            r#""C:\nodejs\\node.exe" "C:\nodejs\\node_modules\npm\bin\npm-prefix.js""#
        );
        assert_eq!(
            host.runs[1].command_line,
            r#""C:\nodejs\\node.exe" "C:\Users\runner\AppData\Roaming\npm\node_modules\npm\bin\npm-cli.js" install left-pad"#
        );
        // Only the final run prints; the captured prefix run does not.
        assert_eq!(host.out(), "C:\\Users\\runner\\AppData\\Roaming\\npm\r\n");
    }

    #[test]
    fn subroutines_shift_setlocal_and_exit_b() {
        let mut host = FakeHost::new();
        host.file(
            r"C:\scripts\sub.cmd",
            "@echo off\r
set OUTER=before\r
call :show one \"two words\" three\r
echo after=%ERRORLEVEL% outer=%OUTER% local=%LOCAL%\r
goto :eof\r
:show\r
setlocal\r
set LOCAL=inside\r
set OUTER=changed\r
echo first=%1 unquoted=%~2\r
shift\r
echo shifted=%1\r
exit /b 5\r
",
        );
        assert_eq!(host.cmd(r"C:\scripts\sub.cmd"), 5);
        assert_eq!(
            host.out(),
            "first=one unquoted=two words\r\nshifted=\"two words\"\r\nafter=5 outer=before local=\r\n"
        );
    }

    #[test]
    fn if_forms_and_else_blocks() {
        let mut host = FakeHost::new();
        host.file(
            r"C:\scripts\if.cmd",
            "@echo off\r
set NAME=Value\r
if /i \"%NAME%\"==\"value\" echo ci-equal\r
if \"%NAME%\"==\"value\" (echo wrong) else (\r
  echo case-sensitive\r
  echo second-line\r
)\r
if not defined MISSING echo not-defined\r
if exist C:\\scripts\\if.cmd echo exists\r
if 10 GTR 9 echo numeric\r
if 10 LSS 9 (echo wrong) else echo not-less\r
fail\r
if errorlevel 3 echo level3\r
if errorlevel 4 echo wrong\r
(\r
  if exist C:\\nope echo wrong\r
  echo block-continues\r
)\r
",
        );
        host.cmd(r"C:\scripts\if.cmd");
        assert_eq!(
            host.out(),
            "ci-equal\r\ncase-sensitive\r\nsecond-line\r\nnot-defined\r\nexists\r\nnumeric\r\nnot-less\r\nlevel3\r\nblock-continues\r\n"
        );
    }

    #[test]
    fn for_loops_over_lists_ranges_strings_and_files() {
        let mut host = FakeHost::new();
        host.file(
            r"C:\data\list.txt",
            "; comment\r\nalpha beta gamma\r\n\r\ndelta\r\n",
        );
        host.file(
            r"C:\scripts\for.cmd",
            "@echo off\r
for %%x in (a \"b c\" d) do echo item=%%~x\r
for /l %%n in (1,2,5) do echo n=%%n\r
for /f \"tokens=1,2*\" %%a in (C:\\data\\list.txt) do echo [%%a][%%b][%%c]\r
for /f \"delims=\" %%l in (\"one line\") do echo whole=%%l\r
",
        );
        host.cmd(r"C:\scripts\for.cmd");
        assert_eq!(
            host.out(),
            "item=a\r\nitem=b c\r\nitem=d\r\nn=1\r\nn=3\r\nn=5\r\n[alpha][beta][gamma]\r\n[delta][][]\r\nwhole=one line\r\n"
        );
    }

    #[test]
    fn echo_on_prints_each_batch_line_with_the_prompt() {
        let mut host = FakeHost::new();
        host.file(r"C:\scripts\loud.cmd", "echo hi\r\n@echo quiet\r\n");
        host.cmd(r"C:\scripts\loud.cmd");
        assert_eq!(
            host.out(),
            "\r\nC:\\Users\\runner>echo hi\r\nhi\r\nquiet\r\n"
        );
    }

    #[test]
    fn batch_files_chain_without_call_and_return_with_call() {
        let mut host = FakeHost::new();
        host.file(r"C:\scripts\inner.cmd", "@echo inner %1\r\n");
        host.file(
            r"C:\scripts\outer.cmd",
            "@echo off\r\ncall C:\\scripts\\inner.cmd called\r\necho back\r\nC:\\scripts\\inner.cmd chained\r\necho never\r\n",
        );
        host.cmd(r"C:\scripts\outer.cmd");
        assert_eq!(host.out(), "inner called\r\nback\r\ninner chained\r\n");
        // From the command line a batch file does return.
        host.cmd(r#""C:\scripts\inner.cmd x & echo then""#);
        assert_eq!(host.out(), "inner x\r\nthen\r\n");
    }

    #[test]
    fn a_goto_to_a_missing_label_finishes_the_line_then_the_batch() {
        let mut host = FakeHost::new();
        host.file(
            r"C:\scripts\goto.cmd",
            "@echo off\r\ngoto nowhere & echo same-line\r\necho next-line\r\n",
        );
        assert_eq!(host.cmd(r"C:\scripts\goto.cmd"), 1);
        assert_eq!(host.out(), "same-line\r\n");
        assert!(host
            .err()
            .contains("cannot find the batch label specified - nowhere"));
    }

    #[test]
    fn file_and_directory_commands_work_on_the_guest_disk() {
        let mut host = FakeHost::new();
        host.cmd(r#""mkdir C:\work\sub & cd /d C:\work & echo data> a.txt & copy a.txt sub & type sub\a.txt""#);
        assert_eq!(host.out(), "        1 file(s) copied.\r\ndata \r\n");
        assert!(host.fs.is_file(r"C:\work\sub\a.txt"));
        host.cmd(r#""cd C:\work & echo x> b.log & echo y> c.log & del *.log & dir""#);
        assert!(!host.fs.exists(r"C:\work\b.log") && !host.fs.exists(r"C:\work\c.log"));
        assert!(host.fs.is_file(r"C:\work\a.txt"));
        assert_eq!(host.cmd(r#""del C:\work\missing.txt""#), 0);
        assert!(host
            .err()
            .starts_with("Could Not Find C:\\work\\missing.txt"));
        assert_eq!(host.cmd(r"rmdir C:\work"), 145);
        assert_eq!(host.cmd(r"rmdir /s /q C:\work"), 0);
        assert!(!host.fs.exists(r"C:\work"));
        host.cmd(r#""pushd C:\Windows & cd & popd & cd""#);
        assert_eq!(host.out(), "C:\\Windows\r\nC:\\Users\\runner\r\n");
        assert_eq!(host.cmd(r"cd C:\nope"), 1);
        assert_eq!(host.cmd(r"mkdir C:\tools"), 1);
    }

    #[test]
    fn set_lists_prefixes_and_quoted_assignments() {
        let mut host = FakeHost::new();
        host.cmd(r#""set "GREETING=hello world" & set GREET""#);
        assert_eq!(host.out(), "GREETING=hello world\r\n");
        assert_eq!(host.cmd(r"set NOPE_PREFIX"), 1);
        host.cmd(r#""set /a X=1+1 >nul & set X""#);
        assert_eq!(host.out(), "X=2\r\n");
    }

    #[test]
    fn windows_command_lines_split_like_command_line_to_argv() {
        assert_eq!(
            split_windows_command_line(r#""C:\Program Files\x.exe" a "b c" d\"e "f""g""#),
            [r"C:\Program Files\x.exe", "a", "b c", "d\"e", "f\"g"]
        );
        assert_eq!(split_windows_command_line(r#"x "open"#), ["x", "open"]);
        assert_eq!(split_windows_command_line(r"a\\b c\\"), [r"a\\b", r"c\\"]);
    }

    #[test]
    fn batch_command_lines_quote_paths_and_arguments_with_spaces() {
        let line = batch_command_line(
            r"C:\Program Files\nodejs\npm.cmd",
            &["install".to_string(), "a b".to_string()],
        );
        assert_eq!(
            line,
            r#"C:\Windows\System32\cmd.exe /d /s /c ""C:\Program Files\nodejs\npm.cmd" install "a b"""#
        );
        assert_eq!(
            command_after_switches(&line, |_| false).unwrap().0,
            r#""C:\Program Files\nodejs\npm.cmd" install "a b""#
        );
    }

    #[test]
    fn pipes_feed_the_left_output_to_the_right_input() {
        let mut host = FakeHost::new();
        host.program(r"C:\tools\produce.exe", 0, b"piped line\r\nsecond\r\n");
        assert_eq!(host.cmd(r#""produce | ok""#), 0);
        let consumer = host.runs.last().unwrap();
        let input = consumer.stdin.clone().expect("consumer reads the pipe");
        assert_eq!(host.runs[0].stdout, Output::Capture);
        // The temporary pipe file is gone afterwards.
        assert!(!host.fs.exists(&input));
        host.cmd(r#""echo hello| set /p GOT=& echo got=!GOT!""#);
        assert_eq!(
            host.out(),
            "got=!GOT!\r\n",
            "delayed expansion is off by default"
        );
    }

    #[test]
    fn set_a_evaluates_integer_expressions_with_cmd_precedence() {
        let mut host = FakeHost::new();
        host.cmd(r#""set /a 2+3*4""#);
        assert_eq!(host.out(), "14");
        host.cmd(r#""set /a "x=7, y=x<<2, z=(x+y)%5, w=0x10|010, x*=2" & echo.& set x & set y & set z & set w""#);
        assert_eq!(host.out(), "14\r\nx=14\r\ny=28\r\nz=0\r\nw=24\r\n");
        host.cmd(r#""set /a -5/2& echo.& set /a !0& echo.& set /a ~0""#);
        assert_eq!(host.out(), "-2\r\n1\r\n-1");
        assert_eq!(host.cmd(r#""set /a 1/0""#), 1_073_750_993);
        assert!(host.err().contains("Divide by zero"));
        assert_eq!(host.cmd(r#""set /a 1+""#), 1_073_750_988);
    }

    #[test]
    fn delayed_expansion_reads_variables_when_each_command_runs() {
        let mut host = FakeHost::new();
        host.file(
            r"C:\scripts\delay.cmd",
            "@echo off\r
setlocal enabledelayedexpansion\r
set COUNT=0\r
for /l %%i in (1,1,3) do (\r
  set /a COUNT+=%%i\r
  echo now=!COUNT! then=%COUNT%\r
)\r
set NAME=abc\r
if \"!NAME!\"==\"abc\" echo matched !NAME:b=X!\r
endlocal\r
echo after=!COUNT!\r
",
        );
        host.cmd(r"C:\scripts\delay.cmd");
        assert_eq!(
            host.out(),
            // After endlocal, delayed expansion is off again: `!COUNT!` is text.
            "now=1 then=0\r\nnow=3 then=0\r\nnow=6 then=0\r\nmatched aXc\r\nafter=!COUNT!\r\n"
        );
        // `cmd /v:on` enables it for the command line.
        run_command_line(
            &mut host,
            r#"cmd /v:on /c "set A=1& echo !A!""#,
            Vec::new(),
            r"C:\Users\runner".to_string(),
        );
        assert!(host.out().ends_with("1\r\n"), "{}", host.out());
    }

    #[test]
    fn set_p_reads_a_line_from_redirected_input() {
        let mut host = FakeHost::new();
        host.file(r"C:\data\answer.txt", "yes please\r\nignored\r\n");
        host.cmd(r#""set /p ANSWER=Continue? < C:\data\answer.txt & set ANSWER""#);
        // The space before `<` is part of the prompt, as in cmd.
        assert_eq!(host.out(), "Continue?  ANSWER=yes please\r\n");
        assert_eq!(host.cmd(r#""set /p NOTHING=?""#), 1, "no console input");
    }
}
