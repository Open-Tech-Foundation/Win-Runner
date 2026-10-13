//! PowerShell expressions: literals, variables, operators with
//! PowerShell's precedence, `(...)`, `$(...)`, `@(...)`, `@{...}`, casts,
//! static members, properties, methods, and indexing.
//!
//! [`Interpreter::eval_expression`] parses a statement or value as one
//! expression; `Ok(None)` means it is not one this engine covers (a command,
//! a construct it lacks), and the caller keeps its own handling.
use super::*;

/// A value during evaluation. Strings that come from variables, commands
/// or `$(...)` are `Auto`: numeric when they read as a number, as values
/// assigned from arithmetic do; quoted literals are `Text`.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum V {
    Null,
    Bool(bool),
    Int(i64),
    Num(f64),
    Text(String),
    Auto(String),
    Arr(Vec<V>),
    Map(Vec<(String, V)>),
}

/// Not an expression this engine evaluates: the caller decides.
struct Unsupported;

type R<T> = Result<Result<T, Unsupported>, String>;

macro_rules! tri {
    ($e:expr) => {
        match $e? {
            Ok(value) => value,
            Err(Unsupported) => return Ok(Err(Unsupported)),
        }
    };
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Number(V),
    Text(String),
    /// A double-quoted string's source, quotes included, for expansion.
    Expandable(String),
    Var(String),
    /// `[type]`
    Type(String),
    /// `-eq`, `-not`, ... (lower case, without the dash)
    Word(String),
    Ident(String),
    Sym(&'static str),
    /// `{ ... }` source, braces included.
    Block(String),
    /// `$( ... )` / `@( ... )` inner source.
    Sub(String),
    ArraySub(String),
    HashOpen,
}

const OPERATOR_WORDS: &[&str] = &[
    "eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch", "contains", "notcontains", "in",
    "notin", "replace", "split", "join", "is", "isnot", "as", "and", "or", "xor", "not", "band", "bor", "bxor",
    "bnot", "shl", "shr", "f",
];

fn operator_word(word: &str) -> Option<String> {
    let lower = word.to_ascii_lowercase();
    let base = lower.strip_prefix('c').or_else(|| lower.strip_prefix('i')).filter(|b| OPERATOR_WORDS.contains(b));
    if OPERATOR_WORDS.contains(&lower.as_str()) || base.is_some() {
        Some(lower)
    } else {
        None
    }
}

/// The text of a `(`/`{`/`[`-balanced span starting at `start` (the opener),
/// quotes respected; the index after the closer.
fn balanced(chars: &[char], start: usize, open: char, close: char) -> Option<(String, usize)> {
    let mut depth = 0;
    let mut index = start;
    let mut quote: Option<char> = None;
    while index < chars.len() {
        let c = chars[index];
        match quote {
            Some(q) => {
                if c == '`' && q == '"' {
                    index += 1;
                } else if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                } else if c == open {
                    depth += 1;
                } else if c == close {
                    depth -= 1;
                    if depth == 0 {
                        return Some((chars[start + 1..index].iter().collect(), index + 1));
                    }
                }
            }
        }
        index += 1;
    }
    None
}

fn lex(source: &str) -> Option<Vec<Tok>> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens: Vec<Tok> = Vec::new();
    let mut index = 0;
    // Whether the next token stands where an operand goes (so `-1` is a
    // number and `[x]` a type) rather than after one.
    let operand_position = |tokens: &Vec<Tok>| match tokens.last() {
        None => true,
        Some(Tok::Sym(s)) => !matches!(*s, ")" | "]" | "}"),
        Some(Tok::Word(_)) | Some(Tok::HashOpen) => true,
        _ => false,
    };
    while index < chars.len() {
        let c = chars[index];
        if c.is_whitespace() {
            index += 1;
            continue;
        }
        let rest: String = chars[index..].iter().take(3).collect();
        // Numbers (an operand `-` with a digit is a negative literal).
        let negative = c == '-' && chars.get(index + 1).is_some_and(|d| d.is_ascii_digit()) && operand_position(&tokens);
        if c.is_ascii_digit() || negative || (c == '.' && chars.get(index + 1).is_some_and(|d| d.is_ascii_digit()) && operand_position(&tokens)) {
            let start = index;
            index += 1;
            let hex = rest.starts_with("0x") || rest.starts_with("0X") || rest.starts_with("-0x");
            while index < chars.len() {
                let d = chars[index];
                if d.is_ascii_alphanumeric() || (d == '.' && !hex && chars.get(index + 1) != Some(&'.')) {
                    index += 1;
                } else {
                    break;
                }
            }
            let text: String = chars[start..index].iter().collect();
            tokens.push(Tok::Number(number_literal(&text)?));
            continue;
        }
        match c {
            '\'' => {
                let mut text = String::new();
                index += 1;
                loop {
                    let d = *chars.get(index)?;
                    index += 1;
                    if d == '\'' {
                        if chars.get(index) == Some(&'\'') {
                            text.push('\'');
                            index += 1;
                            continue;
                        }
                        break;
                    }
                    text.push(d);
                }
                tokens.push(Tok::Text(text));
            }
            '"' => {
                let start = index;
                index += 1;
                loop {
                    let d = *chars.get(index)?;
                    index += 1;
                    if d == '`' {
                        index += 1;
                    } else if d == '$' && chars.get(index) == Some(&'(') {
                        let (_, after) = balanced(&chars, index, '(', ')')?;
                        index = after;
                    } else if d == '"' {
                        break;
                    }
                }
                tokens.push(Tok::Expandable(chars[start..index].iter().collect()));
            }
            '$' => {
                if chars.get(index + 1) == Some(&'(') {
                    let (inner, after) = balanced(&chars, index + 1, '(', ')')?;
                    tokens.push(Tok::Sub(inner));
                    index = after;
                } else if chars.get(index + 1) == Some(&'{') {
                    let (inner, after) = balanced(&chars, index + 1, '{', '}')?;
                    tokens.push(Tok::Var(inner));
                    index = after;
                } else {
                    let start = index + 1;
                    index = start;
                    while index < chars.len() && (chars[index].is_alphanumeric() || matches!(chars[index], '_' | ':' | '?')) {
                        // `$env:Path` keeps its colon; `$a::b` is not a variable.
                        if chars[index] == ':' && chars.get(index + 1) == Some(&':') {
                            break;
                        }
                        index += 1;
                    }
                    if index == start {
                        return None;
                    }
                    tokens.push(Tok::Var(chars[start..index].iter().collect()));
                }
            }
            '@' => match chars.get(index + 1) {
                Some('(') => {
                    let (inner, after) = balanced(&chars, index + 1, '(', ')')?;
                    tokens.push(Tok::ArraySub(inner));
                    index = after;
                }
                Some('{') => {
                    tokens.push(Tok::HashOpen);
                    index += 2;
                }
                _ => return None,
            },
            '[' if operand_position(&tokens) => {
                let (inner, after) = balanced(&chars, index, '[', ']')?;
                if !inner.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '[' | ']' | ',' | ' ')) {
                    return None;
                }
                tokens.push(Tok::Type(inner.trim().to_string()));
                index = after;
            }
            '{' => {
                let (inner, after) = balanced(&chars, index, '{', '}')?;
                tokens.push(Tok::Block(format!("{{{inner}}}")));
                index = after;
            }
            '-' if chars.get(index + 1).is_some_and(|d| d.is_ascii_alphabetic()) => {
                let start = index + 1;
                index = start;
                while index < chars.len() && chars[index].is_ascii_alphabetic() {
                    index += 1;
                }
                let word: String = chars[start..index].iter().collect();
                tokens.push(Tok::Word(operator_word(&word)?));
            }
            _ if c.is_alphabetic() || c == '_' => {
                let start = index;
                while index < chars.len() && (chars[index].is_alphanumeric() || matches!(chars[index], '_' | '-')) {
                    index += 1;
                }
                tokens.push(Tok::Ident(chars[start..index].iter().collect()));
            }
            _ => {
                let symbols = ["..", "::", "+=", "(", ")", "[", "]", "}", ",", ".", "+", "-", "*", "/", "%", "!", ";", "="];
                let symbol = symbols.iter().find(|s| rest.starts_with(**s))?;
                tokens.push(Tok::Sym(symbol));
                index += symbol.len();
            }
        }
    }
    Some(tokens)
}

/// `42`, `0x1F`, `1.5`, `1e3`, `10kb`, `-3`.
fn number_literal(text: &str) -> Option<V> {
    let lower = text.to_ascii_lowercase();
    let (digits, multiplier) = [("kb", 1i64 << 10), ("mb", 1 << 20), ("gb", 1 << 30), ("tb", 1 << 40), ("pb", 1 << 50)]
        .iter()
        .find_map(|(suffix, factor)| lower.strip_suffix(suffix).map(|d| (d.to_string(), *factor)))
        .unwrap_or((lower.clone(), 1));
    let (negative, body) = match digits.strip_prefix('-') {
        Some(rest) => (true, rest.to_string()),
        None => (false, digits),
    };
    let value = if let Some(hex) = body.strip_prefix("0x") {
        V::Int(i64::from_str_radix(hex, 16).ok()?)
    } else if let Some(int) = body.strip_suffix('l').filter(|d| d.chars().all(|c| c.is_ascii_digit())) {
        V::Int(int.parse().ok()?)
    } else if body.chars().all(|c| c.is_ascii_digit()) {
        match body.parse::<i64>() {
            Ok(value) => V::Int(value),
            Err(_) => V::Num(body.parse().ok()?),
        }
    } else {
        V::Num(body.parse().ok()?)
    };
    let value = match (value, multiplier) {
        (V::Int(value), m) => V::Int(value.checked_mul(m)?),
        (V::Num(value), m) => V::Num(value * m as f64),
        (other, _) => other,
    };
    Some(match (value, negative) {
        (V::Int(value), true) => V::Int(-value),
        (V::Num(value), true) => V::Num(-value),
        (value, _) => value,
    })
}

/// How a double prints: up to 15 significant digits, as .NET's default.
fn format_double(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if value == value.trunc() && value.abs() < 1e15 {
        return format!("{}", value as i64);
    }
    let text = format!("{:.*e}", 14, value);
    let parsed: f64 = text.parse().unwrap_or(value);
    let plain = format!("{parsed}");
    if plain.contains('e') { text } else { plain }
}

impl V {
    pub(super) fn from_value(value: &Value) -> V {
        match value {
            Value::Str(s) => V::Auto(s.clone()),
            Value::Arr(items) => V::Arr(items.iter().map(V::from_value).collect()),
            Value::Map(map) => {
                let mut entries: Vec<(String, V)> = map.iter().map(|(k, v)| (k.clone(), V::from_value(v))).collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                V::Map(entries)
            }
        }
    }

    pub(super) fn into_value(self) -> Value {
        match self {
            V::Arr(items) => Value::Arr(items.into_iter().filter(|v| *v != V::Null).map(V::into_value).collect()),
            V::Map(entries) => Value::Map(entries.into_iter().map(|(k, v)| (k, v.into_value())).collect()),
            other => Value::Str(other.text()),
        }
    }

    fn text(&self) -> String {
        match self {
            V::Null => String::new(),
            V::Bool(b) => bool_string(*b),
            V::Int(i) => i.to_string(),
            V::Num(n) => format_double(*n),
            V::Text(s) | V::Auto(s) => s.clone(),
            V::Arr(items) => items.iter().map(V::text).collect::<Vec<_>>().join(" "),
            V::Map(_) => "System.Collections.Hashtable".into(),
        }
    }

    /// A number, when this reads as one.
    fn number(&self) -> Option<V> {
        match self {
            V::Int(_) | V::Num(_) => Some(self.clone()),
            V::Bool(b) => Some(V::Int(i64::from(*b))),
            V::Null => Some(V::Int(0)),
            V::Text(s) | V::Auto(s) => {
                let t = s.trim();
                if t.is_empty() {
                    return Some(V::Int(0));
                }
                number_literal(t).or_else(|| parse_number(t).map(V::Num))
            }
            _ => None,
        }
    }

    fn float(&self) -> Option<f64> {
        match self.number()? {
            V::Int(i) => Some(i as f64),
            V::Num(n) => Some(n),
            _ => None,
        }
    }

    fn truthy(&self) -> bool {
        match self {
            V::Null => false,
            V::Bool(b) => *b,
            V::Int(i) => *i != 0,
            V::Num(n) => *n != 0.0,
            V::Text(s) => !s.is_empty(),
            V::Auto(s) => is_truthy(s),
            V::Arr(items) => match items.len() {
                0 => false,
                1 => items[0].truthy(),
                _ => true,
            },
            V::Map(_) => true,
        }
    }

    fn is_numeric(&self) -> bool {
        match self {
            V::Int(_) | V::Num(_) => true,
            V::Auto(s) => !s.trim().is_empty() && self.number().is_some(),
            _ => false,
        }
    }

    fn items(self) -> Vec<V> {
        match self {
            V::Arr(items) => items,
            V::Null => Vec::new(),
            other => vec![other],
        }
    }
}

fn arithmetic(op: &str, left: &V, right: &V) -> Result<V, String> {
    let (a, b) = (left.number(), right.number());
    let (Some(a), Some(b)) = (a, b) else {
        return Err(format!("cannot apply {op} to {:?} and {:?}", left.text(), right.text()));
    };
    if let (V::Int(x), V::Int(y)) = (&a, &b) {
        let result = match op {
            "+" => x.checked_add(*y),
            "-" => x.checked_sub(*y),
            "*" => x.checked_mul(*y),
            "%" => {
                if *y == 0 {
                    return Err("Attempted to divide by zero.".into());
                }
                Some(x % y)
            }
            "/" => {
                if *y == 0 {
                    return Err("Attempted to divide by zero.".into());
                }
                if x % y == 0 { Some(x / y) } else { None }
            }
            _ => None,
        };
        if let Some(result) = result {
            return Ok(V::Int(result));
        }
    }
    let (x, y) = (a.float().unwrap_or(0.0), b.float().unwrap_or(0.0));
    Ok(V::Num(match op {
        "+" => x + y,
        "-" => x - y,
        "*" => x * y,
        "/" => {
            if y == 0.0 {
                return Err("Attempted to divide by zero.".into());
            }
            x / y
        }
        _ => x % y,
    }))
}

fn add(left: V, right: V) -> Result<V, String> {
    match left {
        V::Arr(mut items) => {
            items.extend(right.items());
            Ok(V::Arr(items))
        }
        V::Map(mut entries) => match right {
            V::Map(more) => {
                for (key, value) in more {
                    if entries.iter().any(|(k, _)| k.eq_ignore_ascii_case(&key)) {
                        return Err(format!("Item has already been added. Key in dictionary: '{key}'"));
                    }
                    entries.push((key, value));
                }
                Ok(V::Map(entries))
            }
            _ => Err("A hash table can only be added to another hash table.".into()),
        },
        V::Text(s) => Ok(V::Text(s + &right.text())),
        left if left.is_numeric() || left == V::Null => {
            if right.is_numeric() || right == V::Null || matches!(right, V::Bool(_)) {
                arithmetic("+", &left, &right)
            } else if left == V::Null {
                Ok(right)
            } else {
                Err(format!("Cannot convert value \"{}\" to type \"System.Int32\".", right.text()))
            }
        }
        left => Ok(V::Text(left.text() + &right.text())),
    }
}

/// `-like` wildcards: `*`, `?`, and `[...]` sets.
fn like(pattern: &str, text: &str, case_sensitive: bool) -> bool {
    let fold = |s: &str| if case_sensitive { s.to_string() } else { s.to_lowercase() };
    let (p, t): (Vec<char>, Vec<char>) = (fold(pattern).chars().collect(), fold(text).chars().collect());
    fn go(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => go(&p[1..], t) || (!t.is_empty() && go(p, &t[1..])),
            Some('?') => !t.is_empty() && go(&p[1..], &t[1..]),
            Some('[') => {
                let Some(end) = p.iter().position(|c| *c == ']') else {
                    return t.first() == Some(&'[') && go(&p[1..], &t[1..]);
                };
                let Some(c) = t.first() else { return false };
                let set = &p[1..end];
                let mut found = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == '-' {
                        found |= (set[i]..=set[i + 2]).contains(c);
                        i += 3;
                    } else {
                        found |= set[i] == *c;
                        i += 1;
                    }
                }
                found && go(&p[end + 1..], &t[1..])
            }
            Some(c) => t.first() == Some(c) && go(&p[1..], &t[1..]),
        }
    }
    go(&p, &t)
}

fn compare(left: &V, right: &V, case_sensitive: bool) -> std::cmp::Ordering {
    if left.is_numeric() && (right.is_numeric() || matches!(right, V::Text(_)) && right.number().is_some()) {
        let (a, b) = (left.float().unwrap_or(0.0), right.float().unwrap_or(0.0));
        return a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal);
    }
    let (a, b) = (left.text(), right.text());
    if case_sensitive { a.cmp(&b) } else { a.to_lowercase().cmp(&b.to_lowercase()) }
}

fn equal(left: &V, right: &V, case_sensitive: bool) -> bool {
    match (left, right) {
        (V::Null, V::Null) => true,
        (V::Null, _) | (_, V::Null) => false,
        (V::Bool(a), other) | (other, V::Bool(a)) => *a == other.truthy(),
        _ => compare(left, right, case_sensitive) == std::cmp::Ordering::Equal,
    }
}

/// `"{0} and {1:N2}" -f a, b`.
fn format_operator(template: &str, args: &[V]) -> Result<String, String> {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if c == '{' && chars.get(index + 1) == Some(&'{') {
            out.push('{');
            index += 2;
            continue;
        }
        if c == '}' && chars.get(index + 1) == Some(&'}') {
            out.push('}');
            index += 2;
            continue;
        }
        if c != '{' {
            out.push(c);
            index += 1;
            continue;
        }
        let end = chars[index..].iter().position(|c| *c == '}').ok_or("Input string was not in a correct format.")? + index;
        let spec: String = chars[index + 1..end].iter().collect();
        let (head, format) = spec.split_once(':').map_or((spec.as_str(), ""), |(h, f)| (h, f));
        let (position, width) = head.split_once(',').map_or((head, None), |(p, w)| (p, w.trim().parse::<i32>().ok()));
        let position: usize = position.trim().parse().map_err(|_| "Input string was not in a correct format.")?;
        let value = args.get(position).ok_or("Index (zero based) must be greater than or equal to zero and less than the size of the argument list.")?;
        let mut text = format_value(value, format);
        if let Some(width) = width {
            let pad = (width.unsigned_abs() as usize).saturating_sub(text.chars().count());
            text = if width < 0 { text + &" ".repeat(pad) } else { " ".repeat(pad) + &text };
        }
        out.push_str(&text);
        index = end + 1;
    }
    Ok(out)
}

/// A .NET standard numeric format: N, D, F, X, P (with a precision).
fn format_value(value: &V, format: &str) -> String {
    let mut chars = format.chars();
    let Some(kind) = chars.next() else { return value.text() };
    let precision: Option<usize> = chars.as_str().parse().ok();
    let Some(number) = value.float() else { return value.text() };
    match kind.to_ascii_uppercase() {
        'N' => {
            let digits = precision.unwrap_or(2);
            let text = format!("{:.*}", digits, number.abs());
            let (whole, fraction) = text.split_once('.').map_or((text.as_str(), None), |(w, f)| (w, Some(f)));
            let mut grouped = String::new();
            for (i, c) in whole.chars().enumerate() {
                if i > 0 && (whole.len() - i) % 3 == 0 {
                    grouped.push(',');
                }
                grouped.push(c);
            }
            let sign = if number < 0.0 { "-" } else { "" };
            match fraction {
                Some(f) => format!("{sign}{grouped}.{f}"),
                None => format!("{sign}{grouped}"),
            }
        }
        'F' => format!("{:.*}", precision.unwrap_or(2), number),
        'D' => format!("{:0width$}", number as i64, width = precision.unwrap_or(0)),
        'X' => {
            let text = format!("{:X}", number as i64);
            let text = format!("{:0>width$}", text, width = precision.unwrap_or(0));
            if kind == 'x' { text.to_lowercase() } else { text }
        }
        'P' => format!("{:.*} %", precision.unwrap_or(2), number * 100.0),
        _ => value.text(),
    }
}

struct Parser {
    tokens: Vec<Tok>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.at)
    }
    fn next(&mut self) -> Option<Tok> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        token
    }
    fn eat_sym(&mut self, symbol: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Sym(s)) if *s == symbol) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn peek_word(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Word(w)) => Some(w.as_str()),
            _ => None,
        }
    }
}

impl Interpreter<'_> {
    /// Evaluate `source` as one PowerShell expression; `Ok(None)` when it
    /// is not one this engine covers.
    pub(super) fn eval_expression(&mut self, source: &str) -> Result<Option<V>, String> {
        let Some(tokens) = lex(source) else {
            return Ok(None);
        };
        if tokens.is_empty() {
            return Ok(None);
        }
        let mut parser = Parser { tokens, at: 0 };
        match self.parse_logical(&mut parser)? {
            Ok(value) if parser.at == parser.tokens.len() => Ok(Some(value)),
            _ => Ok(None),
        }
    }

    fn parse_logical(&mut self, p: &mut Parser) -> R<V> {
        let mut left = tri!(self.parse_comparison(p));
        while let Some(op) = p.peek_word().filter(|w| matches!(*w, "and" | "or" | "xor")).map(str::to_string) {
            p.at += 1;
            let right = tri!(self.parse_comparison(p));
            left = V::Bool(match op.as_str() {
                "and" => left.truthy() && right.truthy(),
                "or" => left.truthy() || right.truthy(),
                _ => left.truthy() != right.truthy(),
            });
        }
        Ok(Ok(left))
    }

    fn parse_comparison(&mut self, p: &mut Parser) -> R<V> {
        let mut left = tri!(self.parse_bitwise(p));
        loop {
            let Some(word) = p.peek_word().map(str::to_string) else { break };
            let case_sensitive = word.starts_with('c') && OPERATOR_WORDS.contains(&&word[1..]);
            let base = if (word.starts_with('c') || word.starts_with('i')) && OPERATOR_WORDS.contains(&&word[1..]) {
                word[1..].to_string()
            } else {
                word.clone()
            };
            if !matches!(
                base.as_str(),
                "eq" | "ne" | "gt" | "ge" | "lt" | "le" | "like" | "notlike" | "match" | "notmatch" | "contains"
                    | "notcontains" | "in" | "notin" | "replace" | "split" | "join" | "is" | "isnot" | "as"
            ) {
                break;
            }
            p.at += 1;
            if matches!(base.as_str(), "is" | "isnot" | "as") {
                let Some(Tok::Type(typ)) = p.next() else { return Ok(Err(Unsupported)) };
                left = tri!(self.type_operator(&base, left, &typ));
                continue;
            }
            let right = tri!(self.parse_bitwise(p));
            left = tri!(self.comparison(&base, case_sensitive, left, right));
        }
        Ok(Ok(left))
    }

    fn type_operator(&mut self, op: &str, value: V, typ: &str) -> R<V> {
        let lower = typ.to_ascii_lowercase();
        let is = match lower.as_str() {
            "int" | "int32" | "long" | "int64" => matches!(value, V::Int(_)),
            "double" | "float" | "decimal" => matches!(value, V::Num(_)),
            "string" => matches!(value, V::Text(_) | V::Auto(_)),
            "bool" | "boolean" => matches!(value, V::Bool(_)),
            "array" | "object[]" => matches!(value, V::Arr(_)),
            "hashtable" => matches!(value, V::Map(_)),
            "object" | "psobject" => value != V::Null,
            _ => return Ok(Err(Unsupported)),
        };
        Ok(Ok(match op {
            "is" => V::Bool(is),
            "isnot" => V::Bool(!is),
            // A failed -as is $null rather than an error.
            _ => match self.cast(typ, value) {
                Ok(Ok(v)) => v,
                Ok(Err(Unsupported)) => return Ok(Err(Unsupported)),
                Err(_) => V::Null,
            },
        }))
    }

    fn comparison(&mut self, op: &str, case_sensitive: bool, left: V, right: V) -> R<V> {
        // An array on the left filters its elements (or tests membership).
        if let V::Arr(items) = &left {
            if !matches!(op, "contains" | "notcontains" | "replace" | "split" | "join" | "in" | "notin") {
                let mut kept = Vec::new();
                for item in items {
                    if tri!(self.comparison(op, case_sensitive, item.clone(), right.clone())).truthy() {
                        kept.push(item.clone());
                    }
                }
                return Ok(Ok(V::Arr(kept)));
            }
        }
        Ok(Ok(match op {
            "eq" => V::Bool(equal(&left, &right, case_sensitive)),
            "ne" => V::Bool(!equal(&left, &right, case_sensitive)),
            "gt" => V::Bool(compare(&left, &right, case_sensitive).is_gt()),
            "ge" => V::Bool(compare(&left, &right, case_sensitive).is_ge()),
            "lt" => V::Bool(compare(&left, &right, case_sensitive).is_lt()),
            "le" => V::Bool(compare(&left, &right, case_sensitive).is_le()),
            "like" => V::Bool(like(&right.text(), &left.text(), case_sensitive)),
            "notlike" => V::Bool(!like(&right.text(), &left.text(), case_sensitive)),
            "match" | "notmatch" => {
                // The regex subset matches without case.
                let matched = regex_match(&right.text(), &left.text())?;
                V::Bool(matched == (op == "match"))
            }
            "contains" | "notcontains" => {
                let found = left.clone().items().iter().any(|item| equal(item, &right, case_sensitive));
                V::Bool(found == (op == "contains"))
            }
            "in" | "notin" => {
                let found = right.clone().items().iter().any(|item| equal(item, &left, case_sensitive));
                V::Bool(found == (op == "in"))
            }
            "replace" => {
                let (pattern, replacement) = match right {
                    V::Arr(parts) if parts.len() > 2 => {
                        return Err(format!("The -replace operator allows only two elements to follow it, not {}.", parts.len()));
                    }
                    V::Arr(parts) => (
                        parts.first().map(V::text).unwrap_or_default(),
                        parts.get(1).map(V::text).unwrap_or_default(),
                    ),
                    other => (other.text(), String::new()),
                };
                // The regex subset matches without case (as -replace does).
                let replace = |text: String| regex_replace(&pattern, &text, &replacement);
                match left {
                    V::Arr(items) => V::Arr(
                        items.into_iter().map(|item| replace(item.text()).map(V::Text)).collect::<Result<_, _>>()?,
                    ),
                    other => V::Text(replace(other.text())?),
                }
            }
            "split" => {
                let pattern = right.text();
                let mut parts = Vec::new();
                for item in left.items() {
                    parts.extend(regex_split(&pattern, &item.text())?.into_iter().map(V::Text));
                }
                V::Arr(parts)
            }
            "join" => V::Text(left.items().iter().map(V::text).collect::<Vec<_>>().join(&right.text())),
            _ => return Ok(Err(Unsupported)),
        }))
    }

    fn parse_bitwise(&mut self, p: &mut Parser) -> R<V> {
        let mut left = tri!(self.parse_additive(p));
        while let Some(op) = p.peek_word().filter(|w| matches!(*w, "band" | "bor" | "bxor" | "shl" | "shr")).map(str::to_string) {
            p.at += 1;
            let right = tri!(self.parse_additive(p));
            let (Some(V::Int(a)), Some(V::Int(b))) = (left.number(), right.number()) else {
                return Err(format!("-{op} needs integers"));
            };
            left = V::Int(match op.as_str() {
                "band" => a & b,
                "bor" => a | b,
                "bxor" => a ^ b,
                "shl" => a << (b & 63),
                _ => a >> (b & 63),
            });
        }
        Ok(Ok(left))
    }

    fn parse_additive(&mut self, p: &mut Parser) -> R<V> {
        let mut left = tri!(self.parse_multiplicative(p));
        loop {
            if p.eat_sym("+") {
                let right = tri!(self.parse_multiplicative(p));
                left = add(left, right)?;
            } else if p.eat_sym("-") {
                let right = tri!(self.parse_multiplicative(p));
                left = arithmetic("-", &left, &right)?;
            } else {
                break;
            }
        }
        Ok(Ok(left))
    }

    fn parse_multiplicative(&mut self, p: &mut Parser) -> R<V> {
        let mut left = tri!(self.parse_format(p));
        loop {
            let op = if p.eat_sym("*") {
                "*"
            } else if p.eat_sym("/") {
                "/"
            } else if p.eat_sym("%") {
                "%"
            } else {
                break;
            };
            let right = tri!(self.parse_format(p));
            left = match (&left, op) {
                // String and array repetition.
                (V::Text(s), "*") => V::Text(s.repeat(right.float().unwrap_or(0.0).max(0.0) as usize)),
                (V::Auto(s), "*") if !left.is_numeric() => V::Text(s.repeat(right.float().unwrap_or(0.0).max(0.0) as usize)),
                (V::Arr(items), "*") => {
                    let times = right.float().unwrap_or(0.0).max(0.0) as usize;
                    V::Arr(items.iter().cloned().cycle().take(items.len() * times).collect())
                }
                _ => arithmetic(op, &left, &right)?,
            };
        }
        Ok(Ok(left))
    }

    fn parse_format(&mut self, p: &mut Parser) -> R<V> {
        let mut left = tri!(self.parse_unary(p));
        while p.peek_word() == Some("f") {
            p.at += 1;
            let right = tri!(self.parse_unary(p));
            left = V::Text(format_operator(&left.text(), &right.items())?);
        }
        Ok(Ok(left))
    }

    fn parse_unary(&mut self, p: &mut Parser) -> R<V> {
        if p.eat_sym("!") || p.peek_word() == Some("not") && {
            p.at += 1;
            true
        } {
            let value = tri!(self.parse_unary(p));
            return Ok(Ok(V::Bool(!value.truthy())));
        }
        if p.eat_sym("-") {
            let value = tri!(self.parse_unary(p));
            return Ok(Ok(arithmetic("-", &V::Int(0), &value)?));
        }
        if p.eat_sym("+") {
            let value = tri!(self.parse_unary(p));
            return Ok(Ok(value.number().unwrap_or(value)));
        }
        if p.peek_word() == Some("bnot") {
            p.at += 1;
            let value = tri!(self.parse_unary(p));
            let Some(V::Int(i)) = value.number() else { return Err("-bnot needs an integer".into()) };
            return Ok(Ok(V::Int(!i)));
        }
        if matches!(p.peek_word(), Some("split" | "join")) {
            let op = p.peek_word().unwrap_or_default().to_string();
            p.at += 1;
            let value = tri!(self.parse_unary(p));
            return Ok(Ok(if op == "join" {
                V::Text(value.items().iter().map(V::text).collect())
            } else {
                V::Arr(value.text().split_whitespace().map(|s| V::Text(s.to_string())).collect())
            }));
        }
        self.parse_range(p)
    }

    fn parse_range(&mut self, p: &mut Parser) -> R<V> {
        let left = tri!(self.parse_comma(p));
        if p.eat_sym("..") {
            let right = tri!(self.parse_comma(p));
            let (Some(a), Some(b)) = (left.float(), right.float()) else {
                return Err("a range needs numbers".into());
            };
            let (a, b) = (a.round() as i64, b.round() as i64);
            let values: Vec<V> = if a <= b { (a..=b).map(V::Int).collect() } else { (b..=a).rev().map(V::Int).collect() };
            return Ok(Ok(V::Arr(values)));
        }
        Ok(Ok(left))
    }

    fn parse_comma(&mut self, p: &mut Parser) -> R<V> {
        let first = tri!(self.parse_cast(p));
        if !matches!(p.peek(), Some(Tok::Sym(","))) {
            return Ok(Ok(first));
        }
        let mut items = vec![first];
        while p.eat_sym(",") {
            items.push(tri!(self.parse_cast(p)));
        }
        Ok(Ok(V::Arr(items)))
    }

    fn parse_cast(&mut self, p: &mut Parser) -> R<V> {
        if let Some(Tok::Type(typ)) = p.peek().cloned() {
            // `[type]::Member` is a static access, not a cast.
            if !matches!(p.tokens.get(p.at + 1), Some(Tok::Sym("::"))) {
                p.at += 1;
                let value = tri!(self.parse_cast(p));
                return self.cast(&typ, value);
            }
        }
        self.parse_postfix(p)
    }

    fn cast(&mut self, typ: &str, value: V) -> R<V> {
        let lower = typ.to_ascii_lowercase();
        let lower = lower.trim_start_matches("system.");
        let number = |value: &V| value.number().ok_or_else(|| format!("Cannot convert value \"{}\" to type \"{typ}\".", value.text()));
        Ok(Ok(match lower {
            "int" | "int32" | "long" | "int64" | "byte" | "sbyte" | "int16" | "uint16" | "uint32" | "uint64" => {
                let n = number(&value)?;
                // .NET rounds to even when converting doubles to integers.
                let whole = match n {
                    V::Num(f) => {
                        let r = f.round();
                        if (f - f.trunc()).abs() == 0.5 && r % 2.0 != 0.0 { r - f.signum() } else { r }
                    }
                    V::Int(i) => i as f64,
                    _ => 0.0,
                };
                let (low, high) = match lower {
                    "byte" => (0.0, 255.0),
                    "sbyte" => (-128.0, 127.0),
                    "int16" => (-32768.0, 32767.0),
                    "uint16" => (0.0, 65535.0),
                    "int" | "int32" => (i32::MIN as f64, i32::MAX as f64),
                    "uint32" => (0.0, u32::MAX as f64),
                    "uint64" => (0.0, u64::MAX as f64),
                    _ => (i64::MIN as f64, i64::MAX as f64),
                };
                if whole < low || whole > high {
                    return Err(format!("Cannot convert value \"{}\" to type \"{typ}\". Value was either too large or too small.", value.text()));
                }
                V::Int(whole as i64)
            }
            "double" | "float" | "single" | "decimal" => V::Num(number(&value)?.float().unwrap_or(0.0)),
            "string" => V::Text(value.text()),
            "bool" | "boolean" => V::Bool(value.truthy()),
            "char" => match value.number() {
                Some(V::Int(code)) if !matches!(value, V::Text(_)) => {
                    V::Text(char::from_u32(code as u32).map(String::from).unwrap_or_default())
                }
                _ => V::Text(value.text().chars().next().map(String::from).unwrap_or_default()),
            },
            "array" | "object[]" | "string[]" | "int[]" => V::Arr(value.items()),
            "hashtable" | "ordered" => match value {
                V::Map(entries) => V::Map(entries),
                _ => return Ok(Err(Unsupported)),
            },
            _ => return Ok(Err(Unsupported)),
        }))
    }

    fn parse_postfix(&mut self, p: &mut Parser) -> R<V> {
        let mut value = tri!(self.parse_primary(p));
        loop {
            if p.eat_sym(".") {
                let Some(Tok::Ident(name)) = p.next() else { return Ok(Err(Unsupported)) };
                if matches!(p.peek(), Some(Tok::Sym("("))) && self.is_call_paren(p) {
                    let args = tri!(self.parse_call_args(p));
                    value = tri!(self.method(value, &name, args));
                } else {
                    value = tri!(self.property(value, &name));
                }
            } else if matches!(p.peek(), Some(Tok::Sym("["))) {
                p.at += 1;
                let index = tri!(self.parse_logical(p));
                if !p.eat_sym("]") {
                    return Ok(Err(Unsupported));
                }
                value = self.index(value, index);
            } else {
                break;
            }
        }
        Ok(Ok(value))
    }

    /// A `(` right after a member name opens its argument list.
    fn is_call_paren(&self, p: &Parser) -> bool {
        matches!(p.peek(), Some(Tok::Sym("(")))
    }

    fn parse_call_args(&mut self, p: &mut Parser) -> R<Vec<V>> {
        p.at += 1; // (
        let mut args = Vec::new();
        if p.eat_sym(")") {
            return Ok(Ok(args));
        }
        loop {
            // Arguments are separated by commas, so each is below comma level.
            let arg = tri!(self.parse_argument(p));
            args.push(arg);
            if p.eat_sym(",") {
                continue;
            }
            if p.eat_sym(")") {
                return Ok(Ok(args));
            }
            return Ok(Err(Unsupported));
        }
    }

    /// One method argument: a full expression without top-level commas.
    fn parse_argument(&mut self, p: &mut Parser) -> R<V> {
        // Parse with commas disabled by evaluating up to the next `,`/`)`
        // at depth 0: re-lex that slice.
        let start = p.at;
        let mut depth = 0i32;
        let mut end = start;
        while let Some(token) = p.tokens.get(end) {
            match token {
                Tok::Sym("(") | Tok::Sym("[") | Tok::HashOpen => depth += 1,
                Tok::Sym(")") | Tok::Sym("]") | Tok::Sym("}") if depth > 0 => depth -= 1,
                Tok::Sym(")") | Tok::Sym(",") if depth == 0 => break,
                _ => {}
            }
            end += 1;
        }
        let mut sub = Parser { tokens: p.tokens[start..end].to_vec(), at: 0 };
        let value = tri!(self.parse_logical(&mut sub));
        if sub.at != sub.tokens.len() {
            return Ok(Err(Unsupported));
        }
        p.at = end;
        Ok(Ok(value))
    }

    fn parse_primary(&mut self, p: &mut Parser) -> R<V> {
        let Some(token) = p.next() else { return Ok(Err(Unsupported)) };
        Ok(Ok(match token {
            Tok::Number(value) => value,
            Tok::Text(text) => V::Text(text),
            Tok::Expandable(source) => {
                let tokens = tokenize(&source)?;
                match tokens.as_slice() {
                    [token] => V::Text(self.expand_token(token)?),
                    _ => return Ok(Err(Unsupported)),
                }
            }
            Tok::Var(name) => tri!(self.variable(&name)),
            // Subexpressions this engine evaluates; statements inside stay
            // with the interpreter (the whole expression falls back).
            Tok::Sub(inner) => match self.eval_expression(&inner)? {
                Some(value) => value,
                None => return Ok(Err(Unsupported)),
            },
            Tok::ArraySub(inner) => match self.eval_expression(&inner)? {
                Some(value) => V::Arr(value.items()),
                None if inner.trim().is_empty() => V::Arr(Vec::new()),
                None => return Ok(Err(Unsupported)),
            },
            Tok::Sym("(") => {
                // A parenthesized expression, or a command or pipeline.
                let start = p.at;
                let mut depth = 1;
                while depth > 0 {
                    match p.next() {
                        Some(Tok::Sym("(")) => depth += 1,
                        Some(Tok::Sym(")")) => depth -= 1,
                        Some(_) => {}
                        None => return Ok(Err(Unsupported)),
                    }
                }
                let mut sub = Parser { tokens: p.tokens[start..p.at - 1].to_vec(), at: 0 };
                match self.parse_logical(&mut sub)? {
                    Ok(value) if sub.at == sub.tokens.len() => value,
                    _ => return Ok(Err(Unsupported)),
                }
            }
            Tok::HashOpen => tri!(self.hashtable(p)),
            Tok::Type(typ) => {
                if !p.eat_sym("::") {
                    return Ok(Err(Unsupported));
                }
                let Some(Tok::Ident(member)) = p.next() else { return Ok(Err(Unsupported)) };
                if matches!(p.peek(), Some(Tok::Sym("("))) {
                    let args = tri!(self.parse_call_args(p));
                    tri!(self.static_call(&typ, &member, args))
                } else {
                    tri!(self.static_property(&typ, &member))
                }
            }
            Tok::Block(source) => V::Text(source),
            _ => return Ok(Err(Unsupported)),
        }))
    }

    /// `@{ key = value; ... }` after its opener.
    fn hashtable(&mut self, p: &mut Parser) -> R<V> {
        let mut entries: Vec<(String, V)> = Vec::new();
        loop {
            while p.eat_sym(";") {}
            if p.eat_sym("}") {
                return Ok(Ok(V::Map(entries)));
            }
            let key = match p.next() {
                Some(Tok::Ident(name)) => name,
                Some(Tok::Text(text)) => text,
                Some(Tok::Number(value)) => value.text(),
                Some(Tok::Expandable(source)) => {
                    let tokens = tokenize(&source)?;
                    match tokens.as_slice() {
                        [token] => self.expand_token(token)?,
                        _ => return Ok(Err(Unsupported)),
                    }
                }
                _ => return Ok(Err(Unsupported)),
            };
            if !p.eat_sym("=") {
                return Ok(Err(Unsupported));
            }
            // A value runs to the next `;` or `}` at this level.
            let start = p.at;
            let mut depth = 0i32;
            while let Some(token) = p.tokens.get(p.at) {
                match token {
                    Tok::Sym("(") | Tok::Sym("[") | Tok::HashOpen => depth += 1,
                    Tok::Sym(")") | Tok::Sym("]") => depth -= 1,
                    Tok::Sym("}") if depth > 0 => depth -= 1,
                    Tok::Sym(";") | Tok::Sym("}") if depth == 0 => break,
                    _ => {}
                }
                p.at += 1;
            }
            let mut sub = Parser { tokens: p.tokens[start..p.at].to_vec(), at: 0 };
            let value = tri!(self.parse_logical(&mut sub));
            if sub.at != sub.tokens.len() {
                return Ok(Err(Unsupported));
            }
            match entries.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&key)) {
                Some(_) => return Err(format!("Duplicate keys '{key}' are not allowed in hash literals.")),
                None => entries.push((key, value)),
            }
        }
    }

    fn variable(&mut self, name: &str) -> R<V> {
        let lower = name.to_ascii_lowercase();
        Ok(Ok(match lower.as_str() {
            "true" => V::Bool(true),
            "false" => V::Bool(false),
            "null" => V::Null,
            _ => {
                if let Some(env) = lower.strip_prefix("env:") {
                    let _ = env;
                    return Ok(Ok(environment_get(self.environment, &name[4..]).map_or(V::Null, |v| V::Auto(v.to_string()))));
                }
                if name.contains(':') && !lower.starts_with("script:") && !lower.starts_with("global:") && !lower.starts_with("local:") {
                    return Ok(Err(Unsupported));
                }
                match self.lookup_value(name) {
                    Some(value) => V::from_value(&value),
                    None if lower == "home" || is_env_name(name) => V::Auto(self.lookup_scalar(name)),
                    None => V::Null,
                }
            }
        }))
    }

    fn index(&mut self, value: V, index: V) -> V {
        match (&value, &index) {
            (V::Map(entries), key) => {
                let key = key.text();
                entries.iter().find(|(k, _)| k.eq_ignore_ascii_case(&key)).map_or(V::Null, |(_, v)| v.clone())
            }
            (_, V::Arr(indices)) => V::Arr(indices.iter().map(|i| self.index(value.clone(), i.clone())).collect()),
            (V::Arr(items), i) => {
                let Some(V::Int(i)) = i.number() else { return V::Null };
                let position = if i < 0 { items.len() as i64 + i } else { i };
                items.get(position as usize).cloned().filter(|_| position >= 0).unwrap_or(V::Null)
            }
            (V::Text(s) | V::Auto(s), i) => {
                let chars: Vec<char> = s.chars().collect();
                let Some(V::Int(i)) = i.number() else { return V::Null };
                let position = if i < 0 { chars.len() as i64 + i } else { i };
                chars.get(position as usize).filter(|_| position >= 0).map_or(V::Null, |c| V::Text(c.to_string()))
            }
            _ => V::Null,
        }
    }

    fn property(&mut self, value: V, name: &str) -> R<V> {
        let lower = name.to_ascii_lowercase();
        Ok(Ok(match (&value, lower.as_str()) {
            (V::Arr(items), "count" | "length") => V::Int(items.len() as i64),
            (V::Map(entries), "count") => V::Int(entries.len() as i64),
            (V::Map(entries), "keys") => V::Arr(entries.iter().map(|(k, _)| V::Text(k.clone())).collect()),
            (V::Map(entries), "values") => V::Arr(entries.iter().map(|(_, v)| v.clone()).collect()),
            (V::Map(entries), _) => entries.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map_or(V::Null, |(_, v)| v.clone()),
            (V::Text(s) | V::Auto(s), "length") => V::Int(s.chars().count() as i64),
            (V::Null, "count") => V::Int(0),
            (V::Null, _) => V::Null,
            // Member enumeration: each element's member.
            (V::Arr(items), _) => {
                let mut values = Vec::new();
                for item in items.clone() {
                    values.push(tri!(self.property(item, name)));
                }
                V::Arr(values)
            }
            (_, "count") => V::Int(1),
            _ => return Ok(Err(Unsupported)),
        }))
    }

    fn method(&mut self, value: V, name: &str, args: Vec<V>) -> R<V> {
        let lower = name.to_ascii_lowercase();
        let arg = |i: usize| args.get(i).map(V::text).unwrap_or_default();
        let int_arg = |i: usize| args.get(i).and_then(V::float).map(|f| f as i64);
        if lower == "tostring" && args.is_empty() {
            return Ok(Ok(V::Text(value.text())));
        }
        if let V::Map(entries) = &value {
            return Ok(Ok(match lower.as_str() {
                "containskey" | "contains" => V::Bool(entries.iter().any(|(k, _)| k.eq_ignore_ascii_case(&arg(0)))),
                "containsvalue" => V::Bool(entries.iter().any(|(_, v)| equal(v, args.first().unwrap_or(&V::Null), false))),
                _ => return Ok(Err(Unsupported)),
            }));
        }
        if let V::Arr(items) = &value {
            return Ok(Ok(match lower.as_str() {
                "contains" => V::Bool(items.iter().any(|item| equal(item, args.first().unwrap_or(&V::Null), true))),
                "indexof" => V::Int(
                    items
                        .iter()
                        .position(|item| equal(item, args.first().unwrap_or(&V::Null), true))
                        .map_or(-1, |i| i as i64),
                ),
                _ => return Ok(Err(Unsupported)),
            }));
        }
        let text = value.text();
        let chars: Vec<char> = text.chars().collect();
        let substring = |start: i64, length: Option<i64>| -> Result<String, String> {
            let start = start.max(0) as usize;
            let end = length.map_or(chars.len(), |l| start + l.max(0) as usize);
            if start > chars.len() || end > chars.len() {
                return Err("Index and length must refer to a location within the string.".into());
            }
            Ok(chars[start..end].iter().collect())
        };
        let trim_set = |args: &[V]| -> Vec<char> { args.iter().flat_map(|a| a.text().chars().collect::<Vec<_>>()).collect() };
        Ok(Ok(match lower.as_str() {
            "toupper" | "toupperinvariant" => V::Text(text.to_uppercase()),
            "tolower" | "tolowerinvariant" => V::Text(text.to_lowercase()),
            "trim" if args.is_empty() => V::Text(text.trim().to_string()),
            "trimstart" if args.is_empty() => V::Text(text.trim_start().to_string()),
            "trimend" if args.is_empty() => V::Text(text.trim_end().to_string()),
            "trim" => V::Text(text.trim_matches(trim_set(&args).as_slice()).to_string()),
            "trimstart" => V::Text(text.trim_start_matches(trim_set(&args).as_slice()).to_string()),
            "trimend" => V::Text(text.trim_end_matches(trim_set(&args).as_slice()).to_string()),
            "contains" => V::Bool(text.contains(&arg(0))),
            "startswith" => V::Bool(text.starts_with(&arg(0))),
            "endswith" => V::Bool(text.ends_with(&arg(0))),
            "indexof" => V::Int(text.find(&arg(0)).map_or(-1, |b| text[..b].chars().count() as i64)),
            "lastindexof" => V::Int(text.rfind(&arg(0)).map_or(-1, |b| text[..b].chars().count() as i64)),
            "replace" => V::Text(text.replace(&arg(0), &arg(1))),
            "substring" => V::Text(substring(int_arg(0).unwrap_or(0), int_arg(1))?),
            "split" => {
                let separators: Vec<char> = trim_set(&args);
                V::Arr(
                    text.split(|c| separators.contains(&c))
                        .map(|part| V::Text(part.to_string()))
                        .collect(),
                )
            }
            "padleft" | "padright" => {
                let width = int_arg(0).unwrap_or(0).max(0) as usize;
                let fill = arg(1).chars().next().unwrap_or(' ');
                let pad: String = std::iter::repeat_n(fill, width.saturating_sub(chars.len())).collect();
                V::Text(if lower == "padleft" { pad + &text } else { text + &pad })
            }
            "insert" => {
                let at = int_arg(0).unwrap_or(0).max(0) as usize;
                V::Text(substring(0, Some(at as i64))? + &arg(1) + &substring(at as i64, None)?)
            }
            "remove" => {
                let start = int_arg(0).unwrap_or(0);
                let rest = match int_arg(1) {
                    Some(count) => substring(start + count, None)?,
                    None => String::new(),
                };
                V::Text(substring(0, Some(start))? + &rest)
            }
            "tochararray" => V::Arr(chars.iter().map(|c| V::Text(c.to_string())).collect()),
            "equals" => V::Bool(text == arg(0)),
            "tostring" if value.is_numeric() => V::Text(format_value(&value, &arg(0))),
            _ => return Ok(Err(Unsupported)),
        }))
    }

    fn static_call(&mut self, typ: &str, member: &str, args: Vec<V>) -> R<V> {
        let lower_type = typ.to_ascii_lowercase();
        let lower_type = lower_type.trim_start_matches("system.");
        let method = member.to_ascii_lowercase();
        let float = |i: usize| args.get(i).and_then(V::float);
        let numbers = |f: fn(f64, f64) -> f64| -> Option<V> {
            let (a, b) = (args.first()?, args.get(1)?);
            if let (Some(V::Int(x)), Some(V::Int(y))) = (a.number(), b.number()) {
                return Some(V::Int(f(x as f64, y as f64) as i64));
            }
            Some(V::Num(f(a.float()?, b.float()?)))
        };
        let result = match (lower_type, method.as_str()) {
            ("math", "max") => numbers(f64::max),
            ("math", "min") => numbers(f64::min),
            ("math", "pow") => Some(V::Num(float(0).unwrap_or(0.0).powf(float(1).unwrap_or(0.0)))),
            ("math", "abs") => args.first().and_then(V::number).map(|n| match n {
                V::Int(i) => V::Int(i.abs()),
                other => V::Num(other.float().unwrap_or(0.0).abs()),
            }),
            ("math", "sqrt") => float(0).map(|f| V::Num(f.sqrt())),
            ("math", "floor") => float(0).map(|f| V::Num(f.floor())),
            ("math", "ceiling") => float(0).map(|f| V::Num(f.ceil())),
            ("math", "truncate") => float(0).map(|f| V::Num(f.trunc())),
            ("math", "round") => float(0).map(|f| {
                let digits = float(1).unwrap_or(0.0) as i32;
                let scale = 10f64.powi(digits);
                // Banker's rounding, as Math.Round.
                let scaled = f * scale;
                let rounded = scaled.round();
                let even = if (scaled - scaled.trunc()).abs() == 0.5 && rounded % 2.0 != 0.0 { rounded - scaled.signum() } else { rounded };
                V::Num(even / scale)
            }),
            ("math", "log") => float(0).map(|f| V::Num(f.ln())),
            ("math", "log10") => float(0).map(|f| V::Num(f.log10())),
            ("math", "exp") => float(0).map(|f| V::Num(f.exp())),
            ("string", "isnullorempty") => Some(V::Bool(args.first().is_none_or(|v| v.text().is_empty()))),
            ("string", "isnullorwhitespace") => Some(V::Bool(args.first().is_none_or(|v| v.text().trim().is_empty()))),
            ("string", "join") => {
                let separator = args.first().map(V::text).unwrap_or_default();
                let rest: Vec<String> = args.iter().skip(1).flat_map(|v| v.clone().items()).map(|v| v.text()).collect();
                Some(V::Text(rest.join(&separator)))
            }
            ("string", "format") => {
                let template = args.first().map(V::text).unwrap_or_default();
                let rest: Vec<V> = match args.get(1..) {
                    Some([V::Arr(items)]) => items.clone(),
                    Some(rest) => rest.to_vec(),
                    None => Vec::new(),
                };
                Some(V::Text(format_operator(&template, &rest)?))
            }
            ("string", "concat") => Some(V::Text(args.iter().map(V::text).collect())),
            _ => None,
        };
        if let Some(value) = result {
            return Ok(Ok(value));
        }
        // Other types ([Environment], [Guid], ...) stay with the
        // interpreter's own static handling, chains included.
        Ok(Err(Unsupported))
    }

    fn static_property(&mut self, typ: &str, member: &str) -> R<V> {
        let lower_type = typ.to_ascii_lowercase();
        let lower_type = lower_type.trim_start_matches("system.");
        let value = match (lower_type, member.to_ascii_lowercase().as_str()) {
            ("math", "pi") => Some(V::Num(std::f64::consts::PI)),
            ("math", "e") => Some(V::Num(std::f64::consts::E)),
            ("int" | "int32", "maxvalue") => Some(V::Int(i32::MAX as i64)),
            ("int" | "int32", "minvalue") => Some(V::Int(i32::MIN as i64)),
            ("long" | "int64", "maxvalue") => Some(V::Int(i64::MAX)),
            ("long" | "int64", "minvalue") => Some(V::Int(i64::MIN)),
            ("string", "empty") => Some(V::Text(String::new())),
            _ => None,
        };
        if let Some(value) = value {
            return Ok(Ok(value));
        }
        Ok(Err(Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(source: &str) -> Option<String> {
        let mut fs = crate::winfs::WinFs::new();
        let mut session = Session::default();
        let mut out = Vec::new();
        let mut interpreter = Interpreter {
            fs: &mut fs,
            out: &mut out,
            depth: 0,
            vars: &mut session.vars,
            funcs: &mut session.funcs,
            types: &mut session.types,
            dir_stack: &mut session.dir_stack,
            environment: &mut session.environment,
            host: None,
        };
        interpreter.vars.insert("n".into(), Value::Str("2".into()));
        interpreter.eval_expression(source).unwrap().map(|v| match v.into_value() {
            Value::Arr(items) => items.iter().map(value_string).collect::<Vec<_>>().join(","),
            other => value_string(&other),
        })
    }

    #[test]
    fn arithmetic_follows_powershell() {
        assert_eq!(eval("1+1").as_deref(), Some("2"));
        assert_eq!(eval("2 * (3 + 4)").as_deref(), Some("14"));
        assert_eq!(eval("7 / 2").as_deref(), Some("3.5"));
        assert_eq!(eval("6 / 3").as_deref(), Some("2"));
        assert_eq!(eval("7 % 3").as_deref(), Some("1"));
        assert_eq!(eval("$n + 1").as_deref(), Some("3"), "a numeric variable adds");
        assert_eq!(eval("'1' + 1").as_deref(), Some("11"), "a string literal concatenates");
        assert_eq!(eval("'x' * 3").as_deref(), Some("xxx"));
        assert_eq!(eval("-3 + 1").as_deref(), Some("-2"));
        assert_eq!(eval("1kb").as_deref(), Some("1024"));
        assert_eq!(eval("0x10").as_deref(), Some("16"));
        assert_eq!(eval("1/3").as_deref(), Some("0.333333333333333"));
    }

    #[test]
    fn arrays_ranges_and_hashtables() {
        assert_eq!(eval("1,2,3").as_deref(), Some("1,2,3"));
        assert_eq!(eval("(1,2,3).Count").as_deref(), Some("3"));
        assert_eq!(eval("1..4").as_deref(), Some("1,2,3,4"));
        assert_eq!(eval("(1,2,3)[-1]").as_deref(), Some("3"));
        assert_eq!(eval("@(1,2) + 3").as_deref(), Some("1,2,3"));
        assert_eq!(eval("@{a=1; b='two'}.b").as_deref(), Some("two"));
        assert_eq!(eval("@{a=1}['A']").as_deref(), Some("1"));
        assert_eq!(eval("(1,5,9) -gt 3").as_deref(), Some("5,9"));
    }

    #[test]
    fn operators_strings_and_statics() {
        assert_eq!(eval("'a;b' -split ';'").as_deref(), Some("a,b"));
        assert_eq!(eval("(1,2) -join '-'").as_deref(), Some("1-2"));
        assert_eq!(eval("'Hello' -replace 'l','L'").as_deref(), Some("HeLLo"));
        assert_eq!(eval("'abc' -like 'A*'").as_deref(), Some("True"));
        assert_eq!(eval("'abc' -clike 'A*'").as_deref(), Some("False"));
        assert_eq!(eval("'Hello' -match 'h.l'").as_deref(), Some("True"));
        assert_eq!(eval("3 -in 1,2,3").as_deref(), Some("True"));
        assert_eq!(eval("'{0}-{1:N1}' -f 'x', 1234.5").as_deref(), Some("x-1,234.5"));
        assert_eq!(eval("[math]::Max(3, 9)").as_deref(), Some("9"));
        assert_eq!(eval("[int]'42' + 1").as_deref(), Some("43"));
        assert_eq!(eval("[int]2.5").as_deref(), Some("2"), "banker's rounding");
        assert_eq!(eval("'  hi '.Trim().ToUpper()").as_deref(), Some("HI"));
        assert_eq!(eval("'hello'.Substring(1, 3)").as_deref(), Some("ell"));
        assert_eq!(eval("-not $false").as_deref(), Some("True"));
        assert_eq!(eval("$null -eq $null").as_deref(), Some("True"));
        assert_eq!(eval("Get-Date"), None, "a command is not an expression");
    }
}
