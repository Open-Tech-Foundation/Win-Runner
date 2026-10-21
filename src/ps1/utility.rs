//! Utility cmdlets: `Get-Date`, `Get-Random`, `Out-String`,
//! `Format-Table`/`Format-List`, `Group-Object`, `ConvertTo-Json`/
//! `ConvertFrom-Json`, `Read-Host`, `Get-Process`, `Start-Process`, and
//! `Get-ItemPropertyValue`. Pipeline input arrives as text lines; objects
//! travel as JSON lines, as the interpreter outputs them.
use super::*;

/// The local time as (year, month, day, hour, minute, second, nanos,
/// weekday 0=Sunday, UTC offset seconds).
fn local_now() -> (i64, u32, u32, u32, u32, u32, u32, u32, i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs() as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&seconds, &mut tm) };
    (
        tm.tm_year as i64 + 1900,
        tm.tm_mon as u32 + 1,
        tm.tm_mday as u32,
        tm.tm_hour as u32,
        tm.tm_min as u32,
        tm.tm_sec as u32,
        now.subsec_nanos(),
        tm.tm_wday as u32,
        tm.tm_gmtoff,
    )
}

const MONTHS: [&str; 12] = [
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
    "December",
];
const DAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/// A .NET date format: standard (`d`, `D`, `t`, `T`, `g`, `G`, `f`, `F`,
/// `s`, `u`, `o`) or custom (`yyyy-MM-dd HH:mm:ss.fff tt zzz`), en-US.
fn format_date(format: &str) -> String {
    let (year, month, day, hour, minute, second, nanos, weekday, offset) = local_now();
    let custom = match format {
        "d" => "M/d/yyyy",
        "D" => "dddd, MMMM d, yyyy",
        "t" => "h:mm tt",
        "T" => "h:mm:ss tt",
        "g" => "M/d/yyyy h:mm tt",
        "G" => "M/d/yyyy h:mm:ss tt",
        "f" => "dddd, MMMM d, yyyy h:mm tt",
        "F" => "dddd, MMMM d, yyyy h:mm:ss tt",
        "s" => "yyyy-MM-ddTHH:mm:ss",
        "u" => "yyyy-MM-dd HH:mm:ssZ",
        "o" | "O" => "yyyy-MM-ddTHH:mm:ss.fffffffzzz",
        other => other,
    };
    let chars: Vec<char> = custom.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        let mut run = 1;
        while index + run < chars.len() && chars[index + run] == c {
            run += 1;
        }
        let hour12 = if hour % 12 == 0 { 12 } else { hour % 12 };
        let piece = match (c, run) {
            ('y', 1) => (year % 100).to_string(),
            ('y', 2) => format!("{:02}", year % 100),
            ('y', _) => format!("{year:04}"),
            ('M', 1) => month.to_string(),
            ('M', 2) => format!("{month:02}"),
            ('M', 3) => MONTHS[month as usize - 1][..3].to_string(),
            ('M', _) => MONTHS[month as usize - 1].to_string(),
            ('d', 1) => day.to_string(),
            ('d', 2) => format!("{day:02}"),
            ('d', 3) => DAYS[weekday as usize][..3].to_string(),
            ('d', _) => DAYS[weekday as usize].to_string(),
            ('H', 1) => hour.to_string(),
            ('H', _) => format!("{hour:02}"),
            ('h', 1) => hour12.to_string(),
            ('h', _) => format!("{hour12:02}"),
            ('m', 1) => minute.to_string(),
            ('m', _) => format!("{minute:02}"),
            ('s', 1) => second.to_string(),
            ('s', _) => format!("{second:02}"),
            ('f', n) => format!("{:09}", nanos)[..n.min(9)].to_string(),
            ('t', 1) => (if hour < 12 { "A" } else { "P" }).to_string(),
            ('t', _) => (if hour < 12 { "AM" } else { "PM" }).to_string(),
            ('z', n) => {
                let sign = if offset < 0 { '-' } else { '+' };
                let (h, m) = (offset.abs() / 3600, offset.abs() % 3600 / 60);
                match n {
                    1 => format!("{sign}{h}"),
                    2 => format!("{sign}{h:02}"),
                    _ => format!("{sign}{h:02}:{m:02}"),
                }
            }
            ('\\', _) => {
                let literal = chars.get(index + 1).copied().unwrap_or('\\');
                index += 2;
                out.push(literal);
                continue;
            }
            ('\'' | '"', _) => {
                let close = chars[index + 1..].iter().position(|d| *d == c).map_or(chars.len(), |p| index + 1 + p);
                out.extend(&chars[index + 1..close]);
                index = close + 1;
                continue;
            }
            (c, n) => std::iter::repeat_n(c, n).collect(),
        };
        out.push_str(&piece);
        index += run;
    }
    out
}

/// A uniformly random integer in `[low, high)`.
fn random_below(low: i64, high: i64) -> i64 {
    let mut bytes = [0u8; 8];
    unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), 8, 0) };
    let span = (high - low).max(1) as u64;
    low + (u64::from_le_bytes(bytes) % span) as i64
}

/// Pipeline lines as values: JSON object and array lines parsed, others
/// as text.
fn pipeline_values(pipe_in: Option<&str>) -> Vec<Value> {
    pipe_in
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                parse_json_keeping_case(trimmed).unwrap_or_else(|_| Value::Str(line.to_string()))
            } else {
                Value::Str(line.to_string())
            }
        })
        .collect()
}

/// A value as PowerShell's JSON: numbers and booleans bare (values read
/// as them), strings quoted, maps and arrays indented by `indent`.
fn render_pretty_json(value: &Value, indent: usize, depth: usize, compress: bool) -> String {
    let pad = |level: usize| if compress { String::new() } else { "  ".repeat(level) };
    let newline = if compress { "" } else { "\n" };
    let separator = if compress { ":" } else { ": " };
    match value {
        Value::Str(s) => {
            let numeric = !s.is_empty()
                && s.chars().all(|c| c.is_ascii_digit() || matches!(c, '-' | '.'))
                && s.parse::<f64>().is_ok()
                && !(s.starts_with('0') && s.len() > 1 && !s.starts_with("0."))
                && !s.starts_with("-0") || s == "0";
            if numeric {
                s.clone()
            } else if s == "True" || s == "False" {
                s.to_lowercase()
            } else {
                render_json_string(s)
            }
        }
        _ if depth == 0 => render_json_string(&value_string(value)),
        Value::Arr(items) => {
            if items.is_empty() {
                return "[]".into();
            }
            let parts: Vec<String> = items
                .iter()
                .map(|item| format!("{}{}", pad(indent + 1), render_pretty_json(item, indent + 1, depth - 1, compress)))
                .collect();
            format!("[{newline}{}{newline}{}]", parts.join(&format!(",{newline}")), pad(indent))
        }
        Value::Map(map) => {
            let mut keys: Vec<&String> = map.keys().filter(|k| !registry::is_hidden_member(k)).collect();
            keys.sort();
            if keys.is_empty() {
                return "{}".into();
            }
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}{}{separator}{}",
                        pad(indent + 1),
                        render_json_string(&display_key(map, k)),
                        render_pretty_json(&map[*k], indent + 1, depth - 1, compress)
                    )
                })
                .collect();
            format!("{{{newline}{}{newline}{}}}", parts.join(&format!(",{newline}")), pad(indent))
        }
    }
}

/// Lay rows out as PowerShell's table: headers, dashes, and padded columns
/// (the last column unpadded). A column has a fixed width where `fixed`
/// gives one (longer cells end in `…`), else its widest cell's.
fn table(headers: &[String], rows: &[Vec<String>], right_aligned: &[bool], fixed: &[Option<usize>]) -> Vec<String> {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    for (index, width) in fixed.iter().enumerate() {
        if let Some(width) = width {
            widths[index] = *width;
        }
    }
    let line = |cells: &[String]| -> String {
        let last = cells.len() - 1;
        let mut text = String::new();
        for (index, cell) in cells.iter().enumerate() {
            let truncated: String;
            let cell = if index != last && cell.chars().count() > widths[index] {
                truncated = cell.chars().take(widths[index].saturating_sub(1)).chain(std::iter::once('…')).collect();
                &truncated
            } else {
                cell
            };
            let pad = widths[index].saturating_sub(cell.chars().count());
            if right_aligned.get(index) == Some(&true) {
                text.push_str(&" ".repeat(pad));
                text.push_str(cell);
            } else if index == last {
                text.push_str(cell);
            } else {
                text.push_str(cell);
                text.push_str(&" ".repeat(pad));
            }
            if index != last {
                text.push(' ');
            }
        }
        text.trim_end().to_string()
    };
    let dashes: Vec<String> = headers.iter().map(|h| "-".repeat(h.chars().count())).collect();
    let mut out = vec![String::new(), line(headers), line(&dashes)];
    out.extend(rows.iter().map(|row| line(row)));
    out.push(String::new());
    out
}

impl Interpreter<'_> {
    pub(super) fn cmd_utility(&mut self, cmd: &str, args: &[String], pipe_in: Option<&str>) -> Result<(), String> {
        match cmd {
            "get-date" => {
                let (named, _) = parse_params(args, &["format", "uformat"])?;
                let text = match named.get("format") {
                    Some(format) => format_date(format),
                    None if named.contains_key("uformat") => return Err("Get-Date: -UFormat is not supported".into()),
                    None => format_date("F"),
                };
                self.emit(&text);
            }
            "get-random" => {
                let (named, pos) = parse_params(args, &["minimum", "maximum", "count", "inputobject", "setseed"])?;
                let mut pool: Vec<String> = named
                    .get("inputobject")
                    .map(|items| items.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();
                if pool.is_empty() {
                    pool = pipe_in.unwrap_or_default().lines().map(str::to_string).collect();
                }
                let number = |name: &str| -> Result<Option<i64>, String> {
                    named
                        .get(name)
                        .map(|v| v.trim().parse::<i64>().map_err(|_| format!("Get-Random: -{name} must be a number")))
                        .transpose()
                };
                if !pool.is_empty() {
                    let count = number("count")?.unwrap_or(1).max(0) as usize;
                    for _ in 0..count.min(pool.len()) {
                        let pick = random_below(0, pool.len() as i64) as usize;
                        let item = pool.remove(pick);
                        self.emit(&item);
                    }
                    return Ok(());
                }
                let maximum = match number("maximum")? {
                    Some(maximum) => maximum,
                    None => pos.first().and_then(|v| v.parse().ok()).unwrap_or(i32::MAX as i64),
                };
                let minimum = number("minimum")?.unwrap_or(0);
                if minimum >= maximum {
                    return Err(format!(
                        "Get-Random: Minimum ({minimum}) cannot be greater than or equal to Maximum ({maximum})."
                    ));
                }
                self.emit(&random_below(minimum, maximum).to_string());
            }
            "out-string" => {
                let (named, _) = parse_params(args, &["stream", "width"])?;
                let text = pipe_in.unwrap_or_default();
                if named.contains_key("stream") {
                    for line in text.lines() {
                        self.emit(line);
                    }
                } else {
                    // One string ending in a newline, which output then
                    // ends with a line break of its own: a blank line.
                    self.out.extend_from_slice(text.as_bytes());
                    if !text.ends_with('\n') {
                        self.out.push(b'\n');
                    }
                    self.out.push(b'\n');
                }
            }
            "format-list" | "format-table" => {
                let (named, pos) = parse_params(args, &["property", "autosize", "wrap", "hidetableheaders"])?;
                let wanted: Option<Vec<String>> = named
                    .get("property")
                    .or_else(|| pos.first())
                    .map(|list| list.split(',').map(|s| s.trim().to_string()).collect());
                let values = pipeline_values(pipe_in);
                let objects: Vec<&HashMap<String, Value>> =
                    values.iter().filter_map(|v| if let Value::Map(m) = v { Some(m) } else { None }).collect();
                if objects.is_empty() {
                    // Plain values print as they are.
                    for value in &values {
                        self.emit_value(value);
                    }
                    return Ok(());
                }
                let mut columns: Vec<String> = match &wanted {
                    Some(names) => names.clone(),
                    None => {
                        let mut names: Vec<String> = Vec::new();
                        for object in &objects {
                            let mut keys: Vec<&String> = object.keys().filter(|k| !registry::is_hidden_member(k)).collect();
                            keys.sort();
                            for key in keys {
                                if !names.iter().any(|n| n.eq_ignore_ascii_case(key)) {
                                    names.push(key.clone());
                                }
                            }
                        }
                        names
                    }
                };
                columns.retain(|c| !c.is_empty());
                let cell = |object: &HashMap<String, Value>, column: &str| {
                    object
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(column))
                        .map(|(_, v)| match v {
                            Value::Arr(items) => format!("{{{}}}", items.iter().map(value_string).collect::<Vec<_>>().join(", ")),
                            other => value_string(other),
                        })
                        .unwrap_or_default()
                };
                if cmd == "format-list" {
                    let width = columns.iter().map(|c| c.chars().count()).max().unwrap_or(0);
                    self.emit("");
                    for object in &objects {
                        for column in &columns {
                            let line = format!("{column:<width$} : {}", cell(object, column));
                            self.emit(&line);
                        }
                        self.emit("");
                    }
                } else {
                    let rows: Vec<Vec<String>> =
                        objects.iter().map(|object| columns.iter().map(|c| cell(object, c)).collect()).collect();
                    // Number columns align right, headers included.
                    let numeric: Vec<bool> = (0..columns.len())
                        .map(|index| {
                            let mut cells = rows.iter().map(|row| row[index].as_str()).filter(|c| !c.is_empty()).peekable();
                            cells.peek().is_some() && cells.all(|c| c.parse::<f64>().is_ok())
                        })
                        .collect();
                    for line in table(&columns, &rows, &numeric, &[]) {
                        self.emit(&line);
                    }
                }
            }
            "group-object" => {
                let (named, pos) = parse_params(args, &["property", "noelement", "ashashtable", "casesensitive"])?;
                let property = named.get("property").or_else(|| pos.first()).cloned();
                let case_sensitive = named.contains_key("casesensitive");
                let mut groups: Vec<(String, Vec<String>)> = Vec::new();
                for value in pipeline_values(pipe_in) {
                    let key = match (&property, &value) {
                        (Some(name), Value::Map(map)) => map
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case(name))
                            .map(|(_, v)| value_string(v))
                            .unwrap_or_default(),
                        _ => value_string(&value),
                    };
                    let item = value_string(&value);
                    match groups.iter_mut().find(|(k, _)| if case_sensitive { *k == key } else { k.eq_ignore_ascii_case(&key) }) {
                        Some((_, items)) => items.push(item),
                        None => groups.push((key, vec![item])),
                    }
                }
                let rows: Vec<Vec<String>> = groups
                    .iter()
                    .map(|(name, items)| vec![items.len().to_string(), name.clone(), format!("{{{}}}", items.join(", "))])
                    .collect();
                let headers = ["Count".to_string(), "Name".to_string(), "Group".to_string()];
                let (headers, rows) = if named.contains_key("noelement") {
                    (headers[..2].to_vec(), rows.into_iter().map(|r| r[..2].to_vec()).collect())
                } else {
                    (headers.to_vec(), rows)
                };
                // GroupInfo's table view: Count 5 wide, Name 25.
                for line in table(&headers, &rows, &[true], &[Some(5), Some(25)]) {
                    self.emit(&line);
                }
            }
            "convertto-json" => {
                let (named, pos) = parse_params(args, &["depth", "compress", "inputobject", "asarray"])?;
                let depth: usize = named.get("depth").and_then(|d| d.parse().ok()).unwrap_or(2);
                let compress = named.contains_key("compress");
                let mut values = pipeline_values(pipe_in);
                if let Some(input) = named.get("inputobject").or_else(|| pos.first()) {
                    values = pipeline_values(Some(input));
                }
                let value = match values.len() {
                    0 => return Ok(()),
                    1 if !named.contains_key("asarray") => values.remove(0),
                    _ => Value::Arr(values),
                };
                let text = render_pretty_json(&value, 0, depth + 1, compress);
                for line in text.lines() {
                    self.emit(line);
                }
            }
            "convertfrom-json" => {
                let (named, pos) = parse_params(args, &["inputobject", "ashashtable", "depth"])?;
                let text = named.get("inputobject").or_else(|| pos.first()).cloned().unwrap_or_else(|| pipe_in.unwrap_or_default().to_string());
                let value = parse_json_keeping_case(text.trim()).map_err(|e| format!("ConvertFrom-Json: {e}"))?;
                // Objects travel on as JSON lines; arrays as one per element.
                match value {
                    Value::Arr(items) => {
                        for item in &items {
                            match item {
                                Value::Str(s) => self.emit(s),
                                other => self.emit(&render_json(other)),
                            }
                        }
                    }
                    Value::Map(_) => self.emit(&render_json(&value)),
                    Value::Str(s) => self.emit(&s),
                }
            }
            "read-host" => {
                let (named, pos) = parse_params(args, &["prompt", "assecurestring", "maskinput"])?;
                if named.contains_key("assecurestring") {
                    return Err("Read-Host: -AsSecureString is not supported".into());
                }
                if let Some(prompt) = named.get("prompt").or_else(|| pos.first()) {
                    eprint!("{prompt}: ");
                }
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).map_err(|e| format!("Read-Host: {e}"))?;
                self.emit(line.trim_end_matches(['\r', '\n']));
            }
            "get-process" => {
                let (named, pos) = parse_params(args, &["name", "id"])?;
                let name = named.get("name").or_else(|| pos.first()).cloned();
                let id: Option<u32> = named.get("id").and_then(|v| v.parse().ok());
                let processes = guest_processes();
                let selected: Vec<_> = processes
                    .into_iter()
                    .filter(|(pid, image)| {
                        id.is_none_or(|id| id == *pid)
                            && name.as_deref().is_none_or(|n| essentials::wildcard(n, image.trim_end_matches(".exe")))
                    })
                    .collect();
                if selected.is_empty() {
                    if let Some(name) = name {
                        return Err(format!("Get-Process: Cannot find a process with the name \"{name}\"."));
                    }
                    if let Some(id) = id {
                        return Err(format!("Get-Process: Cannot find a process with the process identifier {id}."));
                    }
                }
                let headers = vec!["Id".to_string(), "ProcessName".to_string()];
                let rows: Vec<Vec<String>> = selected
                    .iter()
                    .map(|(pid, image)| {
                        let base = image.strip_suffix(".exe").or_else(|| image.strip_suffix(".EXE")).unwrap_or(image);
                        vec![pid.to_string(), base.to_string()]
                    })
                    .collect();
                for line in table(&headers, &rows, &[true], &[]) {
                    self.emit(&line);
                }
            }
            "start-process" => {
                self.start_process(args)?;
            }
            "get-itempropertyvalue" | "gpv" => {
                let (named, pos) = parse_params(args, &["path", "literalpath", "name"])?;
                let path = named.get("literalpath").or_else(|| named.get("path")).or_else(|| pos.first()).cloned().ok_or("Get-ItemPropertyValue: missing -Path")?;
                let name = named.get("name").or_else(|| pos.get(1)).cloned().ok_or("Get-ItemPropertyValue: missing -Name")?;
                let forwarded = vec![path, "-Name".to_string(), name.clone()];
                let Value::Map(map) = self.get_item_property_args(&forwarded)? else {
                    return Err("Get-ItemPropertyValue: not a registry key".into());
                };
                let value = map
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(&name))
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| format!("Get-ItemPropertyValue: Property {name} does not exist."))?;
                self.emit_value(&value);
            }
            _ => return Err(format!("unknown command: {cmd}")),
        }
        Ok(())
    }
}

impl Interpreter<'_> {
    /// `Start-Process`: run the program and return it as the object
    /// `-PassThru` gives (`ExitCode`, `HasExited`, `ProcessName`, `Id`).
    /// The program runs to completion here: winrun has no detached guest
    /// processes yet, so `-Wait` is implied.
    pub(super) fn start_process(&mut self, args: &[String]) -> Result<Value, String> {
        let (named, pos) = parse_params(
            args,
            &["filepath", "argumentlist", "args", "wait", "nonewwindow", "passthru", "workingdirectory", "windowstyle"],
        )?;
        let file = named
            .get("filepath")
            .or_else(|| pos.first())
            .cloned()
            .ok_or("Start-Process: missing -FilePath")?;
        let arguments: Vec<String> = named
            .get("argumentlist")
            .or_else(|| named.get("args"))
            .or_else(|| pos.get(1))
            .map(|list| {
                crate::ps1::native_arguments(list)
                    .into_iter()
                    .flat_map(|item| split_top_commas(&item).into_iter().map(|a| a.trim().trim_matches(['"', '\'']).to_string()).collect::<Vec<_>>())
                    .collect()
            })
            .unwrap_or_default();
        // A single argument string is a command line, split on spaces.
        let arguments = if arguments.len() == 1 && arguments[0].contains(' ') {
            arguments[0].split_whitespace().map(str::to_string).collect()
        } else {
            arguments
        };
        let path = self
            .resolve_program(&file)
            .ok_or_else(|| format!("Start-Process: This command cannot be run because \"{file}\" was not found."))?;
        self.run_program(&path, &arguments)?;
        let code = match self.vars.get("lastexitcode") {
            Some(Value::Str(code)) => code.clone(),
            _ => "0".to_string(),
        };
        let name = path.rsplit(['\\', '/']).next().unwrap_or(&path);
        let name = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
        let mut process = HashMap::new();
        process.insert("exitcode".to_string(), Value::Str(code));
        process.insert("hasexited".to_string(), Value::Str("True".to_string()));
        process.insert("processname".to_string(), Value::Str(name.to_string()));
        Ok(Value::Map(process))
    }
}

/// This session's guest processes (PID, image name).
fn guest_processes() -> Vec<(u32, String)> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        crate::native::process_table::list()
            .into_iter()
            .map(|process| (process.pid, process.image_name().to_string()))
            .collect()
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_format_like_dotnet() {
        let year = format_date("yyyy");
        assert_eq!(year.len(), 4);
        assert!(format_date("yyyy-MM-dd").starts_with(&year));
        assert!(format_date("s").contains('T'));
        assert_eq!(format_date("'year' yyyy"), format!("year {year}"));
    }

    #[test]
    fn tables_pad_columns_and_align_counts() {
        let rows = vec![vec!["2".to_string(), "b".to_string()], vec!["10".to_string(), "a".to_string()]];
        let lines = table(&["Count".into(), "Name".into()], &rows, &[true], &[]);
        assert_eq!(lines, vec!["", "Count Name", "----- ----", "    2 b", "   10 a", ""]);
        let rows = vec![vec!["1".to_string(), "abcdef".to_string(), "x".to_string()]];
        let lines = table(&["N".into(), "Name".into(), "G".into()], &rows, &[true], &[Some(3), Some(4)]);
        assert_eq!(lines[1], "  N Name G");
        assert_eq!(lines[3], "  1 abc… x", "a fixed column truncates with an ellipsis");
    }

    #[test]
    fn json_renders_numbers_bare_and_nests() {
        let value = parse_json(r#"{"b":["x","2"],"a":"1"}"#).unwrap();
        assert_eq!(render_pretty_json(&value, 0, 3, true), r#"{"a":1,"b":["x",2]}"#);
        assert_eq!(render_pretty_json(&value, 0, 3, false), "{\n  \"a\": 1,\n  \"b\": [\n    \"x\",\n    2\n  ]\n}");
        assert_eq!(render_pretty_json(&Value::Str("007".into()), 0, 1, true), "\"007\"");
    }
}
