//! Everyday commands operating on the guest filesystem and text pipeline.
use super::*;

const ALIASES: &[(&str, &str)] = &[
    ("ren", "rename-item"),
    ("rni", "rename-item"),
    ("clc", "clear-content"),
    ("rvpa", "resolve-path"),
    ("gcm", "get-command"),
    ("gal", "get-alias"),
    ("sls", "select-string"),
    ("sort", "sort-object"),
    ("gu", "get-unique"),
    ("measure", "measure-object"),
    ("tee", "tee-object"),
    ("cls", "clear-host"),
    ("clear", "clear-host"),
    ("ni", "new-item"),
    ("sc", "set-content"),
    ("ac", "add-content"),
    ("gc", "get-content"),
    ("type", "get-content"),
    ("cat", "get-content"),
    ("gi", "get-item"),
    ("cpi", "copy-item"),
    ("cp", "copy-item"),
    ("copy", "copy-item"),
    ("ci", "copy-item"),
    ("mv", "move-item"),
    ("move", "move-item"),
    ("mi", "move-item"),
    ("dir", "get-childitem"),
    ("ls", "get-childitem"),
    ("gci", "get-childitem"),
    ("rm", "remove-item"),
    ("del", "remove-item"),
    ("ri", "remove-item"),
    ("erase", "remove-item"),
    ("pwd", "get-location"),
    ("gl", "get-location"),
    ("cd", "set-location"),
    ("chdir", "set-location"),
    ("sl", "set-location"),
    ("pushd", "push-location"),
    ("pushl", "push-location"),
    ("popd", "pop-location"),
    ("popl", "pop-location"),
    ("sleep", "start-sleep"),
    ("echo", "write-output"),
    ("write", "write-output"),
    ("irm", "invoke-restmethod"),
    ("iwr", "invoke-webrequest"),
    ("wget", "invoke-webrequest"),
    ("iex", "invoke-expression"),
    ("%", "foreach-object"),
    ("where", "where-object"),
    ("?", "where-object"),
    ("select", "select-object"),
];

pub(super) fn canonical_command(cmd: &str) -> &str {
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == cmd)
        .map_or(cmd, |(_, name)| *name)
}

pub(super) fn validate_utf8_encoding(named: &HashMap<String, String>) -> Result<(), String> {
    if named
        .get("encoding")
        .is_some_and(|encoding| !["utf8", "utf8nobom"].contains(&encoding.to_lowercase().as_str()))
    {
        return Err("supported encodings are utf8 and utf8NoBOM".into());
    }
    Ok(())
}

pub(super) fn wildcard(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let v: Vec<char> = value.to_lowercase().chars().collect();
    let mut row = vec![false; v.len() + 1];
    row[0] = true;
    for c in p {
        let mut next = vec![false; v.len() + 1];
        if c == '*' {
            next[0] = row[0];
        }
        for i in 1..=v.len() {
            next[i] = if c == '*' {
                row[i] || next[i - 1]
            } else {
                row[i - 1] && (c == '?' || c == v[i - 1])
            };
        }
        row = next;
    }
    row[v.len()]
}

pub(super) fn path_arg(
    named: &HashMap<String, String>,
    pos: &[String],
    cmd: &str,
) -> Result<String, String> {
    if named.contains_key("path") && named.contains_key("literalpath") {
        return Err(format!("{cmd}: -Path and -LiteralPath cannot be combined"));
    }
    named
        .get("literalpath")
        .or_else(|| named.get("path"))
        .or_else(|| pos.first())
        .cloned()
        .ok_or_else(|| format!("{cmd}: missing -Path"))
}

impl Interpreter<'_> {
    pub(super) fn cmd_rename_item(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(
            args,
            &[
                "path",
                "literalpath",
                "newname",
                "force",
                "passthru",
                "whatif",
            ],
        )?;
        let src = path_arg(&named, &pos, "Rename-Item")?;
        let positional_count =
            usize::from(!named.contains_key("path") && !named.contains_key("literalpath"))
                + usize::from(!named.contains_key("newname"));
        if pos.len() > positional_count {
            return Err("Rename-Item: unexpected positional argument".into());
        }
        let name = named
            .get("newname")
            .or_else(|| {
                pos.get(usize::from(
                    !named.contains_key("path") && !named.contains_key("literalpath"),
                ))
            })
            .ok_or("Rename-Item: missing -NewName")?;
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains(['\\', '/', ':', '*', '?', '<', '>', '"', '|'])
            || name.chars().any(char::is_control)
        {
            return Err(
                "Rename-Item: -NewName must be a single filename; use Move-Item to move an item"
                    .into(),
            );
        }
        let source = self
            .fs
            .normalize(&src)
            .map_err(|e| format!("Rename-Item: {e}"))?;
        if source.parts.is_empty() || !self.fs.exists(&src) {
            return Err(format!("Rename-Item: source not found or is a root: {src}"));
        }
        let parent = parent_of(&source.display()).unwrap();
        let target = format!("{}\\{name}", parent.trim_end_matches('\\'));
        if self.fs.exists(&target) && self.fs.normalize(&target).unwrap().key() != source.key() {
            return Err(format!("Rename-Item: destination exists: {target}"));
        }
        if named.contains_key("whatif") {
            self.emit(&format!("What if: Rename {src} to {target}"));
            return Ok(());
        }
        self.fs
            .move_path(&src, &target)
            .map_err(|e| format!("Rename-Item: {e}"))?;
        if named.contains_key("passthru") {
            self.emit(&target);
        }
        Ok(())
    }

    pub(super) fn cmd_clear_content(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path", "literalpath", "force", "whatif"])?;
        let path = path_arg(&named, &pos, "Clear-Content")?;
        if !self.fs.is_file(&path) {
            return Err(format!("Clear-Content: not a file: {path}"));
        }
        if named.contains_key("whatif") {
            self.emit(&format!("What if: Clear {path}"));
            return Ok(());
        }
        self.fs
            .write_file(&path, Vec::new())
            .map_err(|e| format!("Clear-Content: {e}"))
    }

    pub(super) fn cmd_resolve_path(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["path", "literalpath", "relative"])?;
        let path = path_arg(&named, &pos, "Resolve-Path")?;
        if !self.fs.exists(&path) {
            return Err(format!("Resolve-Path: path not found: {path}"));
        }
        let p = self
            .fs
            .normalize(&path)
            .map_err(|e| format!("Resolve-Path: {e}"))?;
        let display = p.display();
        if named.contains_key("relative") {
            let cwd = self.fs.normalize(&self.fs.cwd()).unwrap();
            if p.drive != cwd.drive {
                self.emit(&display);
                return Ok(());
            }
            let shared = p
                .parts
                .iter()
                .zip(&cwd.parts)
                .take_while(|(a, b)| a.eq_ignore_ascii_case(b))
                .count();
            let mut parts = vec!["..".to_string(); cwd.parts.len() - shared];
            parts.extend_from_slice(&p.parts[shared..]);
            self.emit(&if parts.first().is_some_and(|p| p == "..") {
                parts.join("\\")
            } else {
                format!(".\\{}", parts.join("\\"))
            });
        } else {
            self.emit(&display);
        }
        Ok(())
    }

    pub(super) fn cmd_split_path(&mut self, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(
            args,
            &[
                "path",
                "literalpath",
                "parent",
                "leaf",
                "leafbase",
                "extension",
                "qualifier",
                "noqualifier",
                "isabsolute",
            ],
        )?;
        let path = path_arg(&named, &pos, "Split-Path")?.replace('/', "\\");
        let modes = [
            "parent",
            "leaf",
            "leafbase",
            "extension",
            "qualifier",
            "noqualifier",
            "isabsolute",
        ];
        let selected: Vec<_> = modes.iter().filter(|m| named.contains_key(**m)).collect();
        if selected.len() > 1 {
            return Err("Split-Path: choose one output mode".into());
        }
        let mode = selected.first().copied().copied().unwrap_or("parent");
        let leaf = path
            .trim_end_matches('\\')
            .rsplit('\\')
            .next()
            .unwrap_or("");
        let drive = path.as_bytes().get(1) == Some(&b':');
        let output = match mode {
            "leaf" => leaf.to_string(),
            "leafbase" => leaf
                .rsplit_once('.')
                .map_or(leaf, |(base, _)| base)
                .to_string(),
            "extension" => leaf
                .rsplit_once('.')
                .map_or(String::new(), |(_, ext)| format!(".{ext}")),
            "qualifier" => {
                if drive {
                    path[..2].into()
                } else {
                    return Err("Split-Path: path has no qualifier".into());
                }
            }
            "noqualifier" => {
                if drive {
                    path[2..].into()
                } else {
                    path.clone()
                }
            }
            "isabsolute" => bool_string(drive || path.starts_with("\\\\")),
            _ => parent_of(&path).unwrap_or_default(),
        };
        self.emit(&output);
        Ok(())
    }

    pub(super) fn cmd_discovery(&mut self, cmd: &str, args: &[String]) -> Result<(), String> {
        let (named, pos) = parse_params(args, &["name"])?;
        let pattern = named
            .get("name")
            .or_else(|| pos.first())
            .map(String::as_str)
            .unwrap_or("*");
        let mut found = Vec::new();
        if cmd == "get-alias" {
            for (alias, name) in ALIASES {
                if wildcard(pattern, alias) {
                    found.push(format!("{alias} -> {name}"));
                }
            }
        } else {
            for name in COMMAND_NAMES {
                if wildcard(pattern, name) {
                    found.push((*name).to_string());
                }
            }
            for name in self.funcs.keys() {
                if wildcard(pattern, name) {
                    found.push(name.clone());
                }
            }
            if cmd == "get-command" {
                let directories = environment_get(self.environment, "PATH")
                    .unwrap_or("")
                    .split(';')
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                let extensions = environment_get(self.environment, "PATHEXT")
                    .unwrap_or(".COM;.EXE;.BAT;.CMD")
                    .split(';')
                    .map(str::to_lowercase)
                    .chain(std::iter::once(".ps1".into()))
                    .collect::<Vec<_>>();
                for dir in directories {
                    if let Ok(names) = self.fs.list_dir(&dir) {
                        for name in names {
                            let full = format!("{}\\{name}", dir.trim_end_matches('\\'));
                            if self.fs.is_file(&full)
                                && extensions
                                    .iter()
                                    .any(|ext| name.to_lowercase().ends_with(ext))
                                && (wildcard(pattern, &name)
                                    || name
                                        .rsplit_once('.')
                                        .is_some_and(|(stem, _)| wildcard(pattern, stem)))
                            {
                                found.push(full);
                            }
                        }
                    }
                }
            }
        }
        found.sort_by_key(|s| s.to_lowercase());
        found.dedup();
        if found.is_empty() {
            return Err(format!("{cmd}: no matching command: {pattern}"));
        }
        if cmd == "get-help" {
            self.emit("Win-Runner PowerShell subset: guest filesystem commands and text pipelines. Get-Command lists implemented commands; unsupported parameters report errors.");
        }
        for name in found {
            if cmd == "get-help" {
                let syntax = match canonical_command(&name) {
                    "rename-item" => "[-Path|-LiteralPath] <path> [-NewName] <name> [-Force] [-PassThru] [-WhatIf]",
                    "clear-content" => "[-Path|-LiteralPath] <file> [-WhatIf]",
                    "get-content" => "[-Path|-LiteralPath] <file> [-Raw|-TotalCount <n>|-Tail <n>]",
                    "get-childitem" => "[path] [-Recurse] [-File|-Directory] [-Filter <pattern>]",
                    "resolve-path" => "[-Path|-LiteralPath] <path> [-Relative]",
                    "split-path" => "<path> [-Parent|-Leaf|-LeafBase|-Extension|-Qualifier|-NoQualifier|-IsAbsolute]",
                    "out-file" | "tee-object" => "[-FilePath] <file> [-InputObject <text>] [-Append] [-Encoding utf8] (text pipeline input)",
                    "select-string" => "[-Pattern] <pattern> [-Path <file>] [-SimpleMatch] [-Quiet] [-List] [-NotMatch] [-Raw]",
                    "sort-object" => "[-Descending] [-Unique] [-CaseSensitive] (text pipeline input)",
                    "get-unique" => "[-CaseInsensitive] (adjacent text pipeline items)",
                    "measure-object" => "[-Line] [-Word] [-Character] (text pipeline input)",
                    "get-command" | "get-alias" | "get-help" => "[name or wildcard]",
                    _ => "(implemented command; advanced PowerShell object/provider features are not supported)",
                };
                self.emit(&format!("{name} {syntax}"));
            } else {
                self.emit(&name);
            }
        }
        Ok(())
    }

    pub(super) fn cmd_out_file(
        &mut self,
        args: &[String],
        input: Option<&str>,
        tee: bool,
    ) -> Result<(), String> {
        let (named, pos) = parse_params(
            args,
            &[
                "filepath",
                "literalpath",
                "inputobject",
                "append",
                "noclobber",
                "nonewline",
                "encoding",
                "force",
            ],
        )?;
        let path = named
            .get("literalpath")
            .or_else(|| named.get("filepath"))
            .or_else(|| pos.first())
            .ok_or("Out-File: missing -FilePath")?;
        if let Some(encoding) = named.get("encoding") {
            if !["utf8", "utf8nobom"].contains(&encoding.to_lowercase().as_str()) {
                return Err("Out-File: supported encodings are utf8 and utf8NoBOM".into());
            }
        }
        if named.contains_key("noclobber") && !named.contains_key("append") && self.fs.exists(path)
        {
            return Err(format!("Out-File: already exists: {path}"));
        }
        let text = named
            .get("inputobject")
            .map(String::as_str)
            .or(input)
            .unwrap_or("");
        let mut bytes = text.as_bytes().to_vec();
        if named.contains_key("nonewline") {
            bytes = text.lines().collect::<String>().into_bytes();
        } else if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        if named.contains_key("append") {
            self.fs.append_file(path, &bytes)
        } else {
            self.fs.write_file(path, bytes)
        }
        .map_err(|e| format!("Out-File: {e}"))?;
        if tee {
            self.out.extend_from_slice(text.as_bytes());
            if !text.is_empty() && !text.ends_with('\n') {
                self.out.push(b'\n');
            }
        }
        Ok(())
    }

    pub(super) fn cmd_select_string(
        &mut self,
        args: &[String],
        input: Option<&str>,
    ) -> Result<(), String> {
        let (named, pos) = parse_params(
            args,
            &[
                "pattern",
                "path",
                "literalpath",
                "inputobject",
                "simplematch",
                "quiet",
                "list",
                "notmatch",
                "raw",
            ],
        )?;
        let pattern = named
            .get("pattern")
            .or_else(|| pos.first())
            .ok_or("Select-String: missing -Pattern")?;
        // Validate even when the source contains no lines.
        if !named.contains_key("simplematch") {
            regex_match(pattern, "")?;
        }
        let path = named
            .get("literalpath")
            .or_else(|| named.get("path"))
            .or_else(|| pos.get(usize::from(!named.contains_key("pattern"))));
        let data = if let Some(path) = path {
            String::from_utf8_lossy(
                &self
                    .fs
                    .read_file(path)
                    .map_err(|e| format!("Select-String: {e}"))?,
            )
            .into_owned()
        } else {
            named
                .get("inputobject")
                .map(String::as_str)
                .or(input)
                .unwrap_or("")
                .to_string()
        };
        let mut any = false;
        for (index, line) in data.lines().enumerate() {
            let matched = if named.contains_key("simplematch") {
                line.to_lowercase().contains(&pattern.to_lowercase())
            } else {
                regex_match(pattern, line)?
            };
            if matched == !named.contains_key("notmatch") {
                any = true;
                if !named.contains_key("quiet") {
                    if let Some(path) = path.filter(|_| !named.contains_key("raw")) {
                        self.emit(&format!("{path}:{}:{line}", index + 1));
                    } else {
                        self.emit(line);
                    }
                }
                if named.contains_key("list") || named.contains_key("quiet") {
                    break;
                }
            }
        }
        if named.contains_key("quiet") {
            self.emit(&bool_string(any));
        }
        Ok(())
    }

    pub(super) fn cmd_text_pipeline(
        &mut self,
        cmd: &str,
        args: &[String],
        input: Option<&str>,
    ) -> Result<(), String> {
        let known: &[&str] = match cmd {
            "sort-object" => &["descending", "unique", "casesensitive"],
            "get-unique" => &["caseinsensitive"],
            _ => &["line", "word", "character"],
        };
        let (named, pos) = parse_params(args, known)?;
        if !pos.is_empty() {
            return Err(format!(
                "{cmd}: use pipeline input; object properties are unsupported"
            ));
        }
        let data = input.unwrap_or("");
        let mut lines: Vec<&str> = data.lines().collect();
        if cmd == "measure-object" {
            self.emit(&format!("Count: {}", lines.len()));
            if named.contains_key("line") {
                self.emit(&format!("Lines: {}", lines.len()));
            }
            if named.contains_key("word") {
                self.emit(&format!("Words: {}", data.split_whitespace().count()));
            }
            if named.contains_key("character") {
                self.emit(&format!(
                    "Characters: {}",
                    lines.iter().map(|line| line.chars().count()).sum::<usize>()
                ));
            }
        } else {
            let ignore_case = cmd == "sort-object" && !named.contains_key("casesensitive")
                || named.contains_key("caseinsensitive");
            if cmd == "sort-object" {
                if ignore_case {
                    lines.sort_by_key(|line| line.to_lowercase());
                } else {
                    lines.sort();
                }
                if named.contains_key("descending") {
                    lines.reverse();
                }
            }
            if cmd == "get-unique" || named.contains_key("unique") {
                lines.dedup_by(|a, b| {
                    if ignore_case {
                        a.to_lowercase() == b.to_lowercase()
                    } else {
                        a == b
                    }
                });
            }
            for line in lines {
                self.emit(line);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execute(fs: &mut WinFs, script: &str) -> Result<String, String> {
        let mut output = Vec::new();
        run_ps1(fs, script, &mut output)?;
        Ok(String::from_utf8(output).unwrap())
    }

    fn fixture() -> WinFs {
        let mut fs = WinFs::new();
        fs.mkdir("C:\\work\\sub").unwrap();
        fs.set_cwd("C:\\work").unwrap();
        fs.write_file("test.js", b"hello\r\nworld\r\nHELLO again\r\n".to_vec())
            .unwrap();
        fs.write_file("sub\\nested.js", b"nested".to_vec()).unwrap();
        fs
    }

    #[test]
    fn rename_files_directories_named_arguments_and_case() {
        let mut fs = fixture();
        assert_eq!(
            execute(&mut fs, "Rename-Item test.js test.mjs -PassThru").unwrap(),
            "C:\\work\\test.mjs\n"
        );
        assert!(!fs.exists("test.js"));
        assert!(fs.is_file("test.mjs"));
        execute(&mut fs, "rni -LiteralPath test.mjs -NewName TEST.mjs").unwrap();
        assert!(fs.list_dir(".").unwrap().contains(&"TEST.mjs".to_string()));
        execute(&mut fs, "Rename-Item -Path sub renamed").unwrap();
        assert_eq!(fs.read_file("renamed\\nested.js").unwrap(), b"nested");
    }

    #[test]
    fn rename_rejects_collisions_moves_missing_sources_and_previews() {
        let mut fs = fixture();
        fs.write_file("taken.mjs", b"keep".to_vec()).unwrap();
        for script in [
            "Rename-Item test.js taken.mjs -Force",
            "Rename-Item test.js sub\\new.js",
            "Rename-Item missing.js new.js",
            "Rename-Item test.js",
            "Rename-Item test.js ..",
        ] {
            assert!(execute(&mut fs, script).is_err(), "{script}");
        }
        assert_eq!(fs.read_file("taken.mjs").unwrap(), b"keep");
        execute(&mut fs, "Rename-Item test.js future.mjs -WhatIf").unwrap();
        assert!(fs.is_file("test.js"));
        assert!(!fs.exists("future.mjs"));
    }

    #[test]
    fn clear_content_preserves_file_and_rejects_missing_or_directory() {
        let mut fs = fixture();
        execute(&mut fs, "clc test.js -WhatIf").unwrap();
        assert!(!fs.read_file("test.js").unwrap().is_empty());
        execute(&mut fs, "Clear-Content -LiteralPath test.js").unwrap();
        assert!(fs.is_file("test.js"));
        assert!(fs.read_file("test.js").unwrap().is_empty());
        assert!(execute(&mut fs, "clc missing").is_err());
        assert!(execute(&mut fs, "clc sub").is_err());
    }

    #[test]
    fn paths_resolve_relative_and_split_without_requiring_existence() {
        let mut fs = fixture();
        assert_eq!(
            execute(&mut fs, "Resolve-Path sub\\..\\test.js").unwrap(),
            "C:\\work\\test.js\n"
        );
        assert_eq!(
            execute(&mut fs, "rvpa sub\\nested.js -Relative").unwrap(),
            ".\\sub\\nested.js\n"
        );
        assert_eq!(execute(&mut fs, "rvpa C:\\ -Relative").unwrap(), "..\n");
        assert!(execute(&mut fs, "Resolve-Path absent").is_err());
        assert_eq!(execute(&mut fs, "Split-Path C:\\work\\missing.mjs -Leaf\nSplit-Path C:\\work\\missing.mjs -Parent\nSplit-Path missing.mjs -LeafBase\nSplit-Path missing.mjs -Extension\nSplit-Path C:\\x -Qualifier\nSplit-Path C:\\x -NoQualifier\nSplit-Path .\\x -IsAbsolute").unwrap(), "missing.mjs\nC:\\work\nmissing\n.mjs\nC:\n\\x\nFalse\n");
        assert!(execute(&mut fs, "Split-Path test.js -Leaf -Parent").is_err());
    }

    #[test]
    fn child_listing_uses_cwd_and_filters_recursively() {
        let mut fs = fixture();
        assert_eq!(execute(&mut fs, "Get-ChildItem").unwrap(), "sub\ntest.js\n");
        assert_eq!(
            execute(&mut fs, "gci -File -Recurse -Filter *.js").unwrap(),
            "test.js\nsub\\nested.js\n"
        );
        assert_eq!(execute(&mut fs, "gci *.js").unwrap(), "test.js\n");
        assert_eq!(execute(&mut fs, "gci -Directory").unwrap(), "sub\n");
        assert_eq!(execute(&mut fs, "Test-Path test.js -PathType Leaf\nTest-Path sub -PathType Leaf\nTest-Path sub -PathType Container").unwrap(), "True\nFalse\nTrue\n");
        assert!(execute(&mut fs, "gci absent").is_err());
    }

    #[test]
    fn content_handles_raw_counts_empty_files_and_pipeline_writes() {
        let mut fs = fixture();
        assert_eq!(
            execute(&mut fs, "gc test.js -Head 1\ngc test.js -Tail 1").unwrap(),
            "hello\nHELLO again\n"
        );
        assert_eq!(
            execute(&mut fs, "gc test.js -Raw").unwrap(),
            "hello\r\nworld\r\nHELLO again\r\n"
        );
        assert_eq!(execute(&mut fs, "gc test.js -TotalCount 0").unwrap(), "");
        assert!(execute(&mut fs, "gc test.js -Raw -Tail 1").is_err());
        assert!(execute(&mut fs, "gc test.js -Tail -1").is_err());
        execute(&mut fs, "gc test.js -Encoding utf8 | Set-Content result.txt -Encoding utf8\n'last' | Add-Content result.txt -Encoding utf8NoBOM\nsc -Path exact.txt value -NoNewline").unwrap();
        assert_eq!(
            fs.read_file("result.txt").unwrap(),
            b"hello\nworld\nHELLO again\nlast\n"
        );
        assert_eq!(fs.read_file("exact.txt").unwrap(), b"value");
        execute(&mut fs, "clc test.js").unwrap();
        assert_eq!(execute(&mut fs, "gc test.js").unwrap(), "");
    }

    #[test]
    fn copy_and_move_accept_directory_destinations_and_force_file_replacement() {
        let mut fs = fixture();
        execute(
            &mut fs,
            "Copy-Item test.js sub\nCopy-Item test.js sub\nMove-Item sub\\nested.js .",
        )
        .unwrap();
        assert!(fs.is_file("sub\\test.js"));
        assert!(fs.is_file("nested.js"));
        fs.write_file("replace.js", b"old".to_vec()).unwrap();
        assert!(execute(&mut fs, "Move-Item nested.js replace.js").is_err());
        execute(&mut fs, "Move-Item nested.js replace.js -Force").unwrap();
        assert_eq!(fs.read_file("replace.js").unwrap(), b"nested");
        execute(
            &mut fs,
            "Copy-Item sub empty\nCopy-Item sub recursive -Recurse",
        )
        .unwrap();
        assert!(fs.is_dir("empty"));
        assert!(fs.list_dir("empty").unwrap().is_empty());
        assert!(fs.is_file("recursive\\test.js"));
        assert!(!fs.exists("nested.js"));
        assert!(execute(&mut fs, "Move-Item missing replace.js -Force").is_err());
        assert_eq!(fs.read_file("replace.js").unwrap(), b"nested");
    }

    #[test]
    fn text_search_regex_literals_quiet_and_invalid_patterns() {
        let mut fs = fixture();
        assert_eq!(
            execute(&mut fs, "gc test.js | sls '^hello' -Raw").unwrap(),
            "hello\nHELLO again\n"
        );
        assert_eq!(
            execute(
                &mut fs,
                "sls -Path test.js -Pattern WORLD -SimpleMatch -Quiet"
            )
            .unwrap(),
            "True\n"
        );
        assert_eq!(
            execute(&mut fs, "sls hello test.js -List").unwrap(),
            "test.js:1:hello\n"
        );
        assert_eq!(
            execute(&mut fs, "gc test.js | sls absent -Quiet").unwrap(),
            "False\n"
        );
        assert_eq!(
            execute(&mut fs, "gc test.js | sls hello -NotMatch -Raw").unwrap(),
            "world\n"
        );
        assert!(execute(&mut fs, "gc test.js | sls '['").is_err());
    }

    #[test]
    fn text_output_append_clobber_tee_and_encoding_errors() {
        let mut fs = fixture();
        assert_eq!(
            execute(
                &mut fs,
                "gc test.js | Tee-Object log.txt | Select-Object -First 1"
            )
            .unwrap(),
            "hello\n"
        );
        execute(&mut fs, "'tail' | Out-File log.txt -Append -Encoding utf8").unwrap();
        assert_eq!(
            fs.read_file("log.txt").unwrap(),
            b"hello\nworld\nHELLO again\ntail\n"
        );
        assert!(execute(&mut fs, "'overwrite' | Out-File log.txt -NoClobber").is_err());
        assert!(execute(&mut fs, "'bad' | Out-File log.txt -Encoding bogus").is_err());
        execute(&mut fs, "Out-File exact.txt -InputObject 'text' -NoNewline").unwrap();
        assert_eq!(fs.read_file("exact.txt").unwrap(), b"text");
    }

    #[test]
    fn text_sort_unique_and_measure() {
        let mut fs = fixture();
        fs.write_file("lines", b"b\na\na\n".to_vec()).unwrap();
        assert_eq!(
            execute(&mut fs, "gc lines | sort -Unique").unwrap(),
            "a\nb\n"
        );
        assert_eq!(
            execute(&mut fs, "gc lines | sort -Descending | gu").unwrap(),
            "b\na\n"
        );
        assert_eq!(
            execute(&mut fs, "gc lines | measure -Line -Word -Character").unwrap(),
            "Count: 3\nLines: 3\nWords: 3\nCharacters: 3\n"
        );
        assert!(execute(&mut fs, "gc lines | sort -Property Missing").is_err());
    }

    #[test]
    fn discovery_lists_builtin_alias_function_and_path_program() {
        let mut fs = fixture();
        let output = execute(&mut fs, "Get-Command Rename-*\nGet-Alias rni\nGet-Help Rename-Item\nfunction myfunc { echo yes }\ngcm myfunc").unwrap();
        assert!(output.starts_with("rename-item\nrni -> rename-item\n"));
        assert!(output.contains("-NewName"));
        assert!(output.ends_with("myfunc\n"));
        fs.mkdir("C:\\bin").unwrap();
        fs.write_file("C:\\bin\\mytool.cmd", b"@echo hello".to_vec())
            .unwrap();
        assert_eq!(
            execute(&mut fs, "$env:PATH = 'C:\\bin'\ngcm mytool").unwrap(),
            "C:\\bin\\mytool.cmd\n"
        );
        assert!(execute(&mut fs, "gcm missing_command").is_err());
        for name in COMMAND_NAMES {
            assert!(is_builtin_command(name));
        }
        for (alias, _) in ALIASES {
            assert!(is_builtin_command(alias), "missing {alias}");
        }
    }
}
