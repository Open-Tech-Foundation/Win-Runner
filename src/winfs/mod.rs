//! WinFS: completely in-memory Windows-style filesystem.
//!
//! - No mapping to the Linux host filesystem.
//! - Case-insensitive lookup, original casing preserved for listings.
//! - Supports `C:\`, `C:\test\a.txt`, relative paths, `.` and `..`.
//! - Single shared API used by both EXE shims (`winapi`) and PS1 (`ps1`).

use std::collections::HashMap;

#[derive(Debug, Clone)]
enum Node {
    Dir { name: String, children: HashMap<String, Node> },
    File { name: String, data: Vec<u8> },
}

impl Node {
    fn name(&self) -> &str {
        match self {
            Node::Dir { name, .. } => name,
            Node::File { name, .. } => name,
        }
    }
    fn is_dir(&self) -> bool {
        matches!(self, Node::Dir { .. })
    }
    fn is_file(&self) -> bool {
        matches!(self, Node::File { .. })
    }
}

#[derive(Debug, Clone)]
pub struct WinFs {
    /// drive letter (upper) -> root dir node
    drives: HashMap<char, Node>,
    /// current drive + parts (original casing)
    cwd_drive: char,
    cwd_parts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinPath {
    pub drive: char,
    /// path components with original casing (normalized `.`/`..` resolved)
    pub parts: Vec<String>,
}

impl WinPath {
    pub fn display(&self) -> String {
        let mut s = String::new();
        s.push(self.drive);
        s.push_str(":\\");
        s.push_str(&self.parts.join("\\"));
        s
    }
    /// lowercase key for case-insensitive lookup
    pub fn key(&self) -> String {
        let mut s = String::new();
        s.push(self.drive);
        s.push_str(":\\");
        s.push_str(
            &self
                .parts
                .iter()
                .map(|p| p.to_lowercase())
                .collect::<Vec<_>>()
                .join("\\"),
        );
        s
    }
}

fn is_drive_letter(c: char) -> bool {
    c.is_ascii_alphabetic()
}

impl Default for WinFs {
    fn default() -> Self {
        Self::new()
    }
}

impl WinFs {
    pub fn new() -> Self {
        let mut drives = HashMap::new();
        drives.insert(
            'C',
            Node::Dir {
                name: String::new(),
                children: HashMap::new(),
            },
        );
        Self {
            drives,
            cwd_drive: 'C',
            cwd_parts: Vec::new(),
        }
    }

    pub fn cwd(&self) -> String {
        WinPath {
            drive: self.cwd_drive,
            parts: self.cwd_parts.clone(),
        }
        .display()
    }

    pub fn set_cwd(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        // must exist and be a dir
        if !self.is_dir(&p.display()) {
            return Err(format!("path not found: {path}"));
        }
        self.cwd_drive = p.drive;
        self.cwd_parts = p.parts;
        Ok(())
    }

    /// Parse + normalize a Windows path. Handles `\` and `/`, drive letters,
    /// absolute (`C:\...`, `\...`) vs relative, `.` and `..`.
    pub fn normalize(&self, raw: &str) -> Result<WinPath, String> {
        let s = raw.trim();
        if s.is_empty() {
            return Err("empty path".to_string());
        }
        // Normalize separators to backslash for parsing (but keep case).
        let s = s.replace('/', "\\");

        let (drive, rest): (char, &str) = if s.len() >= 2
            && is_drive_letter(s.chars().next().unwrap())
            && s.chars().nth(1) == Some(':')
        {
            let d = s.chars().next().unwrap().to_ascii_uppercase();
            if d != 'C' {
                return Err(format!("unsupported drive in path: {raw} (only C: supported)"));
            }
            let rest = &s[2..];
            (d, rest)
        } else if s.starts_with('\\') {
            (self.cwd_drive, s.as_str())
        } else {
            // relative: start from cwd
            let base_parts = if self.cwd_drive == 'C' {
                self.cwd_parts.clone()
            } else {
                vec![]
            };
            let mut parts = base_parts;
            for comp in s.split('\\') {
                match comp {
                    "" | "." => continue,
                    ".." => {
                        parts.pop();
                    }
                    _ => parts.push(comp.to_string()),
                }
            }
            return Ok(WinPath {
                drive: self.cwd_drive,
                parts,
            });
        };

        // absolute on drive
        let mut parts: Vec<String> = if rest.starts_with('\\') {
            Vec::new()
        } else {
            // e.g. "C:foo" -> drive-relative; treat as cwd-relative on that drive
            if self.cwd_drive == drive {
                self.cwd_parts.clone()
            } else {
                Vec::new()
            }
        };
        // strip leading backslashes
        let rest = rest.trim_start_matches('\\');
        if rest.is_empty() {
            return Ok(WinPath { drive, parts });
        }
        for comp in rest.split('\\') {
            match comp {
                "" => continue, // collapse duplicate separators / trailing slash
                "." => continue,
                ".." => {
                    parts.pop();
                }
                _ => parts.push(comp.to_string()),
            }
        }
        Ok(WinPath { drive, parts })
    }

    fn get_node(&self, p: &WinPath) -> Option<&Node> {
        let mut node = self.drives.get(&p.drive)?;
        for part in &p.parts {
            match node {
                Node::Dir { children, .. } => {
                    node = children.get(&part.to_lowercase())?;
                }
                Node::File { .. } => return None,
            }
        }
        Some(node)
    }

    fn get_node_mut(&mut self, p: &WinPath) -> Option<&mut Node> {
        let mut node = self.drives.get_mut(&p.drive)?;
        for part in &p.parts {
            match node {
                Node::Dir { children, .. } => {
                    node = children.get_mut(&part.to_lowercase())?;
                }
                Node::File { .. } => return None,
            }
        }
        Some(node)
    }

    fn parent_of(&self, p: &WinPath) -> WinPath {
        let mut parts = p.parts.clone();
        parts.pop();
        WinPath {
            drive: p.drive,
            parts,
        }
    }

    // ---- queries (same API for EXE + PS1) ----

    pub fn exists(&self, path: &str) -> bool {
        self.normalize(path)
            .ok()
            .and_then(|p| self.get_node(&p))
            .is_some()
    }

    pub fn is_file(&self, path: &str) -> bool {
        self.normalize(path)
            .ok()
            .and_then(|p| self.get_node(&p))
            .map(|n| n.is_file())
            .unwrap_or(false)
    }

    pub fn is_dir(&self, path: &str) -> bool {
        self.normalize(path)
            .ok()
            .and_then(|p| self.get_node(&p))
            .map(|n| n.is_dir())
            .unwrap_or(false)
    }

    pub fn test_path(&self, path: &str) -> bool {
        self.exists(path)
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
        let p = self.normalize(path)?;
        match self.get_node(&p) {
            Some(Node::File { data, .. }) => Ok(data.clone()),
            Some(Node::Dir { .. }) => Err(format!("path is a directory: {}", p.display())),
            None => Err(format!("file not found: {}", p.display())),
        }
    }

    pub fn list_dir(&self, path: &str) -> Result<Vec<String>, String> {
        let p = self.normalize(path)?;
        match self.get_node(&p) {
            Some(Node::Dir { children, .. }) => {
                let mut names: Vec<String> = children.values().map(|n| n.name().to_string()).collect();
                names.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
                Ok(names)
            }
            Some(Node::File { .. }) => Err(format!("not a directory: {}", p.display())),
            None => Err(format!("path not found: {}", p.display())),
        }
    }

    // ---- mutations ----

    /// Create all missing directories along `path` (like mkdir -p).
    pub fn mkdir(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        if p.parts.is_empty() {
            return Ok(()); // root exists
        }
        // walk, creating as needed (case-insensitive match, preserve first casing)
        let mut node = self
            .drives
            .get_mut(&p.drive)
            .ok_or_else(|| format!("unsupported drive: {}", p.drive))?;
        for part in &p.parts {
            let key = part.to_lowercase();
            let next = node;
            match next {
                Node::Dir { children, .. } => {
                    if let Some(existing) = children.get(&key) {
                        if existing.is_file() {
                            return Err(format!("path component is a file: {part}"));
                        }
                    } else {
                        children.insert(
                            key.clone(),
                            Node::Dir {
                                name: part.clone(),
                                children: HashMap::new(),
                            },
                        );
                    }
                    node = children.get_mut(&key).unwrap();
                }
                Node::File { .. } => return Err("parent is a file".to_string()),
            }
        }
        Ok(())
    }

    /// Create a single directory; fails if parent missing (Windows-like).
    /// Used by CreateDirectoryW. Use `mkdir` (recursive) for PS1 New-Item -Force.
    pub fn mkdir_one(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        if p.parts.is_empty() {
            return Err("cannot create root".to_string());
        }
        if self.get_node(&p).is_some() {
            return Err(format!("already exists: {}", p.display()));
        }
        let parent = self.parent_of(&p);
        let parent_node = self
            .get_node_mut(&parent)
            .ok_or_else(|| format!("parent not found: {}", parent.display()))?;
        match parent_node {
            Node::Dir { children, .. } => {
                let leaf = p.parts.last().unwrap().clone();
                children.insert(
                    leaf.to_lowercase(),
                    Node::Dir {
                        name: leaf,
                        children: HashMap::new(),
                    },
                );
                Ok(())
            }
            Node::File { .. } => Err("parent is a file".to_string()),
        }
    }

    pub fn rmdir(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        if p.parts.is_empty() {
            return Err("cannot remove root".to_string());
        }
        // check empty
        match self.get_node(&p) {
            Some(Node::Dir { children, .. }) => {
                if !children.is_empty() {
                    return Err(format!("directory not empty: {}", p.display()));
                }
            }
            Some(Node::File { .. }) => return Err(format!("not a directory: {}", p.display())),
            None => return Err(format!("path not found: {}", p.display())),
        }
        let parent = self.parent_of(&p);
        let leaf_key = p.parts.last().unwrap().to_lowercase();
        let parent_node = self.get_node_mut(&parent).unwrap();
        if let Node::Dir { children, .. } = parent_node {
            children.remove(&leaf_key);
            Ok(())
        } else {
            Err("parent is a file".to_string())
        }
    }

    pub fn write_file(&mut self, path: &str, data: Vec<u8>) -> Result<(), String> {
        let p = self.normalize(path)?;
        if p.parts.is_empty() {
            return Err("cannot write to root".to_string());
        }
        if let Some(node) = self.get_node_mut(&p) {
            match node {
                Node::File { data: d, .. } => {
                    *d = data;
                    Ok(())
                }
                Node::Dir { .. } => Err(format!("path is a directory: {}", p.display())),
            }
        } else {
            // create; parent must exist
            let parent = self.parent_of(&p);
            let parent_node = self
                .get_node_mut(&parent)
                .ok_or_else(|| format!("parent not found: {}", parent.display()))?;
            match parent_node {
                Node::Dir { children, .. } => {
                    let leaf = p.parts.last().unwrap().clone();
                    children.insert(
                        leaf.to_lowercase(),
                        Node::File { name: leaf, data },
                    );
                    Ok(())
                }
                Node::File { .. } => Err("parent is a file".to_string()),
            }
        }
    }

    pub fn append_file(&mut self, path: &str, data: &[u8]) -> Result<(), String> {
        let p = self.normalize(path)?;
        if let Some(node) = self.get_node_mut(&p) {
            match node {
                Node::File { data: d, .. } => {
                    d.extend_from_slice(data);
                    Ok(())
                }
                Node::Dir { .. } => Err(format!("path is a directory: {}", p.display())),
            }
        } else {
            self.write_file(path, data.to_vec())
        }
    }

    pub fn delete_file(&mut self, path: &str) -> Result<(), String> {
        let p = self.normalize(path)?;
        match self.get_node(&p) {
            Some(Node::File { .. }) => {}
            Some(Node::Dir { .. }) => return Err(format!("is a directory: {}", p.display())),
            None => return Err(format!("file not found: {}", p.display())),
        }
        let parent = self.parent_of(&p);
        let leaf_key = p.parts.last().unwrap().to_lowercase();
        let parent_node = self.get_node_mut(&parent).unwrap();
        if let Node::Dir { children, .. } = parent_node {
            children.remove(&leaf_key);
            Ok(())
        } else {
            Err("parent is a file".to_string())
        }
    }

    /// Remove file or (empty) dir; with `recursive` removes non-empty dirs.
    pub fn remove(&mut self, path: &str, recursive: bool) -> Result<(), String> {
        let p = self.normalize(path)?;
        if p.parts.is_empty() {
            return Err("cannot remove root".to_string());
        }
        let node = self
            .get_node(&p)
            .ok_or_else(|| format!("path not found: {}", p.display()))?
            .clone();
        match node {
            Node::File { .. } => self.delete_file(path),
            Node::Dir { children, .. } => {
                if !children.is_empty() && !recursive {
                    return Err(format!("directory not empty: {}", p.display()));
                }
                let parent = self.parent_of(&p);
                let leaf_key = p.parts.last().unwrap().to_lowercase();
                let parent_node = self.get_node_mut(&parent).unwrap();
                if let Node::Dir { children, .. } = parent_node {
                    children.remove(&leaf_key);
                    Ok(())
                } else {
                    Err("parent is a file".to_string())
                }
            }
        }
    }

    pub fn move_path(&mut self, src: &str, dst: &str) -> Result<(), String> {
        let s = self.normalize(src)?;
        let d = self.normalize(dst)?;
        if s.key() == d.key() {
            return Ok(());
        }
        let node = self
            .get_node(&s)
            .ok_or_else(|| format!("source not found: {}", s.display()))?
            .clone();
        if self.get_node(&d).is_some() {
            return Err(format!("destination exists: {}", d.display()));
        }
        if d.parts.is_empty() {
            return Err("cannot move to root".to_string());
        }
        // insert under dst leaf name (dst casing wins), then remove src
        let dparent = self.parent_of(&d);
        // cannot move a dir into itself
        if node.is_dir() {
            let sk = s.key() + "\\";
            let dk = d.key() + "\\";
            if dk.starts_with(&sk) {
                return Err("cannot move directory into itself".to_string());
            }
        }
        let mut moved = node;
        // rename top-level to dst leaf original casing
        let leaf = d.parts.last().unwrap().clone();
        match &mut moved {
            Node::Dir { name, .. } => *name = leaf.clone(),
            Node::File { name, .. } => *name = leaf.clone(),
        }
        {
            let dp = self
                .get_node_mut(&dparent)
                .ok_or_else(|| format!("destination parent not found: {}", dparent.display()))?;
            match dp {
                Node::Dir { children, .. } => {
                    children.insert(leaf.to_lowercase(), moved);
                }
                Node::File { .. } => return Err("destination parent is a file".to_string()),
            }
        }
        // remove src
        let sparent = self.parent_of(&s);
        let skey = s.parts.last().unwrap().to_lowercase();
        let sp = self.get_node_mut(&sparent).unwrap();
        if let Node::Dir { children, .. } = sp {
            children.remove(&skey);
        }
        Ok(())
    }

    pub fn copy_path(&mut self, src: &str, dst: &str, fail_if_exists: bool) -> Result<(), String> {
        let s = self.normalize(src)?;
        let d = self.normalize(dst)?;
        let node = self
            .get_node(&s)
            .ok_or_else(|| format!("source not found: {}", s.display()))?
            .clone();
        if self.get_node(&d).is_some() {
            if fail_if_exists {
                return Err(format!("destination exists: {}", d.display()));
            } else {
                // overwrite files only (dirs merge is out of scope; require remove first)
                if node.is_file() {
                    let dst_node = self.get_node(&d).unwrap().clone();
                    if dst_node.is_dir() {
                        return Err(format!("destination is a directory: {}", d.display()));
                    }
                    // overwrite preserving dst casing? use existing name
                    let data = match node {
                        Node::File { data, .. } => data,
                        _ => unreachable!(),
                    };
                    let dst_mut = self.get_node_mut(&d).unwrap();
                    if let Node::File { data: dd, .. } = dst_mut {
                        *dd = data;
                        return Ok(());
                    }
                    return Ok(());
                }
                return Err(format!("destination exists: {}", d.display()));
            }
        }
        if d.parts.is_empty() {
            return Err("cannot copy to root".to_string());
        }
        let mut copied = node;
        let leaf = d.parts.last().unwrap().clone();
        match &mut copied {
            Node::Dir { name, .. } => *name = leaf.clone(),
            Node::File { name, .. } => *name = leaf.clone(),
        }
        let dparent = self.parent_of(&d);
        let dp = self
            .get_node_mut(&dparent)
            .ok_or_else(|| format!("destination parent not found: {}", dparent.display()))?;
        match dp {
            Node::Dir { children, .. } => {
                children.insert(leaf.to_lowercase(), copied);
                Ok(())
            }
            Node::File { .. } => Err("destination parent is a file".to_string()),
        }
    }

    /// Copy file bytes (helper for CopyFileW semantics).
    pub fn copy_file(&mut self, src: &str, dst: &str, fail_if_exists: bool) -> Result<(), String> {
        let s = self.normalize(src)?;
        match self.get_node(&s) {
            Some(Node::File { .. }) => {}
            Some(Node::Dir { .. }) => return Err(format!("source is a directory: {}", s.display())),
            None => return Err(format!("source not found: {}", s.display())),
        }
        self.copy_path(src, dst, fail_if_exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_insensitive_preserve_case() {
        let mut fs = WinFs::new();
        fs.mkdir("C:\\Test").unwrap();
        fs.write_file("C:\\TEST\\A.txt", b"hi".to_vec()).unwrap();
        assert!(fs.exists("c:\\test\\a.TXT"));
        assert_eq!(fs.read_file("C:\\test\\A.txt").unwrap(), b"hi");
        assert_eq!(fs.list_dir("c:\\TEST").unwrap(), vec!["A.txt".to_string()]);
    }

    #[test]
    fn dot_dot_normalization() {
        let mut fs = WinFs::new();
        fs.mkdir("C:\\a\\b").unwrap();
        fs.write_file("C:\\a\\b\\f.txt", b"x".to_vec()).unwrap();
        assert_eq!(fs.read_file("C:\\a\\.\\b\\f.txt").unwrap(), b"x");
        assert_eq!(fs.read_file("C:\\a\\b\\..\\b\\f.txt").unwrap(), b"x");
        assert!(fs.exists("C:\\a\\b\\..\\b"));
        // relative
        fs.set_cwd("C:\\a\\b").unwrap();
        assert_eq!(fs.read_file(".\\f.txt").unwrap(), b"x");
        assert_eq!(fs.read_file("..\\b\\f.txt").unwrap(), b"x");
    }

    #[test]
    fn never_touches_host_fs() {
        let mut fs = WinFs::new();
        fs.write_file("C:\\host_check_xyz.txt", b"data".to_vec()).unwrap();
        assert!(!std::path::Path::new("C:\\host_check_xyz.txt").exists());
        assert!(!std::path::Path::new("/tmp/host_check_xyz.txt").exists());
        assert!(!std::path::Path::new("host_check_xyz.txt").exists());
    }
}
