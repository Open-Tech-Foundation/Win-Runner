//! `wincli inspect`: static compatibility report for a Windows PE.
//!
//! Lists every import with its supported/missing verdict against
//! [`SUPPORTED_APIS`](crate::pe::SUPPORTED_APIS). Uses [`load_lenient`](crate::pe::load_lenient),
//! so binaries WinCLI cannot (yet) run still produce a full missing-API list —
//! the fast path for expanding support one real program at a time.
//!
//! Exit-code contract (harness-friendly): `0` = runnable (nothing missing),
//! `1` = missing imports or unreadable/invalid file.

use crate::pe::{load_lenient, Import};

#[derive(Debug, Clone)]
pub struct InspectReport {
    pub arch: String,
    pub entry_rva: u32,
    pub image_base: u64,
    pub supported: Vec<Import>,
    pub missing: Vec<Import>,
}

impl InspectReport {
    pub fn runnable(&self) -> bool {
        self.missing.is_empty()
    }
    pub fn total(&self) -> usize {
        self.supported.len() + self.missing.len()
    }
}

pub fn inspect_pe(data: &[u8]) -> Result<InspectReport, String> {
    let img = load_lenient(data)?;
    Ok(InspectReport {
        arch: "x86_64".to_string(),
        entry_rva: img.entry_rva,
        image_base: img.image_base,
        supported: img.imports,
        missing: img.unsupported,
    })
}

pub fn render(report: &InspectReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("PE: {}\n", report.arch));
    s.push_str(&format!("Entry: 0x{:08x}\n", report.entry_rva));
    s.push_str(&format!("Imports: {}\n", report.total()));
    s.push_str(&format!("Supported imports: {}\n", report.supported.len()));
    s.push_str(&format!("Missing imports:   {}\n", report.missing.len()));
    if !report.missing.is_empty() {
        s.push_str("\nMissing:\n");
        let mut missing = report.missing.clone();
        missing.sort_by(|a, b| {
            a.dll
                .to_uppercase()
                .cmp(&b.dll.to_uppercase())
                .then(a.func.cmp(&b.func))
        });
        for imp in &missing {
            s.push_str(&format!("  {}!{}\n", imp.dll, imp.func));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::builder;

    #[test]
    fn fully_supported_binary_reports_runnable() {
        let exe = builder::hello("hi");
        let rep = inspect_pe(&exe).unwrap();
        assert_eq!(rep.arch, "x86_64");
        assert_eq!(rep.total(), 3);
        assert!(rep.runnable());
        let out = render(&rep);
        assert!(out.contains("Supported imports: 3"));
        assert!(out.contains("Missing imports:   0"));
        assert!(!out.contains("Missing:\n"));
    }

    #[test]
    fn unknown_import_is_listed_not_fatal() {
        let exe = builder::unknown_import();
        // strict load still refuses (exec path unchanged)...
        assert!(crate::pe::load(&exe).is_err());
        // ...but inspect reports it.
        let rep = inspect_pe(&exe).unwrap();
        assert!(!rep.runnable());
        assert_eq!(rep.missing.len(), 1);
        assert_eq!(rep.missing[0].func, "NoSuchApiForTest");
        let out = render(&rep);
        assert!(out.contains("Missing imports:   1"));
        assert!(out.contains("NoSuchApiForTest"));
    }

    #[test]
    fn garbage_is_an_error_not_a_report() {
        assert!(inspect_pe(b"MZ blah blah").is_err());
        assert!(inspect_pe(b"not a pe at all........").is_err());
    }
}
