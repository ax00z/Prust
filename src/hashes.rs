// hashes.rs — File hashes and imphash.
//
// SHA256 and MD5 of the full file bytes are canonical identifiers;
// analysts paste them into VirusTotal, MalwareBazaar, etc.
//
// Imphash (Mandiant, 2014) is the MD5 of a normalized import list:
// lowercase DLL names with common suffixes stripped, function names
// lowercased, ordinals rendered as "ord<N>". Different builds of the
// same malware family often share an imphash because the import list
// is usually compiler-stable.

use crate::pe::ImportEntry;
use md5::{Digest, Md5};
use sha2::Sha256;

#[derive(Debug, Clone)]
pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
    /// `None` if the binary has no imports (DLLs with static-only exports, etc.).
    pub imphash: Option<String>,
}

/// Compute all hashes for a PE file.
pub fn compute(data: &[u8], imports: &[ImportEntry]) -> FileHashes {
    FileHashes {
        md5: md5_hex(data),
        sha256: sha256_hex(data),
        imphash: imphash(imports),
    }
}

fn md5_hex(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Normalize a DLL name for imphash: lowercase, strip common extensions.
fn normalize_dll(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for ext in [".dll", ".ocx", ".sys"] {
        if let Some(stripped) = lower.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    lower
}

/// Normalize a function name for imphash. The parser renders
/// ordinal-only imports as "#<N>"; imphash convention is "ord<N>".
fn normalize_fn(name: &str) -> String {
    if let Some(ord) = name.strip_prefix('#') {
        format!("ord{ord}")
    } else {
        name.to_ascii_lowercase()
    }
}

/// MD5 of the joined normalized "dll.fn,dll.fn,..." string.
fn imphash(imports: &[ImportEntry]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }

    let mut entries = Vec::new();
    for imp in imports {
        let dll = normalize_dll(&imp.dll_name);
        for func in &imp.functions {
            entries.push(format!("{}.{}", dll, normalize_fn(func)));
        }
    }

    if entries.is_empty() {
        return None;
    }

    let joined = entries.join(",");
    Some(md5_hex(joined.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_known_vector() {
        // RFC 1321 test vector
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn normalize_dll_strips_common_extensions() {
        assert_eq!(normalize_dll("KERNEL32.DLL"), "kernel32");
        assert_eq!(normalize_dll("ntoskrnl.exe"), "ntoskrnl.exe"); // .exe not stripped
        assert_eq!(normalize_dll("DRIVER.SYS"), "driver");
        assert_eq!(normalize_dll("widget.ocx"), "widget");
        assert_eq!(normalize_dll("NoExt"), "noext");
    }

    #[test]
    fn normalize_fn_converts_ordinals() {
        assert_eq!(normalize_fn("#123"), "ord123");
        assert_eq!(normalize_fn("CreateFileA"), "createfilea");
    }

    #[test]
    fn imphash_is_deterministic_and_case_insensitive() {
        let a = vec![ImportEntry {
            dll_name: "KERNEL32.DLL".to_string(),
            functions: vec!["CreateFileA".to_string(), "ReadFile".to_string()],
        }];
        let b = vec![ImportEntry {
            dll_name: "kernel32.dll".to_string(),
            functions: vec!["createfilea".to_string(), "readfile".to_string()],
        }];
        assert_eq!(imphash(&a), imphash(&b));
        assert!(imphash(&a).is_some());
    }

    #[test]
    fn imphash_handles_ordinal_imports() {
        let a = vec![ImportEntry {
            dll_name: "COMCTL32.dll".to_string(),
            functions: vec!["#381".to_string()],
        }];
        // Expected: md5("comctl32.ord381")
        let expected = md5_hex(b"comctl32.ord381");
        assert_eq!(imphash(&a), Some(expected));
    }

    #[test]
    fn imphash_returns_none_when_no_imports() {
        assert_eq!(imphash(&[]), None);
        let empty_dll = vec![ImportEntry {
            dll_name: "user32.dll".to_string(),
            functions: vec![],
        }];
        assert_eq!(imphash(&empty_dll), None);
    }

    #[test]
    fn imphash_order_matters() {
        // Imphash is sensitive to order — this is by design (matches the
        // reference implementation). Reordering imports changes the hash.
        let a = vec![ImportEntry {
            dll_name: "kernel32.dll".to_string(),
            functions: vec!["A".to_string(), "B".to_string()],
        }];
        let b = vec![ImportEntry {
            dll_name: "kernel32.dll".to_string(),
            functions: vec!["B".to_string(), "A".to_string()],
        }];
        assert_ne!(imphash(&a), imphash(&b));
    }
}
