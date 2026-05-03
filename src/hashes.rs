// MD5, SHA256, imphash (Mandiant), and Authenticode hash.

use crate::pe::{DIR_SECURITY, ImportEntry, OptionalHeader, SectionHeader};
use md5::{Digest, Md5};
use sha2::Sha256;

#[derive(Debug, Clone)]
pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
    pub imphash: Option<String>,
    /// SHA256 with CheckSum, SECURITY directory entry, and cert blob excluded.
    /// Survives re-signing of the same binary.
    pub authentihash: Option<String>,
}

/// Computes md5/sha256/imphash. Caller fills `authentihash` via `authentihash_sha256`.
pub fn compute(data: &[u8], imports: &[ImportEntry]) -> FileHashes {
    FileHashes {
        md5: md5_hex(data),
        sha256: sha256_hex(data),
        imphash: imphash(imports),
        authentihash: None,
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

fn normalize_dll(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for ext in [".dll", ".ocx", ".sys"] {
        if let Some(stripped) = lower.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    lower
}

/// `#123` -> `ord123`; otherwise lowercase.
fn normalize_fn(name: &str) -> String {
    if let Some(ord) = name.strip_prefix('#') {
        format!("ord{ord}")
    } else {
        name.to_ascii_lowercase()
    }
}

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

// Authenticode SHA256: hash the file with CheckSum (4 bytes), SECURITY
// directory entry (8 bytes), and the cert blob skipped. Sections are walked
// in PointerToRawData order; the overlay (between last section and cert)
// is hashed last.

const COFF_HEADER_SIZE: usize = 24;
const CHECKSUM_OFFSET_IN_OPT: usize = 64;
const SECURITY_ENTRY_OFFSET_PE32: usize = 96 + DIR_SECURITY * 8;
const SECURITY_ENTRY_OFFSET_PE32PLUS: usize = 112 + DIR_SECURITY * 8;

/// `None` when CheckSum, SECURITY entry, or SizeOfHeaders lies past EOF.
pub fn authentihash_sha256(
    data: &[u8],
    opt: &OptionalHeader,
    sections: &[SectionHeader],
    pe_offset: usize,
) -> Option<String> {
    let opt_offset = pe_offset.checked_add(COFF_HEADER_SIZE)?;
    let checksum_off = opt_offset.checked_add(CHECKSUM_OFFSET_IN_OPT)?;
    let security_entry_off = if opt.is_pe32_plus() {
        opt_offset.checked_add(SECURITY_ENTRY_OFFSET_PE32PLUS)?
    } else {
        opt_offset.checked_add(SECURITY_ENTRY_OFFSET_PE32)?
    };
    let size_of_headers = opt.size_of_headers as usize;

    let end_of_security_entry = security_entry_off.checked_add(8)?;
    if checksum_off + 4 > size_of_headers
        || end_of_security_entry > size_of_headers
        || size_of_headers > data.len()
    {
        return None;
    }

    let mut h = Sha256::new();
    h.update(&data[..checksum_off]);
    h.update(&data[checksum_off + 4..security_entry_off]);
    h.update(&data[end_of_security_entry..size_of_headers]);

    let mut sorted: Vec<&SectionHeader> = sections.iter().collect();
    sorted.sort_by_key(|s| s.pointer_to_raw_data);

    let mut last_hashed_end = size_of_headers;
    for sec in sorted {
        let start = sec.pointer_to_raw_data as usize;
        let size = sec.size_of_raw_data as usize;
        if size == 0 || start >= data.len() {
            continue;
        }
        let nominal_end = start.saturating_add(size);
        h.update(&data[start..nominal_end.min(data.len())]);
        if nominal_end > last_hashed_end {
            last_hashed_end = nominal_end;
        }
    }

    let cert_size = opt
        .data_directories
        .get(DIR_SECURITY)
        .map(|d| d.size as usize)
        .unwrap_or(0);
    let overlay_end = data.len().saturating_sub(cert_size);
    if overlay_end > last_hashed_end && last_hashed_end < data.len() {
        h.update(&data[last_hashed_end..overlay_end.min(data.len())]);
    }

    Some(format!("{:x}", h.finalize()))
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

    /// Synthetic PE32+ for authentihash: pe_offset=0x80, headers end at 0x200,
    /// one section at 0x200..0x300, overlay 0x300..0x340, cert 0x340..0x400.
    fn build_synthetic_pe() -> (Vec<u8>, OptionalHeader, Vec<SectionHeader>, usize) {
        let mut data = vec![0u8; 0x400];
        let pe_offset: usize = 0x80;

        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        data[pe_offset] = b'P';
        data[pe_offset + 1] = b'E';
        data[pe_offset + 2] = 0;
        data[pe_offset + 3] = 0;

        let opt_offset = pe_offset + 24;
        let checksum_off = opt_offset + 64;
        data[checksum_off..checksum_off + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let security_entry_off = opt_offset + 144;
        data[security_entry_off..security_entry_off + 4].copy_from_slice(&0x340u32.to_le_bytes());
        data[security_entry_off + 4..security_entry_off + 8]
            .copy_from_slice(&0xC0u32.to_le_bytes());

        let mut data_directories = vec![
            crate::pe::DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ];
        data_directories[DIR_SECURITY] = crate::pe::DataDirectory {
            virtual_address: 0x340,
            size: 0xC0,
        };

        let opt = OptionalHeader {
            magic: 0x20B,
            major_linker_version: 0,
            minor_linker_version: 0,
            size_of_code: 0,
            address_of_entry_point: 0,
            image_base: 0x0001_4000_0000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            major_os_version: 6,
            minor_os_version: 0,
            size_of_image: 0x2000,
            size_of_headers: 0x200,
            checksum: 0xDEAD_BEEF,
            subsystem: 3,
            dll_characteristics: 0,
            number_of_rva_and_sizes: 16,
            data_directories,
        };

        let sections = vec![SectionHeader {
            name: ".text".into(),
            virtual_size: 0x100,
            virtual_address: 0x1000,
            size_of_raw_data: 0x100,
            pointer_to_raw_data: 0x200,
            characteristics: 0x6000_0020,
        }];

        (data, opt, sections, pe_offset)
    }

    #[test]
    fn authentihash_matches_manual_byte_stream() {
        let (data, opt, sections, pe_offset) = build_synthetic_pe();
        let opt_offset = pe_offset + 24;
        let checksum_off = opt_offset + 64;
        let security_entry_off = opt_offset + 144; // PE32+
        let size_of_headers = 0x200;
        let last_section_end = 0x300;
        let cert_start = 0x340;

        let mut expected = Vec::new();
        expected.extend_from_slice(&data[..checksum_off]);
        expected.extend_from_slice(&data[checksum_off + 4..security_entry_off]);
        expected.extend_from_slice(&data[security_entry_off + 8..size_of_headers]);
        expected.extend_from_slice(&data[0x200..last_section_end]);
        expected.extend_from_slice(&data[last_section_end..cert_start]);

        let expected_hash = sha256_hex(&expected);
        let got = authentihash_sha256(&data, &opt, &sections, pe_offset).unwrap();
        assert_eq!(got, expected_hash);
    }

    #[test]
    fn authentihash_differs_from_full_file_sha256() {
        let (data, opt, sections, pe_offset) = build_synthetic_pe();
        let auth = authentihash_sha256(&data, &opt, &sections, pe_offset).unwrap();
        let full = sha256_hex(&data);
        assert_ne!(auth, full);
    }

    #[test]
    fn authentihash_unchanged_when_cert_blob_changes() {
        let (mut data, opt, sections, pe_offset) = build_synthetic_pe();
        let baseline = authentihash_sha256(&data, &opt, &sections, pe_offset).unwrap();
        for b in &mut data[0x340..0x400] {
            *b ^= 0xAA;
        }
        let after = authentihash_sha256(&data, &opt, &sections, pe_offset).unwrap();
        assert_eq!(baseline, after);
    }

    #[test]
    fn authentihash_unchanged_when_checksum_changes() {
        let (mut data, opt, sections, pe_offset) = build_synthetic_pe();
        let baseline = authentihash_sha256(&data, &opt, &sections, pe_offset).unwrap();

        let checksum_off = pe_offset + 24 + 64;
        for b in &mut data[checksum_off..checksum_off + 4] {
            *b = 0xFF;
        }

        let after = authentihash_sha256(&data, &opt, &sections, pe_offset).unwrap();
        assert_eq!(baseline, after);
    }

    #[test]
    fn authentihash_changes_when_section_bytes_change() {
        let (mut data, opt, sections, pe_offset) = build_synthetic_pe();
        let baseline = authentihash_sha256(&data, &opt, &sections, pe_offset).unwrap();

        data[0x250] ^= 0xFF;
        let after = authentihash_sha256(&data, &opt, &sections, pe_offset).unwrap();
        assert_ne!(baseline, after);
    }

    #[test]
    fn authentihash_returns_none_when_size_of_headers_past_eof() {
        let (data, mut opt, sections, pe_offset) = build_synthetic_pe();
        opt.size_of_headers = 0x10000;
        assert!(authentihash_sha256(&data, &opt, &sections, pe_offset).is_none());
    }
}
