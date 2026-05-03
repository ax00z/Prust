//! Analysis pipeline shared by the CLI and Python bindings.
//!
//! [`Analysis`] holds parsed structures plus owned file bytes; [`Report`] is
//! the serializable projection consumed by `--json` and `pythonize`.

use crate::{authenticode, entropy, hashes, loldrivers, overlay, patterns, pe, rules, strings};
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct Report {
    pub file: String,
    pub file_size: usize,
    pub md5: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentihash: Option<String>,
    pub machine: String,
    pub pe_type: String,
    pub subsystem: String,
    pub entry_point: String,
    pub image_base: String,
    pub characteristics: Vec<String>,
    pub dll_characteristics: Vec<String>,
    pub signature: ReportSignature,
    pub sections: Vec<ReportSection>,
    pub imports: Vec<ReportImport>,
    pub export_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_callbacks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<ReportOverlay>,
    pub string_count: usize,
    pub interesting_strings: Vec<String>,
    pub pattern_hits: Vec<ReportPatternHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loldrivers_match: Option<ReportLolDriversMatch>,
    pub triage: rules::TriageResult,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ReportSignature {
    Unsigned,
    Malformed {
        error: String,
    },
    Present {
        blob_size: usize,
        win_cert_revision: String,
        win_cert_type: String,
        content_type_oid: String,
        is_signed_data: bool,
    },
}

#[derive(Serialize, Debug, Clone)]
pub struct ReportSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: String,
    pub raw_size: u32,
    pub permissions: String,
    pub entropy: f64,
    pub entropy_label: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ReportImport {
    pub dll: String,
    pub functions: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ReportOverlay {
    pub offset: usize,
    pub size: usize,
    pub entropy: f64,
    pub entropy_label: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ReportPatternHit {
    pub pattern: String,
    pub severity: u32,
    pub offset: String,
    pub description: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ReportLolDriversMatch {
    pub matched_by: String,
    pub driver_id: String,
    pub filename: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_id: Option<String>,
    pub tags: Vec<String>,
}

impl From<&loldrivers::DriverMatch> for ReportLolDriversMatch {
    fn from(m: &loldrivers::DriverMatch) -> Self {
        Self {
            matched_by: m.kind.as_str().to_string(),
            driver_id: m.entry.id.clone(),
            filename: m.entry.filename.clone(),
            category: m.entry.category.clone(),
            mitre_id: m.entry.mitre_id.clone(),
            tags: m.entry.tags.clone(),
        }
    }
}

impl From<&authenticode::SignatureStatus> for ReportSignature {
    fn from(s: &authenticode::SignatureStatus) -> Self {
        match s {
            authenticode::SignatureStatus::Unsigned => ReportSignature::Unsigned,
            authenticode::SignatureStatus::Malformed(e) => {
                ReportSignature::Malformed { error: e.clone() }
            }
            authenticode::SignatureStatus::Present(p) => ReportSignature::Present {
                blob_size: p.blob_size,
                win_cert_revision: format!("0x{:04X}", p.win_cert_revision),
                win_cert_type: format!("0x{:04X}", p.win_cert_type),
                content_type_oid: p.content_type_oid.clone(),
                is_signed_data: p.is_signed_data,
            },
        }
    }
}

/// Owns the file bytes; downstream consumers can re-read sections without
/// keeping a parallel buffer alive.
pub struct Analysis {
    pub data: Vec<u8>,
    pub dos: pe::DosHeader,
    pub coff: pe::CoffHeader,
    pub opt: pe::OptionalHeader,
    pub sections: Vec<pe::SectionHeader>,
    pub imports: Vec<pe::ImportEntry>,
    pub exports: Option<pe::ExportInfo>,
    pub tls: Option<pe::TlsInfo>,
    pub overlay: Option<overlay::OverlayInfo>,
    pub extracted_strings: Vec<strings::ExtractedString>,
    pub pattern_hits: Vec<patterns::PatternHit>,
    pub file_hashes: hashes::FileHashes,
    pub signature: authenticode::SignatureStatus,
    pub loldrivers_match: Option<loldrivers::DriverMatch>,
    pub triage: rules::TriageResult,
}

pub const INTERESTING_PATTERNS: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "cmd.exe",
    "powershell",
    "wscript",
    "cscript",
    "mshta",
    "HKLM\\",
    "HKCU\\",
    "CurrentVersion\\Run",
    "\\AppData\\",
    "\\Temp\\",
    "\\System32\\",
    ".dll",
    ".exe",
    ".bat",
    ".ps1",
    ".vbs",
    "password",
    "credential",
    "token",
    "secret",
    "CreateRemoteThread",
    "VirtualAlloc",
    "WriteProcessMemory",
    "NtUnmapViewOfSection",
    "IsDebuggerPresent",
    "socket",
    "connect",
    "recv",
    "send",
    "SELECT ",
    "INSERT ",
    "DELETE ",
    "DROP ",
];

pub const MAX_INTERESTING_STRINGS: usize = 100;

pub fn filter_interesting(strings_in: &[strings::ExtractedString]) -> Vec<String> {
    let mut result = Vec::new();
    for s in strings_in {
        let lower = s.value.to_ascii_lowercase();
        for pattern in INTERESTING_PATTERNS {
            if lower.contains(&pattern.to_ascii_lowercase()) {
                result.push(format!("0x{:08X} [{}] {}", s.offset, s.encoding, s.value));
                break;
            }
        }
        if result.len() >= MAX_INTERESTING_STRINGS {
            break;
        }
    }
    result
}

/// Takes ownership of `data`; the returned [`Analysis`] retains it.
/// `lol_db = None` skips the LOLDrivers lookup.
pub fn analyze_bytes(
    data: Vec<u8>,
    lol_db: Option<&loldrivers::LolDriversDb>,
) -> Result<Analysis, Box<dyn std::error::Error>> {
    let dos = pe::DosHeader::parse(&data)?;
    let pe_offset = dos.e_lfanew as usize;
    let coff = pe::CoffHeader::parse(&data, pe_offset)?;
    let opt_offset = pe_offset + 24;
    let opt = pe::OptionalHeader::parse(&data, opt_offset, coff.size_of_optional_header)?;

    let sec_offset = pe::section_table_offset(pe_offset, coff.size_of_optional_header);
    let sections = pe::SectionHeader::parse_all(&data, sec_offset, coff.number_of_sections)?;

    let imports = opt
        .data_directories
        .get(pe::DIR_IMPORT)
        .filter(|d| d.virtual_address != 0)
        .map(|d| pe::parse_imports(&data, d.virtual_address, &sections, opt.is_pe32_plus()))
        .unwrap_or_default();

    let exports = opt
        .data_directories
        .get(pe::DIR_EXPORT)
        .filter(|d| d.virtual_address != 0)
        .and_then(|d| pe::parse_exports(&data, d.virtual_address, &sections));

    let tls = opt
        .data_directories
        .get(pe::DIR_TLS)
        .filter(|d| d.virtual_address != 0)
        .and_then(|d| {
            pe::parse_tls(
                &data,
                d.virtual_address,
                &sections,
                opt.image_base,
                opt.is_pe32_plus(),
            )
        });

    let overlay_info = overlay::detect_overlay(&data, &sections);

    let extracted_strings = strings::extract_all(&data);

    // Skip headers to avoid false MZ/PE hits, then re-anchor offsets.
    let scan_start = patterns::first_section_offset(&sections).min(data.len());
    let pattern_hits_raw = patterns::scan_all(&data[scan_start..], &patterns::builtin_patterns());
    let pattern_hits: Vec<patterns::PatternHit> = pattern_hits_raw
        .into_iter()
        .map(|mut h| {
            h.offset += scan_start;
            h
        })
        .collect();

    let mut file_hashes = hashes::compute(&data, &imports);
    file_hashes.authentihash = hashes::authentihash_sha256(&data, &opt, &sections, pe_offset);

    let signature = authenticode::analyze(&data, &opt);

    let loldrivers_match = lol_db.and_then(|db| {
        db.lookup(
            &file_hashes.sha256,
            file_hashes.authentihash.as_deref(),
            file_hashes.imphash.as_deref(),
        )
    });

    let triage = rules::analyze(
        &coff,
        &opt,
        &sections,
        &imports,
        &data,
        tls.as_ref(),
        overlay_info.as_ref(),
        &pattern_hits,
        loldrivers_match.as_ref(),
    );

    Ok(Analysis {
        data,
        dos,
        coff,
        opt,
        sections,
        imports,
        exports,
        tls,
        overlay: overlay_info,
        extracted_strings,
        pattern_hits,
        file_hashes,
        signature,
        loldrivers_match,
        triage,
    })
}

impl Analysis {
    pub fn to_report(&self, path: &str) -> Report {
        Report {
            file: path.to_string(),
            file_size: self.data.len(),
            md5: self.file_hashes.md5.clone(),
            sha256: self.file_hashes.sha256.clone(),
            imphash: self.file_hashes.imphash.clone(),
            authentihash: self.file_hashes.authentihash.clone(),
            machine: self.coff.machine_name().to_string(),
            pe_type: if self.opt.is_pe32_plus() {
                "PE32+"
            } else {
                "PE32"
            }
            .to_string(),
            subsystem: self.opt.subsystem_name().to_string(),
            entry_point: format!("0x{:08X}", self.opt.address_of_entry_point),
            image_base: format!("0x{:016X}", self.opt.image_base),
            characteristics: self
                .coff
                .characteristics_list()
                .into_iter()
                .map(String::from)
                .collect(),
            dll_characteristics: self
                .opt
                .dll_characteristics_list()
                .into_iter()
                .map(String::from)
                .collect(),
            signature: ReportSignature::from(&self.signature),
            sections: self
                .sections
                .iter()
                .map(|s| {
                    let ent = entropy::shannon_entropy(s.raw_data(&self.data));
                    ReportSection {
                        name: s.name.clone(),
                        virtual_size: s.virtual_size,
                        virtual_address: format!("0x{:08X}", s.virtual_address),
                        raw_size: s.size_of_raw_data,
                        permissions: s.permissions_string(),
                        entropy: (ent * 10000.0).round() / 10000.0,
                        entropy_label: entropy::entropy_label(ent).to_string(),
                    }
                })
                .collect(),
            imports: self
                .imports
                .iter()
                .map(|i| ReportImport {
                    dll: i.dll_name.clone(),
                    functions: i.functions.clone(),
                })
                .collect(),
            export_count: self.exports.as_ref().map_or(0, |e| e.functions.len()),
            tls_callbacks: self.tls.as_ref().map(|t| {
                t.callbacks
                    .iter()
                    .map(|va| format!("0x{va:016X}"))
                    .collect()
            }),
            overlay: self.overlay.as_ref().map(|o| ReportOverlay {
                offset: o.offset,
                size: o.size,
                entropy: o.entropy,
                entropy_label: o.entropy_label.clone(),
            }),
            string_count: self.extracted_strings.len(),
            interesting_strings: filter_interesting(&self.extracted_strings),
            pattern_hits: self
                .pattern_hits
                .iter()
                .map(|h| ReportPatternHit {
                    pattern: h.pattern.to_string(),
                    severity: h.severity,
                    offset: format!("0x{:08X}", h.offset),
                    description: h.description.to_string(),
                })
                .collect(),
            loldrivers_match: self
                .loldrivers_match
                .as_ref()
                .map(ReportLolDriversMatch::from),
            triage: self.triage.clone(),
        }
    }
}
