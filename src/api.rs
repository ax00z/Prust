//! High-level analysis pipeline. Single source of truth for the CLI, the
//! Python bindings, and any future HTTP / gRPC surface.
//!
//! Two layers live here:
//!
//! 1. [`Analysis`] — the raw parsed PE structures plus the analytical
//!    findings (strings, hashes, signature, triage). Internal consumers
//!    (the `prust` CLI's text renderer) walk these directly because they
//!    need fields that don't belong in a JSON report — DOS stub bytes,
//!    raw pointers, data-directory table, etc.
//!
//! 2. [`Report`] — a fully serializable projection of [`Analysis`].
//!    This is what `--json` emits, what Python callers receive as a dict,
//!    and what pipelines ingest. Strings and numbers only; no references.
//!
//! Callers needing only the serializable form do
//! `api::analyze_bytes(data)?.to_report(path)` and drop the Analysis.

use crate::{authenticode, entropy, hashes, overlay, patterns, pe, rules, strings};
use serde::Serialize;

// ─── Serializable report types ──────────────────────────────────────────

#[derive(Serialize, Debug, Clone)]
pub struct Report {
    pub file: String,
    pub file_size: usize,
    pub md5: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
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

// ─── Raw analysis payload ───────────────────────────────────────────────

/// Full analysis result. Owns the original file bytes so the caller
/// doesn't have to keep a parallel buffer alive for later entropy /
/// raw-data lookups.
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
    pub triage: rules::TriageResult,
}

// ─── Interesting-string filtering ───────────────────────────────────────

/// Patterns that are interesting in a malware triage context — C2 URLs,
/// persistence mechanisms, shell interpreters, credential-related terms,
/// injection API names.
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

/// Keep the report focused; analysts don't want to scroll through 500 strings.
pub const MAX_INTERESTING_STRINGS: usize = 100;

/// Filter extracted strings down to those matching suspicious patterns.
pub fn filter_interesting(strings_in: &[strings::ExtractedString]) -> Vec<String> {
    let mut result = Vec::new();
    for s in strings_in {
        // ASCII-only case fold — our patterns are ASCII, and this skips the
        // Unicode case-folding tables `to_lowercase()` would pull in.
        let lower = s.value.to_ascii_lowercase();
        for pattern in INTERESTING_PATTERNS {
            if lower.contains(&pattern.to_ascii_lowercase()) {
                result.push(format!("0x{:08X} [{}] {}", s.offset, s.encoding, s.value));
                break; // one match is enough; avoid duplicates
            }
        }
        if result.len() >= MAX_INTERESTING_STRINGS {
            break;
        }
    }
    result
}

// ─── Pipeline ───────────────────────────────────────────────────────────

/// Run the full analysis pipeline on a file's bytes.
///
/// Takes ownership of the buffer; the returned [`Analysis`] retains it so
/// downstream consumers can recompute entropy per section, re-scan strings,
/// etc. without re-reading from disk.
pub fn analyze_bytes(data: Vec<u8>) -> Result<Analysis, Box<dyn std::error::Error>> {
    let dos = pe::DosHeader::parse(&data)?;
    let pe_offset = dos.e_lfanew as usize;
    let coff = pe::CoffHeader::parse(&data, pe_offset)?;
    let opt_offset = pe_offset + 24;
    let opt = pe::OptionalHeader::parse(&data, opt_offset)?;

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

    // Scan patterns from the first section onward to avoid false-positive
    // MZ/PE hits in the loader's own header region.
    let scan_start = patterns::first_section_offset(&sections).min(data.len());
    let pattern_hits_raw = patterns::scan_all(&data[scan_start..], &patterns::builtin_patterns());
    // Adjust hit offsets back to absolute file offsets.
    let pattern_hits: Vec<patterns::PatternHit> = pattern_hits_raw
        .into_iter()
        .map(|mut h| {
            h.offset += scan_start;
            h
        })
        .collect();

    let file_hashes = hashes::compute(&data, &imports);

    let signature = authenticode::analyze(&data, &opt);

    let triage = rules::analyze(
        &coff,
        &opt,
        &sections,
        &imports,
        &data,
        tls.as_ref(),
        overlay_info.as_ref(),
        &pattern_hits,
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
        triage,
    })
}

impl Analysis {
    /// Build the serializable, JSON/Python-friendly report for this analysis.
    /// Takes `path` as a separate argument because [`Analysis`] itself is
    /// path-agnostic — it's just the parsed bytes.
    pub fn to_report(&self, path: &str) -> Report {
        Report {
            file: path.to_string(),
            file_size: self.data.len(),
            md5: self.file_hashes.md5.clone(),
            sha256: self.file_hashes.sha256.clone(),
            imphash: self.file_hashes.imphash.clone(),
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
            triage: self.triage.clone(),
        }
    }
}
