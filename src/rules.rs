// rules.rs — Detection rules and suspicion scoring.
//
// Each rule checks for one suspicious trait in the parsed PE.
// A finding carries a severity (1–10) and a human-readable description.
// The triage score is the sum of all severities.

use crate::entropy;
use crate::overlay::OverlayInfo;
use crate::patterns::PatternHit;
use crate::pe::{CoffHeader, ImportEntry, OptionalHeader, SectionHeader, TlsInfo};

use serde::Serialize;

// ──────────────────────────────────────────────
// Data structures
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TriageResult {
    pub score: u32,
    pub verdict: &'static str,
    pub findings: Vec<Finding>,
}

impl TriageResult {
    pub fn verdict_from_score(score: u32) -> &'static str {
        match score {
            0..=5 => "CLEAN",
            6..=15 => "LOW RISK",
            16..=30 => "SUSPICIOUS",
            31..=50 => "HIGH RISK",
            _ => "CRITICAL",
        }
    }
}

// ──────────────────────────────────────────────
// Top-level analysis entry point
// ──────────────────────────────────────────────

/// Run all detection rules and return the aggregated triage result.
#[allow(clippy::too_many_arguments)]
pub fn analyze(
    coff: &CoffHeader,
    opt: &OptionalHeader,
    sections: &[SectionHeader],
    imports: &[ImportEntry],
    file_data: &[u8],
    tls: Option<&TlsInfo>,
    overlay: Option<&OverlayInfo>,
    pattern_hits: &[PatternHit],
) -> TriageResult {
    let mut findings = Vec::new();

    check_rwx_sections(sections, &mut findings);
    check_high_entropy_code(sections, file_data, &mut findings);
    check_suspicious_section_names(sections, &mut findings);
    check_no_imports(imports, &mut findings);
    check_few_imports(imports, &mut findings);
    check_suspicious_import_combos(imports, &mut findings);
    check_no_aslr(opt, &mut findings);
    check_no_dep(opt, &mut findings);
    check_zero_entry_point(opt, coff, &mut findings);
    check_section_size_mismatch(sections, &mut findings);
    check_executable_data_section(sections, &mut findings);
    check_tls_callbacks(tls, &mut findings);
    check_overlay(overlay, &mut findings);
    check_patterns(pattern_hits, &mut findings);

    let score: u32 = findings.iter().map(|f| f.severity).sum();
    let verdict = TriageResult::verdict_from_score(score);

    TriageResult {
        score,
        verdict,
        findings,
    }
}

// ──────────────────────────────────────────────
// Individual rules
// ──────────────────────────────────────────────

/// RWX sections: readable + writable + executable.
/// Legitimate binaries almost never need this. Packers and shellcode do.
fn check_rwx_sections(sections: &[SectionHeader], findings: &mut Vec<Finding>) {
    for sec in sections {
        if sec.is_readable() && sec.is_writable() && sec.is_executable() {
            findings.push(Finding {
                rule: "RWX_SECTION",
                severity: 8,
                description: format!(
                    "Section '{}' has Read+Write+Execute permissions (0x{:08X})",
                    sec.name, sec.characteristics
                ),
            });
        }
    }
}

/// High entropy in a code section suggests packing or encryption.
fn check_high_entropy_code(
    sections: &[SectionHeader],
    file_data: &[u8],
    findings: &mut Vec<Finding>,
) {
    for sec in sections {
        if !sec.is_executable() {
            continue;
        }
        let raw = sec.raw_data(file_data);
        if raw.is_empty() {
            continue;
        }
        let ent = entropy::shannon_entropy(raw);
        if ent > 7.0 {
            findings.push(Finding {
                rule: "HIGH_ENTROPY_CODE",
                severity: 7,
                description: format!(
                    "Executable section '{}' has very high entropy ({:.4}) — likely packed/encrypted",
                    sec.name, ent
                ),
            });
        } else if ent > 6.8 {
            findings.push(Finding {
                rule: "ELEVATED_ENTROPY_CODE",
                severity: 3,
                description: format!(
                    "Executable section '{}' has elevated entropy ({:.4})",
                    sec.name, ent
                ),
            });
        }
    }
}

/// Known packer section names (UPX, ASPack, MPRESS, etc).
const PACKER_NAMES: &[&str] = &[
    "UPX0", "UPX1", "UPX2", ".UPX", ".aspack", ".adata", "ASPack", ".nsp0", ".nsp1", ".nsp2",
    "MEW", ".perplex", ".packed", ".RLPack", "PELOCKnt", ".petite", ".yP", "WinLicen", "_winzip_",
    ".MPRESS1", ".MPRESS2",
];

/// Standard section names produced by common compilers/linkers.
const NORMAL_SECTION_NAMES: &[&str] = &[
    ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc", ".bss", ".edata", ".idata", ".tls",
    ".debug", ".CRT", ".gfids", ".00cfg", ".didat", "fothk", ".xdata", "PAGE", "INIT", ".mrdata",
];

fn check_suspicious_section_names(sections: &[SectionHeader], findings: &mut Vec<Finding>) {
    for sec in sections {
        let name = &sec.name;

        // Check for known packer section names.
        let is_packer = PACKER_NAMES.iter().any(|p| name.eq_ignore_ascii_case(p));
        if is_packer {
            findings.push(Finding {
                rule: "PACKER_SECTION_NAME",
                severity: 8,
                description: format!("Section '{}' matches known packer signature", name),
            });
            continue;
        }

        // Flag names with non-printable characters (not in normal list,
        // not dot-prefixed, non-empty).
        let is_known = NORMAL_SECTION_NAMES.iter().any(|&n| n == name);
        if !is_known && !name.starts_with('.') && !name.is_empty() {
            let has_nonprintable = name.bytes().any(|b| !(0x20..=0x7E).contains(&b));
            if has_nonprintable {
                findings.push(Finding {
                    rule: "UNUSUAL_SECTION_NAME",
                    severity: 3,
                    description: format!(
                        "Section has non-printable characters in name: {:?}",
                        name
                    ),
                });
            }
        }
    }
}

fn check_no_imports(imports: &[ImportEntry], findings: &mut Vec<Finding>) {
    if imports.is_empty() {
        findings.push(Finding {
            rule: "NO_IMPORTS",
            severity: 7,
            description: "Binary has no import table — possibly packed or statically resolved"
                .to_string(),
        });
    }
}

fn check_few_imports(imports: &[ImportEntry], findings: &mut Vec<Finding>) {
    if imports.is_empty() {
        return; // already flagged by NO_IMPORTS
    }
    let total_funcs: usize = imports.iter().map(|i| i.functions.len()).sum();
    if total_funcs > 0 && total_funcs <= 5 {
        findings.push(Finding {
            rule: "FEW_IMPORTS",
            severity: 5,
            description: format!(
                "Binary imports only {} function(s) from {} DLL(s) — possible packer stub",
                total_funcs,
                imports.len()
            ),
        });
    }
}

/// Suspicious API combinations indicating injection, evasion, or credential theft.
fn check_suspicious_import_combos(imports: &[ImportEntry], findings: &mut Vec<Finding>) {
    let all_funcs: Vec<String> = imports
        .iter()
        .flat_map(|i| i.functions.iter())
        .map(|f| f.to_lowercase())
        .collect();

    let has = |name: &str| all_funcs.iter().any(|f| f == name);

    // Classic process injection: alloc → write → execute in remote process
    if has("virtualalloc") && has("writeprocessmemory") && has("createremotethread") {
        findings.push(Finding {
            rule: "PROCESS_INJECTION_COMBO",
            severity: 9,
            description: "Imports VirtualAlloc + WriteProcessMemory + CreateRemoteThread \
                — classic process injection pattern"
                .to_string(),
        });
    }

    // Native API injection variant
    if has("writeprocessmemory") && (has("ntcreatethreadex") || has("rtlcreateuserthread")) {
        findings.push(Finding {
            rule: "NTAPI_INJECTION_COMBO",
            severity: 9,
            description: "Imports WriteProcessMemory + NtCreateThreadEx/RtlCreateUserThread \
                — native API injection"
                .to_string(),
        });
    }

    // Shellcode loading: allocate + change protection
    if has("virtualalloc") && has("virtualprotect") {
        findings.push(Finding {
            rule: "SHELLCODE_LOADING",
            severity: 5,
            description: "Imports VirtualAlloc + VirtualProtect \
                — may allocate and change memory permissions"
                .to_string(),
        });
    }

    // Credential prompt APIs
    if has("credentialpromptforwindowsa")
        || has("credentialpromptforwindowsw")
        || has("creduipromptforcredentialsa")
        || has("creduipromptforcredentialsw")
    {
        findings.push(Finding {
            rule: "CREDENTIAL_PROMPT",
            severity: 6,
            description: "Imports credential prompt APIs — may harvest credentials".to_string(),
        });
    }

    // Anti-debugging
    if has("isdebuggerpresent")
        || has("checkremotedebuggerpresent")
        || has("ntqueryinformationprocess")
    {
        findings.push(Finding {
            rule: "ANTI_DEBUG",
            severity: 4,
            description: "Imports anti-debugging APIs (IsDebuggerPresent, \
                CheckRemoteDebuggerPresent, or NtQueryInformationProcess)"
                .to_string(),
        });
    }

    // Dynamic API resolution (requires BOTH GetProcAddress AND a LoadLibrary variant)
    if has("getprocaddress") && (has("loadlibrarya") || has("loadlibraryw")) {
        findings.push(Finding {
            rule: "DYNAMIC_API_RESOLUTION",
            severity: 2,
            description: "Imports GetProcAddress + LoadLibrary \
                — may resolve APIs dynamically to hide behavior"
                .to_string(),
        });
    }
}

fn check_no_aslr(opt: &OptionalHeader, findings: &mut Vec<Finding>) {
    if !opt.has_aslr() {
        findings.push(Finding {
            rule: "NO_ASLR",
            severity: 3,
            description: "ASLR (DYNAMIC_BASE) is not enabled".to_string(),
        });
    }
}

fn check_no_dep(opt: &OptionalHeader, findings: &mut Vec<Finding>) {
    if !opt.has_dep() {
        findings.push(Finding {
            rule: "NO_DEP",
            severity: 3,
            description: "DEP (NX_COMPAT) is not enabled".to_string(),
        });
    }
}

fn check_zero_entry_point(opt: &OptionalHeader, coff: &CoffHeader, findings: &mut Vec<Finding>) {
    // DLLs can legitimately have a zero entry point.
    if opt.address_of_entry_point == 0 && !coff.is_dll() {
        findings.push(Finding {
            rule: "ZERO_ENTRY_POINT",
            severity: 5,
            description: "Entry point is 0x00000000 — unusual for an executable".to_string(),
        });
    }
}

fn check_section_size_mismatch(sections: &[SectionHeader], findings: &mut Vec<Finding>) {
    for sec in sections {
        if sec.size_of_raw_data == 0 && sec.virtual_size > 0x10000 {
            findings.push(Finding {
                rule: "EMPTY_RAW_LARGE_VIRTUAL",
                severity: 6,
                description: format!(
                    "Section '{}' has 0 raw bytes but 0x{:X} virtual bytes — unpacking target?",
                    sec.name, sec.virtual_size
                ),
            });
        } else if sec.size_of_raw_data > 0 && sec.virtual_size > sec.size_of_raw_data * 10 {
            findings.push(Finding {
                rule: "SIZE_RATIO_ANOMALY",
                severity: 4,
                description: format!(
                    "Section '{}' virtual size (0x{:X}) is >10x raw size (0x{:X})",
                    sec.name, sec.virtual_size, sec.size_of_raw_data
                ),
            });
        }
    }
}

fn check_executable_data_section(sections: &[SectionHeader], findings: &mut Vec<Finding>) {
    for sec in sections {
        let name = sec.name.to_lowercase();
        let is_data_section = name == ".data" || name == ".rdata" || name == ".bss";
        if is_data_section && sec.is_executable() {
            findings.push(Finding {
                rule: "EXECUTABLE_DATA_SECTION",
                severity: 6,
                description: format!("Data section '{}' is marked executable", sec.name),
            });
        }
    }
}

fn check_tls_callbacks(tls: Option<&TlsInfo>, findings: &mut Vec<Finding>) {
    if let Some(info) = tls {
        let count = info.callbacks.len();
        findings.push(Finding {
            rule: "TLS_CALLBACKS",
            severity: if count > 2 { 7 } else { 4 },
            description: format!(
                "Binary has {} TLS callback{} — code executes before entry point",
                count,
                if count == 1 { "" } else { "s" }
            ),
        });
    }
}

/// Large overlay with high entropy is a strong packer/dropper signal.
fn check_overlay(overlay: Option<&OverlayInfo>, findings: &mut Vec<Finding>) {
    if let Some(info) = overlay {
        if info.entropy >= 7.0 && info.size >= 4096 {
            findings.push(Finding {
                rule: "HIGH_ENTROPY_OVERLAY",
                severity: 7,
                description: format!(
                    "Overlay at offset 0x{:X} ({} bytes, entropy {:.2}) — \
                    likely packed/encrypted payload",
                    info.offset, info.size, info.entropy
                ),
            });
        } else if info.size >= 4096 {
            findings.push(Finding {
                rule: "OVERLAY_DATA",
                severity: 2,
                description: format!(
                    "File has {} bytes of overlay data at offset 0x{:X} (entropy {:.2})",
                    info.size, info.offset, info.entropy
                ),
            });
        }
    }
}

/// Each pattern hit becomes one finding. Severity and description come
/// from the pattern definition.
fn check_patterns(hits: &[PatternHit], findings: &mut Vec<Finding>) {
    for h in hits {
        findings.push(Finding {
            rule: h.pattern,
            severity: h.severity,
            description: format!("{} (offset 0x{:X})", h.description, h.offset),
        });
    }
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_import(dll_name: &str, functions: &[&str]) -> ImportEntry {
        ImportEntry {
            dll_name: dll_name.to_string(),
            functions: functions.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn make_section(name: &str, chars: u32) -> SectionHeader {
        SectionHeader {
            name: name.to_string(),
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x1000,
            pointer_to_raw_data: 0,
            characteristics: chars,
        }
    }

    // ── Verdict scoring ──

    #[test]
    fn verdict_thresholds() {
        assert_eq!(TriageResult::verdict_from_score(0), "CLEAN");
        assert_eq!(TriageResult::verdict_from_score(5), "CLEAN");
        assert_eq!(TriageResult::verdict_from_score(6), "LOW RISK");
        assert_eq!(TriageResult::verdict_from_score(15), "LOW RISK");
        assert_eq!(TriageResult::verdict_from_score(16), "SUSPICIOUS");
        assert_eq!(TriageResult::verdict_from_score(30), "SUSPICIOUS");
        assert_eq!(TriageResult::verdict_from_score(31), "HIGH RISK");
        assert_eq!(TriageResult::verdict_from_score(50), "HIGH RISK");
        assert_eq!(TriageResult::verdict_from_score(51), "CRITICAL");
    }

    // ── Import combo rules ──

    #[test]
    fn loadlibraryw_alone_does_not_trigger_dynamic_resolution() {
        let imports = vec![make_import("KERNEL32.dll", &["LoadLibraryW"])];
        let mut findings = Vec::new();
        check_suspicious_import_combos(&imports, &mut findings);
        assert!(!findings.iter().any(|f| f.rule == "DYNAMIC_API_RESOLUTION"));
    }

    #[test]
    fn getprocaddress_plus_loadlibraryw_triggers_dynamic_resolution() {
        let imports = vec![make_import(
            "KERNEL32.dll",
            &["GetProcAddress", "LoadLibraryW"],
        )];
        let mut findings = Vec::new();
        check_suspicious_import_combos(&imports, &mut findings);
        assert!(findings.iter().any(|f| f.rule == "DYNAMIC_API_RESOLUTION"));
    }

    #[test]
    fn injection_combo_triggers() {
        let imports = vec![make_import(
            "KERNEL32.dll",
            &["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
        )];
        let mut findings = Vec::new();
        check_suspicious_import_combos(&imports, &mut findings);
        assert!(findings.iter().any(|f| f.rule == "PROCESS_INJECTION_COMBO"));
    }

    #[test]
    fn injection_combo_case_insensitive() {
        let imports = vec![make_import(
            "KERNEL32.dll",
            &["virtualalloc", "WRITEPROCESSMEMORY", "createRemoteThread"],
        )];
        let mut findings = Vec::new();
        check_suspicious_import_combos(&imports, &mut findings);
        assert!(findings.iter().any(|f| f.rule == "PROCESS_INJECTION_COMBO"));
    }

    // ── Section rules ──

    #[test]
    fn rwx_section_detected() {
        let sections = vec![make_section(".text", 0xE000_0000)]; // R+W+X
        let mut findings = Vec::new();
        check_rwx_sections(&sections, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "RWX_SECTION");
    }

    #[test]
    fn rx_section_not_flagged_as_rwx() {
        let sections = vec![make_section(".text", 0x6000_0000)]; // R+X only
        let mut findings = Vec::new();
        check_rwx_sections(&sections, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn packer_section_name_detected() {
        let sections = vec![make_section("UPX0", 0)];
        let mut findings = Vec::new();
        check_suspicious_section_names(&sections, &mut findings);
        assert!(findings.iter().any(|f| f.rule == "PACKER_SECTION_NAME"));
    }

    #[test]
    fn normal_section_name_not_flagged() {
        let sections = vec![make_section(".text", 0)];
        let mut findings = Vec::new();
        check_suspicious_section_names(&sections, &mut findings);
        assert!(findings.is_empty());
    }

    // ── Mitigation rules ──

    #[test]
    fn no_aslr_detected() {
        let opt = OptionalHeader {
            magic: 0x20B,
            major_linker_version: 0,
            minor_linker_version: 0,
            size_of_code: 0,
            address_of_entry_point: 0,
            image_base: 0,
            section_alignment: 0,
            file_alignment: 0,
            major_os_version: 0,
            minor_os_version: 0,
            size_of_image: 0,
            size_of_headers: 0,
            checksum: 0,
            subsystem: 0,
            dll_characteristics: 0x0100, // DEP yes, ASLR no
            number_of_rva_and_sizes: 0,
            data_directories: vec![],
        };
        let mut findings = Vec::new();
        check_no_aslr(&opt, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "NO_ASLR");
    }

    #[test]
    fn aslr_present_not_flagged() {
        let opt = OptionalHeader {
            magic: 0x20B,
            major_linker_version: 0,
            minor_linker_version: 0,
            size_of_code: 0,
            address_of_entry_point: 0,
            image_base: 0,
            section_alignment: 0,
            file_alignment: 0,
            major_os_version: 0,
            minor_os_version: 0,
            size_of_image: 0,
            size_of_headers: 0,
            checksum: 0,
            subsystem: 0,
            dll_characteristics: 0x0140, // ASLR + DEP
            number_of_rva_and_sizes: 0,
            data_directories: vec![],
        };
        let mut findings = Vec::new();
        check_no_aslr(&opt, &mut findings);
        assert!(findings.is_empty());
    }
}
