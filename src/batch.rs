// Recursive directory scan; PE detection by DOS magic, not extension.

use crate::hashes;
use crate::loldrivers::LolDriversDb;
use crate::patterns;
use crate::pe;
use crate::rules;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
const DOS_MAGIC: [u8; 2] = [0x4D, 0x5A];
const MAX_DEPTH: usize = 16;
const MAX_FILES: usize = 10_000;

#[derive(Debug)]
pub struct BatchEntry {
    pub path: PathBuf,
    pub result: BatchResult,
}

#[derive(Debug)]
pub enum BatchResult {
    Ok(rules::TriageResult),
    NotPe,
    TooLarge(u64),
    IoError(String),
    ParseError(String),
}

#[derive(Debug, Serialize)]
pub struct BatchReport {
    pub scanned: usize,
    pub pe_files_analyzed: usize,
    pub errors: usize,
    pub entries: Vec<BatchReportEntry>,
}

#[derive(Debug, Serialize)]
pub struct BatchReportEntry {
    pub path: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_finding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triage: Option<rules::TriageResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn scan_directory(dir: &Path, lol_db: Option<&LolDriversDb>) -> Vec<BatchEntry> {
    let mut entries = Vec::new();
    walk(dir, 0, lol_db, &mut entries);
    entries
}

fn walk(dir: &Path, depth: usize, lol_db: Option<&LolDriversDb>, entries: &mut Vec<BatchEntry>) {
    if depth >= MAX_DEPTH || entries.len() >= MAX_FILES {
        return;
    }

    let Ok(read) = fs::read_dir(dir) else {
        return;
    };

    for entry in read.flatten() {
        if entries.len() >= MAX_FILES {
            return;
        }

        let path = entry.path();

        let Ok(ft) = entry.file_type() else { continue };

        if ft.is_dir() {
            walk(&path, depth + 1, lol_db, entries);
        } else if ft.is_file()
            && let Some(result) = analyze_one(&path, lol_db)
        {
            entries.push(BatchEntry { path, result });
        }
    }
}

fn analyze_one(path: &Path, lol_db: Option<&LolDriversDb>) -> Option<BatchResult> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return Some(BatchResult::IoError(e.to_string())),
    };

    let size = meta.len();
    if size < 2 {
        return None;
    }
    if size > MAX_FILE_SIZE {
        return check_magic_only(path).map(|is_pe| {
            if is_pe {
                BatchResult::TooLarge(size)
            } else {
                BatchResult::NotPe
            }
        });
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return Some(BatchResult::IoError(e.to_string())),
    };

    if data.len() < 2 || data[0..2] != DOS_MAGIC {
        return None;
    }

    Some(run_triage(&data, lol_db))
}

fn check_magic_only(path: &Path) -> Option<bool> {
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let mut buf = [0u8; 2];
    file.read_exact(&mut buf).ok()?;
    Some(buf == DOS_MAGIC)
}

fn run_triage(data: &[u8], lol_db: Option<&LolDriversDb>) -> BatchResult {
    let dos = match pe::DosHeader::parse(data) {
        Ok(d) => d,
        Err(e) => return BatchResult::ParseError(e.to_string()),
    };
    let pe_offset = dos.e_lfanew as usize;

    let coff = match pe::CoffHeader::parse(data, pe_offset) {
        Ok(c) => c,
        Err(e) => return BatchResult::ParseError(e.to_string()),
    };

    let opt_offset = pe_offset + 24;
    let opt = match pe::OptionalHeader::parse(data, opt_offset, coff.size_of_optional_header) {
        Ok(o) => o,
        Err(e) => return BatchResult::ParseError(e.to_string()),
    };

    let sec_offset = pe::section_table_offset(pe_offset, coff.size_of_optional_header);
    let sections = match pe::SectionHeader::parse_all(data, sec_offset, coff.number_of_sections) {
        Ok(s) => s,
        Err(e) => return BatchResult::ParseError(e.to_string()),
    };

    let imports = opt
        .data_directories
        .get(pe::DIR_IMPORT)
        .filter(|d| d.virtual_address != 0)
        .map(|d| pe::parse_imports(data, d.virtual_address, &sections, opt.is_pe32_plus()))
        .unwrap_or_default();

    let tls = opt
        .data_directories
        .get(pe::DIR_TLS)
        .filter(|d| d.virtual_address != 0)
        .and_then(|d| {
            pe::parse_tls(
                data,
                d.virtual_address,
                &sections,
                opt.image_base,
                opt.is_pe32_plus(),
            )
        });

    let overlay_info = crate::overlay::detect_overlay(data, &sections);

    let scan_start = patterns::first_section_offset(&sections).min(data.len());
    let raw_hits = patterns::scan_all(&data[scan_start..], &patterns::builtin_patterns());
    let pattern_hits: Vec<patterns::PatternHit> = raw_hits
        .into_iter()
        .map(|mut h| {
            h.offset += scan_start;
            h
        })
        .collect();

    let loldrivers_match = lol_db.and_then(|db| {
        let mut file_hashes = hashes::compute(data, &imports);
        file_hashes.authentihash = hashes::authentihash_sha256(data, &opt, &sections, pe_offset);
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
        data,
        tls.as_ref(),
        overlay_info.as_ref(),
        &pattern_hits,
        loldrivers_match.as_ref(),
    );
    BatchResult::Ok(triage)
}

/// Sort descending by score (worst first).
pub fn sort_by_risk(entries: &mut [BatchEntry]) {
    entries.sort_by(|a, b| {
        let score_a = match &a.result {
            BatchResult::Ok(t) => t.score,
            _ => 0,
        };
        let score_b = match &b.result {
            BatchResult::Ok(t) => t.score,
            _ => 0,
        };
        score_b.cmp(&score_a)
    });
}

pub fn to_report(entries: &[BatchEntry]) -> BatchReport {
    let pe_files_analyzed = entries
        .iter()
        .filter(|e| matches!(e.result, BatchResult::Ok(_)))
        .count();
    let errors = entries.len() - pe_files_analyzed;

    let entries = entries
        .iter()
        .map(|entry| {
            let path = entry.path.display().to_string();
            match &entry.result {
                BatchResult::Ok(t) => BatchReportEntry {
                    path,
                    status: "ok",
                    score: Some(t.score),
                    verdict: Some(t.verdict),
                    top_finding: t.findings.first().map(|f| f.rule.to_string()),
                    triage: Some(t.clone()),
                    size: None,
                    error: None,
                },
                BatchResult::NotPe => BatchReportEntry {
                    path,
                    status: "not_pe",
                    score: None,
                    verdict: None,
                    top_finding: None,
                    triage: None,
                    size: None,
                    error: None,
                },
                BatchResult::TooLarge(size) => BatchReportEntry {
                    path,
                    status: "too_large",
                    score: None,
                    verdict: None,
                    top_finding: None,
                    triage: None,
                    size: Some(*size),
                    error: None,
                },
                BatchResult::IoError(msg) => BatchReportEntry {
                    path,
                    status: "io_error",
                    score: None,
                    verdict: None,
                    top_finding: None,
                    triage: None,
                    size: None,
                    error: Some(msg.clone()),
                },
                BatchResult::ParseError(msg) => BatchReportEntry {
                    path,
                    status: "parse_error",
                    score: None,
                    verdict: None,
                    top_finding: None,
                    triage: None,
                    size: None,
                    error: Some(msg.clone()),
                },
            }
        })
        .collect();

    BatchReport {
        scanned: pe_files_analyzed + errors,
        pe_files_analyzed,
        errors,
        entries,
    }
}

pub fn print_summary(entries: &mut [BatchEntry]) {
    sort_by_risk(entries);

    let pe_count = entries
        .iter()
        .filter(|e| matches!(e.result, BatchResult::Ok(_)))
        .count();
    let error_count = entries.len() - pe_count;

    println!("=== Batch Scan Summary ===");
    println!("  PE files analyzed: {pe_count}");
    println!("  Errors:            {error_count}");
    println!();

    if entries.is_empty() {
        println!("  No PE files found.");
        return;
    }

    println!(
        "  {:>5}  {:<12}  {:<40}  Path",
        "Score", "Verdict", "Top Finding"
    );
    println!("  {}", "-".repeat(100));

    for entry in entries.iter() {
        let path_str = entry.path.display().to_string();
        let path_display = if path_str.len() > 60 {
            format!("...{}", &path_str[path_str.len() - 57..])
        } else {
            path_str
        };

        match &entry.result {
            BatchResult::Ok(t) => {
                let top = t.findings.first().map_or("-".to_string(), |f| {
                    if f.rule.len() > 38 {
                        f.rule[..38].to_string()
                    } else {
                        f.rule.to_string()
                    }
                });
                println!(
                    "  {:>5}  {:<12}  {:<40}  {}",
                    t.score, t.verdict, top, path_display
                );
            }
            BatchResult::NotPe => {
                println!(
                    "  {:>5}  {:<12}  {:<40}  {}",
                    "-", "NOT PE", "", path_display
                );
            }
            BatchResult::TooLarge(size) => {
                println!(
                    "  {:>5}  {:<12}  {:<40}  {}",
                    "-",
                    "TOO LARGE",
                    format!("{size} bytes"),
                    path_display
                );
            }
            BatchResult::IoError(msg) => {
                let truncated = if msg.len() > 38 { &msg[..38] } else { msg };
                println!(
                    "  {:>5}  {:<12}  {:<40}  {}",
                    "-", "IO ERROR", truncated, path_display
                );
            }
            BatchResult::ParseError(msg) => {
                let truncated = if msg.len() > 38 { &msg[..38] } else { msg };
                println!(
                    "  {:>5}  {:<12}  {:<40}  {}",
                    "-", "PARSE ERROR", truncated, path_display
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_mz_but_invalid_pe() -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[0x3C] = 0xFF;
        data[0x3D] = 0xFF;
        data
    }

    #[test]
    fn walk_skips_non_pe_files() {
        let tmp = std::env::temp_dir().join("prust_test_walk_non_pe");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let mut f = fs::File::create(tmp.join("readme.txt")).unwrap();
        f.write_all(b"hello world this is not a PE file").unwrap();

        let entries = scan_directory(&tmp, None);
        assert!(entries.is_empty());

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn walk_reports_malformed_pe_as_parse_error() {
        let tmp = std::env::temp_dir().join("prust_test_walk_malformed");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let mut f = fs::File::create(tmp.join("fake.exe")).unwrap();
        f.write_all(&make_mz_but_invalid_pe()).unwrap();

        let entries = scan_directory(&tmp, None);
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].result, BatchResult::ParseError(_)));

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn walk_recurses_into_subdirectories() {
        let tmp = std::env::temp_dir().join("prust_test_walk_recurse");
        let _ = fs::remove_dir_all(&tmp);
        let sub = tmp.join("nested").join("deep");
        fs::create_dir_all(&sub).unwrap();

        let mut f = fs::File::create(sub.join("payload.exe")).unwrap();
        f.write_all(&make_mz_but_invalid_pe()).unwrap();

        let entries = scan_directory(&tmp, None);
        assert_eq!(entries.len(), 1);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn walk_handles_empty_directory() {
        let tmp = std::env::temp_dir().join("prust_test_walk_empty");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let entries = scan_directory(&tmp, None);
        assert!(entries.is_empty());

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn walk_handles_nonexistent_directory() {
        let path = PathBuf::from("definitely_does_not_exist_prust_xyz_12345");
        let entries = scan_directory(&path, None);
        assert!(entries.is_empty());
    }

    #[test]
    fn report_projects_parse_errors() {
        let entries = vec![BatchEntry {
            path: PathBuf::from("bad.exe"),
            result: BatchResult::ParseError("bad PE signature".to_string()),
        }];

        let report = to_report(&entries);

        assert_eq!(report.scanned, 1);
        assert_eq!(report.pe_files_analyzed, 0);
        assert_eq!(report.errors, 1);
        assert_eq!(report.entries[0].status, "parse_error");
        assert_eq!(report.entries[0].error.as_deref(), Some("bad PE signature"));
    }
}
