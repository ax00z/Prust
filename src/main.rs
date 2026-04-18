mod batch;
mod entropy;
mod overlay;
mod patterns;
#[allow(dead_code)]
mod pe;
mod rules;
mod strings;

use clap::Parser;
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

/// Maximum file size we'll load into memory (256 MB).
/// PE files larger than this are almost certainly not real executables,
/// or are too large for in-memory analysis to be practical.
const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "prust",
    version,
    about = "PE static analyzer — parse and triage PE files"
)]
struct Cli {
    /// Path to a PE file, or a directory to recursively scan
    file: String,

    /// Output results as JSON
    #[arg(long)]
    json: bool,

    /// Only show the triage result (skip full header dump)
    #[arg(long)]
    triage_only: bool,
}

#[derive(Serialize)]
struct JsonReport {
    file: String,
    file_size: usize,
    machine: String,
    pe_type: String,
    subsystem: String,
    entry_point: String,
    image_base: String,
    characteristics: Vec<String>,
    dll_characteristics: Vec<String>,
    sections: Vec<JsonSection>,
    imports: Vec<JsonImport>,
    export_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_callbacks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    overlay: Option<JsonOverlay>,
    string_count: usize,
    interesting_strings: Vec<String>,
    pattern_hits: Vec<JsonPatternHit>,
    triage: rules::TriageResult,
}

#[derive(Serialize)]
struct JsonPatternHit {
    pattern: &'static str,
    severity: u32,
    offset: String,
    description: &'static str,
}

#[derive(Serialize)]
struct JsonOverlay {
    offset: usize,
    size: usize,
    entropy: f64,
    entropy_label: String,
}

#[derive(Serialize)]
struct JsonSection {
    name: String,
    virtual_size: u32,
    virtual_address: String,
    raw_size: u32,
    permissions: String,
    entropy: f64,
    entropy_label: String,
}

#[derive(Serialize)]
struct JsonImport {
    dll: String,
    functions: Vec<String>,
}

/// Patterns that are interesting in a malware triage context.
/// These cover C2 infrastructure, persistence mechanisms, shell commands,
/// credential access, and other suspicious indicators.
const INTERESTING_PATTERNS: &[&str] = &[
    "http://", "https://", "ftp://",
    "cmd.exe", "powershell", "wscript", "cscript", "mshta",
    "HKLM\\", "HKCU\\", "CurrentVersion\\Run",
    "\\AppData\\", "\\Temp\\", "\\System32\\",
    ".dll", ".exe", ".bat", ".ps1", ".vbs",
    "password", "credential", "token", "secret",
    "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
    "NtUnmapViewOfSection", "IsDebuggerPresent",
    "socket", "connect", "recv", "send",
    "SELECT ", "INSERT ", "DELETE ", "DROP ",
];

/// Maximum number of interesting strings to include in output.
/// Keeps the report focused — analysts don't want to scroll through 500 strings.
const MAX_INTERESTING_STRINGS: usize = 100;

/// Filter extracted strings down to those matching suspicious patterns.
fn filter_interesting(strings: &[strings::ExtractedString]) -> Vec<String> {
    let mut result = Vec::new();
    for s in strings {
        // `to_ascii_lowercase()` returns a new String with ASCII characters
        // lowered. We use this instead of `to_lowercase()` because we only
        // care about ASCII patterns, and the ASCII version is faster (no
        // Unicode case folding tables).
        let lower = s.value.to_ascii_lowercase();
        for pattern in INTERESTING_PATTERNS {
            if lower.contains(&pattern.to_ascii_lowercase()) {
                result.push(format!("0x{:08X} [{}] {}", s.offset, s.encoding, s.value));
                break; // One match is enough — don't duplicate the string
            }
        }
        if result.len() >= MAX_INTERESTING_STRINGS {
            break;
        }
    }
    result
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// All real logic lives here so errors propagate with `?` instead of `process::exit`.
fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let path = &cli.file;

    // Directory mode: recursively scan and print a summary table.
    // We check this BEFORE the size check because directories have no
    // meaningful `len()` and we want different code paths entirely.
    let meta_check = fs::metadata(path)
        .map_err(|e| format!("cannot stat {path}: {e}"))?;
    if meta_check.is_dir() {
        let mut entries = batch::scan_directory(Path::new(path));
        batch::print_summary(&mut entries);
        return Ok(());
    }

    // Check file size before reading into memory.
    let metadata = meta_check;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(format!(
            "{path} is {} bytes — exceeds {} byte limit",
            metadata.len(),
            MAX_FILE_SIZE
        ).into());
    }

    let data = fs::read(path)
        .map_err(|e| format!("cannot read {path}: {e}"))?;

    // ── Parse all structures ──
    let dos = pe::DosHeader::parse(&data)?;
    let pe_offset = dos.e_lfanew as usize;
    let coff = pe::CoffHeader::parse(&data, pe_offset)?;
    let opt_offset = pe_offset + 24;
    let opt = pe::OptionalHeader::parse(&data, opt_offset)?;

    let sec_offset = pe::section_table_offset(pe_offset, coff.size_of_optional_header);
    let sections = pe::SectionHeader::parse_all(&data, sec_offset, coff.number_of_sections)?;

    let imports = opt.data_directories.get(pe::DIR_IMPORT)
        .filter(|d| d.virtual_address != 0)
        .map(|d| pe::parse_imports(&data, d.virtual_address, &sections, opt.is_pe32_plus()))
        .unwrap_or_default();

    let exports = opt.data_directories.get(pe::DIR_EXPORT)
        .filter(|d| d.virtual_address != 0)
        .and_then(|d| pe::parse_exports(&data, d.virtual_address, &sections));

    let tls = opt.data_directories.get(pe::DIR_TLS)
        .filter(|d| d.virtual_address != 0)
        .and_then(|d| pe::parse_tls(&data, d.virtual_address, &sections, opt.image_base, opt.is_pe32_plus()));

    let overlay_info = overlay::detect_overlay(&data, &sections);

    let extracted_strings = strings::extract_all(&data);

    // Scan patterns from the first section onward to avoid false-positive
    // MZ/PE hits in the loader's own header region.
    let scan_start = patterns::first_section_offset(&sections).min(data.len());
    let pattern_hits = patterns::scan_all(&data[scan_start..], &patterns::builtin_patterns());
    // Adjust hit offsets back to absolute file offsets.
    let pattern_hits: Vec<patterns::PatternHit> = pattern_hits
        .into_iter()
        .map(|mut h| {
            h.offset += scan_start;
            h
        })
        .collect();

    let triage = rules::analyze(&coff, &opt, &sections, &imports, &data,
        tls.as_ref(), overlay_info.as_ref(), &pattern_hits);

    // ── Output ──
    if cli.json {
        print_json(path, &data, &coff, &opt, &sections, &imports, exports.as_ref(),
            tls.as_ref(), overlay_info.as_ref(), &extracted_strings, &pattern_hits, triage)?;
    } else {
        print_text(path, &data, &dos, &coff, &opt, &sections, &imports, exports.as_ref(),
            tls.as_ref(), overlay_info.as_ref(), &extracted_strings, &pattern_hits, &triage, cli.triage_only);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_json(
    path: &str,
    data: &[u8],
    coff: &pe::CoffHeader,
    opt: &pe::OptionalHeader,
    sections: &[pe::SectionHeader],
    imports: &[pe::ImportEntry],
    exports: Option<&pe::ExportInfo>,
    tls: Option<&pe::TlsInfo>,
    overlay_info: Option<&overlay::OverlayInfo>,
    extracted_strings: &[strings::ExtractedString],
    pattern_hits: &[patterns::PatternHit],
    triage: rules::TriageResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = JsonReport {
        file: path.to_string(),
        file_size: data.len(),
        machine: coff.machine_name().to_string(),
        pe_type: if opt.is_pe32_plus() { "PE32+" } else { "PE32" }.to_string(),
        subsystem: opt.subsystem_name().to_string(),
        entry_point: format!("0x{:08X}", opt.address_of_entry_point),
        image_base: format!("0x{:016X}", opt.image_base),
        characteristics: coff.characteristics_list().into_iter().map(String::from).collect(),
        dll_characteristics: opt.dll_characteristics_list().into_iter().map(String::from).collect(),
        sections: sections.iter().map(|s| {
            let ent = entropy::shannon_entropy(s.raw_data(data));
            JsonSection {
                name: s.name.clone(),
                virtual_size: s.virtual_size,
                virtual_address: format!("0x{:08X}", s.virtual_address),
                raw_size: s.size_of_raw_data,
                permissions: s.permissions_string(),
                entropy: (ent * 10000.0).round() / 10000.0,
                entropy_label: entropy::entropy_label(ent).to_string(),
            }
        }).collect(),
        imports: imports.iter().map(|i| JsonImport {
            dll: i.dll_name.clone(),
            functions: i.functions.clone(),
        }).collect(),
        export_count: exports.map_or(0, |e| e.functions.len()),
        tls_callbacks: tls.map(|t| {
            t.callbacks.iter().map(|va| format!("0x{va:016X}")).collect()
        }),
        overlay: overlay_info.map(|o| JsonOverlay {
            offset: o.offset,
            size: o.size,
            entropy: o.entropy,
            entropy_label: o.entropy_label.clone(),
        }),
        string_count: extracted_strings.len(),
        interesting_strings: filter_interesting(extracted_strings),
        pattern_hits: pattern_hits.iter().map(|h| JsonPatternHit {
            pattern: h.pattern,
            severity: h.severity,
            offset: format!("0x{:08X}", h.offset),
            description: h.description,
        }).collect(),
        triage,
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_text(
    path: &str,
    data: &[u8],
    dos: &pe::DosHeader,
    coff: &pe::CoffHeader,
    opt: &pe::OptionalHeader,
    sections: &[pe::SectionHeader],
    imports: &[pe::ImportEntry],
    exports: Option<&pe::ExportInfo>,
    tls: Option<&pe::TlsInfo>,
    overlay_info: Option<&overlay::OverlayInfo>,
    extracted_strings: &[strings::ExtractedString],
    pattern_hits: &[patterns::PatternHit],
    triage: &rules::TriageResult,
    triage_only: bool,
) {
    println!("[*] Loaded {} ({} bytes)\n", path, data.len());

    if !triage_only {
        println!("=== DOS Header ===");
        println!("  e_magic:  0x{:04X} (MZ)", dos.e_magic);
        println!("  e_lfanew: 0x{:08X} (PE header at byte {})", dos.e_lfanew, dos.e_lfanew);

        println!("\n=== COFF Header ===");
        println!("  Machine:            0x{:04X} ({})", coff.machine, coff.machine_name());
        println!("  Sections:           {}", coff.number_of_sections);
        println!("  TimeDateStamp:      0x{:08X}", coff.time_date_stamp);
        println!("  SizeOfOptionalHdr:  {}", coff.size_of_optional_header);
        println!("  Characteristics:    0x{:04X} [{}]",
            coff.characteristics, coff.characteristics_list().join(", "));

        println!("\n=== Optional Header ===");
        println!("  Magic:              0x{:04X} ({})", opt.magic,
            if opt.is_pe32_plus() { "PE32+ (64-bit)" } else { "PE32 (32-bit)" });
        println!("  Linker:             {}.{}", opt.major_linker_version, opt.minor_linker_version);
        println!("  EntryPoint:         0x{:08X}", opt.address_of_entry_point);
        println!("  ImageBase:          0x{:016X}", opt.image_base);
        println!("  SectionAlignment:   0x{:08X}", opt.section_alignment);
        println!("  FileAlignment:      0x{:08X}", opt.file_alignment);
        println!("  SizeOfImage:        0x{:08X} ({} bytes)", opt.size_of_image, opt.size_of_image);
        println!("  SizeOfHeaders:      0x{:08X}", opt.size_of_headers);
        println!("  Checksum:           0x{:08X}", opt.checksum);
        println!("  Subsystem:          {} ({})", opt.subsystem, opt.subsystem_name());
        println!("  DllCharacteristics: 0x{:04X} [{}]",
            opt.dll_characteristics, opt.dll_characteristics_list().join(", "));

        println!("\n=== Data Directories ===");
        for (i, dd) in opt.data_directories.iter().enumerate() {
            if dd.virtual_address != 0 || dd.size != 0 {
                println!("  [{:2}] {:<20} RVA=0x{:08X}  Size=0x{:08X}",
                    i, pe::dir_name(i), dd.virtual_address, dd.size);
            }
        }

        println!("\n=== Sections ({}) ===", sections.len());
        println!("  {:<10} {:>10} {:>10} {:>10} {:>10}  {:<5}  {:>7}  Label",
            "Name", "VirtSize", "VirtAddr", "RawSize", "RawPtr", "Perms", "Entropy");
        println!("  {}", "-".repeat(95));
        for sec in sections {
            let ent = entropy::shannon_entropy(sec.raw_data(data));
            println!("  {:<10} 0x{:08X} 0x{:08X} 0x{:08X} 0x{:08X}  {:<5}  {:>7.4}  {}",
                sec.name, sec.virtual_size, sec.virtual_address,
                sec.size_of_raw_data, sec.pointer_to_raw_data,
                sec.permissions_string(), ent, entropy::entropy_label(ent));
        }

        println!("\n=== Imports ({} DLLs) ===", imports.len());
        for imp in imports {
            println!("  {} ({} functions)", imp.dll_name, imp.functions.len());
            for func in &imp.functions {
                println!("    - {}", func);
            }
        }

        if let Some(exp) = exports {
            println!("\n=== Exports ({}) ===", exp.functions.len());
            println!("  DLL Name: {}", exp.dll_name);
            for func in &exp.functions {
                println!("    - {}", func);
            }
        }

        if let Some(tls_info) = tls {
            println!("\n=== TLS Callbacks ({}) ===", tls_info.callbacks.len());
            for (i, va) in tls_info.callbacks.iter().enumerate() {
                println!("  [{}] 0x{:016X}", i, va);
            }
        }

        if let Some(ov) = overlay_info {
            println!("\n=== Overlay ===");
            println!("  Offset:   0x{:08X} (byte {})", ov.offset, ov.offset);
            println!("  Size:     {} bytes", ov.size);
            println!("  Entropy:  {:.4} ({})", ov.entropy, ov.entropy_label);
        }

        let interesting = filter_interesting(extracted_strings);
        println!("\n=== Strings ({} total, {} interesting) ===",
            extracted_strings.len(), interesting.len());
        for s in &interesting {
            println!("  {s}");
        }

        if !pattern_hits.is_empty() {
            println!("\n=== Pattern Hits ({}) ===", pattern_hits.len());
            for h in pattern_hits {
                println!("  0x{:08X} [{:>2}] {}: {}",
                    h.offset, h.severity, h.pattern, h.description);
            }
        }
    }

    println!("\n=== Triage Analysis ===");
    println!("  Score:   {}/100+", triage.score);
    println!("  Verdict: {}", triage.verdict);

    if triage.findings.is_empty() {
        println!("  No suspicious findings.");
    } else {
        println!("\n  Findings:");
        for f in &triage.findings {
            println!("    [{:>2}] {}: {}", f.severity, f.rule, f.description);
        }
    }
}
