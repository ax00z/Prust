mod entropy;
#[allow(dead_code)]
mod pe;
mod rules;

use clap::Parser;
use serde::Serialize;
use std::fs;
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
    /// Path to the PE file to analyze
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
    triage: rules::TriageResult,
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

    // Check file size before reading into memory.
    let metadata = fs::metadata(path)
        .map_err(|e| format!("cannot stat {path}: {e}"))?;
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

    let triage = rules::analyze(&coff, &opt, &sections, &imports, &data);

    // ── Output ──
    if cli.json {
        print_json(path, &data, &coff, &opt, &sections, &imports, exports.as_ref(), triage)?;
    } else {
        print_text(path, &data, &dos, &coff, &opt, &sections, &imports, exports.as_ref(), &triage, cli.triage_only);
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
        println!("  {:<10} {:>10} {:>10} {:>10} {:>10}  {:<5}  {:>7}  {}",
            "Name", "VirtSize", "VirtAddr", "RawSize", "RawPtr", "Perms", "Entropy", "Label");
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
