use sigkill::{api, authenticode, batch, entropy, loldrivers, pe, rules};

use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod fetch;

const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "prust",
    version,
    about = "PE static analyzer; parse and triage PE files"
)]
struct Cli {
    /// PE file or directory. Required unless --update.
    file: Option<String>,

    /// Output as JSON.
    #[arg(long)]
    json: bool,

    /// Skip the full header dump.
    #[arg(long)]
    triage_only: bool,

    /// Use the LOLDrivers corpus at PATH instead of the cached one.
    #[arg(long, value_name = "PATH")]
    loldrivers: Option<PathBuf>,

    /// Skip the LOLDrivers lookup.
    #[arg(long, conflicts_with = "loldrivers")]
    no_loldrivers: bool,

    /// Refresh the cached LOLDrivers corpus and exit.
    #[arg(long)]
    update: bool,
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

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.update {
        let outcome = fetch::fetch_to_cache()?;
        eprintln!(
            "Updated LOLDrivers cache: {} ({} bytes)",
            outcome.path.display(),
            outcome.bytes
        );
        return Ok(());
    }

    let path = cli
        .file
        .as_deref()
        .ok_or("missing FILE argument (or pass --update to refresh the LOLDrivers cache)")?;

    // Resolution: --no-loldrivers > --loldrivers <path> > cached > none.
    let lol_db = if cli.no_loldrivers {
        None
    } else if let Some(p) = &cli.loldrivers {
        Some(loldrivers::LolDriversDb::load_from_path(p)?)
    } else if let Some(p) = fetch::cached_path() {
        let age = fetch::cache_age().map(fetch::human_age).unwrap_or_default();
        eprintln!("[*] Using cached LOLDrivers corpus ({age} old). Refresh with `prust --update`.");
        Some(loldrivers::LolDriversDb::load_from_path(&p)?)
    } else {
        None
    };

    // Directory mode runs before the size check (directories have no len()).
    let meta_check = fs::metadata(path).map_err(|e| format!("cannot stat {path}: {e}"))?;
    if meta_check.is_dir() {
        let mut entries = batch::scan_directory(Path::new(path), lol_db.as_ref());
        if cli.json {
            batch::sort_by_risk(&mut entries);
            let report = batch::to_report(&entries);
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            batch::print_summary(&mut entries);
        }
        return Ok(());
    }

    let metadata = meta_check;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(format!(
            "{path} is {} bytes; exceeds {} byte limit",
            metadata.len(),
            MAX_FILE_SIZE
        )
        .into());
    }

    let data = fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let analysis = api::analyze_bytes(data, lol_db.as_ref())?;

    if cli.json {
        print_json(path, &analysis)?;
    } else {
        print_text(path, &analysis, cli.triage_only);
    }

    Ok(())
}

fn print_json(path: &str, analysis: &api::Analysis) -> Result<(), Box<dyn std::error::Error>> {
    let report = analysis.to_report(path);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn print_text(path: &str, a: &api::Analysis, triage_only: bool) {
    println!("[*] Loaded {} ({} bytes)\n", path, a.data.len());

    println!("=== Hashes ===");
    println!("  MD5:          {}", a.file_hashes.md5);
    println!("  SHA256:       {}", a.file_hashes.sha256);
    match &a.file_hashes.imphash {
        Some(h) => println!("  Imphash:      {h}"),
        None => println!("  Imphash:      (no imports)"),
    }
    match &a.file_hashes.authentihash {
        Some(h) => println!("  Authentihash: {h}"),
        None => println!("  Authentihash: (could not compute)"),
    }
    println!();

    println!("=== Signature ===");
    match &a.signature {
        authenticode::SignatureStatus::Unsigned => {
            println!("  Status:  UNSIGNED");
        }
        authenticode::SignatureStatus::Malformed(err) => {
            println!("  Status:  MALFORMED");
            println!("  Error:   {err}");
        }
        authenticode::SignatureStatus::Present(p) => {
            println!("  Status:  PRESENT");
            println!("  WIN_CERT revision: 0x{:04X}", p.win_cert_revision);
            println!(
                "  WIN_CERT type:     0x{:04X} (PKCS_7_SIGNED_DATA)",
                p.win_cert_type
            );
            println!("  Blob size:         {} bytes", p.blob_size);
            println!(
                "  Content OID:       {} {}",
                p.content_type_oid,
                if p.is_signed_data {
                    "(signedData)"
                } else {
                    "(unexpected)"
                }
            );
        }
    }
    println!();

    if let Some(m) = &a.loldrivers_match {
        println!("=== LOLDrivers Match ===");
        println!("  Matched by: {}", m.kind.as_str());
        println!("  Driver ID:  {}", m.entry.id);
        println!("  Filename:   {}", m.entry.filename);
        println!("  Category:   {}", m.entry.category);
        println!(
            "  MITRE:      {}",
            m.entry.mitre_id.as_deref().unwrap_or("(none)")
        );
        if !m.entry.tags.is_empty() {
            println!("  Tags:       {}", m.entry.tags.join(", "));
        }
        println!();
    }

    if !triage_only {
        println!("=== DOS Header ===");
        println!("  e_magic:  0x{:04X} (MZ)", a.dos.e_magic);
        println!(
            "  e_lfanew: 0x{:08X} (PE header at byte {})",
            a.dos.e_lfanew, a.dos.e_lfanew
        );

        println!("\n=== COFF Header ===");
        println!(
            "  Machine:            0x{:04X} ({})",
            a.coff.machine,
            a.coff.machine_name()
        );
        println!("  Sections:           {}", a.coff.number_of_sections);
        println!("  TimeDateStamp:      0x{:08X}", a.coff.time_date_stamp);
        println!("  SizeOfOptionalHdr:  {}", a.coff.size_of_optional_header);
        println!(
            "  Characteristics:    0x{:04X} [{}]",
            a.coff.characteristics,
            a.coff.characteristics_list().join(", ")
        );

        println!("\n=== Optional Header ===");
        println!(
            "  Magic:              0x{:04X} ({})",
            a.opt.magic,
            if a.opt.is_pe32_plus() {
                "PE32+ (64-bit)"
            } else {
                "PE32 (32-bit)"
            }
        );
        println!(
            "  Linker:             {}.{}",
            a.opt.major_linker_version, a.opt.minor_linker_version
        );
        println!(
            "  EntryPoint:         0x{:08X}",
            a.opt.address_of_entry_point
        );
        println!("  ImageBase:          0x{:016X}", a.opt.image_base);
        println!("  SectionAlignment:   0x{:08X}", a.opt.section_alignment);
        println!("  FileAlignment:      0x{:08X}", a.opt.file_alignment);
        println!(
            "  SizeOfImage:        0x{:08X} ({} bytes)",
            a.opt.size_of_image, a.opt.size_of_image
        );
        println!("  SizeOfHeaders:      0x{:08X}", a.opt.size_of_headers);
        println!("  Checksum:           0x{:08X}", a.opt.checksum);
        println!(
            "  Subsystem:          {} ({})",
            a.opt.subsystem,
            a.opt.subsystem_name()
        );
        println!(
            "  DllCharacteristics: 0x{:04X} [{}]",
            a.opt.dll_characteristics,
            a.opt.dll_characteristics_list().join(", ")
        );

        println!("\n=== Data Directories ===");
        for (i, dd) in a.opt.data_directories.iter().enumerate() {
            if dd.virtual_address != 0 || dd.size != 0 {
                println!(
                    "  [{:2}] {:<20} RVA=0x{:08X}  Size=0x{:08X}",
                    i,
                    pe::dir_name(i),
                    dd.virtual_address,
                    dd.size
                );
            }
        }

        println!("\n=== Sections ({}) ===", a.sections.len());
        println!(
            "  {:<10} {:>10} {:>10} {:>10} {:>10}  {:<5}  {:>7}  Label",
            "Name", "VirtSize", "VirtAddr", "RawSize", "RawPtr", "Perms", "Entropy"
        );
        println!("  {}", "-".repeat(95));
        for sec in &a.sections {
            let ent = entropy::shannon_entropy(sec.raw_data(&a.data));
            println!(
                "  {:<10} 0x{:08X} 0x{:08X} 0x{:08X} 0x{:08X}  {:<5}  {:>7.4}  {}",
                sec.name,
                sec.virtual_size,
                sec.virtual_address,
                sec.size_of_raw_data,
                sec.pointer_to_raw_data,
                sec.permissions_string(),
                ent,
                entropy::entropy_label(ent)
            );
        }

        println!("\n=== Imports ({} DLLs) ===", a.imports.len());
        for imp in &a.imports {
            println!("  {} ({} functions)", imp.dll_name, imp.functions.len());
            for func in &imp.functions {
                println!("    - {}", func);
            }
        }

        if let Some(exp) = &a.exports {
            println!("\n=== Exports ({}) ===", exp.functions.len());
            println!("  DLL Name: {}", exp.dll_name);
            for func in &exp.functions {
                println!("    - {}", func);
            }
        }

        if let Some(tls_info) = &a.tls {
            println!("\n=== TLS Callbacks ({}) ===", tls_info.callbacks.len());
            for (i, va) in tls_info.callbacks.iter().enumerate() {
                println!("  [{}] 0x{:016X}", i, va);
            }
        }

        if let Some(ov) = &a.overlay {
            println!("\n=== Overlay ===");
            println!("  Offset:   0x{:08X} (byte {})", ov.offset, ov.offset);
            println!("  Size:     {} bytes", ov.size);
            println!("  Entropy:  {:.4} ({})", ov.entropy, ov.entropy_label);
        }

        let interesting = api::filter_interesting(&a.extracted_strings);
        println!(
            "\n=== Strings ({} total, {} interesting) ===",
            a.extracted_strings.len(),
            interesting.len()
        );
        for s in &interesting {
            println!("  {s}");
        }

        if !a.pattern_hits.is_empty() {
            println!("\n=== Pattern Hits ({}) ===", a.pattern_hits.len());
            for h in &a.pattern_hits {
                println!(
                    "  0x{:08X} [{:>2}] {}: {}",
                    h.offset, h.severity, h.pattern, h.description
                );
            }
        }
    }

    print_triage(&a.triage);
}

fn print_triage(triage: &rules::TriageResult) {
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
