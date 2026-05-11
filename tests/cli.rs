use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn prust() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_prust"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("prust_cli_{name}_{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn put_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn minimal_pe32_plus() -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    let pe_offset = 0x80;
    let coff_offset = pe_offset + 4;
    let opt_offset = pe_offset + 24;
    let opt_size = 240u16;
    let section_offset = pe_offset + 24 + opt_size as usize;

    data[0] = b'M';
    data[1] = b'Z';
    put_u32(&mut data, 0x3C, pe_offset as u32);

    data[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    put_u16(&mut data, coff_offset, 0x8664);
    put_u16(&mut data, coff_offset + 2, 1);
    put_u16(&mut data, coff_offset + 16, opt_size);
    put_u16(&mut data, coff_offset + 18, 0x0022);

    put_u16(&mut data, opt_offset, 0x20B);
    data[opt_offset + 2] = 14;
    put_u32(&mut data, opt_offset + 4, 0x200);
    put_u32(&mut data, opt_offset + 16, 0x1000);
    put_u64(&mut data, opt_offset + 24, 0x0000_0001_4000_0000);
    put_u32(&mut data, opt_offset + 32, 0x1000);
    put_u32(&mut data, opt_offset + 36, 0x200);
    put_u16(&mut data, opt_offset + 40, 6);
    put_u32(&mut data, opt_offset + 56, 0x2000);
    put_u32(&mut data, opt_offset + 60, 0x200);
    put_u16(&mut data, opt_offset + 68, 3);
    put_u16(&mut data, opt_offset + 70, 0x0140);
    put_u32(&mut data, opt_offset + 108, 16);

    data[section_offset..section_offset + 8].copy_from_slice(b".text\0\0\0");
    put_u32(&mut data, section_offset + 8, 0x1000);
    put_u32(&mut data, section_offset + 12, 0x1000);
    put_u32(&mut data, section_offset + 16, 0x200);
    put_u32(&mut data, section_offset + 20, 0x200);
    put_u32(&mut data, section_offset + 36, 0x6000_0020);

    data[0x200..0x210].copy_from_slice(b"hello from .text");
    data
}

fn set_data_directory(data: &mut [u8], index: usize, rva: u32, size: u32) {
    let opt_offset = 0x80 + 24;
    let dir_offset = opt_offset + 112 + index * 8;
    put_u32(data, dir_offset, rva);
    put_u32(data, dir_offset + 4, size);
}

fn write_c_string(data: &mut [u8], offset: usize, value: &str) {
    data[offset..offset + value.len()].copy_from_slice(value.as_bytes());
    data[offset + value.len()] = 0;
}

fn pe_with_exports_tls_and_overlay() -> Vec<u8> {
    let mut data = minimal_pe32_plus();
    let image_base = 0x0000_0001_4000_0000u64;

    set_data_directory(&mut data, 0, 0x1100, 0x80);
    set_data_directory(&mut data, 9, 0x1180, 0x28);

    let export_offset = 0x300;
    put_u32(&mut data, export_offset + 12, 0x1130);
    put_u32(&mut data, export_offset + 20, 2);
    put_u32(&mut data, export_offset + 24, 2);
    put_u32(&mut data, export_offset + 32, 0x1140);

    write_c_string(&mut data, 0x330, "fixture.dll");
    put_u32(&mut data, 0x340, 0x1150);
    put_u32(&mut data, 0x344, 0x1160);
    write_c_string(&mut data, 0x350, "FirstExport");
    write_c_string(&mut data, 0x360, "SecondExport");

    let tls_offset = 0x380;
    put_u64(&mut data, tls_offset + 0x18, image_base + 0x11B0);
    put_u64(&mut data, 0x3B0, image_base + 0x1010);
    put_u64(&mut data, 0x3B8, 0);

    data.extend_from_slice(&[0xA5; 32]);
    data
}

fn malformed_mz() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[0] = b'M';
    data[1] = b'Z';
    put_u32(&mut data, 0x3C, 0xFFFF);
    data
}

fn run(args: &[&str]) -> Output {
    Command::new(prust())
        .args(args)
        .output()
        .expect("run prust")
}

#[test]
fn json_reports_core_fields_for_single_pe() {
    let dir = temp_dir("single_json");
    let sample = dir.join("sample.exe");
    fs::write(&sample, minimal_pe32_plus()).expect("write sample");

    let out = run(&[
        sample.to_str().expect("utf-8 path"),
        "--json",
        "--no-loldrivers",
    ]);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("valid JSON report");
    assert_eq!(report["file"], sample.to_string_lossy().as_ref());
    assert_eq!(report["file_size"], 1024);
    assert_eq!(report["machine"], "AMD64");
    assert_eq!(report["pe_type"], "PE32+");
    assert_eq!(report["subsystem"], "Windows Console");
    assert_eq!(report["coff_header"]["machine_hex"], "0x8664");
    assert_eq!(report["coff_header"]["number_of_sections"], 1);
    assert_eq!(report["optional_header"]["magic"], "0x020B");
    assert_eq!(report["optional_header"]["section_alignment"], 4096);
    assert_eq!(report["data_directories"].as_array().unwrap().len(), 16);
    assert_eq!(report["signature"]["status"], "unsigned");
    assert_eq!(report["sections"][0]["name"], ".text");
    assert_eq!(report["sections"][0]["raw_pointer"], "0x00000200");
    assert_eq!(report["sections"][0]["permissions"], "R-X");
    assert_eq!(report["sections"][0]["executable"], true);
    assert_eq!(report["import_count"], 0);
    assert_eq!(report["export_count"], 0);
    assert_eq!(report["tls_callback_count"], 0);
    assert_eq!(report["triage"]["verdict"], "LOW RISK");

    fs::remove_dir_all(dir).expect("cleanup temp dir");
}

#[test]
fn json_reports_exports_tls_overlay_and_data_directories() {
    let dir = temp_dir("rich_json");
    let sample = dir.join("rich.exe");
    fs::write(&sample, pe_with_exports_tls_and_overlay()).expect("write sample");

    let out = run(&[
        sample.to_str().expect("utf-8 path"),
        "--json",
        "--no-loldrivers",
    ]);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("valid JSON report");

    assert_eq!(report["file_size"], 1056);
    assert_eq!(report["data_directories"][0]["name"], "Export");
    assert_eq!(report["data_directories"][0]["present"], true);
    assert_eq!(
        report["data_directories"][0]["virtual_address"],
        "0x00001100"
    );
    assert_eq!(report["data_directories"][9]["name"], "TLS");
    assert_eq!(report["data_directories"][9]["present"], true);
    assert_eq!(report["export_count"], 2);
    assert_eq!(report["exports"]["dll"], "fixture.dll");
    assert_eq!(report["exports"]["function_count"], 2);
    assert_eq!(report["exports"]["functions"][0], "FirstExport");
    assert_eq!(report["exports"]["functions"][1], "SecondExport");
    assert_eq!(report["tls_callback_count"], 1);
    assert_eq!(report["tls"]["callback_count"], 1);
    assert_eq!(report["tls"]["callbacks"][0], "0x0000000140001010");
    assert_eq!(report["overlay"]["offset"], 1024);
    assert_eq!(report["overlay"]["offset_hex"], "0x00000400");
    assert_eq!(report["overlay"]["size"], 32);

    fs::remove_dir_all(dir).expect("cleanup temp dir");
}

#[test]
fn triage_only_text_keeps_summary_and_skips_header_dump() {
    let dir = temp_dir("triage_text");
    let sample = dir.join("sample.exe");
    fs::write(&sample, minimal_pe32_plus()).expect("write sample");

    let out = run(&[
        sample.to_str().expect("utf-8 path"),
        "--triage-only",
        "--no-loldrivers",
    ]);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(stdout.contains("=== Hashes ==="));
    assert!(stdout.contains("=== Signature ==="));
    assert!(stdout.contains("=== Triage Analysis ==="));
    assert!(stdout.contains("NO_IMPORTS"));
    assert!(!stdout.contains("=== DOS Header ==="));
    assert!(!stdout.contains("=== Sections"));

    fs::remove_dir_all(dir).expect("cleanup temp dir");
}

#[test]
fn directory_json_reports_ok_and_parse_errors() {
    let dir = temp_dir("dir_json");
    fs::write(dir.join("ok.exe"), minimal_pe32_plus()).expect("write valid sample");
    fs::write(dir.join("bad.exe"), malformed_mz()).expect("write malformed sample");
    fs::write(dir.join("notes.txt"), b"not a PE").expect("write text file");

    let out = run(&[
        dir.to_str().expect("utf-8 path"),
        "--json",
        "--no-loldrivers",
    ]);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("valid JSON report");
    assert_eq!(report["scanned"], 2);
    assert_eq!(report["pe_files_analyzed"], 1);
    assert_eq!(report["errors"], 1);

    let entries = report["entries"].as_array().expect("entries array");
    assert!(entries.iter().any(|entry| entry["status"] == "ok"));
    assert!(entries.iter().any(|entry| entry["status"] == "parse_error"
        && entry["path"].as_str().unwrap_or("").ends_with("bad.exe")));

    fs::remove_dir_all(dir).expect("cleanup temp dir");
}

#[test]
fn malformed_single_file_returns_failure() {
    let dir = temp_dir("bad_single");
    let sample = dir.join("bad.exe");
    fs::write(&sample, malformed_mz()).expect("write malformed sample");

    let out = run(&[
        sample.to_str().expect("utf-8 path"),
        "--json",
        "--no-loldrivers",
    ]);

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("stderr is utf-8");
    assert!(stderr.contains("PE parse error"));

    fs::remove_dir_all(dir).expect("cleanup temp dir");
}
