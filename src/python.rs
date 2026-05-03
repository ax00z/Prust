//! Python bindings for the sigkill library, exported as the `prust` module.
//!
//! Built by maturin, not by `cargo build`. This module is gated on the
//! `python` feature so a plain `cargo build` of the `prust` CLI never drags
//! in `pyo3`.
//!
//! Design: each Python-facing function accepts a filesystem path, reads the
//! file, runs the relevant lib functions, and returns a plain Python dict.
//! Dicts (not PyClasses) are the right default — they drop straight into
//! pandas, Jupyter, JSON pipelines, and SIEM ingest paths, which is where
//! detection engineers and DFIR analysts actually work.

use crate::{api, authenticode, hashes, pe};
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::fs;

/// Read a file from disk; raise Python `OSError` on failure.
fn read_file(path: &str) -> PyResult<Vec<u8>> {
    fs::read(path).map_err(|e| PyOSError::new_err(format!("cannot read {path}: {e}")))
}

/// Parse just enough of a PE to expose imports for imphash. Returns an empty
/// vec on any parse failure — the caller then reports imphash=None rather
/// than raising, so `hashes()` still works on corrupt or non-PE files.
fn parse_imports_best_effort(data: &[u8]) -> Vec<pe::ImportEntry> {
    let Ok(dos) = pe::DosHeader::parse(data) else {
        return vec![];
    };
    let pe_offset = dos.e_lfanew as usize;
    let Ok(coff) = pe::CoffHeader::parse(data, pe_offset) else {
        return vec![];
    };
    let opt_offset = pe_offset + 24;
    let Ok(opt) = pe::OptionalHeader::parse(data, opt_offset, coff.size_of_optional_header) else {
        return vec![];
    };
    let sec_offset = pe::section_table_offset(pe_offset, coff.size_of_optional_header);
    let Ok(sections) = pe::SectionHeader::parse_all(data, sec_offset, coff.number_of_sections)
    else {
        return vec![];
    };
    opt.data_directories
        .get(pe::DIR_IMPORT)
        .filter(|d| d.virtual_address != 0)
        .map(|d| pe::parse_imports(data, d.virtual_address, &sections, opt.is_pe32_plus()))
        .unwrap_or_default()
}

/// Parse the PE up through the OptionalHeader; needed for the security
/// directory. Returns a human-readable error string rather than an
/// exception — the caller folds it into the returned dict.
fn parse_optional_header(data: &[u8]) -> Result<pe::OptionalHeader, String> {
    let dos = pe::DosHeader::parse(data).map_err(|e| e.to_string())?;
    let pe_offset = dos.e_lfanew as usize;
    // Parsing the COFF header validates the PE signature and magic; we
    // don't need its fields here — OptionalHeader sits at a fixed offset.
    let coff = pe::CoffHeader::parse(data, pe_offset).map_err(|e| e.to_string())?;
    let opt_offset = pe_offset + 24;
    pe::OptionalHeader::parse(data, opt_offset, coff.size_of_optional_header)
        .map_err(|e| e.to_string())
}

/// Compute MD5, SHA256, and imphash of a PE file.
///
/// Returns a dict:
///   {"md5": str, "sha256": str, "imphash": str | None, "file_size": int}
///
/// `imphash` is `None` for files without an import table (e.g. DLLs with
/// static-only exports, corrupt PEs, or non-PE files).
///
/// Renamed internally to avoid a symbol clash with the `hashes` lib module;
/// the Python-facing name is set by `#[pyo3(name = ...)]`.
#[pyfunction]
#[pyo3(name = "hashes")]
fn py_hashes(py: Python<'_>, path: &str) -> PyResult<Py<PyDict>> {
    let data = read_file(path)?;
    let imports = parse_imports_best_effort(&data);
    let h = hashes::compute(&data, &imports);

    let dict = PyDict::new(py);
    dict.set_item("md5", h.md5)?;
    dict.set_item("sha256", h.sha256)?;
    dict.set_item("imphash", h.imphash)?;
    dict.set_item("file_size", data.len())?;
    Ok(dict.unbind())
}

/// Analyze the Authenticode signature of a PE file.
///
/// Returns a dict. The `status` key is always one of:
///   - "unsigned"     — no security directory or it's empty
///   - "malformed"    — directory present but doesn't parse (adds "error")
///   - "present"      — WIN_CERTIFICATE unwrapped and PKCS#7 decoded
///                      (adds blob_size, win_cert_revision, win_cert_type,
///                       content_type_oid, is_signed_data)
///   - "parse_error"  — couldn't even get to the security directory
///                      (adds "error")
#[pyfunction]
#[pyo3(name = "signature")]
fn py_signature(py: Python<'_>, path: &str) -> PyResult<Py<PyDict>> {
    let data = read_file(path)?;
    let dict = PyDict::new(py);

    let opt = match parse_optional_header(&data) {
        Ok(o) => o,
        Err(e) => {
            dict.set_item("status", "parse_error")?;
            dict.set_item("error", e)?;
            return Ok(dict.unbind());
        }
    };

    match authenticode::analyze(&data, &opt) {
        authenticode::SignatureStatus::Unsigned => {
            dict.set_item("status", "unsigned")?;
        }
        authenticode::SignatureStatus::Malformed(e) => {
            dict.set_item("status", "malformed")?;
            dict.set_item("error", e)?;
        }
        authenticode::SignatureStatus::Present(p) => {
            dict.set_item("status", "present")?;
            dict.set_item("blob_size", p.blob_size)?;
            dict.set_item(
                "win_cert_revision",
                format!("0x{:04X}", p.win_cert_revision),
            )?;
            dict.set_item("win_cert_type", format!("0x{:04X}", p.win_cert_type))?;
            dict.set_item("content_type_oid", p.content_type_oid)?;
            dict.set_item("is_signed_data", p.is_signed_data)?;
        }
    }
    Ok(dict.unbind())
}

/// Full PE analysis — parses headers, imports, sections, strings, patterns,
/// Authenticode signature, and runs the triage scoring engine.
///
/// Returns a dict with the complete report. Structure mirrors the CLI's
/// `--json` output; see the project README for the full schema. Typical
/// top-level keys: `file`, `file_size`, `md5`, `sha256`, `imphash`,
/// `machine`, `pe_type`, `signature`, `sections`, `imports`, `triage`.
///
/// Raises `OSError` on read failure, `ValueError` if the file isn't a
/// parseable PE.
#[pyfunction]
#[pyo3(name = "analyze")]
fn py_analyze(py: Python<'_>, path: &str) -> PyResult<PyObject> {
    let data = read_file(path)?;
    let analysis = api::analyze_bytes(data)
        .map_err(|e| PyValueError::new_err(format!("PE analysis failed: {e}")))?;
    let report = analysis.to_report(path);
    // `pythonize` walks a `Serialize` value and builds native Python types
    // (dict / list / str / int / float / None / bool) — perfect for Jupyter,
    // pandas, and JSON pipelines without a serde_json round-trip.
    let obj = pythonize::pythonize(py, &report)
        .map_err(|e| PyValueError::new_err(format!("report serialization failed: {e}")))?;
    Ok(obj.unbind())
}

/// The `prust` Python module.
#[pymodule]
fn prust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(py_hashes, m)?)?;
    m.add_function(wrap_pyfunction!(py_signature, m)?)?;
    m.add_function(wrap_pyfunction!(py_analyze, m)?)?;
    Ok(())
}
