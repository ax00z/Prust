//! Python bindings, built by maturin and exported as the `prust` module.

use crate::{api, authenticode, hashes, loldrivers, pe};
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::fs;
use std::path::Path;

fn read_file(path: &str) -> PyResult<Vec<u8>> {
    fs::read(path).map_err(|e| PyOSError::new_err(format!("cannot read {path}: {e}")))
}

/// Pieces that `hashes()` needs for imphash + authentihash. `None` for
/// non-PE inputs so the caller can return missing hashes instead of raising.
struct BestEffortPe {
    pe_offset: usize,
    opt: pe::OptionalHeader,
    sections: Vec<pe::SectionHeader>,
    imports: Vec<pe::ImportEntry>,
}

fn parse_pe_best_effort(data: &[u8]) -> Option<BestEffortPe> {
    let dos = pe::DosHeader::parse(data).ok()?;
    let pe_offset = dos.e_lfanew as usize;
    let coff = pe::CoffHeader::parse(data, pe_offset).ok()?;
    let opt_offset = pe_offset + 24;
    let opt = pe::OptionalHeader::parse(data, opt_offset, coff.size_of_optional_header).ok()?;
    let sec_offset = pe::section_table_offset(pe_offset, coff.size_of_optional_header);
    let sections =
        pe::SectionHeader::parse_all(data, sec_offset, coff.number_of_sections).ok()?;
    let imports = opt
        .data_directories
        .get(pe::DIR_IMPORT)
        .filter(|d| d.virtual_address != 0)
        .map(|d| pe::parse_imports(data, d.virtual_address, &sections, opt.is_pe32_plus()))
        .unwrap_or_default();
    Some(BestEffortPe {
        pe_offset,
        opt,
        sections,
        imports,
    })
}

/// Returns an error string instead of raising; the caller folds it into the dict.
fn parse_optional_header(data: &[u8]) -> Result<pe::OptionalHeader, String> {
    let dos = pe::DosHeader::parse(data).map_err(|e| e.to_string())?;
    let pe_offset = dos.e_lfanew as usize;
    let coff = pe::CoffHeader::parse(data, pe_offset).map_err(|e| e.to_string())?;
    let opt_offset = pe_offset + 24;
    pe::OptionalHeader::parse(data, opt_offset, coff.size_of_optional_header)
        .map_err(|e| e.to_string())
}

/// Returns `{md5, sha256, imphash, authentihash, file_size}`.
/// `imphash` and `authentihash` are `None` when the file has no imports
/// or isn't a parseable PE.
#[pyfunction]
#[pyo3(name = "hashes")]
fn py_hashes(py: Python<'_>, path: &str) -> PyResult<Py<PyDict>> {
    let data = read_file(path)?;
    let parsed = parse_pe_best_effort(&data);
    let imports = parsed
        .as_ref()
        .map(|p| p.imports.clone())
        .unwrap_or_default();
    let mut h = hashes::compute(&data, &imports);
    if let Some(p) = &parsed {
        h.authentihash = hashes::authentihash_sha256(&data, &p.opt, &p.sections, p.pe_offset);
    }

    let dict = PyDict::new(py);
    dict.set_item("md5", h.md5)?;
    dict.set_item("sha256", h.sha256)?;
    dict.set_item("imphash", h.imphash)?;
    dict.set_item("authentihash", h.authentihash)?;
    dict.set_item("file_size", data.len())?;
    Ok(dict.unbind())
}

/// `status` is one of: `unsigned`, `malformed`, `present`, `parse_error`.
/// `present` adds blob_size/win_cert_*/content_type_oid/is_signed_data;
/// `malformed` and `parse_error` add an `error` string.
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

/// Construct once and pass to `analyze(..., loldrivers=db)`.
/// Corpus: https://www.loldrivers.io/api/drivers.json
#[pyclass(name = "LolDriversDb", module = "prust")]
struct PyLolDriversDb {
    inner: loldrivers::LolDriversDb,
}

#[pymethods]
impl PyLolDriversDb {
    #[new]
    fn new(path: &str) -> PyResult<Self> {
        let db = loldrivers::LolDriversDb::load_from_path(Path::new(path))
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner: db })
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __repr__(&self) -> String {
        format!("LolDriversDb({} entries)", self.inner.len())
    }
}

/// Returns a dict mirroring the CLI's `--json` output.
/// `OSError` on read failure, `ValueError` on parse failure.
#[pyfunction]
#[pyo3(name = "analyze", signature = (path, loldrivers=None))]
fn py_analyze(
    py: Python<'_>,
    path: &str,
    loldrivers: Option<&PyLolDriversDb>,
) -> PyResult<PyObject> {
    let data = read_file(path)?;
    let lol_db = loldrivers.map(|d| &d.inner);
    let analysis = api::analyze_bytes(data, lol_db)
        .map_err(|e| PyValueError::new_err(format!("PE analysis failed: {e}")))?;
    let report = analysis.to_report(path);
    let obj = pythonize::pythonize(py, &report)
        .map_err(|e| PyValueError::new_err(format!("report serialization failed: {e}")))?;
    Ok(obj.unbind())
}

#[pymodule]
fn prust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<PyLolDriversDb>()?;
    m.add_function(wrap_pyfunction!(py_hashes, m)?)?;
    m.add_function(wrap_pyfunction!(py_signature, m)?)?;
    m.add_function(wrap_pyfunction!(py_analyze, m)?)?;
    Ok(())
}
