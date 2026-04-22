// sigkill — PE static analyzer and Authenticode forensics library.
//
// This crate compiles as both a binary (the `prust` CLI) and a library.
// The library surface is what the Python bindings and external Rust
// callers consume; the binary in src/main.rs is a thin shim over it.

pub mod api;
pub mod authenticode;
pub mod batch;
pub mod entropy;
pub mod hashes;
pub mod overlay;
pub mod patterns;
#[allow(dead_code)]
pub mod pe;
pub mod rules;
pub mod strings;

// Python bindings. Gated on the `python` feature so a plain `cargo build`
// of the CLI doesn't drag in pyo3 / extension-module linkage.
#[cfg(feature = "python")]
mod python;
