# Prust

`prust` is a Rust CLI for static triage of Windows PE files such as `.exe`,
`.dll`, and `.sys` samples.

## What it does

- Reads the DOS, COFF, and optional headers
- Lists sections with raw offsets, permissions, characteristics, and entropy
- Parses imports, exports, TLS callbacks, data directories, and overlay data
- Computes MD5, SHA256, imphash, and Authenticode authentihash
- Checks Authenticode certificate table presence and basic PKCS#7 shape
- Matches SHA256, authentihash, and imphash values against a LOLDrivers corpus
- Scores suspicious traits such as RWX sections, packer-like names, suspicious imports,
  embedded PE patterns, TLS callbacks, overlays, and missing mitigations
- Supports text output, JSON output, and recursive directory scans

## Project layout

- `src/main.rs` defines the CLI entry point
- `src/api.rs` contains the shared analysis pipeline and JSON report shape
- `src/pe.rs` contains the PE parser
- `src/hashes.rs` computes file hashes, imphash, and authentihash
- `src/authenticode.rs` inspects the PE security directory
- `src/loldrivers.rs` loads and searches the LOLDrivers corpus
- `src/batch.rs` implements recursive directory scans
- `src/entropy.rs` calculates Shannon entropy for section and overlay data
- `src/patterns.rs` scans suspicious byte signatures
- `src/strings.rs` extracts ASCII and UTF-16LE strings
- `src/rules.rs` applies the triage rules and scoring
- `tests/cli.rs` tests the `prust` binary end to end

## Run it

If `cargo` is already on your `PATH`:

```powershell
cargo run -- <path-to-pe-file>
```

If Rust is installed but not on your `PATH` yet:

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" run -- <path-to-pe-file>
```

Useful flags:

- `--json` for machine-readable output
- `--triage-only` to skip the full header dump
- `--no-loldrivers` to skip LOLDrivers lookup
- `--loldrivers <path>` to use a specific LOLDrivers JSON file
- `--update` to refresh the cached LOLDrivers corpus

Example:

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" run -- .\sample.exe --triage-only
```

Directory scan:

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" run -- .\samples --json
```

## Dev workflow

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" fmt --check
& "$env:USERPROFILE\.cargo\bin\cargo.exe" check
& "$env:USERPROFILE\.cargo\bin\cargo.exe" test
```

## Roadmap

- Add delay-import, resource, load-config, debug-directory, and relocation parsing
- Add richer Authenticode signer/certificate metadata instead of only certificate-table shape
- Add rule metadata suitable for stable machine consumption, such as categories and tags
- Decide whether to rename the Cargo package/library from `sigkill` to `prust`
