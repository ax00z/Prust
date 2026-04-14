# Prust

`prust` is a small Rust CLI that parses Windows PE files and prints a quick triage report.

## What it does

- Reads the DOS, COFF, and optional headers
- Lists sections with permissions and entropy
- Parses imports and exports
- Scores suspicious traits such as RWX sections, packer-like names, and missing mitigations
- Supports plain text output or JSON output

## Project layout

- `src/main.rs` wires the CLI together
- `src/pe.rs` contains the PE parser
- `src/entropy.rs` calculates Shannon entropy for section data
- `src/rules.rs` applies the triage rules and scoring

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

Example:

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" run -- .\sample.exe --triage-only
```

## Dev workflow

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" check
& "$env:USERPROFILE\.cargo\bin\cargo.exe" test
```

## Next good steps

- Add parser tests with small hand-built byte fixtures
- Add a sample PE to exercise the CLI end-to-end
- Split reporting from parsing so the JSON and text output paths share less formatting logic
