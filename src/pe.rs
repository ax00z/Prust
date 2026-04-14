// pe.rs — Core PE parsing logic.
//
// Parses raw bytes according to the PE/COFF specification (Microsoft PE format).
// All multi-byte integers are little-endian.
//
// Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

use std::fmt;

// ──────────────────────────────────────────────
// PE spec constants
// ──────────────────────────────────────────────

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const PE32_MAGIC: u16 = 0x10B;
const PE32PLUS_MAGIC: u16 = 0x20B;

const DOS_HEADER_SIZE: usize = 64;
const COFF_HEADER_SIZE: usize = 20;
const PE_SIGNATURE_SIZE: usize = 4;
const SECTION_HEADER_SIZE: usize = 40;
const DATA_DIRECTORY_ENTRY_SIZE: usize = 8;
const E_LFANEW_OFFSET: usize = 0x3C;

/// Upper bound on section count to reject obviously malformed headers.
/// The PE spec doesn't define a hard maximum, but real-world binaries rarely
/// exceed ~30 sections. We cap at 96 to be generous while still rejecting
/// garbage values like 0xFFFF that would cause huge allocations.
const MAX_SECTIONS: u16 = 96;

/// Safety limit: stop reading import descriptors after this many entries.
/// Prevents infinite loops on malformed import directories.
const MAX_IMPORT_DLLS: usize = 4096;

/// Safety limit per thunk array.
const MAX_THUNK_ENTRIES: usize = 65536;

/// Maximum length for a single ASCII string read from the file.
/// Prevents reading the entire remainder of a file on a missing null terminator.
const MAX_ASCII_STRING_LEN: usize = 1024;

// Section characteristic flags (IMAGE_SCN_*)
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// COFF characteristic flags (IMAGE_FILE_*)
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
const IMAGE_FILE_DLL: u16 = 0x2000;

// DLL characteristic flags (IMAGE_DLLCHARACTERISTICS_*)
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

// Machine types
const IMAGE_FILE_MACHINE_I386: u16 = 0x14C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x1C0;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

// ──────────────────────────────────────────────
// Data directory indices
// ──────────────────────────────────────────────

pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_RESOURCE: usize = 2;
pub const DIR_EXCEPTION: usize = 3;
pub const DIR_SECURITY: usize = 4;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_DEBUG: usize = 6;
pub const DIR_TLS: usize = 9;
pub const DIR_LOAD_CONFIG: usize = 10;
pub const DIR_BOUND_IMPORT: usize = 11;
pub const DIR_IAT: usize = 12;
pub const DIR_CLR: usize = 14;

pub fn dir_name(index: usize) -> &'static str {
    match index {
        0 => "Export",
        1 => "Import",
        2 => "Resource",
        3 => "Exception",
        4 => "Security",
        5 => "Base Relocation",
        6 => "Debug",
        7 => "Architecture",
        8 => "Global Pointer",
        9 => "TLS",
        10 => "Load Config",
        11 => "Bound Import",
        12 => "IAT",
        13 => "Delay Import",
        14 => "CLR Runtime",
        15 => "Reserved",
        _ => "Unknown",
    }
}

// ──────────────────────────────────────────────
// Error type
// ──────────────────────────────────────────────

/// Parse error with dynamic context — carries the specific offset or value
/// that caused the failure, not just a static description.
#[derive(Debug, Clone)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    FileTooSmall,
    InvalidMagic,
    InvalidSignature,
    TruncatedHeader,
    MalformedField,
}

impl ParseError {
    fn too_small(need: usize, have: usize, context: &str) -> Self {
        ParseError {
            kind: ParseErrorKind::FileTooSmall,
            detail: format!("{context}: need {need} bytes, have {have}"),
        }
    }

    fn truncated(offset: usize, need: usize, have: usize, context: &str) -> Self {
        ParseError {
            kind: ParseErrorKind::TruncatedHeader,
            detail: format!("{context}: need {need} bytes at offset 0x{offset:X}, file is {have} bytes"),
        }
    }

    fn bad_magic(expected: &str, got: u16) -> Self {
        ParseError {
            kind: ParseErrorKind::InvalidMagic,
            detail: format!("expected {expected}, got 0x{got:04X}"),
        }
    }

    fn malformed(msg: String) -> Self {
        ParseError {
            kind: ParseErrorKind::MalformedField,
            detail: msg,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PE parse error ({:?}): {}", self.kind, self.detail)
    }
}

impl std::error::Error for ParseError {}

// ──────────────────────────────────────────────
// Byte-reading helpers
// ──────────────────────────────────────────────

/// Read a u16 from `data` at `offset` (little-endian).
/// Returns `Err` if the slice is too short — never panics.
fn read_u16_at(data: &[u8], offset: usize, field: &str) -> Result<u16, ParseError> {
    let bytes = data.get(offset..offset + 2).ok_or_else(|| {
        ParseError::truncated(offset, 2, data.len(), field)
    })?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read a u32 from `data` at `offset` (little-endian).
fn read_u32_at(data: &[u8], offset: usize, field: &str) -> Result<u32, ParseError> {
    let bytes = data.get(offset..offset + 4).ok_or_else(|| {
        ParseError::truncated(offset, 4, data.len(), field)
    })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a u64 from `data` at `offset` (little-endian).
fn read_u64_at(data: &[u8], offset: usize, field: &str) -> Result<u64, ParseError> {
    let bytes = data.get(offset..offset + 8).ok_or_else(|| {
        ParseError::truncated(offset, 8, data.len(), field)
    })?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Try to read a u32 from `data` at `offset`. Returns 0 if out of bounds.
/// Used for non-critical fields where truncation is tolerable (e.g. data
/// directory entries at the end of a truncated optional header).
fn read_u32_or_zero(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a null-terminated ASCII string from `data` at `offset`.
///
/// Stops at the first null byte, at `MAX_ASCII_STRING_LEN`, or at end-of-file —
/// whichever comes first. Returns an empty string if `offset` is out of bounds.
fn read_ascii_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let remaining = &data[offset..];
    let max = remaining.len().min(MAX_ASCII_STRING_LEN);
    let len = remaining[..max].iter().position(|&b| b == 0).unwrap_or(max);
    remaining[..len].iter().map(|&b| b as char).collect()
}

// ──────────────────────────────────────────────
// DOS Header (64 bytes, starts at offset 0)
// ──────────────────────────────────────────────

/// The DOS header occupies the first 64 bytes of any PE file.
///
/// Only two fields matter for PE parsing:
/// - `e_magic` at offset 0x00 — must be 0x5A4D ("MZ")
/// - `e_lfanew` at offset 0x3C — file offset to the PE signature
#[derive(Debug, Clone)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_lfanew: u32,
}

impl DosHeader {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < DOS_HEADER_SIZE {
            return Err(ParseError::too_small(DOS_HEADER_SIZE, data.len(), "DOS header"));
        }

        let e_magic = read_u16_at(data, 0, "e_magic")?;
        if e_magic != DOS_MAGIC {
            return Err(ParseError::bad_magic("0x5A4D (MZ)", e_magic));
        }

        let e_lfanew = read_u32_at(data, E_LFANEW_OFFSET, "e_lfanew")?;

        // Sanity-check e_lfanew: it must point somewhere inside the file
        // with enough room for the PE signature + COFF header (24 bytes).
        let min_pe_end = e_lfanew as usize + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE;
        if min_pe_end > data.len() {
            return Err(ParseError::malformed(format!(
                "e_lfanew (0x{e_lfanew:08X}) points past end of file ({} bytes)",
                data.len()
            )));
        }

        Ok(DosHeader { e_magic, e_lfanew })
    }
}

// ──────────────────────────────────────────────
// PE Signature + COFF File Header
// At offset e_lfanew: 4-byte signature + 20-byte COFF header
// ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl CoffHeader {
    pub fn parse(data: &[u8], pe_offset: usize) -> Result<Self, ParseError> {
        let required = pe_offset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE;
        if data.len() < required {
            return Err(ParseError::too_small(required, data.len(), "PE signature + COFF header"));
        }

        let sig = read_u32_at(data, pe_offset, "PE signature")?;
        if sig != PE_SIGNATURE {
            return Err(ParseError {
                kind: ParseErrorKind::InvalidSignature,
                detail: format!("expected PE\\0\\0 (0x{PE_SIGNATURE:08X}), got 0x{sig:08X}"),
            });
        }

        let coff_base = pe_offset + PE_SIGNATURE_SIZE;

        let number_of_sections = read_u16_at(data, coff_base + 2, "NumberOfSections")?;
        if number_of_sections > MAX_SECTIONS {
            return Err(ParseError::malformed(format!(
                "NumberOfSections ({number_of_sections}) exceeds safety limit ({MAX_SECTIONS})"
            )));
        }

        Ok(CoffHeader {
            machine: read_u16_at(data, coff_base, "Machine")?,
            number_of_sections,
            time_date_stamp: read_u32_at(data, coff_base + 4, "TimeDateStamp")?,
            pointer_to_symbol_table: read_u32_at(data, coff_base + 8, "PointerToSymbolTable")?,
            number_of_symbols: read_u32_at(data, coff_base + 12, "NumberOfSymbols")?,
            size_of_optional_header: read_u16_at(data, coff_base + 16, "SizeOfOptionalHeader")?,
            characteristics: read_u16_at(data, coff_base + 18, "Characteristics")?,
        })
    }

    pub fn machine_name(&self) -> &'static str {
        match self.machine {
            IMAGE_FILE_MACHINE_I386 => "i386",
            IMAGE_FILE_MACHINE_AMD64 => "AMD64",
            IMAGE_FILE_MACHINE_ARM => "ARM",
            IMAGE_FILE_MACHINE_ARM64 => "ARM64",
            _ => "Unknown",
        }
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    pub fn characteristics_list(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        let c = self.characteristics;
        if c & IMAGE_FILE_EXECUTABLE_IMAGE != 0 { flags.push("EXECUTABLE_IMAGE"); }
        if c & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 { flags.push("LARGE_ADDRESS_AWARE"); }
        if c & IMAGE_FILE_32BIT_MACHINE != 0 { flags.push("32BIT_MACHINE"); }
        if c & IMAGE_FILE_DEBUG_STRIPPED != 0 { flags.push("DEBUG_STRIPPED"); }
        if c & IMAGE_FILE_DLL != 0 { flags.push("DLL"); }
        flags
    }
}

// ──────────────────────────────────────────────
// Optional Header + Data Directories
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
}

impl OptionalHeader {
    /// Parse from file data. `offset` is the first byte of the optional header
    /// (immediately after the COFF header).
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ParseError> {
        // We need at least 2 bytes to read the magic and determine the format.
        if data.len() < offset + 2 {
            return Err(ParseError::too_small(offset + 2, data.len(), "optional header magic"));
        }

        let magic = read_u16_at(data, offset, "OptionalHeader.Magic")?;
        let is_pe32_plus = match magic {
            PE32_MAGIC => false,
            PE32PLUS_MAGIC => true,
            _ => return Err(ParseError::bad_magic("PE32 (0x10B) or PE32+ (0x20B)", magic)),
        };

        // Minimum size for the fixed portion of the optional header
        // (before data directories): PE32 = 96 bytes, PE32+ = 112 bytes.
        let fixed_size = if is_pe32_plus { 112 } else { 96 };
        if data.len() < offset + fixed_size {
            return Err(ParseError::too_small(
                offset + fixed_size, data.len(), "optional header fixed fields",
            ));
        }

        let major_linker_version = data[offset + 2];
        let minor_linker_version = data[offset + 3];
        let size_of_code = read_u32_at(data, offset + 4, "SizeOfCode")?;
        let address_of_entry_point = read_u32_at(data, offset + 16, "AddressOfEntryPoint")?;

        let image_base = if is_pe32_plus {
            read_u64_at(data, offset + 24, "ImageBase")?
        } else {
            u64::from(read_u32_at(data, offset + 28, "ImageBase")?)
        };

        // Field offsets differ between PE32 and PE32+ because ImageBase is
        // 4 bytes in PE32 and 8 bytes in PE32+. Everything after ImageBase
        // shifts accordingly. Use absolute offsets from the PE spec.
        let (sa, fa, osv, soi, soh, cs, ss, dc, nrva) = if is_pe32_plus {
            (32, 36, 40, 56, 60, 64, 68, 70, 108)
        } else {
            (32, 36, 40, 56, 60, 64, 68, 70, 92)
        };

        let section_alignment = read_u32_at(data, offset + sa, "SectionAlignment")?;
        let file_alignment = read_u32_at(data, offset + fa, "FileAlignment")?;
        let major_os_version = read_u16_at(data, offset + osv, "MajorOperatingSystemVersion")?;
        let minor_os_version = read_u16_at(data, offset + osv + 2, "MinorOperatingSystemVersion")?;
        let size_of_image = read_u32_at(data, offset + soi, "SizeOfImage")?;
        let size_of_headers = read_u32_at(data, offset + soh, "SizeOfHeaders")?;
        let checksum = read_u32_at(data, offset + cs, "CheckSum")?;
        let subsystem = read_u16_at(data, offset + ss, "Subsystem")?;
        let dll_characteristics = read_u16_at(data, offset + dc, "DllCharacteristics")?;
        let number_of_rva_and_sizes = read_u32_at(data, offset + nrva, "NumberOfRvaAndSizes")?;

        // Sanity-check: the PE spec defines at most 16 data directory entries.
        // Accept up to 16 but don't trust values larger than that.
        let num_dirs = (number_of_rva_and_sizes as usize).min(16);
        let dd_offset = offset + nrva + 4;
        let mut data_directories = Vec::with_capacity(num_dirs);

        for i in 0..num_dirs {
            let d_off = dd_offset + i * DATA_DIRECTORY_ENTRY_SIZE;
            data_directories.push(DataDirectory {
                virtual_address: read_u32_or_zero(data, d_off),
                size: read_u32_or_zero(data, d_off + 4),
            });
        }

        Ok(OptionalHeader {
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            address_of_entry_point,
            image_base,
            section_alignment,
            file_alignment,
            major_os_version,
            minor_os_version,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            number_of_rva_and_sizes,
            data_directories,
        })
    }

    pub fn is_pe32_plus(&self) -> bool {
        self.magic == PE32PLUS_MAGIC
    }

    pub fn subsystem_name(&self) -> &'static str {
        match self.subsystem {
            1 => "Native",
            2 => "Windows GUI",
            3 => "Windows Console",
            5 => "OS/2 Console",
            7 => "POSIX Console",
            9 => "Windows CE",
            10 => "EFI Application",
            11 => "EFI Boot Service Driver",
            12 => "EFI Runtime Driver",
            13 => "EFI ROM",
            14 => "XBOX",
            16 => "Windows Boot Application",
            _ => "Unknown",
        }
    }

    pub fn has_aslr(&self) -> bool {
        self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
    }

    pub fn has_dep(&self) -> bool {
        self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0
    }

    pub fn dll_characteristics_list(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        let c = self.dll_characteristics;
        if c & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 { flags.push("HIGH_ENTROPY_VA"); }
        if c & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 { flags.push("DYNAMIC_BASE (ASLR)"); }
        if c & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0 { flags.push("FORCE_INTEGRITY"); }
        if c & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 { flags.push("NX_COMPAT (DEP)"); }
        if c & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION != 0 { flags.push("NO_ISOLATION"); }
        if c & IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 { flags.push("NO_SEH"); }
        if c & IMAGE_DLLCHARACTERISTICS_NO_BIND != 0 { flags.push("NO_BIND"); }
        if c & IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0 { flags.push("APPCONTAINER"); }
        if c & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0 { flags.push("WDM_DRIVER"); }
        if c & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 { flags.push("GUARD_CF"); }
        if c & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE != 0 { flags.push("TERMINAL_SERVER_AWARE"); }
        flags
    }
}

// ──────────────────────────────────────────────
// Section Table
// ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionHeader {
    /// Parse `count` section headers starting at `offset` in the file.
    pub fn parse_all(data: &[u8], offset: usize, count: u16) -> Result<Vec<Self>, ParseError> {
        let count = count as usize;
        let required = offset + count * SECTION_HEADER_SIZE;
        if data.len() < required {
            return Err(ParseError::truncated(
                offset, count * SECTION_HEADER_SIZE, data.len(), "section table",
            ));
        }

        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let off = offset + i * SECTION_HEADER_SIZE;

            // Name: 8 bytes, null-padded ASCII.
            let name_bytes = &data[off..off + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();

            sections.push(SectionHeader {
                name,
                virtual_size: read_u32_at(data, off + 8, "SectionHeader.VirtualSize")?,
                virtual_address: read_u32_at(data, off + 12, "SectionHeader.VirtualAddress")?,
                size_of_raw_data: read_u32_at(data, off + 16, "SectionHeader.SizeOfRawData")?,
                pointer_to_raw_data: read_u32_at(data, off + 20, "SectionHeader.PointerToRawData")?,
                characteristics: read_u32_at(data, off + 36, "SectionHeader.Characteristics")?,
            });
        }

        Ok(sections)
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    pub fn permissions_string(&self) -> String {
        format!(
            "{}{}{}",
            if self.is_readable() { 'R' } else { '-' },
            if self.is_writable() { 'W' } else { '-' },
            if self.is_executable() { 'X' } else { '-' },
        )
    }

    /// Return the raw bytes of this section from the file, clamped to file bounds.
    /// Returns an empty slice if the pointer is out of range.
    pub fn raw_data<'a>(&self, file_data: &'a [u8]) -> &'a [u8] {
        let start = self.pointer_to_raw_data as usize;
        let end = start.saturating_add(self.size_of_raw_data as usize);
        let end = end.min(file_data.len());
        if start >= file_data.len() {
            return &[];
        }
        &file_data[start..end]
    }
}

/// File offset where the section table begins.
pub fn section_table_offset(pe_offset: usize, size_of_optional_header: u16) -> usize {
    pe_offset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE + size_of_optional_header as usize
}

// ──────────────────────────────────────────────
// RVA-to-file-offset conversion
// ──────────────────────────────────────────────

/// Convert a Relative Virtual Address to a file offset using the section table.
///
/// Finds which section contains the RVA and computes:
///   `file_offset = rva - virtual_address + pointer_to_raw_data`
pub fn rva_to_offset(rva: u32, sections: &[SectionHeader]) -> Option<usize> {
    for sec in sections {
        let start = sec.virtual_address;
        let end = start.saturating_add(sec.virtual_size.max(sec.size_of_raw_data));
        if rva >= start && rva < end {
            let delta = rva.wrapping_sub(sec.virtual_address);
            return Some(sec.pointer_to_raw_data as usize + delta as usize);
        }
    }
    None
}

// ──────────────────────────────────────────────
// Import Table
// ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub dll_name: String,
    pub functions: Vec<String>,
}

/// Parse the import directory table.
///
/// The import directory is an array of `IMAGE_IMPORT_DESCRIPTOR` (20 bytes each),
/// terminated by an all-zero entry. Each descriptor points to a DLL name and
/// a list of imported functions (the Import Name Table / Import Address Table).
pub fn parse_imports(
    data: &[u8],
    import_rva: u32,
    sections: &[SectionHeader],
    is_pe32_plus: bool,
) -> Vec<ImportEntry> {
    let mut imports = Vec::new();

    let Some(base_offset) = rva_to_offset(import_rva, sections) else {
        return imports;
    };

    let mut desc_offset = base_offset;
    for _ in 0..MAX_IMPORT_DLLS {
        if desc_offset + 20 > data.len() {
            break;
        }

        let original_first_thunk = read_u32_or_zero(data, desc_offset);
        let name_rva = read_u32_or_zero(data, desc_offset + 12);
        let first_thunk = read_u32_or_zero(data, desc_offset + 16);

        // All-zero descriptor terminates the import directory.
        if name_rva == 0 && original_first_thunk == 0 && first_thunk == 0 {
            break;
        }

        let dll_name = match rva_to_offset(name_rva, sections) {
            Some(off) => read_ascii_string(data, off),
            None => format!("<invalid RVA 0x{name_rva:08X}>"),
        };

        // Prefer the OriginalFirstThunk (INT) when available; fall back to
        // FirstThunk (IAT). The INT is the authoritative list; the IAT may
        // have been overwritten by the loader at runtime.
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let functions = parse_thunk_array(data, thunk_rva, sections, is_pe32_plus);
        imports.push(ImportEntry { dll_name, functions });
        desc_offset += 20;
    }

    imports
}

/// Parse a null-terminated array of thunk values (`IMAGE_THUNK_DATA`).
///
/// Each entry is either:
/// - An ordinal import (high bit set, low 16 bits = ordinal number)
/// - A name import (RVA to `IMAGE_IMPORT_BY_NAME`: 2-byte hint + null-terminated name)
fn parse_thunk_array(
    data: &[u8],
    thunk_rva: u32,
    sections: &[SectionHeader],
    is_pe32_plus: bool,
) -> Vec<String> {
    let mut functions = Vec::new();

    let Some(base) = rva_to_offset(thunk_rva, sections) else {
        return functions;
    };

    let entry_size: usize = if is_pe32_plus { 8 } else { 4 };
    let mut offset = base;

    for _ in 0..MAX_THUNK_ENTRIES {
        if offset + entry_size > data.len() {
            break;
        }

        let (value, is_ordinal) = if is_pe32_plus {
            let v = data.get(offset..offset + 8)
                .map_or(0u64, |b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]));
            (v, v & 0x8000_0000_0000_0000 != 0)
        } else {
            let v = u64::from(data.get(offset..offset + 4)
                .map_or(0u32, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])));
            (v, v & 0x8000_0000 != 0)
        };

        if value == 0 {
            break;
        }

        if is_ordinal {
            functions.push(format!("#{}", value & 0xFFFF));
        } else {
            // For PE32 the value is already 32-bit; for PE32+ the RVA portion
            // is the low 31 bits (bit 31 is the ordinal flag, already checked).
            #[allow(clippy::cast_possible_truncation)]
            let name_rva = value as u32;
            match rva_to_offset(name_rva, sections) {
                Some(off) => {
                    // IMAGE_IMPORT_BY_NAME: skip 2-byte hint, read name.
                    functions.push(read_ascii_string(data, off + 2));
                }
                None => functions.push(format!("<bad RVA 0x{name_rva:08X}>")),
            }
        }

        offset += entry_size;
    }

    functions
}

// ──────────────────────────────────────────────
// Export Table
// ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub dll_name: String,
    pub functions: Vec<String>,
}

/// Parse the export directory table (data directory index 0).
pub fn parse_exports(
    data: &[u8],
    export_rva: u32,
    sections: &[SectionHeader],
) -> Option<ExportInfo> {
    let base = rva_to_offset(export_rva, sections)?;
    if base + 40 > data.len() {
        return None;
    }

    let name_rva = read_u32_or_zero(data, base + 12);
    let number_of_names = read_u32_or_zero(data, base + 24) as usize;
    let names_rva = read_u32_or_zero(data, base + 32);

    // Cap the name count to prevent huge allocations on malformed exports.
    let number_of_names = number_of_names.min(MAX_THUNK_ENTRIES);

    let dll_name = rva_to_offset(name_rva, sections)
        .map(|off| read_ascii_string(data, off))
        .unwrap_or_default();

    let mut functions = Vec::new();
    if let Some(names_off) = rva_to_offset(names_rva, sections) {
        for i in 0..number_of_names {
            let fn_name_rva = read_u32_or_zero(data, names_off + i * 4);
            if let Some(fn_off) = rva_to_offset(fn_name_rva, sections) {
                functions.push(read_ascii_string(data, fn_off));
            }
        }
    }

    Some(ExportInfo { dll_name, functions })
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_empty_file() {
        let result = DosHeader::parse(&[]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ParseErrorKind::FileTooSmall);
    }

    #[test]
    fn reject_bad_dos_magic() {
        let mut data = [0u8; 64];
        data[0] = 0xFF;
        data[1] = 0xFF;
        let result = DosHeader::parse(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ParseErrorKind::InvalidMagic);
    }

    #[test]
    fn reject_e_lfanew_past_eof() {
        let mut data = [0u8; 64];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        // Set e_lfanew to point way past the file
        data[0x3C] = 0xFF;
        data[0x3D] = 0xFF;
        data[0x3E] = 0x00;
        data[0x3F] = 0x00;
        let result = DosHeader::parse(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ParseErrorKind::MalformedField);
    }

    #[test]
    fn parse_valid_dos_header() {
        let mut data = [0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[0x3C] = 0x80; // e_lfanew = 0x80
        // Need PE sig + COFF header at offset 0x80 = 128, so file must be >= 152
        let dos = DosHeader::parse(&data).unwrap();
        assert_eq!(dos.e_magic, 0x5A4D);
        assert_eq!(dos.e_lfanew, 0x80);
    }

    #[test]
    fn reject_excessive_section_count() {
        // Build a minimal valid PE up to the COFF header with 0xFFFF sections
        let mut data = [0u8; 256];
        data[0] = 0x4D; data[1] = 0x5A; // MZ
        data[0x3C] = 0x80; // e_lfanew
        // PE signature at 0x80
        data[0x80] = 0x50; data[0x81] = 0x45; // "PE\0\0"
        // NumberOfSections at 0x86 = 0xFFFF
        data[0x86] = 0xFF; data[0x87] = 0xFF;
        let result = CoffHeader::parse(&data, 0x80);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ParseErrorKind::MalformedField);
    }

    #[test]
    fn ascii_string_respects_max_length() {
        // No null terminator in sight — should still stop.
        let data = vec![0x41u8; MAX_ASCII_STRING_LEN + 100];
        let s = read_ascii_string(&data, 0);
        assert_eq!(s.len(), MAX_ASCII_STRING_LEN);
    }

    #[test]
    fn ascii_string_out_of_bounds_returns_empty() {
        let data = [0x41u8; 10];
        assert_eq!(read_ascii_string(&data, 100), "");
    }

    #[test]
    fn rva_to_offset_finds_correct_section() {
        let sections = vec![
            SectionHeader {
                name: ".text".into(),
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                size_of_raw_data: 0x1000,
                pointer_to_raw_data: 0x400,
                characteristics: 0,
            },
        ];
        // RVA 0x1010 should map to file offset 0x410
        assert_eq!(rva_to_offset(0x1010, &sections), Some(0x410));
        // RVA 0x3000 is outside all sections
        assert_eq!(rva_to_offset(0x3000, &sections), None);
    }

    #[test]
    fn raw_data_clamps_to_file_bounds() {
        let sec = SectionHeader {
            name: ".text".into(),
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0xFFFF,  // larger than file
            pointer_to_raw_data: 5,
            characteristics: 0,
        };
        let file_data = [0u8; 20];
        let raw = sec.raw_data(&file_data);
        assert_eq!(raw.len(), 15); // 20 - 5 = 15, clamped
    }

    #[test]
    fn raw_data_returns_empty_for_pointer_past_eof() {
        let sec = SectionHeader {
            name: ".text".into(),
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x1000,
            pointer_to_raw_data: 0xFFFF,
            characteristics: 0,
        };
        let file_data = [0u8; 20];
        assert!(sec.raw_data(&file_data).is_empty());
    }
}
