// authenticode.rs — Locate and validate the Authenticode signature blob.
//
// A signed PE places its signature in the certificate table, pointed to by
// data directory index 4 (DIR_SECURITY). Unlike every other data directory,
// DIR_SECURITY.VirtualAddress is a FILE OFFSET, not an RVA — the cert table
// sits outside any section.
//
// Wire format at that offset:
//
//   WIN_CERTIFICATE {
//       DWORD dwLength;          // total length including this header
//       WORD  wRevision;         // 0x0200 = revision 2
//       WORD  wCertificateType;  // 0x0002 = PKCS_7_SIGNED_DATA
//       BYTE  bCertificate[];    // DER-encoded PKCS#7 ContentInfo
//   }
//
// Phase 1a: unwrap the header, confirm the inner blob is a valid PKCS#7
// ContentInfo, report bookkeeping (blob size, content-type OID).
// Phase 1b will extract signer cert, digest algorithm, and chain details.

use crate::pe::{DIR_SECURITY, OptionalHeader};
use cms::content_info::ContentInfo;
use der::Decode;

const WIN_CERT_HEADER_SIZE: usize = 8;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// OID 1.2.840.113549.1.7.2 — PKCS#7 signedData content type.
/// Every Authenticode signature's ContentInfo wraps this OID.
const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

#[derive(Debug, Clone)]
pub enum SignatureStatus {
    /// No security directory, or directory is empty.
    Unsigned,
    /// Directory is present but doesn't parse as a valid Authenticode blob.
    Malformed(String),
    /// WIN_CERTIFICATE unwrapped and PKCS#7 ContentInfo decoded successfully.
    Present(PresentSignature),
}

#[derive(Debug, Clone)]
pub struct PresentSignature {
    pub blob_size: usize,
    pub win_cert_revision: u16,
    pub win_cert_type: u16,
    pub content_type_oid: String,
    /// `true` if the content-type OID is PKCS#7 SignedData (expected).
    pub is_signed_data: bool,
}

/// Entry point: inspect the PE's security directory and return a status.
pub fn analyze(data: &[u8], opt: &OptionalHeader) -> SignatureStatus {
    // Look up DIR_SECURITY. Missing or zero-size means unsigned.
    let sec_dir = match opt.data_directories.get(DIR_SECURITY) {
        Some(d) if d.virtual_address != 0 && d.size != 0 => d,
        _ => return SignatureStatus::Unsigned,
    };

    // `virtual_address` here is really a file offset (see module header).
    let offset = sec_dir.virtual_address as usize;
    let size = sec_dir.size as usize;

    // Range-check the whole directory against file length.
    let Some(end) = offset.checked_add(size) else {
        return SignatureStatus::Malformed(format!(
            "security directory offset+size overflows: {offset} + {size}"
        ));
    };
    if end > data.len() {
        return SignatureStatus::Malformed(format!(
            "security directory (offset 0x{offset:X}, size {size}) extends past EOF ({})",
            data.len()
        ));
    }
    if size < WIN_CERT_HEADER_SIZE {
        return SignatureStatus::Malformed(format!(
            "security directory size ({size}) smaller than WIN_CERTIFICATE header ({WIN_CERT_HEADER_SIZE})"
        ));
    }

    // Parse the WIN_CERTIFICATE header.
    let hdr = &data[offset..offset + WIN_CERT_HEADER_SIZE];
    let dw_length = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let w_revision = u16::from_le_bytes([hdr[4], hdr[5]]);
    let w_cert_type = u16::from_le_bytes([hdr[6], hdr[7]]);

    if dw_length < WIN_CERT_HEADER_SIZE {
        return SignatureStatus::Malformed(format!(
            "WIN_CERTIFICATE.dwLength ({dw_length}) smaller than header size"
        ));
    }
    if dw_length > size {
        return SignatureStatus::Malformed(format!(
            "WIN_CERTIFICATE.dwLength ({dw_length}) exceeds directory size ({size})"
        ));
    }
    if w_cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
        return SignatureStatus::Malformed(format!(
            "unsupported certificate type 0x{w_cert_type:04X} (expected 0x0002 PKCS_7_SIGNED_DATA)"
        ));
    }

    // Inner DER blob follows the 8-byte header. WIN_CERTIFICATE.dwLength is
    // rounded up to an 8-byte boundary, so the blob may contain up to 7
    // trailing zero bytes of padding. Trim to the real DER TLV length.
    let padded_blob = &data[offset + WIN_CERT_HEADER_SIZE..offset + dw_length];
    let der_len = match der_tlv_total_length(padded_blob) {
        Some(n) if n <= padded_blob.len() => n,
        Some(n) => {
            return SignatureStatus::Malformed(format!(
                "DER length prefix claims {n} bytes but blob is only {}",
                padded_blob.len()
            ));
        }
        None => {
            return SignatureStatus::Malformed(
                "could not parse DER length prefix of PKCS#7 blob".into(),
            );
        }
    };
    let blob = &padded_blob[..der_len];

    // Decode the outermost PKCS#7 wrapper to confirm structural validity.
    // Full SignerInfo + cert chain parsing comes in Phase 1b.
    let ci = match ContentInfo::from_der(blob) {
        Ok(ci) => ci,
        Err(e) => {
            return SignatureStatus::Malformed(format!(
                "PKCS#7 ContentInfo DER decode failed: {e}"
            ));
        }
    };

    let oid = ci.content_type.to_string();
    let is_signed_data = oid == OID_PKCS7_SIGNED_DATA;

    SignatureStatus::Present(PresentSignature {
        blob_size: blob.len(),
        win_cert_revision: w_revision,
        win_cert_type: w_cert_type,
        content_type_oid: oid,
        is_signed_data,
    })
}

/// Parse a DER TLV header and return the total encoded length
/// (tag byte + length bytes + contents).
///
/// Strips the 8-byte alignment padding that WIN_CERTIFICATE tacks onto the
/// end of a PKCS#7 blob.
fn der_tlv_total_length(blob: &[u8]) -> Option<usize> {
    if blob.len() < 2 {
        return None;
    }
    let len_byte = blob[1];
    if len_byte < 0x80 {
        // Short form: this byte *is* the length.
        Some(2 + len_byte as usize)
    } else {
        // Long form: low 7 bits = number of subsequent length-octets.
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || n > 8 || blob.len() < 2 + n {
            return None;
        }
        let mut total: usize = 0;
        for &b in &blob[2..2 + n] {
            total = total.checked_shl(8)?.checked_add(b as usize)?;
        }
        Some(2 + n + total)
    }
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::DataDirectory;

    /// Build an OptionalHeader stub with a specific security directory.
    fn opt_with_security(va: u32, size: u32) -> OptionalHeader {
        let mut dirs = vec![
            DataDirectory {
                virtual_address: 0,
                size: 0
            };
            16
        ];
        dirs[DIR_SECURITY] = DataDirectory {
            virtual_address: va,
            size,
        };
        OptionalHeader {
            magic: 0x20B,
            major_linker_version: 0,
            minor_linker_version: 0,
            size_of_code: 0,
            address_of_entry_point: 0,
            image_base: 0,
            section_alignment: 0,
            file_alignment: 0,
            major_os_version: 0,
            minor_os_version: 0,
            size_of_image: 0,
            size_of_headers: 0,
            checksum: 0,
            subsystem: 0,
            dll_characteristics: 0,
            number_of_rva_and_sizes: 16,
            data_directories: dirs,
        }
    }

    /// Start cert table at this file offset in test fixtures. Non-zero because
    /// a VA of 0 is treated as "unsigned" by `analyze`.
    const TEST_VA: u32 = 16;

    #[test]
    fn unsigned_when_directory_empty() {
        let opt = opt_with_security(0, 0);
        assert!(matches!(analyze(&[], &opt), SignatureStatus::Unsigned));
    }

    #[test]
    fn malformed_when_directory_past_eof() {
        let opt = opt_with_security(1000, 100);
        let data = vec![0u8; 500];
        assert!(matches!(
            analyze(&data, &opt),
            SignatureStatus::Malformed(_)
        ));
    }

    #[test]
    fn malformed_when_header_too_small() {
        // Directory claims 4 bytes, less than WIN_CERTIFICATE header (8).
        let opt = opt_with_security(TEST_VA, 4);
        let data = vec![0u8; 32];
        assert!(matches!(
            analyze(&data, &opt),
            SignatureStatus::Malformed(_)
        ));
    }

    #[test]
    fn malformed_when_cert_type_unknown() {
        // dwLength=8 (just the header), revision=0x0200, certType=0x0001 (unsupported).
        let mut data = vec![0u8; 32];
        let base = TEST_VA as usize;
        data[base..base + 8].copy_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00]);
        let opt = opt_with_security(TEST_VA, 8);
        match analyze(&data, &opt) {
            SignatureStatus::Malformed(msg) => assert!(msg.contains("0x0001")),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn malformed_when_pkcs7_blob_invalid() {
        // Valid WIN_CERTIFICATE framing, but the inner blob is random bytes.
        let mut data = vec![0u8; 64];
        let base = TEST_VA as usize;
        // dwLength = 24 (header 8 + garbage 16), revision = 0x0200, certType = 0x0002.
        data[base..base + 8].copy_from_slice(&[0x18, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]);
        data[base + 8..base + 24].fill(0xAA);
        let opt = opt_with_security(TEST_VA, 24);
        match analyze(&data, &opt) {
            // Depending on the garbage byte we may fail at length-prefix or
            // at decode. Either Malformed outcome is correct.
            SignatureStatus::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn der_length_short_form() {
        // Short-form: tag 0x30, length 0x05, then 5 content bytes = 7 total.
        let blob = [0x30, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x99, 0x99];
        assert_eq!(der_tlv_total_length(&blob), Some(7));
    }

    #[test]
    fn der_length_long_form_two_bytes() {
        // 0x30 0x82 0x01 0x00 → tag + 2-byte length field + 0x0100 content bytes.
        let mut blob = vec![0x30, 0x82, 0x01, 0x00];
        blob.extend(std::iter::repeat_n(0u8, 0x100));
        assert_eq!(der_tlv_total_length(&blob), Some(4 + 0x100));
    }

    #[test]
    fn der_length_handles_truncated_input() {
        assert_eq!(der_tlv_total_length(&[0x30]), None);
        // Long-form claiming 5 length bytes but buffer only has 2.
        assert_eq!(der_tlv_total_length(&[0x30, 0x85]), None);
    }
}
