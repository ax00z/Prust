// overlay.rs — Detect data appended after the last PE section.
//
// The PE loader ignores bytes past the end of the last section's raw data.
// Packers, droppers, and installers stash payloads there. High-entropy
// overlays are a strong signal of packed or encrypted data.

use crate::entropy;
use crate::pe::SectionHeader;

#[derive(Debug, Clone)]
pub struct OverlayInfo {
    pub offset: usize,
    pub size: usize,
    pub entropy: f64,
    pub entropy_label: String,
}

/// Overlay = `file_size - max(section.pointer_to_raw_data + size_of_raw_data)`.
/// Uses u64 arithmetic and `saturating_add` because section fields are
/// untrusted u32s and could overflow on crafted input.
pub fn detect_overlay(data: &[u8], sections: &[SectionHeader]) -> Option<OverlayInfo> {
    if sections.is_empty() {
        return None;
    }

    let pe_end = sections
        .iter()
        .map(|s| u64::from(s.pointer_to_raw_data).saturating_add(u64::from(s.size_of_raw_data)))
        .max()?;

    let file_size = data.len() as u64;
    if file_size <= pe_end {
        return None;
    }

    let overlay_offset = pe_end as usize;
    let overlay_size = data.len() - overlay_offset;

    // Filter out alignment padding and short trailing runs of nulls.
    if overlay_size < 16 {
        return None;
    }

    let overlay_data = &data[overlay_offset..];
    let ent = entropy::shannon_entropy(overlay_data);

    Some(OverlayInfo {
        offset: overlay_offset,
        size: overlay_size,
        entropy: (ent * 10000.0).round() / 10000.0,
        entropy_label: entropy::entropy_label(ent).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section(pointer: u32, raw_size: u32) -> SectionHeader {
        SectionHeader {
            name: String::from(".test"),
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: raw_size,
            pointer_to_raw_data: pointer,
            characteristics: 0,
        }
    }

    #[test]
    fn no_overlay_when_file_matches_sections() {
        let data = vec![0u8; 512];
        let sections = vec![make_section(0, 512)];
        assert!(detect_overlay(&data, &sections).is_none());
    }

    #[test]
    fn detects_overlay_after_sections() {
        let data = vec![0xAA; 576];
        let sections = vec![make_section(0, 512)];
        let info = detect_overlay(&data, &sections).unwrap();
        assert_eq!(info.offset, 512);
        assert_eq!(info.size, 64);
    }

    #[test]
    fn uses_last_section_end_not_first() {
        let data = vec![0u8; 2048];
        let sections = vec![make_section(0, 512), make_section(512, 1024)];
        let info = detect_overlay(&data, &sections).unwrap();
        assert_eq!(info.offset, 1536);
        assert_eq!(info.size, 512);
    }

    #[test]
    fn ignores_tiny_trailing_bytes() {
        let data = vec![0u8; 520];
        let sections = vec![make_section(0, 512)];
        assert!(detect_overlay(&data, &sections).is_none());
    }

    #[test]
    fn no_sections_means_no_overlay() {
        let data = vec![0u8; 1024];
        let sections: Vec<SectionHeader> = Vec::new();
        assert!(detect_overlay(&data, &sections).is_none());
    }

    #[test]
    fn overlay_entropy_is_computed() {
        let mut data = vec![0u8; 512];
        data.extend_from_slice(&[0xAA; 64]);
        let sections = vec![make_section(0, 512)];
        let info = detect_overlay(&data, &sections).unwrap();
        assert_eq!(info.entropy, 0.0);
    }

    #[test]
    fn handles_saturating_add_on_crafted_values() {
        let data = vec![0u8; 1024];
        let sections = vec![make_section(u32::MAX, u32::MAX)];
        assert!(detect_overlay(&data, &sections).is_none());
    }
}
