// strings.rs — Extract ASCII and UTF-16LE strings.
//
// Windows stores most user-facing strings as UTF-16LE (each character is
// 2 bytes, low byte first). Registry keys, file paths, API names, and
// resource strings use this encoding. ASCII catches Linux-origin tools,
// debug output, and C string literals.
//
// Strings reveal C2 domains, paths, registry keys, shell commands, and
// debug artifacts that a packer typically doesn't hide.

/// Below this length, random byte runs produce too many false positives.
const MIN_STRING_LENGTH: usize = 4;

/// Upper bound per encoding. Prevents output flood on resource-heavy
/// binaries (installers, .NET assemblies).
const MAX_STRINGS: usize = 2048;

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub offset: usize,
    pub value: String,
    pub encoding: StringEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

impl std::fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            StringEncoding::Ascii => write!(f, "ASCII"),
            StringEncoding::Utf16Le => write!(f, "UTF-16LE"),
        }
    }
}

#[inline]
fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | 0x09 | 0x0A)
}

/// Walk the buffer, accumulating runs of printable bytes. Flush a run
/// when it ends or on EOF if it meets `MIN_STRING_LENGTH`.
pub fn extract_ascii(data: &[u8]) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            start.get_or_insert(i);
        } else {
            if let Some(s) = start
                && i - s >= MIN_STRING_LENGTH
            {
                results.push(ExtractedString {
                    offset: s,
                    value: String::from_utf8_lossy(&data[s..i]).into_owned(),
                    encoding: StringEncoding::Ascii,
                });
                if results.len() >= MAX_STRINGS {
                    return results;
                }
            }
            start = None;
        }
    }

    // Flush a run that extends to EOF.
    if let Some(s) = start
        && data.len() - s >= MIN_STRING_LENGTH
    {
        results.push(ExtractedString {
            offset: s,
            value: String::from_utf8_lossy(&data[s..]).into_owned(),
            encoding: StringEncoding::Ascii,
        });
    }

    results
}

/// UTF-16LE extraction restricted to the ASCII subset: high byte == 0x00
/// and low byte printable. This is simpler than full UTF-16 (no surrogate
/// pair handling) and sufficient for the strings that matter in triage
/// (URLs, paths, commands are all ASCII).
pub fn extract_utf16le(data: &[u8]) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut current_chars: Vec<char> = Vec::new();
    let mut start_offset: Option<usize> = None;

    for (chunk_idx, chunk) in data.chunks_exact(2).enumerate() {
        let lo = chunk[0];
        let hi = chunk[1];

        if hi == 0x00 && is_printable_ascii(lo) {
            if start_offset.is_none() {
                start_offset = Some(chunk_idx * 2);
            }
            current_chars.push(lo as char);
        } else {
            if current_chars.len() >= MIN_STRING_LENGTH
                && let Some(offset) = start_offset
            {
                results.push(ExtractedString {
                    offset,
                    value: current_chars.iter().collect(),
                    encoding: StringEncoding::Utf16Le,
                });
                if results.len() >= MAX_STRINGS {
                    return results;
                }
            }
            current_chars.clear();
            start_offset = None;
        }
    }

    if current_chars.len() >= MIN_STRING_LENGTH
        && let Some(offset) = start_offset
    {
        results.push(ExtractedString {
            offset,
            value: current_chars.iter().collect(),
            encoding: StringEncoding::Utf16Le,
        });
    }

    results
}

/// Merge both encodings and sort by file offset so output reads linearly.
pub fn extract_all(data: &[u8]) -> Vec<ExtractedString> {
    let mut all = extract_ascii(data);
    all.extend(extract_utf16le(data));
    all.sort_by_key(|s| s.offset);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_extracts_printable_runs() {
        let mut data = vec![0x00; 10];
        data.extend_from_slice(b"hello world");
        data.extend_from_slice(&[0x00; 10]);

        let strings = extract_ascii(&data);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello world");
        assert_eq!(strings[0].offset, 10);
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);
    }

    #[test]
    fn ascii_ignores_short_runs() {
        let mut data = vec![0x00; 5];
        data.extend_from_slice(b"Hi");
        data.extend_from_slice(&[0x00; 5]);
        assert!(extract_ascii(&data).is_empty());
    }

    #[test]
    fn ascii_handles_string_at_eof() {
        let data = b"AAAA\x00\x00test";
        let strings = extract_ascii(data);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "AAAA");
        assert_eq!(strings[1].value, "test");
    }

    #[test]
    fn utf16le_extracts_wide_strings() {
        let mut data = vec![0xFF; 4];
        data.extend_from_slice(&[0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00]);
        data.extend_from_slice(&[0xFF; 4]);

        let strings = extract_utf16le(&data);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "ABCD");
        assert_eq!(strings[0].offset, 4);
        assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn utf16le_ignores_short_wide_strings() {
        let data = [0x41, 0x00, 0x42, 0x00];
        assert!(extract_utf16le(&data).is_empty());
    }

    #[test]
    fn extract_all_merges_and_sorts_by_offset() {
        let mut data = vec![0x00; 4];
        data.extend_from_slice(&[0x54, 0x00, 0x45, 0x00, 0x53, 0x00, 0x54, 0x00]);
        data.extend_from_slice(&[0x00; 4]);
        data.extend_from_slice(b"hello");
        data.extend_from_slice(&[0x00; 4]);

        let all = extract_all(&data);
        assert!(all.len() >= 2);
        assert!(all[0].offset < all[1].offset);
    }

    #[test]
    fn empty_input_yields_no_strings() {
        assert!(extract_ascii(&[]).is_empty());
        assert!(extract_utf16le(&[]).is_empty());
        assert!(extract_all(&[]).is_empty());
    }

    #[test]
    fn respects_max_strings_cap() {
        let mut data = Vec::new();
        for i in 0..MAX_STRINGS + 100 {
            data.extend_from_slice(format!("STR{i:05}").as_bytes());
            data.push(0x00);
        }
        assert_eq!(extract_ascii(&data).len(), MAX_STRINGS);
    }
}
