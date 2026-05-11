// Hex byte-pattern scanner with `??` wildcards.

const MAX_PATTERN_LEN: usize = 256;
const MAX_HITS_PER_PATTERN: usize = 32;

/// `None` = `??` wildcard, `Some(b)` = literal byte.
pub type PatternByte = Option<u8>;

#[derive(Debug, Clone)]
pub struct Pattern {
    pub name: &'static str,
    pub severity: u32,
    pub description: &'static str,
    pub bytes: Vec<PatternByte>,
}

#[derive(Debug, Clone)]
pub struct PatternHit {
    pub pattern: &'static str,
    pub severity: u32,
    pub description: &'static str,
    pub offset: usize,
}

pub fn parse_pattern(src: &str) -> Option<Vec<PatternByte>> {
    let mut out = Vec::new();
    for tok in src.split_ascii_whitespace() {
        if tok.len() != 2 {
            return None;
        }
        if tok == "??" || tok.eq_ignore_ascii_case("??") {
            out.push(None);
        } else {
            let b = u8::from_str_radix(tok, 16).ok()?;
            out.push(Some(b));
        }
        if out.len() > MAX_PATTERN_LEN {
            return None;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

#[inline]
fn window_matches(pattern: &[PatternByte], window: &[u8]) -> bool {
    pattern.iter().zip(window.iter()).all(|(p, &b)| match p {
        Some(expected) => *expected == b,
        None => true,
    })
}

pub fn scan(data: &[u8], pattern: &[PatternByte]) -> Vec<usize> {
    if pattern.is_empty() || pattern.len() > data.len() {
        return Vec::new();
    }

    let mut hits = Vec::new();
    for (i, window) in data.windows(pattern.len()).enumerate() {
        if window_matches(pattern, window) {
            hits.push(i);
            if hits.len() >= MAX_HITS_PER_PATTERN {
                break;
            }
        }
    }
    hits
}

pub fn builtin_patterns() -> Vec<Pattern> {
    let sources: &[(&'static str, u32, &'static str, &'static str)] = &[
        (
            "SHELLCODE_CALL_POP",
            6,
            "Call-pop prologue - common shellcode technique for PIC",
            "E8 00 00 00 00 5B",
        ),
        (
            "SHELLCODE_CALL_POP_58",
            6,
            "Call-pop prologue (pop eax variant)",
            "E8 00 00 00 00 58",
        ),
        (
            "UPX_ENTRY_STUB",
            7,
            "UPX entry-point stub",
            "60 BE ?? ?? ?? ?? 8D BE",
        ),
        (
            "PEB_FS30_ACCESS",
            5,
            "mov eax, fs:[30h] - manual PEB walk for dynamic API resolution",
            "64 A1 30 00 00 00",
        ),
        (
            "PEB_GS60_ACCESS",
            5,
            "mov rax, gs:[60h] - x64 PEB walk",
            "65 48 8B 04 25 60 00 00 00",
        ),
        (
            "EMBEDDED_MZ",
            8,
            "Embedded PE file (MZ header followed by DOS stub)",
            "4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 00 00",
        ),
    ];

    sources
        .iter()
        .filter_map(|(name, severity, description, src)| {
            parse_pattern(src).map(|bytes| Pattern {
                name,
                severity: *severity,
                description,
                bytes,
            })
        })
        .collect()
}

/// First hit per pattern, sorted by offset.
pub fn scan_all(data: &[u8], patterns: &[Pattern]) -> Vec<PatternHit> {
    let mut hits = Vec::new();
    for pat in patterns {
        let offsets = scan(data, &pat.bytes);
        if let Some(&first) = offsets.first() {
            hits.push(PatternHit {
                pattern: pat.name,
                severity: pat.severity,
                description: pat.description,
                offset: first,
            });
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits
}

/// First section raw-data offset.
pub fn first_section_offset(sections: &[crate::pe::SectionHeader]) -> usize {
    sections
        .iter()
        .map(|s| s.pointer_to_raw_data as usize)
        .filter(|&p| p > 0)
        .min()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_hex() {
        let p = parse_pattern("DE AD BE EF").unwrap();
        assert_eq!(p, vec![Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)]);
    }

    #[test]
    fn parse_with_wildcards() {
        let p = parse_pattern("AA ?? CC").unwrap();
        assert_eq!(p, vec![Some(0xAA), None, Some(0xCC)]);
    }

    #[test]
    fn parse_rejects_bad_tokens() {
        assert!(parse_pattern("XY").is_none());
        assert!(parse_pattern("A").is_none());
        assert!(parse_pattern("ABC").is_none());
        assert!(parse_pattern("").is_none());
    }

    #[test]
    fn scan_finds_exact_match() {
        let data = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00];
        let pat = parse_pattern("DE AD BE EF").unwrap();
        assert_eq!(scan(&data, &pat), vec![2]);
    }

    #[test]
    fn scan_respects_wildcards() {
        let data = [0xAA, 0x11, 0xCC, 0xAA, 0x22, 0xCC];
        let pat = parse_pattern("AA ?? CC").unwrap();
        assert_eq!(scan(&data, &pat), vec![0, 3]);
    }

    #[test]
    fn scan_handles_no_match() {
        let data = [0x00; 32];
        let pat = parse_pattern("DE AD BE EF").unwrap();
        assert!(scan(&data, &pat).is_empty());
    }

    #[test]
    fn scan_respects_max_hits() {
        let data = vec![0xAAu8; 1024];
        let pat = parse_pattern("AA").unwrap();
        let hits = scan(&data, &pat);
        assert!(hits.len() <= MAX_HITS_PER_PATTERN);
    }

    #[test]
    fn scan_rejects_pattern_larger_than_data() {
        let data = [0xDE, 0xAD];
        let pat = parse_pattern("DE AD BE EF").unwrap();
        assert!(scan(&data, &pat).is_empty());
    }

    #[test]
    fn builtin_patterns_all_parse() {
        let patterns = builtin_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().all(|p| !p.bytes.is_empty()));
    }

    #[test]
    fn scan_all_finds_embedded_mz() {
        let mut data = vec![0x00; 100];
        let mz_start = 50;
        data[mz_start] = 0x4D;
        data[mz_start + 1] = 0x5A;
        data[mz_start + 40] = 0x50;
        data[mz_start + 41] = 0x45;
        let patterns = builtin_patterns();
        let hits = scan_all(&data, &patterns);
        assert!(hits.iter().any(|h| h.pattern == "EMBEDDED_MZ"));
    }
}
