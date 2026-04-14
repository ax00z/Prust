// entropy.rs — Shannon entropy calculation
//
// Shannon entropy formula:
//   H = -Σ p(x) * log2(p(x))
// where p(x) is the probability of byte value x occurring in the data.
//
// Result range: 0.0 (all identical bytes) to 8.0 (perfectly random).
// Thresholds:
//   < 1.0  — very low, likely sparse/padded data
//   4.0-6.0 — normal code or structured data
//   6.5-7.0 — compressed or obfuscated
//   > 7.0  — encrypted or packed (suspicious for code sections)

/// Compute Shannon entropy of a byte slice. Returns bits per byte (0.0 to 8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count occurrences of each byte value (0-255)
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Classify an entropy value into a human-readable label.
pub fn entropy_label(entropy: f64) -> &'static str {
    if entropy < 1.0 {
        "very low (sparse/padded)"
    } else if entropy < 4.8 {
        "normal"
    } else if entropy < 6.5 {
        "moderate"
    } else if entropy < 7.0 {
        "high (possibly compressed)"
    } else {
        "very high (packed/encrypted)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn repeated_single_byte_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[0x41; 32]), 0.0);
    }

    #[test]
    fn evenly_split_two_byte_stream_has_one_bit_of_entropy() {
        let entropy = shannon_entropy(&[0x00, 0xFF, 0x00, 0xFF]);
        assert!((entropy - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn entropy_labels_cover_boundary_ranges() {
        assert_eq!(entropy_label(0.5), "very low (sparse/padded)");
        assert_eq!(entropy_label(4.0), "normal");
        assert_eq!(entropy_label(5.5), "moderate");
        assert_eq!(entropy_label(6.8), "high (possibly compressed)");
        assert_eq!(entropy_label(7.2), "very high (packed/encrypted)");
    }
}
