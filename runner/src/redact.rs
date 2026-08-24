//! Output redaction (D11, security-critical).
//!
//! Given raw process output and a [`FlagString`], remove every encoding of
//! the flag that an exploit could plausibly emit: the raw string, hex
//! (lower+upper), base64, base58 (= the raw string itself), and the double
//! encodings (hex-of-base64, base64-of-hex-lower/upper, base64-of-base58,
//! hex-of-base58...). Longer needles are replaced first so shorter encodings
//! cannot corrupt longer ones into undetected fragments.

use crate::flag::FlagString;
use base64::Engine;

pub const REDACTION_TOKEN: &str = "[REDACTED]";

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Every needle that must vanish from hunter-visible output. Order: longest
/// first. Deduplicated.
pub fn needles(flag: &FlagString) -> Vec<String> {
    let raw = flag.expose();
    let bytes = flag.expose_bytes();

    let hex_lower = hex::encode(bytes);
    let hex_upper = hex_lower.to_uppercase();
    let b64_str = b64(bytes);

    // Double encodings.
    let mut doubles: Vec<String> = vec![
        hex::encode(b64_str.as_bytes()),          // hex of base64
        b64(hex_lower.as_bytes()),                // base64 of hex(lower)
        b64(hex_upper.as_bytes()),                // base64 of hex(upper)
        hex::encode(raw.as_bytes()),              // hex of base58 == hex of raw
        b64(raw.as_bytes()),                      // base64 of base58 == base64 of raw
    ];
    doubles.sort_by_key(|s| std::cmp::Reverse(s.len()));

    let mut all: Vec<String> = doubles;
    all.push(b64_str);
    all.push(hex_upper);
    all.push(hex_lower);
    all.push(raw.to_string());
    all.retain(|s| !s.is_empty());
    all.dedup(); // requires sort; re-sort by length desc after dedup:
    all.sort_by_key(|s| std::cmp::Reverse(s.len()));
    all.dedup();
    all
}

/// Replaces every occurrence of every flag encoding with [`REDACTION_TOKEN`].
pub fn redact(output: &str, flag: &FlagString) -> String {
    let mut out = output.to_string();
    for needle in needles(flag) {
        if out.contains(&needle) {
            out = out.replace(&needle, REDACTION_TOKEN);
        }
    }
    out
}

/// True if any encoding of the flag survives in `output`. Used by tests and
/// by the verify pipeline's final paranoia sweep.
pub fn leaks(output: &str, flag: &FlagString) -> bool {
    needles(flag).iter().any(|n| output.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_flag() -> FlagString {
        FlagString::from_raw("2r98DvGdwryXYPe1R8L9KdtWmS33DjMkb4a6bybGG7dA".to_string())
    }

    #[test]
    fn removes_raw_hex_and_base64() {
        let flag = fixture_flag();
        let hex_l = hex::encode(flag.expose_bytes());
        let hex_u = hex_l.to_uppercase();
        let b64v = b64(flag.expose_bytes());

        let raw_out = format!(
            "before {f} mid {hl} MID {hu} mId {b} end",
            f = flag.expose(),
            hl = hex_l,
            hu = hex_u,
            b = b64v
        );
        let out = redact(&raw_out, &flag);
        assert!(!leaks(&out, &flag));
        assert!(out.contains(REDACTION_TOKEN));
        assert_eq!(out.matches(REDACTION_TOKEN).count(), 4);
    }

    #[test]
    fn removes_double_encodings() {
        let flag = fixture_flag();
        let bytes = flag.expose_bytes();
        let b64v = b64(bytes);
        let hex_of_b64 = hex::encode(b64v.as_bytes());
        let b64_of_hex_lower = b64(hex::encode(bytes).as_bytes());
        let b64_of_hex_upper = b64(hex::encode(bytes).to_uppercase().as_bytes());

        for encoded in [hex_of_b64, b64_of_hex_lower, b64_of_hex_upper] {
            let cleaned = redact(&format!("leak attempt: {encoded}"), &flag);
            assert!(!leaks(&cleaned, &flag), "survived: {encoded}");
        }
    }

    #[test]
    fn adjacent_and_repeated_occurrences_are_all_removed() {
        let flag = fixture_flag();
        let doubled = format!("{}{}", flag.expose(), flag.expose());
        let glued = format!("x{}y{}z", flag.expose(), flag.expose());
        assert!(!leaks(&redact(&doubled, &flag), &flag));
        assert!(!leaks(&redact(&glued, &flag), &flag));
    }

    #[test]
    fn partial_overlap_does_not_resurrect_a_needle() {
        // A hex encoding whose tail overlaps the head of the raw flag inside
        // one contiguous run — replacement must not leave a valid fragment.
        let flag = fixture_flag();
        let hex_l = hex::encode(flag.expose_bytes());
        let crafted = format!("{}{}{}", &hex_l[..hex_l.len() - 3], flag.expose(), "tail");
        let cleaned = redact(&crafted, &flag);
        assert!(!leaks(&cleaned, &flag));
    }

    #[test]
    fn benign_output_passes_through_untouched() {
        let flag = fixture_flag();
        let benign = "Traceback (most recent call last):\n  stage3 reached, ret=-5\n";
        assert_eq!(redact(benign, &flag), benign);
        assert!(!leaks(benign, &flag));
    }

    #[test]
    fn empty_output_is_fine() {
        let flag = fixture_flag();
        assert_eq!(redact("", &flag), "");
    }
}
