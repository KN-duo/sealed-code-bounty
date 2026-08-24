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

fn b64_variants(data: &[u8]) -> Vec<String> {
    // All four libsodium/base64 alphabet+padding combinations an attacker's
    // language runtime could emit (Python's b64encode().rstrip("=") included).
    let std_padded = base64::engine::general_purpose::STANDARD.encode(data);
    let std_nopad = base64::engine::general_purpose::STANDARD_NO_PAD.encode(data);
    let url_padded = base64::engine::general_purpose::URL_SAFE.encode(data);
    let url_nopad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
    vec![std_padded, std_nopad, url_padded, url_nopad]
}

/// Every needle that must vanish from hunter-visible output. Longest-first,
/// deduplicated. SINGLE SOURCE OF TRUTH: both [`redact`] and [`leaks`] call
/// this, so they can never diverge.
pub fn needles(flag: &FlagString) -> Vec<String> {
    let raw = flag.expose();
    let bytes = flag.expose_bytes();

    let hex_lower = hex::encode(bytes);
    let hex_upper = hex_lower.to_uppercase();
    let b64_all = b64_variants(bytes);

    let mut all: Vec<String> = Vec::new();

    // Double encodings first (longest): hex over every b64 variant,
    // every b64 variant over hex(lower/upper) and over the raw base58.
    for b64v in &b64_all {
        all.push(hex::encode(b64v.as_bytes()));
        all.push(b64_variants(b64v.as_bytes()).pop().unwrap_or_default());
        all.push(b64_variants(b64v.as_bytes())[0].clone());
        all.push(b64_variants(b64v.as_bytes())[1].clone());
        all.push(b64_variants(b64v.as_bytes())[2].clone());
        all.push(b64_variants(b64v.as_bytes())[3].clone());
        void(b64v);
    }
    for hx in [&hex_lower, &hex_upper] {
        all.extend(b64_variants(hx.as_bytes()));
    }
    all.extend(b64_variants(raw.as_bytes()));

    // Single encodings.
    all.push(hex_upper);
    all.push(hex_lower);
    all.push(raw.to_string());

    all.retain(|s| !s.is_empty());
    all.sort_by_key(|s| std::cmp::Reverse(s.len()));
    all.dedup();
    all
}

#[inline]
fn void<T>(_: &T) {}

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

/// True if any encoding of the flag survives in `output`. Shares the exact
/// needle builder with [`redact`] — they cannot diverge.
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
        let b64v = base64::engine::general_purpose::STANDARD.encode(flag.expose_bytes());

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
        let b64v = base64::engine::general_purpose::STANDARD.encode(bytes);
        let hex_of_b64 = hex::encode(b64v.as_bytes());
        let b64_of_hex_lower = base64::engine::general_purpose::STANDARD
            .encode(hex::encode(bytes).as_bytes());
        let b64_of_hex_upper = base64::engine::general_purpose::STANDARD
            .encode(hex::encode(bytes).to_uppercase().as_bytes());

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

    #[test]
    fn rstrip_equals_b64_attack_is_caught() {
        // The audit's empirical bypass: Python's
        //   base64.b64encode(flag).decode().rstrip("=")
        // emits the UNPADDED standard-alphabet encoding, which the legacy
        // needle set (STANDARD padded only) missed entirely.
        let flag = fixture_flag();
        let bytes = flag.expose_bytes();
        use base64::Engine as _;
        let padded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let stripped = padded.trim_end_matches('=').to_string();
        assert_ne!(stripped, padded, "fixture must actually lose padding");

        // BEFORE (legacy builder): leaks() would return true -> bypass.
        let legacy_needles = [padded.clone()];
        assert!(
            !legacy_needles.iter().any(|n| stripped.contains(n)),
            "sanity: legacy needles miss the stripped form"
        );

        // AFTER: the shared builder catches it.
        assert!(leaks(&stripped, &flag), "leaks must see the stripped form");
        assert!(!leaks(&redact(&format!("out={stripped}"), &flag), &flag));
    }

    #[test]
    fn urlsafe_alphabet_variants_are_caught() {
        let flag = fixture_flag();
        let bytes = flag.expose_bytes();
        use base64::Engine as _;
        let url = base64::engine::general_purpose::URL_SAFE.encode(bytes);
        let url_nopad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        for v in [url, url_nopad] {
            assert!(leaks(&v, &flag), "survived: {v}");
            assert!(!leaks(&redact(&v, &flag), &flag));
        }
    }
}
