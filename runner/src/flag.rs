//! Flag material: the [`FlagString`] newtype and deterministic per-bounty
//! flag derivation (D14/R3).
//!
//! Security contract: a flag value is a secret. It must never be formatted,
//! logged, or serialized. The newtype has no `Display` impl and a `Debug`
//! impl that prints only `[REDACTED]`, so `tracing`/`log` calls and any
//! accidental `{}` formatting fail to compile or leak nothing.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// A secret flag string (32-byte HKDF output, base58-encoded). Not `Display`.
pub struct FlagString(String);

impl std::fmt::Debug for FlagString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FlagString([REDACTED])")
    }
}

impl FlagString {
    /// Wrap an already-derived flag. Callers: derivation + test fixtures only.
    pub fn from_raw(raw: String) -> Self {
        Self(raw)
    }

    /// Deliberately awkward, clearly-marked accessor for the three legitimate
    /// consumers: rootfs injection, output scanning, commitment computation.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Raw bytes of the base58 string (what hex/base64 encodings are built
    /// from by the redactor).
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub const FLAG_HKDF_INFO: &[u8] = b"scb-flag-v1";
pub const VERDICT_KEY_HKDF_INFO: &[u8] = b"scb-verdict-key-v1";

fn hkdf_sha256(ikm: &[u8; 32], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand to 32 bytes cannot fail");
    okm
}

/// Deterministic per-bounty flag: base58(HKDF-SHA256(M, salt=bounty_pda,
/// info=b"scb-flag-v1")). Same M + same bounty ⇒ same flag across restarts.
pub fn derive_flag(master_secret: &[u8; 32], bounty_pda: &[u8; 32]) -> FlagString {
    let out = hkdf_sha256(master_secret, bounty_pda, FLAG_HKDF_INFO);
    FlagString(bs58::encode(out).into_string())
}

/// Public sha256(flag) — safe to publish; committed on-chain at seal time.
pub fn flag_commitment(flag: &FlagString) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(flag.expose_bytes());
    h.finalize().into()
}

/// Deterministic ed25519 signing seed for verdict keys (R3/D14): derived from
/// M so enclave redeploys keep the same pinned operator identity.
pub fn derive_verdict_seed(master_secret: &[u8; 32]) -> [u8; 32] {
    hkdf_sha256(master_secret, b"scb-runner", VERDICT_KEY_HKDF_INFO)
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: [u8; 32] = [0x42; 32];

    #[test]
    fn derivation_is_deterministic_and_binds_the_bounty() {
        let pda_a = [7u8; 32];
        let f1 = derive_flag(&M, &pda_a);
        let f2 = derive_flag(&M, &pda_a);
        assert_eq!(f1.expose(), f2.expose());

        let pda_b = [8u8; 32];
        let fb = derive_flag(&M, &pda_b);
        assert_ne!(f1.expose(), fb.expose());

        // Different master ⇒ different flags for the same bounty.
        let m2 = [0x43u8; 32];
        assert_ne!(f1.expose(), derive_flag(&m2, &pda_a).expose());
    }

    #[test]
    fn flag_is_valid_base58_of_32_bytes() {
        let f = derive_flag(&M, &[9u8; 32]);
        let decoded = bs58::decode(f.expose()).into_vec().expect("valid base58");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn debug_impl_never_leaks() {
        let f = derive_flag(&M, &[1u8; 32]);
        let dbg = format!("{f:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(f.expose()));
    }
}
