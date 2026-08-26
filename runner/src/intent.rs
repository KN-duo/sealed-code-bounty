//! Submit-intent signature gate (review R1 / §4.3 handshake).
//!
//! The solver signs `b"SCB_SUBMIT_V1" || bounty_pda || sha256(plaintext)`
//! with their wallet key. The enclave checks this BEFORE any expensive work
//! (unsealing counts as cheap; unpacking/execution never happen without it),
//! binding the submission to whoever possessed the plaintext. A hostile
//! relayer naming its own wallet cannot forge this.

use ed25519_dalek::{Signature, VerifyingKey, Verifier};

pub const INTENT_TAG: &[u8] = b"SCB_SUBMIT_V1";
pub const INTENT_MSG_LEN: usize = INTENT_TAG.len() + 32 + 32;

/// Canonical intent message bytes.
pub fn build_intent_message(bounty_pda: &[u8; 32], plaintext_sha256: &[u8; 32]) -> [u8; INTENT_MSG_LEN] {
    let mut msg = [0u8; INTENT_MSG_LEN];
    msg[..INTENT_TAG.len()].copy_from_slice(INTENT_TAG);
    let mut off = INTENT_TAG.len();
    msg[off..off + 32].copy_from_slice(bounty_pda);
    off += 32;
    msg[off..off + 32].copy_from_slice(plaintext_sha256);
    msg
}

/// Verifies `signature_b64` over the intent message. Returns Ok(()) or a
/// human-readable rejection reason (never logs key material).
pub fn verify_intent(
    bounty_pda: &[u8; 32],
    plaintext_sha256: &[u8; 32],
    solver_pubkey_bytes: &[u8],
    signature_b64: &str,
) -> Result<(), IntentError> {
    use base64::Engine;
    let vk_bytes: [u8; 32] = solver_pubkey_bytes
        .try_into()
        .map_err(|_| IntentError::Malformed("solver pubkey must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| IntentError::Malformed("solver pubkey not a valid ed25519 point"))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|_| IntentError::Malformed("submit_intent_sig must be base64"))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| IntentError::Malformed("submit_intent_sig must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    let msg = build_intent_message(bounty_pda, plaintext_sha256);
    match vk.verify(&msg, &sig) {
        Ok(()) => Ok(()),
        Err(_) => Err(IntentError::BadSignature),
    }
}

#[derive(Debug)]
pub enum IntentError {
    Malformed(&'static str),
    BadSignature,
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentError::Malformed(m) => write!(f, "malformed intent material: {m}"),
            IntentError::BadSignature => write!(f, "submit_intent_sig does not verify against solver_pubkey"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn genuine_intent_verifies_and_tampering_fails() {
        let solver = SigningKey::generate(&mut rand::rngs::OsRng {});
        let pda = [1u8; 32];
        let plaintext = b"#!/usr/bin/env python3\nprint('pwn')\n";
        let mut h = Sha256::new();
        h.update(plaintext);
        let phash: [u8; 32] = h.finalize().into();

        let msg = build_intent_message(&pda, &phash);
        let sig = solver.sign(&msg);

        assert!(verify_intent(&pda, &phash, solver.verifying_key().as_bytes(), &{
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
        })
        .is_ok());

        // Flip one bit of the plaintext hash → different message → reject.
        let mut bad_hash = phash;
        bad_hash[0] ^= 0x01;
        // hex::encode available via hex crate at root
        let b64sig = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        assert!(matches!(
            verify_intent(&pda, &bad_hash, solver.verifying_key().as_bytes(), &b64sig),
            Err(IntentError::BadSignature)
        ));
        // Impostor key fails too.
        let impostor = SigningKey::generate(&mut rand::rngs::OsRng {});
        assert!(matches!(
            verify_intent(&pda, &phash, impostor.verifying_key().as_bytes(), &b64sig),
            Err(IntentError::BadSignature)
        ));
    }

    #[test]
    fn intent_length_matches_spec() {
        assert_eq!(INTENT_MSG_LEN, 77); // 13 tag (SCB_SUBMIT_V1) + 32 pda + 32 hash
    }
}

// ---------------------------------------------------------------------------
// Cross-language fixture (Task 10): committed to test-vectors/intent_v1.json
// so the TS client can assert byte-equality of its own builder.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod intent_vector {
    use super::*;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    use ed25519_dalek::{Signer, SigningKey};

    /// Prints the canonical intent fixture when run with --nocapture.
    #[test]
    fn dump_intent_vector() {
        let pda_bytes = [0xABu8; 32];
        let plaintext = b"exploit";
        let plaintext_sha256 = {
            let mut h = Sha256::new();
            h.update(plaintext);
            h.finalize().into()
        };

        let seed = [7u8; 32]; // deterministic test-key seed
        let sk = SigningKey::from_bytes(&seed);
        let msg = build_intent_message(&pda_bytes, &plaintext_sha256);
        let sig = sk.sign(&msg);

        eprintln!(
            "INTENT {{\"intent_tag_ascii\":\"SCB_SUBMIT_V1\",\"bounty_pda_hex\":\"{}\",\"plaintext_utf8\":\"exploit\",\"plaintext_sha256_hex\":\"{}\",\"solver_secret_seed_hex\":\"{}\",\"message_hex\":\"{}\",\"signature_b64\":\"{}\",\"signature_hex\":\"{}\"}}",
            hex::encode(pda_bytes),
            hex::encode(plaintext_sha256),
            hex::encode(seed),
            hex::encode(msg),
            b64(&sig.to_bytes()),
            hex::encode(sig.to_bytes()),
        );
    }

    fn b64(b: &[u8]) -> String {
        // hex::encode available via hex crate at root
        base64::engine::general_purpose::STANDARD.encode(b)
    }
}
