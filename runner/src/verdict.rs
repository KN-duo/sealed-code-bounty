//! Verdict construction and signing (R3 wire, D14 stable keys).
//!
//! The 175-byte message MUST stay byte-identical to:
//!   programs/sealed-code-bounty/src/instructions/resolve_with_attestation.rs
//!   relayer/src/verdict.ts
//! layout: tag(14) || bounty_pda(32) || env_blob_sha256(32) ||
//!         exploit_sha256(32) || solver(32) || flag_commitment(32) || outcome(1)

use ed25519_dalek::{Signature, Signer, SigningKey};

pub const VERDICT_TAG: &[u8] = b"SCB_VERDICT_V3";
pub const VERDICT_MSG_LEN: usize = 175;

#[derive(Debug)]
pub struct VerdictFields<'a> {
    pub bounty_pda: &'a [u8; 32],
    pub env_blob_sha256: &'a [u8; 32],
    pub exploit_sha256: &'a [u8; 32],
    pub solver: &'a [u8; 32],
    pub flag_commitment: &'a [u8; 32],
    pub outcome: bool,
}

/// Canonical verdict bytes. Panics only on programmer error (lengths are
/// statically enforced by the type).
pub fn build_message(f: &VerdictFields<'_>) -> [u8; VERDICT_MSG_LEN] {
    let mut msg = [0u8; VERDICT_MSG_LEN];
    let mut off = 0usize;
    msg[off..off + VERDICT_TAG.len()].copy_from_slice(VERDICT_TAG);
    off += VERDICT_TAG.len();
    msg[off..off + 32].copy_from_slice(f.bounty_pda);
    off += 32;
    msg[off..off + 32].copy_from_slice(f.env_blob_sha256);
    off += 32;
    msg[off..off + 32].copy_from_slice(f.exploit_sha256);
    off += 32;
    msg[off..off + 32].copy_from_slice(f.solver);
    off += 32;
    msg[off..off + 32].copy_from_slice(f.flag_commitment);
    off += 32;
    msg[off] = u8::from(f.outcome);
    debug_assert_eq!(off + 1, VERDICT_MSG_LEN);
    msg
}

/// Stable per-deployment signing key: ed25519 seed from
/// HKDF-SHA256(M, salt=b"scb-runner", info=b"scb-verdict-key-v1") (R3/D14).
pub fn verdict_signing_key(master_secret: &[u8; 32]) -> SigningKey {
    let seed = crate::flag::derive_verdict_seed(master_secret);
    SigningKey::from_bytes(&seed)
}

/// Signs the canonical message; returns (sig64, pubkey32).
pub fn sign_verdict(
    key: &SigningKey,
    fields: &VerdictFields<'_>,
) -> ([u8; 64], [u8; 32]) {
    let msg = build_message(fields);
    let sig: Signature = key.sign(&msg);
    (sig.to_bytes(), key.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    // Golden fixture — cross-language anchor for the TS side (relayer tests).
    const GOLDEN_M_HEX: &str =
        "4242424242424242424242424242424242424242424242424242424242424242";
    const GOLDEN_PDA_B58: &str = "H6mYd6dBAMsSNcMzu32rCrUzDzT4Q8zZ3vJqtdpjKbAt";

    #[test]
    fn layout_and_outcome_byte() {
        let pda = [1u8; 32];
        let env = [2u8; 32];
        let ex = [3u8; 32];
        let sol = [4u8; 32];
        let fc = [5u8; 32];

        let pass = build_message(&VerdictFields {
            bounty_pda: &pda,
            env_blob_sha256: &env,
            exploit_sha256: &ex,
            solver: &sol,
            flag_commitment: &fc,
            outcome: true,
        });
        assert_eq!(&pass[0..14], b"SCB_VERDICT_V3");
        assert_eq!(pass[14], 1);
        assert_eq!(pass[174], 1);

        let fail = build_message(&VerdictFields {
            outcome: false,
            ..VerdictFields {
                bounty_pda: &pda,
                env_blob_sha256: &env,
                exploit_sha256: &ex,
                solver: &sol,
                flag_commitment: &fc,
                outcome: true,
            }
        });
        assert_eq!(pass[0..174], fail[0..174]);
        assert_eq!(fail[174], 0);
    }

    #[test]
    fn golden_cross_language_vector() {
        // Deterministic under fixed M; TS tests may pin these same values.
        let m: [u8; 32] = hex::decode(GOLDEN_M_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let pda_bytes: [u8; 32] = bs58::decode(GOLDEN_PDA_B58)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();

        let env: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x20));
        let ex: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x40));
        let sol: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x60));

        // Flag derivation must match runner/src/flag.rs (same M).
        let flag = crate::flag::derive_flag(&m, &pda_bytes);
        let fc = crate::flag::flag_commitment(&flag);

        let key = verdict_signing_key(&m);
        let (sig, vk) = sign_verdict(
            &key,
            &VerdictFields {
                bounty_pda: &pda_bytes,
                env_blob_sha256: &env,
                exploit_sha256: &ex,
                solver: &sol,
                flag_commitment: &fc,
                outcome: true,
            },
        );

        // Cross-check against the committed golden file so any drift in the
        // Rust layout breaks loudly here before it can break the chain.
        let _msg_hex = hex::encode(build_message(&VerdictFields {
            bounty_pda: &pda_bytes,
            env_blob_sha256: &env,
            exploit_sha256: &ex,
            solver: &sol,
            flag_commitment: &fc,
            outcome: true,
        }));
        let golden_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/verdict_v3.json");
        let golden = std::fs::read_to_string(&golden_path)
            .map(|s| serde_json::from_str::<serde_json::Value>(&s).expect("golden json"))
            .expect("tests/golden/verdict_v3.json present");

        assert_eq!(
            golden["operator_pubkey_hex"].as_str().unwrap(),
            hex::encode(vk),
            "verifier pubkey drifted"
        );
        assert_eq!(golden["message_hex"].as_str().unwrap(), hex::encode(build_message(&VerdictFields {
            bounty_pda: &pda_bytes,
            env_blob_sha256: &env,
            exploit_sha256: &ex,
            solver: &sol,
            flag_commitment: &fc,
            outcome: true,
        })));
        assert_eq!(
            golden["signature_b64"].as_str().unwrap(),
            base64::engine::general_purpose::STANDARD.encode(sig)
        );
        assert_eq!(
            golden["flag_commitment_hex"].as_str().unwrap(),
            hex::encode(fc)
        );
        assert_eq!(golden["master_secret_hex"].as_str().unwrap(), GOLDEN_M_HEX);
        assert_eq!(golden["bounty_pda_b58"].as_str().unwrap(), GOLDEN_PDA_B58);
    }
}
