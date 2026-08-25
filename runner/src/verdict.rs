//! Verdict construction and signing (V4 wire, D14 stable keys).
//!
//! The 207-byte message MUST stay byte-identical to:
//!   programs/sealed-code-bounty/src/instructions/resolve_with_attestation.rs
//!   relayer/src/verdict.ts
//! layout: tag(14) || bounty_pda(32) || env_blob_sha256(32) ||
//!         exploit_sha256(32) || solver(32) || flag_commitment(32) ||
//!         buyer_enc_pk(32) || outcome(1)

use ed25519_dalek::{Signature, Signer, SigningKey};

pub const VERDICT_TAG: &[u8] = b"SCB_VERDICT_V4";
pub const VERDICT_MSG_LEN: usize = 207;

#[derive(Debug)]
pub struct VerdictFields<'a> {
    pub bounty_pda: &'a [u8; 32],
    pub env_blob_sha256: &'a [u8; 32],
    pub exploit_sha256: &'a [u8; 32],
    pub solver: &'a [u8; 32],
    pub flag_commitment: &'a [u8; 32],
    /// V4: binds the buyer's reveal key (audit M2) — a colluding
    /// relayer+solver can no longer redirect the PASS ciphertext.
    pub buyer_enc_pk: &'a [u8; 32],
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
    msg[off..off + 32].copy_from_slice(f.buyer_enc_pk);
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
        let buyer = [6u8; 32];

        let pass = build_message(&VerdictFields {
            bounty_pda: &pda,
            env_blob_sha256: &env,
            exploit_sha256: &ex,
            solver: &sol,
            flag_commitment: &fc,
            buyer_enc_pk: &buyer,
            outcome: true,
        });
        assert_eq!(&pass[0..14], b"SCB_VERDICT_V4");
        assert_eq!(&pass[142..174], &fc);
        assert_eq!(&pass[174..206], &buyer); // V4 position
        assert_eq!(pass[206], 1);

        let fail = build_message(&VerdictFields {
            bounty_pda: &pda,
            env_blob_sha256: &env,
            exploit_sha256: &ex,
            solver: &sol,
            flag_commitment: &fc,
            buyer_enc_pk: &buyer,
            outcome: false,
        });
        assert_eq!(pass[0..206], fail[0..206]);
        assert_eq!(fail[206], 0);
    }

    /// Prints the golden JSON when run with --nocapture; values below are
    /// pinned in tests/golden/verdict_v4.json and asserted by
    /// golden_cross_language_vector.
    #[test]
    fn dump_golden() {
        let m: [u8; 32] = hex::decode(GOLDEN_M_HEX).unwrap().try_into().unwrap();
        let pda_bytes: [u8; 32] =
            bs58::decode(GOLDEN_PDA_B58).into_vec().unwrap().try_into().unwrap();
        let env: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x20));
        let ex: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x40));
        let sol: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x60));
        let flag = crate::flag::derive_flag(&m, &pda_bytes);
        let fc = crate::flag::flag_commitment(&flag);
        let key = verdict_signing_key(&m);
        let fields = VerdictFields {
            bounty_pda: &pda_bytes,
            env_blob_sha256: &env,
            exploit_sha256: &ex,
            solver: &sol,
            flag_commitment: &fc,
            buyer_enc_pk: &[0x09u8; 32],
            outcome: true,
        };
        let (sig, vk) = sign_verdict(&key, &fields);
        eprintln!(
            "GOLDEN {}",
            serde_json::json!({
                "master_secret_hex": GOLDEN_M_HEX,
                "bounty_pda_b58": GOLDEN_PDA_B58,
                "tag_ascii": "SCB_VERDICT_V4",
                "env_blob_sha256_hex": hex::encode(fields.env_blob_sha256),
                "exploit_sha256_hex": hex::encode(fields.exploit_sha256),
                "solver_pubkey_hex": hex::encode(fields.solver),
                "operator_pubkey_hex": hex::encode(vk),
                "flag_commitment_hex": hex::encode(fc),
                "buyer_enc_pk_hex": hex::encode(fields.buyer_enc_pk),
                "outcome_byte": "01",
                "message_hex": hex::encode(build_message(&fields)),
                "signature_b64": base64::engine::general_purpose::STANDARD.encode(sig),
            })
        );
    }

    #[test]
    fn golden_cross_language_vector() {
        let m: [u8; 32] = hex::decode(GOLDEN_M_HEX).unwrap().try_into().unwrap();
        let pda_bytes: [u8; 32] =
            bs58::decode(GOLDEN_PDA_B58).into_vec().unwrap().try_into().unwrap();
        let env: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x20));
        let ex: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x40));
        let sol: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x60));
        let buyer: [u8; 32] = [0x09u8; 32];

        let flag = crate::flag::derive_flag(&m, &pda_bytes);
        let fc = crate::flag::flag_commitment(&flag);

        let fields = VerdictFields {
            bounty_pda: &pda_bytes,
            env_blob_sha256: &env,
            exploit_sha256: &ex,
            solver: &sol,
            flag_commitment: &fc,
            buyer_enc_pk: &buyer,
            outcome: true,
        };
        let key = verdict_signing_key(&m);
        let (sig, vk) = sign_verdict(&key, &fields);

        let golden_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/verdict_v4.json");
        let golden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&golden_path)
                .expect("tests/golden/verdict_v4.json present"),
        )
        .expect("golden json");

        assert_eq!(golden["master_secret_hex"].as_str().unwrap(), GOLDEN_M_HEX);
        assert_eq!(golden["bounty_pda_b58"].as_str().unwrap(), GOLDEN_PDA_B58);
        assert_eq!(
            golden["operator_pubkey_hex"].as_str().unwrap(),
            hex::encode(vk),
            "verifier pubkey drifted"
        );
        assert_eq!(
            golden["flag_commitment_hex"].as_str().unwrap(),
            hex::encode(fc)
        );
        assert_eq!(
            golden["buyer_enc_pk_hex"].as_str().unwrap(),
            hex::encode(buyer)
        );
        assert_eq!(
            golden["message_hex"].as_str().unwrap(),
            hex::encode(build_message(&fields))
        );
        assert_eq!(
            golden["signature_b64"].as_str().unwrap(),
            base64::engine::general_purpose::STANDARD.encode(sig)
        );
    }
}
