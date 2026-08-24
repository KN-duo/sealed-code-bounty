use anchor_lang::prelude::*;

#[constant]
pub const CONFIG_SEED: &[u8] = b"config";

#[constant]
pub const BOUNTY_SEED: &[u8] = b"bounty";

#[constant]
pub const RECEIPT_SEED: &[u8] = b"receipt";

#[constant]
pub const REVEAL_SEED: &[u8] = b"reveal";

// Native ed25519 signature-verification program. Verdicts are verified by
// introspecting Ed25519SigVerify instructions placed earlier in the same
// transaction — see instructions/resolve_with_attestation.rs.
pub const ED25519_PROGRAM_ID: Pubkey = pubkey!("Ed25519SigVerify111111111111111111111111111");

/// Upper bound on operator keys pinned in `Config` (bounds account sizing; the
/// threshold design is k-of-n from day one even though launch runs n=1).
pub const MAX_OPERATORS: usize = 10;

/// `SubmissionRef.blob_url` length cap (chars).
pub const MAX_BLOB_URL_LEN: usize = 200;

/// Inline `Reveal.ciphertext` cap (bytes) for a libsodium sealed box.
pub const MAX_CIPHERTEXT_LEN: usize = 10_240;

/// Seconds a submission may sit in `AwaitingResolution` before anyone may call
/// `force_unlock_submission`. A hostile/silent relayer can only delay a bounty,
/// never lock its prize (review P0-4).
pub const FORCE_UNLOCK_DELAY_S: i64 = 3600;

/// Native instructions-sysvar program id (introspected by
/// `resolve_with_attestation`; anchor-lang's `solana_program` facade does not
/// re-export it, so it is pinned here literally).
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey =
    pubkey!("Sysvar1nstructions1111111111111111111111111");

/// Domain tag signed by the enclave in front of every verdict
/// (`SCB_VERDICT_V3`, 14 bytes — domain separation + format version).
pub const VERDICT_DOMAIN_TAG: &[u8] = b"SCB_VERDICT_V3";

/// Canonical verdict wire length:
/// 14 B tag || 32 B bounty_pda || 32 B env_blob_sha256 || 32 B exploit_sha256
/// || 32 B solver || 32 B flag_commitment || 1 B outcome.
///
/// V3 binds `env_blob_sha256`: without it a colluding relayer could mint a
/// PASS against a fake weak environment and the chain could not tell.
pub const VERDICT_MSG_LEN: usize = 175;
