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
///
/// Hard ceiling rationale: an account CREATED BY CPI (init_if_needed inside
/// our instruction) may hold at most 10_240 bytes of data. Reveal totals
/// 8 (discriminator) + 4 + CIPHERTEXT + 4 + 200 (url) + 32 (sha256), so the
/// inline payload must stay <= ~9.7 KB. Larger exploits use the URL fallback
/// path (same sealed-box scheme, blob off-chain) — BUILD_PLAN_v2.md §4.1/D9.
pub const MAX_CIPHERTEXT_LEN: usize = 9_700;

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
/// (`SCB_VERDICT_V4`, 14 bytes — domain separation + format version).
///
/// INVARIANT (audit L4): verdicts are pure functions of the bound inputs
/// below. NEVER rotate the master secret `M` or an environment blob for a
/// LIVE bounty — doing so would make previously-signed verdicts replayable
/// against the mutated state.
pub const VERDICT_DOMAIN_TAG: &[u8] = b"SCB_VERDICT_V4";

/// Canonical verdict wire length:
/// 14 B tag || 32 B bounty_pda || 32 B env_blob_sha256 || 32 B exploit_sha256
/// || 32 B solver || 32 B flag_commitment || 32 B buyer_enc_pk || 1 B outcome.
///
/// V3 bound `env_blob_sha256` (fake-weak-environment hole).
/// V4 binds `buyer_enc_pk`: without it a colluding relayer+solver could
/// redirect the PASS reveal ciphertext to an attacker X25519 key and the
/// buyer would receive an unopenable box, silently.
pub const VERDICT_MSG_LEN: usize = 207;
