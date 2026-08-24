use anchor_lang::prelude::*;

use crate::constants::{MAX_BLOB_URL_LEN, MAX_CIPHERTEXT_LEN, MAX_OPERATORS};
use crate::error::ErrorCode;

// Bounty lifecycle (v2). `Open` accepts a single submission slot; a verdict
// either pays the solver (`Resolved`) or hands the slot back (`Open`).
//
//   Open ──submit_exploit──▶ AwaitingResolution ──resolve(PASS)──▶ Resolved
//    ▲                            │                                │
//    └──── resolve(FAIL) /        │        cancel_expired_bounty ◀─┘ (Open only)
//          force_unlock ──────────┘
#[derive(
    AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, PartialEq, Eq, Debug, InitSpace,
)]
pub enum BountyStatus {
    #[default]
    Open,
    AwaitingResolution,
    Resolved,
    Cancelled,
}

/// The single in-flight submission slot (v1 serialization keeps first-PASS-wins
/// trivial — D5 v1 note in docs/BUILD_PLAN_v2.md). The bond recorded here sits
/// inside the Bounty PDA and is refunded on every resolution path.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, InitSpace)]
pub struct SubmissionRef {
    pub solver: Pubkey,
    pub exploit_sha256: [u8; 32],
    #[max_len(MAX_BLOB_URL_LEN)]
    pub blob_url: String,
    pub bond_lamports: u64,
    pub submitted_at: i64,
}

/// Global protocol configuration — singleton PDA seeded `["config"]`.
/// Holds the enclave operator key set + threshold (D7) and the X25519 key
/// hunters encrypt uploads to.
#[account]
#[derive(InitSpace)]
pub struct Config {
    pub platform_authority: Pubkey,
    #[max_len(MAX_OPERATORS)]
    pub operators: Vec<Pubkey>,
    /// Required number of distinct operator signatures per verdict.
    pub threshold: u8,
    /// Enclave's X25519 encryption key; exploit uploads are sealed to it client-side.
    pub enclave_enc_pk: [u8; 32],
    /// Refundable anti-spam bond per submission (D10).
    pub submission_bond_lamports: u64,
    pub bump: u8,
}

/// Escrow PDA seeded `["bounty", buyer, bounty_id]`. Prize lamports are held
/// by this account from creation until payout/cancel.
#[account]
#[derive(InitSpace)]
pub struct Bounty {
    pub buyer: Pubkey,
    pub bounty_id: u64,
    pub status: BountyStatus,
    pub prize_lamports: u64,
    pub deadline: i64,
    /// SHA-256 of the manifest JSON (§4.2 of docs/BUILD_PLAN_v2.md).
    pub manifest_sha256: [u8; 32],
    /// SHA-256 of the environment tarball the enclave will pull and verify.
    pub env_blob_sha256: [u8; 32],
    /// sha256(flag) for this bounty; enforced against every PASS verdict.
    pub flag_commitment: [u8; 32],
    /// Buyer's X25519 public key — reveals are sealed boxes to this key.
    pub buyer_enc_pk: [u8; 32],
    pub current_submission: Option<SubmissionRef>,
    pub winner: Option<Pubkey>,
    pub bump: u8,
}

/// Reputation primitive (D12) — PDA `["receipt", bounty, winner]`, minted on PASS.
#[account]
#[derive(InitSpace)]
pub struct Receipt {
    pub bounty: Pubkey,
    pub solver: Pubkey,
    pub exploit_sha256: [u8; 32],
    pub first_blood: bool,
    pub timestamp: i64,
}

/// Encrypted exploit handed to the buyer on PASS — PDA `["reveal", bounty]`.
/// Inline ciphertext up to MAX_CIPHERTEXT_LEN bytes; larger blobs fall back to
/// an object-storage URL + hash (both encrypted with the same sealed-box scheme).
#[account]
#[derive(InitSpace)]
pub struct Reveal {
    #[max_len(MAX_CIPHERTEXT_LEN)]
    pub ciphertext: Vec<u8>,
    #[max_len(MAX_BLOB_URL_LEN)]
    pub ciphertext_url: String,
    pub ciphertext_sha256: [u8; 32],
}

impl Bounty {
    pub fn is_open(&self) -> bool {
        self.status == BountyStatus::Open
    }

    pub fn is_awaiting_resolution(&self) -> bool {
        self.status == BountyStatus::AwaitingResolution
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now > self.deadline
    }

    pub fn assert_open(&self) -> Result<()> {
        require!(self.is_open(), ErrorCode::NotOpen);
        Ok(())
    }

    pub fn assert_awaiting_resolution(&self) -> Result<()> {
        require!(
            self.is_awaiting_resolution(),
            ErrorCode::NotAwaitingResolution
        );
        Ok(())
    }

    pub fn assert_expired(&self, now: i64) -> Result<()> {
        require!(self.is_expired(now), ErrorCode::NotExpiredYet);
        Ok(())
    }

    /// Clears the submission slot and returns the bounty to `Open` so another
    /// hunter may submit. Used by FAIL resolutions and force_unlock_submission;
    /// callers are responsible for refunding the bond first.
    pub fn discard_submission(&mut self) {
        self.current_submission = None;
        self.status = BountyStatus::Open;
    }
}
