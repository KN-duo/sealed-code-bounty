use anchor_lang::prelude::*;
use inco_lightning::types::Euint128;

use crate::constants::MAX_SOLUTION_LEN;

// Standalone proof-of-concept, not yet wired into the real bounty flow:
// holds a confidentially-stored expected answer so a guess can be compared
// against it via Inco Lightning's e_eq without ever revealing either value
// on-chain in plaintext.
#[account]
pub struct AnswerVault {
    pub authority: Pubkey,
    pub expected_answer: Euint128,
}

#[account]
#[derive(InitSpace)]
pub struct Bounty {
    pub buyer: Pubkey,
    pub bounty_id: u64,
    pub test_suite_hash: [u8; 32],
    pub prize_amount: u64,
    pub deadline: i64,
    pub submitted: bool,
    pub resolved: bool,
    pub solver: Option<Pubkey>,
    #[max_len(MAX_SOLUTION_LEN)]
    pub solution: String,
    pub bump: u8,
}
