use anchor_lang::prelude::*;
use inco_lightning::types::Euint128;

// Holds a confidentially-stored expected answer so a guess can be compared
// against it via Inco Lightning's e_eq without ever revealing either value
// on-chain in plaintext.
#[account]
pub struct AnswerVault {
    pub authority: Pubkey,
    pub expected_answer: Euint128,
}
