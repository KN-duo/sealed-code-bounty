pub mod instructions;
pub mod state;

use anchor_lang::prelude::*;

pub use instructions::*;
pub use state::*;

declare_id!("2whLGMTr7v1dRwG4gyR9X5EBWWceaLZ57tjHfvzc5t8T");

// Standalone proof of concept: proves the confidential-comparison mechanism
// works in isolation (submit an encrypted guess, compare against an
// encrypted expected value on Inco Lightning, learn only match/no-match)
// before it's wired into the real bounty submit/resolve flow. Deliberately
// kept in its own program — not a CPI callee of sealed-code-bounty yet —
// because inco-lightning pins anchor-lang 0.31.1 while sealed-code-bounty
// uses 1.1.2; mixing both in one crate breaks trait resolution on shared
// types like AnswerVault. See EXPLAIN.md for the plan to bridge the two via
// CPI once the real TEE-attestation flow lands.
#[program]
pub mod sealed_code_bounty_poc {
    use super::*;

    pub fn set_answer(ctx: Context<SetAnswer>, ciphertext: Vec<u8>) -> Result<()> {
        crate::instructions::handle_set_answer(ctx, ciphertext)
    }

    pub fn check_answer(ctx: Context<CheckAnswer>, ciphertext: Vec<u8>) -> Result<()> {
        crate::instructions::handle_check_answer(ctx, ciphertext)
    }
}
