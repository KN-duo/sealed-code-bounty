pub mod constants;
pub mod error;
pub mod instructions;
pub mod state;

use anchor_lang::prelude::*;

pub use constants::*;
pub use instructions::*;
pub use state::*;

declare_id!("FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V");

#[program]
pub mod sealed_code_bounty {
    use super::*;

    pub fn create_bounty(
        ctx: Context<CreateBounty>,
        bounty_id: u64,
        test_suite_hash: [u8; 32],
        prize_amount: u64,
        deadline: i64,
    ) -> Result<()> {
        crate::instructions::create_bounty::handle_create_bounty(
            ctx,
            bounty_id,
            test_suite_hash,
            prize_amount,
            deadline,
        )
    }

    pub fn submit_solution(
        ctx: Context<SubmitSolution>,
        bounty_id: u64,
        solution: String,
    ) -> Result<()> {
        crate::instructions::submit_solution::handle_submit_solution(ctx, bounty_id, solution)
    }

    pub fn resolve_submission(
        ctx: Context<ResolveSubmission>,
        bounty_id: u64,
        passed: bool,
    ) -> Result<()> {
        crate::instructions::resolve_submission::handle_resolve_submission(ctx, bounty_id, passed)
    }

    pub fn cancel_expired_bounty(
        ctx: Context<CancelExpiredBounty>,
        bounty_id: u64,
    ) -> Result<()> {
        crate::instructions::cancel_expired_bounty::handle_cancel_expired_bounty(ctx, bounty_id)
    }

    // Standalone proof-of-concept instructions (see poc_confidential_answer.rs)
    // — not yet wired into the real bounty flow.
    pub fn poc_set_answer(ctx: Context<PocSetAnswer>, ciphertext: Vec<u8>) -> Result<()> {
        crate::instructions::poc_confidential_answer::handle_poc_set_answer(ctx, ciphertext)
    }

    pub fn poc_check_answer(ctx: Context<PocCheckAnswer>, ciphertext: Vec<u8>) -> Result<()> {
        crate::instructions::poc_confidential_answer::handle_poc_check_answer(ctx, ciphertext)
    }
}
