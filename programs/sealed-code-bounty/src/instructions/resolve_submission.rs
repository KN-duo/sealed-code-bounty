use anchor_lang::prelude::*;

use crate::{constants::*, error::ErrorCode, events::BountyResolved, state::Bounty};

// MVP stand-in for the TEE relayer: the bounty's own buyer manually reports
// PASS/FAIL. Phase 1 (v2) replaces this whole instruction with
// `resolve_with_attestation`, which verifies an enclave-signed verdict
// (AWS Nitro, ed25519) so nobody — including the buyer — can lie about the
// result. See docs/BUILD_PLAN_v2.md §4.1.
#[derive(Accounts)]
#[instruction(bounty_id: u64)]
pub struct ResolveSubmission<'info> {
    pub buyer: Signer<'info>,
    #[account(
        mut,
        seeds = [BOUNTY_SEED, buyer.key().as_ref(), &bounty_id.to_le_bytes()],
        bump = bounty.bump,
    )]
    pub bounty: Account<'info, Bounty>,
    /// CHECK: payout destination, validated in the handler against bounty.solver
    #[account(mut)]
    pub solver: UncheckedAccount<'info>,
}

pub fn handle_resolve_submission(
    ctx: Context<ResolveSubmission>,
    _bounty_id: u64,
    passed: bool,
) -> Result<()> {
    let solver_key = ctx.accounts.solver.key();
    let bounty = &mut ctx.accounts.bounty;
    bounty.assert_awaiting_resolution()?;
    require_keys_eq!(
        bounty.solver.unwrap(),
        solver_key,
        ErrorCode::SolverMismatch
    );

    let bounty_key = bounty.key();
    let bounty_id = bounty.bounty_id;
    let prize = bounty.prize_amount;

    if passed {
        **bounty.to_account_info().try_borrow_mut_lamports()? -= prize;
        **ctx
            .accounts
            .solver
            .to_account_info()
            .try_borrow_mut_lamports()? += prize;
        bounty.resolved = true;
        msg!(
            "Bounty {} PASSED — {} lamports paid to solver",
            bounty_id,
            prize
        );
    } else {
        bounty.discard_submission();
        msg!(
            "Bounty {} FAILED — submission discarded, solver may retry",
            bounty_id
        );
    }

    emit!(BountyResolved {
        bounty: bounty_key,
        solver: solver_key,
        bounty_id,
        passed,
        prize_amount: prize,
    });

    Ok(())
}
