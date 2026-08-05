use anchor_lang::prelude::*;

use crate::{constants::*, error::ErrorCode, state::Bounty};

// MVP stand-in for the TEE relayer: the bounty's own buyer manually reports
// PASS/FAIL. Step 4 replaces this signer check with verification of a signed
// Inco attestation, so nobody (including the buyer) can lie about the result.
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
    require!(bounty.submitted, ErrorCode::NoSubmission);
    require!(!bounty.resolved, ErrorCode::AlreadyResolved);
    require_keys_eq!(
        bounty.solver.unwrap(),
        solver_key,
        ErrorCode::SolverMismatch
    );

    if passed {
        let prize = bounty.prize_amount;
        **bounty.to_account_info().try_borrow_mut_lamports()? -= prize;
        **ctx.accounts.solver.to_account_info().try_borrow_mut_lamports()? += prize;
        bounty.resolved = true;
        msg!(
            "Bounty {} PASSED — {} lamports paid to solver",
            bounty.bounty_id,
            prize
        );
    } else {
        bounty.submitted = false;
        bounty.solver = None;
        bounty.solution = String::new();
        msg!(
            "Bounty {} FAILED — submission discarded, solver may retry",
            bounty.bounty_id
        );
    }

    Ok(())
}
