use anchor_lang::prelude::*;

use crate::{
    constants::*,
    error::ErrorCode,
    events::SubmissionUnlocked,
    state::Bounty,
};

// Anti-censorship escape hatch (review P0-4): if the relayer sits on a verdict
// (or vanishes), ANYONE may unlock the bounty once FORCE_UNLOCK_DELAY_S has
// passed since submission. The bond is refunded to the solver and the slot is
// wiped, so a hostile/silent relayer can only delay a bounty, never lock its
// prize.
#[derive(Accounts)]
#[instruction(bounty_id: u64)]
pub struct ForceUnlockSubmission<'info> {
    /// CHECK: permissionless caller — any wallet may trigger the unlock.
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(
        mut,
        seeds = [BOUNTY_SEED, bounty.buyer.as_ref(), &bounty_id.to_le_bytes()],
        bump = bounty.bump,
    )]
    pub bounty: Account<'info, Bounty>,
    /// CHECK: bond refund destination — must equal
    /// `current_submission.solver`; enforced in the handler.
    #[account(mut)]
    pub solver: UncheckedAccount<'info>,
}

pub fn handle_force_unlock_submission(
    ctx: Context<ForceUnlockSubmission>,
    _bounty_id: u64,
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;

    ctx.accounts.bounty.assert_awaiting_resolution()?;
    let submission = ctx
        .accounts
        .bounty
        .current_submission
        .clone()
        .ok_or(ErrorCode::NoSubmission)?;
    require_keys_eq!(
        ctx.accounts.solver.key(),
        submission.solver,
        ErrorCode::SolverMismatch
    );
    require!(
        now >= submission.submitted_at.saturating_add(FORCE_UNLOCK_DELAY_S),
        ErrorCode::ForceUnlockTooEarly
    );

    // Refund the bond out of the escrow PDA back to the solver.
    let bounty_info = ctx.accounts.bounty.to_account_info();
    let solver_info = ctx.accounts.solver.to_account_info();
    let new_bounty_lamports = bounty_info
        .lamports()
        .checked_sub(submission.bond_lamports)
        .ok_or(ErrorCode::EscrowInsufficient)?;
    **bounty_info.try_borrow_mut_lamports()? = new_bounty_lamports;
    let new_solver_lamports = solver_info
        .lamports()
        .checked_add(submission.bond_lamports)
        .ok_or(ErrorCode::EscrowInsufficient)?;
    **solver_info.try_borrow_mut_lamports()? = new_solver_lamports;

    let solver_key = submission.solver;
    let bounty_id = ctx.accounts.bounty.bounty_id;
    ctx.accounts.bounty.discard_submission();

    emit!(SubmissionUnlocked {
        bounty: ctx.accounts.bounty.key(),
        solver: solver_key,
        bounty_id,
    });

    msg!(
        "Bounty {} unlocked after relayer silence — bond refunded",
        bounty_id
    );
    Ok(())
}
