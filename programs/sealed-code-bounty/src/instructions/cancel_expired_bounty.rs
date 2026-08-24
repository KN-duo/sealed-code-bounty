use anchor_lang::prelude::*;

use crate::{
    constants::*,
    error::ErrorCode,
    events::BountyCancelled,
    state::{Bounty, BountyStatus},
};

// Lets the buyer reclaim an escrowed prize once the deadline has passed with
// no submission ever made. Deliberately blocked while the submission slot is
// claimed (status == AwaitingResolution) so a buyer can't dodge paying a
// legitimate solver by stalling past the deadline instead of landing a
// verdict; the solver-side counterpart to that stall is
// force_unlock_submission.
#[derive(Accounts)]
#[instruction(bounty_id: u64)]
pub struct CancelExpiredBounty<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,
    #[account(
        mut,
        seeds = [BOUNTY_SEED, buyer.key().as_ref(), &bounty_id.to_le_bytes()],
        bump = bounty.bump,
        close = buyer,
    )]
    pub bounty: Account<'info, Bounty>,
}

pub fn handle_cancel_expired_bounty(
    ctx: Context<CancelExpiredBounty>,
    _bounty_id: u64,
) -> Result<()> {
    let bounty = &ctx.accounts.bounty;
    require!(
        bounty.status == BountyStatus::Open && bounty.current_submission.is_none(),
        ErrorCode::NotOpen
    );
    bounty.assert_expired(Clock::get()?.unix_timestamp)?;

    emit!(BountyCancelled {
        bounty: bounty.key(),
        buyer: ctx.accounts.buyer.key(),
        bounty_id: bounty.bounty_id,
        refunded_amount: bounty.prize_lamports,
    });

    msg!(
        "Bounty {} expired with no submission — prize + rent refunded to buyer",
        bounty.bounty_id
    );
    Ok(())
}
