use anchor_lang::prelude::*;

use crate::{constants::*, events::BountyCancelled, state::Bounty};

// Lets the buyer reclaim an escrowed prize once the deadline has passed with
// no submission ever made. Deliberately blocked while a submission is
// pending (`bounty.submitted`) so a buyer can't dodge paying a legitimate
// solver by stalling past the deadline instead of calling resolve_submission.
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
    bounty.assert_open()?;
    bounty.assert_expired(Clock::get()?.unix_timestamp)?;

    emit!(BountyCancelled {
        bounty: bounty.key(),
        buyer: ctx.accounts.buyer.key(),
        bounty_id: bounty.bounty_id,
        refunded_amount: bounty.prize_amount,
    });

    msg!(
        "Bounty {} expired with no submission — prize + rent refunded to buyer",
        bounty.bounty_id
    );
    Ok(())
}
