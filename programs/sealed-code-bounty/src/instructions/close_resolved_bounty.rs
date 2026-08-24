use anchor_lang::prelude::*;

use crate::{
    constants::BOUNTY_SEED,
    error::ErrorCode,
    events::BountyClosed,
    state::{Bounty, BountyStatus},
};

// Audit L2: Resolved bounties never closed — prize long gone but the account
// rent stays locked forever. Permissionless sweep: anyone may close a
// Resolved bounty; rent is ALWAYS refunded to the buyer, so the permission-
// less caller has nothing to gain and buyers are never needed for cleanup.
#[derive(Accounts)]
#[instruction(bounty_id: u64)]
pub struct CloseResolvedBounty<'info> {
    /// CHECK: any wallet may trigger the sweep.
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(
        mut,
        seeds = [BOUNTY_SEED, bounty.buyer.as_ref(), &bounty_id.to_le_bytes()],
        bump = bounty.bump,
        constraint = bounty.buyer == buyer.key() @ ErrorCode::Unauthorized,
        close = buyer,
    )]
    pub bounty: Account<'info, Bounty>,
    /// CHECK: rent recipient — enforced to be the buyer above.
    #[account(mut)]
    pub buyer: UncheckedAccount<'info>,
}

pub fn handle_close_resolved_bounty(
    ctx: Context<CloseResolvedBounty>,
    _bounty_id: u64,
) -> Result<()> {
    require!(
        ctx.accounts.bounty.status == BountyStatus::Resolved,
        ErrorCode::NotResolved
    );
    emit!(BountyClosed {
        bounty_id: ctx.accounts.bounty.bounty_id,
        buyer: ctx.accounts.bounty.buyer,
    });
    msg!("Resolved bounty {} swept — rent returned to buyer", ctx.accounts.bounty.bounty_id);
    Ok(())
}
