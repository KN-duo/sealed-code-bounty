use anchor_lang::prelude::*;

use crate::{constants::*, error::ErrorCode, events::BountyCreated, state::Bounty};

#[derive(Accounts)]
#[instruction(bounty_id: u64)]
pub struct CreateBounty<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,
    #[account(
        init,
        payer = buyer,
        space = 8 + Bounty::INIT_SPACE,
        seeds = [BOUNTY_SEED, buyer.key().as_ref(), &bounty_id.to_le_bytes()],
        bump
    )]
    pub bounty: Account<'info, Bounty>,
    pub system_program: Program<'info, System>,
}

pub fn handle_create_bounty(
    ctx: Context<CreateBounty>,
    bounty_id: u64,
    test_suite_hash: [u8; 32],
    prize_amount: u64,
    deadline: i64,
) -> Result<()> {
    require!(prize_amount > 0, ErrorCode::InvalidPrizeAmount);
    require!(
        deadline > Clock::get()?.unix_timestamp,
        ErrorCode::InvalidDeadline
    );

    let bounty = &mut ctx.accounts.bounty;
    bounty.buyer = ctx.accounts.buyer.key();
    bounty.bounty_id = bounty_id;
    bounty.test_suite_hash = test_suite_hash;
    bounty.prize_amount = prize_amount;
    bounty.deadline = deadline;
    bounty.submitted = false;
    bounty.resolved = false;
    bounty.solver = None;
    bounty.solution = String::new();
    bounty.bump = ctx.bumps.bounty;

    let cpi_accounts = anchor_lang::system_program::Transfer {
        from: ctx.accounts.buyer.to_account_info(),
        to: ctx.accounts.bounty.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(anchor_lang::system_program::ID, cpi_accounts);
    anchor_lang::system_program::transfer(cpi_ctx, prize_amount)?;

    emit!(BountyCreated {
        bounty: ctx.accounts.bounty.key(),
        buyer: ctx.accounts.buyer.key(),
        bounty_id,
        prize_amount,
        deadline,
    });

    msg!(
        "Bounty {} created, {} lamports escrowed",
        bounty_id,
        prize_amount
    );
    Ok(())
}
