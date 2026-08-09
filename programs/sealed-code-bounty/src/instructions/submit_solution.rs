use anchor_lang::prelude::*;

use crate::{constants::*, error::ErrorCode, events::SolutionSubmitted, state::Bounty};

#[derive(Accounts)]
#[instruction(bounty_id: u64)]
pub struct SubmitSolution<'info> {
    #[account(mut)]
    pub solver: Signer<'info>,
    #[account(
        mut,
        seeds = [BOUNTY_SEED, bounty.buyer.as_ref(), &bounty_id.to_le_bytes()],
        bump = bounty.bump,
    )]
    pub bounty: Account<'info, Bounty>,
    /// CHECK: fee recipient, validated against bounty.buyer
    #[account(mut, address = bounty.buyer)]
    pub buyer: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

pub fn handle_submit_solution(
    ctx: Context<SubmitSolution>,
    _bounty_id: u64,
    solution: String,
) -> Result<()> {
    {
        let bounty = &ctx.accounts.bounty;
        bounty.assert_open()?;
        require!(
            solution.len() as u64 <= MAX_SOLUTION_LEN,
            ErrorCode::SolutionTooLong
        );
    }

    let cpi_accounts = anchor_lang::system_program::Transfer {
        from: ctx.accounts.solver.to_account_info(),
        to: ctx.accounts.buyer.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(anchor_lang::system_program::ID, cpi_accounts);
    anchor_lang::system_program::transfer(cpi_ctx, SUBMISSION_FEE_LAMPORTS)?;

    let bounty = &mut ctx.accounts.bounty;
    bounty.solver = Some(ctx.accounts.solver.key());
    bounty.solution = solution;
    bounty.submitted = true;

    emit!(SolutionSubmitted {
        bounty: bounty.key(),
        solver: ctx.accounts.solver.key(),
        bounty_id: bounty.bounty_id,
    });

    msg!("Solution submitted for bounty {}", bounty.bounty_id);
    Ok(())
}
