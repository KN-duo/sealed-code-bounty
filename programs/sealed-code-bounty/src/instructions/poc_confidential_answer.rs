use anchor_lang::prelude::*;
use inco_lightning::cpi::accounts::{Allow, Operation};
use inco_lightning::cpi::{allow, e_eq, new_euint128};
use inco_lightning::ID as INCO_LIGHTNING_ID;

use crate::state::AnswerVault;

// PROOF OF CONCEPT ONLY — proves the confidential-comparison mechanism works
// in isolation before it's wired into the real bounty submit/resolve flow.
// This is deliberately separate: it does NOT touch the Bounty account or
// the escrow logic. Scope is "encrypted answer verification" (submit an
// encrypted guess, compare against an encrypted expected value, learn only
// match/no-match) — not arbitrary code execution, which Inco Lightning does
// not support (see README's corrected architecture notes).

#[derive(Accounts)]
pub struct PocSetAnswer<'info> {
    #[account(init, payer = authority, space = 8 + AnswerVault::INIT_SPACE)]
    pub vault: Account<'info, AnswerVault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: Inco Lightning program, verified by address constraint
    #[account(address = INCO_LIGHTNING_ID)]
    pub inco_lightning_program: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

pub fn handle_poc_set_answer(ctx: Context<PocSetAnswer>, ciphertext: Vec<u8>) -> Result<()> {
    let cpi_ctx = CpiContext::new(
        ctx.accounts.inco_lightning_program.to_account_info(),
        Operation {
            signer: ctx.accounts.authority.to_account_info(),
        },
    );
    let answer = new_euint128(cpi_ctx, ciphertext, 0)?;

    ctx.accounts.vault.authority = ctx.accounts.authority.key();
    ctx.accounts.vault.expected_answer = answer;
    Ok(())
}

#[derive(Accounts)]
pub struct PocCheckAnswer<'info> {
    #[account(mut)]
    pub vault: Account<'info, AnswerVault>,
    #[account(mut)]
    pub guesser: Signer<'info>,
    /// CHECK: Inco Lightning program, verified by address constraint
    #[account(address = INCO_LIGHTNING_ID)]
    pub inco_lightning_program: AccountInfo<'info>,
    /// CHECK: allowance PDA managed by the Inco Lightning program
    #[account(mut)]
    pub allowance_account: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

pub fn handle_poc_check_answer(ctx: Context<PocCheckAnswer>, ciphertext: Vec<u8>) -> Result<()> {
    let cpi_ctx = CpiContext::new(
        ctx.accounts.inco_lightning_program.to_account_info(),
        Operation {
            signer: ctx.accounts.guesser.to_account_info(),
        },
    );
    let guess = new_euint128(cpi_ctx.clone(), ciphertext, 0)?;
    let is_match = e_eq(cpi_ctx, ctx.accounts.vault.expected_answer, guess, 0)?;

    let allow_ctx = CpiContext::new(
        ctx.accounts.inco_lightning_program.to_account_info(),
        Allow {
            allowance_account: ctx.accounts.allowance_account.to_account_info(),
            signer: ctx.accounts.guesser.to_account_info(),
            allowed_address: ctx.accounts.guesser.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
        },
    );
    allow(allow_ctx, is_match.0, true, ctx.accounts.guesser.key())?;

    msg!("Encrypted answer comparison complete — result decryptable by guesser only");
    Ok(())
}
