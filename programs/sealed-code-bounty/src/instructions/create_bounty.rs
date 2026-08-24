use anchor_lang::prelude::*;

use crate::{
    constants::*,
    error::ErrorCode,
    events::BountyCreated,
    state::{Bounty, BountyStatus, Config},
};

// Buyer escrows the prize and pins everything the enclave needs to verify a
// submission: manifest + environment hashes, the sha256(flag) commitment
// produced by the enclave sealing step, and an X25519 key to encrypt reveals.
#[derive(Accounts)]
#[instruction(bounty_id: u64)]
pub struct CreateBounty<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
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
    prize_lamports: u64,
    deadline: i64,
    manifest_sha256: [u8; 32],
    env_blob_sha256: [u8; 32],
    flag_commitment: [u8; 32],
    buyer_enc_pk: [u8; 32],
) -> Result<()> {
    require!(prize_lamports > 0, ErrorCode::InvalidPrizeAmount);
    require!(
        deadline > Clock::get()?.unix_timestamp,
        ErrorCode::InvalidDeadline
    );

    let bounty = &mut ctx.accounts.bounty;
    bounty.buyer = ctx.accounts.buyer.key();
    bounty.bounty_id = bounty_id;
    bounty.status = BountyStatus::Open;
    bounty.prize_lamports = prize_lamports;
    bounty.deadline = deadline;
    bounty.manifest_sha256 = manifest_sha256;
    bounty.env_blob_sha256 = env_blob_sha256;
    bounty.flag_commitment = flag_commitment;
    bounty.buyer_enc_pk = buyer_enc_pk;
    bounty.current_submission = None;
    bounty.winner = None;
    bounty.bump = ctx.bumps.bounty;

    let cpi_accounts = anchor_lang::system_program::Transfer {
        from: ctx.accounts.buyer.to_account_info(),
        to: ctx.accounts.bounty.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(anchor_lang::system_program::ID, cpi_accounts);
    anchor_lang::system_program::transfer(cpi_ctx, prize_lamports)?;

    emit!(BountyCreated {
        bounty: ctx.accounts.bounty.key(),
        buyer: ctx.accounts.buyer.key(),
        bounty_id,
        prize_lamports,
        deadline,
    });

    msg!(
        "Bounty {} created, {} lamports escrowed",
        bounty_id,
        prize_lamports
    );
    Ok(())
}
