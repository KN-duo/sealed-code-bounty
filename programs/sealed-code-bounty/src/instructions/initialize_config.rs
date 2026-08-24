use anchor_lang::prelude::*;

use crate::{constants::CONFIG_SEED, events::ConfigInitialized, state::Config};

// One-time protocol bootstrap. The operator key set itself is pinned
// afterwards via set_operators once the enclave's attested ed25519 key has
// been verified off-chain against the pinned PCR0 (docs/BUILD_PLAN_v2.md §4.4).
#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    /// CHECK: deployer paying rent — need not equal `platform_authority`.
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = 8 + Config::INIT_SPACE,
        seeds = [CONFIG_SEED],
        bump
    )]
    pub config: Account<'info, Config>,
    pub system_program: Program<'info, System>,
}

pub fn handle_initialize_config(
    ctx: Context<InitializeConfig>,
    platform_authority: Pubkey,
    enclave_enc_pk: [u8; 32],
    submission_bond_lamports: u64,
) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.platform_authority = platform_authority;
    config.operators = Vec::new();
    config.threshold = 0;
    config.enclave_enc_pk = enclave_enc_pk;
    config.submission_bond_lamports = submission_bond_lamports;
    config.bump = ctx.bumps.config;

    emit!(ConfigInitialized {
        platform_authority,
        enclave_enc_pk,
        submission_bond_lamports,
    });

    msg!("Config initialized (authority {})", platform_authority);
    Ok(())
}
