use anchor_lang::prelude::*;

use crate::{
    constants::{CONFIG_SEED, MAX_OPERATORS},
    error::ErrorCode,
    events::OperatorSetChanged,
    state::Config,
};

// Authority-only rotation of the enclave trust root (D7): the operator ed25519
// key set, the required threshold, and the X25519 encryption key hunters seal
// uploads to. Designed as a k-of-n set from day one even though launch runs n=1.
#[derive(Accounts)]
pub struct SetOperators<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = authority.key() == config.platform_authority @ ErrorCode::Unauthorized
    )]
    pub config: Account<'info, Config>,
}

pub fn handle_set_operators(
    ctx: Context<SetOperators>,
    operators: Vec<Pubkey>,
    threshold: u8,
    enclave_enc_pk: [u8; 32],
) -> Result<()> {
    require!(!operators.is_empty(), ErrorCode::InvalidOperators);
    require!(operators.len() <= MAX_OPERATORS, ErrorCode::InvalidOperators);
    for i in 0..operators.len() {
        require!(
            !operators[i + 1..].contains(&operators[i]),
            ErrorCode::InvalidOperators
        );
    }
    require!(
        threshold >= 1 && threshold as usize <= operators.len(),
        ErrorCode::BadThreshold
    );

    let config = &mut ctx.accounts.config;
    config.operators = operators.clone();
    config.threshold = threshold;
    config.enclave_enc_pk = enclave_enc_pk;

    emit!(OperatorSetChanged {
        operators,
        threshold,
        enclave_enc_pk,
    });

    msg!(
        "Operator set updated: {} operator(s), threshold {}",
        config.operators.len(),
        threshold
    );
    Ok(())
}
