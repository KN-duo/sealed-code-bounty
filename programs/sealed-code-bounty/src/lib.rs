pub mod constants;
pub mod error;
pub mod events;
pub mod instructions;
pub mod state;

use anchor_lang::prelude::*;

pub use constants::*;
pub use events::*;
pub use instructions::*;
pub use state::*;

declare_id!("FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V");

#[program]
pub mod sealed_code_bounty {
    use super::*;

    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        platform_authority: Pubkey,
        enclave_enc_pk: [u8; 32],
        submission_bond_lamports: u64,
    ) -> Result<()> {
        crate::instructions::initialize_config::handle_initialize_config(
            ctx,
            platform_authority,
            enclave_enc_pk,
            submission_bond_lamports,
        )
    }

    pub fn set_operators(
        ctx: Context<SetOperators>,
        operators: Vec<Pubkey>,
        threshold: u8,
        enclave_enc_pk: [u8; 32],
        force_unlock_delay_s: i64,
    ) -> Result<()> {
        crate::instructions::set_operators::handle_set_operators(
            ctx,
            operators,
            threshold,
            enclave_enc_pk,
            force_unlock_delay_s,
        )
    }

    pub fn create_bounty(
        ctx: Context<CreateBounty>,
        bounty_id: u64,
        prize_lamports: u64,
        deadline: i64,
        manifest_sha256: [u8; 32],
        env_blob_sha256: [u8; 32],
        flag_commitment: [u8; 32],
        buyer_enc_pk: [u8; 32],
    ) -> Result<()> {
        crate::instructions::create_bounty::handle_create_bounty(
            ctx,
            bounty_id,
            prize_lamports,
            deadline,
            manifest_sha256,
            env_blob_sha256,
            flag_commitment,
            buyer_enc_pk,
        )
    }

    pub fn submit_exploit(
        ctx: Context<SubmitExploit>,
        bounty_id: u64,
        blob_url: String,
        exploit_sha256: [u8; 32],
    ) -> Result<()> {
        crate::instructions::submit_exploit::handle_submit_exploit(
            ctx,
            bounty_id,
            blob_url,
            exploit_sha256,
        )
    }

    pub fn resolve_with_attestation(
        ctx: Context<ResolveWithAttestation>,
        bounty_id: u64,
        outcome: bool,
        reveal_ciphertext: Vec<u8>,
        ciphertext_url: String,
        ciphertext_sha256: [u8; 32],
    ) -> Result<()> {
        crate::instructions::resolve_with_attestation::handle_resolve_with_attestation(
            ctx,
            bounty_id,
            outcome,
            reveal_ciphertext,
            ciphertext_url,
            ciphertext_sha256,
        )
    }

    pub fn cancel_expired_bounty(ctx: Context<CancelExpiredBounty>, bounty_id: u64) -> Result<()> {
        crate::instructions::cancel_expired_bounty::handle_cancel_expired_bounty(ctx, bounty_id)
    }

    pub fn force_unlock_submission(
        ctx: Context<ForceUnlockSubmission>,
        bounty_id: u64,
    ) -> Result<()> {
        crate::instructions::force_unlock_submission::handle_force_unlock_submission(ctx, bounty_id)
    }
}
