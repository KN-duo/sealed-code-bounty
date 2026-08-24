use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::{
    load_current_index_checked, load_instruction_at_checked,
};

use crate::{
    constants::*,
    error::ErrorCode,
    events::BountyResolved,
    state::{Bounty, Config, Receipt, Reveal},
};

// PERMISSIONLESS resolution (docs/BUILD_PLAN_v2.md §4.1). Anyone may land an
// enclave-signed verdict; trust comes from cryptography, not identity:
//
//   1. The handler RECOMPUTES the canonical `SCB_VERDICT_V2` message bytes
//      from its own accounts/args — never from anything the relayer supplies.
//   2. Every native Ed25519SigVerify instruction placed EARLIER in this same
//      transaction is parsed (native data layout: num_signatures header, then
//      per-signature offsets + embedded pubkey/sig/message bytes) and its
//      embedded message must equal the recomputed bytes byte-for-byte with
//      msg_size == VERDICT_MSG_LEN. Because the recomputed message already
//      binds bounty_pda, exploit_sha256, solver, flag_commitment and outcome,
//      this equality enforces every binding at once.
//   3. Every signing pubkey must be a pinned `Config.operator`, appear at most
//      once (duplicate padding rejected), and `Config.threshold` DISTINCT
//      operators must be collected.
//
// Presence of an Ed25519 instruction alone proves nothing; atomicity plus this
// introspection together prove the enclave signed exactly these bytes.
//
// PASS ⇒ bond refunded, prize paid, Receipt + Reveal PDAs created (pass them as
// `Some`). FAIL ⇒ bond refunded, slot wiped, bounty back to Open (pass them as
// `None`; optional accounts skip their constraints entirely).
#[derive(Accounts)]
#[instruction(bounty_id: u64)]
pub struct ResolveWithAttestation<'info> {
    /// CHECK: permissionless relayer — any wallet may submit a verdict; it is
    /// never authorized beyond paying fees and rent here.
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [BOUNTY_SEED, bounty.buyer.as_ref(), &bounty_id.to_le_bytes()],
        bump = bounty.bump,
    )]
    pub bounty: Account<'info, Bounty>,
    /// CHECK: payout destination — must equal `current_submission.solver`;
    /// enforced in the handler before any lamports move.
    #[account(mut)]
    pub solver: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = relayer,
        space = 8 + Receipt::INIT_SPACE,
        seeds = [RECEIPT_SEED, bounty.key().as_ref(), solver.key().as_ref()],
        bump
    )]
    pub receipt: Option<Account<'info, Receipt>>,
    #[account(
        init_if_needed,
        payer = relayer,
        space = 8 + Reveal::INIT_SPACE,
        seeds = [REVEAL_SEED, bounty.key().as_ref()],
        bump
    )]
    pub reveal: Option<Account<'info, Reveal>>,
    /// CHECK: native ed25519 signature-verification program; its well-known
    /// address is enforced by the constraint below.
    #[account(address = ED25519_PROGRAM_ID)]
    pub ed25519_program: UncheckedAccount<'info>,
    /// CHECK: instructions sysvar — used to introspect the surrounding
    /// transaction; validated by the anchor loader helpers.
    #[account(address = anchor_lang::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// One parsed signature entry out of an Ed25519SigVerify instruction.
struct VerdictCandidate {
    signer: [u8; 32],
    signature: [u8; 64],
    message: Vec<u8>,
}

fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    if off.checked_add(2).is_none() || off + 2 > data.len() {
        return Err(ErrorCode::MissingSigVerify.into());
    }
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

/// Parses the native ed25519 program's instruction data. Layout:
/// `[num_signatures u8][padding u8]` then per signature seven little-endian
/// u16 offsets/sizes (`signature_offset`, `signature_instruction_index`,
/// `public_key_offset`, `public_key_instruction_index`, `message_data_offset`,
/// `message_data_size`, `message_instruction_index`) followed somewhere in the
/// data by the embedded pubkey/signature/message bytes themselves. Offsets
/// referencing OTHER instructions (`*_instruction_index != u16::MAX`) cannot be
/// bound by this handler and are rejected outright.
fn parse_ed25519_verify_data(data: &[u8]) -> Result<Vec<VerdictCandidate>> {
    if data.is_empty() {
        return Err(ErrorCode::MissingSigVerify.into());
    }
    let num_signatures = data[0] as usize;
    if num_signatures == 0 {
        return Err(ErrorCode::MissingSigVerify.into());
    }

    const EMBEDDED_IN_THIS_INSTRUCTION: u16 = u16::MAX;
    let mut out = Vec::with_capacity(num_signatures);

    for i in 0..num_signatures {
        let base = 2usize.checked_add(i.checked_mul(14).ok_or_else(|| error!(ErrorCode::MissingSigVerify))?).ok_or_else(|| error!(ErrorCode::MissingSigVerify))?;
        let signature_offset = read_u16(data, base)? as usize;
        let signature_instruction_index = read_u16(data, base.saturating_add(2))?;
        let public_key_offset = read_u16(data, base.saturating_add(4))? as usize;
        let public_key_instruction_index = read_u16(data, base.saturating_add(6))?;
        let message_data_offset = read_u16(data, base.saturating_add(8))? as usize;
        let message_data_size = read_u16(data, base.saturating_add(10))? as usize;
        let message_instruction_index = read_u16(data, base.saturating_add(12))?;

        require!(
            signature_instruction_index == EMBEDDED_IN_THIS_INSTRUCTION
                && public_key_instruction_index == EMBEDDED_IN_THIS_INSTRUCTION
                && message_instruction_index == EMBEDDED_IN_THIS_INSTRUCTION,
            ErrorCode::MissingSigVerify
        );

        let sig_end = signature_offset.checked_add(64).ok_or_else(|| error!(ErrorCode::MissingSigVerify))?;
        let pk_end = public_key_offset.checked_add(32).ok_or_else(|| error!(ErrorCode::MissingSigVerify))?;
        let msg_end = message_data_offset
            .checked_add(message_data_size)
            .ok_or_else(|| error!(ErrorCode::MissingSigVerify))?;
        if sig_end > data.len() || pk_end > data.len() || msg_end > data.len() {
            return Err(ErrorCode::MissingSigVerify.into());
        }

        out.push(VerdictCandidate {
            signer: data[public_key_offset..pk_end]
                .try_into()
                .map_err(|_| error!(ErrorCode::MissingSigVerify))?,
            signature: data[signature_offset..sig_end]
                .try_into()
                .map_err(|_| error!(ErrorCode::MissingSigVerify))?,
            message: data[message_data_offset..msg_end].to_vec(),
        });
    }
    Ok(out)
}

pub fn handle_resolve_with_attestation(
    ctx: Context<ResolveWithAttestation>,
    outcome: bool,
    reveal_ciphertext: Vec<u8>,
    ciphertext_url: String,
    ciphertext_sha256: [u8; 32],
) -> Result<()> {
    let config = &ctx.accounts.config;
    let bounty_acc = &ctx.accounts.bounty;
    let now = Clock::get()?.unix_timestamp;

    bounty_acc.assert_awaiting_resolution()?;
    let submission = bounty_acc
        .current_submission
        .clone()
        .ok_or(ErrorCode::NoSubmission)?;

    // ---- 1. Recompute the canonical verdict message from OUR OWN state ----
    let bounty_key = bounty_acc.key();
    let flag_commitment = bounty_acc.flag_commitment;
    let mut expected_msg = Vec::with_capacity(VERDICT_MSG_LEN);
    expected_msg.extend_from_slice(VERDICT_DOMAIN_TAG);
    expected_msg.extend_from_slice(bounty_key.as_ref());
    expected_msg.extend_from_slice(&submission.exploit_sha256);
    expected_msg.extend_from_slice(submission.solver.as_ref());
    expected_msg.extend_from_slice(&flag_commitment);
    expected_msg.push(u8::from(outcome));
    require_eq!(
        expected_msg.len(),
        VERDICT_MSG_LEN,
        ErrorCode::MissingSigVerify
    );

    // ---- 2+3. Introspect every preceding Ed25519SigVerify instruction ----
    let ix_sysvar = ctx.accounts.instructions.to_account_info();
    let current_index = load_current_index_checked(&ix_sysvar)?;
    require!(current_index >= 1, ErrorCode::MissingSigVerify);

    let mut seen_keys: Vec<Pubkey> = Vec::new();
    // Signatures are only tracked to reject the same signature bytes being
    // replayed under multiple pubkeys; they are read from the transaction,
    // never from args.
    let mut seen_sigs: Vec<[u8; 64]> = Vec::new();

    for ix_index in 0..current_index {
        let ix = load_instruction_at_checked(ix_index, &ix_sysvar)?;
        if ix.program_id != ED25519_PROGRAM_ID {
            continue;
        }
        for candidate in parse_ed25519_verify_data(&ix.data)? {
            require_eq!(
                candidate.message.len(),
                VERDICT_MSG_LEN,
                ErrorCode::MissingSigVerify
            );
            require_eq!(
                candidate.message.as_slice(),
                expected_msg.as_slice(),
                ErrorCode::MissingSigVerify
            );

            let signer = Pubkey::new_from_array(candidate.signer);
            require!(
                config.operators.contains(&signer),
                ErrorCode::UnauthorizedOperator
            );
            // Duplicate padding to reach the threshold is rejected.
            require!(!seen_keys.contains(&signer), ErrorCode::UnauthorizedOperator);
            require!(
                !seen_sigs.contains(&candidate.signature),
                ErrorCode::MissingSigVerify
            );
            seen_keys.push(signer);
            seen_sigs.push(candidate.signature);
        }
    }

    require!(!seen_sigs.is_empty(), ErrorCode::MissingSigVerify);

    // ---- Threshold over DISTINCT operator pubkeys ----
    require!(
        seen_keys.len() >= config.threshold as usize,
        ErrorCode::BadThreshold
    );

    // ---- Money movement: bond refunded regardless of outcome ----
    let total_debit = if outcome {
        submission
            .bond_lamports
            .saturating_add(bounty_acc.prize_lamports)
    } else {
        submission.bond_lamports
    };

    let bounty_info = ctx.accounts.bounty.to_account_info();
    let solver_info = ctx.accounts.solver.to_account_info();
    require_keys_eq!(solver_info.key(), submission.solver, ErrorCode::SolverMismatch);

    let new_bounty_lamports = bounty_info
        .lamports()
        .checked_sub(total_debit)
        .ok_or(ErrorCode::EscrowInsufficient)?;
    **bounty_info.try_borrow_mut_lamports()? = new_bounty_lamports;
    let new_solver_lamports = solver_info
        .lamports()
        .checked_add(total_debit)
        .ok_or(ErrorCode::EscrowInsufficient)?;
    **solver_info.try_borrow_mut_lamports()? = new_solver_lamports;

    let prize_paid = if outcome { bounty_acc.prize_lamports } else { 0 };
    let winner = if outcome { Some(submission.solver) } else { None };

    if outcome {
        // Validate + persist the reveal payload before touching state.
        let has_ciphertext = !reveal_ciphertext.is_empty();
        let has_url = !ciphertext_url.is_empty();
        require!(
            has_ciphertext || has_url,
            ErrorCode::InvalidRevealPayload
        );
        require!(
            reveal_ciphertext.len() <= MAX_CIPHERTEXT_LEN,
            ErrorCode::InvalidRevealPayload
        );
        require!(
            ciphertext_url.len() <= MAX_BLOB_URL_LEN,
            ErrorCode::InvalidRevealPayload
        );
        if has_ciphertext {
            let digest = anchor_lang::solana_program::hash::hash(&reveal_ciphertext);
            require_eq!(digest.to_bytes(), ciphertext_sha256, ErrorCode::InvalidRevealPayload);
        } else {
            require_neq!(ciphertext_sha256, [0u8; 32], ErrorCode::InvalidRevealPayload);
        }

        let receipt = ctx
            .accounts
            .receipt
            .as_mut()
            .ok_or(ErrorCode::MissingPayoutAccounts)?;
        receipt.bounty = bounty_key;
        receipt.solver = submission.solver;
        receipt.exploit_sha256 = submission.exploit_sha256;
        receipt.first_blood = bounty_acc.winner.is_none();
        receipt.timestamp = now;

        let reveal = ctx
            .accounts
            .reveal
            .as_mut()
            .ok_or(ErrorCode::MissingPayoutAccounts)?;
        reveal.ciphertext = reveal_ciphertext;
        reveal.ciphertext_url = ciphertext_url;
        reveal.ciphertext_sha256 = ciphertext_sha256;
    }

    // ---- Finalize bounty state ----
    let bounty = &mut ctx.accounts.bounty;
    if outcome {
        bounty.winner = winner;
        bounty.status = BountyStatus::Resolved;
        bounty.current_submission = None;
    } else {
        bounty.discard_submission();
    }

    emit!(BountyResolved {
        bounty: bounty_key,
        bounty_id: bounty.bounty_id,
        outcome,
        winner,
        prize_paid,
    });

    if outcome {
        msg!(
            "Bounty {} PASSED — prize + bond paid to solver",
            bounty.bounty_id
        );
    } else {
        msg!(
            "Bounty {} FAILED — bond refunded, submission discarded",
            bounty.bounty_id
        );
    }
    Ok(())
}
