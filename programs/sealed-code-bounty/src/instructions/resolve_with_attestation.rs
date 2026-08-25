use anchor_lang::prelude::*;
use sha2::Digest;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};

use crate::{
    constants::*,
    error::ErrorCode,
    events::BountyResolved,
    state::{Bounty, BountyStatus, Config, Receipt, Reveal, SubmissionRef},
};

// PERMISSIONLESS resolution (docs/BUILD_PLAN_v2.md §4.1). Anyone may land an
// enclave-signed verdict; trust comes from cryptography, not identity:
//
//   1. The handler RECOMPUTES the canonical `SCB_VERDICT_V4` message bytes
//      from its own accounts/args — never from anything the relayer supplies.
//   2. Every native Ed25519SigVerify instruction placed EARLIER in this same
//      transaction is parsed and its embedded message must equal the
//      recomputed bytes byte-for-byte (STRICT-SCAN rule, see
//      collect_quorum_from_candidates).
//   3. Every signing pubkey must be a pinned `Config.operator`, appear at most
//      once, and `Config.threshold` DISTINCT operators must be collected.
//
// Presence of an Ed25519 instruction alone proves nothing; atomicity plus this
// introspection together prove the enclave signed exactly these bytes.

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
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

// ===========================================================================
// Pure helpers — unit-tested below without localnet.
// ===========================================================================

/// Canonical `SCB_VERDICT_V4` wire. MUST stay byte-identical to:
///   constants.rs · relayer/src/verdict.ts · runner/src/verdict.rs
/// Cross-language fixture: test-vectors/verdict_v4.json at the repo root.
pub fn recompute_verdict_msg(
    bounty_key: &Pubkey,
    bounty: &Bounty,
    submission: &SubmissionRef,
    outcome: bool,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(VERDICT_MSG_LEN);
    msg.extend_from_slice(VERDICT_DOMAIN_TAG);
    msg.extend_from_slice(bounty_key.as_ref());
    // V3: bind the environment this verdict was produced against — closes the
    // fake-weak-environment hole (colluding relayer + unbound verdict).
    msg.extend_from_slice(&bounty.env_blob_sha256);
    msg.extend_from_slice(&submission.exploit_sha256);
    msg.extend_from_slice(submission.solver.as_ref());
    msg.extend_from_slice(&bounty.flag_commitment);
    // V4: bind the buyer's reveal key (audit M2) — a colluding relayer+solver
    // can no longer redirect the PASS ciphertext to an attacker X25519 key.
    msg.extend_from_slice(&bounty.buyer_enc_pk);
    msg.push(u8::from(outcome));
    debug_assert_eq!(msg.len(), VERDICT_MSG_LEN);
    msg
}

/// One parsed signature entry out of an Ed25519SigVerify instruction.
pub struct VerdictCandidate {
    pub signer: [u8; 32],
    pub signature: [u8; 64],
    pub message: Vec<u8>,
}

// P2-8: named layout constants for the native ed25519 program's per-entry
// encoding. Each entry is SIG_ENTRY_LEN bytes of little-endian u16 fields:
//   [sig_off(OFF_SIG..+2), sig_ix(+2..4), pk_off(OFF_PK..+2), pk_ix(+2..8),
//    msg_off(OFF_MSG_DATA..+2), msg_size(OFF_MSG_SIZE..+2), msg_ix(+12..14)]
// followed somewhere in the same instruction by the embedded
// pubkey/signature/message bytes themselves. Entries whose *_instruction_index
// points at another transaction instruction cannot be bound by this handler
// and are rejected outright.
const SIG_ENTRY_LEN: usize = 14;
const OFF_SIG: usize = 0;
const OFF_SIG_IX: usize = 2;
const OFF_PK: usize = 4;
const OFF_PK_IX: usize = 6;
const OFF_MSG_DATA: usize = 8;
const OFF_MSG_SIZE: usize = 10;
const OFF_MSG_IX: usize = 12;

fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    let end = off.checked_add(2).ok_or_else(|| error!(ErrorCode::MissingSigVerify))?;
    if end > data.len() {
        return Err(ErrorCode::MissingSigVerify.into());
    }
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

/// Parses the native ed25519 program's instruction data into candidates.
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
        let base = 2usize
            .checked_add(i.checked_mul(SIG_ENTRY_LEN).ok_or_else(|| error!(ErrorCode::MissingSigVerify))?)
            .ok_or_else(|| error!(ErrorCode::MissingSigVerify))?;
        let signature_offset = read_u16(data, base + OFF_SIG)? as usize;
        let signature_instruction_index = read_u16(data, base + OFF_SIG_IX)?;
        let public_key_offset = read_u16(data, base + OFF_PK)? as usize;
        let public_key_instruction_index = read_u16(data, base + OFF_PK_IX)?;
        let message_data_offset = read_u16(data, base + OFF_MSG_DATA)? as usize;
        let message_data_size = read_u16(data, base + OFF_MSG_SIZE)? as usize;
        let message_instruction_index = read_u16(data, base + OFF_MSG_IX)?;

        require!(
            signature_instruction_index == EMBEDDED_IN_THIS_INSTRUCTION
                && public_key_instruction_index == EMBEDDED_IN_THIS_INSTRUCTION
                && message_instruction_index == EMBEDDED_IN_THIS_INSTRUCTION,
            ErrorCode::MissingSigVerify
        );

        let sig_end = signature_offset
            .checked_add(64)
            .ok_or_else(|| error!(ErrorCode::MissingSigVerify))?;
        let pk_end = public_key_offset
            .checked_add(32)
            .ok_or_else(|| error!(ErrorCode::MissingSigVerify))?;
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

/// STRICT-SCAN RULE (audit P2-8): every candidate from EVERY earlier
/// Ed25519SigVerify instruction must carry EXACTLY the expected verdict
/// message. Mismatching entries fail the whole resolution — attackers cannot
/// pad junk signatures around a real one to reach the threshold, because junk
/// never counts toward it.
///
/// Returns the DISTINCT operator pubkeys that reached the threshold set.
pub fn collect_quorum_from_candidates(
    candidates: &[VerdictCandidate],
    expected_msg: &[u8],
    config: &Config,
) -> Result<Vec<Pubkey>> {
    let mut seen_keys: Vec<Pubkey> = Vec::new();
    let mut seen_sigs: Vec<[u8; 64]> = Vec::new();

    for c in candidates {
        require!(
            c.message.len() == VERDICT_MSG_LEN,
            ErrorCode::MissingSigVerify
        );
        require!(
            c.message.as_slice() == expected_msg,
            ErrorCode::MissingSigVerify
        );

        let signer = Pubkey::new_from_array(c.signer);
        require!(
            config.operators.contains(&signer),
            ErrorCode::UnauthorizedOperator
        );
        require!(!seen_keys.contains(&signer), ErrorCode::UnauthorizedOperator);
        require!(!seen_sigs.contains(&c.signature), ErrorCode::MissingSigVerify);
        seen_keys.push(signer);
        seen_sigs.push(c.signature);
    }

    require!(!seen_sigs.is_empty(), ErrorCode::MissingSigVerify);
    require!(
        seen_keys.len() >= config.threshold as usize,
        ErrorCode::BadThreshold
    );
    Ok(seen_keys)
}

/// Thin impure wrapper: extracts candidates from the live instructions
/// sysvar. Everything downstream stays pure.
fn candidates_from_sysvar(
    ix_sysvar: &anchor_lang::prelude::AccountInfo,
) -> Result<Vec<VerdictCandidate>> {
    let info = ix_sysvar;
    let current_index = load_current_index_checked(info)?;
    require!(current_index >= 1, ErrorCode::MissingSigVerify);

    let mut out = Vec::new();
    for ix_index in 0..current_index {
        let ix = load_instruction_at_checked(ix_index as usize, info)?;
        if ix.program_id != ED25519_PROGRAM_ID {
            continue;
        }
        out.extend(parse_ed25519_verify_data(&ix.data)?);
    }
    Ok(out)
}

/// Reveal carrier decision (audit P2-9): EXACTLY ONE of inline ciphertext XOR
/// https URL on PASS; none on FAIL (audit L1 also requires the payout
/// accounts themselves to be absent).
#[derive(Debug)]
pub struct RevealData {
    pub ciphertext: Vec<u8>,
    pub url: String,
    pub sha256: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
pub fn validate_reveal_payload(
    receipt_present: bool,
    reveal_present: bool,
    outcome: bool,
    mut ciphertext: Vec<u8>,
    url: String,
    sha256: [u8; 32],
) -> Result<Option<RevealData>> {
    if !outcome {
        require!(
            !receipt_present && !reveal_present,
            ErrorCode::UnexpectedPayoutAccounts
        );
        require!(
            ciphertext.is_empty() && url.is_empty(),
            ErrorCode::InvalidRevealPayload
        );
        return Ok(None);
    }

    let has_ciphertext = !ciphertext.is_empty();
    let has_url = !url.is_empty();
    require!(has_ciphertext ^ has_url, ErrorCode::InvalidRevealCarrier);
    require!(
        ciphertext.len() <= MAX_CIPHERTEXT_LEN,
        ErrorCode::InvalidRevealPayload
    );
    require!(url.len() <= MAX_BLOB_URL_LEN, ErrorCode::InvalidRevealPayload);

    if has_ciphertext {
        let digest = sha2::Sha256::digest(&ciphertext);
        require!(
            digest.as_slice() == sha256.as_slice(),
            ErrorCode::InvalidRevealPayload
        );
    } else {
        require!(
            url.starts_with("https://"),
            ErrorCode::InvalidRevealUrl
        );
        require!(sha256 != [0u8; 32], ErrorCode::InvalidRevealPayload);
    }

    Ok(Some(RevealData { ciphertext, url, sha256 }))
}

/// Applies the verdict to bounty/payout state. Returns prize paid (0 on FAIL).
#[allow(clippy::too_many_arguments)]
pub fn finalize_outcome(
    bounty: &mut Bounty,
    bounty_key: &Pubkey,
    submission: &SubmissionRef,
    receipt: Option<&mut Receipt>,
    reveal: Option<&mut Reveal>,
    reveal_data: Option<RevealData>,
    outcome: bool,
    now: i64,
) -> u64 {
    if outcome {
        let first_blood = bounty.winner.is_none();
        bounty.winner = Some(submission.solver);
        bounty.status = BountyStatus::Resolved;
        bounty.current_submission = None;

        if let Some(r) = receipt {
            r.bounty = *bounty_key;
            r.solver = submission.solver;
            r.exploit_sha256 = submission.exploit_sha256;
            r.first_blood = first_blood;
            r.timestamp = now;
        }
        if let (Some(r), Some(d)) = (reveal, reveal_data) {
            r.ciphertext = d.ciphertext;
            r.ciphertext_url = d.url;
            r.ciphertext_sha256 = d.sha256;
        }
        bounty.prize_lamports
    } else {
        bounty.discard_submission();
        0
    }
}

// ===========================================================================
// Handler — orchestration only.
// ===========================================================================

pub fn handle_resolve_with_attestation(
    ctx: Context<ResolveWithAttestation>,
    _bounty_id: u64,
    outcome: bool,
    reveal_ciphertext: Vec<u8>,
    ciphertext_url: String,
    ciphertext_sha256: [u8; 32],
) -> Result<()> {
    let config = &ctx.accounts.config;
    let now = Clock::get()?.unix_timestamp;

    ctx.accounts.bounty.assert_awaiting_resolution()?;
    let submission = ctx
        .accounts
        .bounty
        .current_submission
        .clone()
        .ok_or(ErrorCode::NoSubmission)?;

    // ---- 1. Recompute the canonical verdict message from OUR OWN state ----
    let bounty_acc = &ctx.accounts.bounty;
    let bounty_key = bounty_acc.key();
    let expected_msg = recompute_verdict_msg(&bounty_key, bounty_acc, &submission, outcome);

    // ---- L1: FAIL verdicts must not touch payout PDAs ----------------------
    if !outcome {
        require!(
            ctx.accounts.receipt.is_none() && ctx.accounts.reveal.is_none(),
            ErrorCode::UnexpectedPayoutAccounts
        );
    }

    // ---- 2+3. Introspect + quorum ------------------------------------------
    let ix_sysvar = ctx.accounts.instructions.to_account_info();
    let candidates = candidates_from_sysvar(&ix_sysvar)?;
    collect_quorum_from_candidates(&candidates, &expected_msg, config)?;

    // ---- Solver binding -----------------------------------------------------
    let solver_info = ctx.accounts.solver.to_account_info();
    require_keys_eq!(solver_info.key(), submission.solver, ErrorCode::SolverMismatch);

    // ---- Reveal payload validation (P2-9 / L1) ------------------------------
    let reveal_data = validate_reveal_payload(
        ctx.accounts.receipt.is_some(),
        ctx.accounts.reveal.is_some(),
        outcome,
        reveal_ciphertext,
        ciphertext_url,
        ciphertext_sha256,
    )?;

    // ---- Money movement: bond refunded regardless of outcome ----------------
    let total_debit = if outcome {
        submission.bond_lamports.saturating_add(bounty_acc.prize_lamports)
    } else {
        submission.bond_lamports
    };

    let bounty_info = ctx.accounts.bounty.to_account_info();
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

    // ---- Finalize ------------------------------------------------------------
    let prize_paid = if outcome { bounty_acc.prize_lamports } else { 0 };
    let winner = outcome.then(|| submission.solver);

    {
        let bounty = &mut ctx.accounts.bounty;
        let receipt = ctx.accounts.receipt.as_mut().map(|a| &mut **a);
        let reveal = ctx.accounts.reveal.as_mut().map(|a| &mut **a);
        let paid = finalize_outcome(
            bounty,
            &bounty_key,
            &submission,
            receipt,
            reveal,
            reveal_data,
            outcome,
            now,
        );
        debug_assert_eq!(paid, prize_paid);
    }

    emit!(BountyResolved {
        bounty: bounty_key,
        bounty_id: ctx.accounts.bounty.bounty_id,
        outcome,
        winner,
        prize_paid,
    });

    if outcome {
        msg!("Bounty {} PASSED — prize + bond paid to solver", ctx.accounts.bounty.bounty_id);
    } else {
        msg!("Bounty {} FAILED — bond refunded, submission discarded", ctx.accounts.bounty.bounty_id);
    }
    Ok(())
}

// ===========================================================================
// Unit tests — pure fns only; no localnet required.
// ===========================================================================

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub fn fixture_bounty() -> Bounty {
        let mut b = Bounty {
            buyer: Pubkey::new_from_array([1u8; 32]),
            bounty_id: 7,
            status: BountyStatus::AwaitingResolution,
            prize_lamports: 1_000_000,
            deadline: 9_999_999_999,
            manifest_sha256: [2u8; 32],
            env_blob_sha256: [3u8; 32],
            flag_commitment: [4u8; 32],
            buyer_enc_pk: [5u8; 32],
            current_submission: None,
            winner: None,
            bump: 255,
        };
        b.current_submission = Some(SubmissionRef {
            solver: Pubkey::new_from_array([6u8; 32]),
            exploit_sha256: [7u8; 32],
            blob_url: "https://blob.example/1".to_string(),
            bond_lamports: 50_000,
            submitted_at: 1_700_000_000,
        });
        b
    }

    pub fn sha(ct: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(ct).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::fixtures::fixture_bounty;

    #[test]
    fn wire_layout_v4_field_by_field() {
        let bounty = fixture_bounty();
        let key = Pubkey::new_from_array([9u8; 32]);
        let msg = recompute_verdict_msg(&key, &bounty, bounty.current_submission.as_ref().unwrap(), true);

        assert_eq!(msg.len(), VERDICT_MSG_LEN);
        assert_eq!(&msg[0..14], b"SCB_VERDICT_V4");
        assert_eq!(&msg[14..46], &[9u8; 32]); // pda
        assert_eq!(&msg[46..78], &[3u8; 32]); // env
        assert_eq!(&msg[78..110], &[7u8; 32]); // exploit
        assert_eq!(&msg[110..142], &[6u8; 32]); // solver
        assert_eq!(&msg[142..174], &[4u8; 32]); // flag commitment
        assert_eq!(&msg[174..206], &[5u8; 32]); // buyer enc pk (V4)
        assert_eq!(msg[206], 1);
    }

    #[test]
    fn outcome_byte_flips_without_touching_the_rest() {
        let bounty = fixture_bounty();
        let sub = bounty.current_submission.clone().unwrap();
        let pass = recompute_verdict_msg(&Pubkey::new_from_array([9u8; 32]), &bounty, &sub, true);
        let fail = recompute_verdict_msg(&Pubkey::new_from_array([9u8; 32]), &bounty, &sub, false);
        assert_eq!(pass[0..VERDICT_MSG_LEN - 1], fail[0..VERDICT_MSG_LEN - 1]);
        assert_ne!(pass[VERDICT_MSG_LEN - 1], fail[VERDICT_MSG_LEN - 1]);
    }
}

// (tests module continues — appended below the closing brace of `mod tests`
//  is not valid Rust, so these are added as a second cfg(test) module.)

#[cfg(test)]
mod quorum_and_payload_tests {
    use super::fixtures::{fixture_bounty, sha};
    use super::*;

    fn op(i: u8) -> Pubkey {
        Pubkey::new_from_array([i; 32])
    }

    fn config(threshold: u8, operators: Vec<Pubkey>) -> Config {
        Config {
            platform_authority: op(250),
            operators,
            threshold,
            enclave_enc_pk: [0xaa; 32],
            submission_bond_lamports: 0,
            force_unlock_delay_s: 3600,
            bump: 255,
        }
    }

    fn cand(signer: &Pubkey, msg: &[u8]) -> VerdictCandidate {
        VerdictCandidate {
            signer: signer.to_bytes(),
            signature: [0u8; 64],
            message: msg.to_vec(),
        }
    }

    fn msg_for(buyer: u8) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(VERDICT_DOMAIN_TAG);
        m.extend_from_slice(&[9u8; 32]);
        m.extend_from_slice(&[2u8; 32]);
        m.extend_from_slice(&[3u8; 32]);
        m.extend_from_slice(&[6u8; 32]);
        m.extend_from_slice(&[4u8; 32]);
        m.extend_from_slice(&[buyer; 32]);
        m.push(1);
        m
    }

    #[test]
    fn quorum_accepts_distinct_operators_over_the_expected_message() {
        let buyer = 5u8;
        let expected = msg_for(buyer);
        let cfg = config(1, vec![op(1), op(2)]);
        let cands = vec![cand(&op(1), &expected)];
        let keys = collect_quorum_from_candidates(&cands, &expected, &cfg).unwrap();
        assert_eq!(keys, vec![op(1)]);
    }

    #[test]
    fn strict_scan_rejects_junk_padding_around_a_real_signature() {
        // Attacker pads with a junk entry (different message) BEFORE the real
        // one hoping to reach threshold. Strict scan must fail the whole ix.
        let buyer = 5u8;
        let expected = msg_for(buyer);
        let junk = msg_for(200); // well-formed but WRONG message
        let cfg = config(1, vec![op(1)]);
        let cands = vec![cand(&op(200), &junk), cand(&op(1), &expected)];
        let err = collect_quorum_from_candidates(&cands, &expected, &cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("MissingSigVerify") || msg.contains("UnauthorizedOperator"),
            "{msg}"
        );
    }

    #[test]
    fn impostor_operator_is_unauthorized() {
        let buyer = 5u8;
        let expected = msg_for(buyer);
        let cfg = config(1, vec![op(1)]);
        let cands = vec![cand(&op(77), &expected)];
        let err = collect_quorum_from_candidates(&cands, &expected, &cfg).unwrap_err();
        assert!(format!("{err}").contains("UnauthorizedOperator"), "{err}");
    }

    #[test]
    fn duplicate_signatures_do_not_double_count() {
        let buyer = 5u8;
        let expected = msg_for(buyer);
        let cfg = config(2, vec![op(1)]); // threshold 2 with only ONE operator
        let dup = cand(&op(1), &expected);
        let cands = vec![
            cand(&op(1), &expected),
            VerdictCandidate { signature: [7u8; 64], ..dup },
        ];
        let err = collect_quorum_from_candidates(&cands, &expected, &cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("BadThreshold") || msg.contains("UnauthorizedOperator"),
            "{msg}"
        );
    }

    // ---- reveal payload carriers (P2-9 / L1) --------------------------------

    const CT: &[u8] = b"sealed-box-bytes";

    #[test]
    fn pass_inline_carrier_validates() {
        let d = validate_reveal_payload(true, true, true, CT.to_vec(), String::new(), sha(CT))
            .unwrap()
            .expect("inline carrier");
        assert_eq!(d.ciphertext, CT);
        assert!(d.url.is_empty());
    }

    #[test]
    fn pass_https_url_carrier_validates_with_pinned_hash() {
        let d = validate_reveal_payload(
            true,
            true,
            true,
            Vec::new(),
            "https://arweave.net/abc".to_string(),
            [9u8; 32],
        )
        .unwrap()
        .expect("url carrier");
        assert_eq!(d.url, "https://arweave.net/abc");
        assert_eq!(d.sha256, [9u8; 32]);
    }

    #[test]
    fn pass_both_carriers_is_rejected() {
        let err = validate_reveal_payload(
            true,
            true,
            true,
            CT.to_vec(),
            "https://x.test/a".to_string(),
            sha(CT),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("InvalidRevealCarrier"), "{err}");
    }

    #[test]
    fn pass_neither_carrier_is_rejected() {
        let err = validate_reveal_payload(
            true,
            true,
            true,
            Vec::new(),
            String::new(),
            [0u8; 32],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("InvalidRevealCarrier"), "{err}");
    }

    #[test]
    fn pass_plain_http_url_is_rejected() {
        let err = validate_reveal_payload(
            true,
            false,
            true,
            Vec::new(),
            "http://insecure.test/a".to_string(),
            [9u8; 32],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("InvalidRevealUrl"), "{err}");
    }

    #[test]
    fn fail_requires_no_accounts_and_no_carriers() {
        assert!(validate_reveal_payload(false, false, false, Vec::new(), String::new(), [0u8; 32])
            .unwrap()
            .is_none());
        let err = validate_reveal_payload(
            true,
            false,
            false,
            Vec::new(),
            String::new(),
            [0u8; 32],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("UnexpectedPayoutAccounts"), "{err}");
    }

    // ---- finalize -------------------------------------------------------------

    #[test]
    fn finalize_pass_sets_winner_receipt_reveal_and_clears_slot() {
        let mut bounty = fixture_bounty();
        bounty.prize_lamports = 123;
        let sub = bounty.current_submission.clone().unwrap();
        let now = 42i64;

        let mut receipt = Receipt {
            bounty: Pubkey::default(),
            solver: Pubkey::default(),
            exploit_sha256: [0; 32],
            first_blood: true,
            timestamp: 0,
        };
        let mut reveal = Reveal {
            ciphertext: vec![],
            ciphertext_url: String::new(),
            ciphertext_sha256: [0; 32],
        };
        let data = RevealData {
            ciphertext: CT.to_vec(),
            url: String::new(),
            sha256: sha(CT),
        };

        let paid = finalize_outcome(
            &mut bounty,
            &Pubkey::new_from_array([9u8; 32]),
            &sub,
            Some(&mut receipt),
            Some(&mut reveal),
            Some(data),
            true,
            now,
        );

        assert_eq!(paid, 123);
        assert!(bounty.winner.is_some());
        assert_eq!(receipt.solver, sub.solver);
        assert_eq!(receipt.exploit_sha256, sub.exploit_sha256);
        assert_eq!(reveal.ciphertext, CT);
        assert!(bounty.current_submission.is_none());
        assert_eq!(bounty.status, BountyStatus::Resolved);
    }

    #[test]
    fn finalize_fail_wipes_slot_and_pays_nothing() {
        let mut bounty = fixture_bounty(); // AwaitingResolution w/ submission
        let sub = bounty.current_submission.clone().unwrap();
        let paid = finalize_outcome(
            &mut bounty,
            &Pubkey::new_from_array([9u8; 32]),
            &sub,
            None,
            None,
            None,
            false,
            7,
        );
        assert_eq!(paid, 0);
        assert!(bounty.current_submission.is_none());
        assert_eq!(bounty.status, BountyStatus::Open);
        void(sub);
    }

    fn void<T>(_: T) {}
}
