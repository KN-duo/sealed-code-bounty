use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    #[msg("Prize amount must be greater than zero")]
    InvalidPrizeAmount,
    #[msg("Deadline must be in the future")]
    InvalidDeadline,
    #[msg("Bounty is not open for submissions")]
    NotOpen,
    #[msg("Blob URL exceeds maximum allowed length (200)")]
    BlobUrlTooLong,
    #[msg("Bounty deadline has passed; submissions are closed")]
    DeadlinePassed,
    #[msg("Bounty is not awaiting resolution")]
    NotAwaitingResolution,
    #[msg("No submission pending for this bounty")]
    NoSubmission,
    #[msg("Solver account does not match the recorded submitter")]
    SolverMismatch,
    #[msg("Verdict outcome byte does not match the resolution argument")]
    InvalidOutcome,
    #[msg("Verdict exploit_sha256 does not match the pending submission")]
    SubmissionMismatch,
    #[msg("Verdict flag_commitment does not match the bounty commitment")]
    FlagCommitmentMismatch,
    #[msg("No valid Ed25519 verdict instruction over the expected message found in this transaction")]
    MissingSigVerify,
    #[msg("Verdict signer is not a configured operator")]
    UnauthorizedOperator,
    #[msg("Operator threshold not satisfied by supplied signatures")]
    BadThreshold,
    #[msg("Only the platform authority may perform this action")]
    Unauthorized,
    #[msg("Operator list invalid (empty, too large, or contains duplicates)")]
    InvalidOperators,
    #[msg("Reveal payload malformed")]
    InvalidRevealPayload,
    #[msg("Receipt and Reveal accounts are required for a PASS resolution")]
    MissingPayoutAccounts,
    #[msg("Force unlock delay has not elapsed yet")]
    ForceUnlockTooEarly,
    #[msg("Escrow balance insufficient for payout + bond refund")]
    EscrowInsufficient,
    #[msg("Bounty deadline has not passed yet")]
    NotExpiredYet,
}
