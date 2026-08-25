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
    #[msg("FAIL resolutions must not carry Receipt or Reveal accounts")]
    UnexpectedPayoutAccounts,
    #[msg("PASS reveals must carry exactly one carrier: inline ciphertext XOR https URL")]
    InvalidRevealCarrier,
    #[msg("Reveal URL must start with https://")]
    InvalidRevealUrl,
    #[msg("Force unlock delay has not elapsed yet")]
    ForceUnlockTooEarly,
    #[msg("Force unlock delay must be greater than zero")]
    InvalidForceUnlockDelay,
    #[msg("Escrow balance insufficient for payout + bond refund")]
    EscrowInsufficient,
    #[msg("Bounty deadline has not passed yet")]
    NotExpiredYet,
    #[msg("Bounty is not in Resolved status")]
    NotResolved,
}
