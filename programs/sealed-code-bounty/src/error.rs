use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    #[msg("Prize amount must be greater than zero")]
    InvalidPrizeAmount,
    #[msg("Deadline must be in the future")]
    InvalidDeadline,
    #[msg("Solution exceeds maximum allowed length")]
    SolutionTooLong,
    #[msg("Bounty already has a pending submission")]
    AlreadySubmitted,
    #[msg("Bounty has already been resolved")]
    AlreadyResolved,
    #[msg("No submission pending for this bounty")]
    NoSubmission,
    #[msg("Solver account does not match the recorded submitter")]
    SolverMismatch,
    #[msg("Bounty deadline has not passed yet")]
    NotExpiredYet,
}
