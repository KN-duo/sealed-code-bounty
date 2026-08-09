use anchor_lang::prelude::*;

use crate::constants::MAX_SOLUTION_LEN;
use crate::error::ErrorCode;

#[account]
#[derive(InitSpace)]
pub struct Bounty {
    pub buyer: Pubkey,
    pub bounty_id: u64,
    pub test_suite_hash: [u8; 32],
    pub prize_amount: u64,
    pub deadline: i64,
    pub submitted: bool,
    pub resolved: bool,
    pub solver: Option<Pubkey>,
    #[max_len(MAX_SOLUTION_LEN)]
    pub solution: String,
    pub bump: u8,
}

// Bounty moves through three states over its lifetime: open (accepting a
// submission), awaiting resolution (submitted, not yet resolved), and a
// terminal state (resolved, or closed via cancel_expired_bounty). These
// methods centralize the transition guards so each instruction handler
// asserts the precondition it needs instead of re-deriving it from the raw
// `submitted`/`resolved` flags.
impl Bounty {
    pub fn is_open(&self) -> bool {
        !self.submitted && !self.resolved
    }

    pub fn is_awaiting_resolution(&self) -> bool {
        self.submitted && !self.resolved
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now > self.deadline
    }

    pub fn assert_open(&self) -> Result<()> {
        require!(!self.resolved, ErrorCode::AlreadyResolved);
        require!(!self.submitted, ErrorCode::AlreadySubmitted);
        Ok(())
    }

    pub fn assert_awaiting_resolution(&self) -> Result<()> {
        require!(self.submitted, ErrorCode::NoSubmission);
        require!(!self.resolved, ErrorCode::AlreadyResolved);
        Ok(())
    }

    pub fn assert_expired(&self, now: i64) -> Result<()> {
        require!(self.is_expired(now), ErrorCode::NotExpiredYet);
        Ok(())
    }

    /// Resets submission fields after a FAILed resolution so the bounty
    /// returns to `is_open()` and a solver may retry.
    pub fn discard_submission(&mut self) {
        self.submitted = false;
        self.solver = None;
        self.solution = String::new();
    }
}
