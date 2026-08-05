use anchor_lang::prelude::*;

#[constant]
pub const BOUNTY_SEED: &[u8] = b"bounty";

#[constant]
pub const SUBMISSION_FEE_LAMPORTS: u64 = 5_000_000;

#[constant]
pub const MAX_SOLUTION_LEN: u64 = 2_000;
