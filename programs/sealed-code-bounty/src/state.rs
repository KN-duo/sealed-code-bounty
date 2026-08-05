use anchor_lang::prelude::*;

use crate::constants::MAX_SOLUTION_LEN;

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
