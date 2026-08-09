use anchor_lang::prelude::*;

// Emitted on every state transition so an off-chain indexer (or the
// frontend, via `program.addEventListener`) can follow a bounty's lifecycle
// without polling `getProgramAccounts`.

#[event]
pub struct BountyCreated {
    pub bounty: Pubkey,
    pub buyer: Pubkey,
    pub bounty_id: u64,
    pub prize_amount: u64,
    pub deadline: i64,
}

#[event]
pub struct SolutionSubmitted {
    pub bounty: Pubkey,
    pub solver: Pubkey,
    pub bounty_id: u64,
}

#[event]
pub struct BountyResolved {
    pub bounty: Pubkey,
    pub solver: Pubkey,
    pub bounty_id: u64,
    pub passed: bool,
    pub prize_amount: u64,
}

#[event]
pub struct BountyCancelled {
    pub bounty: Pubkey,
    pub buyer: Pubkey,
    pub bounty_id: u64,
    pub refunded_amount: u64,
}
