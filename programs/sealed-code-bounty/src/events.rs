use anchor_lang::prelude::*;

// Emitted on every state transition so an off-chain indexer (or the
// frontend, via `program.addEventListener`) can follow a bounty's lifecycle
// without polling `getProgramAccounts`.

#[event]
pub struct ConfigInitialized {
    pub platform_authority: Pubkey,
    pub enclave_enc_pk: [u8; 32],
    pub submission_bond_lamports: u64,
}

#[event]
pub struct OperatorSetChanged {
    pub operators: Vec<Pubkey>,
    pub threshold: u8,
    pub enclave_enc_pk: [u8; 32],
}

#[event]
pub struct BountyCreated {
    pub bounty: Pubkey,
    pub buyer: Pubkey,
    pub bounty_id: u64,
    pub prize_lamports: u64,
    pub deadline: i64,
}

#[event]
pub struct ExploitSubmitted {
    pub bounty: Pubkey,
    pub solver: Pubkey,
    pub bounty_id: u64,
    pub exploit_sha256: [u8; 32],
    pub bond_lamports: u64,
}

#[event]
pub struct BountyResolved {
    pub bounty: Pubkey,
    pub bounty_id: u64,
    /// true = PASS (paid), false = FAIL (submission discarded).
    pub outcome: bool,
    /// Set only on PASS.
    pub winner: Option<Pubkey>,
    pub prize_paid: u64,
}

#[event]
pub struct BountyCancelled {
    pub bounty: Pubkey,
    pub buyer: Pubkey,
    pub bounty_id: u64,
    pub refunded_amount: u64,
}

#[event]
pub struct SubmissionUnlocked {
    pub bounty: Pubkey,
    pub solver: Pubkey,
    pub bounty_id: u64,
}
