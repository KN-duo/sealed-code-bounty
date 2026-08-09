import * as anchor from "@anchor-lang/core";

export const PROGRAM_ID = new anchor.web3.PublicKey("FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V");

const BOUNTY_SEED = Buffer.from("bounty");

export function bountyPda(buyer: anchor.web3.PublicKey, bountyId: anchor.BN): anchor.web3.PublicKey {
  return anchor.web3.PublicKey.findProgramAddressSync(
    [BOUNTY_SEED, buyer.toBuffer(), bountyId.toArrayLike(Buffer, "le", 8)],
    PROGRAM_ID
  )[0];
}
