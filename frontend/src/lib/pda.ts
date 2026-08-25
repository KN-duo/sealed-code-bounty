import { PublicKey } from "@solana/web3.js";
import { BN } from "@anchor-lang/core";
import { PROGRAM_ID_STRING } from "../env";

export const PROGRAM_ID = new PublicKey(PROGRAM_ID_STRING);

const CONFIG_SEED = Buffer.from("config");
const BOUNTY_SEED = Buffer.from("bounty");
const RECEIPT_SEED = Buffer.from("receipt");
const REVEAL_SEED = Buffer.from("reveal");

function bountyIdLe(bountyId: BN): Buffer {
  return bountyId.toArrayLike(Buffer, "le", 8);
}

export function configPda(): PublicKey {
  return PublicKey.findProgramAddressSync([CONFIG_SEED], PROGRAM_ID)[0];
}

export function bountyPda(buyer: PublicKey, bountyId: BN): PublicKey {
  return PublicKey.findProgramAddressSync(
    [BOUNTY_SEED, buyer.toBuffer(), bountyIdLe(bountyId)],
    PROGRAM_ID,
  )[0];
}

export function receiptPda(bounty: PublicKey, winner: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [RECEIPT_SEED, bounty.toBuffer(), winner.toBuffer()],
    PROGRAM_ID,
  )[0];
}

export function revealPda(bounty: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([REVEAL_SEED, bounty.toBuffer()], PROGRAM_ID)[0];
}
