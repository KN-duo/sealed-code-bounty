import { useMemo } from "react";
import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import * as anchor from "@anchor-lang/core";
import type { Program } from "@anchor-lang/core";
import idl from "./idl/sealed_code_bounty.json";
import type { SealedCodeBounty } from "./idl/sealed_code_bounty";

const PROGRAM_ID = new anchor.web3.PublicKey("FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V");
const BOUNTY_SEED = Buffer.from("bounty");

// Wallet-adapter's wallet doesn't fully satisfy Anchor's provider interface
// (it has no direct access to a private key), but AnchorProvider only needs
// publicKey + signTransaction + signAllTransactions, which every connected
// wallet-adapter wallet provides.
export function useProgram(): Program<SealedCodeBounty> | null {
  const { connection } = useConnection();
  const wallet = useWallet();

  return useMemo(() => {
    if (!wallet.publicKey || !wallet.signTransaction || !wallet.signAllTransactions) return null;

    const provider = new anchor.AnchorProvider(
      connection,
      {
        publicKey: wallet.publicKey,
        signTransaction: wallet.signTransaction,
        signAllTransactions: wallet.signAllTransactions,
      },
      { commitment: "confirmed" }
    );

    return new anchor.Program(idl as anchor.Idl, provider) as unknown as Program<SealedCodeBounty>;
  }, [connection, wallet.publicKey, wallet.signTransaction, wallet.signAllTransactions]);
}

export function bountyPda(buyer: anchor.web3.PublicKey, bountyId: anchor.BN): anchor.web3.PublicKey {
  return anchor.web3.PublicKey.findProgramAddressSync(
    [BOUNTY_SEED, buyer.toBuffer(), bountyId.toArrayLike(Buffer, "le", 8)],
    PROGRAM_ID
  )[0];
}

export { PROGRAM_ID };
