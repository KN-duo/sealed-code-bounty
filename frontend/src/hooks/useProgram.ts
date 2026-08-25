import { useMemo } from "react";
import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import * as anchor from "@anchor-lang/core";
import type { Program } from "@anchor-lang/core";
import idl from "../idl/sealed_code_bounty.json";
import type { SealedCodeBounty } from "../idl/sealed_code_bounty";

// A signing Program for WRITE paths (create/submit/cancel/close). Read paths use
// anchorClient.getReadProgram(), which needs no wallet. Returns null until a
// wallet capable of signing is connected.
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
      { commitment: "confirmed" },
    );

    return new anchor.Program(
      idl as anchor.Idl,
      provider,
    ) as unknown as Program<SealedCodeBounty>;
  }, [connection, wallet.publicKey, wallet.signTransaction, wallet.signAllTransactions]);
}
