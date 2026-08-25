import * as anchor from "@anchor-lang/core";
import { PublicKey, SystemProgram } from "@solana/web3.js";
import type { Program } from "@anchor-lang/core";
import type { SealedCodeBounty } from "../idl/sealed_code_bounty";
import { bountyPda, configPda } from "./pda";

type SCBProgram = Program<SealedCodeBounty>;

// Anchor wants byte-array args as number[].
const b32 = (u: Uint8Array): number[] => Array.from(u);

// `.accounts()` is typed strictly per-instruction; our account maps are correct
// but the fork's generated types are fussy, so we funnel through a small cast.
/* eslint-disable @typescript-eslint/no-explicit-any */
const methods = (program: SCBProgram): any => program.methods;

export interface CreateBountyParams {
  bountyId: anchor.BN;
  prizeLamports: anchor.BN;
  deadline: anchor.BN;
  manifestSha256: Uint8Array;
  envBlobSha256: Uint8Array;
  flagCommitment: Uint8Array;
  buyerEncPk: Uint8Array;
}

export function createBounty(
  program: SCBProgram,
  buyer: PublicKey,
  p: CreateBountyParams,
): Promise<string> {
  const bounty = bountyPda(buyer, p.bountyId);
  return methods(program)
    .createBounty(
      p.bountyId,
      p.prizeLamports,
      p.deadline,
      b32(p.manifestSha256),
      b32(p.envBlobSha256),
      b32(p.flagCommitment),
      b32(p.buyerEncPk),
    )
    .accounts({
      buyer,
      config: configPda(),
      bounty,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export interface SubmitExploitParams {
  bountyId: anchor.BN;
  blobUrl: string;
  exploitSha256: Uint8Array;
}

export function submitExploit(
  program: SCBProgram,
  solver: PublicKey,
  bounty: PublicKey,
  p: SubmitExploitParams,
): Promise<string> {
  return methods(program)
    .submitExploit(p.bountyId, p.blobUrl, b32(p.exploitSha256))
    .accounts({
      solver,
      config: configPda(),
      bounty,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export function cancelExpiredBounty(
  program: SCBProgram,
  buyer: PublicKey,
  bountyId: anchor.BN,
): Promise<string> {
  const bounty = bountyPda(buyer, bountyId);
  return methods(program).cancelExpiredBounty(bountyId).accounts({ buyer, bounty }).rpc();
}

export function closeResolvedBounty(
  program: SCBProgram,
  caller: PublicKey,
  buyer: PublicKey,
  bountyId: anchor.BN,
): Promise<string> {
  const bounty = bountyPda(buyer, bountyId);
  return methods(program)
    .closeResolvedBounty(bountyId)
    .accounts({ caller, bounty, buyer })
    .rpc();
}
/* eslint-enable @typescript-eslint/no-explicit-any */

// Translate an Anchor/web3 transaction failure into a readable message.
export function txErrorMessage(err: unknown): string {
  const anyErr = err as {
    error?: { errorMessage?: string };
    message?: string;
    logs?: string[];
  };
  if (anyErr?.error?.errorMessage) return anyErr.error.errorMessage;
  if (typeof anyErr?.message === "string") {
    if (anyErr.message.includes("User rejected")) return "You rejected the transaction.";
    if (anyErr.message.includes("insufficient")) return "Insufficient balance for this transaction.";
    return anyErr.message;
  }
  return "Transaction failed.";
}
