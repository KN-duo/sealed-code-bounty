import nacl from "tweetnacl";
import { PublicKey } from "@solana/web3.js";

/**
 * Canonical SCB_VERDICT_V4 wire — must stay byte-identical to
 * programs/sealed-code-bounty/src/constants.rs + the recomputation in
 * instructions/resolve_with_attestation.rs:
 *   tag(14) || bounty_pda(32) || env_blob_sha256(32) || exploit_sha256(32)
 *   || solver(32) || flag_commitment(32) || outcome(1)  = 175 bytes
 */
export const VERDICT_TAG = Buffer.from("SCB_VERDICT_V4", "ascii");
export const VERDICT_MSG_LEN = 207;

export interface VerdictFields {
  bountyPda: Buffer;
  envBlobSha256: Buffer;
  exploitSha256: Buffer;
  solver: Buffer;
  flagCommitment: Buffer;
  buyerEncPk: Buffer;
  outcome: boolean;
}

function assert32(b: Buffer, what: string): void {
  if (b.length !== 32) throw new Error(`${what} must be 32 bytes, got ${b.length}`);
}

export function buildVerdictMessage(f: VerdictFields): Buffer {
  assert32(f.bountyPda, "bountyPda");
  assert32(f.envBlobSha256, "envBlobSha256");
  assert32(f.exploitSha256, "exploitSha256");
  assert32(f.solver, "solver");
  assert32(f.flagCommitment, "flagCommitment");
  assert32(f.buyerEncPk, "buyerEncPk");
  const msg = Buffer.concat([
    VERDICT_TAG,
    f.bountyPda,
    f.envBlobSha256,
    f.exploitSha256,
    f.solver,
    f.flagCommitment,
    f.buyerEncPk,
    Buffer.from([f.outcome ? 1 : 0]),
  ]);
  if (msg.length !== VERDICT_MSG_LEN) {
    throw new Error(`internal: verdict wire is ${msg.length} bytes, expected ${VERDICT_MSG_LEN}`);
  }
  return msg;
}

/** Local pre-flight of the enclave signature before we pay fees to land it. */
export function verifyDetached(
  message: Buffer,
  signatureB64: string,
  operatorPubkey: PublicKey
): boolean {
  const sig = Buffer.from(signatureB64, "base64");
  if (sig.length !== nacl.sign.signatureLength) return false;
  return nacl.sign.detached.verify(
    new Uint8Array(message),
    new Uint8Array(sig),
    new Uint8Array(operatorPubkey.toBytes())
  );
}
