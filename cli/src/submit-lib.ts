#!/usr/bin/env node
/**
 * scb-submit — hunter-side submission client (BUILD_PLAN_v2.md §4.3 handshake).
 *
 * Flow:
 *   a. fetch Bounty via RPC   → env_blob_sha256 / buyer_enc_pk / deadline guard
 *   b. fetch Config via RPC   → enclave_enc_pk
 *   c. crypto_box_seal(exploit.py bytes, enclave_enc_pk)
 *   d. intent signature over b"SCB_SUBMIT_V1" || bounty_pda || sha256(plaintext)
 *      (solver wallet is a Solana ed25519 keypair — same scheme the enclave
 *       verifies with ed25519-dalek)
 *   e. POST ENCLAVE_URL/internal/upload
 *   f. submit_exploit tx signed by the hunter wallet
 *   g. --wait polls Bounty until it leaves AwaitingResolution
 *
 * NOTE (redacted log retrieval): on FAIL the redacted debug log currently
 * lives only inside the relayer/enclave exchange; there is no public endpoint
 * yet. TODO(post-MVP): GET /internal/log/{receipt} behind the enclave.
 */
import { Command } from "commander";
import nacl from "tweetnacl";
import sodium from "libsodium-wrappers";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import * as fs from "fs";
import { createHash } from "crypto";

// ---------------------------------------------------------------------------
// Constants — MUST stay in sync with the on-chain program and the runner.
// ---------------------------------------------------------------------------

export const DEFAULT_PROGRAM_ID =
  "FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V";
export const INTENT_TAG = Buffer.from("SCB_SUBMIT_V1", "ascii");

// ---------------------------------------------------------------------------
// Pure helpers (exported for tests)
// ---------------------------------------------------------------------------

/** Anchor discriminator: first 8 bytes of sha256("global:<ix_name>"). */
export function anchorDiscriminator(ixName: string): Buffer {
  return createHash("sha256").update(`global:${ixName}`).digest().subarray(0, 8);
}

export function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

export function u64le(n: bigint | number): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(n));
  return buf;
}

export function borshString(s: string): Buffer {
  const b = Buffer.from(s, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(b.length);
  return Buffer.concat([len, b]);
}

export function buildIntentMessage(
  bountyPdaBytes: Uint8Array,
  plaintextSha256: Uint8Array
): Buffer {
  if (bountyPdaBytes.length !== 32) throw new Error("bountyPda must be 32 bytes");
  if (plaintextSha256.length !== 32)
    throw new Error("plaintextSha256 must be 32 bytes");
  return Buffer.concat([INTENT_TAG, bountyPdaBytes, plaintextSha256]);
}

/** Instruction data for submit_exploit(bounty_id, blob_url, exploit_sha256). */
export function encodeSubmitExploitData(
  bountyId: bigint,
  blobUrl: string,
  exploitSha256: Uint8Array
): Buffer {
  return Buffer.concat([
    anchorDiscriminator("submit_exploit"),
    u64le(bountyId),
    borshString(blobUrl),
    exploitSha256,
  ]);
}

// ---------------------------------------------------------------------------
// Chain parsing (hand-decoded borsh — offsets documented inline)
// ---------------------------------------------------------------------------

export interface ParsedBounty {
  deadlineSecs: number;
  statusByte: number; // 0 Open · 1 AwaitingResolution · 2 Resolved · 3 Cancelled
  envBlobSha256: Buffer;
  flagCommitment: Buffer;
  buyerEncPk: Buffer;
}

/**
 * Bounty layout after the 8-byte Anchor discriminator:
 *   buyer(32) bounty_id(8) status(1) prize(8) deadline(8)
 *   manifest(32) env_blob(32) flag_commitment(32) buyer_enc_pk(32) ...
 */
export function parseBountyFields(data: Buffer): ParsedBounty {
  if (data.length < 161 + 1)
    throw new Error(`Bounty account too short: ${data.length}`);
  return {
    deadlineSecs: Number(data.readBigInt64LE(57)),
    statusByte: data[48],
    envBlobSha256: Buffer.from(data.subarray(97, 129)),
    flagCommitment: Buffer.from(data.subarray(129, 161)),
    buyerEncPk: Buffer.from(data.subarray(161, 193)),
  };
}

/**
 * Config layout after discriminator:
 *   authority(32) operators_vec(u32 + n*32) threshold(1)
 *   enclave_enc_pk(32) bond(8) force_unlock_delay(8) bump(1)
 */
export function parseEnclavePkFromConfig(data: Buffer): Buffer {
  if (data.length < 44 + 32)
    throw new Error(`Config account too short: ${data.length}`);
  const opsLen = data.readUInt32LE(40);
  const start = 44 + opsLen * 32 + 1; // skip threshold byte
  return Buffer.from(data.subarray(start, start + 32));
}

// ---------------------------------------------------------------------------
// Steps c+d — seal + intent signature (pure aside from libsodium init)
// ---------------------------------------------------------------------------

export interface BuiltPayload {
  intentMessage: Buffer;
  intentSigB64: string;
  sealedBoxB64: string;
  plaintextShaHex: string;
  solverPubkeyB58: string;
  claimedChainView: {
    env_blob_sha256: string;
    buyer_enc_pk: string;
    flag_commitment: string;
    exploit_sha256: string;
  };
}

export async function buildSealedPayload(
  exploitBytes: Buffer,
  solver: Keypair,
  bountyPda: PublicKey,
  enclaveEncPk: Uint8Array,
  chain: {
    envBlobSha256: Buffer;
    buyerEncPk: Buffer;
    flagCommitment: Buffer;
  }
): Promise<BuiltPayload> {
  await sodium.ready;
  const sealed = sodium.crypto_box_seal(
    new Uint8Array(exploitBytes),
    new Uint8Array(enclaveEncPk)
  );
  const plaintextSha = sha256(exploitBytes);
  const msg = buildIntentMessage(bountyPda.toBytes(), plaintextSha);
  const sig = nacl.sign.detached(new Uint8Array(msg), solver.secretKey);

  return {
    intentMessage: msg,
    intentSigB64: Buffer.from(sig).toString("base64"),
    sealedBoxB64: Buffer.from(sealed).toString("base64"),
    plaintextShaHex: plaintextSha.toString("hex"),
    solverPubkeyB58: solver.publicKey.toBase58(),
    claimedChainView: {
      env_blob_sha256: chain.envBlobSha256.toString("hex"),
      buyer_enc_pk: chain.buyerEncPk.toString("hex"),
      flag_commitment: chain.flagCommitment.toString("hex"),
      exploit_sha256: plaintextSha.toString("hex"),
    },
  };
}
