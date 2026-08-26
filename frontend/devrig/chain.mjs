// Chain plumbing for the rig: program handle, PDAs, and the attested-verdict path.
//
// Deliberately mirrors tests/sealed-code-bounty.ts so the rig and the Anchor suite
// agree byte-for-byte on the SCB_VERDICT_V4 wire and on account ordering.

import fs from "node:fs";
import BN from "bn.js";
import {
  Connection,
  Ed25519Program,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  Transaction,
} from "@solana/web3.js";
import * as anchor from "@anchor-lang/core";
import {
  IDL_PATH,
  LAMPORTS_PER_SOL,
  MAX_CIPHERTEXT_LEN,
  PROGRAM_ID,
  RPC_URL,
  VERDICT_DOMAIN_TAG,
  VERDICT_MSG_LEN,
} from "./config.mjs";
import { sealTo, signDetached } from "./keys.mjs";

export { BN };
export const programId = new PublicKey(PROGRAM_ID);
const idl = JSON.parse(fs.readFileSync(IDL_PATH, "utf8"));

export function connect() {
  return new Connection(RPC_URL, "confirmed");
}

/**
 * A Program signing as `payer`. @anchor-lang/core lowercases account-namespace keys
 * at runtime (see lib/anchorClient.ts) — `accounts()` below is the same bridge.
 */
export function makeProgram(connection, payer) {
  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(payer), {
    commitment: "confirmed",
    preflightCommitment: "confirmed",
  });
  return new anchor.Program(idl, provider);
}

export function accounts(program) {
  return program.account;
}

// --- PDAs (mirror src/lib/pda.ts) -----------------------------------------

const seed = (s) => Buffer.from(s);

export function configPda() {
  return PublicKey.findProgramAddressSync([seed("config")], programId)[0];
}
export function bountyPda(buyer, bountyId) {
  return PublicKey.findProgramAddressSync(
    [seed("bounty"), buyer.toBuffer(), new BN(bountyId).toArrayLike(Buffer, "le", 8)],
    programId,
  )[0];
}
export function receiptPda(bounty, solver) {
  return PublicKey.findProgramAddressSync(
    [seed("receipt"), bounty.toBuffer(), solver.toBuffer()],
    programId,
  )[0];
}
export function revealPda(bounty) {
  return PublicKey.findProgramAddressSync([seed("reveal"), bounty.toBuffer()], programId)[0];
}

// --- helpers ---------------------------------------------------------------

export const hex = (u8) => Buffer.from(u8).toString("hex");
export const bytes = (v) => (v instanceof Uint8Array ? v : Uint8Array.from(v ?? []));

export function statusKind(raw) {
  const k = raw && typeof raw === "object" ? Object.keys(raw)[0] : undefined;
  return k ?? "unknown";
}

export async function chainNow(connection) {
  const slot = await connection.getSlot();
  return (await connection.getBlockTime(slot)) ?? Math.floor(Date.now() / 1000);
}

/** Airdrop and wait until the balance is actually visible; localnet faucets are lazy. */
export async function fundTo(connection, pubkey, sol) {
  const target = sol * LAMPORTS_PER_SOL;
  if ((await connection.getBalance(pubkey)) >= target) return false;
  const sig = await connection.requestAirdrop(pubkey, target);
  await connection.confirmTransaction(sig, "confirmed");
  for (let i = 0; i < 40; i++) {
    if ((await connection.getBalance(pubkey)) > 0) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return true;
}

// --- verdict attestation ---------------------------------------------------

/**
 * Canonical SCB_VERDICT_V4 wire (constants.rs):
 *   14 B tag || bounty || env_blob_sha256 || exploit_sha256 || solver
 *   || flag_commitment || buyer_enc_pk || 1 B outcome
 */
export function buildVerdictMessage({
  bounty,
  envBlobSha256,
  exploitSha256,
  solver,
  flagCommitment,
  buyerEncPk,
  outcome,
}) {
  const msg = Buffer.concat([
    Buffer.from(VERDICT_DOMAIN_TAG),
    bounty.toBuffer(),
    Buffer.from(envBlobSha256),
    Buffer.from(exploitSha256),
    solver.toBuffer(),
    Buffer.from(flagCommitment),
    Buffer.from(buyerEncPk),
    Buffer.from([outcome ? 1 : 0]),
  ]);
  if (msg.length !== VERDICT_MSG_LEN) {
    throw new Error(`verdict message is ${msg.length} B, expected ${VERDICT_MSG_LEN}`);
  }
  return msg;
}

/**
 * Signs a verdict as the operator and lands [Ed25519SigVerify, resolve_with_attestation]
 * as ONE atomic transaction from the relayer — the program introspects the sig-verify
 * instruction via the instructions sysvar, so they cannot be split.
 *
 * PASS carries the exploit sealed to the buyer's X25519 key as the inline reveal
 * carrier; FAIL must carry no ciphertext, no url, and no receipt/reveal accounts
 * (resolve_with_attestation.rs:276-286).
 */
export async function resolveVerdict({
  connection,
  keys,
  bountyAccount,
  bountyKey,
  outcome,
  plaintext,
}) {
  const program = makeProgram(connection, keys.relayer);
  const solver = bountyAccount.currentSubmission.solver;
  const envBlobSha256 = bytes(bountyAccount.envBlobSha256);
  const exploitSha256 = bytes(bountyAccount.currentSubmission.exploitSha256);
  const flagCommitment = bytes(bountyAccount.flagCommitment);
  const buyerEncPk = bytes(bountyAccount.buyerEncPk);

  const message = buildVerdictMessage({
    bounty: bountyKey,
    envBlobSha256,
    exploitSha256,
    solver,
    flagCommitment,
    buyerEncPk,
    outcome,
  });

  const signature = await signDetached(message, keys.operator);
  const ed25519Ix = Ed25519Program.createInstructionWithPublicKey({
    publicKey: keys.operator.publicKey.toBytes(),
    signature,
    message,
  });

  let ciphertext = Buffer.alloc(0);
  let ciphertextSha = Buffer.alloc(32);
  if (outcome) {
    ciphertext = Buffer.from(await sealTo(plaintext, buyerEncPk));
    if (ciphertext.length > MAX_CIPHERTEXT_LEN) {
      throw new Error(
        `sealed reveal is ${ciphertext.length} B, over the ${MAX_CIPHERTEXT_LEN} B inline cap. ` +
          "The mock enclave only implements the inline carrier — use a smaller exploit.",
      );
    }
    const { createHash } = await import("node:crypto");
    ciphertextSha = createHash("sha256").update(ciphertext).digest();
  }

  const resolveIx = await program.methods
    .resolveWithAttestation(
      new BN(bountyAccount.bountyId.toString()),
      outcome,
      ciphertext,
      "",
      Array.from(ciphertextSha),
    )
    .accountsStrict({
      relayer: keys.relayer.publicKey,
      config: configPda(),
      bounty: bountyKey,
      solver,
      receipt: outcome ? receiptPda(bountyKey, solver) : null,
      reveal: outcome ? revealPda(bountyKey) : null,
      ed25519Program: Ed25519Program.programId,
      instructions: SYSVAR_INSTRUCTIONS_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .instruction();

  const tx = new Transaction().add(ed25519Ix).add(resolveIx);
  return program.provider.sendAndConfirm(tx, []);
}

export { Keypair, PublicKey, SystemProgram };
