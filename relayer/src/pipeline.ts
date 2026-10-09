import {
  Connection,
  Ed25519Program,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import { BN } from "@anchor-lang/core";
import type { Program } from "@anchor-lang/core";
import type { SealedCodeBounty } from "../../target/types/sealed_code_bounty";
import { createHash } from "crypto";
import { buildVerdictMessage, verifyDetached } from "./verdict";
import type { VerifyRequest, VerifyResponse } from "./enclave-types";
import type { Job } from "./queue";
import type { Logger } from "./logger";

export const ED25519_PROGRAM_ID = new PublicKey(
  "Ed25519SigVerify111111111111111111111111111"
);
export const INSTRUCTIONS_SYSVAR_ID = new PublicKey(
  "Sysvar1nstructions1111111111111111111111111"
);

// Two bounded artifact fetches (120s each), execution (60s), transport margin.
const ENCLAVE_TIMEOUT_MS = 310_000;
const ENCLAVE_ATTEMPTS = 5;
const BACKOFF_BASE_MS = 500;

/** Errors that are the job's fault — retrying cannot fix them. */
export class PermanentError extends Error {}

export interface PipelineDeps {
  program: Program<SealedCodeBounty>;
  connection: Connection;
  feePayer: Keypair;
  operatorPubkey: PublicKey;
  enclaveUrl: string;
  log: Logger;
  /** injectable fetch for tests */
  fetchImpl?: typeof fetch;
  /** Shutdown cancels verifier calls and prevents new settlement transactions. */
  signal?: AbortSignal;
}

export interface BountyView {
  bountyId: BN;
  status: Record<string, unknown>;
  prizeLamports: BN;
  deadline: BN;
  envBlobSha256: Uint8Array;
  manifestSha256: Uint8Array;
  flagCommitment: Uint8Array;
  buyerEncPk: Uint8Array;
  currentSubmission: {
    solver: PublicKey;
    exploitSha256: Uint8Array;
    blobUrl: string;
    bondLamports: BN;
    submittedAt: BN;
  } | null;
  winner: PublicKey | null;
}

// ---------------------------------------------------------------------------
// Step a — trust-but-verify the event against live chain state
// ---------------------------------------------------------------------------

export async function validateJob(deps: PipelineDeps, job: Job): Promise<BountyView> {
  const b = (await deps.program.account.bounty.fetch(job.bountyPda)) as unknown as BountyView;
  if (!("awaitingResolution" in b.status)) {
    throw new PermanentError(`status is not AwaitingResolution (${JSON.stringify(b.status)})`);
  }
  const sub = b.currentSubmission;
  if (!sub) throw new PermanentError("no submission recorded");
  if (!sub.solver.equals(job.solver)) {
    throw new PermanentError(
      `submission solver ${sub.solver.toBase58()} != event solver ${job.solver.toBase58()}`
    );
  }
  if (!Buffer.from(sub.exploitSha256).equals(job.exploitSha256)
    || !sub.submittedAt.eq(job.submittedAt) || sub.blobUrl !== job.submissionRef) {
    throw new PermanentError("submission was replaced since this job was queued");
  }
  return b;
}

export function submissionReceipt(reference: string): string {
  const match = /^scb:submission:v1:([0-9a-f]{64})$/.exec(reference);
  if (!match) throw new PermanentError("submission reference must be scb:submission:v1:<64 lowercase hex>");
  return match[1];
}

// ---------------------------------------------------------------------------
// Step b — drive the enclave (retryable transport; verdicts never fabricated)
// ---------------------------------------------------------------------------

function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

export async function callEnclave(
  deps: PipelineDeps,
  job: Job,
  bounty: BountyView
): Promise<VerifyResponse> {
  const sub = bounty.currentSubmission!;
  const body: VerifyRequest = {
    bounty_pda: job.bountyPda.toBase58(),
    manifest_sha256: Buffer.from(bounty.manifestSha256).toString("hex"),
    submission_receipt: submissionReceipt(sub.blobUrl),
    claimed_chain_view: {
      env_blob_sha256: Buffer.from(bounty.envBlobSha256).toString("hex"),
      buyer_enc_pk: Buffer.from(bounty.buyerEncPk).toString("hex"),
      flag_commitment: Buffer.from(bounty.flagCommitment).toString("hex"),
      exploit_sha256: Buffer.from(sub.exploitSha256).toString("hex"),
    },
    solver_pubkey: job.solver.toBase58(),
  };

  let lastErr = "";
  for (let attempt = 0; attempt < ENCLAVE_ATTEMPTS; attempt++) {
    deps.signal?.throwIfAborted();
    try {
      const res = await (deps.fetchImpl ?? fetch)(`${deps.enclaveUrl}/internal/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: deps.signal
          ? AbortSignal.any([deps.signal, AbortSignal.timeout(ENCLAVE_TIMEOUT_MS)])
          : AbortSignal.timeout(ENCLAVE_TIMEOUT_MS),
      });
      if (res.ok) {
        const parsed = (await res.json()) as VerifyResponse;
        if (typeof parsed.outcome !== "boolean" || typeof parsed.sig !== "string") {
          throw new PermanentError("malformed enclave response");
        }
        return parsed;
      }
      lastErr = `HTTP ${res.status}`;
      if (!isRetryableStatus(res.status)) {
        throw new PermanentError(`enclave rejected verification: HTTP ${res.status}`);
      }
    } catch (e) {
      deps.signal?.throwIfAborted();
      if (e instanceof PermanentError) throw e;
      const cause = (e as { cause?: { code?: string; message?: string } })?.cause;
      lastErr = `${cause ? `${cause.code ?? ""} ${cause.message ?? ""}` : ""} :: ${String(e)}`;
    }
    if (attempt + 1 === ENCLAVE_ATTEMPTS) break;
    const delay = Math.min(BACKOFF_BASE_MS * 2 ** attempt, 8000);
    deps.log.warn("enclave call failed; backing off", {
      attempt: attempt + 1,
      nextInMs: delay,
      error: lastErr,
      bounty: job.bountyPda.toBase58(),
    });
    await new Promise<void>((resolve, reject) => {
      const onAbort = () => {
        clearTimeout(timer);
        reject(deps.signal?.reason ?? new Error("shutdown requested"));
      };
      const timer = setTimeout(() => {
        deps.signal?.removeEventListener("abort", onAbort);
        resolve();
      }, delay);
      deps.signal?.addEventListener("abort", onAbort, { once: true });
      if (deps.signal?.aborted) onAbort();
    });
  }
  // Give up: slot stays AwaitingResolution until force_unlock_submission.
  // NEVER fabricate a local FAIL — only enclave-signed verdicts exist.
  throw new Error(`enclave unreachable after ${ENCLAVE_ATTEMPTS} attempts: ${lastErr}`);
}

// ---------------------------------------------------------------------------
// Step c — reconstruct the exact wire, check the signature LOCALLY
// ---------------------------------------------------------------------------

export function reconstructMessage(job: Job, bounty: BountyView, outcome: boolean): Buffer {
  const sub = bounty.currentSubmission!;
  return buildVerdictMessage({
    bountyPda: job.bountyPda.toBuffer(),
    manifestSha256: Buffer.from(bounty.manifestSha256),
    envBlobSha256: Buffer.from(bounty.envBlobSha256),
    exploitSha256: Buffer.from(sub.exploitSha256),
    solver: sub.solver.toBuffer(),
    flagCommitment: Buffer.from(bounty.flagCommitment),
    buyerEncPk: Buffer.from(bounty.buyerEncPk),
    outcome,
  });
}

export interface PreparedVerdict {
  message: Buffer;
  signature: Buffer;
  ciphertext: Buffer;
  ciphertextUrl: string;
  ciphertextSha256: Buffer;
  outcome: boolean;
}

export function prepareVerdict(
  job: Job,
  bounty: BountyView,
  resp: VerifyResponse,
  operatorPubkey: PublicKey
): PreparedVerdict {
  const message = reconstructMessage(job, bounty, resp.outcome);
  if (!verifyDetached(message, resp.sig, operatorPubkey)) {
    throw new PermanentError(
      "enclave signature failed LOCAL verification over reconstructed SCB_VERDICT_V5 bytes"
    );
  }
  const ciphertext =
    resp.reveal_ciphertext && resp.reveal_ciphertext.length > 0
      ? Buffer.from(resp.reveal_ciphertext, "base64")
      : Buffer.alloc(0);
  let sha32: Buffer;
  if (ciphertext.length > 0) {
    sha32 = Buffer.from(createHash("sha256").update(ciphertext).digest());
  } else if (resp.reveal_ciphertext_url && resp.reveal_ciphertext_sha256) {
    sha32 = Buffer.from(resp.reveal_ciphertext_sha256, "hex");
    if (sha32.length !== 32)
      throw new PermanentError("reveal_ciphertext_sha256 must be 32-byte hex");
  } else if (resp.outcome) {
    throw new PermanentError("PASS verdict carries neither inline nor URL-referenced ciphertext");
  } else {
    sha32 = Buffer.alloc(32);
  }
  return {
    message,
    signature: Buffer.from(resp.sig, "base64"),
    ciphertext,
    ciphertextUrl: resp.reveal_ciphertext_url ?? "",
    ciphertextSha256: sha32,
    outcome: resp.outcome,
  };
}

// ---------------------------------------------------------------------------
// Step d — atomic [Ed25519SigVerify, resolve_with_attestation] transaction
// ---------------------------------------------------------------------------

function pdas(programId: PublicKey, bountyKey: Buffer, solver: Buffer) {
  const find = (seeds: Buffer[]) =>
    PublicKey.findProgramAddressSync(seeds, programId)[0];
  return {
    config: find([Buffer.from("config")]),
    receipt: find([Buffer.from("receipt"), bountyKey, solver]),
    reveal: find([Buffer.from("reveal"), bountyKey]),
  };
}

export async function composeVerdictTx(
  deps: PipelineDeps,
  job: Job,
  bounty: BountyView,
  prepared: PreparedVerdict
): Promise<Transaction> {
  const sub = bounty.currentSubmission!;
  const p = pdas(deps.program.programId, job.bountyPda.toBuffer(), sub.solver.toBuffer());

  const ed25519Ix = Ed25519Program.createInstructionWithPublicKey({
    publicKey: deps.operatorPubkey.toBytes(),
    signature: prepared.signature,
    message: prepared.message,
  });

  const resolveIx = await deps.program.methods
    .resolveWithAttestation(
      bounty.bountyId,
      prepared.outcome,
      prepared.ciphertext,
      prepared.ciphertextUrl,
      [...prepared.ciphertextSha256]
    )
    .accountsStrict({
      relayer: deps.feePayer.publicKey,
      config: p.config,
      bounty: job.bountyPda,
      solver: sub.solver,
      receipt: prepared.outcome ? p.receipt : null,
      reveal: prepared.outcome ? p.reveal : null,
      ed25519Program: ED25519_PROGRAM_ID,
      instructions: INSTRUCTIONS_SYSVAR_ID,
      systemProgram: SystemProgram.programId,
    })
    .transaction();

  const tx = new Transaction();
  tx.add(ed25519Ix, resolveIx);
  return tx;
}

export type JobOutcome =
  | { status: "landed"; signature: string; outcome: boolean }
  | { status: "permanent-reject"; reason: string }
  | { status: "left-for-unlock"; reason: string };

/** Orchestrates steps a–d for one job with structured logging throughout. */
export async function processJob(deps: PipelineDeps, job: Job): Promise<JobOutcome> {
  const tag = { bounty: job.bountyPda.toBase58(), solver: job.solver.toBase58() };
  deps.log.info("job start", tag);

  let bounty: BountyView;
  try {
    deps.signal?.throwIfAborted();
    bounty = await validateJob(deps, job);
  } catch (e) {
    const reason = String(e);
    deps.log.error("job rejected by chain-state validation", { ...tag, reason });
    return { status: e instanceof PermanentError ? "permanent-reject" : "left-for-unlock", reason };
  }
  deps.log.info("chain state validated (AwaitingResolution, solver match)", tag);

  let resp: VerifyResponse;
  try {
    resp = await callEnclave(deps, job, bounty);
  } catch (e) {
    // Transport exhaustion after backoff: leave the slot for
    // force_unlock_submission rather than inventing an outcome.
    const reason = String(e);
    deps.log.error("enclave unreachable — leaving slot for force_unlock_submission", {
      ...tag,
      reason,
    });
    return { status: e instanceof PermanentError ? "permanent-reject" : "left-for-unlock", reason };
  }
  deps.log.info("verdict received", { ...tag, outcome: resp.outcome });

  let prepared: PreparedVerdict;
  let tx: Transaction;
  try {
    prepared = prepareVerdict(job, bounty, resp, deps.operatorPubkey);
    tx = await composeVerdictTx(deps, job, bounty, prepared);
  } catch (e) {
    const reason = String(e);
    deps.log.error("verdict rejected before landing", { ...tag, reason });
    return { status: "permanent-reject", reason };
  }

  try {
    // The slot can change while execution runs (e.g. force-unlock/resubmit).
    deps.signal?.throwIfAborted();
    await validateJob(deps, job);
    const { blockhash, lastValidBlockHeight } =
      await deps.connection.getLatestBlockhash("confirmed");
    tx.recentBlockhash = blockhash;
    tx.feePayer = deps.feePayer.publicKey;
    deps.signal?.throwIfAborted();
    const signature = await deps.connection.sendTransaction(tx, [deps.feePayer], {
      skipPreflight: false,
    });
    const confirmation = await deps.connection.confirmTransaction(
      { signature, blockhash, lastValidBlockHeight },
      "confirmed"
    );
    if (confirmation.value.err) throw new Error(`verdict transaction rejected: ${JSON.stringify(confirmation.value.err)}`);
    deps.log.info("verdict transaction landed", {
      ...tag,
      outcome: prepared.outcome,
      signature,
    });
    return { status: "landed", signature, outcome: prepared.outcome };
  } catch (e) {
    const reason = String(e);
    deps.log.error("transaction failed — leaving to retry/unlock", { ...tag, reason });
    return { status: "left-for-unlock", reason };
  }
}
