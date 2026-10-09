#!/usr/bin/env node
import { AnchorProvider, Wallet, BN, Program } from "@anchor-lang/core";
import { Connection, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as path from "path";

import { loadConfig } from "./config";
import { makeLogger } from "./logger";
import { processJob, PipelineDeps, BountyView } from "./pipeline";
import { RecoveryWorker, type BountyRecord } from "./recovery";
import { chainClock } from "./clock";
import type { SealedCodeBounty } from "../../target/types/sealed_code_bounty";

const log = makeLogger("relayer");

async function main(): Promise<void> {
  const cfg = loadConfig();
  let operatorPk: PublicKey;
  try {
    operatorPk = new PublicKey(cfg.operatorPubkey);
  } catch (e) {
    throw new Error(`OPERATOR_PUBKEY "${cfg.operatorPubkey}" is not a valid pubkey: ${String(e)}`);
  }

  let idlAbs = path.resolve(process.cwd(), cfg.idlPath);
  if (!fs.existsSync(idlAbs)) {
    // running from dist/: repo root is four levels above this file
    idlAbs = path.resolve(__dirname, "../../../../target/idl/sealed_code_bounty.json");
  }
  if (!fs.existsSync(idlAbs)) {
    throw new Error(`IDL not found at ${idlAbs} (set IDL_PATH or run from the repo root)`);
  }
  const idl = JSON.parse(fs.readFileSync(idlAbs, "utf8")) as unknown as SealedCodeBounty;
  // anchor 1.x derives the program id from idl.metadata.address.
  // Anchor 0.x IDLs put the address at the top level; 1.x spec puts it in
  // metadata. Accept either, and treat a missing address as "use PROGRAM_ID".
  const idlAddress =
    (idl as unknown as { address?: string }).address ??
    (idl as unknown as { metadata?: { address?: string } }).metadata?.address;
  if (idlAddress && idlAddress !== cfg.programId) {
    throw new Error(`PROGRAM_ID ${cfg.programId} != IDL address ${idlAddress}`);
  }

  const connection = new Connection(cfg.rpcUrl, "confirmed");
  const wallet = new Wallet(cfg.feePayer);
  const provider = new AnchorProvider(connection, wallet, { commitment: "confirmed" });
  // The generated type is compile-time only; at runtime we hand anchor the raw IDL.
  const program = new Program<SealedCodeBounty>(
    idl as unknown as SealedCodeBounty,
    provider
  );

  const abort = new AbortController();
  const configPda = PublicKey.findProgramAddressSync(
    [Buffer.from("config")],
    program.programId
  )[0];

  const deps: PipelineDeps = {
    program,
    connection,
    feePayer: cfg.feePayer,
    operatorPubkey: operatorPk,
    enclaveUrl: cfg.enclaveUrl,
    log,
    signal: abort.signal,
  };

  const worker = new RecoveryWorker({
    // Bounty is discriminator(8), buyer(32), bounty_id(8), then status(u8).
    // AwaitingResolution is enum ordinal 1, base58-encoded as "2". Anchor
    // adds its account discriminator filter to this query.
    listPending: async () => await program.account.bounty.all([
      { memcmp: { offset: 48, bytes: "2" } },
    ]) as unknown as BountyRecord[],
    fetchBounty: async (pda) => await program.account.bounty.fetchNullable(pda) as unknown as BountyView | null,
    process: (job) => processJob(deps, job),
    unlockState: async () => {
      const config = await program.account.config.fetch(configPda) as unknown as { forceUnlockDelayS: BN };
      return { nowSecs: await chainClock(connection), forceUnlockDelayS: config.forceUnlockDelayS.toNumber() };
    },
    unlock: async (job) => {
      abort.signal.throwIfAborted();
      // Anchor's rpc() confirms at the provider commitment and rejects
      // transactions whose on-chain result contains an error.
      await program.methods.forceUnlockSubmission(job.bountyId)
        .accountsStrict({ caller: cfg.feePayer.publicKey, bounty: job.bountyPda, config: configPda, solver: job.solver })
        .signers([cfg.feePayer]).rpc();
    },
    log,
  }, cfg.reconcileIntervalMs, Math.max(cfg.pollIntervalMs, 15_000), cfg.pollIntervalMs);

  // ---- event ingestion ---------------------------------------------------
  // Retry event subscription on ECONNREFUSED (websocket port may not be
  // ready immediately after validator startup — same backoff pattern as
  // enclave calls).
  let listenerId: number | undefined;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      listenerId = program.addEventListener(
        "exploitSubmitted",
        (event: {
          bounty: PublicKey;
          bountyId: BN;
          solver: PublicKey;
          exploitSha256: number[];
        }, slot: number, sig: string) => {
          worker.requestReconcile();
          log.info("submission event observed; chain reconciliation requested", {
            bounty: event.bounty.toBase58(),
            slot,
            signature: sig.slice(0, 16) + "\u2026",
          });
        }
      );
      break;
    } catch (e) {
      if (attempt === 4) throw new Error(`event subscription failed after 5 attempts: ${e}`);
      log.warn("event subscription failed; retrying", { attempt, error: String(e) });
      await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
    }
  }

  // One timer and one serialized worker; no delayed requeue callbacks can
  // resurrect work after shutdown or run concurrently with the unlock sweep.
  const timer = setInterval(() => void worker.tick(), cfg.pollIntervalMs);

  // ---- graceful shutdown --------------------------------------------------
  let shutdownRequested = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shutdownRequested) return;
    shutdownRequested = true;
    log.info("shutdown requested", { signal, pendingJobs: worker.queue.size });
    clearInterval(timer);
    abort.abort(new Error("relayer shutting down"));
    const stopped = worker.stop();
    if (typeof listenerId === "number") await program.removeEventListener(listenerId).catch(() => {});
    await stopped;
    log.info("bye; pending submissions will recover from chain", { pendingJobs: worker.queue.size });
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  await worker.tick();
}

main().catch((e) => {
  log.error("fatal during startup", { error: String(e) });
  process.exit(1);
});
