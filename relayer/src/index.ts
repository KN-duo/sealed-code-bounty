#!/usr/bin/env node
import { AnchorProvider, Wallet, BN, Program } from "@anchor-lang/core";
import { Connection, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as path from "path";

import { loadConfig } from "./config";
import { makeLogger } from "./logger";
import { JobQueue, Job } from "./queue";
import { processJob, PipelineDeps } from "./pipeline";
import { decideRetry, shouldForceUnlock } from "./retry";
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

  const queue = new JobQueue();
  const attempts = new Map<string, number>();
  /** Tracked AwaitingResolution jobs for the force-unlock sweeper. */
  const pendingUnlocks = new Map<
    string,
    { bountyPda: PublicKey; solver: PublicKey; submittedAtSecs: number; bountyId: BN }
  >();
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
  };

  // ---- event ingestion ---------------------------------------------------
  const listenerId: number = program.addEventListener(
    "exploitSubmitted",
    (event: {
      bounty: PublicKey;
      bountyId: BN;
      solver: PublicKey;
      exploitSha256: number[];
    }, slot: number, sig: string) => {
      const job: Job = {
        bountyPda: new PublicKey(event.bounty),
        solver: new PublicKey(event.solver),
        bountyId: event.bountyId,
        exploitSha256: Buffer.from(event.exploitSha256),
      };
      const added = queue.enqueue(job);
      log.info(added ? "job enqueued" : "duplicate event ignored (dedupe)", {
        bounty: job.bountyPda.toBase58(),
        slot,
        signature: sig.slice(0, 16) + "…",
        queueDepth: queue.size,
      });
  });
  log.info("listening for ExploitSubmitted", {
    rpcUrl: cfg.rpcUrl,
    programId: cfg.programId,
    enclaveUrl: cfg.enclaveUrl,
    feePayer: cfg.feePayer.publicKey.toBase58(),
    operator: operatorPk.toBase58(),
  });

  // ---- worker loop (single-flight; POLL_INTERVAL_MS per tick) -------------
  let running = true;
  let busy = false;
  const tick = async (): Promise<void> => {
    if (!running || busy) return;
    busy = true;
    try {
      for (;;) {
        const job = queue.dequeue();
        if (!job) break;
        const key = job.bountyPda.toBase58();
        const attemptNo = attempts.get(key) ?? 0;
        const outcome = await processJob(deps, job);

        if (outcome.status === "left-for-unlock") {
          const decision = decideRetry("left-for-unlock", attemptNo);
          if (decision.action === "requeue" && decision.delayMs >= 0) {
            attempts.set(key, attemptNo + 1);
            log.info("requeueing transient failure", {
              bounty: key,
              attempt: attemptNo + 1,
              delayMs: decision.delayMs,
            });
            setTimeout(() => queue.enqueue(job), decision.delayMs).unref?.();
          } else {
            // Parked: the force-unlock sweeper owns this bounty now.
            log.warn("job parked for force_unlock_submission", { bounty: key });
          }
        } else {
          attempts.delete(key);
        }

        // Track pending submissions so the sweeper can free them.
        try {
          const b = (await deps.program.account.bounty.fetch(
            job.bountyPda
          )) as unknown as {
            status: Record<string, unknown>;
            currentSubmission: { submittedAt: BN } | null;
          };
          if (
            "awaitingResolution" in b.status &&
            b.currentSubmission &&
            !pendingUnlocks.has(key)
          ) {
            pendingUnlocks.set(key, {
              bountyPda: job.bountyPda,
              solver: job.solver,
              submittedAtSecs: b.currentSubmission.submittedAt.toNumber(),
              bountyId: job.bountyId,
            });
          } else if (!("awaitingResolution" in b.status)) {
            pendingUnlocks.delete(key);
          }
        } catch {
          /* best-effort tracking */
        }
      }
    } finally {
      busy = false;
    }
  };

  // ---- force-unlock sweeper (audit P1-4b) --------------------------------
  const sweepInterval = setInterval(() => {
    void (async () => {
      if (!running) return;
      let nowSecs: number | null = null;
      for (const [key, p] of [...pendingUnlocks.entries()]) {
        try {
          const b = (await deps.program.account.bounty.fetch(p.bountyPda)) as unknown as {
            status: Record<string, unknown>;
            currentSubmission: { submittedAt: BN } | null;
          };
          if (!("awaitingResolution" in b.status)) {
            pendingUnlocks.delete(key);
            continue;
          }
          if (nowSecs === null) nowSecs = await chainClock(connection);
          const subAt =
            b.currentSubmission?.submittedAt.toNumber() ?? p.submittedAtSecs;
          const cfgAcc = (await deps.program.account.config.fetch(
            configPda
          )) as unknown as { forceUnlockDelayS: BN };
          if (!shouldForceUnlock(nowSecs, subAt, cfgAcc.forceUnlockDelayS.toNumber()))
            continue;

          await deps.program.methods
            .forceUnlockSubmission(p.bountyId)
            .accountsStrict({
              caller: cfg.feePayer.publicKey,
              bounty: p.bountyPda,
              config: configPda,
              solver: p.solver,
            })
            .signers([cfg.feePayer])
            .rpc();
          pendingUnlocks.delete(key);
          log.info("force_unlock_submission sent", { bounty: key });
        } catch (e) {
          log.warn("force-unlock sweep attempt failed", {
            bounty: key,
            error: String(e).slice(0, 200),
          });
        }
      }
    })().catch(() => {});
  }, Math.max(cfg.pollIntervalMs, 15_000));
  const timer = setInterval(() => void tick(), cfg.pollIntervalMs);

  // ---- graceful shutdown --------------------------------------------------
  const shutdown = (signal: string): void => {
    log.info("shutdown requested", { signal, pendingJobs: queue.size });
    running = false;
    clearInterval(timer);
    void program.removeEventListener(listenerId).catch(() => {});
    const leftover = queue.size;
    log.info("bye", { droppedJobs: leftover });
    process.exit(0);
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((e) => {
  log.error("fatal during startup", { error: String(e) });
  process.exit(1);
});
