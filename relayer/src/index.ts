#!/usr/bin/env node
import { AnchorProvider, Wallet, BN, Program } from "@anchor-lang/core";
import { Connection, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as path from "path";

import { loadConfig } from "./config";
import { makeLogger } from "./logger";
import { JobQueue, Job } from "./queue";
import { processJob, PipelineDeps } from "./pipeline";
import type { SealedCodeBounty } from "../../target/types/sealed_code_bounty";

const log = makeLogger("relayer");
const queue = new JobQueue();

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
  const idlAddress = (idl as unknown as { metadata?: { address?: string } }).metadata?.address;
  if (!idlAddress || idlAddress !== cfg.programId) {
    throw new Error(
      `PROGRAM_ID ${cfg.programId} does not match IDL metadata address ${idlAddress ?? "<none>"}`
    );
  }

  const connection = new Connection(cfg.rpcUrl, "confirmed");
  const wallet = new Wallet(cfg.feePayer);
  const provider = new AnchorProvider(connection, wallet, { commitment: "confirmed" });
  // The generated type is compile-time only; at runtime we hand anchor the raw IDL.
  const program = new Program<SealedCodeBounty>(
    idl as unknown as SealedCodeBounty,
    provider
  );

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
        await processJob(deps, job);
      }
    } finally {
      busy = false;
    }
  };
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
