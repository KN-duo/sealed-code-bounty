import { PublicKey } from "@solana/web3.js";
import { JobQueue, jobIdentity, type Job } from "./queue";
import type { BountyView, JobOutcome } from "./pipeline";
import { shouldForceUnlock } from "./retry";
import type { Logger } from "./logger";

export interface BountyRecord {
  publicKey: PublicKey;
  account: BountyView;
}

export function pendingJob(record: BountyRecord): Job | undefined {
  const { account: bounty, publicKey: bountyPda } = record;
  const sub = bounty.currentSubmission;
  if (!("awaitingResolution" in bounty.status) || !sub) return undefined;
  return {
    bountyPda, bountyId: bounty.bountyId, solver: sub.solver,
    exploitSha256: Buffer.from(sub.exploitSha256), submittedAt: sub.submittedAt,
    submissionRef: sub.blobUrl,
  };
}

export interface RecoveryDeps {
  listPending(): Promise<BountyRecord[]>;
  fetchBounty(pda: PublicKey): Promise<BountyView | null>;
  process(job: Job): Promise<JobOutcome>;
  unlockState(): Promise<{ nowSecs: number; forceUnlockDelayS: number }>;
  unlock(job: Job): Promise<void>;
  log: Logger;
  now?: () => number;
}

/**
 * One serialized lane owns reconciliation, verification and forced unlocks.
 * Events are hints only; startup/periodic chain scans recover missed events.
 * Retry counters are process-local; the chain is the durable queue.
 */
export class RecoveryWorker {
  readonly queue = new JobQueue();
  private reconcileRequested = true;
  private nextReconcileAt = 0;
  private nextHintAt = 0;
  private nextSweepAt = 0;
  private active: Promise<void> | undefined;
  private stopped = false;

  constructor(
    private readonly deps: RecoveryDeps,
    private readonly reconcileIntervalMs = 30_000,
    private readonly sweepIntervalMs = 15_000,
    private readonly hintIntervalMs = 1_000,
  ) {}

  requestReconcile(): void {
    this.reconcileRequested = true;
  }

  tick(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (this.active) return this.active;
    const work = this.run().catch((error: unknown) => {
      this.deps.log.warn("recovery pass failed; pending work retained", { error: String(error).slice(0, 200) });
    });
    this.active = work.finally(() => { this.active = undefined; });
    return this.active;
  }

  async stop(): Promise<void> {
    this.stopped = true;
    await this.active;
  }

  private now(): number { return (this.deps.now ?? Date.now)(); }

  private async run(): Promise<void> {
    const now = this.now();
    if (now >= this.nextReconcileAt || (this.reconcileRequested && now >= this.nextHintAt)) {
      // Set these before awaiting: a websocket hint arriving during the scan
      // remains pending for the next pass. Failures never discard tracked work.
      this.reconcileRequested = false;
      this.nextReconcileAt = now + this.reconcileIntervalMs;
      this.nextHintAt = now + this.hintIntervalMs;
      try {
        const records = await this.deps.listPending();
        this.queue.reconcile(records.flatMap((record) => {
          const job = pendingJob(record);
          return job ? [job] : [];
        }));
        this.deps.log.info("pending submissions reconciled", { pendingJobs: this.queue.size });
      } catch (error) {
        this.deps.log.warn("chain reconciliation failed; keeping tracked work", { error: String(error).slice(0, 200) });
      }
    }
    if (this.stopped) return;
    if (now >= this.nextSweepAt) {
      this.nextSweepAt = now + this.sweepIntervalMs;
      await this.sweep();
    }
    if (this.stopped) return;
    const job = this.queue.dequeue(this.now());
    if (!job) return;
    let result: JobOutcome;
    try {
      result = await this.deps.process(job);
    } catch (error) {
      result = { status: "left-for-unlock", reason: String(error) };
    }
    this.queue.finish(job, result, this.now());
    // Pull fresh state after either settlement or a stale-job rejection.
    if (result.status !== "left-for-unlock") this.requestReconcile();
    this.deps.log.info("job attempt completed", { bounty: job.bountyPda.toBase58(), status: result.status });
  }

  private async sweep(): Promise<void> {
    const pending = this.queue.pendingUnlocks();
    if (pending.length === 0) return;
    // Read the chain clock/config once per pass; never substitute local time.
    const { nowSecs, forceUnlockDelayS } = await this.deps.unlockState();
    for (const previous of pending) {
      if (this.stopped) return;
      if (!shouldForceUnlock(nowSecs, previous.submittedAt.toNumber(), forceUnlockDelayS)) continue;
      try {
        const bounty = await this.deps.fetchBounty(previous.bountyPda);
        const current = bounty ? pendingJob({ publicKey: previous.bountyPda, account: bounty }) : undefined;
        if (!current) {
          this.queue.removeIfCurrent(previous);
          continue;
        }
        if (jobIdentity(current) !== jobIdentity(previous)) {
          this.queue.enqueue(current);
          continue;
        }
        if (this.stopped) return;
        await this.deps.unlock(current);
        this.queue.removeIfCurrent(current);
        this.requestReconcile();
        this.deps.log.info("force_unlock_submission confirmed", { bounty: current.bountyPda.toBase58() });
      } catch (error) {
        this.deps.log.warn("force-unlock sweep attempt failed", {
          bounty: previous.bountyPda.toBase58(), error: String(error).slice(0, 200),
        });
      }
    }
  }
}
