import { PublicKey } from "@solana/web3.js";
import { BN } from "@anchor-lang/core";
import { decideRetry } from "./retry";
import type { JobOutcome } from "./pipeline";

export interface Job {
  bountyPda: PublicKey;
  solver: PublicKey;
  bountyId: BN;
  exploitSha256: Buffer;
  submittedAt: BN;
  submissionRef: string;
}

export function jobIdentity(job: Job): string {
  return JSON.stringify([
    job.bountyPda.toBase58(), job.solver.toBase58(), job.exploitSha256.toString("hex"),
    job.submittedAt.toString(), job.submissionRef,
  ]);
}

interface TrackedJob {
  job: Job;
  state: "queued" | "working" | "waiting" | "parked";
  attempts: number;
  readyAt: number;
}

/** Reconstructible from chain; dedupe also covers in-flight and delayed work. */
export class JobQueue {
  private readonly jobs = new Map<string, TrackedJob>();

  get size(): number {
    return this.jobs.size;
  }

  has(bountyPda: PublicKey): boolean {
    return this.jobs.has(bountyPda.toBase58());
  }

  enqueue(job: Job): boolean {
    const key = job.bountyPda.toBase58();
    const existing = this.jobs.get(key);
    if (existing && jobIdentity(existing.job) === jobIdentity(job)) return false;
    this.jobs.set(key, { job, state: "queued", attempts: 0, readyAt: 0 });
    return true;
  }

  dequeue(nowMs = Date.now()): Job | undefined {
    for (const tracked of this.jobs.values()) {
      if (tracked.state === "queued" || (tracked.state === "waiting" && tracked.readyAt <= nowMs)) {
        tracked.state = "working";
        return tracked.job;
      }
    }
    return undefined;
  }

  finish(job: Job, outcome: JobOutcome, nowMs = Date.now()): void {
    const tracked = this.jobs.get(job.bountyPda.toBase58());
    // A stale completion must never drop or park a newer submission.
    if (!tracked || jobIdentity(tracked.job) !== jobIdentity(job)) return;
    const decision = decideRetry(outcome.status, tracked.attempts);
    tracked.attempts += 1;
    if (decision.action === "requeue" && decision.delayMs >= 0) {
      tracked.state = "waiting";
      tracked.readyAt = nowMs + decision.delayMs;
    } else {
      // Keep a tombstone until the chain changes: polling must not revive a
      // permanent rejection, exhausted retries, or a just-confirmed verdict.
      tracked.state = "parked";
    }
  }

  reconcile(jobs: Job[]): void {
    const live = new Set(jobs.map((job) => job.bountyPda.toBase58()));
    for (const key of this.jobs.keys()) {
      if (!live.has(key)) this.jobs.delete(key);
    }
    for (const job of jobs) this.enqueue(job);
  }

  pendingUnlocks(): Job[] {
    return [...this.jobs.values()].filter((entry) => entry.state !== "working").map((entry) => entry.job);
  }

  removeIfCurrent(job: Job): boolean {
    const current = this.jobs.get(job.bountyPda.toBase58());
    if (!current || jobIdentity(current.job) !== jobIdentity(job)) return false;
    return this.remove(job.bountyPda);
  }

  /** Drops a job without executing (e.g. shutdown flush). */
  remove(bountyPda: PublicKey): boolean {
    const key = bountyPda.toBase58();
    return this.jobs.delete(key);
  }
}
