import { PublicKey } from "@solana/web3.js";
import { BN } from "@anchor-lang/core";

export interface Job {
  bountyPda: PublicKey;
  solver: PublicKey;
  bountyId: BN;
  exploitSha256: Buffer;
}

/**
 * In-memory FIFO with dedupe by Bounty PDA: the single submission slot means
 * at most one job per bounty can ever be actionable, and duplicate event
 * deliveries (websocket reconnects) collapse onto the live entry.
 */
export class JobQueue {
  private readonly order: string[] = [];
  private readonly jobs = new Map<string, Job>();

  get size(): number {
    return this.jobs.size;
  }

  has(bountyPda: PublicKey): boolean {
    return this.jobs.has(bountyPda.toBase58());
  }

  enqueue(job: Job): boolean {
    const key = job.bountyPda.toBase58();
    if (this.jobs.has(key)) return false;
    this.jobs.set(key, job);
    this.order.push(key);
    return true;
  }

  dequeue(): Job | undefined {
    const key = this.order.shift();
    if (key === undefined) return undefined;
    const job = this.jobs.get(key);
    this.jobs.delete(key);
    return job;
  }

  /** Drops a job without executing (e.g. shutdown flush). */
  remove(bountyPda: PublicKey): boolean {
    const key = bountyPda.toBase58();
    if (!this.jobs.has(key)) return false;
    this.jobs.delete(key);
    const i = this.order.indexOf(key);
    if (i >= 0) this.order.splice(i, 1);
    return true;
  }
}
