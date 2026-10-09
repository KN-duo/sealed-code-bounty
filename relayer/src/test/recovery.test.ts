import test from "node:test";
import assert from "node:assert/strict";
import { Keypair, PublicKey } from "@solana/web3.js";
import { BN } from "@anchor-lang/core";
import { RecoveryWorker, pendingJob, type BountyRecord } from "../recovery";
import type { BountyView } from "../pipeline";
import type { Logger } from "../logger";

const quiet: Logger = { debug() {}, info() {}, warn() {}, error() {} };

function pendingRecord(): BountyRecord {
  const bountyPda = Keypair.generate().publicKey;
  const solver = Keypair.generate().publicKey;
  const account: BountyView = {
    bountyId: new BN(7), status: { awaitingResolution: {} },
    prizeLamports: new BN(1), deadline: new BN(9999), envBlobSha256: Buffer.alloc(32), manifestSha256: Buffer.alloc(32),
    flagCommitment: Buffer.alloc(32), buyerEncPk: Buffer.alloc(32), winner: null,
    currentSubmission: {
      solver, exploitSha256: Buffer.alloc(32, 3),
      blobUrl: `scb:submission:v1:${"a".repeat(64)}`,
      bondLamports: new BN(1), submittedAt: new BN(100),
    },
  };
  return { publicKey: bountyPda, account };
}

test("worker reconstructs pending submissions at startup and processes once", async () => {
  const record = pendingRecord();
  const calls: string[] = [];
  let lists = 0;
  const worker = new RecoveryWorker({
    listPending: async () => { lists++; return [record]; },
    fetchBounty: async () => record.account,
    process: async (job) => { calls.push(job.submissionRef); return { status: "landed", signature: "sig", outcome: true }; },
    unlockState: async () => ({ nowSecs: 100, forceUnlockDelayS: 3600 }),
    unlock: async () => assert.fail("must not unlock a fresh job"),
    log: quiet,
  });

  await worker.tick();
  assert.equal(calls.length, 1);
  assert.equal(lists, 1);
  assert.equal(worker.queue.size, 1, "landed job remains parked until chain reconciliation");
});

test("periodic reconciliation preserves retry backoff for an unchanged chain job", async () => {
  const record = pendingRecord();
  let now = 1_000;
  let calls = 0;
  const worker = new RecoveryWorker({
    listPending: async () => [record],
    fetchBounty: async () => record.account,
    process: async () => { calls++; return { status: "left-for-unlock", reason: "temporary" }; },
    unlockState: async () => ({ nowSecs: 100, forceUnlockDelayS: 3600 }),
    unlock: async () => assert.fail("must not unlock a fresh job"),
    log: quiet,
    now: () => now,
  }, 500, 10_000, 500);

  await worker.tick();
  now += 500;
  worker.requestReconcile();
  await worker.tick();
  assert.equal(calls, 1, "unchanged pending chain state must not reset its retry delay");
  assert.equal(worker.queue.size, 1);
  assert.ok(pendingJob(record));
});

