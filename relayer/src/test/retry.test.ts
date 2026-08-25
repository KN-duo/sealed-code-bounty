import { test } from "node:test";
import assert from "node:assert/strict";
import { decideRetry, shouldForceUnlock, MAX_ATTEMPTS } from "../retry";

test("(R1) landed and permanent rejects are dropped regardless of attempts", () => {
  assert.deepEqual(decideRetry("landed", 0), { action: "drop", delayMs: 0 });
  assert.deepEqual(decideRetry("landed", 9), { action: "drop", delayMs: 0 });
  assert.equal(decideRetry("permanent-reject", 5).action, "drop");
});

test("(R2) left-for-unlock backs off exponentially then parks for the sweeper", () => {
  assert.deepEqual(decideRetry("left-for-unlock", 0), { action: "requeue", delayMs: 30_000 });
  assert.deepEqual(decideRetry("left-for-unlock", 1), { action: "requeue", delayMs: 60_000 });
  const last = decideRetry("left-for-unlock", MAX_ATTEMPTS - 1);
  assert.equal(last.action, "requeue");
  assert.equal(last.delayMs, -1); // parked: sweeper owns it now
});

test("(R3) force-unlock fires exactly when chain clock passes submit+delay", () => {
  const now = 100_000;
  assert.equal(shouldForceUnlock(now, now - 3600, 3600), true);
  assert.equal(shouldForceUnlock(now, now - 3599, 3600), false);
  assert.equal(shouldForceUnlock(now, now - 1, 1), true);
  // boundary: >= is required so an exact-delay call unlocks.
  assert.equal(shouldForceUnlock(now, now - 3600 - 1, 3600), true);
});
