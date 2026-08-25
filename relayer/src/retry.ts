/**
 * Retry policy for pipeline outcomes (audit P1-4).
 *
 *  - landed / permanent-reject  → dropped forever.
 *  - left-for-unlock            → transient: requeued with exponential
 *    backoff up to MAX_ATTEMPTS; past that the job is parked until the
 *    force-unlock sweeper fires (bounty stays AwaitingResolution, so the
 *    on-chain escape hatch is always available).
 */

export const MAX_ATTEMPTS = 3;
export const BACKOFF_BASE_MS = 30_000;
export const BACKOFF_CAP_MS = 10 * 60_000;

export interface RetryDecision {
  action: "drop" | "requeue";
  /** ms to wait before the job becomes eligible again (0 = immediately). */
  delayMs: number;
}

export function decideRetry(
  status: "landed" | "permanent-reject" | "left-for-unlock",
  attemptsSoFar: number
): RetryDecision {
  if (status === "landed" || status === "permanent-reject") return { action: "drop", delayMs: 0 };
  if (attemptsSoFar + 1 >= MAX_ATTEMPTS) return { action: "requeue", delayMs: -1 }; // -1 => park for sweeper
  const delay = Math.min(BACKOFF_BASE_MS * 2 ** attemptsSoFar, BACKOFF_CAP_MS);
  return { action: "requeue", delayMs: delay };
}

/** Pure predicate used by the force-unlock sweeper pass. */
export function shouldForceUnlock(
  nowSecs: number,
  submittedAtSecs: number,
  forceUnlockDelayS: number
): boolean {
  return nowSecs >= submittedAtSecs + forceUnlockDelayS;
}
