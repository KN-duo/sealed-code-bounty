import { BN } from "@anchor-lang/core";
import { CLUSTER, RPC_URL } from "../env";

export const LAMPORTS_PER_SOL = 1_000_000_000;

// --- money ----------------------------------------------------------------

export function lamportsToSol(lamports: BN | number | bigint): number {
  const n = typeof lamports === "object" ? Number(lamports.toString()) : Number(lamports);
  return n / LAMPORTS_PER_SOL;
}

export function solToLamports(sol: number): BN {
  return new BN(Math.round(sol * LAMPORTS_PER_SOL));
}

// Compact SOL string: trims trailing zeros, keeps up to 4 decimals.
export function formatSol(lamports: BN | number | bigint): string {
  const sol = lamportsToSol(lamports);
  if (sol === 0) return "0";
  if (sol < 0.0001) return sol.toExponential(2);
  return sol.toLocaleString(undefined, { maximumFractionDigits: 4 });
}

// --- hashes / pubkeys -----------------------------------------------------

// Hex for a raw byte array (sha256, commitments, enc keys).
export function bytesToHex(bytes: Uint8Array | number[]): string {
  const arr = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  let out = "";
  for (const b of arr) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/, "");
  if (clean.length % 2 !== 0) throw new Error("hex string has odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Middle-truncate a long identifier: "FbqouGm…SXba9V".
export function truncate(value: string, head = 6, tail = 6): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

// --- time / countdown -----------------------------------------------------

export function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

// Humanized remaining time from an absolute unix-second deadline.
export function formatCountdown(deadlineUnix: number, from = nowUnix()): string {
  const secs = deadlineUnix - from;
  if (secs <= 0) return "expired";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function isPast(deadlineUnix: number, from = nowUnix()): boolean {
  return from > deadlineUnix;
}

export function formatDate(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// --- explorer links ---------------------------------------------------------

// Cluster-aware explorer URL for a path like "/tx/<sig>" or "/address/<addr>".
// mainnet gets no suffix, devnet the ?cluster=devnet param, localnet a custom
// cluster pointing at the configured RPC. A "custom" cluster has no canonical
// explorer, so callers must render no link.
function explorerUrl(path: string): string | null {
  switch (CLUSTER) {
    case "devnet":
      return `https://explorer.solana.com${path}?cluster=devnet`;
    case "mainnet":
      return `https://explorer.solana.com${path}`;
    case "localnet":
      return `https://explorer.solana.com${path}?cluster=custom&customUrl=${encodeURIComponent(RPC_URL)}`;
    case "custom":
      return null;
  }
}

export function explorerTxUrl(signature: string): string | null {
  return explorerUrl(`/tx/${signature}`);
}

export function explorerAddressUrl(address: string): string | null {
  return explorerUrl(`/address/${address}`);
}

// --- clipboard ------------------------------------------------------------

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
