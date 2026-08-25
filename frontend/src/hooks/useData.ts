import { useAsync } from "./useAsync";
import {
  fetchAllBounties,
  fetchAllReceipts,
  fetchBounty,
  fetchConfig,
} from "../lib/anchorClient";
import type { Bounty, ProtocolConfig, Receipt } from "../lib/types";

// Protocol Config (bond amount, enclave encryption key). null = not initialized.
export function useConfig() {
  return useAsync<ProtocolConfig | null>(() => fetchConfig(), []);
}

// All bounties on the board.
export function useBounties() {
  return useAsync<Bounty[]>(() => fetchAllBounties(), [], (b) => b.length === 0);
}

// One bounty by PDA (base58). Missing account surfaces as empty.
export function useBounty(pda: string) {
  return useAsync<Bounty | null>(() => fetchBounty(pda), [pda], (b) => b === null);
}

// All Receipts — raw material for the leaderboard.
export function useReceipts() {
  return useAsync<Receipt[]>(() => fetchAllReceipts(), [], (r) => r.length === 0);
}
