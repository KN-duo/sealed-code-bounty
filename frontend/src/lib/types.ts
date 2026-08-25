import type { BN } from "@anchor-lang/core";

// Normalized domain models. The rest of the app consumes THESE, never raw Anchor
// account output — so BN/enum/byte-array quirks live only in anchorClient.ts.

export type BountyStatusKind = "open" | "awaitingResolution" | "resolved" | "cancelled";

export interface Submission {
  solver: string;
  exploitSha256: string; // hex
  blobUrl: string;
  bondLamports: BN;
  submittedAt: number; // unix seconds
}

export interface Bounty {
  pda: string;
  buyer: string;
  bountyId: BN;
  status: BountyStatusKind;
  prizeLamports: BN;
  deadline: number; // unix seconds
  manifestSha256: string; // hex
  envBlobSha256: string; // hex
  flagCommitment: string; // hex
  buyerEncPk: string; // hex
  buyerEncPkBytes: Uint8Array;
  submission: Submission | null;
  winner: string | null;
}

export interface ProtocolConfig {
  pda: string;
  platformAuthority: string;
  operators: string[];
  threshold: number;
  enclaveEncPk: string; // hex
  enclaveEncPkBytes: Uint8Array;
  submissionBondLamports: BN;
  forceUnlockDelayS: number;
}

export interface Receipt {
  pda: string;
  bounty: string;
  solver: string;
  exploitSha256: string; // hex
  firstBlood: boolean;
  timestamp: number; // unix seconds
}

export interface Reveal {
  pda: string;
  ciphertext: Uint8Array;
  ciphertextUrl: string;
  ciphertextSha256: string; // hex
}

// UI presentation for each status: label + CSS custom-property color token.
export const STATUS_META: Record<BountyStatusKind, { label: string; token: string }> = {
  open: { label: "Open", token: "var(--status-open)" },
  awaitingResolution: { label: "Verifying", token: "var(--status-verifying)" },
  resolved: { label: "Resolved", token: "var(--status-resolved)" },
  cancelled: { label: "Cancelled", token: "var(--status-cancelled)" },
};
