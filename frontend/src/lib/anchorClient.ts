import { Connection, PublicKey } from "@solana/web3.js";
import * as anchor from "@anchor-lang/core";
import type { Program, Provider } from "@anchor-lang/core";
import idl from "../idl/sealed_code_bounty.json";
import type { SealedCodeBounty } from "../idl/sealed_code_bounty";
import { RPC_URL } from "../env";
import { bytesToHex } from "./format";
import { configPda } from "./pda";
import type {
  Bounty,
  BountyStatusKind,
  ProtocolConfig,
  Receipt,
  Reveal,
  Submission,
} from "./types";

// ---- connection / program plumbing --------------------------------------

let readConn: Connection | null = null;
export function getConnection(): Connection {
  if (!readConn) readConn = new Connection(RPC_URL, "confirmed");
  return readConn;
}

// A wallet-less program for READ paths (Board, Leaderboard, detail). Writes use
// useProgram() which carries a signing wallet. Reads only touch provider.connection.
let readProgram: Program<SealedCodeBounty> | null = null;
export function getReadProgram(): Program<SealedCodeBounty> {
  if (!readProgram) {
    const provider = { connection: getConnection() } as unknown as Provider;
    readProgram = new anchor.Program(
      idl as anchor.Idl,
      provider,
    ) as unknown as Program<SealedCodeBounty>;
  }
  return readProgram;
}

// The @anchor-lang/core fork lowercases account-namespace keys at RUNTIME
// (config/bounty/receipt/reveal) even though its generated types capitalize them
// (Config/Bounty/...). Bridge that mismatch here, in one place, with a typed
// lowercase accessor — everything downstream stays clean.
/* eslint-disable @typescript-eslint/no-explicit-any */
interface AcctClient {
  all(): Promise<{ publicKey: PublicKey; account: any }[]>;
  fetch(addr: PublicKey): Promise<any>;
  fetchNullable(addr: PublicKey): Promise<any | null>;
}
function accounts(program: Program<SealedCodeBounty>): {
  config: AcctClient;
  bounty: AcctClient;
  receipt: AcctClient;
  reveal: AcctClient;
} {
  return program.account as unknown as {
    config: AcctClient;
    bounty: AcctClient;
    receipt: AcctClient;
    reveal: AcctClient;
  };
}

// ---- raw -> normalized coercion -----------------------------------------

function toBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return Uint8Array.from(v as number[]);
  if (v && typeof v === "object" && "length" in (v as ArrayLike<number>)) {
    return Uint8Array.from(v as ArrayLike<number>);
  }
  return new Uint8Array();
}
const hex = (v: unknown): string => bytesToHex(toBytes(v));
const key = (v: unknown): string => (v as PublicKey).toBase58();

function statusKind(raw: unknown): BountyStatusKind {
  const k = raw && typeof raw === "object" ? Object.keys(raw as object)[0] : undefined;
  if (k === "awaitingResolution") return "awaitingResolution";
  if (k === "resolved") return "resolved";
  if (k === "cancelled") return "cancelled";
  return "open";
}

function normalizeSubmission(raw: any): Submission | null {
  if (!raw) return null;
  return {
    solver: key(raw.solver),
    exploitSha256: hex(raw.exploitSha256),
    blobUrl: raw.blobUrl as string,
    bondLamports: raw.bondLamports as anchor.BN,
    submittedAt: Number((raw.submittedAt as anchor.BN).toString()),
  };
}

function normalizeBounty(pda: PublicKey, raw: any): Bounty {
  const buyerEncPkBytes = toBytes(raw.buyerEncPk);
  return {
    pda: pda.toBase58(),
    buyer: key(raw.buyer),
    bountyId: raw.bountyId as anchor.BN,
    status: statusKind(raw.status),
    prizeLamports: raw.prizeLamports as anchor.BN,
    deadline: Number((raw.deadline as anchor.BN).toString()),
    manifestSha256: hex(raw.manifestSha256),
    envBlobSha256: hex(raw.envBlobSha256),
    flagCommitment: hex(raw.flagCommitment),
    buyerEncPk: bytesToHex(buyerEncPkBytes),
    buyerEncPkBytes,
    submission: normalizeSubmission(raw.currentSubmission),
    winner: raw.winner ? key(raw.winner) : null,
  };
}

function normalizeConfig(pda: PublicKey, raw: any): ProtocolConfig {
  const enclaveEncPkBytes = toBytes(raw.enclaveEncPk);
  return {
    pda: pda.toBase58(),
    platformAuthority: key(raw.platformAuthority),
    operators: (raw.operators as PublicKey[]).map((o) => o.toBase58()),
    threshold: Number(raw.threshold),
    enclaveEncPk: bytesToHex(enclaveEncPkBytes),
    enclaveEncPkBytes,
    submissionBondLamports: raw.submissionBondLamports as anchor.BN,
    forceUnlockDelayS: Number((raw.forceUnlockDelayS as anchor.BN).toString()),
  };
}

function normalizeReceipt(pda: PublicKey, raw: any): Receipt {
  return {
    pda: pda.toBase58(),
    bounty: key(raw.bounty),
    solver: key(raw.solver),
    exploitSha256: hex(raw.exploitSha256),
    firstBlood: Boolean(raw.firstBlood),
    timestamp: Number((raw.timestamp as anchor.BN).toString()),
  };
}

function normalizeReveal(pda: PublicKey, raw: any): Reveal {
  return {
    pda: pda.toBase58(),
    ciphertext: toBytes(raw.ciphertext),
    ciphertextUrl: raw.ciphertextUrl as string,
    ciphertextSha256: hex(raw.ciphertextSha256),
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */

// ---- typed fetchers ------------------------------------------------------

export async function fetchConfig(program = getReadProgram()): Promise<ProtocolConfig | null> {
  const pda = configPda();
  const raw = await accounts(program).config.fetchNullable(pda);
  return raw ? normalizeConfig(pda, raw) : null;
}

export async function fetchAllBounties(program = getReadProgram()): Promise<Bounty[]> {
  const rows = await accounts(program).bounty.all();
  return rows.map((r) => normalizeBounty(r.publicKey, r.account));
}

export async function fetchBounty(pda: string, program = getReadProgram()): Promise<Bounty | null> {
  const pk = new PublicKey(pda);
  const raw = await accounts(program).bounty.fetchNullable(pk);
  return raw ? normalizeBounty(pk, raw) : null;
}

export async function fetchAllReceipts(program = getReadProgram()): Promise<Receipt[]> {
  const rows = await accounts(program).receipt.all();
  return rows.map((r) => normalizeReceipt(r.publicKey, r.account));
}

export async function fetchReveal(
  revealAddr: PublicKey,
  program = getReadProgram(),
): Promise<Reveal | null> {
  const raw = await accounts(program).reveal.fetchNullable(revealAddr);
  return raw ? normalizeReveal(revealAddr, raw) : null;
}
