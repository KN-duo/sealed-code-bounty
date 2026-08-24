import { Keypair } from "@solana/web3.js";
import * as fs from "fs";

export interface RelayerConfig {
  rpcUrl: string;
  programId: string;
  feePayer: Keypair;
  enclaveUrl: string;
  operatorPubkey: string;
  pollIntervalMs: number;
  idlPath: string;
}

function required(name: string): string {
  const v = process.env[name];
  if (!v || v.trim() === "") {
    throw new Error(
      `Missing required env var ${name}. Required: PROGRAM_ID, FEE_PAYER_KEYPAIR_PATH, OPERATOR_PUBKEY. Optional: RPC_URL, ENCLAVE_URL, POLL_INTERVAL_MS, IDL_PATH.`
    );
  }
  return v.trim();
}

function intEnv(name: string, dflt: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return dflt;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) throw new Error(`${name} must be a non-negative integer, got "${v}"`);
  return Math.floor(n);
}

/** Loads a solana-keygen JSON file into a Keypair. */
export function loadKeypair(path: string): Keypair {
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`FEE_PAYER_KEYPAIR_PATH "${path}" is not readable JSON: ${String(e)}`);
  }
  if (!Array.isArray(raw)) throw new Error(`FEE_PAYER_KEYPAIR_PATH "${path}" must be a JSON array of 64 bytes`);
  const secret = Uint8Array.from(raw as number[]);
  try {
    return Keypair.fromSecretKey(secret);
  } catch (e) {
    throw new Error(`FEE_PAYER_KEYPAIR_PATH "${path}" contains an invalid secret key: ${String(e)}`);
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): RelayerConfig {
  const keypairPath = required("FEE_PAYER_KEYPAIR_PATH");
  return {
    rpcUrl: env.RPC_URL ?? "http://127.0.0.1:8899",
    programId: required("PROGRAM_ID"),
    feePayer: loadKeypair(keypairPath),
    enclaveUrl: env.ENCLAVE_URL ?? "http://127.0.0.1:8443",
    // The single pinned enclave ed25519 verification key (Config.operators[0]
    // at launch). Verdict signatures are locally checked against it BEFORE
    // any transaction is sent — defense in depth on top of the on-chain check.
    operatorPubkey: required("OPERATOR_PUBKEY"),
    pollIntervalMs: intEnv("POLL_INTERVAL_MS", 10_000),
    idlPath: env.IDL_PATH ?? "target/idl/sealed_code_bounty.json",
  };
}
