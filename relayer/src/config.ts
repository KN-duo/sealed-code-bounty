import { Keypair } from "@solana/web3.js";
import * as fs from "fs";

export interface RelayerConfig {
  rpcUrl: string;
  programId: string;
  feePayer: Keypair;
  enclaveUrl: string;
  operatorPubkey: string;
  pollIntervalMs: number;
  reconcileIntervalMs: number;
  idlPath: string;
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name];
  if (!v || v.trim() === "") {
    throw new Error(
      `Missing required env var ${name}. Required: PROGRAM_ID, FEE_PAYER_KEYPAIR_PATH, OPERATOR_PUBKEY. Optional: RPC_URL, ENCLAVE_URL, POLL_INTERVAL_MS, RECONCILE_INTERVAL_MS, IDL_PATH.`
    );
  }
  return v.trim();
}

function intEnv(env: NodeJS.ProcessEnv, name: string, dflt: number): number {
  const v = env[name];
  if (v === undefined || v === "") return dflt;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 1000 || n > 300_000) {
    throw new Error(`${name} must be an integer between 1000 and 300000 milliseconds`);
  }
  return n;
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
  const keypairPath = required(env, "FEE_PAYER_KEYPAIR_PATH");
  return {
    rpcUrl: env.RPC_URL ?? "http://127.0.0.1:8899",
    programId: required(env, "PROGRAM_ID"),
    feePayer: loadKeypair(keypairPath),
    enclaveUrl: env.ENCLAVE_URL ?? "http://127.0.0.1:8443",
    // The single pinned enclave ed25519 verification key (Config.operators[0]
    // at launch). Verdict signatures are locally checked against it BEFORE
    // any transaction is sent — defense in depth on top of the on-chain check.
    operatorPubkey: required(env, "OPERATOR_PUBKEY"),
    pollIntervalMs: intEnv(env, "POLL_INTERVAL_MS", 10_000),
    reconcileIntervalMs: intEnv(env, "RECONCILE_INTERVAL_MS", 30_000),
    idlPath: env.IDL_PATH ?? "target/idl/sealed_code_bounty.json",
  };
}
