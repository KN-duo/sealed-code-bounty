// Shared configuration for the local test rig.
//
// The rig is DEV-ONLY scaffolding: it stands up a fake enclave so the browser can
// exercise the real seal -> sign -> upload -> submit_exploit -> verdict -> decrypt
// path without Docker or a TEE. Nothing here ships to production.

import { fileURLToPath } from "node:url";
import path from "node:path";

export const DEVRIG_DIR = path.dirname(fileURLToPath(import.meta.url));
export const FRONTEND_DIR = path.resolve(DEVRIG_DIR, "..");
export const REPO_DIR = path.resolve(FRONTEND_DIR, "..");

export const KEYS_PATH = path.join(DEVRIG_DIR, "rig.local.json");
export const IDL_PATH = path.join(FRONTEND_DIR, "src", "idl", "sealed_code_bounty.json");
export const ENV_LOCAL_PATH = path.join(FRONTEND_DIR, ".env.local");

// Must match src/env.ts defaults; override with the same VITE_* vars the app reads.
export const RPC_URL = process.env.VITE_RPC_URL ?? "http://127.0.0.1:8899";
export const PROGRAM_ID = process.env.VITE_PROGRAM_ID ?? "FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V";

// The port vite.config.ts proxies /enclave to.
export const ENCLAVE_PORT = Number(process.env.SCB_MOCK_PORT ?? 8443);

export const LAMPORTS_PER_SOL = 1_000_000_000;
export const BOND_LAMPORTS = 0.05 * LAMPORTS_PER_SOL;
export const DEFAULT_PRIZE_LAMPORTS = 2 * LAMPORTS_PER_SOL;
export const FORCE_UNLOCK_DELAY_S = 3600;

// programs/sealed-code-bounty/src/constants.rs
export const VERDICT_DOMAIN_TAG = "SCB_VERDICT_V4";
export const VERDICT_MSG_LEN = 207;
export const MAX_CIPHERTEXT_LEN = 9_700;

// Deterministic stand-in for the enclave's real flag commitment, so `seed` and the
// mock server derive the same value with no shared state.
export const MOCK_FLAG_PREFIX = "scb-mock-flag";
