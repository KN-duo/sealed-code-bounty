// Central runtime configuration. Everything overridable via Vite env vars so the
// same build points at localnet, devnet, or a hosted enclave without code changes.

export type ClusterKind = "localnet" | "devnet" | "mainnet" | "custom";

const DEFAULT_PROGRAM_ID = "FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V";
const DEFAULT_RPC_URL = "http://127.0.0.1:8899";
// In dev, enclave calls go through the Vite proxy (see vite.config.ts) so they stay
// same-origin: lib/runner.ts sends `content-type: application/json`, which triggers a
// CORS preflight, and the runner serves no OPTIONS handler. Keep in sync with
// ENCLAVE_PREFIX in vite.config.ts.
const DEV_ENCLAVE_PREFIX = "/enclave";
const DEFAULT_ENCLAVE_URL = import.meta.env.DEV ? DEV_ENCLAVE_PREFIX : "http://127.0.0.1:8443";

function readEnv(key: string): string | undefined {
  const value = import.meta.env[key as keyof ImportMetaEnv] as string | undefined;
  return value && value.length > 0 ? value : undefined;
}

export const PROGRAM_ID_STRING = readEnv("VITE_PROGRAM_ID") ?? DEFAULT_PROGRAM_ID;
export const RPC_URL = readEnv("VITE_RPC_URL") ?? DEFAULT_RPC_URL;
export const ENCLAVE_URL = (readEnv("VITE_ENCLAVE_URL") ?? DEFAULT_ENCLAVE_URL).replace(/\/$/, "");

// A relative ENCLAVE_URL is a proxy path, not an address a human can act on, so error
// messages name the real destination instead.
export const ENCLAVE_DISPLAY_URL = ENCLAVE_URL.startsWith("/")
  ? `${ENCLAVE_URL} (dev proxy → http://127.0.0.1:8443)`
  : ENCLAVE_URL;

// Cluster is inferred from the RPC url unless explicitly pinned. Purely cosmetic —
// drives the navbar badge so a user always knows which network they are on.
function inferCluster(rpc: string): ClusterKind {
  const pinned = readEnv("VITE_CLUSTER");
  if (pinned === "localnet" || pinned === "devnet" || pinned === "mainnet" || pinned === "custom") {
    return pinned;
  }
  if (rpc.includes("127.0.0.1") || rpc.includes("localhost")) return "localnet";
  if (rpc.includes("devnet")) return "devnet";
  if (rpc.includes("mainnet")) return "mainnet";
  return "custom";
}

export const CLUSTER: ClusterKind = inferCluster(RPC_URL);

export const CLUSTER_META: Record<ClusterKind, { label: string; color: string }> = {
  localnet: { label: "localnet", color: "var(--accent-green)" },
  devnet: { label: "devnet", color: "var(--accent-purple)" },
  mainnet: { label: "mainnet", color: "var(--accent-amber)" },
  custom: { label: "custom", color: "var(--text-dim)" },
};
