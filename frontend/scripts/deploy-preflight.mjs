import { pathToFileURL } from "node:url";
import { loadEnv } from "vite";
import { PublicKey } from "@solana/web3.js";

const LOOPBACK_HOST = /^(localhost|.*\.localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|::1|\[::1\])$/i;

function isLoopbackUrl(value) {
  try {
    return LOOPBACK_HOST.test(new URL(value).hostname);
  } catch {
    return false;
  }
}

function validateDeployConfig(env) {
  const problems = [];
  const cluster = env.VITE_CLUSTER?.trim();
  if (cluster !== "devnet" && cluster !== "mainnet") {
    problems.push("VITE_CLUSTER must be explicitly set to devnet or mainnet.");
  }

  const programId = env.VITE_PROGRAM_ID?.trim();
  if (!programId) {
    problems.push("VITE_PROGRAM_ID must name the program deployed to that cluster.");
  } else {
    try {
      if (new PublicKey(programId).toBase58() !== programId) {
        problems.push("VITE_PROGRAM_ID must be a canonical Solana public key.");
      }
    } catch {
      problems.push("VITE_PROGRAM_ID must be a valid Solana public key.");
    }
  }

  const rpcUrl = env.VITE_RPC_URL?.trim();
  if (!rpcUrl) {
    problems.push("VITE_RPC_URL must be explicitly set to the selected cluster's HTTPS RPC.");
  } else {
    try {
      const parsed = new URL(rpcUrl);
      if (parsed.protocol !== "https:") {
        problems.push("VITE_RPC_URL must use HTTPS in a public build.");
      }
      if (LOOPBACK_HOST.test(parsed.hostname)) {
        problems.push("VITE_RPC_URL must not point to localhost or a loopback address.");
      }
      if (parsed.username || parsed.password) {
        problems.push("VITE_RPC_URL must not embed credentials.");
      }
    } catch {
      problems.push("VITE_RPC_URL must be a valid absolute HTTPS URL.");
    }
  }

  const enclaveUrl = env.VITE_ENCLAVE_URL?.trim();
  if (!enclaveUrl) {
    problems.push("VITE_ENCLAVE_URL must explicitly name the authenticated verifier route.");
  } else if (enclaveUrl.startsWith("/")) {
    if (enclaveUrl.startsWith("//") || enclaveUrl.includes("\\")) {
      problems.push("VITE_ENCLAVE_URL must be a same-origin path such as /enclave, not a protocol-relative URL.");
    }
  } else {
    try {
      const parsed = new URL(enclaveUrl);
      if (parsed.protocol !== "https:") {
        problems.push("An absolute VITE_ENCLAVE_URL must use HTTPS.");
      }
      if (LOOPBACK_HOST.test(parsed.hostname)) {
        problems.push("VITE_ENCLAVE_URL must not point to localhost or a loopback address.");
      }
      if (parsed.username || parsed.password) {
        problems.push("VITE_ENCLAVE_URL must not embed credentials.");
      }
    } catch {
      problems.push("VITE_ENCLAVE_URL must be an HTTPS URL or same-origin path such as /enclave.");
    }
  }

  return problems;
}

function runPreflight() {
  const env = loadEnv("production", process.cwd(), "");
  const problems = validateDeployConfig(env);
  if (problems.length > 0) {
    console.error("Production frontend build blocked by deployment preflight:");
    for (const problem of problems) console.error(`- ${problem}`);
    console.error("\nThis checks configuration shape only; it does not prove the RPC, API, program, or TEE is live.");
    process.exitCode = 1;
    return;
  }

  console.log("Production frontend configuration shape is valid.");
  console.warn("Confirm the program/RPC match and that /enclave terminates authenticated HTTPS at the reviewed verifier before publishing.");
  console.warn("All VITE_* values are public in the browser bundle; do not put secrets in them.");
}

export { isLoopbackUrl, validateDeployConfig };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runPreflight();
}
