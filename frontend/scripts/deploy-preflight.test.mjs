import test from "node:test";
import assert from "node:assert/strict";
import { validateDeployConfig } from "./deploy-preflight.mjs";

const valid = {
  VITE_CLUSTER: "devnet",
  VITE_PROGRAM_ID: "FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V",
  VITE_RPC_URL: "https://api.devnet.solana.com",
  VITE_ENCLAVE_URL: "/enclave",
};

test("accepts explicit public deployment configuration", () => {
  assert.deepEqual(validateDeployConfig(valid), []);
});

test("rejects absent configuration and the localnet defaults", () => {
  const problems = validateDeployConfig({
    VITE_RPC_URL: "http://127.0.0.1:8899",
    VITE_ENCLAVE_URL: "/enclave",
  });
  assert.ok(problems.some((p) => p.includes("VITE_CLUSTER")));
  assert.ok(problems.some((p) => p.includes("VITE_PROGRAM_ID")));
  assert.ok(problems.some((p) => p.includes("HTTPS")));
  assert.ok(problems.some((p) => p.includes("loopback")));
});

test("rejects malformed program IDs and unencrypted service URLs", () => {
  const problems = validateDeployConfig({
    ...valid,
    VITE_PROGRAM_ID: "not-a-solana-key",
    VITE_ENCLAVE_URL: "http://verifier.example.test",
  });
  assert.ok(problems.some((p) => p.includes("valid Solana public key")));
  assert.ok(problems.some((p) => p.includes("absolute VITE_ENCLAVE_URL must use HTTPS")));
});

test("rejects protocol-relative proxy URLs and credential-bearing endpoints", () => {
  const problems = validateDeployConfig({
    ...valid,
    VITE_RPC_URL: "https://user:password@rpc.example.test",
    VITE_ENCLAVE_URL: "//attacker.example.test/enclave",
  });
  assert.ok(problems.some((p) => p.includes("must not embed credentials")));
  assert.ok(problems.some((p) => p.includes("protocol-relative URL")));
});
