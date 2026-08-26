#!/usr/bin/env node
// Offline self-test for the rig: everything that does NOT need a validator.
//
// Covers the parts that are silently wrong if they drift — the SCB_VERDICT_V4 wire
// length, operator signatures, the two sealed-box hops (hunter -> enclave, enclave ->
// buyer), and the HTTP surface src/lib/runner.ts calls.
//
//   node devrig/selftest.mjs

import { Keypair } from "@solana/web3.js";
import { loadOrCreateKeys, openSealed, sealTo, signDetached, sodium } from "./keys.mjs";
import { buildVerdictMessage } from "./chain.mjs";
import { VERDICT_MSG_LEN } from "./config.mjs";
import { VERDICT_RULE, mockFlagCommitment, serve } from "./enclave.mjs";

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
  if (!ok) failures++;
}

const keys = await loadOrCreateKeys();
const s = await sodium();

console.log("\n  verdict attestation");
const verdictInputs = {
  bounty: Keypair.generate().publicKey,
  envBlobSha256: new Uint8Array(32),
  exploitSha256: new Uint8Array(32),
  solver: Keypair.generate().publicKey,
  flagCommitment: new Uint8Array(32),
  buyerEncPk: new Uint8Array(32),
};
const message = buildVerdictMessage({ ...verdictInputs, outcome: true });
const failMessage = buildVerdictMessage({ ...verdictInputs, outcome: false });
check("message is the canonical length", message.length === VERDICT_MSG_LEN, `${message.length} B`);
check("message opens with the domain tag", message.subarray(0, 14).toString() === "SCB_VERDICT_V4");
check(
  "PASS and FAIL differ only in the trailing outcome byte",
  message.subarray(0, VERDICT_MSG_LEN - 1).equals(failMessage.subarray(0, VERDICT_MSG_LEN - 1)) &&
    message[VERDICT_MSG_LEN - 1] === 1 &&
    failMessage[VERDICT_MSG_LEN - 1] === 0,
);
const sig = await signDetached(message, keys.operator);
check(
  "operator signature verifies as raw ed25519",
  s.crypto_sign_verify_detached(sig, message, keys.operator.publicKey.toBytes()),
);
check(
  "a tampered message does not verify",
  !s.crypto_sign_verify_detached(sig, Buffer.concat([message.subarray(0, 206), Buffer.from([0])]), keys.operator.publicKey.toBytes()),
);

console.log("\n  sealed boxes");
const exploit = Buffer.from("#!/usr/bin/env python3\nprint('ret2win payload')\n");
const sealed = await sealTo(exploit, keys.enclaveEnc.publicKey);
const opened = await openSealed(sealed, keys.enclaveEnc);
check("enclave opens what the hunter sealed to it", Buffer.from(opened ?? []).equals(exploit));
const reveal = await sealTo(opened, keys.buyerEnc.publicKey);
const buyerSees = await openSealed(reveal, keys.buyerEnc);
check("buyer opens the reveal sealed to their key", Buffer.from(buyerSees ?? []).equals(exploit));
check("the wrong key returns null, never throws", (await openSealed(reveal, keys.enclaveEnc)) === null);

console.log("\n  http surface");
const srv = await serve({ keys, force: null, log: () => {} });
const base = `http://127.0.0.1:${srv.port}`;
const post = (path, body) =>
  fetch(base + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
try {
  const health = await (await fetch(`${base}/internal/healthz`)).json();
  check("healthz reports the mock and its rule", health.ok === true && health.rule === VERDICT_RULE);

  const pda = Keypair.generate().publicKey.toBase58();
  const sb = await (await post("/internal/seal_bounty", { bounty_pda: pda })).json();
  check(
    "seal_bounty returns a deterministic 32-byte hex commitment",
    sb.flag_commitment === mockFlagCommitment(pda) && sb.flag_commitment.length === 64,
  );
  check("seal_bounty rejects a missing bounty_pda", (await post("/internal/seal_bounty", {})).status === 400);

  const up = await (
    await post("/internal/upload", {
      bounty_pda: pda,
      claimed_chain_view: {
        env_blob_sha256: "0".repeat(64),
        buyer_enc_pk: "0".repeat(64),
        exploit_sha256: "a".repeat(64),
        flag_commitment: sb.flag_commitment,
      },
      solver_pubkey: Keypair.generate().publicKey.toBase58(),
      submit_intent_sig: "AA==",
      exploit_sealed_box: Buffer.from(sealed).toString("base64"),
    })
  ).json();
  check(
    "upload returns a blob_url inside the 200-char on-chain cap",
    typeof up.blob_url === "string" && up.blob_url.length > 0 && up.blob_url.length <= 200,
    up.blob_url,
  );
  check("upload rejects an empty body", (await post("/internal/upload", {})).status === 400);
  check("unknown routes 404", (await post("/internal/nope", {})).status === 404);
} finally {
  srv.close();
}

console.log(failures === 0 ? "\n  all checks passed\n" : `\n  ${failures} check(s) FAILED\n`);
process.exit(failures === 0 ? 0 : 1);
