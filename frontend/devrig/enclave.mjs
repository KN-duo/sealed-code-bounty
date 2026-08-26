// Mock enclave: speaks the exact HTTP surface src/lib/runner.ts expects, and doubles
// as the relayer that lands the verdict on-chain.
//
// What it is NOT: it does not build or run the target environment, does not execute the
// exploit, and proves nothing. It exists so the browser can walk the real
// seal -> sign -> upload -> submit_exploit -> verdict -> decrypt path end to end.

import http from "node:http";
import { createHash } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import {
  ENCLAVE_PORT,
  MOCK_FLAG_PREFIX,
} from "./config.mjs";
import { openSealed } from "./keys.mjs";
import { accounts, bytes, connect, hex, makeProgram, resolveVerdict, statusKind } from "./chain.mjs";

const sha256 = (data) => new Uint8Array(createHash("sha256").update(data).digest());

/** Deterministic stand-in for the real enclave's flag commitment. */
export function mockFlagCommitment(bountyPda) {
  return hex(sha256(Buffer.from(MOCK_FLAG_PREFIX + bountyPda)));
}

// --- verdict policy --------------------------------------------------------

export const VERDICT_RULE =
  "PASS unless the exploit matches /broken/i or is under 20 bytes";

function decide(plaintext, force) {
  if (force === "pass") return { outcome: true, why: "--always pass" };
  if (force === "fail") return { outcome: false, why: "--always fail" };
  const text = Buffer.from(plaintext).toString("utf8");
  if (text.length < 20) return { outcome: false, why: "exploit under 20 bytes" };
  if (/broken/i.test(text)) return { outcome: false, why: "exploit matches /broken/i" };
  return { outcome: true, why: "no failure marker found" };
}

// --- HTTP ------------------------------------------------------------------

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "content-type",
};

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", ...CORS });
  res.end(payload);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 4_000_000) reject(new Error("request body too large"));
    });
    req.on("end", () => {
      try {
        resolve(raw.length ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("malformed JSON body"));
      }
    });
    req.on("error", reject);
  });
}

export async function serve({ keys, force, log = console.log }) {
  const connection = connect();
  const program = makeProgram(connection, keys.relayer);

  // bountyPda:exploitSha -> { solver, sealed }
  const pending = new Map();

  const server = http.createServer(async (req, res) => {
    if (req.method === "OPTIONS") {
      res.writeHead(204, CORS);
      return res.end();
    }
    const url = new URL(req.url, "http://localhost");
    try {
      if (req.method === "GET" && url.pathname === "/internal/healthz") {
        return send(res, 200, { ok: true, mock: true, rule: VERDICT_RULE });
      }

      if (req.method === "POST" && url.pathname === "/internal/seal_bounty") {
        const body = await readJson(req);
        const pda = String(body.bounty_pda ?? "");
        if (!pda) return send(res, 400, { error: "bounty_pda is required" });
        const flag_commitment = mockFlagCommitment(pda);
        log(`seal_bounty  ${pda} -> ${flag_commitment.slice(0, 16)}…`);
        return send(res, 200, { flag_commitment });
      }

      if (req.method === "POST" && url.pathname === "/internal/upload") {
        const body = await readJson(req);
        const pda = String(body.bounty_pda ?? "");
        const view = body.claimed_chain_view ?? {};
        const exploitSha = String(view.exploit_sha256 ?? "");
        const sealedB64 = String(body.exploit_sealed_box ?? "");
        if (!pda || !exploitSha || !sealedB64) {
          return send(res, 400, { error: "bounty_pda, claimed_chain_view and exploit_sealed_box are required" });
        }
        // The real enclave verifies submit_intent_sig here; the mock records it and
        // moves on. It cannot be forged into a PASS anyway — the on-chain solver comes
        // from the submit_exploit transaction, not from this payload.
        const sealed = new Uint8Array(Buffer.from(sealedB64, "base64"));
        pending.set(`${pda}:${exploitSha}`, { solver: String(body.solver_pubkey ?? ""), sealed });
        const blob_url = `mock://${pda}/${exploitSha.slice(0, 16)}`;
        log(`upload       ${pda} sha=${exploitSha.slice(0, 16)}… (${sealed.length} B sealed)`);
        return send(res, 200, { blob_url });
      }

      return send(res, 404, { error: `no route for ${req.method} ${url.pathname}` });
    } catch (e) {
      return send(res, 400, { error: e instanceof Error ? e.message : String(e) });
    }
  });

  // --- verdict watcher -----------------------------------------------------

  async function tick() {
    for (const [key, entry] of [...pending]) {
      const [pdaStr, exploitSha] = key.split(":");
      let bountyKey;
      try {
        bountyKey = new PublicKey(pdaStr);
      } catch {
        pending.delete(key);
        continue;
      }
      let acct;
      try {
        acct = await accounts(program).bounty.fetchNullable(bountyKey);
      } catch {
        continue; // transient RPC hiccup
      }
      if (!acct) {
        pending.delete(key);
        continue;
      }
      const status = statusKind(acct.status);
      if (status === "resolved" || status === "cancelled") {
        pending.delete(key);
        continue;
      }
      if (status !== "awaitingResolution" || !acct.currentSubmission) continue;
      if (hex(bytes(acct.currentSubmission.exploitSha256)) !== exploitSha) continue;

      const plaintext = await openSealed(entry.sealed, keys.enclaveEnc);
      if (!plaintext) {
        log(`!! could not unseal the exploit for ${pdaStr} — leaving it for force_unlock`);
        pending.delete(key);
        continue;
      }
      const { outcome, why } = decide(plaintext, force);
      log(`verdict      ${pdaStr} -> ${outcome ? "PASS" : "FAIL"} (${why})`);
      try {
        const sig = await resolveVerdict({
          connection,
          keys,
          bountyAccount: acct,
          bountyKey,
          outcome,
          plaintext,
        });
        log(`resolved     ${sig}`);
      } catch (e) {
        log(`!! resolve failed for ${pdaStr}: ${e instanceof Error ? e.message : e}`);
      }
      pending.delete(key);
    }
  }

  const timer = setInterval(() => {
    tick().catch((e) => log(`!! watcher error: ${e?.message ?? e}`));
  }, 2000);

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(ENCLAVE_PORT, "127.0.0.1", resolve);
  });

  return {
    port: ENCLAVE_PORT,
    close: () => {
      clearInterval(timer);
      server.close();
    },
  };
}
