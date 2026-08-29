// Real-execution enclave (pre-TEE).
//
// Exposes the exact /internal/* HTTP surface the relayer and the e2e harness
// already speak to the mock — but the verdict is REAL: the enclave unseals the
// hunter's exploit (only it can), runs it in a hidden Docker sandbox against the
// bounty's target, and decides PASS/FAIL by whether the exploit captured the
// bounty's secret flag. On PASS it re-seals the exploit to the buyer's key so the
// buyer receives it as part of the paying transaction. Verdict signing and buyer
// re-sealing mirror relayer/test/mock-enclave.cjs byte-for-byte, so the on-chain
// program accepts these verdicts unchanged.
//
// This is the pre-TEE stand-in. Moving to the real TEE later means running this
// same logic inside a Nitro Enclave with an in-enclave key — the wire surface and
// the crypto are identical.
//
// Run (on a Docker host, after enclave-exec/build.sh):
//   SCB_MASTER_SECRET_HEX=$(openssl rand -hex 32) \
//   SCB_ENCLAVE_ENC_SECRET_HEX=$(openssl rand -hex 32) \
//   SCB_OPERATOR_KEYPAIR=/path/to/operator.json \
//   PORT=8443 node enclave-exec/enclave.cjs
//
// Endpoints:
//   GET  /internal/operator-pubkey  -> { pubkey }         (base58, arm on-chain)
//   GET  /internal/enclave-pubkey   -> { enclave_enc_pk } (hex X25519; config + sealing)
//   POST /internal/seal_bounty      -> { flag_commitment } (derive per-bounty flag)
//   POST /internal/upload           -> { receipt }         (unseal + store exploit)
//   POST /internal/verify           -> { outcome, sig, reveal_ciphertext? }

const http = require("node:http");
const crypto = require("node:crypto");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

// --- resolve heavy deps from wherever they're installed --------------------
const DEP_BASES = [
  path.join(__dirname, "..", "relayer", "node_modules"),
  path.join(__dirname, "..", "cli", "node_modules"),
  path.join(__dirname, "..", "frontend", "node_modules"),
];
function loadDep(name) {
  for (const base of DEP_BASES) {
    try {
      return require(path.join(base, name));
    } catch {
      /* try next */
    }
  }
  throw new Error(
    `could not load "${name}" — run npm install in relayer/ (or cli/, frontend/) first`,
  );
}
const nacl = loadDep("tweetnacl");
const sodium = loadDep("libsodium-wrappers");
const { Keypair } = loadDep("@solana/web3.js");

// --- config ----------------------------------------------------------------
const PORT = Number(process.env.PORT ?? 8443);
const MASTER = hexToBytes(reqEnv("SCB_MASTER_SECRET_HEX", 64));
const ENC_SECRET = hexToBytes(reqEnv("SCB_ENCLAVE_ENC_SECRET_HEX", 64));

let operatorSecret64;
const kpFile = process.env.SCB_OPERATOR_KEYPAIR;
if (kpFile) {
  operatorSecret64 = Uint8Array.from(JSON.parse(require("node:fs").readFileSync(kpFile, "utf8")));
} else {
  operatorSecret64 = nacl.sign.keyPair().secretKey;
}
const operatorPubB58 = Keypair.fromSecretKey(operatorSecret64).publicKey.toBase58();

function reqEnv(name, hexLen) {
  const v = process.env[name];
  if (!v || v.length !== hexLen || !/^[0-9a-fA-F]+$/.test(v)) {
    throw new Error(`${name} must be ${hexLen} hex chars (${hexLen / 2} bytes)`);
  }
  return v;
}
function hexToBytes(h) {
  return Uint8Array.from(Buffer.from(h, "hex"));
}

// --- base58 (mirrors mock-enclave.cjs) -------------------------------------
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(s) {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new Error("bad base58 char " + ch);
    n = n * 58n + BigInt(i);
  }
  return Buffer.from(n.toString(16).padStart(64, "0"), "hex");
}

// --- flag derivation --------------------------------------------------------
// The bounty's secret flag is deterministic from the master secret and the
// bounty PDA, so seal_bounty (which pins the commitment on-chain) and verify
// (which injects the flag and checks capture) always agree. The flag string
// itself never goes on-chain or into a signed message — only its commitment.
function deriveFlag(pdaB58) {
  const h = crypto.createHmac("sha256", Buffer.from(MASTER)).update(pdaB58).digest("hex");
  return `flag{scb_${h.slice(0, 32)}}`;
}
function flagCommitment(flagString) {
  return crypto.createHash("sha256").update(flagString).digest("hex");
}

// --- verdict message (mirrors mock-enclave.cjs / SCB_VERDICT_V4) -----------
function buildMessage(pdaB58, envHex, exploitHex, solverB58, commitHex, buyerPkHex, outcome) {
  return Buffer.concat([
    Buffer.from("SCB_VERDICT_V4", "ascii"),
    b58decode(pdaB58),
    Buffer.from(envHex, "hex"),
    Buffer.from(exploitHex, "hex"),
    b58decode(solverB58),
    Buffer.from(commitHex, "hex"),
    Buffer.from(buyerPkHex, "hex"),
    Buffer.from([outcome ? 1 : 0]),
  ]);
}

// --- state ------------------------------------------------------------------
const flags = new Map();        // pda -> flag string (secret, never leaves)
const commitments = new Map();  // pda -> commitment hex (public)
const uploads = new Map();      // pda -> { exploit: Buffer, chain_view, solver_pubkey }

// judge() is ESM; load it once.
let judgeFn = null;
async function getJudge() {
  if (!judgeFn) {
    const mod = await import(pathToFileURL(path.join(__dirname, "execute.mjs")).href);
    judgeFn = mod.judge;
  }
  return judgeFn;
}

// --- server -----------------------------------------------------------------
const server = http.createServer((req, res) => {
  const respond = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  const readBody = (cb) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      try {
        cb(JSON.parse(b || "{}"));
      } catch (e) {
        respond(400, { error: "bad json: " + String(e && e.message) });
      }
    });
  };

  if (req.method === "GET" && req.url === "/internal/operator-pubkey") {
    return respond(200, { pubkey: operatorPubB58 });
  }
  if (req.method === "GET" && req.url === "/internal/enclave-pubkey") {
    const pk = sodium.crypto_scalarmult_base(new Uint8Array(ENC_SECRET));
    return respond(200, { enclave_enc_pk: Buffer.from(pk).toString("hex") });
  }
  if (req.method === "GET" && req.url === "/internal/healthz") {
    return respond(200, { ok: true, real_execution: true, operator: operatorPubB58 });
  }

  if (req.method === "POST" && req.url === "/internal/seal_bounty") {
    return readBody(({ bounty_pda }) => {
      if (!bounty_pda) return respond(400, { error: "bounty_pda required" });
      const flag = deriveFlag(bounty_pda);
      const commit = flagCommitment(flag);
      flags.set(bounty_pda, flag);
      commitments.set(bounty_pda, commit);
      respond(200, { flag_commitment: commit });
    });
  }

  if (req.method === "POST" && req.url === "/internal/upload") {
    return readBody(async (body) => {
      try {
        await sodium.ready;
        const sealed = new Uint8Array(Buffer.from(body.exploit_sealed_box, "base64"));
        const encPk = sodium.crypto_scalarmult_base(new Uint8Array(ENC_SECRET));
        // Only this enclave can open the box — this is the confidentiality core.
        const opened = sodium.crypto_box_seal_open(sealed, encPk, new Uint8Array(ENC_SECRET));
        if (!opened) return respond(400, { error: "exploit does not decrypt under the enclave key" });
        const exploit = Buffer.from(opened);

        // Integrity: the unsealed exploit must match the on-chain sha256.
        const sha = crypto.createHash("sha256").update(exploit).digest("hex");
        if (body.claimed_chain_view && body.claimed_chain_view.exploit_sha256 &&
            body.claimed_chain_view.exploit_sha256 !== sha) {
          return respond(409, { error: "exploit_sha256 divergence" });
        }

        uploads.set(body.bounty_pda, {
          exploit,
          chain_view: body.claimed_chain_view,
          solver_pubkey: body.solver_pubkey,
          created_at: Date.now(),
        });
        const receipt = crypto.createHash("sha256")
          .update(Buffer.concat([exploit, Buffer.from(String(body.bounty_pda))]))
          .digest("hex");
        respond(200, { receipt });
      } catch (e) {
        respond(500, { error: String((e && e.message) || e) });
      }
    });
  }

  if (req.method === "POST" && req.url === "/internal/verify") {
    return readBody(async ({ bounty_pda, claimed_chain_view }) => {
      try {
        const rec = uploads.get(bounty_pda);
        if (!rec) return respond(404, { error: "no pending upload for this bounty" });

        // Divergence check (mirrors the mock / runner R1 seam).
        const cv = claimed_chain_view || {};
        const st = rec.chain_view || {};
        if (
          cv.env_blob_sha256 !== st.env_blob_sha256 ||
          cv.buyer_enc_pk !== st.buyer_enc_pk ||
          cv.flag_commitment !== st.flag_commitment ||
          cv.exploit_sha256 !== st.exploit_sha256
        ) {
          return respond(409, { error: "chain_view_divergence" });
        }

        const flag = flags.get(bounty_pda);
        if (!flag) return respond(409, { error: "bounty was not sealed by this enclave" });
        const commit = commitments.get(bounty_pda) ?? st.flag_commitment;

        // === REAL EXECUTION: run the exploit against the target, in Docker. ===
        const judge = await getJudge();
        const result = await judge(rec.exploit, { flag });
        const outcome = result.pass;
        log("verdict", { bounty: bounty_pda, outcome, reason: result.reason });

        const msg = buildMessage(
          bounty_pda,
          st.env_blob_sha256,
          st.exploit_sha256,
          rec.solver_pubkey,
          commit,
          st.buyer_enc_pk,
          outcome,
        );
        const sig = Buffer.from(nacl.sign.detached(new Uint8Array(msg), operatorSecret64));

        // redacted_log must never contain the flag.
        const payload = {
          outcome,
          sig: sig.toString("base64"),
          redacted_log: outcome ? "exploit captured the flag" : `no capture: ${result.reason}`,
        };

        if (outcome) {
          await sodium.ready;
          const buyerPk = new Uint8Array(Buffer.from(st.buyer_enc_pk, "hex"));
          const sealedToBuyer = sodium.crypto_box_seal(new Uint8Array(rec.exploit), buyerPk);
          payload.reveal_ciphertext = Buffer.from(sealedToBuyer).toString("base64");
          // Keep the upload: the relayer may retry verify (e.g. after a transient
          // send failure), and a deleted upload would 404 the retry. A real TTL
          // sweeper reclaims it later.
        }
        respond(200, payload);
      } catch (e) {
        respond(500, { error: String((e && e.message) || e) });
      }
    });
  }

  respond(404, {});
});

function log(msg, extra) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), scope: "enclave-exec", msg, ...extra }));
}

process.on("uncaughtException", (e) =>
  console.error(JSON.stringify({ scope: "enclave-exec", level: "error", msg: String(e) })));

sodium.ready.then(() => {
  server.listen(PORT, "127.0.0.1", () => {
    const encPk = sodium.crypto_scalarmult_base(new Uint8Array(ENC_SECRET));
    log("listening", {
      url: `http://127.0.0.1:${PORT}`,
      operator: operatorPubB58,
      enclave_enc_pk: Buffer.from(encPk).toString("hex"),
      real_execution: true,
    });
    console.error("\n  REAL-EXECUTION enclave: verdicts come from actually running the exploit in Docker.");
    console.error("  Requires scb-target + scb-runtime images (enclave-exec/build.sh).\n");
  });
});
