// Minimal stand-in for the verifier enclave's /internal/verify endpoint.
// TEST HARNESS ONLY: signs canned SCB_VERDICT_V4 verdicts with a throwaway
// keypair so the relayer pipeline can be exercised end-to-end without a TEE.
//
// Usage (programmatic, CommonJS):
//   const { startMockEnclave } = require("./mock-enclave.cjs");
//   const h = await startMockEnclave({ tamper: false }); // h.url/.pubkeyB58/.close()
// Standalone:
//   PORT=8443 node test/mock-enclave.cjs

const http = require("node:http");
const { Keypair } = require("@solana/web3.js");
const nacl = require("tweetnacl");

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58encode(bytes) {
  let n = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

function b58decode(s) {
  let n = 0n;
  for (const ch of s) {
    const idx = B58.indexOf(ch);
    if (idx < 0) throw new Error(`bad base58 char ${ch}`);
    n = n * 58n + BigInt(idx);
  }
  return Buffer.from(n.toString(16).padStart(64, "0"), "hex");
}

function buildMessage(bountyPdaB58, envHex, exploitHex, solverB58, flagHex, buyerPkHex, outcome) {
  return Buffer.concat([
    Buffer.from("SCB_VERDICT_V4", "ascii"),
    b58decode(bountyPdaB58),
    Buffer.from(envHex, "hex"),
    Buffer.from(exploitHex, "hex"),
    b58decode(solverB58),
    Buffer.from(flagHex, "hex"),
    Buffer.from(buyerPkHex, "hex"),
    Buffer.from([outcome ? 1 : 0]),
  ]);
}

function makeHandler(kp, tamper) {
  return (req, res) => {
    if (req.method === "GET" && req.url === "/internal/operator-pubkey") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ pubkey: kp.publicKey.toBase58() }));
      return;
    }
    if (req.method === "POST" && req.url === "/internal/verify") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const rb = JSON.parse(body);
        const cv = rb.claimed_chain_view ?? {};
        const outcome = true;
        const msg = buildMessage(
          rb.bounty_pda,
          cv.env_blob_sha256,
          cv.exploit_sha256,
          rb.solver_pubkey,
          cv.flag_commitment,
          cv.buyer_enc_pk,
          outcome
        );
        const sig = Buffer.from(nacl.sign.detached(new Uint8Array(msg), kp.secretKey));
        if (tamper) sig[0] ^= 0xff;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            outcome,
            sig: sig.toString("base64"),
            reveal_ciphertext: Buffer.from("mock-sealed-box-ciphertext").toString("base64"),
            redacted_log: "",
          })
        );
      });
      return;
    }
    res.writeHead(404);
    res.end();
  };
}

function startMockEnclave(opts = {}) {
  const tamper = Boolean(opts.tamper);
  const kp = Keypair.generate();
  return new Promise((resolve) => {
    const server = http.createServer(makeHandler(kp, tamper));
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        pubkeyB58: kp.publicKey.toBase58(),
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

module.exports = { startMockEnclave };

if (require.main === module) {
  // [PRE-TEE] Standalone e2e mode: emulates the FULL /internal/* surface so
  // localnet rehearsals can run before the real enclave exists.
  // Deviations from the real enclave (marked again at each site):
  //  * operator keypair loaded from a plain JSON file (no KMS/attestation)
  //  * flag_commitment derived as sha256(pda + "|mock") instead of HKDF(M,pda)
  //  * exploit_sealed_box is treated as PLAINTEXT: verify() re-seals it to the
  //    buyer pk so buyers can decrypt; the real enclave unseals the hunter
  //    box and re-seals inside the TEE.
  //  * SCB_MOCK_FORCE_FAIL=1 makes every verdict FAIL (negative rehearsal).
  const http = require("node:http");
  const sodium = require("libsodium-wrappers");
  const sodiumReady = sodium.ready;
  const crypto = require("node:crypto");
  const { Keypair } = require("@solana/web3.js");
  const nacl = require("tweetnacl");

  const port = Number(process.env.PORT ?? 8443);
  const forceFail = process.env.SCB_MOCK_FORCE_FAIL === "1";

  // Operator identity: either a solana-keygen JSON file (64-byte secret) or
  // a freshly generated throwaway key.
  let secret64;
  const kpFile = process.env.SCB_MOCK_OPERATOR_KEYPAIR;
  if (kpFile) {
    secret64 = Uint8Array.from(JSON.parse(require("fs").readFileSync(kpFile, "utf8")));
  } else {
    secret64 = nacl.sign.keyPair().secretKey;
  }
  const operatorPubB58 = Keypair.fromSecretKey(secret64).publicKey.toBase58();

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

  const commitments = new Map(); // bounty_pda_b58 -> commitment hex
  const uploads = new Map();     // bounty_pda_b58 -> {plaintext: Buffer, chain_view}

  function buildMessage(pdaB58, envHex, exploitHex, solverB58, flagHex, buyerPkHex, outcome) {
    return Buffer.concat([
      Buffer.from("SCB_VERDICT_V4", "ascii"),
      b58decode(pdaB58),
      Buffer.from(envHex, "hex"),
      Buffer.from(exploitHex, "hex"),
      b58decode(solverB58),
      Buffer.from(flagHex, "hex"),
      Buffer.from(buyerPkHex, "hex"),
      Buffer.from([outcome ? 1 : 0]),
    ]);
  }

  const server = http.createServer((req, res) => {
    const respond = (code, obj) => {
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    const readBody = (cb) => {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => cb(JSON.parse(b || "{}")));
    };

    if (req.method === "GET" && req.url === "/internal/operator-pubkey") {
      return respond(200, { pubkey: operatorPubB58 });
    }

    if (req.method === "POST" && req.url === "/internal/seal_bounty") {
      return readBody(({ bounty_pda }) => {
        // [PRE-TEE] real enclave derives sha256(HKDF-flag); mock derives a
        // stable pseudo-commitment so create_bounty can pin something.
        const c = crypto.createHash("sha256").update(bounty_pda + "|mock").digest("hex");
        commitments.set(bounty_pda, c);
        respond(200, { flag_commitment: c });
      });
    }

    if (req.method === "POST" && req.url === "/internal/upload") {
      return readBody((body) => {
        // [PRE-TEE] stores the payload verbatim; treated as plaintext below.
        uploads.set(body.bounty_pda, {
          plaintext: Buffer.from(body.exploit_sealed_box, "base64"),
          chain_view: body.claimed_chain_view,
          solver_pubkey: body.solver_pubkey,
          created_at: Date.now(),
        });
        const receipt = crypto.createHash("sha256")
          .update(Buffer.concat([Buffer.from(body.exploit_sealed_box, "base64"), Buffer.from(body.bounty_pda)]))
          .digest("hex");
        respond(200, { receipt });
      });
    }

    if (req.method === "POST" && req.url === "/internal/verify") {
      return readBody(async ({ bounty_pda, claimed_chain_view }) => {
        try {
        const rec = uploads.get(bounty_pda);
        if (!rec) return respond(404, { error: "no pending upload for this bounty" });

        // Divergence check: claim must equal stored values (R1 seam).
        const cv = claimed_chain_view;
        const st = rec.chain_view;
        const differs =
          cv.env_blob_sha256 !== st.env_blob_sha256 ||
          cv.buyer_enc_pk !== st.buyer_enc_pk ||
          cv.flag_commitment !== st.flag_commitment ||
          cv.exploit_sha256 !== st.exploit_sha256;
        if (differs) return respond(409, { error: "chain_view_divergence" });

        const flagCommitment = commitments.get(bounty_pda) ?? st.flag_commitment;
        const outcome = !forceFail;
        const msg = buildMessage(
          bounty_pda,
          st.env_blob_sha256,
          st.exploit_sha256,
          rec.solver_pubkey,
          flagCommitment,
          st.buyer_enc_pk,
          outcome
        );
        const sig = Buffer.from(nacl.sign.detached(new Uint8Array(msg), secret64));

        const payload = { outcome, sig: sig.toString("base64"), redacted_log: "" };
        if (outcome) {
          await sodium.ready;
          // [PRE-TEE] re-seal stored plaintext to the buyer pk. Real enclave
          // unseals the hunter box (inside TEE) and re-seals with the same
          // external effect.
          const { PublicKey } = require("@solana/web3.js");
          void PublicKey;
          const buyerPkBytes = Buffer.from(st.buyer_enc_pk, "hex");
          const sealedToBuyer = sodium.crypto_box_seal(new Uint8Array(rec.plaintext), new Uint8Array(buyerPkBytes));
          payload.reveal_ciphertext = Buffer.from(sealedToBuyer).toString("base64");
        }
        respond(200, payload);
        } catch (e) {
          respond(500, { error: String((e && e.message) || e) });
        }
      });
    }

    respond(404, {});
  });

  process.on("uncaughtException", (e) => console.error(JSON.stringify({ scope:"mock-enclave", level:"error", msg:String(e) })));
  server.listen(port, "127.0.0.1", () => {
    console.log(JSON.stringify({
      ts: new Date().toISOString(), level: "info", scope: "mock-enclave",
      msg: "listening", url: `http://127.0.0.1:${port}`,
      operator: operatorPubB58, forceFail,
    }));
  });
}
