// Minimal stand-in for the verifier enclave's /internal/verify endpoint.
// TEST HARNESS ONLY: signs canned SCB_VERDICT_V3 verdicts with a throwaway
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

function buildMessage(bountyPdaB58, envHex, exploitHex, solverB58, flagHex, outcome) {
  return Buffer.concat([
    Buffer.from("SCB_VERDICT_V3", "ascii"),
    b58decode(bountyPdaB58),
    Buffer.from(envHex, "hex"),
    Buffer.from(exploitHex, "hex"),
    b58decode(solverB58),
    Buffer.from(flagHex, "hex"),
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
  const port = Number(process.env.PORT ?? 8443);
  const kp = Keypair.generate();
  http
    .createServer(makeHandler(kp, false))
    .listen(port, "127.0.0.1", () => {
      console.log(
        JSON.stringify({
          ts: new Date().toISOString(),
          level: "info",
          scope: "mock-enclave",
          msg: "listening",
          url: `http://127.0.0.1:${port}`,
          operator: kp.publicKey.toBase58(),
        })
      );
    });
}
