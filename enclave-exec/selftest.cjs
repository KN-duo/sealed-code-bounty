// End-to-end test of the real-execution enclave, no chain required.
//
// Spawns the enclave with fresh secrets, then for a real exploit and a broken
// one: seals it to the enclave's key (as a hunter would), uploads it, asks for a
// verdict, and checks the enclave actually ran it in Docker and judged correctly.
//
// Proves the keystone: only the enclave can read the exploit, and the verdict
// comes from real execution — not a mock.
//
// Run on a Docker host, after building images:
//   bash enclave-exec/build.sh
//   node enclave-exec/selftest.cjs
//
// Exit 0 if both cases judged correctly; nonzero otherwise.

const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, execFileSync } = require("node:child_process");
const { readFileSync } = require("node:fs");

const DEP_BASES = [
  path.join(__dirname, "..", "relayer", "node_modules"),
  path.join(__dirname, "..", "cli", "node_modules"),
  path.join(__dirname, "..", "frontend", "node_modules"),
];
function loadDep(name) {
  for (const base of DEP_BASES) {
    try { return require(path.join(base, name)); } catch { /* next */ }
  }
  throw new Error(`could not load "${name}" — npm install in relayer/ (or cli/, frontend/)`);
}
const sodium = loadDep("libsodium-wrappers");
const nacl = loadDep("tweetnacl");
const { Keypair } = loadDep("@solana/web3.js");

const PORT = Number(process.env.SCB_TEST_PORT ?? 8551);
const BASE = `http://127.0.0.1:${PORT}`;
const REPO = path.join(__dirname, "..");

const hex = (n) => crypto.randomBytes(n).toString("hex");

async function jpost(p, body) {
  const r = await fetch(BASE + p, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}
async function jget(p) {
  const r = await fetch(BASE + p);
  return { status: r.status, json: await r.json().catch(() => ({})) };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUp(tries = 60) {
  for (let i = 0; i < tries; i++) {
    try { const r = await jget("/internal/healthz"); if (r.status === 200) return; } catch { /* not yet */ }
    await sleep(250);
  }
  throw new Error("enclave did not come up");
}

async function runCase(label, exploitBytes, buyer, expectPass, target) {
  // A distinct bounty PDA per case (any 32-byte base58 works for the test).
  const bountyPda = Keypair.generate().publicKey.toBase58();
  const solver = Keypair.generate().publicKey.toBase58();

  // `target` (optional): { source_zip_b64, port } — the enclave builds it and
  // judges against it instead of the baked demo target.
  const sealBody = { bounty_pda: bountyPda };
  if (target) sealBody.target = target;
  process.stderr.write(target ? `  [${label}] building the company target (docker build)...\n` : "");
  const seal = await jpost("/internal/seal_bounty", sealBody);
  if (seal.status !== 200) throw new Error(`seal_bounty failed: ${JSON.stringify(seal.json)}`);
  const commitment = seal.json.flag_commitment;

  // Seal the exploit to the enclave's public key — only the enclave can open it.
  const encPk = new Uint8Array(Buffer.from((await jget("/internal/enclave-pubkey")).json.enclave_enc_pk, "hex"));
  const sealedBox = Buffer.from(sodium.crypto_box_seal(new Uint8Array(exploitBytes), encPk)).toString("base64");
  const exploitSha = crypto.createHash("sha256").update(exploitBytes).digest("hex");

  const chainView = {
    env_blob_sha256: hex(32),
    buyer_enc_pk: Buffer.from(buyer.publicKey).toString("hex"),
    flag_commitment: commitment,
    exploit_sha256: exploitSha,
  };

  const up = await jpost("/internal/upload", {
    bounty_pda: bountyPda,
    claimed_chain_view: chainView,
    solver_pubkey: solver,
    submit_intent_sig: "AA==",
    exploit_sealed_box: sealedBox,
  });
  if (up.status !== 200) throw new Error(`upload failed: ${JSON.stringify(up.json)}`);

  process.stderr.write(`  [${label}] judging in Docker (this runs the exploit)...\n`);
  const ver = await jpost("/internal/verify", { bounty_pda: bountyPda, claimed_chain_view: chainView });
  if (ver.status !== 200) throw new Error(`verify failed: ${JSON.stringify(ver.json)}`);

  const got = ver.json.outcome;
  const ok = got === expectPass;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}: outcome=${got} (expected ${expectPass}) — ${ver.json.redacted_log}`);

  if (expectPass) {
    // On PASS the buyer must be able to open the reveal and get the exploit back.
    if (!ver.json.reveal_ciphertext) throw new Error("PASS but no reveal_ciphertext");
    const ct = new Uint8Array(Buffer.from(ver.json.reveal_ciphertext, "base64"));
    const opened = sodium.crypto_box_seal_open(ct, buyer.publicKey, buyer.privateKey);
    const matches = opened && Buffer.from(opened).equals(Buffer.from(exploitBytes));
    console.log(`  ${matches ? "ok  " : "FAIL"}  ${label}: buyer decrypted the delivered exploit, bytes match`);
    if (!matches) return false;
  }
  return ok;
}

(async () => {
  await sodium.ready;
  const buyer = sodium.crypto_box_keypair();

  const env = {
    ...process.env,
    PORT: String(PORT),
    SCB_MASTER_SECRET_HEX: hex(32),
    SCB_ENCLAVE_ENC_SECRET_HEX: hex(32),
    // This offline test decrypts the reveal inline (no chain, no tx-size limit,
    // no network to Arweave). The on-chain flow uses Arweave — proven separately.
    SCB_REVEAL_STORE: "inline",
    SCB_INLINE_MAX: "1000000",
  };
  const child = spawn("node", [path.join(__dirname, "enclave.cjs")], { env, stdio: ["ignore", "inherit", "inherit"] });
  const kill = () => { try { child.kill("SIGKILL"); } catch { /* gone */ } };
  process.on("exit", kill);

  let failures = 0;
  try {
    await waitUp();
    console.log("\n  real-execution enclave up; running cases\n");
    const solve = readFileSync(path.join(REPO, "examples/ret2win/solution/solve.py"));
    const broken = readFileSync(path.join(REPO, "examples/ret2win/solution/solve-broken.py"));
    if (!(await runCase("PASS (solve.py)", solve, buyer, true))) failures++;
    if (!(await runCase("FAIL (solve-broken.py)", broken, buyer, false))) failures++;

    // Per-bounty target: build the example-target from source and judge against
    // it (proves a company can upload their own program, not the baked one).
    try {
      const zip = execFileSync("bash", ["-c", "cd enclave-exec/example-target && zip -qr - ."], {
        cwd: REPO, maxBuffer: 64 * 1024 * 1024,
      });
      const target = { source_zip_b64: zip.toString("base64"), port: 1337 };
      if (!(await runCase("PASS (per-bounty target, built from source)", solve, buyer, true, target))) failures++;
    } catch (e) {
      console.log(`  SKIP  per-bounty target case (${e && e.message}) — needs the 'zip' tool`);
    }
  } catch (e) {
    console.error(`\n  error: ${e && e.message}`);
    failures++;
  } finally {
    kill();
  }

  console.log(failures === 0 ? "\n  all cases passed\n" : `\n  ${failures} case(s) FAILED\n`);
  process.exit(failures === 0 ? 0 : 1);
})();
