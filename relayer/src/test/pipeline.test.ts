import { test } from "node:test";
import { createRequire } from "node:module";
type MockEnclaveHandle = { url: string; pubkeyB58: string; close(): Promise<void> };

const requireMock = createRequire(__filename);

/** Walks up to the repo root (dir containing .git), robust to outDir layouts. */
function repoRoot(): string {
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    if (fs.existsSync(path.join(dir, ".git"))) return dir;
    dir = path.dirname(dir);
  }
  throw new Error("repo root not found from " + __dirname);
}

function loadMock(): { startMockEnclave(o?: { tamper?: boolean }): Promise<MockEnclaveHandle> } {
  const p = path.resolve(repoRoot(), "relayer/test/mock-enclave.cjs");
  return requireMock(p);
}

/** Canonical cross-language verdict fixture (single source of truth). */
interface VerdictVector {
  master_secret_hex: string;
  bounty_pda_b58: string;
  tag_ascii: string;
  env_blob_sha256_hex: string;
  exploit_sha256_hex: string;
  solver_pubkey_hex: string;
  operator_pubkey_hex: string;
  flag_commitment_hex: string;
  buyer_enc_pk_hex: string;
  outcome_byte: string;
  message_hex: string;
  signature_b64: string;
}
function loadVerdictVector(): VerdictVector {
  const p = path.resolve(repoRoot(), "test-vectors/verdict_v4.json");
  return JSON.parse(fs.readFileSync(p, "utf8")) as VerdictVector;
}
import assert from "node:assert/strict";
import * as crypto from "crypto";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { AnchorProvider, BN, Program, Wallet } from "@anchor-lang/core";
import * as nacl from "tweetnacl";
import * as fs from "fs";
import * as path from "path";

import {
  VERDICT_MSG_LEN,
  VERDICT_TAG,
  buildVerdictMessage,
  verifyDetached,
} from "../verdict";
import {
  callEnclave,
  composeVerdictTx,
  prepareVerdict,
  processJob,
  reconstructMessage,
  ED25519_PROGRAM_ID,
  INSTRUCTIONS_SYSVAR_ID,
  type BountyView,
  type PipelineDeps,
} from "../pipeline";
import { JobQueue } from "../queue";
import type { Logger } from "../logger";
import type { SealedCodeBounty } from "../../../target/types/sealed_code_bounty";

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const PROGRAM_ID = new PublicKey("FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V");

function idlPath(): string {
  // dist/relayer/src/test -> up four levels = repo root
  return path.resolve(__dirname, "../../../../../target/idl/sealed_code_bounty.json");
}

const silentLog: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

function makeProgram(): Program<SealedCodeBounty> {
  const idl = JSON.parse(fs.readFileSync(idlPath(), "utf8")) as unknown as SealedCodeBounty;
  const connection = new Connection("http://127.0.0.1:8899", "confirmed"); // never contacted offline
  const provider = new AnchorProvider(connection, new Wallet(Keypair.generate()), {});
  return new Program<SealedCodeBounty>(idl, provider);
}

function bountyFixture(): { bounty: BountyView; job: Parameters<typeof reconstructMessage>[0] } {
  const solverKp = Keypair.generate();
  const buyerPda = Keypair.generate().publicKey; // only its bytes matter
  const envHash = Buffer.alloc(32, 2);
  const exploitHash = Buffer.alloc(32, 3);
  const flagCommitment = Buffer.alloc(32, 4);
  const now = new BN(1_700_000_000);

  const bounty: BountyView = {
    bountyId: new BN(7),
    status: { awaitingResolution: {} },
    prizeLamports: new BN(1_000_000),
    deadline: now.addn(3600),
    envBlobSha256: envHash,
    flagCommitment,
    buyerEncPk: Buffer.alloc(32, 9),
    currentSubmission: {
      solver: solverKp.publicKey,
      exploitSha256: exploitHash,
      blobUrl: "https://blob.example/1",
      bondLamports: new BN(50_000),
      submittedAt: now,
    },
    winner: null,
  };
  const bountyKey = PublicKey.findProgramAddressSync(
    [Buffer.from("bounty"), buyerPda.toBuffer(), new BN(7).toArrayLike(Buffer, "le", 8)],
    PROGRAM_ID
  )[0];
  const job = { bountyPda: bountyKey, solver: solverKp.publicKey, bountyId: new BN(7), exploitSha256: exploitHash };
  return { bounty, job };
}

/** Offline stand-in: step-a fetch resolves from the fixture; ix encode is a stub. */
function fakeProgram(bounty: BountyView): Program<SealedCodeBounty> {
  const stubIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [],
    data: Buffer.from([0]),
  });
  return {
    programId: PROGRAM_ID,
    account: {
      bounty: {
        fetch: async () => bounty,
      },
    },
    methods: {
      resolveWithAttestation: () => ({
        accountsStrict: () => ({
          transaction: async () => {
            const tx = new Transaction();
            tx.add(stubIx);
            return tx;
          },
        }),
      }),
    },
  } as unknown as Program<SealedCodeBounty>;
}

function depsWith(
  overrides: Partial<PipelineDeps> & { connection: Connection }
): PipelineDeps {
  return {
    program: makeProgram(),
    feePayer: Keypair.generate(),
    operatorPubkey: Keypair.generate().publicKey,
    enclaveUrl: "http://127.0.0.1:1",
    log: silentLog,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// (T1) verdict wire reconstruction — the bytes everything else stands on
// ---------------------------------------------------------------------------

test("(T1) SCB_VERDICT_V4: TS reconstruction == canonical vector, field by field", () => {
  const vec = loadVerdictVector();
  const wire = Buffer.from(vec.message_hex, "hex");
  const tag = Buffer.from(vec.tag_ascii, "ascii");

  // Rebuild the message from the vector's own witness fields — the same way
  // the Rust golden test does. No hardcoded lengths or offsets here.
  const b58decode = (s: string): Buffer => {
    let n = 0n;
    for (const ch of s) {
      const idx = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".indexOf(ch);
      if (idx < 0) throw new Error("bad b58");
      n = n * 58n + BigInt(idx);
    }
    return Buffer.from(n.toString(16).padStart(64, "0"), "hex");
  };
  const pda = b58decode(vec.bounty_pda_b58);
  const rebuilt = buildVerdictMessage({
    bountyPda: pda,
    envBlobSha256: Buffer.from(vec.env_blob_sha256_hex, "hex"),
    exploitSha256: Buffer.from(vec.exploit_sha256_hex, "hex"),
    solver: Buffer.from(vec.solver_pubkey_hex, "hex"),
    flagCommitment: Buffer.from(vec.flag_commitment_hex, "hex"),
    buyerEncPk: Buffer.from(vec.buyer_enc_pk_hex, "hex"),
    outcome: true,
  });

  assert.equal(rebuilt.length, VERDICT_MSG_LEN); // builder agrees with fixture
  assert.equal(wire.length, VERDICT_MSG_LEN);
  assert.deepEqual(rebuilt, wire);

  // And the pipeline's reconstruction over a matching chain view agrees too.
  const { bounty, job } = bountyFixture();
  bounty.envBlobSha256 = new Uint8Array(Buffer.from(vec.env_blob_sha256_hex, "hex"));
  bounty.flagCommitment = new Uint8Array(Buffer.from(vec.flag_commitment_hex, "hex"));
  const solverPk = Buffer.from(vec.solver_pubkey_hex, "hex");
  bounty.currentSubmission = {
    ...(bounty.currentSubmission as NonNullable<BountyView["currentSubmission"]>),
    exploitSha256: new Uint8Array(Buffer.from(vec.exploit_sha256_hex, "hex")),
    solver: new PublicKey(solverPk),
  };
  job.bountyPda = new PublicKey(pda);
  job.solver = new PublicKey(solverPk);
  job.exploitSha256 = Buffer.from(vec.exploit_sha256_hex, "hex");
  const msg = reconstructMessage(job, bounty, true);
  assert.ok(msg.equals(wire));

  // Field-by-field offsets derived from the tag length.
  let off = 0;
  assert.ok(msg.subarray(off, off + tag.length).equals(tag)); off += tag.length;
  for (const f of [pda, Buffer.from(vec.env_blob_sha256_hex, "hex"), Buffer.from(vec.exploit_sha256_hex, "hex"), solverPk, Buffer.from(vec.flag_commitment_hex, "hex"), Buffer.from(vec.buyer_enc_pk_hex, "hex")]) {
    assert.ok(msg.subarray(off, off + 32).equals(f)); off += 32;
  }
  assert.equal(msg[off], 1);
});

test("(T1b) buildVerdictMessage flips only the outcome byte between PASS/FAIL", () => {
  const f = {
    bountyPda: Buffer.alloc(32, 1),
    envBlobSha256: Buffer.alloc(32, 2),
    exploitSha256: Buffer.alloc(32, 3),
    solver: Buffer.alloc(32, 4),
    flagCommitment: Buffer.alloc(32, 5),
    buyerEncPk: Buffer.alloc(32, 6),
    outcome: false,
  };
  const pass = buildVerdictMessage({ ...f, outcome: true });
  const fail = buildVerdictMessage(f);
  assert.deepEqual(pass.subarray(0, 206), fail.subarray(0, 206));
  assert.equal(pass[206] - fail[206], 1);
});

// ---------------------------------------------------------------------------
// (T2) local signature verification helper
// ---------------------------------------------------------------------------

test("(T2) verifyDetached accepts genuine signatures and rejects tampered ones", () => {
  const op = Keypair.generate();
  const msg = Buffer.alloc(VERDICT_MSG_LEN, 7);
  const sig = nacl.sign.detached(new Uint8Array(msg), op.secretKey);

  assert.equal(verifyDetached(msg, Buffer.from(sig).toString("base64"), op.publicKey), true);
  sig[10] ^= 0x01;
  assert.equal(verifyDetached(msg, Buffer.from(sig).toString("base64"), op.publicKey), false);
  // Wrong length base64 must be rejected without throwing.
  assert.equal(verifyDetached(msg, Buffer.from("short").toString("base64"), op.publicKey), false);
});

// ---------------------------------------------------------------------------
// (T3) transaction composition (offline encode via real Program + IDL)
// ---------------------------------------------------------------------------

test("(T3) composed tx is [Ed25519SigVerify, resolve_with_attestation] atomically", async () => {
  const { bounty, job } = bountyFixture();
  const op = Keypair.generate();
  const message = reconstructMessage(job, bounty, true);
  const signature = Buffer.from(nacl.sign.detached(new Uint8Array(message), op.secretKey));

  const ciphertext = Buffer.from("sealed-box-bytes");
  const prepared = {
    message,
    signature,
    ciphertext,
    ciphertextUrl: "",
    ciphertextSha256: Buffer.from(crypto.createHash("sha256").update(ciphertext).digest()),
    outcome: true,
  };

  const deps = depsWith({ connection: new Connection("http://127.0.0.1:8899") });
  deps.operatorPubkey = op.publicKey;

  const tx: Transaction = await composeVerdictTx(deps, job, bounty, prepared);

  assert.equal(tx.instructions.length, 2);
  const [ed, resolveIx] = tx.instructions;
  assert.ok(ed.programId.equals(ED25519_PROGRAM_ID));
  // The exact verdict bytes must be embedded in the native verify instruction.
  assert.ok(ed.data.includes(message));
  // And the embedded pubkey must be the operator.
  assert.ok(ed.data.includes(Buffer.from(op.publicKey.toBytes())));

  assert.ok(resolveIx.programId.equals(PROGRAM_ID));
  const keyStr = resolveIx.keys.map((k) => k.pubkey.toBase58()).join(",");
  assert.ok(keyStr.includes(bounty.currentSubmission!.solver.toBase58()));
  assert.ok(resolveIx.keys.some((k) => k.pubkey.equals(INSTRUCTIONS_SYSVAR_ID)));
  // PASS carries receipt+reveal PDAs (non-null Options present in keys).
  const expectedReceipt = PublicKey.findProgramAddressSync(
    [
      Buffer.from("receipt"),
      job.bountyPda.toBuffer(),
      bounty.currentSubmission!.solver.toBuffer(),
    ],
    PROGRAM_ID
  )[0];
  assert.ok(resolveIx.keys.some((k) => k.pubkey.equals(expectedReceipt)));
});

// ---------------------------------------------------------------------------
// (T4/T5) full pipeline against the mock enclave with a mocked connection
// ---------------------------------------------------------------------------

class FakeConnection {
  sent: Transaction[] = [];
  async getLatestBlockhash() {
    return { blockhash: "fakeblockhashfakeblockhashfakeblockhashfak", lastValidBlockHeight: 999n };
  }
  async sendTransaction(tx: Transaction) {
    this.sent.push(tx);
    return "FakeSignature11111111111111111111111111111111111";
  }
  async confirmTransaction() {
    return { value: { err: null } };
  }
}

function chainViewOf(bounty: BountyView) {
  return {
    env_blob_sha256: Buffer.from(bounty.envBlobSha256).toString("hex"),
    buyer_enc_pk: Buffer.from(bounty.buyerEncPk).toString("hex"),
    flag_commitment: Buffer.from(bounty.flagCommitment).toString("hex"),
    exploit_sha256: Buffer.from(bounty.currentSubmission!.exploitSha256).toString("hex"),
  };
}

test("(T4) mock-enclave smoke: pipeline lands a locally-verified verdict tx", async () => {
  const mock = await loadMock().startMockEnclave({ tamper: false });

  try {
    const { bounty, job } = bountyFixture();
    const fake = new FakeConnection();
    const deps = depsWith({
      program: fakeProgram(bounty), // no live validator in unit tests
      connection: fake as unknown as Connection,
      enclaveUrl: mock.url,
      operatorPubkey: new PublicKey(mock.pubkeyB58),
    });

    // queue dedupe sanity while we're here
    const q = new JobQueue();
    assert.equal(q.enqueue(job), true);
    assert.equal(q.enqueue(job), false);
    q.dequeue();

    const outcome = await processJob(deps, job);
    assert.equal(outcome.status, "landed");
    if (outcome.status === "landed") assert.equal(outcome.outcome, true);
    assert.equal(fake.sent.length, 1);
    assert.equal(fake.sent[0].instructions.length, 2);
  } finally {
    await mock.close();
  }
});

test("(T5) tampered mock signature is rejected BEFORE any transaction is sent", async () => {
  const mock = await loadMock().startMockEnclave({ tamper: true });

  try {
    const { bounty, job } = bountyFixture();
    const fake = new FakeConnection();
    const deps = depsWith({
      program: fakeProgram(bounty),
      connection: fake as unknown as Connection,
      enclaveUrl: mock.url,
      operatorPubkey: new PublicKey(mock.pubkeyB58),
    });

    const outcome = await processJob(deps, job);
    assert.equal(outcome.status, "permanent-reject");
    if (outcome.status === "permanent-reject") {
      assert.match(outcome.reason, /LOCAL verification/);
    }
    assert.equal(fake.sent.length, 0);
  } finally {
    await mock.close();
  }
});
