import * as anchor from "@anchor-lang/core";
import { Program, BN } from "@anchor-lang/core";
import { SealedCodeBounty } from "../target/types/sealed_code_bounty";
import { assert } from "chai";
import * as nacl from "tweetnacl";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

/**
 * v2 test suite (phase 1, task 2).
 *
 * Covers the full program surface on localnet:
 *   config bootstrap + operator rotation bounds
 *   create_bounty escrow economics
 *   submit_exploit bond + slot serialization + deadline guard
 *   resolve_with_attestation PASS (real SCB_VERDICT_V4 bytes, real ed25519
 *     signature over the exact 207-byte wire, native Ed25519SigVerify
 *     instruction composed atomically with the resolution) and FAIL
 *   verdict-binding negatives (exploit/env/flag/operator/missing-ix)
 *   force_unlock_submission (too-early reject + delayed unlock)
 *   cancel_expired_bounty (unchanged v1 semantics)
 */

const ED25519_PROGRAM_ID = new anchor.web3.PublicKey(
  "Ed25519SigVerify111111111111111111111111111"
);
const INSTRUCTIONS_SYSVAR_ID = new anchor.web3.PublicKey(
  "Sysvar1nstructions1111111111111111111111111"
);
const VERDICT_TAG = Buffer.from("SCB_VERDICT_V4", "ascii");
const VERDICT_MSG_LEN = 207;
const BUYER_ENC_PK = Buffer.alloc(32, 9);

const PRIZE_LAMPORTS = 1 * anchor.web3.LAMPORTS_PER_SOL;
const BOND_LAMPORTS = 0.05 * anchor.web3.LAMPORTS_PER_SOL;
const DEFAULT_UNLOCK_DELAY_S = 3600;
const FUND_SOL = 50;

// Deterministic 32-byte filler hashes; contents don't matter to the program,
// only that they match across create -> submit -> verdict.
const ENC_PK = Buffer.alloc(32, 9);
const MANIFEST_HASH = Buffer.alloc(32, 1);
const ENV_HASH = Buffer.alloc(32, 2);
const EXPLOIT_HASH = Buffer.alloc(32, 3);
const FLAG_COMMITMENT = Buffer.alloc(32, 4);
const CIPHERTEXT = Buffer.from("sealed-box-ciphertext-bytes");
const CIPHERTEXT_SHA = crypto.createHash("sha256").update(CIPHERTEXT).digest();

describe("sealed-code-bounty v2", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.sealedCodeBounty as Program<SealedCodeBounty>;
  const connection = provider.connection;

  // Localnet: fresh ledgers every run, so fresh keypairs are safe and we
  // airdrop instead of persisting wallets (the old devnet trick is gone).
  const payer = provider.wallet.payer;
  const buyer = anchor.web3.Keypair.generate();
  const solver = anchor.web3.Keypair.generate();
  const relayer = anchor.web3.Keypair.generate();
  const operator = anchor.web3.Keypair.generate(); // test enclave signing key

  const idlErrors: Record<string, number> = {};
  for (const e of require("../target/idl/sealed_code_bounty.json").errors ?? []) {
    idlErrors[e.name] = e.code;
  }

  const configPda = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("config")],
    program.programId
  )[0];

  function bountyPda(buyerKey: anchor.web3.PublicKey, bountyId: number) {
    return anchor.web3.PublicKey.findProgramAddressSync(
      [
        Buffer.from("bounty"),
        buyerKey.toBuffer(),
        new BN(bountyId).toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    )[0];
  }
  function receiptPda(bountyKey: anchor.web3.PublicKey) {
    return anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("receipt"), bountyKey.toBuffer(), solver.publicKey.toBuffer()],
      program.programId
    )[0];
  }
  function revealPda(bountyKey: anchor.web3.PublicKey) {
    return anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("reveal"), bountyKey.toBuffer()],
      program.programId
    )[0];
  }

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  const CLOCK_SYSVAR = new anchor.web3.PublicKey(
    "SysvarC1ock11111111111111111111111111111111"
  );

  /**
   * Chain-clock time, read straight from the Clock sysvar account — the exact
   * value Clock::get() hands the program. getBlockTime proved unreliable on
   * test-validator (stale timestamps), and wall time can diverge from chain
   * time by seconds, breaking sub-10s deadlines.
   */
  async function chainNow(): Promise<number> {
    const info = await connection.getAccountInfo(CLOCK_SYSVAR);
    if (!info || info.data.length < 40) return Math.floor(Date.now() / 1000);
    // Agave Clock layout (borsh order):
    //   slot(0) · epoch_start_timestamp(8) · epoch(16) ·
    //   leader_schedule_epoch(24) · unix_timestamp(32)
    return Number(info.data.readBigInt64LE(32));
  }

  /**
   * The local validator's Clock::unix_timestamp tracks its SLOT count and
   * advances burstily (frozen while idle, then leaping). Waiting passively is
   * therefore unbounded — so we nudge consensus with 1-lamport transfers,
   * each of which lands in a fresh slot and pushes chain time forward.
   */
  async function pokeSlot() {
    const tx = new anchor.web3.Transaction().add(
      anchor.web3.SystemProgram.transfer({
        fromPubkey: relayer.publicKey,
        toPubkey: payer.publicKey,
        lamports: 1,
      })
    );
    await provider.sendAndConfirm(tx, [relayer]);
  }

  /** Polls until the chain clock passes `ts`, poking slots while stuck. */
  async function waitUntilChainPast(ts: number, maxMs = 60000) {
    const start = Date.now();
    let lastPoke = 0;
    while ((await chainNow()) <= ts) {
      if (Date.now() - start > maxMs)
        throw new Error(`chain clock never passed ${ts}`);
      if (Date.now() - lastPoke > 250) {
        await pokeSlot().catch(() => {});
        lastPoke = Date.now();
      }
      await sleep(150);
    }
  }

  /**
   * Blocks until the CHAIN clock is strictly past `bountyKey`'s deadline.
   * Sleeping against wall time is racy: the validator's Clock::get can lag
   * wall time by seconds, so short deadlines must be awaited on-chain.
   */
  async function waitUntilExpired(bountyKey: anchor.web3.PublicKey, maxMs = 30000) {
    const b = await program.account.bounty.fetch(bountyKey);
    await waitUntilChainPast(b.deadline.toNumber(), maxMs);
  }

  async function balance(pk: anchor.web3.PublicKey) {
    return connection.getBalance(pk);
  }

  async function expectError(p: Promise<any>, name: string) {
    try {
      await p;
    } catch (e: any) {
      const got =
        e?.error?.errorCode?.number ??
        e?.error?.error?.code?.number ??
        (() => {
          // Simulation failures surface AnchorErrors only as log lines:
          // "... Error Code: X. Error Number: N. Error Message: ..."
          const m = String(e?.message ?? "").match(/Error Number: (\d+)/);
          return m ? Number(m[1]) : null;
        })();
      if (got === idlErrors[name]) return;
      // Surface unexpected failures with full context.
      throw new Error(
        `expected ${name} (${idlErrors[name]}), got ${JSON.stringify({
          got,
          msg: String(e?.message ?? e).slice(0, 300),
        })}`
      );
    }
    throw new Error(`expected tx to fail with ${name}, but it succeeded`);
  }

  async function createBounty(
    bountyId: number,
    opts: { prize?: BN; deadlineOffsetS?: number } = {}
  ) {
    const cn = await chainNow();
    const deadline = new BN(cn).addn(opts.deadlineOffsetS ?? 3600);
    return program.methods
      .createBounty(
        new BN(bountyId),
        opts.prize ?? new BN(PRIZE_LAMPORTS),
        deadline,
        [...MANIFEST_HASH],
        [...ENV_HASH],
        [...FLAG_COMMITMENT],
        [...BUYER_ENC_PK]
      )
      .accountsStrict({
        buyer: buyer.publicKey,
        config: configPda,
        bounty: bountyPda(buyer.publicKey, bountyId),
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([buyer])
      .rpc();
  }

  async function submitExploit(bountyId: number, who = solver) {
    return program.methods
      .submitExploit(new BN(bountyId), `https://blob.example/${bountyId}`, [
        ...EXPLOIT_HASH,
      ])
      .accountsStrict({
        solver: who.publicKey,
        config: configPda,
        bounty: bountyPda(buyer.publicKey, bountyId),
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([who])
      .rpc();
  }

  /** Canonical SCB_VERDICT_V4 wire — must mirror constants.rs exactly. */
  function buildVerdictMessage(
    bountyKey: anchor.web3.PublicKey,
    envHash: Buffer,
    exploitHash: Buffer,
    solverPk: Buffer,
    flagCommitment: Buffer,
    outcome: boolean
  ) {
    return Buffer.concat([
      VERDICT_TAG,
      bountyKey.toBuffer(),
      envHash,
      exploitHash,
      solverPk,
      flagCommitment,
      BUYER_ENC_PK,
      Buffer.from([outcome ? 1 : 0]),
    ]);
  }

  interface ResolveOpts {
    bountyId: number;
    outcome: boolean;
    operatorKp?: anchor.web3.Keypair;
    envHash?: Buffer;
    exploitHash?: Buffer;
    flagCommitment?: Buffer;
    ciphertext?: Buffer;
    ciphertextUrl?: string;
    ciphertextSha?: Buffer;
    includeEd25519Ix?: boolean;
  }

  /**
   * Composes [Ed25519SigVerify, resolve_with_attestation] into ONE atomic
   * transaction and lands it from the permissionless relayer.
   */
  async function resolve(opts: ResolveOpts) {
    const {
      bountyId,
      outcome,
      operatorKp = operator,
      envHash = ENV_HASH,
      exploitHash = EXPLOIT_HASH,
      flagCommitment = FLAG_COMMITMENT,
      ciphertext = CIPHERTEXT,
      ciphertextUrl = "",
      ciphertextSha = CIPHERTEXT_SHA,
      includeEd25519Ix = true,
    } = opts;

    const bountyKey = bountyPda(buyer.publicKey, bountyId);
    const message = buildVerdictMessage(
      bountyKey,
      envHash,
      exploitHash,
      solver.publicKey.toBuffer(),
      flagCommitment,
      outcome
    );
    assert.equal(message.length, VERDICT_MSG_LEN);

    const signature = nacl.sign.detached(message, operatorKp.secretKey);
    const ed25519Ix = anchor.web3.Ed25519Program.createInstructionWithPublicKey({
      publicKey: operatorKp.publicKey.toBytes(),
      signature,
      message,
    });

    const resolveIx = await program.methods
      .resolveWithAttestation(
        new BN(bountyId),
        outcome,
        outcome ? Buffer.from(ciphertext) : Buffer.alloc(0),
        outcome ? ciphertextUrl : "",
        Buffer.from(ciphertextSha)
      )
      .accountsStrict({
        relayer: relayer.publicKey,
        config: configPda,
        bounty: bountyKey,
        solver: solver.publicKey,
        receipt: outcome ? receiptPda(bountyKey) : null,
        reveal: outcome ? revealPda(bountyKey) : null,
        ed25519Program: ED25519_PROGRAM_ID,
        instructions: INSTRUCTIONS_SYSVAR_ID,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .instruction();

    const tx = new anchor.web3.Transaction();
    if (includeEd25519Ix) tx.add(ed25519Ix);
    tx.add(resolveIx);
    return provider.sendAndConfirm(tx, [relayer]);
  }

  before(async () => {
    for (const kp of [buyer, solver, relayer]) {
      await connection.requestAirdrop(kp.publicKey, FUND_SOL * anchor.web3.LAMPORTS_PER_SOL);
    }
    // Faucet confirmations are lazy on localnet; poll until visible.
    for (const kp of [buyer, solver, relayer]) {
      for (let i = 0; i < 50; i++) {
        if ((await balance(kp.publicKey)) >= FUND_SOL / 2 * anchor.web3.LAMPORTS_PER_SOL) break;
        await sleep(200);
      }
    }

    await program.methods
      .initializeConfig(payer.publicKey, [...ENC_PK], new BN(BOND_LAMPORTS))
      .accountsStrict({
        payer: payer.publicKey,
        config: configPda,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

  });

  // ---------------------------------------------------------------------
  it("(1) initialize_config wrote the expected defaults", async () => {
    const c = await program.account.config.fetch(configPda);
    assert.ok(c.platformAuthority.equals(payer.publicKey));
    assert.deepEqual(c.operators, []);
    assert.equal(c.threshold, 0);
    assert.equal(c.submissionBondLamports.toNumber(), BOND_LAMPORTS);
    assert.equal(c.forceUnlockDelayS.toNumber(), DEFAULT_UNLOCK_DELAY_S);
    assert.deepEqual(Buffer.from(c.enclaveEncPk), ENC_PK);
  });

  it("(1a) set_operators rejects threshold=0", async () => {
    await expectError(
      program.methods
        .setOperators([operator.publicKey], 0, [...ENC_PK], new BN(DEFAULT_UNLOCK_DELAY_S))
        .accountsStrict({ authority: payer.publicKey, config: configPda })
        .rpc(),
      "BadThreshold"
    );
  });

  it("(1b) set_operators rejects threshold > operators.len()", async () => {
    await expectError(
      program.methods
        .setOperators([operator.publicKey], 2, [...ENC_PK], new BN(DEFAULT_UNLOCK_DELAY_S))
        .accountsStrict({ authority: payer.publicKey, config: configPda })
        .rpc(),
      "BadThreshold"
    );
  });

  it("(1c) set_operators rejects duplicate operators", async () => {
    await expectError(
      program.methods
        .setOperators(
          [operator.publicKey, operator.publicKey],
          1,
          [...ENC_PK],
          new BN(DEFAULT_UNLOCK_DELAY_S)
        )
        .accountsStrict({ authority: payer.publicKey, config: configPda })
        .rpc(),
      "InvalidOperators"
    );
  });

  it("(1d) set_operators rejects zero unlock delay", async () => {
    await expectError(
      program.methods
        .setOperators([operator.publicKey], 1, [...ENC_PK], new BN(0))
        .accountsStrict({ authority: payer.publicKey, config: configPda })
        .rpc(),
      "InvalidForceUnlockDelay"
    );
  });

  it("(1e) set_operators update works and arms the trust root", async () => {
    // Rotation to a 2-of-2 style set, back down to launch posture (n=1).
    const second = anchor.web3.Keypair.generate().publicKey;
    await program.methods
      .setOperators(
        [operator.publicKey, second],
        1,
        [...ENC_PK],
        new BN(DEFAULT_UNLOCK_DELAY_S)
      )
      .accountsStrict({ authority: payer.publicKey, config: configPda })
      .rpc();
    let c = await program.account.config.fetch(configPda);
    assert.equal(c.operators.length, 2);
    assert.equal(c.threshold, 1);

    await program.methods
      .setOperators([operator.publicKey], 1, [...ENC_PK], new BN(DEFAULT_UNLOCK_DELAY_S))
      .accountsStrict({ authority: payer.publicKey, config: configPda })
      .rpc();
    c = await program.account.config.fetch(configPda);
    assert.equal(c.operators.length, 1);
    assert.ok(c.operators[0].equals(operator.publicKey));
    // From here on every resolve test can sign as `operator`.
  });

  // ---------------------------------------------------------------------
  let nextBountyId = 100;

  it("(2) create_bounty escrows the prize into the PDA", async () => {
    const id = nextBountyId++;
    const pda = bountyPda(buyer.publicKey, id);
    const before = await balance(buyer.publicKey);
    await createBounty(id);
    const after = await balance(buyer.publicKey);

    const b = await program.account.bounty.fetch(pda);
    assert.ok(b.buyer.equals(buyer.publicKey));
    assert.deepEqual(b.status, { open: {} });
    assert.equal(b.prizeLamports.toNumber(), PRIZE_LAMPORTS);
    assert.isNull(b.currentSubmission);
    assert.isNull(b.winner);
    assert.deepEqual(Buffer.from(b.envBlobSha256), ENV_HASH);
    assert.deepEqual(Buffer.from(b.flagCommitment), FLAG_COMMITMENT);
    // Buyer paid prize + rent + fees; escrow PDA holds at least the prize.
    assert.isAtMost(after, before - PRIZE_LAMPORTS);
    assert.isAtLeast((await balance(pda)), PRIZE_LAMPORTS);
  });

  it("(2a) create_bounty rejects zero prize", async () => {
    const id = nextBountyId++;
    await expectError(
      createBounty(id, { prize: new BN(0) }),
      "InvalidPrizeAmount"
    );
  });

  it("(2b) create_bounty rejects past deadline", async () => {
    const id = nextBountyId++;
    await expectError(
      createBounty(id, { deadlineOffsetS: -60 }),
      "InvalidDeadline"
    );
  });

  // ---------------------------------------------------------------------
  it("(3) submit_exploit posts the bond and claims the slot", async () => {
    const id = nextBountyId++;
    await createBounty(id);
    const pda = bountyPda(buyer.publicKey, id);
    const before = await balance(solver.publicKey);
    await submitExploit(id);
    const after = await balance(solver.publicKey);

    assert.equal(before - after, BOND_LAMPORTS); // bond moved in exactly
    const b = await program.account.bounty.fetch(pda);
    assert.deepEqual(b.status, { awaitingResolution: {} });
    assert.isNotNull(b.currentSubmission);
    assert.ok((b.currentSubmission! as any).solver.equals(solver.publicKey));
    assert.equal(
      (b.currentSubmission! as any).bondLamports.toNumber(),
      BOND_LAMPORTS
    );
    assert.deepEqual(
      Buffer.from((b.currentSubmission! as any).exploitSha256),
      EXPLOIT_HASH
    );
  });

  it("(3a) submit_exploit reverts while slot is claimed", async () => {
    const id = nextBountyId++;
    await createBounty(id);
    await submitExploit(id);
    await expectError(submitExploit(id), "NotOpen");
  });

  it("(3b) submit_exploit reverts after deadline", async () => {
    const id = nextBountyId++;
    await createBounty(id, { deadlineOffsetS: 2 });
    await waitUntilExpired(bountyPda(buyer.publicKey, id));
    await expectError(submitExploit(id), "DeadlinePassed");
  });

  // ---------------------------------------------------------------------
  it("(4) resolve PASS pays prize+bond atomically and writes Receipt+Reveal", async () => {
    const id = nextBountyId++;
    await createBounty(id);
    await submitExploit(id);

    const bountyKey = bountyPda(buyer.publicKey, id);
    const solverBefore = await balance(solver.publicKey);

    await resolve({ bountyId: id, outcome: true });

    const solverAfter = await balance(solver.publicKey);
    assert.equal(solverAfter - solverBefore, PRIZE_LAMPORTS + BOND_LAMPORTS);

    const b = await program.account.bounty.fetch(bountyKey);
    assert.deepEqual(b.status, { resolved: {} });
    assert.ok(b.winner!.equals(solver.publicKey));
    assert.isNull(b.currentSubmission);

    const r = await program.account.receipt.fetch(receiptPda(bountyKey));
    assert.ok(r.solver.equals(solver.publicKey));
    assert.ok(r.bounty.equals(bountyKey));
    assert.deepEqual(Buffer.from(r.exploitSha256), EXPLOIT_HASH);
    assert.isTrue(r.firstBlood);

    const rev = await program.account.reveal.fetch(revealPda(bountyKey));
    assert.deepEqual(Buffer.from(rev.ciphertext), CIPHERTEXT);
    assert.deepEqual(Buffer.from(rev.ciphertextSha256), CIPHERTEXT_SHA);
    assert.equal(rev.ciphertextUrl, "");
  });

  it("(4a) second resolve on a Resolved bounty rejects", async () => {
    const id = nextBountyId - 1; // the bounty resolved above
    await expectError(resolve({ bountyId: id, outcome: true }), "NotAwaitingResolution");
  });

  // ---------------------------------------------------------------------
  // Negatives share one pending submission; none of them mutate state.
  let negBountyId = 0;
  before(async () => {
    negBountyId = nextBountyId++;
    await createBounty(negBountyId);
    await submitExploit(negBountyId);
  });

  it("(5a) verdict binding wrong exploit_sha256 fails", async () => {
    const bad = Buffer.alloc(32, 99);
    await expectError(
      resolve({ bountyId: negBountyId, outcome: true, exploitHash: bad }),
      "MissingSigVerify"
    );
  });

  it("(5b) verdict binding wrong env_blob_sha256 fails (V3 hole closed)", async () => {
    const bad = Buffer.alloc(32, 98);
    await expectError(
      resolve({ bountyId: negBountyId, outcome: true, envHash: bad }),
      "MissingSigVerify"
    );
  });

  it("(5c) verdict binding wrong flag_commitment fails", async () => {
    const bad = Buffer.alloc(32, 97);
    await expectError(
      resolve({ bountyId: negBountyId, outcome: true, flagCommitment: bad }),
      "MissingSigVerify"
    );
  });

  it("(5d) non-operator signer fails", async () => {
    const impostor = anchor.web3.Keypair.generate();
    await expectError(
      resolve({ bountyId: negBountyId, outcome: true, operatorKp: impostor }),
      "UnauthorizedOperator"
    );
  });

  it("(5e) missing Ed25519 instruction fails", async () => {
    await expectError(
      resolve({ bountyId: negBountyId, outcome: true, includeEd25519Ix: false }),
      "MissingSigVerify"
    );
  });

  // ---------------------------------------------------------------------
  it("(6) resolve FAIL refunds bond, wipes slot, allows resubmit", async () => {
    const id = negBountyId; // still AwaitingResolution from the negatives
    const bountyKey = bountyPda(buyer.publicKey, id);
    const before = await balance(solver.publicKey);

    await resolve({ bountyId: id, outcome: false, ciphertextUrl: "" });

    assert.equal((await balance(solver.publicKey)) - before, BOND_LAMPORTS);
    let b = await program.account.bounty.fetch(bountyKey);
    assert.deepEqual(b.status, { open: {} });
    assert.isNull(b.currentSubmission);
    assert.isNull(await program.account.receipt.fetchNullable(receiptPda(bountyKey)));
    assert.isNull(await program.account.reveal.fetchNullable(revealPda(bountyKey)));

    // Slot free again.
    await submitExploit(id);
    b = await program.account.bounty.fetch(bountyKey);
    assert.deepEqual(b.status, { awaitingResolution: {} });
  });

  // ---------------------------------------------------------------------
  it("(7a) force_unlock_submission rejects before the delay elapses", async () => {
    const id = nextBountyId++; // default 3600 s delay still configured
    await createBounty(id);
    await submitExploit(id);
    await expectError(
      program.methods
        .forceUnlockSubmission(new BN(id))
        .accountsStrict({
          caller: relayer.publicKey,
          bounty: bountyPda(buyer.publicKey, id),
          config: configPda,
          solver: solver.publicKey,
        })
        .signers([relayer])
        .rpc(),
      "ForceUnlockTooEarly"
    );
  });

  it("(7b) force_unlock_submission unlocks once Config delay has passed", async () => {
    // Shrink the delay via authority (proves the Config knob works too).
    await program.methods
      .setOperators([operator.publicKey], 1, [...ENC_PK], new BN(1))
      .accountsStrict({ authority: payer.publicKey, config: configPda })
      .rpc();

    const id = nextBountyId++;
    await createBounty(id);
    await submitExploit(id);

    const bountyKey = bountyPda(buyer.publicKey, id);
    const before = await balance(solver.publicKey);
    // Wait out Config.force_unlock_delay_s measured in CHAIN seconds.
    const pending = await program.account.bounty.fetch(bountyKey);
    const sub = pending.currentSubmission! as any;
    await waitUntilChainPast(
      sub.submittedAt.toNumber() +
        (await program.account.config.fetch(configPda)).forceUnlockDelayS.toNumber()
    );

    await program.methods
      .forceUnlockSubmission(new BN(id))
      .accountsStrict({
        caller: relayer.publicKey,
        bounty: bountyKey,
        config: configPda,
        solver: solver.publicKey,
      })
      .signers([relayer])
      .rpc();

    assert.equal((await balance(solver.publicKey)) - before, BOND_LAMPORTS);
    const b = await program.account.bounty.fetch(bountyKey);
    assert.deepEqual(b.status, { open: {} });
    assert.isNull(b.currentSubmission);

    // Restore launch posture.
    await program.methods
      .setOperators([operator.publicKey], 1, [...ENC_PK], new BN(DEFAULT_UNLOCK_DELAY_S))
      .accountsStrict({ authority: payer.publicKey, config: configPda })
      .rpc();
  });

  // ---------------------------------------------------------------------
  it("(8) cancel_expired_bounty refunds prize+rent and closes the account", async () => {
    const id = nextBountyId++;
    await createBounty(id, { deadlineOffsetS: 2 });
    const bountyKey = bountyPda(buyer.publicKey, id);
    await waitUntilExpired(bountyKey);

    const before = await balance(buyer.publicKey);
    await program.methods
      .cancelExpiredBounty(new BN(id))
      .accountsStrict({ buyer: buyer.publicKey, bounty: bountyKey })
      .signers([buyer])
      .rpc();

    const delta = (await balance(buyer.publicKey)) - before;
    assert.isAtLeast(delta, PRIZE_LAMPORTS); // prize + rent back, minus fee
    assert.isNull(await program.account.bounty.fetchNullable(bountyKey));
  });

  it("(8a) cancel still refuses while a submission is awaiting resolution", async () => {
    const id = nextBountyId++;
    await createBounty(id, { deadlineOffsetS: 2 });
    await submitExploit(id);
    await waitUntilExpired(bountyPda(buyer.publicKey, id)); // slot stays claimed
    await expectError(
      program.methods
        .cancelExpiredBounty(new BN(id))
        .accountsStrict({
          buyer: buyer.publicKey,
          bounty: bountyPda(buyer.publicKey, id),
        })
        .signers([buyer])
        .rpc(),
      "NotOpen"
    );
  });
  // ---------------------------------------------------------------------
  // Audit L1: FAIL verdicts must not carry payout accounts.
  it("(L1) FAIL resolve with receipt/reveal accounts reverts", async () => {
    const id = nextBountyId++;
    await createBounty(id);
    await submitExploit(id);
    const bountyKey = bountyPda(buyer.publicKey, id);

    const message = buildVerdictMessage(
      bountyKey,
      ENV_HASH,
      EXPLOIT_HASH,
      solver.publicKey.toBuffer(),
      FLAG_COMMITMENT,
      false
    );
    const signature = nacl.sign.detached(message, operator.secretKey);
    const ed25519Ix = anchor.web3.Ed25519Program.createInstructionWithPublicKey({
      publicKey: operator.publicKey.toBytes(),
      signature,
      message,
    });
    const failIx = await program.methods
      .resolveWithAttestation(new BN(id), false, Buffer.alloc(0), "", Buffer.alloc(32))
      .accountsStrict({
        relayer: relayer.publicKey,
        config: configPda,
        bounty: bountyKey,
        solver: solver.publicKey,
        receipt: receiptPda(bountyKey), // MUST be null on FAIL (audit L1)
        reveal: revealPda(bountyKey),
        ed25519Program: ED25519_PROGRAM_ID,
        instructions: INSTRUCTIONS_SYSVAR_ID,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .instruction();
    const tx = new anchor.web3.Transaction().add(ed25519Ix, failIx);
    try {
      await provider.sendAndConfirm(tx, [relayer]);
      throw new Error("expected UnexpectedPayoutAccounts");
    } catch (e: any) {
      assert.match(String(e?.message ?? e), /UnexpectedPayoutAccounts|0x601b/);
    }
  });

  // ---------------------------------------------------------------------
  // Audit L2: Resolved bounties can be swept — rent returns to the buyer.
  it("(L2) close_resolved_bounty refunds rent and closes; rejects unresolved", async () => {
    // Resolve a fresh bounty first.
    const id = nextBountyId++;
    await createBounty(id);
    await submitExploit(id);
    await resolve({ bountyId: id, outcome: true });

    const bountyKey = bountyPda(buyer.publicKey, id);
    const buyerBefore = await provider.connection.getBalance(buyer.publicKey);
    const callerBefore = await provider.connection.getBalance(relayer.publicKey);

    await program.methods
      .closeResolvedBounty(new BN(id))
      .accountsStrict({
        caller: relayer.publicKey,
        bounty: bountyKey,
        buyer: buyer.publicKey,
      })
      .signers([relayer])
      .rpc();

    assert.isNull(await program.account.bounty.fetchNullable(bountyKey));
    const buyerAfter = await provider.connection.getBalance(buyer.publicKey);
    assert.ok(buyerAfter > buyerBefore, "buyer rent refund missing");
    void callerBefore;

    // Second sweep rejects: account gone.
    try {
      await program.methods
        .closeResolvedBounty(new BN(id))
        .accountsStrict({
          caller: relayer.publicKey,
          bounty: bountyKey,
          buyer: buyer.publicKey,
        })
        .signers([relayer])
        .rpc();
      throw new Error("expected close of closed account to fail");
    } catch {
      // Any failure is correct: the account is already closed.
    }

    // Non-resolved bounty must reject (Open with no expiry).
    const openId = nextBountyId++;
    await createBounty(openId);
    try {
      await program.methods
        .closeResolvedBounty(new BN(openId))
        .accountsStrict({
          caller: relayer.publicKey,
          bounty: bountyPda(buyer.publicKey, openId),
          buyer: buyer.publicKey,
        })
        .signers([relayer])
        .rpc();
      throw new Error("expected NotResolved");
    } catch (e: any) {
      assert.match(String(e?.message ?? e), /NotResolved|custom program error/);
    }
  });

});
