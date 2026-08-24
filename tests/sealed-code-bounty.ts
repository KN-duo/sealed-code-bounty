import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { SealedCodeBounty } from "../target/types/sealed_code_bounty";
import { assert } from "chai";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

describe("sealed-code-bounty", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.sealedCodeBounty as Program<SealedCodeBounty>;

  // Devnet SOL is scarce (airdrop faucet is heavily rate-limited), so test
  // wallets are persisted across runs instead of freshly generated each time
  // — a fresh `Keypair.generate()` every run permanently strands whatever
  // it's funded with, since nothing ever sends it back.
  const KEYS_DIR = path.join(__dirname, ".keys");
  function loadOrCreateKeypair(name: string): anchor.web3.Keypair {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
    const file = path.join(KEYS_DIR, `${name}.json`);
    if (fs.existsSync(file)) {
      const secret = Uint8Array.from(JSON.parse(fs.readFileSync(file, "utf8")));
      return anchor.web3.Keypair.fromSecretKey(secret);
    }
    const kp = anchor.web3.Keypair.generate();
    fs.writeFileSync(file, JSON.stringify(Array.from(kp.secretKey)));
    return kp;
  }

  const buyer = loadOrCreateKeypair("buyer");
  const solver = loadOrCreateKeypair("solver");

  // Kept modest on purpose: every run permanently locks bounty #2's and #3's
  // prize (never resolved/cancelled in these tests), so a smaller amount
  // keeps repeated test runs sustainable against a scarce devnet balance.
  const PRIZE_LAMPORTS = 0.05 * anchor.web3.LAMPORTS_PER_SOL;

  // Bounty IDs derived from the current time so a persistent buyer never
  // collides with a bounty PDA it already created (and left unresolved) in
  // an earlier run.
  const RUN_ID = new anchor.BN(Date.now());

  function bountyPda(buyerKey: anchor.web3.PublicKey, bountyId: anchor.BN) {
    return anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bounty"), buyerKey.toBuffer(), bountyId.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];
  }

  // Tops a persistent test wallet up to `targetSol` only if it's currently
  // below that — avoids re-funding (and stranding more SOL) on every rerun
  // once the wallet already has enough from a previous run.
  async function fundIfLow(pubkey: anchor.web3.PublicKey, targetSol: number) {
    const targetLamports = targetSol * anchor.web3.LAMPORTS_PER_SOL;
    const current = await provider.connection.getBalance(pubkey);
    if (current >= targetLamports) return;

    const tx = new anchor.web3.Transaction().add(
      anchor.web3.SystemProgram.transfer({
        fromPubkey: provider.wallet.publicKey,
        toPubkey: pubkey,
        lamports: targetLamports - current,
      })
    );
    const sig = await provider.sendAndConfirm(tx);
    await provider.connection.confirmTransaction(sig, "confirmed");
  }

  // Waits until the on-chain Clock actually passes `targetUnix`. A fresh local
  // validator advances its clock from slots and can lag wall-clock time, so a
  // fixed setTimeout is flaky; poll block time instead of trusting Date.now().
  async function waitUntilOnChainTime(targetUnix: number, maxWaitMs = 30000) {
    const start = Date.now();
    while (Date.now() - start < maxWaitMs) {
      const slot = await provider.connection.getSlot();
      const t = await provider.connection.getBlockTime(slot);
      if (t !== null && t > targetUnix) return;
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error("on-chain clock did not pass the deadline within maxWaitMs");
  }

  async function createBounty(bountyId: anchor.BN, deadlineOffsetSeconds = 3600, prizeLamports = PRIZE_LAMPORTS) {
    const testSuiteHash = crypto.createHash("sha256").update(`suite-${bountyId}`).digest();
    const deadline = new anchor.BN(Math.floor(Date.now() / 1000) + deadlineOffsetSeconds);
    const bounty = bountyPda(buyer.publicKey, bountyId);

    await program.methods
      .createBounty(bountyId, Array.from(testSuiteHash), new anchor.BN(prizeLamports), deadline)
      .accountsPartial({
        buyer: buyer.publicKey,
        bounty,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([buyer])
      .rpc();

    return bounty;
  }

  async function submitSolution(bountyId: anchor.BN, bounty: anchor.web3.PublicKey, solution: string) {
    await program.methods
      .submitSolution(bountyId, solution)
      .accountsPartial({
        solver: solver.publicKey,
        bounty,
        buyer: buyer.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([solver])
      .rpc();
  }

  before(async () => {
    // Targets cover this run's worst case (two 0.05-SOL prizes + two small
    // cancel-test prizes + rent/fees) with headroom; fundIfLow only tops up
    // the shortfall, so reruns that already have enough spend nothing.
    await fundIfLow(buyer.publicKey, 0.3);
    await fundIfLow(solver.publicKey, 0.05);
  });

  it("escrows the prize on create, and releases it to the solver on PASS", async () => {
    const bountyId = RUN_ID;
    const bounty = await createBounty(bountyId);

    const bountyAfterCreate = await program.account.bounty.fetch(bounty);
    assert.equal(bountyAfterCreate.prizeAmount.toNumber(), PRIZE_LAMPORTS);
    assert.equal(bountyAfterCreate.submitted, false);
    assert.equal(bountyAfterCreate.resolved, false);

    await submitSolution(bountyId, bounty, "def solve(x): return x * 2");

    const bountyAfterSubmit = await program.account.bounty.fetch(bounty);
    assert.equal(bountyAfterSubmit.submitted, true);
    assert.equal(bountyAfterSubmit.solver.toBase58(), solver.publicKey.toBase58());
    assert.equal(bountyAfterSubmit.solution, "def solve(x): return x * 2");

    const solverBalanceBeforeResolve = await provider.connection.getBalance(solver.publicKey);

    await program.methods
      .resolveSubmission(bountyId, true)
      .accountsPartial({
        buyer: buyer.publicKey,
        bounty,
        solver: solver.publicKey,
      })
      .signers([buyer])
      .rpc();

    const solverBalanceAfterResolve = await provider.connection.getBalance(solver.publicKey);
    assert.equal(solverBalanceAfterResolve - solverBalanceBeforeResolve, PRIZE_LAMPORTS);

    const bountyAfterResolve = await program.account.bounty.fetch(bounty);
    assert.equal(bountyAfterResolve.resolved, true);
  });

  it("keeps the prize locked on FAIL, discards the submission, and allows a retry", async () => {
    const bountyId = RUN_ID.addn(1);
    const bounty = await createBounty(bountyId);

    await submitSolution(bountyId, bounty, "def solve(x): return x - 1  # wrong");

    const bountyPdaBalanceBeforeResolve = await provider.connection.getBalance(bounty);

    await program.methods
      .resolveSubmission(bountyId, false)
      .accountsPartial({
        buyer: buyer.publicKey,
        bounty,
        solver: solver.publicKey,
      })
      .signers([buyer])
      .rpc();

    const bountyPdaBalanceAfterResolve = await provider.connection.getBalance(bounty);
    assert.equal(bountyPdaBalanceAfterResolve, bountyPdaBalanceBeforeResolve);

    const bountyAfterFail = await program.account.bounty.fetch(bounty);
    assert.equal(bountyAfterFail.submitted, false);
    assert.equal(bountyAfterFail.resolved, false);
    assert.isNull(bountyAfterFail.solver);
    assert.equal(bountyAfterFail.solution, "");

    await submitSolution(bountyId, bounty, "def solve(x): return x + 1  # correct this time");

    const bountyAfterRetry = await program.account.bounty.fetch(bounty);
    assert.equal(bountyAfterRetry.submitted, true);
    assert.equal(bountyAfterRetry.solution, "def solve(x): return x + 1  # correct this time");
  });

  const SMALL_PRIZE_LAMPORTS = 0.01 * anchor.web3.LAMPORTS_PER_SOL; // cancel tests only exercise the deadline logic, not money amounts — no need to lock a full SOL

  it("refuses to cancel a bounty before its deadline has passed", async () => {
    const bountyId = RUN_ID.addn(2);
    const bounty = await createBounty(bountyId, 3600, SMALL_PRIZE_LAMPORTS); // default 1-hour deadline, still in the future

    try {
      await program.methods
        .cancelExpiredBounty(bountyId)
        .accountsPartial({ buyer: buyer.publicKey, bounty })
        .signers([buyer])
        .rpc();
      assert.fail("expected cancel_expired_bounty to reject an unexpired bounty");
    } catch (err) {
      assert.include(err.toString(), "NotExpiredYet");
    }
  });

  it("refunds prize + rent to the buyer once an unsubmitted bounty expires", async () => {
    const bountyId = RUN_ID.addn(3);
    const bounty = await createBounty(bountyId, 2, SMALL_PRIZE_LAMPORTS); // expires in 2 seconds, nobody submits

    // Poll the on-chain clock past the deadline instead of a fixed wall-clock sleep.
    const created = await program.account.bounty.fetch(bounty);
    await waitUntilOnChainTime(created.deadline.toNumber());

    const buyerBalanceBeforeCancel = await provider.connection.getBalance(buyer.publicKey);
    const bountyBalanceBeforeCancel = await provider.connection.getBalance(bounty);

    const sig = await program.methods
      .cancelExpiredBounty(bountyId)
      .accountsPartial({ buyer: buyer.publicKey, bounty })
      .signers([buyer])
      .rpc();
    await provider.connection.confirmTransaction(sig, "confirmed");

    const buyerBalanceAfterCancel = await provider.connection.getBalance(buyer.publicKey);
    // Buyer recovers the full bounty account balance (prize + rent reserve),
    // minus the transaction fee this cancel instruction itself cost.
    assert.isAbove(buyerBalanceAfterCancel, buyerBalanceBeforeCancel + bountyBalanceBeforeCancel - 20_000);

    const closedAccount = await provider.connection.getAccountInfo(bounty);
    assert.isNull(closedAccount, "bounty account should be closed after cancellation");
  });
});
