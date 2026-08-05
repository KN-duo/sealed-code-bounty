import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { SealedCodeBounty } from "../target/types/sealed_code_bounty";
import { assert } from "chai";
import * as crypto from "crypto";

describe("sealed-code-bounty", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.sealedCodeBounty as Program<SealedCodeBounty>;

  const buyer = anchor.web3.Keypair.generate();
  const solver = anchor.web3.Keypair.generate();

  const PRIZE_LAMPORTS = anchor.web3.LAMPORTS_PER_SOL;

  function bountyPda(buyerKey: anchor.web3.PublicKey, bountyId: anchor.BN) {
    return anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("bounty"), buyerKey.toBuffer(), bountyId.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];
  }

  async function airdrop(pubkey: anchor.web3.PublicKey, sol: number) {
    const sig = await provider.connection.requestAirdrop(pubkey, sol * anchor.web3.LAMPORTS_PER_SOL);
    await provider.connection.confirmTransaction(sig, "confirmed");
  }

  async function createBounty(bountyId: anchor.BN) {
    const testSuiteHash = crypto.createHash("sha256").update(`suite-${bountyId}`).digest();
    const deadline = new anchor.BN(Math.floor(Date.now() / 1000) + 3600);
    const bounty = bountyPda(buyer.publicKey, bountyId);

    await program.methods
      .createBounty(bountyId, Array.from(testSuiteHash), new anchor.BN(PRIZE_LAMPORTS), deadline)
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
    await airdrop(buyer.publicKey, 5);
    await airdrop(solver.publicKey, 5);
  });

  it("escrows the prize on create, and releases it to the solver on PASS", async () => {
    const bountyId = new anchor.BN(1);
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
    const bountyId = new anchor.BN(2);
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
});
