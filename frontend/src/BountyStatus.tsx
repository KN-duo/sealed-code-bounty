import { useState } from "react";
import * as anchor from "@anchor-lang/core";
import { useProgram, bountyPda } from "./useProgram";

interface BountyAccount {
  buyer: anchor.web3.PublicKey;
  bountyId: anchor.BN;
  prizeAmount: anchor.BN;
  deadline: anchor.BN;
  submitted: boolean;
  resolved: boolean;
  solver: anchor.web3.PublicKey | null;
  solution: string;
}

export function BountyStatus({ buyerAddress: initialBuyer, bountyId: initialId }: { buyerAddress?: string; bountyId?: string }) {
  const program = useProgram();
  const [buyerAddress, setBuyerAddress] = useState(initialBuyer ?? "");
  const [bountyId, setBountyId] = useState(initialId ?? "");
  const [bounty, setBounty] = useState<BountyAccount | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  async function refresh() {
    if (!program || !buyerAddress || !bountyId) return;
    try {
      const buyer = new anchor.web3.PublicKey(buyerAddress);
      const id = new anchor.BN(bountyId);
      const bounty = bountyPda(buyer, id);
      const account = (await program.account.bounty.fetch(bounty)) as unknown as BountyAccount;
      setBounty(account);
      setStatus(null);
    } catch (err) {
      setBounty(null);
      setStatus(`Not found / not fetched yet: ${(err as Error).message}`);
    }
  }

  async function resolve(passed: boolean) {
    if (!program) return;
    const buyer = new anchor.web3.PublicKey(buyerAddress);
    const id = new anchor.BN(bountyId);
    const bounty = bountyPda(buyer, id);
    try {
      await program.methods
        .resolveSubmission(id, passed)
        .accountsPartial({ buyer, bounty, solver: bountyState()!.solver! })
        .rpc();
      setStatus(passed ? "Resolved PASS — prize paid out." : "Resolved FAIL — submission discarded.");
      refresh();
    } catch (err) {
      setStatus(`Failed: ${(err as Error).message}`);
    }
  }

  async function cancelExpired() {
    if (!program) return;
    const buyer = new anchor.web3.PublicKey(buyerAddress);
    const id = new anchor.BN(bountyId);
    const bounty = bountyPda(buyer, id);
    try {
      await program.methods.cancelExpiredBounty(id).accountsPartial({ buyer, bounty }).rpc();
      setStatus("Cancelled — prize + rent refunded to buyer.");
      setBounty(null);
    } catch (err) {
      setStatus(`Failed: ${(err as Error).message}`);
    }
  }

  function bountyState() {
    return bounty;
  }

  const isPastDeadline = bounty ? Date.now() / 1000 > bounty.deadline.toNumber() : false;

  return (
    <div style={{ display: "grid", gap: 8, maxWidth: 480 }}>
      <h2>Check a bounty</h2>
      <label>
        Buyer address
        <input value={buyerAddress} onChange={(e) => setBuyerAddress(e.target.value)} />
      </label>
      <label>
        Bounty ID
        <input value={bountyId} onChange={(e) => setBountyId(e.target.value)} />
      </label>
      <button onClick={refresh} disabled={!program}>
        Refresh
      </button>

      {bounty && (
        <div style={{ border: "1px solid #ccc", padding: 12, borderRadius: 6 }}>
          <p>Prize: {bounty.prizeAmount.toNumber() / anchor.web3.LAMPORTS_PER_SOL} SOL</p>
          <p>Deadline: {new Date(bounty.deadline.toNumber() * 1000).toLocaleString()}</p>
          <p>Submitted: {String(bounty.submitted)}</p>
          <p>Resolved: {String(bounty.resolved)}</p>
          {bounty.solver && <p>Solver: {bounty.solver.toBase58()}</p>}
          {bounty.solution && <p>Solution (plaintext for now): {bounty.solution}</p>}

          {!bounty.resolved && bounty.submitted && (
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => resolve(true)}>Resolve PASS (pay solver)</button>
              <button onClick={() => resolve(false)}>Resolve FAIL (discard)</button>
            </div>
          )}
          {!bounty.resolved && !bounty.submitted && isPastDeadline && (
            <button onClick={cancelExpired}>Cancel expired bounty (reclaim funds)</button>
          )}
        </div>
      )}
      {status && <p>{status}</p>}
    </div>
  );
}
