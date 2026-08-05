import { useState } from "react";
import * as anchor from "@anchor-lang/core";
import { useProgram, bountyPda } from "./useProgram";

export function SubmitSolutionForm() {
  const program = useProgram();
  const [buyerAddress, setBuyerAddress] = useState("");
  const [bountyId, setBountyId] = useState("");
  const [solution, setSolution] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!program) return;
    setBusy(true);
    setStatus(null);
    try {
      const buyer = new anchor.web3.PublicKey(buyerAddress);
      const id = new anchor.BN(bountyId);
      const bounty = bountyPda(buyer, id);
      const solver = program.provider.publicKey!;

      // NOTE: stored as plaintext right now — the whole point of this
      // project is to fix that (see README's confidentiality roadmap).
      // Don't submit anything you actually need kept private yet.
      await program.methods
        .submitSolution(id, solution)
        .accountsPartial({ solver, bounty, buyer, systemProgram: anchor.web3.SystemProgram.programId })
        .rpc();

      setStatus("Solution submitted.");
    } catch (err) {
      setStatus(`Failed: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: "grid", gap: 8, maxWidth: 480 }}>
      <h2>Submit a solution</h2>
      <p style={{ color: "#b45309" }}>
        ⚠ Not confidential yet — solutions are currently stored in plaintext on-chain (see README).
      </p>
      <label>
        Bounty buyer address
        <input value={buyerAddress} onChange={(e) => setBuyerAddress(e.target.value)} required />
      </label>
      <label>
        Bounty ID
        <input value={bountyId} onChange={(e) => setBountyId(e.target.value)} required />
      </label>
      <label>
        Solution
        <textarea value={solution} onChange={(e) => setSolution(e.target.value)} required />
      </label>
      <button type="submit" disabled={!program || busy}>
        {busy ? "Submitting…" : "Submit solution (pays anti-spam fee)"}
      </button>
      {status && <p>{status}</p>}
    </form>
  );
}
