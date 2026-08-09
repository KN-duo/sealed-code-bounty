import { useState } from "react";
import * as anchor from "@anchor-lang/core";
import { useProgram } from "../hooks/useProgram";
import { bountyPda } from "../lib/pda";

export function CreateBountyForm({ onCreated }: { onCreated: (buyer: string, bountyId: string) => void }) {
  const program = useProgram();
  const [description, setDescription] = useState("");
  const [prizeSol, setPrizeSol] = useState("0.05");
  const [hours, setHours] = useState("1");
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!program) return;
    setBusy(true);
    setStatus(null);
    try {
      const bountyId = new anchor.BN(Date.now());
      // The test suite / requirements text itself is public; we only commit
      // to its hash on-chain so it can't be silently swapped after solvers
      // start submitting against it.
      const testSuiteHash = await sha256(description);
      const deadline = new anchor.BN(Math.floor(Date.now() / 1000) + Number(hours) * 3600);
      const prizeLamports = new anchor.BN(Math.round(Number(prizeSol) * anchor.web3.LAMPORTS_PER_SOL));
      const buyer = program.provider.publicKey!;
      const bounty = bountyPda(buyer, bountyId);

      await program.methods
        .createBounty(bountyId, Array.from(testSuiteHash), prizeLamports, deadline)
        .accountsPartial({ buyer, bounty, systemProgram: anchor.web3.SystemProgram.programId })
        .rpc();

      setStatus(`Bounty created — id ${bountyId.toString()}`);
      onCreated(buyer.toBase58(), bountyId.toString());
    } catch (err) {
      setStatus(`Failed: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: "grid", gap: 8, maxWidth: 480 }}>
      <h2>Post a bounty</h2>
      <label>
        Requirements / test description (only its hash goes on-chain)
        <textarea value={description} onChange={(e) => setDescription(e.target.value)} required />
      </label>
      <label>
        Prize (SOL)
        <input type="number" step="0.001" min="0.001" value={prizeSol} onChange={(e) => setPrizeSol(e.target.value)} required />
      </label>
      <label>
        Deadline (hours from now)
        <input type="number" min="1" value={hours} onChange={(e) => setHours(e.target.value)} required />
      </label>
      <button type="submit" disabled={!program || busy}>
        {busy ? "Submitting…" : "Create bounty"}
      </button>
      {status && <p>{status}</p>}
    </form>
  );
}

async function sha256(text: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}
