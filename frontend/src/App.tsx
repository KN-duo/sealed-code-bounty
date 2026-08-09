import { useState } from "react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { WalletContextProvider } from "./providers/WalletContextProvider";
import { CreateBountyForm } from "./components/CreateBountyForm";
import { SubmitSolutionForm } from "./components/SubmitSolutionForm";
import { BountyStatus } from "./components/BountyStatus";

function AppInner() {
  const [lastBuyer, setLastBuyer] = useState<string | undefined>(undefined);
  const [lastBountyId, setLastBountyId] = useState<string | undefined>(undefined);

  return (
    <div style={{ maxWidth: 960, margin: "0 auto", padding: 24, fontFamily: "sans-serif" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h1>SealedCodeBounty</h1>
        <WalletMultiButton />
      </header>
      <p>
        Devnet only. Program: <code>FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V</code>
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 32, marginTop: 24 }}>
        <CreateBountyForm
          onCreated={(buyer, bountyId) => {
            setLastBuyer(buyer);
            setLastBountyId(bountyId);
          }}
        />
        <SubmitSolutionForm />
      </div>

      <div style={{ marginTop: 32 }}>
        <BountyStatus buyerAddress={lastBuyer} bountyId={lastBountyId} />
      </div>
    </div>
  );
}

export default function App() {
  return (
    <WalletContextProvider>
      <AppInner />
    </WalletContextProvider>
  );
}
