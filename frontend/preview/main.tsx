import { createRoot } from "react-dom/client";
import { ShieldHalf } from "lucide-react";
import "../src/theme.css";
import { PublicPreview } from "../src/pages/PublicPreview";

function PreviewApp() {
  return (
    <div className="shell">
      <header className="nav">
        <div className="container nav-inner">
          <div className="brand">
            <ShieldHalf size={22} color="var(--accent-green)" />
            <span>Sealed<span style={{ color: "var(--accent-green)" }}>Code</span>Bounty</span>
          </div>
          <span className="badge" style={{ color: "var(--accent-amber)" }}>PUBLIC PREVIEW</span>
        </div>
      </header>
      <div className="container" style={{ marginTop: 16 }}>
        <div className="configwarn" role="status">
          Preview only · Solana bounty actions and AWS TEE execution are not live.
        </div>
      </div>
      <main className="container" style={{ padding: "28px 20px 80px" }}>
        <PublicPreview />
      </main>
      <footer className="footer">
        <div className="container faint">SealedCodeBounty · Development preview</div>
      </footer>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<PreviewApp />);
