import type { ReactNode } from "react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { ShieldHalf } from "lucide-react";
import { Link, useHashPath } from "../../router";
import { ClusterBadge } from "./ClusterBadge";

const NAV = [
  { to: "/", label: "Board" },
  { to: "/leaderboard", label: "Leaderboard" },
  { to: "/post", label: "Post a bounty" },
  { to: "/manage", label: "Manage" },
];

function isActive(path: string, to: string): boolean {
  if (to === "/") return path === "/" || path.startsWith("/bounty");
  return path === to || path.startsWith(`${to}/`);
}

export function AppShell({ children }: { children: ReactNode }) {
  const path = useHashPath();
  return (
    <div className="shell">
      <header className="nav">
        <div className="container nav-inner">
          <Link to="/" className="brand">
            <ShieldHalf size={22} color="var(--accent-green)" />
            <span>
              Sealed<span style={{ color: "var(--accent-green)" }}>Code</span>Bounty
            </span>
          </Link>
          <nav className="nav-links">
            {NAV.map((n) => (
              <Link
                key={n.to}
                to={n.to}
                className={`nav-link ${isActive(path, n.to) ? "nav-link-active" : ""}`.trim()}
              >
                {n.label}
              </Link>
            ))}
          </nav>
          <div className="row">
            <ClusterBadge />
            <WalletMultiButton />
          </div>
        </div>
      </header>

      <main className="container" style={{ padding: "28px 20px 80px" }}>
        {children}
      </main>

      <footer className="footer">
        <div className="container spread" style={{ flexWrap: "wrap", gap: 8 }}>
          <span className="faint">
            SealedCodeBounty · break the target, claim the pot · verdicts by enclave attestation
          </span>
          <span className="faint mono">v2</span>
        </div>
      </footer>
    </div>
  );
}
