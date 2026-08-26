import { useState } from "react";
import type { ReactNode } from "react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { AlertTriangle, ShieldHalf, X } from "lucide-react";
import { CLUSTER, ENCLAVE_URL, RPC_URL } from "../../env";
import { Link } from "../../router";
import { useHashPath } from "../../router/core";
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

const LOOPBACK = /127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0/i;
const ABSOLUTE_LOOPBACK = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)/i;

// Warns once per session when the runtime config cannot be right: a public
// cluster paired with loopback endpoints. Coherent configs render nothing.
function ConfigWarning() {
  const [dismissed, setDismissed] = useState(false);
  if (dismissed || (CLUSTER !== "devnet" && CLUSTER !== "mainnet")) return null;

  const problems: string[] = [];
  if (LOOPBACK.test(RPC_URL)) {
    problems.push(
      `VITE_RPC_URL points at ${RPC_URL} but the cluster is ${CLUSTER} — set it to a public ${CLUSTER} RPC endpoint.`,
    );
  }
  if (ABSOLUTE_LOOPBACK.test(ENCLAVE_URL)) {
    problems.push(
      `VITE_ENCLAVE_URL points at ${ENCLAVE_URL} but the cluster is ${CLUSTER} — set it to the hosted enclave URL.`,
    );
  }
  if (problems.length === 0) return null;

  return (
    <div className="container" style={{ marginTop: 16 }}>
      <div className="configwarn" role="alert">
        <AlertTriangle size={16} style={{ flexShrink: 0 }} />
        <span style={{ flex: 1 }}>
          Configuration looks wrong for <strong>{CLUSTER}</strong>. {problems.join(" ")}
        </span>
        <button
          type="button"
          className="configwarn-close"
          aria-label="Dismiss configuration warning"
          onClick={() => setDismissed(true)}
        >
          <X size={14} />
        </button>
      </div>
    </div>
  );
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
          <div className="row nav-right">
            <ClusterBadge />
            <WalletMultiButton />
          </div>
        </div>
      </header>

      <ConfigWarning />

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
