import { useState } from "react";
import { KeyRound } from "lucide-react";
import { FileDrop } from "../ui/forms";
import { bytesToHex, truncate } from "../../lib/format";
import type { X25519Keypair } from "../../lib/crypto";

// Restore a buyer keypair from a downloaded backup file. Used wherever a key
// might not be in the current session (post wizard, decrypt-reveal flow).
export function RestoreKey({ onRestore }: { onRestore: (json: string) => Promise<X25519Keypair> }) {
  const [error, setError] = useState<string | null>(null);
  const [restored, setRestored] = useState<string | null>(null);

  async function handle(_name: string, contents: string) {
    setError(null);
    try {
      const kp = await onRestore(contents);
      setRestored(bytesToHex(kp.publicKey));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not restore this backup.");
    }
  }

  if (restored) {
    return (
      <div className="row" style={{ color: "var(--accent-green)", gap: 8 }}>
        <KeyRound size={16} /> Key restored · <span className="mono">{truncate(restored)}</span>
      </div>
    );
  }

  return (
    <div className="stack" style={{ gap: 8 }}>
      <FileDrop
        accept="application/json,.json"
        label="Restore from a key backup (.json)"
        onFile={handle}
      />
      {error && <div className="dim" style={{ color: "var(--accent-red)" }}>{error}</div>}
    </div>
  );
}
