import { useMemo, useState } from "react";
import { useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { Download, Eye, Lock, ShieldAlert, Unlock } from "lucide-react";
import { useBounties, useConfig } from "../hooks/useData";
import { useBuyerKey } from "../hooks/useBuyerKey";
import { useProgram } from "../hooks/useProgram";
import { AsyncView, EmptyState } from "../components/ui/states";
import { Card, Mono, SolAmount } from "../components/ui/atoms";
import { Button } from "../components/ui/Button";
import { HashBadge } from "../components/ui/HashBadge";
import { Countdown } from "../components/ui/Countdown";
import { Modal } from "../components/ui/Modal";
import { StatusPill } from "../components/bounty/StatusPill";
import { RestoreKey } from "../components/buyer/RestoreKey";
import { Link } from "../router";
import { formatDate, isPast } from "../lib/format";
import { cancelExpiredBounty, closeResolvedBounty, txErrorMessage } from "../lib/tx";
import { loadReveal } from "../lib/reveal";
import { useToast } from "../hooks/useToast";
import type { Bounty } from "../lib/types";
import type { X25519Keypair } from "../lib/crypto";
import type { RevealResult } from "../lib/reveal";

export function Manage() {
  const wallet = useWallet();
  const program = useProgram();
  const toast = useToast();
  const { state, reload } = useBounties();
  const config = useConfig();
  const { keypair, restore } = useBuyerKey();
  const [revealFor, setRevealFor] = useState<Bounty | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const mine = wallet.publicKey?.toBase58();
  const unlockDelay =
    config.state.kind === "success" && config.state.data
      ? config.state.data.forceUnlockDelayS
      : null;

  const own = useMemo(() => {
    if (state.kind !== "success" || !mine) return [];
    return state.data.filter((b) => b.buyer === mine);
  }, [state, mine]);

  if (!wallet.publicKey) {
    return (
      <Card style={{ padding: 40, textAlign: "center" }} className="stack">
        <ShieldAlert size={34} className="dim" style={{ margin: "0 auto" }} />
        <h2>Connect a wallet to manage your bounties</h2>
        <div style={{ margin: "0 auto" }}>
          <WalletMultiButton />
        </div>
      </Card>
    );
  }

  async function onCancel(b: Bounty) {
    if (!program || !wallet.publicKey) return;
    setBusyId(b.pda);
    try {
      await cancelExpiredBounty(program, wallet.publicKey, b.bountyId);
      toast.push("Bounty cancelled — prize refunded.", "success");
      reload();
    } catch (e) {
      toast.push(txErrorMessage(e), "error");
    } finally {
      setBusyId(null);
    }
  }

  async function onClose(b: Bounty) {
    if (!program || !wallet.publicKey) return;
    setBusyId(b.pda);
    try {
      await closeResolvedBounty(program, wallet.publicKey, wallet.publicKey, b.bountyId);
      toast.push("Account closed — rent reclaimed.", "success");
      reload();
    } catch (e) {
      toast.push(txErrorMessage(e), "error");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="stack" style={{ gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 26 }}>My bounties</h1>
        <p className="dim" style={{ margin: "4px 0 0" }}>
          Track your posted bounties, cancel expired ones, and decrypt winning exploits.
        </p>
      </div>

      <AsyncView state={state} onRetry={reload}>
        {() =>
          own.length === 0 ? (
            <EmptyState
              title="You haven't posted any bounties"
              message="Post one to see it here."
              action={
                <Link to="/post">
                  <Button variant="primary">Post a bounty</Button>
                </Link>
              }
            />
          ) : (
            <div className="stack" style={{ gap: 14 }}>
              {own.map((b) => {
                const expired = isPast(b.deadline);
                const canCancel = b.status === "open" && expired && !b.submission;
                const unlockAt =
                  b.submission && unlockDelay != null ? b.submission.submittedAt + unlockDelay : null;
                return (
                  <Card key={b.pda} style={{ padding: 18 }} className="managecard">
                    <div className="spread" style={{ flexWrap: "wrap", gap: 10 }}>
                      <div className="row" style={{ gap: 12 }}>
                        <StatusPill status={b.status} />
                        <Mono className="faint">#{b.bountyId.toString()}</Mono>
                        <Link to={`/bounty/${b.pda}`} className="dim" style={{ fontSize: 13 }}>
                          <HashBadge value={b.pda} />
                        </Link>
                      </div>
                      <SolAmount lamports={b.prizeLamports} />
                    </div>

                    <div className="spread" style={{ flexWrap: "wrap", gap: 10, marginTop: 14 }}>
                      <span className="dim" style={{ fontSize: 13 }}>
                        {b.status === "open" &&
                          (expired ? "Deadline passed" : <>closes <Countdown deadline={b.deadline} /></>)}
                        {b.status === "awaitingResolution" && unlockAt && (
                          <>
                            auto-unlock in <Countdown deadline={unlockAt} />
                          </>
                        )}
                        {b.status === "resolved" && (
                          <span className="row" style={{ color: "var(--accent-green)" }}>
                            <Unlock size={14} /> Resolved {formatDate(b.deadline)}
                          </span>
                        )}
                        {b.status === "cancelled" && "Cancelled"}
                      </span>

                      <div className="row" style={{ gap: 8 }}>
                        {canCancel && (
                          <Button
                            variant="danger"
                            size="sm"
                            loading={busyId === b.pda}
                            onClick={() => onCancel(b)}
                          >
                            Cancel &amp; refund
                          </Button>
                        )}
                        {b.status === "resolved" && (
                          <>
                            <Button variant="primary" size="sm" onClick={() => setRevealFor(b)}>
                              <Eye size={14} /> Decrypt exploit
                            </Button>
                            <Button
                              size="sm"
                              loading={busyId === b.pda}
                              onClick={() => onClose(b)}
                            >
                              Reclaim rent
                            </Button>
                          </>
                        )}
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>
          )
        }
      </AsyncView>

      <RevealModal
        bounty={revealFor}
        hasKey={!!keypair}
        onClose={() => setRevealFor(null)}
        onRestore={restore}
        decrypt={async (b) => {
          if (!keypair) throw new Error("No decryption key in this session.");
          return loadReveal(b.pda, keypair);
        }}
      />
    </div>
  );
}

// -- reveal / decrypt modal -----------------------------------------------

function RevealModal({
  bounty,
  hasKey,
  onClose,
  onRestore,
  decrypt,
}: {
  bounty: Bounty | null;
  hasKey: boolean;
  onClose: () => void;
  onRestore: (json: string) => Promise<X25519Keypair>;
  decrypt: (b: Bounty) => Promise<RevealResult>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [plaintext, setPlaintext] = useState<string | null>(null);

  function reset() {
    setBusy(false);
    setError(null);
    setPlaintext(null);
    onClose();
  }

  async function run() {
    if (!bounty) return;
    setError(null);
    setBusy(true);
    try {
      const res = await decrypt(bounty);
      setPlaintext(new TextDecoder().decode(res.plaintext));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Decryption failed.");
    } finally {
      setBusy(false);
    }
  }

  function download() {
    if (!plaintext) return;
    const blob = new Blob([plaintext], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "exploit.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <Modal open={!!bounty} title="Decrypt winning exploit" onClose={reset}>
      {!hasKey ? (
        <div className="stack" style={{ gap: 12 }}>
          <div className="row" style={{ color: "var(--accent-amber)" }}>
            <Lock size={16} /> Your decryption key isn't in this session. Restore its backup.
          </div>
          <RestoreKey onRestore={onRestore} />
        </div>
      ) : plaintext ? (
        <div className="stack" style={{ gap: 12 }}>
          <div className="row" style={{ color: "var(--accent-green)" }}>
            <Unlock size={16} /> Decrypted successfully.
          </div>
          <pre className="rawjson mono" style={{ maxHeight: 320 }}>
            {plaintext}
          </pre>
          <Button variant="primary" onClick={download}>
            <Download size={15} /> Download exploit
          </Button>
        </div>
      ) : (
        <div className="stack" style={{ gap: 12 }}>
          <p className="dim" style={{ margin: 0 }}>
            The exploit is sealed to your key. It's decrypted locally in your browser — it never
            leaves this device.
          </p>
          {error && <div style={{ color: "var(--accent-red)" }}>{error}</div>}
          <Button variant="primary" loading={busy} onClick={run}>
            Decrypt now
          </Button>
        </div>
      )}
    </Modal>
  );
}
