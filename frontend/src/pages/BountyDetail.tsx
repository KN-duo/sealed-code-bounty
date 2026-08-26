import { useState } from "react";
import type { ReactNode } from "react";
import { ArrowLeft, Code2, Crosshair, Download } from "lucide-react";
import { useBounty } from "../hooks/useData";
import { AsyncView } from "../components/ui/states";
import { Card, Mono, SolAmount, StatBadge } from "../components/ui/atoms";
import { HashBadge } from "../components/ui/HashBadge";
import { Countdown } from "../components/ui/Countdown";
import { Button } from "../components/ui/Button";
import { StatusPill } from "../components/bounty/StatusPill";
import { SubmissionTimeline } from "../components/bounty/SubmissionTimeline";
import { Link } from "../router";
import { explorerAddressUrl, formatDate } from "../lib/format";
import type { Bounty } from "../lib/types";

// A single on-chain fact with a plain-language explanation so a first-timer
// understands what the hash actually commits to.
function Fact({ label, help, children }: { label: string; help: string; children: ReactNode }) {
  return (
    <div className="fact">
      <div className="fact-label">{label}</div>
      <div className="fact-value">{children}</div>
      <div className="fact-help">{help}</div>
    </div>
  );
}

const PRACTICE_EXPLOIT = `#!/usr/bin/env python3
# Practice exploit template for a SealedCodeBounty target.
# Your job: capture the secret flag from the running target, then print it.
# The verifier runs this in an isolated enclave and checks the captured flag
# against the bounty's flag_commitment. Nothing you submit is ever revealed
# on FAIL.

import sys

def exploit() -> str:
    # TODO: interact with the target (tcp service or binary) and recover the flag.
    raise NotImplementedError("write your exploit")

if __name__ == "__main__":
    flag = exploit()
    print(flag)
    sys.exit(0)
`;

function downloadPractice() {
  const blob = new Blob([PRACTICE_EXPLOIT], { type: "text/x-python" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "exploit_template.py";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function rawJson(b: Bounty): string {
  return JSON.stringify(
    {
      pda: b.pda,
      buyer: b.buyer,
      bountyId: b.bountyId.toString(),
      status: b.status,
      prizeLamports: b.prizeLamports.toString(),
      deadline: b.deadline,
      manifestSha256: b.manifestSha256,
      envBlobSha256: b.envBlobSha256,
      flagCommitment: b.flagCommitment,
      buyerEncPk: b.buyerEncPk,
      submission: b.submission
        ? { ...b.submission, bondLamports: b.submission.bondLamports.toString() }
        : null,
      winner: b.winner,
    },
    null,
    2,
  );
}

export function BountyDetail({ pda }: { pda: string }) {
  const { state, reload } = useBounty(pda);
  const [showRaw, setShowRaw] = useState(false);

  return (
    <div className="stack" style={{ gap: 20 }}>
      <Link to="/" className="row dim backlink">
        <ArrowLeft size={16} /> Back to board
      </Link>

      <AsyncView
        state={state}
        onRetry={reload}
        loadingVariant="detail"
        emptyTitle="Bounty not found"
        emptyMessage="No bounty exists at this address on the current cluster. Double-check the link and cluster, or browse the board for open bounties."
      >
        {(bounty) => (
          <div className="stack" style={{ gap: 20 }}>
            <Card style={{ padding: 24 }}>
              <div className="spread" style={{ flexWrap: "wrap", gap: 12 }}>
                <div className="row" style={{ gap: 12 }}>
                  <StatusPill status={bounty.status} />
                  <Mono className="faint">#{bounty.bountyId.toString()}</Mono>
                </div>
                {bounty.status === "open" && (
                  <Countdown deadline={bounty.deadline} prefix="closes in" />
                )}
              </div>

              <div style={{ margin: "18px 0 20px", fontSize: 34, fontWeight: 700 }}>
                <SolAmount lamports={bounty.prizeLamports} />
              </div>

              <div className="fact-grid">
                <StatBadge label="Deadline" value={<Mono>{formatDate(bounty.deadline)}</Mono>} />
                <StatBadge
                  label="Buyer"
                  value={<HashBadge value={bounty.buyer} href={explorerAddressUrl(bounty.buyer)} />}
                />
                <StatBadge
                  label="Attempts"
                  value={<Mono>{bounty.submission ? 1 : 0}</Mono>}
                />
                <StatBadge
                  label="Address"
                  value={<HashBadge value={bounty.pda} href={explorerAddressUrl(bounty.pda)} />}
                />
              </div>

              {bounty.status === "open" && (
                <div className="row" style={{ marginTop: 22, gap: 10, flexWrap: "wrap" }}>
                  <Link to={`/hunt/${bounty.pda}`}>
                    <Button variant="primary">
                      <Crosshair size={16} /> Break this target
                    </Button>
                  </Link>
                  <Button variant="ghost" onClick={downloadPractice}>
                    <Download size={15} /> Practice template
                  </Button>
                </div>
              )}
            </Card>

            <div className="detail-cols">
              <Card style={{ padding: 22 }}>
                <h3 style={{ marginBottom: 4 }}>The target</h3>
                <p className="dim" style={{ marginTop: 0, fontSize: 13 }}>
                  Everything the enclave verifier pins for this bounty.
                </p>
                <div className="stack" style={{ gap: 16, marginTop: 12 }}>
                  <Fact
                    label="Environment hash"
                    help="SHA-256 of the exact target image the verifier boots. Guarantees the environment can't be swapped after the bounty opens."
                  >
                    <HashBadge value={bounty.envBlobSha256} />
                  </Fact>
                  <Fact
                    label="Manifest hash"
                    help="SHA-256 of the target spec (image, limits, entrypoint, flag placeholder)."
                  >
                    <HashBadge value={bounty.manifestSha256} />
                  </Fact>
                  <Fact
                    label="Flag commitment"
                    help="SHA-256 of the secret flag. Every PASS verdict is checked against this — the flag itself is never on-chain."
                  >
                    <HashBadge value={bounty.flagCommitment} />
                  </Fact>
                  <Fact
                    label="Reveal key"
                    help="Buyer's X25519 public key. A winning exploit is sealed to this key so only the buyer can open it."
                  >
                    <HashBadge value={bounty.buyerEncPk} />
                  </Fact>
                </div>
              </Card>

              <Card style={{ padding: 22 }}>
                <h3 style={{ marginBottom: 14 }}>Progress</h3>
                <SubmissionTimeline bounty={bounty} />
              </Card>
            </div>

            <Card style={{ padding: 18 }}>
              <button className="btn btn-ghost btn-sm" onClick={() => setShowRaw((v) => !v)}>
                <Code2 size={15} /> {showRaw ? "Hide" : "Show"} raw account JSON
              </button>
              {showRaw && (
                <pre className="rawjson mono">{rawJson(bounty)}</pre>
              )}
            </Card>
          </div>
        )}
      </AsyncView>
    </div>
  );
}
