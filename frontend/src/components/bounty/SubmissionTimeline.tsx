import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import type { Bounty } from "../../lib/types";
import { HashBadge } from "../ui/HashBadge";
import { formatDate, truncate } from "../../lib/format";

interface Step {
  key: string;
  label: string;
  detail?: ReactNode;
  state: "done" | "active" | "pending" | "failed";
}

function buildSteps(bounty: Bounty): Step[] {
  const sub = bounty.submission;
  const created: Step = { key: "created", label: "Bounty opened & escrow funded", state: "done" };

  const submitted: Step = {
    key: "submitted",
    label: sub ? "Exploit submitted (sealed)" : "Awaiting first exploit",
    state: sub ? "done" : bounty.status === "open" ? "active" : "pending",
    detail: sub ? (
      <div className="stack" style={{ gap: 4 }}>
        <span className="dim">
          by <span className="mono">{truncate(sub.solver)}</span> ·{" "}
          {formatDate(sub.submittedAt)}
        </span>
        <span className="row">
          <span className="faint">exploit sha256</span>
          <HashBadge value={sub.exploitSha256} />
        </span>
      </div>
    ) : undefined,
  };

  let verdict: Step;
  if (bounty.status === "resolved") {
    verdict = {
      key: "verdict",
      label: "PASS — prize paid, receipt minted",
      state: "done",
      detail: bounty.winner ? (
        <span className="dim">
          winner <span className="mono">{truncate(bounty.winner)}</span>
        </span>
      ) : undefined,
    };
  } else if (bounty.status === "cancelled") {
    verdict = { key: "verdict", label: "Cancelled — prize refunded to buyer", state: "failed" };
  } else if (bounty.status === "awaitingResolution") {
    verdict = { key: "verdict", label: "Verifier deciding the verdict…", state: "active" };
  } else {
    verdict = { key: "verdict", label: "Verdict", state: "pending" };
  }

  return [created, submitted, verdict];
}

function icon(state: Step["state"]) {
  if (state === "done") return <CheckCircle2 size={18} color="var(--accent-green)" />;
  if (state === "active") return <Loader2 size={18} color="var(--accent-cyan)" className="spin" />;
  if (state === "failed") return <XCircle size={18} color="var(--text-faint)" />;
  return <Circle size={18} color="var(--text-faint)" />;
}

export function SubmissionTimeline({ bounty }: { bounty: Bounty }) {
  const steps = buildSteps(bounty);
  return (
    <div className="timeline">
      {steps.map((s) => (
        <div key={s.key} className={`timeline-step timeline-${s.state}`}>
          <div className="timeline-icon">{icon(s.state)}</div>
          <div className="stack" style={{ gap: 4 }}>
            <span className="timeline-label">{s.label}</span>
            {s.detail}
          </div>
        </div>
      ))}
    </div>
  );
}
