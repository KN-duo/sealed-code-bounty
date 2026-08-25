import { useMemo, useState } from "react";
import { Plus } from "lucide-react";
import { useBounties } from "../hooks/useData";
import { AsyncView, EmptyState } from "../components/ui/states";
import { BountyCard } from "../components/bounty/BountyCard";
import { Button } from "../components/ui/Button";
import { Link } from "../router";
import { STATUS_META } from "../lib/types";
import type { Bounty, BountyStatusKind } from "../lib/types";

type Filter = "all" | BountyStatusKind;
const FILTERS: { key: Filter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "open", label: "Open" },
  { key: "awaitingResolution", label: "Verifying" },
  { key: "resolved", label: "Resolved" },
  { key: "cancelled", label: "Cancelled" },
];

function sortBounties(list: Bounty[]): Bounty[] {
  // Open first, then by soonest deadline; resolved/cancelled sink to the bottom.
  const rank: Record<BountyStatusKind, number> = {
    open: 0,
    awaitingResolution: 1,
    resolved: 2,
    cancelled: 3,
  };
  return [...list].sort((a, b) => rank[a.status] - rank[b.status] || a.deadline - b.deadline);
}

export function Board() {
  const { state, reload } = useBounties();
  const [filter, setFilter] = useState<Filter>("all");

  const counts = useMemo(() => {
    if (state.kind !== "success") return null;
    const c: Record<string, number> = { all: state.data.length };
    for (const b of state.data) c[b.status] = (c[b.status] ?? 0) + 1;
    return c;
  }, [state]);

  return (
    <div className="stack" style={{ gap: 22 }}>
      <div className="spread" style={{ flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1 style={{ fontSize: 26 }}>Bounty board</h1>
          <p className="dim" style={{ margin: "4px 0 0" }}>
            Break the target, capture the flag, claim the pot.
          </p>
        </div>
        <Link to="/post">
          <Button variant="primary">
            <Plus size={16} /> Post a bounty
          </Button>
        </Link>
      </div>

      <div className="filterbar">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            className={`chip ${filter === f.key ? "chip-active" : ""}`.trim()}
            onClick={() => setFilter(f.key)}
          >
            {f.label}
            {counts && counts[f.key] != null && <span className="chip-count">{counts[f.key]}</span>}
          </button>
        ))}
      </div>

      <AsyncView
        state={state}
        onRetry={reload}
        emptyTitle="No bounties yet"
        emptyMessage="Be the first to post one — connect a wallet and open a bounty against your target."
      >
        {(bounties) => {
          const filtered = sortBounties(
            filter === "all" ? bounties : bounties.filter((b) => b.status === filter),
          );
          if (filtered.length === 0) {
            return (
              <EmptyState
                title={`No ${STATUS_META[filter as BountyStatusKind]?.label.toLowerCase() ?? ""} bounties`}
                message="Try a different filter."
              />
            );
          }
          return (
            <div className="grid-cards">
              {filtered.map((b) => (
                <BountyCard key={b.pda} bounty={b} />
              ))}
            </div>
          );
        }}
      </AsyncView>
    </div>
  );
}
