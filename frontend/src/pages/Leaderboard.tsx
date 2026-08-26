import { useMemo } from "react";
import { Award, Droplet, Trophy } from "lucide-react";
import { useReceipts } from "../hooks/useData";
import { AsyncView } from "../components/ui/states";
import { Card, Mono } from "../components/ui/atoms";
import { HashBadge } from "../components/ui/HashBadge";
import { explorerAddressUrl, formatDate, truncate } from "../lib/format";
import type { Receipt } from "../lib/types";

interface Row {
  solver: string;
  wins: number;
  firstBloods: number;
  lastWin: number;
}

function aggregate(receipts: Receipt[]): Row[] {
  const bySolver = new Map<string, Row>();
  for (const r of receipts) {
    const row = bySolver.get(r.solver) ?? {
      solver: r.solver,
      wins: 0,
      firstBloods: 0,
      lastWin: 0,
    };
    row.wins += 1;
    if (r.firstBlood) row.firstBloods += 1;
    row.lastWin = Math.max(row.lastWin, r.timestamp);
    bySolver.set(r.solver, row);
  }
  return [...bySolver.values()].sort(
    (a, b) => b.wins - a.wins || b.firstBloods - a.firstBloods || b.lastWin - a.lastWin,
  );
}

const MEDAL = ["#ffd166", "#c7d0dc", "#e08a5b"]; // gold / silver / bronze

export function Leaderboard() {
  const { state, reload } = useReceipts();

  const view = useMemo(() => {
    if (state.kind !== "success") return null;
    return aggregate(state.data);
  }, [state]);

  return (
    <div className="stack" style={{ gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 26 }} className="row">
          <Trophy size={24} color="var(--accent-amber)" /> Leaderboard
        </h1>
        <p className="dim" style={{ margin: "4px 0 0" }}>
          A provable track record — every win is an on-chain Receipt, minted the moment an
          exploit passes verification.
        </p>
      </div>

      <AsyncView
        state={state}
        onRetry={reload}
        loadingVariant="list"
        emptyTitle="No winners yet"
        emptyMessage="No bounty has been won here so far. The first hunter to break one lands at the top with a permanent, verifiable trophy."
      >
        {() => (
          <Card>
            {/* the ranked table is wider than a 640-768px viewport, so let it
                scroll inside its own card rather than clip or widen the page */}
            <div style={{ overflowX: "auto" }}>
              <table className="lb">
              <thead>
                <tr>
                  <th style={{ width: 60 }}>Rank</th>
                  <th>Hunter</th>
                  <th className="num">Wins</th>
                  <th className="num">First bloods</th>
                  <th className="num">Last win</th>
                </tr>
              </thead>
              <tbody>
                {view!.map((row, i) => (
                  <tr key={row.solver}>
                    <td>
                      <span
                        className="lb-rank"
                        style={{ color: i < 3 ? MEDAL[i] : "var(--text-faint)" }}
                      >
                        {i < 3 ? <Award size={16} /> : null}#{i + 1}
                      </span>
                    </td>
                    <td>
                      <div className="row" style={{ gap: 8 }}>
                        <HashBadge value={row.solver} title={row.solver} href={explorerAddressUrl(row.solver)} />
                        <span className="faint mono lb-hide-sm">{truncate(row.solver, 4, 4)}</span>
                      </div>
                    </td>
                    <td className="num mono">{row.wins}</td>
                    <td className="num">
                      {row.firstBloods > 0 ? (
                        <span className="row" style={{ justifyContent: "flex-end", gap: 5 }}>
                          <Droplet size={13} color="var(--accent-red)" />
                          <Mono>{row.firstBloods}</Mono>
                        </span>
                      ) : (
                        <span className="faint mono">0</span>
                      )}
                    </td>
                    <td className="num mono faint">{formatDate(row.lastWin)}</td>
                  </tr>
                ))}
              </tbody>
              </table>
            </div>
          </Card>
        )}
      </AsyncView>
    </div>
  );
}
