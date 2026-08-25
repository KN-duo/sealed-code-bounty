import { Clock, Target, User } from "lucide-react";
import type { Bounty } from "../../lib/types";
import { Card, SolAmount } from "../ui/atoms";
import { Countdown } from "../ui/Countdown";
import { StatusPill } from "./StatusPill";
import { Link } from "../../router";
import { truncate } from "../../lib/format";

export function BountyCard({ bounty }: { bounty: Bounty }) {
  const attempts = bounty.submission ? 1 : 0;
  return (
    <Link to={`/bounty/${bounty.pda}`} className="bountycard-link">
      <Card className="bountycard">
        <div className="spread">
          <StatusPill status={bounty.status} />
          <span className="mono faint" title={bounty.bountyId.toString()}>
            #{bounty.bountyId.toString()}
          </span>
        </div>

        <div className="bountycard-prize">
          <SolAmount lamports={bounty.prizeLamports} />
          <span className="faint" style={{ fontSize: 12 }}>
            prize pool
          </span>
        </div>

        <div className="bountycard-meta">
          <div className="row">
            <Clock size={14} className="dim" />
            {bounty.status === "open" ? (
              <Countdown deadline={bounty.deadline} />
            ) : (
              <span className="dim">—</span>
            )}
          </div>
          <div className="row">
            <User size={14} className="dim" />
            <span className="mono dim">{truncate(bounty.buyer)}</span>
          </div>
          <div className="row">
            <Target size={14} className="dim" />
            <span className="dim">
              {attempts} attempt{attempts === 1 ? "" : "s"}
            </span>
          </div>
        </div>
      </Card>
    </Link>
  );
}
