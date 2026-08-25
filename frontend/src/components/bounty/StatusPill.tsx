import { Pill } from "../ui/atoms";
import { STATUS_META } from "../../lib/types";
import type { BountyStatusKind } from "../../lib/types";

export function StatusPill({ status }: { status: BountyStatusKind }) {
  const meta = STATUS_META[status];
  return <Pill color={meta.token}>{meta.label}</Pill>;
}
