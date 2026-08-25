import { CLUSTER, CLUSTER_META, RPC_URL } from "../../env";
import { Pill } from "../ui/atoms";

// Always-visible network indicator so a user never acts on the wrong cluster.
export function ClusterBadge() {
  const meta = CLUSTER_META[CLUSTER];
  return (
    <span title={RPC_URL}>
      <Pill color={meta.color}>{meta.label}</Pill>
    </span>
  );
}
