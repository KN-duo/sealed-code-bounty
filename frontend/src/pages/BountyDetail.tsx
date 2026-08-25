import { EmptyState } from "../components/ui/states";

// Placeholder — implemented in M2.
export function BountyDetail({ pda }: { pda: string }) {
  return <EmptyState title="Bounty detail" message={`Under construction for ${pda}.`} />;
}
