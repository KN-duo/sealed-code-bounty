import { formatCountdown, isPast } from "../../lib/format";
import { useNow } from "../../hooks/useCountdown";

// Live monospace countdown to an absolute unix-second deadline.
export function Countdown({ deadline, prefix }: { deadline: number; prefix?: string }) {
  const now = useNow();
  const expired = isPast(deadline, now);
  return (
    <span className="mono" style={{ color: expired ? "var(--text-faint)" : "var(--text)" }}>
      {prefix ? `${prefix} ` : ""}
      {formatCountdown(deadline, now)}
    </span>
  );
}
