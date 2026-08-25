import { useEffect, useState } from "react";
import { nowUnix } from "../lib/format";

// Ticks once per second so countdowns stay live without each component wiring
// its own interval. Returns the current unix time in seconds.
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(nowUnix);
  useEffect(() => {
    const id = window.setInterval(() => setNow(nowUnix()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}
