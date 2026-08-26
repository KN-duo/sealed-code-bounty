#!/usr/bin/env bash
# Kills leftover e2e processes. Patterns live HERE so the caller's own
# command line never matches them (pkill -f self-match footgun).
pat_val="solana-test-validator"
pat_agave="agave-validator"
pat_mock="mock-enclave.cjs"
pat_relayer="relayer/src/index.js"
pat_localnet="localnet.sh"
for pat in "$pat_val" "$pat_agave"; do
  for pid in $(pgrep -f "$pat" 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    [ "$pid" = "$PPID" ] && continue
    kill -9 "$pid" 2>/dev/null || true
  done
done
for pid in $(pgrep -f "$pat_mock" 2>/dev/null); do
  [ "$pid" = "$$" ] && continue
  kill -9 "$pid" 2>/dev/null || true
done
for pid in $(pgrep -f "$pat_relayer" 2>/dev/null); do
  [ "$pid" = "$$" ] && continue
  kill -9 "$pid" 2>/dev/null || true
done
sleep 0.5
exit 0
