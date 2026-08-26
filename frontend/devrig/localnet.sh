#!/usr/bin/env bash
# Chain half of the local test rig. Run this INSIDE WSL, from the WSL checkout
# (~/sealed-code-bounty), because the Solana/Anchor toolchain only exists there.
#
#   bash frontend/devrig/localnet.sh
#
# It deliberately does only what needs the toolchain: validator + build + deploy.
# Seeding and the mock enclave run natively on Windows against the frontend's own
# node_modules, talking plain JSON-RPC to 127.0.0.1:8899 (WSL2 forwards it).
#
# Leave this running. Ctrl-C stops the validator.

set -euo pipefail

EXPECTED_PROGRAM_ID="FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V"
RPC_URL="http://127.0.0.1:8899"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="$REPO_DIR/frontend/devrig/.validator.log"
cd "$REPO_DIR"

# The toolchain installers put themselves on PATH from .bashrc, which a
# non-interactive shell never reads. Add the standard locations before checking.
for dir in "$HOME/.local/share/solana/install/active_release/bin" "$HOME/.cargo/bin" "$HOME/.avm/bin"; do
  [ -d "$dir" ] && case ":$PATH:" in *":$dir:"*) ;; *) PATH="$dir:$PATH" ;; esac
done
export PATH

for bin in solana solana-test-validator anchor; do
  command -v "$bin" >/dev/null 2>&1 || {
    echo "error: '$bin' is not on PATH, even after adding the usual install dirs." >&2
    echo "       Run this inside WSL, where the Solana/Anchor toolchain lives." >&2
    exit 1
  }
done

# --- validator -------------------------------------------------------------

if curl -fsS -m 2 -X POST -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" >/dev/null 2>&1; then
  echo "==> validator already running at $RPC_URL (not resetting)"
  VALIDATOR_PID=""
else
  echo "==> starting solana-test-validator (--reset), logging to $LOG"
  rm -rf test-ledger
  solana-test-validator --reset --quiet >"$LOG" 2>&1 &
  VALIDATOR_PID=$!
  trap '[ -n "$VALIDATOR_PID" ] && kill "$VALIDATOR_PID" 2>/dev/null || true' EXIT

  printf "    waiting for RPC"
  for _ in $(seq 1 60); do
    if curl -fsS -m 2 -X POST -H 'content-type: application/json' \
         -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" >/dev/null 2>&1; then
      echo " — up"
      break
    fi
    printf "."
    sleep 1
  done
  curl -fsS -m 2 -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" >/dev/null 2>&1 || {
    echo; echo "error: validator never became healthy. Last log lines:" >&2
    tail -20 "$LOG" >&2
    exit 1
  }
fi

solana config set --url "$RPC_URL" >/dev/null

# --- build + deploy --------------------------------------------------------

echo "==> anchor build"
anchor build

echo "==> anchor deploy"
anchor deploy

DEPLOYED_ID="$(solana address -k target/deploy/sealed_code_bounty-keypair.json)"
if [ "$DEPLOYED_ID" != "$EXPECTED_PROGRAM_ID" ]; then
  cat >&2 <<EOF

  !! Deployed program id does not match the one the frontend defaults to.

       deployed: $DEPLOYED_ID
       expected: $EXPECTED_PROGRAM_ID

     Point the frontend at the deployed id before seeding — add this to
     frontend/.env.local (the seed step will otherwise overwrite it):

       VITE_PROGRAM_ID=$DEPLOYED_ID

     and pass the same value through the environment when running the rig:

       VITE_PROGRAM_ID=$DEPLOYED_ID node devrig/rig.mjs seed --wallet <pubkey>

EOF
else
  echo "==> program id matches the frontend default: $DEPLOYED_ID"
fi

# --- IDL sanity -------------------------------------------------------------
# A checkout behind main builds a v1 IDL that looks perfectly valid but names
# submit_solution / resolve_submission. Catch that here rather than three
# confusing steps later.
IDL_JSON="target/idl/sealed_code_bounty.json"
if [ -f "$IDL_JSON" ] && ! grep -q '"submit_exploit"' "$IDL_JSON"; then
  cat >&2 <<EOF

  !! The IDL just built does NOT contain submit_exploit — this looks like the
     stale v1 program (submit_solution / resolve_submission).

     This checkout is probably behind main. Fix it and re-run:

       cd "$REPO_DIR" && git pull --rebase origin main && bash frontend/devrig/localnet.sh

EOF
  exit 1
fi

# --- fresh IDL -------------------------------------------------------------
# frontend/src/idl/* was hand-generated because no real v2 artifact existed. Now
# there is one. Copying is NOT automatic: src/idl/sealed_code_bounty.ts carries a
# DeepMutable<> wrapper the generated file lacks, so it needs a manual merge.
cat <<EOF

==> a real IDL artifact now exists at:
      target/idl/sealed_code_bounty.json
      target/types/sealed_code_bounty.ts

    frontend/src/idl/* is still the hand-generated stand-in. Replacing it is a
    deliberate step — keep the DeepMutable<typeof IDL> wrapper in the .ts file —
    then re-run \`npm run build\` and \`npm run lint\` in frontend/.

==> chain half is up. On the Windows side, in frontend/:

      node devrig/rig.mjs seed --wallet <your-phantom-pubkey>
      node devrig/rig.mjs serve
      npm run dev

EOF

if [ -n "$VALIDATOR_PID" ]; then
  echo "==> validator running as pid $VALIDATOR_PID. Ctrl-C here stops it."
  wait "$VALIDATOR_PID"
fi
