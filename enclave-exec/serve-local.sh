#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Bring up the FULL backend and LEAVE IT RUNNING so you can drive the whole flow
# from the website: validator + real enclave + relayer + one open bounty. Then
# run the frontend in another terminal and hunt the bounty in your browser.
#
# Unlike localnet-real.sh (which submits an exploit itself and exits), this seeds
# an open bounty and waits — you do the hunting through the UI.
#
# Prereqs: the same as localnet-real.sh (anchor build; enclave-exec/build.sh;
# npm installs for relayer/cli/enclave-exec; cli built).
#
#   bash enclave-exec/serve-local.sh          # keep this running
#   # then in another terminal:
#   npm --prefix frontend run dev             # open http://localhost:5173
#
# It writes frontend/.env.local so the site points at this localnet + enclave.
# Ctrl-C here tears everything down.
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PROGRAM_ID="FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V"
export RPC_URL="http://127.0.0.1:8899"
ENCLAVE_PORT=8443
PRIZE_LAMPORTS=2000000000  # 2 SOL
BOND_LAMPORTS=10000000
MANIFEST_HEX=$(printf '02%.0s' $(seq 32))
ENV_HASH_HEX=$(printf '03%.0s' $(seq 32))
BUYER_ENC_SECRET_HEX=$(printf 'ab%.0s' $(seq 32))

WORK="$(mktemp -d /tmp/scb-serve.XXXXXX)"
PIDS=()
cleanup() { echo; echo "tearing down…"; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

for pat in solana-test-validator agave-validator enclave.cjs "relayer run start"; do
  for pid in $(pgrep -f "$pat" 2>/dev/null || true); do [ "$pid" = "$$" ] || kill -9 "$pid" 2>/dev/null || true; done
done

command -v docker >/dev/null || die "docker not found"
docker image inspect scb-target >/dev/null 2>&1 || die "run: bash enclave-exec/build.sh"
[ -f cli/dist/scb-submit.js ] || die "run: npm --prefix cli run build"
[ -d enclave-exec/node_modules/@ardrive ] || die "run: npm --prefix enclave-exec install"

say "boot validator + program"
if [ -f target/deploy/sealed_code_bounty-keypair.json ]; then
  PROGRAM_ID=$(solana-keygen pubkey target/deploy/sealed_code_bounty-keypair.json); export PROGRAM_ID
fi
solana-test-validator --bpf-program "$PROGRAM_ID" target/deploy/sealed_code_bounty.so \
  --ledger "$WORK/ledger" --reset >"$WORK/validator.log" 2>&1 &
PIDS+=("$!")
for i in $(seq 1 40); do solana cluster-version --url "$RPC_URL" >/dev/null 2>&1 && break; [ "$i" = 40 ] && die "validator did not boot"; sleep 0.5; done

say "keys + airdrops"
for name in buyer funder operator; do
  solana-keygen new --no-bip39-passphrase --silent -o "$WORK/$name.json" >/dev/null 2>&1
  solana-keygen pubkey "$WORK/$name.json" > "$WORK/$name.pub"
done
BUYER_PUB=$(cat "$WORK/buyer.pub"); OPERATOR_PUB=$(cat "$WORK/operator.pub")
for name in buyer funder; do solana airdrop 10 "$(cat "$WORK/$name.pub")" --url "$RPC_URL" >/dev/null 2>&1 || true; done
# Fund the wallet you'll connect in the browser, if you pass one.
YOUR_WALLET="${1:-}"
if [ -n "$YOUR_WALLET" ]; then
  solana airdrop 10 "$YOUR_WALLET" --url "$RPC_URL" >/dev/null 2>&1 || true
  echo "airdropped 10 SOL to your wallet $YOUR_WALLET"
fi

say "start real-execution enclave (Arweave delivery)"
SCB_MASTER_SECRET_HEX=$(openssl rand -hex 32) \
SCB_ENCLAVE_ENC_SECRET_HEX=$(openssl rand -hex 32) \
SCB_OPERATOR_KEYPAIR="$WORK/operator.json" \
SCB_REVEAL_STORE="${SCB_REVEAL_STORE:-arweave}" \
PORT="$ENCLAVE_PORT" node enclave-exec/enclave.cjs >"$WORK/enclave.log" 2>&1 &
PIDS+=("$!")
for i in $(seq 1 30); do curl -s "http://127.0.0.1:$ENCLAVE_PORT/internal/healthz" >/dev/null 2>&1 && break; [ "$i" = 30 ] && die "enclave did not start ($WORK/enclave.log)"; sleep 0.3; done
ENC_PK_HEX=$(curl -s "http://127.0.0.1:$ENCLAVE_PORT/internal/enclave-pubkey" | python3 -c "import json,sys; print(json.load(sys.stdin)['enclave_enc_pk'])")

say "init-config + arm operator"
node e2e/chain.mjs init-config "$WORK/funder.json" "$OPERATOR_PUB" "$ENC_PK_HEX" "$BOND_LAMPORTS" >/dev/null
node e2e/chain.mjs arm-operators "$WORK/funder.json" "$OPERATOR_PUB" "$ENC_PK_HEX" 1 3600 >/dev/null
BUYER_ENC_PK_HEX=$(node e2e/x25519-pub.mjs "$BUYER_ENC_SECRET_HEX")

say "seed one open bounty (ret2win, 2 SOL)"
CUR_ID=101
PDA_B58=$(node -e "
function dep(n){for(const b of ['relayer','frontend','cli','.']){try{return require('$ROOT/'+b+'/node_modules/'+n);}catch(e){}}return require(n);}
const web3=dep('@solana/web3.js');
const idBuf=Buffer.alloc(8); idBuf.writeBigUInt64LE(BigInt('$CUR_ID'));
console.log(web3.PublicKey.findProgramAddressSync([Buffer.from('bounty'),new web3.PublicKey('$BUYER_PUB').toBuffer(),idBuf],new web3.PublicKey('$PROGRAM_ID'))[0].toBase58());")
FLAG_COMMITMENT_HEX=$(curl -s -X POST "http://127.0.0.1:$ENCLAVE_PORT/internal/seal_bounty" -H 'content-type: application/json' -d "{\"bounty_pda\":\"$PDA_B58\"}" | python3 -c "import json,sys; print(json.load(sys.stdin)['flag_commitment'])")
node e2e/chain.mjs create-bounty "$WORK/buyer.json" "$CUR_ID" "$PRIZE_LAMPORTS" 86400 \
  "$MANIFEST_HEX" "$ENV_HASH_HEX" "$FLAG_COMMITMENT_HEX" "$BUYER_ENC_PK_HEX" >/dev/null

say "start relayer -> real enclave"
RPC_URL="$RPC_URL" PROGRAM_ID="$PROGRAM_ID" FEE_PAYER_KEYPAIR_PATH="$WORK/funder.json" \
OPERATOR_PUBKEY="$OPERATOR_PUB" ENCLAVE_URL="http://127.0.0.1:$ENCLAVE_PORT" POLL_INTERVAL_MS=800 \
npm --prefix relayer run start >"$WORK/relayer.log" 2>&1 &
PIDS+=("$!")

say "start workspace service (per-bounty practice VMs)"
if docker image inspect scb-workspace >/dev/null 2>&1; then
  SCB_WORKSPACE_PORT=8080 node enclave-exec/workspace-service.mjs >"$WORK/workspace.log" 2>&1 &
  PIDS+=("$!")
  echo "workspace service on :8080"
else
  echo "! scb-workspace image missing — 'Open test environment' will be unavailable."
  echo "  build it: bash enclave-exec/build.sh"
fi

# --- point the frontend at this backend -----------------------------------
cat > frontend/.env.local <<EOF
# Written by enclave-exec/serve-local.sh — points the site at this localnet + enclave.
VITE_RPC_URL=$RPC_URL
VITE_PROGRAM_ID=$PROGRAM_ID
EOF

cat <<EOF

$(printf '\033[1;32m')backend up — leave this running$(printf '\033[0m')

  bounty (open):   $PDA_B58
  hunt it here:    http://localhost:5173/#/hunt/$PDA_B58
  program:         $PROGRAM_ID
  enclave:         http://127.0.0.1:$ENCLAVE_PORT  (proxied as /enclave by vite)
  logs:            $WORK/{validator,enclave,relayer}.log

next, in ANOTHER terminal:
  npm --prefix frontend run dev        # then open http://localhost:5173

in the browser:
  1. connect Backpack (custom RPC http://127.0.0.1:8899; the script airdropped
     to your wallet if you passed it: bash enclave-exec/serve-local.sh <pubkey>)
  2. open the hunt link above, drop enclave-exec/solve-compact.py (or
     examples/ret2win/solution/solve.py), and submit
  3. watch it resolve to a win; check the leaderboard and the bounty page

Ctrl-C here tears the backend down.
EOF

# keep running until interrupted
while true; do sleep 3600; done
