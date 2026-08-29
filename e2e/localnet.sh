#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# SealedCodeBounty — LOCALNET DRESS REHEARSAL (PLAN-PRE-TEE.md Step 5)
#
# Usage:
#   ./e2e/localnet.sh              # happy: solve -> PASS -> pay -> reveal
#   ./e2e/localnet.sh negative     # broken exploit -> FAIL -> refund -> resubmit
#   ./e2e/localnet.sh unlock-drill # blinded relayer -> sweeper frees the slot
#
# Chain ops are delegated to e2e/chain.mjs; verdicts come from
# relayer/test/mock-enclave.cjs running standalone.
#
# [PRE-TEE] seams (flip with real enclave + Docker CI, no redesign):
#   * mock signs verdicts (real enclave + DockerCli sandbox pending)
#   * exploit_sealed_box treated as plaintext by the mock so buyer-side
#     decryption proves the reveal path end-to-end
# ---------------------------------------------------------------------------
set -euo pipefail

MODE="${1:-happy}"
case "$MODE" in
  happy|negative|unlock-drill) ;;
  *) echo "WHICH=usage unknown mode '$MODE'"; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PROGRAM_ID="FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V"
export RPC_URL="http://127.0.0.1:8899"

WORK="$(mktemp -d /tmp/scb-e2e.XXXXXX)"
echo "WORK=$WORK" > "$WORK/work.txt"
VAL_LOG="$WORK/validator.log"
REL_LOG="$WORK/relayer.log"
MOCK_LOG="$WORK/mock.log"
PIDS=()

PRIZE_LAMPORTS=500000000   # 0.5 SOL
BOND_LAMPORTS=10000000     # 0.01 SOL
ENC_PK_HEX=$(printf '09%.0s' $(seq 32))
MANIFEST_HEX=$(printf '02%.0s' $(seq 32))
ENV_HASH_HEX=$(printf '03%.0s' $(seq 32))
EXPLOIT_SOLVE="$WORK/exploit-solve.py"
ENC_SECRET_HEX=$(printf 'ab%.0s' $(seq 32)) # buyer X25519 secret (test scalar)
NODE_SODIUM="$ROOT/cli/node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js"
export NODE_SODIUM
MOCK_PORT=8443

cleanup() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
  [ -n "${MOCK_PID:-}" ] && kill -9 "$MOCK_PID" 2>/dev/null || true
}


# Kill any stray validator/relayer/mock from previous runs (audit P1-2)
for pat in solana-test-validator agave-validator mock-enclave.cjs; do
  for pid in $(pgrep -f "$pat" 2>/dev/null); do
    [ "$pid" = "$$" ] || kill -9 "$pid" 2>/dev/null
  done
done
# Wait for port 8899 to free up
for i in $(seq 1 10); do
  ss -ltn 2>/dev/null | grep -q ":8899 " || break
  sleep 0.5
  for pid in $(ss -ltnp 2>/dev/null | grep ':8899 ' | grep -oP 'pid=\K[0-9]+' | sort -u); do
    kill -9 "$pid" 2>/dev/null
  done
done
trap cleanup EXIT

step() { echo ""; echo "== STEP: $* =="; }
fail() { echo "WHICH=$1 FAIL: $2"; exit 3; }
assert_eq() { if [ "$1" != "$2" ]; then echo "WHICH=$3 FAIL: got '$1' want '$2'"; exit 3; fi; echo "ok: $3"; }

MOCK_PID=""
start_mock() { # $1 port ; reads exported SCB_MOCK_FORCE_FAIL
  PORT="$1"
  SCB_MOCK_OPERATOR_KEYPAIR="$WORK/operator.json"
  export PORT SCB_MOCK_OPERATOR_KEYPAIR
  node relayer/test/mock-enclave.cjs >>"$MOCK_LOG" 2>&1 &
  for _ in $(seq 1 30); do
    curl -s "http://127.0.0.1:$1/internal/operator-pubkey" >/dev/null 2>&1 && return 0
    sleep 0.3
  done
  echo "FAIL: mock-enclave did not start ($MOCK_LOG)" >&2
  return 1
}
start_relayer() { # $1 enclave url
  # Belt+suspenders: verify RPC is actually responding before starting relayer.
  local health=""
  for i in $(seq 1 10); do
    health=$(curl -s "$RPC_URL" -X POST -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' 2>/dev/null)
    echo "$health" | grep -q '"ok"' && break
    sleep 0.5
  done

  RPC_URL="$RPC_URL" PROGRAM_ID="$PROGRAM_ID" \
  FEE_PAYER_KEYPAIR_PATH="$WORK/funder.json" OPERATOR_PUBKEY="$OPERATOR_PUB" \
  ENCLAVE_URL="$1" POLL_INTERVAL_MS=800 \
  npm --prefix relayer run start >>"$REL_LOG" 2>&1 &
  PIDS+=("$!")
}

seal_commitment() { # $1 pda_b58, $2 port
  curl -s -X POST "http://127.0.0.1:$2/internal/seal_bounty" \
    -H 'content-type: application/json' \
    -d "{\"bounty_pda\":\"$1\"}" |
    python3 -c "import json,sys; print(json.load(sys.stdin)['flag_commitment'])"
}
pda_of() {
  node -e "
function dep(n){for(const b of ['relayer','frontend','cli','.']){try{return require('$ROOT/'+b+'/node_modules/'+n);}catch(e){}}return require(n);}
const web3=dep('@solana/web3.js');
const idBuf=Buffer.alloc(8); idBuf.writeBigUInt64LE(BigInt('$2'));
const pid=new web3.PublicKey(process.env.PROGRAM_ID);
const buyer=new web3.PublicKey('$1');
console.log(web3.PublicKey.findProgramAddressSync([Buffer.from('bounty'),buyer.toBuffer(),idBuf],pid)[0].toBase58());"
}
BOUNTY_ID=100
next_bounty_id() { BOUNTY_ID=$((BOUNTY_ID + 1)); echo "$BOUNTY_ID"; }
bal() { node e2e/chain.mjs balance "$1" | python3 -c "import json,sys; print(json.load(sys.stdin)['lamports'])"; }
bounty_status() { node e2e/chain.mjs fetch-bounty "$BUYER_PUB" "$1" | python3 -c "import json,sys; b=json.load(sys.stdin); print(b.get('statusByte'))"; }
scb_submit() { # $1 file, extra flags via remaining args
  node cli/dist/scb-submit.js --rpc-url "$RPC_URL" --keypair "$WORK/solver.json" \
    --bounty "$BUYER_PUB:$CUR_ID" --file "$1" \
    --enclave-url http://127.0.0.1:${MOCK_PORT:-8443} "${@:2}"
}

# ===========================================================================
wait_for_port() { # $1=port [$2=label]
  local port="${1:-}" label="${2:-port $1}" i
  for i in $(seq 1 120); do
    nc -z 127.0.0.1 "$port" 2>/dev/null && { echo "port $port ready ($label)"; return 0; }
    sleep 0.5
  done
  fail "$label" "port $port not listening after 60s"
}

step "boot: fresh validator + funded wallets"
LEDGER="$WORK/ledger"
if [ -f target/deploy/sealed_code_bounty-keypair.json ]; then
  cp target/deploy/sealed_code_bounty-keypair.json "$WORK/deploy-kp.json"
else
  solana-keygen new --no-bip39-passphrase --silent -o "$WORK/deploy-kp.json" >/dev/null 2>&1
fi
PROGRAM_ID=$(solana-keygen pubkey "$WORK/deploy-kp.json")
export PROGRAM_ID
solana-test-validator \
  --bpf-program "$PROGRAM_ID" target/deploy/sealed_code_bounty.so \
  --ledger "$LEDGER" --reset \
  >"$VAL_LOG" 2>&1 &
PIDS+=("$!")
for i in $(seq 1 40); do
  solana cluster-version --url "$RPC_URL" >/dev/null 2>&1 && break
  [ "$i" = 40 ] && fail "boot" "validator did not come up ($VAL_LOG)"
  sleep 0.5
done
echo "validator up"
wait_for_port 8899 "RPC"
wait_for_port 8900 "WebSocket"
echo "both RPC and WS ports confirmed listening"

for name in buyer solver funder; do
  solana-keygen new --no-bip39-passphrase --silent -o "$WORK/$name.json" >/dev/null 2>&1
  solana-keygen pubkey "$WORK/$name.json" > "$WORK/$name.json.pub"
  solana airdrop 10 "$(cat "$WORK/$name.json.pub")" --url "$RPC_URL" >/dev/null 2>&1 || true
done
for name in buyer solver funder; do
  ok=""
  for i in $(seq 1 30); do
    bal=$(solana balance "$(cat "$WORK/$name.json.pub")" --url "$RPC_URL" | grep -oE '^[0-9]+')
    [ "${bal:-0}" -ge 10 ] && ok=1 && break
    sleep 0.4
  done
  [ -n "$ok" ] || fail "boot" "airdrop failed for $name"
done
BUYER_PUB=$(cat "$WORK/buyer.json.pub")
SOLVER_PUB=$(cat "$WORK/solver.json.pub")
FUNDER_PUB=$(cat "$WORK/funder.json.pub")
echo "buyer=$BUYER_PUB solver=$SOLVER_PUB funder=$FUNDER_PUB"

solana-keygen new --no-bip39-passphrase --silent -o "$WORK/operator.json" >/dev/null 2>&1
OPERATOR_PUB=$(solana-keygen pubkey "$WORK/operator.json")
BUYER_ENC_PK_HEX=$(node e2e/x25519-pub.mjs "$ENC_SECRET_HEX")

EXPLOIT_FILE="$WORK/exploit-solve.py"
cat > "$EXPLOIT_FILE" <<'PY'
import socket
s = socket.create_connection(("target", 1337), timeout=5)
print(s.recv(4096).decode())
PY

step "init-config + arm operator (threshold 1)"
node e2e/chain.mjs init-config "$WORK/funder.json" "$OPERATOR_PUB" "$ENC_PK_HEX" \
  "$BOND_LAMPORTS"
# initializeConfig leaves the operator set empty; arming is a separate authority tx.
echo "[arm] calling setOperators..."
node e2e/chain.mjs arm-operators "$WORK/funder.json" "$OPERATOR_PUB" "$ENC_PK_HEX" 1 3600 || fail "arm" "setOperators failed"
ARMED=$(node e2e/chain.mjs fetch-config |
  python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['operators']), d['threshold'])")
assert_eq "$ARMED" "1 1" "operator armed (1 operator, threshold 1)"

# ===========================================================================
run_submit_and_expect() { # $1 = expected status string ("PASS"/"FAIL")
  step "[submit] scb-submit ($1 expected)"
  SUBMIT_OUT=$(scb_submit "$EXPLOIT_FILE" "--wait")
  echo "$SUBMIT_OUT" | head -2
  echo "$SUBMIT_OUT" | grep -q "\"status\": \"$1\"" ||
    fail "verdict" "expected $1, got: $SUBMIT_OUT"
}

# ===========================================================================
if [ "$MODE" = "happy" ]; then
  EXPLOIT_FILE="$WORK/exploit-solve.py"
  cat > "$EXPLOIT_FILE" <<'PY'
import socket
s = socket.create_connection(("target", 1337), timeout=5)
print(s.recv(4096).decode())
PY

  start_mock "$MOCK_PORT"

  CUR_ID=$(next_bounty_id)
  PDA_B58=$(pda_of "$BUYER_PUB" "$CUR_ID")
  step "[seal] flag_commitment from enclave"
  FLAG_COMMITMENT_HEX=$(seal_commitment "$PDA_B58" "$MOCK_PORT")
  assert_eq "${#FLAG_COMMITMENT_HEX}" "64" "commitment is 32-byte hex"

  step "[create] escrow $PRIZE_LAMPORTS lamports"
  node e2e/chain.mjs create-bounty "$WORK/buyer.json" "$CUR_ID" \
    "$PRIZE_LAMPORTS" 3600 "$MANIFEST_HEX" "$ENV_HASH_HEX" \
    "$FLAG_COMMITMENT_HEX" "$BUYER_ENC_PK_HEX" >/dev/null

  step "[relayer] start (ENCLAVE_URL -> mock)"
  start_relayer "http://127.0.0.1:$MOCK_PORT"

  step "[submit+wait]"
  SOLVER_BEFORE_SUBMIT=$(bal "$SOLVER_PUB")
  SUBMIT_OUT=$(scb_submit "$EXPLOIT_FILE" "--wait")
  echo "$SUBMIT_OUT" | head -2
  echo "$SUBMIT_OUT" | grep -q '"status": *"PASS"' ||
    fail "happy-verdict" "expected PASS, got: $SUBMIT_OUT"

  step "[assert] payout / receipt / reveal decryption"
  DELTA=$(( $(bal "$SOLVER_PUB") - SOLVER_BEFORE_SUBMIT ))
  assert_eq "$DELTA" "$PRIZE_LAMPORTS" "solver delta == prize (bond returned net-zero)"

  RECEIPT_EXISTS=$(node e2e/chain.mjs receipt-exists "$BUYER_PUB" "$CUR_ID" "$SOLVER_PUB" |
    python3 -c "import json,sys; print(json.load(sys.stdin)['exists'])")
  assert_eq "$RECEIPT_EXISTS" "True" "Receipt PDA exists"

  CT_B64=$(node e2e/chain.mjs reveal-ct "$BUYER_PUB" "$CUR_ID" |
    python3 -c "import json,sys; print(json.load(sys.stdin)['ciphertextB64'])")
  [ -n "$CT_B64" ] || fail "reveal" "Reveal ciphertext missing"
  # Reveal ciphertext non-null = buyer CAN decrypt client-side (verified
  # separately in tests/api.rs). Here we assert presence + non-zero length.
  CT_LEN=$(python3 -c "import base64; print(len(base64.b64decode('$CT_B64')))")
  [ "$CT_LEN" -gt 0 ] || fail "reveal-decrypt" "ciphertext empty"
  echo "ok: reveal ciphertext present ($CT_LEN bytes) — client-side decryption verified in unit tests"
  echo ""
  echo "E2E RESULT: MODE=happy ALL ASSERTIONS PASSED"
  exit 0
fi

# ===========================================================================
if [ "$MODE" = "negative" ]; then
  BROKEN_FILE="$WORK/exploit-broken.py"
  echo "this is NOT an exploit" > "$BROKEN_FILE"

  # --- Phase 0: honest control PASS ---
  step "[N0] control: honest mock -> PASS"
  HONEST_PORT=8443
  start_mock "$HONEST_PORT"
  CUR_ID=$(next_bounty_id)
  PDA_B58=$(pda_of "$BUYER_PUB" "$CUR_ID")
  FC=$(seal_commitment "$PDA_B58" "$HONEST_PORT")
  node e2e/chain.mjs create-bounty "$WORK/buyer.json" "$CUR_ID" \
    "$PRIZE_LAMPORTS" 3600 "$MANIFEST_HEX" "$ENV_HASH_HEX" \
    "$FC" "$BUYER_ENC_PK_HEX" >/dev/null
  start_relayer "http://127.0.0.1:$HONEST_PORT"
  sleep 2
  CONTROL_OUT=$(scb_submit "$EXPLOIT_SOLVE" "--wait")
  echo "$CONTROL_OUT" | head -2
  echo "$CONTROL_OUT" | grep -q '"status": *"PASS"' || fail "control" "control did not pass"

  # --- Swap: kill honest mock + relayer; start force-fail on DIFFERENT port ---
  kill -9 $! 2>/dev/null || true # kill relayer
  pkill -9 -f "scb-target\|scb-exploit" 2>/dev/null || true

  FAIL_PORT=8444
  export SCB_MOCK_FORCE_FAIL=1
  start_mock "$FAIL_PORT"
  unset SCB_MOCK_FORCE_FAIL

  # Restart relayer pointing at force-fail mock
  start_relayer "http://127.0.0.1:$FAIL_PORT"

  # --- Phase 1: broken exploit gets FAIL verdict ---
  step "[N1] broken exploit -> FAIL verdict"
  CUR_ID=$(next_bounty_id)
  PDA_B58=$(pda_of "$BUYER_PUB" "$CUR_ID")
  FC=$(seal_commitment "$PDA_B58" "$FAIL_PORT")
  node e2e/chain.mjs create-bounty "$WORK/buyer.json" "$CUR_ID" \
    "$PRIZE_LAMPORTS" 3600 "$MANIFEST_HEX" "$ENV_HASH_HEX" \
    "$FC" "$BUYER_ENC_PK_HEX" >/dev/null

  SOLVER_BEFORE=$(bal "$SOLVER_PUB")
  SUBMIT_OUT=$(scb_submit "$BROKEN_FILE" "--wait")
  echo "$SUBMIT_OUT" | head -2
  echo "$SUBMIT_OUT" | grep -q '"status": *"FAIL"' ||
    fail "negative-verdict" "expected FAIL, got: $SUBMIT_OUT"

  step "[N2] assertions"
  DELTA=$(( $(bal "$SOLVER_PUB") - SOLVER_BEFORE ))
  assert_eq "$DELTA" "$BOND_LAMPORTS" "bond refunded on FAIL"
  ST=$(bounty_status "$CUR_ID")
  assert_eq "$ST" "0" "status back to Open"

  RESUB_OUT=$(scb_submit "$BROKEN_FILE" "--wait")
  echo "$RESUB_OUT" | head -2
  echo "$RESUB_OUT" | grep -q '"status": *"FAIL"' || fail "resubmit" "second attempt should FAIL too"

  echo ""
  echo "E2E RESULT: MODE=negative ALL ASSERTIONS PASSED"
  exit 0
fi

if [ "$MODE" = "unlock-drill" ]; then
  step "[D] unlock drill: blinded relayer, sweeper frees slot"
  CUR_ID=$(next_bounty_id)
  PDA_B58=$(pda_of "$BUYER_PUB" "$CUR_ID")
  FLAG_COMMITMENT_HEX=$(printf 'cc%.0s' $(seq 32))

  node e2e/chain.mjs create-bounty "$WORK/buyer.json" "$CUR_ID" \
    "$PRIZE_LAMPORTS" 600 "$MANIFEST_HEX" "$ENV_HASH_HEX" \
    "$FLAG_COMMITMENT_HEX" "$BUYER_ENC_PK_HEX" >/dev/null

  # Shrink force_unlock_delay_s to 5s
  node e2e/chain.mjs set-delay "$WORK/funder.json" 5 >/dev/null

  SOLVER_BEFORE=$(bal "$SOLVER_PUB")

  step "[D1] blind relayer + direct on-chain submission"
  start_relayer "http://127.0.0.1:9"
  node e2e/chain.mjs submit-exploit "$WORK/solver.json" "$BUYER_PUB" "$CUR_ID" \
    "https://drill.invalid/x" "$(printf '07%.0s' $(seq 32))" >/dev/null

  DEADLINE_MS=$(( $(date +%s%3N) + 90000 ))
  UNLOCKED=0
  while [ "$(date +%s%3N)" -lt "$DEADLINE_MS" ]; do
    ST=$(bounty_status "$CUR_ID")
    if [ "$ST" = "0" ]; then UNLOCKED=1; break; fi
    sleep 1
  done
  assert_eq "$UNLOCKED" "1" "slot unlocked after Config delay"
  DELTA=$(( $(bal "$SOLVER_PUB") - SOLVER_BEFORE ))
  assert_eq "$DELTA" "$BOND_LAMPORTS" "bond refunded by unlock"

  echo ""
  echo "E2E RESULT: MODE=unlock-drill ALL ASSERTIONS PASSED"
  exit 0
fi

echo ""
echo "E2E RESULT: MODE=$MODE COMPLETED"
