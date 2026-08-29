#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# FULL REAL CYCLE on localnet: real Docker execution drives the on-chain payout.
#
# A company escrows a prize -> a hunter's exploit (sealed, unreadable) is
# submitted -> the REAL enclave runs it in a hidden Docker sandbox against the
# target -> it captures the secret flag -> Solana pays the hunter and delivers
# the exploit to the buyer, atomically.
#
# This reuses the proven chain plumbing (e2e/chain.mjs, cli/scb-submit, the
# relayer) and swaps the mock judge for enclave-exec/enclave.cjs. The relayer
# needs no changes: the enclave bakes in its own target, so it judges without
# being told what to run.
#
# Prereqs (on a Docker + Solana host, i.e. your Linux box):
#   * the program built:   anchor build   (target/deploy/*.so present)
#   * the judge images:    bash enclave-exec/build.sh
#   * deps installed:      npm --prefix relayer install; npm --prefix cli install
#                          and the cli built: npm --prefix cli run build
#   * run the mock e2e once first (./e2e/localnet.sh) to confirm your chain
#     environment works, and run node enclave-exec/selftest.cjs to confirm the
#     enclave + Docker judging works. THEN run this.
#
#   bash enclave-exec/localnet-real.sh
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PROGRAM_ID="FbqouGmrsFmoC24H3x1vX3LX9jVXhUN5zDH7RnSXba9V"
export RPC_URL="http://127.0.0.1:8899"
ENCLAVE_PORT=8443
PRIZE_LAMPORTS=500000000   # 0.5 SOL
BOND_LAMPORTS=10000000     # 0.01 SOL
MANIFEST_HEX=$(printf '02%.0s' $(seq 32))
ENV_HASH_HEX=$(printf '03%.0s' $(seq 32))
BUYER_ENC_SECRET_HEX=$(printf 'ab%.0s' $(seq 32))

WORK="$(mktemp -d /tmp/scb-real.XXXXXX)"
VAL_LOG="$WORK/validator.log"; REL_LOG="$WORK/relayer.log"; ENC_LOG="$WORK/enclave.log"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

# stray processes from prior runs
for pat in solana-test-validator agave-validator enclave.cjs "relayer run start"; do
  for pid in $(pgrep -f "$pat" 2>/dev/null || true); do [ "$pid" = "$$" ] || kill -9 "$pid" 2>/dev/null || true; done
done

command -v docker >/dev/null || die "docker not found — this needs a Docker host"
docker image inspect scb-target >/dev/null 2>&1 || die "image scb-target missing — run: bash enclave-exec/build.sh"
docker image inspect scb-runtime >/dev/null 2>&1 || die "image scb-runtime missing — run: bash enclave-exec/build.sh"
[ -f cli/dist/scb-submit.js ] || die "cli not built — run: npm --prefix cli run build"

# --- boot validator with the program ---------------------------------------
say "boot validator + program"
if [ -f target/deploy/sealed_code_bounty-keypair.json ]; then
  PROGRAM_ID=$(solana-keygen pubkey target/deploy/sealed_code_bounty-keypair.json)
  export PROGRAM_ID
fi
solana-test-validator --bpf-program "$PROGRAM_ID" target/deploy/sealed_code_bounty.so \
  --ledger "$WORK/ledger" --reset >"$VAL_LOG" 2>&1 &
PIDS+=("$!")
for i in $(seq 1 40); do solana cluster-version --url "$RPC_URL" >/dev/null 2>&1 && break; [ "$i" = 40 ] && die "validator did not boot ($VAL_LOG)"; sleep 0.5; done
echo "validator up (program $PROGRAM_ID)"

# --- keys + funding ---------------------------------------------------------
say "keys + airdrops"
for name in buyer solver funder operator; do
  solana-keygen new --no-bip39-passphrase --silent -o "$WORK/$name.json" >/dev/null 2>&1
  solana-keygen pubkey "$WORK/$name.json" > "$WORK/$name.pub"
done
BUYER_PUB=$(cat "$WORK/buyer.pub"); SOLVER_PUB=$(cat "$WORK/solver.pub")
OPERATOR_PUB=$(cat "$WORK/operator.pub")
for name in buyer solver funder; do solana airdrop 10 "$(cat "$WORK/$name.pub")" --url "$RPC_URL" >/dev/null 2>&1 || true; done
for name in buyer solver funder; do
  for i in $(seq 1 30); do b=$(solana balance "$(cat "$WORK/$name.pub")" --url "$RPC_URL" | grep -oE '^[0-9]+'); [ "${b:-0}" -ge 10 ] && break; sleep 0.4; done
done
echo "buyer=$BUYER_PUB solver=$SOLVER_PUB operator=$OPERATOR_PUB"

# --- start the REAL enclave -------------------------------------------------
say "start real-execution enclave"
SCB_MASTER_SECRET_HEX=$(openssl rand -hex 32) \
SCB_ENCLAVE_ENC_SECRET_HEX=$(openssl rand -hex 32) \
SCB_OPERATOR_KEYPAIR="$WORK/operator.json" \
PORT="$ENCLAVE_PORT" \
node enclave-exec/enclave.cjs >"$ENC_LOG" 2>&1 &
PIDS+=("$!")
for i in $(seq 1 30); do curl -s "http://127.0.0.1:$ENCLAVE_PORT/internal/healthz" >/dev/null 2>&1 && break; [ "$i" = 30 ] && die "enclave did not start ($ENC_LOG)"; sleep 0.3; done
ENC_PK_HEX=$(curl -s "http://127.0.0.1:$ENCLAVE_PORT/internal/enclave-pubkey" | python3 -c "import json,sys; print(json.load(sys.stdin)['enclave_enc_pk'])")
[ ${#ENC_PK_HEX} -eq 64 ] || die "bad enclave pubkey: $ENC_PK_HEX"
echo "enclave up; enclave_enc_pk=$ENC_PK_HEX"

# --- config + operator ------------------------------------------------------
say "init-config + arm operator (with the enclave's real pubkey)"
node e2e/chain.mjs init-config "$WORK/funder.json" "$OPERATOR_PUB" "$ENC_PK_HEX" "$BOND_LAMPORTS"
node e2e/chain.mjs arm-operators "$WORK/funder.json" "$OPERATOR_PUB" "$ENC_PK_HEX" 1 3600
BUYER_ENC_PK_HEX=$(node e2e/x25519-pub.mjs "$BUYER_ENC_SECRET_HEX")

# --- create the bounty ------------------------------------------------------
say "create bounty (escrow $PRIZE_LAMPORTS lamports)"
CUR_ID=101
PDA_B58=$(node -e "
const web3=require('$ROOT/node_modules/@solana/web3.js');
const idBuf=Buffer.alloc(8); idBuf.writeBigUInt64LE(BigInt('$CUR_ID'));
const pid=new web3.PublicKey('$PROGRAM_ID'); const buyer=new web3.PublicKey('$BUYER_PUB');
console.log(web3.PublicKey.findProgramAddressSync([Buffer.from('bounty'),buyer.toBuffer(),idBuf],pid)[0].toBase58());")
FLAG_COMMITMENT_HEX=$(curl -s -X POST "http://127.0.0.1:$ENCLAVE_PORT/internal/seal_bounty" -H 'content-type: application/json' -d "{\"bounty_pda\":\"$PDA_B58\"}" | python3 -c "import json,sys; print(json.load(sys.stdin)['flag_commitment'])")
[ ${#FLAG_COMMITMENT_HEX} -eq 64 ] || die "bad flag commitment"
node e2e/chain.mjs create-bounty "$WORK/buyer.json" "$CUR_ID" "$PRIZE_LAMPORTS" 3600 \
  "$MANIFEST_HEX" "$ENV_HASH_HEX" "$FLAG_COMMITMENT_HEX" "$BUYER_ENC_PK_HEX" >/dev/null
echo "bounty $PDA_B58 created"

# --- relayer pointed at the real enclave ------------------------------------
say "start relayer -> real enclave"
RPC_URL="$RPC_URL" PROGRAM_ID="$PROGRAM_ID" FEE_PAYER_KEYPAIR_PATH="$WORK/funder.json" \
OPERATOR_PUBKEY="$OPERATOR_PUB" ENCLAVE_URL="http://127.0.0.1:$ENCLAVE_PORT" POLL_INTERVAL_MS=800 \
npm --prefix relayer run start >"$REL_LOG" 2>&1 &
PIDS+=("$!")
sleep 2

# --- submit the REAL exploit (sealed to the enclave key) --------------------
say "submit exploit (real ret2win solve.py, sealed & unreadable in transit)"
SOLVER_BEFORE=$(node e2e/chain.mjs balance "$SOLVER_PUB" | python3 -c "import json,sys; print(json.load(sys.stdin)['lamports'])")
SUBMIT_OUT=$(node cli/dist/scb-submit.js --rpc-url "$RPC_URL" --keypair "$WORK/solver.json" \
  --bounty "$BUYER_PUB:$CUR_ID" --file examples/ret2win/solution/solve.py \
  --enclave-url "http://127.0.0.1:$ENCLAVE_PORT" --wait)
echo "$SUBMIT_OUT" | head -3
echo "$SUBMIT_OUT" | grep -q '"status": *"PASS"' || die "expected PASS from real execution; got: $SUBMIT_OUT (enclave log: $ENC_LOG)"

# --- assert the money moved + the exploit was delivered ---------------------
say "assert payout + receipt + delivery"
SOLVER_AFTER=$(node e2e/chain.mjs balance "$SOLVER_PUB" | python3 -c "import json,sys; print(json.load(sys.stdin)['lamports'])")
DELTA=$(( SOLVER_AFTER - SOLVER_BEFORE ))
[ "$DELTA" = "$PRIZE_LAMPORTS" ] || die "solver delta $DELTA != prize $PRIZE_LAMPORTS"
echo "ok: hunter was paid $DELTA lamports from escrow"

RCPT=$(node e2e/chain.mjs receipt-exists "$BUYER_PUB" "$CUR_ID" "$SOLVER_PUB" | python3 -c "import json,sys; print(json.load(sys.stdin)['exists'])")
[ "$RCPT" = "True" ] || die "Receipt PDA missing"
echo "ok: Receipt minted"

CT_B64=$(node e2e/chain.mjs reveal-ct "$BUYER_PUB" "$CUR_ID" | python3 -c "import json,sys; print(json.load(sys.stdin)['ciphertextB64'])")
[ -n "$CT_B64" ] || die "Reveal ciphertext missing"
echo "ok: exploit delivered to buyer (Reveal present, ${#CT_B64} b64 chars)"

printf '\n\033[1;32mFULL REAL CYCLE PASSED — real Docker execution drove the on-chain payout + delivery.\033[0m\n\n'
