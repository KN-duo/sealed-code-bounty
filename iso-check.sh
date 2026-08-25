#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
solana-test-validator --bpf-program target/deploy/sealed_code_bounty-keypair.json target/deploy/sealed_code_bounty.so --reset --quiet &
VPID=$!
sleep 6
npx ts-mocha -p ./tsconfig.json --grep "$1" "tests/**/*.ts" 2>&1 | tail -4
kill $VPID 2>/dev/null || true
wait $VPID 2>/dev/null || true
