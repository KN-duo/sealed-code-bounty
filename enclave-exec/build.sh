#!/usr/bin/env bash
# Build the two images the executor needs: the vulnerable TARGET and the exploit
# RUNTIME. Run once on a Docker host before using execute.mjs.
#   bash enclave-exec/build.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> building target image (scb-target)"
docker build -t scb-target -f "$DIR/target.Dockerfile" "$DIR"

echo "==> building runtime image (scb-runtime)"
docker build -t scb-runtime -f "$DIR/runtime.Dockerfile" "$DIR"

echo "==> building workspace image (scb-workspace)"
docker build -t scb-workspace -f "$DIR/workspace.Dockerfile" "$DIR"

echo "==> done. images:"
docker image ls | grep -E 'scb-target|scb-runtime' || true
echo
echo "next:  node enclave-exec/execute.mjs examples/ret2win/solution/solve.py"
