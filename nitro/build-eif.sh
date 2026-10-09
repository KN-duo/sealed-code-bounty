#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: nitro/build-eif.sh --dev-only|--release

Builds a local candidate EIF from the pinned Rust builder, AWS Nitro KMS
helper, and exploit runtime archive. --release requires clean source and clean
component provenance. Neither mode approves a release or authorizes KMS.

Required environment:
  SCB_KMS_TOOL_DIR  Directory containing kmstool_enclave_cli and libnsm.so
  SCB_RUNTIME_TAR   `docker save` archive of the pinned exploit runtime image

Optional environment:
  SCB_EIF_OUTPUT    Output EIF path (default: /tmp/scb-candidate-dev.eif)
  SCB_EIF_NAME      EIF name (default: scb-candidate-dev)
  SCB_RUNNER_DIR    Reuse a runner binary with matching provenance; otherwise
                    invoke nitro/build-runner.sh with the same build mode

Also writes OUTPUT.provenance.json with source/input hashes, compiler version,
image ID, EIF SHA-384 and PCRs. Build identity is embedded in the Rust binary.
EOF
}

if [[ $# -ne 1 || ( "${1:-}" != "--dev-only" && "${1:-}" != "--release" ) ]]; then
  usage >&2
  exit 2
fi
mode="$1"
release_args=()
[[ "$mode" != --release ]] || release_args=(--release)

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kms_dir="${SCB_KMS_TOOL_DIR:?set SCB_KMS_TOOL_DIR}"
runtime_tar="${SCB_RUNTIME_TAR:?set SCB_RUNTIME_TAR}"
flavor=dev
[[ "$mode" != --release ]] || flavor=release-candidate
output="${SCB_EIF_OUTPUT:-/tmp/scb-candidate-$flavor.eif}"
image_name="${SCB_EIF_NAME:-scb-candidate-$flavor}"
context="$(mktemp -d /tmp/scb-eif-context.XXXXXX)"
cleanup() { rm -rf "$context"; }
trap cleanup EXIT

for artifact in "$kms_dir/kmstool_enclave_cli" "$kms_dir/libnsm.so" "$runtime_tar"; do
  [[ -s "$artifact" ]] || { echo "required artifact missing: $artifact" >&2; exit 1; }
done

python3 "$repo_root/nitro/eif_provenance.py" snapshot "$repo_root" >"$context/source.json"
python3 "$repo_root/nitro/eif_provenance.py" tooling "$repo_root" >"$context/tooling.json"
if [[ "$mode" == --release ]]; then
  python3 - "$context/source.json" <<'PY'
import json, sys
if json.load(open(sys.argv[1]))['dirty']:
    raise SystemExit('release EIF requires clean source; use --dev-only for local development')
PY
fi
runner_dir="${SCB_RUNNER_DIR:-$context/runner-artifacts}"
if [[ -z "${SCB_RUNNER_DIR:-}" ]]; then
  SCB_RUNNER_OUTPUT="$runner_dir" "$repo_root/nitro/build-runner.sh" "$mode"
fi
python3 "$repo_root/nitro/eif_provenance.py" validate-components \
  --repo "$repo_root" --snapshot "$context/source.json" --runner "$runner_dir" \
  --kms "$kms_dir" --runtime "$runtime_tar" "${release_args[@]}" >"$context/components.json"
install -m 0555 "$runner_dir/scb-runner" "$context/scb-runner"
install -m 0555 "$kms_dir/kmstool_enclave_cli" "$context/kmstool_enclave_cli"
install -m 0444 "$kms_dir/libnsm.so" "$context/libnsm.so"
install -m 0444 "$runtime_tar" "$context/scb-exploit-runtime.tar"
install -m 0555 "$repo_root/nitro/enclave-entrypoint.sh" "$context/enclave-entrypoint.sh"
install -d "$context/nitro"
for file in protocol.py storage_protocol.py kms_bootstrap_client.py storage_client.py \
            enclave_proxy.py deny-vsock-seccomp.json ubuntu-snapshot.sources \
            ubuntu-snapshot-ca.pem enclave-apt.lock; do
  install -m 0444 "$repo_root/nitro/$file" "$context/nitro/$file"
done
cp "$repo_root/nitro/Enclave.Dockerfile" "$context/Enclave.Dockerfile"

docker build --platform linux/amd64 --file "$context/Enclave.Dockerfile" --tag "$image_name" "$context"
nitro-cli build-enclave --docker-uri "$image_name" --output-file "$context/verifier.eif" \
  --name "$image_name" --version "${mode#--}"
nitro-cli describe-eif --eif-path "$context/verifier.eif" >"$context/description.json"
python3 "$repo_root/nitro/eif_provenance.py" record \
  --repo "$repo_root" --snapshot "$context/source.json" \
  --description "$context/description.json" --context "$context" \
  --eif "$context/verifier.eif" --image "$image_name" "${release_args[@]}" >"$context/provenance.json"
install -m 0444 "$context/verifier.eif" "$output"
install -m 0444 "$context/provenance.json" "$output.provenance.json"
printf 'Source commit: %s\n' "$(git -C "$repo_root" rev-parse HEAD)"
if [[ -z "$(git -C "$repo_root" status --porcelain)" ]]; then
  echo 'Source worktree: clean'
else
  echo 'Source worktree: dirty (development-only)'
fi
printf 'Docker image ID: %s\n' "$(docker image inspect --format '{{.Id}}' "$image_name")"
nitro-cli describe-eif --eif-path "$output"
sha384sum "$output"
printf '\nEIF candidate (%s) written to %s\nProvenance: %s.provenance.json\n' "$mode" "$output" "$output"
echo 'Release approval, reproducibility review and real Nitro/KMS proofs remain required.'
