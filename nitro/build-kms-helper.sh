#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 || "$1" != --dev-only ]]; then
  echo 'Usage: nitro/build-kms-helper.sh --dev-only' >&2
  echo 'Outputs development helper artifacts; does not approve a release or deploy to AWS.' >&2
  exit 2
fi
recipe="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$recipe/.." && pwd)"
source_commit="$(git -C "$repo_root" rev-parse HEAD)"
source_dirty=false
[[ -z "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]] || source_dirty=true
output="${SCB_KMS_OUTPUT:-/tmp/scb-kms-pinned-artifacts}"
cache="${SCB_KMS_SOURCE_CACHE:-/tmp/scb-kms-source-cache}"
[[ ! -e "$output" ]] || { echo 'output must not exist; choose a fresh SCB_KMS_OUTPUT directory' >&2; exit 1; }
context="$(mktemp -d /tmp/scb-kms-build.XXXXXX)"
cleanup() { rm -rf "$context"; }
trap cleanup EXIT
python3 "$recipe/kms_prepare.py" "$recipe" "$context" "$cache"
# Source preparation happens before this immutable build context is submitted.
docker build --platform linux/amd64 -f "$context/KmsBuilder.Dockerfile" \
  --iidfile "$context/builder.id" "$context"
builder_id="$(cat "$context/builder.id")"
python3 - "$context/context-sha256.json" "$repo_root" <<'PY'
import hashlib, json, pathlib, sys
for name, expected in json.loads(pathlib.Path(sys.argv[1]).read_text()).items():
    actual = hashlib.sha256((pathlib.Path(sys.argv[2]) / name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit('build recipe changed before compilation: ' + name)
PY
mkdir -p "$output"
output="$(cd "$output" && pwd)"
docker run --rm --platform linux/amd64 --network=none \
  --env "SCB_BUILD_JOBS=${SCB_BUILD_JOBS:-2}" \
  --mount "type=bind,src=$output,dst=/output" "$builder_id"
[[ "$(git -C "$repo_root" rev-parse HEAD)" == "$source_commit" ]] || { echo 'source commit changed during build' >&2; exit 1; }
[[ -z "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]] || source_dirty=true
python3 - "$output" "$builder_id" "$repo_root" "$source_commit" "$source_dirty" <<'PY'
import hashlib, json, pathlib, sys
output = pathlib.Path(sys.argv[1])
path = output / 'provenance.json'
report = json.loads(path.read_text())
report['builder_image_id'] = sys.argv[2]
report['source_commit'] = sys.argv[4]
report['source_dirty'] = sys.argv[5] == 'true'
report['development_only'] = report['source_dirty']
report['release_approved'] = False
for name, expected in report['input_sha256'].items():
    actual = hashlib.sha256((pathlib.Path(sys.argv[3]) / name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit('build recipe changed during build: ' + name)
report['artifact_sha256'] = {name: record['sha256'] for name, record in report['artifacts'].items()}
completed = output / 'provenance.completed.json'
completed.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
completed.replace(path)
PY
echo "Development KMS artifacts and provenance: $output"
