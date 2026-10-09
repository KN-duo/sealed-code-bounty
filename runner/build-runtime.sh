#!/usr/bin/env bash
set -euo pipefail

# Assemble a minimal context: do not send local secrets, build outputs or .git
# to Docker. The archive tag matches the runner's offline --pull=never default;
# release provenance must pin the archive SHA256 and loaded image ID.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${SCB_RUNTIME_IMAGE:-scb-runtime:latest}"
output="${SCB_RUNTIME_OUTPUT:-/tmp/scb-exploit-runtime-locked.tar}"
context="$(mktemp -d /tmp/scb-runtime-context.XXXXXX)"
archive=""
cleanup() { rm -rf "$context"; [[ -z "$archive" ]] || rm -f "$archive"; }
trap cleanup EXIT
git -C "$repo_root" rev-parse HEAD >"$context/source-commit.txt"
git -C "$repo_root" status --porcelain >"$context/source-status.txt"
install -d "$context/nitro" "$context/runner/runtime"
for input in nitro/ubuntu-snapshot.sources nitro/ubuntu-snapshot-ca.pem \
             runner/runtime/apt.lock runner/runtime/requirements.lock; do
  install -m 0444 "$repo_root/$input" "$context/$input"
done
install -m 0444 "$repo_root/runner/runtime.Dockerfile" "$context/runtime.Dockerfile"
install -m 0444 "$repo_root/runner/build-runtime.sh" "$context/runner/build-runtime.sh"
docker build --platform linux/amd64 --file "$context/runtime.Dockerfile" \
  --tag "$image" "$context"
docker image inspect "$image" >"$context/image.json"
archive="$(mktemp "${output}.XXXXXX")"
docker image save --output "$archive" "$image"
python3 - "$context" "$archive" "$output.provenance.json" <<'PY'
import hashlib
import json
import pathlib
import sys

context, archive, report = map(pathlib.Path, sys.argv[1:])
def digest(path):
    hasher = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

image = json.loads((context / 'image.json').read_text())[0]
inputs = {str(path.relative_to(context)): digest(path)
          for path in sorted(context.rglob('*'))
          if path.is_file() and path.name not in
          ('image.json', 'source-commit.txt', 'source-status.txt')}
report.write_text(json.dumps({
    'schema': 'scb-runtime-provenance-v1',
    'image_id': image['Id'],
    'platform': image['Os'] + '/' + image['Architecture'],
    'archive_sha256': digest(archive),
    'archive_bytes': archive.stat().st_size,
    'inputs_sha256': inputs,
    'source_commit': (context / 'source-commit.txt').read_text().strip(),
    'source_dirty': bool((context / 'source-status.txt').read_text().strip()),
    'source_identity_is_informational': True,
    'dependency_snapshot': '20261008T000000Z',
    'release_approved': False,
}, indent=2, sort_keys=True) + '\n')
PY
chmod 0444 "$archive" "$output.provenance.json"
mv -f "$archive" "$output"
archive=""
printf 'Runtime archive: %s\nProvenance: %s.provenance.json\n' "$output" "$output"
