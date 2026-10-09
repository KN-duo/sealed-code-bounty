#!/usr/bin/env bash
# Runs in the pinned builder with --network=none; no tests are built or run.
set -euo pipefail
[[ "$(uname -m)" == x86_64 ]] || { echo 'x86_64 build required' >&2; exit 1; }
[[ -d /output && ! -e /output/provenance.json ]] || { echo 'use a fresh output directory' >&2; exit 1; }
jobs="${SCB_BUILD_JOBS:-2}"
[[ "$jobs" =~ ^[1-9][0-9]*$ && "$jobs" -le 16 ]] || exit 2
cd /build
common=(-GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/opt/scb \
  -DCMAKE_INSTALL_PREFIX=/opt/scb -DCMAKE_INSTALL_LIBDIR=lib \
  -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF)
compile() {
  local name="$1"; shift
  cmake -S "$name" -B "$name/build" "${common[@]}" "$@"
  cmake --build "$name/build" --parallel "$jobs" --target install
}
compile aws-lc
compile s2n-tls
compile aws-c-common
compile aws-c-sdkutils
compile aws-c-cal
compile aws-c-io -DUSE_VSOCK=ON
compile aws-c-compression
compile aws-c-http
compile aws-c-auth
compile json-c
cargo build --manifest-path aws-nitro-enclaves-nsm-api/Cargo.toml \
  --locked --offline --release --jobs "$jobs" -p nsm-lib
install -m 0644 aws-nitro-enclaves-nsm-api/target/release/libnsm.so /opt/scb/lib/libnsm.so
install -m 0644 aws-nitro-enclaves-nsm-api/target/release/nsm.h /opt/scb/include/nsm.h
compile aws-nitro-enclaves-sdk-c -DBUILD_RELOCATABLE_BINARIES=ON
install -m 0555 /opt/scb/bin/kmstool_enclave_cli /output/kmstool_enclave_cli
install -m 0444 /opt/scb/lib/libnsm.so /output/libnsm.so
LD_LIBRARY_PATH=/opt/scb/lib ldd /output/kmstool_enclave_cli >/output/dynamic-dependencies.txt
if grep -q 'not found' /output/dynamic-dependencies.txt; then
  echo 'unresolved shared library dependency' >&2; exit 1
fi
python3 - <<'PY'
import hashlib, json, pathlib, subprocess
def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def version(*args):
    return subprocess.check_output(args, text=True).strip()
root = pathlib.Path('/output')
report = {
    'schema': 'scb-kms-build-v1',
    'build_network': 'none',
    'source_lock': json.loads(pathlib.Path('/inputs/kms-sources.lock.json').read_text()),
    'input_sha256': json.loads(pathlib.Path('/inputs/context-sha256.json').read_text()),
    'prepared_source_sha256': json.loads(pathlib.Path('/inputs/prepared-source-sha256.json').read_text()),
    'compiler_versions': {name: version(name, '--version') for name in ('cc', 'cmake', 'cargo', 'rustc', 'ninja')},
    'go_version': version('go', 'version'),
    'os_packages': pathlib.Path('/inputs/kms-build-apt.lock').read_text().splitlines(),
    'artifacts': {name: {'sha256': digest(root / name), 'bytes': (root / name).stat().st_size}
                  for name in ('kmstool_enclave_cli', 'libnsm.so')},
    'verification': 'Local compilation only; not a reproducibility or Nitro/KMS release proof.'
}
(root / 'provenance.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
PY
