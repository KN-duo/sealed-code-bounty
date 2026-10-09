# Locked AWS KMS helper build

The enclave uses the official AWS Nitro Enclaves SDK C `kmstool_enclave_cli`
for recipient-attested KMS decryption through the parent vsock proxy. This
recipe retains that implementation; it does not replace KMS or NSM with a
development secret provider.

## Inputs

- `kms-sources.lock.json` pins SDK C v0.4.2, NSM v0.4.0, all ten upstream C
  dependencies, the Ubuntu base digest, and the official Rust 1.85.0 archive
  checksum. Git fetches exact commits and checks object integrity.
- `kms-nsm-Cargo.lock` fixes the NSM workspace's crates and registry checksums.
  Cargo fetches with `--locked`; compilation uses `--locked --offline`.
- `kms-build-apt.lock` fixes the complete compiler image package inventory,
  including GCC, Go, CMake, Ninja and glibc. Installation uses the signed
  Ubuntu snapshot in `ubuntu-snapshot.sources`, then compares the complete
  installed inventory with the lock. Historical Release expiry is disabled;
  archive signature and TLS validation remain enabled.
- `ubuntu-snapshot-ca.pem` supplies the public TLS roots needed by the minimal
  base image before `ca-certificates` is installed.

Rust 1.85.0 supports the edition needed by the resolved NSM dependencies; the
older compiler in upstream's original AL2 recipe does not. Both compiler and
dependency versions are explicit here. Updating them requires changing the
locks and recording new artifact measurements.

## Build locally

Requires Linux x86_64, Docker, Git and Python 3. No AWS credentials are used.
Source preparation and the compiler image fetch dependencies over HTTPS;
actual compilation runs in a disposable Docker container with networking
disabled. It builds no test targets and runs no tests.

```bash
SCB_KMS_OUTPUT=/tmp/scb-kms-pinned-artifacts \
  bash nitro/build-kms-helper.sh --dev-only
```

The output directory must be absent. Optional `SCB_KMS_SOURCE_CACHE` selects a
Git object cache (default `/tmp/scb-kms-source-cache`); `SCB_BUILD_JOBS` defaults
to two and is bounded at sixteen. The build produces:

- `kmstool_enclave_cli` and `libnsm.so` for `SCB_KMS_TOOL_DIR`;
- `dynamic-dependencies.txt`, which must contain no missing library;
- `provenance.json` (`scb-kms-build-v1`) with source commits, all recipe input
  hashes, prepared-source hash, exact builder image ID, compiler/package
  inventories and both artifact SHA-256 hashes.

The provenance records the project commit and whether its worktree was dirty;
`development_only` follows that value. `release_approved` remains false. A
clean source tree and a successful build are insufficient approval to deploy.
No binary artifacts are committed to the repository.

Git source archives omit repository metadata. SDK C's informational version
string therefore uses its upstream fallback; the exact v0.4.2 source commit
is recorded in provenance. This does not change recipient attestation or
decrypt behavior.

## Remaining release evidence

This pins inputs and fixes build paths and `SOURCE_DATE_EPOCH`. Two independent
clean builds must still establish whether the output bytes match. Container
metadata and upstream generated build metadata can affect repeatability;
do not claim reproducibility from dependency locking alone. No helper command
is executed outside Nitro as a KMS proof: startup needs the NSM device. Real
approved-PCR release, wrong-PCR denial, and parent plaintext denial remain
required before launch. Rebuilding this helper changes the final EIF inputs
and requires new enclave measurements and review.
