# Nitro transport

Status (2026-10-09): protocol/storage-broker source and offline tests exist,
but no enclave has run on Nitro hardware. AWS Nitro CLI v1.5.1 was built from
the pinned upstream release; AWS SDK C v0.4.2's KMS helper and NSM API v0.4.0
were built from their pinned sources with Rust 1.85 because the upstream
container recipe's Rust 1.63 cannot parse a newly resolved Rust 2024 crate.
The application image and a dev-only EIF were built successfully. The EIF is
332 MiB (348,115,420 bytes), has PCR0
`ac126e068b424c0e462835972194c1f0d84cc2f12170f55ca358018ad492687c1d4e2213b85a17c7b89179279ee4d1b1`,
and SHA-384
`6f4fa3fecd367c25a0a28857aefefdc6c6bed636f30e9d49bcfdbf7652eb0118f78d39cc95fe9517ac563863c22dd1b7`.
It came from a dirty worktree and is development-only; it is not approved for
KMS policy or deployment. Podman selected netavark, imported the embedded
runtime, and created an internal network in a disposable local container.
Those host-kernel smoke checks are not a Nitro sandbox run. There is still no
Nitro hardware boot, attestation/KMS
release proof, or enclave sandbox runtime proof. Do not claim hardware
isolation from source review, an EIF measurement, or local checks alone. See
[`../DEPLOYMENT-HANDOFF.md`](../DEPLOYMENT-HANDOFF.md).

The current source adds nonce-bound NSM attestation and build provenance; the
EIF measurement above predates those changes and must not be used for them.
See [ATTESTATION.md](ATTESTATION.md) for the independent operator verifier.
The newer attestation-enabled development artifact is
`/tmp/scb-attestation-dev.eif` (348,526,052 bytes), with provenance at
`/tmp/scb-attestation-dev.eif.provenance.json`. Its PCR0 is
`f0d63c00b13ed4856b8d4d52ec0788db9b4131ae01d5b43c63be441f7a5b46438b5d2ff2cfc7c9e268cc21b5e459618f`.
It has not run on Nitro and is not approved for KMS or deployment.

This directory contains the narrow parent/enclave transport. The parent proxy
binds to loopback and forwards only allowlisted verifier endpoints over AF_VSOCK.
Frames are four-byte big-endian lengths followed by UTF-8 JSON, capped at 8 MiB.
Every request has a UUID that the response must echo. Malformed, oversized,
timed-out, mismatched, and non-allowlisted traffic fails closed.

The enclave proxy forwards accepted requests to the Rust runner on
`127.0.0.1:8443`. Neither proxy logs request bodies or response bodies. The
parent must be placed behind authenticated TLS ingress; it is not itself a
public API gateway.

Run protocol tests locally:

```bash
python3 nitro/test_protocol.py
```

This transport is testable without Nitro hardware. AF_VSOCK integration,
attestation, KMS secret release, and the enclave sandbox remain deployment
gates and must not be claimed from these unit tests alone.

## Candidate EIF packaging

`Enclave.Dockerfile` packages the release runner, Podman, the offline exploit
runtime image, and the KMS/vsock helpers. Once the AWS SDK C helper and runtime
archive are available, build a **development-only** candidate with:

```bash
SCB_KMS_TOOL_DIR=/path/to/kmstool-artifacts \
SCB_RUNTIME_TAR=/path/to/scb-exploit-runtime.tar \
PATH=/path/to/nitro-cli-dir:$PATH \
nitro/build-eif.sh --dev-only
```

The script embeds the source identity into the runner and writes a sibling
`.provenance.json` with source/input hashes, compiler and CLI versions, OS
package inventory, Docker image ID, EIF hash, and PCRs. It rejects source changes
during a build. `--release` produces only a candidate and requires clean source
and component provenance; it does not approve deployment. A release must come
from a reviewed clean commit, be tested on Nitro hardware,
and have its PCR0 and file SHA-384 pinned in Terraform before launch.

Use [build-runtime.sh](../runner/build-runtime.sh),
[build-kms-helper.sh](build-kms-helper.sh) and
[build-runner.sh](build-runner.sh) to generate matching component artifacts.
The EIF builder rejects old or changed binaries/recipes instead of accepting
an arbitrary helper/runtime by its filename. The Ubuntu snapshot/package locks,
Python wheel hashes, pinned Rust compiler and Nitro bootstrap blobs are recorded
in provenance. See [DEPENDENCY_LOCKS.md](DEPENDENCY_LOCKS.md),
[KMS_BUILD.md](KMS_BUILD.md) and [RUNNER_BUILD.md](RUNNER_BUILD.md).
Dependency locking is not a two-build reproducibility proof.

The candidate uses cgroupfs and file container logs without systemd/journald.
Startup requires writable memory, CPU quota, and process-limit controllers.
The pinned Nitro kernel/bootstrap support these controllers, but their use by
this application has not been demonstrated on hardware.

## Content-addressed storage transport

`storage_broker.py` runs on the parent with S3 credentials and serves enclave CID
16 on vsock port 5001 by default. `storage_client.py` runs inside the enclave and
connects only to parent CID 3. Configure the parent with `SCB_STORAGE_BUCKET` and
`SCB_STORAGE_BUCKET_OWNER`; requests cannot override the bucket, owner, URL, or
object path. Storage frames are capped at 1 MiB with a ten-second deadline.

Encrypted submission `put` and `get` retain their SHA-256 receipt contract.
Read-only challenge artifact requests have exactly this shape:

```json
{"op":"get_artifact","kind":"manifest","sha256":"<64 lowercase hex characters>","offset":0}
```

`kind` is `manifest` or `environment`. Keys are respectively
`scb/manifests/<sha256>.json` and `scb/envs/<sha256>.tar.gz`. Manifests are capped at
64 KiB and compressed environments at 128 MiB for the initial small CTF runtime.
Each request returns at most 512 KiB; `offset` must be an integer within the
object, with zero as the first offset. S3 range and length metadata must agree
with the exact streamed bytes. The success response has exactly four fields:

```json
{"ok":true,"body_b64":"<canonical base64>","offset":0,"total_bytes":123}
```

Both broker and helper validate lengths, bounds, and response shape. Individual
chunks are **not authenticated**. The enclave caller must enforce one stable
total length, fetch every byte, and hash the complete object against the on-chain
SHA-256 before parsing or execution. Changes between chunk requests or a dishonest
parent therefore cause full-object verification to fail.

Artifact reads share the process-local request allowance (1024 by default).
Restarting the broker resets that allowance; it is not a durable spending cap.
No artifact writes or arbitrary S3 operations are exposed by this protocol.

Offline tests using injected S3 clients:

```bash
python3 nitro/test_storage.py
python3 nitro/test_storage_artifacts.py
```
