# Nitro transport

Status (2026-10-09): these are protocol/storage-broker prototypes with offline
tests, not a running enclave. `nitro-cli` is absent on the current machine;
there is no EIF, attestation endpoint/verifier, KMS secret-release proof, or
enclave-native execution sandbox. Do not claim hardware isolation from these
tests. See [`../DEPLOYMENT-HANDOFF.md`](../DEPLOYMENT-HANDOFF.md).

This directory contains the narrow parent/enclave transport. The parent proxy
binds to loopback and forwards only the six verifier endpoints over AF_VSOCK.
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
