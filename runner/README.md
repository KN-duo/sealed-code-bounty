# scb-runner

Rust verifier service (`docs/BUILD_PLAN_v2.md` §4.3), intended to run inside an
AWS Nitro Enclave. It binds `127.0.0.1:$PORT` (default 8443) and is currently
run only in local development/tests. No EIF, attestation/KMS key release, or
public authenticated ingress is implemented, so this is not a production TEE.

**Do not use real submissions or production secrets here.** The environment
secret variables below are development-only inputs; production must derive
keys from an attestation-gated KMS release instead. The default sandbox is a
typed stub that returns HTTP 501. Release configuration selects daemonless
Podman and rejects Docker or stub execution. That Podman path is source-level
work only: the required enclave image/runtime bundle and Nitro validation are
not yet available.

The opt-in Cargo feature `dev-secrets` exists for local development. It is
disabled by default. Production builds obtain the KMS ciphertext and temporary
instance-profile credentials through `nitro/kms_bootstrap_client.py`, invoke
`kmstool_enclave_cli` through the parent's KMS-only vsock proxy, and construct
the runner from a zeroizing in-memory key. The upload-decryption key is
derived with HKDF label `scb-enc-key-v1`. This source path compiles, but no EIF,
KMS recipient-attestation release, or Nitro-host execution has been verified.

## Run

```bash
SCB_MASTER_SECRET_HEX=$(openssl rand -hex 32) \
SCB_ENCLAVE_ENC_SECRET_HEX=$(openssl rand -hex 32) \
SCB_SUBMISSION_STORE=development-directory SCB_ALLOW_DEV_DIRECTORY_STORE=1 \
PORT=8443 cargo run --features dev-secrets
```

Both secrets are required at startup; losing them only rotates flag/key
material, they never leave the process.

| Endpoint | Purpose |
|---|---|
| `GET /internal/healthz` | liveness |
| `POST /internal/seal_bounty {bounty_pda}` | → `{flag_commitment}` (deterministic across restarts) |
| `POST /internal/upload {bounty_pda, claimed_chain_view{env_blob_sha256,buyer_enc_pk,flag_commitment,exploit_sha256}, solver_pubkey, submit_intent_sig, exploit_sealed_box}` | → `{receipt}` |
| `POST /internal/verify {bounty_pda, solver_pubkey, submission_receipt, manifest_sha256, claimed_chain_view}` | verdict JSON mirroring `relayer/src/enclave-types.ts` |

## REAL vs STUB

| Piece | Status |
|---|---|
| Flag derivation `base58(HKDF-SHA256(M, salt=pda, info="scb-flag-v1"))` | **REAL** + golden vector (`tests/golden/verdict_v3.json`) |
| Stable verdict key `HKDF(M, info="scb-verdict-key-v1")` (D14) | **REAL in the local runner**, ed25519-dalek; the master key is not yet released through Nitro/KMS |
| Intent-signature gate `SCB_SUBMIT_V1‖pda‖sha256(plaintext)` — 403 before any heavy work | **REAL** |
| Sealed-box unseal/seal (libsodium-compatible, `crypto_box` crate) | **REAL** (hunter→enclave on upload; enclave→buyer reveal on PASS) |
| Public execution log | **REAL**, fixed PASS/FAIL text only; process output is never returned |
| Safe rootfs unpack: total-size cap (2 GiB default), file-count cap (10k), traversal/symlink/hardlink rejection | **REAL**, attack-fixture tested |
| Safe exploit ZIP: 9 KB compressed / 2 MiB expanded, 128-file and 240-byte path caps; traversal and links rejected; Python argv allowlist; plaintext workspace zeroized best-effort, removed, and mounted read-only | **REAL**, adversarially tested |
| Rate limiting: per-wallet AND per-IP token buckets (5/hr default) | **REAL** |
| Immutable encrypted submission store with SHA-256 receipt, aggregate cap, and restart recovery | **REAL** locally via development directory; production uses the vsock helper and parent S3 broker |
| Chain-view divergence check → HTTP 409, never guesses | **REAL** |
| Verdict signing over exact 239-byte `SCB_VERDICT_V5` wire, including the on-chain manifest hash | **REAL locally**, golden-tested in `../test-vectors/verdict_v5.json`; this does not attest the signer |
| Sandbox execution (`SandboxExecutor`) | Development defaults to typed `StubSandbox`; local Docker is opt-in. Release defaults to daemonless Podman with internal per-verification networks, private user namespaces, dropped capabilities, no-new-privileges/read-only exploit rootfs, and a seccomp rule denying AF_VSOCK. The Podman implementation has not been run here; no enclave image yet packages Podman, its subordinate-ID maps, the seccomp profile, or the exploit runtime image. |

## Threat-model notes (maps to BUILD_PLAN §8 checklist)

- **Verdict-bit-only egress**: handlers return either a signed verdict or an
  error — no other channel exists in this process.
- **No logging of secrets**: `FlagString` has no `Display`; its `Debug`
  prints `[REDACTED]`. Master secret excluded from `Config` Debug output.
  Process output is not included in HTTP responses.
- **Intent gate ordering**: rate-limit (cheapest) → size caps → unseal
  (cheap X25519) → intent signature (403) → storage reserve → persist.
  Expensive unpack/execution never runs for impostors.
- **Chain-view divergence** between relayer claim and stored upload values
  aborts with 409 instead of guessing; full account-data proofs are the
  phase-9 upgrade.
- **Hash checks happen here**, inside the boundary, never trusted from the
  parent side.
- The development store persists only sealed submissions and authenticated
  metadata. Production storage runs through a fixed-key vsock broker; account
  credentials remain on the EC2 parent.

## Tests

```bash
cargo test        # unit, HTTP integration, blob and Docker-shim suites
cargo clippy --all-targets   # zero warnings expected
```

Latest recorded local result (2026-10-09): previous 72-test suite and Clippy passed
with warnings denied; the latest edits pass a release build, all-target compile
check, and 6 Docker-shim tests. These shims do not execute Podman. Docker-backed
execution, Nitro boot, AF_VSOCK integration,
attestation, KMS release, and deployed API routing remain open; see
[`../DEPLOYMENT-HANDOFF.md`](../DEPLOYMENT-HANDOFF.md).
