# scb-runner

Verifier runner skeleton (`docs/BUILD_PLAN_v2.md` §4.3) — the trust core of
SealedCodeBounty. Intended to run inside an AWS Nitro Enclave; the binary
binds `127.0.0.1:$PORT` (default 8443) and only ever talks to the parent via
the four `/internal/*` endpoints.

## Run

```bash
SCB_MASTER_SECRET_HEX=$(openssl rand -hex 32) \
SCB_ENCLAVE_ENC_SECRET_HEX=$(openssl rand -hex 32) \
SCB_SUBMISSION_STORE=development-directory SCB_ALLOW_DEV_DIRECTORY_STORE=1 \
PORT=8443 cargo run
```

Both secrets are required at startup; losing them only rotates flag/key
material, they never leave the process.

| Endpoint | Purpose |
|---|---|
| `GET /internal/healthz` | liveness |
| `POST /internal/seal_bounty {bounty_pda}` | → `{flag_commitment}` (deterministic across restarts) |
| `POST /internal/upload {bounty_pda, claimed_chain_view{env_blob_sha256,buyer_enc_pk,flag_commitment,exploit_sha256}, solver_pubkey, submit_intent_sig, exploit_sealed_box}` | → `{receipt}` |
| `POST /internal/verify {bounty_pda, solver_pubkey, submission_receipt, claimed_chain_view}` | verdict JSON mirroring `relayer/src/enclave-types.ts` |

## REAL vs STUB

| Piece | Status |
|---|---|
| Flag derivation `base58(HKDF-SHA256(M, salt=pda, info="scb-flag-v1"))` | **REAL** + golden vector (`tests/golden/verdict_v3.json`) |
| Stable verdict key `HKDF(M, info="scb-verdict-key-v1")` (D14) | **REAL**, ed25519-dalek |
| Intent-signature gate `SCB_SUBMIT_V1‖pda‖sha256(plaintext)` — 403 before any heavy work | **REAL** |
| Sealed-box unseal/seal (libsodium-compatible, `crypto_box` crate) | **REAL** (hunter→enclave on upload; enclave→buyer reveal on PASS) |
| Public execution log | **REAL**, fixed PASS/FAIL text only; process output is never returned |
| Safe rootfs unpack: total-size cap (2 GiB default), file-count cap (10k), traversal/symlink/hardlink rejection | **REAL**, attack-fixture tested |
| Rate limiting: per-wallet AND per-IP token buckets (5/hr default) | **REAL** |
| Immutable encrypted submission store with SHA-256 receipt, aggregate cap, and restart recovery | **REAL** locally via development directory; production uses the vsock helper and parent S3 broker |
| Chain-view divergence check → HTTP 409, never guesses | **REAL** |
| Verdict signing over exact 175-byte `SCB_VERDICT_V3` wire | **REAL**, golden-tested |
| Sandbox execution (`SandboxExecutor`) | **STUB by default**: `StubSandbox` answers typed `Unsupported` → HTTP 501. `DockerCli` impl composes `docker run` arg-arrays (network/memory/cpus/SEED env, work-dir mount) but is not yet wired to blob pulling or a live target container. |

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
