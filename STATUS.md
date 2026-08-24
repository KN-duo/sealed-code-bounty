# STATUS.md — single source of truth (as of 2026-08-25)

Maps every phase row of `docs/BUILD_PLAN_v2.md` §5 to the actual repo state,
with commit hashes. If this file and the build plan disagree, this file wins.

## Phase table

| Phase | Scope | State | Evidence |
|---|---|---|---|
| 0 — Cleanup & foundations | Inco POC removed, docs pivoted to Nitro, tests localnet-first | **DONE** | `4799431`, `8dfbd5e` |
| 1 — Solana program v2 | Config/Bounty-v2/Receipt/Reveal; 7 instructions incl. `force_unlock_submission`; SCB_VERDICT_V3 with `env_blob_sha256` binding; refundable bond; post-deadline submit guard | **DONE** — `anchor test`: 24 passing / 0 failing | `3c5d48d`, `b44f6f8`, fixes `49a7043` + `a3d863f`, suite `71803b3`, reviewed merge `5cef7d6` |
| 2 — Packaging (`scb-pack`) | docker build → `/flag` placeholder gate → save│gzip → sha256-pinned tarball → manifest v2 → dev-plane compose w/ D13 setarch parity | **DONE except R2 upload** (`uploadTarball()` is a typed stub; manifests reference the local relative tarball path) | `f4391a6`; shim-tested end-to-end (`test/docker-shim`), real-docker path reasoned |
| 3 — Verifier pipeline | Rust runner crate: flag derivation, intent gate, safe unpack, redaction D11, abuse controls, verdict signing V3 + golden cross-language fixture | **DONE except real sandbox execution** (`SandboxExecutor::DockerCli` composes real arg-arrays but is not wired to blob pulling/live targets; `StubSandbox` answers typed 501) | `6d33857` |
| 4 — Relayer + wiring | Event ingestion, dedupe, enclave client w/ backoff, local sig pre-check, atomic `[Ed25519SigVerify, resolve]` landing | **PARTIAL** — complete against the mock enclave (`relayer/test/mock-enclave.cjs`, 6/6 tests); the LIVE loop still needs the runner's real sandbox (phase-3 gap) and real enclave operator keys pinned via `set_operators` | `7468773` |
| 5 — Dev plane hosting | Browser-terminal sandbox service | Untouched by design (review P1-9: malware-hosting liability). Packager emits local `docker-compose.yml` instead — hunters run replicas on their own machines | — |
| 6 — Frontend v2 | Buyer/hunter flows over new IDL | Untouched — frontend skeleton still targets v1 instruction names; needs an IDL refresh pass once phase 1 UI work starts | — |
| 7 — Nitro envelope | EIF packaging, attestation ceremony, KMS-conditioned master secret | Untouched — deliberately last (BUILD_PLAN §10 "don't start with the TEE"); runner was built container-first so this is an envelope step | — |
| 8 — Indexer + leaderboard | Receipt indexing, hunter leaderboard API/page | Untouched — receipts already exist on-chain from phase 1, so this is read-only tooling whenever needed | — |
| 9 — Roadmap tiers | Kernel-tier targets (TDX/SEV-SNP CVMs), staked multi-operator network + slashing, fees, Arweave migration, disclosure clock, ZK backends | Untouched — all gated behind shipping 5–8 | — |

## REAL vs STUB (per component)

### Solana program (`programs/sealed-code-bounty`) — COMPLETE
Nothing stubbed. Verified invariants: V3 wire binding of
`env_blob_sha256`+`flag_commitment`, solver bond accounting across
PASS/FAIL/unlock, post-deadline submit guard, threshold-over-distinct-
operators ed25519 introspection. Tests: 24 passing on localnet.

### Packager (`cli/scb-pack`) — COMPLETE, one stub
- REAL: docker build/create/cp/save orchestration (arg arrays only),
  placeholder enforcement, sha256 streaming hash, manifest v2 emission,
  compose generation with verifier-parity contract.
- STUB: `uploadTarball()` → exit 5 until phase-2 storage credentials exist.
- Tested via `test/docker-shim` harness (labeled as such); a machine with a
  real daemon exercises the identical code path.

### Relayer (`relayer/`) — COMPLETE vs mock enclave
- REAL: event ingestion + PDA dedupe, chain-state re-validation of events,
  enclave HTTP client (5× exponential backoff, retryable-only transport
  errors), local tweetnacl verification of reconstructed SCB_VERDICT_V3
  bytes BEFORE fees are spent, atomic two-instruction landing, graceful
  shutdown, JSON-lines logging.
- PENDING: any live enclave (mock signs canned verdicts by design).

### Runner (`runner/`) — CORE COMPLETE, execution stubbed
- REAL: FlagString no-leak newtype; deterministic flag HKDF derivation;
  stable verdict-key derivation (D14); submit-intent signature gate (403
  before heavy work); sealed-box unseal/seal (libsodium-compatible);
  redaction engine D11 incl. double encodings + fail-closed sweep; safe
  rootfs unpack (size/file-count/traversal/symlink/hardlink); per-wallet +
  per-IP token buckets; global storage cap → 503; TTL sweeper; chain-view
  divergence → 409; verdict signing over exact 175-byte wire.
- STUB: sandbox execution (`StubSandbox` → HTTP 501 typed).
- Golden cross-language vector committed:
  `runner/tests/golden/verdict_v3.json` (TS-side nacl verification proven by
  reviewer).

### Dev plane — GENERATED ARTIFACT
`scb-pack` emits per-bounty `docker-compose.yml` (target + pwntools
workspace + ttyd :7681) applying the same determinism block the verifier
applies (D13 parity contract documented in the generated file header).

## Test counts at HEAD (`6d33857` + docs)

| Suite | Command | Result |
|---|---|---|
| Solana program | `anchor test --skip-build` | 24 passing |
| Relayer | `(cd relayer && npm test)` | 6 passing |
| Runner | `(cd runner && cargo test)` | 28 passing (19 lib + 9 api) |
| Runner lint | `(cd runner && cargo clippy --all-targets)` | 0 warnings |
| Packager | `(cd cli && npm run build)` | green (+ shim demo in §README) |
