# SealedCodeBounty

A Solana protocol designed for confidential, automatically verified **exploit bounties**. The intended service has a buyer escrow a prize and hunters submit encrypted exploits for TEE-only execution; PASS pays the hunter and reveals the exploit to the buyer, while FAIL should leave it sealed. This is not a live guarantee today: the project remains pre-production and no attested verifier is deployed.

> **Authorized challenges only.** This project evaluates intentionally
> vulnerable environments supplied by their owner. Third-party targets,
> production systems, malware, credential theft, persistence, destructive
> payloads, and attempts to escape or contact systems outside the isolated
> challenge are prohibited. See [Security scope and acceptable use](SECURITY_SCOPE.md).

The project aims to reduce the trust gap in conventional bug-bounty review: hunters currently must trust a reviewer not to steal or leak work before payment. The intended design replaces that reviewer with a TEE-signed verdict checked on-chain; the production TEE and service are not deployed yet.

> **Status (2026-10-09):** pre-production and not deployed. The local code now
> includes the manifest-bound `SCB_VERDICT_V5` protocol, durable sealed-upload
> interfaces, bounded ZIP validation, and recovery tests. There is no public
> website, deployed devnet/mainnet program, measured EIF, attestation-gated KMS
> release, or proven enclave execution. The local runner defaults to a stub;
> Docker is not installed on the current machine. Do not accept real
> submissions or describe this as a live TEE service. Exact evidence, blockers,
> and next steps are in [`DEPLOYMENT-HANDOFF.md`](DEPLOYMENT-HANDOFF.md),
> [`tasks/todo.md`](tasks/todo.md), and [`docs/hosting-readiness.md`](docs/hosting-readiness.md).

## Table of contents
- [The problem](#the-problem)
- [How it works — user flow](#how-it-works--user-flow)
- [Architecture](#architecture)
- [Why AWS Nitro (and not Inco Lightning)](#why-aws-nitro-and-not-inco-lightning)
- [Repository layout](#repository-layout)
- [Verified local status](#verified-local-status-2026-10-09)
- [Quickstart](#quickstart)
- [Security scope and acceptable use](SECURITY_SCOPE.md)
- [§11 — Trust model (honest v1 disclosure)](#11--trust-model-honest-v1-disclosure)

## The problem

Anyone earning money by finding a security exploit for a prize currently has to expose their actual work *before* being guaranteed payment. The buyer or platform reviewer sees the exploit, and nothing stops them from taking it, rejecting the submission on a technicality, and using it anyway. Bounty platforms solve *payment* trust (via escrow) but not **code-theft** trust. SealedCodeBounty is designed to close that second gap for anything that can be objectively, automatically verified.

## How it works — user flow

1. **Buyer** packages a vulnerable environment (a Docker image with a placeholder `/flag`), locks a prize in escrow, and pins environment + manifest hashes and a `flag_commitment` on-chain via `create_bounty`.
2. **Hunter** develops an exploit against a **flag-stripped replica** (the dev plane), packages it as a bounded ZIP, then submits it encrypted to the configured verifier key.
3. **Intended production flow:** an attested AWS Nitro Enclave decrypts and executes the exploit in an isolated sandbox and checks whether the output contains the secret flag. This boundary is not implemented/proven yet.
4. The runner and program implement an **ed25519-signed `SCB_VERDICT_V5`** bound to the bounty, manifest, environment, exploit, solver, flag commitment, buyer key, and outcome. Local tests verify the bytes and signature checks; they do not prove the signer is an enclave.
5. A permissionless relayer can submit a verdict; the Solana program verifies it against operator keys pinned in `Config` and, on PASS, pays the hunter and writes an encrypted exploit into a `Reveal` PDA. These components have local tests but have not been deployed together to devnet or mainnet.

**Two-plane goal:** hunters develop against flag-stripped replicas; in production, the real flag and plaintext exploit should only coexist inside the enclave. The current local Docker prototype does not provide that TEE guarantee.

## Architecture

The diagram below is the intended production architecture; it is not deployed
or fully implemented yet.

```
┌─────────────┐  create_bounty (escrow SOL,        ┌────────────────────────┐
│    Buyer    │  pin env/manifest hashes,          │   Solana Program        │
└─────────────┘  flag_commitment, buyer X25519 pk)  │   (Anchor, on-chain)    │
                              ───────────────────▶  │  Config (operator keys) │
┌─────────────┐  submit_exploit                     │  Bounty PDA (escrow)    │
│   Hunter    │  (encrypted to enclave key) ─────▶  │  Reveal / Receipt PDAs  │
└─────┬───────┘                                     └───────────┬────────────┘
      │ develop against flag-stripped replica                   │ resolve_with_attestation
      ▼ (DEV PLANE — Docker + nsjail, NOT a TEE)                ▼ (Ed25519 verify + payout)
┌──────────────────────────────┐        signed verdict   ┌────────────────────┐
│  VERIFIER — AWS Nitro Enclave │ ───────────────────────▶│  Relayer (permissionless)
│  inject flag · run · sign     │                         └────────────────────┘
└──────────────────────────────┘
```

Full component specs, account layouts, the canonical verdict message, and the on-chain signature-verification pattern live in [`docs/BUILD_PLAN_v2.md`](docs/BUILD_PLAN_v2.md).

## Why AWS Nitro (and not Inco Lightning)

An earlier design (see `EXPLAIN.md`, pre-pivot history) used **Inco Lightning**. It was removed because it is the wrong primitive for this product:

- **Inco Lightning** provides *encrypted-data operations* — computing over ciphertext (e.g. equality over an encrypted integer). It cannot run arbitrary uploaded programs.
- Real exploit verification means unpacking a rootfs, injecting a flag, and running an **`nsjail`-sandboxed target + attacker binary** — a full userspace Linux workload.
- An **AWS Nitro Enclave** runs exactly that: a container rootfs + `nsjail` inside a hardware-isolated VM, producing a signed attestation. The on-chain interface is **signature-only**, so a later migration to Intel TDX / SEV-SNP (needed only for the kernel-exploit tier) changes pinned values, not program logic.

## Repository layout

| Path | What it is |
|---|---|
| `programs/sealed-code-bounty/` | Anchor program with escrow, refundable submission bond, `force_unlock_submission`, Receipts/Reveals, and manifest-bound `SCB_VERDICT_V5`; **local tests only, not deployed** |
| `cli/` | `scb-pack` challenge packaging and `scb-submit` hunter client; remote environment publication remains incomplete |
| `relayer/` | permissionless relayer with retry/recovery logic and atomic `[Ed25519SigVerify, resolve]` transaction construction; **not running as a hosted service** |
| `runner/` | Rust/axum verifier, sealed upload store, manifest/environment hash checks, bounded ZIP extraction, and V5 signing; Docker executor is opt-in, default sandbox returns HTTP 501 |
| `nitro/` | bounded parent/enclave vsock and S3-broker protocol prototypes with offline tests; not running in a Nitro Enclave |
| `infra/aws-nitro/` | Terraform draft for bounded staging; no resources created, PCR0 remains deny-all placeholder, and the current machine lacks Terraform/AWS CLI |
| `examples/echo-service/` | sample challenge for dogfooding `scb-pack` |
| `test/docker-shim/` | labeled test harness emulating docker subcommands so CI/dev machines without a daemon can exercise packager plumbing |
| `frontend/` | React + Vite + wallet-adapter client |
| `tests/` | ts-mocha integration tests (localnet-first) |
| `docs/BUILD_PLAN_v2.md` | authoritative specification (phases, accounts, wire formats) |
| `DEPLOYMENT-HANDOFF.md`, `tasks/todo.md` | authoritative current deployment gates, verified results, and handoff actions |
| `STATUS.md` | historical snapshot only; do not treat it as current status |
| `EXPLAIN.md` | pre-pivot (v1) per-file history — historical only |

## Verified local status (2026-10-09)

| Component | State | Tests |
|---|---|---|
| Anchor program | V5 manifest binding and escrow paths | 29 passing with `anchor test --skip-build --validator legacy`; no cluster deployment |
| Runner | sealed uploads, recovery, artifact/hash checks, bounded ZIP validation, V5 verdict | 72 passing; Clippy clean; no real Docker-backed run |
| Relayer | V5 verification and retry/recovery paths | 12 passing; no hosted relayer |
| CLI | package/submission contracts and ZIP checks | 12 passing; remote environment publication incomplete |
| Frontend | production bundle and lint succeed; local dev rig is a mock | lint/build pass; no browser E2E against a real runner |
| Nitro/infrastructure | dev-only application EIF built locally; Terraform bootstrap plan prepared | Podman runtime import/internal network passed on the local host; no Nitro boot, attestation/KMS release proof, or AWS resources |

These are local checks, not deployment proofs. Normal `anchor build` currently
reports a mismatch between the source program ID and the preserved program
keypair; `anchor build --ignore-keys` succeeds. Do not run `anchor keys sync`
without deliberately reviewing the identity change.

Historical phase snapshot (not current): [`STATUS.md`](STATUS.md).

## Quickstart

Prerequisites (Linux/WSL2): Rust, Solana CLI, Anchor, Node ≥ 20. Docker is
required for real local sandbox execution; Docker and Nitro CLI are absent from
the current machine. The following commands are local checks, not deployment.

```bash
# 1) Solana program — localnet suite; preserve the existing program keypair
anchor build --ignore-keys
anchor test --skip-build --validator legacy   # 29 passing

# 2) Packager CLI (needs a running docker daemon)
(cd cli && npm install && npm run build)
node cli/dist/index.js examples/echo-service --out out/
# no docker? prove the plumbing against the labeled harness:
PATH="$PWD/test/docker-shim:$PATH" SCB_SHIM_STATE=/tmp/scb-shim \
  node cli/dist/index.js examples/echo-service --out out/

# 3) Relayer — offline suite vs test fixtures
(cd relayer && npm install && npm test)          # 12 passing

# 4) Runner — Rust crate, fully offline tests
(cd runner && cargo clippy --locked --all-targets -- -D warnings)
(cd runner && cargo test --locked)                # 72 passing

# 5) CLI and frontend
(cd cli && npm install && npm test)               # 12 passing
(cd frontend && npm install && npm run lint && npm run build)
```

There is no production deployment command yet. A static host alone cannot serve
the browser-facing verifier API; do not publish this build as a working CTF
service until an authenticated HTTPS proxy, real enclave, deployed program,
explicit cluster/RPC configuration, and independent security review exist.
For a future static build, `(cd frontend && npm run build:deploy)` rejects
missing or obviously local/malformed production settings; it validates
configuration shape, not live service health or TEE attestation.
The budget-compatible hosting investigation is in
[`docs/hosting-readiness.md`](docs/hosting-readiness.md).

**Validator note:** Anchor 1.x defaults to the `surfpool` validator; this project runs its tests on the classic `solana-test-validator` via `--validator legacy`. An optional devnet smoke test is gated behind `SCB_DEVNET=1`.

## §11 — Trust model (honest v1 disclosure)

The intended v1 is **trust-minimized, not trustless**. The controls below are
design requirements, not claims about a deployed system:

- **Current reality:** there is no measured EIF, attestation verifier, PCR-pinned production KMS release, deployed operator key, multisig/timelock, or independent review. Local V5 signatures prove protocol wiring only.
- **Intended trust model:** a reproducibly built grader measurement is approved for key release; operator-key changes are governed by a visible multisig/timelock; the AWS account and KMS policy remain the v1 root of trust.
- **Roadmap** decentralizes this: threshold k-of-n operator sets, staked operators with slashing, and eventually full on-chain attestation verification.

Until the production gates pass, the system makes no live confidentiality or payout guarantee. Follow [`DEPLOYMENT-HANDOFF.md`](DEPLOYMENT-HANDOFF.md) for the remaining evidence required before real users or mainnet.
