# SealedCodeBounty

A confidential, automatically-verified **exploit bounty** protocol on Solana. A buyer posts a vulnerable environment and locks a prize in escrow; hunters submit exploits that are decrypted and run **only inside a hardware Trusted Execution Environment (TEE)**. An exploit succeeds if its output contains a hidden, platform-generated flag. On success the escrow releases to the hunter and the buyer receives the exploit; **on failure the exploit is never seen by anyone** — not the buyer, not the platform.

This removes the trust gap that existing bug-bounty platforms (Immunefi, HackerOne, Bugcrowd) structurally cannot close: today, submitting an exploit means trusting a human reviewer not to steal, leak, or reject-and-reuse your work before paying you. Here the human is replaced by a TEE-signed verdict the Solana program checks on-chain.

> **Status:** v2 is under active construction on the `v2` branch. The **escrow
> program works** (create / submit / resolve / cancel, tested on localnet), but
> the current `resolve_submission` is an **insecure manual placeholder** and
> submissions are currently **plaintext** — the confidential TEE verification
> flow is exactly what the v2 build adds. The full, authoritative spec is
> [`docs/BUILD_PLAN_v2.md`](docs/BUILD_PLAN_v2.md).

## Table of contents
- [The problem](#the-problem)
- [How it works — user flow](#how-it-works--user-flow)
- [Architecture](#architecture)
- [Why AWS Nitro (and not Inco Lightning)](#why-aws-nitro-and-not-inco-lightning)
- [Repository layout](#repository-layout)
- [Build & test](#build--test)
- [Current status vs. the plan](#current-status-vs-the-plan)
- [§11 — Trust model (honest v1 disclosure)](#11--trust-model-honest-v1-disclosure)

## The problem

Anyone earning money by finding a security exploit for a prize currently has to expose their actual work *before* being guaranteed payment. The buyer or platform reviewer sees the exploit, and nothing stops them from taking it, rejecting the submission on a technicality, and using it anyway. Bounty platforms solve *payment* trust (via escrow) but not **code-theft** trust. SealedCodeBounty closes that second gap for anything that can be objectively, automatically verified.

## How it works — user flow

1. **Buyer** packages a vulnerable environment (a Docker image with a placeholder `/flag`), locks a prize in escrow, and pins the environment + manifest hashes and a `flag_commitment` on-chain via `create_bounty`.
2. **Hunter** develops an exploit locally against a **flag-stripped replica** (the *dev plane* — a normal Docker sandbox, no TEE), then submits it **encrypted to the enclave's public key**. The plaintext never leaves their machine unencrypted.
3. The exploit is decrypted and executed **only inside an AWS Nitro Enclave** (the *verification plane*). The enclave injects the real flag, runs the exploit once against the target under `nsjail`, and checks whether the output contains the flag.
4. The enclave emits an **ed25519-signed verdict** bound to `{bounty, env, exploit, solver, flag_commitment, outcome}`.
5. A permissionless relayer submits the verdict; the Solana program **verifies the signature against operator keys pinned in `Config`** (via the native Ed25519 program) and, on PASS, pays the hunter and writes the encrypted exploit into a `Reveal` PDA for the buyer to decrypt. On FAIL, nothing releases and the exploit is discarded.

**Two-plane rule:** confidentiality only matters at *verification* time. Hunters develop against flag-stripped replicas with no secrets in them; the real flag and the plaintext exploit only ever coexist inside the enclave.

## Architecture

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

```
programs/sealed-code-bounty/   # the on-chain Anchor program (escrow today; v2 evolves it)
frontend/                      # React + Vite + wallet-adapter client
tests/                         # ts-mocha integration tests (localnet)
migrations/                    # Anchor deploy stub
docs/BUILD_PLAN_v2.md          # authoritative v2 specification
EXPLAIN.md                     # pre-pivot (v1) per-file history — historical only
```

## Build & test

Solana/Anchor development is done on **Linux / WSL2** (native Windows is not supported for the toolchain).

Prerequisites (in WSL2): [Rust](https://rustup.rs), the [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools), and [Anchor](https://www.anchor-lang.com/docs/installation) (via `avm`), plus Node ≥20.

```bash
# from the repo root, inside WSL2
npm install
anchor build
anchor test            # spins up a throwaway local validator (localnet-first)
```

`anchor test` runs on **localnet** by default — fast, deterministic, and free. An optional devnet smoke test is gated behind an env flag (`SCB_DEVNET=1`) and needs a funded devnet wallet.

## Current status vs. the plan

| Build phase (see `docs/BUILD_PLAN_v2.md` §5) | Status |
|---|---|
| 0. Cleanup — `v2` branch, Inco removed, localnet-first, README | **in progress** (this change) |
| 1. Program v2 — Config / Bounty-v2 / Receipt / Reveal + `resolve_with_attestation` | not started |
| 2. Packager CLI + manifest | not started |
| 3. Verifier runner (plain container first) | not started |
| 4. Wire runner ↔ program (relayer + real signatures) | not started |
| 5–8. Dev plane, frontend v2, Nitro envelope, indexer | not started |

What exists today is a **working SOL escrow program** with a manual (insecure-by-design) resolve and plaintext submissions — the money-movement scaffolding, proven by the tests in `tests/`. Everything that makes submissions *confidential and trustlessly verified* is the v2 work ahead.

## §11 — Trust model (honest v1 disclosure)

v1 is **trust-minimized, not trustless.** Be explicit about what users trust:

- **The grader (enclave) image is open source with a reproducible build.** Its measurement (`PCR0`) is pinned on-chain in `Config`; only that exact image can produce accepted verdicts.
- **Operator-key and config changes go through a multisig authority with a timelock**, so key swaps are visible and delayed, not silent.
- **The real root of trust in v1 is the AWS account and KMS key policy.** The master secret `M` (from which per-bounty flags and the enclave keys are derived) is released by KMS only to an attestation carrying the pinned `PCR0`. That means whoever controls the AWS account / KMS policy — not any on-chain mechanism — can ultimately release `M` or bless different code. **This is the weakest link in v1** and is not constrained by the Solana multisig.
- **Roadmap** decentralizes this: threshold k-of-n operator sets, staked operators with slashing, and eventually full on-chain attestation verification.

Nothing here silently weakens the core guarantee: **failed exploits stay sealed, and payouts only follow a verified enclave verdict.**
