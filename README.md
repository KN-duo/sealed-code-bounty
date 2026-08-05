# SealedCodeBounty

A confidential, automatically-verified bounty protocol on Solana. Post a bounty with an automated test/verification suite and locked prize money; solvers submit solutions that are checked **inside a secure enclave** — nobody, including the bounty poster or the platform, ever sees a submission unless it's verified correct **and** payment has already been released. If it fails, the code is never exposed to anyone.

This fixes something existing bug bounty platforms (Immunefi, HackerOne, Bugcrowd) structurally cannot: today, submitting an exploit or solution means trusting a human reviewer not to steal, leak, or reject-and-reuse your work before paying you. This protocol removes that human entirely for anything that can be objectively, automatically checked.

## Table of contents
- [The problem](#the-problem)
- [How it works — user flow](#how-it-works--user-flow)
- [Architecture](#architecture)
- [Why Inco Lightning (and not Magic Block or Arcium)](#why-inco-lightning-and-not-magic-block-or-arcium)
- [Detailed technical flow](#detailed-technical-flow)
- [MVP scope — what we're building first](#mvp-scope--what-were-building-first)
- [Tools & environment setup](#tools--environment-setup)
- [Build plan — step by step](#build-plan--step-by-step)
- [Open risks / honest unknowns](#open-risks--honest-unknowns)

## The problem

Anyone who wants to earn money by writing a program to spec, finding a security exploit, or solving an algorithmic challenge for a prize currently has to expose their actual work *before* being guaranteed payment. The buyer (or platform reviewer) sees the solution, and there's nothing stopping them from taking it, rejecting the submission on a technicality, and using it anyway. This is a real, documented fear in security research (see the "zero-knowledge proof of exploitability" discussions from Trail of Bits and others) — bounty platforms today solve payment trust (via escrow) but not **code-theft trust**.

## How it works — user flow

1. **Buyer** posts a bounty: a description, an automated test suite (or exploit-verification script), and locks the prize amount in escrow on Solana. The tests themselves are public — only *solutions* are secret.
2. **Solver** writes a candidate solution locally, pays a small non-refundable anti-spam fee, and submits it **encrypted** — the plaintext code never leaves their machine unencrypted.
3. The encrypted submission is decrypted and executed **only inside a Trusted Execution Environment (TEE)** — a hardware-secured black box that not even the platform operator can see inside.
4. The TEE runs the buyer's tests against the solution and produces a **signed attestation**: PASS or FAIL, cryptographically provable to have come from genuine, untampered hardware.
5. The Solana program checks the attestation signature. If PASS: the escrowed prize releases **automatically** to the solver, and the buyer receives the now-paid-for solution. If FAIL: nothing releases, and the code is discarded — never seen by anyone.

## Architecture

```
┌─────────────┐        1. create bounty          ┌──────────────────────┐
│    Buyer    │ ───────(tests + locked prize)───▶ │   Solana Program      │
└─────────────┘                                    │   (Anchor, on-chain)  │
                                                     │  - Escrow PDA         │
┌─────────────┐        2. pay fee +                │  - Submission registry│
│   Solver    │ ───────submit encrypted code───▶   │  - Attestation check  │
└─────────────┘                                     │  - Payout logic       │
                                                     └───────────┬───────────┘
                                                                 │ 3. request execution
                                                                 ▼
                                                     ┌──────────────────────┐
                                                     │   Inco Lightning TEE  │
                                                     │  - Decrypts code      │
                                                     │    INSIDE enclave     │
                                                     │  - Runs vs. tests     │
                                                     │  - Signs attestation  │
                                                     └───────────┬───────────┘
                                                                 │ 4. signed PASS/FAIL
                                                                 ▼
                                                     back to Solana Program
                                                     → releases escrow automatically
```

## Why Inco Lightning (and not Magic Block or Arcium)

I compared all three live Solana confidential-compute options before deciding:

| | Paradigm | Fit for "run arbitrary untrusted code confidentially" |
|---|---|---|
| **Inco Lightning** | TEE-based, general confidential computation, private data types + operations | **Best fit.** This is exactly its stated purpose — encrypted data stays encrypted *during computation*. Integrates directly with Anchor/Rust + a JS SDK. Has a beginner quickstart. |
| **Magic Block** | TEE-based (Intel TDX), but framed around "Ephemeral Rollups" — delegating *accounts* to a temporary high-throughput execution environment, mainly for scaling | Weaker fit. Its core primitives (`delegate_account`, `commit_and_undelegate_accounts`) are built for moving on-chain *state* into a faster environment, not for "confidentially execute this arbitrary uploaded program." Privacy is a secondary use case for it, not the core design. |
| **Arcium** | MPC-based (multi-party computation), flagship use cases are confidential DeFi (private swaps, lending) | Wrong paradigm. MPC is best for computing one *predefined* function over private inputs from multiple parties — not for running arbitrary, potentially adversarial, uploaded programs. TEEs are the standard fit for "run any code in a sealed box," which is what we need. |

**Docs:** https://docs.inco.org/svm/home · beginner tutorial: https://solskills.sh/skills/inco

## Detailed technical flow

**On-chain (Solana / Anchor program) responsibilities:**
- `create_bounty(test_suite_hash, prize_amount, deadline)` — buyer locks `prize_amount` into a PDA (Program Derived Address) acting as escrow. `test_suite_hash` commits to the public test suite so it can't be silently changed later.
- `submit_solution(bounty_id, encrypted_submission_ref)` — solver pays the anti-spam fee (transferred into the program, non-refundable) and registers a reference/pointer to their encrypted submission (the ciphertext itself may live off-chain, e.g. via the Inco SDK's storage, with only a hash/reference on-chain).
- `resolve_submission(bounty_id, submission_id, attestation)` — anyone (typically a relayer/cron, or the solver) can call this once the TEE has produced a result. The program **verifies the attestation's signature against Inco's known TEE public key** — this is the trust anchor: we don't trust the platform, we trust the hardware manufacturer's signing key, the same way a browser trusts a certificate authority.
- If the verified attestation says PASS → transfer escrowed funds to the solver's wallet, mark bounty resolved, reveal the decrypted solution to the buyer.
- If FAIL → no transfer, submission discarded, solver may retry (new fee).

**Off-chain / TEE (Inco Lightning) responsibilities:**
- Provide the encryption primitives the solver's client uses before submission ever leaves their machine.
- Decrypt and execute the submission **only inside the enclave**.
- Run the buyer's test suite against it.
- Produce a **remote attestation**: a signed report proving *which* code ran, *what* result it produced, and that it genuinely executed on unmodified, genuine TEE hardware — this signed report is what the Solana program checks in `resolve_submission`.

**Frontend responsibilities:**
- Solana wallet connection (wallet-adapter).
- Bounty creation form (buyer): description, test suite upload, prize amount.
- Submission form (solver): code upload → client-side encryption via Inco's JS SDK → submit.
- Status view: pending / passed / failed, payout confirmation.

## MVP scope — what we're building first

Full arbitrary security-exploit verification (sandboxing genuinely malicious, system-level code safely) is a much bigger and riskier engineering problem than we should take on for a first build. **For the demo, scope to Codeforces-style coding challenges**: buyer provides a function signature + input/output test cases, solver submits a function in one fixed language (pick Python or JavaScript — simplest to sandbox and test). This keeps the *verification harness* simple (run function, compare output to expected, no OS-level sandboxing concerns) while still proving the full confidential-submit → verify → auto-pay mechanism end-to-end. Real bug-bounty-grade exploit verification becomes the stated post-residency roadmap item, not something we need working by Demo Day.

## Tools & environment setup

You'll need:
- **Rust** + **Solana CLI** + **Anchor framework** — for the on-chain program
- **Node.js** + **@solana/web3.js** + **@solana/wallet-adapter** — for the frontend
- **Inco Lightning SDK** (Rust crate for the Anchor program side, JS SDK for client-side encryption) — https://docs.inco.org/svm/home
- A **Solana devnet wallet** with devnet SOL (via `solana airdrop`)
- Basic **React/Next.js** for the frontend (or plain HTML/JS if time is short — functionality over polish for the demo)

## Build plan — step by step

1. **Environment setup** — install Rust, Solana CLI, Anchor, Node.js; create devnet wallet; get devnet SOL.
2. **Bare-bones Anchor program, no confidentiality yet** — implement `create_bounty` (escrow PDA) and a plaintext `submit_solution` + manual `resolve` to prove the escrow/payout logic works in isolation, using devnet, before adding any TEE complexity.
3. **Integrate Inco Lightning** — work through their quickstart, get a minimal "encrypt something, decrypt+compute inside the enclave, get an attestation back" example running standalone (outside our program) first.
4. **Wire the TEE into the program** — replace the plaintext submission flow with the real encrypted-submit → TEE-execute → attestation-verify → payout flow.
5. **Minimal frontend** — wallet connect, create-bounty form, submit-solution form, status display.
6. **End-to-end test on devnet** — create a real coding-challenge bounty, submit a correct and an incorrect solution, confirm payout only happens on PASS and the incorrect solution is never exposed.
7. **Demo polish** — pick one compelling example bounty to walk through live on Demo Day.

## Open risks / honest unknowns

- **Inco Lightning is in beta** (launched devnet Jan 2026) — expect sparse docs/examples relative to mature tools, more trial-and-error than usual.
- **Attestation verification on-chain** — need to confirm exactly how Inco's TEE public keys are distributed/checked from within an Anchor program; this is the crux of the trust model and needs to be validated early, not assumed.
- **Submission storage** — encrypted submissions likely need to live off-chain (Solana account storage is expensive for arbitrary code blobs); need a storage approach (e.g. Arweave, or Inco's own storage primitives if provided) with only a hash/reference on-chain.
- **Language sandboxing** — even for the simplified MVP (one language, function-based), confirm what the TEE execution environment actually supports before assuming it can run arbitrary user code out of the box.
