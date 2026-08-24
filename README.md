# SealedCodeBounty

A sealed, automatically-verified exploit bounty protocol on Solana. A buyer seals money and a vulnerable target; security hunters attack it with exploits they keep secret; a tamper-proof hardware enclave decides — automatically — whether an exploit won. If it wins: the hunter is paid instantly from escrow and the buyer receives the exploit. If it fails: nobody in the world ever sees the exploit.

> ⚠️ **This repo pivoted.** Early versions of these docs described an Inco Lightning design. The current architecture is AWS Nitro Enclave + Solana — see [`BUILD-PLAN.md`](./BUILD-PLAN.md) (R3) for the authoritative spec and its revision log. `EXPLAIN.md` is pre-pivot history.

## The problem

Submitting work to a bug bounty platform means exposing your work *before* being paid, and trusting a chain of humans not to steal, leak, reject-and-reuse, or lowball it. Escrow services solve payment trust; nobody solves **exploit secrecy** — a human reviewer is always inside the trust boundary. For high-value findings this fear is rational and well-documented ("zero-knowledge proof of exploitability", Trail of Bits and others).

## How it works

1. **Buyer** packages a vulnerable service into a Docker image containing `/flag` = `{{FLAG}}` placeholder (`scb-pack` CLI), posts the bounty, locks the prize in an on-chain PDA escrow.
2. **Hunter** runs a flag-stripped replica locally (`docker compose up`, browser terminal included), finds the bug, writes `exploit.py`.
3. Hunter's client encrypts the exploit to the enclave's pinned public key — **proxies, storage, and logs only ever see ciphertext** — signs a submission-intent message proving authorship, and uploads.
4. Inside an **AWS Nitro Enclave**: the real flag is injected into a private copy of the environment; the exploit runs once in an nsjail sandbox with no network egress. If stdout contains the flag → PASS.
5. The enclave signs a canonical verdict binding `(bounty, environment hash, exploit hash, solver, flag commitment, outcome)`. The Solana program verifies the signatures against pinned enclave keys and atomically: pays the whole pot to the hunter, mints a reputation Receipt, and publishes the exploit encrypted to the buyer's key.
6. FAIL → redacted log back to the hunter (flag scrubbed in every encoding), everything else wiped. Retry.

**Why flag-capture:** objective, binary, machine-checkable — same convention as CTFs and Google kernelCTF ($71k/kernel-bug), which prove automated verification works but stay closed and discretionary. This makes it permissionless.

**Why Nitro Enclave over alternatives:** Inco Lightning computes *over ciphertext* (e.g. encrypted equality checks) — it cannot run arbitrary in-enclave code like unpacking a rootfs and nsjail-sandboxing binaries. MagicBlock is ephemeral-rollup scaling infrastructure. TEEs are the standard fit for "run any code in a sealed box."

## Scope honesty

- **Not a HackerOne replacement.** Open-ended discovery needs human judgment about impact. We serve **verification-style bounties**: buyer pins a specific target, world proves it breaks. Precedent: Pwn2Own, kernelCTF, Immunefi Attackathons.
- **v1 = self-contained CTF-style challenges**, userspace targets only (network services, binaries, parsers). Kernel tier is roadmap.
- **Trust model v1 = trust-minimized, not trustless.** Verification runs in our enclave image; the image source is public, the build is reproducible (anyone can compare their rebuilt EIF hash against the PCR0 pinned on-chain), and operator-key updates go through multisig with timelock discipline. What remains trusted: that the published grader source is honest, and AWS hardware. Federation (k-of-n independent operators) and ZK verification are the roadmap beyond that — full ladder in `BUILD-PLAN.md` §11.

## Guarantees

1. **Sealed failures** — a rejected exploit is as good as deleted; no insider, backup, or log contains it.
2. **Pay-on-proof** — funds move only when pinned enclave hardware attests success against *exactly the environment the buyer pinned*.
3. **First blood wins** — one pot, ordered by the blockchain.
4. **No human reads submissions** — no triage team exists.
5. **Portable reputation** — every win mints an on-chain receipt.
6. **Permissionless** — any wallet posts, any wallet hunts.

## Repo layout

| Path | What |
|---|---|
| `BUILD-PLAN.md` | Authoritative R3 spec: decisions D1–D14, component designs, phases, trust model |
| `PROJECT-OVERVIEW.md` | Product vision, user journeys, who-sees-what table |
| `EXPLAIN.md` | Pre-pivot file-by-file walkthrough (history) |
| `programs/sealed-code-bounty/` | Anchor program: escrow, submissions, verdicts, receipts |
| `frontend/` | React + Vite + wallet-adapter client |
| `tests/` | Integration tests (localnet-first) |

## Build status

Pre-phase-0. See `BUILD-PLAN.md` §5 for the phase plan and acceptance criteria.
