# SealedCodeBounty — Project Overview (Vision & User Experience)

> **Purpose:** this document explains WHAT we are building and WHY, from a product and user perspective. It is the companion to `BUILD-PLAN.md` (which specifies HOW, technically). Terminology here matches the build plan exactly, so an AI reading both documents has goal + implementation aligned.

---

## 1. What we are building (elevator pitch)

**SealedCodeBounty is a trustless bug bounty marketplace on Solana where a company seals money and a vulnerable target, security hunters attack that target with exploits they keep secret, and a tamper-proof hardware enclave decides — automatically — whether an exploit won. If it wins: the hunter is paid instantly from escrow and the company receives the exploit. If it fails: nobody in the world ever sees the exploit.**

Think "pwn.college challenges + real money + no humans judging submissions," running as a permissionless marketplace where anyone can post a bounty and anyone can hunt one.

---

## 2. The problem we solve

### The core problem: code-theft trust

Today, submitting work to a bug bounty platform means **exposing your work before you are paid**, and trusting a chain of humans:

1. On HackerOne/Immunefi/Bugcrowd, a hunter sends their proof-of-concept exploit to the platform and to the vendor's security team.
2. Those humans now possess the exploit. Nothing technical stops them from: rejecting the report on a technicality and using the bug anyway, leaking it, delaying until the hunter gives up, or lowballing severity to shrink the payout.
3. Escrow services (Hats Finance, Immunefi's programs) solve *payment* trust — the money exists — but nobody solves **exploit secrecy**. The human reviewer is always inside the trust boundary.

For high-value findings this fear is rational and well-documented ("zero-knowledge proof of exploitability" discussions, Trail of Bits and others). Skilled researchers rationally under-participate, sell to brokers, or attack silently instead.

### Secondary problems

- **Human triage is slow and biased.** Days-to-weeks of judgment calls per report; severity disputes are common.
- **Proof quality varies.** Vendors receive prose reports and must reproduce bugs by hand.
- **No portable reputation.** A hunter's track record lives inside each platform's private database; it can't be proven to anyone else.
- **Challenge-style bounty programs exist but are closed and trust-based.** Google's kernelCTF pays $71,337 per verified kernel exploit — proof that objective, automated, flag-based verification works at the highest level — but only Google can run it, payment is at Google's sole discretion, and hunters must publicly publish their exploits within 90 days to get paid at all.

### Our thesis

The verification step — *"does this exploit actually work?"* — can be executed by hardware, not humans. Once verification is automatic and confidential, escrowed payment becomes atomic with disclosure, and the entire trust problem collapses into one question: *do you trust signed attestations from a measured enclave?* — the same class of trust browsers already extend to certificate hardware.

---

## 3. What the product is NOT (scope honesty)

- **Not a HackerOne replacement.** Open-ended *discovery* ("find any bug anywhere in this giant codebase") needs human judgment about impact. We serve the complementary case: **verification-style bounties**, where the buyer pins a specific vulnerable target into an environment and asks the world "prove you can break THIS." Real-world precedent proves demand: Pwn2Own, Google kernelCTF, Immunefi Attackathons.
- **No AI/ML magic, no ZK proofs, no custom cryptography** in v1. The novelty is the combination: sealed execution + Solana escrow + objective flag criterion.
- **v1 handles userspace targets only** (network services, binaries, parsers — the pwn.college universe). Kernel-level exploitation tiers come later.
- **Launch targets are self-authored challenges.** Until a proof-of-ownership mechanism exists, buyers post environments they wrote or have rights to (the pwn.college / kctf convention) — not packaged copies of third-party live products. This keeps us from becoming an accidental zero-day broker (review P1-8).

---

## 4. The users and their journeys

Two roles exist. Both are pseudonymous wallet holders; neither ever trusts the other, and neither trusts us with secrets.

### 4.1 The Buyer (company, protocol team, or any software owner)

*Goal: find out cheaply and provably whether my software can be exploited — and own the exploit if it can.*

1. **Prepare.** The buyer packages a vulnerable component they authored or control (v1 rule, see §3) into a Docker image — a small service with a bug (or suspected bug) — containing a placeholder file `/flag` that says `{{FLAG}}`. Our CLI tool (`scb-pack`) builds, checks, hashes, and uploads it; the buyer never touches infrastructure.
2. **Post.** In the web app, the buyer sets a prize (SOL), a deadline, and attaches the packaged environment. Their browser generates a fresh encryption keypair; only the public half goes on-chain. The platform's enclave returns a commitment to a secret per-bounty flag, which is pinned on-chain alongside the environment's SHA-256 hash. The buyer deposits the prize — **the smart contract holds it in escrow from this moment**.
3. **Wait.** Hunters attack. The buyer watches submissions appear (hashes only — contents invisible).
4. **Outcome A — someone wins.** The enclave verified an exploit captured the flag. Escrow pays the winner automatically. A `Reveal` account appears on-chain holding the exploit encrypted to the buyer's key; the app decrypts it in-browser and the buyer downloads a working exploit with full rights to fix their code. They also get an on-chain receipt proving the finding was independently reproduced.
5. **Outcome B — deadline passes unclaimed.** The buyer cancels and reclaims 100% of the prize. Nobody saw anything, nothing was leaked, cost = zero beyond posting.

Buyers also use this proactively: seal a just-patched version as a permanent standing bounty ("if you can still break my patch, the pot is yours") — continuous regression assurance that no audit firm offers.

### 4.2 The Hunter (security researcher, whitehat, student)

*Goal: get paid fairly and instantly for demonstrating an exploit — without ever risking theft of my work.*

1. **Browse.** The app lists open bounties: prize, deadline, description, number of attempts. Environments are downloadable as flag-stripped replicas — the hunter can spin up the exact target locally or in a browser sandbox (`docker compose up`, terminal in the page) and develop against it freely. The replica's `/flag` contains a harmless placeholder, so possessing it leaks nothing.
2. **Develop.** The hunter finds the vulnerability by any means — debugger, fuzzer, staring at disassembly — and writes an exploit script (a single Python file; pwntools is available). Against the replica, the script prints the placeholder flag when it truly works.
3. **Submit (sealed).** The hunter's browser encrypts `exploit.py` to the enclave's on-chain-pinned public key before it leaves the machine — no server, proxy, or bucket ever sees plaintext. A signed submission-intent binds the exploit to the hunter's wallet (nobody can submit on their behalf), and a small **refundable bond** accompanies the on-chain registration — returned automatically whatever the outcome; it exists purely so spamming attempts costs something.
4. **Verdict, minutes later.** Inside the enclave: the real secret flag was injected into a private copy of the environment; the exploit ran against it in a network-isolated sandbox; output scanned. Two possible endings:
   - **FAIL:** the hunter receives their own script's output back with any trace of the flag redacted — enough to debug why stage 3 crashed. The exploit itself is wiped from existence. No buyer, no admin, no log ever saw it. The slot frees; iterate and resubmit (free in v1).
   - **PASS:** the enclave signs a verdict binding `(bounty, exploit-hash, hunter-wallet, PASS)`; Solana verifies the signature against pinned enclave keys and releases the **entire pot** to the hunter in the same transaction that publishes the encrypted exploit for the buyer. The hunter also receives a permanent on-chain **Receipt** — portable, verifiable proof of a successful exploit, feeding a public leaderboard. First valid PASS takes the pot; everyone after is too late.
5. **Walk away rich and famous(ish).** Payment was never contingent on a human's mood, a triage queue, or the buyer's honesty — only on physics and signatures.

### 4.3 What each party can see, at every moment

| Artifact | Hunter | Buyer | Platform operator | Public chain |
|---|---|---|---|---|
| Environment (flag-stripped replica) | ✅ | ✅ | ✅ | ✅ |
| Real flag value | ❌ | ❌ | ❌ | ❌ (commitment hash only) |
| Exploit plaintext before PASS | author only | ❌ | ❌ (inside enclave only) | ❌ (hash only) |
| Failed exploits — forever | author only | ❌ | ❌ | ❌ |
| Winning exploit after payout | author | ✅ (decrypted client-side) | ❌ | ciphertext only |
| Verdicts, payouts, receipts, leaderboard | ✅ | ✅ | ✅ | ✅ |

---

## 5. Why these building blocks

- **Solana** — escrow that cannot be reneged, sub-second finality for first-PASS-wins ordering, native ed25519 signature checks for verdicts, negligible fees, and public receipts that turn hunter reputation into a portable, composable asset. Money movement and dispute-resistant record-keeping live entirely on-chain; the chain never touches secrets.
- **Trusted Execution Environment (AWS Nitro Enclave)** — a hardware-fenced black box even our own servers' admins cannot read. It is the only place where the three secrets (flag, exploit plaintext, environment-with-flag) ever meet. Its results leave only as short ed25519 signatures whose verifying key is pinned on-chain next to the measurement hash of the exact code that produced them.
- **Flag-capture as the success criterion** — the same convention as CTFs and kernelCTF: objective, binary, machine-checkable, immune to severity arguments. Because the flag is generated inside the enclave and never published, "I printed the flag" *is* "I exploited the target."

---

## 6. The promises (product-level guarantees)

1. **Sealed failures.** A rejected exploit is mathematically as good as deleted. No insider, backup, or log contains it.
2. **Pay-on-proof.** Funds move exclusively when a signature from pinned enclave hardware attests to success. Buyers cannot stall, dispute, or selectively pay.
3. **First blood wins.** Exactly one pot, objectively ordered by the blockchain.
4. **No human reads submissions.** There is no triage team, because there is nothing to triage.
5. **Reputation is earned, portable, public.** Every win mints a receipt no one can forge or revoke.
6. **Permissionless.** Any wallet can post a bounty; any wallet can hunt one. The protocol does not care who you are.

### Honest limitations in v1 (read before the promises above)

Promises 1–2 become literally true the moment client-side sealing ships (build-plan phase 3); until then, and structurally until verification decentralizes:

- **The enclave image is ours.** Verifiers trust the platform-pinned measurement (PCR0) and key. A malicious operator running a backdoored image could harvest failed exploits. Mitigations already in v1: client-side sealing, KMS-attestation-guarded flag material, signed verdicts. Full fix: multiple independent stake-backed operators (roadmap).
- **A censoring relayer can delay, not destroy:** permissionless `force_unlock_submission` refunds and reopens any bounty stuck awaiting resolution past a fixed timeout — funds can never be permanently locked by silence.
We state these limits in the README because overclaiming is worse than an honest boundary.

**Trust ladder (full version: `BUILD-PLAN.md` §11):** v1 ships Level 1 — grader source public, build reproducible (anyone can rebuild the EIF and compare PCR0 against the on-chain pin), operator-key changes behind multisig + timelock. Residual v1 trust: "the published grader source is clean" (openly auditable) and "AWS hardware is genuine" (industry-standard). Roadmap: federated k-of-n operators with staking (Level 2), ZK proof-of-exploitability (Level 3, ~zero trust for small targets). Say **"trust-minimized," never "trustless."**

---

## 7. What success looks like

- **Demo-day bar:** a live walkthrough — post a deliberately vulnerable service for 10 SOL, fail once with a broken exploit (showing the redacted feedback and total secrecy), then succeed and watch escrow pay while the buyer decrypts the reveal on screen.
- **Product-market signal:** the first bounty posted by a team we don't know, and the first payout claimed by a hunter we don't know.
- **North star metric:** verified-PASS payouts settled without any human intervention, and the share of hunters returning after their first win.

---

## 8. Glossary (shared vocabulary across all project docs)

| Term | Meaning |
|---|---|
| **Bounty** | An escrowed prize + deadline + sealed vulnerable environment, posted by a buyer |
| **Environment** | Docker-packaged vulnerable target; ships publicly with a placeholder flag |
| **Dev plane** | The normal-Docker sandbox where hunters develop against replicas; holds no secrets |
| **Verification plane** | The Nitro Enclave where real flags exist and submitted exploits execute; the only place secrets coexist |
| **Flag** | Random per-bounty secret derived inside the enclave; capturing it via the exploit = winning |
| **Exploit** | Single Python script (pwntools available) submitted by a hunter; sealed until PASS |
| **Verdict** | 97-byte canonical message `{bounty, exploit_hash, solver, outcome}` signed by the enclave's ed25519 key; the only thing crossing the enclave boundary |
| **Receipt** | Permanent on-chain record minted on PASS: bounty ↔ solver ↔ exploit hash; the reputation primitive |
| **Reveal** | On-chain account created on PASS holding the exploit encrypted to the buyer's X25519 public key |
| **First blood** | The first verified PASS on a bounty; takes the entire pot |
