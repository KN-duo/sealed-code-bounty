# SealedCodeBounty — Independent Review Handoff

> **Context:** this is an external review of `PROJECT-OVERVIEW.md`, `BUILD-PLAN.md`, `README.md`, and `EXPLAIN.md` as committed to gist `e38ecb21f19d9df6c763b6105eaba4ca`. The overall architecture (flag-capture verification, two-plane rule, signature-only chain interface, phased build order) is judged sound. This document lists what must change before implementation continues, ranked by severity. Each item states the problem, why it matters, and the concrete fix.

---

## P0 — Critical: break the core promise or lose funds

### 1. v1 transport exposes plaintext exploits to the platform operator

**Problem:** BUILD-PLAN §4.4 step 5 allows TLS to terminate at the parent proxy in v1 ("may accept trusting the parent proxy for transport"). The hunter's `exploit.py` therefore arrives at the operator's server **in plaintext before entering the enclave**. The operator can sniff a passing exploit, submit it from a second wallet, and take first blood — and since the operator also controls verdict ordering, they always win that race. This directly falsifies PROJECT-OVERVIEW promise #1 ("No human reads submissions") in v1.

**Fix (do in phases 3–4, not roadmap):**
- Hunter client encrypts the exploit **client-side** to the enclave's attested public key (from a fresh attestation doc) before any upload. The proxy only ever relays ciphertext.
- TLS terminates inside the enclave with the self-signed cert hash in the attestation doc's `user_data` (the pattern already named in §4.4) — ship it in v1, don't defer it.
- Until both land, the README must say plainly: "v1 trusts our proxy; sealing the transport is step X." Overclaiming is worse than an honest limitation.

### 2. Enclave does not authenticate the solver — relayer can steal authorship

**Problem:** The verdict message (§4.1) binds `solver_pubkey`, but the verify endpoint (§4.3: `POST /internal/verify {bounty_pda, manifest, exploit_py}`) carries no solver identity and no authentication. The enclave learns the solver from the relayer and signs whatever pubkey it is told. A hostile relayer submits a victim's exploit while naming its own wallet as solver and collects the pot.

**Fix:**
- Add to the verify request: `solver_wallet_sig = ed25519_sign(solver_keypair, b"SCB_SUBMIT_V1" || bounty_pda || exploit_sha256)`.
- The enclave verifies this signature against the claimed solver pubkey **before** running anything, and refuses on failure. Now the verdict's `solver_pubkey` field is cryptographically bound to whoever possessed the exploit, not to whatever the relayer asserted.
- Update §4.1 verdict spec and §4.3 endpoint spec accordingly, plus a program-side test: verdict whose solver never signed the submission intent must be rejected (this is enforceable off-chain only if the intent signature is echoed into the Reveal/Receipt — document where it lives).

### 3. Master secret HKDF is a single point of total compromise

**Problem:** §4.3 step 3 derives every flag as `HKDF-SHA256(M, salt=bounty_pda)`. One leak of master secret `M` reveals **every flag for every bounty, past and future** — holder claims first blood on everything. And because M is delivered by the operator post-attestation (§4.4 step 4), a plaintext copy of M necessarily exists on the parent side, outside the enclave.

**Fix:**
- Move KMS-conditioned delivery into v1: AWS KMS key policy granting Decrypt only when the request carries a valid attestation doc with the pinned PCR0 (`aws-nitro-enclaves-kmi`-style pattern). M then never exists in plaintext on the parent.
- Alternative: per-bounty flags from NSM RNG at seal time, wrapped to KMS immediately; drop the global-HKDF design entirely.
- At minimum, document the blast radius honestly in D7/§9 if deferring: "compromise of M compromises all flags."

### 4. Relayer censorship has no recourse → funds deadlock

**Problem:** Only the designated relayer sees verdicts (§4.6). If it suppresses a FAIL verdict, `current_submission` stays locked forever, and `cancel_expired_bounty` explicitly refuses while a submission is pending — prize locked indefinitely with no escape hatch. Same if it sits on a PASS.

**Fix:**
- New instruction `force_unlock_submission(bounty)`: permissionless, callable T hours after `submit_exploit` if still `AwaitingResolution`. Small program addition; add tests (unlock restores Open + allows cancel path).
- Allow **any** pinned operator enclave to serve any submission (D7's set design already supports n>1): publish submissions to all operators, first valid verdict wins. One hostile relayer can then delay but not silence.

### 5. Free unlimited submissions × single slot = griefing + compute DoS

**Problem:** D10 removed all fees, but every submission costs real money to verify (metal instance burst, up to 60s+ sandbox per run). Anyone can spam junk submissions to hold the slot, block real hunters, and burn platform compute. There is zero cost to attack.

**Fix:** reinstate *something* with a refund path:
- Option A (simplest): small flat submission fee, burned or routed to treasury (revert D10).
- Option B: submission bond refunded automatically inside `resolve_with_attestation` (either outcome) — spam then costs only rent/tx fees and griefing becomes self-limiting.

---

## P1 — Significant: credibility and liability

### 6. Trust-root overclaim vs. D7 reality
PROJECT-OVERVIEW promises "no human reads submissions" while D7 concedes v1 users trust the platform operator entirely (pinned PCR0 chosen by us; a backdoored image harvests failed exploits). State the limitation verbatim in the README trust section and keep promises #1/#2 scoped to "once transport-sealing ships." Honest scoping reads better to judges/grant reviewers than absolute claims contradicted three sections later.

### 7. R2 is a 0day honeypot under the current flow
Exploit blobs are uploaded server-side pre-verdict; a bucket misconfiguration leaks every failed exploit at once. Client-side encryption to the enclave's attested pubkey (fix #1) resolves this too — make "storage never sees plaintext" an explicit invariant in §8's checklist.

### 8. No buyer proof-of-ownership → accidental 0day broker
Nothing binds a bounty's target to software the buyer controls. Anyone can package someone else's vulnerable product and buy working exploits against it. For v1:
- Reposition scope as **self-contained CTF-style challenges** (buyer-authored targets, pwn.college/kctf convention) until an ownership mechanism exists.
- Cheap partial signal to add later: packager requires the image to answer a wallet-signed nonce challenge at build time.

### 9. Dev plane hosts untrusted third-party binaries on platform VMs
§4.5 runs anonymous buyers' Docker images on shared infrastructure with "no multi-tenancy hardening yet," and §8 proposes a review queue that contradicts promise #6 (permissionless). Dropping hosted dev plane for v1 (see Better Ideas #2) eliminates the whole problem class.

### 10. Stale docs contradict each other in the same gist
README still architects around Inco Lightning; OVERVIEW/BUILD-PLAN say AWS Nitro; EXPLAIN.md describes the pre-pivot manual-resolve program. Phase 0 cleanup covers some of this — extend it to rewrite README's "Why Inco" section into "Why Nitro / why we pivoted," so no reader meets two architectures.

---

## Better ideas worth adopting

1. **Reorder phases around making the pitch true:** client-side encryption (#1), signed submission intent (#2), KMS-conditioned flags (#3) are cheaper than the Nitro envelope itself and convert the marketing claims from aspirational to actual. Slot them into phases 3–4.
2. **Drop the hosted dev plane for v1.** `scb-pack` already emits a compose file — hunters run replicas locally. Zero hosting cost, zero malware liability, cleaner permissionless story. Browser terminal becomes a phase-5+ nicety.
3. **Submission timeout instruction** (`force_unlock_submission`) — small, kills deadlock #4, pairs with the bond idea in #5.
4. **CTF-challenge-first positioning** sidesteps ownership-proof entirely for launch; matches the kernelCTF precedent the overview already cites.
5. Consider **GCP Confidential Space instead of Nitro for the hackathon demo**: attestation-to-KMS is first-class there, $300 trial covers it, and per D6 the chain interface is identical either way.

---

## Suggested execution order for the fixes

| Step | Change | Where |
|---|---|---|
| 1 | Solver-signed submission intent in verify API + verdict binding | §4.3, §4.1 |
| 2 | Client-side encrypt-to-enclave upload (kill plaintext-at-proxy) | §4.4 step 5, §4.3 |
| 3 | Replace global-HKDF flags with KMS-attestation delivery | §4.3 step 3, §4.4 step 4 |
| 4 | `force_unlock_submission` + multi-operator serving | §4.1 instructions, §4.6 |
| 5 | Submission fee or refundable bond | D10 |
| 6 | Scope statement: CTF-style challenges only in v1 | §3 of OVERVIEW, README |
| 7 | Drop hosted dev plane; local compose only | §4.5 |
| 8 | README rewrite: Nitro narrative, honest trust-root section | phase 0 |

Items 1–5 are spec changes (cheap, do before code); 6–8 are doc/scope edits. None require re-litigating D1–D12's core decisions.
