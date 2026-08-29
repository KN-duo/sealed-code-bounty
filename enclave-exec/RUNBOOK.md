# Runbook — verify the real workflow on your Linux box

Run these in order. Each step gates the next, so stop and report if one fails —
we fix at that layer instead of debugging four at once.

## 0. One-time setup (Docker + Solana host)

```bash
# a. build the program (needs Anchor toolchain)
anchor build                          # -> target/deploy/*.so

# b. build the judge images (needs Docker)
bash enclave-exec/build.sh            # -> scb-target, scb-runtime

# c. install deps + build the cli
npm --prefix relayer install
npm --prefix cli install && npm --prefix cli run build

# d. Arweave (Turbo) storage for the exploit delivery
npm --prefix enclave-exec install
```

## 1. Confirm your chain environment works (mock)

```bash
./e2e/localnet.sh
```
Expect: "E2E RESULT: MODE=happy ALL ASSERTIONS PASSED". This proves the
validator, program, relayer, and payout path work — with a fake judge.

## 2. Confirm the real judge works (no chain)

```bash
node enclave-exec/selftest.cjs
```
Expect: PASS for solve.py, FAIL for solve-broken.py, and "buyer decrypted the
delivered exploit, bytes match". This proves the novel core: the exploit is
sealed (only the enclave can read it), it runs in a hidden Docker sandbox, the
verdict comes from real flag capture, and the buyer gets the exploit back on PASS.

## 3. The two joined — real execution drives the on-chain payout

```bash
bash enclave-exec/localnet-real.sh
```
Expect: "FULL REAL CYCLE PASSED". A prize is escrowed, a sealed exploit is
submitted, the enclave runs it for real, the flag is captured, and Solana pays
the hunter + delivers the exploit to the buyer — atomically.

If step 3 passes, the entire money-half of the product works end to end:
**upload a (sealed) exploit → it runs in a hidden sandbox → flag → Solana pays
the hacker and hands the exploit to the company.**

## What this does NOT yet include (the website layer)
- The in-browser VM embedded in the site (hunter-vm exists standalone).
- A zip upload field on the bounty page wired to this flow.
- A company "upload your vulnerable program" flow (per-bounty targets; today the
  enclave uses the baked ret2win target for every bounty).
These are the next layer, built once the backend above is verified.

## Notes / current simplifications (pre-TEE)
- The enclave holds its keys in env vars, so pre-TEE the operator can technically
  read exploits. The confidentiality guarantee becomes absolute only in the real
  TEE (Nitro Enclave) — see docs/integration-plan.md, phase P6.
- Every bounty is judged against the same baked ret2win target. Per-bounty
  targets (from the company's uploaded program) are the next backend increment.
