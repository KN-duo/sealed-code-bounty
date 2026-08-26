# HANDOFF — Finish Task 11: localnet dress-rehearsal scripts
> Paste this entire file into your model. Everything below is verified fact as of
> commit `fb20078` + uncommitted working-tree changes described in §3.

## 1. SITUATION

Repo: `~/Documents/work/sealed-code-bounty` (branch main). Project: **SealedCodeBounty**
— Solana sealed-exploit-bounty protocol. All major components are built and tested
(program v2 with 28 tests, packager CLI, relayer, Rust verifier runner, hunter client
`scb-submit`). Read root docs first: `PLAN-PRE-TEE.md` (roadmap — your job is Step 5),
`STATUS.md`, `BUILD-PLAN.md` §1 D1–D14 (locked decisions).

A previous agent ("left chat") was executing **Task 11**: create end-to-end localnet
dress-rehearsal scripts. It died mid-task when its LLM provider returned an unrecoverable
session-ending `503 Upstream request failed` API error (infra outage, not its fault).
You are inheriting its unfinished work.

## 2. WHAT IT ACCOMPLISHED BEFORE DYING (all verified)

- Wrote three files under `e2e/` (currently UNTRACKED):
  - `e2e/localnet.sh` (~12 KB bash orchestrator; header: "LOCALNET DRESS REHEARSAL,
    PLAN-PRE-TEE.md Step 5") — full happy-path lifecycle with step/assert functions.
  - `e2e/chain.mjs` (~10.8 KB node helper + CLI: wallet/PDA helpers, instruction
    builders; has case `"init-config"` around line 151 which calls program
    `initialize_config` then `setOperators(ops, threshold, encPk, delay)` ~line 243).
  - `e2e/x25519-pub.mjs` (small sodium helper).
- Progressed through real execution: started `solana-test-validator`, deployed/funded
  wallets (`funder/solver/buyer` keys written under its WORK dir — find them via the
  script's `$WORK` logic), ran `init-config` step.
- Also modified but UNCOMMITTED (its Task-11 supporting edits): `cli/src/scb-submit.ts`,
  `relayer/package.json`, `relayer/package-lock.json`, `relayer/src/index.ts`,
  `relayer/test/mock-enclave.cjs`, `runner/src/intent.rs`.
- Incident en route (already resolved by it): it accidentally overwrote
  `localnet.sh` with `chain.mjs` content, caught it, rewrote `localnet.sh` correctly.
  At review time verify both files are distinct and complete.

## 3. WHERE EXACTLY IT FAILED

Its orchestrator log (`/tmp/opencode/happy.log`) ends at:

```
== STEP: init-config + arm operator (threshold 1) ==
WHICH=operator armed (1 operator, threshold 1) FAIL: got '0 0' want '1 1'
```

Meaning: after running init-config (+ expected set_operators), the script read back
Config and saw `operators=0, threshold=0`. The session 503'd right after.

**Diagnosis hints (start here):**
1. Does `chain.mjs` `init-config` case actually AWAIT confirmation of BOTH txs
   (`initialize_config` AND `set_operators`) before returning? A fire-and-forget
   send would explain reading zeros.
2. Is `set_operators` signed by the SAME keypair that `initialize_config` recorded as
   `platform_authority`? (authority mismatch ⇒ tx fails or is never sent).
3. Config PDA readback must derive seeds `["config"]` with the program's bump — check
   the reader uses `config.bump`/correct seeds and the same program id.
4. Check whether `localnet.sh` passes OPERATOR_PUB correctly into `chain.mjs`
   (arg order at localnet.sh:148 vs case parsing).

## 4. YOUR MISSION (finish Task 11 per PLAN-PRE-TEE.md Step 5)

1. Adopt ALL inherited working-tree changes listed in §2 (they are yours now).
2. Fix the `'0 0' vs '1 1'` failure using hints above.
3. Make THREE modes pass back-to-back (per original spec):
   - HAPPY: fresh validator → deploy → init-config+arm → pack echo-service → runner
     (SCB_SANDBOX=stub acceptable; mock-enclave signs V4 verdicts) → submit via
     scb-submit/mock path → escrow pays winner+bond → Receipt+Reveal PDAs exist →
     buyer decrypts Reveal client-side and content == exploit plaintext.
   - NEGATIVE: broken exploit ⇒ FAIL verdict ⇒ bond refunded, slot reopened, resubmit OK.
   - UNLOCK-DRILL: kill relayer before verdict ⇒ after Config.force_unlock_delay_s
     (set small, e.g. 5 s, at init) force_unlock refunds bond, bounty Open.
4. Every step logs clearly; script exits nonzero naming the failing step.
5. Gates: `anchor build` green; `anchor test` still 28+; relayer/cli/runner suites
   unaffected-or-better (cargo clippy 0 warnings, npm/cargo tests green).
6. Commit EVERYTHING (targeted paths fine; this WIP is all one task), message:
   `feat(phase1): e2e localnet dress rehearsal (happy/negative/unlock-drill)`.
7. Push: `git pull --rebase origin main` then push via gh-authenticated https
   (`gh auth token`). Reply DONE with: commit hash, tail of each of the three runs,
   gate outputs, EXECUTED-vs-REASONED split, and anything consciously skipped.

## 5. RULES

- Another agent may be active elsewhere in the repo — stage explicit paths you own
  (`e2e/`, your fixes); avoid `git add -A` sweeping unrelated stray files.
- Do not re-litigate D1–D14; do not modify protocol constants/wire format (V4, 207 B).
- Honest reporting: if docker-dependent steps are reasoned-only, say so explicitly.
