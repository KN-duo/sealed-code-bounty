# Plan: real exploit execution on localnet (no TEE)

**Goal.** A buyer posts a pwn.college-style vulnerable target; a hunter submits a
Python exploit; the system **actually builds the target, runs the exploit against
it, and captures a secret flag** to decide PASS/FAIL — all on a plain Linux box
with Docker, no AWS Nitro Enclave. The TEE is a later hardening step, not a
prerequisite (`PLAN-PRE-TEE.md`).

**Key finding from reading the code:** the hard parts already exist and are real.
The `DockerCli` sandbox (`runner/src/sandbox.rs`) loads a target tarball, starts
it on a loopback network, runs the exploit container with a timeout, and captures
output. The verify route (`runner/src/routes.rs`) already decides PASS iff the
output contains the derived flag, then redacts and seals the reveal. What's
missing is **wiring between components**, plus one runtime image and the local
run recipe. This is an integration epic, not new cryptography.

---

## The seams that don't currently connect

1. **Upload response shape mismatch.** The real runner's `/internal/upload`
   returns `{ receipt }` (`routes.rs` `UploadResponse`). The frontend
   (`lib/runner.ts`) and the dev mock (`devrig/enclave.mjs`) both return/expect
   `{ blob_url }`, and the frontend puts that value on-chain as
   `SubmissionRef.blob_url`. These three must agree on what the hunter uploads,
   what comes back, and what is recorded on-chain. This is the same defect that
   produced the `blob url: undefined` → SBF panic in the live run.

2. **The relayer never tells the runner what to execute.** `relayer/src/pipeline.ts`
   builds the `/internal/verify` body with only `bounty_pda`,
   `claimed_chain_view`, `solver_pubkey`. The runner's `VerifyRequest`
   (`routes.rs`) also accepts `env_blob_path`, `target_image`,
   `target_entrypoint`, `target_port` — all omitted, so the sandbox returns
   "no target image" and nothing runs.

3. **The manifest never reaches the relayer.** The chain stores only
   `manifest_sha256`, not the manifest. To fill `target_entrypoint` and
   `target_port`, the relayer must fetch the actual manifest the buyer published
   next to the tarball, and verify it hashes to the on-chain commitment.

4. **The tarball is never fetched.** The relayer must download the
   `image_tarball.url` to a local path and hand that path to the runner as
   `env_blob_path` (the runner then `docker load`s it and re-checks its sha256).
   Lane B's storage (`cli/src/upload.ts`, landed but untested) is the piece that
   put it there.

---

## Phases

### Phase 0 — prove the core runs one exploit (no chain, no relayer)
Smallest real milestone: confirm the sandbox genuinely executes.
- Build the runtime image once: `docker build -t scb/exploit-runtime:latest -f runner/runtime.Dockerfile runner/`.
- `scb-pack examples/ret2win` (cli) → a `<sha>.tar.gz` + `manifest.json`.
- Run the real runner with `SCB_SANDBOX=docker` and both secrets set.
- POST a hand-built `/internal/verify` (env_blob_path = the tarball, entrypoint +
  port from the manifest) and confirm: `solve.py` → PASS, `solve-broken.py` →
  FAIL. **Done when a real Docker run yields a real verdict.** Proves phases 1–3
  are only wiring.

### Phase 1 — settle the upload/blob_url/receipt contract
Decide the single canonical flow for a hunter's sealed exploit and write it once:
who the frontend uploads to, what comes back, what is recorded on-chain, and how
the runner later locates the sealed exploit at verify time. Update `lib/runner.ts`,
`devrig/enclave.mjs`, the real runner, and the on-chain field's meaning to match.
Fold in the `blob_url` validation fix (spec-05) here. **Done when frontend, mock,
and real runner round-trip an upload with no shape mismatch.**

### Phase 2 — relayer passes the target to the runner
- Fetch `image_tarball.url` → local path; verify sha256 against the on-chain
  `env_blob_sha256`.
- Fetch the manifest; verify it hashes to the on-chain `manifest_sha256`; read
  `target.entrypoint`, `target.kind`, and the port.
- Add `env_blob_path`, `target_entrypoint`, `target_port` to the `/internal/verify`
  body. **Done when the relayer drives the real runner to a real verdict from an
  on-chain submission.**

### Phase 3 — end-to-end on localnet, real runner instead of the mock
Replace `devrig/rig.mjs serve` (mock) with the real runner + relayer in the local
loop. Reconcile `devrig`'s seeding (which invents a `flag_commitment`) with the
runner's real `seal_bounty` derivation, so the on-chain commitment matches what
the runner will derive at verify time. **Done when the browser flow — post, hunt,
submit — produces a Docker-executed PASS, a Receipt, and a buyer-decryptable
reveal, with no mock anywhere.**

### Phase 4 (optional, later) — TEE
Wrap the identical runner in the Nitro Enclave per `PLAN-PRE-TEE.md`. No redesign;
the seams above are the same. Out of scope for "see it work."

---

## Lane / ownership note
This spans `runner/`, `relayer/`, `cli/`, and `frontend/`. Per `TASKS-REMAINING.md`
these are split across agents; the user has reassigned the runner/relayer/cli
pieces for this task. **Coordinate before editing** — the other agent authored the
DockerCli sandbox, the e2e scripts, and Lane B, and knows constraints not visible
in the code. Phase 0 touches nothing they own (it only runs their code), so it is
the safe place to start while coordination happens.

## Verification per phase
Phase 0: a terminal transcript of a real `docker`-backed PASS and FAIL.
Phases 1–3: the existing gates (`npm run build/lint`, `cargo test`,
`devrig/selftest.mjs`) plus a recorded end-to-end run.
