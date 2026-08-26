# REMAINING WORK — Task Board for Parallel AI Agents

> **How to use:** each LANE is owned by exactly ONE agent at a time. Never touch files
> outside your lane. Push rules: `git pull --rebase origin main` → stage ONLY your
> lane's paths → commit → push. Report format: DONE + evidence (build/test output,
> EXECUTED-vs-REASONED split) or BLOCKED <reason>.
>
> | Lane | Owner paths | Status |
> |---|---|---|
> | **A — CI/Infra** | `.github/**`, `scripts/ci/**`, `runner/runtime.Dockerfile`, `BUILD.md` | unassigned |
> | **B — Storage** | `cli/src/*upload*`, `runner/src/*fetch*`, `.env.example` storage vars | unassigned |
> | **C — Frontend** | `frontend/**`, `docs/frontend-report.md` | unassigned |
> | **H — Human** | credentials, AWS console, approvals | Konstantine |
>
> Shared files nobody edits without reviewer approval: `programs/**`, `STATUS.md`,
> `PLAN-PRE-TEE.md`, `test-vectors/**`.

---

## LANE A — CI / Infrastructure

### A1. Fast CI gate (`.github/workflows/ci.yml`)
- Sub-tasks: 1) rustfmt/clippy job (`cargo clippy --all-targets -- -D warnings`) 2) tsc
  build + oxlint for cli/, relayer/, frontend/ 3) npm tests (cli, relayer) 4)
  cargo test (runner) 5) anchor build + localnet `anchor test`.
- Done when: green on push; every failure message names the failing step.

### A2. Real-Docker integration proof (`.github/workflows/integration.yml`)
- Sub-tasks: 1) ubuntu-latest job (Docker preinstalled): install Solana CLI + Anchor,
  `anchor build`, boot `solana-test-validator`, deploy program 2) start runner with
  `SCB_SANDBOX=docker` 3) `scb-pack examples/echo-service` (real image build) 4) run
  verify pipeline with real solve.py → assert PASS + escrow debit + Receipt/Reveal PDAs;
  run broken exploit → assert FAIL + bond refund 5) upload artifacts (logs) on failure.
- Done when: workflow_dispatch run is green with run URL in report.
- Notes: wait-for-port helper for validator RPC(8899)+WS(8900) required (known race).

### A3. Reproducible EIF prep (`BUILD.md` + `runner/runtime.Dockerfile`)
- Sub-tasks: document exact base digests/build commands for runner image → EIF recipe;
  pin versions. No AWS execution — recipe only.
- Done when: BUILD.md lets a stranger rebuild byte-identical inputs.

## LANE B — Blob storage (R2)

### B1. Upload implementation (cli)
- Sub-tasks: implement `uploadTarball()` via S3-compatible presigned PUT (R2 endpoint
  env `SCB_R2_ENDPOINT/BUCKET/KEY/SECRET`); manifest `image_tarball.url` becomes real
  URL; keep local-path mode when creds absent.
- Done when: pack→upload→download round-trip hashes match (unit-test w/ mocked S3).

### B2. Runner https fetch
- Sub-tasks: replace typed-unsupported https blob fetch with streaming download +
  existing sha256 check; size cap enforced during stream.
- Done when: integration test fetches from a local http server; sha mismatch aborts.

### B3. Retention policy doc
- Bucket lifecycle rules (delete unregistered blobs ≤30d), documented in BUILD.md.

## LANE C — Frontend hardening

### C1. Devnet mode
- Env-driven cluster switch already exists; verify all flows against devnet deploy
  (needs H: devnet SOL). Fix any hardcoded localhost assumptions.

### C2. UX polish pass
- Empty/error/loading states audit on every view; mobile ≥768px layout check; a11y
  focus rings; bundle-size budget note in report.

### C3. Buyer decrypt E2E in-browser
- Full loop against localnet: create → submit → PASS → decrypt Reveal in UI using
  restored backup key. Done when recorded walkthrough steps reproducible from README.

## H — Human actions (Konstantine)
1. Cloudflare R2 bucket + API token → hand to Lane B.
2. AWS account + budget alarm → needed before TEE phase.
3. Reviewer assignments: name which agent owns which lane.

## SEQUENCE & PARALLELISM
- A1 can start immediately. B1/B2 and C1–C3 immediately after lane assignment.
- A2 requires nothing from B/C (uses local tarball path).
- After ALL lanes: devnet deploy → TEE phase (separate plan).
