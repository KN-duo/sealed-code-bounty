# AWS Nitro Enclave staging plan

Goal: move exploit verification to an attested AWS Nitro Enclave, prove the
complete flow on Solana devnet, and produce a reviewed mainnet deployment
runbook. Mainnet is not a substitute for the staging/security gates below.

## Current user constraints (2026-10-09)

- Latest instruction: proceed step by step to the final public HTTPS website,
  actual Nitro execution, and Solana mainnet after devnet proofs, funding and
  independent review. Initial capacity is one active user for a short session.

- Public website usable from other PCs; code execution must run in AWS TEE.
- Fewer than ten concurrent users; initially one or two simple CTF executions.
- **$2/month maximum**; hosting provider is flexible. No always-running VPS is
  required. Design for free static hosting and short scheduled Nitro sessions.
- The prior four-hour stop-and-retain Terraform plan is unsuitable: retained
  EBS alone exceeds the monthly limit. Do not apply that saved plan. See
  `docs/hosting-readiness.md` for evidence, costs and remaining requirements.
- [x] Fix Rust upload selection for competing hunters and enforce one execution.
- [x] Test hash binding, repeat-upload storage accounting, and concurrent API use.
- [x] Add durable sealed-ciphertext storage and restart/retry recovery locally;
  production S3 broker is implemented but not live-tested against AWS.
- [ ] Add public HTTPS frontend/API configuration and an explicit offline state.
- [~] Revise infrastructure for terminated session compute, durable keys/objects,
  and a bounded runtime allowance within the $2 monthly design target. It is
  not a hard account-level spending cap; the refreshed read-only plan still
  requires cost and launch review.

## Completed locally: durable submissions and recovery

- [x] Persist only sealed submissions plus authenticated public metadata;
  verify stored bytes against a receipt hash before every use.
- [x] Use one upload response `{receipt}` and on-chain reference
  `scb:submission:v1:<receipt>` across frontend, CLI, relayer and runner.
- [x] Re-authenticate and decrypt inside the runner for verification, retaining
  ciphertext for transport retries and restart recovery.
- [x] Add a narrow vsock object-storage broker for the Nitro/S3 boundary, with
  bounded bodies and fixed object keys; use a directory backend only for local
  development and offline tests.
- [x] Recover pending relayer work from chain on startup and periodically,
  preserving retry/backoff and single-worker admission.
- [x] Prove restart, substitution rejection, duplicate upload, and failed
  storage behavior with meaningful tests; rerun affected component checks.

No AWS resources were needed for this implementation.

## Next implementation: manifest and environment discovery

- [x] Correct active runtime overrides, pin launch-template versions, and prove
  teardown handles sessions created outside Terraform using offline tests.
- [x] Unify the CLI and browser manifest formats and canonical hash encoding.
- [x] Derive only fixed S3 object keys from the relayer-supplied manifest/environment
  hashes; never accept submission-controlled URLs or local paths in production.
- [x] Fetch bounded content through the enclave's narrow parent S3 broker and
  verify manifest/tarball hashes inside the enclave before sandbox use.
- [x] Add adversarial tests for schema changes, mismatches, size limits,
  invalid ranges, cancellation, and parent-selected paths/commands.
- [ ] Bind the manifest hash into the on-chain verified verdict (current V4
  signature binds the environment hash but not manifest-controlled commands),
  or provide independently authenticated chain state inside the enclave.
- [ ] Implement environment packaging/publication through the browser. ZIP/Git
  source publishing is blocked instead of committing a fake environment hash.

## Final deployment program (authorized 2026-10-06)

- [~] Step 1: production execution path complete and adversarially tested.
- [ ] Step 2: Nitro trust boundary, attestation, KMS release, and EIF complete.
- [~] Step 3: redesigned Terraform validated and read-only plan refreshed;
  cost review, independent termination backstop, and actual launch remain open.
- [ ] Step 4: approved AWS staging plus Solana devnet proof complete.
- [ ] Step 5: independent review and production-readiness controls complete.
- [ ] Step 6: explicitly approved mainnet canary and gradual launch complete.

External mutation gates remain mandatory: do not create billable AWS resources,
deploy to devnet/mainnet, purchase services, or represent an independent audit
as complete without the user's specific approval or the actual third-party work.

## 1. Close the pre-TEE execution seams

- [ ] Prove real Docker-backed PASS and FAIL locally (no mock verdict rule).
- [ ] Unify the frontend, runner, and relayer upload response contract.
- [ ] Make the relayer fetch and hash-check each bounty target/manifest.
- [ ] Run browser submission -> real execution -> localnet settlement twice.
- [x] Exercise timeout, FAIL, cleanup, and force-unlock paths.

## 2. Build the Nitro runtime without creating AWS resources

- [x] Add an enclave entrypoint with a vsock-only API.
- [ ] Replace Docker-in-enclave execution with an enclave-compatible sandbox.
- [ ] Generate encryption/signing keys from an attestation-gated master secret.
- [x] Add a parent proxy that exposes only the required HTTP surface over vsock.
- [ ] Add deterministic EIF build and PCR measurement scripts.
- [x] Add tests for parent/enclave framing, size limits, and fail-closed behavior.

## 3. Infrastructure as code

- [x] Define a Nitro-enabled `m6i.xlarge` parent in `eu-north-1`.
- [x] Define the restricted instance role, no-ingress security group, private
  S3 buckets, log group, and KMS key.
- [~] Bind KMS decrypt to PCR0; current nonmatching placeholder denies decrypt
  until an EIF measurement is built and reviewed.
- [x] Add project cost tags, a $2 budget with $0.80 actual/$1 forecast alerts,
  one-hour termination timer, an on-demand launch template, a monthly session
  marker, and terminate/destroy scripts. Timer and teardown have not run on EC2;
  the marker is a script guard, not an account-level cap.
- [x] New read-only Terraform plan passed after the redesign: 21 to add, 0 to
  change, 0 to destroy. It creates a launch template but no EC2 instance. No
  resources were created.

## 4. AWS staging and devnet

- [ ] Show the exact AWS plan and cost estimate; obtain launch approval.
- [ ] Launch the parent only for a bounded test window.
- [ ] Build/run the EIF and record PCR0 plus enclave public keys.
- [ ] Pin staging operator keys and deploy the Solana program to devnet.
- [ ] Prove real PASS, FAIL, payout, Reveal decryption, restart, and recovery.
- [ ] Tear down compute after the proof and confirm billing/resource inventory.

## 5. Production gate

- [ ] Remove temporary administrator access and install least-privilege deployment access.
- [ ] Commission an independent program/enclave/infrastructure security review.
- [ ] Document key rotation, PCR upgrades, incident response, monitoring, and backups.
- [ ] Obtain explicit approval for Solana mainnet deployment and ongoing AWS spend.

## Review

- Manifest/artifact contract 2026-10-09: shared CLI/browser strict manifest,
  exact canonical bytes, argument arrays, and common Rust hash vector added.
  The relayer passes the bounty's manifest hash. Vsock mode rejects local paths
  and target overrides, fetches fixed S3 keys in bounded chunks, hashes the
  complete files, then applies verified manifest limits. Binary stdio targets
  return explicit 501 until implemented. These are local tests, not Nitro proof.
- Found a remaining trust-boundary issue: the existing V4 verdict does not
  bind manifest_sha256. A malicious parent could supply another manifest with
  the same environment hash. Keep production blocked until the signature
  contract or independently verified chain state closes this seam.
- Session lifecycle corrections: actual and example tfvars were still four
  hours despite the one-hour default; both now specify one. Start pins the
  numeric launch-template version. Destroy terminates and waits for parents
  outside Terraform before removing infrastructure. Twelve offline mocked
  lifecycle tests pass. Refreshed read-only plan: 21 additions, no EC2 instance,
  parent_max_runtime_hours=1. No apply or AWS resource creation occurred.
- Budget redesign 2026-10-09: EC2 now terminates after the one-hour runtime
  allowance, deleting the root volume; S3 permissions include immutable sealed
  submission objects; the monthly budget alerts at $0.80 actual and $1 forecast.
  Terraform now prepares a launch template only; the separate start script is
  guarded to one session per month. That is not a hard account-level spending
  limit. The old saved plan is stale and must not be applied.
- Terraform 1.16.5 was downloaded to `/tmp` and verified against HashiCorp's
  published SHA-256. `terraform fmt -check -recursive infra/aws-nitro`,
  `init -backend=false`, and `validate` passed. A read-only plan passed against
  the authenticated `eu-north-1` account: 21 to add, 0 to change, 0 to destroy.
  It contains a launch template and no `aws_instance`; the KMS PCR0 remains the
  deny-all placeholder. The plan is only in `/tmp`. No resources were created.
- AWS login rechecked 2026-10-09. Cost Explorer reports effectively $0.00 for
  October so far; no project AWS resources have been created.
- Durable upload/recovery implementation 2026-10-09: runner now writes an
  immutable JSON record containing the sealed exploit and authenticated
  metadata, returns the SHA-256 record receipt, validates it on every read,
  and keeps it available across runner restarts. The directory backend is
  explicitly development-only in environment configuration; production uses
  the bounded vsock helper and fixed-key parent S3 broker. Parent broker tests
  use injected S3 clients and never contact AWS. The broker's byte/request
  allowance resets when its parent process restarts; it is a session bound,
  not a permanent account spending cap.
- Frontend and CLI validate `{receipt}` and register
  `scb:submission:v1:<64 lowercase hex>` on chain. Relayer reconstructs jobs
  from pending on-chain accounts at startup and on periodic/event-triggered
  scans; unchanged pending records preserve retry backoff. No database is
  required for this one-slot-per-bounty workflow because chain state is the
  durable work queue.
- Verification: runner `cargo test --offline` passed (48 tests) and
  `cargo clippy --offline --all-targets -- -D warnings` passed. Nitro storage/protocol Python suite
  passed 25 tests with local socket permission. Relayer `npm test` passed
  11/11, CLI `npm test` passed 9/9, frontend lint/build passed, and devrig
  selftest plus receipt-contract tests passed. These tests validate local
  behavior, not AWS S3, Nitro attestation, or cloud deployment.

- Hosting/concurrency review 2026-10-09: fixed Rust upload selection by bounty,
  solver, and exploit hash; rejected claims inconsistent with decrypted bytes;
  prevented duplicate upload accounting; serialized sandbox execution with
  retryable 503 responses; moved sweeper startup inside Tokio's runtime.
- `cargo test --locked` passed 46 tests; `cargo clippy --locked --all-targets --
  -D warnings` and `cargo build --locked` passed. First API compile exposed a
  leftover renamed variable and Clippy found a redundant test conversion; both
  were corrected before the successful complete run.
- Runner binary boot and ten simultaneous local health requests passed with
  synthetic keys and a stub sandbox. Sandbox initially blocked local sockets;
  the same smoke check passed with local execution permission. This is not an
  execution load test or an AWS proof. No resources were created.
- AWS read-only inspection confirmed `c6i.xlarge`, `c5a.xlarge`, and
  `m6i.xlarge` support Nitro in Stockholm. `c6a.xlarge` was unavailable there.
  No replacement instance or price has been selected.

- AWS access and region verified 2026-10-09: account `172873868884`, region
  `eu-north-1`; `m6i.xlarge` reports Nitro support (4 vCPU, 16 GiB); current
  official AL2023 SSM parameter resolved to `ami-01e082ac2f79f3918`; standard
  On-Demand quota is 16; zero running instances and no existing AWS Budgets.
- `terraform fmt -check -recursive` passed. `terraform init -backend=false`
  selected and locked `hashicorp/aws` 6.68.0. `terraform validate` passed when
  run outside the sandbox because the local sandbox blocks provider startup.
- Preliminary `terraform plan -var-file=staging.tfvars.example` passed:
  21 resources to add, 0 to change, 0 to destroy. It used the example budget
  email and placeholder all-`f` PCR0, so it is not the final apply plan.
  No `terraform apply` was run and no AWS resources were created.
- Final `terraform plan -var-file=staging.tfvars -out=staging.tfplan` passed
  on 2026-10-09: 21 to add, 0 to change, 0 to destroy. The no-color plan is
  saved in ignored `infra/aws-nitro/staging.plan.txt`; the binary plan and
  `staging.tfvars` are also git-ignored. PCR0 remains the deny-all placeholder.
- `aws ce get-cost-and-usage` for 2026-10-01 through 2026-10-10 returned
  `-0.0000000001 USD` unblended cost (effectively $0.00) for the account to
  date. Rechecked after the user's login on 2026-10-09; credentials are valid,
  account `172873868884` is selected in `eu-north-1`, and no resources were
  created by this work.
- Official AWS Price List API rate for Linux On-Demand `m6i.xlarge` in EU
  (Stockholm): $0.204/hour. gp3 rate: $0.0836/GiB-month. Public IPv4 rate:
  $0.005/hour. With a 40 GiB root volume and one active KMS key, the bounded
  four-hour build is estimated at about $0.86 before S3, log ingestion,
  requests, and tax. If stopped but retained for a month, EBS and KMS together
  are about $4.34, plus S3 and CloudWatch Logs. The budget alert is not a hard
  spending cap.

- Baseline recorded 2026-10-08: `git status --short --branch` showed existing
  user modifications in Anchor, README, e2e, enclave-exec, examples, frontend,
  hunter-vm, program, and relayer test files, plus untracked `DEPLOYMENT-HANDOFF.md`,
  `SECURITY_SCOPE.md`, `nitro/`, `tasks/`, and a timeout example. These changes
  were preserved.
- `bash e2e/localnet.sh unlock-drill` first failed in the restricted shell
  because the validator faucet could not bind `0.0.0.0:9900` (operation not
  permitted). Reran the same command with local network permission. Result:
  `E2E RESULT: MODE=unlock-drill ALL ASSERTIONS PASSED`; the slot reopened and
  the bond refund was exactly the 5,000 lamport transaction fee below the
  pre-submit balance.
- Earlier AWS prerequisite check reported expired credentials; the user then
  reauthenticated. Current read-only `aws sts get-caller-identity` succeeds.
  `terraform` and `nitro-cli` are not installed, and `infra/` / `scripts/` do
  not exist yet. No AWS resources were created.
- `python3 nitro/test_protocol.py` initially could not use its local socket
  pairs in the restricted shell. Rerun with local execution permission:
  `Ran 3 tests ... OK`.
- `(cd runner && cargo test --locked)` passed: 23 library, 9 API, 4 blob,
  and 6 Docker-shim integration tests; doc tests had no cases.
- Step 1 local gates run 2026-10-08: `cargo clippy --locked --all-targets --
  -D warnings` passed; `(cd relayer && npm test)` passed 9/9; `(cd cli && npm
  test)` passed 7/7; `(cd frontend && npm run lint && npm run build)` passed
  (Vite reported Node core-module externalization and large-chunk warnings);
  `node enclave-exec/selftest.cjs` passed real Docker PASS, FAIL, buyer Reveal
  decryption, and development-only per-bounty image build/execution.
- `SCB_REVEAL_STORE=inline SCB_EXPLOIT_FILE=enclave-exec/solve-compact.py bash
  enclave-exec/localnet-real.sh` passed twice consecutively. Both runs proved
  exact 0.5 SOL payout, Receipt creation, and buyer Reveal delivery.
- `ENCLAVE_PORT=8544 SCB_REVEAL_STORE=inline
  SCB_EXPLOIT_FILE=examples/ret2win/solution/solve-broken.py
  SCB_EXPECT_OUTCOME=FAIL bash enclave-exec/localnet-real.sh` passed: FAIL
  reopened the slot, produced no Receipt or Reveal, and allowed resubmission.
- Force unlock: `bash e2e/localnet.sh unlock-drill` passed as recorded above;
  timeout/cleanup proof remains as documented in the handoff's prior verified
  state and is distinct from the local Docker prototype.

- [x] Add an explicit authorized-use and prohibited-use security policy.
- [x] Require target owners to attest authorization before posting in the UI.
- [x] Show submission-scope restrictions in the hunter console.
- [x] Make uploaded Dockerfile builds opt-in and remove arbitrary URL fetching.
- [x] Enforce an explicit request-body limit in the local execution prototype.
- [x] Record the current worktree baseline and preserve unrelated changes.
- [ ] Build the real judge images and prove standalone PASS/FAIL execution.
- [ ] Close and test the upload, target-fetch, manifest, and settlement seams.
- [ ] Exercise timeout, cleanup, resubmission, and force-unlock locally.
- [ ] Implement and test the vsock-only enclave/parent protocol and sandbox.
- [ ] Add deterministic EIF build/measurement tooling and AWS Terraform.
- [ ] Run formatting, validation, unit, integration, and local end-to-end gates.
- [ ] Document exact staging cost, security assumptions, deployment, and teardown.

Current baseline: AWS supports Nitro-capable `m6i.xlarge` and KMS in
`eu-north-1`; no billable AWS resources have been created. Existing modified
frontend, localnet, Anchor, and program files are user work and must be
preserved. The user requests public hosting and AWS execution within $2/month;
the old retained-resource plan exceeds that constraint and must be replaced
before launch. The runtime and confidentiality gates remain open.
