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
  not a hard account-level spending cap. The current read-only plan has the PCR
  placeholder and must not be applied.

## Active work: TEE first, preserve the existing CTF workflow

Next launch preparation:

- [x] Add an AWS-managed workflow owning launch, wait and termination, with
  tag-restricted permissions and per-session identity independent of bootstrap.
- [x] Wire session startup to the workflow; preserve monthly reservation and
  numeric launch-template pinning. Live launch/termination proof remains open.
- [x] Lock exploit-runtime Python dependencies and image/OS build inputs.
- [~] Build the Rust runner and KMS helper with pinned compilers/offline compile,
  then assemble the locked-component EIF and record fresh measurements. The
  pinned/offline Rust runner build passed; KMS helper assembly is still running.
- [ ] Compile/validate affected source and refresh the read-only resource plan;
  document remaining clean-release and real-hardware gates without applying.

Current continuation:

- [x] Add a bounded nonce-challenge NSM attestation endpoint binding the upload
  encryption key, verdict key, build commit, and SCB_VERDICT_V5 protocol.
- [x] Add an independent verifier pinned to the official AWS root, checking
  certificate chain, COSE signature, freshness, nonce, PCR and both public keys.
- [x] Embed source identity during EIF builds and record structured provenance.
- [x] Compile the affected code and update the handoff with exact remaining
  launch gates; retain all original CTF application routes.

Review: the new development EIF and provenance are at
`/tmp/scb-attestation-dev.eif` and `.eif.provenance.json`. PCR0 is recorded in
the handoff; this dirty development artifact is not approved for KMS. Rust
release/development compilation and library/binary Clippy pass, Python/shell
syntax checks pass, and Terraform validates. No tests were added/run in this
continuation and no AWS resources/programs were deployed. The independent
verifier is installed in `/tmp/scb-attestation-venv` but has no real AWS proof.
The refreshed plan is `/tmp/scb-staging-attestation-20261009.tfplan`; it still
has 21 additions, no EC2 instance and placeholder PCR/file digest. Explicit KMS
decrypt and re-encryption denials are in the draft policy. The oversized
bootstrap is now gzip-compressed before launch-template base64 encoding. Next: clean release
dependency locking/provenance, independent runtime termination backstop,
adversarial verification, then approved hardware staging.

Newer launch preparation review: AWS login revalidated; read-only plan
`/tmp/scb-staging-backstop-20261009.tfplan` has 24 additions, no changes/deletions
and no EC2 instance. Terraform validation and AWS Step Functions definition
validation passed (future resource IDs substituted for syntax validation).
Workflow-owned launch fixes the separate-launch timer race. Runtime and enclave
OS locks built successfully, and the pinned/offline Rust runner binary built.
No cloud resources were created. Live IAM, shutdown, Nitro/KMS, reproducibility,
and complete nonempty-bucket teardown are unproven.

- [x] Confirm the existing main application routes remain intact: bounty board,
  bounty creation, bounty details, hunter exploit upload, manage/reveal, CLI
  packaging/submission, Rust verification, and on-chain settlement sources are
  present. Public preview is a separate `frontend/preview/` entry point.
- [x] Add a domain-separated HKDF derivation for the enclave upload-decryption
  key, so the eventual attested KMS master can supply both stable enclave keys.
  `cargo check --locked` passes; no AWS key or account resource was changed.
- [x] Zeroize the derived flag's base58 bytes and `FlagString` contents when
  their Rust owners drop. The release runner and opt-in development feature
  compile after the change.
- [x] Add a fail-closed release runner startup path: release builds disable
  plaintext secret environment input and request a 32-byte KMS key via the
  parent bootstrap client. Add a fixed-key parent broker that creates the key
  with `GenerateDataKeyWithoutPlaintext` and stores only ciphertext in S3.
  The development-feature and default release-profile Rust builds compile.
  The Nitro vsock/KMS path has not been run on hardware.
- [ ] Replace the enclave's environment-supplied master/encryption keys with
  attestation-gated KMS bootstrap end to end; keep explicit local-development
  support separate from release builds. The local helper and IAM wiring exist,
  but the parent service deployment and Nitro flow still need integration.
- [ ] Replace the enclave Docker-daemon dependency with a reviewed native
  process sandbox while retaining Dockerfile-based CTF authoring and the hunter
  ZIP upload/verify/payout/reveal workflow.
- [~] Prototype daemonless Podman execution for release builds: per-run
  internal networks, per-container user namespaces, dropped capabilities,
  exploit read-only rootfs/no-new-privileges, and AF_VSOCK seccomp denial.
  The exploit no longer mounts the flag workspace. Release builds reject
  Docker and the stub. This compiles, but is not accepted as enclave-ready:
  The candidate image includes Podman, runtime bundle and subuid configuration,
  and a development EIF has been built. Isolation has not been reviewed or run
  under Nitro; do not treat local Docker checks as hardware proof.
- [~] Build a dedicated pinned verifier image and EIF recipe, including the
  KMS CLI and enclave vsock entrypoint; development measurements and provenance
  exist. OS/runtime dependencies are locked and built; pinned compiler/helper
  integration, a clean reviewed release and reproducibility remain open.
- [ ] Verify on an approved Nitro host: wrong-PCR KMS denial, approved-PCR
  secret release, independent attestation verification, then synthetic PASS,
  FAIL, timeout, restart, recovery, and force-unlock.
- [ ] Deploy public API routing only after the enclave execution and ingress
  paths are implemented and the full plan/cost/teardown have been reviewed.

Planning basis: AWS documents that enclaves lack network access and use
`vsock-proxy` plus `kmstool-enclave-cli` for attested KMS requests. The current
release runner can now bootstrap the KMS master without plaintext secret
environment variables, and the launch template installs the parent brokers.
Those source changes have not been exercised on Nitro. The Podman executor is
only a candidate enclave-native implementation; it still needs an actual EIF
and kernel/runtime validation. Do not create AWS resources until the EIF, PCR,
bounded cost, and approval gates are ready.

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
- [x] Bind the on-chain manifest hash into the verified verdict (SCB_VERDICT_V5);
  the program recomputes it from the Bounty account and rejects a signature over
  a different manifest.
- [x] Replace bare-script submissions with bounded ZIP archives in the browser,
  CLI, and runner; validate extraction and entrypoints, reject links/traversal,
  and clean up the plaintext workspace on every path.
- [ ] Implement environment packaging/publication through the browser. ZIP/Git
  source publishing is blocked instead of committing a fake environment hash.

## Final deployment program (authorized 2026-10-06)

- [~] Step 1: local implementation/adversarial tests mostly complete; current
  Docker-backed V5 execution and local settlement proof remain open.
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
- [x] Unify the frontend, runner, and relayer upload response contract.
- [x] Make the relayer fetch and hash-check each bounty target/manifest.
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
- Rust local executor review: the verified flag was not being staged at the
  target's `/flag-src/flag` mount. Added a private per-run `FlagWorkspace`
  (0600 file, overwrite-on-drop) and an API regression check for its cleanup.
  Also made exploit stdout/stderr drain concurrently with a 512 KiB per-stream
  capture bound so a noisy process cannot block on full pipes or grow memory
  without bound. Full `cargo test --locked --offline`: 73 passed, one explicit
  Docker test ignored by default; Clippy with `-D warnings` passed.
- Explicit local Docker smoke: `cargo test --locked --offline --test live_docker
  -- --ignored --nocapture` passed against cached `scb-target` and `scb-runtime`.
  The real Rust `DockerCli` ran the ret2win exploit and recovered the synthetic
  per-run flag. Local Docker's seccomp blocked `setarch -R`, so this static/no-PIE
  smoke disabled ASLR wrapping. It does not prove AWS Nitro execution or a full
  chain settlement cycle.
- Pulled-change verification: relayer 12 tests; CLI 12 tests; frontend deploy
  preflight, lint and production build pass; 66 Python broker/publisher/session
  tests pass; Terraform fmt/init/validate pass; `anchor build --ignore-keys`
  and a sequential `anchor test --skip-build --validator legacy` pass (29/29).
  The earlier overlapping Anchor build/test run failed and was discarded; the
  sequential run confirms those failures were caused by the shared build race.
- Current machine has Docker, Anchor, AWS CLI, and Terraform 1.16.5 in
  `/tmp/scb-tools/terraform`; `nitro-cli` is being built from pinned AWS v1.5.1
  source under `/tmp`. AWS read-only
  identity was revalidated on 2026-10-09 for account `172873868884` in
  `eu-north-1`. Docker CLI needs elevated access to its local daemon socket.
  No apply or cloud deployment was run.
- TEE key bootstrap implementation 2026-10-09: release runner built with
  `cargo build --release --locked --no-default-features`. It requests the
  master key from the new parent vsock broker, then uses the KMS enclave CLI
  against the parent's KMS-only vsock proxy. Master bytes are held in
  `Zeroizing`; the upload-decryption key is HKDF-derived. The EC2 launch
  template includes the fixed-key S3/KMS broker services and role permissions.
  Only source/build compilation is complete; the EIF, PCR gate, native sandbox,
  AWS deployment, and attested release proof remain open.
- Sandbox continuation 2026-10-09: removed the exploit container's bind mount
  of the per-run flag directory after finding that it could read the actual
  flag directly. The target alone receives the read-only flag mount. Changed
  sandbox network creation to unique per-run internal networks with cleanup,
  and prepared temporary bind-mount permissions for Podman's per-container
  subordinate UID maps. Release config now rejects Docker and the stub. Ran
  `cargo build --release --locked`, `cargo check --locked --all-targets`, and
  `cargo test --locked --test shim_docker` (6 passed). The test shim does not
  execute Podman. Podman/Nitro runtime behavior is unverified; no EIF or AWS
  resources exist. Terraform formatting and validate pass with elevated local
  execution. A fresh read-only plan has 21 additions, 0 changes, 0 deletions,
  no EC2 instance, and the deny-all PCR placeholder. It is unsafe to apply.
- Closed the manifest substitution seam with SCB_VERDICT_V5. The 239-byte
  signed wire includes `manifest_sha256`; the program derives it from its Bounty
  account, and the runner signs the hash it fetched and verified. Added a
  negative Anchor case for a different manifest. Verified 2026-10-09:
  `cargo test --locked` (72 passed after ZIP coverage),
  `cargo clippy --locked --all-targets -- -D warnings`, relayer `npm test` (12
  passed), `anchor test --skip-build
  --validator legacy` (29 passed), and `anchor build --ignore-keys` succeeded.
  These local checks do not prove Nitro attestation, AWS storage, or enclave
  confidentiality. Rust exploit-ZIP adversarial tests and frontend/CLI ZIP
  contracts are also covered locally. Real Docker-backed ZIP execution and the
  V5 local Docker settlement cycles remain to be rerun; Docker is not installed
  in the current workspace.
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
## Historical initial checklist (superseded)

The unchecked list below is from the original pre-TEE planning snapshot. It is
not the current task list; several items are now complete locally. Use
[`DEPLOYMENT-HANDOFF.md`](../DEPLOYMENT-HANDOFF.md) and the status sections above
for current remaining work.

- [ ] Original checklist: build/prove judge, close pipeline seams, exercise
  failure paths, implement vsock/EIF/IaC, rerun gates, document deployment.

Current baseline: AWS supports Nitro-capable `m6i.xlarge` and KMS in
`eu-north-1`; no billable AWS resources have been created. Existing modified
frontend, localnet, Anchor, and program files are user work and must be
preserved. The current machine lacks Docker, Nitro CLI, Terraform, AWS CLI, and
website deploy credentials; no website, AWS service, or chain program is live.
The runtime and confidentiality gates remain open.

- Deployment continuation 2026-10-09: updated root/component READMEs and
  handoff notes to separate implemented local behavior from live deployment
  guarantees. Confirmed the existing `enclave-exec` PASS/FAIL scripts run a
  legacy JavaScript process with environment-held test keys, not the Rust V5
  runner or Nitro; relabeled them accordingly. No external deployment or
  resource creation was performed.
- Fresh local verification: `cargo test --locked` (72 passed),
  `cargo clippy --locked --all-targets -- -D warnings`, relayer `npm test` (12),
  CLI `npm test` (12), frontend `npm run lint` and `npm run build`, and
  `anchor test --skip-build --validator legacy` (29) passed. Nitro protocol (3),
  submission-store (22), and artifact-store (15) Python tests passed using
  local-only socket permission. `node --check enclave-exec/selftest.cjs`,
  `bash -n enclave-exec/localnet-real.sh`, and `git diff --check` passed.
- Docker-backed Rust execution was skipped because Docker is absent. Nitro EIF,
  AWS/S3/KMS, public website/API, devnet, and mainnet deployment were not run.
  The current static frontend cannot work as a CTF service without an
  authenticated `/enclave` reverse proxy, explicit live cluster/program/RPC
  settings, and an attested verifier key.
- Final Anchor recheck after removing two harmless compiler warnings:
  `anchor build --ignore-keys` completed with no compiler warnings and
  `anchor test --skip-build --validator legacy` passed all 29 tests.
- Added a frontend production deploy preflight and Node tests. `npm run
  test:deploy` passed; `npm run build:deploy` correctly stopped because no
  explicit production cluster, deployed program ID, HTTPS RPC, or verifier
  endpoint is configured. The regular local `npm run build` remains available.
  Updated Pages instructions to use `npm ci && npm run build:deploy`; this is a
  configuration-shape check only and does not establish that the services are
  reachable or attested.
- Rechecked the preflight's valid-config path with placeholder devnet settings;
  lint and ordinary frontend build also pass. Vite still reports its existing
  browser crypto/stream externalization and large-bundle warnings. No live
  endpoint was contacted and no deployment was performed.
- Public preview preparation 2026-10-09: added isolated `frontend/preview/`
  build path (`npm run build:preview`) with a read-only project intro, explicit
  no-CTF/no-TEE state, restrictive Cloudflare Pages headers, and no runtime
  RPC/program/verifier configuration in the built bundle. Build and config scan
  passed. Wrangler device authorization succeeded. Created the direct-upload
  Pages project `sealed-code-bounty-preview` and published the preview to
  https://sealed-code-bounty-preview.pages.dev/. Wrangler reports Production,
  branch `main`; HTTPS returned 200 and the configured security headers.
- AWS CLI login revalidated for account `172873868884` in `eu-north-1`.
  Cost Explorer reports approximately $0.00 for October through Oct 9; no
  project-tagged EC2, project-prefixed KMS alias, or project-prefixed S3 bucket
  was found. Refreshed read-only Terraform plan: 21 create, 0 update, 0 delete;
  no EC2 instance. It retains the all-`f` PCR deny-all placeholder, so it
  cannot launch a functional TEE service. Plan saved only under `/tmp` and not
  applied.
- TEE build continuation: built AWS Nitro CLI v1.5.1 and AWS SDK C v0.4.2 KMS
  helper/NSM API v0.4.0 from pinned sources. The app image packages Podman 4.9.3,
  netavark with iptables-legacy (the pinned Nitro 4.14 kernel lacks nftables),
  the release runner, KMS helper, and embedded exploit runtime. A dev-only EIF
  was built at `/tmp/scb-candidate-dev.eif` from the dirty worktree; PCR0 is
  `ac126e068b424c0e462835972194c1f0d84cc2f12170f55ca358018ad492687c1d4e2213b85a17c7b89179279ee4d1b1`
  and file SHA-384 is
  `6f4fa3fecd367c25a0a28857aefefdc6c6bed636f30e9d49bcfdbf7652eb0118f78d39cc95fe9517ac563863c22dd1b7`.
  Podman imported the runtime and created an internal network in a disposable
  local container. This does not prove Nitro boot, runner execution, attestation,
  or KMS release. Do not pin/deploy this dirty-worktree EIF.
- Added Terraform EIF S3 key/digest settings, digest-checked parent download,
  and enclave launch systemd unit. `terraform validate` passed; refreshed plan
  remains 21 additions, no running instance, all-`f` PCR and all-zero EIF digest.
  It is saved at `/tmp/scb-staging-reviewed-20261009.tfplan`; no apply, upload,
  or AWS resource creation occurred.
