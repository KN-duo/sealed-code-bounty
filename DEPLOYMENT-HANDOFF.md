# SealedCodeBounty: completion and deployment handoff

Last updated: 2026-10-09

## Final objective

Ship a publicly hosted website where bounty owners publish intentionally
vulnerable, authorized CTF-style challenge environments and hunters submit
encrypted solutions. Plaintext submission execution must occur inside an AWS
Nitro Enclave. A successful enclave-signed verdict must atomically settle the
Solana bounty and deliver the submission encrypted to the buyer.

The production claim is not complete until all of the following are true:

1. The public website is hosted behind HTTPS.
2. The production frontend points to the intended Solana cluster and hosted API.
3. The Rust verifier and sandbox run inside a measured EIF.
4. The enclave has no network interface and communicates only through vsock.
5. KMS releases the master secret only to an attestation matching the approved
   EIF measurement.
6. The EC2 parent never receives the plaintext master secret or submission.
7. The attested enclave keys are pinned in the Solana configuration.
8. PASS, FAIL, timeout, restart, recovery, and force-unlock are proven on devnet.
9. An independent security review is complete before mainnet or real client code.

## Mandatory working rules

- Read `AGENTS.md`, `tasks/todo.md`, `tasks/lessons.md`,
  `SECURITY_SCOPE.md`, `docs/integration-plan.md`, `BUILD.md`, and this file
  before editing.
- Preserve the existing dirty worktree. Do not reset, checkout, or overwrite
  unrelated user changes.
- Use `apply_patch` for edits.
- Do not create AWS resources, run `terraform apply`, deploy to devnet/mainnet,
  purchase a domain, or incur charges without explicit user approval.
- Do not use real customer submissions until the independent review is complete.
- Do not claim TEE confidentiality based on Docker, vsock unit tests, an EIF
  build, or an enclave boot alone. Require attestation plus the KMS denial and
  release proofs described below.
- Never log plaintext submissions, flags, master secrets, private keys, complete
  process output, or unredacted HTTP/vsock bodies.
- Only owner-supplied or explicitly authorized targets are in scope.

## Current verified state

Only a read-only public preview is deployed at
https://sealed-code-bounty-preview.pages.dev/; no operational website/API,
AWS resources, devnet program, or mainnet program has been deployed. This
machine has Docker 29 CLI, AWS CLI, Anchor, and Terraform 1.16.5 at
`/tmp/scb-tools/terraform`; local Docker access requires elevated tool execution
and Nitro CLI v1.5.1 was built under `/tmp`. AWS CLI access was revalidated on
2026-10-09. A static build is not a
usable verifier service: the browser `/enclave` proxy, production cluster/program
configuration, API authentication, and measured enclave are absent.
The frontend now has a `build:deploy` preflight (with passing tests) that
rejects absent or obviously local/malformed production settings. The production
build remains blocked because no production cluster, program ID, RPC, or
verifier URL is configured. A separate `build:preview` creates a static,
read-only project introduction without blockchain or verifier configuration;
it is not the operational bounty site. Neither build validates deployed
services or attestation.

Verified local implementation and tests (2026-10-09):

- `SCB_VERDICT_V5` binds the Bounty's manifest hash into the signed verdict;
  Anchor reconstructs it from chain state. Cross-language positive and
  mismatched-manifest cases pass.
- Runner: 73 tests and Clippy with warnings denied pass. This includes sealed
  upload persistence/recovery, fixed-key artifact hash checks, ZIP adversarial
  validation, bounded output collection, and Docker CLI argument-shim tests.
  An explicit local Docker smoke test also passed the current Rust executor
  against the cached ret2win target and found a real per-run flag. This is not
  an AWS Nitro or full API-to-Solana settlement proof.
- Relayer: 12 tests pass; pending work recovery and retry/backoff are local
  implementations, not a hosted service.
- CLI: 12 tests pass. Frontend lint/build pass. Anchor localnet has 29 passing
  tests with `anchor test --skip-build --validator legacy`; `anchor build
  --ignore-keys` passes. Normal `anchor build` still reports a source ID vs
  preserved program-keypair mismatch; do not run `anchor keys sync` casually.
- `nitro/` framing/storage broker suites and Terraform lifecycle checks are
  offline tests only. On 2026-10-09 AWS credentials were valid and a fresh
  read-only plan was generated; it had 21 additions, no EC2 instance, and a
  deny-all PCR placeholder. It was not applied.
- A prior pre-V5 JavaScript/Docker prototype and local settlement run were
  recorded on 2026-10-08. They do not establish that the current Rust V5 path
  runs in Docker or that any code runs inside Nitro.

Key completed local changes include durable encrypted upload receipts,
content-addressed manifest/environment retrieval and hashing, bounded ZIP
handling, per-process single-execution admission, relayer restart recovery,
and the parent/enclave storage transport prototype. They remain subject to
the deployment gates below.

## Current deployment boundary (2026-10-09)

The isolated static preview is implemented and `cd frontend && npm run
build:preview` succeeds. It has no wallet or challenge actions, carries a
prominent offline notice, and emits restrictive Pages headers. A bundle scan
confirmed it does not contain the project's program ID, local RPC URL, or
verifier endpoint. It is now published on the Cloudflare Pages Free service at
https://sealed-code-bounty-preview.pages.dev/. The Pages deployment is marked
Production on branch `main`; an HTTPS HEAD returned 200 with the configured
CSP, HSTS, frame, MIME, referrer, and permissions headers. AWS identity is valid;
Cost Explorer shows about
$0.00 for October through the 9th, and no project-tagged EC2 instance or
project-prefixed S3 bucket/KMS alias was found. A refreshed read-only Terraform
plan contains 21 additions, 0 changes, and 0 deletions; it creates no EC2
instance and still uses the deny-all PCR placeholder. No AWS resource was
created and the plan is not deployable as a working verifier.

The force-unlock drill completed with these assertions:

- the relayer observed the submission;
- the deliberately unreachable verifier exhausted retries;
- the sweeper called `force_unlock_submission`;
- the submission slot reopened.

The balance assertion expects the pre-submit balance minus only the Solana
transaction fee. The local drill passed:

```bash
bash e2e/localnet.sh unlock-drill
```

Observed final line:

```text
E2E RESULT: MODE=unlock-drill ALL ASSERTIONS PASSED
```

### Latest continuation: sandbox work (2026-10-09)

The original app source still contains the owner bounty creation/manage/reveal
routes, hunter ZIP upload, CLI packaging, verifier, and settlement integration.
The deployed Cloudflare URL remains an informational static preview, so those
flows are not hosted or usable there yet.

The runner's exploit container previously mounted the per-verification flag
directory at `/srv`; this allowed a submitted exploit to read the answer
without attacking the target. That mount was removed. Only the target receives
the read-only flag mount. Verification networks are now unique per run and
internal, with network cleanup on the normal and handled error paths. Release
configuration selects Podman and rejects Docker-daemon and stub modes. The
candidate Podman flags drop capabilities, use a fixed subordinate UID/GID map,
deny AF_VSOCK via seccomp, and make the exploit root filesystem read-only with
`no-new-privileges`. The host workspaces are mapped to the configured subuid;
the release image must provision matching `/etc/subuid` and `/etc/subgid`
ranges.

`cargo build --release --locked` and the focused Docker argument-shim suite
(6 tests) pass after these source changes. The shim verifies the flag-mount
removal, isolated-network create/cleanup, no-pull behavior, and timeout
cleanup. It does not establish that Podman starts under the Nitro enclave
kernel. An application enclave Dockerfile and explicitly dev-only local EIF
build script package Podman, fixed UID/GID mappings, the AF_VSOCK seccomp
profile, and the embedded exploit runtime image. The release Nitro CLI v1.5.1,
AWS SDK C v0.4.2 KMS helper, and NSM API v0.4.0 were built from pinned upstream
sources. A 332 MiB (348,115,420-byte) application EIF was built at `/tmp/scb-candidate-dev.eif`:
PCR0 `ac126e068b424c0e462835972194c1f0d84cc2f12170f55ca358018ad492687c1d4e2213b85a17c7b89179279ee4d1b1`,
file SHA-384 `6f4fa3fecd367c25a0a28857aefefdc6c6bed636f30e9d49bcfdbf7652eb0118f78d39cc95fe9517ac563863c22dd1b7`,
Docker image ID `sha256:5e6747e065c5727dd94d683ed2e14be25f656dc80b10c963ea82525aacea6dce`.
The source worktree was dirty, so this is a dev-only measurement and must not
be pinned into KMS or deployed. Podman selected netavark, imported the
embedded runtime, and created an internal network in a disposable local
container. Those host-kernel smoke checks are not a Nitro sandbox run. No AWS
enclave boot or hardware runtime proof
exists yet. The Terraform provider schema handshake initially failed because
the sandbox forbids the provider's local Unix socket; with elevated local
execution, `terraform validate` passed and a fresh read-only
`terraform plan -refresh=true -var-file=staging.tfvars` completed: 21
additions, 0 changes, 0 deletions, and no EC2 instance. AWS identity is valid
for account `172873868884` in `eu-north-1`; no AWS resources were created and
no deployment was attempted.

Read-only AWS inventory checks found no project-tagged resources, no
project-tagged EC2 instances, no project-prefixed S3 buckets, and no
project-prefixed KMS alias in `eu-north-1`. Cost Explorer for 2026-10-01 through
2026-10-10 reported approximately $0 for AWS service costs; billing data is
delayed and this is not a spending guarantee. The newest reviewed plan is
`/tmp/scb-staging-reviewed-20261009.tfplan`; it supersedes the prior temporary
plan and includes the pinned EIF S3 download/start configuration.

The AWS Price List API currently reports Linux `m6i.xlarge` at $0.204/hour in
Stockholm; public IPv4 is $0.005/hour, and gp3 is $0.0836/GiB-month. With the
40 GiB root disk, one hour plus the retained $1/month KMS key estimates about
$1.214/month before S3, logs, transfer and taxes. KMS automatic rotation was
disabled in Terraform to avoid its extra $1/month charges for each of the
first two rotations. The $2 AWS Budget sends alerts; it does not enforce a cap.
The fresh plan file is `/tmp/scb-staging-reviewed-20261009.tfplan`; do not apply
until a release application EIF is built and reviewed, its PCR0 and file
SHA-384 are inserted, and the plan is regenerated. The current plan still has
the deny-all PCR0 and all-zero EIF file digest.

The upload receipt contract and durable encrypted store are now implemented
across frontend, CLI, runner, and relayer. Local tests prove receipt validation,
restart recovery, stored-record substitution rejection, and relayer recovery.
Manifest and environment fetching now bind into the on-chain verdict with
SCB_VERDICT_V5 and have passed local runner, relayer, and Anchor tests. The S3
broker is covered by offline injected-client tests only; no AWS object storage
or Nitro enclave has been run. Step 1.4's Rust ZIP handling and browser/CLI ZIP
contract are implemented and covered by local adversarial tests. The V5 local
Docker PASS/FAIL settlement cycle still needs to be rerun.
No AWS resources have been created. The checked-in saved plan
`infra/aws-nitro/staging.tfplan` is stale and must not be applied; the newer
`/tmp/scb-staging-reviewed-20261009.tfplan` is also unsafe to apply while it
contains the placeholder PCR and digest.

### Latest continuation: attestation and artifact provenance (2026-10-09)

`runner/src/attestation.rs` implements `POST /internal/attestation` with a
bounded canonical-base64 nonce, a 1 KiB request limit, serialized NSM calls and
`Cache-Control: no-store`. It requests a real NSM document binding the upload
encryption key, verdict key, compile-time source identity and SCB_VERDICT_V5.
There is no software attestation fallback; unavailable NSM returns 503. Both
vsock proxies now permit this endpoint. Existing owner/hunter application
routes and exploit-upload/verification/settlement sources remain present.

`nitro/verify_attestation.py` independently challenges the endpoint and checks
the pinned AWS root, strict certificate path, ES384 COSE signature, bounded
unambiguous CBOR/JSON, nonce/freshness, expected PCR0 and both application keys.
The official ZIP hash is not the certificate fingerprint; the bundled root
DER SHA-256 is
`641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`.
`nitro/ATTESTATION.md` documents the wire binding and first-boot key provisioning.
This is an operator verifier; browser attestation enforcement and live AWS
verification remain open.

The development EIF builder embeds source identity and writes structured
provenance containing source/input hashes, image ID, compiler/CLI versions,
OS package inventory, EIF digest and measurements. It rejects source changes
during building. The latest development artifact is `/tmp/scb-attestation-dev.eif`
(348,526,052 bytes) with sibling `.provenance.json`:

- PCR0: `f0d63c00b13ed4856b8d4d52ec0788db9b4131ae01d5b43c63be441f7a5b46438b5d2ff2cfc7c9e268cc21b5e459618f`
- PCR1: `0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa`
- PCR2: `1d8c0b6bf2ad784102edff4492127ebc1d5f2e495c93a0edd328130ec4caf4d44bd723c45bfd3d0da66de959813fcd47`
- EIF SHA-384: `419a1ddf924cd7af6eee7429a2ce5e8f59f4bb515c1a4c1cd6ab6c6671d86decd628c9a7b31d1e00f95f2191a9646967`
- Image ID: `sha256:9f76c7d3ffb000ad113e28d28e3ef50a85b70c53dfdafca405482ab991058bcd`
- Compiled identity: `cc80c1bada1a80485cbebf27f71f5afb71fd6bd9-dirty`

This is still a dirty-source development artifact, not a reviewed release or
hardware execution proof. Its provenance describes the snapshot at build time;
later documentation/Terraform changes are not incorporated into that snapshot.
At that build, full OS/runtime/helper dependency locking, clean release provenance
and the two-build reproducibility gate remained open. See the newer dependency
build continuation below. Do not pin this development PCR in
KMS or deploy it as production.

The candidate explicitly selects cgroupfs/file logging instead of requiring
systemd/journald, and startup requires writable memory/CPU/pids controllers.
The EIF downloader now checks account ownership, bounded stream length,
complete length and reviewed digest, rejecting placeholder hashes. The Nitro
CLI log path was corrected to a directory plus `nitro_enclaves.log`; CloudWatch
is configured before enclave startup to collect bootstrap failures.
The launch template now gzip-compresses the entire bootstrap payload before
base64 encoding: a representative rendering was 21,031 bytes uncompressed and
12,800 bytes compressed, below EC2's 16 KiB raw user-data limit. Confirm the
exact rendered payload size in the final launch review.

The draft KMS policy now explicitly denies decrypt with a missing/wrong
recipient PCR and denies re-encryption, closing the broad administrative IAM
grant's plaintext/re-encryption bypass. Administrators can still change policy;
policy changes require review. No live KMS denial or release has been proven.

This continuation completed release and development-feature Rust compilation,
Rust library/binary Clippy with warnings denied, shell/Python syntax checks,
verifier dependency installation/CLI loading/root fingerprint inspection,
Terraform validation and a refreshed read-only plan. No tests were added or run
in this continuation; historical suite counts above predate these changes.
No cloud resources were created, no EIF was uploaded, and no program was
deployed. The newest plan is `/tmp/scb-staging-attestation-20261009.tfplan`;
it supersedes the earlier reviewed temporary plan, has 21 additions/no EC2
instance and retains placeholder PCR/file digest. It must not be applied.

### Latest continuation: locked dependencies and managed sessions (2026-10-09)

The refreshed AWS login works. The new draft Standard Step Functions workflow
owns both `RunInstances` and delayed termination, using a fixed numeric launch
template version and a unique client token. Launch/IAM inputs cannot be
overridden through execution input. Cleanup is restricted to tagged project
parents; launch failure or a lost response still enters delayed cleanup.
This removes the timing gap from a separate local launch after arming a timer.
AWS definition validation returned `OK` with no diagnostics using the actual
Terraform expression rendered with validation-only future resource IDs.
Terraform validation passed. These checks do not prove live IAM or termination.
The newest read-only plan is `/tmp/scb-staging-backstop-20261009.tfplan`, with
24 additions, no updates/deletions and no EC2 instance. It supersedes earlier
temporary plans and retains deny-all PCR/EIF digest placeholders; do not apply
it. The final workflow definition is unknown in the pre-apply plan because its
future launch-template/bucket IDs do not exist. AWS syntax validation used
substitute IDs only and does not establish their eventual IAM permissions.

The start script retains a conditional monthly S3 reservation. Teardown writes
a durable launch-disable marker, stops workflow launchers, and drains parents
before destroying infrastructure. AWS outages/eventual consistency can delay
termination; budget alerts and these guards are not a hard spending cap. A
nonempty versioned bucket deliberately prevents full destruction until an
explicit retention or purge decision; do not claim that all teardown is proven.

The exploit runtime now builds from a digest-pinned Ubuntu base, a signed fixed
snapshot, 116 exact OS packages and 37 hashed Python wheels. The enclave OS
layer's complete 143-package lock also built successfully. The runtime archive
is `/tmp/scb-exploit-runtime-locked.tar` (90,911,232 bytes), SHA256
`cc8c45679274dc614366ee16280a0f9042f1e53169b8cb83baf1f10aee8d47a1`.
These changes preserve the owner's Dockerfile challenge authoring and hunter
ZIP workflow. The dedicated runner and KMS builders pin compilers/source inputs
and disable networking during actual compilation. The EIF builder checks their
provenance against current source and copied binaries, and checks pinned Nitro
kernel/bootstrap blobs. Clean candidate mode refuses dirty source/components;
neither mode approves a release. Build timestamps and Nitro conversion still
require the two-build reproducibility review. No new tests or cloud resources
were created in this continuation. The website remains the static preview.

The pinned Rust 1.89.0 runner build completed with network disabled, Cargo.lock
vendoring and no default features. `/tmp/scb-runner-pinned-artifacts/scb-runner`
is 4,895,608 bytes, SHA256
`9c44ec208fd8fc03ad035a98d66a52c4912f5ab53b0e16819eb9f51921aba30a`.
Its sidecar records 21 stable source inputs and the vendored dependency hashes.

## Step 1 — finish the production execution path

### 1.1 Force-unlock drill — complete locally

Run the command above. If it fails, inspect the newest directory:

```bash
latest=$(ls -dt /tmp/scb-e2e.* | head -1)
tail -200 "$latest/relayer.log"
tail -200 "$latest/validator.log"
```

Gate passed: slot Open, submission absent, bond refunded, and only the
transaction fee charged. Evidence is recorded in `tasks/todo.md`.

### 1.2 Content-addressed environment locator — implemented locally

The on-chain `Bounty` stores `manifest_sha256` and `env_blob_sha256`, not an
object URL. The relayer/runner now derive fixed object keys from those hashes;
production still needs the approved storage bucket/origin configured. Do not
pass host filesystem paths into the enclave in production.

The content-addressed convention is implemented locally:

- manifest object: `scb/manifests/<manifest_sha256>.json`
- environment object: `scb/envs/<env_blob_sha256>.tar.gz`
- object keys are derived from on-chain hashes, never submission URLs;
- the manifest uses a strict schema, byte cap, canonical hash check, and must
  name the committed environment hash;
- the environment is streamed under a cap and hash-checked;
- the runner stages the verified objects and uses the verified manifest limits;
- the signature binds the manifest hash, preventing a parent from substituting
  a different command set without invalidating the verdict.

The current implementation fetches fixed-key content through the narrow parent
S3 broker and verifies the complete objects before sandbox use. This behavior
has offline tests only; the production origin still needs configuration, and
parent/enclave integration and AWS S3 have not run.

The content-addressed fetch, size/hash/schema checks, and enclave-internal
staging are implemented. SCB_VERDICT_V5 includes the committed manifest hash,
and the Anchor program rejects a verdict signed over a different hash. Current
local verification passed: runner suite (72), relayer suite (12), and Anchor
localnet suite (29). Real AWS object storage and Nitro execution remain
unverified.

Key files:

- `relayer/src/pipeline.ts`
- `relayer/src/enclave-types.ts`
- `runner/src/blob_fetch.rs`
- `runner/src/routes.rs`
- `cli/src/manifest.ts`
- `cli/src/upload.ts`
- `frontend/src/lib/manifest.ts`

Those cases are covered locally. Keep the existing size, hash, schema,
cancellation, and path-allowlist tests green when changing this contract.

### 1.3 Unify the upload contract — implemented locally

The canonical upload response is `{ "receipt": "<hex>" }`; production code no
longer invents `https://blob.local/...` references. The encrypted submission
reference is durable and hash-bound locally. Production S3 durability is not
live-tested, and in-memory stores remain test/dev-only.

Gate passed locally: frontend, CLI, runner, relayer, and tests use the same
typed `{receipt}` contract. Production S3 durability is not live-tested.

### 1.4 Complete ZIP handling — implemented locally

The JavaScript prototype invokes `unzip` inside the runtime. The Rust runner
implements the intended bounded extraction path; production deployment remains
gated on real Docker and Nitro verification:

- cap compressed and expanded bytes;
- cap file count and path length;
- reject absolute paths, `..`, symlinks, hardlinks, devices, and FIFOs;
- require `exploit.py` or a strictly validated top-level
  `scb-exploit.json` entrypoint;
- reject shell command strings; use argument arrays;
- zeroize extracted plaintext files best-effort and remove the private workspace
  on every exit path; mount it read-only in the exploit container.

Adversarial Rust tests cover normal archives, traversal, symlinks, duplicate
paths, malformed/shell entrypoints, expanded-size, file-count, path-length, and
compressed-size caps, plus zeroize-and-remove cleanup. Browser and CLI clients
accept ZIP signatures and enforce the same 9,000-byte compressed cap; the runner
is authoritative for full archive validation. Real Docker execution remains a
separate Step 1 verification gate.

### 1.5 Step 1 verification commands

Current local gates (all passed on 2026-10-09):

```bash
(cd runner && cargo test --locked)
(cd runner && cargo clippy --locked --all-targets -- -D warnings)
(cd relayer && npm test)
(cd cli && npm test)
(cd frontend && npm run lint && npm run build)
python3 nitro/test_protocol.py
python3 nitro/test_storage.py
python3 nitro/test_storage_artifacts.py
anchor build --ignore-keys
anchor test --skip-build --validator legacy
bash e2e/localnet.sh unlock-drill
```

The following existing smoke scripts use the legacy JavaScript process/Docker
prototype (`enclave-exec/enclave.cjs`), not the current Rust V5 runner. They
are not a substitute for the open Step 1 gate and their keys are process-held:

```bash
node enclave-exec/selftest.cjs
ENCLAVE_PORT=8543 SCB_REVEAL_STORE=inline \
  SCB_EXPLOIT_FILE=enclave-exec/solve-compact.py \
  bash enclave-exec/localnet-real.sh
```

The Rust Docker smoke test now passes, but current API-to-Solana V5 settlement
has not been proven. Docker's local seccomp profile denied `setarch -R`; the
smoke target is static/no-PIE and passed with ASLR wrapping disabled. Nitro CLI,
an EIF, attestation, KMS key release, hosted API, and AWS object-store access
remain unavailable and unverified.

Build a Rust-runner-backed local PASS/FAIL and settlement harness, run the PASS
cycle twice consecutively, and record commands/results under `tasks/todo.md`
Review. Mark Step 1 complete only when that current path is green.

## Step 2 — complete the Nitro trust boundary

### 2.1 Replace Docker inside the enclave

Nitro Enclaves cannot use the parent Docker daemon. Implement an enclave-native
sandbox. The design currently calls for `nsjail`, but validate its build and
kernel requirements inside the actual EIF before committing to it.

Required isolation:

- separate PID, mount, IPC, UTS, and network namespaces;
- no external route; only target/submission communication;
- read-only target root with a controlled writable flag/work mount;
- no devices, privilege escalation, ambient capabilities, or host filesystem;
- cgroup/rlimit memory, CPU, process, file, and output limits;
- hard wall-clock termination with process-group reaping;
- deterministic cleanup and plaintext zeroization;
- one verification at a time until concurrency isolation is reviewed.

If the enclave kernel cannot support the required namespaces/cgroups, stop and
redesign. Do not silently weaken the sandbox.

### 2.2 Enclave boot and key derivation

The production runner must not read plaintext secrets from environment
variables. At boot:

1. Receive only KMS ciphertext/configuration through vsock.
2. Call `kmstool_enclave_cli` through the parent KMS vsock proxy.
3. Include an NSM attestation document containing the ephemeral public key.
4. Let KMS validate the approved PCR condition.
5. Receive the plaintext secret encrypted to the attested ephemeral key.
6. Decrypt it only inside the enclave.
7. Derive stable keys with domain-separated HKDF:
   - `scb-verdict-key-v1`
   - `scb-enc-key-v1`
8. Keep secret pages locked where supported and zeroize temporary buffers.

Remove production support for `SCB_MASTER_SECRET_HEX` and
`SCB_ENCLAVE_ENC_SECRET_HEX`, or compile it only behind an explicit development
feature that cannot be enabled in release EIFs.

### 2.3 Attestation API

Implemented in source with an independent operator verifier; live AWS evidence,
adversarial verification and browser enforcement remain open. The endpoint returns:

- raw signed attestation document;
- enclave encryption public key;
- verdict public key;
- nonce/challenge binding;
- build version and expected protocol version.

Provide a verifier tool that validates the AWS certificate chain, signature,
fresh nonce, PCR values, and key binding. Do not accept a public key returned by
an unattested parent endpoint.

### 2.4 EIF build

Create a dedicated enclave Dockerfile rather than reusing the exploit runtime.
It must contain only the runner, enclave proxy/entrypoint, sandbox, runtime
dependencies, CA material, and KMS enclave tool.

Add scripts such as:

```text
scripts/build-runner-image.sh
scripts/build-eif.sh
scripts/describe-eif.sh
scripts/verify-reproducible-eif.sh
```

Requirements:

- digest-pin base images;
- pin OS and language dependencies;
- build Rust with `--locked`;
- normalize timestamps and ownership where supported;
- emit image digest, git commit, EIF SHA-384, PCR0/PCR1/PCR2, and PCR8 when
  signed;
- refuse a dirty release build unless explicitly producing a development EIF;
- publish the mapping as a release artifact.

Gate: two clean builds from the same source produce the expected measurement or
the documented Nitro reproducibility boundary is understood and reviewed.

## Step 3 — infrastructure as code

Create `infra/aws-nitro/` with Terraform. Use provider/version lock files and
remote-state guidance, but do not create resources before approval.

Required resources:

- `eu-north-1` provider and explicit project/environment tags;
- enclave-enabled EC2 parent using a verified supported instance type;
- Amazon Linux 2023 AMI resolved from an official SSM parameter;
- encrypted EBS with delete-on-termination;
- instance profile with least-privilege KMS decrypt and required S3 reads;
- KMS key whose decrypt path requires Nitro recipient attestation PCR;
- private, versioned, encrypted S3 buckets with public access blocked;
- lifecycle rules for abandoned objects and logs;
- security group with minimal ingress;
- no SSH by default; use SSM Session Manager;
- CloudWatch metadata logs with explicit redaction policy;
- budget alarm, cost-allocation tags, idle shutdown, stop, and destroy scripts;
- IMDSv2 required and hop limit minimized;
- systemd services for allocator, enclave launch, KMS proxy, parent proxy, and
  relayer with restart limits and health checks.

Use a placeholder PCR variable during initial planning. Do not weaken the KMS
policy to launch staging. Build the EIF, insert the reviewed PCR, regenerate the
plan, and review the diff.

Commands:

```bash
cd infra/aws-nitro
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform plan -var-file=staging.tfvars -out=staging.tfplan
terraform show -no-color staging.tfplan > staging.plan.txt
```

Before requesting apply approval, provide:

- every resource to be created;
- current hourly/monthly estimate from official AWS pricing;
- expected bounded staging duration;
- public exposure and IAM assumptions;
- stop and destroy commands;
- expected resources that may continue billing after EC2 stops.

## Step 4 — AWS staging and Solana devnet

This step requires explicit approval because it creates billable resources and
external deployments.

Sequence:

1. Confirm AWS identity, region, service quotas, and a current Terraform plan.
2. Apply staging Terraform.
3. Build or transfer the EIF and launch it with fixed CID/resources.
4. Record `nitro-cli describe-enclaves` and `describe-eif` outputs.
5. Prove direct parent `kms:Decrypt` is denied.
6. Prove wrong-PCR enclave KMS decrypt is denied.
7. Prove approved-PCR enclave receives and derives keys.
8. Verify attestation from a separate client.
9. Deploy the reviewed Solana program to devnet.
10. Pin the attested keys in devnet Config.
11. Host a staging frontend and API behind HTTPS.
12. Run browser PASS, FAIL, timeout, resubmission, force-unlock, restart, and
    buyer Reveal decryption.
13. Stop/terminate compute immediately after the test window.
14. Inventory all resources and inspect actual costs.

Run the complete devnet proof twice. Save redacted evidence under
`artifacts/staging/<date>/`; never commit credentials or plaintext submissions.

## Step 5 — production readiness

Code can prepare this step, but an AI cannot truthfully perform an independent
security review or supply legal advice.

Required before real clients:

- independent review of the Anchor program, runner, sandbox, attestation/KMS
  flow, parent proxy, relayer, frontend cryptography, and Terraform;
- remediation and retest of every critical/high issue;
- multisig control of Solana upgrade and protocol authorities;
- timelocked enclave operator/PCR rotations;
- documented key/PCR rotation and rollback ceremony;
- authentication, authorization, rate limits, quotas, and abuse response;
- target-ownership evidence and moderation workflow;
- Terms of Service, Privacy Policy, acceptable-use policy, and jurisdictional
  review by qualified counsel;
- monitoring, paging, backup/restore, incident response, and status page;
- dependency and container scanning, SBOMs, signed releases, and secret scanning;
- limited synthetic-challenge beta with capped values.

Gate: signed review report, closed findings, operational owner, and successful
restore/incident exercises.

## Step 6 — hosted production and mainnet

This step requires explicit approval and real funding.

### Website hosting

Host the Vite frontend as immutable static assets using either:

- AWS S3 + CloudFront + ACM + Route 53, if keeping one-provider operations; or
- the user's explicitly selected static hosting provider.

Production frontend variables must identify mainnet explicitly and must never
fall back to localhost or devnet. Add CSP, HSTS, `frame-ancestors`, MIME
sniffing protection, a restrictive permissions policy, immutable hashed-asset
caching, and short caching for `index.html`.

The API ingress must terminate authenticated TLS, rate-limit clients, and proxy
only allowlisted verifier operations to the loopback parent proxy. The enclave
public key presented to browsers must be backed by a fresh verified attestation.

### Mainnet launch order

1. Freeze and tag the independently reviewed commit.
2. Build the release EIF from that tag and publish its measurement evidence.
3. Apply reviewed production Terraform.
4. Deploy the reviewed Solana program to mainnet.
5. Verify program data, program ID, upgrade authority, and multisig ownership.
6. Pin attested enclave keys through the controlled authority process.
7. Deploy the frontend with mainnet-only configuration.
8. Run a tiny synthetic canary bounty with strict value limits.
9. Verify payout, Receipt, Reveal, monitoring, and teardown/recovery procedures.
10. Open a capped private beta, then increase limits only after observed stability.

Never reuse localnet keys, development KMS ciphertext, test operator keys, or
browser `.env.local` values in production.

## Final definition of done

The project is finished only when all checkboxes below have evidence:

- [ ] Step 1 production-equivalent local path is fully green twice.
- [ ] Step 2 real EIF, attestation, sandbox, and KMS secret release are proven.
- [ ] Step 3 reviewed Terraform is applied with budgets and teardown tested.
- [ ] Step 4 hosted AWS staging and Solana devnet browser flow pass twice.
- [ ] Step 5 independent review and production controls are complete.
- [ ] Step 6 hosted website and mainnet canary pass with monitored real services.
- [ ] No plaintext submission or master secret is observed outside the enclave.
- [ ] Documentation states the actual verified guarantees without overclaiming.

Update `tasks/todo.md` continuously and append exact commands/results to its
Review section. If a gate fails, keep the corresponding step open.
