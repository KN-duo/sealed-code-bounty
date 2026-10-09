# Public hosting and small-group readiness

Reviewed 2026-10-09 against the current worktree. The user requires a public
website that works from other computers, AWS TEE execution for authorized CTF
challenges, fewer than ten concurrent users, and a **$2/month maximum**. There
is no requirement to buy a VPS or keep the website on AWS.

An isolated public project preview is live at
https://sealed-code-bounty-preview.pages.dev/. There is still no operational
bounty website/API, devnet or mainnet program, or AWS project resource. The
refreshed AWS plan is not a working verifier deployment and has not been applied.

An isolated static public-preview build is now available with
`cd frontend && npm run build:preview`. It deliberately contains no RPC,
program ID, or verifier endpoint and displays a notice that CTF actions are not
live. It is a project introduction only, not the operational bounty frontend.
It was published to the Cloudflare Pages Free service on 2026-10-09. A live
HTTPS check returned 200 and the configured security headers. This preview
build does not provide the app's `/enclave` or `/workspace-api` services; no
operational verifier API is online.

## Current behavior

| Component | Actual implementation | Hosting implication |
| --- | --- | --- |
| Bounties, escrow, pending submissions, receipts, reveals | Solana accounts; browser reads the configured RPC | Shared authoritative state already exists. Hosted builds need a public cluster/RPC and deployed program, not a local validator. |
| Website | Static Vite application; `/enclave` and `/workspace-api` use the development server's proxies | Uploading the static build alone does not supply these APIs. Public HTTPS routing and correct build variables are required. |
| Rust upload store | Immutable sealed record store, SHA-256 receipts, development directory backend, and Nitro vsock helper for a parent S3 broker | Restart recovery is implemented and tested locally. The AWS broker has offline tests but has not run against a real S3 bucket or enclave. |
| Rust verification | Now selects by bounty, solver, and plaintext hash; one execution admitted at a time | Different hunters' uploads no longer displace one another. Busy requests get retryable HTTP 503. This is process-local admission, not a durable queue or a distributed lock. |
| Relayer queue and retry state | In-memory retry state reconstructed from pending on-chain submissions at startup and periodically | Recovery and unchanged-job backoff are tested. Retry counters reset on relayer restart; chain state remains the source of truth. |
| Submission slot | One pending submission per bounty, enforced on chain | Ten people may browse one bounty; ten submissions to that bounty cannot all be accepted at once. Multiple bounties can have pending jobs. |
| Rate limits | Default five uploads/hour per wallet and per peer IP | The loopback proxy collapses all clients to one peer IP. Public deployment needs wallet limits plus a correctly authenticated edge IP limit. Do not trust arbitrary forwarded headers. |
| Sandbox and key bootstrap | Release selects Podman and attested KMS bootstrap; plaintext environment keys require an explicit development feature | Development EIF, nonce-bound NSM endpoint and independent operator verifier exist. Nitro isolation, live attestation/KMS denial and release, browser attestation checks and clean release remain incomplete. |
| Nitro transport | Parent uses threads; enclave proxy forwards one request at a time | A long verification can block uploads/health through the proxy even though the Rust API stays responsive. Bound transport concurrency separately from execution concurrency. |
| Buyer decryption keys | Browser session storage plus user backup export/import | Using a different PC requires restoring the buyer key backup as well as connecting the wallet. Never solve this by putting private buyer keys into a server database. |
| Practice terminals | Local development workspace service | Public authenticated terminal routing, per-user ownership, quotas, and cleanup are not implemented. Keep this optional feature unavailable in the first hosted CTF session. |

This is a code review and targeted local verification, not a ten-user AWS load
test. No throughput, high availability, or TEE confidentiality claim follows.

## Budget-compatible deployment design

1. Host the static frontend on **Cloudflare Pages Free**, using its provided
   HTTPS subdomain. Static asset requests are free and unlimited under the
   documented plan. This does not host the Rust runner or provide its API.
2. Use **Solana devnet** for synthetic CTF state and settlement. Add restart and
   periodic recovery by reading pending on-chain submissions. This small-group
   version does not need an always-running PostgreSQL/RDS server. A managed
   metadata database can be added later if operational state requires it.
3. Keep manifests, environments, sealed submissions and encrypted reveals in
   private **S3** objects. Hash-bound durable references must replace the current
   synthetic `blob.local` references. Retain the KMS key needed to recover the
   stable enclave keys across sessions; destroying it can permanently lose the
   ability to decrypt previously uploaded submissions.
4. Start one **Nitro parent only for an operator-scheduled session**, initially
   one one-hour session per month. Terraform creates a launch template, not an
   EC2 instance. The start script reserves a monthly session marker; an AWS
   workflow owns launch and delayed termination, and the instance has an early
   termination timer. The workflow has passed definition validation but has not
   run against EC2. These guards are not an
   account-level spending cap. Verify one job at a time; cap queued work to fit the session
   and the on-chain unlock deadline. Show availability before accepting a bond.
5. Publish the API over authenticated HTTPS during sessions. Route only browser
   operations publicly; keep `/internal/verify` private to the relayer. End each
   session by terminating compute and deleting its root volume. Keep durable
   ciphertext and keys independently of ephemeral compute.

When the API/chain gates are actually ready, the static Pages project settings
are: root directory `frontend`, build command `npm ci && npm run build:deploy`,
output directory `dist`. The frontend provides `npm run test:deploy` and a
production build guard. It requires build-time `VITE_CLUSTER` to be `devnet` or
`mainnet`, a valid `VITE_PROGRAM_ID`, an HTTPS `VITE_RPC_URL`, and an explicit
`VITE_ENCLAVE_URL` (same-origin route or HTTPS service URL). Those values still
need to correspond to the same deployed cluster/program, and `/enclave` must
route to the authenticated verifier API. The preflight validates configuration
shape only; it does not verify chain identity or service health. Vite build
variables are public browser config; never put RPC secrets, wallet keys, KMS
material, or bearer credentials in a `VITE_*` variable. These settings are
preparation only—do not publish the current build as an operational bounty
site while `/enclave` and the chain deployment are missing.

The website can stay online between sessions, while execution is unavailable.
Automatic wake-up would require additional orchestration, an enforced monthly
runtime allowance, cold-start feedback, and durable uploads. It is not currently
implemented. If continuous immediate execution is required, the $2 budget is
incompatible with the current Nitro parent design.

## Cost boundary

The AWS Price List API returned **$0.204/hour** for Linux `m6i.xlarge` in
`eu-north-1` (effective 2026-10-01). Public IPv4 is **$0.005/hour**. The
configured 40 GiB gp3 root volume is **$0.0836/GiB-month**, or about $0.0046
for one hour. That is about **$0.214 for a one-hour run**, plus one retained
customer-managed KMS key at **$1/month**: approximately **$1.214/month** for
one such session before S3, log ingestion, transfer, and taxes. Automatic
rotation is disabled because AWS charges an extra $1/month for each of the
first two customer-managed-key rotations. Manual replacement/re-pinning must
be planned with budget headroom. AWS Budgets alerts at $0.80 actual and $1
forecast but are not a hard cap, so this remains an estimate rather than a
spending guarantee. Build and bootstrap time counts as running time too.

At 730 running hours the same compute/address pair would be about $152.57/month,
before disk, KMS and other services. Even stopped, the old 40 GiB gp3 root volume
would cost about $3.34/month at the previously retrieved regional rate. Therefore
the old stop-and-retain staging configuration must not be used for this budget.

AWS Budgets alerts are delayed notifications, not a hard $2 spending limit.
Do not advertise a spending guarantee based on them. Before any cloud session:

- Regenerate the resource plan for ephemeral compute and separately retained
  keys/objects; account for all existing project costs and tax headroom.
- Arm termination before package installation, plus an independent termination
  schedule in case bootstrap fails. Terraform now prepares a one-hour systemd
  termination timer before package installation and makes shutdown terminate
  the instance; this behavior has not been exercised on EC2.
- Enforce a runtime/session allowance and reject excess work. Avoid automatic
  restarts/relaunches after the allowance is exhausted.
- Remove the terminated instance's volume, public address, and temporary build
  artifacts; bound versions of retained S3 objects and logs.
- Do not apply the old `infra/aws-nitro/staging.tfplan`.

AWS confirmed that `c6i.xlarge` and `c5a.xlarge` are also Nitro-capable in
Stockholm (4 vCPU, 8 GiB). Their current prices, memory headroom, and EIF behavior
have not been compared; they are candidates, not a verified cheaper deployment.

## Work completed in this review

- Replaced newest-upload lookup with bounty + solver + exploit hash selection.
- Bound the claimed exploit hash to the authenticated decrypted bytes.
- Made repeated identical uploads idempotent in storage accounting.
- Added process-local verification admission with HTTP 503/Retry-After.
- Fixed runner startup spawning its sweeper before entering a Tokio runtime.
- Required `solver_pubkey` on Rust verify requests, as already supplied by the
  relayer, and corrected the wire documentation to call the hash plaintext SHA-256.

Verification has advanced since the initial concurrency review: the latest
recorded runner suite passed 72 tests and Clippy with warnings denied; relayer
and CLI each passed 12 tests; Anchor passed 29 localnet tests; frontend lint and
build passed. A real local binary boot and ten parallel health requests passed
using the stub sandbox. These checks prove local API behavior only; no enclave
or ten-job workload was tested. Docker is available with elevated local daemon
access; Terraform/AWS access is available for read-only planning. Nitro CLI
v1.5.1 was built in `/tmp`, and only a throwaway EIF CLI smoke test has run.

Manifest/environment verification, V5 manifest binding, and bounded exploit
ZIP handling are implemented and locally tested. Remaining gates include
public HTTPS/authenticated API routing, production cluster configuration,
proxy-aware limits, Docker-backed V5 execution, enclave-native sandbox,
attestation/KMS, two-browser devnet flow, independent review, and an approved
mainnet canary. See `DEPLOYMENT-HANDOFF.md` for the sequence.

## Sources checked

- AWS Price List API read-only lookup, `eu-north-1`: Linux `m6i.xlarge`
  $0.204/hour and gp3 `EUN1-EBS:VolumeUsage.gp3` $0.0836/GiB-month,
  effective 2026-10-01 (queried 2026-10-09).
- [AWS EC2 pricing guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/optimize-costs-microsoft-workloads/right-size-selection.html)
- [AWS EC2 lifecycle and idle billing](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html)
- [AWS KMS pricing](https://aws.amazon.com/kms/pricing/)
- [AWS VPC public IPv4 pricing](https://aws.amazon.com/vpc/pricing/)
- [AWS EBS pricing](https://aws.amazon.com/ebs/pricing/)
- [AWS Nitro Enclaves requirements](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [Cloudflare Pages pricing](https://developers.cloudflare.com/pages/functions/pricing/)
- [Cloudflare Pages Git integration](https://developers.cloudflare.com/pages/get-started/git-integration/)
- [Cloudflare Pages build configuration](https://developers.cloudflare.com/pages/configuration/build-configuration/)
- [CloudFront free flat-rate plan](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/flat-rate-pricing-plan.html)

CloudFront Free is an alternative, subject to account eligibility and separately
metered origin services. The default Terraform CloudFront configuration must not
be assumed to enroll a distribution in that plan automatically.
