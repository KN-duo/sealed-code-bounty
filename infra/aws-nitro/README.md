# AWS Nitro staging infrastructure

**2026-10-09 budget update:** the user set a $2/month maximum. Do not apply the
saved `staging.tfplan`; it describes a stopped instance and 40 GiB retained
volume. The current draft creates only a launch template; it does not create an
EC2 instance. A separately invoked session terminates after one hour and
deletes its root volume. Only the KMS key and stored S3 objects remain between
sessions. Terraform validation and a refreshed read-only plan passed (21
additions, no EC2 instance, configured runtime one hour) on 2026-10-09. That
plan was not applied. Terraform and AWS CLI are available for read-only
inspection; AWS CLI access was reauthenticated on 2026-10-09. Nitro CLI v1.5.1
and a dev-only application EIF were built locally, but no release EIF, AWS
resources, or public API have been deployed. Full cost and launch review remain
required before resources are created.

This Terraform configuration prepares a launch template for one bounded
`m6i.xlarge` Nitro parent in `eu-north-1`, private
challenge/reveal/submission objects, a PCR-gated KMS key, CloudWatch log
retention, an SSM instance profile, and a $2 monthly budget with $0.80 actual
and $1 forecast notifications. It does not create or start an EC2 instance and
creates no public ingress rule. A launched parent gets a temporary public IPv4
address for outbound SSM and AWS API access; the address costs $0.005 per hour
while attached. The enclave has no network interface and its narrow parent
proxy still needs to enforce service and URL allowlists before use.

The Terraform KMS policy defaults to a nonmatching PCR0 placeholder. That
placeholder deliberately denies enclave decrypt. The parent launch unit also
requires a configured EIF SHA-384 file digest and retrieves the EIF from the
private `scb/runtime/` S3 prefix before starting it. After a release EIF has
been built and independently reviewed, publish that exact object, put its PCR0
and file digest into local `staging.tfvars`, regenerate the plan, and review the
policy and user-data diffs. Never change the policy to allow un-attested parent
decrypt.

The key policy explicitly denies decrypt when the recipient PCR0 is absent or
incorrect, including callers with broad account IAM permissions, and denies
re-encryption to prevent moving the stored data key to a less restricted KMS
key. The separate administration permission can still change key policy;
administrative policy changes remain a reviewed trust boundary. These denials
have not yet been demonstrated with live KMS calls.

The launch template now installs a fixed-purpose key broker and the parent
storage/API vsock brokers. On first enclave request, the key broker uses
`GenerateDataKeyWithoutPlaintext`, then stores only the returned KMS ciphertext
at `scb/keys/master-data-key.v1` with a conditional S3 write. It passes the
ciphertext and temporary instance-profile credentials over vsock; the enclave
uses `kmstool_enclave_cli` through the KMS-only vsock proxy. Plaintext is
released only by the attested KMS recipient path. This source and IAM wiring
have not been run on Nitro hardware, and the PCR remains deny-all until a real
EIF is reviewed.

The entire bootstrap is gzip-compressed before launch-template base64 encoding
to fit EC2's 16 KiB raw user-data limit. Cloud-init decompresses it on boot.
The exact decoded compressed payload must be checked in the final launch plan.

## State and input handling

Terraform state can contain account IDs, bucket names, and IAM policy details.
Keep it encrypted and outside version control. For this initial staging plan,
use local state only in a private checkout. For shared or production use,
configure an encrypted, versioned S3 backend with a DynamoDB lock table in a
separate bootstrap stack, restrict access to the deployment role, and enable
CloudTrail data events as appropriate. Do not store credentials in Terraform
variables or state.

Create `staging.tfvars` from `staging.tfvars.example`, then set the budget
notification address. The example uses the reserved `.invalid` domain and
must not be applied. The PCR placeholder must remain until an approved EIF
measurement exists. Terraform plans are written under this directory and are
ignored by git. After applying the reviewed foundation, preview a session
without starting EC2:

```bash
bash scripts/start-staging-session.sh --dry-run
```

`--start` writes a conditional monthly session marker to S3 and launches one
billable session. The marker prevents accidental repeat launches through this
script; it is an operational guardrail, not an AWS-enforced account spending
limit. Use `--start` only after reviewing the current plan and costs.
The script pins the numeric template version recorded in Terraform state.

The budget filters for the `Project=sealed-code-bounty` cost-allocation tag.
Activate that user-defined tag in AWS Billing and Cost Management before
relying on the budget notifications.

## Current deployment boundary

This directory is infrastructure source, not an available service. The
configured PCR0 is deliberately a deny-all placeholder because no production
EIF measurement exists. The plan and credentials are not included in this
repository. Do not apply a saved plan or launch a session until the trust-boundary,
cost, and external-approval gates in [`../../DEPLOYMENT-HANDOFF.md`](../../DEPLOYMENT-HANDOFF.md)
are closed. Static frontend hosting is a separate step and cannot replace the
missing authenticated API/reverse proxy.

## Review commands

```bash
terraform fmt -recursive
terraform init -backend=false
terraform validate
terraform plan -var-file=staging.tfvars -out=staging.tfplan
terraform show -no-color staging.tfplan > staging.plan.txt
```

Review the exact plan before applying. The default VPC and its `default-for-az`
subnets are existing resources; the module selects the first subnet by ID.
There are no VPC endpoints or NAT gateways, so neither incurs an hourly fee.

## Cost and bounded runtime

The last live AWS Price List API lookup returned **$0.204/hour** for Linux On-Demand
`m6i.xlarge` in EU (Stockholm). One attached public IPv4 address adds
**$0.005/hour**, for **$0.209/hour** while running. AWS lists gp3 storage at
**$0.0836/GiB-month** in Stockholm; the 40 GiB root disk is about **$3.34 per
month** while retained. The customer-managed KMS key is **$1/month** while
active (prorated hourly); KMS requests are separately metered.

A one-hour run is approximately **$0.21** for compute and public IPv4, plus
about **$0.0046** for the prorated root disk. With the **$1/month** KMS key,
one such session is approximately **$1.214/month** before S3, CloudWatch Logs,
requests, and taxes. Automatic KMS rotation is disabled because AWS charges an
additional $1/month for each of the first two customer-managed key rotations.
Replacing/re-pinning the key requires budget headroom. Each additional running
hour adds about **$0.21**. The `$2` budget and its notifications are alerts, not
a hard spending cap.

Bootstrap installs an early one-hour termination timer before package
installation, then installs Nitro CLI and Docker and reserves 4 GiB and two
CPUs for the enclave allocator. EC2 shutdown behavior is `terminate`, so the
root volume is deleted. The timer is a backstop, not a substitute for immediate
teardown.

The draft Standard Step Functions workflow independently owns launch, waits
the configured session duration, and requests termination. It pins the numeric
launch-template version, accepts only a session token, and restricts IAM launch
and cleanup to the intended project resources. Startup reserves the monthly
S3 allowance before starting that workflow; it never calls RunInstances locally.
Waits do not require an always-running server. Step Functions transition/request
charges, launch/cleanup overhead and AWS service failures must still be included
in the launch review. This workflow is validated configuration, not a proven
live shutdown or account-level cap.

Teardown disables new workflow launches and drains compute first. Versioned
buckets have `force_destroy=false`; nonempty buckets require an explicit data
retention/purge plan before complete foundation destruction. Retained KMS/S3
resources can continue charging. Do not remove durable ciphertext/key material
until its recovery/retention requirements have been reviewed.

## Terminate and destroy

Terminate the ephemeral parent while retaining the KMS key and S3 objects:

```bash
bash scripts/stop-staging.sh
```

Terminate session parents, wait for them to disappear, then destroy the
Terraform-managed foundation after evidence is collected:

```bash
bash scripts/destroy-staging.sh --confirm
```

The S3 buckets refuse forced deletion. Empty them only after confirming their
contents are no longer needed, then rerun destroy. KMS deletion is scheduled
with a seven-day waiting period. Inventory the account after teardown and check
actual costs.
