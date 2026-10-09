#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tf_dir="$repo_root/infra/aws-nitro"
mode="${1:---dry-run}"
if [[ $# -gt 1 || ( "$mode" != "--dry-run" && "$mode" != "--start" ) ]]; then
  echo "Usage: $0 [--dry-run|--start]" >&2
  exit 2
fi
if [[ ! -f "$tf_dir/terraform.tfstate" ]]; then
  echo "Terraform foundation state not found; apply the reviewed foundation first." >&2
  exit 2
fi

region="$(terraform -chdir="$tf_dir" output -raw region)"
template_id="$(terraform -chdir="$tf_dir" output -raw parent_launch_template_id)"
template_version="$(terraform -chdir="$tf_dir" output -raw parent_launch_template_version)"
runtime_hours="$(terraform -chdir="$tf_dir" output -raw parent_max_runtime_hours)"
instance_type="$(terraform -chdir="$tf_dir" output -raw parent_instance_type)"
parent_name="$(terraform -chdir="$tf_dir" output -raw parent_instance_name)"
content_bucket="$(terraform -chdir="$tf_dir" output -raw content_bucket)"
termination_workflow="$(terraform -chdir="$tf_dir" output -raw termination_workflow_arn)"
if [[ ! "$template_version" =~ ^[1-9][0-9]*$ || ! "$runtime_hours" =~ ^[1-4]$ ]]; then
  echo "Terraform must provide a numeric template version and a runtime of 1–4 hours." >&2
  exit 2
fi

existing="$(aws ec2 describe-instances --region "$region" \
  --filters "Name=tag:Name,Values=$parent_name" \
            'Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down' \
  --query 'Reservations[].Instances[].InstanceId' --output text)"
if [[ -n "$existing" && "$existing" != "None" ]]; then
  echo "A staging parent already exists ($existing); terminate it before starting another." >&2
  exit 2
fi

if [[ "$mode" == "--dry-run" ]]; then
  echo "Would launch one $instance_type Nitro parent from $template_id version $template_version in $region."
  echo "The template installs a termination timer for $runtime_hours hour(s) after boot."
  echo "An AWS-managed workflow owns both launch and independent cleanup."
  echo "The --start mode reserves the month's single session before launch."
  echo "No AWS resources were started. Use --start only after reviewing the current cost plan."
  exit 0
fi

# Reserve one session per calendar month. If launch fails after reservation,
# fail closed for the rest of this month rather than permit an unbounded retry.
month="$(date -u +%Y-%m)"
aws s3api put-object --region "$region" --bucket "$content_bucket" \
  --key "scb/runtime-allowance/$month.json" --body /dev/null \
  --content-type application/json --if-none-match '*' >/dev/null

# The AWS-managed workflow alone launches EC2 and then waits before cleanup.
# A suspended/local CLI cannot launch a parent after the backstop has expired.
# A cryptographic client token binds cleanup even when a launch response is lost.
session_token="$(python3 -c 'import secrets; print("scb-" + secrets.token_hex(24))')"
execution_name="scb-$month-${session_token#scb-}"
execution_input="$(python3 -c 'import json,sys; print(json.dumps({"session_token":sys.argv[1]}))' "$session_token")"
execution_arn="$(aws stepfunctions start-execution --region "$region" \
  --state-machine-arn "$termination_workflow" --name "$execution_name" \
  --input "$execution_input" --query executionArn --output text)"
execution_status="$(aws stepfunctions describe-execution --region "$region" \
  --execution-arn "$execution_arn" --query status --output text)"
if [[ "$execution_status" != "RUNNING" ]]; then
  echo "Staging workflow is not running; inspect execution $execution_arn before taking further action." >&2
  exit 1
fi

# Never stop this workflow on local failure/interruption: AWS might already
# have accepted its launch. The workflow's launch configuration is Terraform's
# fixed numeric template version; the request input cannot override it.
echo "Started bounded staging workflow in $region: $execution_arn"
echo "Session client token: $session_token"
echo "AWS will launch at most one $instance_type parent and request termination after its $runtime_hours hour(s) window."
echo "Allow launch/cleanup overhead; inspect the workflow and parent timer after bootstrap."
