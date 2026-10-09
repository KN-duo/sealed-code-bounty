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

instance_id="$(aws ec2 run-instances --region "$region" \
  --launch-template "LaunchTemplateId=$template_id,Version=$template_version" \
  --min-count 1 --max-count 1 \
  --query 'Instances[0].InstanceId' --output text)"
echo "Started bounded staging parent $instance_id in $region."
echo "It is configured to terminate $runtime_hours hour(s) after boot; verify the timer after bootstrap."
