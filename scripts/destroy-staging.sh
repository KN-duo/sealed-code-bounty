#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || "${1:-}" != "--confirm" ]]; then
  echo "Usage: $0 --confirm" >&2
  echo "Terminates session parents and waits, then Terraform asks to destroy the foundation." >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tf_dir="$repo_root/infra/aws-nitro"

region="$(terraform -chdir="$tf_dir" output -raw region)"
workflow="$(terraform -chdir="$tf_dir" output -raw termination_workflow_arn)"
content_bucket="$(terraform -chdir="$tf_dir" output -raw content_bucket)"

# Durable shared drain marker: workflows started by another PC after teardown
# begins must fail before launch. Leave this marker in place if any step fails.
aws s3api put-object --region "$region" --bucket "$content_bucket" \
  --key scb/runtime-allowance/disabled --body /dev/null >/dev/null

# Stop AWS-owned launchers before enumerating compute, so a suspended local CLI
# cannot launch a new parent after the final instance scan. StopExecution does
# not retract an already accepted RunInstances API request; drain below.
running="$(aws stepfunctions list-executions --region "$region" \
  --state-machine-arn "$workflow" --status-filter RUNNING \
  --query 'executions[].executionArn' --output text)"
if [[ -n "$running" && "$running" != "None" ]]; then
  read -r -a executions <<<"${running//$'\n'/ }"
  for execution in "${executions[@]}"; do
    aws stepfunctions stop-execution --region "$region" \
      --execution-arn "$execution" --cause 'Staging launch disabled; draining parents before foundation teardown' >/dev/null
  done
fi

# Preserve IAM/networking/storage on ANY failed observation or termination.
# Eight finite scans span more than the workflow's 60s launch task timeout and
# reduce the chance of missing an in-flight EC2 launch under eventual consistency.
# This is a conservative drain, not a guarantee during an AWS service outage.
for attempt in {1..8}; do
  bash "$repo_root/scripts/stop-staging.sh"
  if [[ "$attempt" -lt 8 ]]; then
    sleep 15
  fi
done
terraform -chdir="$tf_dir" destroy -var-file=staging.tfvars
