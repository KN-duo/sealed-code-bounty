#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tf_dir="$repo_root/infra/aws-nitro"

if [[ ! -f "$tf_dir/terraform.tfstate" ]]; then
  echo "No local Terraform state found at $tf_dir/terraform.tfstate" >&2
  exit 2
fi

region="$(terraform -chdir="$tf_dir" output -raw region)"
parent_name="$(terraform -chdir="$tf_dir" output -raw parent_instance_name)"
instance_ids="$(aws ec2 describe-instances --region "$region" \
  --filters "Name=tag:Name,Values=$parent_name" \
            'Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down' \
  --query 'Reservations[].Instances[].InstanceId' --output text)"
if [[ -z "$instance_ids" || "$instance_ids" == "None" ]]; then
  echo "No staging parent is currently active."
  exit 0
fi

echo "Terminating ephemeral parent(s) $instance_ids; attached root volumes will be deleted." >&2
read -r -a instance_id_array <<<"${instance_ids//$'\n'/ }"
for instance_id in "${instance_id_array[@]}"; do
  if [[ ! "$instance_id" =~ ^i-[0-9a-f]+$ ]]; then
    echo "AWS returned an invalid instance identifier; refusing termination." >&2
    exit 2
  fi
done
aws ec2 terminate-instances --instance-ids "${instance_id_array[@]}" --region "$region"
echo "Waiting for parent termination before releasing the foundation." >&2
aws ec2 wait instance-terminated --instance-ids "${instance_id_array[@]}" --region "$region"
