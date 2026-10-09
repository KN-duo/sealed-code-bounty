#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || "${1:-}" != "--confirm" ]]; then
  echo "Usage: $0 --confirm" >&2
  echo "Terminates session parents and waits, then Terraform asks to destroy the foundation." >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tf_dir="$repo_root/infra/aws-nitro"

# Session parents are deliberately outside Terraform state. Never remove their
# IAM, networking, or object storage while they can still be running.
bash "$repo_root/scripts/stop-staging.sh"
terraform -chdir="$tf_dir" destroy -var-file=staging.tfvars
