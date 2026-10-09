output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS account used by this plan."
}

output "region" {
  value       = var.aws_region
  description = "AWS region used by this plan."
}

output "ami_id" {
  value       = nonsensitive(data.aws_ssm_parameter.al2023_ami.value)
  description = "Amazon Linux 2023 AMI resolved from the official SSM parameter."
}

output "parent_instance_type" {
  value       = aws_launch_template.parent.instance_type
  description = "Nitro-capable EC2 type used by the on-demand parent launch template."
}

output "parent_launch_template_id" {
  value       = aws_launch_template.parent.id
  description = "Launch template for an explicitly started bounded Nitro parent session."
}

output "parent_launch_template_version" {
  value       = aws_launch_template.parent.latest_version
  description = "Numeric launch template version recorded by the reviewed Terraform apply."
}

output "parent_max_runtime_hours" {
  value       = var.max_runtime_hours
  description = "Boot-relative termination timer configured in the parent launch template."
}

output "parent_instance_name" {
  value       = "${local.name}-nitro-parent"
  description = "Unique tag queried by the bounded session start/termination scripts."
}

output "content_bucket" {
  value       = aws_s3_bucket.content.bucket
  description = "Private, versioned challenge content bucket."
}

output "reveals_bucket" {
  value       = aws_s3_bucket.reveals.bucket
  description = "Private, versioned encrypted reveal bucket."
}

output "master_secret_key_arn" {
  value       = aws_kms_key.master_secret.arn
  description = "KMS key whose decrypt permission requires an attestation with the configured PCR0."
}

output "pcr0_policy_value" {
  value       = local.eif_pcr0
  description = "PCR0 in the key policy; the default placeholder denies enclave decryption."
}
