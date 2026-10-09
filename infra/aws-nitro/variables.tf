variable "aws_region" {
  description = "AWS region for the bounded Nitro staging environment."
  type        = string
  default     = "eu-north-1"
}

variable "project" {
  description = "Project name used in resource names and cost allocation tags."
  type        = string
  default     = "sealed-code-bounty"
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "staging"
}

variable "enclave_pcr0_sha384" {
  description = "Approved EIF PCR0 as 96 lowercase hex chars. The placeholder denies KMS decrypt until replaced with a reviewed measurement."
  type        = string
  default     = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.enclave_pcr0_sha384))
    error_message = "enclave_pcr0_sha384 must be exactly 96 lowercase hexadecimal characters."
  }
}

variable "budget_alert_email" {
  description = "Email address for the $1 monthly actual-cost alert."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_alert_email))
    error_message = "budget_alert_email must be a valid email address."
  }
}

variable "max_runtime_hours" {
  description = "Maximum instance lifetime from boot; termination deletes the ephemeral root disk."
  type        = number
  default     = 1

  validation {
    condition     = var.max_runtime_hours >= 1 && var.max_runtime_hours <= 4
    error_message = "max_runtime_hours must be between 1 and 4 hours."
  }
}

variable "root_volume_gib" {
  description = "Encrypted gp3 root volume size, deleted when the instance is terminated."
  type        = number
  default     = 40

  validation {
    condition     = var.root_volume_gib >= 30 && var.root_volume_gib <= 100
    error_message = "root_volume_gib must be between 30 and 100 GiB."
  }
}
