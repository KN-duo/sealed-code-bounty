data "aws_caller_identity" "current" {}

data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

locals {
  name = "${var.project}-${var.environment}"

  common_tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "Terraform"
    CostCenter  = var.project
  }

  eif_pcr0 = var.enclave_pcr0_sha384
}

resource "aws_security_group" "parent" {
  name_prefix = "${local.name}-parent-"
  description = "No inbound access; parent administration uses SSM Session Manager."
  vpc_id      = data.aws_vpc.default.id

  # No ingress rules. Outbound HTTPS is required for SSM, KMS, package
  # installation, and the configured S3 origin. The Nitro guest itself has no
  # network interface and reaches approved services only through vsock.
  egress {
    description = "HTTPS egress for AWS APIs and package repositories"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS resolution in the selected VPC"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [data.aws_vpc.default.cidr_block]
  }

  egress {
    description = "DNS resolution in the selected VPC"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.default.cidr_block]
  }

  tags = merge(local.common_tags, { Name = "${local.name}-parent" })
}

resource "aws_iam_role" "parent" {
  name = "${local.name}-parent"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.parent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "parent" {
  name = "${local.name}-parent"
  role = aws_iam_role.parent.name
  tags = local.common_tags
}

resource "aws_s3_bucket" "content" {
  bucket_prefix = "${local.name}-content-"
  force_destroy = false
  tags          = merge(local.common_tags, { DataClass = "challenge-content" })
}

resource "aws_s3_bucket" "reveals" {
  bucket_prefix = "${local.name}-reveals-"
  force_destroy = false
  tags          = merge(local.common_tags, { DataClass = "encrypted-reveals" })
}

resource "aws_s3_bucket_public_access_block" "content" {
  bucket                  = aws_s3_bucket.content.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "reveals" {
  bucket                  = aws_s3_bucket.reveals.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "content_tls_only" {
  bucket = aws_s3_bucket.content.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.content.arn, "${aws_s3_bucket.content.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_policy" "reveals_tls_only" {
  bucket = aws_s3_bucket.reveals.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.reveals.arn, "${aws_s3_bucket.reveals.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_versioning" "content" {
  bucket = aws_s3_bucket.content.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "reveals" {
  bucket = aws_s3_bucket.reveals.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "content" {
  bucket = aws_s3_bucket.content.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reveals" {
  bucket = aws_s3_bucket.reveals.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "content" {
  bucket = aws_s3_bucket.content.id
  rule {
    id     = "expire-unregistered-objects"
    status = "Enabled"
    filter {
      tag {
        key   = "lifecycle"
        value = "orphan"
      }
    }
    expiration { days = 30 }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reveals" {
  bucket = aws_s3_bucket.reveals.id
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_kms_key" "master_secret" {
  description             = "${local.name} master secret; decrypt requires the approved Nitro EIF PCR0."
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.master_secret.json
  tags                    = merge(local.common_tags, { DataClass = "master-secret" })
}

data "aws_iam_policy_document" "master_secret" {
  statement {
    sid    = "AccountKeyAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AttestedEnclaveDecryptOnly"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.parent.arn]
    }
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEqualsIgnoreCase"
      variable = "kms:RecipientAttestation:ImageSha384"
      values   = [local.eif_pcr0]
    }
  }
}

resource "aws_iam_role_policy" "parent_runtime" {
  name = "${local.name}-runtime"
  role = aws_iam_role.parent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = [
          "${aws_s3_bucket.content.arn}/scb/manifests/*",
          "${aws_s3_bucket.content.arn}/scb/envs/*",
          "${aws_s3_bucket.content.arn}/scb/submissions/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.content.arn}/scb/submissions/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.reveals.arn}/scb/reveals/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.master_secret.arn
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:ImageSha384" = local.eif_pcr0
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.parent.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "parent" {
  name              = "/${var.project}/${var.environment}/parent"
  retention_in_days = 14
  tags              = local.common_tags
}

data "aws_subnet" "selected" {
  id = sort(data.aws_subnets.default.ids)[0]
}

resource "aws_launch_template" "parent" {
  name_prefix   = "${local.name}-nitro-parent-"
  image_id      = data.aws_ssm_parameter.al2023_ami.value
  instance_type = "m6i.xlarge"

  iam_instance_profile { name = aws_iam_instance_profile.parent.name }
  network_interfaces {
    device_index                = 0
    subnet_id                   = data.aws_subnet.selected.id
    associate_public_ip_address = true
    security_groups             = [aws_security_group.parent.id]
  }
  user_data = base64encode(templatefile("${path.module}/parent-user-data.sh.tftpl", {
    max_runtime_hours = var.max_runtime_hours
  }))

  enclave_options { enabled = true }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = "gp3"
      volume_size           = var.root_volume_gib
      encrypted             = true
      delete_on_termination = true
    }
  }

  instance_initiated_shutdown_behavior = "terminate"

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.common_tags, { Name = "${local.name}-nitro-parent" })
  }
  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.common_tags, { Name = "${local.name}-nitro-parent-root" })
  }

  tags = merge(local.common_tags, { Name = "${local.name}-nitro-launch-template" })
}

resource "aws_budgets_budget" "staging" {
  provider     = aws.global
  name         = "${local.name}-monthly-2usd"
  budget_type  = "COST"
  limit_amount = "2"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = [format("user:Project$%s", var.project)]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 40
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}
