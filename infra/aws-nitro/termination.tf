# Standard Step Functions owns launch and cleanup without a running server.
# The caller never launches EC2 after an independently expiring cleanup timer.
resource "aws_iam_role" "termination" {
  name = "${local.name}-termination"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals = {
          "aws:SourceArn" = "arn:aws:states:${var.aws_region}:${data.aws_caller_identity.current.account_id}:stateMachine:${local.name}-termination"
        }
      }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "termination" {
  name = "${local.name}-termination"
  role = aws_iam_role.termination.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "FixedTemplateResourcesOnly"
        Effect = "Allow"
        Action = "ec2:RunInstances"
        Resource = [
          aws_launch_template.parent.arn,
          "arn:aws:ec2:${var.aws_region}::image/${data.aws_ssm_parameter.al2023_ami.value}",
          data.aws_subnet.selected.arn,
          aws_security_group.parent.arn,
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:network-interface/*",
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:volume/*",
        ]
        Condition = {
          ArnEquals = { "ec2:LaunchTemplate" = aws_launch_template.parent.arn }
          Bool      = { "ec2:IsLaunchTemplateResource" = "true" }
          StringEqualsIfExists = {
            "ec2:InstanceType"           = aws_launch_template.parent.instance_type
            "aws:RequestTag/Project"     = var.project
            "aws:RequestTag/Environment" = var.environment
          }
        }
      },
      {
        Sid      = "FixedTaggedParentOnly"
        Effect   = "Allow"
        Action   = "ec2:RunInstances"
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"
        Condition = {
          ArnEquals = { "ec2:LaunchTemplate" = aws_launch_template.parent.arn }
          Bool      = { "ec2:IsLaunchTemplateResource" = "true" }
          StringEquals = {
            "ec2:InstanceType"           = aws_launch_template.parent.instance_type
            "aws:RequestTag/Project"     = var.project
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Name"        = "${local.name}-nitro-parent"
          }
        }
      },
      {
        Effect = "Allow"
        Action = "ec2:CreateTags"
        Resource = [
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:volume/*",
        ]
        Condition = {
          StringEquals = {
            "ec2:CreateAction"           = "RunInstances"
            "aws:RequestTag/Project"     = var.project
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Name"        = ["${local.name}-nitro-parent", "${local.name}-nitro-parent-root"]
          }
          "ForAllValues:StringEquals" = { "aws:TagKeys" = concat(keys(local.common_tags), ["Name"]) }
        }
      },
      {
        Effect    = "Allow"
        Action    = "iam:PassRole"
        Resource  = aws_iam_role.parent.arn
        Condition = { StringEquals = { "iam:PassedToService" = "ec2.amazonaws.com" } }
      },
      {
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.content.arn
        Condition = { StringEquals = { "s3:prefix" = "scb/runtime-allowance/disabled" } }
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:TerminateInstances"]
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Project"     = var.project
            "ec2:ResourceTag/Environment" = var.environment
            "ec2:ResourceTag/Name"        = "${local.name}-nitro-parent"
          }
        }
      }
    ]
  })
}

resource "aws_sfn_state_machine" "termination" {
  name       = "${local.name}-termination"
  role_arn   = aws_iam_role.termination.arn
  type       = "STANDARD"
  depends_on = [aws_iam_role_policy.termination]
  tags       = local.common_tags

  definition = jsonencode({
    Comment = "Bound one explicitly launched Nitro session independently of its parent."
    StartAt = "ValidateSession"
    # Launch can take up to 60s; allow finite additional cleanup/retry time.
    # The advertised runtime is a session window, not an exact billing cutoff.
    TimeoutSeconds = var.max_runtime_hours * 3600 + 900
    States = {
      ValidateSession = {
        Type = "Choice"
        Choices = [{
          And = [
            { Variable = "$.session_token", IsPresent = true },
            { Variable = "$.session_token", IsString = true },
            { Variable = "$.session_token", StringMatches = "scb-*" },
            # EC2 filter values treat '*' and '?' as wildcards. Never let an
            # externally started workflow broaden its client-token cleanup.
            { Not = { Variable = "$.session_token", StringMatches = "*\\**" } },
            { Not = { Variable = "$.session_token", StringMatches = "*?*" } },
          ]
          Next = "CheckLaunchEnabled"
        }]
        Default = "InvalidSession"
      }
      InvalidSession = { Type = "Fail", Error = "InvalidSessionIdentity" }
      CheckLaunchEnabled = {
        Type           = "Task"
        TimeoutSeconds = 20
        Resource       = "arn:aws:states:::aws-sdk:s3:listObjectsV2"
        Parameters = {
          Bucket  = aws_s3_bucket.content.bucket
          Prefix  = "scb/runtime-allowance/disabled"
          MaxKeys = 1
        }
        ResultSelector = { "count.$" = "$.KeyCount" }
        ResultPath     = "$.disabled"
        Next           = "LaunchEnabled"
      }
      LaunchEnabled = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.disabled.count"
          NumericEquals = 0
          Next          = "LaunchParent"
        }]
        Default = "LaunchDisabled"
      }
      LaunchDisabled = { Type = "Fail", Error = "StagingTeardownInProgress" }
      LaunchParent = {
        Type           = "Task"
        TimeoutSeconds = 60
        Resource       = "arn:aws:states:::aws-sdk:ec2:runInstances"
        Parameters = {
          LaunchTemplate = {
            LaunchTemplateId = aws_launch_template.parent.id
            Version          = tostring(aws_launch_template.parent.latest_version)
          }
          MinCount        = 1
          MaxCount        = 1
          "ClientToken.$" = "$.session_token"
        }
        # Discard the response: cleanup uses EC2's immutable client token even
        # if the launch succeeds but the API response is lost or times out.
        ResultPath = null
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.launch_error"
          Next        = "WaitForDeadline"
        }]
        Next = "WaitForDeadline"
      }
      WaitForDeadline = {
        Type    = "Wait"
        Seconds = var.max_runtime_hours * 3600
        Next    = "FindSessionParents"
      }
      FindSessionParents = {
        Type           = "Task"
        TimeoutSeconds = 20
        Resource       = "arn:aws:states:::aws-sdk:ec2:describeInstances"
        Parameters = {
          Filters = [
            { Name = "tag:Project", Values = [var.project] },
            { Name = "tag:Environment", Values = [var.environment] },
            { Name = "tag:Name", Values = ["${local.name}-nitro-parent"] },
            { Name = "client-token", "Values.$" = "States.Array($.session_token)" },
            { Name = "instance-state-name", Values = ["pending", "running", "stopping", "stopped"] },
          ]
        }
        ResultSelector = { "instance_ids.$" = "$.Reservations[*].Instances[*].InstanceId" }
        ResultPath     = "$.parents"
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 5
          BackoffRate     = 2
          MaxAttempts     = 5
        }]
        Next = "AnyParentsRemain"
      }
      AnyParentsRemain = {
        Type = "Choice"
        Choices = [{
          Variable  = "$.parents.instance_ids[0]"
          IsPresent = true
          Next      = "TerminateSessionParents"
        }]
        Default = "AlreadyTerminated"
      }
      AlreadyTerminated = { Type = "Succeed" }
      TerminateSessionParents = {
        Type           = "Task"
        TimeoutSeconds = 20
        Resource       = "arn:aws:states:::aws-sdk:ec2:terminateInstances"
        Parameters     = { "InstanceIds.$" = "$.parents.instance_ids" }
        Retry = [{
          ErrorEquals     = ["States.ALL"]
          IntervalSeconds = 5
          BackoffRate     = 2
          MaxAttempts     = 5
        }]
        End = true
      }
    }
  })
}
