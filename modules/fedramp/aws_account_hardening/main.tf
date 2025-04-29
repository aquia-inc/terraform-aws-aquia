#########################################
# Password Policy
#########################################

resource "aws_iam_account_password_policy" "strict" {
  count                          = var.enable_password_policy ? 1 : 0
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
  hard_expiry                    = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

#########################################
# CloudTrail and S3 Bucket
#########################################

resource "aws_s3_bucket" "cloudtrail_bucket" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = var.cloudtrail_bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudtrail" "default" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = var.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket[0].bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail_bucket[0].id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy[0].json
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.cloudtrail_bucket[0].arn]
  }

  statement {
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.cloudtrail_bucket[0].arn}/AWSLogs/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

#########################################
# AWS Config
#########################################

resource "aws_iam_role" "config_role" {
  count = var.enable_config_recorder ? 1 : 0

  name = "aws_config_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "config.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "config_role_policy" {
  count = var.enable_config_recorder ? 1 : 0

  role = aws_iam_role.config_role[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "config:Put*",
          "config:Get*",
          "config:Describe*",
          "config:List*"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_config_configuration_recorder" "default" {
  count = var.enable_config_recorder ? 1 : 0

  name     = "default"
  role_arn = aws_iam_role.config_role[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

#########################################
# GuardDuty
#########################################

resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
}

#########################################
# Security Hub
#########################################

resource "aws_securityhub_account" "main" {
  count = var.enable_securityhub ? 1 : 0
}

resource "aws_securityhub_standards_subscription" "cis" {
  count         = var.enable_securityhub ? 1 : 0
  standards_arn = "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.2.0"
}

resource "aws_securityhub_standards_subscription" "aws_best_practices" {
  count         = var.enable_securityhub ? 1 : 0
  standards_arn = "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"
}

#########################################
# IAM Access Analyzer
#########################################

resource "aws_accessanalyzer_analyzer" "account" {
  count         = var.enable_access_analyzer ? 1 : 0
  analyzer_name = "account-access-analyzer"
  type          = "ACCOUNT"
}

#########################################
# MFA Enforcement
#########################################

resource "aws_iam_policy" "require_mfa" {
  count       = var.enable_mfa_enforcement ? 1 : 0
  name        = "require-mfa"
  description = "Deny all AWS actions unless MFA is present"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid : "BlockAllExceptWithMFA",
        Effect : "Deny",
        Action : "*",
        Resource : "*",
        Condition : {
          "BoolIfExists" : {
            "aws:MultiFactorAuthPresent" : "false"
          }
        }
      }
    ]
  })
}

#########################################
# Root Account Monitoring
#########################################

resource "aws_sns_topic" "security_alerts" {
  count = var.enable_root_account_monitoring ? 1 : 0
  name  = "security-alerts"
}

resource "aws_cloudwatch_event_rule" "root_usage" {
  count       = var.enable_root_account_monitoring ? 1 : 0
  name        = "RootAccountUsage"
  description = "Alarm when root account is used"
  event_pattern = jsonencode({
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "userIdentity" : {
        "type" : ["Root"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "root_usage_target" {
  count     = var.enable_root_account_monitoring ? 1 : 0
  rule      = aws_cloudwatch_event_rule.root_usage[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts[0].arn
}

#########################################
# EBS Default Encryption
#########################################

resource "aws_ebs_encryption_by_default" "default" {
  count   = var.enable_ebs_default_encryption ? 1 : 0
  enabled = true
}

#########################################
# S3 Bucket Encryption
#########################################

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_bucket" {
  count  = var.enable_s3_bucket_encryption && var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail_bucket[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
