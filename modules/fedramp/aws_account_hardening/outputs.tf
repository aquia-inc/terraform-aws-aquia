# CloudTrail Outputs
output "cloudtrail_name" {
  description = "The name of the created CloudTrail."
  value       = var.enable_cloudtrail ? aws_cloudtrail.default[0].name : null
}

output "cloudtrail_bucket_name" {
  description = "The name of the S3 bucket storing CloudTrail logs."
  value       = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail_bucket[0].bucket : null
}

# SNS Topic for Root Usage Monitoring
output "security_alerts_sns_topic_arn" {
  description = "The ARN of the SNS topic for root account usage alerts."
  value       = var.enable_root_account_monitoring ? aws_sns_topic.security_alerts[0].arn : null
}

# GuardDuty Detector
output "guardduty_detector_id" {
  description = "The ID of the GuardDuty detector."
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : null
}

# Security Hub Account ID
output "securityhub_account_id" {
  description = "The ID of the Security Hub account subscription."
  value       = var.enable_securityhub ? aws_securityhub_account.main[0].id : null
}

# Access Analyzer Name
output "access_analyzer_name" {
  description = "The name of the Access Analyzer created."
  value       = var.enable_access_analyzer ? aws_accessanalyzer_analyzer.account[0].analyzer_name : null
}

# IAM Policy for MFA Enforcement
output "mfa_enforcement_policy_arn" {
  description = "The ARN of the IAM policy that enforces MFA."
  value       = var.enable_mfa_enforcement ? aws_iam_policy.require_mfa[0].arn : null
}
