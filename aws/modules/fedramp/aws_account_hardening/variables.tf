# Required Variables
variable "cloudtrail_name" {
  description = "Name for the CloudTrail trail"
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  type        = string
}

# Optional Toggles (Feature Flags)

variable "enable_password_policy" {
  description = "Enable strong IAM account password policy"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail for audit logging"
  type        = bool
  default     = true
}

variable "enable_config_recorder" {
  description = "Enable AWS Config configuration recorder"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty threat detection"
  type        = bool
  default     = true
}

variable "enable_securityhub" {
  description = "Enable Security Hub and subscribe to standards"
  type        = bool
  default     = true
}

variable "enable_access_analyzer" {
  description = "Enable IAM Access Analyzer"
  type        = bool
  default     = true
}

variable "enable_mfa_enforcement" {
  description = "Enable IAM policy to require MFA for API actions"
  type        = bool
  default     = true
}

variable "enable_root_account_monitoring" {
  description = "Enable CloudWatch alarm for root account usage"
  type        = bool
  default     = true
}

variable "enable_ebs_default_encryption" {
  description = "Enable default encryption for EBS volumes"
  type        = bool
  default     = true
}

variable "enable_s3_bucket_encryption" {
  description = "Enforce default encryption on the CloudTrail S3 bucket"
  type        = bool
  default     = true
}
