# terraform-aws-account-hardening

This Terraform module provides **baseline AWS account hardening** aligned with **FedRAMP Moderate** and **NIST 800-53** controls.

It includes:
- Strong password policies
- Full audit logging (CloudTrail + AWS Config)
- Threat detection (GuardDuty, Security Hub)
- Root account usage monitoring
- IAM Access Analyzer
- MFA enforcement
- EBS and S3 default encryption

---

## Features

| Feature                                | Enabled by Default | FedRAMP / NIST Controls |
|----------------------------------------|---------------------|-------------------------|
| Strong IAM Password Policy             | ✅                  | AC-2, IA-5, IA-5(1)     |
| CloudTrail Multi-Region Logging        | ✅                  | AU-2, AU-6, AU-12       |
| CloudTrail Log Encryption              | ✅                  | SC-12, SC-13, SC-28     |
| AWS Config Recorder                    | ✅                  | CM-2, CM-6, CM-8        |
| GuardDuty Threat Detection             | ✅                  | SI-4, IR-5              |
| AWS Security Hub CIS Benchmark         | ✅                  | CA-7, CA-2, RA-5        |
| IAM Access Analyzer                    | ✅                  | AC-6, AC-17             |
| Root Account Usage Monitoring (SNS)    | ✅                  | AC-2(9), SI-4(4)        |
| MFA Enforcement Policy                 | ✅                  | IA-2, IA-2(1), IA-2(12) |
| EBS Default Encryption                 | ✅                  | SC-12, SC-13, SC-28     |
| S3 Default Encryption for CloudTrail   | ✅                  | SC-12, SC-13, SC-28     |

---

## Usage

```hcl
## Usage

```hcl
module "account_hardening" {
  source = "git::https://github.com/jessedye/terraform.git//modules/account-hardening?ref=main"

  cloudtrail_name        = "organization-cloudtrail"
  cloudtrail_bucket_name = "org-cloudtrail-logs-bucket"

  # Optional feature flags (default true)
  enable_password_policy           = true
  enable_cloudtrail                = true
  enable_config_recorder           = true
  enable_guardduty                 = true
  enable_securityhub               = true
  enable_access_analyzer           = true
  enable_mfa_enforcement           = true
  enable_root_account_monitoring   = true
  enable_ebs_default_encryption    = true
  enable_s3_bucket_encryption      = true
}

```


## Inputs

| Variable                         | Type    | Default | Description |
|----------------------------------|---------|---------|-------------|
| cloudtrail_name                  | string  | n/a     | Name for the CloudTrail trail. |
| cloudtrail_bucket_name           | string  | n/a     | Name for the S3 bucket to store CloudTrail logs. |
| enable_password_policy           | bool    | true    | Enforce strong IAM password policy. |
| enable_cloudtrail                | bool    | true    | Enable CloudTrail. |
| enable_config_recorder           | bool    | true    | Enable AWS Config recorder. |
| enable_guardduty                 | bool    | true    | Enable GuardDuty detector. |
| enable_securityhub               | bool    | true    | Enable AWS Security Hub and subscribe to benchmarks. |
| enable_access_analyzer           | bool    | true    | Enable IAM Access Analyzer. |
| enable_mfa_enforcement           | bool    | true    | Attach IAM policy to enforce MFA usage. |
| enable_root_account_monitoring   | bool    | true    | Create CloudWatch alarms for root account usage. |
| enable_ebs_default_encryption    | bool    | true    | Enable default encryption for EBS volumes. |
| enable_s3_bucket_encryption      | bool    | true    | Enforce server-side encryption on CloudTrail S3 bucket. |

---

## Outputs

| Output Name                    | Description |
|---------------------------------|-------------|
| cloudtrail_name                 | Name of the created CloudTrail. |
| cloudtrail_bucket_name          | Name of the CloudTrail log bucket. |
| security_alerts_sns_topic_arn   | ARN of SNS topic for root account usage alerts. |
| guardduty_detector_id           | ID of the GuardDuty detector. |
| securityhub_account_id          | ID of the Security Hub account subscription. |
| access_analyzer_name            | Name of the Access Analyzer created. |
| mfa_enforcement_policy_arn      | ARN of the IAM policy that enforces MFA usage. |

---

## Compliance Mapping

| Feature                                | FedRAMP Moderate / NIST 800-53 Mapping |
|----------------------------------------|----------------------------------------|
| Strong Password Policy                 | IA-5 (Authentication Management), AC-2 (Account Management) |
| CloudTrail Logging + Encryption        | AU-2 (Audit Events), AU-6 (Audit Review), SC-12 (Cryptographic Key Establishment) |
| AWS Config Resource Tracking           | CM-2 (Baseline Configuration), CM-6 (Configuration Settings) |
| GuardDuty Threat Detection             | SI-4 (System Monitoring), IR-5 (Incident Monitoring) |
| AWS Security Hub (CIS Benchmark)        | CA-7 (Continuous Monitoring), RA-5 (Vulnerability Scanning) |
| Root Account Usage Alarm               | AC-2(9) (Privileged Account Monitoring) |
| IAM Access Analyzer                    | AC-6 (Least Privilege), AC-17 (Remote Access Monitoring) |
| MFA Enforcement                        | IA-2 (Identification and Authentication) |
| EBS/S3 Encryption                      | SC-12 (Cryptographic Operations), SC-13 (Cryptographic Protection) |

---

## Notes

- **This module does not create IAM users.** You must manually assign the `require_mfa` policy to users/groups as needed.
- **Root account protections** include alerts but do not physically block root — AWS recommends root login only for account break-glass scenarios.
- **Security Hub standards subscribed:**
  - CIS AWS Foundations Benchmark 1.2.0
  - AWS Foundational Security Best Practices v1.0.0

---

## Future Enhancements (Roadmap)

- Macie integration for sensitive S3 data discovery
- Inspector integration for vulnerability scanning
- AWS Config Conformance Packs (for strict FedRAMP High)
- Audit Manager for compliance reporting
