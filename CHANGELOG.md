# Changelog

All notable changes to SpecterKeys are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2025-06-18

### Added
- Initial release of SpecterKeys deception system
- Zero-permission IAM honey user creation with `DenyAll` inline policy
- Four credential file renderers: CSV, INI, `.env`, Terraform tfvars
- CloudFormation stack: CloudTrail → CloudWatch Logs → Metric Filter → Alarm → SNS
- Lambda auto-responder: disables triggered key and tags IAM user with incident timestamp
- Secrets Manager registry for honey key lifecycle management
- CLI: `--deploy`, `--list`, `--status`, `--revoke`
- GitHub Actions CI: lint, bandit security scan, CloudFormation validation
- Incident report issue template
- Full unit test suite with mock AWS clients
