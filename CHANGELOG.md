# Changelog

All notable changes to SpecterKeys are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Fixed
- Moved sources into the documented `src/`, `tests/`, `infra/`, `docs/`, and
  `.github/` layout so CI, the test path shim, and the README commands work
- Rewrote the auto-responder Lambda so it disables keys for the stack-level
  alarm (whose name carries no key ID); honey users are now enumerated with
  pagination instead of a single unpaginated `list_users` call
- `--revoke` now deletes the per-key metric filter, so filters no longer leak
  (CloudWatch caps a log group at 100 metric filters)
- `deploy` rolls back the honey IAM user if any wiring step fails, so a live,
  unmonitored credential is never left behind; metric-filter failures are now
  fatal rather than logged-and-ignored
- Broke the `AlertTopic` ↔ auto-responder Lambda circular dependency that
  would have blocked stack creation

### Added
- Real AWS account ID and deploy region embedded in planted files; file
  timestamps are backdated so a drop looks organic
- `--region` / `--profile` flags, `--json` output for `--list`/`--status`,
  non-zero exit on `ALARM`, and a guarded revoke (`--key-id` / `--all --yes`)
- Metric filters now match `accessKeyId` as well as `userName`
- `.flake8` config and `requirements-dev.txt`

### Changed
- Corrected the detection-latency claim from "< 60 seconds" to a realistic
  CloudTrail-bound few-minute window
- Removed the unused `specterkeys/registry` secret; the Lambda now marks the
  per-key registry entry as `TRIGGERED`
- SNS subscriptions are no longer duplicated on every deploy, and the
  placeholder alert email is skipped

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
