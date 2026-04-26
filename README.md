<div align="center">

**Insider Threat Detection via AWS Honey Tokens**

[![CI](https://github.com/your-org/specterkeys/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/specterkeys/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-CloudTrail%20%7C%20CloudWatch%20%7C%20SNS-orange.svg)](https://aws.amazon.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: Restricted](https://img.shields.io/badge/Security-Restricted-red.svg)](#operational-security)

> **Zero false positives. Any trigger = confirmed malicious intent.**

</div>

---

## What is SpecterKeys?

SpecterKeys plants fake AWS Access Keys — called **honey tokens** — into tempting locations across your environment (shared S3 buckets, internal wikis, GitHub repos, `.env` files). The keys are cryptographically valid but backed by a `DenyAll` IAM policy, making them completely powerless.

The moment any actor attempts to use one, CloudTrail captures the event, a CloudWatch alarm fires in under 60 seconds, your security team is paged, and a Lambda function automatically disables the key and opens an incident trail.

Since these keys have no legitimate use, **every single alert is a true positive.**

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         SPECTERKEYS PIPELINE                         │
│                                                                      │
│  ┌─────────────────────┐   generates   ┌──────────────────────────┐ │
│  │  specterkeys.py      │ ──────────►  │  IAM Honey User          │ │
│  │  (--deploy)          │              │  svc-legacy-backup-XXXX  │ │
│  └─────────────────────┘              │  Policy: DenyAll (*)      │ │
│           │                           │  Keys: valid, powerless   │ │
│           │ plants                    └──────────────────────────┘ │
│           ▼                                                          │
│  ┌──────────────────────────────────────────┐                        │
│  │  ./honey_drop/                           │                        │
│  │  ├── prod_access_keys.csv                │  ◄── Upload to         │
│  │  ├── aws_credentials_backup.txt          │      tempting          │
│  │  ├── .env.production                     │      locations         │
│  │  └── terraform.tfvars                    │                        │
│  └──────────────────────────────────────────┘                        │
│                                                                      │
│  DETECTION CHAIN                                                     │
│                                                                      │
│  API Call ──► CloudTrail ──► CloudWatch Logs                         │
│                                    │                                 │
│                           Metric Filter                              │
│                    (userName = svc-legacy-backup-*)                  │
│                                    │                                 │
│                    Metric: HoneyKeyAPICall                           │
│                                    │                                 │
│                    CW Alarm (threshold ≥ 1, period 60s)             │
│                                    │                                 │
│                         SNS: SpecterKeysAlerts                       │
│                            ┌───────┴────────┐                        │
│                       Email alert     Lambda Responder               │
│                                        ├─ Disable key               │
│                                        ├─ Tag IAM user              │
│                                        └─ Log IR event              │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
specterkeys/
├── src/
│   └── specterkeys.py              # Main CLI — generate, deploy, revoke
├── infra/
│   └── cloudformation.yaml         # Full AWS infrastructure stack
├── tests/
│   └── test_specterkeys.py         # Unit tests (mocked AWS clients)
├── docs/
│   └── ir-playbook.md              # Incident response runbook
├── .github/
│   ├── workflows/
│   │   └── ci.yml                  # Lint, test, CFN validate
│   └── ISSUE_TEMPLATE/
│       └── incident_report.yml     # Structured IR ticket template
├── .gitignore
├── requirements.txt
├── CHANGELOG.md
├── CONTRIBUTING.md
└── SECURITY.md
```

---

## Prerequisites

- Python 3.12+
- AWS CLI configured with an IAM role that has permissions to:
  - `iam:CreateUser`, `iam:CreateAccessKey`, `iam:PutUserPolicy`, `iam:DeleteUser`
  - `cloudwatch:PutMetricAlarm`, `cloudwatch:DescribeAlarms`
  - `logs:PutMetricFilter`, `logs:DescribeMetricFilters`
  - `sns:CreateTopic`, `sns:Subscribe`
  - `secretsmanager:CreateSecret`, `secretsmanager:GetSecretValue`
  - `cloudformation:*` (for stack deployment)
- CloudTrail already enabled, streaming to a CloudWatch Log Group

---

## Quick Start

### 1. Deploy the AWS Infrastructure Stack

```bash
aws cloudformation deploy \
  --template-file infra/cloudformation.yaml \
  --stack-name SpecterKeysStack \
  --parameter-overrides AlertEmail=security@yourcompany.com \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

This provisions the full detection pipeline in a single command. Stack outputs include the SNS topic ARN and CloudWatch dashboard URL.

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Your Alert Email

```bash
export SPECTERKEYS_ALERT_EMAIL="security@yourcompany.com"
```

### 4. Deploy a Honey Key

```bash
python src/specterkeys.py --deploy
```

Output:

```
2025-06-18 09:41:55 [INFO] === SpecterKeys Deployment — Session a1b2c3d4 ===
2025-06-18 09:41:56 [INFO] Creating honey IAM user: svc-legacy-backup-a1b2c3d4
2025-06-18 09:41:56 [INFO]   ✓ Access Key ID: AKIA4EXAMPLEKEY0001
2025-06-18 09:41:57 [INFO] Creating CloudWatch alarm: SpecterKeys-Triggered-AKIA4EXAMPLE
2025-06-18 09:41:57 [INFO] Planting honey credential files...
2025-06-18 09:41:57 [INFO]   ✓ Planted: ./honey_drop/prod_access_keys.csv
2025-06-18 09:41:57 [INFO]   ✓ Planted: ./honey_drop/aws_credentials_backup.txt
2025-06-18 09:41:57 [INFO]   ✓ Planted: ./honey_drop/.env.production
2025-06-18 09:41:57 [INFO]   ✓ Planted: ./honey_drop/terraform.tfvars

=== Deployment Complete ===
  Key ID   : AKIA4EXAMPLEKEY0001
  IAM User : svc-legacy-backup-a1b2c3d4
  Alarm    : SpecterKeys-Triggered-AKIA4EXAMPLEKEY0001
  Files    : 4 planted in ./honey_drop/
```

### 5. Plant the Honey Files

Upload `./honey_drop/` to tempting locations — where a snooping insider would look:

```bash
# Internal shared S3 bucket
aws s3 cp ./honey_drop/ s3://company-shared-assets/legacy-creds/ --recursive

# Private GitHub repo (internal access only)
cp ./honey_drop/* /path/to/internal-repo/config/
git -C /path/to/internal-repo add . && git commit -m "Add legacy credential backup" && git push

# Internal developer wiki attachment
# Internal SharePoint / Google Drive
```

> **File naming rationale:**
> - `prod_access_keys.csv` — looks like an accidental admin export
> - `aws_credentials_backup.txt` — appears to be a DR asset
> - `.env.production` — looks like a developer left secrets exposed
> - `terraform.tfvars` — targets DevOps/infrastructure engineers

---

## CLI Reference

```bash
# Deploy a new honey key + plant credential files
python src/specterkeys.py --deploy

# List all active honey keys from Secrets Manager registry
python src/specterkeys.py --list

# Check CloudWatch alarm states for all keys
python src/specterkeys.py --status

# Revoke all honey keys (IAM users, alarms, registry entries)
python src/specterkeys.py --revoke

# Use a custom CloudTrail log group
python src/specterkeys.py --deploy --log-group /custom/cloudtrail
```

---

## Detection Logic

```
 Legitimate user  ──►  Opens file  ──►  Does NOT use keys
                                        (no legitimate reason to)

 Malicious actor  ──►  Opens file  ──►  Uses keys to authenticate
                                               │
                                     CloudTrail event logged
                                               │
                                     CW Metric Filter fires
                                               │
                                     Alarm → ALARM in < 60s
                                               │
                                     SNS → Email + Lambda
                                               │
                                     Key auto-disabled
                                               │
                                     IR ticket opened
```

Because the honey keys are covered by a `DenyAll` IAM policy, they cannot perform any action. There is no legitimate workflow that would involve testing or using them. **Any API call is adversarial by definition**, which is why this technique produces zero false positives.

---

## Incident Response

When an alert fires:

**1. Identify the caller**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
```

**2. Geolocate the source IP** — compare against known corporate egress ranges

**3. Identify the drop location** — which location did the actor access to find the file?

**4. Cross-reference access logs** — who has access to that S3 bucket / repo / drive?

**5. Preserve evidence** — export CloudTrail events before rotation

**6. Escalate** — legal, HR, executive leadership per your IR policy

**7. Re-arm** — deploy a fresh honey key to the same location
```bash
python src/specterkeys.py --revoke
python src/specterkeys.py --deploy
```

---

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=src
```

---

## Analyst Value

| Metric | Traditional DLP | SpecterKeys |
|---|---|---|
| False positive rate | High | **Zero** |
| Detection latency | Minutes–hours | **< 60 seconds** |
| Evidence quality | Heuristic alerts | **CloudTrail proof of action** |
| Coverage | Known patterns only | **Any key usage, any action** |
| Insider vs external | Hard to distinguish | **Same detection path** |
| Tuning required | Ongoing | **None — trap is binary** |

---

## Operational Security

> **This repository is classified RESTRICTED.**

- Do not document honey drop locations in any wiki, ticket, or runbook accessible to general staff
- Store the deployer IAM role credentials in a vault with MFA-enforced access
- Rotate the deployer role's own credentials every 90 days
- Audit repository access quarterly
- `honey_drop/` is listed in `.gitignore` — never commit generated files

See [SECURITY.md](SECURITY.md) for the full vulnerability disclosure policy.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
<sub>Built for blue teams. Operated in silence. Devastating when tripped.</sub>
</div>
