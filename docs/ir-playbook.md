# SpecterKeys — Incident Response Playbook

**Classification: RESTRICTED — Security Team Only**
**Last updated: 2025-06-18**

---

## Trigger Conditions

This playbook activates when any of the following occur:

- You receive a `SpecterKeysAlerts` SNS email notification
- The CloudWatch alarm `SpecterKeys-HoneyTokenTriggered` enters `ALARM` state
- A colleague reports suspicious credential activity matching a `svc-legacy-backup-*` IAM user

---

## Phase 1 — Triage (0–5 minutes)

### 1.1 Confirm the trigger is genuine

```bash
aws cloudwatch describe-alarms \
  --alarm-names SpecterKeys-HoneyTokenTriggered \
  --query 'MetricAlarms[0].{State:StateValue,Reason:StateReason,Updated:StateUpdatedTimestamp}'
```

### 1.2 Pull the raw CloudTrail event

```bash
# Replace AKIA... with the Key ID from the alert
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --max-results 10 \
  --query 'Events[*].{Time:EventTime,Action:EventName,IP:CloudTrailEvent}' \
  --output table
```

### 1.3 Extract source IP and user agent from the event

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --max-results 1 \
  --query 'Events[0].CloudTrailEvent' \
  --output text | python3 -m json.tool
```

Key fields to capture:
- `sourceIPAddress`
- `userAgent`
- `eventTime`
- `eventName` (the API action attempted)
- `requestParameters`

---

## Phase 2 — Identification (5–30 minutes)

### 2.1 Geolocate the source IP

```bash
curl -s https://ipinfo.io/<SOURCE_IP>/json
```

Compare against your known corporate IP ranges. VPN egress IPs, cloud NAT gateways, and home IP ranges of employees are all significant signals.

### 2.2 Identify who has access to the drop location

Determine which drop location was accessed to retrieve the honey file. Cross-reference:

- **S3 bucket**: check S3 access logs for the `honey_drop/` prefix
- **GitHub repo**: check audit logs in GitHub → Settings → Audit log
- **SharePoint / Drive**: check file access history

Compile a list of users with access to that location.

### 2.3 Correlate with HR and identity systems

- Is the source IP associated with any known employee device?
- Was any employee working unusual hours around the event time?
- Does the user agent string match internal tooling, a known developer tool, or an unknown client?
- Is any employee on a PIP, recently passed over for promotion, or under any disciplinary action?

---

## Phase 3 — Containment (30–60 minutes)

### 3.1 Confirm auto-responder ran

The Lambda auto-responder should have already disabled the key. Verify:

```bash
aws iam list-access-keys --user-name svc-legacy-backup-XXXXXXXX \
  --query 'AccessKeyMetadata[*].{Key:AccessKeyId,Status:Status}'
```

Expected: `Status: Inactive`

If the key is still `Active`, disable it manually:

```bash
aws iam update-access-key \
  --user-name svc-legacy-backup-XXXXXXXX \
  --access-key-id AKIA... \
  --status Inactive
```

### 3.2 Preserve all evidence before cleanup

```bash
# Export all CloudTrail events for this key to a file
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --output json > evidence/cloudtrail-$(date +%Y%m%d-%H%M%S).json

# Export IAM user details
aws iam get-user --user-name svc-legacy-backup-XXXXXXXX --output json \
  > evidence/iam-user-$(date +%Y%m%d-%H%M%S).json
```

### 3.3 If actor is identified — escalate immediately

Contact in order:
1. Your direct security leadership
2. Legal counsel
3. HR (if insider threat is confirmed)
4. Executive leadership (CISO / CTO)

**Do not confront the suspect directly** without HR and legal guidance.

---

## Phase 4 — Re-Arm (after containment)

Always replace triggered honey tokens with fresh ones. The trap location should never go dark.

```bash
# Revoke the triggered key (use --all --yes to clear every key)
python src/specterkeys.py --revoke --key-id AKIA... --yes

# Deploy a fresh honey key
python src/specterkeys.py --deploy

# Re-upload the new honey files to the same drop location
aws s3 cp ./honey_drop/ s3://your-bucket/drop-location/ --recursive
```

---

## Evidence Checklist

- [ ] CloudTrail event JSON exported
- [ ] Source IP and user agent documented
- [ ] Drop location access logs pulled
- [ ] Suspect user list compiled
- [ ] Key disabled (confirmed `Inactive`)
- [ ] Legal and HR notified (if insider confirmed)
- [ ] Incident ticket opened (use GitHub issue template)
- [ ] Fresh honey key deployed

---

## Severity Classification

| Indicator | Severity |
|---|---|
| Source IP matches corporate VPN / office egress | **CRITICAL — confirmed insider** |
| Source IP is residential, matches employee location | **HIGH — strong insider signal** |
| Source IP is cloud provider (AWS, GCP, Azure) | **HIGH — lateral movement post-breach** |
| Source IP is TOR / proxy / anonymous | **HIGH — deliberate obfuscation** |
| Source IP is unknown / international | **MEDIUM — investigate further** |
| User-agent matches internal tooling | **CRITICAL — access was deliberate** |

---

*SpecterKeys IR Playbook — Classification: RESTRICTED*
