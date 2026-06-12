#!/usr/bin/env python3
"""
SpecterKeys — Honey Token Deception System
==========================================
Insider Threat Detection via AWS Canary Credentials

Zero false positives. Any trigger = confirmed malicious intent.

Architecture:
  - Creates IAM users with ZERO permissions (deny-all policy)
  - Attaches CloudTrail → CloudWatch Logs → Metric Filter → Alarm chain
  - Plants realistic credential files in tempting locations
  - Lambda auto-responder disables keys and logs incidents on trigger

Usage:
  python src/specterkeys.py --deploy   [--log-group <name>] [--region <r>] [--profile <p>]
  python src/specterkeys.py --list     [--json]
  python src/specterkeys.py --status   [--json]
  python src/specterkeys.py --revoke   (--all --yes | --key-id <AKIA...>)
"""

import boto3
import json
import os
import sys
import uuid
import random
import argparse
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from botocore.exceptions import ClientError

# ── Configuration ──────────────────────────────────────────────────────────────

PLACEHOLDER_EMAIL = "security-team@company.com"

CONFIG = {
    "region":            os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
    "honey_user_prefix": "svc-legacy-backup",       # Looks like a real service account
    "secret_prefix":     "specterkeys",
    "sns_topic_name":    "SpecterKeysAlerts",
    "alarm_prefix":      "SpecterKeys-Triggered",
    "tag_key":           "SpecterKeys",
    "tag_value":         "HoneyToken-DoNotUse",
    "alert_email":       os.getenv("SPECTERKEYS_ALERT_EMAIL", PLACEHOLDER_EMAIL),
    "deploy_targets": [
        {"filename": "prod_access_keys.csv",        "type": "csv"},
        {"filename": "aws_credentials_backup.txt",  "type": "ini"},
        {"filename": ".env.production",             "type": "env"},
        {"filename": "terraform.tfvars",            "type": "tfvars"},
    ],
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("SpecterKeys")


def build_session(region: str = None, profile: str = None) -> boto3.Session:
    """Build a boto3 session honoring optional region and named profile."""
    return boto3.Session(
        region_name=region or CONFIG["region"],
        profile_name=profile,
    )


def get_account_id(session: boto3.Session) -> str:
    """Return the real AWS account ID for the active session.

    GetCallerIdentity cannot be denied by IAM, so an attacker who probes the
    planted credentials will see this account ID. Embedding the real value in
    the decoy files keeps the deception consistent under scrutiny.
    """
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except ClientError as e:
        log.warning(f"Could not resolve account ID, using placeholder: {e}")
        return "123456789012"


# ── IAM — Zero-Permission Honey User ──────────────────────────────────────────

DENY_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":      "DenyAllActions",
            "Effect":   "Deny",
            "Action":   "*",
            "Resource": "*",
        }
    ],
}

# The honey user CAN authenticate (keys are valid) but cannot DO anything.
# Every API call is logged to CloudTrail regardless of the deny — that is the trap.


def create_honey_iam_user(iam_client, session_id: str) -> dict:
    """Create a zero-permission IAM user that looks like a legitimate service account."""
    username = f"{CONFIG['honey_user_prefix']}-{session_id[:8]}"
    log.info(f"Creating honey IAM user: {username}")

    iam_client.create_user(
        UserName=username,
        Tags=[
            {"Key": CONFIG["tag_key"],  "Value": CONFIG["tag_value"]},
            {"Key": "CreatedBy",        "Value": "SpecterKeys"},
            {"Key": "CreatedAt",        "Value": datetime.now(timezone.utc).isoformat()},
            {"Key": "SessionID",        "Value": session_id},
        ],
    )

    iam_client.put_user_policy(
        UserName=username,
        PolicyName="SpecterKeys-DenyAll",
        PolicyDocument=json.dumps(DENY_ALL_POLICY),
    )

    key_response = iam_client.create_access_key(UserName=username)
    credentials  = key_response["AccessKey"]

    log.info(f"  ✓ Access Key ID: {credentials['AccessKeyId']}")
    return {
        "username":          username,
        "access_key_id":     credentials["AccessKeyId"],
        "secret_access_key": credentials["SecretAccessKey"],
        "session_id":        session_id,
        "created_at":        datetime.now(timezone.utc).isoformat(),
    }


def delete_honey_iam_user(iam_client, username: str, key_id: str = None):
    """Best-effort teardown of a honey IAM user and its inline policy/keys."""
    if key_id:
        try:
            iam_client.delete_access_key(UserName=username, AccessKeyId=key_id)
        except ClientError as e:
            log.warning(f"  IAM (delete_access_key): {e}")
    try:
        iam_client.delete_user_policy(UserName=username, PolicyName="SpecterKeys-DenyAll")
    except ClientError as e:
        log.warning(f"  IAM (delete_user_policy): {e}")
    try:
        iam_client.delete_user(UserName=username)
    except ClientError as e:
        log.warning(f"  IAM (delete_user): {e}")


# ── CloudWatch Alarm Setup ─────────────────────────────────────────────────────

def setup_sns_topic(sns_client, alert_email: str = None) -> str:
    """Create or retrieve the SNS topic and subscribe the alert email once."""
    alert_email = alert_email or CONFIG["alert_email"]
    log.info(f"Setting up SNS topic: {CONFIG['sns_topic_name']}")
    response  = sns_client.create_topic(Name=CONFIG["sns_topic_name"])
    topic_arn = response["TopicArn"]

    if not alert_email or alert_email == PLACEHOLDER_EMAIL:
        log.warning(
            "  Alert email is the placeholder default — skipping subscription. "
            "Set SPECTERKEYS_ALERT_EMAIL to receive alerts."
        )
        return topic_arn

    if _is_already_subscribed(sns_client, topic_arn, alert_email):
        log.info(f"  ✓ {alert_email} already subscribed to alerts")
        return topic_arn

    try:
        sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol="email",
            Endpoint=alert_email,
        )
        log.info(f"  ✓ Subscribed {alert_email} to alerts")
    except ClientError as e:
        log.warning(f"  Could not subscribe email: {e}")

    return topic_arn


def _is_already_subscribed(sns_client, topic_arn: str, endpoint: str) -> bool:
    """Return True if endpoint already has an email subscription on the topic."""
    try:
        paginator = sns_client.get_paginator("list_subscriptions_by_topic")
        for page in paginator.paginate(TopicArn=topic_arn):
            for sub in page.get("Subscriptions", []):
                if sub.get("Protocol") == "email" and sub.get("Endpoint") == endpoint:
                    return True
    except ClientError as e:
        log.warning(f"  Could not list existing subscriptions: {e}")
    return False


def create_cloudwatch_alarm(cw_client, credentials: dict, topic_arn: str) -> str:
    """Create a CloudWatch alarm that fires on ANY API call from the honey user."""
    alarm_name = f"{CONFIG['alarm_prefix']}-{credentials['access_key_id']}"
    username   = credentials["username"]

    log.info(f"Creating CloudWatch alarm: {alarm_name}")
    cw_client.put_metric_alarm(
        AlarmName=        alarm_name,
        AlarmDescription= (
            f"SPECTERKEYS TRIGGERED — Honey token used by {username}. "
            f"Key: {credentials['access_key_id']}. "
            "This credential has zero legitimate use. Treat as confirmed insider threat."
        ),
        MetricName=       "HoneyKeyAPICall",
        Namespace=        "SpecterKeys/DeceptionSystem",
        Statistic=        "Sum",
        Dimensions=[{"Name": "Username", "Value": username}],
        Period=           60,
        EvaluationPeriods=1,
        Threshold=        1,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData= "notBreaching",
        AlarmActions=[topic_arn],
        Tags=[
            {"Key": CONFIG["tag_key"], "Value": CONFIG["tag_value"]},
            {"Key": "KeyID",           "Value": credentials["access_key_id"]},
        ],
    )
    log.info(f"  ✓ Alarm fires on ANY API call from {username}")
    return alarm_name


def setup_cloudtrail_metric_filter(logs_client, log_group: str, credentials: dict) -> str:
    """Create a metric filter that counts API calls from the honey IAM user.

    Matches on both the IAM username and the access key ID so that events
    where ``userName`` is absent (e.g. some failed-auth / STS paths) are still
    caught. Raises on failure so the deploy pipeline can roll back rather than
    leave a live, unmonitored credential.
    """
    username    = credentials["username"]
    key_id      = credentials["access_key_id"]
    filter_name = f"SpecterKeys-Filter-{username}"
    filter_pattern = (
        f'{{ ($.userIdentity.userName = "{username}") '
        f'|| ($.userIdentity.accessKeyId = "{key_id}") }}'
    )

    log.info(f"Creating metric filter for user: {username}")
    logs_client.put_metric_filter(
        logGroupName=  log_group,
        filterName=    filter_name,
        filterPattern= filter_pattern,
        metricTransformations=[{
            "metricName":      "HoneyKeyAPICall",
            "metricNamespace": "SpecterKeys/DeceptionSystem",
            "metricValue":     "1",
            "defaultValue":    0,
            "dimensions":      {"Username": username},
            "unit":            "Count",
        }],
    )
    log.info(f"  ✓ Metric filter: {filter_name}")
    return filter_name


# ── Credential File Renderers ──────────────────────────────────────────────────

def render_csv(creds: dict, account_id: str = "123456789012", region: str = "us-east-1") -> str:
    return (
        "Environment,AccessKeyId,SecretAccessKey,Region,Account\n"
        f"production,{creds['access_key_id']},{creds['secret_access_key']},{region},{account_id}\n"
        f"staging,AKIA{'X'*16},{'Y'*40},us-west-2,{account_id}\n"
    )


def render_ini(creds: dict, account_id: str = "123456789012", region: str = "us-east-1") -> str:
    return (
        f"[default]\n"
        f"aws_access_key_id     = {creds['access_key_id']}\n"
        f"aws_secret_access_key = {creds['secret_access_key']}\n"
        f"region                = {region}\n\n"
        f"[prod-admin]\n"
        f"aws_access_key_id     = {creds['access_key_id']}\n"
        f"aws_secret_access_key = {creds['secret_access_key']}\n"
        f"region                = {region}\n"
    )


def render_env(creds: dict, account_id: str = "123456789012", region: str = "us-east-1") -> str:
    return (
        f"# Production Environment — DO NOT COMMIT\n"
        f"NODE_ENV=production\n"
        f"DATABASE_URL=postgresql://admin:Sup3rS3cr3t@prod-db.internal:5432/main\n"
        f"REDIS_URL=redis://prod-cache.internal:6379\n\n"
        f"AWS_ACCESS_KEY_ID={creds['access_key_id']}\n"
        f"AWS_SECRET_ACCESS_KEY={creds['secret_access_key']}\n"
        f"AWS_DEFAULT_REGION={region}\n\n"
        f"STRIPE_SECRET_KEY=sk_live_XXXXXXXXXXXXXXXXXXXX\n"
        f"SENDGRID_API_KEY=SG.XXXXXXXXXXXXXXXXXXXXXXXX\n"
    )


def render_tfvars(creds: dict, account_id: str = "123456789012", region: str = "us-east-1") -> str:
    # Backdate the "last updated" stamp so the file does not look freshly minted.
    updated = (datetime.now() - timedelta(days=random.randint(8, 90))).strftime("%Y-%m-%d")
    return (
        f'# Terraform Production Variables\n'
        f'# Last updated: {updated}\n\n'
        f'aws_region   = "{region}"\n'
        f'aws_access_key = "{creds["access_key_id"]}"\n'
        f'aws_secret_key = "{creds["secret_access_key"]}"\n'
        f'environment    = "production"\n'
        f'vpc_id         = "vpc-0abc123def456789"\n'
        f'cluster_name   = "prod-eks-cluster"\n'
    )


RENDERERS = {"csv": render_csv, "ini": render_ini, "env": render_env, "tfvars": render_tfvars}


def plant_credential_files(
    creds: dict,
    output_dir: str = "./honey_drop",
    account_id: str = "123456789012",
    region: str = "us-east-1",
) -> list:
    """Write honey credential files to a staging directory ready for deployment."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    planted = []
    for target in CONFIG["deploy_targets"]:
        content  = RENDERERS[target["type"]](creds, account_id=account_id, region=region)
        filepath = Path(output_dir) / target["filename"]
        filepath.write_text(content)
        _backdate(filepath)
        planted.append(str(filepath))
        log.info(f"  ✓ Planted: {filepath}")
    return planted


def _backdate(filepath: Path):
    """Set the file's access/modify times to a plausible point in the past.

    Identical, just-created timestamps across every planted file are a forensic
    tell. Spreading them over the last few weeks makes the drop look organic.
    """
    past = datetime.now() - timedelta(
        days=random.randint(5, 120),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )
    ts = past.timestamp()
    os.utime(filepath, (ts, ts))


# ── Secrets Manager — Central Registry ────────────────────────────────────────

def store_in_secrets_manager(
    sm_client,
    creds: dict,
    alarm_name: str,
    filter_name: str = None,
    log_group: str = None,
) -> str:
    """Register honey key metadata in Secrets Manager for audit and lifecycle management."""
    secret_name  = f"{CONFIG['secret_prefix']}/{creds['access_key_id']}"
    secret_value = json.dumps({
        **creds,
        "alarm_name":  alarm_name,
        "filter_name": filter_name,
        "log_group":   log_group,
        "status":      "ACTIVE",
    })

    log.info(f"Registering in Secrets Manager: {secret_name}")
    try:
        sm_client.create_secret(
            Name=         secret_name,
            Description=  "SpecterKeys honey token metadata",
            SecretString= secret_value,
            Tags=[{"Key": CONFIG["tag_key"], "Value": CONFIG["tag_value"]}],
        )
    except sm_client.exceptions.ResourceExistsException:
        sm_client.put_secret_value(SecretId=secret_name, SecretString=secret_value)

    log.info(f"  ✓ Registered: {secret_name}")
    return secret_name


# ── List / Revoke / Status ─────────────────────────────────────────────────────

def list_honey_keys(sm_client) -> list:
    paginator = sm_client.get_paginator("list_secrets")
    keys = []
    for page in paginator.paginate(Filters=[{"Key": "tag-key", "Values": [CONFIG["tag_key"]]}]):
        for secret in page["SecretList"]:
            val  = sm_client.get_secret_value(SecretId=secret["Name"])
            keys.append(json.loads(val["SecretString"]))
    return keys


def revoke_honey_key(iam_client, sm_client, cw_client, key_data: dict, logs_client=None):
    """Fully decommission a honey key — IAM user, alarm, metric filter, and registry entry."""
    username = key_data["username"]
    key_id   = key_data["access_key_id"]
    log.info(f"Revoking: {key_id} (user: {username})")

    delete_honey_iam_user(iam_client, username, key_id)

    try:
        cw_client.delete_alarms(AlarmNames=[key_data.get("alarm_name", "")])
        log.info("  ✓ Alarm deleted")
    except ClientError as e:
        log.warning(f"  Alarm: {e}")

    filter_name = key_data.get("filter_name")
    log_group   = key_data.get("log_group")
    if logs_client and filter_name and log_group:
        try:
            logs_client.delete_metric_filter(
                logGroupName=log_group,
                filterName=filter_name,
            )
            log.info("  ✓ Metric filter deleted")
        except ClientError as e:
            log.warning(f"  Metric filter: {e}")

    try:
        sm_client.delete_secret(
            SecretId=f"{CONFIG['secret_prefix']}/{key_id}",
            ForceDeleteWithoutRecovery=True,
        )
        log.info("  ✓ Secret deleted")
    except ClientError as e:
        log.warning(f"  Secret: {e}")


def check_alarm_status(cw_client, key_data: dict) -> dict:
    try:
        response = cw_client.describe_alarms(AlarmNames=[key_data.get("alarm_name", "")])
        alarms   = response.get("MetricAlarms", [])
        if alarms:
            return {
                "key_id":   key_data["access_key_id"],
                "username": key_data["username"],
                "alarm":    key_data.get("alarm_name"),
                "state":    alarms[0]["StateValue"],
                "reason":   alarms[0]["StateReason"],
                "updated":  alarms[0]["StateUpdatedTimestamp"].isoformat(),
            }
    except ClientError:
        pass
    return {"key_id": key_data["access_key_id"], "state": "UNKNOWN"}


# ── Deployment Pipeline ────────────────────────────────────────────────────────

def deploy(cloudtrail_log_group: str = "/specterkeys/cloudtrail", region: str = None, profile: str = None):
    """Full pipeline: create honey key → wire alarms → plant files → register.

    The IAM user is created first; if any subsequent wiring step fails, the user
    (and its access key) is torn down so we never leave a live, unmonitored
    credential behind.
    """
    session = build_session(region, profile)
    iam     = session.client("iam")
    sns     = session.client("sns")
    cw      = session.client("cloudwatch")
    logs    = session.client("logs")
    sm      = session.client("secretsmanager")

    deploy_region = session.region_name or CONFIG["region"]
    account_id    = get_account_id(session)

    session_id = str(uuid.uuid4())
    log.info(f"=== SpecterKeys Deployment — Session {session_id[:8]} ===")

    creds = create_honey_iam_user(iam, session_id)
    try:
        topic_arn   = setup_sns_topic(sns)
        alarm_name  = create_cloudwatch_alarm(cw, creds, topic_arn)
        filter_name = setup_cloudtrail_metric_filter(logs, cloudtrail_log_group, creds)

        log.info("Planting honey credential files...")
        planted     = plant_credential_files(creds, account_id=account_id, region=deploy_region)
        secret_name = store_in_secrets_manager(
            sm, creds, alarm_name, filter_name, cloudtrail_log_group
        )
    except Exception as e:
        log.error(f"Deployment failed after key creation: {e}")
        log.error("Rolling back honey IAM user to avoid a live, unmonitored credential...")
        delete_honey_iam_user(iam, creds["username"], creds["access_key_id"])
        raise

    log.info("\n=== Deployment Complete ===")
    log.info(f"  Key ID   : {creds['access_key_id']}")
    log.info(f"  IAM User : {creds['username']}")
    log.info(f"  Alarm    : {alarm_name}")
    log.info(f"  Filter   : {filter_name}")
    log.info(f"  Registry : {secret_name}")
    log.info(f"  Files    : {len(planted)} planted in ./honey_drop/")
    log.info("\n  Upload ./honey_drop/* to your tempting drop location.")
    log.info("  Any use of these credentials = confirmed threat. 🎯")
    return creds


# ── CLI ────────────────────────────────────────────────────────────────────────

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="specterkeys",
        description="SpecterKeys — Insider Threat Honey Token System",
    )
    parser.add_argument("--deploy",    action="store_true", help="Deploy a new honey key")
    parser.add_argument("--list",      action="store_true", help="List active honey keys")
    parser.add_argument("--revoke",    action="store_true", help="Revoke honey keys")
    parser.add_argument("--status",    action="store_true", help="Check CloudWatch alarm states")
    parser.add_argument("--log-group", default="/specterkeys/cloudtrail",
                        help="CloudTrail CloudWatch log group name")
    parser.add_argument("--region",    default=None, help="AWS region (overrides default)")
    parser.add_argument("--profile",   default=None, help="AWS named profile")
    parser.add_argument("--key-id",    default=None, help="Target a single key ID (with --revoke)")
    parser.add_argument("--all",       action="store_true", help="Revoke ALL honey keys")
    parser.add_argument("--yes",       action="store_true", help="Skip confirmation prompts")
    parser.add_argument("--json",      action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args(argv)

    session = build_session(args.region, args.profile)
    sm   = session.client("secretsmanager")
    iam  = session.client("iam")
    cw   = session.client("cloudwatch")
    logs = session.client("logs")

    if args.deploy:
        deploy(args.log_group, region=args.region, profile=args.profile)

    elif args.list:
        keys = list_honey_keys(sm)
        if args.json:
            redacted = [
                {k: v for k, v in key.items() if k != "secret_access_key"}
                for key in keys
            ]
            print(json.dumps(redacted, indent=2))
        else:
            print(f"\n{'─'*60}")
            print(f"SpecterKeys — Active Honey Tokens: {len(keys)}")
            print(f"{'─'*60}")
            for k in keys:
                print(f"  {k['access_key_id']}  {k['username']}  {k['created_at'][:10]}")

    elif args.revoke:
        return _handle_revoke(args, iam, sm, cw, logs)

    elif args.status:
        keys     = list_honey_keys(sm)
        statuses = [check_alarm_status(cw, k) for k in keys]
        if args.json:
            print(json.dumps(statuses, indent=2))
        else:
            print(f"\n{'─'*70}")
            print(f"{'Key ID':<22} {'User':<30} {'State'}")
            print(f"{'─'*70}")
            for s in statuses:
                icon = "ALARM" if s["state"] == "ALARM" else "OK"
                print(f"  {s['key_id']:<20} {s.get('username',''):<30} [{icon}] {s['state']}")
        if any(s["state"] == "ALARM" for s in statuses):
            return 2

    else:
        parser.print_help()

    return 0


def _handle_revoke(args, iam, sm, cw, logs) -> int:
    """Revoke a single key (--key-id) or all keys (--all), with a confirmation guard."""
    keys = list_honey_keys(sm)

    if args.key_id:
        targets = [k for k in keys if k["access_key_id"] == args.key_id]
        if not targets:
            log.error(f"No honey key found with ID {args.key_id}")
            return 1
    elif args.all:
        targets = keys
    else:
        log.error("Specify --key-id <AKIA...> to revoke one key, or --all to revoke every key.")
        return 1

    if not targets:
        log.info("No honey keys to revoke.")
        return 0

    if not args.yes:
        log.error(
            f"This will permanently revoke {len(targets)} honey key(s) "
            "(IAM users, alarms, metric filters, registry entries). "
            "Re-run with --yes to confirm."
        )
        return 1

    log.info(f"Revoking {len(targets)} honey key(s)...")
    for k in targets:
        revoke_honey_key(iam, sm, cw, k, logs_client=logs)
    log.info("Revocation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
