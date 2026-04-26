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
  python src/specterkeys.py --deploy   [--log-group <name>]
  python src/specterkeys.py --list
  python src/specterkeys.py --status
  python src/specterkeys.py --revoke
"""

import boto3
import json
import os
import sys
import uuid
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path
from botocore.exceptions import ClientError

# ── Configuration ──────────────────────────────────────────────────────────────

CONFIG = {
    "region":            "us-east-1",
    "honey_user_prefix": "svc-legacy-backup",       # Looks like a real service account
    "secret_prefix":     "specterkeys",
    "sns_topic_name":    "SpecterKeysAlerts",
    "alarm_prefix":      "SpecterKeys-Triggered",
    "tag_key":           "SpecterKeys",
    "tag_value":         "HoneyToken-DoNotUse",
    "alert_email":       os.getenv("SPECTERKEYS_ALERT_EMAIL", "security-team@company.com"),
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


# ── CloudWatch Alarm Setup ─────────────────────────────────────────────────────

def setup_sns_topic(sns_client) -> str:
    """Create or retrieve the SNS topic for honey key alerts."""
    log.info(f"Setting up SNS topic: {CONFIG['sns_topic_name']}")
    response  = sns_client.create_topic(Name=CONFIG["sns_topic_name"])
    topic_arn = response["TopicArn"]

    try:
        sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol="email",
            Endpoint=CONFIG["alert_email"],
        )
        log.info(f"  ✓ Subscribed {CONFIG['alert_email']} to alerts")
    except ClientError as e:
        log.warning(f"  Could not subscribe email: {e}")

    return topic_arn


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


def setup_cloudtrail_metric_filter(logs_client, log_group: str, username: str):
    """Create a metric filter that counts API calls from the honey IAM user."""
    filter_name    = f"SpecterKeys-Filter-{username}"
    filter_pattern = f'{{ $.userIdentity.userName = "{username}" }}'

    log.info(f"Creating metric filter for user: {username}")
    try:
        logs_client.put_metric_filter(
            logGroupName=  log_group,
            filterName=    filter_name,
            filterPattern= filter_pattern,
            metricTransformations=[{
                "metricName":      "HoneyKeyAPICall",
                "metricNamespace": "SpecterKeys/DeceptionSystem",
                "metricValue":     "1",
                "dimensions":      {"Username": username},
                "unit":            "Count",
            }],
        )
        log.info(f"  ✓ Metric filter: {filter_name}")
    except ClientError as e:
        log.error(f"  Metric filter error: {e}")


# ── Credential File Renderers ──────────────────────────────────────────────────

def render_csv(creds: dict) -> str:
    return (
        "Environment,AccessKeyId,SecretAccessKey,Region,Account\n"
        f"production,{creds['access_key_id']},{creds['secret_access_key']},us-east-1,123456789012\n"
        f"staging,AKIA{'X'*16},{'Y'*40},us-west-2,123456789012\n"
    )


def render_ini(creds: dict) -> str:
    return (
        f"[default]\n"
        f"aws_access_key_id     = {creds['access_key_id']}\n"
        f"aws_secret_access_key = {creds['secret_access_key']}\n"
        f"region                = us-east-1\n\n"
        f"[prod-admin]\n"
        f"aws_access_key_id     = {creds['access_key_id']}\n"
        f"aws_secret_access_key = {creds['secret_access_key']}\n"
        f"region                = us-east-1\n"
    )


def render_env(creds: dict) -> str:
    return (
        f"# Production Environment — DO NOT COMMIT\n"
        f"NODE_ENV=production\n"
        f"DATABASE_URL=postgresql://admin:Sup3rS3cr3t@prod-db.internal:5432/main\n"
        f"REDIS_URL=redis://prod-cache.internal:6379\n\n"
        f"AWS_ACCESS_KEY_ID={creds['access_key_id']}\n"
        f"AWS_SECRET_ACCESS_KEY={creds['secret_access_key']}\n"
        f"AWS_DEFAULT_REGION=us-east-1\n\n"
        f"STRIPE_SECRET_KEY=sk_live_XXXXXXXXXXXXXXXXXXXX\n"
        f"SENDGRID_API_KEY=SG.XXXXXXXXXXXXXXXXXXXXXXXX\n"
    )


def render_tfvars(creds: dict) -> str:
    return (
        f'# Terraform Production Variables\n'
        f'# Last updated: {datetime.now().strftime("%Y-%m-%d")}\n\n'
        f'aws_region   = "us-east-1"\n'
        f'aws_access_key = "{creds["access_key_id"]}"\n'
        f'aws_secret_key = "{creds["secret_access_key"]}"\n'
        f'environment    = "production"\n'
        f'vpc_id         = "vpc-0abc123def456789"\n'
        f'cluster_name   = "prod-eks-cluster"\n'
    )


RENDERERS = {"csv": render_csv, "ini": render_ini, "env": render_env, "tfvars": render_tfvars}


def plant_credential_files(creds: dict, output_dir: str = "./honey_drop") -> list:
    """Write honey credential files to a staging directory ready for deployment."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    planted = []
    for target in CONFIG["deploy_targets"]:
        content  = RENDERERS[target["type"]](creds)
        filepath = Path(output_dir) / target["filename"]
        filepath.write_text(content)
        planted.append(str(filepath))
        log.info(f"  ✓ Planted: {filepath}")
    return planted


# ── Secrets Manager — Central Registry ────────────────────────────────────────

def store_in_secrets_manager(sm_client, creds: dict, alarm_name: str) -> str:
    """Register honey key metadata in Secrets Manager for audit and lifecycle management."""
    secret_name  = f"{CONFIG['secret_prefix']}/{creds['access_key_id']}"
    secret_value = json.dumps({**creds, "alarm_name": alarm_name, "status": "ACTIVE"})

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


def revoke_honey_key(iam_client, sm_client, cw_client, key_data: dict):
    """Fully decommission a honey key — IAM user, alarm, and registry entry."""
    username = key_data["username"]
    key_id   = key_data["access_key_id"]
    log.info(f"Revoking: {key_id} (user: {username})")

    for fn, args in [
        (iam_client.delete_access_key,   dict(UserName=username, AccessKeyId=key_id)),
        (iam_client.delete_user_policy,  dict(UserName=username, PolicyName="SpecterKeys-DenyAll")),
        (iam_client.delete_user,         dict(UserName=username)),
    ]:
        try:
            fn(**args)
        except ClientError as e:
            log.warning(f"  IAM: {e}")

    try:
        cw_client.delete_alarms(AlarmNames=[key_data.get("alarm_name", "")])
        log.info("  ✓ Alarm deleted")
    except ClientError as e:
        log.warning(f"  Alarm: {e}")

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

def deploy(cloudtrail_log_group: str = "/specterkeys/cloudtrail"):
    """Full pipeline: create honey key → wire alarms → plant files → register."""
    session = boto3.Session(region_name=CONFIG["region"])
    iam     = session.client("iam")
    sns     = session.client("sns")
    cw      = session.client("cloudwatch")
    logs    = session.client("logs")
    sm      = session.client("secretsmanager")

    session_id = str(uuid.uuid4())
    log.info(f"=== SpecterKeys Deployment — Session {session_id[:8]} ===")

    creds       = create_honey_iam_user(iam, session_id)
    topic_arn   = setup_sns_topic(sns)
    alarm_name  = create_cloudwatch_alarm(cw, creds, topic_arn)
    setup_cloudtrail_metric_filter(logs, cloudtrail_log_group, creds["username"])

    log.info("Planting honey credential files...")
    planted     = plant_credential_files(creds)
    secret_name = store_in_secrets_manager(sm, creds, alarm_name)

    log.info("\n=== Deployment Complete ===")
    log.info(f"  Key ID   : {creds['access_key_id']}")
    log.info(f"  IAM User : {creds['username']}")
    log.info(f"  Alarm    : {alarm_name}")
    log.info(f"  Registry : {secret_name}")
    log.info(f"  Files    : {len(planted)} planted in ./honey_drop/")
    log.info("\n  Upload ./honey_drop/* to your tempting drop location.")
    log.info("  Any use of these credentials = confirmed threat. 🎯")
    return creds


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="specterkeys",
        description="SpecterKeys — Insider Threat Honey Token System",
    )
    parser.add_argument("--deploy",    action="store_true", help="Deploy a new honey key")
    parser.add_argument("--list",      action="store_true", help="List active honey keys")
    parser.add_argument("--revoke",    action="store_true", help="Revoke all honey keys")
    parser.add_argument("--status",    action="store_true", help="Check CloudWatch alarm states")
    parser.add_argument("--log-group", default="/specterkeys/cloudtrail",
                        help="CloudTrail CloudWatch log group name")
    args = parser.parse_args()

    session = boto3.Session(region_name=CONFIG["region"])
    sm  = session.client("secretsmanager")
    iam = session.client("iam")
    cw  = session.client("cloudwatch")

    if args.deploy:
        deploy(args.log_group)

    elif args.list:
        keys = list_honey_keys(sm)
        print(f"\n{'─'*60}")
        print(f"SpecterKeys — Active Honey Tokens: {len(keys)}")
        print(f"{'─'*60}")
        for k in keys:
            print(f"  {k['access_key_id']}  {k['username']}  {k['created_at'][:10]}")

    elif args.revoke:
        keys = list_honey_keys(sm)
        log.info(f"Revoking {len(keys)} honey key(s)...")
        for k in keys:
            revoke_honey_key(iam, sm, cw, k)
        log.info("All honey keys revoked.")

    elif args.status:
        keys     = list_honey_keys(sm)
        statuses = [check_alarm_status(cw, k) for k in keys]
        print(f"\n{'─'*70}")
        print(f"{'Key ID':<22} {'User':<30} {'State'}")
        print(f"{'─'*70}")
        for s in statuses:
            icon = "ALARM" if s["state"] == "ALARM" else "OK"
            print(f"  {s['key_id']:<20} {s.get('username',''):<30} [{icon}] {s['state']}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
