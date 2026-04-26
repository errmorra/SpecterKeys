"""
SpecterKeys — Unit Tests
========================
Run with: pytest tests/ -v
"""

import json
import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone

import sys
sys.path.insert(0, "src")

from specterkeys import (
    DENY_ALL_POLICY,
    CONFIG,
    create_honey_iam_user,
    setup_sns_topic,
    create_cloudwatch_alarm,
    plant_credential_files,
    render_csv,
    render_ini,
    render_env,
    render_tfvars,
    check_alarm_status,
    list_honey_keys,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────

SAMPLE_CREDS = {
    "username":          "svc-legacy-backup-a1b2c3d4",
    "access_key_id":     "AKIATESTKEY000001",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "session_id":        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "created_at":        "2025-06-18T09:42:00+00:00",
}

# ── IAM Tests ──────────────────────────────────────────────────────────────────

class TestCreateHoneyIAMUser:
    def test_creates_user_with_correct_prefix(self):
        iam = MagicMock()
        iam.create_access_key.return_value = {
            "AccessKey": {
                "AccessKeyId":     "AKIATEST",
                "SecretAccessKey": "secret",
            }
        }
        session_id = "a1b2c3d4-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        result = create_honey_iam_user(iam, session_id)

        assert result["username"].startswith(CONFIG["honey_user_prefix"])
        assert result["username"].endswith("a1b2c3d4")

    def test_attaches_deny_all_policy(self):
        iam = MagicMock()
        iam.create_access_key.return_value = {
            "AccessKey": {"AccessKeyId": "AKIATEST", "SecretAccessKey": "secret"}
        }
        create_honey_iam_user(iam, "a1b2c3d4-test")

        call_args = iam.put_user_policy.call_args
        policy    = json.loads(call_args.kwargs["PolicyDocument"])
        assert policy["Statement"][0]["Effect"] == "Deny"
        assert policy["Statement"][0]["Action"] == "*"

    def test_tags_include_specterkeys_marker(self):
        iam = MagicMock()
        iam.create_access_key.return_value = {
            "AccessKey": {"AccessKeyId": "AKIATEST", "SecretAccessKey": "secret"}
        }
        create_honey_iam_user(iam, "a1b2c3d4-test")

        tags = iam.create_user.call_args.kwargs["Tags"]
        tag_keys = {t["Key"] for t in tags}
        assert CONFIG["tag_key"] in tag_keys
        assert "CreatedBy" in tag_keys

    def test_returns_access_key_in_result(self):
        iam = MagicMock()
        iam.create_access_key.return_value = {
            "AccessKey": {"AccessKeyId": "AKIATEST123", "SecretAccessKey": "supersecret"}
        }
        result = create_honey_iam_user(iam, "a1b2c3d4-test")
        assert result["access_key_id"] == "AKIATEST123"
        assert result["secret_access_key"] == "supersecret"


# ── Policy Tests ───────────────────────────────────────────────────────────────

class TestDenyAllPolicy:
    def test_policy_denies_all_actions(self):
        stmt = DENY_ALL_POLICY["Statement"][0]
        assert stmt["Effect"] == "Deny"
        assert stmt["Action"] == "*"
        assert stmt["Resource"] == "*"

    def test_policy_is_valid_json(self):
        dumped = json.dumps(DENY_ALL_POLICY)
        loaded = json.loads(dumped)
        assert loaded["Version"] == "2012-10-17"


# ── File Renderer Tests ────────────────────────────────────────────────────────

class TestCredentialRenderers:
    def test_csv_contains_access_key(self):
        output = render_csv(SAMPLE_CREDS)
        assert SAMPLE_CREDS["access_key_id"] in output
        assert SAMPLE_CREDS["secret_access_key"] in output
        assert "production" in output

    def test_ini_has_default_and_prod_profiles(self):
        output = render_ini(SAMPLE_CREDS)
        assert "[default]" in output
        assert "[prod-admin]" in output
        assert SAMPLE_CREDS["access_key_id"] in output

    def test_env_includes_aws_vars(self):
        output = render_env(SAMPLE_CREDS)
        assert "AWS_ACCESS_KEY_ID" in output
        assert "AWS_SECRET_ACCESS_KEY" in output
        assert SAMPLE_CREDS["access_key_id"] in output

    def test_tfvars_includes_aws_keys(self):
        output = render_tfvars(SAMPLE_CREDS)
        assert "aws_access_key" in output
        assert "aws_secret_key" in output
        assert SAMPLE_CREDS["access_key_id"] in output

    def test_env_has_plausible_decoy_vars(self):
        output = render_env(SAMPLE_CREDS)
        assert "DATABASE_URL" in output
        assert "STRIPE_SECRET_KEY" in output


# ── File Planting Tests ────────────────────────────────────────────────────────

class TestPlantCredentialFiles:
    def test_plants_all_configured_targets(self, tmp_path):
        planted = plant_credential_files(SAMPLE_CREDS, output_dir=str(tmp_path))
        assert len(planted) == len(CONFIG["deploy_targets"])

    def test_files_exist_on_disk(self, tmp_path):
        planted = plant_credential_files(SAMPLE_CREDS, output_dir=str(tmp_path))
        for path in planted:
            import os
            assert os.path.exists(path), f"Missing: {path}"

    def test_csv_file_is_named_correctly(self, tmp_path):
        planted = plant_credential_files(SAMPLE_CREDS, output_dir=str(tmp_path))
        filenames = [p.split("/")[-1] for p in planted]
        assert "prod_access_keys.csv" in filenames

    def test_env_file_contains_key(self, tmp_path):
        plant_credential_files(SAMPLE_CREDS, output_dir=str(tmp_path))
        env_file = tmp_path / ".env.production"
        content  = env_file.read_text()
        assert SAMPLE_CREDS["access_key_id"] in content


# ── SNS Tests ──────────────────────────────────────────────────────────────────

class TestSetupSNSTopic:
    def test_creates_topic_with_correct_name(self):
        sns = MagicMock()
        sns.create_topic.return_value = {"TopicArn": "arn:aws:sns:us-east-1:123:SpecterKeysAlerts"}
        arn = setup_sns_topic(sns)
        sns.create_topic.assert_called_once_with(Name=CONFIG["sns_topic_name"])
        assert arn == "arn:aws:sns:us-east-1:123:SpecterKeysAlerts"

    def test_subscribes_alert_email(self):
        sns = MagicMock()
        sns.create_topic.return_value = {"TopicArn": "arn:aws:sns:us-east-1:123:SpecterKeysAlerts"}
        setup_sns_topic(sns)
        subscribe_call = sns.subscribe.call_args
        assert subscribe_call.kwargs["Protocol"] == "email"


# ── Alarm Status Tests ─────────────────────────────────────────────────────────

class TestCheckAlarmStatus:
    def test_returns_alarm_state(self):
        cw = MagicMock()
        cw.describe_alarms.return_value = {
            "MetricAlarms": [{
                "StateValue":            "ALARM",
                "StateReason":           "Threshold crossed",
                "StateUpdatedTimestamp": datetime.now(timezone.utc),
            }]
        }
        result = check_alarm_status(cw, SAMPLE_CREDS | {"alarm_name": "SpecterKeys-Triggered-AKIATEST"})
        assert result["state"] == "ALARM"

    def test_returns_unknown_on_client_error(self):
        from botocore.exceptions import ClientError
        cw = MagicMock()
        cw.describe_alarms.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFound", "Message": ""}}, "DescribeAlarms"
        )
        result = check_alarm_status(cw, SAMPLE_CREDS | {"alarm_name": "missing-alarm"})
        assert result["state"] == "UNKNOWN"


# ── Config Integrity Tests ─────────────────────────────────────────────────────

class TestConfig:
    def test_all_deploy_targets_have_renderer(self):
        from specterkeys import RENDERERS
        for target in CONFIG["deploy_targets"]:
            assert target["type"] in RENDERERS, f"No renderer for type: {target['type']}"

    def test_honey_user_prefix_is_plausible(self):
        prefix = CONFIG["honey_user_prefix"]
        assert len(prefix) > 4
        assert "ghost" not in prefix.lower()     # Should not self-identify as a trap
        assert "honey" not in prefix.lower()
        assert "fake"  not in prefix.lower()
