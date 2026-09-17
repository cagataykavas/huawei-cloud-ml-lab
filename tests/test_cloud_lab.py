from __future__ import annotations

import json

import pytest

from cloud_lab.config import DeploymentConfig
from cloud_lab.functiongraph import handler, normalize_obs_event
from cloud_lab.planner import build_plan
from cloud_lab.policies import has_errors, validate


def valid_values(**changes):
    values = {
        "name": "model-prod",
        "environment": "prod",
        "region": "tr-west-1",
        "replicas": 3,
        "model_uri": "obs://models/model.onnx",
        "model_sha256": "a" * 64,
        "kms_key_id": "kms-key",
        "database_private": True,
        "database_high_availability": True,
        "backup_retention_days": 14,
        "autoscaling_enabled": True,
        "min_replicas": 3,
        "max_replicas": 10,
        "public_api": True,
    }
    values.update(changes)
    return values


def test_valid_production_config_has_no_errors():
    findings = validate(DeploymentConfig.from_dict(valid_values()))
    assert has_errors(findings) is False
    assert [item.code for item in findings] == ["API001"]


@pytest.mark.parametrize(
    "change,code",
    [
        ({"replicas": 2}, "HA001"),
        ({"database_high_availability": False}, "HA002"),
        ({"backup_retention_days": 3}, "DR001"),
        ({"autoscaling_enabled": False}, "SCALE001"),
        ({"min_replicas": 1}, "SCALE002"),
        ({"kms_key_id": None}, "ENC001"),
        ({"database_private": False}, "NET001"),
    ],
)
def test_production_policy_failures_are_explicit(change, code):
    findings = validate(DeploymentConfig.from_dict(valid_values(**change)))
    assert code in {item.code for item in findings if item.severity == "error"}


def test_dev_allows_warning_only_posture():
    config = DeploymentConfig.from_dict(
        valid_values(
            environment="dev",
            replicas=1,
            min_replicas=1,
            max_replicas=1,
            autoscaling_enabled=False,
            database_high_availability=False,
            backup_retention_days=1,
            kms_key_id=None,
            public_api=False,
        )
    )
    findings = validate(config)
    assert has_errors(findings) is False
    assert {item.code for item in findings} == {"ENC001", "HA003"}


def test_config_rejects_unknown_keys():
    values = valid_values(extra=True)
    with pytest.raises(ValueError, match="unknown"):
        DeploymentConfig.from_dict(values)


def test_config_rejects_non_obs_model_uri():
    with pytest.raises(ValueError, match="obs"):
        DeploymentConfig.from_dict(valid_values(model_uri="https://example.com/model"))


def test_config_loads_json(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(valid_values()), encoding="utf-8")
    assert DeploymentConfig.from_json(path).name == "model-prod"


def test_plan_is_deterministic_and_deployable():
    config = DeploymentConfig.from_dict(valid_values())
    assert build_plan(config) == build_plan(config)
    assert build_plan(config)["deployable"] is True
    assert "CCE HPA" in {item["service"] for item in build_plan(config)["services"]}


def test_obs_event_normalization_decodes_key():
    event = {
        "records": [
            {
                "eventName": "ObjectCreated:Put",
                "obs": {"bucket": {"name": "models"}, "object": {"key": "risk%2Fv1.onnx"}},
            }
        ]
    }
    assert normalize_obs_event(event)[0]["source_uri"] == "obs://models/risk/v1.onnx"
    assert handler(event, object())["statusCode"] == 202


def test_obs_event_rejects_invalid_shape():
    with pytest.raises(ValueError, match="records"):
        normalize_obs_event({})
    with pytest.raises(ValueError, match="record 0"):
        normalize_obs_event({"records": [{}]})
