from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from cloud_lab.config import DeploymentConfig
from cloud_lab.schema import SCHEMA_ID, canonical_schema_json, deployment_config_schema, main

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "deployment-config-v1.schema.json"


def valid_values(**changes):
    values = json.loads((ROOT / "configs" / "prod.json").read_text(encoding="utf-8"))
    values.update(changes)
    return values


def test_checked_in_schema_is_canonical_and_covers_exact_runtime_fields():
    schema = deployment_config_schema()
    assert schema["$id"] == SCHEMA_ID
    assert schema["required"] == [field.name for field in fields(DeploymentConfig)]
    assert set(schema["properties"]) == set(schema["required"])
    assert schema["additionalProperties"] is False
    assert SCHEMA_PATH.read_text(encoding="utf-8") == canonical_schema_json()


@pytest.mark.parametrize("name", ["dev.json", "prod.json"])
def test_example_configs_pass_schema_and_runtime_validation(name):
    values = json.loads((ROOT / "configs" / name).read_text(encoding="utf-8"))
    Draft202012Validator(deployment_config_schema()).validate(values)
    DeploymentConfig.from_dict(values)


@pytest.mark.parametrize(
    "change",
    [
        {"replicas": True},
        {"environment": "qa"},
        {"name": "   "},
        {"model_uri": "https://example.com/model.onnx"},
        {"model_sha256": "A" * 64},
        {"backup_retention_days": -1},
        {"kms_key_id": ""},
        {"extra": True},
    ],
)
def test_schema_rejects_scalar_contract_violations(change):
    with pytest.raises(ValidationError):
        Draft202012Validator(deployment_config_schema()).validate(valid_values(**change))


def test_schema_rejects_missing_required_field():
    values = valid_values()
    del values["model_uri"]
    with pytest.raises(ValidationError):
        Draft202012Validator(deployment_config_schema()).validate(values)


def test_runtime_remains_authoritative_for_cross_field_invariants():
    values = valid_values(replicas=2, min_replicas=3, max_replicas=10)
    Draft202012Validator(deployment_config_schema()).validate(values)
    with pytest.raises(ValueError, match="envelope"):
        DeploymentConfig.from_dict(values)


def test_schema_cli_detects_stale_artifact(tmp_path):
    stale = tmp_path / "schema.json"
    stale.write_text("{}\n", encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        main(["--check", str(stale)])
    assert error.value.code == 2
    assert main(["--check", str(SCHEMA_PATH)]) == 0
