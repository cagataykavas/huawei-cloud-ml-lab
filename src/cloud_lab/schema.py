"""Generate the versioned editor-facing deployment configuration schema."""

from __future__ import annotations

import argparse
import json
from dataclasses import fields
from pathlib import Path

from .config import (
    ENVIRONMENTS,
    MODEL_SHA256_PATTERN,
    MODEL_URI_PATTERN,
    NON_BLANK_PATTERN,
    DeploymentConfig,
)

SCHEMA_VERSION = 1
SCHEMA_ID = (
    "https://raw.githubusercontent.com/cagataykavas/huawei-cloud-ml-lab/main/"
    "schemas/deployment-config-v1.schema.json"
)


def deployment_config_schema() -> dict[str, object]:
    """Return a fresh JSON Schema derived from the runtime config field contract."""
    properties: dict[str, object] = {
        "name": {"type": "string", "pattern": NON_BLANK_PATTERN},
        "environment": {"type": "string", "enum": list(ENVIRONMENTS)},
        "region": {"type": "string", "pattern": NON_BLANK_PATTERN},
        "replicas": {"type": "integer", "minimum": 1},
        "model_uri": {"type": "string", "pattern": MODEL_URI_PATTERN},
        "model_sha256": {"type": "string", "pattern": MODEL_SHA256_PATTERN},
        "kms_key_id": {
            "anyOf": [
                {"type": "null"},
                {"type": "string", "pattern": NON_BLANK_PATTERN},
            ]
        },
        "database_private": {"type": "boolean"},
        "database_high_availability": {"type": "boolean"},
        "backup_retention_days": {"type": "integer", "minimum": 0},
        "autoscaling_enabled": {"type": "boolean"},
        "min_replicas": {"type": "integer", "minimum": 1},
        "max_replicas": {"type": "integer", "minimum": 1},
        "public_api": {"type": "boolean"},
    }
    required = [field.name for field in fields(DeploymentConfig)]
    if set(properties) != set(required):
        raise RuntimeError("schema properties do not match DeploymentConfig fields")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_ID,
        "title": "Huawei Cloud ML deployment configuration",
        "description": (
            "Editor and pre-submit checks for DeploymentConfig. Runtime validation remains "
            "authoritative for cross-field replica-envelope consistency and deployment policy."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
        "x-schema-version": SCHEMA_VERSION,
        "x-runtime-invariants": [
            "min_replicas <= replicas <= max_replicas",
            "max_replicas >= min_replicas",
        ],
    }


def canonical_schema_json() -> str:
    return json.dumps(deployment_config_schema(), indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit or verify the deployment config schema")
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument("--output", type=Path, help="write the canonical schema to a file")
    destination.add_argument("--check", type=Path, help="fail if a file differs from the schema")
    args = parser.parse_args(argv)
    expected = canonical_schema_json()
    if args.check is not None:
        if args.check.read_text(encoding="utf-8") != expected:
            parser.error(f"schema is stale: {args.check}")
        return 0
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(expected, encoding="utf-8")
        return 0
    print(expected, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
