"""Generate an auditable vendor-service plan from validated configuration."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .config import DeploymentConfig
from .policies import has_errors, validate


def build_plan(config: DeploymentConfig) -> dict[str, Any]:
    findings = validate(config)
    services = [
        {"service": "VPC", "purpose": "private network and security groups"},
        {"service": "CCE", "purpose": "containerized inference API"},
        {"service": "OBS", "purpose": "versioned model artifacts"},
        {"service": "ModelArts", "purpose": "training and model lifecycle"},
        {"service": "RDS/GaussDB", "purpose": "prediction metadata and audit records"},
        {"service": "Cloud Eye", "purpose": "metrics, alarms and operational visibility"},
        {"service": "IAM/KMS", "purpose": "least privilege and encryption keys"},
    ]
    if config.public_api:
        services.extend(
            [
                {"service": "ELB", "purpose": "regional load balancing"},
                {"service": "API Gateway", "purpose": "authenticated public API boundary"},
            ]
        )
    if config.autoscaling_enabled:
        services.append({"service": "CCE HPA", "purpose": "replica autoscaling"})

    return {
        "deployment": config.name,
        "environment": config.environment,
        "region": config.region,
        "deployable": not has_errors(findings),
        "model": {"uri": config.model_uri, "sha256": config.model_sha256},
        "capacity": {
            "replicas": config.replicas,
            "minimum": config.min_replicas,
            "maximum": config.max_replicas,
            "autoscaling": config.autoscaling_enabled,
        },
        "services": services,
        "findings": [asdict(item) for item in findings],
    }
