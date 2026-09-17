"""Opinionated production-readiness checks with actionable findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .config import DeploymentConfig

Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    message: str


def validate(config: DeploymentConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.database_private:
        findings.append(Finding("NET001", "error", "GaussDB/RDS must use a private subnet"))
    if config.kms_key_id is None:
        severity: Severity = "error" if config.environment == "prod" else "warning"
        findings.append(Finding("ENC001", severity, "configure a KMS key for model and data"))
    if config.public_api:
        findings.append(
            Finding("API001", "warning", "public API requires APIG authentication and WAF policy")
        )

    if config.environment == "prod":
        if config.replicas < 3:
            findings.append(Finding("HA001", "error", "production requires at least 3 replicas"))
        if not config.database_high_availability:
            findings.append(
                Finding("HA002", "error", "production database must be highly available")
            )
        if config.backup_retention_days < 7:
            findings.append(Finding("DR001", "error", "production backups require >= 7 days"))
        if not config.autoscaling_enabled:
            findings.append(Finding("SCALE001", "error", "production requires CCE autoscaling"))
        if config.min_replicas < 3:
            findings.append(
                Finding("SCALE002", "error", "production minimum replicas must be >= 3")
            )
    elif config.replicas < 2:
        findings.append(Finding("HA003", "warning", "single replica has no rollout availability"))

    if config.autoscaling_enabled and config.max_replicas <= config.min_replicas:
        findings.append(
            Finding("SCALE003", "warning", "autoscaling range cannot grow above its minimum")
        )
    return sorted(findings, key=lambda item: (item.severity != "error", item.code))


def has_errors(findings: list[Finding]) -> bool:
    return any(item.severity == "error" for item in findings)
