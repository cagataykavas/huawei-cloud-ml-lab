"""Audit evidence from an isolated database restore rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RestoreAuditInputError(ValueError):
    """Raised when restore-drill evidence is malformed or incomplete."""


@dataclass(frozen=True)
class RestoreAuditPolicy:
    max_rpo_minutes: float = 60.0
    max_rto_minutes: float = 30.0
    max_backup_age_hours: float = 24.0
    min_validation_queries: int = 3
    require_private_network: bool = True
    require_encryption: bool = True
    require_cleanup: bool = True
    max_identifier_length: int = 256


def _finite_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RestoreAuditInputError(f"{field} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise RestoreAuditInputError(f"{field} must be a finite number")
    return result


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RestoreAuditInputError(f"{field} must be a positive integer")
    return value


def _validate_policy(policy: RestoreAuditPolicy) -> None:
    for field in ("max_rpo_minutes", "max_rto_minutes", "max_backup_age_hours"):
        value = _finite_number(getattr(policy, field), f"policy.{field}")
        if value <= 0.0:
            raise RestoreAuditInputError(f"policy.{field} must be greater than zero")
    _positive_int(policy.min_validation_queries, "policy.min_validation_queries")
    _positive_int(policy.max_identifier_length, "policy.max_identifier_length")
    for field in ("require_private_network", "require_encryption", "require_cleanup"):
        if not isinstance(getattr(policy, field), bool):
            raise RestoreAuditInputError(f"policy.{field} must be boolean")


def _identifier(value: Any, field: str, policy: RestoreAuditPolicy) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RestoreAuditInputError(f"{field} must be a non-empty string")
    if len(value) > policy.max_identifier_length:
        raise RestoreAuditInputError(
            f"{field} exceeds policy.max_identifier_length={policy.max_identifier_length}"
        )
    return value


def _timestamp(value: Any, field: str) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value.strip():
        raise RestoreAuditInputError(f"{field} must be a non-empty ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RestoreAuditInputError(f"{field} must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RestoreAuditInputError(f"{field} must include a UTC offset")
    normalized = parsed.astimezone(UTC)
    return normalized, normalized.isoformat().replace("+00:00", "Z")


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise RestoreAuditInputError(f"{field} must be boolean")
    return value


def _non_negative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RestoreAuditInputError(f"{field} must be a non-negative integer")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value.lower()):
        raise RestoreAuditInputError(f"{field} must be a 64-character SHA-256 digest")
    return value.lower()


def _manifest(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RestoreAuditInputError(f"{field} must be an object")
    row_count = _non_negative_int(value.get("row_count"), f"{field}.row_count")
    schema_sha256 = _digest(value.get("schema_sha256"), f"{field}.schema_sha256")
    data_sha256 = _digest(value.get("data_sha256"), f"{field}.data_sha256")
    return {
        "row_count": row_count,
        "schema_sha256": schema_sha256,
        "data_sha256": data_sha256,
    }


def audit_restore_drill(
    artifact: dict[str, Any], policy: RestoreAuditPolicy | None = None
) -> dict[str, Any]:
    """Return a deterministic release decision for one restore rehearsal."""

    active_policy = policy or RestoreAuditPolicy()
    _validate_policy(active_policy)
    if not isinstance(artifact, dict):
        raise RestoreAuditInputError("artifact must be an object")
    if artifact.get("schema_version") != 1:
        raise RestoreAuditInputError("artifact.schema_version must equal 1")

    drill_id = _identifier(artifact.get("drill_id"), "drill_id", active_policy)
    backup_id = _identifier(artifact.get("backup_id"), "backup_id", active_policy)
    source_instance_id = _identifier(
        artifact.get("source_instance_id"), "source_instance_id", active_policy
    )
    restore_instance_id = _identifier(
        artifact.get("restore_instance_id"), "restore_instance_id", active_policy
    )
    region = _identifier(artifact.get("region"), "region", active_policy)

    backup_completed, backup_completed_text = _timestamp(
        artifact.get("backup_completed_at"), "backup_completed_at"
    )
    recovery_point, recovery_point_text = _timestamp(
        artifact.get("recovery_point_at"), "recovery_point_at"
    )
    restore_started, restore_started_text = _timestamp(
        artifact.get("restore_started_at"), "restore_started_at"
    )
    restore_ready, restore_ready_text = _timestamp(
        artifact.get("restore_ready_at"), "restore_ready_at"
    )
    validation_completed, validation_completed_text = _timestamp(
        artifact.get("validation_completed_at"), "validation_completed_at"
    )
    cleanup_completed, cleanup_completed_text = _timestamp(
        artifact.get("cleanup_completed_at"), "cleanup_completed_at"
    )
    if backup_completed > restore_started:
        raise RestoreAuditInputError("backup_completed_at cannot follow restore_started_at")
    if recovery_point > restore_started:
        raise RestoreAuditInputError("recovery_point_at cannot follow restore_started_at")
    if not restore_started <= restore_ready <= validation_completed <= cleanup_completed:
        raise RestoreAuditInputError(
            "restore, validation and cleanup timestamps must be chronologically ordered"
        )

    source_manifest = _manifest(artifact.get("source_manifest"), "source_manifest")
    restored_manifest = _manifest(artifact.get("restored_manifest"), "restored_manifest")
    validation_queries_total = _non_negative_int(
        artifact.get("validation_queries_total"), "validation_queries_total"
    )
    validation_queries_passed = _non_negative_int(
        artifact.get("validation_queries_passed"), "validation_queries_passed"
    )
    if validation_queries_passed > validation_queries_total:
        raise RestoreAuditInputError(
            "validation_queries_passed cannot exceed validation_queries_total"
        )
    private_network = _boolean(artifact.get("private_network"), "private_network")
    cleanup_succeeded = _boolean(artifact.get("cleanup_succeeded"), "cleanup_succeeded")
    kms_key_id = artifact.get("kms_key_id")
    if kms_key_id is not None:
        kms_key_id = _identifier(kms_key_id, "kms_key_id", active_policy)

    rpo_minutes = (restore_started - recovery_point).total_seconds() / 60.0
    rto_minutes = (validation_completed - restore_started).total_seconds() / 60.0
    backup_age_hours = (restore_started - backup_completed).total_seconds() / 3600.0
    manifest_matches = source_manifest == restored_manifest
    findings: list[str] = []
    if rpo_minutes > active_policy.max_rpo_minutes:
        findings.append("RPO_BUDGET_EXCEEDED")
    if rto_minutes > active_policy.max_rto_minutes:
        findings.append("RTO_BUDGET_EXCEEDED")
    if backup_age_hours > active_policy.max_backup_age_hours:
        findings.append("BACKUP_TOO_OLD")
    if source_instance_id == restore_instance_id:
        findings.append("RESTORE_TARGET_NOT_ISOLATED")
    if not manifest_matches:
        findings.append("RESTORE_MANIFEST_MISMATCH")
    if validation_queries_total < active_policy.min_validation_queries:
        findings.append("INSUFFICIENT_VALIDATION_QUERIES")
    if validation_queries_passed != validation_queries_total:
        findings.append("VALIDATION_QUERY_FAILURE")
    if active_policy.require_private_network and not private_network:
        findings.append("PRIVATE_NETWORK_EVIDENCE_MISSING")
    if active_policy.require_encryption and kms_key_id is None:
        findings.append("ENCRYPTION_EVIDENCE_MISSING")
    if active_policy.require_cleanup and not cleanup_succeeded:
        findings.append("CLEANUP_INCOMPLETE")

    normalized = {
        "schema_version": 1,
        "drill_id": drill_id,
        "backup_id": backup_id,
        "source_instance_id": source_instance_id,
        "restore_instance_id": restore_instance_id,
        "region": region,
        "backup_completed_at": backup_completed_text,
        "recovery_point_at": recovery_point_text,
        "restore_started_at": restore_started_text,
        "restore_ready_at": restore_ready_text,
        "validation_completed_at": validation_completed_text,
        "cleanup_completed_at": cleanup_completed_text,
        "source_manifest": source_manifest,
        "restored_manifest": restored_manifest,
        "validation_queries_total": validation_queries_total,
        "validation_queries_passed": validation_queries_passed,
        "private_network": private_network,
        "kms_key_id": kms_key_id,
        "cleanup_succeeded": cleanup_succeeded,
    }
    canonical = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return {
        "audit": "isolated_database_restore_rehearsal",
        "schema_version": 1,
        "accepted": not findings,
        "findings": findings or ["ALL_RESTORE_GATES_PASSED"],
        "policy": asdict(active_policy),
        "evidence": {
            "artifact_sha256": hashlib.sha256(canonical).hexdigest(),
            "drill_id": drill_id,
            "backup_id": backup_id,
            "source_instance_id": source_instance_id,
            "restore_instance_id": restore_instance_id,
            "region": region,
        },
        "metrics": {
            "rpo_minutes": rpo_minutes,
            "rto_minutes": rto_minutes,
            "restore_ready_minutes": (restore_ready - restore_started).total_seconds() / 60.0,
            "validation_minutes": (validation_completed - restore_ready).total_seconds() / 60.0,
            "backup_age_hours": backup_age_hours,
            "manifest_matches": manifest_matches,
            "source_row_count": source_manifest["row_count"],
            "restored_row_count": restored_manifest["row_count"],
            "validation_queries_total": validation_queries_total,
            "validation_queries_passed": validation_queries_passed,
        },
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RestoreAuditInputError(f"JSON contains duplicate field {key!r}")
        value[key] = item
    return value


def load_artifact(path: Path, max_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    if path.stat().st_size > max_bytes:
        raise RestoreAuditInputError(f"artifact exceeds {max_bytes} bytes")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RestoreAuditInputError(f"cannot read artifact: {exc}") from exc
    if not isinstance(value, dict):
        raise RestoreAuditInputError("artifact must be a JSON object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit an isolated database restore rehearsal.")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-rpo-minutes", type=float, default=60.0)
    parser.add_argument("--max-rto-minutes", type=float, default=30.0)
    parser.add_argument("--max-backup-age-hours", type=float, default=24.0)
    parser.add_argument("--min-validation-queries", type=int, default=3)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        policy = RestoreAuditPolicy(
            max_rpo_minutes=args.max_rpo_minutes,
            max_rto_minutes=args.max_rto_minutes,
            max_backup_age_hours=args.max_backup_age_hours,
            min_validation_queries=args.min_validation_queries,
        )
        report = audit_restore_drill(load_artifact(args.artifact), policy)
    except (OSError, RestoreAuditInputError) as exc:
        print(
            json.dumps(
                {
                    "status": "invalid_input",
                    "error_code": "INVALID_RESTORE_EVIDENCE",
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["accepted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
