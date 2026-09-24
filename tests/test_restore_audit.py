from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy

import pytest

from cloud_lab.restore_audit import (
    RestoreAuditInputError,
    RestoreAuditPolicy,
    audit_restore_drill,
    load_artifact,
)


def _artifact(**changes) -> dict:
    manifest = {"row_count": 150_000, "schema_sha256": "a" * 64, "data_sha256": "b" * 64}
    values = {
        "schema_version": 1,
        "drill_id": "drill-2026-09-24",
        "backup_id": "backup-prod-0042",
        "source_instance_id": "gaussdb-prod",
        "restore_instance_id": "gaussdb-restore-drill",
        "region": "tr-west-1",
        "backup_completed_at": "2026-09-24T08:00:00Z",
        "recovery_point_at": "2026-09-24T09:45:00Z",
        "restore_started_at": "2026-09-24T10:00:00Z",
        "restore_ready_at": "2026-09-24T10:12:00Z",
        "validation_completed_at": "2026-09-24T10:20:00Z",
        "cleanup_completed_at": "2026-09-24T10:25:00Z",
        "source_manifest": manifest,
        "restored_manifest": deepcopy(manifest),
        "validation_queries_total": 5,
        "validation_queries_passed": 5,
        "private_network": True,
        "kms_key_id": "kms-prod-key",
        "cleanup_succeeded": True,
    }
    values.update(changes)
    return values


def test_accepts_restore_drill_within_policy() -> None:
    report = audit_restore_drill(_artifact())

    assert report["accepted"] is True
    assert report["findings"] == ["ALL_RESTORE_GATES_PASSED"]
    assert report["metrics"]["rpo_minutes"] == 15.0
    assert report["metrics"]["rto_minutes"] == 20.0
    assert report["metrics"]["manifest_matches"] is True


@pytest.mark.parametrize(
    ("changes", "finding"),
    [
        ({"recovery_point_at": "2026-09-24T08:30:00Z"}, "RPO_BUDGET_EXCEEDED"),
        (
            {
                "validation_completed_at": "2026-09-24T10:45:00Z",
                "cleanup_completed_at": "2026-09-24T10:50:00Z",
            },
            "RTO_BUDGET_EXCEEDED",
        ),
        ({"backup_completed_at": "2026-09-23T08:00:00Z"}, "BACKUP_TOO_OLD"),
        ({"restore_instance_id": "gaussdb-prod"}, "RESTORE_TARGET_NOT_ISOLATED"),
        (
            {"validation_queries_total": 2, "validation_queries_passed": 2},
            "INSUFFICIENT_VALIDATION_QUERIES",
        ),
        ({"validation_queries_passed": 4}, "VALIDATION_QUERY_FAILURE"),
        ({"private_network": False}, "PRIVATE_NETWORK_EVIDENCE_MISSING"),
        ({"kms_key_id": None}, "ENCRYPTION_EVIDENCE_MISSING"),
        ({"cleanup_succeeded": False}, "CLEANUP_INCOMPLETE"),
    ],
)
def test_policy_failures_have_stable_findings(changes: dict, finding: str) -> None:
    report = audit_restore_drill(_artifact(**changes))

    assert report["accepted"] is False
    assert finding in report["findings"]


def test_detects_schema_data_and_row_count_mismatch() -> None:
    artifact = _artifact()
    artifact["restored_manifest"] = {
        "row_count": 149_999,
        "schema_sha256": "c" * 64,
        "data_sha256": "d" * 64,
    }

    report = audit_restore_drill(artifact)

    assert report["findings"] == ["RESTORE_MANIFEST_MISMATCH"]
    assert report["metrics"]["source_row_count"] == 150_000
    assert report["metrics"]["restored_row_count"] == 149_999


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"schema_version": 2}, "schema_version"),
        ({"restore_started_at": "2026-09-24T07:00:00Z"}, "backup_completed_at"),
        ({"restore_ready_at": "2026-09-24T10:30:00Z"}, "chronologically ordered"),
        ({"cleanup_completed_at": "2026-09-24T10:10:00Z"}, "chronologically ordered"),
        ({"validation_queries_passed": 6}, "cannot exceed"),
        ({"private_network": "yes"}, "boolean"),
        ({"restore_started_at": "2026-09-24T10:00:00"}, "UTC offset"),
        (
            {
                "source_manifest": {
                    "row_count": -1,
                    "schema_sha256": "a" * 64,
                    "data_sha256": "b" * 64,
                }
            },
            "non-negative",
        ),
        (
            {"source_manifest": {"row_count": 1, "schema_sha256": "bad", "data_sha256": "b" * 64}},
            "SHA-256",
        ),
    ],
)
def test_malformed_evidence_fails_closed(changes: dict, message: str) -> None:
    with pytest.raises(RestoreAuditInputError, match=message):
        audit_restore_drill(_artifact(**changes))


@pytest.mark.parametrize(
    "policy",
    [
        RestoreAuditPolicy(max_rpo_minutes=0),
        RestoreAuditPolicy(max_rto_minutes=float("nan")),
        RestoreAuditPolicy(min_validation_queries=0),
        RestoreAuditPolicy(require_cleanup="yes"),
    ],
)
def test_invalid_policy_fails_closed(policy: RestoreAuditPolicy) -> None:
    with pytest.raises(RestoreAuditInputError, match="policy"):
        audit_restore_drill(_artifact(), policy)


def test_policy_can_relax_nonproduction_controls() -> None:
    report = audit_restore_drill(
        _artifact(kms_key_id=None, cleanup_succeeded=False),
        RestoreAuditPolicy(require_encryption=False, require_cleanup=False),
    )

    assert report["accepted"] is True


def test_digest_normalizes_equivalent_utc_timestamps() -> None:
    left = _artifact()
    right = _artifact()
    for key in [
        "backup_completed_at",
        "recovery_point_at",
        "restore_started_at",
        "restore_ready_at",
        "validation_completed_at",
        "cleanup_completed_at",
    ]:
        right[key] = right[key].replace("Z", "+00:00")

    assert (
        audit_restore_drill(left)["evidence"]["artifact_sha256"]
        == (audit_restore_drill(right)["evidence"]["artifact_sha256"])
    )


def test_loader_rejects_duplicate_json_fields(tmp_path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")

    with pytest.raises(RestoreAuditInputError, match="duplicate field"):
        load_artifact(path)


def test_cli_distinguishes_acceptance_rejection_and_invalid_input(tmp_path) -> None:
    accepted_path = tmp_path / "accepted.json"
    accepted_path.write_text(json.dumps(_artifact()), encoding="utf-8")
    accepted = subprocess.run(
        [sys.executable, "-m", "cloud_lab.restore_audit", str(accepted_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert accepted.returncode == 0
    assert json.loads(accepted.stdout)["accepted"] is True

    rejected_path = tmp_path / "rejected.json"
    rejected_path.write_text(json.dumps(_artifact(cleanup_succeeded=False)), encoding="utf-8")
    output_path = tmp_path / "report.json"
    rejected = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_lab.restore_audit",
            str(rejected_path),
            "--output",
            str(output_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode == 2
    assert json.loads(output_path.read_text(encoding="utf-8"))["accepted"] is False

    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("{}", encoding="utf-8")
    invalid = subprocess.run(
        [sys.executable, "-m", "cloud_lab.restore_audit", str(invalid_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert invalid.returncode == 3
    assert json.loads(invalid.stderr)["error_code"] == "INVALID_RESTORE_EVIDENCE"
