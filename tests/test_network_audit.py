from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from cloud_lab.network_audit import (
    MAX_RULES,
    NetworkAuditValidationError,
    NetworkPolicy,
    SecurityGroupSnapshot,
    audit_security_group,
)

NOW = datetime(2026, 11, 12, 18, 0, tzinfo=UTC)


def rule(
    rule_id: str,
    *,
    direction: str = "ingress",
    protocol: str = "tcp",
    port_min: int | None = 8443,
    port_max: int | None = 8443,
    remote_cidr: str | None = None,
    remote_group_id: str | None = "sg-apig-prod",
) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "direction": direction,
        "protocol": protocol,
        "port_min": port_min,
        "port_max": port_max,
        "remote_cidr": remote_cidr,
        "remote_group_id": remote_group_id,
    }


def allowance(
    allowance_id: str,
    *,
    direction: str = "ingress",
    protocol: str = "tcp",
    port_min: int | None = 8443,
    port_max: int | None = 8443,
    remote_cidr: str | None = None,
    remote_group_id: str | None = "sg-apig-prod",
    required: bool = True,
    permit_global: bool = False,
) -> dict[str, object]:
    return {
        "allowance_id": allowance_id,
        "direction": direction,
        "protocol": protocol,
        "port_min": port_min,
        "port_max": port_max,
        "remote_cidr": remote_cidr,
        "remote_group_id": remote_group_id,
        "required": required,
        "permit_global": permit_global,
    }


def snapshot_values(*rules: dict[str, object], **changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "snapshot_id": "snapshot-42",
        "security_group_id": "sg-cce-inference",
        "revision": "rev-7",
        "captured_at": "2026-11-12T17:59:00Z",
        "rules": list(rules),
    }
    values.update(changes)
    return values


def policy_values(*allowances: dict[str, object], **changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "policy_id": "cce-private-network-v1",
        "security_group_id": "sg-cce-inference",
        "max_age_seconds": 300,
        "max_future_skew_seconds": 30,
        "allowances": list(allowances),
    }
    values.update(changes)
    return values


def valid_inputs() -> tuple[SecurityGroupSnapshot, NetworkPolicy]:
    ingress = rule("ingress-apig")
    egress = rule(
        "egress-rds",
        direction="egress",
        port_min=5432,
        port_max=5432,
        remote_cidr="10.20.4.0/24",
        remote_group_id=None,
    )
    ingress_allowance = allowance("require-apig")
    egress_allowance = allowance(
        "require-rds",
        direction="egress",
        port_min=5432,
        port_max=5432,
        remote_cidr="10.20.0.0/16",
        remote_group_id=None,
    )
    return (
        SecurityGroupSnapshot.from_dict(snapshot_values(ingress, egress)),
        NetworkPolicy.from_dict(policy_values(ingress_allowance, egress_allowance)),
    )


def test_reviewed_private_paths_are_accepted() -> None:
    snapshot, policy = valid_inputs()

    report = audit_security_group(snapshot, policy, evaluated_at=NOW)

    assert report.accepted is True
    assert report.findings == ()
    assert report.age_seconds == 60
    assert report.evidence_digest.startswith("sha256:")
    json.dumps(report.to_dict(), allow_nan=False)


def test_broad_public_ingress_is_rejected() -> None:
    snapshot, policy = valid_inputs()
    broad_rule = rule(
        "public-api",
        port_min=443,
        port_max=443,
        remote_cidr="0.0.0.0/0",
        remote_group_id=None,
    )
    snapshot = SecurityGroupSnapshot.from_dict(snapshot_values(broad_rule))

    report = audit_security_group(snapshot, policy, evaluated_at=NOW)

    assert report.accepted is False
    assert {item.code for item in report.findings} == {
        "NET_REQUIRED_PATH_MISSING",
        "NET_RULE_NOT_ALLOWED",
    }


def test_global_allowance_requires_explicit_opt_in() -> None:
    public = allowance(
        "public-https",
        port_min=443,
        port_max=443,
        remote_cidr="0.0.0.0/0",
        remote_group_id=None,
    )
    with pytest.raises(NetworkAuditValidationError, match="permit_global"):
        NetworkPolicy.from_dict(policy_values(public))

    public["permit_global"] = True
    policy = NetworkPolicy.from_dict(policy_values(public))
    snapshot = SecurityGroupSnapshot.from_dict(
        snapshot_values(
            rule(
                "public-https-rule",
                port_min=443,
                port_max=443,
                remote_cidr="203.0.113.0/24",
                remote_group_id=None,
            )
        )
    )
    assert audit_security_group(snapshot, policy, evaluated_at=NOW).accepted is True


def test_stale_and_future_snapshots_fail_closed() -> None:
    _, policy = valid_inputs()
    stale = SecurityGroupSnapshot.from_dict(
        snapshot_values(rule("ingress-apig"), captured_at="2026-11-12T17:00:00Z")
    )
    future = SecurityGroupSnapshot.from_dict(
        snapshot_values(rule("ingress-apig"), captured_at="2026-11-12T18:01:00Z")
    )

    stale_report = audit_security_group(stale, policy, evaluated_at=NOW)
    future_report = audit_security_group(future, policy, evaluated_at=NOW)

    assert "NET_SNAPSHOT_STALE" in {item.code for item in stale_report.findings}
    assert "NET_SNAPSHOT_FUTURE" in {item.code for item in future_report.findings}


def test_group_identity_and_required_paths_are_enforced() -> None:
    snapshot, policy = valid_inputs()
    mismatched = NetworkPolicy.from_dict(
        policy_values(
            allowance("optional-apig", required=False),
            security_group_id="sg-other",
        )
    )
    report = audit_security_group(snapshot, mismatched, evaluated_at=NOW)

    assert "NET_GROUP_MISMATCH" in {item.code for item in report.findings}

    missing = SecurityGroupSnapshot.from_dict(snapshot_values())
    report = audit_security_group(missing, policy, evaluated_at=NOW)
    assert [item.code for item in report.findings] == [
        "NET_REQUIRED_PATH_MISSING",
        "NET_REQUIRED_PATH_MISSING",
    ]


def test_digest_is_deterministic_order_independent_and_input_sensitive() -> None:
    snapshot, policy = valid_inputs()
    first = audit_security_group(snapshot, policy, evaluated_at=NOW)
    permuted_snapshot = SecurityGroupSnapshot(
        snapshot.snapshot_id,
        snapshot.security_group_id,
        snapshot.revision,
        snapshot.captured_at,
        tuple(reversed(snapshot.rules)),
    )
    permuted = audit_security_group(permuted_snapshot, policy, evaluated_at=NOW)
    changed = audit_security_group(
        SecurityGroupSnapshot(
            snapshot.snapshot_id,
            snapshot.security_group_id,
            "rev-8",
            snapshot.captured_at,
            snapshot.rules,
        ),
        policy,
        evaluated_at=NOW,
    )

    assert first.evidence_digest == permuted.evidence_digest
    assert first.evidence_digest != changed.evidence_digest


@pytest.mark.parametrize(
    "bad_rule",
    [
        rule("bad-direction", direction="sideways"),
        rule("bad-protocol", protocol="gre"),
        rule("bad-port", port_min=0),
        rule("bad-cidr", remote_cidr="10.0.0.1/24", remote_group_id=None),
        rule("two-remotes", remote_cidr="10.0.0.0/24"),
        rule("no-remote", remote_group_id=None),
    ],
)
def test_malformed_rules_fail_closed(bad_rule: dict[str, object]) -> None:
    with pytest.raises(NetworkAuditValidationError):
        SecurityGroupSnapshot.from_dict(snapshot_values(bad_rule))


def test_unknown_fields_duplicate_ids_and_naive_time_fail_closed() -> None:
    unknown = rule("rule-1")
    unknown["description"] = "not in contract"
    with pytest.raises(NetworkAuditValidationError, match="fields"):
        SecurityGroupSnapshot.from_dict(snapshot_values(unknown))
    with pytest.raises(NetworkAuditValidationError, match="duplicate rule_id"):
        SecurityGroupSnapshot.from_dict(snapshot_values(rule("same"), rule("same")))

    snapshot, policy = valid_inputs()
    with pytest.raises(NetworkAuditValidationError, match="timezone-aware"):
        audit_security_group(
            snapshot,
            policy,
            evaluated_at=datetime(2026, 11, 12, 18, 0),
        )


def test_rule_and_allowance_limits_fail_closed() -> None:
    too_many_rules = [rule(f"rule-{index}") for index in range(MAX_RULES + 1)]
    with pytest.raises(NetworkAuditValidationError, match="rule count"):
        SecurityGroupSnapshot.from_dict(snapshot_values(*too_many_rules))


def test_direct_construction_rejects_wrong_collection_members() -> None:
    with pytest.raises(NetworkAuditValidationError, match="SecurityGroupRule"):
        SecurityGroupSnapshot(
            "snapshot-42",
            "sg-cce-inference",
            "rev-7",
            NOW,
            ("not-a-rule",),  # type: ignore[arg-type]
        )
    with pytest.raises(NetworkAuditValidationError, match="NetworkAllowance"):
        NetworkPolicy(
            "policy-v1",
            "sg-cce-inference",
            300,
            30,
            ("not-an-allowance",),  # type: ignore[arg-type]
        )


def test_age_boundary_is_inclusive() -> None:
    snapshot, policy = valid_inputs()
    evaluated_at = snapshot.captured_at + timedelta(seconds=policy.max_age_seconds)
    assert audit_security_group(snapshot, policy, evaluated_at=evaluated_at).accepted is True
