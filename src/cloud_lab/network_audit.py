"""Fail-closed admission audit for normalized security-group snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Self

MAX_RULES = 512
MAX_AGE_SECONDS = 86_400
MAX_FUTURE_SKEW_SECONDS = 300
SCHEMA_VERSION = 1
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_DIRECTIONS = {"ingress", "egress"}
_PROTOCOLS = {"tcp", "udp", "icmp", "any"}


class NetworkAuditValidationError(ValueError):
    """Raised when network evidence or policy is structurally invalid."""


@dataclass(frozen=True, slots=True)
class SecurityGroupRule:
    rule_id: str
    direction: str
    protocol: str
    port_min: int | None
    port_max: int | None
    remote_cidr: str | None
    remote_group_id: str | None

    def __post_init__(self) -> None:
        _validate_endpoint(
            identifier=self.rule_id,
            direction=self.direction,
            protocol=self.protocol,
            port_min=self.port_min,
            port_max=self.port_max,
            remote_cidr=self.remote_cidr,
            remote_group_id=self.remote_group_id,
        )

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> Self:
        _require_fields(
            values,
            {
                "rule_id",
                "direction",
                "protocol",
                "port_min",
                "port_max",
                "remote_cidr",
                "remote_group_id",
            },
            "security-group rule",
        )
        return cls(**values)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class NetworkAllowance:
    allowance_id: str
    direction: str
    protocol: str
    port_min: int | None
    port_max: int | None
    remote_cidr: str | None
    remote_group_id: str | None
    required: bool
    permit_global: bool

    def __post_init__(self) -> None:
        network = _validate_endpoint(
            identifier=self.allowance_id,
            direction=self.direction,
            protocol=self.protocol,
            port_min=self.port_min,
            port_max=self.port_max,
            remote_cidr=self.remote_cidr,
            remote_group_id=self.remote_group_id,
        )
        if not isinstance(self.required, bool) or not isinstance(self.permit_global, bool):
            raise NetworkAuditValidationError("allowance flags must be booleans")
        if network is not None and network.is_global and not self.permit_global:
            raise NetworkAuditValidationError("global CIDR allowances require permit_global=true")
        if self.remote_group_id is not None and self.permit_global:
            raise NetworkAuditValidationError("permit_global is only valid for CIDR allowances")

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> Self:
        _require_fields(
            values,
            {
                "allowance_id",
                "direction",
                "protocol",
                "port_min",
                "port_max",
                "remote_cidr",
                "remote_group_id",
                "required",
                "permit_global",
            },
            "network allowance",
        )
        return cls(**values)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class SecurityGroupSnapshot:
    snapshot_id: str
    security_group_id: str
    revision: str
    captured_at: datetime
    rules: tuple[SecurityGroupRule, ...]

    def __post_init__(self) -> None:
        _validate_identifier(self.snapshot_id, "snapshot_id")
        _validate_identifier(self.security_group_id, "security_group_id")
        _validate_identifier(self.revision, "revision")
        _validate_timestamp(self.captured_at, "captured_at")
        if not isinstance(self.rules, tuple):
            raise NetworkAuditValidationError("rules must be a tuple")
        if len(self.rules) > MAX_RULES:
            raise NetworkAuditValidationError(f"rule count exceeds limit of {MAX_RULES}")
        if any(not isinstance(rule, SecurityGroupRule) for rule in self.rules):
            raise NetworkAuditValidationError("rules must contain SecurityGroupRule values")
        _require_unique((rule.rule_id for rule in self.rules), "rule_id")

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> Self:
        _require_fields(
            values,
            {"snapshot_id", "security_group_id", "revision", "captured_at", "rules"},
            "security-group snapshot",
        )
        raw_rules = values["rules"]
        if not isinstance(raw_rules, list):
            raise NetworkAuditValidationError("rules must be a list")
        captured_at = _parse_timestamp(values["captured_at"], "captured_at")
        rules = tuple(_rule_from_value(value) for value in raw_rules)
        return cls(
            snapshot_id=_string(values["snapshot_id"], "snapshot_id"),
            security_group_id=_string(values["security_group_id"], "security_group_id"),
            revision=_string(values["revision"], "revision"),
            captured_at=captured_at,
            rules=rules,
        )


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    policy_id: str
    security_group_id: str
    max_age_seconds: int
    max_future_skew_seconds: int
    allowances: tuple[NetworkAllowance, ...]

    def __post_init__(self) -> None:
        _validate_identifier(self.policy_id, "policy_id")
        _validate_identifier(self.security_group_id, "security_group_id")
        if (
            isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, int)
            or not 1 <= self.max_age_seconds <= MAX_AGE_SECONDS
        ):
            raise NetworkAuditValidationError(f"max_age_seconds must be in [1, {MAX_AGE_SECONDS}]")
        if (
            isinstance(self.max_future_skew_seconds, bool)
            or not isinstance(self.max_future_skew_seconds, int)
            or not 0 <= self.max_future_skew_seconds <= MAX_FUTURE_SKEW_SECONDS
        ):
            raise NetworkAuditValidationError(
                f"max_future_skew_seconds must be in [0, {MAX_FUTURE_SKEW_SECONDS}]"
            )
        if not isinstance(self.allowances, tuple):
            raise NetworkAuditValidationError("allowances must be a tuple")
        if len(self.allowances) > MAX_RULES:
            raise NetworkAuditValidationError(f"allowance count exceeds limit of {MAX_RULES}")
        if any(not isinstance(item, NetworkAllowance) for item in self.allowances):
            raise NetworkAuditValidationError("allowances must contain NetworkAllowance values")
        _require_unique(
            (allowance.allowance_id for allowance in self.allowances),
            "allowance_id",
        )

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> Self:
        _require_fields(
            values,
            {
                "policy_id",
                "security_group_id",
                "max_age_seconds",
                "max_future_skew_seconds",
                "allowances",
            },
            "network policy",
        )
        raw_allowances = values["allowances"]
        if not isinstance(raw_allowances, list):
            raise NetworkAuditValidationError("allowances must be a list")
        allowances = tuple(_allowance_from_value(value) for value in raw_allowances)
        return cls(
            policy_id=_string(values["policy_id"], "policy_id"),
            security_group_id=_string(values["security_group_id"], "security_group_id"),
            max_age_seconds=_integer(values["max_age_seconds"], "max_age_seconds"),
            max_future_skew_seconds=_integer(
                values["max_future_skew_seconds"], "max_future_skew_seconds"
            ),
            allowances=allowances,
        )


@dataclass(frozen=True, slots=True)
class NetworkFinding:
    code: str
    subject_id: str
    message: str


@dataclass(frozen=True, slots=True)
class NetworkAuditReport:
    schema_version: int
    accepted: bool
    snapshot_id: str
    policy_id: str
    evaluated_at: datetime
    age_seconds: int
    evidence_digest: str
    findings: tuple[NetworkFinding, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "accepted": self.accepted,
            "snapshot_id": self.snapshot_id,
            "policy_id": self.policy_id,
            "evaluated_at": _timestamp(self.evaluated_at),
            "age_seconds": self.age_seconds,
            "evidence_digest": self.evidence_digest,
            "findings": [
                {"code": item.code, "subject_id": item.subject_id, "message": item.message}
                for item in self.findings
            ],
        }


def audit_security_group(
    snapshot: SecurityGroupSnapshot,
    policy: NetworkPolicy,
    *,
    evaluated_at: datetime,
) -> NetworkAuditReport:
    """Audit one normalized security-group snapshot against an exact allowlist."""

    _validate_timestamp(evaluated_at, "evaluated_at")
    evaluated_at = evaluated_at.astimezone(UTC)
    captured_at = snapshot.captured_at.astimezone(UTC)
    delta_seconds = int((evaluated_at - captured_at).total_seconds())
    findings: list[NetworkFinding] = []

    if snapshot.security_group_id != policy.security_group_id:
        findings.append(
            NetworkFinding(
                "NET_GROUP_MISMATCH",
                snapshot.security_group_id,
                "snapshot security group does not match the reviewed policy",
            )
        )
    if delta_seconds > policy.max_age_seconds:
        findings.append(
            NetworkFinding(
                "NET_SNAPSHOT_STALE",
                snapshot.snapshot_id,
                "security-group snapshot exceeds the maximum evidence age",
            )
        )
    if -delta_seconds > policy.max_future_skew_seconds:
        findings.append(
            NetworkFinding(
                "NET_SNAPSHOT_FUTURE",
                snapshot.snapshot_id,
                "security-group snapshot is too far in the future",
            )
        )

    matched_allowances: set[str] = set()
    for rule in snapshot.rules:
        matches = tuple(allowance for allowance in policy.allowances if _matches(rule, allowance))
        if not matches:
            findings.append(
                NetworkFinding(
                    "NET_RULE_NOT_ALLOWED",
                    rule.rule_id,
                    "security-group rule is outside the reviewed allowlist",
                )
            )
        matched_allowances.update(item.allowance_id for item in matches)

    for allowance in policy.allowances:
        if allowance.required and allowance.allowance_id not in matched_allowances:
            findings.append(
                NetworkFinding(
                    "NET_REQUIRED_PATH_MISSING",
                    allowance.allowance_id,
                    "required network path is absent from the snapshot",
                )
            )

    findings.sort(key=lambda item: (item.code, item.subject_id))
    digest = _evidence_digest(snapshot, policy)
    return NetworkAuditReport(
        schema_version=SCHEMA_VERSION,
        accepted=not findings,
        snapshot_id=snapshot.snapshot_id,
        policy_id=policy.policy_id,
        evaluated_at=evaluated_at,
        age_seconds=max(0, delta_seconds),
        evidence_digest=digest,
        findings=tuple(findings),
    )


def _matches(rule: SecurityGroupRule, allowance: NetworkAllowance) -> bool:
    if rule.direction != allowance.direction or rule.protocol != allowance.protocol:
        return False
    if rule.port_min != allowance.port_min or rule.port_max != allowance.port_max:
        return False
    if rule.remote_group_id is not None:
        return rule.remote_group_id == allowance.remote_group_id
    if allowance.remote_cidr is None or rule.remote_cidr is None:
        return False
    rule_network = ip_network(rule.remote_cidr)
    allowance_network = ip_network(allowance.remote_cidr)
    return rule_network.version == allowance_network.version and rule_network.subnet_of(
        allowance_network
    )


def _validate_endpoint(
    *,
    identifier: str,
    direction: str,
    protocol: str,
    port_min: int | None,
    port_max: int | None,
    remote_cidr: str | None,
    remote_group_id: str | None,
) -> IPv4Network | IPv6Network | None:
    _validate_identifier(identifier, "rule or allowance identifier")
    if direction not in _DIRECTIONS:
        raise NetworkAuditValidationError("direction must be ingress or egress")
    if protocol not in _PROTOCOLS:
        raise NetworkAuditValidationError("protocol must be tcp, udp, icmp or any")
    if (remote_cidr is None) == (remote_group_id is None):
        raise NetworkAuditValidationError(
            "exactly one of remote_cidr or remote_group_id is required"
        )
    network = None
    if remote_cidr is not None:
        if not isinstance(remote_cidr, str):
            raise NetworkAuditValidationError("remote_cidr must be a string or null")
        try:
            network = ip_network(remote_cidr, strict=True)
        except ValueError as exc:
            raise NetworkAuditValidationError("remote_cidr must be canonical CIDR") from exc
        if str(network) != remote_cidr:
            raise NetworkAuditValidationError("remote_cidr must use canonical formatting")
    else:
        _validate_identifier(remote_group_id, "remote_group_id")

    if protocol in {"tcp", "udp"}:
        if any(
            isinstance(value, bool) or not isinstance(value, int) for value in (port_min, port_max)
        ):
            raise NetworkAuditValidationError("tcp and udp rules require integer ports")
        assert isinstance(port_min, int) and isinstance(port_max, int)
        if not 1 <= port_min <= port_max <= 65_535:
            raise NetworkAuditValidationError("port range must be within [1, 65535]")
    elif port_min is not None or port_max is not None:
        raise NetworkAuditValidationError("icmp and any rules must not declare ports")
    return network


def _evidence_digest(snapshot: SecurityGroupSnapshot, policy: NetworkPolicy) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "snapshot": {
            "snapshot_id": snapshot.snapshot_id,
            "security_group_id": snapshot.security_group_id,
            "revision": snapshot.revision,
            "captured_at": _timestamp(snapshot.captured_at),
            "rules": [
                _endpoint_dict(item)
                for item in sorted(snapshot.rules, key=lambda item: item.rule_id)
            ],
        },
        "policy": {
            "policy_id": policy.policy_id,
            "security_group_id": policy.security_group_id,
            "max_age_seconds": policy.max_age_seconds,
            "max_future_skew_seconds": policy.max_future_skew_seconds,
            "allowances": [
                {
                    **_endpoint_dict(item),
                    "required": item.required,
                    "permit_global": item.permit_global,
                }
                for item in sorted(policy.allowances, key=lambda x: x.allowance_id)
            ],
        },
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


def _endpoint_dict(value: SecurityGroupRule | NetworkAllowance) -> dict[str, object]:
    identifier = value.rule_id if isinstance(value, SecurityGroupRule) else value.allowance_id
    key = "rule_id" if isinstance(value, SecurityGroupRule) else "allowance_id"
    return {
        key: identifier,
        "direction": value.direction,
        "protocol": value.protocol,
        "port_min": value.port_min,
        "port_max": value.port_max,
        "remote_cidr": value.remote_cidr,
        "remote_group_id": value.remote_group_id,
    }


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise NetworkAuditValidationError(f"{name} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NetworkAuditValidationError(f"{name} must be an RFC 3339 string") from exc
    _validate_timestamp(parsed, name)
    return parsed.astimezone(UTC)


def _validate_timestamp(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise NetworkAuditValidationError(f"{name} must be timezone-aware")


def _require_fields(values: object, expected: set[str], label: str) -> None:
    if not isinstance(values, dict) or set(values) != expected:
        raise NetworkAuditValidationError(f"{label} fields do not match schema")


def _require_unique(values: Iterable[str], label: str) -> None:
    identifiers = tuple(values)
    if len(identifiers) != len(set(identifiers)):
        raise NetworkAuditValidationError(f"duplicate {label}")


def _validate_identifier(value: object, name: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise NetworkAuditValidationError(f"{name} is invalid")


def _string(value: object, name: str) -> str:
    _validate_identifier(value, name)
    assert isinstance(value, str)
    return value


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise NetworkAuditValidationError(f"{name} must be an integer")
    return value


def _rule_from_value(value: object) -> SecurityGroupRule:
    if not isinstance(value, dict):
        raise NetworkAuditValidationError("each rule must be an object")
    return SecurityGroupRule.from_dict(value)


def _allowance_from_value(value: object) -> NetworkAllowance:
    if not isinstance(value, dict):
        raise NetworkAuditValidationError("each allowance must be an object")
    return NetworkAllowance.from_dict(value)
