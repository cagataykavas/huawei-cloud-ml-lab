"""Fail-closed reconciliation of an approved ML plan and rendered CCE manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import DeploymentConfig
from .policies import validate

SCHEMA_VERSION = "cce-release-contract/v1"
IMAGE_PATTERN = re.compile(r"^(?P<repository>[^@]+)@sha256:(?P<digest>[0-9a-f]{64})$")


class ArtifactError(ValueError):
    """Raised when evidence cannot be interpreted safely."""


@dataclass(frozen=True)
class AuditPolicy:
    allowed_registry_prefixes: tuple[str, ...]
    max_document_bytes: int = 128 * 1024

    def __post_init__(self) -> None:
        if not self.allowed_registry_prefixes or any(
            not prefix or "://" in prefix for prefix in self.allowed_registry_prefixes
        ):
            raise ValueError("allowed registry prefixes must be non-empty image-name prefixes")
        if not 1 <= self.max_document_bytes <= 1024 * 1024:
            raise ValueError("max_document_bytes must be between 1 byte and 1 MiB")


@dataclass(frozen=True)
class Finding:
    code: str
    location: str
    message: str


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in mapping:
            raise ArtifactError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=False)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _read_bounded(path: Path, limit: int) -> tuple[bytes, str]:
    def fingerprint(value: os.stat_result) -> tuple[int, int, int, int]:
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns

    before = path.stat(follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ArtifactError(f"{path.name} must be a regular, non-symlink file")
    if before.st_size > limit:
        raise ArtifactError(f"{path.name} exceeds the {limit}-byte document budget")
    payload = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    if len(payload) != before.st_size or fingerprint(before) != fingerprint(after):
        raise ArtifactError(f"{path.name} changed while it was being read")
    return payload, hashlib.sha256(payload).hexdigest()


def _reject_duplicate_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in pairs:
        if key in values:
            raise ArtifactError(f"duplicate JSON key: {key}")
        values[key] = value
    return values


def _reject_constant(value: str) -> None:
    raise ArtifactError(f"non-finite JSON value: {value}")


def load_evidence(
    config_path: Path,
    deployment_path: Path,
    hpa_path: Path,
    policy: AuditPolicy,
) -> tuple[DeploymentConfig, dict[str, Any], dict[str, Any], dict[str, str]]:
    config_bytes, config_digest = _read_bounded(config_path, policy.max_document_bytes)
    deployment_bytes, deployment_digest = _read_bounded(deployment_path, policy.max_document_bytes)
    hpa_bytes, hpa_digest = _read_bounded(hpa_path, policy.max_document_bytes)
    try:
        config_values = json.loads(
            config_bytes,
            object_pairs_hook=_reject_duplicate_json,
            parse_constant=_reject_constant,
        )
        deployment = yaml.load(deployment_bytes, Loader=_UniqueKeyLoader)
        hpa = yaml.load(hpa_bytes, Loader=_UniqueKeyLoader)
    except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise ArtifactError("evidence contains malformed JSON or YAML") from error
    if not isinstance(config_values, dict):
        raise ArtifactError("configuration root must be an object")
    if not isinstance(deployment, dict) or not isinstance(hpa, dict):
        raise ArtifactError("manifest roots must be mappings")
    return (
        DeploymentConfig.from_dict(config_values),
        deployment,
        hpa,
        {
            "config_sha256": config_digest,
            "deployment_sha256": deployment_digest,
            "hpa_sha256": hpa_digest,
        },
    )


def _required(values: dict[str, Any], path: str) -> Any:
    current: Any = values
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ArtifactError(f"missing required manifest field: {path}")
        current = current[part]
    return current


def _environment(container: dict[str, Any]) -> dict[str, str]:
    raw = container.get("env")
    if not isinstance(raw, list):
        raise ArtifactError("container.env must be a list")
    environment: dict[str, str] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != {"name", "value"}:
            raise ArtifactError(
                f"container.env[{index}] must contain literal name and value fields"
            )
        name, value = item["name"], item["value"]
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or not name
            or name in environment
        ):
            raise ArtifactError(f"container.env[{index}] is duplicate or invalid")
        environment[name] = value
    return environment


def audit_release_contract(
    config: DeploymentConfig,
    deployment: dict[str, Any],
    hpa: dict[str, Any],
    policy: AuditPolicy,
    source_digests: dict[str, str] | None = None,
) -> dict[str, Any]:
    if (
        _required(deployment, "apiVersion") != "apps/v1"
        or _required(deployment, "kind") != "Deployment"
    ):
        raise ArtifactError("deployment must be an apps/v1 Deployment")
    if (
        _required(hpa, "apiVersion") != "autoscaling/v2"
        or _required(hpa, "kind") != "HorizontalPodAutoscaler"
    ):
        raise ArtifactError("HPA must be an autoscaling/v2 HorizontalPodAutoscaler")
    deployment_name = _required(deployment, "metadata.name")
    hpa_name = _required(hpa, "metadata.name")
    containers = _required(deployment, "spec.template.spec.containers")
    if not isinstance(deployment_name, str) or not deployment_name:
        raise ArtifactError("deployment metadata.name must be a non-empty string")
    if not isinstance(hpa_name, str) or not hpa_name:
        raise ArtifactError("HPA metadata.name must be a non-empty string")
    if (
        not isinstance(containers, list)
        or len(containers) != 1
        or not isinstance(containers[0], dict)
    ):
        raise ArtifactError("deployment must contain exactly one auditable container")
    container = containers[0]
    environment = _environment(container)
    findings: list[Finding] = []

    config_errors = sorted(item.code for item in validate(config) if item.severity == "error")
    if config_errors:
        findings.append(
            Finding(
                "CFG001",
                "config",
                f"configuration has blocking policy findings: {','.join(config_errors)}",
            )
        )

    def require_equal(code: str, location: str, observed: Any, expected: Any) -> None:
        if observed != expected:
            findings.append(
                Finding(code, location, "observed value does not match approved configuration")
            )

    require_equal(
        "CAP001",
        "deployment.spec.replicas",
        _required(deployment, "spec.replicas"),
        config.replicas,
    )
    require_equal(
        "CAP002", "hpa.spec.minReplicas", _required(hpa, "spec.minReplicas"), config.min_replicas
    )
    require_equal(
        "CAP003", "hpa.spec.maxReplicas", _required(hpa, "spec.maxReplicas"), config.max_replicas
    )
    require_equal("REF001", "hpa.metadata.name", hpa_name, deployment_name)
    require_equal(
        "REF002",
        "hpa.spec.scaleTargetRef.apiVersion",
        _required(hpa, "spec.scaleTargetRef.apiVersion"),
        "apps/v1",
    )
    require_equal(
        "REF003",
        "hpa.spec.scaleTargetRef.kind",
        _required(hpa, "spec.scaleTargetRef.kind"),
        "Deployment",
    )
    require_equal(
        "REF004",
        "hpa.spec.scaleTargetRef.name",
        _required(hpa, "spec.scaleTargetRef.name"),
        deployment_name,
    )
    require_equal(
        "MODEL001", "container.env.MODEL_URI", environment.get("MODEL_URI"), config.model_uri
    )
    require_equal(
        "MODEL002",
        "container.env.MODEL_SHA256",
        environment.get("MODEL_SHA256"),
        config.model_sha256,
    )
    require_equal(
        "ENC001", "container.env.KMS_KEY_ID", environment.get("KMS_KEY_ID"), config.kms_key_id
    )

    image = container.get("image")
    match = IMAGE_PATTERN.fullmatch(image) if isinstance(image, str) else None
    if match is None:
        findings.append(
            Finding("IMG001", "container.image", "image must use an immutable sha256 digest")
        )
    elif not any(
        match.group("repository").startswith(prefix) for prefix in policy.allowed_registry_prefixes
    ):
        findings.append(
            Finding(
                "IMG002", "container.image", "image repository is outside the allowed SWR prefixes"
            )
        )

    selector = _required(deployment, "spec.selector.matchLabels")
    labels = _required(deployment, "spec.template.metadata.labels")
    if not isinstance(selector, dict) or not selector or not isinstance(labels, dict):
        raise ArtifactError("deployment selector and pod labels must be non-empty mappings")
    if any(labels.get(key) != value for key, value in selector.items()):
        findings.append(
            Finding("REF005", "deployment.spec.selector", "selector must match pod labels")
        )

    pod_spec = _required(deployment, "spec.template.spec")
    service_account = pod_spec.get("serviceAccountName")
    if not isinstance(service_account, str) or not service_account or service_account == "default":
        findings.append(
            Finding("IAM001", "pod.serviceAccountName", "a dedicated service account is required")
        )
    pod_security = pod_spec.get("securityContext", {})
    container_security = container.get("securityContext", {})
    controls = (
        ("SEC001", "pod.securityContext.runAsNonRoot", pod_security.get("runAsNonRoot"), True),
        (
            "SEC002",
            "pod.securityContext.seccompProfile.type",
            pod_security.get("seccompProfile", {}).get("type"),
            "RuntimeDefault",
        ),
        (
            "SEC003",
            "container.securityContext.allowPrivilegeEscalation",
            container_security.get("allowPrivilegeEscalation"),
            False,
        ),
        (
            "SEC004",
            "container.securityContext.readOnlyRootFilesystem",
            container_security.get("readOnlyRootFilesystem"),
            True,
        ),
        (
            "SEC005",
            "container.securityContext.capabilities.drop",
            container_security.get("capabilities", {}).get("drop"),
            ["ALL"],
        ),
        (
            "ROL001",
            "deployment.spec.strategy.rollingUpdate.maxUnavailable",
            _required(deployment, "spec.strategy.rollingUpdate.maxUnavailable"),
            0,
        ),
    )
    for code, location, observed, expected in controls:
        require_equal(code, location, observed, expected)
    for probe in ("readinessProbe", "livenessProbe"):
        if not isinstance(container.get(probe), dict):
            findings.append(Finding("HLT001", f"container.{probe}", f"{probe} is required"))
    resources = container.get("resources", {})
    if not isinstance(resources.get("requests"), dict) or not isinstance(
        resources.get("limits"), dict
    ):
        findings.append(
            Finding("RES001", "container.resources", "requests and limits are required")
        )

    findings.sort(key=lambda item: (item.code, item.location))
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "accepted" if not findings else "rejected",
        "deployment": {
            "name": deployment_name,
            "environment": config.environment,
            "region": config.region,
        },
        "policy": {
            "allowed_registry_prefix_count": len(policy.allowed_registry_prefixes),
            "allowed_registry_prefixes_sha256": hashlib.sha256(
                json.dumps(policy.allowed_registry_prefixes, separators=(",", ":")).encode()
            ).hexdigest(),
            "max_document_bytes": policy.max_document_bytes,
        },
        "sources": source_digests or {},
        "findings": [asdict(item) for item in findings],
        "checks": {"performed": 23, "failed": len(findings)},
        "limitations": [
            "The audit reconciles supplied artifacts; it does not query live CCE, SWR, OBS, "
            "IAM, or KMS state.",
            "A digest-pinned image is not proof of image provenance, signature validity, "
            "or vulnerability status.",
        ],
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    report["evidence_sha256"] = hashlib.sha256(canonical).hexdigest()
    return report


def _atomic_write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit an approved Huawei CCE release contract")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--hpa", type=Path, required=True)
    parser.add_argument("--allowed-registry", action="append", required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts/release-contract.json"))
    values = parser.parse_args(argv)
    try:
        policy = AuditPolicy(tuple(sorted(set(values.allowed_registry))))
        config, deployment, hpa, digests = load_evidence(
            values.config, values.deployment, values.hpa, policy
        )
        report = audit_release_contract(config, deployment, hpa, policy, digests)
        _atomic_write(values.output, report)
    except (ArtifactError, OSError, TypeError, ValueError) as error:
        print(json.dumps({"status": "malformed", "error": str(error)}))
        return 2
    print(json.dumps({"status": report["status"], "evidence_sha256": report["evidence_sha256"]}))
    return 0 if report["status"] == "accepted" else 3


if __name__ == "__main__":
    raise SystemExit(main())
