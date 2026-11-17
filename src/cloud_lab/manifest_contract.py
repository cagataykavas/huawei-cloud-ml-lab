"""Cross-resource availability and security contract for rendered CCE manifests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class ManifestContractError(ValueError):
    """Raised when a rendered CCE manifest violates the reviewed contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestContractError(message)


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"{name} must be a mapping")
    return value


def _integer(value: object, name: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), f"{name} must be an integer")
    return value


def _selected_labels(resource: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    spec = _mapping(resource.get("spec"), f"{name}.spec")
    selector = _mapping(spec.get("selector"), f"{name}.spec.selector")
    labels = _mapping(selector.get("matchLabels"), f"{name}.spec.selector.matchLabels")
    _require(bool(labels), f"{name} selector must not be empty")
    return labels


def validate_contract(
    deployment: Mapping[str, Any],
    hpa: Mapping[str, Any],
    pdb: Mapping[str, Any],
) -> None:
    """Validate one CCE Deployment/HPA/PDB availability and security contract."""

    _require(deployment.get("apiVersion") == "apps/v1", "Deployment must use apps/v1")
    _require(deployment.get("kind") == "Deployment", "expected a Deployment")
    deployment_spec = _mapping(deployment.get("spec"), "Deployment.spec")
    replicas = _integer(deployment_spec.get("replicas"), "Deployment.spec.replicas")
    _require(replicas >= 3, "Deployment requires at least three replicas")

    deployment_labels = _selected_labels(deployment, "Deployment")
    template = _mapping(deployment_spec.get("template"), "Deployment.spec.template")
    pod_metadata = _mapping(template.get("metadata"), "Deployment.spec.template.metadata")
    pod_labels = _mapping(pod_metadata.get("labels"), "Deployment pod labels")
    _require(
        deployment_labels.items() <= pod_labels.items(),
        "Deployment selector must match pod template labels",
    )

    strategy = _mapping(deployment_spec.get("strategy"), "Deployment.spec.strategy")
    _require(strategy.get("type") == "RollingUpdate", "Deployment requires RollingUpdate")
    rolling = _mapping(strategy.get("rollingUpdate"), "Deployment rollingUpdate")
    max_unavailable = _integer(rolling.get("maxUnavailable"), "maxUnavailable")
    max_surge = _integer(rolling.get("maxSurge"), "maxSurge")
    _require(
        0 <= max_unavailable <= 1,
        "rolling update may make at most one replica unavailable",
    )
    _require(max_surge >= 1, "rolling update requires surge capacity")

    pod_spec = _mapping(template.get("spec"), "Deployment pod spec")
    pod_security = _mapping(pod_spec.get("securityContext"), "pod securityContext")
    _require(pod_security.get("runAsNonRoot") is True, "pods must run as non-root")
    containers = pod_spec.get("containers")
    _require(
        isinstance(containers, list) and len(containers) == 1, "expected exactly one container"
    )
    container = _mapping(containers[0], "container")
    container_security = _mapping(container.get("securityContext"), "container securityContext")
    _require(
        container_security.get("allowPrivilegeEscalation") is False,
        "privilege escalation must be disabled",
    )
    _require(
        container_security.get("readOnlyRootFilesystem") is True,
        "container root filesystem must be read-only",
    )
    resources = _mapping(container.get("resources"), "container resources")
    _require(bool(resources.get("requests")), "resource requests are required")
    _require(bool(resources.get("limits")), "resource limits are required")
    _require(bool(container.get("readinessProbe")), "readiness probe is required")
    _require(bool(container.get("livenessProbe")), "liveness probe is required")

    spread = pod_spec.get("topologySpreadConstraints")
    _require(isinstance(spread, list), "topologySpreadConstraints must be a list")
    zone_constraints = [
        _mapping(item, "topology spread constraint")
        for item in spread
        if isinstance(item, Mapping) and item.get("topologyKey") == "topology.kubernetes.io/zone"
    ]
    _require(len(zone_constraints) == 1, "exactly one zone-spread constraint is required")
    zone = zone_constraints[0]
    _require(zone.get("whenUnsatisfiable") == "DoNotSchedule", "zone spread must fail closed")
    _require(_integer(zone.get("maxSkew"), "zone maxSkew") == 1, "zone maxSkew must be one")
    _require(
        _integer(zone.get("minDomains"), "zone minDomains") >= 3,
        "zone spread requires at least three eligible domains",
    )
    zone_selector = _mapping(zone.get("labelSelector"), "zone labelSelector")
    _require(
        zone_selector.get("matchLabels") == deployment_labels,
        "zone spread selector must match the Deployment selector",
    )

    _require(pdb.get("apiVersion") == "policy/v1", "PDB must use policy/v1")
    _require(pdb.get("kind") == "PodDisruptionBudget", "expected a PodDisruptionBudget")
    _require(_selected_labels(pdb, "PDB") == deployment_labels, "PDB selector drifted")
    pdb_spec = _mapping(pdb.get("spec"), "PDB.spec")
    min_available = _integer(pdb_spec.get("minAvailable"), "PDB minAvailable")
    _require(
        min_available == replicas - 1,
        "PDB must preserve all but one desired replica during voluntary disruption",
    )

    _require(hpa.get("apiVersion") == "autoscaling/v2", "HPA must use autoscaling/v2")
    _require(hpa.get("kind") == "HorizontalPodAutoscaler", "expected an HPA")
    hpa_spec = _mapping(hpa.get("spec"), "HPA.spec")
    target = _mapping(hpa_spec.get("scaleTargetRef"), "HPA scaleTargetRef")
    deployment_name = _mapping(deployment.get("metadata"), "Deployment.metadata").get("name")
    _require(
        target.get("apiVersion") == "apps/v1"
        and target.get("kind") == "Deployment"
        and target.get("name") == deployment_name,
        "HPA target must be the reviewed Deployment",
    )
    hpa_min = _integer(hpa_spec.get("minReplicas"), "HPA minReplicas")
    hpa_max = _integer(hpa_spec.get("maxReplicas"), "HPA maxReplicas")
    _require(hpa_min >= replicas, "HPA minimum cannot reduce the reviewed replica floor")
    _require(hpa_max > hpa_min, "HPA maximum must exceed its minimum")
