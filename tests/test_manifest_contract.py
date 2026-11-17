from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from cloud_lab.manifest_contract import ManifestContractError, validate_contract


def load_manifest(path: Path) -> dict:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def manifests() -> tuple[dict, dict, dict]:
    return (
        dict(load_manifest(Path("deploy/cce-deployment.yaml"))),
        dict(load_manifest(Path("deploy/cce-hpa.yaml"))),
        dict(load_manifest(Path("deploy/cce-pdb.yaml"))),
    )


def test_checked_in_manifests_satisfy_contract() -> None:
    validate_contract(*manifests())


def test_rejects_pdb_selector_drift() -> None:
    deployment, hpa, pdb = deepcopy(manifests())
    pdb["spec"]["selector"]["matchLabels"]["app"] = "another-workload"

    with pytest.raises(ManifestContractError, match="PDB selector drifted"):
        validate_contract(deployment, hpa, pdb)


@pytest.mark.parametrize("min_available", [1, 3])
def test_rejects_under_or_over_constrained_disruption_budget(min_available: int) -> None:
    deployment, hpa, pdb = deepcopy(manifests())
    pdb["spec"]["minAvailable"] = min_available

    with pytest.raises(ManifestContractError, match="preserve all but one"):
        validate_contract(deployment, hpa, pdb)


def test_rejects_soft_zone_spread() -> None:
    deployment, hpa, pdb = deepcopy(manifests())
    constraint = deployment["spec"]["template"]["spec"]["topologySpreadConstraints"][0]
    constraint["whenUnsatisfiable"] = "ScheduleAnyway"

    with pytest.raises(ManifestContractError, match="zone spread must fail closed"):
        validate_contract(deployment, hpa, pdb)


def test_rejects_too_few_zone_domains() -> None:
    deployment, hpa, pdb = deepcopy(manifests())
    constraint = deployment["spec"]["template"]["spec"]["topologySpreadConstraints"][0]
    constraint["minDomains"] = 2

    with pytest.raises(ManifestContractError, match="three eligible domains"):
        validate_contract(deployment, hpa, pdb)


@pytest.mark.parametrize("max_unavailable", [-1, 2])
def test_rejects_invalid_rollout_unavailability(max_unavailable: int) -> None:
    deployment, hpa, pdb = deepcopy(manifests())
    deployment["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] = max_unavailable

    with pytest.raises(ManifestContractError, match="at most one replica"):
        validate_contract(deployment, hpa, pdb)


def test_rejects_hpa_below_reviewed_replica_floor() -> None:
    deployment, hpa, pdb = deepcopy(manifests())
    hpa["spec"]["minReplicas"] = 2

    with pytest.raises(ManifestContractError, match="reviewed replica floor"):
        validate_contract(deployment, hpa, pdb)
