from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from cloud_lab.config import DeploymentConfig
from cloud_lab.release_contract import (
    ArtifactError,
    AuditPolicy,
    audit_release_contract,
    load_evidence,
    main,
)

ROOT = Path(__file__).parents[1]
POLICY = AuditPolicy(("swr.example.com/ml/",))


def _evidence() -> tuple[DeploymentConfig, dict, dict]:
    config, deployment, hpa, _ = load_evidence(
        ROOT / "configs/prod.json",
        ROOT / "deploy/cce-deployment.yaml",
        ROOT / "deploy/cce-hpa.yaml",
        POLICY,
    )
    return config, deployment, hpa


def test_repository_release_contract_is_accepted_and_deterministic():
    config, deployment, hpa = _evidence()
    first = audit_release_contract(config, deployment, hpa, POLICY)
    second = audit_release_contract(config, deployment, hpa, POLICY)

    assert first == second
    assert first["status"] == "accepted"
    assert first["findings"] == []
    assert len(first["evidence_sha256"]) == 64
    serialized = json.dumps(first)
    assert config.model_uri not in serialized
    assert config.kms_key_id not in serialized


@pytest.mark.parametrize(
    "path,value,code",
    [
        (("spec", "replicas"), 2, "CAP001"),
        (("spec", "strategy", "rollingUpdate", "maxUnavailable"), 1, "ROL001"),
        (("spec", "template", "spec", "serviceAccountName"), "default", "IAM001"),
        (("spec", "template", "spec", "securityContext", "runAsNonRoot"), False, "SEC001"),
    ],
)
def test_deployment_drift_is_rejected(path, value, code):
    config, deployment, hpa = _evidence()
    current = deployment
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value

    report = audit_release_contract(config, deployment, hpa, POLICY)
    assert report["status"] == "rejected"
    assert code in {finding["code"] for finding in report["findings"]}


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("minReplicas", 2, "CAP002"),
        ("maxReplicas", 99, "CAP003"),
    ],
)
def test_capacity_envelope_must_match_approved_config(field, value, code):
    config, deployment, hpa = _evidence()
    hpa["spec"][field] = value
    report = audit_release_contract(config, deployment, hpa, POLICY)
    assert code in {finding["code"] for finding in report["findings"]}


def test_hpa_must_target_the_audited_deployment():
    config, deployment, hpa = _evidence()
    hpa["spec"]["scaleTargetRef"]["name"] = "other-workload"
    report = audit_release_contract(config, deployment, hpa, POLICY)
    assert "REF004" in {finding["code"] for finding in report["findings"]}


def test_configuration_must_still_pass_blocking_platform_policy():
    config, deployment, hpa = _evidence()
    report = audit_release_contract(
        replace(config, database_private=False), deployment, hpa, POLICY
    )
    assert "CFG001" in {finding["code"] for finding in report["findings"]}


@pytest.mark.parametrize(
    "name,code",
    [("MODEL_URI", "MODEL001"), ("MODEL_SHA256", "MODEL002"), ("KMS_KEY_ID", "ENC001")],
)
def test_runtime_identity_must_match_approved_config(name, code):
    config, deployment, hpa = _evidence()
    env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    next(item for item in env if item["name"] == name)["value"] = "drifted"
    report = audit_release_contract(config, deployment, hpa, POLICY)
    assert code in {finding["code"] for finding in report["findings"]}
    serialized = json.dumps(report)
    assert config.model_uri not in serialized
    assert config.model_sha256 not in serialized
    assert config.kms_key_id not in serialized


@pytest.mark.parametrize(
    "image,code",
    [
        ("swr.example.com/ml/fraud-risk:latest", "IMG001"),
        ("untrusted.example/ml/fraud-risk@sha256:" + "a" * 64, "IMG002"),
    ],
)
def test_container_image_requires_allowed_immutable_digest(image, code):
    config, deployment, hpa = _evidence()
    deployment["spec"]["template"]["spec"]["containers"][0]["image"] = image
    report = audit_release_contract(config, deployment, hpa, POLICY)
    assert code in {finding["code"] for finding in report["findings"]}


def test_selector_drift_and_missing_probe_are_rejected():
    config, deployment, hpa = _evidence()
    deployment["spec"]["template"]["metadata"]["labels"]["app"] = "other"
    del deployment["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]
    codes = {
        item["code"] for item in audit_release_contract(config, deployment, hpa, POLICY)["findings"]
    }
    assert {"REF005", "HLT001"} <= codes


def test_duplicate_or_oversized_evidence_fails_closed(tmp_path):
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("apiVersion: apps/v1\nkind: Deployment\nkind: Pod\n", encoding="utf-8")
    with pytest.raises(ArtifactError, match="duplicate YAML"):
        load_evidence(ROOT / "configs/prod.json", duplicate, ROOT / "deploy/cce-hpa.yaml", POLICY)

    tiny_policy = AuditPolicy(("swr.example.com/",), max_document_bytes=10)
    with pytest.raises(ArtifactError, match="budget"):
        load_evidence(
            ROOT / "configs/prod.json",
            ROOT / "deploy/cce-deployment.yaml",
            ROOT / "deploy/cce-hpa.yaml",
            tiny_policy,
        )


def test_symlink_evidence_fails_closed(tmp_path):
    linked = tmp_path / "deployment.yaml"
    linked.symlink_to(ROOT / "deploy/cce-deployment.yaml")
    with pytest.raises(ArtifactError, match="non-symlink"):
        load_evidence(ROOT / "configs/prod.json", linked, ROOT / "deploy/cce-hpa.yaml", POLICY)


def test_duplicate_json_key_fails_closed(tmp_path):
    duplicate = tmp_path / "config.json"
    duplicate.write_text('{"name":"first","name":"second"}', encoding="utf-8")
    with pytest.raises(ArtifactError, match="duplicate JSON"):
        load_evidence(
            duplicate, ROOT / "deploy/cce-deployment.yaml", ROOT / "deploy/cce-hpa.yaml", POLICY
        )


def test_missing_required_structure_is_malformed():
    config, deployment, hpa = _evidence()
    del deployment["spec"]["strategy"]
    with pytest.raises(ArtifactError, match="missing required"):
        audit_release_contract(config, deployment, hpa, POLICY)


def _cli_args(output: Path) -> list[str]:
    return [
        "--config",
        str(ROOT / "configs/prod.json"),
        "--deployment",
        str(ROOT / "deploy/cce-deployment.yaml"),
        "--hpa",
        str(ROOT / "deploy/cce-hpa.yaml"),
        "--allowed-registry",
        "swr.example.com/ml/",
        "--output",
        str(output),
    ]


def test_cli_writes_accepted_atomic_report(tmp_path):
    output = tmp_path / "nested" / "report.json"
    assert main(_cli_args(output)) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "accepted"
    assert not list(output.parent.glob("*.tmp"))


def test_cli_distinguishes_policy_rejection_and_malformed_input(tmp_path):
    rejected = tmp_path / "rejected.yaml"
    _, deployment, _ = _evidence()
    deployment["spec"]["template"]["spec"]["containers"][0]["image"] = "repo:latest"
    rejected.write_text(yaml.safe_dump(deployment), encoding="utf-8")
    reject_args = _cli_args(tmp_path / "rejected.json")
    reject_args[reject_args.index(str(ROOT / "deploy/cce-deployment.yaml"))] = str(rejected)
    assert main(reject_args) == 3

    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("kind: [", encoding="utf-8")
    malformed_args = _cli_args(tmp_path / "malformed.json")
    malformed_args[malformed_args.index(str(ROOT / "deploy/cce-deployment.yaml"))] = str(malformed)
    assert main(malformed_args) == 2
