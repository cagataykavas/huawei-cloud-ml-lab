from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from cloud_lab.config import DeploymentConfig
from cloud_lab.model_integrity import verify_model_artifact
from cloud_lab.verify_cli import run


def config_for(content: bytes) -> DeploymentConfig:
    return DeploymentConfig.from_dict(
        {
            "name": "verified-model",
            "environment": "prod",
            "region": "tr-west-1",
            "replicas": 3,
            "model_uri": "obs://models/risk/model.onnx",
            "model_sha256": hashlib.sha256(content).hexdigest(),
            "kms_key_id": "kms-key",
            "database_private": True,
            "database_high_availability": True,
            "backup_retention_days": 14,
            "autoscaling_enabled": True,
            "min_replicas": 3,
            "max_replicas": 10,
            "public_api": True,
        }
    )


def write_config(path: Path, config: DeploymentConfig) -> None:
    path.write_text(json.dumps(config.__dict__), encoding="utf-8")


def test_matching_artifact_is_verified_deterministically(tmp_path: Path):
    content = b"deterministic-model-weights"
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(content)
    config = config_for(content)

    first = verify_model_artifact(config, artifact)
    second = verify_model_artifact(config, artifact)

    assert first.verified is True
    assert first.reasons == ()
    assert first.observed_sha256 == config.model_sha256
    assert first.size_bytes == len(content)
    assert first.verification_id == second.verification_id


def test_digest_mismatch_fails_closed(tmp_path: Path):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"tampered")

    result = verify_model_artifact(config_for(b"approved"), artifact)

    assert result.verified is False
    assert result.reasons == ("sha256_mismatch",)
    assert result.observed_sha256 == hashlib.sha256(b"tampered").hexdigest()


def test_symbolic_link_is_rejected_without_hashing_target(tmp_path: Path):
    target = tmp_path / "target.onnx"
    target.write_bytes(b"approved")
    link = tmp_path / "model.onnx"
    link.symlink_to(target)

    result = verify_model_artifact(config_for(b"approved"), link)

    assert result.verified is False
    assert result.reasons == ("symbolic_link_forbidden",)
    assert result.observed_sha256 is None


@pytest.mark.parametrize(
    ("content", "max_bytes", "reason"),
    [
        (b"", 10, "empty_artifact"),
        (b"123456", 5, "artifact_too_large"),
    ],
)
def test_size_policy_rejects_before_hashing(
    tmp_path: Path, content: bytes, max_bytes: int, reason: str
):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(content)

    result = verify_model_artifact(
        config_for(content or b"approved"), artifact, max_bytes=max_bytes
    )

    assert result.verified is False
    assert reason in result.reasons
    assert result.observed_sha256 is None


def test_non_regular_file_is_rejected(tmp_path: Path):
    result = verify_model_artifact(config_for(b"approved"), tmp_path)

    assert result.verified is False
    assert result.reasons == ("regular_file_required",)


def test_named_pipe_is_rejected_without_blocking(tmp_path: Path):
    pipe = tmp_path / "model.pipe"
    os.mkfifo(pipe)

    result = verify_model_artifact(config_for(b"approved"), pipe)

    assert result.verified is False
    assert result.reasons == ("regular_file_required",)


@pytest.mark.parametrize(
    ("max_bytes", "chunk_bytes"),
    [(0, 1), (10, 0)],
)
def test_invalid_resource_policy_is_rejected(max_bytes: int, chunk_bytes: int):
    with pytest.raises(ValueError):
        verify_model_artifact(
            config_for(b"approved"),
            "unused.onnx",
            max_bytes=max_bytes,
            chunk_bytes=chunk_bytes,
        )


def test_cli_uses_distinct_success_rejection_and_operational_exits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    approved = b"approved-model"
    config = config_for(approved)
    config_path = tmp_path / "config.json"
    artifact = tmp_path / "model.onnx"
    write_config(config_path, config)
    artifact.write_bytes(approved)

    assert run([str(config_path), str(artifact)]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True

    artifact.write_bytes(b"tampered-model")
    assert run([str(config_path), str(artifact)]) == 2
    assert json.loads(capsys.readouterr().out)["reasons"] == ["sha256_mismatch"]

    assert run([str(config_path), str(tmp_path / "missing.onnx")]) == 3
    error = json.loads(capsys.readouterr().err)
    assert error == {
        "error": "ArtifactAccessError",
        "schema_version": "model-artifact-verification/v1",
        "verified": False,
    }


def test_open_descriptor_identity_change_is_detected(tmp_path: Path, monkeypatch):
    content = b"approved-model"
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(content)
    original_fstat = os.fstat
    calls = 0

    def changed_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        value = original_fstat(descriptor)
        if calls == 2:
            fields = list(value)
            fields[6] += 1
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(os, "fstat", changed_fstat)
    result = verify_model_artifact(config_for(content), artifact)

    assert result.verified is False
    assert "artifact_changed_during_verification" in result.reasons
