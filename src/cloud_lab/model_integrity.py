"""Fail-closed verification for model artifacts downloaded from OBS."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import DeploymentConfig

DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 1024 * 1024
SCHEMA_VERSION = "model-artifact-verification/v1"


class ArtifactAccessError(RuntimeError):
    """The verifier could not safely inspect the requested artifact."""


@dataclass(frozen=True)
class ModelArtifactVerification:
    schema_version: str
    artifact_name: str
    model_uri: str
    expected_sha256: str
    observed_sha256: str | None
    size_bytes: int
    max_bytes: int
    verified: bool
    reasons: tuple[str, ...]
    verification_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_json(values: dict[str, Any]) -> bytes:
    return json.dumps(
        values,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _build_result(
    config: DeploymentConfig,
    path: Path,
    *,
    observed_sha256: str | None,
    size_bytes: int,
    max_bytes: int,
    reasons: tuple[str, ...],
) -> ModelArtifactVerification:
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "artifact_name": path.name,
        "model_uri": config.model_uri,
        "expected_sha256": config.model_sha256.lower(),
        "observed_sha256": observed_sha256,
        "size_bytes": size_bytes,
        "max_bytes": max_bytes,
        "verified": not reasons,
        "reasons": reasons,
    }
    return ModelArtifactVerification(
        **evidence,
        verification_id=hashlib.sha256(_canonical_json(evidence)).hexdigest(),
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _unchanged(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        _same_file(left, right)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def verify_model_artifact(
    config: DeploymentConfig,
    artifact_path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
) -> ModelArtifactVerification:
    """Verify a regular model file against the digest approved in configuration.

    The verifier hashes through one file descriptor, refuses symbolic links, and
    reconciles file identity and metadata before and after the read. It does not
    load the model or trust a filename extension.
    """

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    if chunk_bytes < 1:
        raise ValueError("chunk_bytes must be positive")

    path = Path(artifact_path)
    try:
        path_before = path.lstat()
    except OSError as error:
        raise ArtifactAccessError(f"cannot inspect artifact {path.name!r}") from error

    if stat.S_ISLNK(path_before.st_mode):
        return _build_result(
            config,
            path,
            observed_sha256=None,
            size_bytes=path_before.st_size,
            max_bytes=max_bytes,
            reasons=("symbolic_link_forbidden",),
        )
    if not stat.S_ISREG(path_before.st_mode):
        return _build_result(
            config,
            path,
            observed_sha256=None,
            size_bytes=path_before.st_size,
            max_bytes=max_bytes,
            reasons=("regular_file_required",),
        )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ArtifactAccessError(f"cannot open artifact {path.name!r} safely") from error

    try:
        opened = os.fstat(descriptor)
        reasons: list[str] = []
        if not _same_file(path_before, opened):
            reasons.append("artifact_changed_before_open")
        if not stat.S_ISREG(opened.st_mode):
            reasons.append("regular_file_required")
        if opened.st_size == 0:
            reasons.append("empty_artifact")
        if opened.st_size > max_bytes:
            reasons.append("artifact_too_large")
        if reasons:
            return _build_result(
                config,
                path,
                observed_sha256=None,
                size_bytes=opened.st_size,
                max_bytes=max_bytes,
                reasons=tuple(reasons),
            )

        digest = hashlib.sha256()
        bytes_read = 0
        while block := os.read(descriptor, chunk_bytes):
            bytes_read += len(block)
            if bytes_read > max_bytes:
                reasons.append("artifact_too_large")
                break
            digest.update(block)

        opened_after = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError:
            reasons.append("artifact_changed_during_verification")
        else:
            if not _unchanged(opened, opened_after) or not _same_file(opened_after, path_after):
                reasons.append("artifact_changed_during_verification")
        if bytes_read != opened.st_size:
            reasons.append("artifact_size_changed")

        observed = digest.hexdigest()
        if observed != config.model_sha256.lower():
            reasons.append("sha256_mismatch")
        reasons = list(dict.fromkeys(reasons))
        return _build_result(
            config,
            path,
            observed_sha256=observed,
            size_bytes=bytes_read,
            max_bytes=max_bytes,
            reasons=tuple(reasons),
        )
    finally:
        os.close(descriptor)
