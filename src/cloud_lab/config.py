"""Typed deployment configuration loaded from portable JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DeploymentConfig:
    name: str
    environment: str
    region: str
    replicas: int
    model_uri: str
    model_sha256: str
    kms_key_id: str | None
    database_private: bool
    database_high_availability: bool
    backup_retention_days: int
    autoscaling_enabled: bool
    min_replicas: int
    max_replicas: int
    public_api: bool

    def __post_init__(self) -> None:
        string_fields = ("name", "environment", "region", "model_uri", "model_sha256")
        for field_name in string_fields:
            if not isinstance(getattr(self, field_name), str):
                raise TypeError(f"{field_name} must be a string")

        integer_fields = (
            "replicas",
            "backup_retention_days",
            "min_replicas",
            "max_replicas",
        )
        for field_name in integer_fields:
            if type(getattr(self, field_name)) is not int:
                raise TypeError(f"{field_name} must be an integer")

        boolean_fields = (
            "database_private",
            "database_high_availability",
            "autoscaling_enabled",
            "public_api",
        )
        for field_name in boolean_fields:
            if type(getattr(self, field_name)) is not bool:
                raise TypeError(f"{field_name} must be a boolean")

        if self.kms_key_id is not None and (
            not isinstance(self.kms_key_id, str) or not self.kms_key_id.strip()
        ):
            raise TypeError("kms_key_id must be null or a non-empty string")
        if not self.name.strip() or not self.region.strip():
            raise ValueError("name and region are required")
        if self.environment not in {"dev", "staging", "prod"}:
            raise ValueError("environment must be dev, staging or prod")
        if self.replicas < 1 or self.min_replicas < 1:
            raise ValueError("replica counts must be positive")
        if self.max_replicas < self.min_replicas:
            raise ValueError("max_replicas must be >= min_replicas")
        if not self.min_replicas <= self.replicas <= self.max_replicas:
            raise ValueError("replicas must be within the min_replicas/max_replicas envelope")
        if self.backup_retention_days < 0:
            raise ValueError("backup_retention_days must be non-negative")
        if not self.model_uri.startswith("obs://"):
            raise ValueError("model_uri must use obs://")
        if len(self.model_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.model_sha256
        ):
            raise ValueError("model_sha256 must be a canonical lowercase SHA-256 digest")

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> DeploymentConfig:
        expected = {field.name for field in cls.__dataclass_fields__.values()}
        unknown = sorted(values.keys() - expected)
        missing = sorted(expected - values.keys())
        if unknown:
            raise ValueError(f"unknown configuration keys: {unknown}")
        if missing:
            raise ValueError(f"missing configuration keys: {missing}")
        return cls(**values)

    @classmethod
    def from_json(cls, path: str | Path) -> DeploymentConfig:
        with Path(path).open(encoding="utf-8") as stream:
            values = json.load(stream)
        if not isinstance(values, dict):
            raise ValueError("configuration root must be an object")
        return cls.from_dict(values)
