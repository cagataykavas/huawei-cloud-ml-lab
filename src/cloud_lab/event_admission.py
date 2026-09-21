"""Idempotent admission boundary for at-least-once OBS event delivery."""

from __future__ import annotations

import hashlib
import math
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any, Protocol
from urllib.parse import unquote_plus


class ClaimStore(Protocol):
    """Storage boundary implemented with an atomic create-if-absent operation."""

    def claim(self, key: str, expires_at: float) -> bool:
        """Return true only when this call atomically creates the claim."""


@dataclass(frozen=True)
class AdmissionPolicy:
    claim_ttl_seconds: int = 86_400
    max_records: int = 100
    allowed_events: tuple[str, ...] = ("ObjectCreated:Put", "ObjectCreated:CompleteMultipartUpload")


@dataclass(frozen=True)
class DeliveryDecision:
    event_id: str
    source_uri: str
    event_name: str
    object_identity: str
    decision: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class InMemoryClaimStore:
    """Thread-safe reference store for tests and single-process development."""

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        import time

        self._clock = clock or time.time
        self._claims: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, key: str, expires_at: float) -> bool:
        with self._lock:
            now = self._clock()
            self._claims = {item: expiry for item, expiry in self._claims.items() if expiry > now}
            if key in self._claims:
                return False
            self._claims[key] = expires_at
            return True


def _validate_policy(policy: AdmissionPolicy) -> None:
    if policy.claim_ttl_seconds < 1:
        raise ValueError("claim_ttl_seconds must be positive")
    if policy.max_records < 1:
        raise ValueError("max_records must be positive")
    if not policy.allowed_events or any(not value for value in policy.allowed_events):
        raise ValueError("allowed_events must contain non-empty event names")


def _read_record(record: object, index: int) -> tuple[str, str, str, str]:
    try:
        event_name = record["eventName"]
        bucket = record["obs"]["bucket"]["name"]
        object_data = record["obs"]["object"]
        key = unquote_plus(object_data["key"])
        identity = object_data.get("versionId") or object_data.get("eTag")
    except (AttributeError, KeyError, TypeError) as error:
        raise ValueError(f"record {index} has an invalid OBS event shape") from error
    values = (event_name, bucket, key, identity)
    if not all(isinstance(value, str) and value.strip() for value in values):
        raise ValueError(f"record {index} requires non-empty event, bucket, key and versionId/eTag")
    return event_name, bucket, key, identity


def admit_obs_event(
    event: dict[str, Any],
    store: ClaimStore,
    *,
    now: float,
    policy: AdmissionPolicy | None = None,
) -> dict[str, object]:
    """Claim OBS deliveries once and return deterministic, JSON-ready evidence.

    Production stores must implement ``claim`` as one atomic conditional write.
    A read followed by a write is not sufficient under concurrent delivery.
    """
    policy = policy or AdmissionPolicy()
    _validate_policy(policy)
    if not math.isfinite(now) or now < 0:
        raise ValueError("now must be a non-negative finite timestamp")
    records = event.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("event requires a non-empty records list")
    if len(records) > policy.max_records:
        raise ValueError(f"event exceeds max_records={policy.max_records}")

    prepared: list[tuple[str, str, str, str, str]] = []
    batch_ids: set[str] = set()
    for index, record in enumerate(records):
        event_name, bucket, key, identity = _read_record(record, index)
        if event_name not in policy.allowed_events:
            raise ValueError(f"record {index} event is not allowed: {event_name}")
        canonical = "\n".join((bucket, key, event_name, identity))
        event_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if event_id in batch_ids:
            raise ValueError(f"duplicate delivery in event batch: {event_id}")
        batch_ids.add(event_id)
        prepared.append((event_id, f"obs://{bucket}/{key}", event_name, identity, key))

    decisions: list[DeliveryDecision] = []
    expires_at = now + policy.claim_ttl_seconds
    for event_id, source_uri, event_name, identity, _ in prepared:
        accepted = store.claim(event_id, expires_at)
        decisions.append(
            DeliveryDecision(
                event_id=event_id,
                source_uri=source_uri,
                event_name=event_name,
                object_identity=identity,
                decision="accepted" if accepted else "duplicate",
                reason="claim_created" if accepted else "claim_exists",
            )
        )

    return {
        "schema_version": 1,
        "accepted": sum(item.decision == "accepted" for item in decisions),
        "duplicates": sum(item.decision == "duplicate" for item in decisions),
        "claim_expires_at": expires_at,
        "decisions": [item.to_dict() for item in decisions],
    }
