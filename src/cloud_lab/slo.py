"""Deterministic multi-window burn-rate evaluation for request telemetry buckets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any


@dataclass(frozen=True)
class BurnRatePolicy:
    name: str
    short_seconds: int
    long_seconds: int
    threshold: float


POLICIES = (
    BurnRatePolicy("fast", short_seconds=300, long_seconds=3600, threshold=14.4),
    BurnRatePolicy("slow", short_seconds=1800, long_seconds=21600, threshold=6.0),
)


@dataclass(frozen=True)
class RequestBucket:
    end: datetime
    requests: int
    errors: int


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed.astimezone(UTC)


def _require_integer(value: Any, field: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")
    return value


def _parse_buckets(values: Any) -> list[RequestBucket]:
    if not isinstance(values, list) or not values:
        raise ValueError("buckets must be a non-empty list")
    buckets: list[RequestBucket] = []
    for index, value in enumerate(values):
        if not isinstance(value, dict) or set(value) != {"end", "requests", "errors"}:
            raise ValueError(
                f"buckets[{index}] must contain exactly end, requests and errors"
            )
        requests = _require_integer(value["requests"], f"buckets[{index}].requests", minimum=0)
        errors = _require_integer(value["errors"], f"buckets[{index}].errors", minimum=0)
        if errors > requests:
            raise ValueError(f"buckets[{index}].errors cannot exceed requests")
        buckets.append(
            RequestBucket(
                end=_parse_timestamp(value["end"], f"buckets[{index}].end"),
                requests=requests,
                errors=errors,
            )
        )
    return buckets


def _validate_coverage(
    buckets: list[RequestBucket], as_of: datetime, bucket_seconds: int
) -> None:
    longest_window = max(policy.long_seconds for policy in POLICIES)
    if longest_window % bucket_seconds:
        raise ValueError("bucket_seconds must divide every evaluation window")
    if any(policy.short_seconds % bucket_seconds for policy in POLICIES):
        raise ValueError("bucket_seconds must divide every evaluation window")
    expected_count = longest_window // bucket_seconds
    if len(buckets) != expected_count:
        raise ValueError(
            f"buckets must provide exactly {expected_count} contiguous intervals ending at as_of"
        )
    expected_end = as_of - timedelta(seconds=longest_window - bucket_seconds)
    for index, bucket in enumerate(buckets):
        if bucket.end != expected_end:
            raise ValueError(
                f"buckets[{index}].end breaks contiguous coverage; expected "
                f"{expected_end.isoformat().replace('+00:00', 'Z')}"
            )
        expected_end += timedelta(seconds=bucket_seconds)


def _window_result(
    buckets: list[RequestBucket], seconds: int, bucket_seconds: int, error_budget: float
) -> dict[str, int | float]:
    selected = buckets[-(seconds // bucket_seconds) :]
    requests = sum(bucket.requests for bucket in selected)
    errors = sum(bucket.errors for bucket in selected)
    error_rate = errors / requests if requests else 0.0
    return {
        "seconds": seconds,
        "requests": requests,
        "errors": errors,
        "error_rate": error_rate,
        "burn_rate": error_rate / error_budget,
    }


def evaluate_slo(evidence: dict[str, Any]) -> dict[str, Any]:
    """Validate bucket coverage and evaluate paired fast/slow burn-rate policies."""

    required = {
        "service",
        "objective",
        "as_of",
        "bucket_seconds",
        "minimum_requests",
        "buckets",
    }
    if not isinstance(evidence, dict) or set(evidence) != required:
        raise ValueError(f"evidence must contain exactly: {', '.join(sorted(required))}")
    service = evidence["service"]
    if not isinstance(service, str) or not service.strip():
        raise ValueError("service must be a non-empty string")
    objective = evidence["objective"]
    if isinstance(objective, bool) or not isinstance(objective, (int, float)):
        raise ValueError("objective must be a number between 0 and 1")
    objective = float(objective)
    if not 0 < objective < 1:
        raise ValueError("objective must be a number between 0 and 1")
    bucket_seconds = _require_integer(evidence["bucket_seconds"], "bucket_seconds", minimum=1)
    minimum_requests = _require_integer(
        evidence["minimum_requests"], "minimum_requests", minimum=1
    )
    as_of = _parse_timestamp(evidence["as_of"], "as_of")
    buckets = _parse_buckets(evidence["buckets"])
    _validate_coverage(buckets, as_of, bucket_seconds)

    error_budget = 1 - objective
    evaluations: list[dict[str, Any]] = []
    for policy in POLICIES:
        short = _window_result(buckets, policy.short_seconds, bucket_seconds, error_budget)
        long = _window_result(buckets, policy.long_seconds, bucket_seconds, error_budget)
        enough_traffic = (
            short["requests"] >= minimum_requests and long["requests"] >= minimum_requests
        )
        alert = bool(
            enough_traffic
            and short["burn_rate"] >= policy.threshold
            and long["burn_rate"] >= policy.threshold
        )
        evaluations.append(
            {
                "policy": policy.name,
                "threshold": policy.threshold,
                "enough_traffic": enough_traffic,
                "alert": alert,
                "short_window": short,
                "long_window": long,
            }
        )

    if any(item["alert"] for item in evaluations):
        status = "alert"
    elif all(item["enough_traffic"] for item in evaluations):
        status = "healthy"
    else:
        status = "insufficient_traffic"
    return {
        "service": service,
        "as_of": as_of.isoformat().replace("+00:00", "Z"),
        "objective": objective,
        "error_budget": error_budget,
        "status": status,
        "evaluations": evaluations,
    }
