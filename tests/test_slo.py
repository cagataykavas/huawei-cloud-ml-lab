from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest

from cloud_lab.slo import evaluate_slo

AS_OF = datetime(2026, 1, 1, 6, tzinfo=UTC)


def evidence(*, errors: list[int] | None = None, requests: int = 1000):
    error_counts = errors or [0] * 72
    start = AS_OF - timedelta(hours=6) + timedelta(minutes=5)
    return {
        "service": "fraud-risk-inference",
        "objective": 0.999,
        "as_of": AS_OF.isoformat().replace("+00:00", "Z"),
        "bucket_seconds": 300,
        "minimum_requests": 100,
        "buckets": [
            {
                "end": (start + timedelta(minutes=5 * index))
                .isoformat()
                .replace("+00:00", "Z"),
                "requests": requests,
                "errors": count,
            }
            for index, count in enumerate(error_counts)
        ],
    }


def test_healthy_telemetry_evaluates_both_policies():
    report = evaluate_slo(evidence())
    assert report["status"] == "healthy"
    assert [item["policy"] for item in report["evaluations"]] == ["fast", "slow"]
    assert all(item["alert"] is False for item in report["evaluations"])


def test_fast_alert_requires_both_windows_to_burn():
    report = evaluate_slo(evidence(errors=[0] * 60 + [20] * 12))
    fast = report["evaluations"][0]
    assert report["status"] == "alert"
    assert fast["short_window"]["burn_rate"] == pytest.approx(20.0)
    assert fast["long_window"]["burn_rate"] == pytest.approx(20.0)
    assert fast["alert"] is True


def test_isolated_spike_does_not_trigger_multiwindow_alert():
    report = evaluate_slo(evidence(errors=[0] * 71 + [20]))
    fast = report["evaluations"][0]
    assert fast["short_window"]["burn_rate"] == pytest.approx(20.0)
    assert fast["long_window"]["burn_rate"] < fast["threshold"]
    assert report["status"] == "healthy"


def test_slow_burn_is_detected_without_fast_breach():
    report = evaluate_slo(evidence(errors=[10] * 72))
    fast, slow = report["evaluations"]
    assert fast["alert"] is False
    assert slow["alert"] is True
    assert report["status"] == "alert"


def test_low_volume_is_not_reported_as_healthy():
    report = evaluate_slo(evidence(requests=1))
    assert report["status"] == "insufficient_traffic"
    assert all(item["enough_traffic"] is False for item in report["evaluations"])


def test_rejects_telemetry_gaps_and_impossible_counts():
    missing = evidence()
    missing["buckets"].pop(10)
    with pytest.raises(ValueError, match="exactly 72"):
        evaluate_slo(missing)

    impossible = evidence()
    impossible["buckets"][0]["errors"] = 1001
    with pytest.raises(ValueError, match="cannot exceed"):
        evaluate_slo(impossible)


def test_cli_uses_stable_alert_exit_code(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence(errors=[10] * 72)), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "cloud_lab.slo_cli", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3
    assert json.loads(result.stdout)["status"] == "alert"
