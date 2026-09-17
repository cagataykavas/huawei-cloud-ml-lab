"""FunctionGraph-compatible OBS event normalization boundary."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote_plus


def normalize_obs_event(event: dict[str, Any]) -> list[dict[str, str]]:
    records = event.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("event requires a non-empty records list")
    jobs: list[dict[str, str]] = []
    for index, record in enumerate(records):
        try:
            bucket = record["obs"]["bucket"]["name"]
            key = unquote_plus(record["obs"]["object"]["key"])
            event_name = record["eventName"]
        except (KeyError, TypeError) as error:
            raise ValueError(f"record {index} has an invalid OBS event shape") from error
        if not all(isinstance(value, str) and value for value in (bucket, key, event_name)):
            raise ValueError(f"record {index} contains empty OBS fields")
        jobs.append(
            {
                "source_uri": f"obs://{bucket}/{key}",
                "event_name": event_name,
                "job_key": f"{bucket}:{key}:{event_name}",
            }
        )
    return jobs


def handler(event: dict[str, Any], context: object) -> dict[str, Any]:
    del context
    jobs = normalize_obs_event(event)
    return {"statusCode": 202, "body": {"accepted": len(jobs), "jobs": jobs}}
