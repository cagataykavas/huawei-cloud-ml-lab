import json

import pytest

from cloud_lab.event_admission import AdmissionPolicy, InMemoryClaimStore, admit_obs_event


def obs_event(*, identity="etag-1", event_name="ObjectCreated:Put"):
    return {
        "records": [
            {
                "eventName": event_name,
                "obs": {
                    "bucket": {"name": "models"},
                    "object": {"key": "risk%2Fv1.onnx", "eTag": identity},
                },
            }
        ]
    }


def test_claims_delivery_once_and_returns_json_ready_evidence():
    store = InMemoryClaimStore(clock=lambda: 100.0)

    first = admit_obs_event(obs_event(), store, now=100.0)
    replay = admit_obs_event(obs_event(), store, now=101.0)

    assert first["accepted"] == 1
    assert first["decisions"][0]["source_uri"] == "obs://models/risk/v1.onnx"
    assert replay["duplicates"] == 1
    assert replay["decisions"][0]["reason"] == "claim_exists"
    json.dumps(first)


def test_new_object_identity_is_a_distinct_delivery():
    store = InMemoryClaimStore(clock=lambda: 100.0)
    first = admit_obs_event(obs_event(identity="etag-1"), store, now=100.0)
    second = admit_obs_event(obs_event(identity="etag-2"), store, now=101.0)

    assert first["decisions"][0]["event_id"] != second["decisions"][0]["event_id"]
    assert second["accepted"] == 1


def test_expired_claim_can_be_reprocessed():
    current = [100.0]
    store = InMemoryClaimStore(clock=lambda: current[0])
    policy = AdmissionPolicy(claim_ttl_seconds=10)
    admit_obs_event(obs_event(), store, now=100.0, policy=policy)
    current[0] = 111.0

    assert admit_obs_event(obs_event(), store, now=111.0, policy=policy)["accepted"] == 1


def test_rejects_duplicate_delivery_inside_one_batch_before_claiming():
    event = obs_event()
    event["records"].append(event["records"][0])

    with pytest.raises(ValueError, match="duplicate delivery"):
        admit_obs_event(event, InMemoryClaimStore(), now=100.0)


@pytest.mark.parametrize(
    ("event", "message"),
    [
        ({}, "non-empty records"),
        (obs_event(identity=""), "requires non-empty"),
        (obs_event(event_name="ObjectRemoved:Delete"), "not allowed"),
        (
            {
                "records": [
                    {
                        "eventName": "ObjectCreated:Put",
                        "obs": {"bucket": {"name": "models"}, "object": {"key": "x"}},
                    }
                ]
            },
            "requires non-empty",
        ),
    ],
)
def test_rejects_unverifiable_or_unsupported_events(event, message):
    with pytest.raises(ValueError, match=message):
        admit_obs_event(event, InMemoryClaimStore(), now=100.0)


def test_enforces_batch_limit_and_timestamp_validation():
    event = obs_event()
    event["records"].append(
        {
            "eventName": "ObjectCreated:Put",
            "obs": {
                "bucket": {"name": "models"},
                "object": {"key": "other.onnx", "eTag": "etag-2"},
            },
        }
    )
    with pytest.raises(ValueError, match="max_records"):
        admit_obs_event(
            event, InMemoryClaimStore(), now=100.0, policy=AdmissionPolicy(max_records=1)
        )
    with pytest.raises(ValueError, match="now must"):
        admit_obs_event(obs_event(), InMemoryClaimStore(), now=float("nan"))
