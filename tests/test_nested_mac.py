import pytest

from app.security import make_mac, verify_mac
from app.nested_mac import (
    make_child_manifest_digest,
    canonical_aggregate_payload,
    make_aggregate_mac,
    verify_aggregate_mac,
)


def sample_records():
    return [
        {
            "meter_id": "METER-001",
            "sequence_no": 1,
            "child_mac": "mac-001",
            "chain_hash": "hash-001",
        },
        {
            "meter_id": "METER-002",
            "sequence_no": 1,
            "child_mac": "mac-002",
            "chain_hash": "hash-002",
        },
    ]


def test_individual_meter_mac():
    secret = b"meter-secret"
    message = b"METER-001|1|100"

    mac = make_mac(secret, message)

    assert verify_mac(secret, message, mac)


def test_invalid_individual_mac():
    secret = b"meter-secret"

    assert not verify_mac(
        secret,
        b"METER-001|1|100",
        "invalid-mac"
    )


def test_child_manifest_digest():
    records = sample_records()

    digest = make_child_manifest_digest(records)

    assert len(digest) == 64
    assert digest == make_child_manifest_digest(records)


def test_parent_aggregate_mac():
    secret = b"aggregator-secret"
    digest = make_child_manifest_digest(sample_records())

    payload = canonical_aggregate_payload(
        "NEIGHBORHOOD-01",
        "BATCH-001",
        2,
        300,
        digest,
    )

    mac = make_aggregate_mac(secret, payload)

    assert verify_aggregate_mac(secret, payload, mac)


def test_tampered_aggregate_rejected():
    secret = b"aggregator-secret"
    digest = make_child_manifest_digest(sample_records())

    original = canonical_aggregate_payload(
        "NEIGHBORHOOD-01", "BATCH-001", 2, 300, digest
    )

    tampered = canonical_aggregate_payload(
        "NEIGHBORHOOD-01", "BATCH-001", 2, 500, digest
    )

    mac = make_aggregate_mac(secret, original)

    assert not verify_aggregate_mac(secret, tampered, mac)


def test_child_evidence_change_changes_digest():
    records = sample_records()
    original_digest = make_child_manifest_digest(records)

    records[0]["child_mac"] = "changed-mac"

    assert make_child_manifest_digest(records) != original_digest
