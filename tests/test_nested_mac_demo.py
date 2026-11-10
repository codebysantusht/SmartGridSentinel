from app.security import make_mac, verify_mac
from app.nested_mac import (
    make_child_manifest_digest,
    canonical_aggregate_payload,
    make_aggregate_mac,
    verify_aggregate_mac,
)

# Three smart meters
meter_secrets = {
    "METER-001": b"meter-secret-001",
    "METER-002": b"meter-secret-002",
    "METER-003": b"meter-secret-003",
}

readings = [
    {"meter_id": "METER-001", "sequence_no": 1, "consumption_wh": 100},
    {"meter_id": "METER-002", "sequence_no": 1, "consumption_wh": 200},
    {"meter_id": "METER-003", "sequence_no": 1, "consumption_wh": 150},
]

# Generate and verify individual MACs
records = []

for reading in readings:
    message = (
        f'{reading["meter_id"]}|'
        f'{reading["sequence_no"]}|'
        f'{reading["consumption_wh"]}'
    ).encode()

    child_mac = make_mac(
        meter_secrets[reading["meter_id"]],
        message
    )

    assert verify_mac(
        meter_secrets[reading["meter_id"]],
        message,
        child_mac
    )

    records.append({
        "meter_id": reading["meter_id"],
        "sequence_no": reading["sequence_no"],
        "child_mac": child_mac,
        "chain_hash": f'chain-{reading["meter_id"]}',
    })

# Create aggregate evidence
digest = make_child_manifest_digest(records)
total = sum(r["consumption_wh"] for r in readings)

aggregator_secret = b"neighborhood-aggregator-secret"

payload = canonical_aggregate_payload(
    "NEIGHBORHOOD-01",
    "BATCH-001",
    len(readings),
    total,
    digest,
)

parent_mac = make_aggregate_mac(aggregator_secret, payload)

# Verify parent MAC
assert verify_aggregate_mac(
    aggregator_secret,
    payload,
    parent_mac
)

# Tampering test
tampered_payload = canonical_aggregate_payload(
    "NEIGHBORHOOD-01",
    "BATCH-001",
    len(readings),
    total + 100,
    digest,
)

assert not verify_aggregate_mac(
    aggregator_secret,
    tampered_payload,
    parent_mac
)

print("Individual meter MAC verification: PASSED")
print("Aggregate parent MAC verification: PASSED")
print("Tampering detection: PASSED")
print("Total consumption:", total, "Wh")
