import hashlib
import json

from app.security import make_mac, verify_mac


def canonical_child_manifest(records: list[dict]) -> bytes:
    """Create a deterministic representation of individual meter evidence."""
    ordered = sorted(
        records,
        key=lambda r: (r["meter_id"], r["sequence_no"])
    )

    manifest = [
        {
            "meter_id": record["meter_id"],
            "sequence_no": record["sequence_no"],
            "child_mac": record["child_mac"],
            "chain_hash": record["chain_hash"],
        }
        for record in ordered
    ]

    return json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def make_child_manifest_digest(records: list[dict]) -> str:
    """Hash the individual meter authentication evidence."""
    manifest = canonical_child_manifest(records)
    return hashlib.sha256(manifest).hexdigest()


def canonical_aggregate_payload(
    neighborhood_id: str,
    batch_id: str,
    meter_count: int,
    total_consumption_wh: int,
    child_manifest_digest: str,
) -> bytes:
    """Build the parent aggregator's authenticated payload."""
    payload = {
        "neighborhood_id": neighborhood_id,
        "batch_id": batch_id,
        "meter_count": meter_count,
        "total_consumption_wh": total_consumption_wh,
        "child_manifest_digest": child_manifest_digest,
    }

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def make_aggregate_mac(
    aggregator_secret: bytes,
    payload: bytes
) -> str:
    """Generate the parent MAC for the aggregated batch."""
    return make_mac(aggregator_secret, payload)


def verify_aggregate_mac(
    aggregator_secret: bytes,
    payload: bytes,
    supplied_mac: str
) -> bool:
    """Verify the parent aggregator MAC."""
    return verify_mac(aggregator_secret, payload, supplied_mac)
