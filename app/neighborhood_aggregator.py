from app.security import canonical_payload, verify_mac
from app.nested_mac import (
    make_child_manifest_digest,
    canonical_aggregate_payload,
    make_aggregate_mac,
    verify_aggregate_mac,
)
from app.aggregator_keys import get_aggregator_secret


def create_neighborhood_aggregate(
    db,
    neighborhood_id: str,
    batch_id: str,
    meter_ids: list[str],
):
    """
    Verify individual meter readings and create an authenticated
    neighborhood-level aggregate.
    """

    if not meter_ids:
        raise ValueError("At least one meter ID is required.")

    if len(set(meter_ids)) != len(meter_ids):
        raise ValueError("Duplicate meter IDs are not allowed.")

    child_records = []
    total_consumption = 0

    for meter_id in sorted(meter_ids):
        meter = db.execute(
            "SELECT meter_id, secret_hex, status FROM meters WHERE meter_id = ?",
            (meter_id,),
        ).fetchone()

        if meter is None:
            raise ValueError(f"Meter {meter_id} not found.")

        if meter["status"] != "ACTIVE":
            raise ValueError(f"Meter {meter_id} is not active.")

        rows = db.execute(
            """
            SELECT meter_id, sequence_no, timestamp, consumption_wh,
                   mac, chain_hash, previous_hash
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no
            """,
            (meter_id,),
        ).fetchall()

        if not rows:
            raise ValueError(f"Meter {meter_id} has no readings.")

        secret = bytes.fromhex(meter["secret_hex"])
        expected_previous_hash = "GENESIS"

        for row in rows:
            payload = canonical_payload(
                row["meter_id"],
                row["sequence_no"],
                row["timestamp"],
                row["consumption_wh"],
                row["previous_hash"],
            )

            if not verify_mac(secret, payload, row["mac"]):
                raise ValueError(
                    f"Invalid child MAC for {meter_id}, "
                    f"sequence {row['sequence_no']}."
                )

            if row["previous_hash"] != expected_previous_hash:
                raise ValueError(
                    f"Hash-chain link failed for {meter_id}, "
                    f"sequence {row['sequence_no']}."
                )

            expected_chain_hash = __import__("hashlib").sha256(
                payload + b"|" + row["mac"].encode("ascii")
            ).hexdigest()

            if expected_chain_hash != row["chain_hash"]:
                raise ValueError(
                    f"Chain hash mismatch for {meter_id}, "
                    f"sequence {row['sequence_no']}."
                )

            expected_previous_hash = row["chain_hash"]

            child_records.append({
                "meter_id": meter_id,
                "sequence_no": row["sequence_no"],
                "child_mac": row["mac"],
                "chain_hash": row["chain_hash"],
            })

            total_consumption += row["consumption_wh"]

    child_digest = make_child_manifest_digest(child_records)

    aggregator_secret = get_aggregator_secret(neighborhood_id)

    aggregate_payload = canonical_aggregate_payload(
        neighborhood_id,
        batch_id,
        len(meter_ids),
        total_consumption,
        child_digest,
    )

    parent_mac = make_aggregate_mac(
        aggregator_secret,
        aggregate_payload,
    )

    return {
        "neighborhood_id": neighborhood_id,
        "batch_id": batch_id,
        "meter_count": len(meter_ids),
        "reading_count": len(child_records),
        "total_consumption_wh": total_consumption,
        "child_manifest_digest": child_digest,
        "parent_mac": parent_mac,
        "verification": "passed",
    }


def verify_neighborhood_aggregate(aggregate: dict) -> bool:
    """Verify the parent MAC of an aggregate response."""

    secret = get_aggregator_secret(aggregate["neighborhood_id"])

    payload = canonical_aggregate_payload(
        aggregate["neighborhood_id"],
        aggregate["batch_id"],
        aggregate["meter_count"],
        aggregate["total_consumption_wh"],
        aggregate["child_manifest_digest"],
    )

    return verify_aggregate_mac(
        secret,
        payload,
        aggregate["parent_mac"],
    )
