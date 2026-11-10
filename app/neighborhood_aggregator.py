
from app.security import (
    GENESIS,
    canonical_payload,
    verify_mac,
    make_chain_hash,
    ciphertext_digest,
)
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
    if not meter_ids:
        raise ValueError("At least one meter ID is required.")

    if len(set(meter_ids)) != len(meter_ids):
        raise ValueError("Duplicate meter IDs are not allowed.")

    child_records = []
    total_consumption = 0
    legacy_reading_count = 0
    bound_reading_count = 0

    for meter_id in sorted(meter_ids):
        meter = db.execute(
            """
            SELECT meter_id, secret_hex, status
            FROM meters
            WHERE meter_id = ?
            """,
            (meter_id,),
        ).fetchone()

        if meter is None:
            raise ValueError(f"Meter {meter_id} not found.")

        if meter["status"] != "ACTIVE":
            raise ValueError(f"Meter {meter_id} is not active.")

        rows = db.execute(
            """
            SELECT meter_id, sequence_no, timestamp, consumption_wh,
                   encrypted_consumption, ciphertext_digest,
                   auth_version, mac, chain_hash, previous_hash
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no
            """,
            (meter_id,),
        ).fetchall()

        if not rows:
            raise ValueError(f"Meter {meter_id} has no readings.")

        secret = bytes.fromhex(meter["secret_hex"])
        expected_previous_hash = GENESIS
        expected_sequence = 1

        for row in rows:
            version = row["auth_version"] or 1

            if row["sequence_no"] != expected_sequence:
                raise ValueError(
                    f"Sequence gap or ordering error for {meter_id}: "
                    f"expected {expected_sequence}, "
                    f"found {row['sequence_no']}."
                )

            if row["previous_hash"] != expected_previous_hash:
                raise ValueError(
                    f"Hash-chain link failed for {meter_id}, "
                    f"sequence {row['sequence_no']}."
                )

            if version == 1:
                payload = canonical_payload(
                    row["meter_id"],
                    row["sequence_no"],
                    row["timestamp"],
                    row["consumption_wh"],
                    row["previous_hash"],
                )
                legacy_reading_count += 1

            elif version == 2:
                ciphertext = row["encrypted_consumption"]

                if not ciphertext:
                    raise ValueError(
                        f"Missing ciphertext for {meter_id}, "
                        f"sequence {row['sequence_no']}."
                    )

                actual_digest = ciphertext_digest(ciphertext)

                if not row["ciphertext_digest"]:
                    raise ValueError(
                        f"Missing authenticated ciphertext digest for "
                        f"{meter_id}, sequence {row['sequence_no']}."
                    )

                if actual_digest != row["ciphertext_digest"]:
                    raise ValueError(
                        f"Ciphertext digest mismatch for {meter_id}, "
                        f"sequence {row['sequence_no']}."
                    )

                payload = canonical_payload(
                    row["meter_id"],
                    row["sequence_no"],
                    row["timestamp"],
                    row["consumption_wh"],
                    row["previous_hash"],
                    actual_digest,
                )
                bound_reading_count += 1

            else:
                raise ValueError(
                    f"Unsupported authentication version {version} "
                    f"for {meter_id}, sequence {row['sequence_no']}."
                )

            if not verify_mac(secret, payload, row["mac"]):
                raise ValueError(
                    f"Invalid child MAC for {meter_id}, "
                    f"sequence {row['sequence_no']}."
                )

            expected_chain_hash = make_chain_hash(
                payload,
                row["mac"],
            )

            if expected_chain_hash != row["chain_hash"]:
                raise ValueError(
                    f"Chain hash mismatch for {meter_id}, "
                    f"sequence {row['sequence_no']}."
                )

            expected_previous_hash = row["chain_hash"]
            expected_sequence += 1

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
        "legacy_reading_count": legacy_reading_count,
        "ciphertext_bound_reading_count": bound_reading_count,
    }


def verify_neighborhood_aggregate(aggregate: dict) -> bool:
    secret = get_aggregator_secret(
        aggregate["neighborhood_id"]
    )

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
