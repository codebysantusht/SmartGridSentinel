
from app.neighborhood_aggregator import create_neighborhood_aggregate
from app.paillier_manager import paillier_manager
from app.security import ciphertext_digest


def create_private_neighborhood_aggregate(
    db,
    neighborhood_id: str,
    batch_id: str,
    meter_ids: list[str],
):
    """
    Validate authenticated version 2 readings and aggregate their
    Paillier ciphertexts without decrypting individual readings.

    Legacy version 1 readings are rejected because their ciphertexts
    were not authenticated when originally submitted.
    """

    result = create_neighborhood_aggregate(
        db=db,
        neighborhood_id=neighborhood_id,
        batch_id=batch_id,
        meter_ids=meter_ids,
    )

    legacy_count = result.get("legacy_reading_count", 0)

    if legacy_count > 0:
        raise ValueError(
            "Private aggregation requires version 2 readings. "
            f"Found {legacy_count} legacy readings. "
            "Submit new authenticated readings before using this endpoint."
        )

    encrypted_readings = []
    encrypted_reading_count = 0

    for meter_id in sorted(meter_ids):
        rows = db.execute(
            """
            SELECT sequence_no, encrypted_consumption,
                   ciphertext_digest, auth_version
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no
            """,
            (meter_id,),
        ).fetchall()

        for row in rows:
            if row["auth_version"] != 2:
                raise ValueError(
                    f"Reading {meter_id}/{row['sequence_no']} "
                    "does not use authentication version 2."
                )

            ciphertext = row["encrypted_consumption"]

            if not ciphertext:
                raise ValueError(
                    f"Missing ciphertext for {meter_id}, "
                    f"sequence {row['sequence_no']}."
                )

            actual_digest = ciphertext_digest(ciphertext)

            if actual_digest != row["ciphertext_digest"]:
                raise ValueError(
                    f"Ciphertext digest mismatch for {meter_id}, "
                    f"sequence {row['sequence_no']}."
                )

            encrypted_reading = (
                paillier_manager.load_encrypted_reading(ciphertext)
            )

            encrypted_readings.append(encrypted_reading)
            encrypted_reading_count += 1

    if encrypted_reading_count != result["reading_count"]:
        raise ValueError(
            "Encrypted reading count does not match validated reading count."
        )

    encrypted_total = paillier_manager.aggregate_encrypted(
        encrypted_readings
    )

    encrypted_total_value = str(encrypted_total.ciphertext())

    total_consumption = paillier_manager.decrypt_aggregate(
        encrypted_total
    )

    if total_consumption != result["total_consumption_wh"]:
        raise ValueError(
            "Encrypted and validated totals do not match."
        )

    result.update({
        "total_consumption_wh": total_consumption,
        "encrypted_aggregation": encrypted_total_value,
        "encrypted_reading_count": encrypted_reading_count,
        "aggregation_algorithm": "Paillier Homomorphic Addition",
        "aggregation_mode": "Authenticated encrypted ciphertext aggregation",
        "privacy_note": (
            "Version 2 ciphertexts were checked against their "
            "authenticated SHA-256 digests and added homomorphically. "
            "Only the final aggregate was decrypted. Individual source "
            "readings remain stored in plaintext in this prototype."
        ),
    })

    return result
