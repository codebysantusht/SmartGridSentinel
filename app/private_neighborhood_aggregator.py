
from app.neighborhood_aggregator import create_neighborhood_aggregate
from app.paillier_manager import paillier_manager


def create_private_neighborhood_aggregate(
    db,
    neighborhood_id: str,
    batch_id: str,
    meter_ids: list[str],
):
    """
    Validate child meter MACs and hash chains using the existing
    neighborhood aggregator, then aggregate stored Paillier
    ciphertexts without decrypting individual readings.
    """

    # Reuse existing validation and parent-MAC generation.
    # This preserves the current child verification behavior.
    result = create_neighborhood_aggregate(
        db=db,
        neighborhood_id=neighborhood_id,
        batch_id=batch_id,
        meter_ids=meter_ids,
    )

    encrypted_readings = []

    for meter_id in sorted(meter_ids):
        rows = db.execute(
            """
            SELECT id, encrypted_consumption, consumption_wh
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no
            """,
            (meter_id,),
        ).fetchall()

        for row in rows:
            ciphertext = row["encrypted_consumption"]

            # Safely support older readings without ciphertext.
            if not ciphertext:
                encrypted_reading = paillier_manager.encrypt_reading(
                    row["consumption_wh"]
                )

                db.execute(
                    """
                    UPDATE readings
                    SET encrypted_consumption = ?
                    WHERE id = ?
                      AND encrypted_consumption IS NULL
                    """,
                    (
                        str(encrypted_reading.ciphertext()),
                        row["id"],
                    ),
                )
            else:
                encrypted_reading = (
                    paillier_manager.load_encrypted_reading(ciphertext)
                )

            encrypted_readings.append(encrypted_reading)

    encrypted_total = paillier_manager.aggregate_encrypted(
        encrypted_readings
    )

    encrypted_total_value = str(encrypted_total.ciphertext())

    # Decrypt only the final aggregate for the existing result format.
    total_consumption = paillier_manager.decrypt_aggregate(
        encrypted_total
    )

    if total_consumption != result["total_consumption_wh"]:
        raise ValueError("Encrypted and validated totals do not match.")

    result.update({
        "total_consumption_wh": total_consumption,
        "encrypted_aggregation": encrypted_total_value,
        "aggregation_algorithm": "Paillier Homomorphic Addition",
        "aggregation_mode": "Encrypted ciphertext aggregation",
        "privacy_note": (
            "Individual ciphertexts are added before decryption. "
            "Child MAC validation still uses the existing plaintext "
            "readings stored by the application."
        ),
    })

    return result
