
from datetime import datetime, timezone
from pathlib import Path
import secrets

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.database import init_db, db_session

from app.security import (
    GENESIS,
    CURRENT_AUTH_VERSION,
    canonical_payload,
    make_mac,
    verify_mac,
    make_chain_hash,
    reading_root,
    ciphertext_digest,
)

from app.neighborhood_aggregator import (
    create_neighborhood_aggregate,
    verify_neighborhood_aggregate,
)

from app.private_neighborhood_aggregator import (
    create_private_neighborhood_aggregate,
)


BASE = Path(__file__).resolve().parent

app = FastAPI(
    title="SmartGrid Sentinel",
    description=(
        "Privacy-preserving aggregate MACs and "
        "hash-based metering verification"
    ),
    version="0.2.0",
)

app.mount(
    "/static",
    StaticFiles(directory=str(BASE / "static")),
    name="static",
)


# ---------------------------------------------------------
# COMMON HELPERS
# ---------------------------------------------------------

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def event(db, meter_id, event_type, severity, message):
    db.execute(
        """
        INSERT INTO events(
            timestamp,
            meter_id,
            event_type,
            severity,
            message
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (now(), meter_id, event_type, severity, message),
    )


def get_meter(db, meter_id):
    row = db.execute(
        "SELECT * FROM meters WHERE meter_id = ?",
        (meter_id,),
    ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"Meter {meter_id} not found",
        )

    return row


# ---------------------------------------------------------
# STARTUP
# ---------------------------------------------------------

@app.on_event("startup")
def startup():
    init_db()


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (
        BASE / "static" / "index.html"
    ).read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "project": "SmartGrid Sentinel",
        "version": "0.2.0",
    }


@app.get("/api/dashboard")
def dashboard_stats():
    with db_session() as db:
        meter_count = db.execute(
            "SELECT COUNT(*) FROM meters"
        ).fetchone()[0]

        reading_count = db.execute(
            "SELECT COUNT(*) FROM readings"
        ).fetchone()[0]

        event_count = db.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        high_count = db.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE severity IN ('HIGH', 'CRITICAL')
            """
        ).fetchone()[0]

        total_wh = db.execute(
            """
            SELECT COALESCE(SUM(consumption_wh), 0)
            FROM readings
            """
        ).fetchone()[0]

        baseline_count = db.execute(
            "SELECT COUNT(*) FROM baselines"
        ).fetchone()[0]

        recent = db.execute(
            """
            SELECT timestamp, consumption_wh
            FROM readings
            ORDER BY id DESC
            LIMIT 12
            """
        ).fetchall()

        chart = [
            {
                "label": f"R{i + 1}",
                "wh": row["consumption_wh"],
            }
            for i, row in enumerate(reversed(recent))
        ]

        return {
            "meters": meter_count,
            "readings": reading_count,
            "events": event_count,
            "high_alerts": high_count,
            "total_wh": total_wh,
            "baselines": baseline_count,
            "chart": chart,
        }


# ---------------------------------------------------------
# METER MANAGEMENT
# ---------------------------------------------------------

@app.get("/api/meters")
def list_meters():
    with db_session() as db:
        rows = db.execute(
            """
            SELECT
                m.meter_id,
                m.label,
                m.status,
                m.created_at,
                COUNT(r.id) AS reading_count,
                COALESCE(SUM(r.consumption_wh), 0) AS total_wh
            FROM meters m
            LEFT JOIN readings r
                ON r.meter_id = m.meter_id
            GROUP BY m.meter_id
            ORDER BY m.created_at DESC
            """
        ).fetchall()

        return {
            "meters": [dict(row) for row in rows]
        }


class MeterCreate(BaseModel):
    meter_id: str = Field(
        min_length=3,
        max_length=40,
        pattern=r"^[A-Za-z0-9_-]+$",
    )

    label: str = Field(
        default="Residential Smart Meter",
        min_length=2,
        max_length=80,
    )


@app.post("/api/meters")
def create_meter(data: MeterCreate):
    with db_session() as db:
        existing = db.execute(
            "SELECT 1 FROM meters WHERE meter_id = ?",
            (data.meter_id,),
        ).fetchone()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="Meter ID already exists",
            )

        secret = secrets.token_bytes(32)

        db.execute(
            """
            INSERT INTO meters(
                meter_id,
                label,
                secret_hex,
                created_at,
                status
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                data.meter_id,
                data.label,
                secret.hex(),
                now(),
                "ACTIVE",
            ),
        )

        event(
            db,
            data.meter_id,
            "METER_REGISTERED",
            "INFO",
            "New meter registered.",
        )

        return {
            "status": "registered",
            "meter_id": data.meter_id,
        }


@app.get("/api/meters/{meter_id}/readings")
def readings(meter_id: str):
    with db_session() as db:
        get_meter(db, meter_id)

        rows = db.execute(
            """
            SELECT
                id,
                meter_id,
                sequence_no,
                timestamp,
                consumption_wh,
                mac,
                chain_hash,
                previous_hash,
                auth_version,
                ciphertext_digest
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no
            """,
            (meter_id,),
        ).fetchall()

        return {
            "meter_id": meter_id,
            "count": len(rows),
            "readings": [dict(row) for row in rows],
        }


# ---------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------

class ReadingCreate(BaseModel):
    meter_id: str = Field(
        min_length=3,
        max_length=40,
    )

    consumption_wh: int = Field(
        gt=0,
        le=10_000_000,
    )


class NeighborhoodAggregateCreate(BaseModel):
    neighborhood_id: str = Field(
        min_length=3,
        max_length=40,
    )

    batch_id: str = Field(
        min_length=3,
        max_length=60,
    )

    meter_ids: list[str] = Field(
        min_length=1,
        max_length=50,
    )


class NeighborhoodAggregateVerifyRequest(BaseModel):
    neighborhood_id: str = Field(
        min_length=3,
        max_length=40,
    )

    batch_id: str = Field(
        min_length=3,
        max_length=60,
    )

    meter_count: int = Field(
        gt=0,
        le=50,
    )

    total_consumption_wh: int = Field(
        ge=0,
    )

    child_manifest_digest: str = Field(
        pattern=r"^[a-fA-F0-9]{64}$",
    )

    parent_mac: str = Field(
        pattern=r"^[a-fA-F0-9]{64}$",
    )


# ---------------------------------------------------------
# SUBMIT AUTHENTICATED AND ENCRYPTED READING
# ---------------------------------------------------------

@app.post("/api/readings")
def submit_reading(data: ReadingCreate):
    from app.paillier_manager import paillier_manager

    with db_session() as db:
        meter = get_meter(db, data.meter_id)

        latest = db.execute(
            """
            SELECT sequence_no, chain_hash
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no DESC
            LIMIT 1
            """,
            (data.meter_id,),
        ).fetchone()

        sequence = (
            latest["sequence_no"] + 1
            if latest
            else 1
        )

        previous_hash = (
            latest["chain_hash"]
            if latest
            else GENESIS
        )

        timestamp = now()

        # Step 1: Encrypt the reading.
        encrypted_reading = paillier_manager.encrypt_reading(
            data.consumption_wh
        )

        encrypted_ciphertext = str(
            encrypted_reading.ciphertext()
        )

        # Step 2: Calculate the ciphertext digest.
        digest = ciphertext_digest(
            encrypted_ciphertext
        )

        # Step 3: Authenticate the reading and ciphertext digest.
        payload = canonical_payload(
            data.meter_id,
            sequence,
            timestamp,
            data.consumption_wh,
            previous_hash,
            digest,
        )

        secret = bytes.fromhex(
            meter["secret_hex"]
        )

        mac = make_mac(secret, payload)

        if not verify_mac(secret, payload, mac):
            event(
                db,
                data.meter_id,
                "INVALID_HMAC",
                "HIGH",
                "Generated packet failed authentication.",
            )

            raise HTTPException(
                status_code=400,
                detail="HMAC authentication failed",
            )

        # Step 4: Generate the hash-chain value.
        chain_hash = make_chain_hash(
            payload,
            mac,
        )

        # Step 5: Store the authenticated encrypted reading.
        db.execute(
            """
            INSERT INTO readings(
                meter_id,
                sequence_no,
                timestamp,
                consumption_wh,
                encrypted_consumption,
                mac,
                chain_hash,
                previous_hash,
                auth_version,
                ciphertext_digest
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.meter_id,
                sequence,
                timestamp,
                data.consumption_wh,
                encrypted_ciphertext,
                mac,
                chain_hash,
                previous_hash,
                CURRENT_AUTH_VERSION,
                digest,
            ),
        )

        event(
            db,
            data.meter_id,
            "SECURE_READING_ACCEPTED",
            "INFO",
            (
                f"Reading #{sequence} authenticated, "
                "encrypted and ciphertext-bound."
            ),
        )

        return {
            "status": "accepted",
            "meter_id": data.meter_id,
            "sequence_no": sequence,
            "mac": mac,
            "chain_hash": chain_hash,
            "auth_version": CURRENT_AUTH_VERSION,
            "ciphertext_digest": digest,
            "encryption": "Paillier",
            "encrypted_storage": True,
        }


# ---------------------------------------------------------
# SINGLE METER HOMOMORPHIC AGGREGATION
# ---------------------------------------------------------

@app.get("/api/meters/{meter_id}/aggregate")
def aggregate(meter_id: str):
    from app.paillier_manager import paillier_manager

    with db_session() as db:
        get_meter(db, meter_id)

        rows = db.execute(
            """
            SELECT
                id,
                consumption_wh,
                encrypted_consumption
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no ASC
            """,
            (meter_id,),
        ).fetchall()

        encrypted_values = []
        migrated_count = 0

        for row in rows:
            ciphertext = row["encrypted_consumption"]

            if not ciphertext:
                encrypted_reading = (
                    paillier_manager.encrypt_reading(
                        int(row["consumption_wh"])
                    )
                )

                ciphertext = str(
                    encrypted_reading.ciphertext()
                )

                db.execute(
                    """
                    UPDATE readings
                    SET encrypted_consumption = ?
                    WHERE id = ?
                    """,
                    (ciphertext, row["id"]),
                )

                migrated_count += 1

            else:
                encrypted_reading = (
                    paillier_manager.load_encrypted_reading(
                        ciphertext
                    )
                )

            encrypted_values.append(encrypted_reading)

        encrypted_total = (
            paillier_manager.aggregate_encrypted(
                encrypted_values
            )
        )

        total_wh = paillier_manager.decrypt_aggregate(
            encrypted_total
        )

        event(
            db,
            meter_id,
            "PAILLIER_AGGREGATE_REQUESTED",
            "INFO",
            (
                "Paillier encrypted aggregation executed; "
                "only the final total was decrypted."
            ),
        )

        return {
            "status": "success",
            "meter_id": meter_id,
            "reading_count": len(rows),
            "total_consumption_wh": total_wh,
            "aggregation_algorithm": "Paillier Homomorphic Encryption",
            "encrypted_aggregation": str(
                encrypted_total.ciphertext()
            ),
            "legacy_ciphertexts_migrated": migrated_count,
            "privacy_note": (
                "Stored Paillier ciphertexts were aggregated "
                "homomorphically; only the final total was decrypted. "
                "Source readings remain stored in plaintext "
                "in this prototype."
            ),
        }


# ---------------------------------------------------------
# INTEGRITY BASELINE
# ---------------------------------------------------------

@app.post("/api/meters/{meter_id}/baseline")
def create_baseline(meter_id: str):
    with db_session() as db:
        get_meter(db, meter_id)

        rows = db.execute(
            """
            SELECT chain_hash
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no
            """,
            (meter_id,),
        ).fetchall()

        if not rows:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Submit at least one reading "
                    "before creating a baseline"
                ),
            )

        root_hash = reading_root(rows)

        db.execute(
            """
            INSERT INTO baselines(
                meter_id,
                root_hash,
                reading_count,
                created_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(meter_id)
            DO UPDATE SET
                root_hash = excluded.root_hash,
                reading_count = excluded.reading_count,
                created_at = excluded.created_at
            """,
            (
                meter_id,
                root_hash,
                len(rows),
                now(),
            ),
        )

        event(
            db,
            meter_id,
            "BASELINE_CREATED",
            "INFO",
            (
                f"Integrity baseline created "
                f"for {len(rows)} readings."
            ),
        )

        return {
            "status": "baseline_created",
            "meter_id": meter_id,
            "reading_count": len(rows),
            "root_hash": root_hash,
        }


# ---------------------------------------------------------
# VERIFY METER INTEGRITY
# ---------------------------------------------------------

def verify_meter(db, meter_id):
    meter = get_meter(db, meter_id)

    rows = db.execute(
        """
        SELECT *
        FROM readings
        WHERE meter_id = ?
        ORDER BY sequence_no
        """,
        (meter_id,),
    ).fetchall()

    secret = bytes.fromhex(
        meter["secret_hex"]
    )

    expected_prev = GENESIS
    expected_sequence = 1

    chain_ok = True
    mac_ok = True
    ciphertext_binding_ok = True

    legacy_count = 0
    bound_count = 0
    failed_sequence = None

    for row in rows:
        version = row["auth_version"] or 1

        if row["sequence_no"] != expected_sequence:
            chain_ok = False
            failed_sequence = row["sequence_no"]
            break

        if version == 1:
            payload = canonical_payload(
                row["meter_id"],
                row["sequence_no"],
                row["timestamp"],
                row["consumption_wh"],
                row["previous_hash"],
            )

            legacy_count += 1

        elif version == 2:
            ciphertext = row["encrypted_consumption"]

            if (
                not ciphertext
                or not row["ciphertext_digest"]
            ):
                ciphertext_binding_ok = False
                failed_sequence = row["sequence_no"]
                break

            try:
                digest = ciphertext_digest(ciphertext)
            except ValueError:
                ciphertext_binding_ok = False
                failed_sequence = row["sequence_no"]
                break

            if digest != row["ciphertext_digest"]:
                ciphertext_binding_ok = False
                failed_sequence = row["sequence_no"]
                break

            payload = canonical_payload(
                row["meter_id"],
                row["sequence_no"],
                row["timestamp"],
                row["consumption_wh"],
                row["previous_hash"],
                digest,
            )

            bound_count += 1

        else:
            mac_ok = False
            failed_sequence = row["sequence_no"]
            break

        valid_mac = verify_mac(
            secret,
            payload,
            row["mac"],
        )

        valid_chain = (
            row["previous_hash"] == expected_prev
            and make_chain_hash(
                payload,
                row["mac"],
            ) == row["chain_hash"]
        )

        if not valid_mac or not valid_chain:
            mac_ok = mac_ok and valid_mac
            chain_ok = chain_ok and valid_chain
            failed_sequence = row["sequence_no"]
            break

        expected_prev = row["chain_hash"]
        expected_sequence += 1

    baseline = db.execute(
        """
        SELECT *
        FROM baselines
        WHERE meter_id = ?
        """,
        (meter_id,),
    ).fetchone()

    current_root = (
        reading_root(rows)
        if rows
        else None
    )

    baseline_ok = (
        current_root == baseline["root_hash"]
    ) if baseline else None

    overall = (
        chain_ok
        and mac_ok
        and ciphertext_binding_ok
        and baseline_ok is not False
    )

    if legacy_count > 0:
        binding_result = False
    elif bound_count > 0:
        binding_result = True
    else:
        binding_result = None

    return {
        "meter_id": meter_id,
        "status": "verified" if overall else "failed",
        "integrity_valid": overall,
        "hash_chain_valid": chain_ok,
        "hmac_valid": mac_ok,
        "ciphertext_binding_valid": binding_result,
        "legacy_reading_count": legacy_count,
        "ciphertext_bound_reading_count": bound_count,
        "baseline_valid": baseline_ok,
        "reading_count": len(rows),
        "failed_sequence": failed_sequence,
        "current_root": current_root,
        "message": (
            "All readings passed their applicable integrity checks."
            if overall
            else (
                "Mismatch detected. "
                "Stored data may have been changed."
            )
        ),
    }


@app.post("/api/meters/{meter_id}/verify")
def verify(meter_id: str):
    with db_session() as db:
        result = verify_meter(db, meter_id)

        event(
            db,
            meter_id,
            (
                "INTEGRITY_VERIFIED"
                if result["integrity_valid"]
                else "INTEGRITY_VIOLATION"
            ),
            (
                "INFO"
                if result["integrity_valid"]
                else "HIGH"
            ),
            result["message"],
        )

        return result


# ---------------------------------------------------------
# REPLAY ATTACK DEMO
# ---------------------------------------------------------

@app.post("/api/demo/replay/{meter_id}")
def replay_demo(meter_id: str):
    with db_session() as db:
        get_meter(db, meter_id)

        row = db.execute(
            """
            SELECT sequence_no
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no DESC
            LIMIT 1
            """,
            (meter_id,),
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Submit a reading before "
                    "simulating replay"
                ),
            )

        event(
            db,
            meter_id,
            "REPLAY_ATTACK_BLOCKED",
            "HIGH",
            (
                "Replay packet rejected: duplicate sequence "
                f"number {row['sequence_no']}."
            ),
        )

        return {
            "status": "blocked",
            "detected": True,
            "attack": "Replay attack",
            "reason": (
                f"Duplicate sequence number "
                f"{row['sequence_no']} rejected."
            ),
        }


# ---------------------------------------------------------
# TAMPERING ATTACK DEMO
# ---------------------------------------------------------

@app.post("/api/demo/tamper/{meter_id}")
def tamper_demo(meter_id: str):
    with db_session() as db:
        get_meter(db, meter_id)

        row = db.execute(
            """
            SELECT id, consumption_wh, sequence_no
            FROM readings
            WHERE meter_id = ?
            ORDER BY sequence_no DESC
            LIMIT 1
            """,
            (meter_id,),
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Submit a reading before "
                    "simulating tampering"
                ),
            )

        original_value = row["consumption_wh"]
        changed_value = original_value + 1

        db.execute(
            """
            UPDATE readings
            SET consumption_wh = ?
            WHERE id = ?
            """,
            (changed_value, row["id"]),
        )

        result = verify_meter(
            db,
            meter_id,
        )

        # Restore the original value.
        db.execute(
            """
            UPDATE readings
            SET consumption_wh = ?
            WHERE id = ?
            """,
            (original_value, row["id"]),
        )

        event(
            db,
            meter_id,
            (
                "TAMPERING_DETECTED"
                if not result["integrity_valid"]
                else "TAMPERING_NOT_DETECTED"
            ),
            (
                "HIGH"
                if not result["integrity_valid"]
                else "INFO"
            ),
            (
                f"Temporary tampering simulation on reading "
                f"#{row['sequence_no']}; "
                f"integrity_valid={result['integrity_valid']}."
            ),
        )

        return {
            "status": (
                "tampering_detected"
                if not result["integrity_valid"]
                else "not_detected"
            ),
            "meter_id": meter_id,
            "sequence_no": row["sequence_no"],
            "original_value_wh": original_value,
            "simulated_value_wh": changed_value,
            "integrity_valid_during_simulation": (
                result["integrity_valid"]
            ),
            "hmac_valid": result["hmac_valid"],
            "hash_chain_valid": result["hash_chain_valid"],
            "note": (
                "Original reading restored; "
                "stored consumption was not changed permanently."
            ),
        }


# ---------------------------------------------------------
# EVENTS
# ---------------------------------------------------------

@app.get("/api/events")
def events(limit: int = 20):
    limit = max(1, min(limit, 100))

    with db_session() as db:
        rows = db.execute(
            """
            SELECT *
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return {
            "events": [dict(row) for row in rows]
        }


# ---------------------------------------------------------
# SEED DEMO DATA
# ---------------------------------------------------------

@app.post("/api/demo/seed")
def seed_demo():
    from app.paillier_manager import paillier_manager

    with db_session() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM meters"
        ).fetchone()[0]

        if count:
            return {
                "status": "already_seeded",
                "message": (
                    "Database already has meters; "
                    "no demo rows were added."
                ),
            }

        demo_meters = [
            ("METER-001", "North Block - Residential"),
            ("METER-002", "Library & Labs"),
            ("METER-003", "Hostel Cluster"),
        ]

        for mid, label in demo_meters:
            secret = secrets.token_bytes(32)

            db.execute(
                """
                INSERT INTO meters(
                    meter_id,
                    label,
                    secret_hex,
                    created_at,
                    status
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    mid,
                    label,
                    secret.hex(),
                    now(),
                    "ACTIVE",
                ),
            )

            event(
                db,
                mid,
                "METER_REGISTERED",
                "INFO",
                "Demo meter registered.",
            )

        demo_readings = [
            ("METER-001", [1250, 980, 1420]),
            ("METER-002", [850, 920]),
            ("METER-003", [2100, 1980, 2050]),
        ]

        for mid, values in demo_readings:
            meter = get_meter(db, mid)
            previous_hash = GENESIS

            for sequence, wh in enumerate(
                values,
                start=1,
            ):
                timestamp = now()

                encrypted_reading = (
                    paillier_manager.encrypt_reading(wh)
                )

                encrypted_ciphertext = str(
                    encrypted_reading.ciphertext()
                )

                digest = ciphertext_digest(
                    encrypted_ciphertext
                )

                payload = canonical_payload(
                    mid,
                    sequence,
                    timestamp,
                    wh,
                    previous_hash,
                    digest,
                )

                mac = make_mac(
                    bytes.fromhex(meter["secret_hex"]),
                    payload,
                )

                chain = make_chain_hash(
                    payload,
                    mac,
                )

                db.execute(
                    """
                    INSERT INTO readings(
                        meter_id,
                        sequence_no,
                        timestamp,
                        consumption_wh,
                        encrypted_consumption,
                        mac,
                        chain_hash,
                        previous_hash,
                        auth_version,
                        ciphertext_digest
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        mid,
                        sequence,
                        timestamp,
                        wh,
                        encrypted_ciphertext,
                        mac,
                        chain,
                        previous_hash,
                        CURRENT_AUTH_VERSION,
                        digest,
                    ),
                )

                previous_hash = chain

            event(
                db,
                mid,
                "SECURE_READING_ACCEPTED",
                "INFO",
                (
                    f"Seeded {len(values)} "
                    "authenticated demo readings."
                ),
            )

        return {
            "status": "seeded",
            "meters_created": 3,
            "readings_created": 8,
        }


# ---------------------------------------------------------
# NEIGHBORHOOD AGGREGATION
# ---------------------------------------------------------

@app.post("/api/neighborhoods/aggregate")
def neighborhood_aggregate(
    data: NeighborhoodAggregateCreate,
):
    with db_session() as db:
        try:
            result = create_neighborhood_aggregate(
                db=db,
                neighborhood_id=data.neighborhood_id,
                batch_id=data.batch_id,
                meter_ids=data.meter_ids,
            )

        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            )

        event(
            db,
            None,
            "NEIGHBORHOOD_AGGREGATED",
            "INFO",
            (
                f"Batch {data.batch_id}: "
                f"{result['meter_count']} meters aggregated."
            ),
        )

        return result


# ---------------------------------------------------------
# VERIFY NEIGHBORHOOD AGGREGATE
# ---------------------------------------------------------

@app.post("/api/neighborhoods/verify")
def neighborhood_aggregate_verify(
    data: NeighborhoodAggregateVerifyRequest,
):
    aggregate_data = data.model_dump()

    try:
        valid = verify_neighborhood_aggregate(
            aggregate_data
        )

    except (KeyError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Invalid aggregate verification payload.",
        )

    return {
        "neighborhood_id": data.neighborhood_id,
        "batch_id": data.batch_id,
        "valid": valid,
        "verification": (
            "PASSED" if valid else "FAILED"
        ),
    }


# ---------------------------------------------------------
# PRIVATE NEIGHBORHOOD AGGREGATION
# ---------------------------------------------------------

@app.post("/api/neighborhoods/private-aggregate")
def private_neighborhood_aggregate(
    data: NeighborhoodAggregateCreate,
):
    with db_session() as db:
        try:
            result = create_private_neighborhood_aggregate(
                db=db,
                neighborhood_id=data.neighborhood_id,
                batch_id=data.batch_id,
                meter_ids=data.meter_ids,
            )

        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            )

        event(
            db,
            None,
            "PRIVATE_NEIGHBORHOOD_AGGREGATED",
            "INFO",
            (
                f"Private batch {data.batch_id}: "
                f"{result['meter_count']} meters aggregated "
                "using Paillier."
            ),
        )

        return result
