
import sqlite3

import pytest
from phe import paillier

from app.security import canonical_payload, make_mac, make_chain_hash
from app.paillier_manager import PaillierManager
from app import neighborhood_aggregator
from app import private_neighborhood_aggregator as private_aggregator


@pytest.fixture
def test_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row

    db.executescript("""
        CREATE TABLE meters (
            meter_id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            secret_hex TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL
        );

        CREATE TABLE readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id TEXT NOT NULL,
            sequence_no INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            consumption_wh INTEGER NOT NULL,
            encrypted_consumption TEXT,
            mac TEXT NOT NULL,
            chain_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL
        );
    """)

    yield db
    db.close()


@pytest.fixture
def test_manager():
    manager = PaillierManager.__new__(PaillierManager)
    manager.public_key, manager.private_key = (
        paillier.generate_paillier_keypair(n_length=512)
    )
    return manager


@pytest.fixture
def setup_environment(monkeypatch, test_manager):
    monkeypatch.setattr(
        private_aggregator,
        "paillier_manager",
        test_manager,
    )

    monkeypatch.setattr(
        neighborhood_aggregator,
        "get_aggregator_secret",
        lambda neighborhood_id: b"test-aggregator-secret",
    )

    return test_manager


def add_meter(
    db,
    meter_id,
    readings,
    manager,
    missing_ciphertexts=False,
):
    secret = f"test-secret-{meter_id}".encode()

    db.execute(
        """
        INSERT INTO meters
        (meter_id, label, secret_hex, created_at, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            meter_id,
            meter_id,
            secret.hex(),
            "2026-11-10",
            "ACTIVE",
        ),
    )

    previous_hash = "GENESIS"

    for sequence_no, consumption in enumerate(readings, start=1):
        timestamp = f"2026-11-10T10:{sequence_no:02d}:00"

        payload = canonical_payload(
            meter_id,
            sequence_no,
            timestamp,
            consumption,
            previous_hash,
        )

        mac = make_mac(secret, payload)
        chain_hash = make_chain_hash(payload, mac)

        encrypted = None

        if not missing_ciphertexts:
            encrypted = str(
                manager.encrypt_reading(consumption).ciphertext()
            )

        db.execute(
            """
            INSERT INTO readings (
                meter_id,
                sequence_no,
                timestamp,
                consumption_wh,
                encrypted_consumption,
                mac,
                chain_hash,
                previous_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                meter_id,
                sequence_no,
                timestamp,
                consumption,
                encrypted,
                mac,
                chain_hash,
                previous_hash,
            ),
        )

        previous_hash = chain_hash


def test_private_aggregation_success(test_db, setup_environment):
    manager = setup_environment

    add_meter(test_db, "METER-001", [100, 200], manager)
    add_meter(test_db, "METER-002", [300], manager)

    result = private_aggregator.create_private_neighborhood_aggregate(
        test_db,
        "TEST_ZONE",
        "TEST_BATCH_001",
        ["METER-001", "METER-002"],
    )

    assert result["total_consumption_wh"] == 600
    assert result["meter_count"] == 2
    assert result["reading_count"] == 3
    assert result["verification"] == "passed"
    assert result["aggregation_algorithm"] == "Paillier Homomorphic Addition"

    encrypted_total = manager.load_encrypted_reading(
        result["encrypted_aggregation"]
    )

    assert manager.decrypt_aggregate(encrypted_total) == 600


def test_invalid_child_mac_is_rejected(test_db, setup_environment):
    manager = setup_environment

    add_meter(test_db, "METER-001", [100], manager)

    test_db.execute("""
        UPDATE readings
        SET mac = 'invalid-mac'
        WHERE meter_id = 'METER-001'
    """)

    with pytest.raises(ValueError, match="Invalid child MAC"):
        private_aggregator.create_private_neighborhood_aggregate(
            test_db,
            "TEST_ZONE",
            "TEST_BATCH_002",
            ["METER-001"],
        )


def test_encrypted_total_mismatch_is_rejected(
    test_db,
    setup_environment,
    monkeypatch,
):
    manager = setup_environment

    add_meter(test_db, "METER-001", [100, 200], manager)

    monkeypatch.setattr(
        private_aggregator,
        "create_neighborhood_aggregate",
        lambda **kwargs: {"total_consumption_wh": 999},
    )

    with pytest.raises(
        ValueError,
        match="Encrypted and validated totals do not match",
    ):
        private_aggregator.create_private_neighborhood_aggregate(
            test_db,
            "TEST_ZONE",
            "TEST_BATCH_003",
            ["METER-001"],
        )


def test_missing_ciphertexts_are_migrated(test_db, setup_environment):
    manager = setup_environment

    add_meter(
        test_db,
        "METER-001",
        [500, 500],
        manager,
        missing_ciphertexts=True,
    )

    private_aggregator.create_private_neighborhood_aggregate(
        test_db,
        "TEST_ZONE",
        "TEST_BATCH_004",
        ["METER-001"],
    )

    rows = test_db.execute("""
        SELECT id, encrypted_consumption
        FROM readings
        WHERE meter_id = 'METER-001'
        ORDER BY sequence_no
    """).fetchall()

    assert len(rows) == 2
    assert all(row["encrypted_consumption"] for row in rows)

    decrypted_values = [
        manager.decrypt_aggregate(
            manager.load_encrypted_reading(row["encrypted_consumption"])
        )
        for row in rows
    ]

    assert decrypted_values == [500, 500]
    assert rows[0]["id"] != rows[1]["id"]
    assert rows[0]["encrypted_consumption"] != rows[1]["encrypted_consumption"]


def test_duplicate_meter_ids_are_rejected(test_db, setup_environment):
    manager = setup_environment

    add_meter(test_db, "METER-001", [100], manager)

    with pytest.raises(ValueError, match="Duplicate meter IDs"):
        private_aggregator.create_private_neighborhood_aggregate(
            test_db,
            "TEST_ZONE",
            "TEST_BATCH_005",
            ["METER-001", "METER-001"],
        )
