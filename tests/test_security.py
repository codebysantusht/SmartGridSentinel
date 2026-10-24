import hashlib

from app.security import (
    GENESIS,
    canonical_payload,
    make_mac,
    verify_mac,
    make_chain_hash,
    reading_root,
)


def test_canonical_payload_is_deterministic():
    first = canonical_payload("METER-TEST", 1, "2026-10-24T10:00:00Z", 2000, GENESIS)
    second = canonical_payload("METER-TEST", 1, "2026-10-24T10:00:00Z", 2000, GENESIS)
    assert first == second


def test_hmac_accepts_original_payload():
    secret = b"test-secret-key"
    payload = canonical_payload("METER-TEST", 1, "2026-10-24T10:00:00Z", 2000, GENESIS)
    mac = make_mac(secret, payload)
    assert verify_mac(secret, payload, mac)


def test_hmac_rejects_modified_payload():
    secret = b"test-secret-key"
    original = canonical_payload("METER-TEST", 1, "2026-10-24T10:00:00Z", 2000, GENESIS)
    modified = canonical_payload("METER-TEST", 1, "2026-10-24T10:00:00Z", 2001, GENESIS)
    mac = make_mac(secret, original)
    assert not verify_mac(secret, modified, mac)


def test_hmac_rejects_wrong_secret():
    payload = canonical_payload("METER-TEST", 1, "2026-10-24T10:00:00Z", 2000, GENESIS)
    mac = make_mac(b"correct-secret", payload)
    assert not verify_mac(b"wrong-secret", payload, mac)


def test_chain_hash_changes_when_payload_changes():
    secret = b"test-secret-key"
    first = canonical_payload("METER-TEST", 1, "2026-10-24T10:00:00Z", 2000, GENESIS)
    second = canonical_payload("METER-TEST", 1, "2026-10-24T10:00:00Z", 2001, GENESIS)
    first_hash = make_chain_hash(first, make_mac(secret, first))
    second_hash = make_chain_hash(second, make_mac(secret, second))
    assert first_hash != second_hash


def test_reading_root_is_stable_for_same_order():
    rows = [
        {"chain_hash": "hash-a"},
        {"chain_hash": "hash-b"},
    ]
    expected = hashlib.sha256(b"hash-a|hash-b").hexdigest()
    assert reading_root(rows) == expected


def test_reading_root_changes_when_order_changes():
    rows_a = [{"chain_hash": "hash-a"}, {"chain_hash": "hash-b"}]
    rows_b = [{"chain_hash": "hash-b"}, {"chain_hash": "hash-a"}]
    assert reading_root(rows_a) != reading_root(rows_b)
