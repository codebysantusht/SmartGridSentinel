import hashlib
import hmac
import json

GENESIS = "GENESIS"

def canonical_payload(meter_id: str, sequence_no: int, timestamp: str,
                      consumption_wh: int, previous_hash: str) -> bytes:
    # Canonical JSON prevents field-order ambiguity in the authenticated message.
    payload = {
        "meter_id": meter_id,
        "sequence_no": sequence_no,
        "timestamp": timestamp,
        "consumption_wh": consumption_wh,
        "previous_hash": previous_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

def make_mac(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

def verify_mac(secret: bytes, payload: bytes, supplied_mac: str) -> bool:
    expected = make_mac(secret, payload)
    return hmac.compare_digest(expected, supplied_mac)

def make_chain_hash(payload: bytes, mac: str) -> str:
    return hashlib.sha256(payload + b"|" + mac.encode("ascii")).hexdigest()

def reading_root(rows) -> str:
    # A compact teaching baseline: hash ordered chain hashes into one root.
    joined = "|".join(row["chain_hash"] for row in rows).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()
