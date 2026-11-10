
import hashlib
import hmac
import json

GENESIS = "GENESIS"
CURRENT_AUTH_VERSION = 2


def ciphertext_digest(ciphertext: str) -> str:
    """Return the SHA-256 digest of a persisted Paillier ciphertext."""
    if not isinstance(ciphertext, str) or not ciphertext.isdecimal():
        raise ValueError("Ciphertext must be a decimal integer string.")

    return hashlib.sha256(ciphertext.encode("ascii")).hexdigest()


def canonical_payload(
    meter_id: str,
    sequence_no: int,
    timestamp: str,
    consumption_wh: int,
    previous_hash: str,
    ciphertext_hash: str | None = None,
) -> bytes:
    """
    Build deterministic authenticated JSON.

    Version 1 payloads omit ciphertext_hash to preserve compatibility
    with existing readings.

    Version 2 payloads include the SHA-256 digest of the Paillier
    ciphertext.
    """
    payload = {
        "meter_id": meter_id,
        "sequence_no": sequence_no,
        "timestamp": timestamp,
        "consumption_wh": consumption_wh,
        "previous_hash": previous_hash,
    }

    if ciphertext_hash is not None:
        if (
            not isinstance(ciphertext_hash, str)
            or len(ciphertext_hash) != 64
            or any(c not in "0123456789abcdef" for c in ciphertext_hash.lower())
        ):
            raise ValueError("Invalid ciphertext SHA-256 digest.")

        payload["ciphertext_hash"] = ciphertext_hash.lower()

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def make_mac(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def verify_mac(secret: bytes, payload: bytes, supplied_mac: str) -> bool:
    if not isinstance(supplied_mac, str):
        return False

    expected = make_mac(secret, payload)
    return hmac.compare_digest(expected, supplied_mac)


def make_chain_hash(payload: bytes, mac: str) -> str:
    return hashlib.sha256(
        payload + b"|" + mac.encode("ascii")
    ).hexdigest()


def reading_root(rows) -> str:
    joined = "|".join(
        row["chain_hash"] for row in rows
    ).encode("utf-8")

    return hashlib.sha256(joined).hexdigest()
