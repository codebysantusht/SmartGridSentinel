import json
import secrets
from pathlib import Path

KEY_FILE = Path(__file__).resolve().parent.parent / "data" / "aggregator_keys.json"


def get_aggregator_secret(neighborhood_id: str) -> bytes:
    """Load or create a persistent secret for a neighborhood aggregator."""

    if KEY_FILE.exists():
        keys = json.loads(KEY_FILE.read_text(encoding="utf-8"))
    else:
        keys = {}

    if neighborhood_id not in keys:
        keys[neighborhood_id] = secrets.token_hex(32)

        KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        KEY_FILE.write_text(
            json.dumps(keys, indent=4),
            encoding="utf-8"
        )

    return bytes.fromhex(keys[neighborhood_id])
