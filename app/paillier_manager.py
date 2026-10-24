
import json
import os
from pathlib import Path

from phe import paillier


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
KEY_FILE = DATA_DIR / "paillier_keys.json"


class PaillierManager:
    """
    Paillier homomorphic encryption manager.
    Loads an existing key pair or creates one for a local demo.
    """

    def __init__(self, key_length: int = 1024):
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        if KEY_FILE.exists():
            self._load_keys()
        else:
            self._generate_and_save_keys(key_length)

    def _generate_and_save_keys(self, key_length: int):
        public_key, private_key = paillier.generate_paillier_keypair(
            n_length=key_length
        )

        key_data = {
            "n": str(public_key.n),
            "p": str(private_key.p),
            "q": str(private_key.q),
        }

        # Write to a temporary file before replacing the key file.
        temporary_file = KEY_FILE.with_suffix(".tmp")
        temporary_file.write_text(
            json.dumps(key_data),
            encoding="utf-8"
        )

        try:
            os.chmod(temporary_file, 0o600)
        except OSError:
            # Windows may not support Unix permission semantics.
            pass

        temporary_file.replace(KEY_FILE)

        self.public_key = public_key
        self.private_key = private_key

    def _load_keys(self):
        key_data = json.loads(KEY_FILE.read_text(encoding="utf-8"))

        self.public_key = paillier.PaillierPublicKey(
            int(key_data["n"])
        )

        self.private_key = paillier.PaillierPrivateKey(
            self.public_key,
            int(key_data["p"]),
            int(key_data["q"])
        )

    def encrypt_reading(self, reading_wh: int):
        if isinstance(reading_wh, bool) or not isinstance(reading_wh, int):
            raise ValueError("Reading must be an integer in Wh.")

        if reading_wh < 0:
            raise ValueError("Reading cannot be negative.")

        return self.public_key.encrypt(reading_wh)

    def load_encrypted_reading(self, ciphertext: str):
        """Reconstruct a persisted integer-reading ciphertext.

        The database stores the Paillier ciphertext as a decimal string.
        Readings are encrypted as integers in Wh, so their Paillier
        exponent is zero.
        """
        if not isinstance(ciphertext, str) or not ciphertext.isdecimal():
            raise ValueError(
                "Stored Paillier ciphertext must be a decimal integer."
            )

        value = int(ciphertext)

        if value <= 0 or value >= self.public_key.n ** 2:
            raise ValueError(
                "Stored Paillier ciphertext is outside the valid range."
            )

        return paillier.EncryptedNumber(
            self.public_key,
            value,
            0
        )

    def aggregate_encrypted(self, encrypted_readings):
        encrypted_readings = list(encrypted_readings)

        if not encrypted_readings:
            return self.public_key.encrypt(0)

        total = encrypted_readings[0]

        for encrypted_reading in encrypted_readings[1:]:
            total = total + encrypted_reading

        return total

    def decrypt_aggregate(self, encrypted_total) -> int:
        return self.private_key.decrypt(encrypted_total)

    def get_public_key_info(self):
        return {
            "algorithm": "Paillier",
            "modulus_bits": self.public_key.n.bit_length(),
        }


paillier_manager = PaillierManager()
