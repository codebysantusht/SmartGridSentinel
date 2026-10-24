import pytest
from phe import paillier

from app.paillier_manager import PaillierManager


@pytest.fixture
def manager():
    instance = PaillierManager.__new__(PaillierManager)
    instance.public_key, instance.private_key = (
        paillier.generate_paillier_keypair(n_length=512)
    )
    return instance


def test_encrypt_and_decrypt_reading(manager):
    encrypted = manager.encrypt_reading(1500)
    assert manager.private_key.decrypt(encrypted) == 1500


def test_aggregate_encrypted_readings(manager):
    readings = [100, 200, 300]
    encrypted = [manager.encrypt_reading(value) for value in readings]

    total = manager.aggregate_encrypted(encrypted)

    assert manager.decrypt_aggregate(total) == 600


def test_empty_aggregation_returns_zero(manager):
    total = manager.aggregate_encrypted([])
    assert manager.decrypt_aggregate(total) == 0


@pytest.mark.parametrize("value", [-1, 1.5, "100", True])
def test_invalid_readings_are_rejected(manager, value):
    with pytest.raises(ValueError):
        manager.encrypt_reading(value)


def test_load_encrypted_reading_round_trip(manager):
    original = manager.encrypt_reading(2500)
    restored = manager.load_encrypted_reading(
        str(original.ciphertext())
    )

    assert manager.decrypt_aggregate(restored) == 2500


@pytest.mark.parametrize("ciphertext", ["abc", "-10", "0", ""])
def test_invalid_ciphertexts_are_rejected(manager, ciphertext):
    with pytest.raises(ValueError):
        manager.load_encrypted_reading(ciphertext)
