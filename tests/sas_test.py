from typing import Final

import pytest
from vodozemac import Sas, EstablishedSas
from vodozemac.vodozemac import Curve25519PublicKey

EXTRA_INFO: Final[str] = "extra_info"

@pytest.fixture
def alice_sas() -> Sas:
    return Sas()

@pytest.fixture
def bob_sas() -> Sas:
    return Sas()

@pytest.fixture
def alice_established_sas(alice_sas: Sas, bob_sas: Sas) -> EstablishedSas:
    return alice_sas.diffie_hellman(bob_sas.public_key)

@pytest.fixture
def bob_established_sas(alice_sas: Sas, bob_sas: Sas) -> EstablishedSas:
    return bob_sas.diffie_hellman(alice_sas.public_key)

def test_creation(alice_sas: Sas, alice_established_sas):
    assert isinstance(alice_sas.public_key, Curve25519PublicKey)
    assert isinstance(alice_established_sas, EstablishedSas)

def test_bytes_generating(alice_sas: Sas, bob_sas: Sas):
    alice_bytes = alice_sas.diffie_hellman(bob_sas.public_key).bytes(info=EXTRA_INFO)
    bob_bytes = bob_sas.diffie_hellman(alice_sas.public_key).bytes(info=EXTRA_INFO)

    assert alice_bytes.emoji_indices == bob_bytes.emoji_indices
    assert alice_bytes.decimals == bob_bytes.decimals

def test_mac_generating(alice_established_sas: EstablishedSas, bob_established_sas: EstablishedSas):
    message = "Test message"
    alice_mac = alice_established_sas.calculate_mac(message, EXTRA_INFO)
    bob_mac = bob_established_sas.calculate_mac(message, EXTRA_INFO)

    assert alice_established_sas.verify_mac(message, EXTRA_INFO, bob_mac) is None
    assert bob_established_sas.verify_mac(message, EXTRA_INFO, alice_mac) is None

    assert alice_mac == bob_mac
