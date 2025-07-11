from typing import NamedTuple, Final

import pytest
from vodozemac import Sas, EstablishedSas
from vodozemac.vodozemac import Curve25519PublicKey

MESSAGE: Final[str] = "Test message"
EXTRA_INFO: Final[str] = "extra_info"

class SasPair(NamedTuple):
    alice: Sas
    bob: Sas

class EstablishedSasPair(NamedTuple):
    alice: EstablishedSas
    bob: EstablishedSas

@pytest.fixture
def sas_pair() -> SasPair:
    return SasPair(alice=Sas(), bob=Sas())

@pytest.fixture
def established_sas_pair(sas_pair: SasPair) -> EstablishedSasPair:
    return EstablishedSasPair(
        alice=sas_pair.alice.diffie_hellman(sas_pair.bob.public_key),
        bob=sas_pair.bob.diffie_hellman(sas_pair.alice.public_key),
    )

def test_creation(sas_pair: SasPair):
    for sas in sas_pair:
        assert isinstance(sas.public_key, Curve25519PublicKey)

def test_other_key_setting(established_sas_pair: EstablishedSasPair):
    for sas in established_sas_pair:
        assert isinstance(sas, EstablishedSas)

def test_bytes_generating(sas_pair: SasPair):
    alice_bytes = sas_pair.alice.diffie_hellman(sas_pair.bob.public_key).bytes(info=EXTRA_INFO)
    bob_bytes = sas_pair.bob.diffie_hellman(sas_pair.alice.public_key).bytes(info=EXTRA_INFO)

    assert alice_bytes.emoji_indices == bob_bytes.emoji_indices
    assert alice_bytes.decimals == bob_bytes.decimals

def test_mac_generating(established_sas_pair: EstablishedSasPair):
    alice_sas = established_sas_pair.alice
    bob_sas = established_sas_pair.bob

    alice_mac = alice_sas.calculate_mac(MESSAGE, EXTRA_INFO)
    bob_mac = bob_sas.calculate_mac(MESSAGE, EXTRA_INFO)

    assert alice_sas.verify_mac(MESSAGE, EXTRA_INFO, bob_mac) is None
    assert bob_sas.verify_mac(MESSAGE, EXTRA_INFO, alice_mac) is None

    assert alice_mac == bob_mac
