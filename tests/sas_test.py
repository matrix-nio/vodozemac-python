import pytest

from vodozemac import SasException, Sas

MESSAGE = "Test message"
EXTRA_INFO = "extra_info"


class TestClass(object):
    def test_sas_creation(self):
        sas = Sas()
        assert sas.public_key

    def test_other_key_setting(self):
        sas_alice = Sas()
        sas_bob = Sas()

        established = sas_alice.diffie_hellman(sas_bob.public_key)

    def test_bytes_generating(self):
        sas_alice = Sas()
        sas_bob = Sas()

        bob_public_key = sas_bob.public_key
        sas_bob = sas_bob.diffie_hellman(sas_alice.public_key)
        sas_alice = sas_alice.diffie_hellman(bob_public_key)

        alice_bytes = sas_alice.bytes(EXTRA_INFO)
        bob_bytes = sas_bob.bytes(EXTRA_INFO)

        assert alice_bytes.emoji_indices == bob_bytes.emoji_indices
        assert alice_bytes.decimals == bob_bytes.decimals

    def test_mac_generating(self):
        sas_alice = Sas()
        sas_bob = Sas()

        bob_public_key = sas_bob.public_key
        sas_bob = sas_bob.diffie_hellman(sas_alice.public_key)
        sas_alice = sas_alice.diffie_hellman(bob_public_key)

        alice_mac = sas_alice.calculate_mac(MESSAGE, EXTRA_INFO)
        bob_mac = sas_bob.calculate_mac(MESSAGE, EXTRA_INFO)

        sas_alice.verify_mac(MESSAGE, EXTRA_INFO, bob_mac)
        sas_bob.verify_mac(MESSAGE, EXTRA_INFO, alice_mac)

        assert alice_mac == bob_mac
