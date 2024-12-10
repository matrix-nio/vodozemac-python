import importlib
import pytest

from vodozemac import (
    Curve25519SecretKey,
    Curve25519PublicKey,
    PkEncryption,
    PkDecryption,
    PkDecodeException,
)

CLEARTEXT = b"test"


class TestClass(object):
    def test_encrypt_decrypt(self):
        d = PkDecryption()
        e = PkEncryption.from_key(d.public_key)

        decoded = d.decrypt(e.encrypt(CLEARTEXT))
        assert decoded == CLEARTEXT

    def test_encrypt_decrypt_with_wrong_key(self):
        wrong_e = PkEncryption.from_key(PkDecryption().public_key)
        with pytest.raises(PkDecodeException, match="MAC tag mismatch"):
            PkDecryption().decrypt(wrong_e.encrypt(CLEARTEXT))

    def test_encrypt_decrypt_with_serialized_keys(self):
        secret_key = Curve25519SecretKey()
        secret_key_bytes = secret_key.to_bytes()
        public_key_bytes = secret_key.public_key().to_bytes()

        d = PkDecryption.from_key(Curve25519SecretKey.from_bytes(secret_key_bytes))
        e = PkEncryption.from_key(Curve25519PublicKey.from_bytes(public_key_bytes))

        decoded = d.decrypt(e.encrypt(CLEARTEXT))
        assert decoded == CLEARTEXT

    def test_encrypt_message_attr(self):
        """Test that the Message object has accessible Python attributes (mac, ciphertext, ephemeral_key)."""
        decryption = PkDecryption()
        encryption = PkEncryption.from_key(decryption.public_key)

        message = encryption.encrypt(CLEARTEXT)

        assert message.mac is not None
        assert message.ciphertext is not None
        assert message.ephemeral_key is not None
