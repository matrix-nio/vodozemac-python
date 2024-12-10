import importlib
import pytest
import olm
import base64

from vodozemac import (
    Curve25519SecretKey,
    Curve25519PublicKey,
    PkEncryption,
    PkDecryption,
    PkDecodeException,
    Message,
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

    def test_olm_encrypt_vodo_decrypt(self):
        """Test encrypting with Olm and decrypting with Vodo."""
        vodo_decryption = PkDecryption()
        olm_encrypts = olm.pk.PkEncryption(vodo_decryption.public_key.to_base64())
        olm_msg = olm_encrypts.encrypt(CLEARTEXT)

        # Convert the Olm message into a Vodo message structure.
        def pad_base64_decode(b64_str: str) -> bytes:
            """Add the required number of '=' padding to make the length a multiple of 4, then Base64 decode."""
            return base64.b64decode(b64_str + "=" * ((4 - len(b64_str) % 4) % 4))

        vodo_msg = Message(
            pad_base64_decode(olm_msg.ciphertext),
            pad_base64_decode(olm_msg.mac),
            pad_base64_decode(olm_msg.ephemeral_key),
        )

        # Decrypt the message with Vodo
        decrypted_plaintext = vodo_decryption.decrypt(vodo_msg)
        assert decrypted_plaintext == CLEARTEXT

    def test_vodo_encrypt_olm_decrypt(self):
        """Test encrypting with Vodo and decrypting with Olm."""
        olm_decryption = olm.pk.PkDecryption()

        public_key = Curve25519PublicKey.from_base64(olm_decryption.public_key)
        vodo_encryption = PkEncryption.from_key(public_key)
        vodo_msg = vodo_encryption.encrypt(CLEARTEXT)

        # Convert the Vodo message into an Olm message structure
        def unpad_base64_encode(vodo_bytes: bytes) -> str:
            """Base64 encode the given bytes and remove trailing '=' padding."""
            return base64.b64encode(vodo_bytes).decode("utf-8").rstrip("=")

        olm_msg = olm.pk.PkMessage(
            unpad_base64_encode(vodo_msg.ephemeral_key),
            unpad_base64_encode(vodo_msg.mac),
            unpad_base64_encode(vodo_msg.ciphertext),
        )

        # Decrypt the message with Olm
        decrypted_plaintext = olm_decryption.decrypt(olm_msg)
        assert decrypted_plaintext.encode("utf-8") == CLEARTEXT
