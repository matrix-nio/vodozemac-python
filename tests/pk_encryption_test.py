import pytest
from base64 import b64encode
from hypothesis import given
from vodozemac import (
    Message,
    Curve25519PublicKey,
    Curve25519SecretKey,
    PkDecodeException,
    PkDecryption,
    PkEncryption,
)


@pytest.fixture(scope="module")
def pk_decryption() -> PkDecryption:
    return PkDecryption()

@pytest.fixture(scope="module")
def pk_encryption(pk_decryption: PkDecryption) -> PkEncryption:
    return PkEncryption.from_key(pk_decryption.public_key)

@pytest.fixture(scope="module")
def secret_key() -> Curve25519SecretKey:
    return Curve25519SecretKey()

@given(cleartext=...)
def test_round_trip(pk_decryption: PkDecryption, pk_encryption: PkEncryption, cleartext: bytes):
    assert cleartext == pk_decryption.decrypt(pk_encryption.encrypt(cleartext))

@given(cleartext=...)
def test_wrong_key(pk_decryption: PkDecryption, pk_encryption: PkEncryption, cleartext: bytes):
    with pytest.raises(PkDecodeException, match="MAC tag mismatch"):
        PkDecryption().decrypt(pk_encryption.encrypt(cleartext))

@given(cleartext=...)
def test_serialized_keys(secret_key: Curve25519SecretKey, cleartext: bytes):
    secret_key_bytes = secret_key.to_bytes()
    public_key_bytes = secret_key.public_key().to_bytes()

    d = PkDecryption.from_key(Curve25519SecretKey.from_bytes(secret_key_bytes))
    e = PkEncryption.from_key(Curve25519PublicKey.from_bytes(public_key_bytes))

    assert cleartext == d.decrypt(e.encrypt(cleartext))

@given(cleartext=...)
def test_encrypt_message_attr(cleartext: bytes):
    """Test that the Message object has accessible Python attributes (mac, ciphertext, ephemeral_key)."""
    decryption = PkDecryption()
    encryption = PkEncryption.from_key(decryption.public_key)

    message = encryption.encrypt(cleartext)

    assert message.mac is not None
    assert message.ciphertext is not None
    assert message.ephemeral_key is not None


def test_message_from_invalid_base64():
    """Test that invalid base64 input raises PkDecodeException."""
    # Test invalid ciphertext
    with pytest.raises(PkDecodeException, match="Invalid symbol"):
        Message.from_base64(
            "not-valid-base64!@#",  # Invalid base64 for ciphertext
            b64encode(b"some_mac").decode(),  # Valid base64
            b64encode(b"some_key").decode()   # Valid base64
        )

    # Test invalid mac
    with pytest.raises(PkDecodeException, match="Invalid symbol"):
        Message.from_base64(
            b64encode(b"some_text").decode(),
            "not-valid-base64!@#",  # Invalid base64 for mac
            b64encode(b"some_key").decode()
        )

    # Test invalid ephemeral key
    with pytest.raises(PkDecodeException, match="Invalid symbol"):
        Message.from_base64(
            b64encode(b"some_text").decode(),
            b64encode(b"some_mac").decode(),
            "not-valid-base64!@#"  # Invalid base64 for ephemeral key
        )