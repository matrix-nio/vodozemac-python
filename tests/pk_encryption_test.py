import pytest
from hypothesis import given
from vodozemac import (
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
