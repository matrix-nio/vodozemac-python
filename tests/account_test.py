import pytest
from hypothesis import strategies as st, given
from vodozemac import Account, PickleException, SignatureException, Ed25519PublicKey, Curve25519PublicKey

PICKLE_KEY = b"DEFAULT_PICKLE_KEY_1234567890___"
PICKLE_STRATEGY = st.binary(min_size=32, max_size=32)

@pytest.fixture(scope="module")
def account() -> Account:
    return Account()

def test_creation(account: Account):
    assert isinstance(account.ed25519_key, Ed25519PublicKey)
    assert isinstance(account.curve25519_key, Curve25519PublicKey)
    assert isinstance(account.max_number_of_one_time_keys, int)

def test_generate_and_publish_one_time_keys(account: Account):
    assert len(account.one_time_keys) == 0
    account.generate_one_time_keys(10)
    assert len(account.one_time_keys) == 10
    account.mark_keys_as_published()
    assert not account.one_time_keys

def test_pickling(account: Account):
    pickle = account.pickle(PICKLE_KEY)
    unpickled = Account.from_pickle(pickle, PICKLE_KEY)
    assert account.ed25519_key == unpickled.ed25519_key
    assert account.curve25519_key == unpickled.curve25519_key
    assert account.one_time_keys == unpickled.one_time_keys

def test_libolm_pickling():
    pickle = (
        "3wpPcPT4xsRYCYF34NcnozxE5bN2E6qwBXQYuoovt/TX//8Dnd8gaKsxN9En/"
        "7Hkh5XemuGUo3dXHVTl76G2pjf9ehfryhITMbeBrE/XuxmNvS2aB9KU4mOKXl"
        "AWhCEsE7JW9fUkRhHWWkFwTvSC3eDthd6eNx3VKZlmGR270vIpIG5/Ho4YK9/"
        "03lPGpil0cuEuGTTjKHXGRu9kpnQe99QGCB4KBuP5IJjFeWbtSgJ4ZrajZdlTew"
    )

    unpickled = Account.from_libolm_pickle(pickle, b"It's a secret to everybody")

    assert unpickled.ed25519_key.to_base64() == "MEQCwaTE/gcrHaxwv06WEVy5xDA30FboFzCAtYhzmoc"

def test_invalid_pickle():
    with pytest.raises(PickleException):
        Account.from_pickle("", PICKLE_KEY)

@given(message=...)
def test_signing(account: Account, message: bytes):
    signature = account.sign(message)
    account.ed25519_key.verify_signature(message, signature)
    with pytest.raises(SignatureException):
        account.ed25519_key.verify_signature(b"This should fail", signature)
