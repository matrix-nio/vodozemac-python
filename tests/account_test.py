import vodozemac
import pytest

from vodozemac import Account, PickleException, SignatureException

PICKLE_KEY = b"DEFAULT_PICKLE_KEY_1234567890___"

class TestClass(object):
    def test_account_creation(self):
        account = Account()

        assert account.ed25519_key
        assert account.curve25519_key

    def test_generating_onet_time_keys(self):
        account = Account()

        assert len(account.one_time_keys) == 0

        account.generate_one_time_keys(10)
        assert len(account.one_time_keys) == 10

    def test_pickling(self):
        alice = Account()
        pickle = alice.pickle(PICKLE_KEY)
        unpickled = Account.from_pickle(pickle, PICKLE_KEY)
        assert (alice.ed25519_key == unpickled.ed25519_key)

    def test_libolm_pickling(self):
        pickle = (
                "3wpPcPT4xsRYCYF34NcnozxE5bN2E6qwBXQYuoovt/TX//8Dnd8gaKsxN9En/"
                "7Hkh5XemuGUo3dXHVTl76G2pjf9ehfryhITMbeBrE/XuxmNvS2aB9KU4mOKXl"
                "AWhCEsE7JW9fUkRhHWWkFwTvSC3eDthd6eNx3VKZlmGR270vIpIG5/Ho4YK9/"
                "03lPGpil0cuEuGTTjKHXGRu9kpnQe99QGCB4KBuP5IJjFeWbtSgJ4ZrajZdlTew"
        )

        unpickled = Account.from_libolm_pickle(pickle, b"It's a secret to everybody")

        assert unpickled.ed25519_key.to_base64() == "MEQCwaTE/gcrHaxwv06WEVy5xDA30FboFzCAtYhzmoc"

    def test_invalid_pickle(self):
        with pytest.raises(PickleException):
            Account.from_pickle("", PICKLE_KEY)

    def test_max_one_time_keys(self):
        alice = Account()
        assert isinstance(alice.max_number_of_one_time_keys, int)

    def test_publish_one_time_keys(self):
        alice = Account()
        alice.generate_one_time_keys(10)

        assert len(alice.one_time_keys) == 10

        alice.mark_keys_as_published()
        assert not alice.one_time_keys

    def test_signing(self):
        alice = Account()
        signature = alice.sign(b"This is a test")

        alice.ed25519_key.verify_signature(b"This is a test", signature)
        with pytest.raises(SignatureException):
            alice.ed25519_key.verify_signature(b"This should fail", signature)
