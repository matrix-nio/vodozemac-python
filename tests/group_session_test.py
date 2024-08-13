import pytest

from vodozemac import (
    InboundGroupSession,
    GroupSession,
    PickleException,
    DecodeException,
    MegolmDecryptionException,
)

PICKLE_KEY = b"DEFAULT_PICKLE_KEY_1234567890___"


class TestClass(object):
    def test_session_create(self):
        GroupSession()

    def test_session_id(self):
        session = GroupSession()
        assert isinstance(session.session_id, str)

    def test_session_index(self):
        session = GroupSession()
        assert isinstance(session.message_index, int)
        assert session.message_index == 0

    def test_outbound_pickle(self):
        session = GroupSession()
        pickle = session.pickle(PICKLE_KEY)
        unpickled = GroupSession.from_pickle(pickle, PICKLE_KEY)

        assert session.session_id == unpickled.session_id

    def test_invalid_unpickle(self):
        with pytest.raises(PickleException):
            GroupSession.from_pickle("", PICKLE_KEY)

        with pytest.raises(PickleException):
            InboundGroupSession.from_pickle("", PICKLE_KEY)

    def test_inbound_create(self):
        outbound = GroupSession()
        InboundGroupSession(outbound.session_key)

    def test_invalid_decrypt(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key)

        with pytest.raises(DecodeException):
            inbound.decrypt("")

    def test_inbound_pickle(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        pickle = inbound.pickle(PICKLE_KEY)
        InboundGroupSession.from_pickle(pickle, PICKLE_KEY)

    def test_inbound_export(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        imported = InboundGroupSession.import_session(
            inbound.export_at(inbound.first_known_index)
        )
        message = imported.decrypt(outbound.encrypt("Test"))
        assert message.plaintext == "Test"
        assert message.message_index == 0

    def test_first_index(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        index = inbound.first_known_index
        assert index == 0
        assert isinstance(index, int)

    def test_encrypt(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        message = inbound.decrypt(outbound.encrypt("Test"))
        assert "Test", 0 == inbound.decrypt(outbound.encrypt("Test"))

    def test_decrypt_twice(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        outbound.encrypt("Test 1")
        message = inbound.decrypt(outbound.encrypt("Test 2"))
        assert isinstance(message.message_index, int)
        assert message.message_index == 1
        assert message.plaintext == "Test 2"

    def test_decrypt_failure(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        eve_outbound = GroupSession()
        with pytest.raises(MegolmDecryptionException):
            inbound.decrypt(eve_outbound.encrypt("Test"))

    def test_id(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        assert outbound.session_id == inbound.session_id

    def test_inbound_fail(self):
        with pytest.raises(TypeError):
            InboundGroupSession()

    def test_outbound_pickle_fail(self):
        outbound = GroupSession()
        pickle_key = b"It's a secret to everybody 12345"
        pickle = outbound.pickle(pickle_key)

        with pytest.raises(ValueError):
            GroupSession.from_pickle(pickle, PICKLE_KEY)

    def test_outbound_clear(self):
        session = GroupSession()
        del session

    def test_inbound_clear(self):
        outbound = GroupSession()
        inbound = InboundGroupSession(outbound.session_key)
        del inbound
