import pytest
from hypothesis import given
from vodozemac import (
    GroupSession,
    InboundGroupSession,
    MegolmDecryptionException,
    PickleException,
)

@pytest.fixture(scope="module")
def group_session() -> GroupSession:
    return GroupSession()

@pytest.fixture(scope="module")
def inbound_group_session(group_session: GroupSession) -> InboundGroupSession:
    return InboundGroupSession(group_session.session_key)


def test_create(group_session: GroupSession, inbound_group_session: InboundGroupSession):
    assert isinstance(group_session.session_id, str)
    assert isinstance(group_session.message_index, int)
    assert group_session.message_index == 0

    assert isinstance(inbound_group_session.first_known_index, int)
    assert inbound_group_session.first_known_index == 0

    assert group_session.session_id == inbound_group_session.session_id

def test_outbound_pickle(group_session: GroupSession, pickle_key: bytes):
    pickle = group_session.pickle(pickle_key)
    unpickled = GroupSession.from_pickle(pickle, pickle_key)

    assert group_session.session_id == unpickled.session_id

def test_outbound_pickle_fail(group_session: GroupSession, pickle_key: bytes):
    wrong_pickle_key = b"It's a secret to everybody 12345"
    pickle = group_session.pickle(wrong_pickle_key)

    with pytest.raises(ValueError):
        GroupSession.from_pickle(pickle, pickle_key)

@pytest.mark.parametrize("cls", (GroupSession, InboundGroupSession))
def test_invalid_pickle(cls: type, pickle_key: bytes):
    with pytest.raises(PickleException):
        cls.from_pickle("", pickle_key)


def test_inbound_create(inbound_group_session: InboundGroupSession, pickle_key: bytes):
    pickle = inbound_group_session.pickle(pickle_key)
    unpickled = InboundGroupSession.from_pickle(pickle, pickle_key)
    assert unpickled.session_id == inbound_group_session.session_id

@given(message1=..., message2=...)
def test_encrypt_twice(group_session: GroupSession, inbound_group_session: InboundGroupSession, message1: bytes, message2: bytes):
    decrypted1 = inbound_group_session.decrypt(group_session.encrypt(message1))
    assert decrypted1.plaintext == message1

    decrypted2 = inbound_group_session.decrypt(group_session.encrypt(message2))
    assert decrypted2.plaintext == message2

    assert decrypted2.message_index == decrypted1.message_index + 1

def test_decrypt_failure(inbound_group_session: InboundGroupSession):
    wrong_group_session = GroupSession()
    with pytest.raises(MegolmDecryptionException):
        inbound_group_session.decrypt(wrong_group_session.encrypt(b"Test"))


@given(message=...)
def test_inbound_export(group_session: GroupSession, inbound_group_session: InboundGroupSession, message: bytes):
    imported = InboundGroupSession.import_session(
        session_key=inbound_group_session.export_at(
            index=inbound_group_session.first_known_index
        )
    )
    index = group_session.message_index
    decrypted = imported.decrypt(group_session.encrypt(message))

    assert decrypted.plaintext == message
    assert decrypted.message_index == index

def test_outbound_clear():
    session = GroupSession()
    del session

def test_inbound_clear():
    outbound = GroupSession()
    inbound = InboundGroupSession(outbound.session_key)
    del inbound
