from collections.abc import Generator
from typing import TypeAlias

import pytest
from vodozemac import (
    Account,
    AnyOlmMessage,
    DecodeException,
    Session,
    PickleException,
    PreKeyMessage
)


@pytest.fixture(scope="module")
def alice() -> Account:
    return Account()

@pytest.fixture(scope="module")
def bob() -> Account:
    return Account()

SessionGenerator: TypeAlias = Generator[Session]

@pytest.fixture
def alice_session_gen(alice: Account, bob: Account) -> SessionGenerator:
    def session_generator() -> SessionGenerator:
        while True:
            bob.generate_one_time_keys(1)
            identity_key = bob.curve25519_key
            one_time_key = next(iter(bob.one_time_keys.values()))
            yield alice.create_outbound_session(identity_key, one_time_key)
    return session_generator()

@pytest.fixture
def alice_session(alice_session_gen: SessionGenerator) -> Session:
    return next(alice_session_gen)

def test_create(alice_session_gen: SessionGenerator):
    session1, session2 = next(alice_session_gen), next(alice_session_gen)
    assert session1.session_id != session2.session_id
    for session in (session1, session2):
        assert isinstance(session, Session)
        assert isinstance(session.session_id, str)

def test_clear(alice_session: Session):
    del alice_session

def test_pickle(alice_session: Session, pickle_key: bytes):
    unpickled = Session.from_pickle(alice_session.pickle(pickle_key), pickle_key)
    assert unpickled.session_id == alice_session.session_id

def test_wrong_pickle_key(alice_session: Session, pickle_key: bytes):
    pickle = alice_session.pickle(pickle_key)
    with pytest.raises(PickleException):
        Session.from_pickle(pickle, b"Definitely wrong key")

def test_invalid_pickle(pickle_key: bytes):
    with pytest.raises(PickleException):
        Session.from_pickle("", pickle_key)

def test_two_messages(alice: Account, bob: Account, alice_session: Session):
    alice_plaintext = b"It's a secret to everybody"
    alice_message = alice_session.encrypt(alice_plaintext).to_pre_key()

    assert isinstance(alice_message, PreKeyMessage)

    bob_session, alice_decrypted = bob.create_inbound_session(alice.curve25519_key, alice_message)
    assert alice_plaintext == alice_decrypted

    bob_plaintext = b"Grumble, Grumble"
    bob_message = bob_session.encrypt(bob_plaintext)

    assert bob_plaintext == alice_session.decrypt(bob_message)

def test_empty_message():
    with pytest.raises(DecodeException):
        AnyOlmMessage.from_parts(0, b"x")

def test_matches(alice: Account, bob: Account, alice_session_gen: SessionGenerator):
    alice_plaintext = b"It's a secret to everybody"
    alice_session1, alice_session2 = next(alice_session_gen), next(alice_session_gen)
    alice_message1 = alice_session1.encrypt(alice_plaintext).to_pre_key()

    bob_session, alice_decrypted = bob.create_inbound_session(alice.curve25519_key, alice_message1)
    assert alice_plaintext == alice_decrypted

    alice_message2 = alice_session2.encrypt(alice_plaintext).to_pre_key()
    assert bob_session.session_matches(alice_message2) is False

def test_does_not_match(alice: Account, bob: Account, alice_session: Session):
    alice_plaintext = b"It's a secret to everybody"
    alice_message1 = alice_session.encrypt(alice_plaintext).to_pre_key()

    bob_session, alice_decrypted = bob.create_inbound_session(alice.curve25519_key, alice_message1)
    assert alice_plaintext == alice_decrypted

    alice_message2 = alice_session.encrypt(b"Hey! Listen!").to_pre_key()
    assert bob_session.session_matches(alice_message2) is True

def test_invalid(alice_session_gen: SessionGenerator):
    session1, session2 = next(alice_session_gen), next(alice_session_gen)
    message = session1.encrypt(b"It's a secret to everybody").to_pre_key()

    assert not session2.session_matches(message)

def test_message_to_parts(alice: Account, bob: Account, alice_session: Session):
    alice_plaintext = b"It's a secret to everybody"
    encrypted = alice_session.encrypt(alice_plaintext)

    alice_message = encrypted.to_pre_key()
    alice_message_from_parts = AnyOlmMessage.from_parts(*encrypted.to_parts()).to_pre_key()

    assert alice_message.session_id() == alice_message_from_parts.session_id()

    bob_session, alice_decrypted = bob.create_inbound_session(alice.curve25519_key, alice_message)
    assert alice_plaintext == alice_decrypted
