import pytest

from vodozemac import (
    Account,
    AnyOlmMessage,
    DecodeException,
    Session,
    PickleException,
    KeyException,
)

PICKLE_KEY = b"DEFAULT_PICKLE_KEY_1234567890___"


class TestClass(object):
    def _create_session(self):
        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)

        identity_key = bob.curve25519_key
        one_time_key = list(bob.one_time_keys.values())[0]

        session = alice.create_outbound_session(identity_key, one_time_key)

        return alice, bob, session

    def test_session_create(self):
        _, _, session_1 = self._create_session()
        _, _, session_2 = self._create_session()
        assert session_1
        assert session_2
        assert session_1.session_id != session_2.session_id
        assert isinstance(session_1.session_id, str)

    def test_session_clear(self):
        _, _, session = self._create_session()
        del session

    def test_session_pickle(self):
        alice, bob, session = self._create_session()
        unpickled = Session.from_pickle(session.pickle(PICKLE_KEY), PICKLE_KEY)
        assert unpickled.session_id == session.session_id

    def test_session_invalid_pickle(self):
        with pytest.raises(PickleException):
            Session.from_pickle("", PICKLE_KEY)

    def test_wrong_passphrase_pickle(self):
        alice, bob, session = self._create_session()
        pickle_key = b"It's a secret to everybody 12345"
        pickle = session.pickle(pickle_key)

        with pytest.raises(PickleException):
            Session.from_pickle(pickle, PICKLE_KEY)

    def test_encrypt(self):
        plaintext = b"It's a secret to everybody"
        alice, bob, session = self._create_session()
        message = session.encrypt(plaintext)

        message = message.to_pre_key()
        assert message != None

        (bob_session, decrypted) = bob.create_inbound_session(
            alice.curve25519_key, message
        )
        assert plaintext == decrypted

    def test_empty_message(self):
        with pytest.raises(DecodeException):
            AnyOlmMessage.from_parts(0, b"x")

    def test_two_messages(self):
        plaintext = b"It's a secret to everybody"
        alice, bob, session = self._create_session()
        message = session.encrypt(plaintext)
        message = message.to_pre_key()

        (bob_session, decrypted) = bob.create_inbound_session(
            alice.curve25519_key, message
        )
        assert plaintext == decrypted

        bob_plaintext = b"Grumble, Grumble"
        bob_message = bob_session.encrypt(bob_plaintext)

        assert bob_plaintext == session.decrypt(bob_message)

    def test_matches(self):
        plaintext = b"It's a secret to everybody"
        alice, bob, session = self._create_session()
        message = session.encrypt(plaintext)
        message = message.to_pre_key()

        (bob_session, decrypted) = bob.create_inbound_session(
            alice.curve25519_key, message
        )
        assert plaintext == decrypted

        message2 = session.encrypt(b"Hey! Listen!")
        message2 = message2.to_pre_key()

        assert bob_session.session_matches(message2) is True

    def test_invalid(self):
        alice, bob, session = self._create_session()
        _, _, another_session = self._create_session()

        message = another_session.encrypt(b"It's a secret to everybody")
        message = message.to_pre_key()

        assert not session.session_matches(message)

    def test_does_not_match(self):
        plaintext = b"It's a secret to everybody"
        alice, bob, session = self._create_session()
        message = session.encrypt(plaintext)
        message = message.to_pre_key()

        (bob_session, decrypted) = bob.create_inbound_session(
            alice.curve25519_key, message
        )

        _, _, new_session = self._create_session()

        new_message = new_session.encrypt(plaintext)
        new_message = new_message.to_pre_key()
        assert bob_session.session_matches(new_message) is False

    def test_message_to_parts(self):
        plaintext = b"It's a secret to everybody"
        alice, bob, session = self._create_session()
        message = session.encrypt(plaintext)

        (message_type, ciphertext) = message.to_parts()

        message = AnyOlmMessage.from_parts(message_type, ciphertext)
        message = message.to_pre_key()

        (bob_session, decrypted) = bob.create_inbound_session(
            alice.curve25519_key, message
        )

        assert plaintext == decrypted
