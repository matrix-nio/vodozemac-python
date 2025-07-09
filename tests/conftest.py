import pytest

from vodozemac import Account, GroupSession
from vodozemac.vodozemac import InboundGroupSession


@pytest.fixture(scope="session")
def pickle_key():
    return b"DEFAULT_PICKLE_KEY_1234567890___"


@pytest.fixture(scope="module")
def account() -> Account:
    return Account()

@pytest.fixture(scope="module")
def group_session() -> GroupSession:
    return GroupSession()

@pytest.fixture(scope="module")
def inbound_group_session(group_session: GroupSession) -> InboundGroupSession:
    return InboundGroupSession(group_session.session_key)
