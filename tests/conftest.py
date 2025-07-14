import pytest


@pytest.fixture(scope="session")
def pickle_key():
    return b"DEFAULT_PICKLE_KEY_1234567890___"