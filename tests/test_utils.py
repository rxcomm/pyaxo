import pytest

from pyaxo import generate_keypair


@pytest.fixture()
def keypair():
    return generate_keypair()


def test_keypair_tuple(keypair):
    assert isinstance(keypair, tuple)
    assert keypair.priv == keypair[0] and keypair.pub == keypair[1]


def test_keypair_different_values(keypair):
    assert keypair.priv != keypair.pub


def test_keypair_bytes(keypair):
    assert isinstance(keypair.priv, bytes) and isinstance(keypair.pub, bytes)
