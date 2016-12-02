import pytest

from pyaxo import Axolotl, generate_keypair

from . import utils


@pytest.fixture()
def a_identity_keys():
    return generate_keypair()


@pytest.fixture()
def b_identity_keys():
    return generate_keypair()


@pytest.fixture()
def c_identity_keys():
    return generate_keypair()


@pytest.fixture()
def a_handshake_keys():
    return generate_keypair()


@pytest.fixture()
def b_handshake_keys():
    return generate_keypair()


@pytest.fixture()
def c_handshake_keys():
    return generate_keypair()


@pytest.fixture()
def a_ratchet_keys():
    return generate_keypair()


@pytest.fixture()
def b_ratchet_keys():
    return generate_keypair()


@pytest.fixture()
def c_ratchet_keys():
    return generate_keypair()


@pytest.fixture()
def axolotl_a():
    return Axolotl('Angie', dbpassphrase=None)


@pytest.fixture()
def axolotl_b():
    return Axolotl('Barb', dbpassphrase=None)


@pytest.fixture()
def axolotl_c():
    return Axolotl('Charlie', dbpassphrase=None)


@pytest.fixture(params=utils.EXCHANGES, ids=utils.EXCHANGE_IDS)
def exchange(request):
    return request.param
