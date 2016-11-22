import pytest

from pyaxo import Axolotl

from . import utils


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
