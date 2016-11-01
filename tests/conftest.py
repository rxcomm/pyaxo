import pytest

from . import utils


@pytest.fixture(params=utils.EXCHANGES, ids=utils.EXCHANGE_IDS)
def exchange(request):
    return request.param
