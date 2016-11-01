import sqlite3

import pytest

from pyaxo import Axolotl

from . import utils


PASSPHRASES = [None, '123', '321']


class TestDefaultDatabase:
    dbs = [utils.DEFAULT_DB]

    def test_shared_db(self):
        # create two instance classes - one which will share its database
        # (note that Dick and Harry's passphrases must match or Harry won't
        # be able to load Dick's saved database)
        shared_pass = 'shared passphrase'
        tom = Axolotl('Tom', dbpassphrase="tom's passphrase")
        dick = Axolotl('Dick', dbpassphrase=shared_pass)

        # initialize Tom and Dick's states
        tom.initState(other_name=dick.name,
                      other_identityKey=dick.state['DHIs'],
                      other_handshakeKey=dick.handshakePKey,
                      other_ratchetKey=dick.state['DHRs'],
                      verify=False)
        dick.initState(other_name=tom.name,
                       other_identityKey=tom.state['DHIs'],
                       other_handshakeKey=tom.handshakePKey,
                       other_ratchetKey=tom.state['DHRs'],
                       verify=False)

        # get the plaintext
        with open('./file.txt', 'r') as f:
            msg = f.read()

        # Tom encrypts it to Dick
        ciphertext = tom.encrypt(msg)

        # save Dick's state prior to decrypting the message
        dick.saveState()

        # Dick decrypts the ciphertext
        assert dick.decrypt(ciphertext) == msg

        # now load Dick's state to Harry
        harry = Axolotl('Harry', dbpassphrase=shared_pass)
        harry.loadState(dick.name, tom.name)

        # Harry decrypts the ciphertext
        assert harry.decrypt(ciphertext) == msg

    @pytest.mark.parametrize('passphrase_1', PASSPHRASES)
    @pytest.mark.parametrize('passphrase_0', PASSPHRASES)
    def test_passphrase(self, passphrase_0, passphrase_1):
        a = Axolotl('Angie', dbpassphrase=passphrase_0)
        b = Axolotl('Barb', dbpassphrase=None)

        a.initState(other_name=b.name,
                    other_identityKey=b.state['DHIs'],
                    other_handshakeKey=b.handshakePKey,
                    other_ratchetKey=b.state['DHRs'],
                    verify=False)
        a.saveState()

        if passphrase_0 == passphrase_1:
            a = Axolotl('Angie', dbpassphrase=passphrase_1)
            assert isinstance(a.db, sqlite3.Connection)
        else:
            with pytest.raises(SystemExit):
                a = Axolotl('Angie', dbpassphrase=passphrase_1)


class TestIndividualDatabases:
    dbs = ['angie.db', 'barb.db']

    def test_individual_dbs(self, exchange):
        # create two instance classes with encrypted databases
        a = Axolotl('angie', dbname=self.dbs[0], dbpassphrase=self.dbs[0])
        b = Axolotl('barb', dbname=self.dbs[1], dbpassphrase=self.dbs[1])

        # initialize the states
        a.initState(other_name=b.name,
                    other_identityKey=b.state['DHIs'],
                    other_handshakeKey=b.handshakePKey,
                    other_ratchetKey=b.state['DHRs'],
                    verify=False)
        b.initState(other_name=a.name,
                    other_identityKey=a.state['DHIs'],
                    other_handshakeKey=a.handshakePKey,
                    other_ratchetKey=a.state['DHRs'],
                    verify=False)

        # save the states
        a.saveState()
        b.saveState()

        # reload the databases
        a = Axolotl('angie', dbname=self.dbs[0], dbpassphrase=self.dbs[0])
        b = Axolotl('barb', dbname=self.dbs[1], dbpassphrase=self.dbs[1])

        # load their states
        a.loadState(a.name, b.name)
        b.loadState(b.name, a.name)

        # send some messages back and forth
        exchange(a, b)


@pytest.fixture(autouse=True)
def setup_teardown_dbs(request):
    remove_dbs(request.cls.dbs)
    yield
    remove_dbs(request.cls.dbs)


def remove_dbs(dbs):
    for db in dbs:
        utils.remove_db(db)
