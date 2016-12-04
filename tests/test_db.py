import sqlite3
from copy import deepcopy

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
        msg = 'plaintext'

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

    def test_delete_conversation(
            self, axolotl_a, axolotl_b, axolotl_c,
            a_identity_keys, b_identity_keys, c_identity_keys,
            a_handshake_keys, b_handshake_keys, c_handshake_keys,
            a_ratchet_keys, b_ratchet_keys, c_ratchet_keys):
        conv_b = axolotl_a.init_conversation(
            axolotl_b.name,
            priv_identity_key=a_identity_keys.priv,
            identity_key=a_identity_keys.pub,
            priv_handshake_key=a_handshake_keys.priv,
            other_identity_key=b_identity_keys.pub,
            other_handshake_key=b_handshake_keys.pub,
            priv_ratchet_key=a_ratchet_keys.priv,
            ratchet_key=a_ratchet_keys.pub,
            other_ratchet_key=b_ratchet_keys.pub)

        conv_b.save()
        conv_b.delete()

        assert not axolotl_a.load_conversation(axolotl_b.name)

    def test_get_other_names(
            self, axolotl_a, axolotl_b, axolotl_c,
            a_identity_keys, b_identity_keys, c_identity_keys,
            a_handshake_keys, b_handshake_keys, c_handshake_keys,
            a_ratchet_keys, b_ratchet_keys, c_ratchet_keys):
        conv_b = axolotl_a.init_conversation(
            axolotl_b.name,
            priv_identity_key=a_identity_keys.priv,
            identity_key=a_identity_keys.pub,
            priv_handshake_key=a_handshake_keys.priv,
            other_identity_key=b_identity_keys.pub,
            other_handshake_key=b_handshake_keys.pub,
            priv_ratchet_key=a_ratchet_keys.priv,
            ratchet_key=a_ratchet_keys.pub,
            other_ratchet_key=b_ratchet_keys.pub)

        conv_c = axolotl_a.init_conversation(
            axolotl_c.name,
            priv_identity_key=a_identity_keys.priv,
            identity_key=a_identity_keys.pub,
            priv_handshake_key=a_handshake_keys.priv,
            other_identity_key=c_identity_keys.pub,
            other_handshake_key=c_handshake_keys.pub,
            priv_ratchet_key=a_ratchet_keys.priv,
            ratchet_key=a_ratchet_keys.pub,
            other_ratchet_key=c_ratchet_keys.pub)

        conv_b.save()
        conv_c.save()

        assert (sorted(axolotl_a.get_other_names()) ==
                sorted([axolotl_b.name, axolotl_c.name]))


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

    def test_persist_skipped_mk(
            self, a_identity_keys, a_handshake_keys, a_ratchet_keys,
            b_identity_keys, b_handshake_keys, b_ratchet_keys):
        a = Axolotl('angie', dbname=self.dbs[0], dbpassphrase=self.dbs[0])
        b = Axolotl('barb', dbname=self.dbs[1], dbpassphrase=self.dbs[1])

        conv_a = a.init_conversation(
            b.name,
            priv_identity_key=a_identity_keys.priv,
            identity_key=a_identity_keys.pub,
            priv_handshake_key=a_handshake_keys.priv,
            other_identity_key=b_identity_keys.pub,
            other_handshake_key=b_handshake_keys.pub,
            priv_ratchet_key=a_ratchet_keys.priv,
            ratchet_key=a_ratchet_keys.pub,
            other_ratchet_key=b_ratchet_keys.pub)

        conv_b = b.init_conversation(
            a.name,
            priv_identity_key=b_identity_keys.priv,
            identity_key=b_identity_keys.pub,
            priv_handshake_key=b_handshake_keys.priv,
            other_identity_key=a_identity_keys.pub,
            other_handshake_key=a_handshake_keys.pub,
            priv_ratchet_key=b_ratchet_keys.priv,
            ratchet_key=b_ratchet_keys.pub,
            other_ratchet_key=a_ratchet_keys.pub)

        pt = [utils.PLAINTEXT.format(i) for i in range(5)]
        ct = list()

        utils.encrypt(conv_a, 0, pt, ct)
        utils.decrypt(conv_b, 0, pt, ct)
        utils.encrypt(conv_a, 1, pt, ct)
        utils.encrypt(conv_a, 2, pt, ct)
        utils.decrypt(conv_b, 2, pt, ct)
        utils.encrypt(conv_a, 3, pt, ct)
        utils.encrypt(conv_a, 4, pt, ct)
        utils.decrypt(conv_b, 4, pt, ct)

        # make sure there are staged skipped keys
        assert conv_b.staged_hk_mk

        # save the database, copy the staged keys dict and delete the objects
        conv_b.save()
        persisted_hk_mk = deepcopy(conv_b.staged_hk_mk)
        del b, conv_b

        # load the conversation from disk
        B = Axolotl('barb', dbname=self.dbs[1], dbpassphrase=self.dbs[1])
        conv_B = B.load_conversation(a.name)

        # assert both dicts have the same content
        assert conv_B.staged_hk_mk.keys() == persisted_hk_mk.keys()
        for mk in conv_B.staged_hk_mk:
            assert conv_B.staged_hk_mk[mk].mk == persisted_hk_mk[mk].mk
            assert conv_B.staged_hk_mk[mk].hk == persisted_hk_mk[mk].hk
            assert (conv_B.staged_hk_mk[mk].timestamp ==
                    persisted_hk_mk[mk].timestamp)

        # decrypt the skipped messages
        utils.decrypt(conv_B, 1, pt, ct)
        utils.decrypt(conv_B, 3, pt, ct)


@pytest.fixture(autouse=True)
def setup_teardown_dbs(request):
    remove_dbs(request.cls.dbs)
    yield
    remove_dbs(request.cls.dbs)


def remove_dbs(dbs):
    for db in dbs:
        utils.remove_db(db)
