"""
pyaxo.py - a python implementation of the axolotl ratchet protocol.
https://github.com/trevp/axolotl/wiki/newversion

Symmetric encryption is done using the python-gnupg module.

Copyright (C) 2014 by David R. Andersen <k0rx@RXcomm.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

For more information, see https://github.com/rxcomm/pyaxo
"""

import errno
import os
import sqlite3
import sys
import struct
from collections import namedtuple
from functools import wraps
from getpass import getpass
from threading import Lock
from time import time

import nacl.secret
import nacl.utils
from nacl.encoding import Base64Encoder
from nacl.exceptions import CryptoError
from nacl.hash import sha256
from nacl.public import PrivateKey, PublicKey, Box
from passlib.utils.pbkdf2 import pbkdf2


ALICE_MODE = True
BOB_MODE = False

SALTS = {'RK': b'\x00',
         'HK': {ALICE_MODE: b'\x01', BOB_MODE: b'\x02'},
         'NHK': {ALICE_MODE: b'\x03', BOB_MODE: b'\x04'},
         'CK': {ALICE_MODE: b'\x05', BOB_MODE: b'\x06'},
         'CONVid': b'\x07'}

HEADER_LEN = 84
HEADER_PAD_NUM_LEN = 1
HEADER_COUNT_NUM_LEN = 4


def sync(f):
    @wraps(f)
    def synced_f(self, *args, **kwargs):
        with self.lock:
            return f(self, *args, **kwargs)
    return synced_f


class Axolotl(object):

    def __init__(self, name, dbname='axolotl.db', dbpassphrase='', nonthreaded_sql=True):
        self.name = name
        self.dbname = dbname
        self.nonthreaded_sql = nonthreaded_sql
        if dbpassphrase is None:
            self.dbpassphrase = None
        elif dbpassphrase != '':
            self.dbpassphrase = hash_(dbpassphrase)
        else:
            self.dbpassphrase = getpass('Database passphrase for '+ self.name + ': ').strip()
        self.conversation = AxolotlConversation(self, keys=dict(), mode=None)
        self.state['DHIs_priv'], self.state['DHIs'] = generate_keypair()
        self.state['DHRs_priv'], self.state['DHRs'] = generate_keypair()
        self.handshakeKey, self.handshakePKey = generate_keypair()
        self.storeTime = 2*86400 # minimum time (seconds) to store missed ephemeral message keys
        self.persistence = SqlitePersistence(self.dbname,
                                             self.dbpassphrase,
                                             self.storeTime,
                                             self.nonthreaded_sql)

    @property
    def state(self):
        return self.conversation.keys

    @state.setter
    def state(self, state):
        self.conversation.keys = state

    @property
    def mode(self):
        return self.conversation.mode

    @mode.setter
    def mode(self, mode):
        self.conversation.mode = mode

    @property
    def db(self):
        return self.persistence.db

    @db.setter
    def db(self, db):
        self.persistence.db = db

    def tripleDH(self, a, a0, B, B0):
        if self.mode == None:
            sys.exit(1)
        return generate_3dh(a, a0, B, B0, self.mode)

    def genDH(self, a, B):
        return generate_dh(a, B)

    def genKey(self):
        return generate_keypair()

    def initState(self, other_name, other_identityKey, other_handshakeKey,
                  other_ratchetKey, verify=True):
        if verify:
            print 'Confirm ' + other_name + ' has identity key fingerprint:\n'
            fingerprint = hash_(other_identityKey).encode('hex').upper()
            fprint = ''
            for i in range(0, len(fingerprint), 4):
                fprint += fingerprint[i:i+2] + ':'
            print fprint[:-1] + '\n'
            print 'Be sure to verify this fingerprint with ' + other_name + \
                  ' by some out-of-band method!'
            print 'Otherwise, you may be subject to a Man-in-the-middle attack!\n'
            ans = raw_input('Confirm? y/N: ').strip()
            if ans != 'y':
                print 'Key fingerprint not confirmed - exiting...'
                sys.exit()

        self.conversation = self.init_conversation(other_name,
                                                   self.state['DHIs_priv'],
                                                   self.state['DHIs'],
                                                   self.handshakeKey,
                                                   other_identityKey,
                                                   other_handshakeKey,
                                                   self.state['DHRs_priv'],
                                                   self.state['DHRs'],
                                                   other_ratchetKey)

    def init_conversation(self, other_name,
                          priv_identity_key, identity_key, priv_handshake_key,
                          other_identity_key, other_handshake_key,
                          priv_ratchet_key=None, ratchet_key=None,
                          other_ratchet_key=None, mode=None):
        if mode is None:
            if identity_key < other_identity_key:
                mode = ALICE_MODE
            else:
                mode = BOB_MODE

        mkey = generate_3dh(priv_identity_key, priv_handshake_key,
                            other_identity_key, other_handshake_key,
                            mode)

        return self.create_conversation(other_name,
                                        mkey,
                                        mode,
                                        priv_identity_key,
                                        identity_key,
                                        other_identity_key,
                                        priv_ratchet_key,
                                        ratchet_key,
                                        other_ratchet_key)

    def createState(self, other_name, mkey, mode=None, other_identityKey=None, other_ratchetKey=None):
        if mode is not None:
            self.mode = mode
        else:
            if self.mode is None: # mode not selected
                sys.exit(1)

        self.conversation = self.create_conversation(other_name,
                                                     mkey,
                                                     self.mode,
                                                     self.state['DHIs_priv'],
                                                     self.state['DHIs'],
                                                     other_identityKey,
                                                     self.state['DHRs_priv'],
                                                     self.state['DHRs'],
                                                     other_ratchetKey)

        self.ratchetKey = False
        self.ratchetPKey = False

    def create_conversation(self, other_name, mkey, mode,
                            priv_identity_key, identity_key,
                            other_identity_key,
                            priv_ratchet_key=None, ratchet_key=None,
                            other_ratchet_key=None):
        if mode is ALICE_MODE:
            HKs = None
            HKr = kdf(mkey, SALTS['HK'][BOB_MODE])
            CKs = None
            CKr = kdf(mkey, SALTS['CK'][BOB_MODE])
            DHRs_priv = None
            DHRs = None
            DHRr = other_ratchet_key
            Ns = 0
            Nr = 0
            PNs = 0
            ratchet_flag = True
        else: # bob mode
            HKs = kdf(mkey, SALTS['HK'][BOB_MODE])
            HKr = None
            CKs = kdf(mkey, SALTS['CK'][BOB_MODE])
            CKr = None
            DHRs_priv = priv_ratchet_key
            DHRs = ratchet_key
            DHRr = None
            Ns = 0
            Nr = 0
            PNs = 0
            ratchet_flag = False
        RK = kdf(mkey, SALTS['RK'])
        NHKs = kdf(mkey, SALTS['NHK'][mode])
        NHKr = kdf(mkey, SALTS['NHK'][not mode])
        CONVid = kdf(mkey, SALTS['CONVid'])
        DHIr = other_identity_key

        keys = \
               { 'name': self.name,
                 'other_name': other_name,
                 'RK': RK,
                 'HKs': HKs,
                 'HKr': HKr,
                 'NHKs': NHKs,
                 'NHKr': NHKr,
                 'CKs': CKs,
                 'CKr': CKr,
                 'DHIs_priv': priv_identity_key,
                 'DHIs': identity_key,
                 'DHIr': DHIr,
                 'DHRs_priv': DHRs_priv,
                 'DHRs': DHRs,
                 'DHRr': DHRr,
                 'CONVid': CONVid,
                 'Ns': Ns,
                 'Nr': Nr,
                 'PNs': PNs,
                 'ratchet_flag': ratchet_flag,
               }

        return AxolotlConversation(self, keys, mode)

    def encrypt(self, plaintext):
        return self.conversation.encrypt(plaintext)

    def enc(self, key, plaintext):
        return encrypt_symmetric(key, plaintext)

    def dec(self, key, encrypted):
        return decrypt_symmetric(key, encrypted)

    def decrypt(self, msg):
        return self.conversation.decrypt(msg)

    def encrypt_file(self, filename):
        self.conversation.encrypt_file(filename)

    def decrypt_file(self, filename):
        self.conversation.decrypt_file(filename)

    def encrypt_pipe(self):
        self.conversation.encrypt_pipe()

    def decrypt_pipe(self):
        self.conversation.decrypt_pipe()

    def printKeys(self):
        self.conversation.print_keys()

    def saveState(self):
        self.save_conversation(self.conversation)

    def save_conversation(self, conversation):
        self.persistence.save_conversation(conversation)

    def loadState(self, name, other_name):
        self.persistence.db = self.openDB()
        self.conversation = self.load_conversation(other_name, name)
        if self.conversation:
            return
        else:
            return False

    def load_conversation(self, other_name, name=None):
        return self.persistence.load_conversation(self,
                                                  name or self.name,
                                                  other_name)

    def delete_conversation(self, conversation):
        return self.persistence.delete_conversation(conversation)

    def get_other_names(self):
        return self.persistence.get_other_names(self.name)

    def openDB(self):
        return self.persistence._open_db()

    def writeDB(self):
        self.persistence.write_db()

    def printState(self):
        self.conversation.print_state()


class AxolotlConversation:
    def __init__(self, axolotl, keys, mode, staged_hk_mk=None):
        self._axolotl = axolotl
        self.lock = Lock()
        self.keys = keys
        self.mode = mode
        self.staged_hk_mk = staged_hk_mk or dict()
        self.staged = False

        self.handshake_key = None
        self.handshake_pkey = None

    @property
    def name(self):
        return self.keys['name']

    @name.setter
    def name(self, name):
        self.keys['name'] = name

    @property
    def other_name(self):
        return self.keys['other_name']

    @other_name.setter
    def other_name(self, other_name):
        self.keys['other_name'] = other_name

    @property
    def id_(self):
        return self.keys['CONVid']

    @id_.setter
    def id_(self, id_):
        self.keys['CONVid'] = id_

    @property
    def ns(self):
        return self.keys['Ns']

    @ns.setter
    def ns(self, ns):
        self.keys['Ns'] = ns

    @property
    def nr(self):
        return self.keys['Nr']

    @nr.setter
    def nr(self, nr):
        self.keys['Nr'] = nr

    @property
    def pns(self):
        return self.keys['PNs']

    @pns.setter
    def pns(self, pns):
        self.keys['PNs'] = pns

    @property
    def ratchet_flag(self):
        return self.keys['ratchet_flag']

    @ratchet_flag.setter
    def ratchet_flag(self, ratchet_flag):
        self.keys['ratchet_flag'] = ratchet_flag

    def _try_skipped_mk(self, msg, pad_length):
        msg1 = msg[:HEADER_LEN-pad_length]
        msg2 = msg[HEADER_LEN:]
        for skipped_mk in self.staged_hk_mk.values():
            try:
                decrypt_symmetric(skipped_mk.hk, msg1)
                body = decrypt_symmetric(skipped_mk.mk, msg2)
            except CryptoError:
                pass
            else:
                del self.staged_hk_mk[skipped_mk.mk]
                return body
        return None

    def _stage_skipped_mk(self, hkr, nr, np, ckr):
        timestamp = int(time())
        ckp = ckr
        for i in range(np - nr):
            mk = hash_(ckp + '0')
            ckp = hash_(ckp + '1')
            self.staged_hk_mk[mk] = SkippedMessageKey(mk, hkr, timestamp)
            self.staged = True
        mk = hash_(ckp + '0')
        ckp = hash_(ckp + '1')
        return ckp, mk

    @sync
    def encrypt(self, plaintext):
        if self.ratchet_flag:
            self.keys['DHRs_priv'], self.keys['DHRs'] = generate_keypair()
            self.keys['HKs'] = self.keys['NHKs']
            self.keys['RK'] = hash_(self.keys['RK'] +
                                    generate_dh(self.keys['DHRs_priv'], self.keys['DHRr']))
            self.keys['NHKs'] = kdf(self.keys['RK'], SALTS['NHK'][self.mode])
            self.keys['CKs'] = kdf(self.keys['RK'], SALTS['CK'][self.mode])
            self.pns = self.ns
            self.ns = 0
            self.ratchet_flag = False
        mk = hash_(self.keys['CKs'] + '0')
        msg1 = encrypt_symmetric(
            self.keys['HKs'],
            struct.pack('>I', self.ns) + struct.pack('>I', self.pns) +
            self.keys['DHRs'])
        msg2 = encrypt_symmetric(mk, plaintext)
        pad_length = HEADER_LEN - len(msg1)
        pad = os.urandom(pad_length - HEADER_PAD_NUM_LEN) + chr(pad_length)
        msg = msg1 + pad + msg2
        self.ns += 1
        self.keys['CKs'] = hash_(self.keys['CKs'] + '1')
        return msg

    @sync
    def decrypt(self, msg):
        pad = msg[HEADER_LEN-HEADER_PAD_NUM_LEN:HEADER_LEN]
        pad_length = ord(pad)
        msg1 = msg[:HEADER_LEN-pad_length]

        body = self._try_skipped_mk(msg, pad_length)
        if body and body != '':
            return body

        header = None
        if self.keys['HKr']:
            try:
                header = decrypt_symmetric(self.keys['HKr'], msg1)
            except CryptoError:
                pass
        if header and header != '':
            Np = struct.unpack('>I', header[:HEADER_COUNT_NUM_LEN])[0]
            CKp, mk = self._stage_skipped_mk(self.keys['HKr'], self.nr, Np, self.keys['CKr'])
            try:
                body = decrypt_symmetric(mk, msg[HEADER_LEN:])
            except CryptoError:
                print 'Undecipherable message'
                sys.exit(1)
        else:
            try:
                header = decrypt_symmetric(self.keys['NHKr'], msg1)
            except CryptoError:
                pass
            if self.ratchet_flag or not header or header == '':
                print 'Undecipherable message'
                sys.exit(1)
            Np = struct.unpack('>I', header[:HEADER_COUNT_NUM_LEN])[0]
            PNp = struct.unpack('>I', header[HEADER_COUNT_NUM_LEN:HEADER_COUNT_NUM_LEN*2])[0]
            DHRp = header[HEADER_COUNT_NUM_LEN*2:]
            if self.keys['CKr']:
                self._stage_skipped_mk(self.keys['HKr'], self.nr, PNp, self.keys['CKr'])
            HKp = self.keys['NHKr']
            RKp = hash_(self.keys['RK'] + generate_dh(self.keys['DHRs_priv'], DHRp))
            NHKp = kdf(RKp, SALTS['NHK'][not self.mode])
            CKp = kdf(RKp, SALTS['CK'][not self.mode])
            CKp, mk = self._stage_skipped_mk(HKp, 0, Np, CKp)
            try:
                body = decrypt_symmetric(mk, msg[HEADER_LEN:])
            except CryptoError:
                pass
            if not body or body == '':
                print 'Undecipherable message'
                sys.exit(1)
            self.keys['RK'] = RKp
            self.keys['HKr'] = HKp
            self.keys['NHKr'] = NHKp
            self.keys['DHRr'] = DHRp
            self.keys['DHRs_priv'] = None
            self.keys['DHRs'] = None
            self.ratchet_flag = True
        self.nr = Np + 1
        self.keys['CKr'] = CKp
        return body

    def encrypt_file(self, filename):
        with open(filename, 'r') as f:
            plaintext = f.read()
        ciphertext = b2a(self.encrypt(plaintext)) + '\n'
        with open(filename+'.asc', 'w') as f:
            lines = [ciphertext[i:i+64] for i in xrange(0, len(ciphertext), 64)]
            for line in lines:
                f.write(line+'\n')

    def decrypt_file(self, filename):
        with open(filename, 'r') as f:
            ciphertext = a2b(f.read())
        plaintext = self.decrypt(ciphertext)
        print plaintext

    def encrypt_pipe(self):
        plaintext = sys.stdin.read()
        ciphertext = b2a(self.encrypt(plaintext)) + '\n'
        sys.stdout.write(ciphertext)
        sys.stdout.flush()

    def decrypt_pipe(self):
        ciphertext = a2b(sys.stdin.read())
        plaintext = self.decrypt(ciphertext)
        sys.stdout.write(plaintext)
        sys.stdout.flush()

    def save(self):
        self._axolotl.save_conversation(self)

    def delete(self):
        self._axolotl.delete_conversation(self)

    def print_keys(self):
        print 'Your Identity key is:\n' + b2a(self.keys['DHIs']) + '\n'
        fingerprint = hash_(self.keys['DHIs']).encode('hex').upper()
        fprint = ''
        for i in range(0, len(fingerprint), 4):
            fprint += fingerprint[i:i+2] + ':'
        print 'Your identity key fingerprint is: '
        print fprint[:-1] + '\n'
        print 'Your Ratchet key is:\n' + b2a(self.keys['DHRs']) + '\n'
        if self.handshake_key:
            print 'Your Handshake key is:\n' + b2a(self.handshake_pkey)
        else:
            print 'Your Handshake key is not available'

    def print_state(self):
        print
        print 'Warning: saving this data to disk is insecure!'
        print
        for key in sorted(self.keys):
             if 'priv' in key:
                 pass
             else:
                 if self.keys[key] is None:
                     print key + ': None'
                 elif type(self.keys[key]) is bool:
                     if self.keys[key]:
                         print key + ': True'
                     else:
                         print key + ': False'
                 elif type(self.keys[key]) is str:
                     try:
                         self.keys[key].decode('ascii')
                         print key + ': ' + self.keys[key]
                     except UnicodeDecodeError:
                         print key + ': ' + b2a(self.keys[key])
                 else:
                     print key + ': ' + str(self.keys[key])
        if self.mode is ALICE_MODE:
            print 'Mode: Alice'
        else:
            print 'Mode: Bob'


class SkippedMessageKey:
    def __init__(self, mk, hk, timestamp):
        self.mk = mk
        self.hk = hk
        self.timestamp = timestamp


class SqlitePersistence(object):
    def __init__(self, dbname, dbpassphrase, store_time, nonthreaded):
        super(SqlitePersistence, self).__init__()
        self.lock = Lock()
        self.dbname = dbname
        self.dbpassphrase = dbpassphrase
        self.store_time = store_time
        self.nonthreaded = nonthreaded

        self.db = self._open_db()

    def _open_db(self):
        db = sqlite3.connect(':memory:', check_same_thread=self.nonthreaded)
        db.row_factory = sqlite3.Row

        with db:
            try:
                if self.dbpassphrase is not None:
                    with open(self.dbname, 'rb') as f:
                        crypt_sql = f.read()
                        try:
                            sql = decrypt_symmetric(self.dbpassphrase,
                                                    crypt_sql)
                        except CryptoError:
                            print 'Bad passphrase!'
                            sys.exit(1)
                        else:
                            db.cursor().executescript(sql)
                else:
                    with open(self.dbname, 'r') as f:
                        sql = f.read()
                        try:
                            db.cursor().executescript(sql)
                        except sqlite3.OperationalError:
                            print 'Bad sql! Password problem - cannot create the database.'
                            sys.exit(1)
            except IOError as e:
                if e.errno == errno.ENOENT:
                    self._create_db(db)
                else:
                    raise
            else:
                self._delete_expired_skipped_mk(db)
        return db

    def _create_db(self, db):
        db.execute('''
            CREATE TABLE IF NOT EXISTS
                skipped_mk (
                    my_identity,
                    to_identity,
                    HKr TEXT,
                    mk TEXT,
                    timestamp INTEGER)''')
        db.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS
                message_keys
            ON
                skipped_mk (mk)''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS
                conversations (
                    my_identity TEXT,
                    other_identity TEXT,
                    RK TEXT,
                    HKs TEXT,
                    HKr TEXT,
                    NHKs TEXT,
                    NHKr TEXT,
                    CKs TEXT,
                    CKr TEXT,
                    DHIs_priv TEXT,
                    DHIs TEXT,
                    DHIr TEXT,
                    DHRs_priv TEXT,
                    DHRs TEXT,
                    DHRr TEXT,
                    CONVid TEXT,
                    Ns INTEGER,
                    Nr INTEGER,
                    PNs INTEGER,
                    ratchet_flag INTEGER,
                    mode INTEGER)''')
        db.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS
                conversation_route
            ON
                conversations (
                    my_identity,
                    other_identity)''')

    def _delete_expired_skipped_mk(self, db):
        timestamp = int(time())
        rowtime = timestamp - self.store_time
        db.execute('''
            DELETE FROM
                skipped_mk
            WHERE
                timestamp < ?''', (rowtime,))

    def _commit_skipped_mk(self, conversation):
        with self.db as db:
            db.execute('''
                DELETE FROM
                    skipped_mk
                WHERE
                    my_identity = ? AND
                    to_identity = ?''', (
                        conversation.name,
                        conversation.other_name))
            for skipped_mk in conversation.staged_hk_mk.values():
                db.execute('''
                    INSERT INTO
                        skipped_mk (
                            my_identity,
                            to_identity,
                            HKr,
                            mk,
                            timestamp)
                    VALUES (?, ?, ?, ?, ?)''', (
                        conversation.name,
                        conversation.other_name,
                        b2a(skipped_mk.hk),
                        b2a(skipped_mk.mk),
                        skipped_mk.timestamp))

    def _load_skipped_mk(self, name, other_name):
        skipped_hk_mk = dict()
        with self.db as db:
            rows = db.execute('''
                SELECT
                    *
                FROM
                    skipped_mk
                WHERE
                    my_identity = ? AND
                    to_identity = ?''', (name, other_name))
        for row in rows:
            mk = a2b(row['mk'])
            skipped_hk_mk[mk] = SkippedMessageKey(mk,
                                                  hk=a2b(row['hkr']),
                                                  timestamp=row['timestamp'])
        return skipped_hk_mk

    def write_db(self):
        with self.db as db:
            sql = bytes('\n'.join(db.iterdump()))
            if self.dbpassphrase is not None:
                crypt_sql = encrypt_symmetric(self.dbpassphrase, sql)
                with open(self.dbname, 'wb') as f:
                    f.write(crypt_sql)
            else:
                with open(self.dbname, 'w') as f:
                    f.write(sql)

    @sync
    def save_conversation(self, conversation):
        HKs = 0 if conversation.keys['HKs'] is None else b2a(conversation.keys['HKs'])
        HKr = 0 if conversation.keys['HKr'] is None else b2a(conversation.keys['HKr'])
        CKs = 0 if conversation.keys['CKs'] is None else b2a(conversation.keys['CKs'])
        CKr = 0 if conversation.keys['CKr'] is None else b2a(conversation.keys['CKr'])
        DHIr = 0 if conversation.keys['DHIr'] is None else b2a(conversation.keys['DHIr'])
        DHRs_priv = 0 if conversation.keys['DHRs_priv'] is None else b2a(conversation.keys['DHRs_priv'])
        DHRs = 0 if conversation.keys['DHRs'] is None else b2a(conversation.keys['DHRs'])
        DHRr = 0 if conversation.keys['DHRr'] is None else b2a(conversation.keys['DHRr'])
        ratchet_flag = 1 if conversation.ratchet_flag else 0
        mode = 1 if conversation.mode else 0
        with self.db as db:
            db.execute('''
                REPLACE INTO
                    conversations (
                        my_identity,
                        other_identity,
                        RK,
                        HKS,
                        HKr,
                        NHKs,
                        NHKr,
                        CKs,
                        CKr,
                        DHIs_priv,
                        DHIs,
                        DHIr,
                        DHRs_priv,
                        DHRs,
                        DHRr,
                        CONVid,
                        Ns,
                        Nr,
                        PNs,
                        ratchet_flag,
                        mode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?)''', (
                    conversation.name,
                    conversation.other_name,
                    b2a(conversation.keys['RK']),
                    HKs,
                    HKr,
                    b2a(conversation.keys['NHKs']),
                    b2a(conversation.keys['NHKr']),
                    CKs,
                    CKr,
                    b2a(conversation.keys['DHIs_priv']),
                    b2a(conversation.keys['DHIs']),
                    DHIr,
                    DHRs_priv,
                    DHRs,
                    DHRr,
                    b2a(conversation.keys['CONVid']),
                    conversation.ns,
                    conversation.nr,
                    conversation.pns,
                    ratchet_flag,
                    mode))
        self._commit_skipped_mk(conversation)
        self.write_db()

    @sync
    def load_conversation(self, axolotl, name, other_name):
        with self.db as db:
            cur = db.cursor()
            cur.execute('''
                SELECT
                    *
                FROM
                    conversations
                WHERE
                    my_identity = ? AND
                    other_identity = ?''', (name, other_name))
            row = cur.fetchone()
        if row:
            keys = \
                    { 'name': row['my_identity'],
                        'other_name': row['other_identity'],
                        'RK': a2b(row['rk']),
                        'NHKs': a2b(row['nhks']),
                        'NHKr': a2b(row['nhkr']),
                        'DHIs_priv': a2b(row['dhis_priv']),
                        'DHIs': a2b(row['dhis']),
                        'CONVid': a2b(row['convid']),
                        'Ns': row['ns'],
                        'Nr': row['nr'],
                        'PNs': row['pns'],
                    }
            keys['HKs'] = None if row['hks'] == '0' else a2b(row['hks'])
            keys['HKr'] = None if row['hkr'] == '0' else a2b(row['hkr'])
            keys['CKs'] = None if row['cks'] == '0' else a2b(row['cks'])
            keys['CKr'] = None if row['ckr'] == '0' else a2b(row['ckr'])
            keys['DHIr'] = None if row['dhir'] == '0' else a2b(row['dhir'])
            keys['DHRs_priv'] = None if row['dhrs_priv'] == '0' else a2b(row['dhrs_priv'])
            keys['DHRs'] = None if row['dhrs'] == '0' else a2b(row['dhrs'])
            keys['DHRr'] = None if row['dhrr'] == '0' else a2b(row['dhrr'])
            ratchet_flag = row['ratchet_flag']
            keys['ratchet_flag'] = True if ratchet_flag == 1 \
                                                else False
            mode = row['mode']
            mode = True if mode == 1 else False

            skipped_hk_mk = self._load_skipped_mk(name, other_name)

            # exit at first match
            return AxolotlConversation(axolotl, keys, mode, skipped_hk_mk)
        else:
            # if no matches
            return None

    @sync
    def delete_conversation(self, conversation):
        with self.db as db:
            db.execute('''
                DELETE FROM
                    skipped_mk
                WHERE
                    to_identity = ?''', (conversation.other_name,))
            db.execute('''
                DELETE FROM
                    conversations
                WHERE
                    other_identity = ?''', (conversation.other_name,))
        self.write_db()

    @sync
    def get_other_names(self, name):
        with self.db as db:
            rows = db.execute('''
                SELECT
                    other_identity
                FROM
                    conversations
                WHERE
                    my_identity = ?''', (name,))
            return [row['other_identity'] for row in rows]


def a2b(a):
    return Base64Encoder.decode(a)


def b2a(b):
    return Base64Encoder.encode(b)


def hash_(data):
    return sha256(data).decode('hex')


def kdf(secret, salt):
    return pbkdf2(secret, salt, rounds=10, prf='hmac-sha256')


Keypair = namedtuple('Keypair', 'priv pub')


def generate_keypair():
    privkey = PrivateKey.generate()
    return Keypair(bytes(privkey), bytes(privkey.public_key))


def generate_dh(a, b):
    a = PrivateKey(a)
    b = PublicKey(b)
    return bytes(Box(a, b))


def generate_3dh(a, a0, b, b0, mode=ALICE_MODE):
    if mode is ALICE_MODE:
        return hash_(generate_dh(a, b0) +
                     generate_dh(a0, b) +
                     generate_dh(a0, b0))
    else:
        return hash_(generate_dh(a0, b) +
                     generate_dh(a, b0) +
                     generate_dh(a0, b0))


def encrypt_symmetric(key, plaintext):
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    box = nacl.secret.SecretBox(key)
    return bytes(box.encrypt(plaintext, nonce))


def decrypt_symmetric(key, ciphertext):
    box = nacl.secret.SecretBox(key)
    return box.decrypt(ciphertext)
