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

import sqlite3
import hashlib
import binascii
import hmac
import gnupg
import os
import sys
from binascii import a2b_base64 as a2b
from binascii import b2a_base64 as b2a
from getpass import getpass
from time import time
from passlib.utils.pbkdf2 import pbkdf2
from curve25519 import keys

# We cut out the inner cipher header to minimize bandwidth
# and then add it back at decrypt time.
cipher_hdr = {
   'IDEA' :        '8c0d04010308',
   '3DES' :        '8c0d04020308',
   'CAST5' :       '8c0d04030308',
   'BLOWFISH' :    '8c0d04040308',
   #'RESERVED1' :   '8c0d04050308',
   #'RESERVED2' :   '8c0d04060308',
   'AES' :         '8c0d04070308',
   'AES192' :      '8c0d04080308',
   'AES256' :      '8c0d04090308',
   'TWOFISH' :     '8c0d040a0308',
   'CAMELLIA128' : '8c0d040b0308',
   'CAMELLIA192' : '8c0d040c0308',
   'CAMELLIA256' : '8c0d040d0308'
}

GPG_CIPHER = 'AES256'
GPG_HEADER = binascii.unhexlify(cipher_hdr[GPG_CIPHER])

user_path = os.path.expanduser('~')
KEYRING = [user_path+'/.gnupg/pubring.gpg']
SECRET_KEYRING = [user_path+'/.gnupg/secring.gpg']
GPGBINARY = 'gpg'

gpg = gnupg.GPG(gnupghome=user_path+'/.axolotl', gpgbinary=GPGBINARY, keyring=KEYRING,
                secret_keyring=SECRET_KEYRING, options=['--throw-keyids',
                '--personal-digest-preferences=sha256','--s2k-digest-algo=sha256'])
gpg.encoding = 'utf-8'

ALICE_MODE = True
BOB_MODE = False

SALTS = {'RK': b'\x00',
         'HK': {ALICE_MODE: b'\x01', BOB_MODE: b'\x02'},
         'NHK': {ALICE_MODE: b'\x03', BOB_MODE: b'\x04'},
         'CK': {ALICE_MODE: b'\x05', BOB_MODE: b'\x06'},
         'CONVid': b'\x07'}

HEADER_LEN = 106
HEADER_PAD_NUM_LEN = 1
HEADER_COUNT_NUM_LEN = 3

class Axolotl:

    def __init__(self, name, dbname='axolotl.db', dbpassphrase='', nonthreaded_sql=True):
        self.name = name
        self.dbname = dbname
        self.nonthreaded_sql = nonthreaded_sql
        if dbpassphrase != '' or dbpassphrase is None:
            self.dbpassphrase = dbpassphrase
        else:
            self.dbpassphrase = getpass('Database passphrase for '+ self.name + ': ').strip()
        try:
            self.db = self.openDB()
        except sqlite3.OperationalError:
            print 'Bad sql! Password problem - cannot create the database.'
            sys.exit(1)
        self.mode = None
        self.staged_HK_mk = {}
        self.state = {}
        self.state['DHIs_priv'], self.state['DHIs'] = generate_keypair()
        self.state['DHRs_priv'], self.state['DHRs'] = generate_keypair()
        self.handshakeKey, self.handshakePKey = generate_keypair()
        self.storeTime = 2*86400 # minimum time (seconds) to store missed ephemeral message keys
        with self.db:
            cur = self.db.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS
                    skipped_mk (
                        my_identity,
                        to_identity,
                        HKr TEXT,
                        mk TEXT,
                        timestamp INTEGER)''')
            cur.execute('''
                CREATE UNIQUE INDEX IF NOT EXISTS
                    message_keys
                ON
                    skipped_mk (mk)''')
            cur.execute('''
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
            cur.execute('''
                CREATE UNIQUE INDEX IF NOT EXISTS
                    conversation_route
                ON
                    conversations (
                        my_identity,
                        other_identity)''')
        self.commitSkippedMK()

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
            fingerprint = hashlib.sha224(other_identityKey).hexdigest().upper()
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
        if self.state['DHIs'] < other_identityKey:
            self.mode = ALICE_MODE
        else:
            self.mode = BOB_MODE
        mkey = self.tripleDH(self.state['DHIs_priv'], self.handshakeKey,
                             other_identityKey, other_handshakeKey)

        self.createState(other_name, mkey,
                         other_identityKey=other_identityKey,
                         other_ratchetKey=other_ratchetKey)

    def createState(self, other_name, mkey, mode=None, other_identityKey=None, other_ratchetKey=None):
        if mode is not None:
            self.mode = mode
        else:
            if self.mode is None: # mode not selected
                sys.exit(1)
        if self.mode is ALICE_MODE:
            HKs = None
            HKr = kdf(mkey, SALTS['HK'][BOB_MODE])
            CKs = None
            CKr = kdf(mkey, SALTS['CK'][BOB_MODE])
            DHRs_priv = None
            DHRs = None
            DHRr = other_ratchetKey
            Ns = 0
            Nr = 0
            PNs = 0
            ratchet_flag = True
        else: # bob mode
            HKs = kdf(mkey, SALTS['HK'][BOB_MODE])
            HKr = None
            CKs = kdf(mkey, SALTS['CK'][BOB_MODE])
            CKr = None
            DHRs_priv = self.state['DHRs_priv']
            DHRs = self.state['DHRs']
            DHRr = None
            Ns = 0
            Nr = 0
            PNs = 0
            ratchet_flag = False
        RK = kdf(mkey, SALTS['RK'])
        NHKs = kdf(mkey, SALTS['NHK'][self.mode])
        NHKr = kdf(mkey, SALTS['NHK'][not self.mode])
        CONVid = kdf(mkey, SALTS['CONVid'])
        DHIr = other_identityKey

        self.state = \
               { 'name': self.name,
                 'other_name': other_name,
                 'RK': RK,
                 'HKs': HKs,
                 'HKr': HKr,
                 'NHKs': NHKs,
                 'NHKr': NHKr,
                 'CKs': CKs,
                 'CKr': CKr,
                 'DHIs_priv': self.state['DHIs_priv'],
                 'DHIs': self.state['DHIs'],
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

        self.ratchetKey = False
        self.ratchetPKey = False

    def encrypt(self, plaintext):
        if self.state['ratchet_flag']:
            self.state['DHRs_priv'], self.state['DHRs'] = generate_keypair()
            self.state['HKs'] = self.state['NHKs']
            self.state['RK'] = hash_(self.state['RK'] +
                                     generate_dh(self.state['DHRs_priv'], self.state['DHRr']))
            self.state['NHKs'] = kdf(self.state['RK'], SALTS['NHK'][self.mode])
            self.state['CKs'] = kdf(self.state['RK'], SALTS['CK'][self.mode])
            self.state['PNs'] = self.state['Ns']
            self.state['Ns'] = 0
            self.state['ratchet_flag'] = False
        mk = hash_(self.state['CKs'] + '0')
        msg1 = encrypt_symmetric(
            self.state['HKs'],
            str(self.state['Ns']).zfill(HEADER_COUNT_NUM_LEN) +
            str(self.state['PNs']).zfill(HEADER_COUNT_NUM_LEN) +
            self.state['DHRs'])
        msg2 = encrypt_symmetric(mk, plaintext)
        pad_length = HEADER_LEN - len(msg1)
        pad = os.urandom(pad_length - HEADER_PAD_NUM_LEN) + chr(pad_length)
        msg = msg1 + pad + msg2
        self.state['Ns'] += 1
        self.state['CKs'] = hash_(self.state['CKs'] + '1')
        return msg


    def enc(self, key, plaintext):
        return encrypt_symmetric(key, plaintext)

    def dec(self, key, encrypted):
        return decrypt_symmetric(key, encrypted)

    def commitSkippedMK(self):
        timestamp = int(time())
        with self.db:
            cur = self.db.cursor()
            for mk, HKr in self.staged_HK_mk.iteritems():
                cur.execute('''
                    REPLACE INTO
                        skipped_mk (
                            my_identity,
                            to_identity,
                            HKr,
                            mk,
                            timestamp)
                    VALUES (?, ?, ?, ?, ?)''', (
                        self.state['name'],
                        self.state['other_name'],
                        b2a(HKr).strip(),
                        b2a(mk).strip(),
                            timestamp))
            rowtime = timestamp - self.storeTime
            cur.execute('''
                DELETE FROM
                    skipped_mk
                WHERE
                    timestamp < ?''', (rowtime,))

    def trySkippedMK(self, msg, pad_length, name, other_name):
        with self.db:
            cur = self.db.cursor()
            cur.execute('''
                SELECT
                    *
                FROM
                    skipped_mk
                WHERE
                    my_identity = ? AND
                    to_identity = ?''', (name, other_name))
            rows = cur.fetchall()
            for row in rows:
                msg1 = msg[:HEADER_LEN-pad_length]
                msg2 = msg[HEADER_LEN:]
                header = decrypt_symmetric(a2b(row['hkr']), msg1)
                body = decrypt_symmetric(a2b(row['mk']), msg2)
                if header != '' and body != '':
                    cur.execute('''
                        DELETE FROM
                            skipped_mk
                        WHERE
                            mk = ?''', (row['mk'],))
                    return body
        return False

    def stageSkippedMK(self, HKr, Nr, Np, CKr):
        CKp = CKr
        for i in range(Np - Nr):
            mk = hash_(CKp + '0')
            CKp = hash_(CKp + '1')
            self.staged_HK_mk[mk] = HKr
        mk = hash_(CKp + '0')
        CKp = hash_(CKp + '1')
        return CKp, mk

    def decrypt(self, msg):
        pad = msg[HEADER_LEN-HEADER_PAD_NUM_LEN:HEADER_LEN]
        pad_length = ord(pad)
        msg1 = msg[:HEADER_LEN-pad_length]

        body = self.trySkippedMK(msg, pad_length, self.state['name'],
                                      self.state['other_name'])
        if body and body != '':
            return body

        header = None
        if self.state['HKr']:
            header = decrypt_symmetric(self.state['HKr'], msg1)
        if header and header != '':
            Np = int(header[:HEADER_COUNT_NUM_LEN])
            CKp, mk = self.stageSkippedMK(self.state['HKr'], self.state['Nr'], Np, self.state['CKr'])
            body = decrypt_symmetric(mk, msg[HEADER_LEN:])
            if not body or body == '':
                print 'Undecipherable message'
                sys.exit(1)
        else:
            header = decrypt_symmetric(self.state['NHKr'], msg1)
            if self.state['ratchet_flag'] or not header or header == '':
                print 'Undecipherable message'
                sys.exit(1)
            Np = int(header[:HEADER_COUNT_NUM_LEN])
            PNp = int(header[HEADER_COUNT_NUM_LEN:HEADER_COUNT_NUM_LEN*2])
            DHRp = header[HEADER_COUNT_NUM_LEN*2:]
            if self.state['CKr']:
                self.stageSkippedMK(self.state['HKr'], self.state['Nr'], PNp, self.state['CKr'])
            HKp = self.state['NHKr']
            RKp = hash_(self.state['RK'] + generate_dh(self.state['DHRs_priv'], DHRp))
            NHKp = kdf(RKp, SALTS['NHK'][not self.mode])
            CKp = kdf(RKp, SALTS['CK'][not self.mode])
            CKp, mk = self.stageSkippedMK(HKp, 0, Np, CKp)
            body = decrypt_symmetric(mk, msg[HEADER_LEN:])
            if not body or body == '':
                print 'Undecipherable message'
                sys.exit(1)
            self.state['RK'] = RKp
            self.state['HKr'] = HKp
            self.state['NHKr'] = NHKp
            self.state['DHRr'] = DHRp
            self.state['DHRs_priv'] = None
            self.state['DHRs'] = None
            self.state['ratchet_flag'] = True
        self.commitSkippedMK()
        self.state['Nr'] = Np + 1
        self.state['CKr'] = CKp
        return body

    def encrypt_file(self, filename):
        with open(filename, 'r') as f:
            plaintext = f.read()
        ciphertext = b2a(self.encrypt(plaintext))
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
        ciphertext = b2a(self.encrypt(plaintext))
        sys.stdout.write(ciphertext)
        sys.stdout.flush()

    def decrypt_pipe(self):
        ciphertext = a2b(sys.stdin.read())
        plaintext = self.decrypt(ciphertext)
        sys.stdout.write(plaintext)
        sys.stdout.flush()

    def printKeys(self):
        print 'Your Identity key is:\n' + b2a(self.state['DHIs'])
        fingerprint = hashlib.sha224(self.state['DHIs']).hexdigest().upper()
        fprint = ''
        for i in range(0, len(fingerprint), 4):
            fprint += fingerprint[i:i+2] + ':'
        print 'Your identity key fingerprint is: '
        print fprint[:-1] + '\n'
        print 'Your Ratchet key is:\n' + b2a(self.state['DHRs'])
        if self.handshakeKey:
            print 'Your Handshake key is:\n' + b2a(self.handshakePKey)
        else:
            print 'Your Handshake key is not available'

    def saveState(self):
        HKs = 0 if self.state['HKs'] is None else b2a(self.state['HKs']).strip()
        HKr = 0 if self.state['HKr'] is None else b2a(self.state['HKr']).strip()
        CKs = 0 if self.state['CKs'] is None else b2a(self.state['CKs']).strip()
        CKr = 0 if self.state['CKr'] is None else b2a(self.state['CKr']).strip()
        DHIr = 0 if self.state['DHIr'] is None else b2a(self.state['DHIr']).strip()
        DHRs_priv = 0 if self.state['DHRs_priv'] is None else b2a(self.state['DHRs_priv']).strip()
        DHRs = 0 if self.state['DHRs'] is None else b2a(self.state['DHRs']).strip()
        DHRr = 0 if self.state['DHRr'] is None else b2a(self.state['DHRr']).strip()
        ratchet_flag = 1 if self.state['ratchet_flag'] else 0
        mode = 1 if self.mode else 0
        with self.db:
            cur = self.db.cursor()
            cur.execute('''
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
                    self.state['name'],
                    self.state['other_name'],
                    b2a(self.state['RK']).strip(),
                    HKs,
                    HKr,
                    b2a(self.state['NHKs']).strip(),
                    b2a(self.state['NHKr']).strip(),
                    CKs,
                    CKr,
                    b2a(self.state['DHIs_priv']).strip(),
                    b2a(self.state['DHIs']).strip(),
                    DHIr,
                    DHRs_priv,
                    DHRs,
                    DHRr,
                    b2a(self.state['CONVid']).strip(),
                    self.state['Ns'],
                    self.state['Nr'],
                    self.state['PNs'],
                    ratchet_flag,
                    mode))
        self.writeDB()

    def loadState(self, name, other_name):
        self.db = self.openDB()
        with self.db:
            cur = self.db.cursor()
            try:
                cur.execute('''
                    SELECT
                        *
                    FROM
                        conversations
                    WHERE
                        my_identity = ? AND
                        other_identity = ?''', (name, other_name))
            except sqlite3.OperationalError:
                print 'Bad sql! Password problem - cannot loadState()'
                sys.exit(1)
            row = cur.fetchone()
            if row:
                self.state = \
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
                self.name = self.state['name']
                self.state['HKs'] = None if row['hks'] == '0' else a2b(row['hks'])
                self.state['HKr'] = None if row['hkr'] == '0' else a2b(row['hkr'])
                self.state['CKs'] = None if row['cks'] == '0' else a2b(row['cks'])
                self.state['CKr'] = None if row['ckr'] == '0' else a2b(row['ckr'])
                self.state['DHIr'] = None if row['dhir'] == '0' else a2b(row['dhir'])
                self.state['DHRs_priv'] = None if row['dhrs_priv'] == '0' else a2b(row['dhrs_priv'])
                self.state['DHRs'] = None if row['dhrs'] == '0' else a2b(row['dhrs'])
                self.state['DHRr'] = None if row['dhrr'] == '0' else a2b(row['dhrr'])
                ratchet_flag = row['ratchet_flag']
                self.state['ratchet_flag'] = True if ratchet_flag == 1 \
                                                    else False
                mode = row['mode']
                self.mode = True if mode == 1 else False
                return # exit at first match
            else:
                return False # if no matches

    def openDB(self):

        db = sqlite3.connect(':memory:', check_same_thread=self.nonthreaded_sql)
        db.row_factory = sqlite3.Row

        try:
            with open(self.dbname, 'rb') as f:
                if self.dbpassphrase is not None:
                    sql = gpg.decrypt_file(f, passphrase=self.dbpassphrase)
                    if sql and sql != '':
                        db.cursor().executescript(sql.data)
                        return db
                    else:
                        print 'Bad passphrase!'
                        sys.exit(1)
                else:
                    sql = f.read()
                    db.cursor().executescript(sql)
                    return db
        except IOError:
            return db

    def writeDB(self):

        sql = ''
        for item in self.db.iterdump():
            sql = sql+item+'\n'
        if self.dbpassphrase is not None:
            crypt_sql = gpg.encrypt(sql, recipients=None, symmetric='AES256', armor=False,
                                always_trust=True, passphrase=self.dbpassphrase)
            with open(self.dbname, 'wb') as f:
                f.write(crypt_sql.data)
        else:
            with open(self.dbname, 'w') as f:
                f.write(sql)

    def printState(self):
        print
        print 'Warning: saving this data to disk is insecure!'
        print
        for key in sorted(self.state):
             if 'priv' in key:
                 pass
             else:
                 if self.state[key] is None:
                     print key + ': None'
                 elif type(self.state[key]) is bool:
                     if self.state[key]:
                         print key + ': True'
                     else:
                         print key + ': False'
                 elif type(self.state[key]) is str:
                     try:
                         self.state[key].decode('ascii')
                         print key + ': ' + self.state[key]
                     except UnicodeDecodeError:
                         print key + ': ' + b2a(self.state[key]).strip()
                 else:
                     print key + ': ' + str(self.state[key])
        if self.mode is ALICE_MODE:
            print 'Mode: Alice'
        else:
            print 'Mode: Bob'


def hash_(data):
    return hashlib.sha256(data).digest()


def kdf(secret, salt):
    return pbkdf2(secret, salt, rounds=10, prf='hmac-sha256')


def generate_keypair():
    key = keys.Private()
    privkey = key.serialize()
    pubkey = key.get_public().serialize()
    return privkey, pubkey


def generate_dh(a, b):
    key = keys.Private(secret=a)
    return key.get_shared_key(keys.Public(b))


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
    key = binascii.hexlify(key)
    msg = gpg.encrypt(plaintext, recipients=None, symmetric=GPG_CIPHER,
                      armor=False, always_trust=True, passphrase=key)
    return msg.data[len(GPG_HEADER):]


def decrypt_symmetric(key, ciphertext):
    key = binascii.hexlify(key)
    msg = gpg.decrypt(GPG_HEADER + ciphertext, passphrase=key,
                      always_trust=True)
    return msg.data
