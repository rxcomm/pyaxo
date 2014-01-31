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
from time import time
from passlib.utils.pbkdf2 import pbkdf2
from curve25519 import keys

# If a secure random number generator is unavailable, exit with an error.
try:
    import Crypto.Random.random
    secure_random = Crypto.Random.random.getrandbits
except ImportError:
    import OpenSSL
    secure_random = lambda x: long(binascii.hexlify(OpenSSL.rand.bytes(x>>3)), 16)

user_path = os.path.expanduser('~')
KEYRING = [user_path+'/.gnupg/pubring.gpg']
SECRET_KEYRING = [user_path+'/.gnupg/secring.gpg']
GPGBINARY = 'gpg'

gpg = gnupg.GPG(gnupghome=user_path+'/.axolotl', gpgbinary=GPGBINARY, keyring=KEYRING,
                secret_keyring=SECRET_KEYRING, options=['--throw-keyids',
                '--personal-digest-preferences=sha256','--s2k-digest-algo=sha256'])
gpg.encoding = 'utf-8'

class Axolotl:

    def __init__(self, name):
        self.name = name
        self.identityKey, self.identityPKey = self.genKey()
        self.ratchetKey, self.ratchetPKey = self.genKey()
        self.handshakeKey, self.handshakePKey = self.genKey()
        self.mode = None
        self.staged_HK_mk = {}
        self.state = {}
        self.storeTime = 2*86400 # minimum time (seconds) to store missed ephemeral message keys
        db = sqlite3.connect('axolotl.db')
        with db:
            cur = db.cursor()
            cur.execute('CREATE TABLE IF NOT EXISTS skipped_mk ( \
              id INTEGER PRIMARY KEY, \
              my_identity, \
              to_identity, \
              HKr TEXT, \
              mk TEXT, \
              timestamp INTEGER \
            )')
        self.commitSkippedMK()

    def tripleDH(self, a, a0, B, B0):
        if self.mode == None:
            exit(1)
        if self.mode:
            return hashlib.sha256(self.genDH(a, B0) + self.genDH(a0, B) + self.genDH(a0, B0)).digest()
        else:
            return hashlib.sha256(self.genDH(a0, B) + self.genDH(a, B0) + self.genDH(a0, B0)).digest()

    def genDH(self, a, B):
        key = keys.Private(secret=a)
        return key.get_shared_key(keys.Public(B))

    def genKey(self):
        key = keys.Private()
        privkey = key.private
        pubkey = key.get_public().serialize()
        return privkey, pubkey

    def initState(self, other_name, other_identityKey, other_handshakeKey, other_ratchetKey):
        if self.identityPKey < other_identityKey:
            self.mode = True
        else:
            self.mode = False
        DHIr = other_identityKey
        DHRr = other_ratchetKey
        self.mkey = self.tripleDH(self.identityKey, self.handshakeKey,
                                  other_identityKey, other_handshakeKey)
        if self.mode == None: # mode not selected
            exit(1)
        if self.mode: # alice mode
            RK = pbkdf2(self.mkey, hex(00), 10, prf='hmac-sha256')
            HKs = pbkdf2(self.mkey, hex(01), 10, prf='hmac-sha256')
            HKr = pbkdf2(self.mkey, hex(02), 10, prf='hmac-sha256')
            NHKs = pbkdf2(self.mkey, hex(03), 10, prf='hmac-sha256')
            NHKr = pbkdf2(self.mkey, hex(04), 10, prf='hmac-sha256')
            CKs = pbkdf2(self.mkey, hex(05), 10, prf='hmac-sha256')
            CKr = pbkdf2(self.mkey, hex(06), 10, prf='hmac-sha256')
            DHIs_priv = self.identityKey
            DHIs = self.identityPKey
            DHRs_priv = self.ratchetKey
            DHRs = self.ratchetPKey
            Ns = 0
            Nr = 0
            PNs = 0
            bobs_first_message = False
        else: # bob mode
            RK = pbkdf2(self.mkey, hex(00), 10, prf='hmac-sha256')
            HKs = pbkdf2(self.mkey, hex(02), 10, prf='hmac-sha256')
            HKr = pbkdf2(self.mkey, hex(01), 10, prf='hmac-sha256')
            NHKs = pbkdf2(self.mkey, hex(04), 10, prf='hmac-sha256')
            NHKr = pbkdf2(self.mkey, hex(03), 10, prf='hmac-sha256')
            CKs = pbkdf2(self.mkey, hex(06), 10, prf='hmac-sha256')
            CKr = pbkdf2(self.mkey, hex(05), 10, prf='hmac-sha256')
            DHIs_priv = self.identityKey
            DHIs = self.identityPKey
            DHRs_priv = self.ratchetKey
            DHRs = self.ratchetPKey
            Ns = 0
            Nr = 0
            PNs = 0
            bobs_first_message = True

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
                 'DHIs_priv': DHIs_priv,
                 'DHIs': DHIs,
                 'DHIr': DHIr,
                 'DHRs_priv': DHRs_priv,
                 'DHRs': DHRs,
                 'DHRr': DHRr,
                 'Ns': Ns,
                 'Nr': Nr,
                 'PNs': PNs,
                 'bobs_first_message': bobs_first_message,
               }

    def encrypt(self, plaintext):
        if self.state['DHRs'] == None:
            self.state['DHRs_priv'], self.state['DHRs'] = self.genKey()
            self.state['Ns'] = 0
        mk = hashlib.sha256(self.state['CKs'] + '0').digest()
        msg1 = self.enc(self.state['HKs'], str(self.state['Ns']).zfill(3) +
                        str(self.state['PNs']).zfill(3) + str(self.state['DHRs']))
        msg2 = self.enc(mk, plaintext)
        msg = str(len(msg1)).zfill(3) + msg1 + msg2
        self.state['Ns'] += 1
        self.state['CKs'] = hashlib.sha256(self.state['CKs'] + '1').digest()
        return msg


    def enc(self, key, plaintext):
        key = binascii.hexlify(key)
        msg = gpg.encrypt(plaintext, recipients=None, symmetric='AES256', armor=False,
                                always_trust=True, passphrase=key)
        return msg.data

    def dec(self, key, encrypted):
        key = binascii.hexlify(key)
        msg = gpg.decrypt(encrypted, passphrase=key, always_trust=True)
        return msg.data

    def commitSkippedMK(self):
        timestamp = int(time())
        db = sqlite3.connect('axolotl.db')
        with db:
            cur = db.cursor()
            for mk, HKr in self.staged_HK_mk.iteritems():
                cur.execute('INSERT INTO skipped_mk ( \
                  my_identity, \
                  to_identity, \
                  HKr, \
                  mk, \
                  timestamp \
                ) VALUES (?, ?, ?, ?, ?)', \
                ( self.state['name'], \
                  self.state['other_name'], \
                  binascii.b2a_base64(HKr).strip(), \
                  binascii.b2a_base64(mk).strip(), \
                  timestamp \
                ))
            rowtime = timestamp - self.storeTime
            cur.execute('DELETE FROM skipped_mk WHERE timestamp < ?', (rowtime,))

    def trySkippedMK(self, msg, name, other_name):
        db = sqlite3.connect('axolotl.db')
        with db:
            cur = db.cursor()
            cur.execute('SELECT * FROM skipped_mk')
            rows = cur.fetchall()
            for row in rows:
                if name == row[1] and other_name == row[2]:
                    msg1 = msg[3:3+int(msg[:3])]
                    msg2 = msg[3+int(msg[:3]):]
                    header = self.dec(binascii.a2b_base64(row[3]), msg1)
                    body = self.dec(binascii.a2b_base64(row[4]), msg2)
                    if header != '' and body != '':
                        return body
        return False

    def stageSkippedMK(self, HKr, Nr, Np, CKr):
        CKp = CKr
        for i in range(Np - Nr):
            mk = hashlib.sha256(CKp + '0').digest()
            CKp = hashlib.sha256(CKp + '1').digest()
            self.staged_HK_mk[mk] = HKr
        mk = hashlib.sha256(CKp + '0').digest()
        CKp = hashlib.sha256(CKp + '1').digest()
        return CKp, mk

    def decrypt(self, msg):
        body = self.trySkippedMK(msg, self.state['name'],
                                      self.state['other_name'])
        if body and body != '':
            return body

        header = self.dec(self.state['HKr'], msg[3:3+int(msg[:3])])
        if header and header != '':
            Np = int(header[:3])
            CKp, mk = self.stageSkippedMK(self.state['HKr'], self.state['Nr'], Np, self.state['CKr'])
            body = self.dec(mk, msg[3+int(msg[:3]):])
            if not body or body == '':
                print 'Undecipherable message'
                exit(1)
            if self.state['bobs_first_message']:
                self.state['DHRr'] = int(header[6:], 0)
                self.state['RK'] = hashlib.sha256(self.state['RK'] +
                                     self.genDH(self.state['DHRs_priv'], self.state['DHRr'])).digest()
                self.state['HKs'] = self.state['NHKs']
                if self.mode:
                    self.state['NHKs'] = pbkdf2(self.state['RK'], hex(03), 10, prf='hmac-sha256')
                    self.state['CKs'] = pbkdf2(self.state['RK'], hex(05), 10, prf='hmac-sha256')
                else:
                    self.state['NHKs'] = pbkdf2(self.state['RK'], hex(04), 10, prf='hmac-sha256')
                    self.state['CKs'] = pbkdf2(self.state['RK'], hex(06), 10, prf='hmac-sha256')
                self.state['DHRs_priv'] = None
                self.state['DHRs'] = None
                self.state['bobs_first_message'] = False
        else:
            header = self.dec(self.state['NHKr'], msg[3:3+int(msg[:3])])
            if not header or header == '':
                print 'Undecipherable message'
                exit(1)
            Np = int(header[:3])
            PNp = int(header[3:6])
            DHRp = int(header[6:], 0)
            self.stageSkippedMK(self.state['HKr'], self.state['Nr'], PNp, self.state['CKr'])
            RKp = hashlib.sha256(self.state['RK'] +
                  self.genDH(self.state['DHRs_priv'], self.state['DHRr'])).digest()
            HKp = self.state['NHKr']
            if self.mode:
                NHKp = pbkdf2(RKp, hex(04), 10, prf='hmac-sha256')
                CKp = pbkdf2(RKp, hex(06), 10, prf='hmac-sha256')
            else:
                NHKp = pbkdf2(RKp, hex(03), 10, prf='hmac-sha256')
                CKp = pbkdf2(RKp, hex(05), 10, prf='hmac-sha256')
            CKp, mk = self.stageSkippedMK(HKp, 0, Np, CKp)
            body = self.dec(mk, msg[3+int(msg[:3]):])
            if not body or body == '':
                print 'Undecipherable message'
                exit(1)
            self.state['RK'] = RKp
            self.state['HKr'] = HKp
            self.state['NHKr'] = NHKp
            self.state['DHRr'] = DHRp
            self.state['RK'] = hashlib.sha256(self.state['RK'] +
                                 self.genDH(self.state['DHRs_priv'], self.state['DHRr'])).digest()
            self.state['HKs'] = self.state['NHKs']
            if self.mode:
                self.state['NHKs'] = pbkdf2(self.state['RK'], hex(03), 10, prf='hmac-sha256')
                self.state['CKs'] = pbkdf2(self.state['RK'], hex(05), 10, prf='hmac-sha256')
            else:
                self.state['NHKs'] = pbkdf2(self.state['RK'], hex(04), 10, prf='hmac-sha256')
                self.state['CKs'] = pbkdf2(self.state['RK'], hex(06), 10, prf='hmac-sha256')
            self.state['DHRs_priv'] = None
            self.state['DHRs'] = None
        self.commitSkippedMK()
        self.state['Nr'] = Np + 1
        self.state['CKr'] = CKp
        return body

    def encrypt_file(self, filename):
        with open(filename, 'r') as f:
            plaintext = f.read()
        ciphertext = binascii.b2a_base64(self.encrypt(plaintext))
        with open(filename+'.asc', 'w') as f:
            lines = [ciphertext[i:i+64] for i in xrange(0, len(ciphertext), 64)]
            for line in lines:
                f.write(line+'\n')

    def decrypt_file(self, filename):
        with open(filename, 'r') as f:
            ciphertext = binascii.a2b_base64(f.read())
        plaintext = self.decrypt(ciphertext)
        print plaintext

    def encrypt_pipe(self):
        plaintext = sys.stdin.read()
        ciphertext = binascii.b2a_base64(self.encrypt(plaintext))
        sys.stdout.write(ciphertext)
        sys.stdout.flush()

    def decrypt_pipe(self):
        ciphertext = binascii.a2b_base64(sys.stdin.read())
        plaintext = self.decrypt(ciphertext)
        sys.stdout.write(plaintext)
        sys.stdout.flush()

    def printKeys(self):
        if self.name == self.state['name']:
            print 'Identity key:\n' + binascii.b2a_base64(self.identityPKey)
            print 'Handshake key:\n' + binascii.b2a_base64(self.handshakePKey)
            print 'Identity key:\n' + binascii.b2a_base64(self.ratchetPKey)
        else:
            print "The state doesn't match the name."

    def saveState(self):
        DHRs_priv = 0 if self.state['DHRs_priv'] is None else binascii.b2a_base64(self.state['DHRs_priv']).strip()
        DHRs = 0 if self.state['DHRs'] is None else binascii.b2a_base64(self.state['DHRs']).strip()
        bobs_first_message = 1 if self.state['bobs_first_message'] else 0
        mode = 1 if self.mode else 0
        db = sqlite3.connect('axolotl.db')
        with db:
            cur = db.cursor()
            cur.execute('CREATE TABLE IF NOT EXISTS conversations ( \
              id INTEGER PRIMARY KEY, \
              my_identity TEXT, \
              other_identity TEXT, \
              master_key TEXT, \
              RK TEXT, \
              HKs TEXT, \
              HKr TEXT, \
              NHKs TEXT, \
              NHKr TEXT, \
              CKs TEXT, \
              CKr TEXT, \
              DHIs_priv TEXT, \
              DHIs TEXT, \
              DHIr TEXT, \
              DHRs_priv TEXT, \
              DHRs TEXT, \
              DHRr TEXT, \
              Ns INTEGER, \
              Nr INTEGER, \
              PNs INTEGER, \
              bobs_first_message INTEGER, \
              mode INTEGER,\
              identityKey TEXT, \
              identityPKey TEXT, \
              handshakeKey TEXT, \
              handshakePKey TEXT, \
              ratchetKey TEXT, \
              ratchetPKey TEXT\
            )')
            cur.execute('INSERT INTO conversations ( \
              my_identity, \
              other_identity, \
              master_key, \
              RK, \
              HKS, \
              HKr, \
              NHKs, \
              NHKr, \
              CKs, \
              CKr, \
              DHIs_priv, \
              DHIs, \
              DHIr, \
              DHRs_priv, \
              DHRs, \
              DHRr, \
              Ns, \
              Nr, \
              PNs, \
              bobs_first_message, \
              mode, \
              identityKey, \
              identityPKey, \
              handshakeKey, \
              handshakePKey, \
              ratchetKey, \
              ratchetPKey \
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', \
            ( self.state['name'], \
              self.state['other_name'], \
              binascii.b2a_base64(self.mkey).strip(), \
              binascii.b2a_base64(self.state['RK']).strip(), \
              binascii.b2a_base64(self.state['HKs']).strip(), \
              binascii.b2a_base64(self.state['HKr']).strip(), \
              binascii.b2a_base64(self.state['NHKs']).strip(), \
              binascii.b2a_base64(self.state['NHKr']).strip(), \
              binascii.b2a_base64(self.state['CKs']).strip(), \
              binascii.b2a_base64(self.state['CKr']).strip(), \
              binascii.b2a_base64(self.state['DHIs_priv']).strip(), \
              binascii.b2a_base64(self.state['DHIs']).strip(), \
              binascii.b2a_base64(self.state['DHIr']).strip(), \
              DHRs_priv, \
              DHRs, \
              binascii.b2a_base64(self.state['DHRr']).strip(), \
              self.state['Ns'], \
              self.state['Nr'], \
              self.state['PNs'], \
              bobs_first_message, \
              mode, \
              binascii.b2a_base64(self.identityKey).strip(), \
              binascii.b2a_base64(self.identityPKey).strip(), \
              binascii.b2a_base64(self.handshakeKey).strip(), \
              binascii.b2a_base64(self.handshakePKey).strip(), \
              binascii.b2a_base64(self.ratchetKey).strip(), \
              binascii.b2a_base64(self.ratchetPKey).strip() \
            ))

    def loadState(self, name, other_name):
        db = sqlite3.connect('axolotl.db')

        with db:
            cur = db.cursor()
            cur.execute('SELECT * FROM conversations')
            rows = cur.fetchall()
            for row in rows:
                if row[1] == name and row[2] == other_name:
                    self.state = \
                           { 'name': row[1],
                             'other_name': row[2],
                             'RK': binascii.a2b_base64(row[4]),
                             'HKs': binascii.a2b_base64(row[5]),
                             'HKr': binascii.a2b_base64(row[6]),
                             'NHKs': binascii.a2b_base64(row[7]),
                             'NHKr': binascii.a2b_base64(row[8]),
                             'CKs': binascii.a2b_base64(row[9]),
                             'CKr': binascii.a2b_base64(row[10]),
                             'DHIs_priv': binascii.a2b_base64(row[11]),
                             'DHIs': binascii.a2b_base64(row[12]),
                             'DHIr': binascii.a2b_base64(row[13]),
                             'DHRr': binascii.a2b_base64(row[16]),
                             'Ns': row[17],
                             'Nr': row[18],
                             'PNs': row[19],
                           }
                    self.name = self.state['name']
                    self.state['DHRs_priv'] = None if row[14] == '0' else binascii.a2b_base64(row[14])
                    self.state['DHRs'] = None if row[15] == '0' else binascii.a2b_base64(row[15])
                    bobs_first_message = row[20]
                    self.state['bobs_first_message'] = True if bobs_first_message == 1 \
                                                       else False
                    self.mkey = binascii.a2b_base64(row[3])
                    mode = row[21]
                    self.mode = True if mode == 1 else False
                    self.identityKey = binascii.a2b_base64(row[22])
                    self.identityPKey = binascii.a2b_base64(row[23])
                    self.handshakeKey = binascii.a2b_base64(row[24])
                    self.handshakePKey = binascii.a2b_base64(row[25])
                    self.ratchetKey = binascii.a2b_base64(row[26])
                    self.ratchetPKey = binascii.a2b_base64(row[27])
                    return # exit at first match
            return False # if no matches
