"""
pyaxo.py - a python implementation of the axolotl ratchet protocol.
https://github.com/trevp/axolotl/wiki/newversion
This version uses straight Diffie-Hellman, rather than ECDH.

Symmetric encryption is done using the python-gnupg module.

Copyright (C) 2014 by David R. Andersen

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
from time import time
from passlib.utils.pbkdf2 import pbkdf2

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
        self.generator = 5
        # 2048-bit MODP from RFC 3526
        self.prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.identityKey = self.genPrivateKey(2048)
        self.identityPKey = self.genPublicKey(self.identityKey)
        self.ratchetKey = self.genPrivateKey(2048)
        self.ratchetPKey = self.genPublicKey(self.ratchetKey)
        self.handshakeKey = self.genPrivateKey(2048)
        self.handshakePKey = self.genPublicKey(self.handshakeKey)
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
            return hashlib.sha256(self.genDH(a, B0) + self.genDH(a0, B) + self.genDH(a0, B0)).hexdigest()
        else:
            return hashlib.sha256(self.genDH(a0, B) + self.genDH(a, B0) + self.genDH(a0, B0)).hexdigest()

    def genDH(self, a, B):
        return str(pow(B, a, self.prime))

    def genPublicKey(self, a):
        return pow(self.generator, a, self.prime)

    def genPrivateKey(self, bits):
        return secure_random(bits)

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
            self.state['DHRs_priv'] = self.genPrivateKey(2048)
            self.state['DHRs'] = self.genPublicKey(self.state['DHRs_priv'])
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
                print 'undecipherable location 1'
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
                print 'undecipherable location 2'
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
                print 'undecipherable location 3'
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


    def saveState(self):
        DHRs_priv = 0 if self.state['DHRs_priv'] is None else str(self.state['DHRs_priv'])
        DHRs = 0 if self.state['DHRs'] is None else str(self.state['DHRs'])
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
              mode INTEGER \
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
              mode \
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', \
            ( self.state['name'], \
              self.state['other_name'], \
              self.mkey, \
              binascii.b2a_base64(self.state['RK']).strip(), \
              binascii.b2a_base64(self.state['HKs']).strip(), \
              binascii.b2a_base64(self.state['HKr']).strip(), \
              binascii.b2a_base64(self.state['NHKs']).strip(), \
              binascii.b2a_base64(self.state['NHKr']).strip(), \
              binascii.b2a_base64(self.state['CKs']).strip(), \
              binascii.b2a_base64(self.state['CKr']).strip(), \
              str(self.state['DHIs_priv']), \
              str(self.state['DHIs']), \
              str(self.state['DHIr']), \
              DHRs_priv, \
              DHRs, \
              str(self.state['DHRr']), \
              self.state['Ns'], \
              self.state['Nr'], \
              self.state['PNs'], \
              bobs_first_message, \
              mode \
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
                             'DHIs_priv': int(row[11]),
                             'DHIs': int(row[12]),
                             'DHIr': int(row[13]),
                             #'DHRs_priv': row[14],
                             #'DHRs': row[15],
                             'DHRr': int(row[16]),
                             'Ns': row[17],
                             'Nr': row[18],
                             'PNs': row[19],
                             #'bobs_first_message': row[20]
                           }
                    self.state['DHRs_priv'] = None if row[14] == '0' else int(row[14])
                    self.state['DHRs'] = None if row[15] == '0' else int(row[15])
                    bobs_first_message = row[20]
                    self.state['bobs_first_message'] = True if bobs_first_message == 1 \
                                                       else False
                    self.mkey = row[3]
                    mode = row[21]
                    self.mode = True if mode == 1 else False
                    print "state loaded for " + self.state['name'] + " -> " + \
                           self.state['other_name']
                    return # exit at first match
            return False # if no matches
