#!/usr/bin/env python

from dict import DictDiffer
import binascii
import os
from pyaxo import Axolotl

# need clean database for this example to work
os.remove('./axolotl.db')

# create three instance classes
tom = Axolotl('Tom')
dick = Axolotl('Dick')
harry = Axolotl('Harry')

# initialize Tom and Dick's states
tom.initState('Dick', dick.identityPKey, dick.handshakePKey, dick.ratchetPKey)
dick.initState('Tom', tom.identityPKey, tom.handshakePKey, tom.ratchetPKey)

# tell who is who
if tom.mode:
    print 'Tom is Alice-like'
    print 'Dick is Bob-like'
else:
    print 'Tom is Bob-like'
    print 'Dick is Alice-like'

print

# get the plaintext
with open('file.txt', 'r') as f:
    msg = f.read()

# Tom encrypts it to Dick
ciphertext = tom.encrypt(msg)

# save Dick's state prior to decrypting the message
dick.saveState()

# Dick decrypts the ciphertext
print "Dick's decryption..."
print dick.decrypt(ciphertext)

# now load Dick's state to Harry
print
print "Harry is loading Dick's state..."
harry.loadState('Dick', 'Tom')

# Harry decrypts the ciphertext
print
print "Harry's decryption..."
print harry.decrypt(ciphertext)

# they match, so the two states are the same!!!
