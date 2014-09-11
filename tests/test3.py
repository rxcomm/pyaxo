#!/usr/bin/env python

import binascii
import os
from pyaxo import Axolotl

# need clean database for this example to work
try:
    os.remove('./axolotl.db')
except OSError:
    pass

# create three instance classes - axolotl will prompt for database passphrases
# Note that dick and harry's passphrases must match or harry won't be able to
# load dick's saved database
tom = Axolotl('Tom')
dick = Axolotl('Dick')
harry = Axolotl('Harry')

# initialize Tom and Dick's states
tom.initState('Dick', dick.state['DHIs'], dick.handshakePKey, dick.state['DHRs'], verify=False)
dick.initState('Tom', tom.state['DHIs'], tom.handshakePKey, tom.state['DHRs'], verify=False)

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
